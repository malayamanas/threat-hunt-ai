---
name: fsiem-l3-hunt
description: L3 senior threat hunter and threat intelligence analyst workflow — attribution, APT campaign analysis, MITRE ATT&CK mapping, diamond model, threat actor profiling, long-dwell detection, and proactive hunting using internal telemetry plus external threat intel feeds. Use when L2 escalates a complex or advanced threat, or for proactive weekly hunts.
---

# L3 Threat Intelligence & Advanced Hunting

L3 answers: **Who is doing this? How long have they been here? What's their full campaign? What will they do next?**

## L3 vs L2 Distinction

| L2 | L3 |
|---|---|
| What happened? | Who did it and why? |
| How far did it spread? | What's the full campaign scope? |
| Contained incident | Eradicated persistent access |
| Single incident | Multi-incident correlation |
| Days of telemetry | Weeks/months of telemetry |
| Playbook-driven | Hypothesis-driven |

## Step 1 — Long Dwell Time Detection

```python
import os, base64, requests, xml.etree.ElementTree as ET, time, re
from datetime import datetime, timedelta
from collections import defaultdict

def fsiem_headers():
    user, org, pw = os.environ["FSIEM_USER"], os.environ["FSIEM_ORG"], os.environ["FSIEM_PASS"]
    return {"Authorization": f"Basic {base64.b64encode(f'{user}/{org}:{pw}'.encode()).decode()}",
            "Content-Type": "text/xml"}

def fsiem_verify_ssl():
    return os.environ.get("FSIEM_VERIFY_SSL","false").lower() == "true"

def run_query(xml_str, max_results=1000):
    host = os.environ["FSIEM_HOST"]
    h = fsiem_headers()
    v = fsiem_verify_ssl()
    r = requests.post(f"{host}/phoenix/rest/query/eventQuery",
                      data=xml_str, headers=h, verify=v, timeout=30)
    r.raise_for_status()
    qid = r.text.strip()
    for _ in range(90):
        p = requests.get(f"{host}/phoenix/rest/query/progress/{qid}",
                         headers=h, verify=v, timeout=10)
        if int(p.text.strip() or "0") >= 100: break
        time.sleep(2)
    r2 = requests.get(f"{host}/phoenix/rest/query/events/{qid}/0/{max_results}",
                      headers=h, verify=v, timeout=30)
    root = ET.fromstring(r2.text)
    return [{a.findtext("name",""): a.findtext("value","")
             for a in ev.findall("attributes/attribute")}
            for ev in root.findall(".//event")]

def detect_long_dwell(days_back: int = 90, min_dwell_days: int = 14) -> list:
    """
    Hunt for attackers with long dwell time — persistent low-and-slow access.
    Looks for: rare outbound connections consistent over weeks, beaconing patterns,
    accounts with very infrequent logins to sensitive systems.
    """
    findings = []

    # 1. Beaconing detection — regular interval external connections
    beaconing_query = f"""<Reports><Report><n>Beaconing Hunt</n>
      <SelectClause><AttrList>srcIpAddr,destIpAddr,destPort,COUNT(eventId) AS conn_count</AttrList></SelectClause>
      <ReportInterval><Window>Last {days_back} days</Window></ReportInterval>
      <PatternClause><SubPattern><Filters>
        <Filter><n>eventType</n><Operator>CONTAIN</Operator><Value>Network Connection</Value></Filter>
        <Filter><n>destIpAddr</n><Operator>NOT_IN</Operator><Value>10.0.0.0/8,172.16.0.0/12,192.168.0.0/16</Value></Filter>
      </Filters></SubPattern></PatternClause></Report></Reports>"""

    beacon_events = run_query(beaconing_query, max_results=2000)

    # Group by src→dest pair and check for regularity
    pairs = defaultdict(list)
    for e in beacon_events:
        key = f"{e.get('srcIpAddr','')}->{e.get('destIpAddr','')}"
        pairs[key].append(e.get("eventTime",""))

    for pair, times in pairs.items():
        if len(times) >= 7:  # At least 7 connections over 90 days
            src, dest = pair.split("->")
            findings.append({
                "type": "BEACONING",
                "src_ip": src,
                "dest_ip": dest,
                "connection_count": len(times),
                "first_seen": min(times),
                "last_seen": max(times),
                "dwell_days": (datetime.now() - datetime.fromisoformat(min(times)[:10])).days
                              if times[0] else 0,
                "confidence": "HIGH" if len(times) > 30 else "MEDIUM",
                "mitre": "T1071 (Application Layer Protocol)",
            })

    # 2. Dormant account reactivation
    dormant_query = f"""<Reports><Report><n>Dormant Account Hunt</n>
      <SelectClause><AttrList>user,srcIpAddr,destIpAddr,eventTime,hostName</AttrList></SelectClause>
      <ReportInterval><Window>Last {days_back} days</Window></ReportInterval>
      <PatternClause><SubPattern><Filters>
        <Filter><n>eventType</n><Operator>CONTAIN</Operator><Value>Successful Login</Value></Filter>
        <Filter><n>user</n><Operator>NOT_CONTAIN</Operator><Value>svc_,service,system,health</Value></Filter>
      </Filters></SubPattern></PatternClause></Report></Reports>"""

    logins = run_query(dormant_query, max_results=2000)

    # Find accounts with long gaps between logins
    user_times = defaultdict(list)
    for e in logins:
        user = e.get("user","")
        t = e.get("eventTime","")
        if user and t:
            user_times[user].append(t)

    for user, times in user_times.items():
        times_sorted = sorted(times)
        for i in range(1, len(times_sorted)):
            try:
                gap = (datetime.fromisoformat(times_sorted[i][:10]) -
                       datetime.fromisoformat(times_sorted[i-1][:10])).days
                if gap > 60:  # 60+ day gap then reactivation
                    findings.append({
                        "type": "DORMANT_ACCOUNT_REACTIVATION",
                        "user": user,
                        "last_login_before_gap": times_sorted[i-1],
                        "reactivation_login": times_sorted[i],
                        "gap_days": gap,
                        "confidence": "HIGH" if gap > 90 else "MEDIUM",
                        "mitre": "T1078 (Valid Accounts)",
                    })
                    break
            except Exception:
                continue

    return sorted(findings, key=lambda x: x.get("dwell_days",0), reverse=True)
```

## Step 2 — MITRE ATT&CK Campaign Mapping

ATT&CK mapping uses a 24-technique library covering all major kill-chain stages.
Full implementation (ATTACK_TECHNIQUES dict + map_attack_campaign): see [reference.md](reference.md).

**Quick reference** — techniques covered:

| Tactic | Key Techniques |
|---|---|
| Initial Access | T1078, T1190, T1566 |
| Execution/Persistence | T1059, T1053, T1547, T1136 |
| Privilege Escalation | T1055, T1548 |
| Defense Evasion | T1027, T1562 |
| Credential Access | T1003, T1110, T1558 |
| Discovery | T1046, T1082, T1087 |
| Lateral Movement | T1021, T1550 |
| Collection/Exfil | T1074, T1056, T1041, T1048 |
| Impact | T1486, T1490 |

```python
# Copy ATTACK_TECHNIQUES dict and map_attack_campaign function
# from reference.md into your session before using them
```

## Step 3 — Diamond Model Threat Actor Profiling

```python
def build_diamond_model(campaign: dict, scope: dict, enrichments: dict) -> dict:
    """
    Build a Diamond Model profile for the threat actor.
    Returns adversary/capability/infrastructure/victim assessment.
    """
    techniques = campaign.get("techniques_detected", {})
    external_ips = scope.get("external_ips_contacted", [])
    sophistication = campaign.get("sophistication","UNKNOWN")

    # Infrastructure analysis
    infra_countries = list(set(
        enrichments.get(ip,{}).get("sources",{}).get("geoip",{}).get("country_code","?")
        for ip in external_ips if ip in enrichments
    ))
    infra_orgs = list(set(
        enrichments.get(ip,{}).get("sources",{}).get("geoip",{}).get("org","?")
        for ip in external_ips if ip in enrichments
    ))

    # Capability indicators
    uses_living_off_land = any(t in techniques for t in ["T1059","T1053","T1027"])
    uses_custom_tooling  = any(t in techniques for t in ["T1055","T1056"])
    long_dwell           = any(t in techniques for t in ["T1078","T1547"])

    # Adversary attribution (conservative)
    if sophistication == "APT-LEVEL" and long_dwell:
        adversary_tier = "Nation-State or Sponsored Actor (suspected)"
    elif sophistication == "ADVANCED":
        adversary_tier = "Organized Threat Actor (criminal or sponsored)"
    elif sophistication == "INTERMEDIATE":
        adversary_tier = "Script kiddie or opportunistic attacker"
    else:
        adversary_tier = "Unknown"

    return {
        "adversary": {
            "tier": adversary_tier,
            "sophistication": sophistication,
            "suspected_motivation": (
                "Espionage/IP Theft" if "T1074" in techniques and long_dwell else
                "Financial (Ransomware)" if "T1486" in techniques else
                "Financial (Fraud)" if "T1110" in techniques and not long_dwell else
                "Sabotage" if "T1490" in techniques else
                "Unknown"
            ),
            "ttps": list(techniques.keys()),
        },
        "capability": {
            "lives_off_land":    uses_living_off_land,
            "custom_tooling":    uses_custom_tooling,
            "long_dwell":        long_dwell,
            "techniques_count":  len(techniques),
            "tactics_count":     campaign.get("kill_chain_stages", 0),
        },
        "infrastructure": {
            "c2_ips":           external_ips[:10],
            "countries":        infra_countries,
            "hosting_orgs":     infra_orgs[:5],
            "uses_tor":         any(
                enrichments.get(ip,{}).get("sources",{}).get("abuseipdb",{}).get("is_tor",False)
                for ip in external_ips
            ),
            "uses_vps":         any("data" in str(enrichments.get(ip,{})
                                    .get("sources",{}).get("abuseipdb",{})
                                    .get("usage_type","")).lower()
                                    for ip in external_ips),
        },
        "victim": {
            "hosts_compromised":  scope.get("internal_hosts_reached",[]),
            "users_compromised":  scope.get("users_involved",[]),
            "data_exfil_mb":      scope.get("total_data_transferred_mb",0),
            "lateral_movement":   scope.get("lateral_movement_detected", False),
        }
    }
```

## Step 4 — L3 Threat Hunt Report

```python
def generate_l3_report(
    l2_investigation_id: str,
    dwell_findings: list,
    campaign: dict,
    diamond: dict,
    analyst: str,
) -> str:
    """Generate L3 threat intelligence report with full actor profiling."""
    adv = diamond["adversary"]
    cap = diamond["capability"]
    infra = diamond["infrastructure"]
    victim = diamond["victim"]
    techniques = campaign.get("techniques_detected", {})

    lines = [
        "# L3 Threat Intelligence Report",
        f"**Analyst**: {analyst} | **Date**: {datetime.now().strftime('%Y-%m-%d')}",
        f"**Source Investigation**: {l2_investigation_id}",
        f"**Classification**: TLP:AMBER",
        "",
        "---",
        "",
        "## Executive Summary",
        f"This investigation identified a **{adv['sophistication']}** threat actor "
        f"classified as **{adv['tier']}**. The actor demonstrated knowledge of "
        f"{cap['techniques_count']} ATT&CK techniques across {cap['tactics_count']} "
        f"kill-chain stages. Suspected motivation: **{adv['suspected_motivation']}**.",
        "",
        "## Diamond Model Assessment",
        "",
        "### Adversary",
        f"| Attribute | Assessment |",
        f"|---|---|",
        f"| Tier | {adv['tier']} |",
        f"| Sophistication | {adv['sophistication']} |",
        f"| Motivation | {adv['suspected_motivation']} |",
        f"| TTPs | {', '.join(adv['ttps'][:8])} |",
        "",
        "### Capability",
        f"| Capability | Present |",
        f"|---|---|",
        f"| Living off the land | {'✓' if cap['lives_off_land'] else '✗'} |",
        f"| Custom tooling | {'✓' if cap['custom_tooling'] else '✗'} |",
        f"| Long dwell time | {'✓' if cap['long_dwell'] else '✗'} |",
        f"| Kill chain stages covered | {cap['tactics_count']} / 14 |",
        "",
        "### Infrastructure",
        f"| Attribute | Value |",
        f"|---|---|",
        f"| C2 IPs | {', '.join(infra['c2_ips'][:5])} |",
        f"| Countries | {', '.join(infra['countries'])} |",
        f"| Uses TOR | {'Yes' if infra['uses_tor'] else 'No'} |",
        f"| Uses VPS/Datacenter | {'Yes' if infra['uses_vps'] else 'No'} |",
        "",
        "## MITRE ATT&CK Coverage",
        "",
        "| ID | Technique | Tactic | Hits | First Seen |",
        "|---|---|---|---|---|",
    ]

    # Group by tactic
    tactic_order = ["Initial Access","Execution","Persistence","Privilege Escalation",
                    "Defense Evasion","Credential Access","Discovery","Lateral Movement",
                    "Collection","Exfiltration","Impact"]
    sorted_techs = sorted(techniques.items(),
                          key=lambda x: tactic_order.index(x[1]["tactic"])
                          if x[1]["tactic"] in tactic_order else 99)
    for tech_id, tech in sorted_techs:
        lines.append(
            f"| {tech_id} | {tech['name']} | {tech['tactic']} | "
            f"{tech['hit_count']} | {tech['first_seen'][:10]} |"
        )

    if dwell_findings:
        lines += [
            "",
            "## Long Dwell Detection Findings",
            "",
            f"| Type | Entity | First Seen | Dwell Days | Confidence |",
            f"|---|---|---|---|---|",
        ]
        for f in dwell_findings[:10]:
            entity = f.get("src_ip") or f.get("user","?")
            lines.append(
                f"| {f['type']} | `{entity}` | {f.get('first_seen','')[:10]} | "
                f"{f.get('dwell_days',0)} | {f.get('confidence','?')} |"
            )

    lines += [
        "",
        "## Strategic Recommendations",
        "",
        "### Immediate (0-24h)",
        "- Block all identified C2 IPs at perimeter and proxy",
        "- Reset credentials for all compromised accounts",
        "- Isolate confirmed compromised hosts",
        "",
        "### Short-term (1-7 days)",
        "- Deploy new detection rules for observed TTPs (see IOCs below)",
        "- Increase logging on: " + (
            "AD authentication, " if "T1110" in techniques else ""
        ) + (
            "endpoint process launch, " if "T1059" in techniques else ""
        ) + "network egress",
        "- Run UEBA baseline refresh for affected users",
        "",
        "### Strategic (1-30 days)",
        "- Schedule purple team exercise simulating observed TTPs",
        "- Review and harden " + (
            "VPN/remote access" if "T1021" in techniques else
            "AD security (tiering model)" if "T1550" in techniques else
            "endpoint protection"
        ),
        "- Share IOCs with sector ISAC / threat intel sharing partners",
        "",
        "## Indicators of Compromise (for detection rules)",
        "",
        "| Type | Value | Context |",
        "|---|---|---|",
    ]
    for ip in infra["c2_ips"][:5]:
        lines.append(f"| IP | `{ip}` | Observed C2 communication |")
    for user in victim["users_compromised"][:3]:
        lines.append(f"| Account | `{user}` | Compromised credential |")

    lines += [
        "",
        "---",
        f"*TLP:AMBER — Share only within your organization and trusted partners.*",
        f"*Report generated: {datetime.now().isoformat()}*",
    ]
    return "\n".join(lines)
```
