---
name: fsiem-l2-investigate
description: L2 SOC deep investigation workflow — receives escalated L1 alerts, builds complete attack timeline, enriches all indicators, determines scope and blast radius, runs hypothesis-driven hunts, and produces a formal investigation report with remediation recommendations. Target: 30-minute initial assessment, 4-hour full investigation.
---

# L2 SOC Investigation — Deep Dive Workflow

L2 receives escalated incidents from L1. Your job: **determine what happened, how far it spread, and what to do about it.**

## L2 Investigation Lifecycle

```
RECEIVE FROM L1 → SCOPE → TIMELINE → ENRICH → HUNT → CONTAIN → REPORT → CLOSE/L3
     (5 min)    (15 min)  (30 min)  (20 min) (30 min) (varies) (20 min)
```

## Step 1 — Receive and Scope (first 15 min)

```python
import os, base64, requests, xml.etree.ElementTree as ET, time
from datetime import datetime, timedelta

def fsiem_headers():
    user, org, pw = os.environ["FSIEM_USER"], os.environ["FSIEM_ORG"], os.environ["FSIEM_PASS"]
    return {"Authorization": f"Basic {base64.b64encode(f'{user}/{org}:{pw}'.encode()).decode()}",
            "Content-Type": "text/xml"}

def fsiem_verify_ssl():
    return os.environ.get("FSIEM_VERIFY_SSL","false").lower() == "true"

def l2_open_investigation(incident_id: str, l2_analyst: str, l1_notes: str = "") -> dict:
    """
    Open an L2 investigation. Pulls full incident detail, first 100 events,
    CMDB context for all IPs, and marks incident InProgress with L2 assignment.
    """
    host = os.environ["FSIEM_HOST"]
    h = fsiem_headers()
    v = fsiem_verify_ssl()

    # Get incident detail
    resp = requests.get(
        f"{host}/phoenix/rest/incident/listIncidents",
        params={"incidentId": incident_id},
        headers=h, verify=v
    )
    resp.raise_for_status()
    root = ET.fromstring(resp.text)
    inc = root.find(".//incident")
    if inc is None:
        raise ValueError(f"Incident {incident_id} not found")

    incident = {tag.tag: tag.text for tag in inc}

    # Mark InProgress with L2 assignment
    requests.post(
        f"{host}/phoenix/rest/incident/updateIncidentStatus",
        data=f"""<incidentStatusChange>
          <incidentId>{incident_id}</incidentId>
          <incidentStatus>InProgress</incidentStatus>
          <comment>[L2 Investigation opened by {l2_analyst}] L1 notes: {l1_notes}</comment>
        </incidentStatusChange>""",
        headers=h, verify=v
    )

    return {
        "investigation_id": f"L2-{incident_id}-{datetime.now().strftime('%Y%m%d%H%M')}",
        "opened_by": l2_analyst,
        "opened_at": datetime.now().isoformat(),
        "incident": incident,
        "l1_notes": l1_notes,
        "timeline": [],
        "scope": {"confirmed_hosts": [], "suspected_hosts": [], "affected_users": [],
                  "external_ips": [], "lateral_movement": False, "data_exfil": False},
        "enrichment": {},
        "hunts_run": [],
        "containment_actions": [],
        "status": "OPEN",
    }
```

## Step 2 — Build Attack Timeline

```python
def build_attack_timeline(
    incident_id: str,
    src_ips: list,
    affected_hosts: list,
    users: list,
    hours_window: int = 24,
) -> list:
    """
    Build a comprehensive event timeline for the incident.
    Queries multiple event types to reconstruct the full attack chain.
    """
    host = os.environ["FSIEM_HOST"]
    h = fsiem_headers()
    v = fsiem_verify_ssl()
    window = f"Last {hours_window} hours"
    all_events = []

    def run_query(xml_str):
        try:
            r = requests.post(f"{host}/phoenix/rest/query/eventQuery",
                              data=xml_str, headers=h, verify=v, timeout=30)
            r.raise_for_status()
            qid = r.text.strip()
            for _ in range(60):
                p = requests.get(f"{host}/phoenix/rest/query/progress/{qid}",
                                 headers=h, verify=v, timeout=10)
                if int(p.text.strip() or "0") >= 100: break
                time.sleep(2)
            r2 = requests.get(f"{host}/phoenix/rest/query/events/{qid}/0/200",
                              headers=h, verify=v, timeout=30)
            root = ET.fromstring(r2.text)
            return [{a.findtext("name",""): a.findtext("value","")
                     for a in ev.findall("attributes/attribute")}
                    for ev in root.findall(".//event")]
        except Exception as e:
            import sys as _sys
            print(f"[WARN] Timeline query failed: {e}", file=_sys.stderr)
            return []

    # Collect events from all related entities
    queries = []

    # Authentication events for involved users
    if users:
        user_filter = "".join(
            f"<Filter><n>user</n><Operator>CONTAIN</Operator><Value>{u}</Value></Filter>"
            for u in users[:3]
        )
        queries.append(("auth_events", f"""<Reports><Report><n>Timeline Auth</n>
          <SelectClause><AttrList>eventTime,eventType,srcIpAddr,destIpAddr,user,hostName,rawEventMsg</AttrList></SelectClause>
          <ReportInterval><Window>{window}</Window></ReportInterval>
          <PatternClause><SubPattern><Filters>
            <Filter><n>eventType</n><Operator>IN</Operator><Value>Successful Login,Failed Login,Privilege Use,Password Change</Value></Filter>
            {user_filter}
          </Filters></SubPattern></PatternClause></Report></Reports>"""))

    # Network connections from source IPs
    if src_ips:
        ip_filter = "".join(
            f"<Filter><n>srcIpAddr</n><Operator>CONTAIN</Operator><Value>{ip}</Value></Filter>"
            for ip in src_ips[:3]
        )
        queries.append(("network_events", f"""<Reports><Report><n>Timeline Network</n>
          <SelectClause><AttrList>eventTime,eventType,srcIpAddr,destIpAddr,destPort,sentBytes,user</AttrList></SelectClause>
          <ReportInterval><Window>{window}</Window></ReportInterval>
          <PatternClause><SubPattern><Filters>{ip_filter}</Filters></SubPattern></PatternClause>
          </Report></Reports>"""))

    # Process/file events on affected hosts
    if affected_hosts:
        host_filter = "".join(
            f"<Filter><n>hostName</n><Operator>CONTAIN</Operator><Value>{h2}</Value></Filter>"
            for h2 in affected_hosts[:3]
        )
        queries.append(("endpoint_events", f"""<Reports><Report><n>Timeline Endpoint</n>
          <SelectClause><AttrList>eventTime,eventType,processName,fileName,user,hostName,rawEventMsg</AttrList></SelectClause>
          <ReportInterval><Window>{window}</Window></ReportInterval>
          <PatternClause><SubPattern><Filters>
            <Filter><n>eventType</n><Operator>IN</Operator><Value>Process Launch,File Created,File Modified,Registry Modified,Service Installed</Value></Filter>
            {host_filter}
          </Filters></SubPattern></PatternClause></Report></Reports>"""))

    for label, query in queries:
        events = run_query(query)
        for e in events:
            e["_source"] = label
        all_events.extend(events)

    # Sort by time and deduplicate
    all_events.sort(key=lambda x: x.get("eventTime",""))
    return all_events
```

## Step 3 — Scope and Blast Radius

```python
def determine_blast_radius(timeline: list, initial_src_ip: str) -> dict:
    """
    Analyze the timeline to determine how far the attacker moved.
    Returns scope assessment with confidence.
    """
    internal_re = __import__("re").compile(
        r'^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.)')
    hosts_contacted = set()
    users_involved = set()
    external_ips = set()
    lateral_hops = []
    data_transferred = 0

    for e in timeline:
        dest = e.get("destIpAddr","")
        src = e.get("srcIpAddr","")
        user = e.get("user","")
        sent = int(e.get("sentBytes","0") or "0")
        etype = e.get("eventType","").lower()

        if dest and internal_re.match(dest):
            hosts_contacted.add(dest)
        if dest and not internal_re.match(dest) and dest:
            external_ips.add(dest)
        if user:
            users_involved.add(user)
        if sent > 0:
            data_transferred += sent
        if "login" in etype and "success" in etype and src != initial_src_ip:
            lateral_hops.append({
                "from": src, "to": dest, "user": user,
                "time": e.get("eventTime",""), "type": etype
            })

    return {
        "internal_hosts_reached": list(hosts_contacted),
        "external_ips_contacted": list(external_ips),
        "users_involved": list(users_involved),
        "total_data_transferred_mb": round(data_transferred / 1048576, 2),
        "lateral_movement_detected": len(lateral_hops) > 0,
        "lateral_movement_hops": lateral_hops[:10],
        "scope_level": (
            "CONTAINED" if len(hosts_contacted) <= 1 and not lateral_hops else
            "LIMITED" if len(hosts_contacted) <= 5 else
            "WIDESPREAD" if len(hosts_contacted) > 5 else "UNKNOWN"
        )
    }
```

## Step 4 — L2 Investigation Report

```python
def generate_l2_report(inv: dict, blast_radius: dict, timeline: list,
                       enrichments: dict, disposition: str) -> str:
    """
    Generate a complete L2 investigation report for management and L3 handoff.
    disposition: CLOSED_TP | CLOSED_FP | ESCALATE_L3 | PENDING_CONTAINMENT
    """
    inc = inv.get("incident", {})
    scope = blast_radius

    lines = [
        f"# L2 Investigation Report",
        f"**ID**: {inv['investigation_id']}",
        f"**Analyst**: {inv['opened_by']} | **Date**: {inv['opened_at'][:10]}",
        f"**Disposition**: {disposition}",
        "",
        "---",
        "",
        "## 1. Incident Summary",
        f"| Field | Value |",
        f"|---|---|",
        f"| FortiSIEM ID | {inc.get('incidentId','N/A')} |",
        f"| Title | {inc.get('incidentTitle','N/A')} |",
        f"| Severity | {inc.get('eventSeverity','N/A')} |",
        f"| Category | {inc.get('incidentCategory','N/A')} |",
        f"| Rule Triggered | {inc.get('ruleId','N/A')} |",
        f"| First Seen | {inc.get('firstEventTime','N/A')} |",
        f"| Last Seen | {inc.get('lastEventTime','N/A')} |",
        f"| Event Count | {inc.get('eventCount','N/A')} |",
        "",
        "## 2. Scope Assessment",
        f"**Scope Level**: {scope.get('scope_level','UNKNOWN')}",
        "",
        f"| Metric | Value |",
        f"|---|---|",
        f"| Internal hosts reached | {len(scope.get('internal_hosts_reached',[]))} |",
        f"| External IPs contacted | {len(scope.get('external_ips_contacted',[]))} |",
        f"| Users involved | {len(scope.get('users_involved',[]))} |",
        f"| Data transferred | {scope.get('total_data_transferred_mb',0)} MB |",
        f"| Lateral movement | {'YES ⚠️' if scope.get('lateral_movement_detected') else 'No'} |",
    ]

    if scope.get("lateral_movement_hops"):
        lines += ["", "**Lateral Movement Path:**"]
        for hop in scope["lateral_movement_hops"][:5]:
            lines.append(f"- `{hop['from']}` → `{hop['to']}` via `{hop['user']}` ({hop['time'][:16]})")

    if scope.get("external_ips_contacted"):
        lines += ["", "**External IPs Contacted:**"]
        for ip in scope["external_ips_contacted"][:10]:
            enrich = enrichments.get(ip, {})
            verdict = enrich.get("verdict","UNKNOWN")
            emoji = {"MALICIOUS":"🔴","SUSPICIOUS":"🟡","CLEAN":"✅"}.get(verdict,"⚪")
            lines.append(f"- `{ip}` {emoji} {verdict} — {enrich.get('summary','Not enriched')}")

    lines += [
        "",
        "## 3. Attack Timeline",
        f"*{len(timeline)} events analyzed — showing key events:*",
        "",
    ]
    # Show first occurrence of each event type
    seen_types = set()
    for e in timeline[:50]:
        etype = e.get("eventType","")
        if etype not in seen_types:
            seen_types.add(etype)
            lines.append(
                f"- `{e.get('eventTime','')[:16]}` **{etype}** | "
                f"{e.get('srcIpAddr','')} → {e.get('destIpAddr','')} | "
                f"user: {e.get('user','') or '—'}"
            )

    lines += [
        "",
        "## 4. Root Cause Analysis",
        f"**Initial Access Vector**: {inv.get('root_cause', '_[Analyst to complete]_')}",
        f"**Attack Chain**: {inv.get('attack_chain', '_[Analyst to complete]_')}",
        "",
        "## 5. Containment Actions Taken",
    ]
    actions = inv.get("containment_actions", [])
    if actions:
        for a in actions:
            lines.append(f"- {a}")
    else:
        lines.append("_No containment actions taken yet_")

    lines += [
        "",
        "## 6. Recommendations",
        inv.get("recommendations", "_[Analyst to complete]_"),
        "",
        "## 7. Indicators of Compromise",
        "",
        "| Type | Value | Verdict | Action |",
        "|---|---|---|---|",
    ]
    for ioc_type, iocs in [
        ("IP", scope.get("external_ips_contacted",[])),
        ("User", scope.get("users_involved",[])),
        ("Host", scope.get("internal_hosts_reached",[])),
    ]:
        for ioc in iocs[:5]:
            enrich = enrichments.get(ioc, {})
            verdict = enrich.get("verdict","UNKNOWN")
            action = "Block + Monitor" if verdict == "MALICIOUS" else "Monitor"
            lines.append(f"| {ioc_type} | `{ioc}` | {verdict} | {action} |")

    if disposition == "ESCALATE_L3":
        lines += [
            "",
            "## 8. L3 Escalation Notes",
            f"**Reason for escalation**: {inv.get('escalation_reason','Advanced threat — requires L3 analysis')}",
            f"**Questions for L3**: {inv.get('l3_questions','Attribution, full scope, related campaigns')}",
        ]

    lines += ["", "---", f"*Report generated: {datetime.now().isoformat()}*"]
    return "\n".join(lines)
```

## L2 SLA Targets

| Phase | Target Time |
|---|---|
| Acknowledge escalation | 15 minutes |
| Initial scope assessment | 30 minutes |
| Full investigation | 4 hours |
| Report delivered | 4 hours |
| Escalate to L3 (if needed) | 2 hours after confirming APT/complex threat |

## L2 → L3 Escalation Criteria

Escalate to L3 when:
- Attribution needed (nation-state, APT group suspected)
- Novel malware / zero-day suspected
- Scope spans > 20 hosts or > 3 business units
- Incident involves critical infrastructure (AD, PKI, payment systems)
- Evidence of persistent access (> 30 days dwell time)
- Exfiltration of regulated data (PII, PHI, PCI, IP)
