---
name: fsiem-coverage-gap
description: Analyze FortiSIEM correlation rule coverage against MITRE ATT&CK. Identifies which techniques have no active detection rules, which are covered, and generates a prioritized gap report for the detection engineering backlog. Use when asked about detection coverage, ATT&CK gaps, or what rules are missing.
---

# MITRE ATT&CK Coverage Gap Analysis

Maps your active FortiSIEM rules against the MITRE ATT&CK framework to show exactly what you can and cannot detect. Produces a prioritized backlog for `fsiem-rule-engineer`.

## Step 1 — Get All Active Rules

```python
import os, base64, requests, xml.etree.ElementTree as ET, re
from datetime import datetime

def fsiem_headers():
    user, org, pw = os.environ["FSIEM_USER"], os.environ["FSIEM_ORG"], os.environ["FSIEM_PASS"]
    return {"Authorization": f"Basic {base64.b64encode(f'{user}/{org}:{pw}'.encode()).decode()}",
            "Content-Type": "text/xml"}

def fsiem_verify_ssl():
    return os.environ.get("FSIEM_VERIFY_SSL", "false").lower() == "true"

def get_active_rules() -> list:
    """
    Get all enabled correlation rules from FortiSIEM.
    Returns list of rules with name, description, and any MITRE tags.
    """
    host = os.environ["FSIEM_HOST"]
    resp = requests.get(
        f"{host}/phoenix/rest/rules",
        headers=fsiem_headers(), verify=fsiem_verify_ssl(), timeout=30
    )
    resp.raise_for_status()
    root = ET.fromstring(resp.text)
    rules = []
    for r in root.findall(".//rule"):
        enabled = r.findtext("active") or r.findtext("enabled") or r.findtext("status") or ""
        if enabled.lower() in ("false", "disabled", "inactive"):
            continue
        name = r.findtext("name") or r.findtext("n") or ""
        desc = r.findtext("description") or r.findtext("desc") or ""
        # Some FortiSIEM versions embed MITRE tags in rule notes/description
        mitre_tags = re.findall(r'T\d{4}(?:\.\d{3})?', name + " " + desc)
        rules.append({
            "id":          r.findtext("id") or "",
            "name":        name,
            "description": desc,
            "severity":    r.findtext("severity") or r.findtext("eventSeverity") or "",
            "category":    r.findtext("category") or "",
            "mitre_tags":  list(set(mitre_tags)),
        })
    return rules
```

## Step 2 — Technique Coverage Map

```python
# The full detection-relevant ATT&CK technique library
# Grouped by priority for a typical enterprise SOC
ATTACK_COVERAGE_REQUIREMENTS = {
    # ── CRITICAL — must have detection ──────────────────────────────────
    "T1486": {"name": "Data Encrypted for Impact (Ransomware)", "tactic": "Impact",
              "priority": "CRITICAL", "keywords": ["shadow copy","vssadmin","ransomware","wbadmin delete","bcdedit"]},
    "T1078": {"name": "Valid Accounts", "tactic": "Initial Access / Persistence",
              "priority": "CRITICAL", "keywords": ["successful login","account logon","authentication success"]},
    "T1110": {"name": "Brute Force", "tactic": "Credential Access",
              "priority": "CRITICAL", "keywords": ["failed login","authentication failure","brute force","lockout"]},
    "T1059": {"name": "Command and Scripting Interpreter", "tactic": "Execution",
              "priority": "CRITICAL", "keywords": ["powershell","cmd","wscript","cscript","bash","encoded command"]},
    "T1003": {"name": "OS Credential Dumping", "tactic": "Credential Access",
              "priority": "CRITICAL", "keywords": ["lsass","mimikatz","procdump","hashdump","sekurlsa"]},
    "T1190": {"name": "Exploit Public-Facing Application", "tactic": "Initial Access",
              "priority": "CRITICAL", "keywords": ["web attack","sql injection","rce","exploit","web shell"]},
    # ── HIGH ────────────────────────────────────────────────────────────
    "T1021": {"name": "Remote Services", "tactic": "Lateral Movement",
              "priority": "HIGH", "keywords": ["rdp","ssh","smb","remote login","lateral"]},
    "T1053": {"name": "Scheduled Task/Job", "tactic": "Persistence",
              "priority": "HIGH", "keywords": ["schtasks","scheduled task","cron","at.exe"]},
    "T1055": {"name": "Process Injection", "tactic": "Defense Evasion",
              "priority": "HIGH", "keywords": ["process inject","dll inject","hollowing","reflective"]},
    "T1071": {"name": "Application Layer Protocol (C2)", "tactic": "Command and Control",
              "priority": "HIGH", "keywords": ["c2","beacon","command and control","suspicious outbound"]},
    "T1566": {"name": "Phishing", "tactic": "Initial Access",
              "priority": "HIGH", "keywords": ["phishing","malicious attachment","email","suspicious email"]},
    "T1041": {"name": "Exfiltration Over C2 Channel", "tactic": "Exfiltration",
              "priority": "HIGH", "keywords": ["exfiltration","data theft","large upload","outbound data"]},
    "T1136": {"name": "Create Account", "tactic": "Persistence",
              "priority": "HIGH", "keywords": ["account created","new user","useradd","net user /add"]},
    "T1562": {"name": "Impair Defenses", "tactic": "Defense Evasion",
              "priority": "HIGH", "keywords": ["antivirus disabled","defender stopped","audit disabled","log cleared"]},
    # ── MEDIUM ──────────────────────────────────────────────────────────
    "T1046": {"name": "Network Service Scanning", "tactic": "Discovery",
              "priority": "MEDIUM", "keywords": ["port scan","nmap","network scan","service discovery"]},
    "T1082": {"name": "System Information Discovery", "tactic": "Discovery",
              "priority": "MEDIUM", "keywords": ["systeminfo","whoami","hostname","ipconfig","uname"]},
    "T1547": {"name": "Boot/Logon Autostart Execution", "tactic": "Persistence",
              "priority": "MEDIUM", "keywords": ["registry run","autostart","startup","autorun"]},
    "T1027": {"name": "Obfuscated Files or Information", "tactic": "Defense Evasion",
              "priority": "MEDIUM", "keywords": ["base64","encoded","obfuscat","frombase64string"]},
    "T1550": {"name": "Pass the Hash/Ticket", "tactic": "Lateral Movement",
              "priority": "MEDIUM", "keywords": ["pass the hash","pass the ticket","overpass","pth"]},
    "T1074": {"name": "Data Staged", "tactic": "Collection",
              "priority": "MEDIUM", "keywords": ["data staged","archive","zip","rar","7z","compress"]},
    "T1087": {"name": "Account Discovery", "tactic": "Discovery",
              "priority": "MEDIUM", "keywords": ["net user","net group","get-aduser","ldapsearch","account enum"]},
    "T1048": {"name": "Exfiltration Over Alternative Protocol", "tactic": "Exfiltration",
              "priority": "MEDIUM", "keywords": ["dns tunnel","ftp upload","icmp tunnel","covert channel"]},
    "T1558": {"name": "Steal/Forge Kerberos Tickets", "tactic": "Credential Access",
              "priority": "MEDIUM", "keywords": ["kerberoast","asreproast","kerberos ticket","tgs request"]},
    # ── LOWER PRIORITY ──────────────────────────────────────────────────
    "T1490": {"name": "Inhibit System Recovery", "tactic": "Impact",
              "priority": "HIGH", "keywords": ["vssadmin","wbadmin","backup deleted","recovery disabled"]},
    "T1489": {"name": "Service Stop", "tactic": "Impact",
              "priority": "MEDIUM", "keywords": ["service stopped","net stop","sc stop","service disabled"]},
}

def map_rules_to_techniques(rules: list) -> dict:
    """
    Map each ATT&CK technique to any rules that cover it.
    Uses keyword matching against rule names + descriptions since most
    FortiSIEM deployments don't have formal MITRE tags on rules.
    """
    coverage = {}
    for tech_id, tech in ATTACK_COVERAGE_REQUIREMENTS.items():
        covering_rules = []
        for rule in rules:
            searchable = (rule["name"] + " " + rule["description"]).lower()
            # Check explicit MITRE tags first
            if tech_id in rule["mitre_tags"]:
                covering_rules.append(rule)
                continue
            # Fall back to keyword matching
            if any(kw.lower() in searchable for kw in tech["keywords"]):
                covering_rules.append(rule)

        coverage[tech_id] = {
            **tech,
            "covered":       len(covering_rules) > 0,
            "rule_count":    len(covering_rules),
            "covering_rules": [r["name"] for r in covering_rules[:3]],
        }
    return coverage
```

## Step 3 — Generate Gap Report

```python
def generate_coverage_gap_report(
    include_covered: bool = False,
) -> str:
    """
    Generate the full ATT&CK coverage gap report.
    This is what you hand to the CISO and the detection engineering team.
    """
    rules = get_active_rules()
    coverage = map_rules_to_techniques(rules)

    covered   = {k: v for k, v in coverage.items() if v["covered"]}
    gaps      = {k: v for k, v in coverage.items() if not v["covered"]}
    crit_gaps = {k: v for k, v in gaps.items() if v["priority"] == "CRITICAL"}
    high_gaps = {k: v for k, v in gaps.items() if v["priority"] == "HIGH"}
    med_gaps  = {k: v for k, v in gaps.items() if v["priority"] == "MEDIUM"}

    coverage_pct = round(len(covered) / len(coverage) * 100, 1) if coverage else 0
    total = len(coverage)

    lines = [
        "# MITRE ATT&CK Coverage Gap Report",
        f"**Generated**: {datetime.now().strftime('%Y-%m-%d %H:%M')}",
        f"**Active Rules Analyzed**: {len(rules)}",
        f"**Techniques Checked**: {total}",
        "",
        "## Coverage Summary",
        "",
        f"| | Count | % |",
        f"|---|---|---|",
        f"| ✅ Covered | {len(covered)} | {coverage_pct}% |",
        f"| ❌ Gaps | {len(gaps)} | {round(100-coverage_pct,1)}% |",
        f"| 🔴 Critical gaps | {len(crit_gaps)} | — |",
        f"| 🟠 High gaps | {len(high_gaps)} | — |",
        f"| 🟡 Medium gaps | {len(med_gaps)} | — |",
        "",
    ]

    if crit_gaps:
        lines += [
            "## 🔴 Critical Gaps — Build These Rules First",
            "",
            "| Technique | Name | Tactic | Keywords to Hunt |",
            "|---|---|---|---|",
        ]
        for tech_id, tech in crit_gaps.items():
            kws = ", ".join(tech["keywords"][:3])
            lines.append(f"| [{tech_id}](https://attack.mitre.org/techniques/{tech_id.replace('.','/')}) "
                         f"| {tech['name']} | {tech['tactic']} | `{kws}` |")

    if high_gaps:
        lines += [
            "",
            "## 🟠 High Priority Gaps",
            "",
            "| Technique | Name | Tactic |",
            "|---|---|---|",
        ]
        for tech_id, tech in high_gaps.items():
            lines.append(f"| [{tech_id}](https://attack.mitre.org/techniques/{tech_id.replace('.','/')}) "
                         f"| {tech['name']} | {tech['tactic']} |")

    if med_gaps:
        lines += [
            "",
            "## 🟡 Medium Priority Gaps",
            "",
            "| Technique | Name | Tactic |",
            "|---|---|---|",
        ]
        for tech_id, tech in med_gaps.items():
            lines.append(f"| {tech_id} | {tech['name']} | {tech['tactic']} |")

    if include_covered and covered:
        lines += [
            "",
            "## ✅ Covered Techniques",
            "",
            "| Technique | Name | Rules Covering |",
            "|---|---|---|",
        ]
        for tech_id, tech in covered.items():
            lines.append(f"| {tech_id} | {tech['name']} | {', '.join(tech['covering_rules'][:2])} |")

    lines += [
        "",
        "## Detection Engineering Backlog (Priority Order)",
        "",
        "Use `/fsiem-rule-create` to build rules for each gap, starting from 🔴 Critical.",
        "",
    ]
    priority_order = [("🔴 CRITICAL", crit_gaps), ("🟠 HIGH", high_gaps), ("🟡 MEDIUM", med_gaps)]
    i = 1
    for label, gap_dict in priority_order:
        for tech_id, tech in gap_dict.items():
            kws = " | ".join(tech["keywords"][:2])
            lines.append(f"{i}. **{label}** `{tech_id}` {tech['name']} — Keywords: `{kws}`")
            i += 1

    return "\n".join(lines)
```

## Quick Coverage Score

```python
def coverage_score() -> dict:
    """Quick coverage score — useful for dashboard KPI."""
    rules = get_active_rules()
    coverage = map_rules_to_techniques(rules)
    covered = sum(1 for v in coverage.values() if v["covered"])
    crit_covered = sum(1 for v in coverage.values()
                       if v["covered"] and v["priority"] == "CRITICAL")
    crit_total = sum(1 for v in coverage.values() if v["priority"] == "CRITICAL")

    return {
        "overall_pct":        round(covered / len(coverage) * 100, 1),
        "critical_coverage":  f"{crit_covered}/{crit_total}",
        "critical_pct":       round(crit_covered / crit_total * 100, 1) if crit_total else 0,
        "total_active_rules": len(rules),
        "techniques_checked": len(coverage),
        "gaps":               len(coverage) - covered,
        "grade": ("A" if covered/len(coverage) > 0.85 else
                  "B" if covered/len(coverage) > 0.70 else
                  "C" if covered/len(coverage) > 0.50 else "D"),
    }
```
