---
name: fsiem-threat-report
description: Ingest any threat intelligence report, blog post, or CISA advisory — extract all ATT&CK techniques mentioned, map them to required FortiSIEM data sources, generate hunt queries for each technique, and produce a prioritized action plan. Anton's Day 5 workflow adapted for FortiSIEM. Use when you have a new threat report and want to know if you can detect it and how to hunt for it.
---

# Threat Report → ATT&CK → FortiSIEM Hunt Queries

Anton's Day 5 insight: a threat report should immediately produce actionable defensive work — not just reading material. This skill automates: report → TTPs → data sources → hunt queries → detection gaps.

## Step 1 — Extract TTPs from Report Text

```python
import re
from datetime import datetime

# ATT&CK technique ID patterns
TECHNIQUE_PATTERN = re.compile(r'\bT\d{4}(?:\.\d{3})?\b')

# Technique name → ID mapping for natural language extraction
# When reports say "pass the hash" without citing the ID
TECHNIQUE_NAME_MAP = {
    "pass the hash":          "T1550.002",
    "pass-the-hash":          "T1550.002",
    "pass the ticket":        "T1550.003",
    "kerberoasting":          "T1558.003",
    "as-rep roasting":        "T1558.004",
    "golden ticket":          "T1558.001",
    "silver ticket":          "T1558.002",
    "mimikatz":               "T1003.001",
    "lsass":                  "T1003.001",
    "credential dumping":     "T1003",
    "shadow copy":            "T1490",
    "vssadmin":               "T1490",
    "ransomware":             "T1486",
    "living off the land":    "T1059",
    "lolbins":                "T1059",
    "powershell":             "T1059.001",
    "cobalt strike":          "T1071.001",
    "beacon":                 "T1071",
    "c2":                     "T1071",
    "command and control":    "T1071",
    "lateral movement":       "T1021",
    "rdp":                    "T1021.001",
    "smb":                    "T1021.002",
    "brute force":            "T1110",
    "credential stuffing":    "T1110.004",
    "spearphishing":          "T1566.001",
    "phishing":               "T1566",
    "supply chain":           "T1195",
    "scheduled task":         "T1053.005",
    "persistence":            "T1053",
    "privilege escalation":   "T1055",
    "process injection":      "T1055",
    "defense evasion":        "T1027",
    "obfuscation":            "T1027",
    "exfiltration":           "T1041",
    "data exfiltration":      "T1048",
    "dns tunneling":          "T1071.004",
    "web shell":              "T1505.003",
    "valid accounts":         "T1078",
    "stolen credentials":     "T1078",
    "exploit":                "T1190",
    "zero day":               "T1190",
    "watering hole":          "T1189",
    "drive by":               "T1189",
    "loader":                 "T1059",
    "dropper":                "T1105",
    "ingress tool":           "T1105",
}

def extract_techniques_from_report(report_text: str) -> dict:
    """
    Extract all ATT&CK technique IDs from a threat report.
    Handles both explicit IDs (T1110) and natural language references.

    Returns: {technique_id: {source: "explicit"|"inferred", context: str}}
    """
    found = {}
    text_lower = report_text.lower()

    # 1. Explicit technique IDs
    for match in TECHNIQUE_PATTERN.finditer(report_text):
        tech_id = match.group(0).upper()
        # Get surrounding context (50 chars either side)
        start = max(0, match.start() - 50)
        end   = min(len(report_text), match.end() + 50)
        context = report_text[start:end].strip()
        found[tech_id] = {"source": "explicit", "context": context}

    # 2. Natural language technique names
    for phrase, tech_id in TECHNIQUE_NAME_MAP.items():
        if phrase in text_lower:
            # Find context
            idx = text_lower.find(phrase)
            context = report_text[max(0,idx-30):min(len(report_text),idx+60)].strip()
            if tech_id not in found:
                found[tech_id] = {"source": "inferred", "phrase": phrase, "context": context}

    return found

def extract_iocs_from_report(report_text: str) -> dict:
    """Extract IOCs from report for immediate FortiSIEM hunting."""
    import re
    iocs = {"ips": [], "domains": [], "hashes": [], "urls": []}

    # IPs (exclude private ranges)
    ip_pattern = re.compile(r'\b(?!10\.|192\.168\.|172\.(?:1[6-9]|2\d|3[01])\.)(\d{1,3}\.){3}\d{1,3}\b')
    iocs["ips"] = list(set(ip_pattern.findall(report_text)))

    # Domains
    domain_pattern = re.compile(r'\b(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+(?:com|net|org|io|cc|tk|xyz|ru|cn|eu|biz|info)\b', re.IGNORECASE)
    iocs["domains"] = [d for d in set(domain_pattern.findall(report_text))
                       if len(d) > 6 and "example" not in d][:20]

    # Hashes
    hashes = re.findall(r'\b[0-9a-fA-F]{32}\b|\b[0-9a-fA-F]{40}\b|\b[0-9a-fA-F]{64}\b', report_text)
    iocs["hashes"] = list(set(hashes))[:20]

    return iocs
```

## Step 2 — Map to FortiSIEM Hunt Queries

```python
# FortiSIEM query templates per ATT&CK technique
# These are ready-to-run queries, not just descriptions

TECHNIQUE_HUNT_QUERIES = {
    "T1078": """<Reports><Report><n>T1078 Valid Accounts</n>
      <SelectClause><AttrList>eventTime,user,srcIpAddr,destIpAddr,hostName,rawEventMsg</AttrList></SelectClause>
      <ReportInterval><Window>Last 30 days</Window></ReportInterval>
      <PatternClause><SubPattern><Filters>
        <Filter><n>eventType</n><Operator>IN</Operator><Value>Successful Login,Win-Security-4624,Win-Security-4648</Value></Filter>
      </Filters></SubPattern></PatternClause></Report></Reports>""",

    "T1110": """<Reports><Report><n>T1110 Brute Force</n>
      <SelectClause><AttrList>srcIpAddr,user,COUNT(eventId) AS attempts</AttrList></SelectClause>
      <ReportInterval><Window>Last 24 hours</Window></ReportInterval>
      <PatternClause><SubPattern><Filters>
        <Filter><n>eventType</n><Operator>IN</Operator><Value>Failed Login,Win-Security-4625,Win-Security-4740</Value></Filter>
      </Filters></SubPattern></PatternClause></Report></Reports>""",

    "T1059": """<Reports><Report><n>T1059 Script Execution</n>
      <SelectClause><AttrList>eventTime,processName,user,hostName,rawEventMsg</AttrList></SelectClause>
      <ReportInterval><Window>Last 7 days</Window></ReportInterval>
      <PatternClause><SubPattern><Filters>
        <Filter><n>eventType</n><Operator>IN</Operator><Value>Process Launch,Sysmon-1,Win-Security-4688</Value></Filter>
        <Filter><n>rawEventMsg</n><Operator>REGEXP</Operator><Value>powershell.*(-enc|-e |-nop|-w h)|wscript|cscript|mshta|certutil.*-decode</Value></Filter>
      </Filters></SubPattern></PatternClause></Report></Reports>""",

    "T1003": """<Reports><Report><n>T1003 Credential Dumping</n>
      <SelectClause><AttrList>eventTime,processName,user,hostName,rawEventMsg</AttrList></SelectClause>
      <ReportInterval><Window>Last 7 days</Window></ReportInterval>
      <PatternClause><SubPattern><Filters>
        <Filter><n>rawEventMsg</n><Operator>REGEXP</Operator><Value>lsass|mimikatz|procdump|sekurlsa|hashdump|wce\.exe|fgdump</Value></Filter>
      </Filters></SubPattern></PatternClause></Report></Reports>""",

    "T1486": """<Reports><Report><n>T1486 Ransomware Indicators</n>
      <SelectClause><AttrList>eventTime,processName,user,hostName,rawEventMsg</AttrList></SelectClause>
      <ReportInterval><Window>Last 7 days</Window></ReportInterval>
      <PatternClause><SubPattern><Filters>
        <Filter><n>rawEventMsg</n><Operator>REGEXP</Operator><Value>vssadmin.*delete|wbadmin.*delete|bcdedit.*recover|shadowcopy.*delete</Value></Filter>
      </Filters></SubPattern></PatternClause></Report></Reports>""",

    "T1071": """<Reports><Report><n>T1071 C2 Communication</n>
      <SelectClause><AttrList>srcIpAddr,destIpAddr,destPort,sentBytes,COUNT(eventId) AS connections</AttrList></SelectClause>
      <ReportInterval><Window>Last 7 days</Window></ReportInterval>
      <PatternClause><SubPattern><Filters>
        <Filter><n>eventType</n><Operator>CONTAIN</Operator><Value>Network Connection</Value></Filter>
        <Filter><n>destIpAddr</n><Operator>NOT_IN</Operator><Value>10.0.0.0/8,172.16.0.0/12,192.168.0.0/16</Value></Filter>
      </Filters></SubPattern></PatternClause></Report></Reports>""",

    "T1021": """<Reports><Report><n>T1021 Remote Services</n>
      <SelectClause><AttrList>eventTime,user,srcIpAddr,destIpAddr,hostName,rawEventMsg</AttrList></SelectClause>
      <ReportInterval><Window>Last 7 days</Window></ReportInterval>
      <PatternClause><SubPattern><Filters>
        <Filter><n>eventType</n><Operator>IN</Operator><Value>RDP Login,SSH Login,Win-Security-4624,Remote Login</Value></Filter>
      </Filters></SubPattern></PatternClause></Report></Reports>""",

    "T1558": """<Reports><Report><n>T1558 Kerberoasting</n>
      <SelectClause><AttrList>eventTime,user,srcIpAddr,hostName,rawEventMsg</AttrList></SelectClause>
      <ReportInterval><Window>Last 7 days</Window></ReportInterval>
      <PatternClause><SubPattern><Filters>
        <Filter><n>eventType</n><Operator>IN</Operator><Value>Win-Security-4769,Kerberos-TGS</Value></Filter>
        <Filter><n>rawEventMsg</n><Operator>CONTAIN</Operator><Value>0x17</Value></Filter>
      </Filters></SubPattern></PatternClause></Report></Reports>""",

    "T1041": """<Reports><Report><n>T1041 Exfiltration</n>
      <SelectClause><AttrList>srcIpAddr,destIpAddr,SUM(sentBytes) AS total_bytes</AttrList></SelectClause>
      <ReportInterval><Window>Last 7 days</Window></ReportInterval>
      <PatternClause><SubPattern><Filters>
        <Filter><n>sentBytes</n><Operator>&gt;=</Operator><Value>10485760</Value></Filter>
        <Filter><n>destIpAddr</n><Operator>NOT_IN</Operator><Value>10.0.0.0/8,172.16.0.0/12,192.168.0.0/16</Value></Filter>
      </Filters></SubPattern></PatternClause></Report></Reports>""",
}

def generate_hunt_pack(report_text: str) -> dict:
    """
    Full workflow: report text → hunt pack with queries + IOC list + action plan.
    """
    techniques = extract_techniques_from_report(report_text)
    iocs = extract_iocs_from_report(report_text)

    hunt_pack = {
        "generated": datetime.now().isoformat(),
        "techniques_found": len(techniques),
        "iocs_found": sum(len(v) for v in iocs.values()),
        "techniques": {},
        "immediate_queries": [],
        "iocs": iocs,
        "data_gaps": [],
    }

    for tech_id, info in techniques.items():
        # Get query if available
        base_id = tech_id.split(".")[0]
        query = TECHNIQUE_HUNT_QUERIES.get(tech_id) or TECHNIQUE_HUNT_QUERIES.get(base_id)

        # Get data source info
        # Import ATTACK_DATASOURCE_MAP from skills/attack_datasources/SKILL.md
        ds_info = ATTACK_DATASOURCE_MAP.get(base_id, {})

        hunt_pack["techniques"][tech_id] = {
            "name": ds_info.get("name", tech_id),
            "source": info["source"],
            "has_query": query is not None,
            "query": query,
            "priority": ds_info.get("priority", "MEDIUM"),
        }

        if query:
            hunt_pack["immediate_queries"].append({
                "technique": tech_id,
                "query": query,
                "priority": ds_info.get("priority", "MEDIUM"),
            })
        else:
            hunt_pack["data_gaps"].append(tech_id)

    # Sort immediate queries by priority
    priority_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    hunt_pack["immediate_queries"].sort(
        key=lambda x: priority_order.get(x["priority"], 9)
    )

    return hunt_pack
```

## Step 3 — Full Report

```python
def threat_report_to_action_plan(report_text: str, report_name: str = "Threat Report") -> str:
    """
    The complete workflow output:
    - Techniques extracted
    - Coverage assessment
    - Immediate hunt queries
    - IOC list for watchlist
    - Detection gaps (what you can't detect because data is missing)
    """
    techniques = extract_techniques_from_report(report_text)
    iocs = extract_iocs_from_report(report_text)

    lines = [
        f"# Threat Report Action Plan: {report_name}",
        f"**Generated**: {datetime.now().strftime('%Y-%m-%d %H:%M')}",
        f"**Techniques found**: {len(techniques)} | **IOCs**: {sum(len(v) for v in iocs.values())}",
        "",
        "## ATT&CK Techniques Identified",
        "",
        "| ID | Name | Source | Has Query | Priority |",
        "|---|---|---|---|---|",
    ]

    # Import ATTACK_DATASOURCE_MAP from skills/attack_datasources/SKILL.md

    for tech_id, info in sorted(techniques.items()):
        base_id = tech_id.split(".")[0]
        ds_info = ATTACK_DATASOURCE_MAP.get(base_id, {})
        name = ds_info.get("name", "—")
        has_query = "✅" if (tech_id in TECHNIQUE_HUNT_QUERIES or base_id in TECHNIQUE_HUNT_QUERIES) else "❌"
        priority = ds_info.get("priority", "?")
        source_tag = "📌" if info["source"] == "explicit" else "🔍"
        lines.append(f"| {source_tag} {tech_id} | {name} | {info['source']} | {has_query} | {priority} |")

    lines += ["", "📌 = explicit technique ID in report  🔍 = inferred from keywords", ""]

    # Immediate actions
    lines += ["## ⚡ Immediate Hunt Queries (run these now)", ""]
    for tech_id, info in techniques.items():
        base_id = tech_id.split(".")[0]
        query = TECHNIQUE_HUNT_QUERIES.get(tech_id) or TECHNIQUE_HUNT_QUERIES.get(base_id)
        if query:
            ds_info = ATTACK_DATASOURCE_MAP.get(base_id, {})
            lines += [
                f"### {tech_id} — {ds_info.get('name', tech_id)}",
                f"~~~xml",
                query.strip(),
                "~~~",
                "",
            ]

    # IOCs
    if any(iocs.values()):
        lines += ["## 🎯 IOCs for FortiSIEM Watchlist", ""]
        if iocs["ips"]:
            lines.append(f"**IPs** ({len(iocs['ips'])}): `{'`, `'.join(iocs['ips'][:10])}`")
        if iocs["domains"]:
            lines.append(f"**Domains** ({len(iocs['domains'])}): `{'`, `'.join(iocs['domains'][:10])}`")
        if iocs["hashes"]:
            lines.append(f"**Hashes** ({len(iocs['hashes'])}): `{'`, `'.join(iocs['hashes'][:5])}`")
        lines += ["", "Add to FortiSIEM watchlist via `/fsiem-ioc`", ""]

    lines += [
        "## 🔧 Next Steps",
        "1. Run all hunt queries above — prioritize CRITICAL first",
        "2. Add IOCs to FortiSIEM watchlist: `/fsiem-ioc`",
        "3. For any technique without a query: `/fsiem-attack-datasources` to check if data is present",
        "4. Convert hunt findings to detection rules: `/fsiem-rule-create`",
    ]
    return "\n".join(lines)
```

## Usage

```python
# Paste any threat report text
report = """
APT29 was observed using T1078 valid accounts obtained via T1566 spearphishing.
The group used PowerShell and scheduled tasks for persistence.
C2 communication used HTTPS beaconing. Indicators include:
IP: 185.220.101.45, domain: update.microsoftcdn.net
Hash: a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4
"""

# Get full action plan
plan = threat_report_to_action_plan(report, "APT29 Campaign Report")
print(plan)

# Or just get the hunt pack for programmatic use
pack = generate_hunt_pack(report)
print(f"Found {pack['techniques_found']} techniques, {len(pack['immediate_queries'])} have queries")
```
