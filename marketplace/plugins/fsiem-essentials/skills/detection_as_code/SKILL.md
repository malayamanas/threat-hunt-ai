---
name: fsiem-detection-as-code
description: Detection-as-code workflow for FortiSIEM — export all active rules to XML files, track FP rates and review dates, manage rules via version control, and generate a rule catalog with ATT&CK mappings. Use for Day 41 detection engineering maturity — rules as versioned artifacts, not undocumented SIEM configuration.
---

# Detection as Code

Rules in your SIEM should be treated like code: versioned, reviewed, owned, and tested. This skill exports FortiSIEM rules to files and maintains a catalog.

## Export Rules to Version Control

```python
import os, base64, requests, xml.etree.ElementTree as ET, json, re
from datetime import datetime

def fsiem_headers():
    user, org, pw = os.environ["FSIEM_USER"], os.environ["FSIEM_ORG"], os.environ["FSIEM_PASS"]
    return {"Authorization": f"Basic {base64.b64encode(f'{user}/{org}:{pw}'.encode()).decode()}",
            "Content-Type": "text/xml"}

def fsiem_verify_ssl():
    return os.environ.get("FSIEM_VERIFY_SSL","false").lower() == "true"

def export_rules_to_files(
    output_dir: str = "./rules",
    include_disabled: bool = False,
) -> dict:
    """
    Export all FortiSIEM correlation rules to individual XML files.
    Also creates a rules/catalog.json with metadata.

    Directory structure:
      rules/
        catalog.json          — metadata for all rules
        active/               — enabled rules
          T1110_brute_force.xml
          T1059_powershell.xml
        disabled/             — disabled rules (if include_disabled=True)
    """
    os.makedirs(f"{output_dir}/active", exist_ok=True)
    if include_disabled:
        os.makedirs(f"{output_dir}/disabled", exist_ok=True)

    host = os.environ["FSIEM_HOST"]
    resp = requests.get(
        f"{host}/phoenix/rest/rules",
        headers=fsiem_headers(), verify=fsiem_verify_ssl(), timeout=30
    )
    resp.raise_for_status()
    root = ET.fromstring(resp.text)

    catalog = {"exported_at": datetime.now().isoformat(), "rules": []}
    exported = 0

    for rule in root.findall(".//rule"):
        rule_id   = rule.findtext("id") or rule.findtext("ruleId") or ""
        rule_name = rule.findtext("name") or rule.findtext("n") or ""
        enabled   = (rule.findtext("active") or rule.findtext("enabled") or "true").lower()
        severity  = rule.findtext("severity") or rule.findtext("eventSeverity") or ""
        category  = rule.findtext("category") or ""
        desc      = rule.findtext("description") or ""

        if enabled == "false" and not include_disabled:
            continue

        # Detect ATT&CK technique from rule name or description
        techniques = re.findall(r'T\d{4}(?:\.\d{3})?', rule_name + " " + desc)

        # Safe filename from rule name
        safe_name = re.sub(r'[^a-zA-Z0-9_\-]', '_', rule_name)[:60]
        if techniques:
            safe_name = f"{techniques[0]}_{safe_name}"
        filename = f"{safe_name}.xml"

        subdir = "active" if enabled != "false" else "disabled"
        filepath = os.path.join(output_dir, subdir, filename)

        # Write rule XML with metadata header
        rule_xml = ET.tostring(rule, encoding="unicode")
        with open(filepath, "w") as f:
            f.write(f"<!-- Rule: {rule_name} -->\n")
            f.write(f"<!-- ID: {rule_id} -->\n")
            f.write(f"<!-- Exported: {datetime.now().isoformat()} -->\n")
            f.write(f"<!-- ATT&CK: {', '.join(techniques) if techniques else 'None mapped'} -->\n")
            f.write(rule_xml)

        catalog["rules"].append({
            "id":         rule_id,
            "name":       rule_name,
            "filename":   os.path.join(subdir, filename),
            "enabled":    enabled != "false",
            "severity":   severity,
            "category":   category,
            "techniques": techniques,
            "exported":   datetime.now().isoformat(),
            "fp_rate":    None,       # filled by update_fp_rates()
            "last_reviewed": None,    # filled manually or by review workflow
            "owner":      os.environ.get("FSIEM_RULE_OWNER", "SOC Team"),
        })
        exported += 1

    # Write catalog
    with open(os.path.join(output_dir, "catalog.json"), "w") as f:
        json.dump(catalog, f, indent=2)

    return {
        "exported":      exported,
        "output_dir":    output_dir,
        "catalog_path":  os.path.join(output_dir, "catalog.json"),
        "message":       f"Exported {exported} rules to {output_dir}/",
    }

def update_catalog_fp_rates(
    catalog_path: str = "./rules/catalog.json",
    days_back: int = 30,
) -> dict:
    """
    Update the rule catalog with current FP rates from FortiSIEM incident history.
    Run after export_rules_to_files() to enrich the catalog with quality metrics.
    """
    import time
    from collections import defaultdict

    with open(catalog_path) as f:
        catalog = json.load(f)

    host = os.environ["FSIEM_HOST"]
    now_ms  = int(datetime.now().timestamp() * 1000)
    start_ms = int((datetime.now().timestamp() - days_back*86400) * 1000)

    # Load incident history for FP calculation
    rule_stats = defaultdict(lambda: {"fp": 0, "total": 0})
    for status in ["False Positive", "Cleared", "Active", "InProgress"]:
        try:
            resp = requests.get(
                f"{host}/phoenix/rest/incident/listIncidents",
                params={"startTime": start_ms, "endTime": now_ms,
                        "maxResults": 1000, "status": status},
                headers=fsiem_headers(), verify=fsiem_verify_ssl()
            )
            if resp.status_code != 200: continue
            root = ET.fromstring(resp.text)
            for inc in root.findall(".//incident"):
                rule = inc.findtext("ruleId") or inc.findtext("ruleName") or ""
                rule_stats[rule]["total"] += 1
                if status == "False Positive":
                    rule_stats[rule]["fp"] += 1
        except Exception:
            continue

    # Update catalog entries
    updated = 0
    for rule in catalog["rules"]:
        stats = rule_stats.get(rule["id"], {})
        total = stats.get("total", 0)
        fp    = stats.get("fp", 0)
        if total > 0:
            rule["fp_rate"]       = round(fp / total * 100, 1)
            rule["fp_count"]      = fp
            rule["total_count"]   = total
            rule["fp_confidence"] = "HIGH" if total >= 20 else "MEDIUM" if total >= 5 else "LOW"
            updated += 1

    catalog["fp_updated_at"] = datetime.now().isoformat()
    with open(catalog_path, "w") as f:
        json.dump(catalog, f, indent=2)

    return {"updated": updated, "catalog": catalog_path}

def generate_rule_catalog_report(
    catalog_path: str = "./rules/catalog.json",
) -> str:
    """Generate a formatted rule catalog report for documentation."""
    with open(catalog_path) as f:
        catalog = json.load(f)

    rules = catalog["rules"]
    active = [r for r in rules if r.get("enabled")]
    high_fp = [r for r in active if (r.get("fp_rate") or 0) >= 50]
    no_technique = [r for r in active if not r.get("techniques")]

    lines = [
        "# Detection Rule Catalog",
        f"**Exported**: {catalog.get('exported_at','')[:10]} | "
        f"**Total rules**: {len(rules)} | **Active**: {len(active)}",
        "",
        "## Quality Summary",
        f"| Metric | Value |",
        f"|---|---|",
        f"| Active rules | {len(active)} |",
        f"| Rules with ATT&CK mapping | {len([r for r in active if r.get('techniques')])} |",
        f"| Rules without ATT&CK mapping | {len(no_technique)} |",
        f"| Rules with FP rate ≥50% | {len(high_fp)} |",
        "",
        "## Rules Requiring Attention",
        "",
    ]

    if high_fp:
        lines += ["### High FP Rate (≥50%) — Tune These", ""]
        lines += ["| Rule | FP Rate | Total Incidents | ATT&CK |",
                  "|---|---|---|---|"]
        for r in sorted(high_fp, key=lambda x: x.get("fp_rate",0), reverse=True)[:10]:
            lines.append(f"| {r['name'][:50]} | {r.get('fp_rate','?')}% | "
                         f"{r.get('total_count','?')} | {', '.join(r.get('techniques',[]) or ['—'])} |")

    if no_technique:
        lines += ["", "### No ATT&CK Mapping — Tag These", ""]
        for r in no_technique[:10]:
            lines.append(f"- {r['name']}")

    lines += [
        "",
        "## Full Active Rule List",
        "",
        "| Rule | Severity | ATT&CK | FP Rate | Owner |",
        "|---|---|---|---|---|",
    ]
    for r in sorted(active, key=lambda x: x.get("severity",""), reverse=True):
        techniques = ", ".join(r.get("techniques",[]) or ["—"])
        fp = f"{r['fp_rate']}%" if r.get("fp_rate") is not None else "—"
        lines.append(f"| {r['name'][:45]} | {r.get('severity','?')} | "
                     f"{techniques[:20]} | {fp} | {r.get('owner','?')} |")

    return "\n".join(lines)
```

## Atomic Red Team Validation

```python
def validate_rule_with_art(
    technique_id: str,
    rule_name: str = None,
) -> str:
    """
    Generate Atomic Red Team test guidance for validating a FortiSIEM rule.
    Links to the ART GitHub test for the technique.
    Provides: test command, expected FortiSIEM events, validation steps.
    """
    # ART test library — key techniques with their test commands
    ART_TESTS = {
        "T1110": {
            "test_name": "Brute Force - Password Spraying",
            "command":   "Invoke-AtomicTest T1110 -TestNumbers 1",
            "expected_events": ["Win-Security-4625 (multiple failures)", "Win-Security-4740 (lockout)"],
            "fortisiem_query": "eventType IN (Failed Login, Win-Security-4625) AND COUNT > 5",
        },
        "T1059.001": {
            "test_name": "PowerShell Encoded Command",
            "command":   "Invoke-AtomicTest T1059.001 -TestNumbers 1",
            "expected_events": ["Win-Security-4688 with powershell.exe", "Win-Powershell-4104"],
            "fortisiem_query": "processName CONTAIN powershell AND rawEventMsg REGEXP -enc|-EncodedCommand",
        },
        "T1003.001": {
            "test_name": "LSASS Memory Dump via ProcDump",
            "command":   "Invoke-AtomicTest T1003.001 -TestNumbers 1",
            "expected_events": ["Sysmon-10 (ProcessAccess targeting lsass.exe)"],
            "fortisiem_query": "eventType IN (Sysmon-10) AND rawEventMsg CONTAIN lsass",
            "prerequisite": "Requires Sysmon with Event 10 configured",
        },
        "T1486": {
            "test_name": "Data Encrypted via vssadmin",
            "command":   "Invoke-AtomicTest T1486 -TestNumbers 1",
            "expected_events": ["Win-Security-4688: vssadmin.exe delete shadows"],
            "fortisiem_query": "processName CONTAIN vssadmin AND rawEventMsg CONTAIN delete",
            "warning": "⚠️ ONLY run in isolated test environment — deletes shadow copies",
        },
        "T1558.003": {
            "test_name": "Kerberoasting - Request TGS for RC4",
            "command":   "Invoke-AtomicTest T1558.003 -TestNumbers 1",
            "expected_events": ["Win-Security-4769 with etype 0x17 (RC4)"],
            "fortisiem_query": "eventType IN (Win-Security-4769) AND rawEventMsg CONTAIN 0x17",
            "prerequisite": "Requires Domain Controller log ingestion",
        },
        "T1021.001": {
            "test_name": "RDP Lateral Movement",
            "command":   "Invoke-AtomicTest T1021.001 -TestNumbers 1",
            "expected_events": ["Win-Security-4624 Type 10 (RemoteInteractive)"],
            "fortisiem_query": "eventType IN (Win-Security-4624) AND rawEventMsg CONTAIN LogonType.*10",
        },
    }

    base_id = technique_id.split(".")[0]
    art = ART_TESTS.get(technique_id) or ART_TESTS.get(base_id)

    lines = [
        f"# Atomic Red Team Validation: {technique_id}",
        f"**Rule to validate**: {rule_name or 'Specify rule name'}",
        "",
    ]

    if art:
        lines += [
            f"## Test: {art['test_name']}",
            "",
            "### Prerequisites",
            "1. Isolated test environment (separate from production)",
            "2. [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team) installed",
            "3. FortiSIEM ingesting endpoint logs from test machine",
            art.get("prerequisite", ""),
            "",
            "### Test Command",
            "~~~powershell",
            f"# Install ART if not present",
            f"IEX (IWR 'https://raw.githubusercontent.com/redcanaryco/invoke-atomicredteam/master/install-atomicredteam.ps1' -UseBasicParsing)",
            f"",
            f"# Run the test",
            f"{art['command']}",
            "~~~",
            "",
            "### Expected FortiSIEM Events",
        ]
        for event in art["expected_events"]:
            lines.append(f"- `{event}`")

        lines += [
            "",
            "### Validation Query (run in FortiSIEM after test)",
            "~~~",
            f"{art['fortisiem_query']}",
            "~~~",
            "",
            "### Pass/Fail Criteria",
            "- ✅ PASS: FortiSIEM alert fired within 5 minutes of test execution",
            "- ✅ PASS: Rule classification matches (TP, not FP)",
            "- ❌ FAIL: No alert — check data source ingestion first",
            "- ❌ FAIL: Alert fired but auto-triage classified as FP — review asset criticality",
        ]
        if art.get("warning"):
            lines += ["", f"⚠️ **WARNING**: {art['warning']}"]
    else:
        lines += [
            f"No ART test template for {technique_id}.",
            f"Check: https://github.com/redcanaryco/atomic-red-team/tree/master/atomics/{technique_id}",
            "",
            "General validation steps:",
            "1. Simulate the technique manually in test environment",
            "2. Confirm FortiSIEM receives the event (check raw events)",
            "3. Confirm your rule fires on the event",
            "4. Confirm auto-triage correctly classifies as TRUE_POSITIVE",
        ]

    return "\n".join(lines)
```
