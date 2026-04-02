---
name: fsiem-compliance
description: Run FortiSIEM compliance reports — PCI DSS, HIPAA, SOX, NIST, ISO 27001. List available reports, execute them, and export results. Use when asked about compliance posture, audit evidence, or regulatory reporting.
---

# FortiSIEM Compliance Reporting

FortiSIEM includes 1,300+ pre-built compliance reports. This skill lists, runs, and exports them.

## List Available Compliance Reports

```python
import requests, base64, os, xml.etree.ElementTree as ET

def fsiem_headers():
    user = os.environ["FSIEM_USER"]
    org  = os.environ["FSIEM_ORG"]
    pw   = os.environ["FSIEM_PASS"]
    token = base64.b64encode(f"{user}/{org}:{pw}".encode()).decode()
    return {"Authorization": f"Basic {token}", "Content-Type": "text/xml"}

def fsiem_verify_ssl():
    return os.environ.get("FSIEM_VERIFY_SSL", "false").lower() == "true"

def list_compliance_reports(framework: str = None) -> list[dict]:
    """
    List FortiSIEM compliance reports, optionally filtered by framework.

    Args:
        framework: Filter by name (e.g. "PCI", "HIPAA", "SOX", "NIST", "ISO")
    Returns:
        List of report dicts: id, name, category, description
    """
    host = os.environ["FSIEM_HOST"]
    resp = requests.get(
        f"{host}/phoenix/rest/report/listReports",
        headers=fsiem_headers(),
        verify=fsiem_verify_ssl()
    )
    resp.raise_for_status()
    root = ET.fromstring(resp.text)

    reports = []
    for r in root.findall(".//report"):
        name = r.findtext("n") or r.findtext("name") or ""
        cat  = r.findtext("category") or ""
        if framework and framework.upper() not in name.upper() and framework.upper() not in cat.upper():
            continue
        reports.append({
            "id":          r.findtext("id"),
            "name":        name,
            "category":    cat,
            "description": r.findtext("description") or "",
        })
    return reports
```

## Compliance Report Catalog (Key Reports)

| Framework | Report Name Pattern | Use For |
|---|---|---|
| **PCI DSS** | `PCI*` | Card data environment audit |
| **HIPAA** | `HIPAA*` | Healthcare data compliance |
| **SOX** | `SOX*` | Financial controls evidence |
| **NIST 800-53** | `NIST*` | Federal/government compliance |
| **ISO 27001** | `ISO*` | Information security standard |
| **GDPR** | `GDPR*` | EU data protection |
| **CIS** | `CIS*` | Center for Internet Security benchmarks |
| **GLBA** | `GLBA*` | Financial institution privacy |
| **FISMA** | `FISMA*` | US federal agency requirements |
| **NERC CIP** | `NERC*` | Energy sector / critical infrastructure |

## Run a Compliance Report

```python
import time

def run_compliance_report(
    report_id: str,
    time_window: str = "Last 30 days",
    org: str = None
) -> dict:
    """
    Execute a compliance report and return results.

    Args:
        report_id: Report ID from list_compliance_reports()
        time_window: Time range for the report
        org: Organization (SP mode). Defaults to FSIEM_ORG env var.
    Returns:
        dict with report metadata and result rows
    """
    host = os.environ["FSIEM_HOST"]
    org = org or os.environ.get("FSIEM_ORG", "super")

    # Build run request
    xml_body = f"""<reportRun>
      <id>{report_id}</id>
      <timeRange>{time_window}</timeRange>
      <organization>{org}</organization>
    </reportRun>"""

    resp = requests.post(
        f"{host}/phoenix/rest/report/run",
        data=xml_body,
        headers=fsiem_headers(),
        verify=fsiem_verify_ssl(),
        timeout=30
    )
    resp.raise_for_status()
    run_id = resp.text.strip()

    # Poll for completion
    for _ in range(60):
        p = requests.get(
            f"{host}/phoenix/rest/report/progress/{run_id}",
            headers=fsiem_headers(),
            verify=fsiem_verify_ssl()
        )
        if int(p.text.strip() or "0") >= 100:
            break
        time.sleep(3)

    # Fetch results
    r2 = requests.get(
        f"{host}/phoenix/rest/report/results/{run_id}",
        headers=fsiem_headers(),
        verify=fsiem_verify_ssl()
    )
    r2.raise_for_status()
    root = ET.fromstring(r2.text)

    rows = []
    for row in root.findall(".//row"):
        rows.append({col.get("name", ""): col.text or ""
                     for col in row.findall("col")})

    return {
        "report_id": report_id,
        "run_id": run_id,
        "time_window": time_window,
        "org": org,
        "row_count": len(rows),
        "rows": rows,
    }
```

## Compliance Workflow by Framework

### PCI DSS Quick Audit
```python
# List all PCI reports
pci_reports = list_compliance_reports("PCI")
print(f"Found {len(pci_reports)} PCI reports")

# Run key PCI reports
key_pci = [
    "PCI - Failed Login Attempts",
    "PCI - Admin Activity",
    "PCI - Firewall Rule Changes",
    "PCI - Privileged User Activity",
]
for report_name in key_pci:
    matches = [r for r in pci_reports if report_name.lower() in r["name"].lower()]
    if matches:
        result = run_compliance_report(matches[0]["id"], time_window="Last 30 days")
        print(f"{report_name}: {result['row_count']} findings")
```

### HIPAA Evidence Package
```python
hipaa_reports = list_compliance_reports("HIPAA")
evidence = {}
for report in hipaa_reports[:10]:  # Top 10 HIPAA reports
    result = run_compliance_report(report["id"], time_window="Last 90 days")
    evidence[report["name"]] = result
    print(f"✓ {report['name']}: {result['row_count']} rows")

# Export evidence package
import json
with open("hipaa_evidence.json", "w") as f:
    json.dump(evidence, f, indent=2)
print("Evidence package saved to hipaa_evidence.json")
```

### SOX IT Controls
```python
sox_reports = list_compliance_reports("SOX")
sox_results = {}
for r in sox_reports:
    result = run_compliance_report(r["id"], time_window="Last 90 days")
    sox_results[r["name"]] = {
        "findings": result["row_count"],
        "status": "PASS" if result["row_count"] == 0 else "REVIEW",
    }

# Summary
print("\nSOX IT Controls Summary:")
print(f"{'Control':<50} {'Findings':<10} {'Status'}")
print("-" * 75)
for name, data in sorted(sox_results.items()):
    print(f"{name[:50]:<50} {data['findings']:<10} {data['status']}")
```

## Compliance Report Export (CSV)

```python
def export_report_csv(result: dict, filename: str):
    """Export report results to CSV for auditor submission."""
    import csv
    if not result["rows"]:
        print(f"No data to export for report {result['report_id']}")
        return
    with open(filename, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=result["rows"][0].keys())
        writer.writeheader()
        writer.writerows(result["rows"])
    print(f"Exported {result['row_count']} rows to {filename}")

# Example: export PCI admin activity report
result = run_compliance_report("PCI_ADMIN_ACTIVITY_ID", time_window="Last 30 days")
export_report_csv(result, "pci_admin_activity_Q1_2025.csv")
```

## Scheduled Compliance Checks

For automated monthly compliance evidence collection, see `scripts/scheduled_hunt.py` which includes a `--compliance` flag.
