---
name: fsiem-report-generate
description: Generate formal SOC reports — executive/management summary, operational daily/weekly shift reports, incident investigation reports, threat hunt reports, and compliance evidence packages. Use when asked to generate a report, create a management summary, produce a shift handover, or export findings.
---

# FortiSIEM Report Generation

Generate professional, structured reports for every audience: executives, operations managers, auditors, and analysts.

## Report Types

| Report | Audience | Frequency | Covers |
|---|---|---|---|
| Executive Summary | CISO / Board | Weekly/Monthly | KPIs, risk posture, top incidents |
| Operational Daily | SOC Manager | Daily | Queue metrics, open incidents, SLA performance |
| Shift Handover | Next-shift Analyst | Per shift | Triaged alerts, open items, context |
| Incident Report | Management / Legal | Per incident | Full investigation, timeline, impact |
| Threat Hunt Report | SOC / Threat Team | Per hunt | Hunt methodology, findings, new IOCs |
| Compliance Evidence | Auditors | Quarterly | Framework control coverage |

## Executive Summary Report

```python
import os, base64, requests, xml.etree.ElementTree as ET
from datetime import datetime, timedelta

def fsiem_headers():
    user, org, pw = os.environ["FSIEM_USER"], os.environ["FSIEM_ORG"], os.environ["FSIEM_PASS"]
    return {"Authorization": f"Basic {base64.b64encode(f'{user}/{org}:{pw}'.encode()).decode()}",
            "Content-Type": "text/xml"}

def fsiem_verify_ssl():
    return os.environ.get("FSIEM_VERIFY_SSL","false").lower() == "true"

def get_incident_stats(days_back: int = 7) -> dict:
    """Pull incident statistics for the reporting period."""
    host = os.environ["FSIEM_HOST"]
    now = int(datetime.now().timestamp() * 1000)
    start = int((datetime.now() - timedelta(days=days_back)).timestamp() * 1000)
    stats = {"total": 0, "by_severity": {}, "by_category": {},
             "closed": 0, "open": 0, "false_positive": 0, "mttr_hours": 0}

    for severity in ["CRITICAL","HIGH","MEDIUM","LOW"]:
        for status in ["Active","Cleared","False Positive"]:
            resp = requests.get(
                f"{host}/phoenix/rest/incident/listIncidents",
                params={"startTime": start, "endTime": now,
                        "maxResults": 500, "eventSeverity": severity, "status": status},
                headers=fsiem_headers(), verify=fsiem_verify_ssl()
            )
            if resp.status_code != 200:
                continue
            root = ET.fromstring(resp.text)
            incidents = root.findall(".//incident")
            count = len(incidents)
            stats["total"] += count
            stats["by_severity"][severity] = stats["by_severity"].get(severity, 0) + count
            if status in ("Cleared",):
                stats["closed"] += count
            elif status == "Active":
                stats["open"] += count
            elif status == "False Positive":
                stats["false_positive"] += count
            for inc in incidents:
                cat = inc.findtext("incidentCategory") or "Other"
                stats["by_category"][cat] = stats["by_category"].get(cat, 0) + 1
    return stats

def generate_executive_report(
    period_days: int = 7,
    org_name: str = "Your Organization",
    prev_stats: dict = None,
) -> str:
    """
    Generate an executive summary report for CISO/management.
    Includes KPIs, trend vs prior period, top threats, and risk posture.
    """
    stats = get_incident_stats(period_days)
    period_label = f"Last {period_days} Days"
    now = datetime.now()
    period_start = (now - timedelta(days=period_days)).strftime("%Y-%m-%d")
    period_end = now.strftime("%Y-%m-%d")

    # Risk posture
    critical = stats["by_severity"].get("CRITICAL", 0)
    high = stats["by_severity"].get("HIGH", 0)
    fp_rate = round(stats["false_positive"] / stats["total"] * 100, 1) if stats["total"] else 0
    risk_level = ("CRITICAL" if critical > 5 else
                  "HIGH" if critical > 0 or high > 20 else
                  "MEDIUM" if high > 5 else "LOW")
    risk_emoji = {"CRITICAL":"🔴","HIGH":"🟠","MEDIUM":"🟡","LOW":"🟢"}.get(risk_level,"⚪")

    # Trend vs previous period
    trend = ""
    if prev_stats:
        diff = stats["total"] - prev_stats.get("total", 0)
        trend = f"{'▲' if diff > 0 else '▼'} {abs(diff)} vs prior period"

    lines = [
        f"# Security Operations Executive Summary",
        f"**Organization**: {org_name}",
        f"**Period**: {period_start} → {period_end} ({period_label})",
        f"**Generated**: {now.strftime('%Y-%m-%d %H:%M')}",
        "",
        f"## Overall Risk Posture: {risk_emoji} {risk_level}",
        "",
        "## Key Performance Indicators",
        "",
        "| KPI | Value | Target | Status |",
        "|---|---|---|---|",
        f"| Total Incidents | {stats['total']} {trend} | — | — |",
        f"| Critical Incidents | {critical} | 0 | {'✅' if critical == 0 else '🔴'} |",
        f"| High Incidents | {high} | <10/week | {'✅' if high < 10 else '🟡'} |",
        f"| Open (Unresolved) | {stats['open']} | <5 | {'✅' if stats['open'] < 5 else '🟠'} |",
        f"| False Positive Rate | {fp_rate}% | <20% | {'✅' if fp_rate < 20 else '🟡'} |",
        "",
        "## Incident Breakdown by Severity",
        "",
        "| Severity | Count | % of Total |",
        "|---|---|---|",
    ]
    for sev in ["CRITICAL","HIGH","MEDIUM","LOW"]:
        count = stats["by_severity"].get(sev, 0)
        pct = round(count / stats["total"] * 100, 1) if stats["total"] else 0
        lines.append(f"| {sev} | {count} | {pct}% |")

    lines += [
        "",
        "## Top Incident Categories",
        "",
        "| Category | Count |",
        "|---|---|",
    ]
    for cat, count in sorted(stats["by_category"].items(), key=lambda x: -x[1])[:5]:
        lines.append(f"| {cat} | {count} |")

    lines += [
        "",
        "## Recommended Management Actions",
        "",
    ]
    if critical > 0:
        lines.append(f"1. 🔴 **{critical} CRITICAL incidents** require immediate executive attention — review investigation reports")
    if fp_rate > 30:
        lines.append(f"2. 🟡 **False positive rate {fp_rate}%** exceeds target — schedule rule tuning session")
    if stats["open"] > 10:
        lines.append(f"3. 🟠 **{stats['open']} open incidents** — review analyst capacity and escalation paths")
    if not (critical or fp_rate > 30 or stats["open"] > 10):
        lines.append("✅ All KPIs within target — no management actions required this period")

    lines += ["", "---", f"*Prepared by SOC | {now.strftime('%Y-%m-%d')}*"]
    return "\n".join(lines)
```

## Daily Operational Report

```python
def generate_daily_ops_report(analyst: str = "SOC Team") -> str:
    """
    Generate a daily operational report for SOC managers.
    Covers last 24h activity, queue status, SLA performance.
    """
    stats = get_incident_stats(days_back=1)
    now = datetime.now()

    lines = [
        f"# Daily SOC Operations Report",
        f"**Date**: {now.strftime('%Y-%m-%d')} | **Analyst**: {analyst}",
        "",
        "## 24-Hour Summary",
        f"| Metric | Count |",
        f"|---|---|",
        f"| New incidents | {stats['total']} |",
        f"| Closed | {stats['closed']} |",
        f"| Still open | {stats['open']} |",
        f"| False positives | {stats['false_positive']} |",
        f"| Critical | {stats['by_severity'].get('CRITICAL',0)} |",
        f"| High | {stats['by_severity'].get('HIGH',0)} |",
        "",
        "## Queue Status",
        f"- **Backlog**: {stats['open']} incidents pending",
        f"- **SLA Risk**: {'🔴 Yes' if stats['open'] > 10 else '✅ No'}",
        "",
        "## Top Categories (Last 24h)",
    ]
    for cat, count in sorted(stats["by_category"].items(), key=lambda x: -x[1])[:5]:
        lines.append(f"- {cat}: {count}")

    lines += [
        "",
        "## Open Items for Next Shift",
        "_[Analyst to complete]_",
        "",
        "## Notes",
        "_[Analyst to complete]_",
    ]
    return "\n".join(lines)
```

## Threat Hunt Report Template

```python
def generate_hunt_report(
    hunt_name: str,
    hypothesis: str,
    methodology: str,
    queries_run: list,
    findings: list,
    verdict: str,  # CONFIRMED | POSSIBLE | NOT_FOUND
    new_iocs: list,
    analyst: str,
) -> str:
    """Generate a structured threat hunt report."""
    verdict_emoji = {"CONFIRMED": "🔴", "POSSIBLE": "🟡", "NOT_FOUND": "✅"}.get(verdict, "⚪")

    lines = [
        f"# Threat Hunt Report",
        f"**Hunt**: {hunt_name}",
        f"**Analyst**: {analyst} | **Date**: {datetime.now().strftime('%Y-%m-%d')}",
        f"**Verdict**: {verdict_emoji} {verdict}",
        "",
        "## Hypothesis",
        hypothesis,
        "",
        "## Methodology",
        methodology,
        "",
        f"## Queries Executed ({len(queries_run)})",
        "",
    ]
    for i, q in enumerate(queries_run, 1):
        lines.append(f"{i}. {q.get('description','')} — {q.get('results',0)} results")

    lines += ["", f"## Findings ({len(findings)} total)", ""]
    if findings:
        lines += [
            "| Time | Type | Source | Destination | Detail |",
            "|---|---|---|---|---|",
        ]
        for f in findings[:20]:
            lines.append(
                f"| {f.get('time','')[:16]} | {f.get('type','')} | "
                f"`{f.get('src','')}` | `{f.get('dest','')}` | {f.get('detail','')[:60]} |"
            )
    else:
        lines.append("No findings matching hypothesis.")

    if new_iocs:
        lines += ["", "## New IOCs Discovered", "", "| Type | Value | Confidence |", "|---|---|---|"]
        for ioc in new_iocs:
            lines.append(f"| {ioc.get('type','')} | `{ioc.get('value','')}` | {ioc.get('confidence','')} |")

    lines += [
        "",
        "## Recommendations",
        (f"- Deploy detection rule for observed TTP (see IOCs above)"
         if verdict == "CONFIRMED" else
         f"- Re-run hunt in 7 days with wider time window"
         if verdict == "POSSIBLE" else
         f"- Hypothesis not confirmed — archive for future reference"),
        "",
        "---",
        f"*Report generated: {datetime.now().isoformat()}*",
    ]
    return "\n".join(lines)
```

## Saving Reports

```python
def save_report(content: str, report_type: str, format: str = "md") -> str:
    """Save a report to disk with timestamped filename."""
    ts = datetime.now().strftime("%Y%m%d_%H%M")
    filename = f"fsiem_{report_type}_{ts}.{format}"
    output_dir = os.environ.get("REPORT_OUTPUT_DIR", "/tmp/fsiem_reports")
    os.makedirs(output_dir, exist_ok=True)
    path = os.path.join(output_dir, filename)
    with open(path, "w") as f:
        f.write(content)
    return path
```
