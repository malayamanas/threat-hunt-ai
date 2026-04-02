---
name: fsiem-report-generate
description: Generate formal SOC reports — executive/management summary, daily operational report, shift handover, incident investigation report, threat hunt report, and compliance evidence packages. Use when asked for any report, summary, or to document findings.
---
# Command: /fsiem-report-generate

## Usage
- `/fsiem-report-generate executive` — weekly CISO/management KPI report
- `/fsiem-report-generate daily` — daily operations report for SOC manager
- `/fsiem-report-generate shift` — end-of-shift handover for next analyst
- `/fsiem-report-generate incident 10432` — incident investigation report for incident 10432
- `/fsiem-report-generate hunt "APT lateral movement hypothesis"` — threat hunt report
- `/fsiem-report-generate compliance PCI` — PCI DSS compliance evidence package

## Output
All reports are saved to `$REPORT_OUTPUT_DIR` (default: `/tmp/fsiem_reports/`) as:
- `fsiem_executive_YYYYMMDD_HHMM.md`
- `fsiem_daily_YYYYMMDD_HHMM.md`
- `fsiem_incident_INCID_YYYYMMDD.md`
- etc.

Reports are also displayed inline in the current session.

## Report Sections by Type
| Report | Key Sections |
|---|---|
| Executive | KPIs, risk posture, top incidents, management actions |
| Daily Ops | 24h metrics, queue status, top categories, open items |
| Incident | Summary, scope, timeline, root cause, IOCs, recommendations |
| Hunt | Hypothesis, methodology, findings, new IOCs, recommendations |
| Compliance | Framework coverage, control evidence, gap analysis |
