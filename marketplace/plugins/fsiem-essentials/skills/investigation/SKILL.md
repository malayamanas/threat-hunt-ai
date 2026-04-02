---
name: fsiem-investigate
description: Create structured SOC investigation records and health reports for FortiSIEM incidents. Use when documenting an investigation or generating a report.
---

# FortiSIEM Investigation & Reporting

Investigations automatically gather incident details, enrich with CMDB data, build an event timeline, and run a threat hunt on primary source IPs.

## Key Functions

- `fsiem_investigate_incident(incident_id, analyst_name, deep_hunt=True)` — full investigation record
- `fsiem_investigation_summary(investigation)` — generate executive summary text
- `fsiem_report_org_health(org, days_back=7)` — org-level health report
- `fsiem_report_top_incidents(hours_back=168, top_n=10)` — top incidents by event count

## Investigation Record Contains

- Incident metadata (title, severity, category, rule triggered)
- Scope (source IPs, dest IPs, affected users, event count)
- Asset inventory (CMDB enrichment for all involved IPs)
- Event timeline (first 50 events, sorted by time)
- Threat hunt results (7-day lookback on primary source IP)
- Analysis and remediation fields for analyst completion

## Quick Example

```python
inv = fsiem_investigate_incident("10432", analyst_name="Alice Smith")
summary = fsiem_investigation_summary(inv)
print(summary)
```

## Additional Resources
- Full implementations and report templates: [reference.md](reference.md)
