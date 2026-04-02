---
name: fsiem-report
description: Generate a security health report for a FortiSIEM organization.
---
# Command: /fsiem-report
# Usage: /fsiem-report [org] [days]

## Description
Generate a security health report for a FortiSIEM organization.
Defaults to the configured `$FSIEM_ORG` over the last 7 days.

## Arguments
- `org` — Organization name. Use `all` in Service Provider mode to report across every org. (default: `$FSIEM_ORG`)
- `days` — Number of days to cover. (default: `7`)

## Workflow

1. Call `fsiem_report_org_health(org, days_back)` from `skills/investigation.md`
2. Call `fsiem_report_top_incidents(hours_back=days*24)` for top incident patterns
3. Render a formatted report including:

```
## FortiSIEM Health Report
Organization: {org} | Period: Last {days} days | Generated: {timestamp}

### Incident Summary
  Total:    42
  Critical:  3  ██░░░░░░░░
  High:     12  ████░░░░░░
  Medium:   18  ██████░░░░
  Low:       9  ███░░░░░░░

### Open Critical Incidents Requiring Attention
  #10432 — Brute Force: 185.220.101.5        (847 events, 2h ago)
  #10431 — Lateral Movement Detected          ( 23 events, 14m ago)

### Top 5 Incident Categories
  1. Security/Access        18 incidents
  2. Security/Malware        9 incidents
  3. Network/Anomaly         7 incidents
  4. Security/Exploit        5 incidents
  5. Policy/Violation        3 incidents

### Recommendations
  • 3 critical incidents require immediate triage
  • Consider tuning rule "Multiple Failed Logins" — 40% false positive rate
```

## Example Invocations
- `/fsiem-report`
- `/fsiem-report ACME_Corp 30`
- `/fsiem-report all 7`
