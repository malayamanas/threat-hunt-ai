---
name: fsiem-hunt
description: Hunt for IOCs, suspicious IPs, domains, users, or MITRE techniques across FortiSIEM event data. Use when threat hunting or investigating indicators.
---

# FortiSIEM Threat Hunting

Threat hunting searches historical event data for attacker indicators. Always hunt at least 7 days back; use 30 days for IOC hunts from threat reports.

## Key Functions

- `fsiem_hunt_ip(ip, days_back=7)` — all activity from/to a suspicious IP
- `fsiem_hunt_domain(domain, days_back=7)` — DNS and connection events for a domain
- `fsiem_hunt_user(username, days_back=7)` — anomalous account activity
- `fsiem_hunt_ioc_list(iocs, days_back=7)` — bulk hunt for a list of IOCs
- `fsiem_hunt_from_report(report_text, days_back=30)` — extract IOCs from a threat report and hunt all of them automatically
- `fsiem_hunt_mitre_technique(technique_id, days_back=7)` — hunt for MITRE ATT&CK evidence

## Quick Example

```python
# Hunt a suspicious IP
results = fsiem_hunt_ip("185.220.101.5", days_back=30)
print(f"Found {results['src_event_count']} events")

# Hunt from a threat report
with open("apt_report.txt") as f:
    results = fsiem_hunt_from_report(f.read(), days_back=30)
print(f"IOCs found in environment: {results['hits']}")
```

## Additional Resources
- Full implementations and IOC extraction logic: [reference.md](reference.md)
