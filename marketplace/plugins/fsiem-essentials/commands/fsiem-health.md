---
name: fsiem-health
description: Check FortiSIEM operational health — silent devices, collector status, parser failures detected by event volume anomaly. Use at shift start, when a device is suspected to have stopped reporting, or for daily health checks. This is the first command to run before triaging alerts.
---
# Command: /fsiem-health

## Usage
- `/fsiem-health` — full health dashboard (collectors + silent devices + parser anomalies)
- `/fsiem-health --silent 2` — flag devices silent for more than 2 hours
- `/fsiem-health --collectors` — collector status only
- `/fsiem-health --parsers` — parser/volume anomaly check only (vs 7-day baseline)
- `/fsiem-health --device 10.0.1.5` — check a specific device

## What it checks
1. **Collectors** — status, EPS utilization, queue backlog, drop count
2. **Silent devices** — any monitored device with no events in N hours
3. **Parser anomalies** — event volume drops ≥50% vs 7-day baseline = likely parser break

## Output example
```
✅ 3/3 collectors healthy
🔴 Silent devices (CRITICAL): 2
  - 10.10.0.1 (fw-core-01) [Firewall] — silent 6.2h, last event: 2025-03-22 08:14
  - 10.10.0.5 (vpn-gw) [VPN] — silent 5.1h, last event: 2025-03-22 09:22
🟡 Parser anomalies: 1
  - 10.10.0.20 (dc-01): -82% event volume vs baseline — possible parser issue
```

## Priority rule
A silent firewall, IDS, or VPN = **P1 incident** until proven otherwise.
