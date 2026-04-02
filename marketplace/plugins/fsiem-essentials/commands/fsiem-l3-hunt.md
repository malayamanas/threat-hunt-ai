---
name: fsiem-l3-hunt
description: L3 advanced threat hunt and threat intelligence analysis. Detects long-dwell attackers, maps full ATT&CK campaign coverage, builds Diamond Model actor profile, and produces a TLP:AMBER threat intelligence report. Use proactively (weekly hunt) or when L2 escalates a complex/suspected APT incident.
---
# Command: /fsiem-l3-hunt

## Usage
- `/fsiem-l3-hunt` — run proactive weekly hunt (90 days, all techniques)
- `/fsiem-l3-hunt --l2 L2-10432-20250322` — build on specific L2 investigation
- `/fsiem-l3-hunt --dwell-only` — only run long-dwell detection (faster)
- `/fsiem-l3-hunt --days 180` — extend lookback to 180 days

## Workflow
1. `detect_long_dwell(days_back, min_dwell)` — find beaconing, dormant account reactivation
2. `map_attack_campaign(events)` — map all events to MITRE ATT&CK techniques
3. `build_diamond_model(campaign, scope, enrichments)` — actor profiling
4. `generate_l3_report(...)` — TLP:AMBER threat intelligence report with IOCs and strategic recommendations

## Outputs
- Diamond Model actor profile (adversary / capability / infrastructure / victim)
- MITRE ATT&CK technique heatmap for the campaign
- Long dwell detection findings table
- IOC list for immediate blocking + detection rules
- Strategic recommendations (0-24h, 1-7 days, 1-30 days)
