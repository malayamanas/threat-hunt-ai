---
name: fsiem-ioc
description: Hunt for IOCs in FortiSIEM. Accepts a list of IPs/domains/hashes, a pasted threat report, or a threat actor name. Extracts all indicators, hunts each in FortiSIEM history, generates detection rules for hits, and produces a prioritised action report.
---
# Command: /fsiem-ioc
# Usage: /fsiem-ioc <IOC list, threat report text, or threat actor name>

## Behavior
1. Detect input type:
   - IP list / domain list / hash list → hunt each directly
   - Long text (>100 chars) → extract IOCs with regex, then hunt all
   - Threat actor name → ask user to paste the report or IOC list
2. Run `hunt_all_iocs()` from `skills/ioc_management/` across last 30 days
3. For each hit: show event count, earliest/latest occurrence, affected internal hosts
4. Generate detection rules for confirmed hits
5. Output `ioc_hunt_report()` with prioritised action list

## Example Invocations
- `/fsiem-ioc 185.220.101.5 45.33.32.156 evil.example.com`
- `/fsiem-ioc [paste threat report here]`
- `/fsiem-ioc d41d8cd98f00b204e9800998ecf8427e` (MD5 hash)
