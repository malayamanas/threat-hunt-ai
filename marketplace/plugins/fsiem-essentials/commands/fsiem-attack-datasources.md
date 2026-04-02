---
name: fsiem-attack-datasources
description: Map MITRE ATT&CK techniques to required data sources and check FortiSIEM coverage. Answers "what logs do I need to detect T1110?" and "which techniques are undetectable because data is missing from my SIEM?" Based on actual ATT&CK data source components — not keyword matching.
---
# Command: /fsiem-attack-datasources

## Usage
- `/fsiem-attack-datasources T1110` — what logs needed to detect brute force
- `/fsiem-attack-datasources T1003` — what logs needed for credential dumping
- `/fsiem-attack-datasources coverage` — full coverage report (checks live FortiSIEM data)
- `/fsiem-attack-datasources gaps` — only show uncovered techniques + data to enable
- `/fsiem-attack-datasources priority` — biggest bang for buck data sources to enable

## What it answers
- "What log sources do I need for VPN compromise detection?" (T1078, T1133, T1110)
- "Why can't I detect T1003 — what's missing in FortiSIEM?"
- "If I enable Sysmon, how many more techniques become detectable?"

## Anton's insight applied
ATT&CK's data source component tells you exactly what collection layer you need.
This maps that to FortiSIEM event types so you know precisely what to ingest.
