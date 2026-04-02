---
name: fsiem-apt-hunt
description: Run FortiSIEM hunt queries for a specific APT group — APT28, APT29, Lazarus, FIN7, Sandworm, APT41. Each profile contains the group's known TTPs, C2 infrastructure characteristics, and ready-to-run FortiSIEM queries. Use when building a proactive hunt program or after receiving threat intelligence about a specific actor.
---
# Command: /fsiem-apt-hunt

## Usage
- `/fsiem-apt-hunt APT28` — run all APT28 hunt queries (Fancy Bear / GRU)
- `/fsiem-apt-hunt APT29` — run all APT29 hunt queries (Cozy Bear / SVR)
- `/fsiem-apt-hunt Lazarus` — run Lazarus Group hunt queries (DPRK / financial)
- `/fsiem-apt-hunt FIN7` — run FIN7 queries (criminal / POS targeting)
- `/fsiem-apt-hunt Sandworm` — run Sandworm queries (GRU / critical infra)
- `/fsiem-apt-hunt --sector financial` — show relevant groups for your sector
- `/fsiem-apt-hunt --sector energy` — energy sector actor profiles

## Available Sectors
financial, government, healthcare, energy, defence, technology, retail, critical_infra

## Output per group
- Hunt query results from FortiSIEM (events found or clean)
- Key TTPs for detection rule creation
- Infrastructure signatures for enrichment pivoting
- Escalation guidance if findings detected
