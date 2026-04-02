---
name: fsiem-multiorg
description: Run operations across ALL organizations in a FortiSIEM Service Provider deployment — sweep incidents, hunt IOCs, or generate a consolidated health report for every tenant. Use in MSSP environments.
---
# Command: /fsiem-multiorg
# Usage: /fsiem-multiorg <incidents|hunt|report> [options]

## Subcommands
- `incidents` — list all HIGH/CRITICAL incidents across every org (last 24h)
- `hunt <IOC>` — hunt for an IOC across all tenants simultaneously
- `report` — consolidated health report for all orgs (last 7 days)

## Examples
- `/fsiem-multiorg incidents`
- `/fsiem-multiorg hunt 185.220.101.5`
- `/fsiem-multiorg report`
