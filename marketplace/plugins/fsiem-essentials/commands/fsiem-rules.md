---
name: fsiem-rules
description: Create, list, enable, disable, or tune FortiSIEM correlation rules.
---
# Command: /fsiem-rules
# Usage: /fsiem-rules <create|list|enable|disable|tune> [args]

## Description
Create, list, enable, disable, or tune FortiSIEM correlation rules.

## Subcommands

### create <description>
Generate and deploy a new correlation rule from a plain-English description.

Examples:
- `/fsiem-rules create brute force detection for SSH`
- `/fsiem-rules create rule for MITRE T1059 PowerShell execution`
- `/fsiem-rules create IOC detection for IP 185.220.101.5`

Workflow:
1. Parse description to determine rule type (brute force / beaconing / MITRE / IOC / custom)
2. Call the appropriate builder from `skills/rules.md`
3. Show the generated XML to the analyst for review
4. Ask: "Deploy this rule? (yes/no/edit)"
5. On yes: call `fsiem_rule_create`, confirm success

### list [filter]
List all active correlation rules. Optionally filter by name or category.

### enable <rule_name>
Enable a disabled rule by name.

### disable <rule_name>
Disable an active rule (e.g., during maintenance).

### tune <rule_name>
Review false positives for a rule and suggest threshold/filter adjustments:
1. Fetch incidents triggered by this rule (last 30 days)
2. Identify patterns in false positives (source IPs, user accounts, time-of-day)
3. Suggest specific XML changes to reduce noise
4. Apply changes after confirmation
