---
name: fsiem-rule-create
description: Design and deploy a new FortiSIEM correlation rule. Describe the threat to detect in plain English or provide a MITRE technique ID, and this command generates validated rule XML, tests it against historical data, and deploys it.
---
# Command: /fsiem-rule-create
# Usage: /fsiem-rule-create <threat description or MITRE technique>

## Behavior
1. Parse input:
   - Plain description → extract: event type, threshold, time window, grouping
   - MITRE technique ID → look up in `skills/hypothesis_hunting/` mapping table
   - "brute force / beaconing / exfil / etc." → use matching template from `skills/rule_creation/`
2. Ask the 7 design questions (if info is missing)
3. Generate rule XML using the appropriate template
4. Validate XML (parse check, required fields, operator escaping)
5. Test: run event query with same filters — show how many times it would have fired in last 30 days
6. Show generated rule to analyst for review
7. On approval: deploy via `POST /phoenix/rest/rules`
8. Confirm deployment by listing rules

## Example Invocations
- `/fsiem-rule-create brute force SSH from external IPs`
- `/fsiem-rule-create T1486 ransomware`
- `/fsiem-rule-create detect PowerShell with encoded commands`
- `/fsiem-rule-create alert when service account logs in interactively`
- `/fsiem-rule-create IOC rule for IP 185.220.101.5`
