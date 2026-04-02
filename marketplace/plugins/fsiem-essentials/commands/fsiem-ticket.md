---
name: fsiem-ticket
description: Create a ticket in ServiceNow, Jira, or PagerDuty from a FortiSIEM incident or investigation. Automatically detects which integrations are configured from environment variables.
---
# Command: /fsiem-ticket
# Usage: /fsiem-ticket <incident_id> [servicenow|jira|pagerduty]

## Behavior
1. Fetch the incident and run `fsiem-investigate` if not already done
2. Auto-detect configured integrations (SNOW_URL, JIRA_URL, PAGERDUTY_ROUTING_KEY)
3. Call `escalate_incident()` from `skills/ticketing/`
4. Report back ticket numbers/URLs created

## Examples
- `/fsiem-ticket 10432` — create ticket in all configured systems
- `/fsiem-ticket 10432 servicenow` — ServiceNow only
- `/fsiem-ticket 10432 pagerduty` — PagerDuty alert only

## Required env vars (set whichever you use)
- ServiceNow: `SNOW_URL`, `SNOW_USER`, `SNOW_PASS`
- Jira: `JIRA_URL`, `JIRA_USER`, `JIRA_TOKEN`, `JIRA_PROJECT`
- PagerDuty: `PAGERDUTY_ROUTING_KEY`
