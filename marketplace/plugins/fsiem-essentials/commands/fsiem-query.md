---
name: fsiem-query
description: Run a FortiSIEM event query described in plain English.
---
# Command: /fsiem-query
# Usage: /fsiem-query <natural language description of what to find>

## Description
Run a FortiSIEM event query described in plain English. Claude will translate
the request into a FortiSIEM query XML, execute it, and present results.

## Behavior
1. Parse the natural language request to extract:
   - Event types / keywords
   - Source/destination IPs, users, hostnames
   - Time range (default: last 1 hour)
   - Any other filters
2. Build query XML with `fsiem_build_query_xml`
3. Execute with `fsiem_query_full` (submit → poll → results)
4. Present results in a readable table
5. Highlight any anomalies or interesting findings
6. Offer to pivot: "Want me to investigate any of these IPs?" etc.

## Example Invocations
- `/fsiem-query all failed logins in the last hour`
- `/fsiem-query traffic from 10.0.0.50 to external IPs today`
- `/fsiem-query firewall denies on port 22 in the last 4 hours`
- `/fsiem-query activity for user jsmith yesterday`
- `/fsiem-query DNS queries to suspicious domains last week`

## Time Parsing
| User says | Window |
|---|---|
| "last hour", "past hour" | Last 1 hour |
| "today", "last 24 hours" | Last 24 hours |
| "this week", "last 7 days" | Last 7 days |
| "yesterday" | Previous calendar day |
| "last month", "30 days" | Last 30 days |
