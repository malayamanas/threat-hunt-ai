---
name: fsiem-incidents
description: List and triage FortiSIEM incidents by severity, status, or time range.
---
# Command: /fsiem-incidents
# Usage: /fsiem-incidents [hours_back] [severity] [status]

## Description
Query and triage FortiSIEM incidents. Without arguments, shows all open
HIGH and CRITICAL incidents from the last 24 hours.

## Arguments
- `hours_back` – How many hours back to search (default: 24)
- `severity` – Filter by severity: CRITICAL, HIGH, MEDIUM, LOW (default: all)
- `status` – Filter by status: Active, Cleared, InProgress, False Positive (default: Active)

## Behavior
1. Call `fsiem_get_incidents` with provided filters
2. Sort by severity (CRITICAL first) then by lastOccurred (most recent first)
3. Display a formatted table with columns: ID, Title, Severity, Count, Last Seen, Source IPs
4. For any CRITICAL incidents, automatically fetch detail and show summary
5. Ask: "Which incident would you like to investigate further?"

## Example Output
```
📊 FortiSIEM Incidents (Last 24h | Active | HIGH+)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
ID      │ Severity │ Count │ Title                          │ Last Seen
--------|----------|-------|--------------------------------|------------------
#10432  │ CRITICAL │  847  │ Brute Force: 185.220.101.5     │ 2 minutes ago
#10431  │ HIGH     │   23  │ Lateral Movement Detected      │ 14 minutes ago
#10428  │ HIGH     │    5  │ Possible Data Exfiltration     │ 1 hour ago
#10419  │ MEDIUM   │  102  │ Multiple Failed Logins         │ 3 hours ago

4 incidents found. Type an incident ID to investigate, or ask me anything.
```
