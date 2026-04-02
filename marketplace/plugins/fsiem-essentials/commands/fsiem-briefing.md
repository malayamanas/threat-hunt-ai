---
name: fsiem-briefing
description: Generate a daily security briefing from FortiSIEM data — Active Directory events, authentication anomalies, privileged account activity, and overnight incidents. Adapted from Anton Ovrutsky's Day 8 workflow for FortiSIEM. Run at session start or on demand for a situational awareness snapshot.
---
# Command: /fsiem-briefing

## Usage
- `/fsiem-briefing` — today's security briefing (last 24h)
- `/fsiem-briefing --hours 8` — last 8h (overnight briefing)
- `/fsiem-briefing --focus ad` — AD-only briefing
- `/fsiem-briefing --focus auth` — authentication anomalies
- `/fsiem-briefing --focus incidents` — incident summary

## What it covers
**AD Security** (T1136, T1098, T1078):
- New accounts created/deleted
- Group membership changes (especially Domain Admins)
- Admin account logons outside business hours

**Authentication** (T1110, T1078):
- Accounts with > threshold failed logins
- Successful logins from new countries/IPs
- Service accounts logging in interactively

**Privileged Activity** (T1078.002):
- Admin tool usage by non-admin accounts
- Pass-the-hash indicators (Type 3 logon, no prior 4776)
- Privilege use events (4672)

**Overnight Incidents**:
- CRITICAL/HIGH incidents opened while off shift
- Status changes on open investigations

## As a session hook
Add to your morning routine — run `/fsiem-briefing` before `/fsiem-l1-triage`.
You'll know what happened overnight before you start clearing the queue.
