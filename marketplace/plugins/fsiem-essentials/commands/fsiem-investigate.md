---
name: fsiem-investigate
description: Create a complete structured SOC investigation record for a FortiSIEM incident.
---
# Command: /fsiem-investigate
# Usage: /fsiem-investigate <incident_id>

## Description
Create a complete structured investigation record for a FortiSIEM incident.
Automatically gathers all context, enriches with CMDB data, hunts for related
activity, and produces a report ready for ticketing or escalation.

## Workflow

1. Run `fsiem_investigate_incident(incident_id)` from `skills/investigation.md`
2. Display the structured investigation record:
   - Incident summary (title, severity, category, rule triggered)
   - Scope (source IPs, destination IPs, affected users, event count)
   - Asset inventory (CMDB enrichment for all involved IPs)
   - Event timeline (first 50 events, sorted by time)
   - Threat hunt results (7-day lookback on primary source IP)
3. Generate and display the executive summary
4. Ask the analyst:
   - "Is this a True Positive, False Positive, or Benign/Expected?"
5. Based on answer:
   - **True Positive** → suggest remediation steps, offer to update incident status to `InProgress`, create ticket notes
   - **False Positive** → offer to mark incident as `False Positive` with a comment, suggest rule tuning
   - **Benign** → offer to mark as `Cleared` with explanation

## Example Invocations
- `/fsiem-investigate 10432`
- `/fsiem-investigate INC-2024-0042`
