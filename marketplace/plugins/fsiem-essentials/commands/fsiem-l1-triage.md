---
name: fsiem-l1-triage
description: L1 first-responder alert triage. Load the alert queue, run quick-check signals on each incident, classify as True Positive / False Positive / Benign / Needs More Info, update FortiSIEM status, and generate an end-of-shift handover report. Target under 5 minutes per alert.
---
# Command: /fsiem-l1-triage

## Usage
- `/fsiem-l1-triage` — load queue for last 8h, triage all HIGH+ alerts
- `/fsiem-l1-triage --hours 4` — triage last 4h of alerts
- `/fsiem-l1-triage --id 10432` — triage a single incident
- `/fsiem-l1-triage --report` — generate end-of-shift handover report

## Workflow (per alert)
1. `load_triage_queue()` — fetch open incidents sorted by priority
2. `l1_quick_check(incident)` — evaluate TP/FP signals, compute score, recommend disposition
3. Analyst reviews recommendation + enrichment card
4. `triage_incident(id, disposition, note)` — record decision, update FortiSIEM
5. If TRUE_POSITIVE: immediately run `/fsiem-enrich` on source IPs before escalating

## Dispositions
| Disposition | Action |
|---|---|
| `TRUE_POSITIVE` | Set InProgress, add L2 escalation note, run enrichment |
| `FALSE_POSITIVE` | Set "False Positive", note reason, flag rule for tuning |
| `BENIGN` | Set "Cleared", note authorized activity or change record |
| `NEEDS_MORE_INFO` | Set InProgress, query 10 triggering events, set 2h follow-up |

## SLA Targets
- CRITICAL: acknowledge 5 min, triage 15 min
- HIGH: acknowledge 15 min, triage 30 min
