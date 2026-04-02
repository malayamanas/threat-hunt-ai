---
name: fsiem-auto-triage
description: Run autonomous alert triage — closes confirmed false positives and escalates confirmed true positives without analyst involvement. Only acts when ALL three signals agree (rule FP rate ≥95%, asset criticality LOW, no threat intel hit for auto-close; or MALICIOUS IP on HIGH/CRITICAL asset for auto-escalate). Everything else goes to the analyst queue pre-scored. Always runs dry-run first.
---
# Command: /fsiem-auto-triage

## Usage
- `/fsiem-auto-triage` — dry run: shows what WOULD happen, writes nothing
- `/fsiem-auto-triage --live` — execute: writes decisions to FortiSIEM
- `/fsiem-auto-triage --hours 4` — process last 4h of alerts (default: 8h)
- `/fsiem-auto-triage --report` — show last run summary

## Decision logic (all 3 signals must agree)

**AUTO-CLOSE** (writes "False Positive" to FortiSIEM):
- Rule FP rate ≥ 95% with HIGH confidence (≥20 historical incidents)
- AND asset criticality = LOW (dev/test/lab/sandbox)
- AND source IP enrichment = CLEAN or UNKNOWN (no threat intel hit)

**AUTO-ESCALATE** (writes "InProgress" + L2 note):
- Source IP enrichment = MALICIOUS AND asset = HIGH or CRITICAL
- OR TP keyword score ≥ 8 AND asset = CRITICAL

**ANALYST QUEUE** (everything else — pre-scored, not acted on):
- Any uncertain signal routes here
- Analyst sees: asset criticality, rule FP rate, enrichment verdict, recommendation

## Audit trail
Every autonomous decision writes a `[AUTO-TRIAGE]` comment to the FortiSIEM incident with the full reasoning chain — rule FP rate, asset level, enrichment verdict. Nothing is a black box.

## Safe to run
Default is always dry-run. Use `--live` deliberately. A silent firewall or DC will NEVER be auto-closed regardless of rule FP rate.
