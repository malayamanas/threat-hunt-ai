---
name: fsiem-fp-tune
description: Find and fix false positive rules in FortiSIEM. Identifies the noisiest rules by FP rate, diagnoses root cause (wrong threshold, missing IP exclusion, wrong event scope), applies the fix to the rule XML, and optionally redeploys. Always previews changes before deploying.
---
# Command: /fsiem-fp-tune

## Usage
- `/fsiem-fp-tune report` — show top 10 noisiest rules with FP rates (last 30 days)
- `/fsiem-fp-tune diagnose <rule_id>` — deep-dive one rule: top FP source IPs, users, times
- `/fsiem-fp-tune fix <rule_id>` — preview the fix (dry run, no deploy)
- `/fsiem-fp-tune fix <rule_id> --deploy` — apply and deploy the fix
- `/fsiem-fp-tune all --threshold 60` — fix all rules with FP rate ≥ 60% (preview only)

## How it diagnoses
1. Fetches all incidents marked "False Positive" for the rule
2. Finds the top 3 source IPs, users, and peak hours
3. If top 3 IPs = >70% of FPs → recommends IP exclusion
4. If FPs cluster in specific hours → recommends threshold raise (scheduled job)
5. Otherwise → recommends narrowing event type filter

## Fix types applied automatically
| Problem | Fix |
|---|---|
| Scanner / monitoring tool firing rule | Add `NOT_IN` filter for known-good IPs |
| Service account triggering auth rule | Add `NOT_REGEXP` filter for service accounts |
| Backup job firing at 2am | Raise event count threshold |
| Too many event types matching | Must tune manually (shows guidance) |

**Always use `--deploy` deliberately — default is preview only.**
