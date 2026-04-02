---
name: fsiem-ueba
description: Run User and Entity Behavior Analytics for a user or host in FortiSIEM. Builds a 30-day baseline and detects anomalous logins, off-hours activity, new resource access, and statistical volume outliers. Produces a risk score and action recommendation.
---
# Command: /fsiem-ueba
# Usage: /fsiem-ueba <username or host IP>

## Behavior
1. Detect input: username or IP address
2. Query 30-day baseline events from FortiSIEM
3. Query last 7 days recent events
4. Run full `run_ueba_investigation()` from `skills/ueba/`:
   - Login baseline (known IPs, typical hours)
   - Login anomaly detection (new IP, unusual time)
   - Off-hours activity flagging
   - First-time resource access detection
   - Statistical volume anomaly (Z-score)
5. Output risk score (LOW/MEDIUM/HIGH) with evidence for each signal
6. Recommend: no action / monitor / escalate to Tier 2

## Example Invocations
- `/fsiem-ueba jsmith`
- `/fsiem-ueba DOMAIN\administrator`
- `/fsiem-ueba 10.0.0.50`
- `/fsiem-ueba svc_backup` (service account abuse check)
