---
name: fsiem-hypothesis-hunt
description: Run a structured hypothesis-driven threat hunt in FortiSIEM. Provide a hypothesis like "C2 beaconing from internal hosts", a MITRE technique (T1071), or a threat scenario. Produces a full hunt report with findings and rule recommendations.
---
# Command: /fsiem-hypothesis-hunt
# Usage: /fsiem-hypothesis-hunt <hypothesis or threat scenario>

## Behavior
1. Restate the input as a formal hypothesis (who, behavior, timeframe)
2. Map to MITRE ATT&CK technique and FortiSIEM event types
3. Execute the appropriate queries from `skills/hypothesis_hunting/`
4. Score findings using the evidence rubric
5. Produce structured hunt report with findings, MITRE mapping, and rule recommendations

## Example Invocations
- `/fsiem-hypothesis-hunt there may be C2 beaconing from our network`
- `/fsiem-hypothesis-hunt T1486 ransomware indicators`
- `/fsiem-hypothesis-hunt lateral movement via SMB last 30 days`
- `/fsiem-hypothesis-hunt unusual outbound DNS traffic`
- `/fsiem-hypothesis-hunt credential dumping on domain controllers`
