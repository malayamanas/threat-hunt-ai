---
name: fsiem-playbook
description: Run a step-by-step SOC response playbook for a specific incident type. Includes FortiSIEM queries, decision logic, and containment actions for ransomware, account compromise, data exfiltration, malware, and insider threat.
---
# Command: /fsiem-playbook
# Usage: /fsiem-playbook <incident type or incident ID>

## Behavior
1. Identify playbook type from input:
   - "ransomware" / shadow copy / mass file encryption → Playbook 1
   - "account compromise" / impossible travel / suspicious login → Playbook 2
   - "exfiltration" / large transfer / cloud upload → Playbook 3
   - "malware" / AV alert / suspicious process → Playbook 4
   - "insider" / departing employee / bulk download → Playbook 5
   - Incident ID number → fetch incident, auto-select matching playbook
2. Load the playbook from `skills/playbooks/`
3. Walk through Phase 1 (Confirm) queries first — wait for analyst confirmation
4. Proceed to Phase 2 (Contain) with explicit go/no-go at each action
5. Provide Phase 3 (Eradicate/Recover) steps
6. Output completed Playbook Execution Record

## Example Invocations
- `/fsiem-playbook ransomware`
- `/fsiem-playbook account compromise for user jsmith`
- `/fsiem-playbook 10432` (auto-detect from incident ID)
- `/fsiem-playbook insider threat — departing employee`
