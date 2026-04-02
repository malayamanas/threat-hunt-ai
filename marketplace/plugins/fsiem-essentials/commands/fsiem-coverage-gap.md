---
name: fsiem-coverage-gap
description: Analyze FortiSIEM detection rule coverage against MITRE ATT&CK. Shows which techniques are covered, which are gaps, and generates a prioritized detection engineering backlog. Use for quarterly coverage reviews, CISO reporting, or to decide what rules to build next.
---
# Command: /fsiem-coverage-gap

## Usage
- `/fsiem-coverage-gap` — full gap report (gaps only, prioritized)
- `/fsiem-coverage-gap --full` — include covered techniques too
- `/fsiem-coverage-gap --score` — quick coverage score KPI (for dashboard)
- `/fsiem-coverage-gap --critical` — only show CRITICAL gaps (fast)

## Output
```
MITRE ATT&CK Coverage: 14/25 techniques (56%) — Grade: C

🔴 Critical Gaps (6):
  T1486 Ransomware — no rule covering shadow copy deletion
  T1003 Credential Dumping — no rule covering lsass access
  ...

Detection Engineering Backlog (25 items, priority-ordered):
  1. CRITICAL T1486 — keywords: shadow copy, vssadmin, wbadmin
  2. CRITICAL T1003 — keywords: lsass, mimikatz, procdump
  ...
```

## After running
Feed the backlog directly to `/fsiem-rule-create` — it reads the technique ID and builds the rule automatically.
