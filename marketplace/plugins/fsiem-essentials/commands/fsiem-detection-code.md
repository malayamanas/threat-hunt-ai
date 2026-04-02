---
name: fsiem-detection-code
description: Detection-as-code workflow — export all FortiSIEM rules to version-controlled XML files, track FP rates per rule in a catalog, generate ATT&CK coverage report, and get Atomic Red Team validation guidance. Day 41 of the 50-day program.
---
# Command: /fsiem-detection-code

## Usage
- `/fsiem-detection-code export` — export all active rules to ./rules/ directory
- `/fsiem-detection-code catalog` — generate rule catalog report with FP rates
- `/fsiem-detection-code validate T1110` — Atomic Red Team test guidance for a technique
- `/fsiem-detection-code gaps` — rules missing ATT&CK technique mappings

## Output structure
```
rules/
  catalog.json          — all rules with FP rates, ATT&CK tags, owners
  active/
    T1110_brute_force.xml
    T1059_powershell.xml
    ...
  disabled/
    ...
```

## Atomic Red Team integration
`/fsiem-detection-code validate T1059.001` returns:
- Exact `Invoke-AtomicTest` command to run
- Expected FortiSIEM events after simulation
- Validation query to confirm rule fired
- Pass/fail criteria

## Add to git workflow
```bash
cd fortisiem-ai
/fsiem-detection-code export
git add rules/
git commit -m "Rule export $(date +%Y-%m-%d)"
git push
```
