---
name: fsiem-rules
description: Build, deploy, enable, and tune FortiSIEM correlation rules. Use when creating or managing detection rules or MITRE ATT&CK mappings.
---

# FortiSIEM Correlation Rule Engineering

Rules are defined in XML and deployed via the REST API. Each rule has: filters, time window, group-by attributes, count threshold, and incident title.

## Key Functions

- `fsiem_rule_build_brute_force(threshold, window_seconds)` → XML
- `fsiem_rule_build_beaconing(interval_seconds, min_count)` → XML
- `fsiem_rule_build_from_mitre(technique_id)` → XML (T1059, T1110, T1071, T1486, T1078)
- `fsiem_rule_build_from_ioc(ioc_type, ioc_value)` → XML (`"ip"`, `"domain"`, `"hash"`)
- `fsiem_rule_create(rule_xml)` — deploy a rule
- `fsiem_rule_enable(rule_name)` / `fsiem_rule_disable(rule_name)`

## Quick Example

```python
# Deploy brute force detection
xml = fsiem_rule_build_brute_force(threshold=10, window_seconds=300)
fsiem_rule_create(xml)

# Deploy MITRE technique detection
xml = fsiem_rule_build_from_mitre("T1486")
fsiem_rule_create(xml)
```

## Supported MITRE Techniques
`T1059` (Script Exec) | `T1078` (Valid Accounts) | `T1110` (Brute Force) | `T1071` (C2) | `T1486` (Ransomware)

## Additional Resources
- Full rule XML schema and all builder functions: [reference.md](reference.md)
