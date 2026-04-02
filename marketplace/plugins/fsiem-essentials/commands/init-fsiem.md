---
name: init-fsiem
description: Initialize the FortiSIEM AI session. Run this first to verify connectivity, confirm environment variables are set, and display the full command menu.
---
# Command: /init-fsiem

## Behavior
1. Verify required env vars: FSIEM_HOST, FSIEM_USER, FSIEM_PASS, FSIEM_ORG
2. Test connectivity: GET /phoenix/rest/config/Domain
3. Print session summary with full command menu

## Session Summary Output
```
✅ FortiSIEM AI Ready
Host : {FSIEM_HOST}
Org  : {FSIEM_ORG}
User : {FSIEM_USER}

── L1 Triage ──────────────────────────────────────
  /fsiem-l1-triage       Alert queue triage (L1 first-responder)
  /fsiem-incidents        List/filter raw incidents
  /fsiem-enrich           Enrich IP/domain/hash with threat intel

── L2 Investigation ───────────────────────────────
  /fsiem-l2-investigate   Deep incident investigation (L2)
  /fsiem-investigate      Investigation records and reports
  /fsiem-playbook         IR playbook (ransomware/compromise/exfil/malware/insider)
  /fsiem-ticket           Escalate to ServiceNow/Jira/PagerDuty

── L3 Threat Hunting ──────────────────────────────
  /fsiem-l3-hunt          Advanced hunt / threat intel (L3, APT analysis)
  /fsiem-hunt             Quick IOC or MITRE technique hunt
  /fsiem-hypothesis-hunt  Structured hypothesis-driven hunt
  /fsiem-ioc              Extract and hunt IOCs from threat report
  /fsiem-ueba             Behavioral analysis for user or entity

── Detection Engineering ──────────────────────────
  /fsiem-rule-create      Design and deploy correlation rule
  /fsiem-rules            List, enable, disable, tune rules

── Event & Asset Operations ───────────────────────
  /fsiem-query            Event query in plain English
  /fsiem-cmdb             Device inventory or discovery
  /fsiem-report           Org health and incident summary report

── Reporting ──────────────────────────────────────
  /fsiem-report-generate  Executive / daily / shift / hunt reports
  /fsiem-compliance       Compliance reports (PCI/HIPAA/SOX/NIST)

── Operations & Detection Quality ─────────────────────
  /fsiem-health           Parser health, silent devices, collector status
  /fsiem-fp-tune          Find and fix false positive rules
  /fsiem-coverage-gap     ATT&CK coverage gaps and rule backlog

── MSSP / Multi-Org ───────────────────────────────
  /fsiem-multiorg         Sweep all organizations

  Type a command or describe what you need in plain language.
```
