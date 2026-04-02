---
name: fsiem-compliance
description: Run FortiSIEM compliance reports for PCI DSS, HIPAA, SOX, NIST, ISO 27001. List available reports, execute them, and export results for audit evidence.
---
# Command: /fsiem-compliance
# Usage: /fsiem-compliance <framework> [time_window]

## Examples
- `/fsiem-compliance PCI` — list and run all PCI DSS reports (last 30 days)
- `/fsiem-compliance HIPAA 90 days` — HIPAA evidence package for 90 days
- `/fsiem-compliance list` — show all available compliance reports
- `/fsiem-compliance SOX` — SOX IT controls evidence
