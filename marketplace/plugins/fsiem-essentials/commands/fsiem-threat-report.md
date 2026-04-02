---
name: fsiem-threat-report
description: Ingest a threat intelligence report, CISA advisory, or vendor blog — extract all ATT&CK techniques, generate FortiSIEM hunt queries for each, extract IOCs for the watchlist, and produce a prioritized action plan. Anton's Day 5 workflow for FortiSIEM. Use when you get a new threat report and need to immediately translate it into defensive action.
---
# Command: /fsiem-threat-report

## Usage
- `/fsiem-threat-report` — paste report text interactively
- `/fsiem-threat-report --url https://cisa.gov/advisory/...` — fetch and analyze
- `/fsiem-threat-report --file report.txt` — analyze local file

## Output
1. **ATT&CK techniques extracted** — explicit IDs + inferred from keywords
2. **Immediate hunt queries** — FortiSIEM XML queries, CRITICAL first
3. **IOC list** — IPs, domains, hashes ready for `/fsiem-ioc`
4. **Data gaps** — techniques with no query because data is missing

## Example
Input: CISA advisory on APT29 campaign
Output:
- 8 techniques identified (T1078, T1059, T1566, T1071, T1003...)
- 6 FortiSIEM hunt queries ready to run
- 12 IOCs for watchlist
- 2 techniques need Sysmon enabled to be detectable
