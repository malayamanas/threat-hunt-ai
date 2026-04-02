---
name: fsiem-hunt
description: Hunt for a threat indicator: IP, domain, hash, username, MITRE technique, or paste a threat report.
---
# Command: /fsiem-hunt
# Usage: /fsiem-hunt <IOC or threat description>

## Description
Hunt for threats in FortiSIEM. Accepts IPs, domains, file hashes, usernames,
MITRE technique IDs, or a pasted threat report.

## Behavior
1. Detect what type of input was provided:
   - IP address → `fsiem_hunt_ip`
   - Domain name → `fsiem_hunt_domain`
   - MD5/SHA256 hash → search rawEventMsg
   - Username → `fsiem_hunt_user`
   - MITRE ID (e.g. T1110) → `fsiem_hunt_mitre_technique`
   - Long text (>200 chars) → `fsiem_hunt_from_report` (extract all IOCs)
   - Multiple values → `fsiem_hunt_ioc_list`
2. Execute the hunt across the last 30 days
3. Report: what was found, which internal hosts were involved, timeline of activity
4. Recommend next steps

## Example Invocations
- `/fsiem-hunt 185.220.101.5`
- `/fsiem-hunt malicious-domain.com`
- `/fsiem-hunt T1486`
- `/fsiem-hunt [paste threat report text here]`
- `/fsiem-hunt 192.168.1.50 192.168.1.51 192.168.1.52`
