---
name: fsiem-advanced-hunt
description: Run advanced mathematical threat hunting — beacon analysis using coefficient of variation math, DNS long-tail subdomain analysis, stack counting for rare process detection, impossible travel credential anomaly, and Office application process tree hunting. Week 4 techniques that find what keyword rules cannot.
---
# Command: /fsiem-advanced-hunt

## Usage
- `/fsiem-advanced-hunt` — run all 5 techniques, combined report (last 7 days)
- `/fsiem-advanced-hunt beacon` — beacon detection (CV analysis, jitter-aware)
- `/fsiem-advanced-hunt dns` — DNS long-tail subdomain analysis
- `/fsiem-advanced-hunt stack` — stack count rare processes (bottom 1%)
- `/fsiem-advanced-hunt travel` — impossible travel / new country logins
- `/fsiem-advanced-hunt office` — Office spawning shells (T1566→T1059)
- `/fsiem-advanced-hunt --days 14` — extend lookback

## What each technique finds
- **Beacon**: C2 implants with regular check-in intervals. CV < 0.4 = suspicious. Jitter-aware so it catches Cobalt Strike's default 20% jitter.
- **DNS**: Tunneling tools (dnscat2, iodine) using subdomains as data channel. Average subdomain length > 25 chars = investigate.
- **Stack**: Malware hiding as processes that run on 1-2 machines. Legitimate software appears on many machines.
- **Travel**: Valid credentials used from a country never seen in the account's 30-day baseline.
- **Office**: Word/Excel/Outlook spawning cmd.exe or PowerShell = active phishing exploitation.
