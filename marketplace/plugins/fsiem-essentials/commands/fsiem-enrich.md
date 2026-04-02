---
name: fsiem-enrich
description: Enrich IPs, domains, and file hashes with external threat intelligence — VirusTotal, AbuseIPDB, Shodan, GeoIP, WHOIS. Returns a verdict (MALICIOUS / SUSPICIOUS / CLEAN / UNKNOWN), risk score, geolocation, ASN, open ports, and known CVEs. Use during L1 triage before escalating, or during L2 investigation for all external IPs.
---
# Command: /fsiem-enrich

## Usage
- `/fsiem-enrich 185.220.101.5` — enrich single IP
- `/fsiem-enrich evil.example.com` — enrich domain (VT + WHOIS + domain age)
- `/fsiem-enrich 44d88612fea8a8f36de82e1278abb02f` — enrich file hash (MD5/SHA1/SHA256)
- `/fsiem-enrich 185.220.101.5 8.8.4.4 evil.com` — enrich multiple indicators at once
- `/fsiem-enrich --incident 10432` — enrich all IPs from a FortiSIEM incident

## Enrichment Sources
| Source | Covers | Requires |
|---|---|---|
| VirusTotal | Malware reputation, detection rate | VT_API_KEY (optional, free tier) |
| AbuseIPDB | Abuse reports, TOR detection, ISP | ABUSEIPDB_API_KEY (optional, free tier) |
| Shodan | Open ports, services, CVEs | SHODAN_API_KEY (optional) |
| ipapi.co | GeoIP, country, org, timezone | None (free) |
| rdap.org | Domain WHOIS, registration date | None (free) |

## Output: Enrichment Card (per indicator)
```
🔴 185.220.101.5 — MALICIOUS (score: 9/10)
  185.220.101.5 [MALICIOUS] | DE Digital Ocean | VT: 12/87 | Abuse: 98%
  📍 Frankfurt, Germany | AS-DIGITALOCEAN-ASN
  🔓 Open ports: [22, 80, 443, 9001, 9030]
  🧅 TOR exit node
  📋 AbuseIPDB: 1,240 reports, 98% confidence
```
