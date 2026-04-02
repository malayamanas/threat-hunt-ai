# Demo Walkthroughs

Real-world scenarios showing what this plugin does step by step. Each walkthrough shows the command, what happens behind the scenes, and the output you get.

---

## Demo 1: Morning Shift — L1 Triage in 10 Minutes

**Scenario:** You're starting your SOC shift. There are 23 open alerts.

```
> /fsiem-l1-triage
```

**What happens behind the scenes:**
1. Pulls all open incidents from FortiSIEM (last 24 hours)
2. For each incident, runs quick-check signals:
   - Checks the rule's historical false positive rate (30-day window)
   - Looks up the source IP in VirusTotal / AbuseIPDB
   - Checks the target asset's criticality in CMDB
   - Checks if the same rule fired on the same source before
3. Classifies each as: True Positive / False Positive / Benign / Needs Escalation
4. Updates FortiSIEM incident status for clear-cut cases
5. Generates a shift handover report

**Output:**
```
L1 Triage Report — 23 incidents processed
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

TRUE POSITIVE (3) — Escalate to L2
  #10432  HIGH  Brute force SSH from 45.33.32.156 → 10.0.1.5
          VT: 12/88 | AbuseIPDB: 94% | Rule FP rate: 8%
  #10445  HIGH  Malware detected on WS-142 (Trojan.PS1.Agent)
          Trend Micro XDR confirmed | Asset: Finance workstation
  #10451  MED   CyberArk bulk password retrieval (47 passwords in 3 min)
          Unusual volume | Source: 10.0.5.22 (not a known PAM admin)

FALSE POSITIVE (14) — Auto-closed
  #10433-#10446  Windows Agent Reporting Device List (rule FP rate: 97%)

BENIGN (4) — Closed with context
  #10448  Password resets by svc_sync (known service account, normal pattern)
  #10449  Add computer to DC (scheduled deployment window)
  ...

NEEDS ESCALATION (2) — Requires L2
  #10450  Inbound from malicious IP — flow PERMITTED (needs firewall review)
  #10452  Multiple new user accounts created on DC (off-hours)

Shift handover saved to: /tmp/fsiem_reports/shift_handover_20260401.md
```

**Time: 5 minutes** (vs 60+ minutes manually)

---

## Demo 2: Hypothesis Hunt — "Is There C2 in Our Network?"

**Scenario:** Threat intel report mentions a new campaign using DNS tunneling for C2. You want to check your environment.

```
> /fsiem-hypothesis-hunt "C2 beaconing via DNS tunneling — 
  look for high-entropy subdomains, unusual DNS query volume, 
  and periodic beacon patterns"
```

**What happens:**
1. Structures the hypothesis formally
2. Maps to MITRE ATT&CK: T1071.004 (DNS C2), T1568 (Dynamic Resolution)
3. Designs 4 FortiSIEM queries:
   - DNS query volume by source (find hosts making 10x+ normal DNS queries)
   - Long subdomain analysis (entropy > 3.5 = possible encoding)
   - Beacon periodicity (coefficient of variation < 0.2 = regular interval)
   - Queries to non-corporate DNS resolvers
4. Runs all queries against last 7 days of data
5. Analyzes results and produces a hunt report

**Output:**
```
Hypothesis Hunt Report
━━━━━━━━━━━━━━━━━━━━━

Hypothesis: C2 beaconing via DNS tunneling
Status: PARTIALLY CONFIRMED
MITRE: T1071.004, T1568.002

Query 1 — DNS Volume Anomaly
  3 hosts making >5,000 DNS queries/day (baseline: 200-400)
  10.0.3.42  →  12,847 queries (32x baseline)
  10.0.3.55  →  8,211 queries (20x baseline)  
  10.0.1.18  →  6,503 queries (16x baseline)

Query 2 — High-Entropy Subdomains
  10.0.3.42 querying: a3f8d2e1b7c4.update.example-cdn.com (entropy: 4.1)
  Pattern: 12-char hex prefix, rotating every 30 seconds
  Domain: example-cdn.com — NOT in Alexa top 1M, registered 3 days ago

Query 3 — Beacon Periodicity
  10.0.3.42 → example-cdn.com: CV = 0.08 (highly periodic, every 30s)
  This is textbook C2 beaconing behavior.

Query 4 — External DNS
  10.0.3.42 using 8.8.8.8 directly (bypassing corporate DNS)
  Other 2 hosts using corporate DNS — may be false positive (CNAME chains)

CONFIRMED FINDING:
  Host 10.0.3.42 is beaconing to example-cdn.com via DNS tunneling
  Beacon interval: 30 seconds | Data encoding: hex in subdomain
  Domain registered: 3 days ago | No legitimate business purpose

SUSPICIOUS:
  Hosts 10.0.3.55 and 10.0.1.18 have elevated DNS volume but no
  clear encoding pattern — may be legitimate (CDN, telemetry)

RECOMMENDED ACTIONS:
  1. Isolate 10.0.3.42 immediately
  2. Block example-cdn.com at DNS firewall
  3. Check 10.0.3.42 for persistence mechanisms
  4. Create detection rule: /fsiem-rule-create DNS beacon to newly 
     registered domains with periodic query pattern
```

**Time: 20 minutes** (vs 4+ hours manually)

---

## Demo 3: Detection Rule from Plain English

**Scenario:** After the hunt, you want a permanent detection rule.

```
> /fsiem-rule-create alert when any internal host makes more than 
  1000 DNS queries to a single external domain in 10 minutes
```

**What happens:**
1. Parses the requirement into rule logic
2. Maps to MITRE ATT&CK: T1071.004 (Application Layer Protocol: DNS)
3. Generates FortiSIEM correlation rule XML with:
   - Event filter: DNS query events
   - Aggregation: group by source IP + destination domain
   - Threshold: count > 1000
   - Window: 10 minutes
4. Validates XML syntax
5. Tests against historical data (last 7 days)
6. Shows results and asks for deployment confirmation

**Output:**
```
Detection Rule Design
━━━━━━━━━━━━━━━━━━━━

Name: DNS Query Flood to Single Domain
MITRE: T1071.004 — Application Layer Protocol: DNS
Severity: HIGH
Trigger: >1000 DNS queries from single host to single domain in 10 min

Generated Rule XML: [92 lines, validated ✓]

Historical Test (last 7 days):
  Would have fired 4 times:
  - 10.0.3.42 → example-cdn.com (12,847 queries) ← your confirmed C2
  - 10.0.5.11 → windowsupdate.com (3,200 queries) ← legitimate Windows Update
  - 10.0.5.11 → officeapps.live.com (2,100 queries) ← legitimate O365
  - 10.0.2.8 → cdn.jsdelivr.net (1,400 queries) ← legitimate CDN

Estimated FP rate: ~60% from Windows Update / O365 / CDN traffic
Recommendation: Add exclusion list for known legitimate domains

Deploy with exclusions? [y/N]
```

---

## Demo 4: Full Incident Investigation

**Scenario:** L1 escalated incident #10432 — brute force SSH. You need the full picture.

```
> /fsiem-l2-investigate 10432
```

**What happens:**
1. Pulls incident details and triggering events
2. Builds a timeline from raw events (auth logs, firewall logs, DNS)
3. Enriches all external IPs (VirusTotal, AbuseIPDB, Shodan, GeoIP, WHOIS)
4. Maps blast radius (what else did the attacker touch?)
5. Checks for lateral movement from compromised host
6. Produces a structured investigation report

**Output:**
```
L2 Investigation Report — Incident #10432
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

SUMMARY: Successful brute force SSH followed by lateral movement

TIMELINE:
  02:10  45.33.32.156 → 10.0.1.5:22  SSH brute force begins (47 attempts)
  02:14  45.33.32.156 → 10.0.1.5:22  Login SUCCESS as svc_backup
  02:15  10.0.1.5 → 8.8.8.8:53       DNS query for pastebin.com
  02:16  10.0.1.5 → 10.0.1.10:445    SMB connection to file server
  02:17  10.0.1.5 → 10.0.1.10        File access: \\shares\finance\*.xlsx
  02:22  10.0.1.5 → 45.33.32.156     Outbound HTTPS (2.1 MB transferred)

ENRICHMENT:
  45.33.32.156: Linode VPS, US | VT: 14/88 | AbuseIPDB: 94% | Shodan: SSH open

BLAST RADIUS:
  Compromised: 10.0.1.5 (svc_backup account)
  Accessed: 10.0.1.10 (file server, finance share)
  Data exfiltrated: ~2.1 MB via HTTPS to attacker IP

MITRE ATT&CK:
  T1110.001 → T1021.002 → T1083 → T1041
  (Brute Force → SMB Lateral → File Discovery → Exfiltration over C2)

RECOMMENDED ACTIONS:
  1. Disable svc_backup account immediately
  2. Block 45.33.32.156 at perimeter firewall
  3. Isolate 10.0.1.5 for forensic imaging
  4. Audit all files accessed on 10.0.1.10
  5. Check if svc_backup credentials are used elsewhere
  6. Reset all service account passwords
```

**Time: 15 minutes** (vs 3+ hours manually)

---

## Demo 5: Multi-Org MSSP Sweep

**Scenario:** You manage 50 organizations. A new CVE dropped and you need to check all tenants.

```
> /fsiem-multiorg hunt 185.220.101.5 across all organizations
```

**Output:**
```
Multi-Org IOC Sweep — 185.220.101.5
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Scanning 50 organizations...

HITS FOUND (3 orgs):
  Org: AcmeBank.org     | 12 events | Last seen: 2h ago | Inbound SSH
  Org: GlobalTech.org   | 3 events  | Last seen: 6h ago | Inbound HTTPS  
  Org: MedGroup.org     | 1 event   | Last seen: 4d ago | Blocked by FW

NO HITS (47 orgs): [all clear]

Priority actions:
  1. AcmeBank.org — active inbound SSH, investigate immediately
  2. GlobalTech.org — recent HTTPS, check if connection was permitted
  3. MedGroup.org — blocked, no action needed (firewall working)
```

---

## Demo 6: APT Group Hunt

**Scenario:** Threat intel says APT29 (Cozy Bear) is targeting your sector.

```
> /fsiem-apt-hunt APT29
```

**Output:**
```
APT29 (Cozy Bear / Nobelium) Hunt
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Running 8 hunt queries based on known APT29 TTPs...

Query 1: WMI remote execution (T1047)
  0 hits ✓

Query 2: Scheduled task creation via schtasks.exe (T1053.005)
  2 hits — both from SCCM (legitimate, excluded)

Query 3: DLL side-loading in C:\ProgramData (T1574.002)
  0 hits ✓

Query 4: OAuth token theft via device code phishing (T1528)
  1 HIT — user m.johnson, Azure AD device code auth from unmanaged device
  ⚠️  Requires investigation

Query 5: Cobalt Strike beacon indicators (T1071.001)
  0 hits ✓

Query 6: Golden SAML / ADFS token forgery (T1606.002)
  0 hits ✓

Query 7: SolarWinds-style supply chain (T1195.002)
  0 hits ✓

Query 8: EnvyScout HTML smuggling (T1027.006)
  0 hits ✓

RESULT: 1 suspicious finding requires investigation
  Priority: Investigate OAuth device code auth for m.johnson
  Context: APT29 is known to use device code phishing for initial access
  Next step: /fsiem-ueba m.johnson
```

---

## What's Next?

- [INSTALL.md](INSTALL.md) — Full installation guide
- [examples/quick-start.md](examples/quick-start.md) — More command examples
- [ARCHITECTURE.md](ARCHITECTURE.md) — How it works under the hood
- [CONTRIBUTING.md](CONTRIBUTING.md) — Add your own skills and hunts
