<p align="center">
  <h1 align="center">Hunt with FortiSIEM</h1>
  <p align="center">
    <strong>AI-powered threat hunting, incident response, and detection engineering for FortiSIEM</strong>
  </p>
  <p align="center">
    <a href="LICENSE"><img src="https://img.shields.io/badge/License-Apache%202.0-blue.svg" alt="License"></a>
    <a href="CHANGELOG.md"><img src="https://img.shields.io/badge/version-2.0.0-green.svg" alt="Version"></a>
    <img src="https://img.shields.io/badge/FortiSIEM-7.x-orange.svg" alt="FortiSIEM">
    <img src="https://img.shields.io/badge/Python-3.9%2B-blue.svg" alt="Python">
    <img src="https://img.shields.io/badge/Skills-30%2B-purple.svg" alt="Skills">
    <img src="https://img.shields.io/badge/Commands-31-yellow.svg" alt="Commands">
  </p>
</p>

---

**SOC analysts spend 80% of their time writing XML queries, copy-pasting IPs into threat intel tools, and manually correlating events across tabs.** This plugin changes that.

Describe what you're looking for in plain English. The AI writes the FortiSIEM queries, runs them, correlates the results, enriches indicators, and gives you an answer — not just data.

### Before vs After

| Task | Without this plugin | With this plugin |
|------|-------------------|-----------------|
| Hunt for an IOC across 30 days | Write XML query, submit, poll, parse XML, check VirusTotal, check AbuseIPDB, check Shodan, write up findings — **45 min** | `/fsiem-hunt 185.220.101.5` — **3 min** |
| Triage 20 alerts | Open each, check source IP, check dest IP, check user, check rule FP rate, update status — **60 min** | `/fsiem-l1-triage` — **5 min** |
| Build a detection rule | Research MITRE technique, write XML, test, tune, deploy — **2 hours** | `/fsiem-rule-create detect DCSync from non-machine accounts` — **10 min** |
| Investigate an incident | Pull events, build timeline, enrich IPs, map blast radius, write report — **3 hours** | `/fsiem-l2-investigate 12345` — **15 min** |
| Hypothesis hunt | Design queries, run them, analyze, document — **4 hours** | `/fsiem-hypothesis-hunt "C2 beaconing via DNS tunneling"` — **20 min** |

---

## What's Inside

- **31 slash commands** — every SOC workflow, one command away
- **30+ skills** — deep domain knowledge the AI uses to reason about your SIEM data
- **3 specialized agents** — L1/L2 SOC analyst, detection engineer, L3 threat hunter
- **5 IR playbooks** — ransomware, account compromise, data exfiltration, malware, insider threat
- **15 rule templates** — production-ready correlation rules with MITRE ATT&CK mapping
- **6 APT profiles** — ready-to-run hunts for APT28, APT29, Lazarus, FIN7, Sandworm, APT41
- **Multi-org / MSSP** — sweep all tenants in one command

---

## Get Started in 2 Minutes

```bash
# 1. Clone
git clone https://github.com/threat-hunt-ai/threat-hunt-ai.git

# 2. Set credentials
export FSIEM_HOST="https://your-fortisiem-host"
export FSIEM_USER="admin"
export FSIEM_PASS="yourpassword"
export FSIEM_ORG="super"

# 3. Install plugin
/plugin marketplace add /path/to/fortisiem-ai/marketplace
/plugin install fsiem-essentials@fsiem-marketplace

# 4. Go
/init-fsiem
```

See [INSTALL.md](INSTALL.md) for detailed setup, Docker installation, and credential persistence.

> **Want to see what it looks like in action?** Check out [DEMO.md](DEMO.md) for 6 real-world walkthroughs with full output examples.

---

## Real-World Scenarios

### Scenario 1: "Is this IP malicious?"

```
> /fsiem-hunt 185.220.101.5

Searching FortiSIEM for 185.220.101.5...

  Found 47 events across 3 devices in the last 7 days
  Enrichment: VirusTotal 14/88 detections | AbuseIPDB 98% confidence | Tor exit node
  
  Timeline:
  Mar 28 02:14  →  Inbound SSH to 10.0.1.5 (PERMITTED)
  Mar 28 02:14  →  Failed login as root (4 attempts)
  Mar 28 02:15  →  Successful login as svc_backup
  Mar 28 02:17  →  Outbound DNS to 8.8.8.8 (unusual for this host)
  
  Verdict: HIGH RISK — Tor exit node achieved access via brute force on svc_backup.
  Recommended: Isolate 10.0.1.5, disable svc_backup, check for persistence.
```

### Scenario 2: "Hunt for ransomware indicators"

```
> /fsiem-hypothesis-hunt "Ransomware precursors: shadow copy deletion, 
  mass file rename, or encryption tool command lines"

Hypothesis Hunt Report
━━━━━━━━━━━━━━━━━━━━━

Hypothesis: Ransomware precursors active in environment
MITRE Techniques: T1486, T1490, T1059.001

Queries executed: 5
Events analyzed: 1,247

FINDING 1 — CONFIRMED
  Host: FILE-SRV-03  |  User: admin_jsmith
  vssadmin.exe delete shadows /all /quiet
  Followed by: rename of 340 files in \\shares\finance\ within 8 minutes
  
FINDING 2 — SUSPICIOUS  
  Host: WS-142  |  Process: powershell.exe -enc <base64>
  Decoded: Invoke-WebRequest to external IP, downloads payload to %TEMP%

Verdict: Active ransomware engagement on FILE-SRV-03. WS-142 may be initial access.
Playbook: /fsiem-playbook ransomware
```

### Scenario 3: "Is this user compromised?"

```
> /fsiem-ueba john.doe

UEBA Analysis — john.doe (30-day baseline)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Risk Score: 87/100 (HIGH)

ANOMALY 1: Off-hours VPN login
  Baseline: Logs in Mon-Fri 08:00-18:00 IST
  Today: Login at 03:14 IST from IP in Moldova (79.140.x.x)
  
ANOMALY 2: First-time resource access
  Accessed \\dc01\SYSVOL (never accessed before in 30 days)
  Accessed CyberArk vault (never accessed before)

ANOMALY 3: Volume spike
  Outbound data: 2.4 GB (baseline average: 120 MB/day)
  
Verdict: Account likely compromised. Login from unusual geo + first-time 
privileged access + data volume spike = classic credential theft pattern.
```

### Scenario 4: "Build me a detection rule"

```
> /fsiem-rule-create alert when a single source IP fails login 
  more than 10 times in 5 minutes on any Windows host

Designing correlation rule...

Rule: Brute Force Login — Windows (10 failures / 5 min)
MITRE: T1110.001 — Password Guessing
Severity: HIGH

Generated XML: [validated ✓]
Historical test: 3 matches in last 7 days (2 from known scanner, 1 from 
  internal IP 10.0.5.22 → investigate)
False positive rate: ~15% (scanner IPs)

Recommendation: Deploy with scanner IP exclusion list.
Deploy now? [y/N]
```

---

## Full Command Reference

### Threat Hunting
| Command | What it does |
|---|---|
| `/fsiem-hunt <IP\|domain\|hash\|user\|technique>` | Quick hunt for any indicator |
| `/fsiem-hypothesis-hunt "<hypothesis>"` | Structured hunt with formal report |
| `/fsiem-advanced-hunt beacon <subnet>` | Detect C2 beaconing via statistical analysis |
| `/fsiem-advanced-hunt dns-longtail` | Find DGA/tunneling via DNS entropy analysis |
| `/fsiem-advanced-hunt stacking processes` | Rare process detection via stack counting |
| `/fsiem-advanced-hunt impossible-travel` | Credential anomaly via geolocation |
| `/fsiem-apt-hunt <group>` | Hunt for APT28, APT29, Lazarus, FIN7, Sandworm, APT41 |
| `/fsiem-threat-report <URL or text>` | Ingest threat intel report, auto-hunt all IOCs |
| `/fsiem-ioc <indicator list>` | Bulk IOC hunt |
| `/fsiem-attack-datasources T1110` | Check if you have the data sources to detect a technique |

### Incident Response
| Command | What it does |
|---|---|
| `/fsiem-l1-triage` | Process alert queue — classify, enrich, handover |
| `/fsiem-l2-investigate <incident_id>` | Full investigation — timeline, blast radius, report |
| `/fsiem-l3-hunt` | Proactive hunt with Diamond Model and ATT&CK mapping |
| `/fsiem-playbook ransomware` | Step-by-step ransomware response |
| `/fsiem-playbook account-compromise` | Account takeover response |
| `/fsiem-playbook data-exfiltration` | Data theft response |
| `/fsiem-playbook malware` | Malware containment response |
| `/fsiem-playbook insider-threat` | Insider threat investigation |
| `/fsiem-investigate <incident_id>` | Create structured investigation record |
| `/fsiem-ticket` | Create ticket in ServiceNow / Jira / PagerDuty |

### Detection Engineering
| Command | What it does |
|---|---|
| `/fsiem-rule-create <description>` | Design and deploy a correlation rule |
| `/fsiem-rules list` | List all active correlation rules |
| `/fsiem-rules enable\|disable "<name>"` | Toggle rules |
| `/fsiem-fp-tune` | Find and fix false positive rules |
| `/fsiem-coverage-gap` | MITRE ATT&CK coverage gap analysis |
| `/fsiem-detection-code` | Export rules as version-controlled XML |

### Daily Operations
| Command | What it does |
|---|---|
| `/fsiem-incidents` | List open incidents by severity |
| `/fsiem-query <plain English>` | Event query without writing XML |
| `/fsiem-enrich <IP\|domain\|hash>` | Threat intel enrichment (VT, AbuseIPDB, Shodan, GeoIP) |
| `/fsiem-briefing` | Daily security briefing |
| `/fsiem-ueba <user\|host>` | Behavioral analytics with 30-day baseline |
| `/fsiem-health` | Parser health, silent devices, collector status |
| `/fsiem-cmdb <IP\|hostname>` | Device inventory lookup |
| `/fsiem-auto-triage` | Autonomous TP/FP classification |

### Reporting & Compliance
| Command | What it does |
|---|---|
| `/fsiem-report-generate executive` | CISO/management KPI report |
| `/fsiem-report-generate daily` | Daily operations report |
| `/fsiem-report-generate shift` | Shift handover |
| `/fsiem-compliance PCI\|HIPAA\|NIST\|ISO\|SOX` | Compliance report |
| `/fsiem-multiorg sweep` | All-tenant sweep (MSSP) |

---

## Specialized AI Agents

Three purpose-built agents that don't just run commands — they **think**, correlate, and reason like experienced security professionals.

### SOC Analyst Agent (`fsiem-analyst`)
**Your L1/L2 analyst that never sleeps.** Triages the alert queue, runs quick-check enrichment on every indicator, classifies incidents as TP/FP/Benign, escalates to L2 when needed, and builds full investigation reports with attack timelines, blast radius, and remediation steps. Handles the complete L1 > L2 lifecycle — from first alert to signed-off investigation.

```
/fsiem-l1-triage              → Agent processes 20+ alerts in minutes
/fsiem-l2-investigate 10432   → Agent builds complete attack narrative
```

### Detection Engineer Agent (`fsiem-rule-engineer`)
**Turns attack patterns into detection rules.** Analyzes TTPs, designs FortiSIEM XML correlation rules from plain English, tests them against historical data before deployment, tunes noisy rules by diagnosing FP root causes, and maps your rule library against MITRE ATT&CK to find coverage gaps.

```
/fsiem-rule-create detect credential dumping via DCSync
/fsiem-fp-tune                → Agent finds noisiest rules and fixes them
/fsiem-coverage-gap           → Agent maps gaps to MITRE ATT&CK matrix
```

### Threat Hunter Agent (`fsiem-threat-hunter`)
**Senior threat hunter that thinks like an attacker.** Runs hypothesis-driven hunts, detects long-dwell attackers, performs beacon analysis with statistical methods, builds Diamond Model adversary profiles, maps MITRE ATT&CK campaigns, and produces TLP:AMBER threat intelligence reports. Finds what's already in your environment that nobody has detected yet.

```
/fsiem-hypothesis-hunt "insider exfiltrating data via DNS tunneling"
/fsiem-apt-hunt APT29         → Agent runs all known Cozy Bear TTPs
/fsiem-l3-hunt                → Agent runs proactive hunt with full report
```

---

## Architecture

```
You: "Hunt for lateral movement using PsExec"
 │
 ▼
┌─────────────────────────────────────────┐
│         fsiem-essentials plugin          │
│                                          │
│  Skills    → Domain knowledge + code     │
│  Commands  → Slash command entry points  │
│  Agents    → Specialized sub-processes   │
│  Scripts   → Python API wrappers         │
└────────────────┬────────────────────────┘
                 │  HTTPS (Basic Auth)
                 ▼
        ┌─────────────────┐     ┌──────────────────┐
        │   FortiSIEM     │     │  Threat Intel     │
        │   REST API      │     │  VirusTotal       │
        │                 │     │  AbuseIPDB        │
        │  Events         │     │  Shodan           │
        │  Incidents      │     │  GeoIP / WHOIS    │
        │  CMDB           │     └──────────────────┘
        │  Rules          │
        └─────────────────┘
```

See [ARCHITECTURE.md](ARCHITECTURE.md) for full details.

## Requirements

- **FortiSIEM 7.x** (tested on 7.2 and 7.4)
- **Python 3.9+**
- **FortiSIEM API user** with Incident View, Analytics View, CMDB View permissions
- Optional: VirusTotal, AbuseIPDB, Shodan API keys for enrichment

## Roadmap

- [ ] Real-time alert stream processing
- [ ] Slack / Teams integration for alert notifications
- [ ] FortiSIEM 7.6 API support
- [ ] Grafana dashboard templates
- [ ] Automated weekly threat hunt scheduling
- [ ] PDF report export with charts
- [ ] FortiAnalyzer cross-correlation

## Documentation

| Document | Description |
|---|---|
| [DEMO.md](DEMO.md) | 6 real-world walkthroughs with full output |
| [INSTALL.md](INSTALL.md) | Step-by-step installation guide |
| [ARCHITECTURE.md](ARCHITECTURE.md) | System design and API flow |
| [CONTRIBUTING.md](CONTRIBUTING.md) | How to add skills, commands, and agents |
| [TROUBLESHOOTING.md](TROUBLESHOOTING.md) | 50+ common issues and fixes |
| [CHANGELOG.md](CHANGELOG.md) | Release history |
| [SECURITY.md](SECURITY.md) | Vulnerability reporting |
| [examples/quick-start.md](examples/quick-start.md) | Common workflow examples |

## Contributing

We welcome contributions. See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

Whether it's a new skill, a better hunt query, a bug fix, or improved docs — every PR makes FortiSIEM hunting better for everyone.

## License

Apache 2.0 — see [LICENSE](LICENSE).

---

<p align="center">
  <strong>Built and maintained by <a href="https://techowl.in">TechOwl Infosec</a></strong><br>
  <sub>Making FortiSIEM hunting faster for security teams worldwide</sub>
</p>
