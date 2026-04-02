# FortiSIEM Essentials — Skills Summary

Complete reference for all skills. Each skill is invocable by name (e.g. `/fsiem-hypothesis-hunt`).

---

## Core API Skills

| Skill | Name | Use When |
|---|---|---|
| `skills/auth/` | `fsiem-auth` | Starting any API interaction — builds auth headers |
| `skills/incidents/` | `fsiem-incidents` | Querying, triaging, or updating incidents |
| `skills/event_query/` | `fsiem-event-query` | Running async event searches (submit→poll→results) |
| `skills/cmdb/` | `fsiem-cmdb` | Device inventory, credentials, discovery, orgs |
| `skills/investigation/` | `fsiem-investigate` | Creating full investigation records and reports |

---

## Threat Hunting Skills

| Skill | Name | Use When |
|---|---|---|
| `skills/hypothesis_hunting/` | `fsiem-hypothesis-hunt` | Starting a structured hunt from a hypothesis ("there may be C2 beaconing") |
| `skills/threat_hunting/` | `fsiem-hunt` | Quick hunt by IP, domain, user, hash, or MITRE technique |
| `skills/ioc_management/` | `fsiem-ioc` | Hunting IOCs from threat reports, managing indicator lists |
| `skills/ueba/` | `fsiem-ueba` | Behavioral analysis — anomalous logins, off-hours activity, peer group deviations |

---

## Detection Engineering Skills

| Skill | Name | Use When |
|---|---|---|
| `skills/rule_creation/` | `fsiem-rule-create` | Building new correlation rules from scratch — includes 15 production-ready templates |
| `skills/rules/` | `fsiem-rules` | Listing, enabling, disabling, tuning existing rules |

---

## Response & Operations Skills

| Skill | Name | Use When |
|---|---|---|
| `skills/playbooks/` | `fsiem-playbook` | Step-by-step IR playbooks: ransomware, account compromise, exfil, malware, insider threat |

---

## Skill Details

### `fsiem-auth`
Builds FortiSIEM Basic Auth headers using the `org/user:password` format.
Always used first in any API interaction.

### `fsiem-incidents`
Full incident lifecycle: list by severity/status/time, get detail, get triggering events,
update status, add comments, assign to analyst.

### `fsiem-event-query`
FortiSIEM's async 3-step query flow:
1. `POST /query/eventQuery` → queryId
2. `GET /query/progress/{queryId}` → poll to 100%
3. `GET /query/events/{queryId}/{start}/{end}` → retrieve results

Includes `fsiem_build_query_xml()` to build XML from plain parameters.

### `fsiem-cmdb`
Device inventory queries, credential management, discovery trigger/poll,
organization management (Service Provider deployments).

### `fsiem-investigate`
Automated investigation record: pulls incident + events, enriches with CMDB,
builds event timeline, runs threat hunt on primary IPs, generates executive summary.

### `fsiem-hypothesis-hunt`
Full hypothesis-driven hunt lifecycle:
- Formulate hypothesis (who, behavior, timeframe)
- Map to FortiSIEM event types and MITRE ATT&CK
- Execute queries for 10 hunt scenarios (C2, lateral movement, exfil, DNS tunneling, etc.)
- Analyze results with scoring rubric
- Produce structured hunt report with findings and recommendations
- MITRE hypothesis library (15 techniques with detection approach)

### `fsiem-hunt`
Quick IOC and pattern hunting: by IP (as src and dest), domain, username,
file hash, or MITRE technique. Bulk IOC list support. Produces summary with affected hosts.

### `fsiem-ioc`
Full IOC management lifecycle:
- Extract IOCs from free-form threat report text (regex for IPs, domains, MD5, SHA256, URLs)
- Hunt each IOC in FortiSIEM historical data
- Generate detection rules from confirmed hits
- Produce IOC hunt report with action priorities

### `fsiem-ueba`
User and Entity Behavior Analytics:
- Build 30-day login baseline per user
- Detect anomalous logins (new IP, unusual hour, new location)
- Peer group analysis (who accesses what peers don't)
- Privileged account abuse (service accounts, admin from workstations)
- First-time access detection
- Statistical volume anomaly detection (Z-score)
- Risk scoring rubric (LOW/MEDIUM/HIGH)

### `fsiem-rule-create`
Complete rule creation with:
- Design checklist (7 questions before writing XML)
- Full XML schema with all attributes, operators, and options documented
- **15 production-ready rules**: SSH brute force, RDP brute force, C2 beaconing,
  lateral movement (SMB), PowerShell encoded, ransomware (shadow copy), data exfil,
  after-hours admin account creation, DNS tunneling, Kerberoasting, external admin login,
  port scan, impossible travel, malware hash match, scheduled task persistence
- Deployment workflow (Python)
- XML validation function
- Pre-deploy checklist

### `fsiem-rules`
List, enable, disable, and tune existing correlation rules.
Includes false positive analysis workflow.

### `fsiem-playbook`
5 complete IR playbooks with FortiSIEM queries built in:
1. **Ransomware** — shadow copy queries, patient zero identification, lateral movement
2. **Account Compromise** — login analysis, blast radius, containment steps
3. **Data Exfiltration** — outbound transfer queries, cloud storage detection, email exfil
4. **Malware** — process anomaly queries, persistence detection, network connections
5. **Insider Threat** — covert investigation queries (after-hours, sensitive file access, USB, bulk download)

Each playbook includes: triage queries, decision logic, containment actions,
and a standardized execution tracker template.

---

## Slash Commands

| Command | What It Does |
|---|---|
| `/init-fsiem` | Initialize session, verify connectivity, display all commands |
| **Incident Response** | |
| `/fsiem-incidents` | List open incidents by severity/status |
| `/fsiem-investigate` | Full investigation for a specific incident ID |
| `/fsiem-playbook` | IR playbook — ransomware, account compromise, exfil, malware, insider |
| **Threat Hunting** | |
| `/fsiem-hunt` | Hunt for an IOC, MITRE technique, or paste a threat report |
| `/fsiem-hypothesis-hunt` | Structured hypothesis-driven hunt with MITRE mapping and hunt report |
| `/fsiem-ioc` | Extract IOCs from a threat report, hunt all, generate rules for hits |
| `/fsiem-ueba` | Behavioral analysis — baseline + anomaly detection for a user or host |
| **Detection Engineering** | |
| `/fsiem-rule-create` | Design and deploy a new correlation rule from description or MITRE ID |
| `/fsiem-rules` | List, enable, disable, or tune existing rules |
| **Event & Asset Operations** | |
| `/fsiem-query` | Run an event query in plain English |
| `/fsiem-cmdb` | Query device inventory or trigger discovery |
| `/fsiem-report` | Org health and incident summary report |

## Agents

| Agent | Role |
|---|---|
| `fsiem-analyst` | SOC triage — prioritizes incidents, enriches with CMDB, recommends next action |
| `fsiem-rule-engineer` | Detection engineering — designs rules from scratch or from hunt findings |
| `fsiem-threat-hunter` | Proactive hunting — runs hypothesis-driven hunts, produces hunt reports |


---

## New Production Skills (v2.0)

| Skill | Name | Use When |
|---|---|---|
| `skills/multiorg/` | `fsiem-multiorg` | MSSP/SP deployments — sweep incidents or hunt IOCs across all tenants |
| `skills/compliance/` | `fsiem-compliance` | Compliance reporting — PCI DSS, HIPAA, SOX, NIST, ISO 27001 |
| `skills/ticketing/` | `fsiem-ticketing` | Escalate incidents to ServiceNow, Jira, or PagerDuty |

## Additional Commands (v2.0)

| Command | What It Does |
|---|---|
| `/fsiem-multiorg` | Sweep all SP orgs for incidents or IOCs |
| `/fsiem-compliance` | Run and export compliance reports |
| `/fsiem-ticket` | Create ticket from incident in ITSM/alerting systems |

## Troubleshooting

See [TROUBLESHOOTING.md](../../../../TROUBLESHOOTING.md) for solutions to common issues:
installation problems, auth errors, SSL issues, empty results, Docker networking.

## Scripts

| Script | Usage |
|---|---|
| `fsiem_api.py` | General CLI — incidents, queries, CMDB |
| `hunt_iocs.py` | Hunt IOCs from file or list |
| `ueba_report.py` | UEBA behavioral analysis |
| `scheduled_hunt.py` | Cron-ready scheduled hunting and compliance |

---

## L1 / L2 / L3 Tier Skills (v3.0)

| Skill | Name | Tier | Use When |
|---|---|---|---|
| `skills/l1_triage/` | `fsiem-l1-triage` | L1 | Processing alert queue, first-responder triage, shift handover |
| `skills/l2_investigation/` | `fsiem-l2-investigate` | L2 | Deep investigation of escalated incidents, blast radius, timeline |
| `skills/l3_threat_intel/` | `fsiem-l3-hunt` | L3 | APT analysis, long dwell detection, MITRE mapping, Diamond Model |
| `skills/enrichment/` | `fsiem-enrich` | All | Enrich IPs/domains/hashes with VT, AbuseIPDB, Shodan, GeoIP |
| `skills/report_generation/` | `fsiem-report-generate` | All | Executive, daily ops, incident, hunt, shift handover reports |

## New Commands (v3.0)

| Command | What It Does |
|---|---|
| `/fsiem-l1-triage` | L1 alert queue triage with quick-check scoring |
| `/fsiem-l2-investigate` | L2 deep investigation with timeline and blast radius |
| `/fsiem-l3-hunt` | L3 APT hunt, MITRE mapping, Diamond Model, TLP:AMBER report |
| `/fsiem-enrich` | Enrich indicators with external threat intel |
| `/fsiem-report-generate` | Generate any formal report type |
