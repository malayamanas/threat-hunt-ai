# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What This Repo Is

A Claude Code plugin marketplace for FortiSIEM SOC operations. The plugin (`fsiem-essentials`) delivers AI-assisted threat hunting, incident response, detection engineering, UEBA, and compliance workflows via 31 slash commands, 30+ skills, and 3 specialized agents.

## Plugin Installation and Testing

There is no build step. To test changes, reinstall the plugin in a Claude Code session:

```bash
# Register marketplace (first time only)
/plugin marketplace add /path/to/this/repo/marketplace

# Install plugin
/plugin install fsiem-essentials@fsiem-marketplace

# After any skill/command/agent change
/reload-plugins

# Verify everything loaded
/init-fsiem
```

To update after a `git pull`:
```bash
git pull
/reload-plugins
```

## Architecture

```
marketplace/
├── .claude-plugin/marketplace.json        ← marketplace registry
└── plugins/fsiem-essentials/
    ├── .claude-plugin/plugin.json         ← plugin manifest (name, version)
    ├── skills/<skill_name>/
    │   ├── SKILL.md                       ← YAML frontmatter + domain knowledge + inline Python
    │   └── reference.md                   ← full Python implementations (overflow from SKILL.md)
    ├── commands/fsiem-<name>.md            ← slash command definitions (one file per command)
    ├── agents/fsiem-<role>.md              ← specialized sub-agents
    └── scripts/                            ← standalone Python CLIs (no deps beyond requests + stdlib)
```

**How the layers connect:**
- **Skills** are the knowledge base. Claude reads the matching skill when a user's request triggers it (via the `description:` field in frontmatter). Skills contain domain knowledge AND Python code Claude can run.
- **Commands** are shorthand entry points. `/fsiem-hunt` expands into a prompt that activates the threat hunting skill with context pre-loaded.
- **Agents** (`fsiem-analyst`, `fsiem-rule-engineer`, `fsiem-threat-hunter`) are multi-step sub-processes with focused toolsets for L1/L2 triage, detection engineering, and L3 proactive hunting.
- **Scripts** are runnable Python utilities that can be called directly (`python3 scripts/fsiem_api.py`) or imported as modules by skills.

## FortiSIEM API — Non-Obvious Facts

These trip up almost every new implementation:

**Auth format** — `org/user:password` encoded as Basic Auth, NOT `user:password`:
```python
credentials = f"{os.environ['FSIEM_ORG']}/{os.environ['FSIEM_USER']}:{os.environ['FSIEM_PASS']}"
token = base64.b64encode(credentials.encode()).decode()
headers = {"Authorization": f"Basic {token}", "Content-Type": "text/xml"}
```

**Event queries are async** — always three steps, never one:
```
POST /query/eventQuery        → returns queryId (plain text body)
GET  /query/progress/{id}     → poll until body = "100"
GET  /query/events/{id}/0/N   → paginated XML results
```

**XML in, XML out** — query bodies are XML `<Reports>` documents; responses are XML. A `200 OK` can still contain an error — always parse the body. Use `xml.etree.ElementTree`.

**Operator escaping in filter values** — XML comparison operators must be entity-encoded:
- `>=` → `&gt;=`
- `<=` → `&lt;=`

**Base URL:** `https://{FSIEM_HOST}/phoenix/rest/`

**Key endpoints:**

| Endpoint | Method | Purpose |
|---|---|---|
| `/pub/incident` | GET | List/filter incidents (JSON) |
| `/query/eventQuery` | POST | Submit event query (XML body) |
| `/query/progress/{id}` | GET | Poll query progress (0–100) |
| `/query/events/{id}/{start}/{end}` | GET | Retrieve paginated results |
| `/cmdbDeviceInfo/device` | GET | CMDB device lookup |
| `/config/Domain` | GET | List organizations (MSSP) |
| `/incident/updateIncidentStatus` | POST | Update incident status |

## Credential Environment Variables

All code reads from environment variables — never hardcode:

```bash
FSIEM_HOST=https://your-supervisor    # must include https://
FSIEM_USER=api_user
FSIEM_PASS=password
FSIEM_ORG=super                        # "super" for Enterprise; org name for MSSP/SP
FSIEM_VERIFY_SSL=false                 # set true in production

# Optional enrichment
VT_API_KEY=...          # VirusTotal
ABUSEIPDB_API_KEY=...   # AbuseIPDB
SHODAN_API_KEY=...      # Shodan

# Optional ITSM
SNOW_INSTANCE=...  SNOW_USER=...  SNOW_PASS=...      # ServiceNow
JIRA_URL=...  JIRA_USER=...  JIRA_TOKEN=...          # Jira
PAGERDUTY_TOKEN=...  PAGERDUTY_SERVICE=...           # PagerDuty
```

## Adding a Skill

1. Create `skills/<dir_name>/SKILL.md` with YAML frontmatter:
   ```yaml
   ---
   name: fsiem-skill-name
   description: What this does. When Claude should auto-invoke it. (used for trigger matching)
   ---
   ```
2. Keep `SKILL.md` under 400 lines — move long Python to `reference.md`
3. If adding runnable Python, add a script to `scripts/` (shebang, argparse, stdlib+requests only)
4. Update `SKILLS_SUMMARY.md` with a new row
5. If user-invocable: add `commands/fsiem-<name>.md` with `name:` and `description:` frontmatter
6. Update `commands/init-fsiem.md` to list the new command in the welcome output
7. Test: `/reload-plugins` then confirm the skill appears

## Operational Defaults (use in any generated query code)

| Parameter | Default |
|---|---|
| Incident lookback | 24 hours |
| Event query window | Last 1 hour |
| Threat hunt window | Last 7 days |
| IOC hunt window | Last 30 days |
| Max incidents returned | 100 |
| Max events returned | 200 |
| Organization | `$FSIEM_ORG` (fallback: `super`) |

## Scripts Reference

| Script | Purpose | Run with |
|---|---|---|
| `fsiem_api.py` | Core API wrapper — auth, queries, incidents | `python3 scripts/fsiem_api.py --help` |
| `investigation_pipeline.py` | End-to-end investigation automation | CLI or import |
| `ai_reasoning.py` | AI-powered event correlation and analysis | Import as module |
| `hunt_iocs.py` | IOC extraction and bulk hunting from file/list | `python3 scripts/hunt_iocs.py --iocs file.txt` |
| `ueba_report.py` | Behavioral analytics reporting | `python3 scripts/ueba_report.py --user john.doe` |
| `report_pdf.py` | PDF report generation | Import as module |
| `scheduled_hunt.py` | Cron-ready automated hunting | `python3 scripts/scheduled_hunt.py` |

Scripts must: have `#!/usr/bin/env python3` shebang, use `argparse`, document env vars in the docstring, require no packages beyond `requests` and stdlib, and be `chmod +x`.

## Docker Alternative

```bash
cd docker
cp .env.example .env   # edit with credentials
docker compose run --rm fsiem-claude
```
