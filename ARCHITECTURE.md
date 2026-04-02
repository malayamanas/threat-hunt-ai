# Architecture

## Overview

Hunt with FortiSIEM is a **plugin marketplace** that adds AI-assisted security operations to any FortiSIEM deployment. It uses a skills-based plugin system (skills, commands, agents) to provide natural language access to FortiSIEM's REST API.

```
┌─────────────────────────────────────────────────────┐
│                    AI Assistant                       │
│                                                      │
│  User: "/fsiem-hunt 185.220.101.5"                  │
│         ↓                                            │
│  ┌──────────────────────────────────────────────┐   │
│  │           fsiem-essentials Plugin             │   │
│  │                                               │   │
│  │  Commands (.md)  → Slash command definitions  │   │
│  │  Skills (.md)    → Domain knowledge + code    │   │
│  │  Agents (.md)    → Specialized sub-agents     │   │
│  │  Scripts (.py)   → Reusable Python utilities  │   │
│  └──────────────────┬───────────────────────────┘   │
│                      │                               │
└──────────────────────┼───────────────────────────────┘
                       │ HTTPS (Basic Auth)
                       ▼
              ┌─────────────────┐
              │   FortiSIEM     │
              │   REST API      │
              │                 │
              │  /pub/incident  │
              │  /query/*       │
              │  /cmdbDeviceInfo│
              │  /config/*      │
              └─────────────────┘
```

## Plugin Structure

```
marketplace/plugins/fsiem-essentials/
├── .claude-plugin/plugin.json    ← Plugin manifest (name, version, entry points)
├── commands/                     ← 28 slash commands (one .md per command)
├── skills/                       ← 12+ skills (domain knowledge + reference code)
│   └── <skill>/
│       ├── SKILL.md              ← Skill definition (YAML frontmatter + overview)
│       └── reference.md          ← Full Python implementations (optional)
├── agents/                       ← 3 specialized agents
│   ├── fsiem-analyst.md          ← L1/L2 SOC analyst
│   ├── fsiem-rule-engineer.md    ← Detection engineering
│   └── fsiem-threat-hunter.md    ← L3 proactive hunting
└── scripts/                      ← 7 Python utilities
    ├── fsiem_api.py              ← Core API wrapper (auth, queries, incidents)
    ├── investigation_pipeline.py ← End-to-end investigation automation
    ├── ai_reasoning.py           ← AI-powered analysis and correlation
    ├── hunt_iocs.py              ← IOC extraction and bulk hunting
    ├── ueba_report.py            ← Behavioral analytics reporting
    ├── report_pdf.py             ← PDF report generation
    └── scheduled_hunt.py         ← Cron-ready automated hunting
```

## How It Works

### Skills
Skills are markdown files containing domain-specific knowledge about FortiSIEM. Each skill has:
- **YAML frontmatter**: name, description, auto-invocation triggers
- **Overview**: When and how to use this skill
- **Reference code**: Python implementations that can be adapted and executed

The AI reads the relevant skill when a user's request matches the skill's description, then generates and runs the appropriate API calls.

### Commands
Slash commands are shorthand entry points. `/fsiem-hunt` expands to a full prompt that activates the threat hunting skill with the right parameters.

### Agents
Agents are specialized sub-processes with focused toolsets:
- **fsiem-analyst**: Handles the L1 > L2 triage and investigation lifecycle
- **fsiem-rule-engineer**: Designs, tests, and deploys correlation rules
- **fsiem-threat-hunter**: Runs hypothesis-driven hunts and threat intel analysis

### Scripts
Python scripts provide reusable API wrappers and automation. They can be called directly via `python3 scripts/fsiem_api.py` or imported as modules.

## FortiSIEM API Flow

### Event Queries (Async 3-Step)
```
1. POST /query/eventQuery     → Submit XML query → get queryId
2. GET  /query/progress/{id}  → Poll until progress = 100
3. GET  /query/events/{id}/0/N → Retrieve paginated results
```

### Authentication
```
Base64( "org/user:password" )  →  Authorization: Basic <token>
```

### Key Endpoints
| Endpoint | Method | Purpose |
|---|---|---|
| `/pub/incident` | GET | List/filter incidents (JSON) |
| `/query/eventQuery` | POST | Submit event query (XML) |
| `/cmdbDeviceInfo/device` | GET | CMDB device lookup |
| `/config/Domain` | GET | List organizations |
| `/incident/updateIncidentStatus` | POST | Update incident |

## Design Decisions

1. **Markdown over code** — Skills are markdown files, not Python packages. Readable, editable, version-controllable without build steps.
2. **XML query format** — FortiSIEM's native query language uses XML `<Reports>` format with `<PatternClause>` filters. The plugin generates this XML dynamically.
3. **No local storage** — All data comes from FortiSIEM in real-time. No local database or cache.
4. **Environment-based config** — Credentials via `$FSIEM_*` environment variables. No config files with secrets.
5. **Multi-org by default** — All queries support Service Provider (MSSP) mode with organization filtering.
