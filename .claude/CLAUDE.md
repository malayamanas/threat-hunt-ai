# FortiSIEM AI — Project Guidelines

This project is a Claude Code plugin marketplace for FortiSIEM security operations.

## What This Repo Is

A Claude Code plugin marketplace (`marketplace/plugins/fsiem-essentials/`) providing
AI-assisted FortiSIEM workflows across 12 skills and 13 slash commands:

- **Incident Response** — triage, investigation, 5 IR playbooks
- **Threat Hunting** — hypothesis-driven hunts, IOC management, quick hunts
- **UEBA** — behavioral baselines, anomaly detection, risk scoring
- **Detection Engineering** — 15 production rule templates, full design workflow
- **Event & Asset Operations** — async event queries, CMDB, org management

## Plugin Location

```
marketplace/
├── .claude-plugin/marketplace.json   ← Claude Code reads this
└── plugins/fsiem-essentials/
    ├── .claude-plugin/plugin.json
    ├── skills/         ← 12 skills (each skill/ has SKILL.md + optional reference.md)
    ├── commands/       ← 13 slash commands (one .md per command)
    ├── agents/         ← 3 agents (analyst, rule-engineer, threat-hunter)
    └── scripts/        ← 3 runnable Python CLIs
```

## Working on Skills

Each skill directory requires:
- `SKILL.md` — YAML frontmatter + concise overview (keep under 400 lines)
- `reference.md` — full Python implementations (optional, for long detail)

YAML frontmatter format:
```yaml
---
name: fsiem-skill-name
description: What this does. When Claude should auto-invoke it.
---
```

## Testing Changes

```bash
/plugin marketplace add /path/to/this/repo/marketplace
/plugin install fsiem-essentials@fsiem-marketplace
/reload-plugins
```

## FortiSIEM API Key Facts

- Auth: `org/user:password` Basic Auth — NOT `user:password`
- Event queries are **async**: POST submit → GET poll (0→100%) → GET results
- Responses are **XML** — parse with `xml.etree.ElementTree`
- Base URL: `https://{FSIEM_HOST}/phoenix/rest/`
- Operators in XML filter values must be escaped: `>=` → `&gt;=`, `<=` → `&lt;=`

## Skill Categories

| Directory | Skill Name | Purpose |
|---|---|---|
| `auth/` | `fsiem-auth` | API auth headers |
| `incidents/` | `fsiem-incidents` | Incident CRUD |
| `event_query/` | `fsiem-event-query` | Async event search |
| `cmdb/` | `fsiem-cmdb` | Device inventory |
| `investigation/` | `fsiem-investigate` | Investigation records |
| `hypothesis_hunting/` | `fsiem-hypothesis-hunt` | Structured hunt lifecycle |
| `threat_hunting/` | `fsiem-hunt` | Quick IOC/pattern hunts |
| `ioc_management/` | `fsiem-ioc` | IOC extraction and hunting |
| `ueba/` | `fsiem-ueba` | Behavioral analytics |
| `rule_creation/` | `fsiem-rule-create` | Rule design and deployment |
| `rules/` | `fsiem-rules` | Rule management |
| `playbooks/` | `fsiem-playbook` | IR playbooks |
| `multiorg/` | `fsiem-multiorg` | Multi-org / MSSP operations |
| `compliance/` | `fsiem-compliance` | Compliance report execution |
| `ticketing/` | `fsiem-ticketing` | ITSM integration |
