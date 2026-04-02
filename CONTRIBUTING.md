# Contributing to Hunt with FortiSIEM

Contributions are welcome. This document explains how to add skills, agents, commands, scripts, and fix bugs.

## Getting Started

```bash
git clone https://github.com/YOUR_ORG/fortisiem-ai.git
cd your-project
/plugin marketplace add /path/to/fortisiem-ai/marketplace
/plugin install fsiem-essentials@fsiem-marketplace
```

## Skill Categories

Skills live in `marketplace/plugins/fsiem-essentials/skills/`. Current categories:

| Directory | Purpose |
|---|---|
| `auth/` | API authentication helpers |
| `incidents/` | Incident CRUD and triage |
| `event_query/` | Async event query flow |
| `cmdb/` | Device inventory and discovery |
| `investigation/` | Investigation records and reports |
| `hypothesis_hunting/` | Structured hypothesis-driven hunts |
| `threat_hunting/` | Quick IOC and pattern hunts |
| `ioc_management/` | IOC extraction, hunting, and rule generation |
| `ueba/` | User and entity behavior analytics |
| `rule_creation/` | Correlation rule design and deployment |
| `rules/` | Rule management (list/enable/disable/tune) |
| `playbooks/` | IR playbooks for common incident types |
| `multiorg/` | Multi-org / MSSP sweep operations |
| `compliance/` | Compliance report execution and export |
| `ticketing/` | ITSM/alerting integration (ServiceNow, Jira, PagerDuty) |

## Adding a Skill

1. Create a new directory: `skills/my_skill_name/`
2. Create `SKILL.md` with YAML frontmatter:
   ```markdown
   ---
   name: fsiem-my-skill
   description: What this skill does. When it should be auto-invoked.
   ---
   # Skill Title
   [content]
   ```
3. Keep `SKILL.md` under 400 lines — move detailed reference to `reference.md`
4. If the skill has runnable Python, add a script to `scripts/`
5. Update `SKILLS_SUMMARY.md` with a row in the appropriate table
6. Add a command file to `commands/` if users should invoke it directly
7. Test: reinstall plugin and verify the skill appears with `/reload-plugins`

## Adding a Command

1. Create `commands/fsiem-mycommand.md` with frontmatter:
   ```markdown
   ---
   name: fsiem-mycommand
   description: One-line description for the slash command picker.
   ---
   ```
2. Update `init-fsiem.md` to include the new command in the welcome message
3. Commands are discovered automatically from the `commands/` directory

## Adding a Script

Scripts in `scripts/` should:
- Have a `#!/usr/bin/env python3` shebang
- Use `argparse` for CLI arguments
- Document required env vars in the docstring
- Not require any packages beyond `requests` and stdlib
- Be `chmod +x` executable

## Pull Request Guidelines

- One PR per skill, bug fix, or feature
- Update `SKILLS_SUMMARY.md` and `CONTRIBUTING.md` as needed
- Test against a real FortiSIEM instance if possible
- XML in skill files must be valid (check operator escaping: `>=` → `&gt;=`)
- Commit messages: imperative, present tense (`Add DNS tunneling rule`, not `Added`)

## Reporting Issues

Open a GitHub Issue with:
- FortiSIEM version
- Plugin version  
- Steps to reproduce
- Expected vs actual behavior
- Relevant SIEM logs if applicable
