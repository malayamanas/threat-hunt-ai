# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What This Tool Is

`generate_plugin.py` — a single-file Python script that generates a Claude Code plugin scaffold
by invoking `claude -p` from the repository root. Claude uses its own Write tool to create all
plugin files directly on disk.

Input: a plain-English description of the software or domain (e.g. `"Kubernetes cluster health monitor"`).
Output: 19 plugin files written under `marketplace/plugins/<slug>/` plus an updated `marketplace/.claude-plugin/marketplace.json`.

## Repository Layout

```
your-repo-root/
├── generate_plugin.py           ← the tool
├── CLAUDE.md                    ← this file
├── README.md                    ← user documentation
└── marketplace/
    ├── .claude-plugin/
    │   └── marketplace.json     ← registry; tool reads the "name" field at runtime
    └── plugins/
        └── <generated-plugin>/  ← Claude writes here
```

`REPO_ROOT` is derived as `Path(__file__).parent.resolve()` — the directory containing `generate_plugin.py`.
The `marketplace/` directory must exist at that same level before running the tool.

## Running the Tool

```bash
python3 generate_plugin.py "Kubernetes cluster health monitor"
python3 generate_plugin.py                              # interactive prompt
echo "GitHub Actions CI/CD manager" | python3 generate_plugin.py
python3 generate_plugin.py --show-prompt "PostgreSQL optimizer"   # debug: print prompt, no Claude call
python3 generate_plugin.py --no-tree "AWS cost monitor"           # skip tree display
```

Requires: Claude Code binary in PATH (`claude --version`), Python 3.9+, no pip installs.

## Code Architecture

All logic lives in `generate_plugin.py`. No imports beyond stdlib + `shutil` + `subprocess`.

| Function | Purpose |
|---|---|
| `check_claude()` | Locates the `claude` binary; checks PATH + common install locations |
| `get_input_text(args)` | Accepts description via CLI arg, stdin pipe, or interactive prompt |
| `tree_string(root)` | Builds an ASCII directory tree passed to Claude for format context |
| `build_spec(text)` | Derives `slug`, `prefix`, `env_prefix` locally (no Claude call) |
| `get_marketplace_name()` | Reads `marketplace/.claude-plugin/marketplace.json` at runtime — never hardcoded |
| `build_prompt(spec, tree)` | Assembles the structured prompt listing all 19 files Claude must write |
| `call_claude(path, prompt)` | Runs `subprocess.run([claude, "-p", prompt], cwd=REPO_ROOT)` — Claude writes files via its Write tool |
| `report_created_files(dir)` | Lists files found under the new plugin directory |

## What Claude Generates (19 files)

```
marketplace/plugins/<slug>/
├── .claude-plugin/plugin.json
├── CLAUDE.md
├── SKILLS_SUMMARY.md
├── agents/<prefix>-agent.md
├── commands/
│   ├── init-<slug>.md
│   └── <prefix>-<name>.md   (×5)
├── skills/
│   └── <skill_name>/
│       ├── SKILL.md          (×4)
│       └── reference.md      (×4)
└── scripts/<slug>_helper.py
```

Plus one new entry in `marketplace/.claude-plugin/marketplace.json`.

## Plugin File Format Rules

Claude Code plugin files follow these conventions — important when reviewing or extending generated output:

**YAML frontmatter** is required on every `.md` file:
```yaml
---
name: <skill-or-command-name>
description: One sentence. Used by Claude for auto-invocation matching.
---
```

**Skills** (`skills/<name>/SKILL.md`): keep under 60 lines; move Python implementations to `reference.md`.

**Commands** (`commands/<prefix>-<name>.md`): define `## Behavior` as numbered steps and `## Example Invocations`.

**Scripts** (`scripts/*.py`): stdlib only (no `requests`, no third-party packages). Must have `#!/usr/bin/env python3` shebang and use `argparse`.

## Slug / Prefix Derivation

Identifiers are derived in `build_spec()` before Claude is called:
- **slug**: kebab-case from description, stop words stripped, max 4 words
- **prefix**: domain keyword lookup (`kubernetes→k8s`, `aws→aws`, etc.); falls back to initials
- **env_prefix**: slug uppercased with `-` → `_`

## Modifying the Prompt

The full prompt is in `build_prompt()`. To inspect what gets sent to Claude without running it:

```bash
python3 generate_plugin.py --show-prompt "your description here"
```

## Prerequisites for the Marketplace

Before the tool can generate and register a plugin, the repo needs:

```
marketplace/.claude-plugin/marketplace.json
```

Minimal content:
```json
{
  "name": "my-marketplace",
  "plugins": []
}
```

The tool reads the `"name"` field for install instructions. The `"plugins"` array is updated by Claude.
