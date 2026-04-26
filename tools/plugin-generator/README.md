# Plugin Generator

`generate_plugin.py` — AI-powered Claude Code plugin scaffold generator.

Describe any software, tool, or domain in plain English. The script invokes
`claude -p` from the repository root so Claude Code uses its own Write tool to
create a complete, production-ready plugin scaffold directly on disk — no
templates, no output parsing, no boilerplate to delete.

---

## The Problem It Solves

Building a Claude Code plugin from scratch means creating 19 interdependent
files in the right directory structure with correct YAML frontmatter, consistent
naming conventions, matching skill/command/agent cross-references, a valid Python
CLI script, and a registered entry in `marketplace.json`. Done by hand, this
takes 2–3 hours and requires deep knowledge of the plugin format.

This tool reduces that to a single command and a ~60 second wait.

| Without this tool | With this tool |
|---|---|
| Manually create 19 files | One command |
| Copy-paste from existing plugins, clean up references | Fresh content tailored to your domain |
| Look up YAML frontmatter format, skill naming rules | Claude reads the repo and matches the format exactly |
| Write Python CLI boilerplate | Generated script with correct argparse structure |
| Remember to update marketplace.json | Claude updates it automatically |
| 2–3 hours | ~60 seconds |

---

## Prerequisites

| Requirement | Details |
|---|---|
| **Claude Code** | Binary must be in `PATH`. Install: `npm install -g @anthropic-ai/claude-code` |
| **Python 3.9+** | Standard library only — no pip installs needed |
| **Active Claude session** | `claude` must be authenticated (`claude auth` if not already done) |

Check both are ready:
```bash
claude --version
python3 --version
```

---

## Usage

Run from anywhere in the repository:

```bash
# Inline description
python3 tools/plugin-generator/generate_plugin.py "Kubernetes cluster health monitor"

# Interactive prompt (run with no arguments)
python3 tools/plugin-generator/generate_plugin.py

# Pipe description from stdin
echo "GitHub Actions CI/CD pipeline manager" | python3 tools/plugin-generator/generate_plugin.py

# Preview the prompt Claude will receive (does NOT call Claude)
python3 tools/plugin-generator/generate_plugin.py --show-prompt "PostgreSQL query optimizer"

# Skip the project tree in output
python3 tools/plugin-generator/generate_plugin.py --no-tree "AWS cost monitor"
```

### Flags

| Flag | Effect |
|---|---|
| `--show-prompt` | Print the full prompt that would be sent to Claude, then exit. No files written, Claude not called. Useful for reviewing or debugging the prompt. |
| `--no-tree` | Skip printing the current project directory tree. Speeds up the startup output. |

---

## What Happens Step by Step

```
1  Check claude binary in PATH
   └─ Exits with install instructions if not found

2  Accept input description
   └─ From CLI argument, stdin pipe, or interactive prompt

3  Scan the repository tree
   └─ Passes the live structure to Claude so it matches the existing format

4  Derive plugin identifiers
   └─ slug: kebab-case name from the description (e.g. "kubernetes-cluster-health")
   └─ prefix: short command prefix (e.g. "k8s", "aws", "db")
   └─ env_prefix: uppercase env var prefix (e.g. "KUBERNETES_CLUSTER_HEALTH")
   └─ marketplace name: read from marketplace/.claude-plugin/marketplace.json

5  Build a structured prompt
   └─ Includes: description, live repo tree, identifiers, file list with requirements

6  Invoke: claude -p "<prompt>" (cwd = repo root)
   └─ Claude's output streams to your terminal in real time
   └─ Claude uses its Write tool to create every file on disk
   └─ Claude reads and updates marketplace.json with the new plugin entry

7  Report created files
   └─ Lists every file written under marketplace/plugins/<slug>/

8  Print install instructions
   └─ /plugin marketplace add ...
   └─ /plugin install <slug>@<marketplace-name>
```

---

## What Gets Generated

For a description like `"Kubernetes cluster health monitor"`, Claude creates:

```
marketplace/plugins/kubernetes-cluster-health/
├── .claude-plugin/
│   └── plugin.json                      ← Plugin manifest (name, version, description)
├── CLAUDE.md                            ← Guidelines Claude reads every session
├── SKILLS_SUMMARY.md                   ← Full skill + command reference
├── agents/
│   └── k8s-operator.md                 ← Specialized AI agent for this domain
├── commands/
│   ├── init-kubernetes-cluster-health.md  ← /init command with connectivity check
│   ├── k8s-status.md                   ← /k8s-status slash command
│   ├── k8s-pods.md
│   ├── k8s-deploy.md
│   ├── k8s-logs.md
│   └── k8s-events.md
├── skills/
│   ├── cluster_health/
│   │   ├── SKILL.md                    ← Skill definition + auto-invoke triggers
│   │   └── reference.md               ← Python implementation stub
│   ├── workload_management/
│   │   ├── SKILL.md
│   │   └── reference.md
│   ├── namespace_ops/
│   │   ├── SKILL.md
│   │   └── reference.md
│   └── log_analysis/
│       ├── SKILL.md
│       └── reference.md
└── scripts/
    └── k8s_helper.py                   ← Executable Python CLI (stdlib only)
```

And `marketplace/.claude-plugin/marketplace.json` is updated to register the plugin.

**Total: 19 plugin files + 1 marketplace.json update.**

### What each file contains

| File | Contents |
|---|---|
| `plugin.json` | Name, version, description, author — Claude derives all values from your input |
| `CLAUDE.md` | Domain-specific guidelines: skill table, command table, operational defaults |
| `SKILLS_SUMMARY.md` | Complete cross-reference of all skills, commands, agents, scripts |
| `commands/init-*.md` | Session initializer: env var checks, connectivity test, full command menu |
| `commands/<prefix>-*.md` | Five slash commands with YAML frontmatter, numbered behavior steps, usage examples |
| `skills/*/SKILL.md` | Four skills with auto-invoke `description:` field, overview, key operations, output format |
| `skills/*/reference.md` | Python reference implementation using `urllib` (stdlib only) with `get_config()`, `auth_headers()`, main function stub |
| `agents/*.md` | Agent YAML frontmatter, role description, architecture section, step-by-step workflow |
| `scripts/*.py` | Executable CLI: `get_config()`, `check_config()`, `auth_headers()`, `api_get()`, per-command `cmd_*()` functions, `argparse` subcommands |
| `marketplace.json` | Claude reads the current file and appends your plugin's entry with category inferred from the description |

---

## What to Expect During Generation

When you run the script, you will see:

```
Checking Claude Code installation...
  ✓  /usr/local/bin/claude

Plugin description:
  Kubernetes cluster health monitor

Current project structure:
  FortiSIEM-Threat-Hunting-Using-AI/
  ├── marketplace/
  ...

Plugin identifiers:
  slug        : kubernetes-cluster-health
  prefix      : k8s
  env prefix  : KUBERNETES_CLUSTER_HEALTH
  marketplace : fsiem-marketplace

Calling Claude Code to generate plugin files...
  (Claude will write files directly using its Write tool)
```

After that, **Claude's own output streams to your terminal** — you will see Claude's
reasoning and tool calls in real time as it writes each file. This is normal Claude
Code behavior. Example output from Claude:

```
I'll create a complete Kubernetes cluster health monitor plugin. Let me start
with the plugin manifest and work through all required files.

[Writing .claude-plugin/plugin.json...]
[Writing CLAUDE.md...]
[Writing skills/cluster_health/SKILL.md...]
...
```

**Typical generation time: 45–90 seconds** depending on network latency and
the complexity of the domain.

After Claude finishes:

```
Plugin files written (19 total):
  + marketplace/plugins/kubernetes-cluster-health/.claude-plugin/plugin.json
  + marketplace/plugins/kubernetes-cluster-health/CLAUDE.md
  ...

Install the new plugin:

  /plugin marketplace add /path/to/repo/marketplace
  /plugin install kubernetes-cluster-health@fsiem-marketplace
  /reload-plugins
  /init-kubernetes-cluster-health
```

---

## After Generation

### 1. Install and verify
```bash
# In a Claude Code session:
/plugin marketplace add /path/to/repo/marketplace
/plugin install <slug>@<marketplace-name>
/reload-plugins
/init-<slug>
```

### 2. Fill in the TODOs in the script
Every generated `scripts/*.py` has TODO comments marking where real API calls go:
```python
def cmd_status(cfg: dict, args) -> None:
    """Show cluster health."""
    host = cfg["host"]
    # TODO: implement — call host API and print results
    # url = f"{host}/api/v1/status"
    # data = api_get(url, auth_headers(cfg))
```
Replace these with actual API calls for your target system.

### 3. Enrich the skills
Generated `SKILL.md` files contain accurate overrides but minimal detail.
Expand the **Key Operations** section with domain-specific queries, filters,
and real API patterns your use case needs.

### 4. Set environment variables
The generated script reads from env vars named `<ENV_PREFIX>_HOST`, `<ENV_PREFIX>_TOKEN`, etc.
Set these before running:
```bash
export KUBERNETES_CLUSTER_HEALTH_HOST="https://your-k8s-api"
export KUBERNETES_CLUSTER_HEALTH_TOKEN="your-token"
```

---

## Slug and Prefix Derivation

The script derives identifiers locally (without calling Claude) so they are
consistent before Claude starts writing files:

| Input | Slug | Prefix |
|---|---|---|
| `"Kubernetes cluster health monitor"` | `kubernetes-cluster-health` | `k8s` |
| `"GitHub Actions CI/CD manager"` | `github-actions-ci-cd` | `gha` |
| `"PostgreSQL schema migration tool"` | `postgresql-schema-migration` | `db` |
| `"AWS cost optimization"` | `aws-cost-optimization` | `aws` |
| `"Custom internal workflow"` | `custom-internal-workflow` | `cust` |

Stop words (`a`, `the`, `and`, `build`, `create`, `tool`, etc.) are stripped
from the slug. The prefix is matched against a domain keyword table; unknown
domains fall back to initials of the slug words.

---

## Troubleshooting

**`ERROR: Claude Code binary not found`**
```bash
npm install -g @anthropic-ai/claude-code
# then re-open terminal or:
export PATH="$PATH:$(npm root -g)/.bin"
```

**`claude exited with code 1`**
Claude Code is not authenticated. Run `claude auth` and complete the login flow.

**Plugin directory already exists**
The script prompts before overwriting. Answer `y` to regenerate, `n` to abort.

**Generated files look generic / not domain-specific**
Try a more specific description. Compare:
- Vague: `"monitoring tool"` → generic output
- Specific: `"Prometheus alert manager with silence and routing rule management"` → targeted output

**Fewer than 19 files were created**
Claude occasionally truncates long responses. Run again — the prompt is
deterministic so results are consistent across runs.

**Paths in install instructions point to wrong directory**
The marketplace path in the output is computed from the actual file location
at runtime. If it looks wrong, copy the path from the "Current project structure"
section shown at startup.
