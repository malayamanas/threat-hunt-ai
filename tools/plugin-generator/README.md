# Plugin Generator

`generate_plugin.py` — generates a Claude Code plugin scaffold by invoking
`claude -p` from the repository root. Claude uses its own Write tool to create
all files directly on disk.

---

## Does It Produce a Perfect Plugin?

**No. It produces a correct, installable scaffold — not a finished plugin.**

Understanding this distinction upfront will save you frustration:

| What the generator produces | What you still need to add |
|---|---|
| Correct directory structure, all 19 files | Real API calls in `scripts/*.py` |
| Valid YAML frontmatter on every file | Domain-specific query patterns in skills |
| Consistent slug / prefix / env var naming | Actual endpoint URLs and auth flow |
| Working `argparse` CLI (`--help` runs) | Responses that return real data |
| `marketplace.json` entry (plugin installs) | Testing against a live system |
| Claude-readable skill descriptions | Edge cases and error handling |

Think of it as the difference between a **building frame** and a **finished building**.
The frame is structurally correct and saves significant time — but the walls,
plumbing, and wiring are still your work.

### What "correct scaffold" means in practice

The generated `scripts/k8s_helper.py` for a Kubernetes plugin looks like this:

```python
def cmd_status(cfg: dict, args) -> None:
    """Cluster health overview — nodes, resource pressure, failing workloads."""
    host = cfg["host"]
    # TODO: implement — call host API and print results
    # url = f"{host}/api/v1/nodes"
    # data = api_get(url, auth_headers(cfg))
    print(f"[kubernetes-cluster-health] status: not yet implemented")
```

A finished version of the same function looks like this:

```python
def cmd_status(cfg: dict, args) -> None:
    """Cluster health overview — nodes, resource pressure, failing workloads."""
    data = api_get(f"{cfg['host']}/api/v1/nodes", auth_headers(cfg))
    nodes = data.get("items", [])
    print(f"{'NODE':<30} {'STATUS':<10} {'ROLES':<20} {'VERSION'}")
    print("-" * 75)
    for node in nodes:
        name    = node["metadata"]["name"]
        roles   = ",".join(k.split("/")[-1] for k in node["metadata"].get("labels", {})
                           if "node-role.kubernetes.io" in k) or "worker"
        version = node["status"]["nodeInfo"]["kubeletVersion"]
        ready   = next((c["status"] for c in node["status"]["conditions"]
                        if c["type"] == "Ready"), "Unknown")
        print(f"{name:<30} {ready:<10} {roles:<20} {version}")
```

The generator gives you the function signature, the docstring, the `cfg` wiring,
and the commented URL hint. The implementation is yours to write.

---

## The Problem It Solves

Building a Claude Code plugin from scratch means creating 19 interdependent
files — correct YAML frontmatter, consistent naming across all files, valid
`plugin.json`, skill/command/agent cross-references, a working Python CLI, and
a registered `marketplace.json` entry. Done by hand this takes 2–3 hours and
requires deep knowledge of the plugin format.

The generator eliminates the structural work entirely so you start at
implementation, not at blank files.

| Without the generator | With the generator |
|---|---|
| Manually create 19 files from scratch | One command |
| Look up YAML frontmatter field names | Claude reads the repo, matches format exactly |
| Copy-paste an existing plugin, strip all references | Fresh content for your domain |
| Write argparse boilerplate, helper functions | Generated `get_config()`, `auth_headers()`, `api_get()` |
| Update marketplace.json by hand | Claude reads and updates it automatically |
| 2–3 hours of setup | ~60 seconds to a working scaffold |

---

## Prerequisites

| Requirement | Details |
|---|---|
| **Claude Code** | Binary in `PATH`. Install: `npm install -g @anthropic-ai/claude-code` |
| **Authenticated** | Run `claude auth` if not already logged in |
| **Python 3.9+** | Stdlib only — no pip installs needed |

```bash
claude --version
python3 --version
```

---

## Usage

Run from the repository root:

```bash
# Pass description directly
python3 generate_plugin.py "Kubernetes cluster health monitor"

# Interactive prompt
python3 generate_plugin.py

# Pipe from stdin
echo "GitHub Actions CI/CD pipeline manager" | python3 generate_plugin.py

# Preview the prompt sent to Claude without calling it
python3 generate_plugin.py --show-prompt "PostgreSQL query optimizer"

# Skip project tree display
python3 generate_plugin.py --no-tree "AWS cost monitor"
```

### Flags

| Flag | Effect |
|---|---|
| `--show-prompt` | Print the full prompt, then exit. Claude is not called, no files written. |
| `--no-tree` | Skip displaying the project directory tree at startup. |

### Writing a good description

The description is the only domain knowledge Claude has to work with.
Specificity directly determines the quality of the output.

| Description | What you get |
|---|---|
| `"monitoring tool"` | Four generic monitoring skills, five generic commands |
| `"Prometheus alert manager"` | Alert-specific skills (`alert_rules`, `silences`, `receivers`), commands like `/prom-silence` and `/prom-routes` |
| `"Prometheus alert manager with silence scheduling, receiver routing, and inhibition rules"` | Highly specific skills and commands matching exactly those three concerns |

More words about the specific capabilities = better generated structure.

---

## What Happens Step by Step

```
1  Check claude binary in PATH
   └─ Exits with install instructions if not found

2  Accept description
   └─ CLI argument, stdin pipe, or interactive prompt

3  Scan the live repository tree
   └─ Passed to Claude so generated files match the existing plugin format

4  Derive plugin identifiers (locally, no Claude call)
   └─ slug:       kebab-case from description  ("kubernetes-cluster-health")
   └─ prefix:     short command prefix         ("k8s")
   └─ env_prefix: uppercase env var prefix     ("KUBERNETES_CLUSTER_HEALTH")
   └─ marketplace name: read from marketplace.json at runtime

5  Build structured prompt
   └─ Description + live tree + identifiers + per-file requirements

6  Invoke: claude -p "<prompt>"  (cwd = repo root)
   └─ Claude streams output to your terminal in real time
   └─ Claude uses its Write tool to create every file on disk
   └─ Claude reads and updates marketplace.json

7  Report created files
8  Print install instructions
```

---

## What Gets Generated

For `"Kubernetes cluster health monitor with pod management"`:

```
marketplace/plugins/kubernetes-cluster-health/
├── .claude-plugin/
│   └── plugin.json
├── CLAUDE.md
├── SKILLS_SUMMARY.md
├── agents/
│   └── k8s-operator.md
├── commands/
│   ├── init-kubernetes-cluster-health.md
│   ├── k8s-status.md
│   ├── k8s-pods.md
│   ├── k8s-deploy.md
│   ├── k8s-logs.md
│   └── k8s-events.md
├── skills/
│   ├── cluster_health/
│   │   ├── SKILL.md
│   │   └── reference.md
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
    └── k8s_helper.py
```

Plus a new entry in `marketplace/.claude-plugin/marketplace.json`.

**Total: 19 plugin files + 1 marketplace.json update.**

### Example: generated SKILL.md

```markdown
---
name: kubernetes-cluster-health-cluster_health
description: Cluster health monitoring — node status, resource pressure, failing
  pods. Use this skill when the user asks about kubernetes cluster health.
---
# Cluster Health

Node-level health monitoring across the cluster. Surfaces resource pressure,
unschedulable nodes, and pods in failed or pending states.

## Key Operations
- Query node readiness and condition flags (MemoryPressure, DiskPressure, PIDPressure)
- List pods in CrashLoopBackOff, Pending, or OOMKilled state
- Report resource requests vs allocatable capacity per node
- Detect unschedulable nodes and cordoned workers

## Output Format
Table: NODE · STATUS · ROLES · CPU% · MEM% · PODS
Follow with any failing pods grouped by namespace.
```

This is accurate and immediately usable as a skill Claude will auto-invoke.
The gap is in `reference.md` — the Python implementation needs real API calls.

### Example: generated command

```markdown
---
name: k8s-status
description: Cluster health overview — nodes, resource pressure, failing workloads
---
# Command: /k8s-status
# Usage: /k8s-status [--namespace <ns>]

## Description
Cluster health overview — nodes, resource pressure, failing workloads.

## Behavior
1. Read configuration from environment variables
2. Query node status and resource conditions via Kubernetes API
3. List pods in failed, pending, or crash-loop state
4. Present results as a structured table
5. Recommend next steps based on findings

## Example Invocations
- `/k8s-status`
- `/k8s-status --namespace kube-system`
```

The structure and frontmatter are correct. The behavior steps are real but
abstract — step 2 says "query via API" without knowing your auth method
(kubeconfig, service account token, in-cluster).

### Example: generated Python script (what you receive)

```python
#!/usr/bin/env python3
"""
k8s_helper.py — Kubernetes cluster health helper.

Usage:
    python3 k8s_helper.py status
    python3 k8s_helper.py pods
    python3 k8s_helper.py deploy

Required environment variables:
    KUBERNETES_CLUSTER_HEALTH_HOST    Kubernetes API server URL
    KUBERNETES_CLUSTER_HEALTH_TOKEN   Bearer token for authentication
"""

import os, sys, json, argparse, urllib.request, urllib.error

def get_config() -> dict:
    return {
        "host":  os.environ.get("KUBERNETES_CLUSTER_HEALTH_HOST", "").rstrip("/"),
        "token": os.environ.get("KUBERNETES_CLUSTER_HEALTH_TOKEN", ""),
        "org":   os.environ.get("KUBERNETES_CLUSTER_HEALTH_ORG", ""),
    }

def check_config() -> dict:
    cfg = get_config()
    if not cfg["host"]:
        print("ERROR: KUBERNETES_CLUSTER_HEALTH_HOST is not set", file=sys.stderr)
        sys.exit(1)
    return cfg

def auth_headers(cfg: dict) -> dict:
    h = {"Accept": "application/json", "Content-Type": "application/json"}
    if cfg["token"]:
        h["Authorization"] = f"Bearer {cfg['token']}"
    return h

def api_get(url: str, headers: dict) -> dict:
    try:
        req = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(req, timeout=30) as resp:
            return json.loads(resp.read())
    except urllib.error.HTTPError as e:
        print(f"HTTP {e.code}: {e.read().decode()[:200]}", file=sys.stderr)
        sys.exit(1)

def cmd_status(cfg: dict, args) -> None:
    """Cluster health overview — nodes, resource pressure, failing workloads."""
    host = cfg["host"]
    # TODO: implement — call host API and print results
    # url = f"{host}/api/v1/nodes"
    # data = api_get(url, auth_headers(cfg))
    print(f"[kubernetes-cluster-health] status: not yet implemented")
```

The helper functions (`get_config`, `check_config`, `auth_headers`, `api_get`)
are complete and production-quality. Only the `cmd_*` function bodies need work.

---

## What to Expect During Generation

```
Checking Claude Code installation...
  ✓  /usr/local/bin/claude

Plugin description:
  Kubernetes cluster health monitor with pod management

Current project structure:
  your-plugin-repo/
  ├── marketplace/
  │   ├── .claude-plugin/
  │   │   └── marketplace.json
  │   └── plugins/
  ...

Plugin identifiers:
  slug        : kubernetes-cluster-health
  prefix      : k8s
  env prefix  : KUBERNETES_CLUSTER_HEALTH
  marketplace : my-marketplace      ← read from marketplace/.claude-plugin/marketplace.json

Calling Claude Code to generate plugin files...
  (Claude will write files directly using its Write tool)
```

Claude's output then streams live to your terminal — you see each file being
written in real time. **Typical time: 45–90 seconds.**

After Claude finishes, the script lists every created file:

```
Plugin files written (19 total):
  + marketplace/plugins/kubernetes-cluster-health/.claude-plugin/plugin.json
  + marketplace/plugins/kubernetes-cluster-health/CLAUDE.md
  + marketplace/plugins/kubernetes-cluster-health/SKILLS_SUMMARY.md
  ...

Install the new plugin:

  /plugin marketplace add /Users/you/repo/marketplace
  /plugin install kubernetes-cluster-health@my-marketplace
  /reload-plugins
  /init-kubernetes-cluster-health
```

---

## After Generation: Closing the Gap

The scaffold is a starting point. Here is the realistic path from scaffold to
working plugin.

### Step 1 — Install and confirm the structure loads

```
/plugin marketplace add /path/to/repo/marketplace
/plugin install kubernetes-cluster-health@my-marketplace
/reload-plugins
/init-kubernetes-cluster-health
```

You should see the command menu. The plugin is loaded but commands return
"not yet implemented."

### Step 2 — Implement the Python script

Open a Claude Code session and point it at the generated script and your
target system's API docs:

```
Read marketplace/plugins/kubernetes-cluster-health/scripts/k8s_helper.py.

Then implement cmd_status() to call GET /api/v1/nodes on the Kubernetes
API server using the token in cfg["token"], and print a table of:
node name | Ready status | CPU allocatable | Memory allocatable | Pod count

The Kubernetes nodes API response has this shape:
{"items": [{"metadata": {"name": "..."}, "status": {"conditions": [...],
"allocatable": {"cpu": "...", "memory": "..."}}}]}
```

Claude Code will read the file, understand the existing helpers, and write
a working implementation.

### Step 3 — Enrich the skills

The generated `SKILL.md` files are structurally correct but thin on detail.
After implementing the script, update the **Key Operations** sections with
the actual queries and filters your commands use:

**Generated (thin):**
```markdown
## Key Operations
- Query current status and health
- Identify issues and anomalies
- Recommend remediation actions
- Automate common cluster_health tasks
```

**Enriched (useful):**
```markdown
## Key Operations
- `GET /api/v1/nodes` — node readiness, MemoryPressure, DiskPressure, PIDPressure conditions
- `GET /api/v1/pods?fieldSelector=status.phase=Failed` — failed pods cluster-wide
- `GET /apis/apps/v1/deployments` — deployment replica status and rollout state
- Node NotReady for >5 min → escalate; CrashLoopBackOff >3 restarts → investigate logs
```

### Step 4 — Set environment variables

```bash
export KUBERNETES_CLUSTER_HEALTH_HOST="https://your-k8s-api-server:6443"
export KUBERNETES_CLUSTER_HEALTH_TOKEN="$(kubectl get secret ... -o jsonpath=...)"
```

### Full before/after example

**Before (generated, ~60 seconds):**
```
/k8s-status  →  "[kubernetes-cluster-health] status: not yet implemented"
```

**After (30–60 min of implementation work):**
```
/k8s-status

NODE                           STATUS     ROLES         VERSION
──────────────────────────────────────────────────────────────────
prod-node-01                   Ready      control-plane v1.28.4
prod-node-02                   Ready      worker        v1.28.4
prod-node-03                   NotReady   worker        v1.28.4   ← MemoryPressure

FAILING PODS (2)
  kube-system / coredns-abc123    CrashLoopBackOff  (8 restarts)
  default / api-server-xyz        OOMKilled         (2 restarts)

Recommendation: prod-node-03 has memory pressure — check running pods.
  /k8s-logs coredns-abc123 --namespace kube-system
```

---

## Slug and Prefix Derivation

Identifiers are derived locally (before Claude is called) for consistency:

| Input description | Slug | Prefix | Env prefix |
|---|---|---|---|
| `"Kubernetes cluster health monitor"` | `kubernetes-cluster-health` | `k8s` | `KUBERNETES_CLUSTER_HEALTH` |
| `"GitHub Actions CI/CD manager"` | `github-actions-ci-cd` | `gha` | `GITHUB_ACTIONS_CI_CD` |
| `"PostgreSQL schema migration tool"` | `postgresql-schema-migration` | `db` | `POSTGRESQL_SCHEMA_MIGRATION` |
| `"AWS cost optimization"` | `aws-cost-optimization` | `aws` | `AWS_COST_OPTIMIZATION` |
| `"Prometheus alert silence manager"` | `prometheus-alert-silence` | `mon` | `PROMETHEUS_ALERT_SILENCE` |
| `"Custom internal approval workflow"` | `custom-internal-approval` | `cust` | `CUSTOM_INTERNAL_APPROVAL` |

Stop words (`a`, `the`, `and`, `build`, `create`, `tool`, `app`, etc.) are
stripped. Domain keywords (`kubernetes`, `aws`, `docker`, etc.) map to known
prefixes. Unknown domains use initials of the slug words.

---

## Troubleshooting

**`ERROR: Claude Code binary not found`**
```bash
npm install -g @anthropic-ai/claude-code
export PATH="$PATH:$(npm root -g)/.bin"
```

**`claude exited with code 1`**
Not authenticated. Run `claude auth` and complete the login flow, then retry.

**Plugin directory already exists**
The script prompts before overwriting. Answer `y` to regenerate all files,
`n` to abort and keep the existing plugin.

**Output looks generic, not specific to my domain**
Use a more specific description. Add the names of key operations, APIs, or
concepts your plugin will cover:
- Too vague: `"monitoring tool"` → generic skills
- Better: `"Datadog monitor management with downtime scheduling and SLO tracking"` → targeted skills

**Fewer than 19 files were created**
Claude occasionally truncates. Run the generator again — the prompt is
identical each run so you will get a complete result on retry.

**`/plugin install` says marketplace not found**
Register the marketplace first:
```
/plugin marketplace add /absolute/path/to/repo/marketplace
```
The marketplace path printed by the script is always the correct absolute path.
