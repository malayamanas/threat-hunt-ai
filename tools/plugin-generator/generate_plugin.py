#!/usr/bin/env python3
"""
generate_plugin.py — Claude Code Plugin Generator

Verifies the Claude Code binary, scans the current marketplace structure,
then invokes `claude -p` from the repo root so Claude uses its own Write
tool to create every plugin file directly — no template generation, no
output parsing.  Claude writes the files; we just drive the invocation.

Usage:
    python3 generate_plugin.py "Kubernetes cluster health monitor"
    python3 generate_plugin.py                    # interactive prompt
    echo "GitHub Actions CI/CD manager" | python3 generate_plugin.py
    python3 generate_plugin.py --show-prompt "…"  # print prompt and exit
"""

import re
import sys
import json
import shutil
import argparse
import subprocess
from pathlib import Path

REPO_ROOT        = Path(__file__).parent.parent.parent.resolve()
MARKETPLACE_DIR  = REPO_ROOT / "marketplace"
PLUGINS_DIR      = MARKETPLACE_DIR / "plugins"
MARKETPLACE_JSON = MARKETPLACE_DIR / ".claude-plugin" / "marketplace.json"

# ── Terminal helpers ──────────────────────────────────────────────────────────

def bold(s):   return f"\033[1m{s}\033[0m"
def green(s):  return f"\033[32m{s}\033[0m"
def yellow(s): return f"\033[33m{s}\033[0m"
def dim(s):    return f"\033[2m{s}\033[0m"


# ── 1. Locate Claude Code binary ──────────────────────────────────────────────

def check_claude() -> str:
    """Return path to claude binary or print install instructions and exit."""
    path = shutil.which("claude")
    if path:
        return path
    for extra in [
        Path.home() / ".claude" / "bin" / "claude",
        Path("/usr/local/bin/claude"),
        Path("/opt/homebrew/bin/claude"),
        Path("/home/linuxbrew/.linuxbrew/bin/claude"),
    ]:
        if extra.exists():
            print(yellow(f"  claude found at {extra} (not on PATH)"))
            print(yellow(f"  To fix: export PATH=\"$PATH:{extra.parent}\""))
            return str(extra)
    print(bold("ERROR: Claude Code binary not found."))
    print()
    print("Install:")
    print("  npm install -g @anthropic-ai/claude-code")
    print("  Or download from: https://claude.ai/download")
    sys.exit(1)


# ── 2. Input ──────────────────────────────────────────────────────────────────

def get_input_text(args) -> str:
    if args.description:
        text = " ".join(args.description).strip()
        if text:
            return text
    if not sys.stdin.isatty():
        text = sys.stdin.read().strip()
        if text:
            return text
    print()
    print(bold("Describe the plugin / software to build:"))
    print(dim("  Examples:"))
    print(dim("    Kubernetes cluster health monitor with pod management"))
    print(dim("    GitHub Actions CI/CD pipeline manager"))
    print(dim("    PostgreSQL schema migration and query optimizer"))
    print(dim("    AWS cost analysis and resource inventory"))
    print()
    try:
        text = input("> ").strip()
    except (EOFError, KeyboardInterrupt):
        print()
        sys.exit(0)
    if not text:
        print("ERROR: No description provided.")
        sys.exit(1)
    return text


# ── 3. Project tree ───────────────────────────────────────────────────────────

_SKIP = {".git", "__pycache__", ".DS_Store", "node_modules",
         ".mypy_cache", ".pytest_cache", ".ruff_cache", "dist", "build"}

def _tree_lines(root: Path, prefix: str = "", depth: int = 4) -> list:
    if depth == 0:
        return [prefix + "  ..."]
    try:
        entries = sorted(root.iterdir(), key=lambda p: (p.is_file(), p.name.lower()))
    except PermissionError:
        return []
    entries = [e for e in entries if e.name not in _SKIP and not e.name.startswith(".git")]
    lines = []
    for i, e in enumerate(entries):
        last = i == len(entries) - 1
        lines.append(f"{prefix}{'└── ' if last else '├── '}{e.name}{'/' if e.is_dir() else ''}")
        if e.is_dir():
            lines.extend(_tree_lines(e, prefix + ("    " if last else "│   "), depth - 1))
    return lines

def tree_string(root: Path) -> str:
    return root.name + "/\n" + "\n".join(_tree_lines(root, depth=4))

def print_project_tree(root: Path):
    print()
    print(bold("Current project structure:"))
    for line in tree_string(root).splitlines():
        print("  " + line)
    print()


# ── 4. Plugin slug + prefix (naming only — all content comes from Claude) ─────

_STOP = {
    "a","an","the","and","or","for","of","with","by","in","on","to","from",
    "as","is","are","be","this","that","build","create","make","develop",
    "write","add","using","use","new","tool","plugin","app","application",
    "help","based","into","via","my","your","our","it","its",
}

_DOMAIN_PREFIXES = {
    "kubernetes":"k8s", "k8s":"k8s", "pod":"k8s",
    "github":"gh", "gitlab":"gl",
    "actions":"gha", "ci/cd":"gha", "pipeline":"pipe",
    "terraform":"tf", "pulumi":"iac", "ansible":"iac",
    "aws":"aws", "amazon":"aws",
    "gcp":"gcp", "azure":"az",
    "docker":"dkr", "container":"dkr",
    "django":"dj", "flask":"api", "fastapi":"api",
    "react":"fe", "vue":"fe", "frontend":"fe",
    "postgresql":"db", "postgres":"db", "mysql":"db", "sql":"db",
    "mongodb":"mdb", "redis":"rdb", "elastic":"es",
    "prometheus":"mon", "grafana":"mon", "monitoring":"mon",
    "security":"sec", "vulnerability":"sec",
    "pytest":"test", "jest":"test", "testing":"test",
    "airflow":"data", "spark":"data", "dbt":"data",
    "machine":"ml", "mlflow":"ml", "model":"ml",
    "jira":"pm", "kanban":"pm",
    "slack":"ntfy", "teams":"ntfy",
    "linux":"sys", "bash":"sys", "server":"sys",
}

def _slugify(text: str) -> str:
    text = re.sub(r"[^a-zA-Z0-9\s\-]", "", text)
    text = re.sub(r"\s+", "-", text.strip()).lower()
    parts = [p for p in text.split("-") if p and p not in _STOP and len(p) > 1]
    return "-".join(parts[:4]) or "custom-plugin"

def _make_prefix(text: str, slug: str) -> str:
    tl = text.lower()
    for kw, pfx in _DOMAIN_PREFIXES.items():
        if kw in tl:
            return pfx
    parts = slug.split("-")
    return "".join(p[0] for p in parts[:5]) if len(parts) > 1 else parts[0][:5]

def build_spec(text: str) -> dict:
    slug       = _slugify(text)
    prefix     = _make_prefix(text, slug)
    env_prefix = slug.upper().replace("-", "_")
    return {
        "slug":        slug,
        "prefix":      prefix,
        "env_prefix":  env_prefix,
        "description": text,
        "plugin_dir":  PLUGINS_DIR / slug,
    }


# ── 5. Marketplace name (read from JSON, never hardcoded) ─────────────────────

def get_marketplace_name() -> str:
    if MARKETPLACE_JSON.exists():
        try:
            data = json.loads(MARKETPLACE_JSON.read_text())
            name = data.get("name", "").strip()
            if name:
                return name
        except (json.JSONDecodeError, OSError):
            pass
    return MARKETPLACE_DIR.name  # fallback: directory name


# ── 6. Build the prompt that Claude will execute ──────────────────────────────

def build_prompt(spec: dict, repo_tree: str) -> str:
    slug        = spec["slug"]
    prefix      = spec["prefix"]
    env_prefix  = spec["env_prefix"]
    description = spec["description"]
    mkt_name    = get_marketplace_name()

    return f"""Create a complete Claude Code plugin scaffold in this repository.

SOFTWARE / TOOL TO BUILD FOR:
{description}

CURRENT REPOSITORY STRUCTURE:
{repo_tree}

PLUGIN IDENTIFIERS:
  slug        : {slug}
  prefix      : {prefix}    (slash command prefix, e.g. /{prefix}-status)
  env_prefix  : {env_prefix}    (env var prefix, e.g. {env_prefix}_HOST)
  marketplace : {mkt_name}

YOUR TASK:
Use the Write tool to create all 19 files listed below inside this repository.
After writing all plugin files, also update marketplace/.claude-plugin/marketplace.json
to register the new plugin (add an entry to the "plugins" array).

Make all content specific and meaningful for: {description}
Do NOT copy content from fsiem-essentials — generate fresh content for this domain.

FILES TO CREATE:

[1] marketplace/plugins/{slug}/.claude-plugin/plugin.json
    JSON with: name="{slug}", version="1.0.0", description (one sentence about {description}),
    author object with name and email placeholders.

[2] marketplace/plugins/{slug}/CLAUDE.md
    Plugin-level Claude guidelines. Include:
    - H1 title + overview paragraph for {description}
    - Skills table: Directory | Skill Name | Purpose
    - Commands table: Command | Purpose
    - Operational defaults section

[3] marketplace/plugins/{slug}/SKILLS_SUMMARY.md
    Full reference tables: skills, commands, agent, scripts.

[4] marketplace/plugins/{slug}/commands/init-{slug}.md
    YAML frontmatter: name: init-{slug}, description: one-line.
    ## Behavior: check env vars, test connectivity, print command menu.
    ## Session Summary Output: fenced block with the full command menu.

[5–9] Five slash commands (one file each):
    marketplace/plugins/{slug}/commands/{prefix}-<name>.md
    Design 5 meaningful commands for: {description}
    Each file: YAML frontmatter (name, description), ## Description,
    ## Behavior (numbered steps), ## Example Invocations.

[10–17] Four skills (two files each):

    marketplace/plugins/{slug}/skills/<skill_name>/SKILL.md
      YAML frontmatter:
        name: {slug}-<skill_name>
        description: what it does and when Claude should auto-invoke it
      ## Overview (2–3 sentences)
      ## Key Operations (3–4 bullets)
      ## Output Format
      Keep under 60 lines; move long code to reference.md.

    marketplace/plugins/{slug}/skills/<skill_name>/reference.md
      Python reference implementation.
      Use urllib only (no requests / no third-party libs).
      get_config() reads {env_prefix}_HOST and {env_prefix}_TOKEN from env.
      One main function with a TODO where the real API call goes.
      if __name__ == "__main__": block for standalone use.

[18] marketplace/plugins/{slug}/agents/<agent-name>.md
    YAML frontmatter: name, description (full agent role).
    ## Architecture, ## Core Script, ## Workflow, ## Available Commands.

[19] marketplace/plugins/{slug}/scripts/<script-name>.py
    #!/usr/bin/env python3 shebang.
    Docstring: usage examples + required env vars ({env_prefix}_HOST, {env_prefix}_TOKEN).
    Helper functions: get_config(), check_config(), auth_headers(cfg), api_get(url, headers).
    One cmd_<name>(cfg, args) per command with TODO for API call.
    main() with argparse subparsers.
    stdlib ONLY — no requests, no boto3, no third-party packages.

Write all 19 files now.

Then update marketplace/.claude-plugin/marketplace.json:
- Read the current file
- Add a new entry to the "plugins" array:
  {{
    "name":        "{slug}",
    "description": "{description}",
    "source":      "./plugins/{slug}",
    "category":    "<choose the most accurate single-word category for: {description}>",
    "version":     "1.0.0"
  }}
- Write the updated JSON back (preserve all existing entries)"""


# ── 7. Invoke Claude Code (writes files via its own Write tool) ───────────────

def call_claude(claude_path: str, prompt: str):
    """
    Run `claude -p <prompt>` from the repo root.
    Claude's output streams directly to the terminal — Claude uses its
    Write tool to create every plugin file in place.
    Exits the script if claude returns a non-zero exit code.
    """
    result = subprocess.run(
        [claude_path, "-p", prompt],
        cwd=str(REPO_ROOT),   # gives Claude file-system access to the whole repo
    )
    if result.returncode != 0:
        print()
        print(bold(f"ERROR: claude exited with code {result.returncode}"))
        sys.exit(1)


# ── 8. Verify and report what Claude created ──────────────────────────────────

def report_created_files(plugin_dir: Path):
    if not plugin_dir.exists():
        print(yellow("  WARNING: plugin directory was not created."))
        return 0
    files = sorted(f for f in plugin_dir.rglob("*") if f.is_file())
    print(bold(f"\nPlugin files written ({len(files)} total):"))
    for f in files:
        print(f"  {green('+')} {f.relative_to(REPO_ROOT)}")
    return len(files)


# ── 9. Main ───────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Generate a Claude Code plugin by invoking `claude -p` in the repo.",
        epilog=(
            "Examples:\n"
            "  python3 generate_plugin.py \"Kubernetes cluster health monitor\"\n"
            "  python3 generate_plugin.py \"GitHub Actions CI/CD manager\"\n"
            "  echo \"Django REST API\" | python3 generate_plugin.py\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("description", nargs="*", help="Plugin description")
    parser.add_argument("--no-tree",     action="store_true", help="Skip project tree display")
    parser.add_argument("--show-prompt", action="store_true", help="Print the prompt and exit without calling Claude")
    args = parser.parse_args()

    # ── Step 1: Verify claude binary ──────────────────────────────────────────
    print(bold("Checking Claude Code installation..."))
    claude_path = check_claude()
    print(green(f"  ✓  {claude_path}"))

    # ── Step 2: Input ─────────────────────────────────────────────────────────
    text = get_input_text(args)
    print()
    print(bold("Plugin description:"))
    print(f"  {text}")

    # ── Step 3: Project tree ──────────────────────────────────────────────────
    repo_tree = tree_string(REPO_ROOT)
    if not args.no_tree:
        print_project_tree(REPO_ROOT)

    # ── Step 4: Derive slug / prefix for naming ────────────────────────────────
    spec = build_spec(text)
    print(bold("Plugin identifiers:"))
    print(f"  slug        : {spec['slug']}")
    print(f"  prefix      : {spec['prefix']}")
    print(f"  env prefix  : {spec['env_prefix']}")
    print(f"  marketplace : {get_marketplace_name()}")

    # ── Step 5: Build prompt ──────────────────────────────────────────────────
    prompt = build_prompt(spec, repo_tree)

    if args.show_prompt:
        print()
        print(bold("Prompt sent to Claude:"))
        print(dim("─" * 60))
        print(prompt)
        print(dim("─" * 60))
        sys.exit(0)

    # ── Step 6: Guard against overwriting existing plugin ─────────────────────
    if spec["plugin_dir"].exists():
        print()
        print(yellow(f"  WARNING: {spec['plugin_dir'].relative_to(REPO_ROOT)} already exists."))
        try:
            ans = input("  Overwrite? [y/N] ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            print()
            sys.exit(0)
        if ans != "y":
            print("  Aborted.")
            sys.exit(0)

    # ── Step 7: Call Claude — it writes all files via its Write tool ──────────
    print()
    print(bold("Calling Claude Code to generate plugin files..."))
    print(dim("  (Claude will write files directly using its Write tool)"))
    print()
    call_claude(claude_path, prompt)

    # ── Step 8: Report what was created ───────────────────────────────────────
    report_created_files(spec["plugin_dir"])

    # ── Step 9: Install instructions ─────────────────────────────────────────
    slug            = spec["slug"]
    marketplace_name = get_marketplace_name()
    print()
    print(bold("Install the new plugin:"))
    print()
    print(f"  /plugin marketplace add {MARKETPLACE_DIR}")
    print(f"  /plugin install {slug}@{marketplace_name}")
    print(f"  /reload-plugins")
    print(f"  /init-{slug}")
    print()


if __name__ == "__main__":
    main()
