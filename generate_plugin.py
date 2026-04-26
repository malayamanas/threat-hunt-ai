#!/usr/bin/env python3
"""
generate_plugin.py — Claude Code Plugin Generator (Claude-Powered)

Verifies the Claude Code binary, scans the current marketplace structure,
builds a context-rich prompt, and invokes `claude -p` to generate a complete
plugin scaffold tailored to the input description.  Every file's content
comes from Claude — no hardcoded templates.

Usage:
    python3 generate_plugin.py "Kubernetes cluster health monitor"
    python3 generate_plugin.py                   # interactive prompt
    echo "GitHub Actions CI/CD manager" | python3 generate_plugin.py
    python3 generate_plugin.py --dry-run "..."   # preview paths without writing
"""

import os
import sys
import re
import json
import shutil
import argparse
import subprocess
import threading
import time
from pathlib import Path

REPO_ROOT        = Path(__file__).parent.resolve()
MARKETPLACE_DIR  = REPO_ROOT / "marketplace"
PLUGINS_DIR      = MARKETPLACE_DIR / "plugins"
MARKETPLACE_JSON = MARKETPLACE_DIR / ".claude-plugin" / "marketplace.json"

# ── Terminal helpers ──────────────────────────────────────────────────────────

def bold(s):   return f"\033[1m{s}\033[0m"
def green(s):  return f"\033[32m{s}\033[0m"
def yellow(s): return f"\033[33m{s}\033[0m"
def dim(s):    return f"\033[2m{s}\033[0m"
def cyan(s):   return f"\033[36m{s}\033[0m"


# ── 1. Locate Claude Code binary ──────────────────────────────────────────────

def check_claude() -> str:
    """Return path to the claude binary or print install instructions and exit."""
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
    print()
    print("Verify with: claude --version")
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

_SKIP = {".git", "__pycache__", ".DS_Store", "node_modules", ".mypy_cache",
         ".pytest_cache", ".ruff_cache", "dist", "build"}

def _tree_lines(root: Path, prefix: str = "", depth: int = 4) -> list:
    if depth == 0:
        return ["  " + prefix + "  ..."]
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


# ── 4. Minimal spec (slug + prefix only — content comes from Claude) ──────────

_STOP = {
    "a","an","the","and","or","for","of","with","by","in","on","to","from",
    "as","is","are","be","this","that","build","create","make","develop",
    "write","add","using","use","new","tool","plugin","app","application",
    "help","based","into","via","my","your","our","it","its",
}

_DOMAIN_PREFIXES = {
    "kubernetes": "k8s",  "k8s": "k8s",  "pod": "k8s",
    "github":     "gh",   "gitlab": "gl",
    "actions":    "gha",  "ci/cd": "gha",  "pipeline": "pipe",
    "terraform":  "tf",   "pulumi": "iac",  "ansible": "iac",
    "aws":        "aws",  "amazon": "aws",
    "gcp":        "gcp",  "azure": "az",
    "docker":     "dkr",  "container": "dkr",
    "django":     "dj",   "flask": "api",  "fastapi": "api",
    "react":      "fe",   "vue": "fe",  "frontend": "fe",
    "postgresql": "db",   "postgres": "db",  "mysql": "db",  "sql": "db",
    "mongodb":    "mdb",  "redis": "rdb",  "elastic": "es",
    "prometheus": "mon",  "grafana": "mon",  "monitoring": "mon",
    "security":   "sec",  "vulnerability": "sec",
    "pytest":     "test", "jest": "test",  "testing": "test",
    "airflow":    "data", "spark": "data",  "dbt": "data",
    "machine":    "ml",   "mlflow": "ml",  "model": "ml",
    "jira":       "pm",   "kanban": "pm",
    "slack":      "ntfy", "teams": "ntfy",
    "linux":      "sys",  "bash": "sys",  "server": "sys",
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
    if len(parts) == 1:
        return parts[0][:5]
    return "".join(p[0] for p in parts[:5])

def build_spec(text: str) -> dict:
    slug       = _slugify(text)
    prefix     = _make_prefix(text, slug)
    env_prefix = slug.upper().replace("-", "_")
    return {
        "slug":       slug,
        "prefix":     prefix,
        "env_prefix": env_prefix,
        "description": text,
        "plugin_dir": PLUGINS_DIR / slug,
    }


# ── 5. Build prompt for Claude ────────────────────────────────────────────────

def build_prompt(spec: dict, repo_tree: str) -> str:
    slug       = spec["slug"]
    prefix     = spec["prefix"]
    env_prefix = spec["env_prefix"]
    description = spec["description"]

    return f"""You are generating a Claude Code plugin scaffold for this existing marketplace repository.

SOFTWARE / TOOL TO BUILD A PLUGIN FOR:
{description}

REPOSITORY STRUCTURE (for context and format reference):
{repo_tree}

PLUGIN METADATA:
  slug:       {slug}
  prefix:     {prefix}    (slash command prefix  e.g. /{prefix}-status)
  env_prefix: {env_prefix}   (env var prefix  e.g. {env_prefix}_HOST)

=== OUTPUT FORMAT ===
Use EXACTLY this delimiter format for every file. No prose, no markdown fences around the delimiters.

>>>FILE: relative/path/from/repo/root
<complete file contents>
>>>ENDFILE

Start your response immediately with >>>FILE:  (no preamble).
=== END FORMAT ===

Generate these 19 files, all tailored specifically to: {description}

[1] marketplace/plugins/{slug}/.claude-plugin/plugin.json
    JSON manifest. Fields: name="{slug}", version="1.0.0", description (one sentence), author object.

[2] marketplace/plugins/{slug}/CLAUDE.md
    Plugin-level Claude guidelines. Include:
    - H1 title + one-paragraph overview of {description}
    - Skills table  (Directory | Skill Name | Purpose)
    - Commands table (Command | Purpose)
    - Operational defaults (confirm before destructive ops, table output format, read creds from env vars)

[3] marketplace/plugins/{slug}/SKILLS_SUMMARY.md
    Full reference. Tables: skills, commands, agent, scripts.

[4] marketplace/plugins/{slug}/commands/init-{slug}.md
    YAML frontmatter (name: init-{slug}, description: one-line init description).
    ## Behavior: check env vars, test connectivity, print command menu.
    ## Session Summary Output: fenced block showing the menu.

[5-9] Five slash commands: marketplace/plugins/{slug}/commands/{prefix}-<name>.md
    Design 5 meaningful commands for: {description}
    Each file must have:
      - YAML frontmatter: name and description fields
      - ## Description
      - ## Behavior (numbered steps)
      - ## Example Invocations (2-3 examples)

[10-17] Four skills (8 files total):
    marketplace/plugins/{slug}/skills/<skill_name>/SKILL.md
      YAML frontmatter:
        name: {slug}-<skill_name>
        description: <what it does and when Claude should auto-invoke it>
      ## Overview (2-3 sentences)
      ## Key Operations (3-4 bullet points)
      ## Output Format (table columns and structure)
      Keep under 60 lines. Long implementations go in reference.md.

    marketplace/plugins/{slug}/skills/<skill_name>/reference.md
      Full Python implementation using only urllib (no third-party libs).
      Include get_config() reading {env_prefix}_HOST and {env_prefix}_TOKEN from env.
      One main function implementing the skill with a TODO where the API call goes.
      Include if __name__ == "__main__": block for standalone use.

[18] marketplace/plugins/{slug}/agents/<agent-name>.md
    YAML frontmatter (name, description as the agent's full role description).
    ## Architecture: Python scripts handle data collection, AI agent interprets results.
    ## Core Script: bash code block showing how to run the main script.
    ## Workflow: Step 1 collect, Step 2 analyze, Step 3 report.
    ## Available Commands: list of /{prefix}-* commands.

[19] marketplace/plugins/{slug}/scripts/<script-name>.py
    Requirements (all must be met):
    - #!/usr/bin/env python3 shebang
    - Module docstring with usage examples and required env var list
    - get_config() → dict reading {env_prefix}_HOST, {env_prefix}_TOKEN, {env_prefix}_ORG
    - check_config() → validates required vars, prints helpful error and exits if missing
    - auth_headers(cfg) → returns Authorization header dict
    - api_get(url, headers) → urllib GET returning parsed JSON, handles HTTPError/URLError
    - One cmd_<name>(cfg, args) function per command with TODO comment for API call
    - main() with argparse subparsers, one per command
    - if __name__ == "__main__": main()
    - stdlib ONLY — no requests, no boto3, no third-party packages

Generate all 19 files now, starting immediately with >>>FILE:"""


# ── 6. Invoke Claude ──────────────────────────────────────────────────────────

def _spinner(stop_event: threading.Event, message: str):
    frames = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]
    i = 0
    while not stop_event.is_set():
        print(f"\r  {frames[i % len(frames)]}  {message}", end="", flush=True)
        time.sleep(0.1)
        i += 1
    print(f"\r  ✓  {message}          ")


def call_claude(claude_path: str, prompt: str) -> str:
    """Run `claude -p <prompt>` and return stdout. Streams a spinner while waiting."""
    stop = threading.Event()
    spin = threading.Thread(
        target=_spinner,
        args=(stop, "Claude is generating plugin content..."),
        daemon=True,
    )
    spin.start()
    try:
        result = subprocess.run(
            [claude_path, "-p", prompt],
            capture_output=True,
            text=True,
            timeout=360,
        )
    except subprocess.TimeoutExpired:
        stop.set()
        spin.join()
        print(bold("ERROR: claude timed out after 6 minutes."))
        sys.exit(1)
    finally:
        stop.set()
        spin.join()

    if result.returncode != 0:
        print(bold(f"ERROR: claude exited with code {result.returncode}"))
        if result.stderr:
            print(result.stderr[:600])
        sys.exit(1)

    return result.stdout


# ── 7. Parse Claude's output into {path: content} ────────────────────────────

def parse_output(raw: str) -> dict:
    """
    Scan for >>>FILE: / >>>ENDFILE delimiters and return {relative_path: content}.
    Robust to extra whitespace and missing trailing ENDFILE.
    """
    files = {}
    current_path = None
    current_lines = []

    for line in raw.splitlines():
        stripped = line.strip()
        if stripped.startswith(">>>FILE:"):
            # Save previous block
            if current_path is not None:
                files[current_path] = "\n".join(current_lines).rstrip() + "\n"
            current_path = stripped[len(">>>FILE:"):].strip()
            current_lines = []
        elif stripped.startswith(">>>ENDFILE") or stripped == ">>>END FILE":
            if current_path is not None:
                files[current_path] = "\n".join(current_lines).rstrip() + "\n"
            current_path = None
            current_lines = []
        elif current_path is not None:
            current_lines.append(line)

    # Handle last block with no closing ENDFILE
    if current_path and current_lines:
        files[current_path] = "\n".join(current_lines).rstrip() + "\n"

    return files


# ── 8. Write plugin files ─────────────────────────────────────────────────────

def _write(path: Path, content: str, dry_run: bool):
    rel = path.relative_to(REPO_ROOT)
    if dry_run:
        print(f"  {dim('[dry-run]')} {rel}")
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    print(f"  {green('+')} {rel}")


def create_plugin(files: dict, spec: dict, dry_run: bool):
    if not files:
        print(bold("ERROR: Claude returned no parseable files."))
        print("  Claude's raw output did not contain any >>>FILE: blocks.")
        print("  Try running again — the model occasionally misformats the output.")
        sys.exit(1)

    slug = spec["slug"]
    print()
    print(bold(f"Writing {len(files)} files for plugin '{slug}':"))
    for rel_path, content in sorted(files.items()):
        abs_path = REPO_ROOT / rel_path
        _write(abs_path, content, dry_run)

    # chmod +x any generated .py scripts
    if not dry_run:
        for rel_path in files:
            if rel_path.endswith(".py"):
                p = REPO_ROOT / rel_path
                if p.exists():
                    p.chmod(p.stat().st_mode | 0o111)


def get_marketplace_name() -> str:
    """Read the marketplace name from marketplace.json (the @handle used in /plugin install)."""
    if MARKETPLACE_JSON.exists():
        try:
            with open(MARKETPLACE_JSON) as f:
                data = json.load(f)
            name = data.get("name", "").strip()
            if name:
                return name
        except (json.JSONDecodeError, OSError):
            pass
    return MARKETPLACE_DIR.name   # fallback: directory name


def update_marketplace(spec: dict, dry_run: bool):
    if not MARKETPLACE_JSON.exists():
        print(yellow("  marketplace.json not found — skipping"))
        return
    with open(MARKETPLACE_JSON) as f:
        data = json.load(f)
    if any(p["name"] == spec["slug"] for p in data.get("plugins", [])):
        print(yellow(f"  '{spec['slug']}' already in marketplace.json — skipping"))
        return
    data.setdefault("plugins", []).append({
        "name":        spec["slug"],
        "description": spec["description"],
        "source":      f"./plugins/{spec['slug']}",
        "category":    "plugin",
        "version":     "1.0.0",
    })
    _write(MARKETPLACE_JSON, json.dumps(data, indent=2) + "\n", dry_run)


# ── 9. Main ───────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Generate a Claude Code plugin scaffold via claude -p.",
        epilog=(
            "Examples:\n"
            "  python3 generate_plugin.py \"Kubernetes cluster health monitor\"\n"
            "  python3 generate_plugin.py --dry-run \"GitHub Actions manager\"\n"
            "  echo \"Django REST API\" | python3 generate_plugin.py\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("description", nargs="*", help="Plugin description")
    parser.add_argument("--dry-run",  action="store_true", help="Preview paths without writing files")
    parser.add_argument("--no-tree",  action="store_true", help="Skip project tree display")
    parser.add_argument("--show-prompt", action="store_true", help="Print the prompt sent to Claude and exit")
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

    # ── Step 4: Derive slug / prefix (naming only) ────────────────────────────
    spec = build_spec(text)
    print(bold("Plugin identifiers:"))
    print(f"  slug       : {spec['slug']}")
    print(f"  prefix     : {spec['prefix']}")
    print(f"  env prefix : {spec['env_prefix']}")

    # ── Step 5: Build prompt ──────────────────────────────────────────────────
    prompt = build_prompt(spec, repo_tree)

    if args.show_prompt:
        print()
        print(bold("Prompt that would be sent to Claude:"))
        print(dim("─" * 60))
        print(prompt)
        print(dim("─" * 60))
        sys.exit(0)

    # ── Step 6: Confirm if plugin directory already exists ────────────────────
    if not args.dry_run and spec["plugin_dir"].exists():
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

    # ── Step 7: Call Claude ───────────────────────────────────────────────────
    print()
    print(bold("Calling Claude Code..."))
    raw_output = call_claude(claude_path, prompt)

    # ── Step 8: Parse output ──────────────────────────────────────────────────
    files = parse_output(raw_output)
    print(cyan(f"  Parsed {len(files)} files from Claude's response"))

    if len(files) < 10:
        print(yellow(f"  WARNING: expected ~19 files, got {len(files)}."))
        print(yellow("  Claude may have truncated. Consider running again."))

    # ── Step 9: Write files ───────────────────────────────────────────────────
    create_plugin(files, spec, args.dry_run)

    # ── Step 10: Update marketplace.json ─────────────────────────────────────
    print()
    print(bold("Updating marketplace.json..."))
    update_marketplace(spec, args.dry_run)

    # ── Step 11: Install instructions ────────────────────────────────────────
    slug = spec["slug"]
    marketplace_name = get_marketplace_name()
    print()
    if args.dry_run:
        print(bold("Dry run complete — no files written."))
    else:
        print(bold("Plugin created. Install it:"))
        print()
        print(f"  /plugin marketplace add {MARKETPLACE_DIR}")
        print(f"  /plugin install {slug}@{marketplace_name}")
        print(f"  /reload-plugins")
        print(f"  /init-{slug}")
    print()


if __name__ == "__main__":
    main()
