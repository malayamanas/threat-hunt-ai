#!/usr/bin/env python3
"""
generate_plugin.py — Claude Code Plugin Scaffold Generator

Verifies the Claude Code binary, scans the current marketplace structure,
then generates a complete new plugin scaffold from a plain-language description.

Usage:
    python3 generate_plugin.py "Kubernetes cluster health monitor"
    python3 generate_plugin.py                   # interactive prompt
    echo "GitHub Actions CI/CD manager" | python3 generate_plugin.py
    python3 generate_plugin.py --dry-run "PostgreSQL query optimizer"
"""

import os
import sys
import json
import re
import shutil
import argparse
from pathlib import Path

REPO_ROOT = Path(__file__).parent.resolve()
MARKETPLACE_DIR = REPO_ROOT / "marketplace"
PLUGINS_DIR = MARKETPLACE_DIR / "plugins"
MARKETPLACE_JSON = MARKETPLACE_DIR / ".claude-plugin" / "marketplace.json"

# ── Terminal helpers ──────────────────────────────────────────────────────────

def bold(s):   return f"\033[1m{s}\033[0m"
def green(s):  return f"\033[32m{s}\033[0m"
def yellow(s): return f"\033[33m{s}\033[0m"
def dim(s):    return f"\033[2m{s}\033[0m"


# ── 1. Check Claude Code binary ───────────────────────────────────────────────

def check_claude() -> str:
    """Return path to claude binary, or print install instructions and exit."""
    path = shutil.which("claude")
    if path:
        return path
    extra_locations = [
        Path.home() / ".claude" / "bin" / "claude",
        Path("/usr/local/bin/claude"),
        Path("/opt/homebrew/bin/claude"),
        Path("/home/linuxbrew/.linuxbrew/bin/claude"),
    ]
    for p in extra_locations:
        if p.exists():
            print(yellow(f"  claude found at {p} (not on PATH)"))
            print(yellow(f"  To add to PATH: export PATH=\"$PATH:{p.parent}\""))
            return str(p)
    print(bold("ERROR: Claude Code binary not found in PATH"))
    print()
    print("Install Claude Code:")
    print("  npm install -g @anthropic-ai/claude-code")
    print("  Or download from: https://claude.ai/download")
    print()
    print("Verify after installing: claude --version")
    sys.exit(1)


# ── 2. Get input text ─────────────────────────────────────────────────────────

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
    print(dim("    GitHub Actions CI/CD pipeline manager and debugger"))
    print(dim("    PostgreSQL query optimizer and schema migration tool"))
    print(dim("    AWS cost optimization and resource inventory manager"))
    print(dim("    Django REST API scaffolding and test runner"))
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

_TREE_SKIP = {
    ".git", "__pycache__", ".DS_Store", "node_modules",
    ".mypy_cache", ".pytest_cache", ".ruff_cache", "dist", "build",
}

def _tree_lines(root: Path, prefix: str = "", depth: int = 4) -> list:
    if depth == 0:
        return []
    try:
        entries = sorted(root.iterdir(), key=lambda p: (p.is_file(), p.name.lower()))
    except PermissionError:
        return []
    entries = [e for e in entries if e.name not in _TREE_SKIP and not e.name.startswith(".git")]
    lines = []
    for i, entry in enumerate(entries):
        last = i == len(entries) - 1
        connector = "└── " if last else "├── "
        child_pfx = prefix + ("    " if last else "│   ")
        lines.append(f"{prefix}{connector}{entry.name}{'/' if entry.is_dir() else ''}")
        if entry.is_dir():
            lines.extend(_tree_lines(entry, child_pfx, depth - 1))
    return lines

def print_project_tree(root: Path):
    print()
    print(bold("Current project structure:"))
    print(f"  {root.name}/")
    for line in _tree_lines(root, prefix="  ", depth=4):
        print(line)
    print()


# ── 4. Derive plugin spec ─────────────────────────────────────────────────────

_STOP = {
    "a", "an", "the", "and", "or", "for", "of", "with", "by", "in", "on",
    "to", "from", "as", "is", "are", "be", "this", "that", "build", "create",
    "make", "develop", "write", "add", "using", "use", "new", "tool", "plugin",
    "app", "application", "help", "based", "into", "via", "my", "your", "our",
}

# (keywords list, domain_key) — checked in order; first match wins
_DOMAIN_MAP = [
    (["kubernetes", "k8s", "pod", "helm", "cluster", "kubectl", "ingress", "rbac", "namespace"], "kubernetes"),
    (["github actions", "ci/cd", "cicd", "github workflow", "pipeline runner", "artifact"], "github_actions"),
    (["github", "pull request", "pr review", "branch protection"], "github"),
    (["gitlab", "gitlab-ci", "merge request"], "gitlab"),
    (["terraform", "pulumi", "bicep", "cloudformation", "infrastructure as code", "iac", "ansible"], "iac"),
    (["aws", "amazon web", "ec2", "s3 bucket", "lambda", "cloudwatch", "iam role", "eks", "ecs", "rds"], "aws"),
    (["gcp", "google cloud", "gke", "bigquery", "cloud run", "pubsub", "firestore"], "gcp"),
    (["azure", "aks", "azure devops", "cosmos db", "azure blob"], "azure"),
    (["docker", "container", "dockerfile", "compose", "registry", "image build", "podman"], "docker"),
    (["django", "flask", "fastapi", "aiohttp", "python api", "rest api", "backend api"], "python_api"),
    (["react", "vue", "angular", "svelte", "nextjs", "nuxt", "vite", "webpack", "frontend", "ui component"], "frontend"),
    (["postgresql", "postgres", "mysql", "sqlite", "mariadb", "sql server", "database schema", "migration"], "database"),
    (["mongodb", "dynamodb", "redis", "elasticsearch", "cassandra", "nosql"], "nosql"),
    (["prometheus", "grafana", "datadog", "monitoring", "observability", "metrics", "alert rule"], "monitoring"),
    (["security", "vulnerability", "cve", "sast", "dast", "sbom", "secret scan", "pentest", "owasp"], "security"),
    (["pytest", "jest", "unit test", "integration test", "e2e", "test coverage", "qa"], "testing"),
    (["spark", "airflow", "dbt", "etl", "data pipeline", "kafka", "data warehouse", "analytics"], "data"),
    (["machine learning", "mlflow", "model training", "hugging face", "langchain", "llm", "ml model"], "ml"),
    (["jira", "confluence", "sprint", "kanban", "project management", "agile", "backlog"], "project_management"),
    (["slack", "teams", "discord", "webhook", "pagerduty", "opsgenie", "notification"], "notifications"),
    (["linux", "server", "bash script", "shell script", "cron", "systemd", "sysadmin"], "sysadmin"),
    (["git", "commit", "rebase", "cherry-pick", "submodule", "git workflow"], "git"),
]

# Per-domain: (prefix, title, skills[], commands[], agent, script)
_DOMAIN_TEMPLATES = {
    "kubernetes": {
        "prefix": "k8s", "title": "Kubernetes",
        "skills": [
            ("cluster_health",    "Cluster health monitoring — node status, resource pressure, failing pods"),
            ("workload_mgmt",     "Deployment, StatefulSet, DaemonSet lifecycle, rollout, and rollback"),
            ("namespace_ops",     "Namespace isolation, quota management, and RBAC administration"),
            ("log_analysis",      "Pod log aggregation, error pattern detection, and crash-loop diagnosis"),
        ],
        "commands": [
            ("status",   "Cluster health overview — nodes, resource pressure, failing workloads"),
            ("pods",     "List, describe, exec into, or delete pods across namespaces"),
            ("deploy",   "Roll out, rollback, or scale a Deployment or StatefulSet"),
            ("logs",     "Stream and analyze logs from pods or deployments"),
            ("events",   "Show recent cluster events filtered by type or namespace"),
        ],
        "agent":  ("k8s-operator",    "Kubernetes cluster operator — diagnoses workload issues, manages deployments, responds to incidents"),
        "script": ("k8s_helper.py",   "kubectl wrapper and Kubernetes REST API helper"),
    },
    "github_actions": {
        "prefix": "gha", "title": "GitHub Actions",
        "skills": [
            ("workflow_design",   "Workflow file structure, trigger configuration, and YAML best practices"),
            ("run_monitoring",    "Pipeline run tracking, log streaming, and failure root-cause analysis"),
            ("artifact_ops",      "Build artifact management, caching strategy, and retention policies"),
            ("runner_mgmt",       "Self-hosted and GitHub-hosted runner provisioning and scaling"),
        ],
        "commands": [
            ("status",     "Latest workflow runs with pass/fail status per branch"),
            ("logs",       "Stream logs from a workflow run or specific job step"),
            ("trigger",    "Manually dispatch a workflow with optional inputs"),
            ("artifacts",  "List, download, or expire build artifacts"),
            ("debug",      "Analyze a failed run and suggest root-cause fixes"),
        ],
        "agent":  ("gha-engineer",    "CI/CD engineer — optimizes workflows, diagnoses failures, manages runners and secrets"),
        "script": ("github_api.py",   "GitHub REST and Actions API wrapper (stdlib urllib, no extra deps)"),
    },
    "aws": {
        "prefix": "aws", "title": "AWS",
        "skills": [
            ("resource_inventory", "Cross-region resource discovery and inventory with tagging"),
            ("cost_analysis",      "Cost Explorer trend analysis and savings recommendations"),
            ("security_posture",   "IAM policy audit, security group exposure, and compliance checks"),
            ("cloudwatch_ops",     "CloudWatch alarms, log groups, and metric query workflows"),
        ],
        "commands": [
            ("inventory", "List and summarize AWS resources across services and regions"),
            ("costs",     "Analyze costs and surface the top spending resources"),
            ("security",  "Audit IAM policies, security groups, and public exposure"),
            ("logs",      "Query CloudWatch log groups in plain English"),
            ("deploy",    "Deploy or update Lambda, ECS service, or CloudFormation stack"),
        ],
        "agent":  ("aws-ops",      "AWS operations agent — manages resources, monitors costs, responds to CloudWatch alarms"),
        "script": ("aws_helper.py","AWS API helper (boto3 if available, falls back to urllib + SigV4)"),
    },
    "docker": {
        "prefix": "dkr", "title": "Docker",
        "skills": [
            ("image_mgmt",      "Image build, multi-stage optimization, tagging, and registry push/pull"),
            ("container_ops",   "Container run, inspect, exec, stop, and resource monitoring"),
            ("compose_ops",     "Compose multi-service orchestration and dependency management"),
            ("security_scan",   "Image vulnerability scanning and Dockerfile best-practice audit"),
        ],
        "commands": [
            ("status",  "Running containers with resource usage and health status"),
            ("build",   "Build and tag an image with layer and size analysis"),
            ("deploy",  "Start, stop, scale, or restart Compose services"),
            ("scan",    "Scan image for CVEs and Dockerfile misconfigurations"),
            ("logs",    "Stream logs from containers with pattern filtering"),
        ],
        "agent":  ("docker-engineer", "Container engineer — builds, secures, and deploys containerized workloads"),
        "script": ("docker_api.py",   "Docker Engine API and registry HTTP wrapper"),
    },
    "python_api": {
        "prefix": "api", "title": "Python API",
        "skills": [
            ("endpoint_design",  "REST endpoint design, request validation, and OpenAPI spec generation"),
            ("auth_patterns",    "JWT, OAuth2, API key, and session authentication patterns"),
            ("data_models",      "ORM model design, Pydantic schemas, and migration generation"),
            ("api_testing",      "API test design, fixture management, and coverage reporting"),
        ],
        "commands": [
            ("scaffold",  "Scaffold a new endpoint, model, serializer, or test file"),
            ("test",      "Run API tests and display a coverage summary"),
            ("docs",      "Generate or sync OpenAPI documentation"),
            ("migrate",   "Create and apply database migrations"),
            ("profile",   "Profile slow endpoints and suggest query optimizations"),
        ],
        "agent":  ("api-developer",  "Python API developer — scaffolds endpoints, writes tests, manages schema migrations"),
        "script": ("api_helper.py",  "Project scaffolding, migration runner, and test coverage helper"),
    },
    "database": {
        "prefix": "db", "title": "Database",
        "skills": [
            ("query_analysis",  "Explain-plan analysis and index optimization recommendations"),
            ("schema_mgmt",     "Schema design review, migration generation, and drift detection"),
            ("health_monitor",  "Connection pool, lock contention, and slow-query monitoring"),
            ("backup_ops",      "Backup scheduling, integrity verification, and point-in-time restore"),
        ],
        "commands": [
            ("query",     "Explain or run a SQL query with performance analysis"),
            ("schema",    "Show schema, detect drift, or generate a migration script"),
            ("health",    "Database health — connections, cache hit rate, locks, table sizes"),
            ("backup",    "Trigger or verify a database backup"),
            ("optimize",  "Find the slowest queries and recommend index changes"),
        ],
        "agent":  ("db-admin",       "Database administrator — monitors performance, manages migrations, responds to incidents"),
        "script": ("db_helper.py",   "Database connection, query execution, and schema inspection helper"),
    },
    "monitoring": {
        "prefix": "mon", "title": "Monitoring",
        "skills": [
            ("metrics_analysis", "Time-series metric analysis, baseline establishment, and anomaly detection"),
            ("alert_mgmt",       "Alert rule design, threshold tuning, and escalation policy management"),
            ("dashboard_ops",    "Dashboard design, SLO tracking, and panel management"),
            ("incident_triage",  "Alert correlation, noise reduction, and root-cause analysis"),
        ],
        "commands": [
            ("status",    "Current system health — active alerts, SLO status, top issues"),
            ("metrics",   "Query and summarize metrics for a service or host"),
            ("alerts",    "List active alerts, acknowledge, or create alert rules"),
            ("correlate", "Correlate related alerts to identify root cause"),
            ("report",    "Generate SLO/availability/performance report"),
        ],
        "agent":  ("mon-engineer",   "Monitoring engineer — manages alerts, correlates incidents, optimizes observability coverage"),
        "script": ("metrics_api.py", "Prometheus/Grafana metrics backend API wrapper"),
    },
    "security": {
        "prefix": "sec", "title": "Security",
        "skills": [
            ("vuln_scanning",   "Vulnerability scanning, CVE enrichment, and CVSS-based prioritization"),
            ("secret_detection","Secret and credential leak detection in code, configs, and git history"),
            ("compliance_audit","Compliance mapping to CIS, NIST, SOC 2, or OWASP Top 10"),
            ("threat_modeling", "Attack surface enumeration and data-flow risk scoring"),
        ],
        "commands": [
            ("scan",        "Run security scan on code, container image, or IaC config"),
            ("secrets",     "Detect exposed secrets in files, environment, or git history"),
            ("compliance",  "Audit posture against a security framework"),
            ("cve",         "Look up CVE details and check if environment is affected"),
            ("report",      "Generate security posture or audit report"),
        ],
        "agent":  ("security-engineer", "Security engineer — scans for vulnerabilities, detects secrets, maps compliance gaps"),
        "script": ("security_api.py",   "Vulnerability scanner and CVE database API wrapper"),
    },
    "data": {
        "prefix": "data", "title": "Data Engineering",
        "skills": [
            ("pipeline_ops",    "Pipeline orchestration, monitoring, and failure recovery"),
            ("data_quality",    "Data quality rules, anomaly detection, and lineage tracking"),
            ("warehouse_ops",   "Query optimization and data warehouse cost management"),
            ("report_auto",     "Automated report generation and distribution workflows"),
        ],
        "commands": [
            ("pipeline",  "Pipeline run status and failure diagnosis"),
            ("quality",   "Data quality checks on a table or dataset"),
            ("query",     "Run a data query described in plain English"),
            ("lineage",   "Trace data lineage for a field or table"),
            ("report",    "Generate a business or operational data report"),
        ],
        "agent":  ("data-engineer",  "Data engineer — manages pipelines, enforces quality, optimizes warehouse costs"),
        "script": ("data_api.py",    "Data warehouse and pipeline platform API wrapper"),
    },
    "iac": {
        "prefix": "iac", "title": "Infrastructure as Code",
        "skills": [
            ("plan_analysis",   "Plan analysis — resource changes, cost impact, risk assessment"),
            ("state_mgmt",      "State inspection, drift detection, and import workflows"),
            ("module_design",   "Reusable module architecture and provider configuration"),
            ("deploy_workflow", "Safe plan→approve→apply→verify lifecycle with rollback"),
        ],
        "commands": [
            ("plan",    "Run infrastructure plan and summarize what will change"),
            ("apply",   "Apply infrastructure changes with staged confirmation"),
            ("drift",   "Detect drift between IaC code and live infrastructure"),
            ("cost",    "Estimate cost impact of planned changes"),
            ("module",  "Scaffold or validate a reusable infrastructure module"),
        ],
        "agent":  ("iac-engineer",   "IaC engineer — plans, reviews, and applies infrastructure changes safely"),
        "script": ("iac_helper.py",  "Terraform plan parser and infrastructure state inspection helper"),
    },
    "frontend": {
        "prefix": "fe", "title": "Frontend",
        "skills": [
            ("component_design", "UI component architecture, design system patterns, and accessibility"),
            ("perf_ops",         "Bundle analysis, code splitting, lazy loading, and Core Web Vitals"),
            ("test_workflow",    "Unit, integration, and E2E test design and coverage reporting"),
            ("build_pipeline",   "Build config, asset optimization, and deployment workflow"),
        ],
        "commands": [
            ("scaffold", "Scaffold a new component, page, hook, or feature module"),
            ("test",     "Run tests and show coverage by module"),
            ("perf",     "Analyze bundle size and suggest optimizations"),
            ("build",    "Build for production and summarize output stats"),
            ("audit",    "Accessibility and Lighthouse performance audit"),
        ],
        "agent":  ("frontend-engineer", "Frontend engineer — designs components, optimizes performance, manages build pipeline"),
        "script": ("frontend_helper.py","Bundle analyzer and test runner wrapper"),
    },
    "sysadmin": {
        "prefix": "sys", "title": "System Administration",
        "skills": [
            ("health_monitor",  "System resource monitoring — CPU, memory, disk, and network"),
            ("process_mgmt",    "Process and service lifecycle management and troubleshooting"),
            ("log_analysis",    "System log analysis, error pattern detection, and audit trails"),
            ("automation",      "Administrative task scripting, scheduling, and change management"),
        ],
        "commands": [
            ("health",    "System health overview — resources, top processes, recent issues"),
            ("services",  "List, start, stop, or restart system services"),
            ("logs",      "Analyze system logs for errors and security events"),
            ("deploy",    "Deploy an application update or configuration change"),
            ("cron",      "List, add, or troubleshoot scheduled tasks"),
        ],
        "agent":  ("sysadmin",        "System administrator — monitors health, diagnoses issues, automates maintenance"),
        "script": ("system_helper.py","System resource monitoring and service management helper"),
    },
    "ml": {
        "prefix": "ml", "title": "Machine Learning",
        "skills": [
            ("experiment_tracking", "Experiment tracking, metric comparison, and model registry management"),
            ("data_prep",           "Dataset validation, feature engineering, and data pipeline management"),
            ("model_eval",          "Model performance analysis, bias detection, and benchmark comparison"),
            ("deploy_ops",          "Model serving, A/B testing, shadow deployment, and drift monitoring"),
        ],
        "commands": [
            ("experiments", "List and compare ML experiments by metric"),
            ("train",       "Trigger a training run with specified config"),
            ("evaluate",    "Evaluate model performance on a validation set"),
            ("deploy",      "Deploy a model to serving infrastructure"),
            ("monitor",     "Monitor production model for drift and degradation"),
        ],
        "agent":  ("ml-engineer",   "ML engineer — tracks experiments, evaluates models, manages production deployments"),
        "script": ("ml_api.py",     "MLflow/experiment tracking and model serving API wrapper"),
    },
    "github": {
        "prefix": "gh", "title": "GitHub",
        "skills": [
            ("pr_mgmt",         "Pull request review workflow, approval gates, and merge automation"),
            ("issue_tracking",  "Issue triage, labeling, milestone management, and project boards"),
            ("repo_health",     "Repository settings, branch protection, secrets, and dependency alerts"),
            ("release_mgmt",    "Release creation, changelog generation, and tag management"),
        ],
        "commands": [
            ("prs",      "List open PRs with review status and merge readiness"),
            ("review",   "Summarize and review a pull request for quality and correctness"),
            ("issues",   "List, triage, or create GitHub issues"),
            ("release",  "Draft and publish a GitHub release with changelog"),
            ("health",   "Repository health check — settings, alerts, branch protection"),
        ],
        "agent":  ("github-ops",    "GitHub ops agent — manages PRs, triages issues, maintains repository health"),
        "script": ("github_api.py", "GitHub REST API wrapper (stdlib urllib, no extra deps)"),
    },
    "testing": {
        "prefix": "test", "title": "Testing",
        "skills": [
            ("test_design",    "Test case design, boundary analysis, and coverage gap identification"),
            ("fixture_mgmt",   "Fixture, mock, and test-data factory management patterns"),
            ("ci_integration", "Test pipeline parallelization and flaky test detection"),
            ("report_analysis","Test results analysis, failure triaging, and trend tracking"),
        ],
        "commands": [
            ("run",      "Run the test suite with coverage and summarize failures"),
            ("coverage", "Analyze test coverage and identify untested paths"),
            ("flaky",    "Detect and diagnose intermittently failing tests"),
            ("scaffold", "Scaffold tests for a module, class, or function"),
            ("report",   "Generate a test quality and trend report"),
        ],
        "agent":  ("test-engineer",   "Test engineer — designs tests, improves coverage, diagnoses failures"),
        "script": ("test_helper.py",  "Test runner wrapper and coverage analysis helper"),
    },
    "project_management": {
        "prefix": "pm", "title": "Project Management",
        "skills": [
            ("backlog_mgmt",     "Backlog grooming, priority scoring, and sprint planning"),
            ("progress_tracking","Velocity tracking, burndown, and delivery forecasting"),
            ("stakeholder_rpt",  "Status report generation for different stakeholder levels"),
            ("dependency_map",   "Cross-team dependency detection and blocker tracking"),
        ],
        "commands": [
            ("sprint",   "Current sprint status, velocity, and blockers"),
            ("backlog",  "List, prioritize, or groom the product backlog"),
            ("report",   "Generate project status report for stakeholders"),
            ("roadmap",  "Show and update the product roadmap"),
            ("risks",    "Identify and track project risks and dependencies"),
        ],
        "agent":  ("pm-agent",   "Project management agent — tracks progress, surfaces blockers, generates reports"),
        "script": ("pm_api.py",  "Jira/Linear/GitHub Projects API wrapper"),
    },
    "notifications": {
        "prefix": "notify", "title": "Notifications",
        "skills": [
            ("channel_mgmt",    "Notification channel setup, routing rules, and escalation policies"),
            ("message_design",  "Alert message templates, context enrichment, and formatting"),
            ("alert_routing",   "Intelligent routing by severity, team, and on-call schedule"),
            ("silence_mgmt",    "Scheduled silences, maintenance windows, and suppression rules"),
        ],
        "commands": [
            ("send",     "Send a notification or alert to a channel"),
            ("channels", "List and configure notification channels"),
            ("rules",    "View and modify alert routing rules"),
            ("silence",  "Create or list alert silences and maintenance windows"),
            ("history",  "Recent notification history and delivery status"),
        ],
        "agent":  ("notify-ops",   "Notification ops agent — manages channels, routes alerts, enforces escalation policies"),
        "script": ("notify_api.py","Slack/Teams/webhook notification API wrapper"),
    },
}


def _slugify(text: str) -> str:
    text = re.sub(r"[^a-zA-Z0-9\s\-/]", "", text)
    text = re.sub(r"[\s/]+", "-", text.strip()).lower()
    parts = [p for p in text.split("-") if p and p not in _STOP and len(p) > 1]
    return "-".join(parts[:4]) if parts else "custom-plugin"

def _title_case(slug: str) -> str:
    return " ".join(w.capitalize() for w in slug.replace("-", " ").split())

def _make_prefix(slug: str) -> str:
    parts = slug.split("-")
    if len(parts) == 1:
        return parts[0][:4]
    if len(parts) == 2:
        return parts[0][:2] + parts[1][:2]
    return "".join(p[0] for p in parts[:4])

def _detect_domain(text: str):
    tl = text.lower()
    scores = {}
    for keywords, domain in _DOMAIN_MAP:
        score = sum(1 for kw in keywords if kw in tl)
        if score:
            scores[domain] = score
    if scores:
        best = max(scores, key=scores.get)
        if best in _DOMAIN_TEMPLATES:
            return best, _DOMAIN_TEMPLATES[best]
    return "generic", None

def build_spec(text: str) -> dict:
    domain_key, tmpl = _detect_domain(text)
    slug = _slugify(text) or "custom-plugin"
    title = _title_case(slug)
    env_prefix = slug.upper().replace("-", "_")

    if tmpl:
        prefix   = tmpl["prefix"]
        skills   = tmpl["skills"]
        commands = tmpl["commands"]
        agent    = tmpl["agent"]
        script   = tmpl["script"]
        domain_title = tmpl["title"]
    else:
        prefix = _make_prefix(slug)[:5]
        domain_title = title
        skills = [
            ("core_ops",     f"Core {title} operations and workflow management"),
            ("configuration",f"{title} configuration, setup, and environment management"),
            ("monitoring",   f"{title} health monitoring and status reporting"),
            ("automation",   f"{title} task automation and scheduled workflow execution"),
        ]
        commands = [
            ("status", f"Show {title} status and health overview"),
            ("list",   f"List {title} resources or entities"),
            ("create", f"Create a new {title} resource or workflow"),
            ("update", f"Update or modify an existing {title} resource"),
            ("report", f"Generate a {title} summary report"),
        ]
        agent  = (f"{prefix}-agent", f"{title} operations agent — manages workflows, monitors status, automates tasks")
        script = (f"{prefix}_api.py", f"{title} API wrapper and automation helper")

    return {
        "slug":         slug,
        "title":        title,
        "description":  text,
        "domain":       domain_key,
        "domain_title": domain_title,
        "prefix":       prefix,
        "env_prefix":   env_prefix,
        "skills":       skills,
        "commands":     commands,
        "agent":        agent,
        "script":       script,
        "plugin_dir":   PLUGINS_DIR / slug,
    }


# ── 5. Content generators ─────────────────────────────────────────────────────

def _plugin_json(s: dict) -> str:
    return json.dumps({
        "name": s["slug"], "version": "1.0.0",
        "description": s["description"],
        "author": {"name": "Your Name", "email": "you@example.com"},
    }, indent=2) + "\n"


def _claude_md(s: dict) -> str:
    skill_rows = "\n".join(
        f"| `skills/{n}/` | `{s['slug']}-{n}` | {d.split(' — ')[0]} |"
        for n, d in s["skills"]
    )
    cmd_rows = "\n".join(
        f"| `/{s['prefix']}-{n}` | {d} |" for n, d in s["commands"]
    )
    an, ad = s["agent"]
    lines = [
        f"# {s['title']} Plugin — Claude Guidelines",
        "",
        f"You are operating as a {s['title']} engineer. These guidelines are active for this session.",
        "",
        "## Plugin Overview",
        "",
        s["description"],
        "",
        "## Skills",
        "",
        "| Directory | Skill Name | Purpose |",
        "|---|---|---|",
        skill_rows,
        "",
        "## Commands",
        "",
        "| Command | Purpose |",
        "|---|---|",
        cmd_rows,
        "",
        "## Agent",
        "",
        "| Agent | Role |",
        "|---|---|",
        f"| `{an}` | {ad} |",
        "",
        "## Operational Defaults",
        "",
        "- Confirm before any destructive operation (delete, apply to production, force-update)",
        "- Present resource lists as tables with id · name · status · last-updated columns",
        "- Always include a recommended next action",
        "- Read all credentials from environment variables — never hardcode them",
    ]
    return "\n".join(lines) + "\n"


def _skills_summary(s: dict) -> str:
    skill_rows = "\n".join(
        f"| `skills/{n}/` | `{s['slug']}-{n}` | {d} |"
        for n, d in s["skills"]
    )
    cmd_rows = "\n".join(
        f"| `/{s['prefix']}-{n}` | {d} |" for n, d in s["commands"]
    )
    an, ad = s["agent"]
    sn, sd = s["script"]
    lines = [
        f"# {s['title']} Plugin — Skills Summary",
        "",
        "## Skills",
        "",
        "| Directory | Name | Use When |",
        "|---|---|---|",
        skill_rows,
        "",
        "## Commands",
        "",
        "| Command | What It Does |",
        "|---|---|",
        f"| `/init-{s['slug']}` | Initialize session and display all available commands |",
        cmd_rows,
        "",
        "## Agent",
        "",
        "| Agent | Role |",
        "|---|---|",
        f"| `{an}` | {ad} |",
        "",
        "## Scripts",
        "",
        "| Script | Usage |",
        "|---|---|",
        f"| `{sn}` | {sd} |",
    ]
    return "\n".join(lines) + "\n"


def _skill_md(s: dict, name: str, desc: str) -> str:
    short = desc.split(" — ")[0]
    detail = desc.split(" — ")[1] if " — " in desc else ""
    skill_title = _title_case(name)
    lines = [
        f"---",
        f"name: {s['slug']}-{name}",
        f"description: {desc}. Use this skill when the user asks about {s['slug']} {name.replace('_', ' ')}.",
        f"---",
        f"# {skill_title}",
        "",
        f"{short}.{' ' + detail if detail else ''}",
        "",
        "## Overview",
        "",
        f"This skill provides {s['title']} {name.replace('_', ' ')} capabilities:",
        "- Query current status and health",
        "- Identify issues and anomalies",
        "- Recommend remediation actions",
        f"- Automate common {name.replace('_', ' ')} tasks",
        "",
        "## Key Operations",
        "",
        f"See [reference.md](reference.md) for full Python implementations.",
        "",
        "## Output Format",
        "",
        "Present results as:",
        "- Summary line (total count, severity breakdown)",
        "- Table: id · name · status · last-updated",
        "- Recommended next action",
    ]
    return "\n".join(lines) + "\n"


def _skill_reference(s: dict, name: str, desc: str) -> str:
    fn = f"{s['slug'].replace('-', '_')}_{name}"
    ep = s["env_prefix"]
    skill_title = _title_case(name)
    name_path = name.replace("_", "/")
    url_comment = '    # url = f"{cfg[\'host\']}/api/v1/' + name_path + '"'
    hdr_comment = '    # headers = {"Authorization": f"Bearer {cfg[\'token\']}", "Accept": "application/json"}'
    lines = [
        f"# {skill_title} — Reference Implementations",
        "",
        f"Full Python implementations for the `{s['slug']}-{name}` skill.",
        "",
        f"## `{fn}()`",
        "",
        "```python",
        "#!/usr/bin/env python3",
        '"""',
        f"{skill_title} for {s['title']}.",
        f"{desc}",
        '"""',
        "import os",
        "import json",
        "import urllib.request",
        "import urllib.error",
        "from typing import Optional",
        "",
        "",
        "def get_config() -> dict:",
        '    """Read configuration from environment variables."""',
        "    return {",
        f'        "host":  os.environ.get("{ep}_HOST", ""),',
        f'        "token": os.environ.get("{ep}_TOKEN", ""),',
        f'        "org":   os.environ.get("{ep}_ORG", ""),',
        "    }",
        "",
        "",
        f"def {fn}(",
        "    limit: int = 50,",
        "    filters: Optional[dict] = None,",
        ") -> list:",
        '    """',
        f"    {desc}.",
        "    Returns list of dicts: id, name, status, message, updated_at",
        '    """',
        "    cfg = get_config()",
        '    if not cfg["host"]:',
        f'        raise ValueError("Missing env var: {ep}_HOST")',
        "",
        "    # TODO: implement API call",
        url_comment,
        hdr_comment,
        "    # req = urllib.request.Request(url, headers=headers)",
        "    # with urllib.request.urlopen(req) as resp:",
        "    #     data = json.loads(resp.read())",
        '    # return data.get("items", [])',
        "",
        "    return []",
        "",
        "",
        'if __name__ == "__main__":',
        "    import pprint",
        f"    pprint.pprint({fn}())",
        "```",
    ]
    return "\n".join(lines) + "\n"


def _command_md(s: dict, name: str, desc: str) -> str:
    full = f"{s['prefix']}-{name}"
    lines = [
        f"---",
        f"name: {full}",
        f"description: {desc}",
        f"---",
        f"# Command: /{full}",
        f"# Usage: /{full} [arguments]",
        "",
        "## Description",
        desc,
        "",
        "## Behavior",
        "1. Read configuration from environment variables",
        f"2. Call the appropriate {s['title']} API or helper function",
        "3. Present results in a structured table format",
        "4. Recommend next steps based on findings",
        "",
        "## Example Invocations",
        f"- `/{full}`",
        f"- `/{full} --help`",
    ]
    return "\n".join(lines) + "\n"


def _init_command_md(s: dict) -> str:
    cmd_lines = "\n".join(
        f"  /{s['prefix']}-{n:<22} {d}" for n, d in s["commands"]
    )
    lines = [
        f"---",
        f"name: init-{s['slug']}",
        f"description: Initialize the {s['title']} plugin session. Verifies environment and displays all available commands.",
        f"---",
        f"# Command: /init-{s['slug']}",
        "",
        "## Behavior",
        f"1. Check required environment variable: {s['env_prefix']}_HOST",
        "2. Test connectivity (if applicable)",
        "3. Print session summary with full command menu",
        "",
        "## Session Summary Output",
        "```",
        f"✅ {s['title']} Plugin Ready",
        "",
        "── Commands ─────────────────────────────────────────",
        cmd_lines,
        "",
        "  Type a command or describe what you need in plain language.",
        "```",
    ]
    return "\n".join(lines) + "\n"


def _agent_md(s: dict) -> str:
    an, ad = s["agent"]
    sn, _ = s["script"]
    skill_refs = "\n".join(
        f"- `skills/{n}/` — {d.split(' — ')[0]}" for n, d in s["skills"]
    )
    cmd_refs = "\n".join(
        f"  /{s['prefix']}-{n}  → {d}" for n, d in s["commands"]
    )
    lines = [
        f"---",
        f"name: {an}",
        f"description: {ad}",
        f"---",
        "",
        f"# {an} Agent",
        "",
        f"{ad}.",
        "",
        "## Architecture",
        "",
        f"**Helper scripts** (`scripts/`) handle API calls and data collection.",
        "**You (the AI agent)** interpret results, identify issues, and produce actionable recommendations.",
        "",
        "### Core Script",
        "",
        "```bash",
        f"python3 scripts/{sn} --help",
        "```",
        "",
        "### Available Skills",
        skill_refs,
        "",
        "## Workflow",
        "",
        "### Step 1: Gather Data",
        "```bash",
        f"python3 scripts/{sn} status",
        "```",
        "",
        "### Step 2: AI Analysis",
        "For each result, analyze:",
        "- **What**: What is the current state or issue?",
        "- **Why it matters**: Impact on the system or team",
        "- **What changed**: Deviation from expected baseline",
        "- **What to do**: Specific, actionable next steps",
        "",
        "### Step 3: Report",
        "1. Executive summary (1–2 sentences)",
        "2. Details table (id · name · status · issue)",
        "3. Prioritized action list",
        "",
        "## Available Commands",
        "```",
        cmd_refs,
        "```",
    ]
    return "\n".join(lines) + "\n"


def _script_py(s: dict) -> str:
    sn, sd = s["script"]
    ep = s["env_prefix"]
    title = s["title"]

    # Build per-command function stubs
    func_blocks = []
    for name, desc in s["commands"]:
        func_blocks.append(
            f"def cmd_{name}(cfg: dict, args) -> None:\n"
            f'    """{desc}."""\n'
            f'    host = cfg["host"]\n'
            f"    # TODO: implement — call host API and print results\n"
            f'    # url = f"{{host}}/api/v1/{name}"\n'
            f'    # data = api_get(url, auth_headers(cfg))\n'
            f'    # print(json.dumps(data, indent=2))\n'
            f'    print(f"[{s["slug"]}] {name}: not yet implemented")\n'
        )

    # Subparser registrations
    sub_adds = [
        f'    sub.add_parser("{name}", help="{desc}")'
        for name, desc in s["commands"]
    ]

    # Dispatch chain
    dispatch = []
    for i, (name, _) in enumerate(s["commands"]):
        kw = "if" if i == 0 else "elif"
        dispatch.append(f'    {kw} args.command == "{name}":')
        dispatch.append(f"        cmd_{name}(cfg, args)")

    usage_examples = "\n".join(
        f"    python3 {sn} {name}" for name, _ in s["commands"][:3]
    )

    lines = [
        f"#!/usr/bin/env python3",
        f'"""',
        f"{sd}",
        f"",
        f"{title} plugin helper script.",
        f"",
        f"Usage:",
        usage_examples,
        f"",
        f"Required environment variables:",
        f"    {ep}_HOST    Base URL or hostname for {title}",
        f"    {ep}_TOKEN   API token or credential (if required)",
        f"    {ep}_ORG     Organization or namespace (if applicable)",
        f'"""',
        "",
        "import os",
        "import sys",
        "import json",
        "import argparse",
        "import urllib.request",
        "import urllib.error",
        "",
        "",
        "def get_config() -> dict:",
        "    return {",
        f'        "host":  os.environ.get("{ep}_HOST", "").rstrip("/"),',
        f'        "token": os.environ.get("{ep}_TOKEN", ""),',
        f'        "org":   os.environ.get("{ep}_ORG", ""),',
        "    }",
        "",
        "",
        "def check_config() -> dict:",
        "    cfg = get_config()",
        '    if not cfg["host"]:',
        f'        print(f"ERROR: {ep}_HOST is not set", file=sys.stderr)',
        f'        print(f"  export {ep}_HOST=<{title.lower()}-url>", file=sys.stderr)',
        "        sys.exit(1)",
        "    return cfg",
        "",
        "",
        "def auth_headers(cfg: dict) -> dict:",
        '    h = {"Accept": "application/json", "Content-Type": "application/json"}',
        '    if cfg["token"]:',
        '        h["Authorization"] = f"Bearer {cfg[\'token\']}"',
        "    return h",
        "",
        "",
        "def api_get(url: str, headers: dict) -> dict:",
        '    """GET request returning parsed JSON."""',
        "    try:",
        "        req = urllib.request.Request(url, headers=headers)",
        "        with urllib.request.urlopen(req, timeout=30) as resp:",
        "            return json.loads(resp.read())",
        "    except urllib.error.HTTPError as e:",
        '        body = e.read().decode(errors="replace")',
        '        print(f"HTTP {e.code} {e.reason}: {body[:200]}", file=sys.stderr)',
        "        sys.exit(1)",
        "    except urllib.error.URLError as e:",
        '        print(f"Connection error: {e.reason}", file=sys.stderr)',
        "        sys.exit(1)",
        "",
        "",
    ]
    lines.extend("\n".join(fb.splitlines()) + "\n" for fb in func_blocks)
    lines += [
        "",
        "def main() -> None:",
        f'    parser = argparse.ArgumentParser(description="{sd}")',
        '    sub = parser.add_subparsers(dest="command", required=True, metavar="COMMAND")',
    ]
    lines.extend(sub_adds)
    lines += [
        "    args = parser.parse_args()",
        "    cfg = check_config()",
    ]
    lines.extend(dispatch)
    lines += [
        "",
        "",
        'if __name__ == "__main__":',
        "    main()",
    ]
    return "\n".join(lines) + "\n"


# ── 6. Write files ────────────────────────────────────────────────────────────

def _write(path: Path, content: str, dry_run: bool) -> None:
    rel = path.relative_to(REPO_ROOT)
    if dry_run:
        print(f"  {dim('[dry-run]')} {rel}")
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    print(f"  {green('+')} {rel}")


def create_plugin(spec: dict, dry_run: bool) -> None:
    d = spec["plugin_dir"]
    slug = spec["slug"]
    pfx = spec["prefix"]

    files = {
        d / ".claude-plugin" / "plugin.json": _plugin_json(spec),
        d / "CLAUDE.md":                      _claude_md(spec),
        d / "SKILLS_SUMMARY.md":              _skills_summary(spec),
        d / "commands" / f"init-{slug}.md":   _init_command_md(spec),
    }
    for name, desc in spec["commands"]:
        files[d / "commands" / f"{pfx}-{name}.md"] = _command_md(spec, name, desc)
    for name, desc in spec["skills"]:
        files[d / "skills" / name / "SKILL.md"]    = _skill_md(spec, name, desc)
        files[d / "skills" / name / "reference.md"] = _skill_reference(spec, name, desc)
    an, _ = spec["agent"]
    files[d / "agents" / f"{an}.md"]              = _agent_md(spec)
    sn, _  = spec["script"]
    files[d / "scripts" / sn]                     = _script_py(spec)

    print()
    print(bold(f"Generating {len(files)} files for plugin '{slug}':"))
    for path, content in files.items():
        _write(path, content, dry_run)

    if not dry_run:
        script_path = d / "scripts" / sn
        script_path.chmod(script_path.stat().st_mode | 0o111)


def update_marketplace(spec: dict, dry_run: bool) -> None:
    if not MARKETPLACE_JSON.exists():
        print(yellow(f"  marketplace.json not found — skipping"))
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
        "category":    spec["domain"],
        "version":     "1.0.0",
    })
    _write(MARKETPLACE_JSON, json.dumps(data, indent=2) + "\n", dry_run)


# ── 7. Main ───────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Generate a Claude Code plugin scaffold from a plain-language description.",
        epilog=(
            "Examples:\n"
            "  python3 generate_plugin.py \"Kubernetes cluster health monitor\"\n"
            "  python3 generate_plugin.py --dry-run \"GitHub Actions CI/CD manager\"\n"
            "  echo \"Django REST API\" | python3 generate_plugin.py\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("description", nargs="*", help="Plugin description")
    parser.add_argument("--dry-run",  action="store_true", help="Preview without writing files")
    parser.add_argument("--no-tree",  action="store_true", help="Skip project tree display")
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
    if not args.no_tree:
        print_project_tree(REPO_ROOT)

    # ── Step 4: Derive spec ───────────────────────────────────────────────────
    spec = build_spec(text)
    print(bold("Derived plugin spec:"))
    print(f"  slug     : {spec['slug']}")
    print(f"  domain   : {spec['domain']} ({spec['domain_title']})")
    print(f"  prefix   : {spec['prefix']}")
    print(f"  skills   : {', '.join(n for n, _ in spec['skills'])}")
    print(f"  commands : {', '.join(n for n, _ in spec['commands'])}")
    print(f"  agent    : {spec['agent'][0]}")
    print(f"  script   : {spec['script'][0]}")

    # ── Step 5: Confirm if directory exists ───────────────────────────────────
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

    # ── Step 6: Generate files ────────────────────────────────────────────────
    create_plugin(spec, args.dry_run)

    # ── Step 7: Update marketplace.json ──────────────────────────────────────
    print()
    print(bold("Updating marketplace.json..."))
    update_marketplace(spec, args.dry_run)

    # ── Step 8: Install instructions ─────────────────────────────────────────
    slug = spec["slug"]
    pfx = spec["prefix"]
    sn, _ = spec["script"]
    print()
    if args.dry_run:
        print(bold("Dry run complete — no files written."))
        print(f"  Remove --dry-run to generate the plugin.")
    else:
        print(bold("Plugin scaffold created."))
        print()
        print("Next steps:")
        print(f"  1. Fill in TODOs in  marketplace/plugins/{slug}/scripts/{sn}")
        print(f"  2. Enrich each       marketplace/plugins/{slug}/skills/*/SKILL.md")
        print(f"  3. Install the plugin:")
        print(f"       /plugin marketplace add {MARKETPLACE_DIR}")
        print(f"       /plugin install {slug}@fsiem-marketplace")
        print(f"       /reload-plugins")
        print(f"       /init-{slug}")
    print()


if __name__ == "__main__":
    main()
