# Github Actions Ci Cd Plugin — Skills Summary

## Skills

| Directory | Name | Use When |
|---|---|---|
| `skills/workflow_design/` | `github-actions-ci-cd-workflow_design` | Workflow file structure, trigger configuration, and YAML best practices |
| `skills/run_monitoring/` | `github-actions-ci-cd-run_monitoring` | Pipeline run tracking, log streaming, and failure root-cause analysis |
| `skills/artifact_ops/` | `github-actions-ci-cd-artifact_ops` | Build artifact management, caching strategy, and retention policies |
| `skills/runner_mgmt/` | `github-actions-ci-cd-runner_mgmt` | Self-hosted and GitHub-hosted runner provisioning and scaling |

## Commands

| Command | What It Does |
|---|---|
| `/init-github-actions-ci-cd` | Initialize session and display all available commands |
| `/gha-status` | Latest workflow runs with pass/fail status per branch |
| `/gha-logs` | Stream logs from a workflow run or specific job step |
| `/gha-trigger` | Manually dispatch a workflow with optional inputs |
| `/gha-artifacts` | List, download, or expire build artifacts |
| `/gha-debug` | Analyze a failed run and suggest root-cause fixes |

## Agent

| Agent | Role |
|---|---|
| `gha-engineer` | CI/CD engineer — optimizes workflows, diagnoses failures, manages runners and secrets |

## Scripts

| Script | Usage |
|---|---|
| `github_api.py` | GitHub REST and Actions API wrapper (stdlib urllib, no extra deps) |
