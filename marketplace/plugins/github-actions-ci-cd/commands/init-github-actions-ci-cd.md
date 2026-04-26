---
name: init-github-actions-ci-cd
description: Initialize the Github Actions Ci Cd plugin session. Verifies environment and displays all available commands.
---
# Command: /init-github-actions-ci-cd

## Behavior
1. Check required environment variable: GITHUB_ACTIONS_CI_CD_HOST
2. Test connectivity (if applicable)
3. Print session summary with full command menu

## Session Summary Output
```
✅ Github Actions Ci Cd Plugin Ready

── Commands ─────────────────────────────────────────
  /gha-status                 Latest workflow runs with pass/fail status per branch
  /gha-logs                   Stream logs from a workflow run or specific job step
  /gha-trigger                Manually dispatch a workflow with optional inputs
  /gha-artifacts              List, download, or expire build artifacts
  /gha-debug                  Analyze a failed run and suggest root-cause fixes

  Type a command or describe what you need in plain language.
```
