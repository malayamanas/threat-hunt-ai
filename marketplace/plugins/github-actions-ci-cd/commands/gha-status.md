---
name: gha-status
description: Latest workflow runs with pass/fail status per branch
---
# Command: /gha-status
# Usage: /gha-status [arguments]

## Description
Latest workflow runs with pass/fail status per branch

## Behavior
1. Read configuration from environment variables
2. Call the appropriate Github Actions Ci Cd API or helper function
3. Present results in a structured table format
4. Recommend next steps based on findings

## Example Invocations
- `/gha-status`
- `/gha-status --help`
