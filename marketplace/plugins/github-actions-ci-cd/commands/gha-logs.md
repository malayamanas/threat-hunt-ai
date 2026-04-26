---
name: gha-logs
description: Stream logs from a workflow run or specific job step
---
# Command: /gha-logs
# Usage: /gha-logs [arguments]

## Description
Stream logs from a workflow run or specific job step

## Behavior
1. Read configuration from environment variables
2. Call the appropriate Github Actions Ci Cd API or helper function
3. Present results in a structured table format
4. Recommend next steps based on findings

## Example Invocations
- `/gha-logs`
- `/gha-logs --help`
