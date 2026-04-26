---
name: gha-debug
description: Analyze a failed run and suggest root-cause fixes
---
# Command: /gha-debug
# Usage: /gha-debug [arguments]

## Description
Analyze a failed run and suggest root-cause fixes

## Behavior
1. Read configuration from environment variables
2. Call the appropriate Github Actions Ci Cd API or helper function
3. Present results in a structured table format
4. Recommend next steps based on findings

## Example Invocations
- `/gha-debug`
- `/gha-debug --help`
