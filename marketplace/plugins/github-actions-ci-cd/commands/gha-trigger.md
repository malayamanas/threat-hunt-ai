---
name: gha-trigger
description: Manually dispatch a workflow with optional inputs
---
# Command: /gha-trigger
# Usage: /gha-trigger [arguments]

## Description
Manually dispatch a workflow with optional inputs

## Behavior
1. Read configuration from environment variables
2. Call the appropriate Github Actions Ci Cd API or helper function
3. Present results in a structured table format
4. Recommend next steps based on findings

## Example Invocations
- `/gha-trigger`
- `/gha-trigger --help`
