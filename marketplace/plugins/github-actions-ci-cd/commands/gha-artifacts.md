---
name: gha-artifacts
description: List, download, or expire build artifacts
---
# Command: /gha-artifacts
# Usage: /gha-artifacts [arguments]

## Description
List, download, or expire build artifacts

## Behavior
1. Read configuration from environment variables
2. Call the appropriate Github Actions Ci Cd API or helper function
3. Present results in a structured table format
4. Recommend next steps based on findings

## Example Invocations
- `/gha-artifacts`
- `/gha-artifacts --help`
