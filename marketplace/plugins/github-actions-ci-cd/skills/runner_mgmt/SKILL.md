---
name: github-actions-ci-cd-runner_mgmt
description: Self-hosted and GitHub-hosted runner provisioning and scaling. Use this skill when the user asks about github-actions-ci-cd runner mgmt.
---
# Runner_mgmt

Self-hosted and GitHub-hosted runner provisioning and scaling.

## Overview

This skill provides Github Actions Ci Cd runner mgmt capabilities:
- Query current status and health
- Identify issues and anomalies
- Recommend remediation actions
- Automate common runner mgmt tasks

## Key Operations

See [reference.md](reference.md) for full Python implementations.

## Output Format

Present results as:
- Summary line (total count, severity breakdown)
- Table: id · name · status · last-updated
- Recommended next action
