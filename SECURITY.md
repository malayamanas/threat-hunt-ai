# Security Policy

## Reporting Vulnerabilities

If you discover a security vulnerability in this project, please report it responsibly.

**Do NOT open a public GitHub issue for security vulnerabilities.**

Instead, email **security@techowl.in** with:

- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

We will acknowledge receipt within 48 hours and provide a timeline for a fix.

## Scope

This project is a plugin that interacts with FortiSIEM APIs. Security concerns include:

- **Credential handling** — Credentials are read from environment variables, never hardcoded. The `.env` file is gitignored.
- **API communication** — All FortiSIEM API calls use HTTPS. SSL verification is configurable via `FSIEM_VERIFY_SSL`.
- **No data storage** — This plugin does not persist event data, credentials, or investigation results beyond the current session unless explicitly saved by the user.

## Best Practices for Users

- Never commit `.env` files or credentials to version control
- Use `FSIEM_VERIFY_SSL=true` in production environments
- Restrict FortiSIEM API user permissions to read-only where possible
- Review generated correlation rules before deploying to production
- Audit investigation reports before sharing externally — they may contain sensitive IP addresses and hostnames
