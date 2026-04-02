# Installation Guide — Hunt with FortiSIEM

Step-by-step guide to install and configure the FortiSIEM AI plugin.

---

## Prerequisites

- **FortiSIEM 7.x** (tested on 7.2 and 7.4)
- **FortiSIEM API user** with permissions: Incident View, Analytics View, CMDB View
- **Claude Code CLI** installed — see [official docs](https://docs.anthropic.com/en/docs/claude-code/overview)
- **Python 3.9+** (for helper scripts)
- **Git** (to clone the repo)

Optional (for threat intel enrichment):
- VirusTotal API key (free tier: 4 req/min)
- AbuseIPDB API key (free tier: 1000 checks/day)
- Shodan API key (paid)

---

## Step 1: Clone the Repository

```bash
git clone https://github.com/threat-hunt-ai/threat-hunt-ai.git
cd fortisiem-ai
```

---

## Step 2: Set FortiSIEM Credentials

Create a `.env` file from the provided template:

```bash
cp .env.example .env
```

Edit `.env` with your values:

```bash
# .env
FSIEM_HOST='https://your-fortisiem-supervisor'
FSIEM_USER='your-api-username'
FSIEM_PASS='your-api-password'
FSIEM_ORG='super'                  # "super" for Enterprise deployments
                                   # Your org name for Service Provider mode
FSIEM_VERIFY_SSL='false'           # Set to 'true' in production with valid certs
```

### Important Notes on Credentials

- **Auth format**: FortiSIEM uses `org/user:password`, NOT `user:password`
- **FSIEM_HOST**: Must be the Supervisor URL with `https://` prefix
- **FSIEM_ORG**: Use `super` for Enterprise deployments. For MSSP/Service Provider, use the organization name exactly as it appears in FortiSIEM
- **Passwords with special characters**: Values are single-quoted in `.env` to handle `&`, `#`, `!`, etc.
- The `.env` file is gitignored and will never be committed

### Make Credentials Persist Across Sessions

Add this line to your shell profile (`~/.zshrc` or `~/.bashrc`):

```bash
echo '# FortiSIEM credentials
if [ -f "$HOME/path/to/fortisiem-ai/.env" ]; then
  set -a; source "$HOME/path/to/fortisiem-ai/.env"; set +a
fi' >> ~/.zshrc
```

Then reload:
```bash
source ~/.zshrc
```

---

## Step 3: Install the Plugin

Open a terminal in your project directory and run:

```bash
# Register the marketplace
/plugin marketplace add /path/to/fortisiem-ai/marketplace

# Install the plugin
/plugin install fsiem-essentials@fsiem-marketplace
```

Replace `/path/to/fortisiem-ai` with the actual path where you cloned the repo.

---

## Step 4: Verify Installation

```bash
/init-fsiem
```

You should see:

```
FortiSIEM AI Ready
Host : https://your-fortisiem-host
Org  : super
User : your-username

── L1 Triage ──────────────────
  /fsiem-l1-triage       Alert queue triage
  /fsiem-incidents       List/filter incidents
  /fsiem-enrich          Enrich IP/domain/hash
  ...
```

If you see an error, check [TROUBLESHOOTING.md](TROUBLESHOOTING.md).

---

## Step 5: Test Connectivity

Run a simple query to confirm the API is working:

```
/fsiem-incidents
```

This should return recent incidents from your FortiSIEM instance.

---

## Alternative: Docker Installation

If you prefer to run in a container:

```bash
cd docker
cp .env.example .env        # Edit with your FortiSIEM credentials
docker compose run --rm fsiem-claude
```

The Docker container includes:
- Debian bookworm-slim base
- Python 3 + requests/lxml
- fsiem-essentials plugin pre-installed
- git, jq, vim, curl, xmllint

---

## Optional: Enrichment API Keys

For threat intelligence enrichment during investigations and hunting:

```bash
# Add to your .env file
VT_API_KEY='your-virustotal-api-key'           # VirusTotal
ABUSEIPDB_API_KEY='your-abuseipdb-api-key'     # AbuseIPDB
SHODAN_API_KEY='your-shodan-api-key'            # Shodan
```

All enrichment functions degrade gracefully if keys are absent — basic GeoIP lookups still work without any keys.

---

## Optional: ITSM Integration

For automatic ticket creation from incidents:

```bash
# ServiceNow
SNOW_INSTANCE='your-instance.service-now.com'
SNOW_USER='your-servicenow-user'
SNOW_PASS='your-servicenow-password'

# Jira
JIRA_URL='https://your-jira.atlassian.net'
JIRA_USER='your-email@company.com'
JIRA_TOKEN='your-jira-api-token'
JIRA_PROJECT='SOC'

# PagerDuty
PAGERDUTY_TOKEN='your-pagerduty-token'
PAGERDUTY_SERVICE='your-service-id'
```

---

## Updating

```bash
cd fortisiem-ai
git pull
/reload-plugins
```

---

## Uninstalling

```bash
/plugin uninstall fsiem-essentials
/plugin marketplace remove fsiem-marketplace
```

---

## FortiSIEM API User Setup

If you need to create a dedicated API user in FortiSIEM:

1. Log in to FortiSIEM as admin
2. Go to **Admin > Roles** and create a role with these permissions:
   - Incident: View, Update (if you want auto-triage to update status)
   - Analytics: View
   - CMDB: View
   - Reports: View, Execute
   - Rules: View (add Create/Delete if using rule deployment)
3. Go to **Admin > Users** and create a user with the new role
4. Use this user's credentials in your `.env` file

For read-only hunting and investigation, only View permissions are needed. Rule deployment and incident status updates require write permissions.

---

## Directory Structure After Installation

```
fortisiem-ai/
├── .env.example          ← Template (safe to commit)
├── .env                  ← Your credentials (gitignored, never committed)
├── .gitignore
├── LICENSE
├── README.md
├── INSTALL.md            ← This file
├── ARCHITECTURE.md
├── CONTRIBUTING.md
├── TROUBLESHOOTING.md
├── CHANGELOG.md
├── SECURITY.md
├── CODE_OF_CONDUCT.md
├── examples/
│   └── quick-start.md
├── docker/
│   ├── Dockerfile
│   ├── docker-compose.yml
│   ├── entrypoint.sh
│   └── .env.example
└── marketplace/
    └── plugins/
        └── fsiem-essentials/
            ├── commands/       ← 28 slash commands
            ├── skills/         ← 12+ skills
            ├── agents/         ← 3 agents
            └── scripts/        ← 7 Python utilities
```
