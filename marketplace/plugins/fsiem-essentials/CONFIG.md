# FortiSIEM AI Plugin — Configuration Guide

## Required FortiSIEM Account Permissions

**Do not use the built-in `admin` account in production.** Create a dedicated service account with least-privilege access.

### Minimum Required Role Permissions

| Permission | Required For | API Endpoints Used |
|---|---|---|
| Incident → View | Reading incidents | `GET /incident/listIncidents` |
| Incident → Update | Updating status, adding comments | `POST /incident/updateIncidentStatus` |
| Analytics → View | Running event queries | `POST /query/eventQuery`, `GET /query/*` |
| CMDB → View | Device inventory lookups | `GET /cmdbDeviceInfo/*` |
| Rule → View | Listing correlation rules | `GET /rules` |
| Rule → Manage | Creating/enabling/disabling rules | `POST /rules` |
| Report → View | Running compliance reports | `GET /report/*` |
| Admin → View | System health, org management | `GET /config/*` |

### Creating the Service Account

1. FortiSIEM GUI → **Admin → Security Settings → Users**
2. Create user: `svc_claude_ai` (or your naming convention)
3. Assign role: **Full Analyst** (covers Incident + Analytics + CMDB + Rule View)
4. For rule deployment: also add **Rule Manager** role
5. For MSSP/SP deployments: assign to **Super Global** org for cross-tenant access

### Enterprise vs Service Provider Auth

```bash
# Enterprise — single org
export FSIEM_ORG="super"

# Service Provider — access specific tenant
export FSIEM_ORG="ACME_Corp"

# Service Provider — global admin
export FSIEM_ORG="super"
```

## Environment Variables

```bash
export FSIEM_HOST="https://your-fortisiem-host"   # Full URL including https://
export FSIEM_USER="svc_claude_ai"                 # Service account (not admin)
export FSIEM_PASS="yourpassword"                  # Use a secrets manager in production
export FSIEM_ORG="super"                          # "super" for Enterprise
export FSIEM_VERIFY_SSL="true"                    # "true" for production with valid cert
                                                  # "false" only for lab/self-signed
```

### Production SSL

For production with a valid cert:
```bash
export FSIEM_VERIFY_SSL="true"
```

For self-signed certs — install the CA instead of disabling verification:
```bash
# Export from FortiSIEM: Admin → Settings → SSL → Download CA Certificate
export REQUESTS_CA_BUNDLE=/path/to/fortisiem-ca.crt
export FSIEM_VERIFY_SSL="true"
```

### Storing Credentials Securely

**Never store `FSIEM_PASS` in `.claude/settings.json` or version control.**

```bash
# Option 1: .env file (in .gitignore)
cp docker/.env.example docker/.env   # edit — not committed to git

# Option 2: Vault / secrets manager
export FSIEM_PASS=$(vault kv get -field=password secret/fortisiem)

# Option 3: Docker secrets
docker secret create fsiem_pass - <<< "yourpassword"
```

## Version Compatibility

| FortiSIEM Version | Event Query API | Incident API | SOAR API | Notes |
|---|---|---|---|---|
| 6.7.x | ✅ XML | ✅ XML+JSON | ❌ | All core skills work |
| 7.0–7.3 | ✅ XML | ✅ XML+JSON | ❌ | All core skills work |
| 7.4.x | ✅ XML | ✅ XML+JSON | ✅ Beta | SOAR automation available |
| 7.5.x | ✅ XML | ✅ XML+JSON | ✅ GA | Full SOAR support |

All skills in this plugin work with FortiSIEM **6.7 and above**.

## API Base URL Reference

Base: `https://{FSIEM_HOST}/phoenix/rest/`

| Category | Endpoint | Method |
|---|---|---|
| Incidents | `/incident/listIncidents` | GET |
| Incident update | `/incident/updateIncidentStatus` | POST |
| Event query submit | `/query/eventQuery` | POST |
| Event query poll | `/query/progress/{id}` | GET |
| Event query results | `/query/events/{id}/{start}/{end}` | GET |
| CMDB devices | `/cmdbDeviceInfo/devices` | POST |
| CMDB device | `/cmdbDeviceInfo/device` | GET |
| Discovery trigger | `/cmdbDeviceInfo/discover` | POST |
| Rules | `/rules` | GET / POST |
| Organizations | `/config/Domain` | GET / POST |
| Reports | `/report/listReports` | GET |
| Run report | `/report/run` | POST |

## CLI Scripts

```bash
# General-purpose: incidents, queries, CMDB
python3 scripts/fsiem_api.py --help

# IOC hunting from threat report
python3 scripts/hunt_iocs.py --report apt_report.txt --days 30

# UEBA behavioral analysis
python3 scripts/ueba_report.py --user jsmith --baseline-days 30

# Scheduled daily IOC sweep (add to cron)
python3 scripts/scheduled_hunt.py --ioc-file watchlist.txt --days 1 --output /var/log/ioc_sweep.json
```
