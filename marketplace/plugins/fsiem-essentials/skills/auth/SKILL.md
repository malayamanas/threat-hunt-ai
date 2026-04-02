---
name: fsiem-auth
description: Build FortiSIEM Basic Auth headers and base URL. Use at the start of any FortiSIEM API interaction.
---

# FortiSIEM Authentication

FortiSIEM uses HTTP Basic Auth. The credential format varies by deployment:
- Most deployments: `org/user:password` (e.g. `super/admin:secret`)
- Some older versions: `user/org:password`

Set `FSIEM_AUTH_FORMAT=user_org` to force the legacy format.

## Quick Reference

```python
import base64, os

def fsiem_auth_header():
    user = os.environ.get("FSIEM_USER", "admin")
    org  = os.environ.get("FSIEM_ORG", "super")
    pw   = os.environ.get("FSIEM_PASS", "")
    fmt  = os.environ.get("FSIEM_AUTH_FORMAT", "").lower()
    if fmt == "user_org":
        credentials = f"{user}/{org}:{pw}"
    else:
        credentials = f"{org}/{user}:{pw}"
    token = base64.b64encode(credentials.encode()).decode()
    return {"Authorization": f"Basic {token}", "Content-Type": "text/xml"}

def fsiem_base_url():
    return os.environ.get("FSIEM_HOST", "").rstrip("/") + "/phoenix/rest"

def fsiem_verify_ssl():
    return os.environ.get("FSIEM_VERIFY_SSL", "false").lower() == "true"
```

## Key API Endpoints

| Endpoint | Method | Purpose |
|---|---|---|
| `/phoenix/rest/config/Domain` | GET | Connectivity test |
| `/phoenix/rest/pub/incident` | GET | List incidents (JSON) |
| `/phoenix/rest/pub/incident?incidentId=X` | GET | Incident detail (JSON) |
| `/phoenix/rest/pub/incident/triggeringEvents?incidentId=X` | GET | Triggering events (JSON) |
| `/phoenix/rest/query/eventQuery` | POST | Submit async event query (XML) |
| `/phoenix/rest/query/progress/{qid}` | GET | Poll query progress |
| `/phoenix/rest/query/events/{qid}/{start}/{end}` | GET | Retrieve query results |
| `/phoenix/rest/cmdbDeviceInfo/devices` | GET | CMDB device list |

## Environment Variables

| Variable | Default | Purpose |
|---|---|---|
| `FSIEM_HOST` | -- | Full URL to FortiSIEM Supervisor |
| `FSIEM_USER` | `admin` | Username |
| `FSIEM_ORG` | `super` | `super` for Enterprise; org name for SP |
| `FSIEM_PASS` | -- | Password |
| `FSIEM_VERIFY_SSL` | `false` | SSL cert verification |
| `FSIEM_AUTH_FORMAT` | (auto) | Force `user_org` for legacy format |

## Python SDK

All functions are in `scripts/fsiem_api.py`. Import and use:

```python
from fsiem_api import (
    get_config, auth_header, base_url,
    list_incidents, get_incident_detail, get_incident_events,
    build_query, query_run, cmdb_get_device
)
```
