---
name: fsiem-incidents
description: Query, triage, and update FortiSIEM incidents. Use when asked about incidents, alerts, or security events in FortiSIEM.
---

# FortiSIEM Incident Management

Incidents are queried via `GET /phoenix/rest/pub/incident` and return JSON.

## API Endpoints

| Endpoint | Method | Returns |
|---|---|---|
| `/pub/incident?timeFrom=X&timeTo=Y` | GET | All incidents in time range (JSON) |
| `/pub/incident?incidentId=X` | GET | Single incident detail (JSON) |
| `/pub/incident/triggeringEvents?incidentId=X` | GET | Triggering events with raw logs (JSON) |
| `/incident/updateIncidentStatus` | POST | Update status (XML body) |

## Key Functions (scripts/fsiem_api.py)

```python
from fsiem_api import list_incidents, get_incident_detail, get_incident_events, update_incident

# List incidents (last 24h, all severities)
incidents = list_incidents(hours_back=24)

# Filter by severity
high_incidents = list_incidents(hours_back=24, severity="HIGH")

# Get single incident
detail = get_incident_detail(10001234)

# Get triggering events (includes raw syslog messages)
events = get_incident_events(10001234)

# Update status
update_incident("10001234", "InProgress", "L2 investigation started")
```

## Incident JSON Fields

| Field | Type | Description |
|---|---|---|
| `incidentId` | int | Unique ID |
| `incidentTitle` | str | Human-readable title |
| `eventName` | str | Correlation rule name |
| `eventSeverityCat` | str | CRITICAL/HIGH/MEDIUM/LOW |
| `eventSeverity` | int | 1-10 numeric score |
| `incidentStatus` | int | 0=Active, 1=Auto-Cleared, 2=Manually-Cleared |
| `count` | int | Number of triggering events |
| `incidentFirstSeen` | int | Epoch ms |
| `incidentLastSeen` | int | Epoch ms |
| `incidentRptIp` | str | Reporting device IP |
| `incidentRptDevName` | str | Reporting device name |
| `customer` | str | Organization name |
| `attackTechnique` | str | MITRE ATT&CK JSON array |
| `attackTactic` | str | MITRE tactic(s) |
| `incidentTagName` | str | Incident tag |

## Triggering Event Fields

Each event in `get_incident_events()` includes:
- `rawMessage`: Full raw syslog/log line
- `eventType`: Parsed event type
- `receiveTime`: Epoch ms
- `attributes`: Dict with Reporting IP, Event Severity, Organization Name, etc.

## Full Pipeline

For end-to-end investigation, use `scripts/investigation_pipeline.py`:
```bash
python3 investigation_pipeline.py --incident 10001234 --output inv.json
python3 report_pdf.py --input inv.json --output report.pdf
```
