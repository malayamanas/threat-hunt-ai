---
name: fsiem-ticketing
description: Create tickets in ServiceNow, Jira, or PagerDuty from FortiSIEM incidents and investigations. Use when asked to create a ticket, escalate an incident, or integrate with ITSM/alerting tools.
---

# FortiSIEM Ticketing Integration

FortiSIEM has a native ServiceNow connector. This skill also covers Jira and PagerDuty via their REST APIs.

## ServiceNow Integration

### Using FortiSIEM's Native ServiceNow Connector

FortiSIEM 6.7+ has built-in ServiceNow integration via **Admin → General Settings → Notification Policy**.

To create a ticket programmatically from an investigation:

```python
import requests, os, json

def create_servicenow_ticket(
    incident_id: str,
    investigation: dict,
    priority: int = 2,  # 1=Critical, 2=High, 3=Medium, 4=Low
) -> dict:
    """
    Create a ServiceNow incident from a FortiSIEM investigation record.

    Required env vars:
    SNOW_URL      = https://yourinstance.service-now.com
    SNOW_USER     = service account username
    SNOW_PASS     = service account password
    """
    snow_url  = os.environ["SNOW_URL"]
    snow_user = os.environ["SNOW_USER"]
    snow_pass = os.environ["SNOW_PASS"]

    inc  = investigation.get("incident", {})
    scope = investigation.get("scope", {})

    # Build description from investigation record
    description = f"""FortiSIEM Incident #{incident_id}

SUMMARY
=======
Title:     {inc.get('title', 'Unknown')}
Severity:  {inc.get('severity', 'Unknown')}
Category:  {inc.get('category', 'Unknown')}
Rule:      {inc.get('rule_triggered', 'Unknown')}
First Seen: {inc.get('first_seen', 'Unknown')}
Last Seen:  {inc.get('last_seen', 'Unknown')}
Event Count: {inc.get('event_count', 0)}

SCOPE
=====
Source IPs:  {', '.join(scope.get('source_ips', [])[:5])}
Dest IPs:    {', '.join(scope.get('destination_ips', [])[:5])}
Users:       {', '.join(scope.get('affected_users', [])[:5])}

INVESTIGATION ID: {investigation.get('investigation_id', 'N/A')}
Analyst: {investigation.get('analyst', 'N/A')}

See FortiSIEM for full event timeline and asset details.
"""

    payload = {
        "short_description": f"[FortiSIEM] {inc.get('severity','HIGH')}: {inc.get('title','Security Incident')}",
        "description": description,
        "priority": str(priority),
        "category": "Security",
        "subcategory": inc.get("category", "").replace("Security/", ""),
        "caller_id": snow_user,
        "assignment_group": os.environ.get("SNOW_ASSIGNMENT_GROUP", "SOC"),
        "work_notes": f"Auto-created from FortiSIEM investigation {investigation.get('investigation_id')}",
    }

    resp = requests.post(
        f"{snow_url}/api/now/table/incident",
        auth=(snow_user, snow_pass),
        headers={"Content-Type": "application/json", "Accept": "application/json"},
        json=payload
    )
    resp.raise_for_status()
    result = resp.json().get("result", {})
    return {
        "ticket_number": result.get("number"),
        "sys_id": result.get("sys_id"),
        "url": f"{snow_url}/nav_to.do?uri=incident.do?sys_id={result.get('sys_id')}",
        "state": result.get("state"),
    }
```

## Jira Integration

```python
def create_jira_ticket(
    incident_id: str,
    investigation: dict,
    priority: str = "High",  # Critical, High, Medium, Low
) -> dict:
    """
    Create a Jira issue from a FortiSIEM investigation.

    Required env vars:
    JIRA_URL      = https://yourcompany.atlassian.net
    JIRA_USER     = your-email@company.com
    JIRA_TOKEN    = API token (not password)
    JIRA_PROJECT  = Project key (e.g. SOC, SEC, IR)
    """
    jira_url     = os.environ["JIRA_URL"]
    jira_user    = os.environ["JIRA_USER"]
    jira_token   = os.environ["JIRA_TOKEN"]
    jira_project = os.environ.get("JIRA_PROJECT", "SOC")

    inc   = investigation.get("incident", {})
    scope = investigation.get("scope", {})

    description = {
        "type": "doc",
        "version": 1,
        "content": [
            {"type": "heading", "attrs": {"level": 2},
             "content": [{"type": "text", "text": "Incident Summary"}]},
            {"type": "paragraph", "content": [
                {"type": "text", "text":
                 f"FortiSIEM ID: {incident_id} | Severity: {inc.get('severity')} | "
                 f"Category: {inc.get('category')} | Events: {inc.get('event_count', 0)}"
                }]},
            {"type": "heading", "attrs": {"level": 2},
             "content": [{"type": "text", "text": "Scope"}]},
            {"type": "paragraph", "content": [
                {"type": "text", "text":
                 f"Source IPs: {', '.join(scope.get('source_ips', [])[:5])}\n"
                 f"Users: {', '.join(scope.get('affected_users', [])[:5])}"
                }]},
        ]
    }

    payload = {
        "fields": {
            "project": {"key": jira_project},
            "summary": f"[FortiSIEM #{incident_id}] {inc.get('severity','HIGH')}: {inc.get('title','Security Incident')}",
            "description": description,
            "issuetype": {"name": "Incident"},
            "priority": {"name": priority},
            "labels": ["fortisiem", "security", inc.get("category","").replace("Security/","").lower()],
        }
    }

    resp = requests.post(
        f"{jira_url}/rest/api/3/issue",
        auth=(jira_user, jira_token),
        headers={"Content-Type": "application/json"},
        json=payload
    )
    resp.raise_for_status()
    result = resp.json()
    return {
        "key": result.get("key"),
        "url": f"{jira_url}/browse/{result.get('key')}",
        "id": result.get("id"),
    }
```

## PagerDuty Integration

```python
def create_pagerduty_alert(
    incident_id: str,
    investigation: dict,
    routing_key: str = None,
) -> dict:
    """
    Trigger a PagerDuty alert from a FortiSIEM investigation.

    Required env vars:
    PAGERDUTY_ROUTING_KEY = Events API v2 integration key
    """
    routing_key = routing_key or os.environ["PAGERDUTY_ROUTING_KEY"]
    inc = investigation.get("incident", {})

    # Map FortiSIEM severity to PagerDuty
    severity_map = {"CRITICAL": "critical", "HIGH": "error", "MEDIUM": "warning", "LOW": "info"}
    pd_severity = severity_map.get(inc.get("severity", "HIGH"), "error")

    payload = {
        "routing_key": routing_key,
        "event_action": "trigger",
        "dedup_key": f"fortisiem-{incident_id}",
        "payload": {
            "summary": f"[FortiSIEM] {inc.get('title', 'Security Incident')}",
            "severity": pd_severity,
            "source": "FortiSIEM",
            "component": inc.get("category", "Security"),
            "group": "SOC",
            "custom_details": {
                "incident_id": incident_id,
                "severity": inc.get("severity"),
                "category": inc.get("category"),
                "event_count": inc.get("event_count"),
                "source_ips": investigation.get("scope", {}).get("source_ips", [])[:3],
                "investigation_id": investigation.get("investigation_id"),
            }
        }
    }

    resp = requests.post(
        "https://events.pagerduty.com/v2/enqueue",
        json=payload,
        headers={"Content-Type": "application/json"}
    )
    resp.raise_for_status()
    result = resp.json()
    return {
        "dedup_key": result.get("dedup_key"),
        "status": result.get("status"),
        "message": result.get("message"),
    }
```

## Unified Escalation Function

```python
def escalate_incident(
    incident_id: str,
    investigation: dict,
    targets: list[str] = None,  # ["servicenow", "jira", "pagerduty"]
) -> dict:
    """
    Escalate a FortiSIEM investigation to one or more ticketing systems.
    Detects available integrations from environment variables automatically.
    """
    targets = targets or []
    results = {}

    # Auto-detect available integrations
    if not targets:
        if os.environ.get("SNOW_URL"):
            targets.append("servicenow")
        if os.environ.get("JIRA_URL"):
            targets.append("jira")
        if os.environ.get("PAGERDUTY_ROUTING_KEY"):
            targets.append("pagerduty")

    if not targets:
        return {"error": "No ticketing integrations configured. Set SNOW_URL, JIRA_URL, or PAGERDUTY_ROUTING_KEY."}

    for target in targets:
        try:
            if target == "servicenow":
                results["servicenow"] = create_servicenow_ticket(incident_id, investigation)
                print(f"✓ ServiceNow: {results['servicenow']['ticket_number']}")
            elif target == "jira":
                results["jira"] = create_jira_ticket(incident_id, investigation)
                print(f"✓ Jira: {results['jira']['key']}")
            elif target == "pagerduty":
                results["pagerduty"] = create_pagerduty_alert(incident_id, investigation)
                print(f"✓ PagerDuty: {results['pagerduty']['status']}")
        except Exception as e:
            results[target] = {"error": str(e)}
            print(f"✗ {target}: {e}")

    return results
```

## Required Environment Variables

| Integration | Variables |
|---|---|
| ServiceNow | `SNOW_URL`, `SNOW_USER`, `SNOW_PASS`, `SNOW_ASSIGNMENT_GROUP` |
| Jira | `JIRA_URL`, `JIRA_USER`, `JIRA_TOKEN`, `JIRA_PROJECT` |
| PagerDuty | `PAGERDUTY_ROUTING_KEY` |
