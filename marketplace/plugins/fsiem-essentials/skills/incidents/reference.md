---
name: fsiem-incidents
description: Query, triage, and update FortiSIEM incidents. Use when asked about incidents, alerts, or security events in FortiSIEM.
---
# Skill: Incident Management
# Query and manage FortiSIEM incidents

## Overview
FortiSIEM incident APIs return XML. Parse with `xml.etree.ElementTree`.
Base endpoint: `GET/POST /phoenix/rest/incident/`

---

## fsiem_get_incidents

Query open or historical incidents with optional filters.

```python
import requests
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta

def fsiem_get_incidents(
    hours_back: int = 24,
    severity: str = None,        # "HIGH", "MEDIUM", "LOW", "INFO"
    status: str = None,          # "Active", "Cleared", "False Positive", "InProgress"
    category: str = None,        # e.g. "Security/Malware"
    max_results: int = 100,
    org: str = "super"
) -> list[dict]:
    """
    List incidents matching the given filters.
    Returns list of incident dicts with keys: id, name, severity, status,
    count, firstOccurred, lastOccurred, category, srcIPs, destIPs.
    """
    from .auth import fsiem_auth_header, fsiem_base_url, fsiem_verify_ssl
    
    now = int(datetime.now().timestamp() * 1000)
    start = int((datetime.now() - timedelta(hours=hours_back)).timestamp() * 1000)
    
    params = {
        "startTime": start,
        "endTime": now,
        "maxResults": max_results,
    }
    if severity:
        params["eventSeverity"] = severity
    if status:
        params["status"] = status
    if category:
        params["incidentCategory"] = category

    url = f"{fsiem_base_url()}/incident/listIncidents"
    resp = requests.get(
        url,
        params=params,
        headers={**fsiem_auth_header(), "Content-Type": "application/xml"},
        verify=fsiem_verify_ssl()
    )
    resp.raise_for_status()
    
    root = ET.fromstring(resp.text)
    incidents = []
    for inc in root.findall(".//incident"):
        incidents.append({
            "id": inc.findtext("incidentId"),
            "name": inc.findtext("incidentTitle"),
            "severity": inc.findtext("eventSeverity"),
            "status": inc.findtext("incidentStatus"),
            "count": inc.findtext("eventCount"),
            "firstOccurred": inc.findtext("firstEventTime"),
            "lastOccurred": inc.findtext("lastEventTime"),
            "category": inc.findtext("incidentCategory"),
            "srcIPs": [ip.text for ip in inc.findall(".//srcIpAddr")],
            "destIPs": [ip.text for ip in inc.findall(".//destIpAddr")],
            "ruleId": inc.findtext("ruleId"),
        })
    return incidents
```

---

## fsiem_get_incident_detail

```python
def fsiem_get_incident_detail(incident_id: str) -> dict:
    """Get full detail for a specific incident."""
    from .auth import fsiem_auth_header, fsiem_base_url, fsiem_verify_ssl
    
    url = f"{fsiem_base_url()}/incident/listIncidents"
    params = {"incidentId": incident_id}
    resp = requests.get(url, params=params,
                        headers=fsiem_auth_header(),
                        verify=fsiem_verify_ssl())
    resp.raise_for_status()
    root = ET.fromstring(resp.text)
    inc = root.find(".//incident")
    if inc is None:
        return {}
    return {tag.tag: tag.text for tag in inc}
```

---

## fsiem_update_incident_status

```python
def fsiem_update_incident_status(
    incident_id: str,
    status: str,          # "Active" | "Cleared" | "False Positive" | "InProgress"
    comment: str = ""
) -> bool:
    """Update the status of an incident. Returns True on success."""
    from .auth import fsiem_auth_header, fsiem_base_url, fsiem_verify_ssl
    
    xml_body = f"""<incidentStatusChange>
  <incidentId>{incident_id}</incidentId>
  <incidentStatus>{status}</incidentStatus>
  <comment>{comment}</comment>
</incidentStatusChange>"""
    
    url = f"{fsiem_base_url()}/incident/updateIncidentStatus"
    resp = requests.post(url, data=xml_body,
                         headers={**fsiem_auth_header(), "Content-Type": "application/xml"},
                         verify=fsiem_verify_ssl())
    return resp.status_code == 200
```

---

## fsiem_get_incident_events

```python
def fsiem_get_incident_events(incident_id: str, max_results: int = 50) -> list[dict]:
    """
    Retrieve raw events associated with an incident.
    Uses the event query API to find events by incidentId.
    """
    from .query import fsiem_query_full
    
    query_xml = f"""<Reports>
  <Report>
    <Name>Incident Events</Name>
    <Description>Events for incident {incident_id}</Description>
    <SelectClause>
      <AttrList>reptDevIpAddr,eventType,srcIpAddr,destIpAddr,user,msg,rawEventMsg</AttrList>
    </SelectClause>
    <ReportInterval>
      <Window>Last 7 days</Window>
    </ReportInterval>
    <PatternClause>
      <SubPattern>
        <Filters>
          <Filter>
            <Name>incidentId</Name>
            <Operator>CONTAINS</Operator>
            <Value>{incident_id}</Value>
          </Filter>
        </Filters>
      </SubPattern>
    </PatternClause>
  </Report>
</Reports>"""
    return fsiem_query_full(query_xml, max_results=max_results)
```

---

## Usage Notes
- Incident IDs are integers but treat as strings for API calls
- Severity values: `"1"` = LOW, `"2"` = MEDIUM, `"3"` = HIGH, `"4"` = CRITICAL (check your version)
- Always check `resp.status_code` – FortiSIEM sometimes returns 200 with an error XML body
- For SP deployments, filter by org using `?organization=ORG_NAME` query param
