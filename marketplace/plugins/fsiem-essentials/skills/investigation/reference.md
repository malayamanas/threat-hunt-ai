---
name: fsiem-investigate
description: Create structured SOC investigation records and health reports for FortiSIEM incidents. Use when documenting an investigation or generating a report.
---
# Skill: Investigation & Reporting
# Create structured SOC investigations and reports

## Overview
Investigations document incident analysis, timelines, affected assets, and remediation steps.
Reports provide management-level summaries of FortiSIEM health and security posture.

---

## fsiem_investigate_incident

```python
from datetime import datetime
from .incidents import fsiem_get_incident_detail, fsiem_get_incident_events
from .cmdb import fsiem_cmdb_get_device
from .threat_hunting import fsiem_hunt_ip

def fsiem_investigate_incident(
    incident_id: str,
    analyst_name: str = "SOC Analyst",
    deep_hunt: bool = True
) -> dict:
    """
    Create a comprehensive investigation record for a FortiSIEM incident.
    
    Automatically:
    - Retrieves incident details and raw events
    - Looks up CMDB info for involved hosts
    - Optionally hunts for related activity
    - Generates a structured investigation record
    
    Returns:
        dict with full investigation record ready for documentation
    """
    print(f"Starting investigation for incident {incident_id}...")
    
    # Step 1: Get incident details
    incident = fsiem_get_incident_detail(incident_id)
    if not incident:
        return {"error": f"Incident {incident_id} not found"}
    
    # Step 2: Get raw events
    events = fsiem_get_incident_events(incident_id, max_results=100)
    
    # Step 3: Extract involved IPs
    src_ips = list(set(
        e.get("srcIpAddr","") for e in events if e.get("srcIpAddr","").strip()
    ))
    dest_ips = list(set(
        e.get("destIpAddr","") for e in events if e.get("destIpAddr","").strip()
    ))
    users = list(set(
        e.get("user","") for e in events if e.get("user","").strip()
    ))
    
    # Step 4: CMDB enrichment for involved IPs
    asset_info = {}
    for ip in (src_ips + dest_ips)[:10]:  # Limit to avoid too many API calls
        try:
            dev = fsiem_cmdb_get_device(ip=ip)
            if dev:
                asset_info[ip] = {
                    "hostname": dev.get("deviceName"),
                    "type": dev.get("deviceType"),
                    "os": dev.get("os"),
                    "owner": dev.get("owner"),
                    "org": dev.get("organization"),
                }
        except:
            asset_info[ip] = {"error": "Not in CMDB"}
    
    # Step 5: Build timeline
    timeline = sorted(
        [{"time": e.get("eventTime",""), "type": e.get("eventType",""),
          "src": e.get("srcIpAddr",""), "dest": e.get("destIpAddr",""),
          "msg": e.get("rawEventMsg","")[:200]}
         for e in events],
        key=lambda x: x["time"]
    )
    
    # Step 6: Threat hunt on primary source IP (if deep_hunt enabled)
    hunt_results = {}
    if deep_hunt and src_ips:
        primary_src = src_ips[0]
        try:
            hunt_results = fsiem_hunt_ip(primary_src, days_back=7)
            print(f"Hunt for {primary_src}: {hunt_results.get('src_event_count',0)} events found")
        except Exception as e:
            hunt_results = {"error": str(e)}
    
    # Build investigation record
    investigation = {
        "investigation_id": f"INV-{incident_id}-{datetime.now().strftime('%Y%m%d%H%M%S')}",
        "created_at": datetime.now().isoformat(),
        "analyst": analyst_name,
        "status": "In Progress",
        
        "incident": {
            "id": incident_id,
            "title": incident.get("incidentTitle") or incident.get("n"),
            "severity": incident.get("eventSeverity"),
            "status": incident.get("incidentStatus"),
            "category": incident.get("incidentCategory"),
            "rule_triggered": incident.get("ruleId"),
            "first_seen": incident.get("firstEventTime"),
            "last_seen": incident.get("lastEventTime"),
            "event_count": incident.get("eventCount"),
        },
        
        "scope": {
            "source_ips": src_ips,
            "destination_ips": dest_ips,
            "affected_users": users,
            "total_events": len(events),
        },
        
        "asset_inventory": asset_info,
        "timeline": timeline[:50],
        
        "threat_hunt": hunt_results,
        
        "analysis": {
            "initial_assessment": "",   # Analyst fills in
            "attack_vector": "",        # Analyst fills in
            "impact_assessment": "",    # Analyst fills in
            "false_positive": False,    # Set after analysis
        },
        
        "remediation": {
            "actions_taken": [],
            "recommendations": [],
            "status": "Pending",
        },
        
        "notes": "",
    }
    
    return investigation
```

---

## fsiem_investigation_summary (AI-Generated)

```python
def fsiem_investigation_summary(investigation: dict) -> str:
    """
    Generate a plain-English executive summary of an investigation.
    Suitable for management reporting or ticket documentation.
    """
    inc = investigation.get("incident", {})
    scope = investigation.get("scope", {})
    hunt = investigation.get("threat_hunt", {})
    
    summary_lines = [
        f"## Investigation Summary: {investigation.get('investigation_id')}",
        f"**Analyst**: {investigation.get('analyst')} | **Date**: {investigation.get('created_at', '')[:10]}",
        "",
        f"### Incident: {inc.get('title', 'Unknown')}",
        f"- **Severity**: {inc.get('severity', 'Unknown')}",
        f"- **Category**: {inc.get('category', 'Unknown')}",
        f"- **First Observed**: {inc.get('first_seen', 'Unknown')}",
        f"- **Last Observed**: {inc.get('last_seen', 'Unknown')}",
        f"- **Event Count**: {inc.get('event_count', 0)}",
        "",
        "### Scope of Impact",
        f"- **Source IPs**: {', '.join(scope.get('source_ips', [])) or 'None identified'}",
        f"- **Destination IPs**: {', '.join(scope.get('destination_ips', [])) or 'None identified'}",
        f"- **Affected Users**: {', '.join(scope.get('affected_users', [])) or 'None identified'}",
        f"- **Total Events Analyzed**: {scope.get('total_events', 0)}",
        "",
    ]
    
    if hunt.get("src_event_count", 0) > 0:
        summary_lines += [
            "### Threat Hunt Results",
            f"- Found {hunt.get('src_event_count', 0)} historical events from primary source IP",
            f"- Destinations contacted: {len(hunt.get('summary',{}).get('dest_ips_contacted', []))} unique IPs",
            "",
        ]
    
    summary_lines += [
        "### Recommended Actions",
        "1. Verify whether this is a false positive",
        "2. Block or investigate identified source IPs",
        "3. Reset credentials for affected user accounts",
        "4. Review firewall rules for affected hosts",
        "5. Update correlation rules if new TTPs identified",
    ]
    
    return "\n".join(summary_lines)
```

---

## fsiem_report_org_health

```python
def fsiem_report_org_health(org: str = "super", days_back: int = 7) -> dict:
    """
    Generate a health report for a FortiSIEM organization.
    Includes: incident counts by severity, top rules triggered,
    device coverage, and event volume.
    """
    from .incidents import fsiem_get_incidents
    
    # Get all incidents for the period
    all_incidents = fsiem_get_incidents(hours_back=days_back*24, org=org)
    
    # Categorize by severity
    by_severity = {}
    for inc in all_incidents:
        sev = inc.get("severity", "UNKNOWN")
        by_severity[sev] = by_severity.get(sev, 0) + 1
    
    # Top categories
    by_category = {}
    for inc in all_incidents:
        cat = inc.get("category", "Unknown")
        by_category[cat] = by_category.get(cat, 0) + 1
    
    top_categories = sorted(by_category.items(), key=lambda x: x[1], reverse=True)[:10]
    
    # Status breakdown
    by_status = {}
    for inc in all_incidents:
        st = inc.get("status", "Unknown")
        by_status[st] = by_status.get(st, 0) + 1
    
    return {
        "organization": org,
        "report_period_days": days_back,
        "generated_at": datetime.now().isoformat(),
        "summary": {
            "total_incidents": len(all_incidents),
            "by_severity": by_severity,
            "by_status": by_status,
        },
        "top_incident_categories": top_categories,
        "open_critical": [i for i in all_incidents
                          if i.get("severity") in ("CRITICAL","HIGH")
                          and i.get("status") == "Active"],
    }
```

---

## fsiem_report_top_incidents

```python
def fsiem_report_top_incidents(
    hours_back: int = 168,   # Default: 1 week
    top_n: int = 10
) -> list[dict]:
    """
    Report on the top N incidents by event count over the given period.
    Useful for identifying high-volume, recurring incident patterns.
    """
    from .incidents import fsiem_get_incidents
    
    incidents = fsiem_get_incidents(hours_back=hours_back, max_results=1000)
    
    # Sort by event count descending
    sorted_incidents = sorted(
        incidents,
        key=lambda x: int(x.get("count", 0) or 0),
        reverse=True
    )
    
    return sorted_incidents[:top_n]
```
