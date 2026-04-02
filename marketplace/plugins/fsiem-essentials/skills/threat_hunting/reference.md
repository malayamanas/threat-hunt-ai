---
name: fsiem-hunt
description: Hunt for IOCs, suspicious IPs, domains, users, or MITRE techniques across FortiSIEM event data. Use when threat hunting or investigating indicators.
---
# Skill: Threat Hunting
# Hunt for IOCs and anomalous activity across FortiSIEM event data

## Overview
Threat hunting combines event querying with automated IOC extraction and cross-correlation.
Always hunt across at least 7 days of data unless timeframe is known to be shorter.

---

## fsiem_hunt_ip

```python
from typing import Union
from .event_query import fsiem_query_full, fsiem_build_query_xml

def fsiem_hunt_ip(
    ip: str,
    days_back: int = 7,
    include_as_dest: bool = True
) -> dict:
    """
    Hunt for all activity from (and optionally to) a suspicious IP.
    
    Returns:
        dict with keys: src_events, dest_events, summary
    """
    time_window = f"Last {days_back} days" if days_back <= 30 else "Last 30 days"
    
    # Events where IP is the source
    src_query = fsiem_build_query_xml(
        src_ips=[ip],
        time_window=time_window,
        attributes=["eventTime", "reptDevIpAddr", "eventType", "srcIpAddr",
                    "destIpAddr", "destPort", "user", "rawEventMsg"]
    )
    src_events = fsiem_query_full(src_query, max_results=500)
    
    dest_events = []
    if include_as_dest:
        # Events where IP is the destination (e.g., attacks targeting this IP)
        dest_query = fsiem_build_query_xml(
            dest_ips=[ip],
            time_window=time_window,
            attributes=["eventTime", "reptDevIpAddr", "eventType", "srcIpAddr",
                        "destIpAddr", "destPort", "user", "rawEventMsg"]
        )
        dest_events = fsiem_query_full(dest_query, max_results=500)
    
    # Summarize findings
    src_event_types = list(set(e.get("eventType", "") for e in src_events))
    dest_ips_contacted = list(set(e.get("destIpAddr", "") for e in src_events))
    
    return {
        "ip": ip,
        "days_back": days_back,
        "src_event_count": len(src_events),
        "dest_event_count": len(dest_events),
        "src_events": src_events[:50],    # First 50 for review
        "dest_events": dest_events[:50],
        "summary": {
            "event_types_as_src": src_event_types,
            "dest_ips_contacted": dest_ips_contacted[:20],
            "first_seen": min((e.get("eventTime","") for e in src_events), default=""),
            "last_seen": max((e.get("eventTime","") for e in src_events), default=""),
        }
    }
```

---

## fsiem_hunt_domain

```python
def fsiem_hunt_domain(domain: str, days_back: int = 7) -> dict:
    """
    Hunt for DNS lookups and connections to a suspicious domain.
    Searches rawEventMsg for domain name references.
    """
    time_window = f"Last {days_back} days"
    
    query = fsiem_build_query_xml(
        free_text=domain,
        time_window=time_window,
        attributes=["eventTime", "reptDevIpAddr", "eventType", "srcIpAddr",
                    "destIpAddr", "destPort", "user", "rawEventMsg"]
    )
    events = fsiem_query_full(query, max_results=500)
    
    # Separate DNS vs connection events
    dns_events = [e for e in events if "dns" in e.get("eventType", "").lower()]
    conn_events = [e for e in events if "dns" not in e.get("eventType", "").lower()]
    
    affected_hosts = list(set(e.get("srcIpAddr", "") for e in events))
    
    return {
        "domain": domain,
        "total_events": len(events),
        "dns_events": dns_events[:20],
        "connection_events": conn_events[:20],
        "affected_hosts": affected_hosts,
        "summary": {
            "first_seen": min((e.get("eventTime","") for e in events), default=""),
            "last_seen": max((e.get("eventTime","") for e in events), default=""),
            "unique_source_hosts": len(affected_hosts),
        }
    }
```

---

## fsiem_hunt_user

```python
def fsiem_hunt_user(username: str, days_back: int = 7) -> dict:
    """
    Hunt for anomalous activity from a user account.
    Checks logins, privilege usage, data access patterns.
    """
    time_window = f"Last {days_back} days"
    
    query = fsiem_build_query_xml(
        usernames=[username],
        time_window=time_window,
        attributes=["eventTime", "reptDevIpAddr", "eventType", "srcIpAddr",
                    "destIpAddr", "user", "hostName", "rawEventMsg"]
    )
    events = fsiem_query_full(query, max_results=1000)
    
    login_events = [e for e in events if "login" in e.get("eventType", "").lower()]
    failed_logins = [e for e in login_events if "fail" in e.get("eventType","").lower()]
    success_logins = [e for e in login_events if "fail" not in e.get("eventType","").lower()]
    
    source_ips = list(set(e.get("srcIpAddr","") for e in events if e.get("srcIpAddr")))
    hosts_accessed = list(set(e.get("hostName","") or e.get("destIpAddr","") for e in events))
    
    return {
        "username": username,
        "total_events": len(events),
        "failed_logins": len(failed_logins),
        "successful_logins": len(success_logins),
        "unique_source_ips": source_ips,
        "hosts_accessed": hosts_accessed[:20],
        "recent_events": events[:30],
        "risk_indicators": {
            "multiple_source_ips": len(source_ips) > 3,
            "high_failure_rate": len(failed_logins) > 10,
            "off_hours_activity": False,  # Implement based on your business hours
        }
    }
```

---

## fsiem_hunt_ioc_list

```python
def fsiem_hunt_ioc_list(
    iocs: list[dict],   # [{"type": "ip", "value": "1.2.3.4"}, ...]
    days_back: int = 7
) -> dict:
    """
    Hunt for a list of IOCs (bulk threat hunting).
    Efficiently queries for each IOC and aggregates results.
    
    Args:
        iocs: List of IOC dicts with "type" ("ip","domain","hash") and "value"
        days_back: Days of history to search
    Returns:
        dict mapping each IOC to its findings
    """
    results = {}
    hits = []
    
    for ioc in iocs:
        ioc_type = ioc.get("type", "").lower()
        ioc_value = ioc.get("value", "")
        
        try:
            if ioc_type == "ip":
                r = fsiem_hunt_ip(ioc_value, days_back=days_back)
            elif ioc_type == "domain":
                r = fsiem_hunt_domain(ioc_value, days_back=days_back)
            elif ioc_type == "user":
                r = fsiem_hunt_user(ioc_value, days_back=days_back)
            else:
                # Generic text search
                query = fsiem_build_query_xml(
                    free_text=ioc_value,
                    time_window=f"Last {days_back} days"
                )
                events = fsiem_query_full(query, max_results=100)
                r = {"events": events, "count": len(events)}
            
            results[ioc_value] = r
            if r.get("src_event_count", 0) > 0 or r.get("total_events", 0) > 0 or r.get("count",0) > 0:
                hits.append(ioc_value)
        
        except Exception as e:
            results[ioc_value] = {"error": str(e)}
    
    return {
        "total_iocs": len(iocs),
        "hits": hits,
        "hit_count": len(hits),
        "results": results,
    }
```

---

## fsiem_hunt_from_report

```python
import re

def fsiem_hunt_from_report(report_text: str, days_back: int = 30) -> dict:
    """
    Parse a threat report and automatically hunt for all extracted IOCs.
    
    Extracts: IPs, domains, file hashes (MD5/SHA1/SHA256)
    Then hunts for each in FortiSIEM.
    
    Args:
        report_text: Raw text of a threat intelligence report
        days_back: Days of history to search
    Returns:
        Hunt results for all extracted IOCs
    """
    iocs = []
    
    # Extract IPs (basic RFC-valid ranges, excluding private and reserved)
    ip_pattern = r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b'
    for ip in set(re.findall(ip_pattern, report_text)):
        # Filter private/loopback
        if not (ip.startswith("192.168.") or ip.startswith("10.") or
                ip.startswith("172.1") or ip.startswith("127.") or ip == "0.0.0.0"):
            iocs.append({"type": "ip", "value": ip})
    
    # Extract domains
    domain_pattern = r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+(?:com|net|org|io|cc|tk|xyz|top|info|biz|ru|cn|eu|co)\b'
    for domain in set(re.findall(domain_pattern, report_text)):
        if len(domain) > 4:
            iocs.append({"type": "domain", "value": domain})
    
    # Extract MD5 hashes
    md5_pattern = r'\b[0-9a-fA-F]{32}\b'
    for h in set(re.findall(md5_pattern, report_text)):
        iocs.append({"type": "hash", "value": h})
    
    # Extract SHA256 hashes
    sha256_pattern = r'\b[0-9a-fA-F]{64}\b'
    for h in set(re.findall(sha256_pattern, report_text)):
        iocs.append({"type": "hash", "value": h})
    
    print(f"Extracted {len(iocs)} IOCs: {len([i for i in iocs if i['type']=='ip'])} IPs, "
          f"{len([i for i in iocs if i['type']=='domain'])} domains, "
          f"{len([i for i in iocs if i['type']=='hash'])} hashes")
    
    return fsiem_hunt_ioc_list(iocs, days_back=days_back)
```

---

## fsiem_hunt_mitre_technique

```python
MITRE_HUNT_QUERIES = {
    "T1110": {  # Brute Force
        "description": "Hunt for brute force authentication activity",
        "event_types": ["Failed Login", "Authentication Failed"],
        "group_analysis": "Count failures per source IP"
    },
    "T1059": {  # Command and Scripting Interpreter
        "description": "Hunt for suspicious script/command execution",
        "free_text": "powershell|cmd.exe|wscript|cscript|bash -c|python -c",
        "event_types": ["Process Launch"]
    },
    "T1071": {  # Application Layer Protocol (C2)
        "description": "Hunt for C2 beaconing over standard protocols",
        "event_types": ["Network Connection", "HTTP Request"],
        "dest_ports": [80, 443, 8080, 8443, 4444, 9999]
    },
    "T1486": {  # Data Encrypted for Impact (Ransomware)
        "description": "Hunt for ransomware indicators",
        "free_text": ".encrypted|.locked|.ransom|DECRYPT_INSTRUCTIONS|HELP_DECRYPT",
        "event_types": ["File Create", "File Modify", "File Rename"]
    },
    "T1078": {  # Valid Accounts
        "description": "Hunt for anomalous use of legitimate accounts",
        "event_types": ["Successful Login", "Privileged Login"]
    },
}

def fsiem_hunt_mitre_technique(technique_id: str, days_back: int = 7) -> dict:
    """Hunt for evidence of a specific MITRE ATT&CK technique."""
    template = MITRE_HUNT_QUERIES.get(technique_id)
    if not template:
        return {"error": f"No hunt template for {technique_id}. Use fsiem_query_full with custom XML."}
    
    query = fsiem_build_query_xml(
        event_types=template.get("event_types"),
        free_text=template.get("free_text"),
        time_window=f"Last {days_back} days",
        attributes=["eventTime", "reptDevIpAddr", "eventType", "srcIpAddr",
                    "destIpAddr", "user", "hostName", "rawEventMsg"]
    )
    events = fsiem_query_full(query, max_results=500)
    
    return {
        "technique": technique_id,
        "description": template["description"],
        "days_back": days_back,
        "event_count": len(events),
        "events": events[:50],
        "affected_hosts": list(set(e.get("srcIpAddr","") for e in events if e.get("srcIpAddr"))),
    }
```
