#!/usr/bin/env python3
"""
FortiSIEM Investigation Pipeline
End-to-end L1 Triage -> L2 Investigation -> L3 Threat Intel for a single incident.
Outputs structured JSON consumed by report_pdf.py to generate the final PDF.

Usage:
    export FSIEM_HOST=https://soc.example.com
    export FSIEM_USER=admin FSIEM_PASS=secret FSIEM_ORG=super
    python3 investigation_pipeline.py --incident 10001234 --output investigation.json
    python3 report_pdf.py --input investigation.json --output report.pdf
"""

import os
import sys
import json
import re
import time
from datetime import datetime, timedelta
from collections import Counter, defaultdict

# Import the API helper (same directory)
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from fsiem_api import (
    get_config, check_env, list_incidents, get_incident_detail,
    get_incident_events, update_incident, build_query, query_run,
    query_submit, query_poll, query_results, cmdb_get_device,
    api_get_json, test_connectivity
)
from ai_reasoning import (
    detect_repeating_pattern, classify_actor, analyze_event_chain,
    generate_verdict, reason_about_correlation
)


# --- L1 Triage ---------------------------------------------------------------

CRITICAL_KEYWORDS = [
    "ransomware", "lsass", "mimikatz", "cobalt", "c2", "beacon",
    "exfiltration", "credential dump", "pass the hash", "kerberoast",
    "bloodhound", "lateral movement", "privilege escalation",
    "zero-day", "0-day", "apt", "nation-state",
    "malicious ip", "malware", "ioc", "command and control",
    "darkTrace", "nsdl ioc", "sentinel one", "threat",
    "c2 detection", "malicious", "botnet",
]

FP_KEYWORDS = [
    "nessus", "qualys", "rapid7", "tenable", "vulnerability scan",
    "patch scan", "health check", "scheduled task", "backup"
]

SLA_TARGETS = {
    "CRITICAL": {"ack": 5, "triage": 15, "close": 30},
    "HIGH":     {"ack": 15, "triage": 30, "close": 120},
    "MEDIUM":   {"ack": 60, "triage": 240, "close": 480},
    "LOW":      {"ack": 240, "triage": 1440, "close": 4320},
}

STATUS_LABELS = {0: "Active", 1: "Auto-Cleared", 2: "Manually Cleared", 3: "InProgress"}


def l1_triage(incident: dict, events: list) -> dict:
    """
    L1 quick-check triage for a single incident.
    Returns triage result dict with signals, disposition, confidence, priority.
    """
    triage = {
        "tier": "L1",
        "analyst": "FortiSIEM AI L1 Triage",
        "timestamp": datetime.now().isoformat(),
        "incident_id": incident.get("incidentId"),
        "signals": [],
        "tp_score": 0,
        "fp_score": 0,
        "disposition": None,
        "confidence": 0,
        "priority": None,
        "sla": {},
        "escalate_to": None,
        "notes": [],
    }

    title = (incident.get("incidentTitle") or "").lower()
    rule = (incident.get("eventName") or "").lower()
    severity = incident.get("eventSeverityCat", "MEDIUM").upper()
    count = incident.get("count", 0)
    mitre = incident.get("attackTechnique", "")
    tactic = incident.get("attackTactic", "")
    tag = incident.get("incidentTagName", "")

    # --- Signal scoring ---

    # Critical keyword match
    for kw in CRITICAL_KEYWORDS:
        if kw in title or kw in rule:
            triage["signals"].append({
                "type": "CRITICAL_KEYWORD",
                "detail": f"Matched: '{kw}'",
                "weight": 10
            })
            triage["tp_score"] += 10
            break

    # FP keyword match
    for kw in FP_KEYWORDS:
        if kw in title or kw in rule:
            triage["signals"].append({
                "type": "KNOWN_SCANNER",
                "detail": f"Matched: '{kw}'",
                "weight": -5
            })
            triage["fp_score"] += 5
            break

    # Severity scoring
    sev_scores = {"CRITICAL": 10, "HIGH": 7, "MEDIUM": 4, "LOW": 1}
    sev_weight = sev_scores.get(severity, 2)
    triage["signals"].append({
        "type": "SEVERITY",
        "detail": f"{severity} ({incident.get('eventSeverity', '?')}/10)",
        "weight": sev_weight
    })
    triage["tp_score"] += sev_weight

    # Volume scoring
    if count >= 100:
        triage["signals"].append({
            "type": "HIGH_VOLUME",
            "detail": f"{count} events",
            "weight": 5
        })
        triage["tp_score"] += 5
    elif count >= 50:
        triage["signals"].append({
            "type": "MODERATE_VOLUME",
            "detail": f"{count} events",
            "weight": 3
        })
        triage["tp_score"] += 3

    # MITRE ATT&CK mapping
    if mitre:
        triage["signals"].append({
            "type": "MITRE_MAPPED",
            "detail": mitre if isinstance(mitre, str) else json.dumps(mitre),
            "weight": 4
        })
        triage["tp_score"] += 4

    # Network infra keywords
    net_keywords = ["mac flap", "mac move", "spanning tree", "loop", "arp", "vlan"]
    for kw in net_keywords:
        if kw in title or kw in rule:
            triage["signals"].append({
                "type": "NETWORK_INFRA",
                "detail": f"Network keyword: '{kw}'",
                "weight": 3
            })
            triage["tp_score"] += 3
            break

    # Event pattern analysis
    event_patterns = analyze_event_patterns(events)
    if event_patterns.get("single_source_ratio", 0) > 0.9:
        triage["signals"].append({
            "type": "CONCENTRATED_SOURCE",
            "detail": f"Single source accounts for {event_patterns['single_source_ratio']:.0%} of events",
            "weight": 3
        })
        triage["tp_score"] += 3

    triage["event_patterns"] = event_patterns

    # --- Disposition decision ---
    tp = triage["tp_score"]
    fp = triage["fp_score"]

    if tp >= 15 and fp < 5:
        triage["disposition"] = "TRUE_POSITIVE"
        triage["confidence"] = min(95, 70 + tp)
        triage["escalate_to"] = "L2"
        triage["priority"] = "P1" if severity == "CRITICAL" else "P2"
    elif tp >= 10 and fp < 5:
        triage["disposition"] = "TRUE_POSITIVE"
        triage["confidence"] = min(90, 60 + tp)
        triage["escalate_to"] = "L2"
        triage["priority"] = "P2"
    elif fp > tp:
        triage["disposition"] = "FALSE_POSITIVE"
        triage["confidence"] = min(90, 50 + fp * 5)
        triage["priority"] = "P4"
    elif tp >= 5:
        triage["disposition"] = "INVESTIGATE"
        triage["confidence"] = min(80, 50 + tp * 2)
        triage["escalate_to"] = "L2"
        triage["priority"] = "P3"
    else:
        triage["disposition"] = "NEEDS_MORE_INFO"
        triage["confidence"] = 30
        triage["priority"] = "P3"

    triage["sla"] = SLA_TARGETS.get(severity, SLA_TARGETS["MEDIUM"])

    return triage


def analyze_event_patterns(events: list) -> dict:
    """Analyze triggering events for patterns."""
    patterns = {
        "total_events": len(events),
        "unique_macs": [],
        "affected_vlans": [],
        "port_movements": [],
        "unique_src_ips": [],
        "unique_event_types": [],
        "time_span_minutes": 0,
        "single_source_ratio": 0,
        "raw_samples": [],
    }

    if not events:
        return patterns

    macs = Counter()
    vlans = Counter()
    port_moves = Counter()
    src_ips = Counter()
    event_types = Counter()
    timestamps = []

    for e in events:
        raw = e.get("rawMessage", "")
        attrs = e.get("attributes", {})

        # Parse MAC flap events
        m = re.search(r"Mac\s+(\S+)\s+in\s+vlan\s+(\d+)\s+has\s+moved\s+from\s+(\S+)\s+to\s+(\S+)", raw)
        if m:
            mac, vlan, src_port, dst_port = m.groups()
            macs[mac] += 1
            vlans[vlan] += 1
            port_moves[f"{src_port} -> {dst_port}"] += 1

        # Collect IPs and event types
        rpt_ip = attrs.get("Reporting IP", "")
        if rpt_ip:
            src_ips[rpt_ip] += 1
        evt = e.get("eventType", attrs.get("Event Type", ""))
        if evt:
            event_types[evt] += 1

        # Timestamps
        recv_time = attrs.get("Event Receive Time") or e.get("receiveTime")
        if recv_time:
            try:
                timestamps.append(int(recv_time))
            except (ValueError, TypeError):
                pass

        # Raw samples (first 5)
        if len(patterns["raw_samples"]) < 5 and raw:
            patterns["raw_samples"].append(raw[:200])

    patterns["unique_macs"] = [{"mac": mac, "count": cnt} for mac, cnt in macs.most_common()]
    patterns["affected_vlans"] = sorted(vlans.keys())
    patterns["port_movements"] = [{"movement": mv, "count": cnt} for mv, cnt in port_moves.most_common()]
    patterns["unique_src_ips"] = [{"ip": ip, "count": cnt} for ip, cnt in src_ips.most_common()]
    patterns["unique_event_types"] = [{"type": et, "count": cnt} for et, cnt in event_types.most_common()]

    if timestamps:
        span = (max(timestamps) - min(timestamps)) / 60000  # ms to minutes
        patterns["time_span_minutes"] = round(span, 1)

    # Single source ratio
    if src_ips:
        top_count = src_ips.most_common(1)[0][1]
        patterns["single_source_ratio"] = top_count / sum(src_ips.values())

    return patterns


# --- L2 Investigation ---------------------------------------------------------

def _extract_actor(incident: dict, events: list) -> dict:
    """Extract who did what from incident and triggering events."""
    actor = {
        "username": "",
        "domain": "",
        "security_id": "",
        "logon_id": "",
        "source_ip": "",
        "hostname": "",
        "device_type": "",
        "action": "",
        "event_id": "",
    }

    # From incident fields
    title = incident.get("incidentTitle", "")
    # Extract username from title patterns like "User admin Cleared..."
    m = re.search(r"[Uu]ser\s+(\S+)\s+", title)
    if m:
        actor["username"] = m.group(1)
    # Extract hostname from title like "...on DESKTOP-D8DASL8"
    m = re.search(r"on\s+(\S+)", title)
    if m:
        actor["hostname"] = m.group(1)

    # From triggering event attributes (much richer)
    for e in events:
        attrs = e.get("attributes", {})
        if isinstance(attrs, dict):
            actor["username"] = attrs.get("User", actor["username"]) or actor["username"]
            actor["domain"] = attrs.get("Target Domain", attrs.get("Domain Name", "")) or actor["domain"]
            actor["security_id"] = attrs.get("Security ID", "") or actor["security_id"]
            actor["logon_id"] = attrs.get("Win Logon Id", "") or actor["logon_id"]
            actor["source_ip"] = attrs.get("Host IP", attrs.get("Reporting IP", "")) or actor["source_ip"]
            actor["hostname"] = attrs.get("Host Name", attrs.get("Reporting Device", "")) or actor["hostname"]
            actor["device_type"] = attrs.get("Device Type", "") or actor["device_type"]
            actor["event_id"] = attrs.get("Windows Event ID", "") or actor["event_id"]

        # Extract from raw message if attributes missing
        raw = e.get("rawMessage", "")
        if not actor["username"]:
            m = re.search(r"Account Name:\s*(\S+)", raw)
            if m:
                actor["username"] = m.group(1)
        if not actor["security_id"]:
            m = re.search(r"Security ID:\s*(S-[\d-]+)", raw)
            if m:
                actor["security_id"] = m.group(1)
        if not actor["logon_id"]:
            m = re.search(r"Logon ID:\s*(0x[\dA-Fa-f]+)", raw)
            if m:
                actor["logon_id"] = m.group(1)
        if not actor["source_ip"]:
            m = re.search(r'IP:\s*"?(\d+\.\d+\.\d+\.\d+)', raw)
            if m:
                actor["source_ip"] = m.group(1)

    # Determine the action
    title_lower = title.lower()
    if "cleared" in title_lower or "clear" in title_lower:
        actor["action"] = "Cleared security/audit logs"
    elif "created" in title_lower:
        actor["action"] = "Created account/object"
    elif "deleted" in title_lower:
        actor["action"] = "Deleted account/object"
    elif "logon" in title_lower or "login" in title_lower:
        actor["action"] = "Authentication event"
    elif "modified" in title_lower or "changed" in title_lower:
        actor["action"] = "Modified configuration"
    else:
        actor["action"] = title[:60]

    return actor


def _build_event_timeline(queried_events: list, incident_time_ms: int) -> list:
    """
    Build a forensic timeline from queried events.
    Groups events by type, shows what happened before/during/after the incident.
    Returns sorted list of timeline entries.
    """
    timeline = []
    incident_time = incident_time_ms / 1000 if incident_time_ms else 0

    for e in queried_events:
        entry = {
            "time": "",
            "event_type": e.get("eventType", "Unknown"),
            "user": e.get("user", ""),
            "src_ip": e.get("srcIpAddr", ""),
            "dest_ip": e.get("destIpAddr", ""),
            "hostname": e.get("hostName", ""),
            "detail": "",
            "phase": "",  # BEFORE, DURING, AFTER
        }

        # Parse timestamp
        recv_time = e.get("phRecvTime", "")
        if recv_time:
            entry["time"] = recv_time
            # Try to determine phase relative to incident
            try:
                from datetime import datetime as dt
                # Handle "Sat Mar 28 16:01:31 IST 2026" format
                time_str = recv_time.replace("IST ", "").replace("UTC ", "")
                for fmt in ["%a %b %d %H:%M:%S %Y", "%Y-%m-%d %H:%M:%S"]:
                    try:
                        t = dt.strptime(time_str, fmt)
                        ts = t.timestamp()
                        if incident_time:
                            diff = ts - incident_time
                            if diff < -300:
                                entry["phase"] = "BEFORE"
                            elif diff > 300:
                                entry["phase"] = "AFTER"
                            else:
                                entry["phase"] = "DURING"
                        break
                    except ValueError:
                        continue
            except Exception:
                pass

        # Extract meaningful detail from raw event
        raw = e.get("rawEventMsg", "")
        if raw:
            # FortiGate log: extract action/dstip/app
            for field in ["action", "app", "dstip", "service", "url"]:
                m = re.search(rf'{field}="?([^"\s]+)', raw)
                if m:
                    entry["detail"] += f"{field}={m.group(1)} "
            # Windows event: extract key info
            if "MSWinEventLog" in raw or "EventLog" in raw:
                m = re.search(r'(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})\s+\S+\s+\S+\s+\d+\s+(.*?)$', raw[:200])
                if m:
                    entry["detail"] = m.group(2)[:80]
            # Seqrite
            if "Seqrite" in e.get("eventType", ""):
                m = re.search(r'application_name="?([^"]+)"?', raw)
                if m:
                    entry["detail"] = f"app={m.group(1)}"

        entry["detail"] = entry["detail"].strip()[:100]
        timeline.append(entry)

    # Sort by time and deduplicate
    timeline.sort(key=lambda x: x["time"])

    # Summarize: group consecutive same-type events
    summarized = []
    prev_type = None
    prev_count = 0
    for entry in timeline:
        if entry["event_type"] == prev_type and len(summarized) > 0:
            prev_count += 1
            summarized[-1]["count"] = prev_count
        else:
            entry["count"] = 1
            summarized.append(entry)
            prev_type = entry["event_type"]
            prev_count = 1

    return summarized


def l2_investigate(incident: dict, events: list, all_incidents: list, cfg=None) -> dict:
    """
    L2 deep investigation: correlation, timeline, blast radius.
    """
    inv = {
        "tier": "L2",
        "analyst": "FortiSIEM AI L2 Investigator",
        "timestamp": datetime.now().isoformat(),
        "investigation_id": f"L2-{incident.get('incidentId')}-{int(time.time())}",
        "actor": {},
        "correlated_incidents": [],
        "timeline": [],
        "event_timeline": [],
        "blast_radius": {},
        "affected_assets": [],
        "event_queries": [],
        "containment_actions": [],
        "notes": [],
    }

    # --- Extract actor details from triggering events ---
    inv["actor"] = _extract_actor(incident, events)

    inc_id = incident.get("incidentId")
    rpt_ip = incident.get("incidentRptIp", "")
    org = incident.get("customer", "")
    first_seen = incident.get("incidentFirstSeen", 0)
    last_seen = incident.get("incidentLastSeen", 0)

    # --- Correlated incidents (same device + same org) ---
    same_device = []
    same_org = []
    for i in all_incidents:
        if i.get("incidentId") == inc_id:
            continue
        if i.get("incidentRptIp") == rpt_ip:
            same_device.append(i)
        if i.get("customer") == org:
            same_org.append(i)

    inv["correlated_incidents"] = {
        "same_device": _format_incidents(same_device),
        "same_org": _format_incidents(same_org),
        "total_same_device": len(same_device),
        "total_same_org": len(same_org),
    }

    # --- Build timeline from all correlated incidents ---
    all_timeline_incidents = [incident] + same_org
    timeline = []
    for i in sorted(all_timeline_incidents, key=lambda x: x.get("incidentFirstSeen", 0)):
        timeline.append({
            "time_start": _ts_to_str(i.get("incidentFirstSeen", 0)),
            "time_end": _ts_to_str(i.get("incidentLastSeen", 0)),
            "incident_id": i.get("incidentId"),
            "severity": i.get("eventSeverityCat", ""),
            "title": i.get("incidentTitle", ""),
            "count": i.get("count", 0),
            "source_ip": i.get("incidentRptIp", ""),
            "rule": i.get("eventName", ""),
        })
    inv["timeline"] = timeline

    # --- Blast radius ---
    unique_ips = set()
    unique_rules = set()
    sev_counts = Counter()
    total_events = 0

    for i in same_org + [incident]:
        if i.get("incidentRptIp"):
            unique_ips.add(i["incidentRptIp"])
        if i.get("eventName"):
            unique_rules.add(i["eventName"])
        sev_counts[i.get("eventSeverityCat", "UNKNOWN")] += 1
        total_events += i.get("count", 0)

    inv["blast_radius"] = {
        "total_incidents": len(same_org) + 1,
        "total_events": total_events,
        "unique_source_ips": sorted(unique_ips),
        "unique_rules": sorted(unique_rules),
        "severity_breakdown": dict(sev_counts),
        "scope_level": _assess_scope(unique_ips, same_org),
    }

    # --- Event queries for deeper context ---
    # Query 1: Events from the reporting device/IP
    query_events = []
    if rpt_ip:
        try:
            query_xml = build_query(
                src_ips=[rpt_ip],
                time_window="Last 6 hours",
                limit=200
            )
            print(f"  [L2] Running event query for {rpt_ip}...")
            query_events = query_run(query_xml, max_results=200, timeout=90, cfg=cfg)
            inv["event_queries"].append({
                "description": f"All events from {rpt_ip} (last 6h)",
                "result_count": len(query_events),
                "sample_events": query_events[:10]
            })
            print(f"  [L2] Got {len(query_events)} events from query")
        except Exception as e:
            inv["event_queries"].append({
                "description": f"All events from {rpt_ip} (last 6h)",
                "result_count": 0,
                "error": str(e)
            })
            print(f"  [L2] Event query error: {e}")

    # Query 2: If actor has a different source IP, query that too
    actor_ip = inv["actor"].get("source_ip", "")
    if actor_ip and actor_ip != rpt_ip:
        try:
            query_xml2 = build_query(
                src_ips=[actor_ip],
                time_window="Last 6 hours",
                limit=200
            )
            print(f"  [L2] Running event query for actor IP {actor_ip}...")
            actor_events = query_run(query_xml2, max_results=200, timeout=90, cfg=cfg)
            query_events.extend(actor_events)
            inv["event_queries"].append({
                "description": f"All events from actor IP {actor_ip} (last 6h)",
                "result_count": len(actor_events),
                "sample_events": actor_events[:10]
            })
            print(f"  [L2] Got {len(actor_events)} events from actor IP query")
        except Exception as e:
            inv["event_queries"].append({
                "description": f"All events from actor IP {actor_ip} (last 6h)",
                "result_count": 0,
                "error": str(e)
            })
            print(f"  [L2] Actor IP query error: {e}")

    # Build forensic event timeline from queried events
    if query_events:
        incident_time = incident.get("incidentFirstSeen", 0)
        inv["event_timeline"] = _build_event_timeline(query_events, incident_time)
        print(f"  [L2] Built event timeline: {len(inv['event_timeline'])} entries")

    # --- Lateral spread check: find OTHER hosts contacting the same external IPs ---
    inv["lateral_spread"] = []
    title = incident.get("incidentTitle", "")
    ext_ips_in_title = [ip for ip in re.findall(r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b', title)
                        if not ip.startswith(("10.", "172.16.", "172.17.", "172.18.", "172.19.",
                                              "172.20.", "172.21.", "172.22.", "172.23.", "172.24.",
                                              "172.25.", "172.26.", "172.27.", "172.28.", "172.29.",
                                              "172.30.", "172.31.", "192.168.", "127.", "0."))]
    if ext_ips_in_title:
        # Search all incidents for the same malicious external IP
        for mal_ip in ext_ips_in_title[:3]:
            other_hosts = set()
            other_incidents = []
            for i in all_incidents:
                i_title = i.get("incidentTitle", "")
                if mal_ip in i_title and i.get("incidentId") != inc_id:
                    other_incidents.append({
                        "id": i.get("incidentId"),
                        "title": i_title,
                        "org": i.get("customer", ""),
                        "source_ip": i.get("incidentRptIp", ""),
                        "severity": i.get("eventSeverityCat", ""),
                        "last_seen": _ts_to_str(i.get("incidentLastSeen", 0)),
                    })
                    # Extract internal IPs from that incident's title
                    for ip in re.findall(r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b', i_title):
                        if ip.startswith(("10.", "172.", "192.168.")):
                            other_hosts.add(ip)
            inv["lateral_spread"].append({
                "malicious_ip": mal_ip,
                "other_incidents": other_incidents,
                "other_internal_hosts": sorted(other_hosts),
                "total_affected_hosts": len(other_hosts),
                "total_incidents": len(other_incidents),
            })
            if other_incidents:
                print(f"  [L2] SPREAD CHECK: {mal_ip} also seen in {len(other_incidents)} other incidents, {len(other_hosts)} other hosts")
            else:
                print(f"  [L2] SPREAD CHECK: {mal_ip} not seen in other incidents")

    # --- Affected assets from CMDB ---
    for ip in list(unique_ips)[:5]:
        try:
            device = cmdb_get_device(ip=ip, cfg=cfg)
            if device:
                inv["affected_assets"].append({
                    "ip": ip,
                    "name": device.get("name", ""),
                    "type": device.get("deviceType", device.get("type", "")),
                    "os": device.get("osType", ""),
                })
        except Exception:
            inv["affected_assets"].append({"ip": ip, "name": "Unknown", "type": "Unknown"})

    return inv


def _format_incidents(incidents: list) -> list:
    """Format incidents for the report."""
    formatted = []
    for i in sorted(incidents, key=lambda x: x.get("incidentFirstSeen", 0)):
        formatted.append({
            "id": i.get("incidentId"),
            "title": i.get("incidentTitle", ""),
            "severity": i.get("eventSeverityCat", ""),
            "count": i.get("count", 0),
            "status": STATUS_LABELS.get(i.get("incidentStatus", -1), "Unknown"),
            "first_seen": _ts_to_str(i.get("incidentFirstSeen", 0)),
            "last_seen": _ts_to_str(i.get("incidentLastSeen", 0)),
            "source_ip": i.get("incidentRptIp", ""),
            "rule": i.get("eventName", ""),
        })
    return formatted


def _ts_to_str(ts_ms) -> str:
    """Convert epoch milliseconds to readable string."""
    if not ts_ms:
        return ""
    try:
        return datetime.fromtimestamp(int(ts_ms) / 1000).strftime("%Y-%m-%d %H:%M:%S")
    except (ValueError, TypeError, OSError):
        return str(ts_ms)


def _assess_scope(unique_ips, correlated) -> str:
    if len(unique_ips) > 10:
        return "WIDESPREAD"
    elif len(unique_ips) > 3:
        return "LIMITED"
    else:
        return "CONTAINED"


# --- L3 Threat Intelligence ---------------------------------------------------

MITRE_TECHNIQUES = {
    "T1557.002": {"name": "ARP Cache Poisoning", "tactic": "Credential Access", "kill_chain": "Lateral Movement + Collection"},
    "T1557.001": {"name": "LLMNR/NBT-NS Poisoning", "tactic": "Credential Access", "kill_chain": "Credential Access"},
    "T1557":     {"name": "Man-in-the-Middle", "tactic": "Credential Access, Collection", "kill_chain": "Lateral Movement"},
    "T1040":     {"name": "Network Sniffing", "tactic": "Credential Access", "kill_chain": "Collection"},
    "T1071":     {"name": "Application Layer Protocol", "tactic": "Command and Control", "kill_chain": "C2"},
    "T1018":     {"name": "Remote System Discovery", "tactic": "Discovery", "kill_chain": "Discovery"},
    "T1078":     {"name": "Valid Accounts", "tactic": "Initial Access", "kill_chain": "Initial Access"},
    "T1110":     {"name": "Brute Force", "tactic": "Credential Access", "kill_chain": "Credential Access"},
    "T1059":     {"name": "Command and Scripting Interpreter", "tactic": "Execution", "kill_chain": "Execution"},
    "T1003":     {"name": "OS Credential Dumping", "tactic": "Credential Access", "kill_chain": "Credential Access"},
    "T1486":     {"name": "Data Encrypted for Impact", "tactic": "Impact", "kill_chain": "Impact"},
    "T1021":     {"name": "Remote Services", "tactic": "Lateral Movement", "kill_chain": "Lateral Movement"},
    "T1046":     {"name": "Network Service Discovery", "tactic": "Discovery", "kill_chain": "Discovery"},
    "T1048":     {"name": "Exfiltration Over Alternative Protocol", "tactic": "Exfiltration", "kill_chain": "Exfiltration"},
    "T1204":     {"name": "User Execution", "tactic": "Execution", "kill_chain": "Execution"},
    "T1566":     {"name": "Phishing", "tactic": "Initial Access", "kill_chain": "Initial Access"},
    "T1548":     {"name": "Abuse Elevation Control", "tactic": "Privilege Escalation", "kill_chain": "Privilege Escalation"},
}


def l3_threat_intel(incident: dict, events: list, l2_result: dict) -> dict:
    """
    L3 threat intelligence analysis: MITRE mapping, Diamond Model, risk scoring.
    """
    l3 = {
        "tier": "L3",
        "analyst": "FortiSIEM AI L3 Threat Hunter",
        "timestamp": datetime.now().isoformat(),
        "mitre_mapping": {},
        "diamond_model": {},
        "risk_score": {},
        "attribution": {},
        "iocs": [],
        "recommendations": {},
    }

    # --- MITRE ATT&CK Mapping ---
    primary_techniques = []
    related_techniques = []

    # Parse MITRE from incident
    mitre_raw = incident.get("attackTechnique", "")
    if isinstance(mitre_raw, str):
        try:
            mitre_list = json.loads(mitre_raw)
        except (json.JSONDecodeError, ValueError):
            mitre_list = []
    else:
        mitre_list = mitre_raw if isinstance(mitre_raw, list) else []

    for tech in mitre_list:
        tid = tech.get("techniqueid", "")
        name = tech.get("name", "")
        if tid in MITRE_TECHNIQUES:
            info = MITRE_TECHNIQUES[tid]
            primary_techniques.append({
                "id": tid,
                "name": name or info["name"],
                "tactic": info["tactic"],
                "kill_chain": info["kill_chain"],
                "evidence": "Directly mapped by FortiSIEM rule",
                "confidence": "HIGH"
            })

    # Infer MITRE from title/rule when FortiSIEM doesn't tag attackTechnique
    if not primary_techniques:
        title_lower = (incident.get("incidentTitle") or "").lower()
        rule_lower = (incident.get("eventName") or "").lower()
        combined = title_lower + " " + rule_lower

        # Title/rule -> MITRE mapping
        title_mitre_map = [
            (["malicious ip", "ioc", "darkTrace", "nsdl ioc", "c2 detection", "command and control", "outbound communication"],
             "T1071", "Application Layer Protocol", "Command and Control", "C2",
             "Outbound communication to known malicious IP"),
            (["malware", "sentinel one", "trellix", "antivirus", "virus", "trojan", "worm"],
             "T1204", "User Execution", "Execution", "Execution",
             "Malware detection on endpoint"),
            (["brute force", "failed logon", "login failure", "excessive login"],
             "T1110", "Brute Force", "Credential Access", "Credential Access",
             "Authentication attack pattern"),
            (["ransomware", "encrypt", "shadow copy", "vssadmin"],
             "T1486", "Data Encrypted for Impact", "Impact", "Impact",
             "Ransomware behavior detected"),
            (["exfiltration", "data leak", "dlp", "removable device"],
             "T1048", "Exfiltration Over Alternative Protocol", "Exfiltration", "Exfiltration",
             "Data loss prevention alert"),
            (["lateral movement", "remote service", "psexec", "wmi", "rdp"],
             "T1021", "Remote Services", "Lateral Movement", "Lateral Movement",
             "Lateral movement indicator"),
            (["privilege escalation", "admin", "sudo", "uac"],
             "T1548", "Abuse Elevation Control", "Privilege Escalation", "Privilege Escalation",
             "Privilege escalation attempt"),
            (["phishing", "spear", "email"],
             "T1566", "Phishing", "Initial Access", "Initial Access",
             "Phishing attempt detected"),
            (["port scan", "network scan", "reconnaissance"],
             "T1046", "Network Service Discovery", "Discovery", "Discovery",
             "Network scanning activity"),
        ]

        for keywords, tid, tname, tactic, kill_chain, evidence in title_mitre_map:
            if any(kw in combined for kw in keywords):
                primary_techniques.append({
                    "id": tid,
                    "name": tname,
                    "tactic": tactic,
                    "kill_chain": kill_chain,
                    "evidence": f"Inferred from rule: {evidence}",
                    "confidence": "MEDIUM"
                })
                break  # Take the first (most specific) match

    # Add related techniques based on primary
    primary_ids = {t["id"] for t in primary_techniques}
    related_map = {
        "T1557.002": ["T1557", "T1557.001", "T1040", "T1071", "T1018"],
        "T1557.001": ["T1557", "T1040"],
        "T1110":     ["T1078", "T1021"],
        "T1003":     ["T1078", "T1550"],
        "T1486":     ["T1490", "T1059"],
    }
    for pid in primary_ids:
        for rid in related_map.get(pid, []):
            if rid not in primary_ids and rid in MITRE_TECHNIQUES:
                info = MITRE_TECHNIQUES[rid]
                related_techniques.append({
                    "id": rid,
                    "name": info["name"],
                    "tactic": info["tactic"],
                    "kill_chain": info["kill_chain"],
                    "evidence": f"Related to {pid}",
                    "confidence": "MEDIUM"
                })

    # Check correlated incidents for additional MITRE mappings
    # Track which technique IDs we've already added to avoid duplicates
    related_ids = set()
    for ci in l2_result.get("correlated_incidents", {}).get("same_org", []):
        ci_title = ci.get("title", "").lower()
        ci_rule = ci.get("rule", "").lower()
        if ("brute force" in ci_title or "failed logon" in ci_title or
                "login failure" in ci_title or "account locked" in ci_title):
            if "T1110" not in primary_ids and "T1110" not in related_ids:
                related_ids.add("T1110")
                evidence_parts = []
                for c in l2_result.get("correlated_incidents", {}).get("same_org", []):
                    t = c.get("title", "").lower()
                    if "brute" in t or "failed logon" in t or "locked" in t:
                        evidence_parts.append(c.get("title", "")[:40])
                related_techniques.append({
                    "id": "T1110", "name": "Brute Force",
                    "tactic": "Credential Access", "kill_chain": "Credential Access",
                    "evidence": f"Correlated: {'; '.join(evidence_parts[:2])}",
                    "confidence": "MEDIUM"
                })
        if "dlp" in ci_title or "removable" in ci_title or "exfil" in ci_title:
            if "T1048" not in primary_ids and "T1048" not in related_ids:
                related_ids.add("T1048")
                dlp_count = sum(1 for c in l2_result.get("correlated_incidents", {}).get("same_org", [])
                               if "dlp" in c.get("title","").lower() or "removable" in c.get("title","").lower())
                related_techniques.append({
                    "id": "T1048", "name": "Exfiltration Over Alternative Protocol",
                    "tactic": "Exfiltration", "kill_chain": "Exfiltration",
                    "evidence": f"{dlp_count} DLP violation(s) during incident window",
                    "confidence": "LOW"
                })

    # Deduplicate related techniques by ID
    seen_ids = set()
    deduped = []
    for t in related_techniques:
        if t["id"] not in seen_ids:
            seen_ids.add(t["id"])
            deduped.append(t)
    related_techniques = deduped

    l3["mitre_mapping"] = {
        "primary": primary_techniques,
        "related": related_techniques,
        "total_techniques": len(primary_techniques) + len(related_techniques),
        "tactics_covered": sorted(set(
            t["tactic"].split(",")[0].strip()
            for t in primary_techniques + related_techniques
        )),
    }

    # --- Diamond Model ---
    org = incident.get("customer", "Unknown")
    rpt_ip = incident.get("incidentRptIp", "")

    l3["diamond_model"] = {
        "adversary": {
            "identity": "Unknown -- likely insider or physical access actor",
            "tier": _assess_adversary_tier(primary_techniques, l2_result),
            "sophistication": _assess_sophistication(primary_techniques, events),
            "motivation": _assess_motivation(incident, primary_techniques, l2_result),
            "access_type": "Physical/Local Network" if any("ARP" in t.get("name","") or "MAC" in t.get("name","") for t in primary_techniques) else "Remote",
        },
        "capability": {
            "tool_class": _assess_tools(primary_techniques),
            "skill_level": _assess_skill(primary_techniques),
            "customization": "None detected -- standard attack pattern",
        },
        "infrastructure": {
            "pivot_point": rpt_ip,
            "scope": f"{len(l2_result.get('blast_radius', {}).get('unique_source_ips', []))} unique IPs",
            "network_tier": "Core/Distribution" if "switch" in (incident.get("incidentRptDevName") or "").lower() else "Edge",
        },
        "victim": {
            "organization": org,
            "sector": _infer_sector(org),
            "criticality": "HIGH" if _is_banking_org(org) else "MEDIUM",
            "compliance": _infer_compliance(org),
        },
    }

    # --- Risk Score ---
    event_patterns = {}
    # Get event patterns from L1 if available
    blast = l2_result.get("blast_radius", {})

    attack_feasibility = 9 if any("ARP" in t.get("name","") for t in primary_techniques) else 6
    asset_criticality = 9 if _is_banking_org(org) else 6
    evidence_confidence = 8 if len(primary_techniques) > 0 else 5
    blast_score = min(9, 3 + len(blast.get("unique_source_ips", [])))

    combined = round((attack_feasibility + asset_criticality + evidence_confidence + blast_score) / 4, 1)

    l3["risk_score"] = {
        "attack_feasibility": {"score": attack_feasibility, "reason": "Based on technique complexity"},
        "asset_criticality": {"score": asset_criticality, "reason": f"{org} -- {_infer_sector(org)}"},
        "evidence_confidence": {"score": evidence_confidence, "reason": f"{len(primary_techniques)} confirmed techniques"},
        "blast_radius": {"score": blast_score, "reason": f"{len(blast.get('unique_source_ips', []))} affected IPs"},
        "combined": combined,
        "level": "CRITICAL" if combined >= 9 else "HIGH" if combined >= 7 else "MEDIUM" if combined >= 5 else "LOW",
    }

    # --- Attribution ---
    l3["attribution"] = {
        "status": "UNATTRIBUTED",
        "assessment": "No known APT group signatures match this pattern.",
        "likely_actor_type": l3["diamond_model"]["adversary"]["tier"],
        "confidence": "LOW",
    }

    # --- IOCs ---
    iocs = []
    seen_values = set()
    title = incident.get("incidentTitle", "")

    def _add_ioc(ioc_type, value, context, action):
        if value and value not in seen_values:
            seen_values.add(value)
            iocs.append({"type": ioc_type, "value": value, "context": context, "action": action})

    # Extract IPs from incident title (e.g., "From 192.168.1.1 to 8.8.8.8")
    title_ips = re.findall(r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b', title)
    for ip in title_ips:
        is_private = ip.startswith(("10.", "172.16.", "172.17.", "172.18.", "172.19.",
                                     "172.20.", "172.21.", "172.22.", "172.23.", "172.24.",
                                     "172.25.", "172.26.", "172.27.", "172.28.", "172.29.",
                                     "172.30.", "172.31.", "192.168."))
        if is_private:
            _add_ioc("IP (Internal)", ip, "Source host from incident", "Isolate and scan for malware")
        else:
            _add_ioc("IP (External)", ip, "Malicious destination IP", "Block at perimeter firewall")

    # Reporting device
    if rpt_ip and rpt_ip not in seen_values:
        _add_ioc("IP (Device)", rpt_ip, "Reporting device", "Audit configuration")

    # MAC addresses from events
    mac_seen = set()
    for e in events[:100]:
        raw = e.get("rawMessage", "")
        m = re.search(r"Mac\s+(\S+)", raw)
        if m and m.group(1) not in mac_seen:
            mac_seen.add(m.group(1))
            _add_ioc("MAC", m.group(1), "Flapping MAC address", "Block / Identify device")

    # Port IOCs from MAC flap events
    for e in events[:100]:
        raw = e.get("rawMessage", "")
        m = re.search(r"has\s+moved\s+from\s+(\S+)\s+to\s+(\S+)", raw)
        if m:
            _add_ioc("Port", m.group(1), "Source port", "Verify configuration")
            _add_ioc("Port", m.group(2), "Destination port", "Verify configuration")
            break

    # Extract external IPs from raw events (dest IPs, srcip, dstip fields)
    ext_ips = Counter()
    for e in events[:100]:
        raw = e.get("rawMessage", "")
        # FortiGate log format: dstip=X.X.X.X or srcip=X.X.X.X
        for field in ["dstip", "dst", "destip"]:
            m = re.search(rf'{field}[=:]"?(\d{{1,3}}\.\d{{1,3}}\.\d{{1,3}}\.\d{{1,3}})', raw)
            if m:
                ip = m.group(1)
                if not ip.startswith(("10.", "172.16.", "172.17.", "172.18.", "172.19.",
                                       "172.20.", "172.21.", "172.22.", "172.23.", "172.24.",
                                       "172.25.", "172.26.", "172.27.", "172.28.", "172.29.",
                                       "172.30.", "172.31.", "192.168.", "127.", "0.")):
                    ext_ips[ip] += 1
    for ip, cnt in ext_ips.most_common(5):
        _add_ioc("IP (External)", ip, f"External dest ({cnt} connections)", "Block at firewall + threat intel lookup")

    # Extract source IPs from raw events
    src_ips = Counter()
    for e in events[:100]:
        raw = e.get("rawMessage", "")
        for field in ["srcip", "src"]:
            m = re.search(rf'{field}[=:]"?(\d{{1,3}}\.\d{{1,3}}\.\d{{1,3}}\.\d{{1,3}})', raw)
            if m:
                src_ips[m.group(1)] += 1
    for ip, cnt in src_ips.most_common(3):
        _add_ioc("IP (Internal)", ip, f"Source host ({cnt} events)", "Isolate and scan")

    # User IOCs from correlated incidents
    for ci in l2_result.get("correlated_incidents", {}).get("same_org", []):
        ci_title = ci.get("title", "")
        m = re.search(r"(?:user|account)\s+(\S+)\s+(?:locked|created|modified|failed)", ci_title, re.IGNORECASE)
        if m:
            _add_ioc("Account", m.group(1), f"From: {ci_title[:45]}", "Reset password")

    # Domains from raw events
    for e in events[:50]:
        raw = e.get("rawMessage", "")
        m = re.search(r'hostname[=:]"?([a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,})', raw)
        if m:
            _add_ioc("Domain", m.group(1), "From network traffic", "Block and investigate")

    l3["iocs"] = iocs

    # --- Recommendations ---
    l3["recommendations"] = {
        "immediate": _gen_immediate_recs(incident, primary_techniques, l2_result),
        "short_term": _gen_short_term_recs(incident, primary_techniques, l2_result),
        "long_term": _gen_long_term_recs(incident, primary_techniques, l2_result),
    }

    return l3


def _assess_adversary_tier(techniques, l2_result) -> str:
    tactics = set(t.get("tactic", "") for t in techniques)
    if len(tactics) >= 4:
        return "Advanced Persistent Threat"
    elif len(tactics) >= 2:
        return "Organized / Semi-Sophisticated"
    return "Opportunistic / Script Kiddie"


def _assess_sophistication(techniques, events) -> str:
    if any("T1003" in t.get("id","") or "T1055" in t.get("id","") for t in techniques):
        return "HIGH"
    elif any("T1557" in t.get("id","") for t in techniques):
        return "LOW-MEDIUM"
    return "LOW"


def _assess_motivation(incident, techniques, l2_result) -> str:
    org = incident.get("customer", "")
    if _is_banking_org(org):
        return "Financial Gain / Credential Theft"
    if any("T1486" in t.get("id","") for t in techniques):
        return "Ransomware / Extortion"
    if any("T1048" in t.get("id","") for t in techniques):
        return "Data Theft / Exfiltration"
    return "Unknown -- requires further investigation"


def _assess_tools(techniques) -> str:
    tool_map = {
        "T1557.002": "ARP spoofing (arpspoof, bettercap, ettercap)",
        "T1557.001": "Responder, Inveigh",
        "T1003":     "Mimikatz, procdump, secretsdump",
        "T1110":     "Hydra, Medusa, Burp Suite",
        "T1059":     "PowerShell, cmd, bash",
    }
    for t in techniques:
        if t.get("id") in tool_map:
            return tool_map[t["id"]]
    return "Unknown tooling"


def _assess_skill(techniques) -> str:
    if any(t.get("id","") in ["T1003","T1055","T1550"] for t in techniques):
        return "Advanced"
    return "Script kiddie to intermediate"


def _is_banking_org(org: str) -> bool:
    """Detect banking/financial orgs including Indian co-operative banks."""
    org_lower = org.lower()
    # Direct banking keywords
    banking_kw = [
        "bank", "finance", "credit", "co-op", "cooperative",
        "urban", "mercantile", "peoples", "district",
        "savings", "loan", "mutual", "federal", "national",
    ]
    return any(kw in org_lower for kw in banking_kw)


def _infer_sector(org: str) -> str:
    if _is_banking_org(org):
        return "Banking / Financial Services (BFSI)"
    org_lower = org.lower()
    if any(kw in org_lower for kw in ["hospital", "health", "medical", "pharma", "clinic"]):
        return "Healthcare / Pharma"
    if any(kw in org_lower for kw in ["university", "school", "college", "education", "academy"]):
        return "Education"
    if any(kw in org_lower for kw in ["infosec", "tech", "msp", "cloud", "data", "cyber", "software"]):
        return "Information Technology / MSP"
    return "Enterprise"


def _infer_compliance(org: str) -> str:
    if _is_banking_org(org):
        return "RBI IT Framework, PCI DSS, CERT-In"
    org_lower = org.lower()
    if any(kw in org_lower for kw in ["hospital", "health", "pharma"]):
        return "HIPAA, NABH"
    return "ISO 27001, CERT-In"


def _extract_ips_from_title(title: str) -> dict:
    """Extract source and dest IPs from incident title."""
    ips = re.findall(r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b', title)
    result = {"source": [], "dest": []}
    for ip in ips:
        is_private = ip.startswith(("10.", "172.16.", "172.17.", "172.18.", "172.19.",
                                     "172.20.", "172.21.", "172.22.", "172.23.", "172.24.",
                                     "172.25.", "172.26.", "172.27.", "172.28.", "172.29.",
                                     "172.30.", "172.31.", "192.168."))
        if is_private:
            result["source"].append(ip)
        else:
            result["dest"].append(ip)
    return result


def _gen_immediate_recs(incident, techniques, l2_result) -> list:
    recs = []
    title = incident.get("incidentTitle", "")
    rpt_ip = incident.get("incidentRptIp", "")
    title_ips = _extract_ips_from_title(title)

    # C2 / Malicious IP specific
    if any(t.get("id") == "T1071" for t in techniques) or "malicious" in title.lower() or "ioc" in title.lower() or "c2" in title.lower():
        for ip in title_ips.get("dest", []):
            recs.append(f"Block external IP {ip} at perimeter firewall immediately")
        for ip in title_ips.get("source", []):
            recs.append(f"Isolate internal host {ip} from network pending malware scan")
        recs.append("Verify the malicious IP against threat intel feeds (VirusTotal, AbuseIPDB, OTX)")
        recs.append("Check for active processes and network connections on the source host")
        recs.append("Capture memory dump from affected host before remediation")

    # ARP-specific
    elif any("ARP" in t.get("name","") or "T1557" in t.get("id","") for t in techniques):
        recs.append("Run 'show mac address-table' on the affected switch to identify rogue device")
        recs.append("If unauthorized device found, shut down the switch port immediately")
        recs.append("Capture ARP tables on affected VLANs for forensic evidence")
        recs.append("Check for duplicate IP addresses on affected VLANs")

    # Brute force specific
    elif any("T1110" in t.get("id","") for t in techniques):
        recs.append("Lock out source accounts showing brute force activity")
        recs.append("Block source IP at perimeter firewall")
        recs.append("Enable account lockout policy if not already configured")

    # Malware specific
    elif any("T1204" in t.get("id","") for t in techniques):
        for ip in title_ips.get("source", []):
            recs.append(f"Isolate host {ip} and run full antivirus scan")
        recs.append("Collect malware samples for analysis (quarantine, do not delete)")
        recs.append("Check for persistence mechanisms on the infected host")

    # Generic fallback
    else:
        if rpt_ip:
            recs.append(f"Investigate device at {rpt_ip}")
        recs.append("Isolate affected system from network pending investigation")
        recs.append("Preserve all logs and forensic artifacts")

    return recs


def _gen_short_term_recs(incident, techniques, l2_result) -> list:
    recs = []
    title = incident.get("incidentTitle", "").lower()

    # C2 / Malicious IP
    if any(t.get("id") == "T1071" for t in techniques) or "malicious" in title or "ioc" in title:
        recs.append("Run full endpoint scan (EDR/AV) on all affected internal hosts")
        recs.append("Review DNS logs for the malicious IP -- identify all internal hosts that contacted it")
        recs.append("Check firewall logs for other hosts communicating with the same external IP")
        recs.append("Review proxy/web filter logs for related malicious domains")
        recs.append("Check if the malicious IP appears in any threat intel watchlists")

    # ARP poisoning
    elif any("T1557" in t.get("id","") for t in techniques):
        recs.append("Enable Dynamic ARP Inspection (DAI) on affected VLANs")
        recs.append("Enable DHCP snooping as prerequisite for DAI")
        recs.append("Configure port security with maximum MAC address limit")
        recs.append("Review all active sessions from the identified MAC/IP")

    # DLP correlation
    for ci in l2_result.get("correlated_incidents", {}).get("same_org", []):
        if "dlp" in ci.get("title", "").lower():
            recs.append("Investigate DLP violations -- determine if data was exfiltrated during attack window")
            break

    # Account lockouts
    for ci in l2_result.get("correlated_incidents", {}).get("same_org", []):
        if "locked" in ci.get("title", "").lower():
            recs.append("Force password reset for locked accounts detected during incident window")
            break

    # Bulk email correlation
    for ci in l2_result.get("correlated_incidents", {}).get("same_org", []):
        if "bulk mail" in ci.get("title", "").lower() or "spam" in ci.get("title", "").lower():
            recs.append("Investigate bulk email activity -- check if compromised account is sending spam/phishing")
            break

    if not recs:
        recs.append("Review firewall rules for affected network segments")
        recs.append("Scan affected hosts for indicators of compromise")

    return recs


def _gen_long_term_recs(incident, techniques, l2_result) -> list:
    recs = []
    org = incident.get("customer", "")
    title = incident.get("incidentTitle", "").lower()

    # C2 / Malicious IP
    if any(t.get("id") == "T1071" for t in techniques) or "malicious" in title or "ioc" in title:
        recs.append("Deploy or update threat intel feeds on perimeter firewalls")
        recs.append("Implement DNS sinkholing for known C2 domains")
        recs.append("Review and harden endpoint protection (EDR) coverage")
        recs.append("Create FortiSIEM watchlist for IOCs discovered in this investigation")

    # ARP poisoning
    elif any("T1557" in t.get("id","") for t in techniques):
        recs.append("Deploy 802.1X network access control on all access ports")
        recs.append("Implement VLAN ACLs to restrict inter-VLAN ARP traffic")
        recs.append("Create FortiSIEM rule: alert when any MAC spans >3 VLANs")
        recs.append("Conduct physical security audit of switch port locations")

    if _is_banking_org(org):
        recs.append(f"Report incident to {org} CISO per RBI/CERT-In incident reporting guidelines")

    recs.append("Schedule penetration test focusing on the attack vector identified")
    recs.append("Review and update incident response playbook based on lessons learned")

    return recs


# --- Pipeline Runner ----------------------------------------------------------

def run_pipeline(incident_id: int, hours_back: int = 24, output_file: str = None) -> dict:
    """
    Run the full L1 -> L2 -> L3 investigation pipeline for a single incident.
    Returns the complete investigation data structure.
    """
    cfg = get_config()

    print(f"{'='*70}")
    print(f"FortiSIEM Investigation Pipeline")
    print(f"Incident: #{incident_id}")
    print(f"Started:  {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"{'='*70}")

    # Fetch incident data
    print("\n[1/5] Fetching incident detail...")
    incident = get_incident_detail(incident_id, cfg)
    if not incident:
        print(f"ERROR: Incident #{incident_id} not found")
        sys.exit(1)
    print(f"  Title: {incident.get('incidentTitle')}")
    print(f"  Severity: {incident.get('eventSeverityCat')} ({incident.get('eventSeverity')}/10)")
    print(f"  Org: {incident.get('customer')}")

    # Fetch triggering events
    print("\n[2/5] Fetching triggering events...")
    events = get_incident_events(incident_id, cfg)
    print(f"  Got {len(events)} triggering events")

    # Fetch all incidents for correlation
    print("\n[3/5] Running L1 triage...")
    l1_result = l1_triage(incident, events)
    print(f"  Disposition: {l1_result['disposition']}")
    print(f"  Confidence: {l1_result['confidence']}%")
    print(f"  TP Score: {l1_result['tp_score']} | FP Score: {l1_result['fp_score']}")
    print(f"  Priority: {l1_result['priority']}")
    print(f"  Signals: {len(l1_result['signals'])}")
    for s in l1_result["signals"]:
        print(f"    - [{s['type']}] {s['detail']} (weight: {s['weight']})")

    # L2 Investigation
    print("\n[4/5] Running L2 investigation...")
    all_incidents = list_incidents(hours_back=hours_back, cfg=cfg)
    print(f"  Total incidents in last {hours_back}h: {len(all_incidents)}")
    l2_result = l2_investigate(incident, events, all_incidents, cfg)
    print(f"  Correlated (same device): {l2_result['correlated_incidents']['total_same_device']}")
    print(f"  Correlated (same org): {l2_result['correlated_incidents']['total_same_org']}")
    print(f"  Timeline entries: {len(l2_result['timeline'])}")
    print(f"  Blast radius: {l2_result['blast_radius']['scope_level']}")
    print(f"  Unique IPs: {len(l2_result['blast_radius']['unique_source_ips'])}")
    print(f"  Unique rules: {len(l2_result['blast_radius']['unique_rules'])}")

    # L3 Threat Intel
    print("\n[5/6] Running L3 threat intel analysis...")
    l3_result = l3_threat_intel(incident, events, l2_result)
    print(f"  MITRE techniques: {l3_result['mitre_mapping']['total_techniques']}")
    print(f"  Tactics covered: {len(l3_result['mitre_mapping']['tactics_covered'])}")
    print(f"  Risk score: {l3_result['risk_score']['combined']}/10 ({l3_result['risk_score']['level']})")
    print(f"  IOCs: {len(l3_result['iocs'])}")
    print(f"  Attribution: {l3_result['attribution']['status']}")

    # AI Reasoning
    print("\n[6/6] Running AI reasoning engine...")

    # Collect all queried events for pattern analysis
    all_queried_events = []
    for eq in l2_result.get("event_queries", []):
        all_queried_events.extend(eq.get("sample_events", []))

    # If we see security product events (Seqrite, Trellix, Sophos), run a
    # dedicated query to get enough events for pattern detection
    security_product_types = ["Seqrite", "Trellix", "Sophos", "QuickHeal", "McAfee", "CrowdStrike"]
    detected_product = None
    for eq in l2_result.get("event_queries", []):
        for se in eq.get("sample_events", []):
            et = se.get("eventType", "")
            for prod in security_product_types:
                if prod.lower() in et.lower():
                    detected_product = prod
                    break
            if detected_product:
                break
        if detected_product:
            break

    security_events = []
    if detected_product:
        actor_ip = l2_result.get("actor", {}).get("source_ip", "") or incident.get("incidentRptIp", "")
        if actor_ip:
            print(f"  Detected {detected_product} events -- running dedicated query for pattern analysis...")
            try:
                sec_xml = build_query(
                    src_ips=[actor_ip],
                    event_types=[detected_product],
                    time_window="Last 24 hours",
                    limit=200
                )
                security_events = query_run(sec_xml, max_results=200, timeout=90, cfg=cfg)
                print(f"  Got {len(security_events)} {detected_product} events for pattern analysis")
            except Exception as e:
                print(f"  {detected_product} query failed: {e}")

    # Pattern detection -- use security product events if available, else all events
    pattern_events = security_events if security_events else (events + all_queried_events)
    pattern = detect_repeating_pattern(pattern_events)
    print(f"  Pattern: {'REPEATING' if pattern['is_repeating'] else 'One-time'} "
          f"({pattern.get('interval_label', 'N/A')}, confidence: {pattern['confidence']}%)")

    # Actor classification
    actor = l2_result.get("actor", {})
    actor_class = classify_actor(actor, events)
    print(f"  Actor: {actor_class['type']} (confidence: {actor_class['confidence']}%)")

    # Event chain analysis -- use security product events for better app detection
    chain_events = security_events if security_events else (events + all_queried_events)
    chain = analyze_event_chain(chain_events)
    print(f"  Event chain: {chain['chain_type']}")

    # Correlation reasoning
    corr_incidents = l2_result.get("correlated_incidents", {}).get("same_org", [])
    correlation = reason_about_correlation(incident, corr_incidents)
    print(f"  Correlation: {correlation['relationship']} -- {correlation['narrative'][:80]}")

    # Final verdict
    verdict = generate_verdict(incident, actor_class, pattern, chain,
                               l2_result.get("correlated_incidents", {}))
    print(f"  VERDICT: {verdict['disposition']} (confidence: {verdict['confidence']}%)")
    print(f"  Risk: {verdict['risk_level']}")
    print(f"  Summary: {verdict['summary'][:100]}")

    ai_reasoning = {
        "pattern_analysis": pattern,
        "actor_classification": actor_class,
        "event_chain": chain,
        "correlation_reasoning": correlation,
        "verdict": verdict,
    }

    # Assemble final report data
    report_data = {
        "metadata": {
            "incident_id": incident_id,
            "generated_at": datetime.now().isoformat(),
            "pipeline_version": "3.0.0",
            "tiers_executed": ["L1", "L2", "L3", "AI_REASONING"],
        },
        "incident": {
            "id": incident.get("incidentId"),
            "title": incident.get("incidentTitle", ""),
            "rule": incident.get("eventName", ""),
            "severity": incident.get("eventSeverityCat", ""),
            "severity_score": incident.get("eventSeverity", 0),
            "status": STATUS_LABELS.get(incident.get("incidentStatus", -1), "Unknown"),
            "organization": incident.get("customer", ""),
            "reporting_ip": incident.get("incidentRptIp", ""),
            "reporting_device": incident.get("incidentRptDevName", ""),
            "first_seen": _ts_to_str(incident.get("incidentFirstSeen", 0)),
            "last_seen": _ts_to_str(incident.get("incidentLastSeen", 0)),
            "event_count": incident.get("count", 0),
            "mitre_technique": incident.get("attackTechnique", ""),
            "mitre_tactic": incident.get("attackTactic", ""),
            "tag": incident.get("incidentTagName", ""),
            "category": incident.get("phIncidentCategory", ""),
        },
        "triggering_events": {
            "count": len(events),
            "samples": events[:10],
        },
        "l1_triage": l1_result,
        "l2_investigation": l2_result,
        "l3_threat_intel": l3_result,
        "ai_reasoning": ai_reasoning,
    }

    # Save to file
    if output_file:
        with open(output_file, "w") as f:
            json.dump(report_data, f, indent=2, default=str)
        print(f"\nInvestigation data saved to: {output_file}")

    print(f"\n{'='*70}")
    print(f"Pipeline complete.")
    print(f"  L1 Disposition : {l1_result['disposition']} ({l1_result['confidence']}%)")
    print(f"  L3 Risk Score  : {l3_result['risk_score']['combined']}/10")
    print(f"  AI Verdict     : {verdict['disposition']} ({verdict['confidence']}%) -- {verdict['risk_level']}")
    print(f"{'='*70}")

    return report_data


# --- Main --------------------------------------------------------------------

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="FortiSIEM Investigation Pipeline")
    parser.add_argument("--incident", type=int, required=True, help="Incident ID to investigate")
    parser.add_argument("--hours", type=int, default=24, help="Hours back for correlation (default: 24)")
    parser.add_argument("--output", default=None, help="Output JSON file path")
    args = parser.parse_args()

    check_env()

    if not args.output:
        args.output = f"investigation_{args.incident}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"

    run_pipeline(args.incident, args.hours, args.output)
    print(f"\nNext step: python3 report_pdf.py --input {args.output} --output report.pdf")
