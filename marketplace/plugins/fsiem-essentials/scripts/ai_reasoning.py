#!/usr/bin/env python3
"""
FortiSIEM AI Reasoning Engine
Automated analysis logic that would normally require AI/analyst judgment.
Called by investigation_pipeline.py to enrich findings with contextual reasoning.

This module replaces ad-hoc AI prompting with deterministic reasoning functions
that detect patterns, classify behavior, and generate verdicts.
"""

import re
from collections import Counter, defaultdict
from datetime import datetime, timedelta
from typing import List, Dict, Optional, Tuple


# =============================================================================
# TIMESTAMP PARSING — Handle all FortiSIEM event timestamp formats
# =============================================================================

def _parse_event_timestamp(event: dict, raw: str = "", attrs: dict = None) -> Optional[datetime]:
    """
    Parse timestamp from a FortiSIEM event. Handles all known formats:
    - incident_date=2026-03-28 09:40:40  (Seqrite LEEF)
    - phRecvTime: Sat Mar 28 15:30:07 IST 2026  (query results)
    - receiveTime: 2026-03-28T15:30:07+05:30  (ISO from query results)
    - receiveTime: 1774694077000  (epoch ms from /pub/incident)
    - Event Receive Time: 1774694077000  (epoch ms in attributes)
    """
    if not raw:
        raw = event.get("rawMessage", event.get("rawEventMsg", ""))
    if attrs is None:
        attrs = event.get("attributes", {})

    ts = None

    # 1. Seqrite/LEEF incident_date (most specific for Seqrite events)
    m = re.search(r'incident_date=(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})', raw)
    if m:
        try:
            ts = datetime.strptime(m.group(1), "%Y-%m-%d %H:%M:%S")
            return ts
        except ValueError:
            pass

    # 2. phRecvTime: "Sat Mar 28 15:30:07 IST 2026"
    recv_time = event.get("phRecvTime", "")
    if recv_time and not str(recv_time).isdigit():
        # Remove timezone abbreviation (IST, UTC, etc.) and parse
        cleaned = re.sub(r'\s+[A-Z]{2,4}\s+', ' ', recv_time)
        for fmt in ["%a %b %d %H:%M:%S %Y", "%Y-%m-%d %H:%M:%S"]:
            try:
                ts = datetime.strptime(cleaned.strip(), fmt)
                return ts
            except ValueError:
                continue

    # 3. receiveTime: "2026-03-28T15:30:07+05:30" (ISO)
    recv = event.get("receiveTime", "")
    if recv and not str(recv).isdigit():
        # Strip timezone offset for simple parsing
        iso_clean = re.sub(r'[+-]\d{2}:\d{2}$', '', str(recv))
        try:
            ts = datetime.fromisoformat(iso_clean)
            return ts
        except (ValueError, TypeError):
            pass

    # 4. receiveTime as epoch ms
    if recv and str(recv).isdigit():
        try:
            ts = datetime.fromtimestamp(int(recv) / 1000)
            return ts
        except (ValueError, OSError):
            pass

    # 5. Event Receive Time in attributes (epoch ms)
    if isinstance(attrs, dict):
        attr_recv = attrs.get("Event Receive Time")
        if attr_recv and str(attr_recv).isdigit():
            try:
                ts = datetime.fromtimestamp(int(attr_recv) / 1000)
                return ts
            except (ValueError, OSError):
                pass

    # 6. Syslog timestamp in raw: "Mar 28 16:01:31"
    m = re.search(r'(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})', raw[:50])
    if m:
        try:
            ts = datetime.strptime(f"2026 {m.group(1)}", "%Y %b %d %H:%M:%S")
            return ts
        except ValueError:
            pass

    return None


# =============================================================================
# 1. PATTERN DETECTION — Is this a scheduled task or a one-time attack?
# =============================================================================

def detect_repeating_pattern(events: list, time_field: str = "incident_date") -> dict:
    """
    Analyze events for repeating time patterns.
    Returns pattern info: is_repeating, interval_minutes, confidence, evidence.
    """
    result = {
        "is_repeating": False,
        "interval_minutes": 0,
        "interval_label": "",
        "batch_count": 0,
        "confidence": 0,
        "evidence": "",
        "runs_overnight": False,
        "continues_after_incident": False,
    }

    if len(events) < 4:
        result["evidence"] = f"Only {len(events)} events -- too few to detect pattern"
        return result

    # Extract timestamps from events using all known formats
    timestamps = []
    for e in events:
        raw = e.get("rawMessage", e.get("rawEventMsg", ""))
        attrs = e.get("attributes", {})

        ts = _parse_event_timestamp(e, raw, attrs)
        if ts:
            timestamps.append(ts)

    if len(timestamps) < 4:
        result["evidence"] = "Could not parse enough timestamps"
        return result

    timestamps.sort()

    # Group into batches (events within 5 minutes of each other = one batch)
    batches = []
    current_batch = [timestamps[0]]
    for i in range(1, len(timestamps)):
        if (timestamps[i] - current_batch[-1]).total_seconds() < 300:
            current_batch.append(timestamps[i])
        else:
            batches.append(current_batch[0])  # Use first timestamp of batch
            current_batch = [timestamps[i]]
    batches.append(current_batch[0])

    result["batch_count"] = len(batches)

    if len(batches) < 3:
        result["evidence"] = f"Only {len(batches)} batches -- need at least 3 for pattern"
        return result

    # Calculate intervals between batches
    intervals = []
    for i in range(1, len(batches)):
        diff = (batches[i] - batches[i - 1]).total_seconds() / 60
        intervals.append(round(diff))

    if not intervals:
        return result

    # Check if intervals are consistent (CV < 0.3 = regular pattern)
    avg_interval = sum(intervals) / len(intervals)
    if avg_interval == 0:
        return result

    variance = sum((x - avg_interval) ** 2 for x in intervals) / len(intervals)
    std_dev = variance ** 0.5
    cv = std_dev / avg_interval if avg_interval > 0 else 999

    # Use median for robustness against outlier intervals
    sorted_intervals = sorted(intervals)
    median_interval = sorted_intervals[len(sorted_intervals) // 2]

    # Also compute CV after removing outliers (intervals > 3x median)
    filtered = [i for i in intervals if i <= median_interval * 3]
    if filtered:
        f_avg = sum(filtered) / len(filtered)
        f_var = sum((x - f_avg) ** 2 for x in filtered) / len(filtered)
        f_cv = (f_var ** 0.5) / f_avg if f_avg > 0 else 999
        outlier_count = len(intervals) - len(filtered)
    else:
        f_avg, f_cv, outlier_count = avg_interval, cv, 0

    result["interval_minutes"] = round(median_interval)

    if median_interval < 5:
        result["interval_label"] = f"Every ~{round(median_interval)} minutes"
    elif median_interval < 120:
        result["interval_label"] = f"Every ~{round(median_interval)} minutes"
    elif median_interval < 1500:
        result["interval_label"] = f"Every ~{round(median_interval/60, 1)} hours"
    else:
        result["interval_label"] = f"Every ~{round(median_interval/1440, 1)} days"

    # Pattern detection -- use filtered CV for outlier-resistant detection
    effective_cv = min(cv, f_cv)  # Use the better (lower) CV

    if effective_cv < 0.3 and len(batches) >= 4:
        result["is_repeating"] = True
        result["confidence"] = min(95, 70 + len(batches) * 2)
        result["evidence"] = (
            f"Regular pattern: {len(batches)} batches at {result['interval_label']} "
            f"(CV={effective_cv:.2f}, {outlier_count} outliers removed)"
        )
    elif effective_cv < 0.5 and len(batches) >= 5:
        result["is_repeating"] = True
        result["confidence"] = min(80, 50 + len(batches) * 2)
        result["evidence"] = (
            f"Semi-regular pattern: {len(batches)} batches at {result['interval_label']} "
            f"with some variation (CV={effective_cv:.2f})"
        )
    elif len(batches) >= 8 and effective_cv < 0.7:
        # Many batches with moderate regularity = still likely scheduled
        result["is_repeating"] = True
        result["confidence"] = min(70, 40 + len(batches) * 2)
        result["evidence"] = (
            f"Likely scheduled: {len(batches)} batches at ~{result['interval_label']} "
            f"(CV={effective_cv:.2f}, {outlier_count} off-cycle batches)"
        )
    else:
        result["evidence"] = (
            f"No clear pattern: {len(batches)} batches, intervals vary (CV={effective_cv:.2f})"
        )

    # Check if runs overnight (between 00:00 and 06:00)
    overnight_batches = [b for b in batches if 0 <= b.hour < 6]
    result["runs_overnight"] = len(overnight_batches) >= 2

    return result


# =============================================================================
# 2. ACTOR CLASSIFICATION — Service vs human, local vs remote
# =============================================================================

def classify_actor(actor: dict, events: list) -> dict:
    """
    Determine if the actor is a human, automated service, or suspicious.
    Returns classification with reasoning.
    """
    classification = {
        "type": "UNKNOWN",       # HUMAN, SERVICE, SCHEDULED_TASK, SUSPICIOUS
        "confidence": 0,
        "reasoning": [],
        "risk_modifiers": [],    # Factors that increase/decrease risk
    }

    username = (actor.get("username") or "").lower()
    logon_id = actor.get("logon_id", "")
    source_ip = actor.get("source_ip", "")
    hostname = actor.get("hostname", "")
    domain = actor.get("domain", "")
    event_id = actor.get("event_id", "")

    signals_human = 0
    signals_service = 0

    # Check logon source
    if source_ip == "127.0.0.1" or source_ip == "::1":
        signals_service += 3
        classification["reasoning"].append("Source IP is localhost (127.0.0.1) -- local service logon")
    elif source_ip == "-" or not source_ip:
        signals_service += 1
        classification["reasoning"].append("No source IP recorded -- likely service")
    elif source_ip.startswith(("10.", "172.", "192.168.")):
        signals_human += 2
        classification["reasoning"].append(f"Source IP is internal ({source_ip}) -- could be remote admin")

    # Check if domain matches hostname (local account)
    if domain and hostname and domain.upper() == hostname.upper():
        signals_service += 1
        classification["reasoning"].append("Domain matches hostname -- local account, not domain account")

    # Check username patterns
    service_accounts = ["system", "local service", "network service", "nt authority",
                        "svchost", "machineaccount$", "health", "monitor"]
    if any(sa in username for sa in service_accounts) or username.endswith("$"):
        signals_service += 3
        classification["reasoning"].append(f"Username '{username}' matches service account pattern")
    elif username in ("admin", "administrator", "root"):
        # Could be either -- need more context
        signals_human += 1
        signals_service += 1
        classification["reasoning"].append(f"Username '{username}' is generic -- could be human or service")
    else:
        signals_human += 2
        classification["reasoning"].append(f"Username '{username}' appears to be a personal account")

    # Check raw events for process info
    for e in events[:10]:
        raw = e.get("rawMessage", "")
        # If svchost.exe initiated the logon
        if "svchost.exe" in raw.lower():
            signals_service += 3
            classification["reasoning"].append("Logon initiated by svchost.exe (Windows service host)")
            break
        # If wevtutil or PowerShell cleared logs
        if any(tool in raw.lower() for tool in ["wevtutil", "powershell", "clear-eventlog"]):
            signals_human += 3
            classification["reasoning"].append("Log clear via wevtutil/PowerShell -- human-initiated tool")
            break

    # Determine type
    total = signals_human + signals_service
    if total == 0:
        classification["type"] = "UNKNOWN"
        classification["confidence"] = 20
    elif signals_service > signals_human * 2:
        classification["type"] = "SERVICE"
        classification["confidence"] = min(90, 50 + signals_service * 10)
    elif signals_human > signals_service * 2:
        classification["type"] = "HUMAN"
        classification["confidence"] = min(90, 50 + signals_human * 10)
    else:
        classification["type"] = "AMBIGUOUS"
        classification["confidence"] = 40
        classification["reasoning"].append("Mixed signals -- cannot definitively determine human vs service")

    # Risk modifiers
    if username in ("admin", "administrator", "root"):
        classification["risk_modifiers"].append("Privileged account -- higher impact if compromised")
    if event_id == "1102":
        classification["risk_modifiers"].append("Audit log clearing -- compliance concern regardless of cause")

    return classification


# =============================================================================
# 3. EVENT CHAIN ANALYSIS — Attack chain or benign workflow?
# =============================================================================

def analyze_event_chain(events: list, incident_time_ms: int = 0) -> dict:
    """
    Analyze a sequence of events and classify as attack chain or benign workflow.
    Groups by application/process and identifies suspicious sequences.
    """
    analysis = {
        "chain_type": "UNKNOWN",  # ATTACK_CHAIN, BENIGN_WORKFLOW, MIXED, UNKNOWN
        "applications": [],
        "suspicious_sequences": [],
        "benign_indicators": [],
        "event_summary": {},
        "reasoning": "",
    }

    # Extract applications and event types
    apps = Counter()
    event_types = Counter()
    app_timeline = defaultdict(list)

    for e in events:
        raw = e.get("rawMessage", e.get("rawEventMsg", ""))
        et = e.get("eventType", "")
        event_types[et] += 1

        # Extract application names
        app_match = re.search(r'application_name=([^|]+)', raw)
        if app_match:
            app = app_match.group(1).strip()
            apps[app] += 1

        # Extract application paths
        path_match = re.search(r'application_path=([^|]+)', raw)
        if path_match:
            path = path_match.group(1).strip()
            app_timeline[path].append(e)

    analysis["applications"] = [{"name": a, "count": c} for a, c in apps.most_common()]
    analysis["event_summary"] = dict(event_types.most_common(10))

    # Detect suspicious sequences
    SUSPICIOUS_APPS = {
        "mimikatz": "Credential dumping tool",
        "psexec": "Remote execution tool (lateral movement)",
        "wevtutil": "Event log manipulation",
        "certutil": "Certificate tool often abused for downloads",
        "bitsadmin": "Background transfer often abused for downloads",
        "mshta": "Script execution via HTML applications",
        "regsvr32": "DLL registration often abused for execution",
        "cscript": "Script execution engine",
        "wscript": "Script execution engine",
    }

    BENIGN_APPS = {
        "rundll32": "DLL loader -- common in Windows service operations",
        "sc": "Service controller -- used by endpoint security products",
        "svchost": "Windows service host",
        "msiexec": "Windows installer",
        "taskhostw": "Task scheduler host",
    }

    for app, count in apps.items():
        app_lower = app.lower()
        if app_lower in SUSPICIOUS_APPS:
            analysis["suspicious_sequences"].append({
                "application": app,
                "count": count,
                "concern": SUSPICIOUS_APPS[app_lower],
            })
        elif app_lower in BENIGN_APPS:
            analysis["benign_indicators"].append({
                "application": app,
                "count": count,
                "explanation": BENIGN_APPS[app_lower],
            })

    # Determine chain type
    if analysis["suspicious_sequences"]:
        if analysis["benign_indicators"]:
            analysis["chain_type"] = "MIXED"
            analysis["reasoning"] = (
                f"Found {len(analysis['suspicious_sequences'])} suspicious and "
                f"{len(analysis['benign_indicators'])} benign applications. "
                "Requires human judgment."
            )
        else:
            analysis["chain_type"] = "ATTACK_CHAIN"
            analysis["reasoning"] = (
                f"Found {len(analysis['suspicious_sequences'])} suspicious applications "
                f"with no benign context."
            )
    elif analysis["benign_indicators"]:
        analysis["chain_type"] = "BENIGN_WORKFLOW"
        analysis["reasoning"] = (
            f"All detected applications ({', '.join(a['application'] for a in analysis['benign_indicators'])}) "
            f"are standard Windows/security tool processes. Consistent with endpoint security maintenance."
        )
    else:
        analysis["chain_type"] = "UNKNOWN"
        analysis["reasoning"] = "No recognized applications found in events."

    return analysis


# =============================================================================
# 4. VERDICT ENGINE — Combine all analysis into a final verdict
# =============================================================================

# Known security product process patterns
SECURITY_PRODUCTS = {
    "seqrite": {
        "processes": ["sc.exe", "rundll32.exe", "svchost.exe"],
        "pattern": "sc.exe + rundll32.exe in recurring batches",
        "explanation": "Seqrite EPS service health check cycle",
    },
    "trellix": {
        "processes": ["mfemactl.exe", "masvc.exe", "mctray.exe"],
        "pattern": "periodic service restarts",
        "explanation": "Trellix/McAfee endpoint agent maintenance",
    },
    "sophos": {
        "processes": ["savservice.exe", "sophosui.exe"],
        "pattern": "scheduled scan and update",
        "explanation": "Sophos endpoint protection cycle",
    },
    "quickheal": {
        "processes": ["scanmain.exe", "bdagent.exe"],
        "pattern": "scheduled scan",
        "explanation": "QuickHeal/Seqrite scan cycle",
    },
}


def generate_verdict(
    incident: dict,
    actor_classification: dict,
    pattern_analysis: dict,
    event_chain: dict,
    correlated_incidents: dict,
) -> dict:
    """
    Generate a final verdict combining all reasoning engines.
    Returns verdict with confidence, reasoning, and recommended actions.
    """
    verdict = {
        "disposition": "NEEDS_REVIEW",  # TRUE_POSITIVE, FALSE_POSITIVE, BENIGN, NEEDS_REVIEW
        "confidence": 0,
        "summary": "",
        "reasoning": [],
        "risk_level": "MEDIUM",
        "recommended_actions": [],
        "compliance_notes": [],
        "what_would_make_it_malicious": [],
    }

    title = incident.get("incidentTitle", incident.get("title", "")).lower()
    org = incident.get("customer", incident.get("organization", ""))

    fp_score = 0
    tp_score = 0

    # Factor 1: Repeating pattern
    if pattern_analysis.get("is_repeating"):
        fp_score += 30
        verdict["reasoning"].append(
            f"BENIGN SIGNAL: Repeating pattern detected -- {pattern_analysis['batch_count']} batches "
            f"at {pattern_analysis['interval_label']} (confidence: {pattern_analysis['confidence']}%)"
        )
        if pattern_analysis.get("runs_overnight"):
            fp_score += 15
            verdict["reasoning"].append(
                "BENIGN SIGNAL: Pattern runs overnight (01:00-05:00) -- automated, not human"
            )
    else:
        tp_score += 10
        verdict["reasoning"].append(
            "SUSPICIOUS: No repeating pattern -- this appears to be a one-time event"
        )

    # Factor 2: Actor classification
    actor_type = actor_classification.get("type", "UNKNOWN")
    if actor_type == "SERVICE":
        fp_score += 25
        verdict["reasoning"].append(
            f"BENIGN SIGNAL: Actor classified as SERVICE (confidence: {actor_classification['confidence']}%) "
            f"-- {'; '.join(actor_classification['reasoning'][:2])}"
        )
    elif actor_type == "HUMAN":
        tp_score += 20
        verdict["reasoning"].append(
            f"SUSPICIOUS: Actor classified as HUMAN (confidence: {actor_classification['confidence']}%) "
            f"-- {'; '.join(actor_classification['reasoning'][:2])}"
        )

    # Factor 3: Event chain
    chain_type = event_chain.get("chain_type", "UNKNOWN")
    if chain_type == "BENIGN_WORKFLOW":
        fp_score += 20
        verdict["reasoning"].append(
            f"BENIGN SIGNAL: Event chain is a benign workflow -- {event_chain['reasoning']}"
        )
    elif chain_type == "ATTACK_CHAIN":
        tp_score += 30
        verdict["reasoning"].append(
            f"SUSPICIOUS: Event chain looks like an attack -- {event_chain['reasoning']}"
        )

    # Factor 4: Continues after incident
    if pattern_analysis.get("continues_after_incident"):
        fp_score += 10
        verdict["reasoning"].append(
            "BENIGN SIGNAL: Activity continues normally after the incident -- attacker would stop"
        )

    # Factor 5: Known security product pattern
    for product, info in SECURITY_PRODUCTS.items():
        apps_in_chain = [a["name"].lower() for a in event_chain.get("applications", [])]
        matching = [p.replace(".exe", "") for p in info["processes"]
                    if p.replace(".exe", "") in apps_in_chain]
        if len(matching) >= 2:
            fp_score += 20
            verdict["reasoning"].append(
                f"BENIGN SIGNAL: Matches known {product.title()} maintenance pattern "
                f"({', '.join(matching)}). {info['explanation']}"
            )
            break

    # Determine disposition
    total = fp_score + tp_score
    if total == 0:
        verdict["disposition"] = "NEEDS_REVIEW"
        verdict["confidence"] = 20
    elif fp_score > tp_score * 2:
        verdict["disposition"] = "LIKELY_BENIGN"
        verdict["confidence"] = min(95, fp_score)
        verdict["risk_level"] = "LOW"
    elif tp_score > fp_score * 2:
        verdict["disposition"] = "TRUE_POSITIVE"
        verdict["confidence"] = min(95, tp_score)
        verdict["risk_level"] = "HIGH"
    elif fp_score > tp_score:
        verdict["disposition"] = "LIKELY_BENIGN"
        verdict["confidence"] = min(70, fp_score)
        verdict["risk_level"] = "LOW"
    else:
        verdict["disposition"] = "NEEDS_REVIEW"
        verdict["confidence"] = 40
        verdict["risk_level"] = "MEDIUM"

    # Generate summary
    if verdict["disposition"] == "LIKELY_BENIGN":
        verdict["summary"] = (
            f"Analysis indicates this is likely a benign event caused by automated security software "
            f"maintenance, not a malicious attack. {pattern_analysis.get('evidence', '')}"
        )
    elif verdict["disposition"] == "TRUE_POSITIVE":
        verdict["summary"] = (
            f"Analysis indicates this is likely a genuine security incident. "
            f"Actor appears to be human-initiated, no repeating pattern detected, "
            f"and suspicious tools/processes were observed."
        )
    else:
        verdict["summary"] = (
            f"Analysis is inconclusive. Some signals point to benign activity, "
            f"others are suspicious. Manual review recommended."
        )

    # Compliance notes for banking orgs
    from investigation_pipeline import _is_banking_org
    if _is_banking_org(org):
        verdict["compliance_notes"].append(
            f"{org} is a banking institution. Regardless of verdict, "
            f"audit log clearing must be documented per RBI IT Framework."
        )
        if "log" in title and ("clear" in title or "1102" in title):
            verdict["compliance_notes"].append(
                "Security event log clearing at a bank is a compliance violation. "
                "Ensure logs are forwarded to SIEM before any local clearing occurs."
            )

    # What would make this malicious
    verdict["what_would_make_it_malicious"] = [
        "One-time event (not part of a repeating scheduled pattern)",
        "Initiated by wevtutil.exe, PowerShell, or cmd.exe (not svchost.exe)",
        "Remote source IP (not 127.0.0.1 / localhost)",
        "Failed login attempts or brute force before the log clear",
        "Lateral movement or data staging after the log clear",
        "Pattern does NOT continue after the incident (attacker stops)",
        "Suspicious tools (mimikatz, psexec, certutil) in the same session",
    ]

    # Recommended actions based on verdict
    if verdict["disposition"] in ("LIKELY_BENIGN", "FALSE_POSITIVE"):
        verdict["recommended_actions"] = [
            "Verify with IT that the security product (Seqrite/AV) is configured for scheduled maintenance",
            "If AV IS clearing Security logs -- reconfigure to preserve audit logs",
            "Add FortiSIEM rule exclusion for service-initiated log clears to reduce FP noise",
            "Ensure Windows Security logs are forwarded to SIEM before local clearing",
            "Document this finding for the next compliance audit",
        ]
    elif verdict["disposition"] == "TRUE_POSITIVE":
        verdict["recommended_actions"] = [
            "Isolate the affected host immediately",
            "Capture memory dump and disk image before remediation",
            "Identify what the actor did BEFORE clearing logs (look for evidence gaps)",
            "Check for persistence mechanisms on the host",
            "Reset credentials for the actor account",
            "Escalate to L3 for full forensic investigation",
        ]
    else:
        verdict["recommended_actions"] = [
            "Query for additional context: what happened in the hour before this event",
            "Check if this event has occurred before on this host (weekly/monthly)",
            "Verify the actor account is expected to be on this host",
            "Review with the org IT team whether this is planned maintenance",
        ]

    return verdict


# =============================================================================
# 5. CORRELATION REASONING — What story do related incidents tell?
# =============================================================================

def reason_about_correlation(primary_incident: dict, correlated: list) -> dict:
    """
    Analyze correlated incidents and determine the narrative relationship.
    Are they part of the same attack chain, or unrelated noise?
    """
    result = {
        "narrative": "",
        "relationship": "UNRELATED",  # ATTACK_CHAIN, SAME_ISSUE, UNRELATED, UNCLEAR
        "related_incidents": [],
        "unrelated_incidents": [],
    }

    if not correlated:
        result["narrative"] = "No correlated incidents found."
        return result

    primary_title = (primary_incident.get("incidentTitle") or primary_incident.get("title", "")).lower()
    primary_rule = (primary_incident.get("eventName") or primary_incident.get("rule", "")).lower()
    primary_ip = primary_incident.get("incidentRptIp") or primary_incident.get("source_ip", "")

    attack_chain_signals = 0
    for ci in correlated:
        ci_title = (ci.get("title") or ci.get("incidentTitle", "")).lower()
        ci_ip = ci.get("source_ip") or ci.get("incidentRptIp", "")
        ci_rule = ci.get("rule") or ci.get("eventName", "")

        relationship = "UNRELATED"
        reason = ""

        # Same IP = likely related
        if ci_ip == primary_ip:
            relationship = "SAME_SOURCE"
            reason = f"Same source IP ({ci_ip})"
            attack_chain_signals += 1

        # Check for attack chain keywords
        attack_pairs = [
            (["brute force", "failed logon", "login fail"], ["clear", "1102", "log"]),
            (["malware", "virus", "trojan"], ["exfil", "c2", "beacon"]),
            (["scan", "discovery", "recon"], ["lateral", "remote", "psexec"]),
            (["credential", "mimikatz", "lsass"], ["lateral", "remote", "rdp"]),
        ]
        for precursors, followers in attack_pairs:
            if any(p in primary_title for p in precursors) and any(f in ci_title for f in followers):
                relationship = "ATTACK_CHAIN"
                reason = "Attack chain: precursor -> follow-up pattern"
                attack_chain_signals += 2
            elif any(p in ci_title for p in precursors) and any(f in primary_title for f in followers):
                relationship = "ATTACK_CHAIN"
                reason = "Attack chain: this incident is the precursor"
                attack_chain_signals += 2

        # Same rule = same issue type
        if ci_rule.lower() == primary_rule:
            relationship = "SAME_ISSUE"
            reason = "Same correlation rule fired"

        entry = {
            "id": ci.get("id") or ci.get("incidentId"),
            "title": ci.get("title") or ci.get("incidentTitle", ""),
            "relationship": relationship,
            "reason": reason,
        }

        if relationship in ("ATTACK_CHAIN", "SAME_SOURCE", "SAME_ISSUE"):
            result["related_incidents"].append(entry)
        else:
            result["unrelated_incidents"].append(entry)

    # Generate narrative
    related_count = len(result["related_incidents"])
    unrelated_count = len(result["unrelated_incidents"])

    if attack_chain_signals >= 3:
        result["relationship"] = "ATTACK_CHAIN"
        result["narrative"] = (
            f"ALERT: {related_count} correlated incidents form a potential attack chain. "
            f"The incidents share source IPs or show precursor-followup patterns."
        )
    elif related_count > 0 and unrelated_count > related_count:
        result["relationship"] = "MIXED"
        result["narrative"] = (
            f"{related_count} incidents appear related (same source or rule), "
            f"{unrelated_count} are unrelated noise from the same org."
        )
    elif unrelated_count > 0 and related_count == 0:
        result["relationship"] = "UNRELATED"
        result["narrative"] = (
            f"The {unrelated_count} correlated incidents are from the same org but unrelated -- "
            f"different rules, different IPs, different activity types."
        )
    else:
        result["narrative"] = f"{related_count} related, {unrelated_count} unrelated incidents found."

    return result
