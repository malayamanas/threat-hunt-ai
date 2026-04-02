---
name: fsiem-l1-triage
description: L1 SOC analyst triage workflow — process the alert queue, classify incidents as True Positive / False Positive / Benign, enrich with basic context, assign severity, escalate to L2 or close. Designed for first-responder speed: each incident triage target under 5 minutes.
---

# L1 SOC Triage — First Responder Workflow

L1 goal: **clear the queue fast and accurately**. Every alert gets one of four dispositions within 5 minutes:
- `TRUE_POSITIVE` → escalate to L2 with notes
- `FALSE_POSITIVE` → close with reason, flag rule for tuning
- `BENIGN` → close with explanation (authorized activity)
- `NEEDS_MORE_INFO` → assign to self, set 2h follow-up

## Step 1 — Load the Queue

```python
import os, base64, requests, xml.etree.ElementTree as ET
from datetime import datetime, timedelta

def fsiem_headers():
    user, org, pw = os.environ["FSIEM_USER"], os.environ["FSIEM_ORG"], os.environ["FSIEM_PASS"]
    token = base64.b64encode(f"{user}/{org}:{pw}".encode()).decode()
    return {"Authorization": f"Basic {token}", "Content-Type": "text/xml"}

def fsiem_verify_ssl():
    return os.environ.get("FSIEM_VERIFY_SSL","false").lower() == "true"

def load_triage_queue(hours_back: int = 8, max_results: int = 200) -> list:
    """
    Load all open incidents sorted by priority:
    1. CRITICAL (unacknowledged)
    2. HIGH (unacknowledged)
    3. HIGH (acknowledged but not closed)
    4. MEDIUM
    Returns incidents with basic enrichment pre-loaded.
    """
    host = os.environ["FSIEM_HOST"]
    now = int(datetime.now().timestamp() * 1000)
    start = int((datetime.now() - timedelta(hours=hours_back)).timestamp() * 1000)

    all_incidents = []
    for severity in ["CRITICAL", "HIGH", "MEDIUM"]:
        resp = requests.get(
            f"{host}/phoenix/rest/incident/listIncidents",
            params={"startTime": start, "endTime": now, "maxResults": max_results,
                    "eventSeverity": severity, "status": "Active"},
            headers=fsiem_headers(), verify=fsiem_verify_ssl()
        )
        resp.raise_for_status()
        root = ET.fromstring(resp.text)
        for inc in root.findall(".//incident"):
            all_incidents.append({
                "id":          inc.findtext("incidentId"),
                "title":       inc.findtext("incidentTitle") or "",
                "severity":    inc.findtext("eventSeverity") or severity,
                "status":      inc.findtext("incidentStatus") or "Active",
                "count":       int(inc.findtext("eventCount") or "0"),
                "category":    inc.findtext("incidentCategory") or "",
                "rule":        inc.findtext("ruleId") or "",
                "first_seen":  inc.findtext("firstEventTime") or "",
                "last_seen":   inc.findtext("lastEventTime") or "",
                "src_ips":     [ip.text for ip in inc.findall(".//srcIpAddr") if ip.text],
                "dest_ips":    [ip.text for ip in inc.findall(".//destIpAddr") if ip.text],
                "users":       [u.text for u in inc.findall(".//user") if u.text],
                # Triage fields (filled by analyst)
                "disposition": None,
                "triage_note": "",
                "triage_time": None,
            })

    # Sort: CRITICAL first, then by event count descending
    priority = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    return sorted(all_incidents, key=lambda x: (priority.get(x["severity"], 9), -x["count"]))
```

## Step 2 — L1 Quick Checks (per incident, under 2 min each)

```python
def l1_quick_check(incident: dict) -> dict:
    """
    Run L1 triage checks on a single incident.
    Returns enriched incident with triage_signals populated.
    """
    signals = []
    fp_signals = []

    title = incident["title"].lower()
    category = incident["category"].lower()
    src_ips = incident["src_ips"]
    count = incident["count"]

    # --- TRUE POSITIVE signals ---
    if any(kw in title for kw in ["ransomware", "shadow copy", "lsass", "mimikatz",
                                   "c2 beacon", "exfiltration", "impossible travel"]):
        signals.append(("CRITICAL_KEYWORD", "Title contains high-confidence attack keyword", 10))

    if incident["severity"] == "CRITICAL":
        signals.append(("CRITICAL_SEVERITY", "CRITICAL severity — immediate action", 8))

    if count > 1000:
        signals.append(("HIGH_VOLUME", f"{count} events — sustained/automated attack", 5))

    if len(set(src_ips)) > 5:
        signals.append(("DISTRIBUTED_SRC", f"{len(set(src_ips))} source IPs — possible campaign", 4))

    # --- FALSE POSITIVE signals ---
    if any(kw in title for kw in ["scan", "vulnerability", "nessus", "qualys", "rapid7"]):
        fp_signals.append(("KNOWN_SCANNER", "Title suggests authorized vulnerability scan"))

    if count > 10000 and "login" in title:
        fp_signals.append(("MASS_AUTH_EVENT", "Very high login count — check if batch job or migration"))

    if not src_ips:
        fp_signals.append(("NO_SOURCE_IP", "No source IP — may be internal system event"))

    # Compute triage recommendation
    tp_score = sum(s[2] for s in signals)
    has_fp_signals = len(fp_signals) > 0

    if tp_score >= 8 or (tp_score >= 5 and not has_fp_signals):
        recommendation = "ESCALATE_L2"
        confidence = "HIGH"
    elif has_fp_signals and tp_score < 3:
        recommendation = "LIKELY_FP"
        confidence = "MEDIUM"
    elif tp_score > 0:
        recommendation = "INVESTIGATE"
        confidence = "MEDIUM"
    else:
        recommendation = "REVIEW"
        confidence = "LOW"

    incident["triage_signals"] = signals
    incident["fp_signals"] = fp_signals
    incident["tp_score"] = tp_score
    incident["recommendation"] = recommendation
    incident["confidence"] = confidence
    return incident
```

## Step 3 — L1 Disposition Decision Tree

```
ALERT RECEIVED
│
├─ Is severity CRITICAL?
│   └─ YES → Run quick check → If any TP signal → ESCALATE L2 immediately (< 2 min)
│
├─ Does title contain known-bad keywords? (ransomware, lsass, mimikatz, C2, shadow copy)
│   └─ YES → TRUE_POSITIVE → ESCALATE L2 with notes
│
├─ Is source IP a known scanner / monitoring tool? (Nessus, Qualys, internal security scanner)
│   └─ YES → FALSE_POSITIVE → Close with "Authorized scan from {ip}"
│
├─ Has this exact pattern fired > 3 times this week with no confirmed TP?
│   └─ YES → Likely noisy rule → FALSE_POSITIVE → Flag rule for L3 tuning
│
├─ Is the affected asset non-critical? (printer, guest WiFi, decommissioned server)
│   └─ YES → BENIGN → Close with asset context
│
├─ Is there a change record / maintenance window covering this activity?
│   └─ YES → BENIGN → Close with change ticket reference
│
└─ None of the above → NEEDS_MORE_INFO → Assign to self, query 10 triggering events
```

## Step 4 — Triage and Disposition

```python
def triage_incident(
    incident_id: str,
    disposition: str,  # TRUE_POSITIVE, FALSE_POSITIVE, BENIGN, NEEDS_MORE_INFO
    note: str,
    analyst: str = "L1 Analyst",
    escalate_to: str = None,  # L2 analyst name for TRUE_POSITIVE
) -> dict:
    """
    Record L1 triage decision and update FortiSIEM incident status.
    """
    host = os.environ["FSIEM_HOST"]
    status_map = {
        "TRUE_POSITIVE":   "InProgress",
        "FALSE_POSITIVE":  "False Positive",
        "BENIGN":          "Cleared",
        "NEEDS_MORE_INFO": "InProgress",
    }
    comment = f"[L1 Triage - {analyst}] {disposition}: {note}"
    if escalate_to:
        comment += f" | Escalated to L2: {escalate_to}"

    xml_body = f"""<incidentStatusChange>
      <incidentId>{incident_id}</incidentId>
      <incidentStatus>{status_map[disposition]}</incidentStatus>
      <comment>{comment}</comment>
    </incidentStatusChange>"""

    resp = requests.post(
        f"{host}/phoenix/rest/incident/updateIncidentStatus",
        data=xml_body, headers=fsiem_headers(), verify=fsiem_verify_ssl()
    )
    return {
        "incident_id": incident_id,
        "disposition": disposition,
        "status_set": status_map[disposition],
        "note": comment,
        "success": resp.status_code == 200,
        "triage_time": datetime.now().isoformat(),
    }
```

## Step 5 — L1 Shift Handover Report

```python
def l1_shift_report(triaged: list, analyst: str, shift_hours: int = 8) -> str:
    """Generate end-of-shift L1 report for handover to next analyst."""
    tp  = [i for i in triaged if i.get("disposition") == "TRUE_POSITIVE"]
    fp  = [i for i in triaged if i.get("disposition") == "FALSE_POSITIVE"]
    ben = [i for i in triaged if i.get("disposition") == "BENIGN"]
    nmi = [i for i in triaged if i.get("disposition") == "NEEDS_MORE_INFO"]
    total = len(triaged)

    lines = [
        f"# L1 Shift Handover Report",
        f"**Analyst**: {analyst} | **Shift**: {shift_hours}h | **Date**: {datetime.now().strftime('%Y-%m-%d %H:%M')}",
        "",
        "## Queue Statistics",
        f"| Metric | Count |",
        f"|---|---|",
        f"| Total alerts triaged | {total} |",
        f"| True Positives (escalated to L2) | {len(tp)} |",
        f"| False Positives (closed) | {len(fp)} |",
        f"| Benign (closed) | {len(ben)} |",
        f"| Needs More Info (pending) | {len(nmi)} |",
        f"| FP Rate | {round(len(fp)/total*100, 1) if total else 0}% |",
        "",
    ]

    if tp:
        lines += ["## ⚠️ Escalated to L2 — Requires Follow-up", ""]
        for i in tp:
            lines.append(f"- **#{i['id']}** [{i['severity']}] {i['title']} — {i.get('triage_note','')}")

    if nmi:
        lines += ["", "## 🔍 Needs More Info — In Progress", ""]
        for i in nmi:
            lines.append(f"- **#{i['id']}** {i['title']} — {i.get('triage_note','')}")

    if fp:
        lines += ["", "## 🔧 Rules to Flag for Tuning (recurring FP)", ""]
        rule_fps = {}
        for i in fp:
            rule = i.get("rule", "unknown")
            rule_fps[rule] = rule_fps.get(rule, 0) + 1
        for rule, count in sorted(rule_fps.items(), key=lambda x: -x[1]):
            if count >= 2:
                lines.append(f"- Rule `{rule}`: {count} FPs this shift → request L3 tuning")

    lines += ["", "## Handover Notes", "_[Add any open items or context for next analyst here]_"]
    return "\n".join(lines)
```

## L1 SLA Targets

| Alert Severity | Acknowledge | Initial Triage | Escalate/Close |
|---|---|---|---|
| CRITICAL | 5 minutes | 15 minutes | 30 minutes |
| HIGH | 15 minutes | 30 minutes | 2 hours |
| MEDIUM | 1 hour | 4 hours | 8 hours |
| LOW | 4 hours | 24 hours | 72 hours |

## L1 → L2 Escalation Checklist

Before handing off to L2, always include:
- [ ] Incident ID and FortiSIEM link
- [ ] Your disposition and confidence (e.g. "HIGH confidence TRUE_POSITIVE")
- [ ] Source IP(s) and affected asset(s)
- [ ] What triggered the rule (1-2 sentence summary)
- [ ] What you already checked (to avoid duplicate work)
- [ ] Any timeline context (first seen, frequency, pattern)
