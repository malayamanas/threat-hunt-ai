---
name: fsiem-auto-triage
description: Autonomous alert triage engine for FortiSIEM. Combines asset criticality scoring (derived from CMDB device type + naming patterns), per-rule historical false positive rates (from 30-day incident history), and enrichment verdicts to make autonomous triage decisions — closing confirmed FPs and escalating confirmed TPs without analyst involvement. Only acts autonomously when ALL confidence conditions are met; everything else routes to assisted triage. Use when asked to triage alerts automatically, run autonomous triage, or process the alert queue without analyst input.
---

# Autonomous Triage Engine

## Design Philosophy

**The system only acts autonomously when the evidence is overwhelming.** Three independent signals must all agree before any action fires without a human. One uncertain signal = human queue, not auto-action.

```
Signal 1: Asset criticality    (from CMDB device type + hostname patterns)
Signal 2: Rule FP rate         (from 30-day incident history)
Signal 3: Enrichment verdict   (from VT/AbuseIPDB on source IPs)

AUTO-CLOSE only if:
  Rule FP rate ≥ 95%  AND  asset criticality = LOW  AND  no enrichment hit

AUTO-ESCALATE only if:
  Enrichment = MALICIOUS  AND  asset criticality = HIGH/CRITICAL
  OR  keyword score ≥ 8  AND  asset criticality = CRITICAL

EVERYTHING ELSE → assisted triage queue (human decides)
```

## Step 1 — Asset Criticality Engine

```python
import os, re, base64, requests, xml.etree.ElementTree as ET, time, sys
from datetime import datetime, timedelta
from collections import defaultdict

def fsiem_headers():
    user, org, pw = os.environ["FSIEM_USER"], os.environ["FSIEM_ORG"], os.environ["FSIEM_PASS"]
    return {"Authorization": f"Basic {base64.b64encode(f'{user}/{org}:{pw}'.encode()).decode()}",
            "Content-Type": "text/xml"}

def fsiem_verify_ssl():
    return os.environ.get("FSIEM_VERIFY_SSL", "false").lower() == "true"

# ── CRITICALITY RULES ─────────────────────────────────────────────────────────
# FortiSIEM CMDB has no criticality field — we derive it from device type + hostname.
# Override per-device via env var: FSIEM_CRITICAL_IPS="10.0.0.1,10.0.0.2"
#                                  FSIEM_LOW_IPS="192.168.99.0/24"

# Device types that are always CRITICAL
CRITICAL_DEVICE_TYPES = {
    "Firewall", "IDS", "IPS", "VPN", "Router", "Switch",
    "Domain Controller", "Active Directory", "DNS Server",
    "Database Server", "Payment System", "PKI", "CA Server",
}

# Device types that are always HIGH
HIGH_DEVICE_TYPES = {
    "Server", "Web Server", "Application Server", "Mail Server",
    "File Server", "Backup Server", "Hypervisor", "ESXi",
}

# Hostname patterns that indicate CRITICAL (regex)
CRITICAL_HOSTNAME_PATTERNS = [
    r"dc\d*[-_]",          # dc01, dc-prod
    r"[-_]dc\d*",          # prod-dc1
    r"fw[-_]",             # fw-core
    r"[-_]fw\d*",          # core-fw1
    r"pci[-_]",            # pci-zone
    r"pay[-_]",            # payment
    r"prod[-_]",           # prod servers
    r"[-_]prod\d*$",
    r"core[-_]",           # core infrastructure
]

# Hostname patterns that indicate LOW (dev, test, lab)
LOW_HOSTNAME_PATTERNS = [
    r"dev[-_]", r"[-_]dev\d*$",
    r"test[-_]", r"[-_]test\d*$",
    r"lab[-_]", r"[-_]lab\d*$",
    r"sandbox", r"staging",
    r"demo[-_]", r"poc[-_]",
    r"honeypot", r"honey[-_]",
]

def get_asset_criticality(ip: str, cmdb_cache: dict = None) -> dict:
    """
    Derive asset criticality from CMDB data.
    Returns: {level: CRITICAL|HIGH|MEDIUM|LOW, reason: str, device: dict}

    Criticality levels:
      CRITICAL — production firewall, DC, payment, IDS/IPS, core infra
      HIGH     — production server, web server, mail, backup
      MEDIUM   — workstation, printer, general device
      LOW      — dev/test/sandbox/lab, honeypot, unknown

    Uses env var overrides for manual pinning:
      FSIEM_CRITICAL_IPS=10.0.0.1,10.0.0.5
      FSIEM_LOW_IPS=192.168.99.0/24,10.99.0.0/16
    """
    # Check env var overrides first
    critical_ips = os.environ.get("FSIEM_CRITICAL_IPS", "").split(",")
    low_ips = os.environ.get("FSIEM_LOW_IPS", "").split(",")
    if ip in critical_ips:
        return {"level": "CRITICAL", "reason": "Manually pinned as CRITICAL (FSIEM_CRITICAL_IPS)", "device": {}}
    if ip in low_ips:
        return {"level": "LOW", "reason": "Manually pinned as LOW (FSIEM_LOW_IPS)", "device": {}}

    # Get from CMDB (use cache to avoid repeated API calls in bulk triage)
    device = {}
    if cmdb_cache and ip in cmdb_cache:
        device = cmdb_cache[ip]
    else:
        try:
            host = os.environ["FSIEM_HOST"]
            resp = requests.get(
                f"{host}/phoenix/rest/cmdbDeviceInfo/device",
                params={"ip": ip},
                headers=fsiem_headers(), verify=fsiem_verify_ssl(), timeout=10
            )
            if resp.status_code == 200:
                root = ET.fromstring(resp.text)
                dev = root.find(".//device")
                if dev is not None:
                    device = {tag.tag: tag.text for tag in dev}
                    if cmdb_cache is not None:
                        cmdb_cache[ip] = device
        except Exception:
            pass

    if not device:
        return {"level": "MEDIUM", "reason": "Not in CMDB — treating as MEDIUM", "device": {}}

    device_type = device.get("deviceType") or device.get("type") or ""
    hostname = (device.get("hostName") or device.get("name") or "").lower()

    # Check device type
    if device_type in CRITICAL_DEVICE_TYPES:
        return {"level": "CRITICAL", "reason": f"Device type: {device_type}", "device": device}
    if device_type in HIGH_DEVICE_TYPES:
        level = "HIGH"
        reason = f"Device type: {device_type}"
    else:
        level = "MEDIUM"
        reason = f"Device type: {device_type or 'unknown'}"

    # Hostname patterns can upgrade or downgrade
    for pattern in CRITICAL_HOSTNAME_PATTERNS:
        if re.search(pattern, hostname, re.IGNORECASE):
            return {"level": "CRITICAL", "reason": f"Hostname pattern '{pattern}' matches {hostname}", "device": device}

    for pattern in LOW_HOSTNAME_PATTERNS:
        if re.search(pattern, hostname, re.IGNORECASE):
            return {"level": "LOW", "reason": f"Hostname pattern '{pattern}' matches {hostname} (dev/test/lab)", "device": device}

    return {"level": level, "reason": reason, "device": device}
```

## Step 2 — Rule History Engine

```python
# In-memory cache: populated once per triage session from 30-day incident history
_rule_history_cache = {}
_rule_history_loaded = False

def load_rule_history(days_back: int = 30) -> dict:
    """
    Load 30-day FP/TP history for ALL rules in one API sweep.
    Cache result for the session — don't query per-incident.

    Returns: {rule_id: {fp_rate, fp_count, total, confidence}}
    confidence = HIGH if total >= 20, MEDIUM if >= 5, LOW if < 5
    """
    global _rule_history_cache, _rule_history_loaded
    if _rule_history_loaded:
        return _rule_history_cache

    host = os.environ["FSIEM_HOST"]
    now = int(datetime.now().timestamp() * 1000)
    start = int((datetime.now() - timedelta(days=days_back)).timestamp() * 1000)

    rule_stats = defaultdict(lambda: {"fp": 0, "tp": 0, "total": 0})

    for status in ["False Positive", "Cleared", "Active", "InProgress"]:
        try:
            resp = requests.get(
                f"{host}/phoenix/rest/incident/listIncidents",
                params={"startTime": start, "endTime": now,
                        "maxResults": 1000, "status": status},
                headers=fsiem_headers(), verify=fsiem_verify_ssl(), timeout=30
            )
            if resp.status_code != 200:
                continue
            root = ET.fromstring(resp.text)
            for inc in root.findall(".//incident"):
                rule = inc.findtext("ruleId") or inc.findtext("ruleName") or "unknown"
                rule_stats[rule]["total"] += 1
                if status == "False Positive":
                    rule_stats[rule]["fp"] += 1
                elif status in ("Cleared", "InProgress"):
                    rule_stats[rule]["tp"] += 1
        except Exception:
            continue

    cache = {}
    for rule_id, stats in rule_stats.items():
        total = stats["total"]
        fp_rate = round(stats["fp"] / total * 100, 1) if total > 0 else 0
        cache[rule_id] = {
            "fp_rate":    fp_rate,
            "fp_count":   stats["fp"],
            "tp_count":   stats["tp"],
            "total":      total,
            "confidence": "HIGH"   if total >= 20 else
                          "MEDIUM" if total >= 5  else "LOW",
        }

    _rule_history_cache = cache
    _rule_history_loaded = True
    return cache
```

## Step 3 — Autonomous Decision Engine

```python
# ── THRESHOLDS ────────────────────────────────────────────────────────────────
AUTO_CLOSE_RULES = {
    "fp_rate_min":      95.0,   # Rule must be ≥95% FP over 30 days
    "history_confidence": "HIGH",  # Must have ≥20 historical incidents
    "max_asset_level":  "LOW",  # Only auto-close LOW criticality assets
    "no_enrichment_hit": True,  # Source IP must NOT be flagged by VT/AbuseIPDB
}

AUTO_ESCALATE_RULES = {
    "malicious_enrichment_min_asset": "HIGH",   # MALICIOUS IP + HIGH/CRITICAL asset
    "keyword_score_min":              8,         # keyword score ≥8 + CRITICAL asset
    "keyword_score_critical_only":    True,
}

def make_triage_decision(
    incident: dict,
    rule_history: dict,
    asset_criticality: dict,
    enrichment: dict = None,
) -> dict:
    """
    The core autonomous decision function.
    Returns a decision dict with action and full reasoning chain.

    Actions:
      AUTO_CLOSE    — write False Positive to FortiSIEM, no human needed
      AUTO_ESCALATE — write InProgress + L2 note, no human needed
      ASSISTED      — put in human queue with pre-scored context
    """
    rule_id    = incident.get("rule") or incident.get("ruleId") or "unknown"
    asset_lvl  = asset_criticality.get("level", "MEDIUM")
    asset_rsn  = asset_criticality.get("reason", "")
    rule_stats = rule_history.get(rule_id, {})
    fp_rate    = rule_stats.get("fp_rate", 0)
    history_conf = rule_stats.get("confidence", "LOW")
    tp_score   = incident.get("tp_score", 0)
    enrichment_verdict = (enrichment or {}).get("verdict", "UNKNOWN")
    reasoning  = []

    # ── AUTO-CLOSE PATH ───────────────────────────────────────────────────────
    can_auto_close = (
        fp_rate    >= AUTO_CLOSE_RULES["fp_rate_min"]
        and history_conf == AUTO_CLOSE_RULES["history_confidence"]
        and asset_lvl   == AUTO_CLOSE_RULES["max_asset_level"]
        and enrichment_verdict not in ("MALICIOUS", "SUSPICIOUS")
    )
    if can_auto_close:
        reasoning = [
            f"Rule FP rate: {fp_rate}% (≥95% threshold) over {rule_stats['total']} incidents — HIGH confidence",
            f"Asset criticality: {asset_lvl} ({asset_rsn})",
            f"Enrichment: {enrichment_verdict} — no threat intel hit",
            "All 3 AUTO-CLOSE conditions met",
        ]
        return {
            "action":     "AUTO_CLOSE",
            "disposition": "FALSE_POSITIVE",
            "confidence": "HIGH",
            "autonomous": True,
            "reasoning":  reasoning,
            "note":       (f"[AUTO-TRIAGE] Closed: rule {rule_id} has {fp_rate}% FP rate "
                           f"({rule_stats['total']} historical incidents). "
                           f"Asset: {asset_lvl}. Enrichment: {enrichment_verdict}."),
        }

    # ── AUTO-ESCALATE PATH ────────────────────────────────────────────────────
    malicious_high_asset = (
        enrichment_verdict == "MALICIOUS"
        and asset_lvl in ("HIGH", "CRITICAL")
    )
    high_score_critical = (
        tp_score >= AUTO_ESCALATE_RULES["keyword_score_min"]
        and asset_lvl == "CRITICAL"
    )
    if malicious_high_asset or high_score_critical:
        if malicious_high_asset:
            reasoning = [
                f"Enrichment verdict: MALICIOUS on source IP",
                f"Asset criticality: {asset_lvl} ({asset_rsn})",
                "MALICIOUS indicator + HIGH/CRITICAL asset = AUTO-ESCALATE",
            ]
        else:
            reasoning = [
                f"TP keyword score: {tp_score}/10 (≥8 threshold)",
                f"Asset criticality: CRITICAL ({asset_rsn})",
                "High keyword score on CRITICAL asset = AUTO-ESCALATE",
            ]
        return {
            "action":      "AUTO_ESCALATE",
            "disposition": "TRUE_POSITIVE",
            "confidence":  "HIGH",
            "autonomous":  True,
            "reasoning":   reasoning,
            "note":        (f"[AUTO-TRIAGE] Escalated to L2: "
                            + (f"MALICIOUS IP on {asset_lvl} asset. " if malicious_high_asset else "")
                            + (f"TP score {tp_score}/10 on CRITICAL asset. " if high_score_critical else "")
                            + f"Rule: {rule_id}"),
        }

    # ── ASSISTED TRIAGE PATH (human queue) ───────────────────────────────────
    # Build explanation of WHY it's going to human
    blockers = []
    if fp_rate >= 95 and history_conf != "HIGH":
        blockers.append(f"Rule FP rate is {fp_rate}% but only {rule_stats.get('total',0)} historical incidents — need ≥20 for auto-close")
    if fp_rate >= 95 and asset_lvl != "LOW":
        blockers.append(f"Rule FP rate {fp_rate}% but asset criticality is {asset_lvl} — only auto-close LOW assets")
    if enrichment_verdict in ("MALICIOUS","SUSPICIOUS") and asset_lvl not in ("HIGH","CRITICAL"):
        blockers.append(f"MALICIOUS/SUSPICIOUS enrichment but asset is {asset_lvl} — manual review needed")
    if not blockers:
        blockers.append("Insufficient signal for autonomous action — requires analyst judgment")

    # Pre-score the recommendation for the analyst
    if fp_rate >= 80 and asset_lvl == "LOW":
        recommendation = "LIKELY_FP"
    elif tp_score >= 5 or enrichment_verdict == "MALICIOUS":
        recommendation = "LIKELY_TP"
    elif fp_rate >= 50:
        recommendation = "LIKELY_FP"
    else:
        recommendation = "INVESTIGATE"

    return {
        "action":         "ASSISTED",
        "disposition":    None,
        "confidence":     "MEDIUM" if recommendation in ("LIKELY_FP","LIKELY_TP") else "LOW",
        "autonomous":     False,
        "recommendation": recommendation,
        "reasoning":      blockers,
        "context": {
            "fp_rate":     fp_rate,
            "fp_history":  f"{rule_stats.get('total',0)} incidents over 30 days",
            "asset":       f"{asset_lvl} — {asset_rsn}",
            "enrichment":  enrichment_verdict,
            "tp_score":    tp_score,
        }
    }
```

## Step 4–5 — Full Triage Run & Report

Full implementation of `run_autonomous_triage()` and `auto_triage_report()`:
see [reference.md](reference.md).

```python
# Quick start
results = run_autonomous_triage(hours_back=8, dry_run=True)
print(auto_triage_report(results))

# Go live after reviewing dry run
results = run_autonomous_triage(hours_back=8, dry_run=False)
```
