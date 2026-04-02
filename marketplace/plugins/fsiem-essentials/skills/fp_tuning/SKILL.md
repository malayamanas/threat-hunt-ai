---
name: fsiem-fp-tuning
description: False positive fine-tuning for FortiSIEM correlation rules. Identifies the noisiest rules, diagnoses why they're firing (wrong threshold, missing exclusion, bad filter), modifies the rule XML to add exclusions or raise thresholds, redeploys, and tracks FP rate before/after. Use when a rule fires too often on benign activity, when asked to tune a noisy rule, or after L1 flags recurring FPs in shift handover.
---

# False Positive Fine-Tuning

The #1 analyst time-sink in any SIEM. This skill identifies noisy rules, diagnoses root cause, and applies the right fix — not just disabling the rule.

## Three root causes of FPs (and the right fix for each)

| Root Cause | Wrong Fix | Right Fix |
|---|---|---|
| Threshold too low | Disable rule | Raise event count threshold |
| Missing exclusion (scanner, backup job, known admin) | Disable rule | Add `NOT_CONTAIN` filter for known-good source |
| Wrong event type scope | Disable rule | Narrow filter to specific `eventType` values |
| Time window too broad | Disable rule | Shorten correlation window |

## Step 1 — Find the Noisiest Rules

```python
import os, base64, requests, xml.etree.ElementTree as ET, time
from collections import defaultdict
from datetime import datetime, timedelta

def fsiem_headers():
    user, org, pw = os.environ["FSIEM_USER"], os.environ["FSIEM_ORG"], os.environ["FSIEM_PASS"]
    return {"Authorization": f"Basic {base64.b64encode(f'{user}/{org}:{pw}'.encode()).decode()}",
            "Content-Type": "text/xml"}

def fsiem_verify_ssl():
    return os.environ.get("FSIEM_VERIFY_SSL", "false").lower() == "true"

def get_noisy_rules(days_back: int = 7, top_n: int = 20) -> list:
    """
    Find rules generating the most False Positive incidents.
    Returns rules ranked by FP count descending.
    """
    host = os.environ["FSIEM_HOST"]
    now = int(datetime.now().timestamp() * 1000)
    start = int((datetime.now() - timedelta(days=days_back)).timestamp() * 1000)

    rule_stats = defaultdict(lambda: {"fp": 0, "tp": 0, "total": 0,
                                       "rule_name": "", "titles": []})

    for status in ["False Positive", "Cleared", "Active", "InProgress"]:
        resp = requests.get(
            f"{host}/phoenix/rest/incident/listIncidents",
            params={"startTime": start, "endTime": now, "maxResults": 500, "status": status},
            headers=fsiem_headers(), verify=fsiem_verify_ssl()
        )
        if resp.status_code != 200:
            continue
        root = ET.fromstring(resp.text)
        for inc in root.findall(".//incident"):
            rule = inc.findtext("ruleId") or inc.findtext("ruleName") or "unknown"
            rule_name = inc.findtext("incidentTitle") or rule
            rule_stats[rule]["total"] += 1
            rule_stats[rule]["rule_name"] = rule_name
            if status == "False Positive":
                rule_stats[rule]["fp"] += 1
            elif status in ("Cleared", "InProgress"):
                rule_stats[rule]["tp"] += 1
            title = inc.findtext("incidentTitle") or ""
            if title and title not in rule_stats[rule]["titles"]:
                rule_stats[rule]["titles"].append(title)

    # Compute FP rate and rank
    results = []
    for rule_id, stats in rule_stats.items():
        if stats["total"] < 3:
            continue
        fp_rate = round(stats["fp"] / stats["total"] * 100, 1) if stats["total"] else 0
        results.append({
            "rule_id":   rule_id,
            "rule_name": stats["rule_name"],
            "fp_count":  stats["fp"],
            "tp_count":  stats["tp"],
            "total":     stats["total"],
            "fp_rate":   fp_rate,
            "priority":  "HIGH" if fp_rate >= 80 else
                         "MEDIUM" if fp_rate >= 50 else "LOW",
        })

    return sorted(results, key=lambda x: x["fp_count"], reverse=True)[:top_n]
```

## Step 2 — Diagnose a Noisy Rule

```python
def diagnose_rule_fps(rule_id: str, days_back: int = 7) -> dict:
    """
    Deep-dive a specific rule to understand WHY it's generating FPs.
    Returns: most common source IPs, users, event types, and times triggering the rule.
    These tell you exactly what exclusion to add.
    """
    host = os.environ["FSIEM_HOST"]
    h = fsiem_headers()
    v = fsiem_verify_ssl()
    now = int(datetime.now().timestamp() * 1000)
    start = int((datetime.now() - timedelta(days=days_back)).timestamp() * 1000)

    # Get FP incidents for this rule
    resp = requests.get(
        f"{host}/phoenix/rest/incident/listIncidents",
        params={"startTime": start, "endTime": now, "maxResults": 200,
                "status": "False Positive", "ruleId": rule_id},
        headers=h, verify=v
    )
    if resp.status_code != 200:
        return {"error": f"HTTP {resp.status_code}"}

    root = ET.fromstring(resp.text)
    incidents = root.findall(".//incident")

    # Aggregate FP patterns
    src_ips   = defaultdict(int)
    users     = defaultdict(int)
    hostnames = defaultdict(int)
    hours     = defaultdict(int)

    for inc in incidents:
        for ip in inc.findall(".//srcIpAddr"):
            if ip.text: src_ips[ip.text] += 1
        for u in inc.findall(".//user"):
            if u.text: users[u.text] += 1
        for h2 in inc.findall(".//hostName"):
            if h2.text: hostnames[h2.text] += 1
        t = inc.findtext("lastEventTime","")
        if t:
            try:
                hour = datetime.fromtimestamp(int(t)/1000).hour
                hours[hour] += 1
            except Exception:
                pass

    # Determine fix recommendation
    top_ips = sorted(src_ips.items(), key=lambda x: -x[1])[:5]
    top_users = sorted(users.items(), key=lambda x: -x[1])[:5]
    total_fps = len(incidents)

    # If top 3 IPs account for >70% of FPs → exclusion fix
    top3_count = sum(c for _, c in top_ips[:3])
    exclusion_fix = total_fps > 0 and (top3_count / total_fps) > 0.7

    # If FPs cluster in specific hours → scheduled job, time-based fix
    peak_hours = sorted(hours.items(), key=lambda x: -x[1])[:3]
    time_pattern = sum(c for _, c in peak_hours[:2]) > total_fps * 0.6 if total_fps > 0 else False

    recommendation = (
        "ADD_IP_EXCLUSION"    if exclusion_fix and top_ips else
        "ADD_USER_EXCLUSION"  if top_users and not exclusion_fix else
        "RAISE_THRESHOLD"     if time_pattern else
        "NARROW_EVENT_FILTER"
    )

    return {
        "rule_id":        rule_id,
        "fp_count":       total_fps,
        "top_src_ips":    top_ips,
        "top_users":      top_users,
        "top_hostnames":  sorted(hostnames.items(), key=lambda x: -x[1])[:5],
        "peak_hours":     peak_hours,
        "recommendation": recommendation,
        "exclusion_fix":  exclusion_fix,
        "time_pattern":   time_pattern,
    }
```

## Step 3 — Apply the Fix

```python
def get_rule_xml(rule_id: str) -> str:
    """Fetch the current XML for a rule by ID."""
    host = os.environ["FSIEM_HOST"]
    resp = requests.get(
        f"{host}/phoenix/rest/rules/{rule_id}",
        headers=fsiem_headers(), verify=fsiem_verify_ssl()
    )
    resp.raise_for_status()
    return resp.text

def apply_ip_exclusion(rule_xml: str, exclude_ips: list, comment: str = "") -> str:
    """
    Add source IP exclusions to a rule's SubPattern filter.
    exclude_ips: list of IPs or CIDR ranges to exclude, e.g. ['10.0.1.5', '192.168.1.0/24']
    Returns modified rule XML.
    """
    ip_list = ",".join(exclude_ips)
    note = f"<!-- FP exclusion added {datetime.now().strftime('%Y-%m-%d')}"
    if comment:
        note += f": {comment}"
    note += " -->"
    exclusion_filter = f"""{note}
            <Filter>
              <n>srcIpAddr</n>
              <Operator>NOT_IN</Operator>
              <Value>{ip_list}</Value>
            </Filter>"""

    # Insert after the first <Filters> opening tag
    return rule_xml.replace("<Filters>", f"<Filters>{exclusion_filter}", 1)

def apply_user_exclusion(rule_xml: str, exclude_users: list, comment: str = "") -> str:
    """Add user exclusions (service accounts, known admins) to a rule."""
    user_list = "|".join(exclude_users)  # FortiSIEM uses pipe-separated for REGEXP
    note = f"<!-- FP exclusion added {datetime.now().strftime('%Y-%m-%d')}"
    if comment:
        note += f": {comment}"
    note += " -->"
    exclusion_filter = f"""{note}
            <Filter>
              <n>user</n>
              <Operator>NOT_REGEXP</Operator>
              <Value>{user_list}</Value>
            </Filter>"""
    return rule_xml.replace("<Filters>", f"<Filters>{exclusion_filter}", 1)

def raise_threshold(rule_xml: str, new_threshold: int) -> str:
    """
    Raise the event count threshold in a correlation rule.
    Use when the rule fires correctly but the threshold is too sensitive.
    """
    root = ET.fromstring(rule_xml)
    # FortiSIEM threshold is in <countThreshold> or <threshold> or <triggerCount>
    for tag in ("countThreshold", "threshold", "triggerCount"):
        for elem in root.iter(tag):
            old = elem.text
            elem.text = str(new_threshold)
            print(f"  Raised threshold {tag}: {old} → {new_threshold}")
    return ET.tostring(root, encoding="unicode")

def deploy_tuned_rule(rule_id: str, tuned_xml: str) -> dict:
    """Deploy the modified rule back to FortiSIEM."""
    host = os.environ["FSIEM_HOST"]
    resp = requests.put(
        f"{host}/phoenix/rest/rules/{rule_id}",
        data=tuned_xml, headers=fsiem_headers(), verify=fsiem_verify_ssl()
    )
    return {
        "rule_id":  rule_id,
        "success":  resp.status_code in (200, 201),
        "status":   resp.status_code,
        "response": resp.text[:200],
    }
```

## Step 4 — Full Tuning Workflow (end-to-end)

```python
def tune_rule_auto(
    rule_id: str,
    days_back: int = 7,
    dry_run: bool = True,
) -> dict:
    """
    Full automated tuning workflow for a single rule:
    1. Diagnose FP patterns
    2. Determine best fix
    3. Fetch current rule XML
    4. Apply fix
    5. Deploy (or show preview if dry_run=True)

    dry_run=True (default): shows what WOULD change, doesn't deploy.
    dry_run=False: deploys the change.
    """
    print(f"[1/4] Diagnosing FPs for rule {rule_id}...")
    diagnosis = diagnose_rule_fps(rule_id, days_back=days_back)

    print(f"[2/4] Fetching rule XML...")
    original_xml = get_rule_xml(rule_id)

    print(f"[3/4] Applying fix: {diagnosis['recommendation']}...")
    rec = diagnosis["recommendation"]

    if rec == "ADD_IP_EXCLUSION":
        ips_to_exclude = [ip for ip, _ in diagnosis["top_src_ips"][:3]]
        comment = "Auto-excluded: top FP source IPs"
        tuned_xml = apply_ip_exclusion(original_xml, ips_to_exclude, comment)
        change_desc = f"Added exclusion for IPs: {ips_to_exclude}"

    elif rec == "ADD_USER_EXCLUSION":
        users_to_exclude = [u for u, _ in diagnosis["top_users"][:3]]
        comment = "Auto-excluded: top FP users (service accounts)"
        tuned_xml = apply_user_exclusion(original_xml, users_to_exclude, comment)
        change_desc = f"Added exclusion for users: {users_to_exclude}"

    elif rec == "RAISE_THRESHOLD":
        # Find current threshold and double it
        root = ET.fromstring(original_xml)
        current = 5
        for tag in ("countThreshold", "threshold", "triggerCount"):
            for elem in root.iter(tag):
                try: current = int(elem.text or "5")
                except ValueError: pass
        new_threshold = current * 2
        tuned_xml = raise_threshold(original_xml, new_threshold)
        change_desc = f"Raised threshold from {current} to {new_threshold}"

    else:
        tuned_xml = original_xml
        change_desc = "Manual review needed — no automatic fix applicable"

    result = {
        "rule_id":      rule_id,
        "fp_count":     diagnosis["fp_count"],
        "recommendation": rec,
        "change_desc":  change_desc,
        "dry_run":      dry_run,
        "diagnosis":    diagnosis,
    }

    if not dry_run and change_desc != "Manual review needed — no automatic fix applicable":
        print(f"[4/4] Deploying tuned rule...")
        deploy_result = deploy_tuned_rule(rule_id, tuned_xml)
        result["deployed"] = deploy_result["success"]
        result["deploy_status"] = deploy_result["status"]
        print(f"  {'✓ Deployed' if deploy_result['success'] else '✗ Deploy failed'}")
    else:
        print(f"[4/4] Dry run — not deploying. Change would be: {change_desc}")
        result["deployed"] = False

    return result

def tune_all_noisy_rules(
    fp_rate_threshold: float = 60.0,
    days_back: int = 7,
    dry_run: bool = True,
) -> list:
    """
    Find all rules above FP rate threshold and tune them.
    Always defaults to dry_run=True — review before deploying.
    """
    noisy = get_noisy_rules(days_back=days_back)
    targets = [r for r in noisy if r["fp_rate"] >= fp_rate_threshold]

    print(f"Found {len(targets)} rules with FP rate >= {fp_rate_threshold}%")
    results = []
    for rule in targets:
        print(f"\nTuning: {rule['rule_name']} ({rule['fp_rate']}% FP rate, {rule['fp_count']} FPs)")
        result = tune_rule_auto(rule["rule_id"], days_back=days_back, dry_run=dry_run)
        results.append(result)

    return results
```

## FP Tuning Report

```python
def fp_tuning_report(days_back: int = 30) -> str:
    """Generate a FP tuning report showing before/after metrics."""
    noisy = get_noisy_rules(days_back=days_back, top_n=10)
    lines = [
        f"# False Positive Tuning Report",
        f"**Period**: Last {days_back} days | **Generated**: {datetime.now().strftime('%Y-%m-%d %H:%M')}",
        "",
        "## Top Noisy Rules",
        "",
        "| Rule | FPs | Total | FP Rate | Priority | Recommended Fix |",
        "|---|---|---|---|---|---|",
    ]

    fix_map = {
        "HIGH":   "Tune immediately — causing alert fatigue",
        "MEDIUM": "Schedule for next maintenance window",
        "LOW":    "Monitor — acceptable noise level",
    }

    for r in noisy:
        diagnosis = diagnose_rule_fps(r["rule_id"], days_back=days_back)
        rec = diagnosis.get("recommendation", "REVIEW")
        lines.append(
            f"| {r['rule_name'][:40]} | {r['fp_count']} | {r['total']} | "
            f"{r['fp_rate']}% | {r['priority']} | {rec} |"
        )

    total_fps = sum(r["fp_count"] for r in noisy)
    total_incidents = sum(r["total"] for r in noisy)
    overall_fp_rate = round(total_fps / total_incidents * 100, 1) if total_incidents else 0

    lines += [
        "",
        "## Summary",
        f"- Total incidents analyzed: {total_incidents}",
        f"- Total false positives: {total_fps}",
        f"- Overall FP rate (top 10 rules): {overall_fp_rate}%",
        f"- Target FP rate: <20%",
        f"- {'✅ Within target' if overall_fp_rate < 20 else '🔴 Above target — tuning required'}",
    ]
    return "\n".join(lines)
```
