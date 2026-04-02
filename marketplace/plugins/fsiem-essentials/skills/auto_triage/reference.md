---
name: fsiem-auto-triage-reference
description: Full implementation of run_autonomous_triage() and auto_triage_report(). See SKILL.md for the decision engine and design philosophy.
---

# Auto-Triage — Full Implementation Reference

Full `run_autonomous_triage()` and `auto_triage_report()` implementations.
See [SKILL.md](SKILL.md) for the decision engine and threshold reference.

## Step 4 — Full Autonomous Triage Run

```python
def run_autonomous_triage(
    hours_back:   int   = 8,
    dry_run:      bool  = True,
    enrichment_fn = None,   # pass enrich_ip from skills/enrichment/ if available
) -> dict:
    """
    Process the full alert queue autonomously.
    dry_run=True (default): decide + log, don't write to FortiSIEM.
    dry_run=False: write autonomous decisions to FortiSIEM immediately.

    Returns summary with auto_closed, auto_escalated, assisted counts + full log.
    """
    host = os.environ["FSIEM_HOST"]
    h = fsiem_headers()
    v = fsiem_verify_ssl()
    started = datetime.now()

    print(f"[AUTO-TRIAGE] Starting {'DRY RUN' if dry_run else 'LIVE'} triage — last {hours_back}h")

    # Load rule history once
    print("[1/4] Loading 30-day rule history...")
    rule_history = load_rule_history(days_back=30)
    print(f"      {len(rule_history)} rules in history")

    # Load alert queue
    print("[2/4] Loading alert queue...")
    now_ms = int(datetime.now().timestamp() * 1000)
    start_ms = int((datetime.now() - timedelta(hours=hours_back)).timestamp() * 1000)
    incidents = []
    for severity in ["CRITICAL", "HIGH", "MEDIUM"]:
        try:
            resp = requests.get(
                f"{host}/phoenix/rest/incident/listIncidents",
                params={"startTime": start_ms, "endTime": now_ms,
                        "maxResults": 200, "eventSeverity": severity, "status": "Active"},
                headers=h, verify=v, timeout=30
            )
            if resp.status_code != 200:
                continue
            root = ET.fromstring(resp.text)
            for inc in root.findall(".//incident"):
                src_ips = [ip.text for ip in inc.findall(".//srcIpAddr") if ip.text]
                incidents.append({
                    "id":       inc.findtext("incidentId"),
                    "title":    inc.findtext("incidentTitle") or "",
                    "severity": inc.findtext("eventSeverity") or severity,
                    "rule":     inc.findtext("ruleId") or "",
                    "src_ips":  src_ips,
                    "count":    int(inc.findtext("eventCount") or "0"),
                    # Pre-score keywords (reuse l1_triage signals)
                    "tp_score": _quick_keyword_score(inc.findtext("incidentTitle") or "",
                                                      severity),
                })
        except Exception as e:
            print(f"      Warning: failed to load {severity}: {e}", file=sys.stderr)

    print(f"      {len(incidents)} active incidents")

    # CMDB cache — load all at once
    cmdb_cache = {}

    # Process each incident
    print("[3/4] Running decisions...")
    results = {"auto_closed": [], "auto_escalated": [], "assisted": [], "errors": []}

    for inc in incidents:
        try:
            # Get asset criticality for primary source IP
            primary_ip = inc["src_ips"][0] if inc["src_ips"] else ""
            criticality = get_asset_criticality(primary_ip, cmdb_cache) if primary_ip else \
                          {"level": "MEDIUM", "reason": "No source IP"}

            # Enrichment (optional — skip if fn not provided or IP is internal)
            enrichment = {}
            if enrichment_fn and primary_ip and not _is_internal(primary_ip):
                try:
                    enrichment = enrichment_fn(primary_ip)
                except Exception:
                    pass

            # Make decision
            decision = make_triage_decision(inc, rule_history, criticality, enrichment)
            inc["decision"] = decision
            inc["criticality"] = criticality

            # Execute if not dry run
            if not dry_run and decision["autonomous"]:
                status = "False Positive" if decision["disposition"] == "FALSE_POSITIVE" else "InProgress"
                requests.post(
                    f"{host}/phoenix/rest/incident/updateIncidentStatus",
                    data=f"""<incidentStatusChange>
                      <incidentId>{inc['id']}</incidentId>
                      <incidentStatus>{status}</incidentStatus>
                      <comment>{decision['note']}</comment>
                    </incidentStatusChange>""",
                    headers=h, verify=v, timeout=15
                )

            # Bucket results
            action = decision["action"]
            if action == "AUTO_CLOSE":
                results["auto_closed"].append(inc)
            elif action == "AUTO_ESCALATE":
                results["auto_escalated"].append(inc)
            else:
                results["assisted"].append(inc)

        except Exception as e:
            results["errors"].append({"incident_id": inc.get("id"), "error": str(e)})

    elapsed = round((datetime.now() - started).total_seconds(), 1)
    results["summary"] = {
        "total":          len(incidents),
        "auto_closed":    len(results["auto_closed"]),
        "auto_escalated": len(results["auto_escalated"]),
        "assisted":       len(results["assisted"]),
        "errors":         len(results["errors"]),
        "autonomous_pct": round((len(results["auto_closed"]) + len(results["auto_escalated"]))
                                / max(len(incidents), 1) * 100, 1),
        "elapsed_s":      elapsed,
        "dry_run":        dry_run,
        "mode":           "DRY RUN" if dry_run else "LIVE",
    }
    print(f"[4/4] Done in {elapsed}s")
    return results


def _quick_keyword_score(title: str, severity: str) -> int:
    """Fast keyword score for triage — mirrors l1_triage logic."""
    score = 0
    title_lower = title.lower()
    HIGH_CONF = ["ransomware","shadow copy","lsass","mimikatz","c2 beacon",
                 "exfiltration","impossible travel","credential dump"]
    if any(kw in title_lower for kw in HIGH_CONF): score += 10
    if severity == "CRITICAL": score += 8
    return min(score, 10)

def _is_internal(ip: str) -> bool:
    """Check if IP is RFC1918 private — skip enrichment for internal IPs."""
    return (ip.startswith("10.") or ip.startswith("192.168.")
            or (ip.startswith("172.") and
                16 <= int(ip.split(".")[1]) <= 31 if ip.count(".") >= 2 else False))
```

## Step 5 — Autonomous Triage Report

```python
def auto_triage_report(results: dict) -> str:
    """Format the autonomous triage run as a handover report."""
    s = results["summary"]
    lines = [
        f"# Autonomous Triage Report",
        f"**Mode**: {s['mode']} | **Incidents**: {s['total']} | "
        f"**Autonomous**: {s['autonomous_pct']}% | **Time**: {s['elapsed_s']}s",
        "",
        "## Outcome Summary",
        f"| Outcome | Count | Action |",
        f"|---|---|---|",
        f"| 🤖 Auto-closed (FP) | {s['auto_closed']} | Written to FortiSIEM as False Positive |",
        f"| 🚨 Auto-escalated | {s['auto_escalated']} | Set InProgress, L2 note added |",
        f"| 👤 Needs analyst | {s['assisted']} | In queue with pre-scored context |",
        f"| ⚠️ Errors | {s['errors']} | Check logs |",
        "",
    ]

    if results["auto_escalated"]:
        lines += ["## 🚨 Auto-Escalated — L2 Action Required", ""]
        for inc in results["auto_escalated"][:10]:
            d = inc.get("decision", {})
            lines.append(f"- **#{inc['id']}** [{inc['severity']}] {inc['title'][:60]}")
            lines.append(f"  Asset: {inc.get('criticality',{}).get('level','?')} | "
                         f"Reason: {' | '.join(d.get('reasoning',[])[:2])}")

    if results["assisted"]:
        lines += ["", "## 👤 Analyst Queue (pre-scored)", ""]
        lines += ["| # | Severity | Title | Asset | Recommendation |",
                  "|---|---|---|---|---|"]
        for inc in results["assisted"][:20]:
            d = inc.get("decision", {})
            rec = d.get("recommendation", "INVESTIGATE")
            asset = inc.get("criticality", {}).get("level", "?")
            lines.append(f"| #{inc['id']} | {inc['severity']} | "
                         f"{inc['title'][:40]} | {asset} | {rec} |")

    if not s["dry_run"] and s["auto_closed"] > 0:
        lines += ["", f"## Audit Trail",
                  f"All {s['auto_closed']} auto-closed incidents have been updated in FortiSIEM "
                  f"with `[AUTO-TRIAGE]` comment including rule FP rate, asset criticality, "
                  f"and enrichment verdict for full auditability."]

    lines += ["", "---",
              "*Auto-triage acts only when ALL confidence conditions are met. "
              "Every autonomous decision is logged with full reasoning chain.*"]
    return "\n".join(lines)
```

## Confidence Thresholds Reference

| Condition | Auto-Close | Auto-Escalate | Assisted |
|---|---|---|---|
| Rule FP rate | ≥ 95% with HIGH confidence (≥20 incidents) | Any | < 95% OR low history |
| Asset criticality | LOW only | HIGH or CRITICAL | MEDIUM or ambiguous |
| Enrichment | UNKNOWN or CLEAN | MALICIOUS | SUSPICIOUS |
| TP keyword score | Any (if above are met) | ≥ 8 on CRITICAL asset | < 8 |

## Tuning the Thresholds

Change via env vars before running:
```bash
# Make auto-close more aggressive (lower FP rate threshold)
export FSIEM_AUTO_CLOSE_FP_THRESHOLD=90

# Pin specific IPs as critical regardless of CMDB
export FSIEM_CRITICAL_IPS="10.0.0.1,10.0.0.5,10.0.1.100"

# Mark dev/test subnets as LOW criticality
export FSIEM_LOW_IPS="192.168.99.0/24,10.99.0.0/16"
```

