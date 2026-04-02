---
name: fsiem-health
description: Monitor FortiSIEM parser and collector health — detect silent devices (stopped sending logs), slow/lagging collectors, parser failures, and event volume anomalies. Use when asked about log source health, why a device stopped reporting, whether parsers are working, or for daily health checks. This is the #1 operational pain point in any SIEM deployment.
---

# FortiSIEM Parser & Collector Health Monitoring

The most common silent failure in FortiSIEM: a log source stops sending events and nobody notices for days. This skill detects it proactively.

## Core Health Functions

```python
import os, base64, requests, xml.etree.ElementTree as ET, sys
from datetime import datetime, timedelta

def fsiem_headers():
    user, org, pw = os.environ["FSIEM_USER"], os.environ["FSIEM_ORG"], os.environ["FSIEM_PASS"]
    return {"Authorization": f"Basic {base64.b64encode(f'{user}/{org}:{pw}'.encode()).decode()}",
            "Content-Type": "text/xml"}

def fsiem_verify_ssl():
    return os.environ.get("FSIEM_VERIFY_SSL", "false").lower() == "true"

def get_all_devices(include_unmonitored: bool = False) -> list:
    """
    Get all CMDB devices with last event time.
    This is the foundation of health monitoring — every silent device shows up here.
    """
    host = os.environ["FSIEM_HOST"]
    xml_body = """<DeviceFilter>
      <includeMonitored>true</includeMonitored>
      <includeUnmonitored>{}</includeUnmonitored>
    </DeviceFilter>""".format(str(include_unmonitored).lower())

    resp = requests.post(
        f"{host}/phoenix/rest/cmdbDeviceInfo/devices",
        data=xml_body, headers=fsiem_headers(), verify=fsiem_verify_ssl(), timeout=30
    )
    resp.raise_for_status()
    root = ET.fromstring(resp.text)
    devices = []
    for d in root.findall(".//device"):
        devices.append({
            "ip":              d.findtext("deviceIP") or d.findtext("ipAddr") or "",
            "hostname":        d.findtext("hostName") or d.findtext("name") or "",
            "type":            d.findtext("deviceType") or "",
            "vendor":          d.findtext("vendor") or "",
            "model":           d.findtext("model") or "",
            "org":             d.findtext("organization") or "",
            "last_event_time": d.findtext("lastEventTime") or "",
            "monitored":       d.findtext("monitored") or "false",
            "approved":        d.findtext("approved") or "false",
        })
    return devices
```

## Step 1 — Silent Device Detection

```python
def find_silent_devices(
    silence_threshold_hours: int = 4,
    critical_threshold_hours: int = 1,
    device_types_to_check: list = None,
) -> dict:
    """
    Find devices that have stopped sending events.
    Returns dict with CRITICAL, WARNING, and OK buckets.

    silence_threshold_hours: flag as WARNING if no events in this many hours
    critical_threshold_hours: flag as CRITICAL if no events in this many hours
    device_types_to_check: if None, checks all device types
    """
    devices = get_all_devices()
    now = datetime.now()
    results = {"CRITICAL": [], "WARNING": [], "UNKNOWN": [], "OK": [], "summary": {}}

    for dev in devices:
        if dev["monitored"].lower() != "true":
            continue
        if device_types_to_check and dev["type"] not in device_types_to_check:
            continue

        last = dev["last_event_time"]
        if not last:
            results["UNKNOWN"].append({**dev, "silent_hours": None,
                                        "reason": "No event time recorded"})
            continue

        try:
            # FortiSIEM stores last event time as epoch milliseconds
            ts = int(last) / 1000 if len(last) > 10 else int(last)
            last_dt = datetime.fromtimestamp(ts)
            silent_hours = (now - last_dt).total_seconds() / 3600
            dev["silent_hours"] = round(silent_hours, 1)
            dev["last_event_human"] = last_dt.strftime("%Y-%m-%d %H:%M")

            if silent_hours >= silence_threshold_hours:
                severity = "CRITICAL" if silent_hours >= 24 else \
                           "CRITICAL" if (silent_hours >= critical_threshold_hours and
                                          dev["type"] in ("Firewall", "IDS", "VPN", "Router")) else \
                           "WARNING"
                results[severity].append(dev)
            else:
                results["OK"].append(dev)
        except (ValueError, OSError):
            results["UNKNOWN"].append({**dev, "reason": f"Unparseable time: {last}"})

    results["summary"] = {
        "total_monitored": len(results["CRITICAL"]) + len(results["WARNING"]) +
                           len(results["OK"]) + len(results["UNKNOWN"]),
        "critical":  len(results["CRITICAL"]),
        "warning":   len(results["WARNING"]),
        "unknown":   len(results["UNKNOWN"]),
        "ok":        len(results["OK"]),
        "checked_at": now.isoformat(),
    }
    return results
```

## Step 2 — Collector Health

```python
def get_collector_health() -> list:
    """
    Get health status of all FortiSIEM collectors (Workers).
    Collectors that are lagging or down will miss events even if devices are sending.
    """
    host = os.environ["FSIEM_HOST"]
    resp = requests.get(
        f"{host}/phoenix/rest/config/collector",
        headers=fsiem_headers(), verify=fsiem_verify_ssl(), timeout=15
    )
    resp.raise_for_status()
    root = ET.fromstring(resp.text)
    collectors = []
    for c in root.findall(".//collector"):
        eps = float(c.findtext("currentEPS") or "0")
        max_eps = float(c.findtext("maxEPS") or "1")
        collectors.append({
            "id":          c.findtext("id") or "",
            "name":        c.findtext("name") or c.findtext("hostName") or "",
            "ip":          c.findtext("ipAddr") or "",
            "status":      c.findtext("status") or "unknown",
            "current_eps": eps,
            "max_eps":     max_eps,
            "eps_pct":     round(eps / max_eps * 100, 1) if max_eps > 0 else 0,
            "queue_size":  int(c.findtext("queueSize") or "0"),
            "drop_count":  int(c.findtext("dropCount") or "0"),
            "version":     c.findtext("version") or "",
        })
    return collectors

def check_collector_health(collectors: list) -> dict:
    """Assess collector health and flag issues."""
    issues = []
    for c in collectors:
        if c["status"].lower() not in ("up", "running", "online"):
            issues.append({"collector": c["name"], "severity": "CRITICAL",
                           "issue": f"Status: {c['status']}"})
        elif c["eps_pct"] > 85:
            issues.append({"collector": c["name"], "severity": "WARNING",
                           "issue": f"EPS at {c['eps_pct']}% capacity — risk of event drop"})
        elif c["drop_count"] > 0:
            issues.append({"collector": c["name"], "severity": "WARNING",
                           "issue": f"Dropping events: {c['drop_count']} dropped"})
        elif c["queue_size"] > 10000:
            issues.append({"collector": c["name"], "severity": "WARNING",
                           "issue": f"Queue backlog: {c['queue_size']:,} events pending"})
    return {"collectors": collectors, "issues": issues,
            "healthy": len(issues) == 0}
```

## Step 3 — Parser Health (Event Volume Anomaly)

```python
def check_parser_health(
    baseline_days: int = 7,
    alert_threshold_pct: float = 50.0,
) -> list:
    """
    Detect parser failures by comparing today's event volume per device type
    against the baseline. A 50%+ drop in events from a device type = likely parser issue.

    FortiSIEM has no direct 'parser health' API — volume drop IS the signal.
    """
    host = os.environ["FSIEM_HOST"]
    h = fsiem_headers()
    v = fsiem_verify_ssl()
    import time

    def run_volume_query(window: str) -> dict:
        """Get event count grouped by reporting device."""
        q = f"""<Reports><Report><n>Volume Check {window}</n>
          <SelectClause><AttrList>reptDevIpAddr,COUNT(eventId) AS event_count</AttrList></SelectClause>
          <ReportInterval><Window>{window}</Window></ReportInterval>
          <PatternClause><SubPattern><Filters></Filters></SubPattern></PatternClause>
        </Report></Reports>"""
        r = requests.post(f"{host}/phoenix/rest/query/eventQuery",
                          data=q, headers=h, verify=v, timeout=30)
        r.raise_for_status()
        qid = r.text.strip()
        for _ in range(60):
            p = requests.get(f"{host}/phoenix/rest/query/progress/{qid}",
                             headers=h, verify=v, timeout=10)
            if int(p.text.strip() or "0") >= 100: break
            time.sleep(2)
        r2 = requests.get(f"{host}/phoenix/rest/query/events/{qid}/0/500",
                          headers=h, verify=v, timeout=30)
        root = ET.fromstring(r2.text)
        counts = {}
        for ev in root.findall(".//event"):
            attrs = {a.findtext("name",""): a.findtext("value","")
                     for a in ev.findall("attributes/attribute")}
            ip = attrs.get("reptDevIpAddr","unknown")
            try:
                counts[ip] = int(attrs.get("event_count","0"))
            except ValueError:
                pass
        return counts

    today_counts    = run_volume_query("Last 24 hours")
    baseline_counts = run_volume_query(f"Last {baseline_days} days")

    # Normalize baseline to per-day average
    baseline_daily = {ip: count / baseline_days
                      for ip, count in baseline_counts.items()}

    anomalies = []
    for ip, today in today_counts.items():
        baseline = baseline_daily.get(ip, 0)
        if baseline < 10:
            continue  # Too low to be meaningful
        drop_pct = (baseline - today) / baseline * 100
        spike_pct = (today - baseline) / baseline * 100
        if drop_pct >= alert_threshold_pct:
            anomalies.append({
                "device_ip":    ip,
                "today_events": today,
                "baseline_avg": round(baseline, 0),
                "change_pct":   round(-drop_pct, 1),
                "severity":     "CRITICAL" if drop_pct >= 90 else "WARNING",
                "issue":        f"Event volume dropped {round(drop_pct,0)}% vs {baseline_days}-day baseline — possible parser failure or device went silent",
            })
        elif spike_pct >= 300:
            anomalies.append({
                "device_ip":    ip,
                "today_events": today,
                "baseline_avg": round(baseline, 0),
                "change_pct":   round(spike_pct, 1),
                "severity":     "WARNING",
                "issue":        f"Event volume spiked {round(spike_pct,0)}% vs baseline — possible attack or misconfiguration",
            })

    # Also flag devices in baseline that sent ZERO today (completely silent)
    for ip, baseline in baseline_daily.items():
        if baseline >= 10 and ip not in today_counts:
            anomalies.append({
                "device_ip":    ip,
                "today_events": 0,
                "baseline_avg": round(baseline, 0),
                "change_pct":   -100.0,
                "severity":     "CRITICAL",
                "issue":        "Device sent 0 events today but averaged events in baseline — SILENT",
            })

    return sorted(anomalies, key=lambda x: x["change_pct"])
```

## Step 4 — Full Health Dashboard

```python
def health_dashboard(silence_hours: int = 4) -> str:
    """
    Generate a complete operational health dashboard.
    Covers: collectors, silent devices, parser/volume anomalies.
    Run this daily or as part of shift start.
    """
    now = datetime.now().strftime("%Y-%m-%d %H:%M")
    lines = [
        f"# FortiSIEM Health Dashboard",
        f"**Generated**: {now} | **Silence threshold**: {silence_hours}h",
        "",
    ]

    # Collectors
    try:
        collector_result = check_collector_health(get_collector_health())
        lines += ["## Collectors", ""]
        if collector_result["healthy"]:
            lines.append(f"✅ All {len(collector_result['collectors'])} collectors healthy")
        else:
            for issue in collector_result["issues"]:
                emoji = "🔴" if issue["severity"] == "CRITICAL" else "🟡"
                lines.append(f"{emoji} **{issue['collector']}**: {issue['issue']}")
    except Exception as e:
        lines.append(f"⚠️ Collector health check failed: {e}")

    # Silent devices
    lines += ["", "## Silent Devices", ""]
    try:
        silent = find_silent_devices(silence_threshold_hours=silence_hours)
        s = silent["summary"]
        lines.append(f"| Status | Count |")
        lines.append(f"|---|---|")
        lines.append(f"| 🔴 Critical (silent) | {s['critical']} |")
        lines.append(f"| 🟡 Warning | {s['warning']} |")
        lines.append(f"| ⚪ Unknown | {s['unknown']} |")
        lines.append(f"| ✅ OK | {s['ok']} |")
        lines.append("")
        if silent["CRITICAL"]:
            lines.append("**Critical — Immediate Attention:**")
            for d in silent["CRITICAL"][:10]:
                lines.append(f"- `{d['ip']}` ({d['hostname']}) [{d['type']}] "
                              f"— silent {d.get('silent_hours','?')}h, last event: {d.get('last_event_human','unknown')}")
    except Exception as e:
        lines.append(f"⚠️ Silent device check failed: {e}")

    # Parser/volume anomalies
    lines += ["", "## Parser / Volume Anomalies (vs 7-day baseline)", ""]
    try:
        anomalies = check_parser_health(baseline_days=7, alert_threshold_pct=50)
        if not anomalies:
            lines.append("✅ All device event volumes within normal range")
        else:
            lines.append(f"| Device | Today | Baseline | Change | Issue |")
            lines.append(f"|---|---|---|---|---|")
            for a in anomalies[:15]:
                emoji = "🔴" if a["severity"] == "CRITICAL" else "🟡"
                lines.append(
                    f"| {emoji} `{a['device_ip']}` | {a['today_events']:,} | "
                    f"{int(a['baseline_avg']):,}/day | {a['change_pct']:+.0f}% | "
                    f"{a['issue'][:60]} |"
                )
    except Exception as e:
        lines.append(f"⚠️ Parser health check failed: {e}")

    lines += ["", "---",
              "**Action guide**: CRITICAL = investigate now | WARNING = investigate within 2h | "
              "Silent firewall/IDS = treat as P1 until proven otherwise"]
    return "\n".join(lines)
```

## Common Issues and Fixes

| Symptom | Likely Cause | Fix |
|---|---|---|
| Device silent after maintenance | Syslog port blocked by firewall change | Check network path, re-open UDP/TCP 514 |
| Parser volume drop 50–90% | Parser broke after firmware upgrade | Check FortiSIEM parser editor, re-import vendor parser |
| Parser volume drop 100% | Device stopped sending / wrong IP | Verify syslog config on device, check CMDB IP |
| Collector EPS > 85% | Too many devices on one collector | Re-balance log sources across collectors |
| Collector queue backlog | Collector can't keep up / disk full | Check collector disk, increase EPS license |
| All devices silent | Supervisor issue, not device issue | Check FortiSIEM supervisor service status |
