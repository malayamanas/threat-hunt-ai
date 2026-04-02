---
name: fsiem-ueba
description: Perform User and Entity Behavior Analytics (UEBA) in FortiSIEM — detect anomalous login patterns, unusual access times, peer group deviations, and suspicious entity behavior. Use when investigating potential insider threats, compromised accounts, or behavioral anomalies.
---

# FortiSIEM UEBA — Behavioral Analytics

UEBA finds threats that rule-based detection misses by establishing baselines and flagging deviations. No single event is the alert — the *pattern* is.

## Core UEBA Queries

### 1. User Login Baseline — Establish Normal

```xml
<!-- Step 1: Build login frequency baseline for a user (30 days) -->
<Reports><Report>
  <n>UEBA: User Login Baseline</n>
  <SelectClause><AttrList>user,srcIpAddr,eventTime,eventType,hostName,COUNT(*)</AttrList></SelectClause>
  <ReportInterval><Window>Last 30 days</Window></ReportInterval>
  <PatternClause><SubPattern>
    <Filters>
      <Filter><n>eventType</n><Operator>IN</Operator><Value>Successful Login,Failed Login,VPN Login</Value></Filter>
      <Filter><n>user</n><Operator>CONTAIN</Operator><Value>TARGET_USER</Value></Filter>
    </Filters>
    <GroupByAttr>user,srcIpAddr</GroupByAttr>
    <SingleEvt>false</SingleEvt>
  </SubPattern></PatternClause>
</Report></Reports>
```

```python
def analyze_login_baseline(events: list) -> dict:
    """
    Compute login behavior baseline from 30 days of events.
    Returns: known IPs, typical hours, average logins/day, known hosts
    """
    from collections import Counter
    import datetime

    known_ips = Counter()
    known_hosts = Counter()
    login_hours = Counter()
    daily_counts = Counter()

    for e in events:
        if e.get("eventType", "").lower() in ("successful login", "vpn login"):
            known_ips[e.get("srcIpAddr", "")] += 1
            known_hosts[e.get("hostName", "")] += 1

            # Parse hour from eventTime (format: "2024-01-15 09:23:44")
            try:
                t = datetime.datetime.strptime(e["eventTime"][:19], "%Y-%m-%d %H:%M:%S")
                login_hours[t.hour] += 1
                daily_counts[t.strftime("%Y-%m-%d")] += 1
            except (KeyError, ValueError):
                pass

    total_days = max(len(daily_counts), 1)
    return {
        "known_ips": dict(known_ips.most_common(20)),
        "known_hosts": dict(known_hosts.most_common(10)),
        "typical_hours": sorted([h for h, c in login_hours.items() if c >= total_days * 0.1]),
        "avg_logins_per_day": sum(daily_counts.values()) / total_days,
        "total_events": len(events),
    }

def detect_login_anomalies(new_events: list, baseline: dict) -> list:
    """Compare recent logins against established baseline."""
    import datetime
    anomalies = []

    for e in new_events:
        if "login" not in e.get("eventType", "").lower():
            continue

        flags = []
        ip = e.get("srcIpAddr", "")
        host = e.get("hostName", "")

        # New IP never seen before
        if ip and ip not in baseline["known_ips"]:
            flags.append(f"NEW IP: {ip} (never used in last 30 days)")

        # Unusual hour
        try:
            t = datetime.datetime.strptime(e["eventTime"][:19], "%Y-%m-%d %H:%M:%S")
            if t.hour not in baseline["typical_hours"]:
                flags.append(f"UNUSUAL HOUR: {t.hour}:00 (typical: {baseline['typical_hours']})")
        except (KeyError, ValueError):
            pass

        if flags:
            anomalies.append({
                "event": e,
                "flags": flags,
                "risk_score": len(flags) * 3
            })

    return sorted(anomalies, key=lambda x: x["risk_score"], reverse=True)
```

### 2. Peer Group Analysis — Who Is Doing What Others Don't

```xml
<!-- Users accessing resources not accessed by their peer group -->
<Reports><Report>
  <n>UEBA: Unusual Resource Access by Department</n>
  <SelectClause><AttrList>user,hostName,fileName,eventType,COUNT(*)</AttrList></SelectClause>
  <ReportInterval><Window>Last 7 days</Window></ReportInterval>
  <PatternClause><SubPattern>
    <Filters>
      <Filter><n>eventType</n><Operator>IN</Operator><Value>File Access,File Read,Successful Login</Value></Filter>
      <Filter><n>hostName</n><Operator>REGEXP</Operator>
        <Value>(?i)(finance|hr|legal|exec|payroll|board)</Value>
      </Filter>
    </Filters>
    <GroupByAttr>user,hostName</GroupByAttr>
    <SingleEvt>false</SingleEvt>
  </SubPattern></PatternClause>
</Report></Reports>
```

### 3. Privileged Account Abuse Detection

```xml
<!-- Service accounts performing interactive logins (should never happen) -->
<Reports><Report>
  <n>UEBA: Service Account Interactive Login</n>
  <SelectClause><AttrList>eventTime,user,srcIpAddr,hostName,eventType,rawEventMsg</AttrList></SelectClause>
  <ReportInterval><Window>Last 7 days</Window></ReportInterval>
  <PatternClause><SubPattern><Filters>
    <Filter><n>user</n><Operator>REGEXP</Operator><Value>(?i)(svc_|service|sa_|sql|oracle|backup|scan)</Value></Filter>
    <Filter><n>eventType</n><Operator>IN</Operator><Value>Successful Login,Interactive Login,Console Login</Value></Filter>
  </Filters></SubPattern></PatternClause>
</Report></Reports>

<!-- Admin accounts used from workstations (should use jump server) -->
<Reports><Report>
  <n>UEBA: Admin Login from Workstation (not jump server)</n>
  <SelectClause><AttrList>eventTime,user,srcIpAddr,destIpAddr,hostName</AttrList></SelectClause>
  <ReportInterval><Window>Last 7 days</Window></ReportInterval>
  <PatternClause><SubPattern><Filters>
    <Filter><n>user</n><Operator>REGEXP</Operator><Value>(?i)(admin|administrator|domain.admin)</Value></Filter>
    <Filter><n>eventType</n><Operator>CONTAIN</Operator><Value>Successful Login</Value></Filter>
    <Filter><n>srcIpAddr</n><Operator>NOT IN</Operator>
      <Value>10.0.0.10,10.0.0.11,10.0.0.12</Value>
    </Filter>
    <!-- Replace with your actual jump server IPs -->
  </Filters></SubPattern></PatternClause>
</Report></Reports>
```

### 4. First-Time Access Detection

```python
def find_first_time_accesses(recent_events: list, historical_events: list) -> list:
    """
    Find user-resource pairs that appear in recent data but never in historical data.
    Use to find: first-time logins to sensitive servers, first-time file access, etc.
    """
    # Build historical access set
    historical_pairs = set()
    for e in historical_events:
        user = e.get("user", "")
        host = e.get("hostName", "") or e.get("destIpAddr", "")
        if user and host:
            historical_pairs.add((user, host))

    # Find first-time accesses in recent data
    first_times = []
    seen_in_recent = set()
    for e in recent_events:
        user = e.get("user", "")
        host = e.get("hostName", "") or e.get("destIpAddr", "")
        if not user or not host:
            continue
        pair = (user, host)
        if pair not in historical_pairs and pair not in seen_in_recent:
            seen_in_recent.add(pair)
            first_times.append({
                "user": user,
                "resource": host,
                "first_seen": e.get("eventTime", ""),
                "event_type": e.get("eventType", ""),
                "source_ip": e.get("srcIpAddr", ""),
            })

    return first_times
```

### 5. Off-Hours Activity Detection

```python
def flag_off_hours_activity(
    events: list,
    business_start: int = 7,   # 07:00
    business_end: int = 19,    # 19:00
    weekend: bool = True
) -> list:
    """
    Flag events occurring outside business hours.
    Returns events with risk annotation.
    """
    import datetime
    flagged = []

    for e in events:
        try:
            t = datetime.datetime.strptime(e["eventTime"][:19], "%Y-%m-%d %H:%M:%S")
            is_weekend = t.weekday() >= 5  # Saturday=5, Sunday=6
            is_off_hours = not (business_start <= t.hour < business_end)

            if is_off_hours or (weekend and is_weekend):
                e["off_hours_flag"] = True
                e["day_type"] = "weekend" if is_weekend else f"off-hours ({t.hour}:00)"
                flagged.append(e)
        except (KeyError, ValueError):
            pass

    return flagged
```

### 6. Volume Anomaly Detection

```python
def detect_volume_anomalies(
    events: list,
    group_by: str = "user",
    metric: str = "count",
    std_threshold: float = 3.0
) -> list:
    """
    Flag entities whose activity volume is > N standard deviations from mean.
    Classic statistical anomaly detection.
    """
    import math
    from collections import Counter, defaultdict

    # Count events per entity
    entity_counts = Counter()
    for e in events:
        key = e.get(group_by, "unknown")
        entity_counts[key] += 1

    if len(entity_counts) < 3:
        return []  # Not enough data for statistics

    values = list(entity_counts.values())
    mean = sum(values) / len(values)
    variance = sum((v - mean) ** 2 for v in values) / len(values)
    std_dev = math.sqrt(variance) if variance > 0 else 1

    anomalies = []
    for entity, count in entity_counts.items():
        z_score = (count - mean) / std_dev
        if abs(z_score) >= std_threshold:
            anomalies.append({
                "entity": entity,
                "group_by": group_by,
                "count": count,
                "mean": round(mean, 1),
                "std_dev": round(std_dev, 1),
                "z_score": round(z_score, 2),
                "direction": "HIGH" if z_score > 0 else "LOW",
            })

    return sorted(anomalies, key=lambda x: abs(x["z_score"]), reverse=True)
```

## UEBA Investigation Workflow

```python
def run_ueba_investigation(username: str, days_baseline: int = 30, days_recent: int = 7) -> dict:
    """
    Full UEBA investigation for a specific user.
    Returns structured findings with risk scores.
    """
    # Self-contained run_query (same implementation as skills/event_query/)
import time, xml.etree.ElementTree as ET

def run_query(query_xml: str, max_results: int = 500) -> list:
    host = os.environ["FSIEM_HOST"]
    h = fsiem_headers()
    r = requests.post(f"{host}/phoenix/rest/query/eventQuery", data=query_xml, headers=h, verify=fsiem_verify_ssl())
    qid = r.text.strip()
    for _ in range(60):
        p = requests.get(f"{host}/phoenix/rest/query/progress/{qid}", headers=h, verify=fsiem_verify_ssl())
        if int(p.text.strip() or 0) >= 100:
            break
        time.sleep(2)
    r2 = requests.get(f"{host}/phoenix/rest/query/events/{qid}/0/{max_results}", headers=h, verify=fsiem_verify_ssl())
    root = ET.fromstring(r2.text)
    events = []
    for ev in root.findall(".//event"):
        d = {}
        for a in ev.findall("attributes/attribute"):
            d[a.findtext("name", "")] = a.findtext("value", "")
        events.append(d)
    return events

    # Query templates
    baseline_q = f"""<Reports><Report>
      <n>UEBA Baseline</n>
      <SelectClause><AttrList>eventTime,eventType,srcIpAddr,hostName,user,sentBytes</AttrList></SelectClause>
      <ReportInterval><Window>Last {days_baseline} days</Window></ReportInterval>
      <PatternClause><SubPattern><Filters>
        <Filter><n>user</n><Operator>CONTAIN</Operator><Value>{username}</Value></Filter>
      </Filters></SubPattern></PatternClause>
    </Report></Reports>"""

    recent_q = f"""<Reports><Report>
      <n>UEBA Recent</n>
      <SelectClause><AttrList>eventTime,eventType,srcIpAddr,hostName,user,sentBytes,fileName</AttrList></SelectClause>
      <ReportInterval><Window>Last {days_recent} days</Window></ReportInterval>
      <PatternClause><SubPattern><Filters>
        <Filter><n>user</n><Operator>CONTAIN</Operator><Value>{username}</Value></Filter>
      </Filters></SubPattern></PatternClause>
    </Report></Reports>"""

    baseline_events = run_query(baseline_q, max_results=2000)
    recent_events   = run_query(recent_q,   max_results=500)

    baseline = analyze_login_baseline(baseline_events)
    anomalies = detect_login_anomalies(recent_events, baseline)
    off_hours = flag_off_hours_activity(recent_events)
    first_times = find_first_time_accesses(recent_events, baseline_events)
    vol_anomalies = detect_volume_anomalies(recent_events, group_by="hostName")

    total_risk = (
        sum(a["risk_score"] for a in anomalies) +
        len(off_hours) +
        len(first_times) * 2 +
        sum(abs(v["z_score"]) for v in vol_anomalies)
    )

    return {
        "username": username,
        "total_risk_score": round(total_risk, 1),
        "risk_level": "HIGH" if total_risk > 20 else "MEDIUM" if total_risk > 10 else "LOW",
        "baseline": baseline,
        "login_anomalies": anomalies[:10],
        "off_hours_events": off_hours[:10],
        "first_time_accesses": first_times[:10],
        "volume_anomalies": vol_anomalies[:5],
        "recommendation": (
            "Escalate to Tier 2 immediately" if total_risk > 20
            else "Monitor and review" if total_risk > 10
            else "No action required"
        )
    }
```

## UEBA Risk Scoring Guide

| Signal | Risk Points |
|---|---|
| Login from new IP (never seen in 30 days) | +3 |
| Login at unusual hour | +2 |
| Login from new country (geo lookup) | +5 |
| First-time access to sensitive resource | +4 |
| Service account interactive login | +8 |
| Activity volume 3+ std devs above mean | +5 |
| Activity during off-hours | +2 |
| Bulk file download (>50 files/hour) | +6 |
| Admin tool usage from non-admin account | +7 |
| Multiple concurrent sessions | +3 |

**Risk Level**: LOW <10 | MEDIUM 10-20 | HIGH >20 (escalate)
