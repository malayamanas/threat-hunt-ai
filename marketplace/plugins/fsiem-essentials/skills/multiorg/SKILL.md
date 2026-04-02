---
name: fsiem-multiorg
description: Run operations across all organizations in a FortiSIEM Service Provider deployment — sweep incidents, hunt IOCs, or generate reports for every tenant at once. Use when managing an MSSP environment or when asked to check all orgs.
---

# FortiSIEM Multi-Org Operations (MSSP / Service Provider)

For SP deployments managing multiple tenants, these functions loop all orgs automatically.

## Get All Organizations

```python
import requests, base64, os, xml.etree.ElementTree as ET

def fsiem_headers(org="super"):
    user = os.environ["FSIEM_USER"]
    pw   = os.environ["FSIEM_PASS"]
    token = base64.b64encode(f"{user}/{org}:{pw}".encode()).decode()
    return {"Authorization": f"Basic {token}", "Content-Type": "text/xml"}

def fsiem_verify_ssl():
    return os.environ.get("FSIEM_VERIFY_SSL", "false").lower() == "true"

def get_all_orgs() -> list[str]:
    """Return list of all organization names in SP deployment."""
    host = os.environ["FSIEM_HOST"]
    resp = requests.get(
        f"{host}/phoenix/rest/config/Domain",
        headers=fsiem_headers("super"),
        verify=fsiem_verify_ssl()
    )
    resp.raise_for_status()
    root = ET.fromstring(resp.text)
    orgs = [o.findtext("n") or o.findtext("name")
            for o in root.findall(".//organization")]
    return [o for o in orgs if o and o.lower() not in ("super", "system")]
```

## Multi-Org Incident Sweep

```python
from datetime import datetime, timedelta

def multiorg_incident_sweep(hours_back: int = 24, severity: str = "HIGH") -> dict:
    """
    Fetch open incidents across ALL organizations.
    Returns dict: org_name → list of incidents.
    """
    host = os.environ["FSIEM_HOST"]
    orgs = get_all_orgs()
    results = {}
    now = int(datetime.now().timestamp() * 1000)
    start = int((datetime.now() - timedelta(hours=hours_back)).timestamp() * 1000)

    for org in orgs:
        params = {
            "startTime": start,
            "endTime": now,
            "maxResults": 100,
            "eventSeverity": severity,
            "status": "Active",
            "organization": org,
        }
        try:
            resp = requests.get(
                f"{host}/phoenix/rest/incident/listIncidents",
                params=params,
                headers=fsiem_headers(org),
                verify=fsiem_verify_ssl()
            )
            resp.raise_for_status()
            root = ET.fromstring(resp.text)
            incidents = []
            for inc in root.findall(".//incident"):
                incidents.append({
                    "id":       inc.findtext("incidentId"),
                    "title":    inc.findtext("incidentTitle"),
                    "severity": inc.findtext("eventSeverity"),
                    "count":    inc.findtext("eventCount"),
                    "lastSeen": inc.findtext("lastEventTime"),
                    "org":      org,
                })
            if incidents:
                results[org] = incidents
        except Exception as e:
            results[org] = [{"error": str(e)}]

    return results

def multiorg_incident_summary(results: dict) -> str:
    """Print a formatted summary table of incidents across all orgs."""
    lines = [
        f"{'Organization':<25} {'HIGH':<6} {'CRITICAL':<10} {'Top Incident'}",
        "-" * 80,
    ]
    for org, incidents in sorted(results.items()):
        if isinstance(incidents[0], dict) and "error" in incidents[0]:
            lines.append(f"{org:<25} ERROR: {incidents[0]['error'][:40]}")
            continue
        high    = sum(1 for i in incidents if i["severity"] == "HIGH")
        crit    = sum(1 for i in incidents if i["severity"] == "CRITICAL")
        top     = incidents[0]["title"][:40] if incidents else ""
        lines.append(f"{org:<25} {high:<6} {crit:<10} {top}")
    return "\n".join(lines)
```

## Multi-Org IOC Hunt

```python
import time

def multiorg_ioc_hunt(iocs: list[str], days: int = 7) -> dict:
    """
    Hunt a list of IOCs across every organization.
    Returns dict: ioc → list of {org, event_count, sample_event}.
    """
    host = os.environ["FSIEM_HOST"]
    orgs = get_all_orgs()
    hits = {}

    for ioc in iocs:
        ioc_hits = []
        query_xml = f"""<Reports><Report>
          <n>MultiOrg IOC Hunt {ioc}</n>
          <SelectClause><AttrList>eventTime,eventType,srcIpAddr,destIpAddr,rawEventMsg</AttrList></SelectClause>
          <ReportInterval><Window>Last {days} days</Window></ReportInterval>
          <PatternClause><SubPattern><Filters>
            <Filter><n>rawEventMsg</n><Operator>CONTAIN</Operator><Value>{ioc}</Value></Filter>
          </Filters></SubPattern></PatternClause>
        </Report></Reports>"""

        for org in orgs:
            try:
                # Submit
                r = requests.post(
                    f"{host}/phoenix/rest/query/eventQuery",
                    data=query_xml,
                    headers=fsiem_headers(org),
                    verify=fsiem_verify_ssl(),
                    timeout=30
                )
                qid = r.text.strip()

                # Poll
                for _ in range(30):
                    p = requests.get(
                        f"{host}/phoenix/rest/query/progress/{qid}",
                        headers=fsiem_headers(org),
                        verify=fsiem_verify_ssl(),
                        timeout=10
                    )
                    if int(p.text.strip() or "0") >= 100:
                        break
                    time.sleep(2)

                # Results (first page only for sweep)
                r2 = requests.get(
                    f"{host}/phoenix/rest/query/events/{qid}/0/20",
                    headers=fsiem_headers(org),
                    verify=fsiem_verify_ssl(),
                    timeout=30
                )
                root = ET.fromstring(r2.text)
                events = [{a.findtext("name",""): a.findtext("value","")
                           for a in ev.findall("attributes/attribute")}
                          for ev in root.findall(".//event")]

                if events:
                    ioc_hits.append({
                        "org": org,
                        "event_count": len(events),
                        "sample": events[0],
                    })
            except Exception as e:
                pass  # Skip failed orgs silently in sweep

        if ioc_hits:
            hits[ioc] = ioc_hits

    return hits
```

## Multi-Org Health Report

```python
def multiorg_health_report(days_back: int = 7) -> str:
    """
    Generate a consolidated health report across all organizations.
    Returns a formatted Markdown report.
    """
    results = multiorg_incident_sweep(hours_back=days_back * 24, severity="HIGH")
    crit_results = multiorg_incident_sweep(hours_back=days_back * 24, severity="CRITICAL")

    # Merge
    all_orgs = set(list(results.keys()) + list(crit_results.keys()))

    lines = [
        f"# FortiSIEM Multi-Org Health Report",
        f"**Period**: Last {days_back} days | **Generated**: {datetime.now().strftime('%Y-%m-%d %H:%M')}",
        f"**Organizations**: {len(all_orgs)}",
        "",
        "## Incident Summary",
        "",
        f"| Organization | Critical | High | Action Required |",
        f"|---|---|---|---|",
    ]

    needs_action = []
    for org in sorted(all_orgs):
        crits = crit_results.get(org, [])
        highs = results.get(org, [])
        crit_count = len([i for i in crits if isinstance(i, dict) and "id" in i])
        high_count  = len([i for i in highs if isinstance(i, dict) and "id" in i])
        action = "🔴 YES" if crit_count > 0 else ("🟡 REVIEW" if high_count > 5 else "✅ OK")
        if crit_count > 0:
            needs_action.append((org, crit_count, high_count))
        lines.append(f"| {org} | {crit_count} | {high_count} | {action} |")

    if needs_action:
        lines += ["", "## Orgs Requiring Immediate Attention", ""]
        for org, c, h in sorted(needs_action, key=lambda x: x[1], reverse=True):
            lines.append(f"- **{org}**: {c} CRITICAL, {h} HIGH incidents open")

    return "\n".join(lines)
```

## Usage Examples

```python
# Get all org names
orgs = get_all_orgs()
print(f"Managing {len(orgs)} organizations: {orgs}")

# Morning incident sweep
results = multiorg_incident_sweep(hours_back=24, severity="HIGH")
print(multiorg_incident_summary(results))

# Hunt IOCs across all tenants
hits = multiorg_ioc_hunt(["185.220.101.5", "evil.example.com"], days=7)
for ioc, orgs_hit in hits.items():
    print(f"IOC {ioc} found in: {[h['org'] for h in orgs_hit]}")

# Weekly board report
report = multiorg_health_report(days_back=7)
print(report)
```
