---
name: fsiem-briefing
description: Generate a daily FortiSIEM security briefing covering Active Directory events, authentication anomalies, privileged account activity, and overnight incidents. Run at session start before triage. Adapted from Anton Ovrutsky's Day 8 workflow for FortiSIEM. Use every morning or when asked for today's security summary.
---

# Daily FortiSIEM Security Briefing

Anton's Day 8 concept: before you touch the alert queue, know what happened. This skill generates an AD-focused security briefing from FortiSIEM Windows Security events.

## Full Briefing Implementation

```python
import os, base64, requests, xml.etree.ElementTree as ET, time, sys
from datetime import datetime, timedelta
from collections import defaultdict

def fsiem_headers():
    user, org, pw = os.environ["FSIEM_USER"], os.environ["FSIEM_ORG"], os.environ["FSIEM_PASS"]
    return {"Authorization": f"Basic {base64.b64encode(f'{user}/{org}:{pw}'.encode()).decode()}",
            "Content-Type": "text/xml"}

def fsiem_verify_ssl():
    return os.environ.get("FSIEM_VERIFY_SSL","false").lower() == "true"

def _run_query(xml_str: str, max_results: int = 500) -> list:
    host = os.environ["FSIEM_HOST"]
    h = fsiem_headers()
    v = fsiem_verify_ssl()
    try:
        r = requests.post(f"{host}/phoenix/rest/query/eventQuery",
                          data=xml_str, headers=h, verify=v, timeout=30)
        r.raise_for_status()
        qid = r.text.strip()
        for _ in range(60):
            p = requests.get(f"{host}/phoenix/rest/query/progress/{qid}",
                             headers=h, verify=v, timeout=10)
            if int(p.text.strip() or "0") >= 100: break
            time.sleep(2)
        r2 = requests.get(f"{host}/phoenix/rest/query/events/{qid}/0/{max_results}",
                          headers=h, verify=v, timeout=30)
        root = ET.fromstring(r2.text)
        return [{a.findtext("name",""): a.findtext("value","")
                 for a in ev.findall("attributes/attribute")}
                for ev in root.findall(".//event")]
    except Exception as e:
        print(f"[WARN] Query failed: {e}", file=sys.stderr)
        return []

def get_ad_events(hours_back: int = 24) -> dict:
    """
    Pull all AD-relevant Windows Security events for the briefing period.
    Returns events bucketed by type.
    """
    window = f"Last {hours_back} hours"

    # Account lifecycle: created, enabled, disabled, deleted (4720, 4722, 4725, 4726)
    account_events = _run_query(f"""<Reports><Report><n>Account Lifecycle</n>
      <SelectClause><AttrList>eventTime,user,targetUser,hostName,rawEventMsg</AttrList></SelectClause>
      <ReportInterval><Window>{window}</Window></ReportInterval>
      <PatternClause><SubPattern><Filters>
        <Filter><n>eventType</n><Operator>IN</Operator>
          <Value>Win-Security-4720,Win-Security-4722,Win-Security-4725,Win-Security-4726,
                 User Created,User Disabled,User Deleted,User Enabled</Value></Filter>
      </Filters></SubPattern></PatternClause></Report></Reports>""")

    # Group membership changes (4728, 4732, 4756 = added; 4729, 4733, 4757 = removed)
    group_events = _run_query(f"""<Reports><Report><n>Group Changes</n>
      <SelectClause><AttrList>eventTime,user,targetUser,targetGroup,hostName,rawEventMsg</AttrList></SelectClause>
      <ReportInterval><Window>{window}</Window></ReportInterval>
      <PatternClause><SubPattern><Filters>
        <Filter><n>eventType</n><Operator>IN</Operator>
          <Value>Win-Security-4728,Win-Security-4732,Win-Security-4756,
                 Win-Security-4729,Win-Security-4733,Win-Security-4757,
                 Group Membership Change,Added To Group</Value></Filter>
      </Filters></SubPattern></PatternClause></Report></Reports>""")

    # Privileged logon assignments (4672 = special privileges)
    priv_events = _run_query(f"""<Reports><Report><n>Privilege Assignments</n>
      <SelectClause><AttrList>eventTime,user,hostName,rawEventMsg</AttrList></SelectClause>
      <ReportInterval><Window>{window}</Window></ReportInterval>
      <PatternClause><SubPattern><Filters>
        <Filter><n>eventType</n><Operator>IN</Operator>
          <Value>Win-Security-4672,Privilege Use,Special Logon</Value></Filter>
        <Filter><n>user</n><Operator>NOT_REGEXP</Operator>
          <Value>SYSTEM|LOCAL SERVICE|NETWORK SERVICE|\$</Value></Filter>
      </Filters></SubPattern></PatternClause></Report></Reports>""")

    # Interactive logons outside business hours (4624 Type 2/10)
    offhours_events = _run_query(f"""<Reports><Report><n>Off-Hours Logons</n>
      <SelectClause><AttrList>eventTime,user,srcIpAddr,hostName,rawEventMsg</AttrList></SelectClause>
      <ReportInterval><Window>{window}</Window></ReportInterval>
      <PatternClause><SubPattern><Filters>
        <Filter><n>eventType</n><Operator>IN</Operator>
          <Value>Win-Security-4624,Successful Login,Interactive Login</Value></Filter>
        <Filter><n>user</n><Operator>NOT_REGEXP</Operator>
          <Value>SYSTEM|LOCAL SERVICE|NETWORK SERVICE|\$</Value></Filter>
      </Filters></SubPattern></PatternClause></Report></Reports>""")

    # Failed logins (4625) — accounts with >5 failures
    failed_events = _run_query(f"""<Reports><Report><n>Failed Logins</n>
      <SelectClause><AttrList>user,srcIpAddr,COUNT(eventId) AS fail_count</AttrList></SelectClause>
      <ReportInterval><Window>{window}</Window></ReportInterval>
      <PatternClause><SubPattern><Filters>
        <Filter><n>eventType</n><Operator>IN</Operator>
          <Value>Win-Security-4625,Failed Login,Auth Failure</Value></Filter>
      </Filters></SubPattern></PatternClause></Report></Reports>""")

    # High criticality incidents opened in this period
    host_url = os.environ["FSIEM_HOST"]
    now_ms = int(datetime.now().timestamp() * 1000)
    start_ms = int((datetime.now() - timedelta(hours=hours_back)).timestamp() * 1000)
    incidents = []
    try:
        for sev in ["CRITICAL", "HIGH"]:
            resp = requests.get(
                f"{host_url}/phoenix/rest/incident/listIncidents",
                params={"startTime": start_ms, "endTime": now_ms,
                        "maxResults": 50, "eventSeverity": sev, "status": "Active"},
                headers=fsiem_headers(), verify=fsiem_verify_ssl()
            )
            if resp.status_code == 200:
                root = ET.fromstring(resp.text)
                for inc in root.findall(".//incident"):
                    incidents.append({
                        "id":       inc.findtext("incidentId"),
                        "title":    inc.findtext("incidentTitle") or "",
                        "severity": sev,
                        "rule":     inc.findtext("ruleId") or "",
                        "time":     inc.findtext("firstEventTime") or "",
                    })
    except Exception:
        pass

    return {
        "account_events": account_events,
        "group_events":   group_events,
        "priv_events":    priv_events,
        "offhours_events": offhours_events,
        "failed_events":  failed_events,
        "incidents":      incidents,
    }

def generate_briefing(hours_back: int = 24, focus: str = "all") -> str:
    """
    Generate the daily security briefing.
    focus: all | ad | auth | incidents
    """
    now = datetime.now()
    period_start = (now - timedelta(hours=hours_back)).strftime("%Y-%m-%d %H:%M")
    data = get_ad_events(hours_back=hours_back)

    lines = [
        f"# FortiSIEM Security Briefing",
        f"**{now.strftime('%A, %d %B %Y %H:%M')}** | Period: {period_start} → now ({hours_back}h)",
        "",
    ]

    # ── HIGH PRIORITY FINDINGS ─────────────────────────────────────
    high_priority = []

    # Domain Admin group changes
    da_changes = [e for e in data["group_events"]
                  if "domain admin" in (e.get("targetGroup","") + e.get("rawEventMsg","")).lower()]
    if da_changes:
        high_priority.append(f"🔴 **{len(da_changes)} Domain Admin group change(s)**")

    # Accounts created then deleted quickly (create → delete within 24h = suspicious)
    created = {e.get("targetUser","").lower() for e in data["account_events"]
               if "4720" in e.get("eventType","") or "created" in e.get("rawEventMsg","").lower()}
    deleted = {e.get("targetUser","").lower() for e in data["account_events"]
               if "4726" in e.get("eventType","") or "deleted" in e.get("rawEventMsg","").lower()}
    short_lived = created & deleted
    if short_lived:
        high_priority.append(f"🔴 **Short-lived accounts (created+deleted same period)**: {', '.join(list(short_lived)[:5])}")

    # CRITICAL incidents
    crit_incidents = [i for i in data["incidents"] if i["severity"] == "CRITICAL"]
    if crit_incidents:
        high_priority.append(f"🔴 **{len(crit_incidents)} CRITICAL incident(s) active**")

    if high_priority:
        lines += ["## ⚠️ High Priority — Action Required", ""]
        for h in high_priority:
            lines.append(f"- {h}")
        lines.append("")

    # ── AD SECURITY ────────────────────────────────────────────────
    if focus in ("all", "ad"):
        lines += ["## Active Directory Events", ""]

        # Account lifecycle
        if data["account_events"]:
            lines += [f"**Account Changes** ({len(data['account_events'])} events):", ""]
            # Group by event type
            by_type = defaultdict(list)
            for e in data["account_events"]:
                raw = e.get("rawEventMsg","").lower()
                etype = ("Created"  if "4720" in e.get("eventType","") or "created" in raw else
                         "Deleted"  if "4726" in e.get("eventType","") or "deleted" in raw else
                         "Disabled" if "4725" in e.get("eventType","") or "disabled" in raw else
                         "Enabled"  if "4722" in e.get("eventType","") or "enabled" in raw else
                         "Modified")
                by_type[etype].append(e)
            for etype, events in by_type.items():
                flag = "🔴" if etype == "Created" or etype == "Deleted" else "🟡"
                lines.append(f"{flag} **{etype}**: {len(events)} accounts — "
                              f"{', '.join(set(e.get('targetUser','?') for e in events[:3]))}")
        else:
            lines.append("✅ No account lifecycle changes")

        lines.append("")

        # Group membership
        if data["group_events"]:
            lines += [f"**Group Membership Changes** ({len(data['group_events'])} events):", ""]
            for e in data["group_events"][:8]:
                group = e.get("targetGroup","unknown group")
                user_changed = e.get("targetUser","unknown")
                actor = e.get("user","unknown")
                t = e.get("eventTime","")[:16]
                flag = "🔴" if "admin" in group.lower() else "🟡"
                lines.append(f"  {flag} `{t}` | **{user_changed}** added/removed from **{group}** by {actor}")
        else:
            lines.append("✅ No group membership changes")

        lines.append("")

    # ── AUTHENTICATION ─────────────────────────────────────────────
    if focus in ("all", "auth"):
        lines += ["## Authentication", ""]

        # Failed logins
        high_fail = [e for e in data["failed_events"]
                     if int(e.get("fail_count","0") or "0") >= 5]
        if high_fail:
            lines += [f"**High Failure Rate Accounts** ({len(high_fail)}):", ""]
            for e in sorted(high_fail, key=lambda x: int(x.get("fail_count","0") or "0"), reverse=True)[:5]:
                lines.append(f"  🟡 `{e.get('user','?')}` — {e.get('fail_count','?')} failures from `{e.get('srcIpAddr','?')}`")
        else:
            lines.append("✅ No accounts with high failure rate")

        lines.append("")

        # Off-hours privileged logons
        off_hours = []
        for e in data["offhours_events"]:
            t = e.get("eventTime","")
            if t:
                try:
                    hour = datetime.fromisoformat(t[:19]).hour
                    if hour < 6 or hour >= 22:
                        off_hours.append(e)
                except Exception:
                    pass

        if off_hours:
            lines += [f"**Off-Hours Logons** ({len(off_hours)}):", ""]
            for e in off_hours[:5]:
                lines.append(f"  🟡 `{e.get('eventTime','')[:16]}` | {e.get('user','?')} from `{e.get('srcIpAddr','?')}` on {e.get('hostName','?')}")
        else:
            lines.append("✅ No off-hours logons detected")

        lines.append("")

    # ── INCIDENTS ──────────────────────────────────────────────────
    if focus in ("all", "incidents"):
        lines += ["## Active Incidents", ""]
        if data["incidents"]:
            lines += ["| Severity | ID | Title | Time |", "|---|---|---|---|"]
            for inc in data["incidents"][:15]:
                flag = "🔴" if inc["severity"] == "CRITICAL" else "🟠"
                lines.append(f"| {flag} {inc['severity']} | #{inc['id']} | "
                              f"{inc['title'][:50]} | {inc['time'][:16]} |")
        else:
            lines.append("✅ No active HIGH/CRITICAL incidents")

    lines += ["", "---",
              f"*Run `/fsiem-l1-triage` to process the alert queue | `/fsiem-health` for log source status*"]
    return "\n".join(lines)
```
