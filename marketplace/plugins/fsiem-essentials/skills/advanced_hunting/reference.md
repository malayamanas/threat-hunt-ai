---
name: fsiem-advanced-hunt-reference  
description: Stack counting, impossible travel, and Office process tree hunting implementations. See SKILL.md for beacon analysis and DNS long-tail.
---

# Advanced Hunting — Reference Implementation

See [SKILL.md](SKILL.md) for beacon CV analysis and DNS long-tail.

## Technique 3 — Stack Counting (Day 25)

```python
def stack_count_processes(
    days_back: int = 7,
    bottom_percentile: float = 1.0,
    exclude_common: bool = True,
) -> list:
    """
    Stack count process names across all endpoints.
    Sort ascending — the rarest processes at the bottom are your hunting ground.

    Legitimate software: consistent process names across many machines.
    Malware: unique or rare process names that appear on 1-2 machines.

    Returns bottom N% sorted by occurrence count ascending.
    """
    host = os.environ["FSIEM_HOST"]
    h = fsiem_headers()
    v = fsiem_verify_ssl()

    # Common legitimate process names to exclude (reduce noise)
    COMMON_PROCESSES = {
        "svchost.exe", "lsass.exe", "csrss.exe", "wininit.exe", "services.exe",
        "explorer.exe", "taskhostw.exe", "spoolsv.exe", "winlogon.exe",
        "chrome.exe", "msedge.exe", "firefox.exe", "outlook.exe", "excel.exe",
        "winword.exe", "powerpnt.exe", "msiexec.exe", "conhost.exe",
        "backgroundtaskhost.exe", "dllhost.exe", "rundll32.exe",
    }

    query_xml = f"""<Reports><Report><n>Process Stack Count</n>
      <SelectClause><AttrList>processName,hostName,COUNT(eventId) AS count</AttrList></SelectClause>
      <ReportInterval><Window>Last {days_back} days</Window></ReportInterval>
      <PatternClause><SubPattern><Filters>
        <Filter><n>eventType</n><Operator>IN</Operator>
          <Value>Process Launch,Process Create,Sysmon-1,Win-Security-4688</Value></Filter>
      </Filters></SubPattern></PatternClause></Report></Reports>"""

    r = requests.post(f"{host}/phoenix/rest/query/eventQuery",
                      data=query_xml, headers=h, verify=v, timeout=30)
    r.raise_for_status()
    qid = r.text.strip()
    for _ in range(90):
        p = requests.get(f"{host}/phoenix/rest/query/progress/{qid}",
                         headers=h, verify=v, timeout=10)
        if int(p.text.strip() or "0") >= 100: break
        time.sleep(2)
    r2 = requests.get(f"{host}/phoenix/rest/query/events/{qid}/0/2000",
                      headers=h, verify=v, timeout=30)
    root = ET.fromstring(r2.text)

    process_counts = defaultdict(lambda: {"count": 0, "hosts": set()})
    for ev in root.findall(".//event"):
        attrs = {a.findtext("name",""): a.findtext("value","")
                 for a in ev.findall("attributes/attribute")}
        proc = attrs.get("processName","").lower().strip()
        host_name = attrs.get("hostName","")
        count = int(attrs.get("count","1") or "1")
        if not proc: continue
        if exclude_common and proc in COMMON_PROCESSES: continue
        process_counts[proc]["count"] += count
        if host_name:
            process_counts[proc]["hosts"].add(host_name)

    all_processes = [
        {
            "process_name":  proc,
            "total_count":   data["count"],
            "unique_hosts":  len(data["hosts"]),
            "hosts_sample":  list(data["hosts"])[:3],
            "suspicion":     (
                "HIGH"   if data["count"] <= 3 and len(data["hosts"]) == 1 else
                "MEDIUM" if data["count"] <= 10 else
                "LOW"
            ),
        }
        for proc, data in process_counts.items()
    ]
    all_processes.sort(key=lambda x: x["total_count"])

    # Return bottom percentile
    cutoff = max(1, int(len(all_processes) * bottom_percentile / 100))
    return all_processes[:cutoff]
```

## Technique 4 — Impossible Travel Detection (Day 26)

```python
def hunt_impossible_travel(
    days_back: int = 30,
    baseline_days: int = 30,
) -> list:
    """
    Detect accounts authenticating from countries not in their baseline.
    Most reliable APT initial access indicator — valid credentials used
    from attacker infrastructure in a country the user never operates from.
    """
    host = os.environ["FSIEM_HOST"]
    h = fsiem_headers()
    v = fsiem_verify_ssl()
    import time as time_module

    def query_auth_with_country(window: str) -> list:
        q = f"""<Reports><Report><n>Auth Country Analysis</n>
          <SelectClause><AttrList>user,srcIpAddr,srcCountry,eventTime,hostName</AttrList></SelectClause>
          <ReportInterval><Window>{window}</Window></ReportInterval>
          <PatternClause><SubPattern><Filters>
            <Filter><n>eventType</n><Operator>IN</Operator>
              <Value>Successful Login,Win-Security-4624,VPN-Login,RADIUS-Auth</Value></Filter>
            <Filter><n>srcCountry</n><Operator>NOT_EMPTY</Operator><Value></Value></Filter>
          </Filters></SubPattern></PatternClause></Report></Reports>"""
        r = requests.post(f"{host}/phoenix/rest/query/eventQuery",
                          data=q, headers=h, verify=v, timeout=30)
        r.raise_for_status()
        qid = r.text.strip()
        for _ in range(60):
            p = requests.get(f"{host}/phoenix/rest/query/progress/{qid}",
                             headers=h, verify=v, timeout=10)
            if int(p.text.strip() or "0") >= 100: break
            time_module.sleep(2)
        r2 = requests.get(f"{host}/phoenix/rest/query/events/{qid}/0/2000",
                          headers=h, verify=v, timeout=30)
        root = ET.fromstring(r2.text)
        events = []
        for ev in root.findall(".//event"):
            attrs = {a.findtext("name",""): a.findtext("value","")
                     for a in ev.findall("attributes/attribute")}
            if attrs.get("user") and attrs.get("srcCountry"):
                events.append(attrs)
        return events

    # Build country baseline per user
    baseline_events = query_auth_with_country(f"Last {baseline_days} days")
    user_countries = defaultdict(set)
    for e in baseline_events:
        user = e.get("user","").lower()
        country = e.get("srcCountry","").upper()
        if user and country and country not in ("", "UNKNOWN", "N/A"):
            user_countries[user].add(country)

    # Get recent logins (last 24h-48h)
    recent_events = query_auth_with_country("Last 48 hours")

    findings = []
    for e in recent_events:
        user = e.get("user","").lower()
        country = e.get("srcCountry","").upper()
        if not user or not country: continue
        baseline = user_countries.get(user, set())
        if not baseline: continue  # No history = can't assess

        if country not in baseline:
            findings.append({
                "user":             e.get("user",""),
                "new_country":      country,
                "src_ip":           e.get("srcIpAddr",""),
                "event_time":       e.get("eventTime",""),
                "known_countries":  list(baseline),
                "host":             e.get("hostName",""),
                "confidence":       "HIGH" if len(baseline) >= 5 else "MEDIUM",
                "note":             f"Account baseline: {', '.join(sorted(baseline))}. New login from: {country}",
            })

    return sorted(findings, key=lambda x: x["confidence"] == "HIGH", reverse=True)
```

## Technique 5 — Office Process Tree Anomaly (Day 27)

```python
def hunt_office_spawned_shells(
    days_back: int = 14,
) -> list:
    """
    Hunt for Office applications spawning execution engines.
    In a clean environment: zero results.
    One result: immediate L2 investigation — T1566 → T1059 kill chain.

    Parent processes: Word, Excel, Outlook, PowerPoint, OneNote, Access
    Suspicious children: cmd, powershell, wscript, cscript, mshta, certutil,
                         rundll32 (with URL), regsvr32, msbuild, installutil
    """
    host = os.environ["FSIEM_HOST"]
    h = fsiem_headers()
    v = fsiem_verify_ssl()

    OFFICE_PARENTS = [
        "winword.exe", "excel.exe", "outlook.exe", "powerpnt.exe",
        "onenote.exe", "msaccess.exe", "mspub.exe", "visio.exe",
        "teams.exe",  # Teams is increasingly abused
    ]

    SUSPICIOUS_CHILDREN = [
        "cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe",
        "mshta.exe", "certutil.exe", "rundll32.exe", "regsvr32.exe",
        "msbuild.exe", "installutil.exe", "cmstp.exe", "wmic.exe",
        "bitsadmin.exe", "curl.exe", "wget.exe",
    ]

    parent_filter = "|".join(OFFICE_PARENTS)
    child_filter  = "|".join(SUSPICIOUS_CHILDREN)

    query_xml = f"""<Reports><Report><n>Office Process Tree</n>
      <SelectClause><AttrList>eventTime,processName,parentProcessName,user,hostName,rawEventMsg</AttrList></SelectClause>
      <ReportInterval><Window>Last {days_back} days</Window></ReportInterval>
      <PatternClause><SubPattern><Filters>
        <Filter><n>eventType</n><Operator>IN</Operator>
          <Value>Process Launch,Process Create,Sysmon-1,Win-Security-4688</Value></Filter>
        <Filter><n>parentProcessName</n><Operator>REGEXP</Operator>
          <Value>{parent_filter}</Value></Filter>
        <Filter><n>processName</n><Operator>REGEXP</Operator>
          <Value>{child_filter}</Value></Filter>
      </Filters></SubPattern></PatternClause></Report></Reports>"""

    r = requests.post(f"{host}/phoenix/rest/query/eventQuery",
                      data=query_xml, headers=h, verify=v, timeout=30)
    r.raise_for_status()
    qid = r.text.strip()
    for _ in range(60):
        p = requests.get(f"{host}/phoenix/rest/query/progress/{qid}",
                         headers=h, verify=v, timeout=10)
        if int(p.text.strip() or "0") >= 100: break
        time.sleep(2)
    r2 = requests.get(f"{host}/phoenix/rest/query/events/{qid}/0/200",
                      headers=h, verify=v, timeout=30)
    root = ET.fromstring(r2.text)

    findings = []
    for ev in root.findall(".//event"):
        attrs = {a.findtext("name",""): a.findtext("value","")
                 for a in ev.findall("attributes/attribute")}
        parent = attrs.get("parentProcessName","").lower()
        child  = attrs.get("processName","").lower()
        if not parent or not child: continue

        # Enrich with command line if available
        raw = attrs.get("rawEventMsg","")
        cmdline = ""
        for kw in ["CommandLine", "command_line", "Image"]:
            if kw in raw:
                start = raw.find(kw) + len(kw) + 1
                cmdline = raw[start:start+200].split("\n")[0].strip()
                break

        findings.append({
            "event_time":    attrs.get("eventTime",""),
            "parent":        parent,
            "child":         child,
            "user":          attrs.get("user",""),
            "host":          attrs.get("hostName",""),
            "cmdline":       cmdline,
            "severity":      "CRITICAL",
            "mitre":         "T1566.001 → T1059 (Phishing → Script Execution)",
            "action":        "Immediate L2 investigation — isolate host if cmdline contains URL/encoded content",
        })

    return findings
```

## Combined Advanced Hunt Report

```python
def run_advanced_hunt_report(days_back: int = 7) -> str:
    """Run all 5 advanced hunting techniques and produce a combined report."""
    lines = [
        f"# Advanced Hunt Report",
        f"**Generated**: {datetime.now().strftime('%Y-%m-%d %H:%M')} | **Period**: Last {days_back} days",
        "",
    ]

    # 1. Beacons
    lines += ["## 🔴 Beacon Candidates (CV Analysis)", ""]
    try:
        beacons = hunt_beacons(days_back=days_back)
        if beacons:
            lines += ["| Src IP | Dest IP | Port | CV | Interval | Connections | Dwell | Confidence |",
                      "|---|---|---|---|---|---|---|---|"]
            for b in beacons[:10]:
                lines.append(f"| `{b['src_ip']}` | `{b['dest_ip']}` | {b['dest_port']} | "
                              f"{b['cv']} | {b['mean_interval_human']} | {b['connection_count']} | "
                              f"{b['dwell_days']}d | {b['confidence']} |")
        else:
            lines.append("✅ No beacon candidates found")
    except Exception as e:
        lines.append(f"⚠️ Beacon analysis failed: {e}")

    # 2. DNS tunneling
    lines += ["", "## 🔴 DNS Tunneling Candidates", ""]
    try:
        dns = hunt_dns_tunneling(days_back=max(days_back, 14))
        if dns:
            lines += ["| Domain | Unique Subdomains | Avg Length | Confidence |",
                      "|---|---|---|---|"]
            for d in dns[:10]:
                lines.append(f"| `{d['parent_domain']}` | {d['unique_subdomains']} | "
                              f"{d['avg_subdomain_length']} chars | {d['confidence']} |")
        else:
            lines.append("✅ No DNS tunneling candidates found")
    except Exception as e:
        lines.append(f"⚠️ DNS analysis failed: {e}")

    # 3. Stack counting
    lines += ["", "## 🔍 Rare Process Stack Count (bottom 1%)", ""]
    try:
        rare = stack_count_processes(days_back=days_back, bottom_percentile=1.0)
        if rare:
            lines += ["| Process | Count | Hosts | Suspicion |", "|---|---|---|---|"]
            for p in rare[:15]:
                hosts = ", ".join(p["hosts_sample"][:2])
                lines.append(f"| `{p['process_name']}` | {p['total_count']} | "
                              f"{p['unique_hosts']} ({hosts}) | {p['suspicion']} |")
        else:
            lines.append("✅ No rare processes found")
    except Exception as e:
        lines.append(f"⚠️ Stack count failed: {e}")

    # 4. Impossible travel
    lines += ["", "## 🌍 Impossible Travel / New Country Logins", ""]
    try:
        travel = hunt_impossible_travel()
        if travel:
            for t in travel[:10]:
                lines.append(f"- **{t['user']}** logged in from **{t['new_country']}** "
                              f"at {t['event_time'][:16]} from `{t['src_ip']}`")
                lines.append(f"  Known countries: {', '.join(t['known_countries'])} | "
                              f"Confidence: {t['confidence']}")
        else:
            lines.append("✅ No impossible travel detected")
    except Exception as e:
        lines.append(f"⚠️ Travel analysis failed: {e}")

    # 5. Office process tree
    lines += ["", "## 🔴 Office Application Spawning Shells (CRITICAL if any)", ""]
    try:
        office = hunt_office_spawned_shells(days_back=days_back)
        if office:
            for o in office:
                lines.append(f"- **CRITICAL** `{o['host']}` | `{o['parent']}` → `{o['child']}` | "
                              f"User: {o['user']} | {o['event_time'][:16]}")
                if o['cmdline']:
                    lines.append(f"  Command: `{o['cmdline'][:80]}`")
        else:
            lines.append("✅ No Office shell spawning detected")
    except Exception as e:
        lines.append(f"⚠️ Process tree analysis failed: {e}")

    return "\n".join(lines)
```
