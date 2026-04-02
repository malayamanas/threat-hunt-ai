## ATT&CK Data Source Map

Full technique → data component → FortiSIEM event type mappings for 15 techniques
(T1133, T1078, T1190, T1566, T1059, T1053, T1547, T1055, T1562, T1110, T1003, T1558, T1046, T1087, T1021, T1550, T1041, T1486).

See [reference.md](reference.md) for the complete `ATTACK_DATASOURCE_MAP` dict.

```python
# The full map is in reference.md — copy ATTACK_DATASOURCE_MAP into your session
# Or reference it directly when using the analysis functions below
```

## Step 1 — Answer "What Logs Do I Need for Technique X?"

```python
import os, base64, requests, xml.etree.ElementTree as ET

def fsiem_headers():
    user, org, pw = os.environ["FSIEM_USER"], os.environ["FSIEM_ORG"], os.environ["FSIEM_PASS"]
    return {"Authorization": f"Basic {base64.b64encode(f'{user}/{org}:{pw}'.encode()).decode()}",
            "Content-Type": "text/xml"}

def fsiem_verify_ssl():
    return os.environ.get("FSIEM_VERIFY_SSL", "false").lower() == "true"

def what_logs_for_technique(technique_id: str) -> str:
    """
    Anton's Day 1 use case: given a technique ID, return exactly what logs
    you need in FortiSIEM to detect it — with collection source guidance.
    """
    tech = ATTACK_DATASOURCE_MAP.get(technique_id.upper())
    if not tech:
        return f"Technique {technique_id} not in library. Supported: {list(ATTACK_DATASOURCE_MAP.keys())}"

    lines = [
        f"# Detection Requirements: {technique_id} — {tech['name']}",
        f"**Tactic**: {tech['tactic']} | **Priority**: {tech['priority']}",
        "",
        "## Required Data Sources",
        "",
    ]

    for component, details in tech["data_components"].items():
        coverage_emoji = {"FULL": "✅", "PARTIAL": "🟡", "LOW": "🔴"}.get(details["coverage"], "⚪")
        lines += [
            f"### {coverage_emoji} {component}",
            f"**FortiSIEM Event Types**: `{'`, `'.join(details['fortisiem_event_types'][:4])}`",
            f"**Must collect from**: {', '.join(details['collection_sources'])}",
        ]
        if details.get("gap_note"):
            lines.append(f"⚠️ **Note**: {details['gap_note']}")
        lines.append("")

    lines += [
        "## FortiSIEM Hunt Query (if data is available)",
        "",
        f"~~~xml",
        f"<!-- Query for {technique_id} indicators -->",
        f"<Reports><Report><n>Hunt {technique_id}</n>",
        f"  <SelectClause><AttrList>eventTime,eventType,srcIpAddr,destIpAddr,user,hostName,rawEventMsg</AttrList></SelectClause>",
        f"  <ReportInterval><Window>Last 7 days</Window></ReportInterval>",
        f"  <PatternClause><SubPattern><Filters>",
        f"    <Filter><n>eventType</n><Operator>IN</Operator>",
        f"    <Value>{','.join(list(tech['data_components'].values())[0]['fortisiem_event_types'][:3])}</Value>",
        f"    </Filter>",
        f"  </Filters></SubPattern></PatternClause>",
        f"</Report></Reports>",
        f"~~~",
    ]
    return "\n".join(lines)
```

## Step 2 — FortiSIEM Data Source Coverage Analysis (Anton's Day 10)

```python
def get_fortisiem_event_types_present(days_back: int = 7) -> set:
    """
    Query FortiSIEM to find what event types are actually present in your data.
    This is the key function — it tells you what you CAN detect vs what you can't.
    """
    host = os.environ["FSIEM_HOST"]
    import time

    query_xml = f"""<Reports><Report><n>Event Type Inventory</n>
      <SelectClause><AttrList>eventType,COUNT(eventId) AS event_count</AttrList></SelectClause>
      <ReportInterval><Window>Last {days_back} days</Window></ReportInterval>
      <PatternClause><SubPattern><Filters></Filters></SubPattern></PatternClause>
    </Report></Reports>"""

    r = requests.post(f"{host}/phoenix/rest/query/eventQuery",
                      data=query_xml, headers=fsiem_headers(),
                      verify=fsiem_verify_ssl(), timeout=30)
    r.raise_for_status()
    qid = r.text.strip()
    for _ in range(60):
        p = requests.get(f"{host}/phoenix/rest/query/progress/{qid}",
                         headers=fsiem_headers(), verify=fsiem_verify_ssl(), timeout=10)
        if int(p.text.strip() or "0") >= 100: break
        time.sleep(2)
    r2 = requests.get(f"{host}/phoenix/rest/query/events/{qid}/0/1000",
                      headers=fsiem_headers(), verify=fsiem_verify_ssl(), timeout=30)
    root = ET.fromstring(r2.text)
    event_types = set()
    for ev in root.findall(".//event"):
        for attr in ev.findall("attributes/attribute"):
            if attr.findtext("name") == "eventType":
                val = attr.findtext("value","")
                if val:
                    event_types.add(val)
    return event_types

def analyze_datasource_coverage(present_event_types: set = None) -> dict:
    """
    Anton's Day 10: map ATT&CK data sources to what's actually in FortiSIEM.
    Returns per-technique coverage + 'biggest bang for buck' data source gaps.

    present_event_types: pass result of get_fortisiem_event_types_present()
                         or None to use simulation mode
    """
    coverage = {}
    data_source_value = {}  # track how many techniques each data source enables

    for tech_id, tech in ATTACK_DATASOURCE_MAP.items():
        tech_coverage = {"name": tech["name"], "tactic": tech["tactic"],
                         "priority": tech["priority"], "components": {}}
        any_covered = False
        fully_covered = True

        for component, details in tech["data_components"].items():
            if present_event_types:
                # Real coverage check: does FortiSIEM have ANY of the required event types?
                matches = [et for et in details["fortisiem_event_types"]
                           if any(et.lower() in pet.lower() or pet.lower() in et.lower()
                                  for pet in present_event_types)]
                covered = len(matches) > 0
            else:
                # Simulation: assume partial coverage for common types
                covered = details["coverage"] in ("FULL", "PARTIAL")

            tech_coverage["components"][component] = {
                "covered": covered,
                "coverage_level": details["coverage"],
                "gap_note": details.get("gap_note"),
                "collection_sources": details["collection_sources"],
            }

            if covered:
                any_covered = True
                # Track data source value
                for src in details["collection_sources"]:
                    data_source_value[src] = data_source_value.get(src, 0) + 1
            else:
                fully_covered = False
                for src in details["collection_sources"]:
                    data_source_value[src] = data_source_value.get(src, 0) + 1

        tech_coverage["overall_coverage"] = (
            "FULL"    if fully_covered and any_covered else
            "PARTIAL" if any_covered else
            "NONE"
        )
        coverage[tech_id] = tech_coverage

    return {
        "technique_coverage": coverage,
        "data_source_value":  sorted(data_source_value.items(), key=lambda x: -x[1]),
    }

def generate_datasource_gap_report(present_event_types: set = None) -> str:
    """Generate the full data source coverage report — Anton's Day 10 output."""
    result = analyze_datasource_coverage(present_event_types)
    coverage = result["technique_coverage"]
    ds_value = result["data_source_value"]

    full     = {k: v for k, v in coverage.items() if v["overall_coverage"] == "FULL"}
    partial  = {k: v for k, v in coverage.items() if v["overall_coverage"] == "PARTIAL"}
    none_cov = {k: v for k, v in coverage.items() if v["overall_coverage"] == "NONE"}

    crit_gaps = {k: v for k, v in none_cov.items() if v["priority"] == "CRITICAL"}

    lines = [
        "# ATT&CK Data Source Coverage Report",
        f"**Techniques analyzed**: {len(coverage)} | "
        f"**Full coverage**: {len(full)} | "
        f"**Partial**: {len(partial)} | "
        f"**No coverage (data missing)**: {len(none_cov)}",
        "",
        "## Coverage by Technique",
        "",
        "| Technique | Name | Priority | Coverage | Missing Data Source |",
        "|---|---|---|---|---|",
    ]

    for tech_id, tech in coverage.items():
        emoji = {"FULL":"✅","PARTIAL":"🟡","NONE":"🔴"}.get(tech["overall_coverage"],"⚪")
        missing = ""
        if tech["overall_coverage"] != "FULL":
            missing_srcs = []
            for comp, details in tech["components"].items():
                if not details["covered"]:
                    missing_srcs.extend(details["collection_sources"][:1])
            missing = ", ".join(set(missing_srcs))[:40]
        lines.append(f"| {tech_id} | {tech['name']} | {tech['priority']} | {emoji} {tech['overall_coverage']} | {missing} |")

    if crit_gaps:
        lines += [
            "",
            "## 🔴 Critical Techniques with NO Coverage",
            "_These are undetectable because the required data is not in FortiSIEM_",
            "",
        ]
        for tech_id, tech in crit_gaps.items():
            lines.append(f"**{tech_id} — {tech['name']}** ({tech['tactic']})")
            for comp, details in tech["components"].items():
                lines.append(f"  - Need: {', '.join(details['collection_sources'])}")
                if details.get("gap_note"):
                    lines.append(f"  - How to fix: {details['gap_note']}")
            lines.append("")

    lines += [
        "## 📊 Biggest Bang for Buck — Data Sources to Enable",
        "_Enable these data sources to unlock detection of the most techniques_",
        "",
        "| Data Source | Techniques Enabled | Action |",
        "|---|---|---|",
    ]
    for ds, count in ds_value[:10]:
        lines.append(f"| {ds} | +{count} techniques | Enable ingestion in FortiSIEM |")

    return "\n".join(lines)
```

## Quick Query: Data Sources for Any Technique

```python
# Answer: "What logs do I need to detect VPN compromise?" (Anton's Day 1 example)
print(what_logs_for_technique("T1078"))  # Valid Accounts — primary VPN technique
print(what_logs_for_technique("T1110"))  # Brute Force — credential stuffing

# Run full coverage analysis against your live FortiSIEM
event_types = get_fortisiem_event_types_present(days_back=7)
print(f"FortiSIEM has {len(event_types)} distinct event types in last 7 days")
report = generate_datasource_gap_report(event_types)
print(report)
```
