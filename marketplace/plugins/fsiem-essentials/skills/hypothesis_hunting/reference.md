# Hypothesis Hunting — Python Implementation Reference

Full Python implementations for the queries shown in [SKILL.md](SKILL.md).

## run_query helper

```python
import os, time, base64, requests, xml.etree.ElementTree as ET

def fsiem_verify_ssl():
    return os.environ.get("FSIEM_VERIFY_SSL", "false").lower() == "true"

def fsiem_headers():
    user = os.environ["FSIEM_USER"]
    org  = os.environ["FSIEM_ORG"]
    pw   = os.environ["FSIEM_PASS"]
    token = base64.b64encode(f"{user}/{org}:{pw}".encode()).decode()
    return {"Authorization": f"Basic {token}", "Content-Type": "text/xml"}

def run_query(query_xml: str, max_results: int = 500) -> list:
    host = os.environ["FSIEM_HOST"]
    h = fsiem_headers()
    r = requests.post(f"{host}/phoenix/rest/query/eventQuery",
                      data=query_xml, headers=h, verify=fsiem_verify_ssl(), timeout=30)
    r.raise_for_status()
    qid = r.text.strip()
    for _ in range(90):
        p = requests.get(f"{host}/phoenix/rest/query/progress/{qid}",
                         headers=h, verify=fsiem_verify_ssl(), timeout=10)
        if int(p.text.strip() or "0") >= 100:
            break
        time.sleep(2)
    r2 = requests.get(f"{host}/phoenix/rest/query/events/{qid}/0/{max_results}",
                      headers=h, verify=fsiem_verify_ssl(), timeout=30)
    root = ET.fromstring(r2.text)
    return [{a.findtext("name",""): a.findtext("value","")
             for a in ev.findall("attributes/attribute")}
            for ev in root.findall(".//event")]
```

## Execute Hunt and Score Findings

```python
def run_hunt(query_xml: str, days: int, hypothesis: str) -> dict:
    events = run_query(query_xml, max_results=500)
    if not events:
        return {"hypothesis": hypothesis, "result": "NOT FOUND", "events": []}

    # Score each hit
    scored = []
    known_dest = set()
    for e in events:
        score = 0
        dest = e.get("destIpAddr", "")
        if dest and dest not in known_dest:
            score += 3
            known_dest.add(dest)
        try:
            from datetime import datetime
            t = datetime.strptime(e["eventTime"][:19], "%Y-%m-%d %H:%M:%S")
            if not (7 <= t.hour < 19):
                score += 2
        except (KeyError, ValueError):
            pass
        if score > 0:
            scored.append({"event": e, "score": score})

    top = sorted(scored, key=lambda x: x["score"], reverse=True)
    max_score = top[0]["score"] if top else 0

    return {
        "hypothesis": hypothesis,
        "result": "CONFIRMED" if max_score >= 5 else "POSSIBLE" if max_score >= 3 else "LOW CONFIDENCE",
        "event_count": len(events),
        "top_findings": top[:5],
        "all_events": events[:50],
    }
```

## Full Hunt Report Generator

```python
from datetime import datetime

def generate_hunt_report(hypothesis: str, results: dict, analyst: str = "SOC Analyst") -> str:
    return f"""## Threat Hunt Report
**Hypothesis**: {hypothesis}
**Analyst**: {analyst}
**Date**: {datetime.now().strftime("%Y-%m-%d %H:%M")}
**Result**: {results["result"]}

### Evidence
- Events found: {results["event_count"]}
- Top finding score: {results["top_findings"][0]["score"] if results["top_findings"] else 0}

### Sample Events
{chr(10).join(
    f"- {e['event'].get('eventTime','')} | {e['event'].get('eventType','')} | "
    f"{e['event'].get('srcIpAddr','')} → {e['event'].get('destIpAddr','')}"
    for e in results["top_findings"][:3]
)}

### Recommended Next Steps
{"- Escalate immediately — evidence score >= 5" if results["result"] == "CONFIRMED"
 else "- Continue monitoring — run again in 7 days" if results["result"] == "LOW CONFIDENCE"
 else "- Investigate further — moderate evidence found"}
"""
```
