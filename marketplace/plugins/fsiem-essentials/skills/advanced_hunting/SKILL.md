---
name: fsiem-advanced-hunt
description: Advanced mathematical threat hunting techniques for FortiSIEM — beacon analysis with jitter-aware coefficient of variation, DNS long-tail subdomain analysis, stack counting for rare process detection, impossible travel credential anomaly, and Office application process tree hunting. These are Week 4 hunting techniques that find what keyword rules cannot.
---

# Advanced Hunting Techniques

These techniques work on statistical anomaly — finding what's rare, regular, or out of pattern — rather than signature matching. They require FortiSIEM event data + post-processing.

## Technique 1 — Mathematical Beacon Detection (Day 23)

A C2 beacon has regularity. A human browsing does not. Measure it mathematically.

```python
import os, base64, requests, xml.etree.ElementTree as ET, time, math
from datetime import datetime, timedelta
from collections import defaultdict

def fsiem_headers():
    user, org, pw = os.environ["FSIEM_USER"], os.environ["FSIEM_ORG"], os.environ["FSIEM_PASS"]
    return {"Authorization": f"Basic {base64.b64encode(f'{user}/{org}:{pw}'.encode()).decode()}",
            "Content-Type": "text/xml"}

def fsiem_verify_ssl():
    return os.environ.get("FSIEM_VERIFY_SSL","false").lower() == "true"

def hunt_beacons(
    days_back: int = 7,
    min_connections: int = 24,   # at least 24 connections over period
    max_cv: float = 0.40,        # CV below 0.4 = suspiciously regular
    jitter_tolerance: float = 0.25,
) -> list:
    """
    Beacon detection using Coefficient of Variation (CV = StdDev/Mean).

    CV < 0.3  = almost perfectly regular → high confidence C2
    CV < 0.4  = regular with jitter (Cobalt Strike default ~0.2 ± jitter)
    CV > 1.0  = irregular → normal human browsing

    Returns candidates sorted by CV ascending (most regular first).
    """
    host = os.environ["FSIEM_HOST"]
    h = fsiem_headers()
    v = fsiem_verify_ssl()

    # Query all outbound connections with timestamps
    query_xml = f"""<Reports><Report><n>Beacon Candidates</n>
      <SelectClause><AttrList>srcIpAddr,destIpAddr,destPort,eventTime,sentBytes</AttrList></SelectClause>
      <ReportInterval><Window>Last {days_back} days</Window></ReportInterval>
      <PatternClause><SubPattern><Filters>
        <Filter><n>eventType</n><Operator>IN</Operator>
          <Value>Network Connection,Firewall Allow,Proxy Access</Value></Filter>
        <Filter><n>destIpAddr</n><Operator>NOT_IN</Operator>
          <Value>10.0.0.0/8,172.16.0.0/12,192.168.0.0/16</Value></Filter>
        <Filter><n>destPort</n><Operator>IN</Operator>
          <Value>80,443,8080,8443,4444,5555,1080</Value></Filter>
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
    r2 = requests.get(f"{host}/phoenix/rest/query/events/{qid}/0/5000",
                      headers=h, verify=v, timeout=30)
    root = ET.fromstring(r2.text)

    # Group connections by src→dest→port
    pairs = defaultdict(list)
    for ev in root.findall(".//event"):
        attrs = {a.findtext("name",""): a.findtext("value","")
                 for a in ev.findall("attributes/attribute")}
        key = f"{attrs.get('srcIpAddr','')}->{attrs.get('destIpAddr','')}:{attrs.get('destPort','')}"
        t = attrs.get("eventTime","")
        if t:
            try:
                pairs[key].append({
                    "time": datetime.fromisoformat(t[:19]),
                    "bytes": int(attrs.get("sentBytes","0") or "0"),
                    "src": attrs.get("srcIpAddr",""),
                    "dest": attrs.get("destIpAddr",""),
                    "port": attrs.get("destPort",""),
                })
            except Exception:
                pass

    candidates = []
    for pair_key, events in pairs.items():
        if len(events) < min_connections:
            continue

        events_sorted = sorted(events, key=lambda x: x["time"])

        # Calculate inter-connection intervals in seconds
        intervals = [
            (events_sorted[i+1]["time"] - events_sorted[i]["time"]).total_seconds()
            for i in range(len(events_sorted)-1)
        ]
        if len(intervals) < 3:
            continue

        mean_interval = sum(intervals) / len(intervals)
        if mean_interval <= 0:
            continue

        variance = sum((x - mean_interval)**2 for x in intervals) / len(intervals)
        std_dev = math.sqrt(variance)
        cv = std_dev / mean_interval

        # Jitter-aware: also check if intervals cluster around base period
        # even if raw CV is higher (malware adds random jitter)
        base_period = mean_interval
        jitter_range = base_period * jitter_tolerance
        within_jitter = sum(1 for i in intervals
                           if abs(i - base_period) <= jitter_range)
        jitter_score = within_jitter / len(intervals)

        avg_bytes = sum(e["bytes"] for e in events) / len(events)

        if cv <= max_cv or (jitter_score >= 0.75 and cv <= 0.6):
            first_ev = events_sorted[0]
            candidates.append({
                "src_ip":           first_ev["src"],
                "dest_ip":          first_ev["dest"],
                "dest_port":        first_ev["port"],
                "connection_count": len(events),
                "cv":               round(cv, 3),
                "mean_interval_s":  round(mean_interval, 1),
                "mean_interval_human": _seconds_to_human(mean_interval),
                "jitter_score":     round(jitter_score, 2),
                "avg_bytes":        round(avg_bytes, 0),
                "first_seen":       events_sorted[0]["time"].isoformat(),
                "last_seen":        events_sorted[-1]["time"].isoformat(),
                "dwell_days":       round((events_sorted[-1]["time"] - events_sorted[0]["time"]).days, 0),
                "confidence":       "HIGH"   if cv <= 0.2 else
                                    "HIGH"   if jitter_score >= 0.85 else
                                    "MEDIUM" if cv <= 0.3 else "LOW",
            })

    return sorted(candidates, key=lambda x: x["cv"])

def _seconds_to_human(seconds: float) -> str:
    if seconds < 60:   return f"{round(seconds)}s"
    if seconds < 3600: return f"{round(seconds/60)}m"
    return f"{round(seconds/3600, 1)}h"
```

## Technique 2 — DNS Long-Tail Analysis (Day 24)

```python
def hunt_dns_tunneling(
    days_back: int = 30,
    min_unique_subdomains: int = 20,
    min_avg_subdomain_length: int = 25,
) -> list:
    """
    DNS tunneling detection using subdomain analysis.

    Legitimate CDN: avg subdomain length 8-15 chars, modest unique count
    DNS tunneling:  avg subdomain length 30-60 chars, many unique subdomains
    Indicators:
      - dnscat2:   hex-encoded data in subdomains, very long
      - iodine:    base32 encoded, fixed structure
      - dns2tcp:   base64 encoded chunks
    """
    host = os.environ["FSIEM_HOST"]
    h = fsiem_headers()
    v = fsiem_verify_ssl()

    query_xml = f"""<Reports><Report><n>DNS Query Analysis</n>
      <SelectClause><AttrList>srcIpAddr,destDomain,eventTime</AttrList></SelectClause>
      <ReportInterval><Window>Last {days_back} days</Window></ReportInterval>
      <PatternClause><SubPattern><Filters>
        <Filter><n>eventType</n><Operator>IN</Operator>
          <Value>DNS Query,DNS-Query,DNS Request</Value></Filter>
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
    r2 = requests.get(f"{host}/phoenix/rest/query/events/{qid}/0/5000",
                      headers=h, verify=v, timeout=30)
    root = ET.fromstring(r2.text)

    # Group by parent domain
    domain_data = defaultdict(lambda: {"subdomains": set(), "sources": set(), "queries": 0})
    for ev in root.findall(".//event"):
        attrs = {a.findtext("name",""): a.findtext("value","")
                 for a in ev.findall("attributes/attribute")}
        full_domain = attrs.get("destDomain","").lower().strip(".")
        src = attrs.get("srcIpAddr","")
        if not full_domain or len(full_domain) < 4: continue

        # Extract parent domain (last 2 parts) and subdomain
        parts = full_domain.split(".")
        if len(parts) >= 3:
            parent = ".".join(parts[-2:])
            subdomain = ".".join(parts[:-2])
            if subdomain:
                domain_data[parent]["subdomains"].add(subdomain)
                domain_data[parent]["sources"].add(src)
                domain_data[parent]["queries"] += 1

    candidates = []
    for parent_domain, data in domain_data.items():
        unique_sub = len(data["subdomains"])
        if unique_sub < min_unique_subdomains: continue

        subdomain_list = list(data["subdomains"])
        avg_len = sum(len(s) for s in subdomain_list) / len(subdomain_list)
        max_len = max(len(s) for s in subdomain_list)

        if avg_len < min_avg_subdomain_length: continue

        # Entropy check — tunneling uses high-entropy base32/64 encoded data
        sample = subdomain_list[0] if subdomain_list else ""
        char_freq = {}
        for c in sample.lower():
            char_freq[c] = char_freq.get(c, 0) + 1
        entropy = -sum((f/len(sample)) * math.log2(f/len(sample))
                       for f in char_freq.values()) if sample else 0

        candidates.append({
            "parent_domain":         parent_domain,
            "unique_subdomains":     unique_sub,
            "avg_subdomain_length":  round(avg_len, 1),
            "max_subdomain_length":  max_len,
            "total_queries":         data["queries"],
            "source_ips":            list(data["sources"])[:5],
            "sample_subdomain":      subdomain_list[0][:50] if subdomain_list else "",
            "entropy_score":         round(entropy, 2),
            "confidence":            "HIGH"   if avg_len >= 40 and unique_sub >= 50 else
                                     "MEDIUM" if avg_len >= 30 else "LOW",
        })

    return sorted(candidates, key=lambda x: x["avg_subdomain_length"], reverse=True)
```

## Techniques 3-5 — Stack Counting, Impossible Travel, Office Process Tree

Full implementations in [reference.md](reference.md):
- `stack_count_processes()` — Day 25
- `hunt_impossible_travel()` — Day 26
- `hunt_office_spawned_shells()` — Day 27
- `run_advanced_hunt_report()` — combined report
