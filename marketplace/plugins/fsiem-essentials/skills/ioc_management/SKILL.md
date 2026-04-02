---
name: fsiem-ioc
description: Manage IOCs in FortiSIEM — import threat intel feeds, hunt for indicators, create watchlists, and generate rules from IOC lists. Use when given a list of IPs, domains, hashes, or a threat report to action in FortiSIEM.
---

# IOC Management in FortiSIEM

## IOC Types FortiSIEM Supports

| IOC Type | Hunt Method | Rule Type |
|---|---|---|
| Malicious IP | Query `srcIpAddr` / `destIpAddr` | Single-event filter on IP |
| Malicious Domain | Query `rawEventMsg` for domain string | Single-event regex on domain |
| File Hash (MD5/SHA256) | Query `rawEventMsg` / `fileHash` | Single-event filter on hash |
| Malicious URL | Query `rawEventMsg` for URL | Single-event regex on URL |
| User Account (compromised) | Query all events for `user` | Monitor account activity |

## Step 1 — Extract IOCs from Threat Report

```python
import re

def extract_iocs(text: str) -> dict:
    """
    Extract all IOC types from free-form threat report text.
    Returns dict with keys: ips, domains, md5s, sha256s, urls
    """
    # IPs — exclude private/loopback
    ip_pattern = r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b'
    all_ips = set(re.findall(ip_pattern, text))
    private = re.compile(r'^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|127\.|0\.0\.0\.0)')
    public_ips = [ip for ip in all_ips if not private.match(ip)]

    # Domains
    domain_pattern = r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+(?:com|net|org|io|cc|tk|xyz|top|biz|ru|cn|eu|co|info|me)\b'
    domains = list(set(re.findall(domain_pattern, text)))
    # Remove false positives (too common)
    domains = [d for d in domains if len(d) > 8 and not d.startswith('www.microsoft')]

    # MD5
    md5s = list(set(re.findall(r'\b[0-9a-fA-F]{32}\b', text)))

    # SHA256
    sha256s = list(set(re.findall(r'\b[0-9a-fA-F]{64}\b', text)))

    # URLs
    urls = list(set(re.findall(r'https?://[^\s<>"\']+', text)))

    return {
        "ips": public_ips,
        "domains": domains,
        "md5s": md5s,
        "sha256s": sha256s,
        "urls": urls,
        "total": len(public_ips) + len(domains) + len(md5s) + len(sha256s) + len(urls)
    }
```

## Step 2 — Hunt All IOCs in FortiSIEM

```python
import requests, base64, os, time, xml.etree.ElementTree as ET

def fsiem_headers():
    user = os.environ["FSIEM_USER"]
    org  = os.environ["FSIEM_ORG"]
    pw   = os.environ["FSIEM_PASS"]
    token = base64.b64encode(f"{user}/{org}:{pw}".encode()).decode()
    return {"Authorization": f"Basic {token}", "Content-Type": "text/xml"}


def fsiem_verify_ssl() -> bool:
    """Read SSL verification setting from environment."""
    return os.environ.get("FSIEM_VERIFY_SSL", "false").lower() == "true"

def run_query(query_xml: str, max_results: int = 500) -> list:
    """Full async query: submit → poll → results."""
    host = os.environ["FSIEM_HOST"]
    h = fsiem_headers()

    # Submit
    r = requests.post(f"{host}/phoenix/rest/query/eventQuery", data=query_xml, headers=h, verify=fsiem_verify_ssl())
    qid = r.text.strip()

    # Poll
    for _ in range(60):
        p = requests.get(f"{host}/phoenix/rest/query/progress/{qid}", headers=h, verify=fsiem_verify_ssl())
        if int(p.text.strip() or 0) >= 100:
            break
        time.sleep(2)

    # Results
    r2 = requests.get(f"{host}/phoenix/rest/query/events/{qid}/0/{max_results}", headers=h, verify=fsiem_verify_ssl())
    root = ET.fromstring(r2.text)
    events = []
    for ev in root.findall(".//event"):
        d = {}
        for a in ev.findall("attributes/attribute"):
            d[a.findtext("name", "")] = a.findtext("value", "")
        events.append(d)
    return events

def hunt_ip(ip: str, days: int = 30) -> list:
    xml = f"""<Reports><Report>
      <n>IOC Hunt - IP {ip}</n>
      <SelectClause><AttrList>eventTime,reptDevIpAddr,eventType,srcIpAddr,destIpAddr,destPort,user,rawEventMsg</AttrList></SelectClause>
      <ReportInterval><Window>Last {days} days</Window></ReportInterval>
      <PatternClause><SubPattern><Filters>
        <Filter><n>srcIpAddr</n><Operator>CONTAIN</Operator><Value>{ip}</Value></Filter>
      </Filters></SubPattern></PatternClause>
    </Report></Reports>"""
    src = run_query(xml)

    xml2 = f"""<Reports><Report>
      <n>IOC Hunt - IP {ip} dest</n>
      <SelectClause><AttrList>eventTime,reptDevIpAddr,eventType,srcIpAddr,destIpAddr,destPort,rawEventMsg</AttrList></SelectClause>
      <ReportInterval><Window>Last {days} days</Window></ReportInterval>
      <PatternClause><SubPattern><Filters>
        <Filter><n>destIpAddr</n><Operator>CONTAIN</Operator><Value>{ip}</Value></Filter>
      </Filters></SubPattern></PatternClause>
    </Report></Reports>"""
    dst = run_query(xml2)
    return src + dst

def hunt_domain(domain: str, days: int = 30) -> list:
    xml = f"""<Reports><Report>
      <n>IOC Hunt - Domain {domain}</n>
      <SelectClause><AttrList>eventTime,reptDevIpAddr,eventType,srcIpAddr,destIpAddr,rawEventMsg</AttrList></SelectClause>
      <ReportInterval><Window>Last {days} days</Window></ReportInterval>
      <PatternClause><SubPattern><Filters>
        <Filter><n>rawEventMsg</n><Operator>CONTAIN</Operator><Value>{domain}</Value></Filter>
      </Filters></SubPattern></PatternClause>
    </Report></Reports>"""
    return run_query(xml)

def hunt_hash(hash_val: str, days: int = 30) -> list:
    xml = f"""<Reports><Report>
      <n>IOC Hunt - Hash {hash_val[:16]}</n>
      <SelectClause><AttrList>eventTime,reptDevIpAddr,eventType,hostName,fileName,rawEventMsg</AttrList></SelectClause>
      <ReportInterval><Window>Last {days} days</Window></ReportInterval>
      <PatternClause><SubPattern><Filters>
        <Filter><n>rawEventMsg</n><Operator>CONTAIN</Operator><Value>{hash_val}</Value></Filter>
      </Filters></SubPattern></PatternClause>
    </Report></Reports>"""
    return run_query(xml)

def hunt_all_iocs(iocs: dict, days: int = 30) -> dict:
    """Hunt all extracted IOCs and return hits."""
    results = {"hits": [], "clean": [], "errors": []}

    for ip in iocs.get("ips", []):
        try:
            events = hunt_ip(ip, days)
            if events:
                results["hits"].append({"type": "ip", "ioc": ip, "count": len(events), "events": events[:5]})
            else:
                results["clean"].append({"type": "ip", "ioc": ip})
        except Exception as e:
            results["errors"].append({"ioc": ip, "error": str(e)})

    for domain in iocs.get("domains", []):
        try:
            events = hunt_domain(domain, days)
            if events:
                results["hits"].append({"type": "domain", "ioc": domain, "count": len(events), "events": events[:5]})
            else:
                results["clean"].append({"type": "domain", "ioc": domain})
        except Exception as e:
            results["errors"].append({"ioc": domain, "error": str(e)})

    for h in iocs.get("md5s", []) + iocs.get("sha256s", []):
        try:
            events = hunt_hash(h, days)
            if events:
                results["hits"].append({"type": "hash", "ioc": h, "count": len(events), "events": events[:5]})
            else:
                results["clean"].append({"type": "hash", "ioc": h})
        except Exception as e:
            results["errors"].append({"ioc": h, "error": str(e)})

    return results
```

## Step 3 — Create Rules from IOC Hits

For each confirmed hit, generate a detection rule:

```python
def ioc_to_rule(ioc_type: str, ioc_value: str, severity: str = "HIGH", source: str = "Threat Intel") -> str:
    """Generate a FortiSIEM rule XML from an IOC."""
    safe_val = ioc_value.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    short = ioc_value[:40]

    if ioc_type == "ip":
        filter_xml = f"""
        <Filter><n>srcIpAddr</n><Operator>CONTAIN</Operator><Value>{safe_val}</Value></Filter>"""
        filter_xml += f"""
        <Filter><n>destIpAddr</n><Operator>CONTAIN</Operator><Value>{safe_val}</Value></Filter>"""
        # Note: FortiSIEM OR logic requires separate subpatterns or IN operator
        filter_block = f"""
        <Filter><n>rawEventMsg</n><Operator>CONTAIN</Operator><Value>{safe_val}</Value></Filter>"""
    elif ioc_type == "domain":
        filter_block = f"""
        <Filter><n>rawEventMsg</n><Operator>CONTAIN</Operator><Value>{safe_val}</Value></Filter>"""
    else:  # hash
        filter_block = f"""
        <Filter><n>rawEventMsg</n><Operator>CONTAIN</Operator><Value>{safe_val}</Value></Filter>"""

    return f"""<Rule>
  <n>IOC Match: {ioc_type.upper()} — {short}</n>
  <Description>Detects activity matching {ioc_type} IOC [{ioc_value}] from {source}.</Description>
  <Active>true</Active>
  <Severity>{severity}</Severity>
  <Category>Security/Malware</Category>
  <SubCategory>IOC Match</SubCategory>
  <Pattern>
    <Operator>Filter</Operator>
    <SubPatterns>
      <SubPattern>
        <n>ioc_match</n>
        <Filters>{filter_block}
        </Filters>
        <SingleEvt>true</SingleEvt>
      </SubPattern>
    </SubPatterns>
  </Pattern>
  <IncidentTitle>IOC Match: {ioc_type} [{short}] on @@srcIpAddr@@</IncidentTitle>
  <Remediation>
    Known malicious {ioc_type} [{ioc_value}] detected from {source}.
    1. Isolate the source host from the network.
    2. Capture memory and disk if possible.
    3. Block IOC at all perimeter controls.
    4. Check for other hosts communicating with this IOC.
    5. Initiate full incident response.
  </Remediation>
</Rule>"""
```

## Step 4 — IOC Hunt Report

```python
def ioc_hunt_report(iocs: dict, results: dict, report_source: str = "Threat Report") -> str:
    total_hunted = iocs["total"]
    total_hits = len(results["hits"])
    total_clean = len(results["clean"])

    lines = [
        f"# IOC Hunt Report — {report_source}",
        f"**Date**: {__import__('datetime').datetime.now().strftime('%Y-%m-%d %H:%M')}",
        f"**IOCs Hunted**: {total_hunted} | **Hits**: {total_hits} | **Clean**: {total_clean}",
        "",
        "## IOC Summary",
        f"- IPs: {len(iocs['ips'])} | Domains: {len(iocs['domains'])} | "
        f"Hashes: {len(iocs['md5s']) + len(iocs['sha256s'])}",
        "",
        "## Hits — Requires Action",
    ]

    if not results["hits"]:
        lines.append("*No IOCs found in environment — no action required.*")
    else:
        for hit in sorted(results["hits"], key=lambda x: x["count"], reverse=True):
            lines.append(f"\n### 🔴 {hit['type'].upper()}: `{hit['ioc']}`")
            lines.append(f"**Events found**: {hit['count']}")
            if hit["events"]:
                e = hit["events"][0]
                lines.append(f"**Example**: {e.get('eventTime','')} | {e.get('eventType','')} | "
                             f"{e.get('srcIpAddr','')} → {e.get('destIpAddr','')}")
            lines.append(f"**Action**: Create detection rule and investigate affected hosts")

    lines += ["", "## Recommended Next Steps"]
    if results["hits"]:
        lines += [
            "1. Deploy detection rules for all hits (use `fsiem-rule-create` skill)",
            "2. Investigate all internal hosts that communicated with hit IOCs",
            "3. Check if hits correlate with existing open incidents",
            "4. Block all hit IOCs at perimeter firewall and DNS filter",
            "5. Add hit IOCs to FortiSIEM threat intelligence watchlists",
        ]
    else:
        lines += [
            "1. Archive this report — no active compromise detected",
            "2. Consider adding IOCs as preventive watchlist entries",
            "3. Re-run hunt after 7 days in case of delayed activity",
        ]

    return "\n".join(lines)
```
