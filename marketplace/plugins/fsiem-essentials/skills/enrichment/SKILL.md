---
name: fsiem-enrich
description: Enrich IPs, domains, and file hashes with external threat intelligence — VirusTotal, AbuseIPDB, Shodan, GeoIP, WHOIS. Use during L1 triage or L2 investigation to determine if an indicator is known-malicious, its geolocation, owner, and exposure profile.
---

# Indicator Enrichment

Enrichment answers: **Is this indicator known-bad? Who owns it? Where is it? What ports is it exposing?**

## Required API Keys (optional but recommended)

```bash
export VT_API_KEY="your-virustotal-api-key"       # https://virustotal.com (free tier: 4 req/min)
export ABUSEIPDB_API_KEY="your-abuseipdb-key"      # https://abuseipdb.com (free tier: 1000 req/day)
export SHODAN_API_KEY="your-shodan-key"            # https://shodan.io (free tier: limited)
```

All functions degrade gracefully if API keys are absent.

## IP Enrichment

```python
import os, requests, json
from datetime import datetime

def enrich_ip(ip: str) -> dict:
    """
    Full IP enrichment: reputation, geo, WHOIS, open ports.
    Calls all available APIs and merges results.
    """
    result = {"ip": ip, "sources": {}, "verdict": "UNKNOWN", "risk_score": 0, "summary": ""}

    # 1. AbuseIPDB — abuse reputation
    abuseipdb_key = os.environ.get("ABUSEIPDB_API_KEY")
    if abuseipdb_key:
        try:
            r = requests.get(
                "https://api.abuseipdb.com/api/v2/check",
                headers={"Key": abuseipdb_key, "Accept": "application/json"},
                params={"ipAddress": ip, "maxAgeInDays": 90, "verbose": True},
                timeout=10
            )
            if r.status_code == 200:
                d = r.json().get("data", {})
                result["sources"]["abuseipdb"] = {
                    "abuse_score":    d.get("abuseConfidenceScore", 0),
                    "total_reports":  d.get("totalReports", 0),
                    "last_reported":  d.get("lastReportedAt", ""),
                    "country":        d.get("countryCode", ""),
                    "isp":            d.get("isp", ""),
                    "usage_type":     d.get("usageType", ""),
                    "is_tor":         d.get("isTor", False),
                    "is_datacenter":  "data" in (d.get("usageType","")).lower(),
                    "categories":     list(set(
                        cat for report in d.get("reports", [])
                        for cat in report.get("categories", [])
                    ))[:5],
                }
                score = d.get("abuseConfidenceScore", 0)
                if score >= 75:
                    result["risk_score"] += 8
                elif score >= 25:
                    result["risk_score"] += 4
        except Exception as e:
            result["sources"]["abuseipdb"] = {"error": str(e)}

    # 2. VirusTotal — malware association
    vt_key = os.environ.get("VT_API_KEY")
    if vt_key:
        try:
            r = requests.get(
                f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
                headers={"x-apikey": vt_key},
                timeout=10
            )
            if r.status_code == 200:
                d = r.json().get("data", {}).get("attributes", {})
                last_analysis = d.get("last_analysis_stats", {})
                malicious = last_analysis.get("malicious", 0)
                suspicious = last_analysis.get("suspicious", 0)
                total = sum(last_analysis.values()) or 1
                result["sources"]["virustotal"] = {
                    "malicious":   malicious,
                    "suspicious":  suspicious,
                    "clean":       last_analysis.get("undetected", 0),
                    "total_av":    total,
                    "detection_rate": f"{round((malicious+suspicious)/total*100, 1)}%",
                    "country":     d.get("country", ""),
                    "asn":         d.get("asn", ""),
                    "as_owner":    d.get("as_owner", ""),
                    "reputation":  d.get("reputation", 0),
                }
                if malicious >= 5:
                    result["risk_score"] += 8
                elif malicious >= 1:
                    result["risk_score"] += 4
        except Exception as e:
            result["sources"]["virustotal"] = {"error": str(e)}

    # 3. Free GeoIP (no key required)
    try:
        r = requests.get(f"https://ipapi.co/{ip}/json/", timeout=5)
        if r.status_code == 200:
            d = r.json()
            result["sources"]["geoip"] = {
                "country":      d.get("country_name", ""),
                "country_code": d.get("country_code", ""),
                "region":       d.get("region", ""),
                "city":         d.get("city", ""),
                "org":          d.get("org", ""),
                "timezone":     d.get("timezone", ""),
                "is_eu":        d.get("in_eu", False),
            }
    except Exception:
        pass

    # 4. Shodan — open ports / services
    shodan_key = os.environ.get("SHODAN_API_KEY")
    if shodan_key:
        try:
            r = requests.get(
                f"https://api.shodan.io/shodan/host/{ip}",
                params={"key": shodan_key},
                timeout=10
            )
            if r.status_code == 200:
                d = r.json()
                result["sources"]["shodan"] = {
                    "open_ports":  d.get("ports", []),
                    "hostnames":   d.get("hostnames", []),
                    "tags":        d.get("tags", []),
                    "vulns":       list(d.get("vulns", {}).keys())[:5],
                    "os":          d.get("os", ""),
                }
                if d.get("vulns"):
                    result["risk_score"] += 3
        except Exception as e:
            pass

    # Determine final verdict
    if result["risk_score"] >= 8:
        result["verdict"] = "MALICIOUS"
    elif result["risk_score"] >= 4:
        result["verdict"] = "SUSPICIOUS"
    elif result["risk_score"] > 0:
        result["verdict"] = "LOW_RISK"
    else:
        result["verdict"] = "UNKNOWN"

    # Build summary
    geo = result["sources"].get("geoip", {})
    vt = result["sources"].get("virustotal", {})
    ab = result["sources"].get("abuseipdb", {})
    result["summary"] = (
        f"{ip} [{result['verdict']}] | "
        f"{geo.get('country_code','?')} {geo.get('org','')} | "
        f"VT: {vt.get('malicious','-')}/{vt.get('total_av','-')} | "
        f"Abuse score: {ab.get('abuse_score','-')}% | "
        f"Reports: {ab.get('total_reports','-')}"
    )
    return result
```

## Domain Enrichment

```python
def enrich_domain(domain: str) -> dict:
    """Enrich a domain with VirusTotal reputation and WHOIS data."""
    result = {"domain": domain, "sources": {}, "verdict": "UNKNOWN", "risk_score": 0}

    vt_key = os.environ.get("VT_API_KEY")
    if vt_key:
        try:
            r = requests.get(
                f"https://www.virustotal.com/api/v3/domains/{domain}",
                headers={"x-apikey": vt_key}, timeout=10
            )
            if r.status_code == 200:
                d = r.json().get("data", {}).get("attributes", {})
                last_analysis = d.get("last_analysis_stats", {})
                malicious = last_analysis.get("malicious", 0)
                total = sum(last_analysis.values()) or 1
                result["sources"]["virustotal"] = {
                    "malicious": malicious,
                    "detection_rate": f"{round(malicious/total*100,1)}%",
                    "categories": d.get("categories", {}),
                    "registrar": d.get("registrar", ""),
                    "creation_date": d.get("creation_date", ""),
                    "reputation": d.get("reputation", 0),
                }
                if malicious >= 5:
                    result["risk_score"] += 8
                elif malicious >= 1:
                    result["risk_score"] += 4
        except Exception as e:
            result["sources"]["virustotal"] = {"error": str(e)}

    # Domain age via WHOIS (free)
    try:
        r = requests.get(f"https://rdap.org/domain/{domain}", timeout=5)
        if r.status_code == 200:
            d = r.json()
            events = {e.get("eventAction",""): e.get("eventDate","")
                      for e in d.get("events", [])}
            result["sources"]["whois"] = {
                "registered": events.get("registration", ""),
                "last_changed": events.get("last changed", ""),
                "status": d.get("status", []),
                "nameservers": [n.get("ldhName","") for n in d.get("nameservers",[])],
            }
            # Newly registered domains (< 30 days) are higher risk
            reg_date = events.get("registration","")
            if reg_date:
                try:
                    age_days = (datetime.now() - datetime.fromisoformat(reg_date[:10])).days
                    if age_days < 30:
                        result["risk_score"] += 4
                        result["sources"]["whois"]["age_days"] = age_days
                        result["sources"]["whois"]["newly_registered"] = True
                except Exception:
                    pass
    except Exception:
        pass

    if result["risk_score"] >= 8:
        result["verdict"] = "MALICIOUS"
    elif result["risk_score"] >= 4:
        result["verdict"] = "SUSPICIOUS"
    else:
        result["verdict"] = "UNKNOWN"
    return result
```

## Hash Enrichment

```python
def enrich_hash(file_hash: str) -> dict:
    """Enrich a file hash (MD5/SHA1/SHA256) via VirusTotal."""
    result = {"hash": file_hash, "sources": {}, "verdict": "UNKNOWN", "risk_score": 0}

    vt_key = os.environ.get("VT_API_KEY")
    if not vt_key:
        result["error"] = "VT_API_KEY not set — hash enrichment requires VirusTotal"
        return result

    try:
        r = requests.get(
            f"https://www.virustotal.com/api/v3/files/{file_hash}",
            headers={"x-apikey": vt_key}, timeout=10
        )
        if r.status_code == 404:
            result["verdict"] = "NOT_FOUND"
            result["summary"] = f"Hash {file_hash[:16]}... not found in VirusTotal — may be new/unknown"
            return result
        if r.status_code == 200:
            d = r.json().get("data", {}).get("attributes", {})
            stats = d.get("last_analysis_stats", {})
            malicious = stats.get("malicious", 0)
            total = sum(stats.values()) or 1
            result["sources"]["virustotal"] = {
                "malicious":      malicious,
                "suspicious":     stats.get("suspicious", 0),
                "detection_rate": f"{round(malicious/total*100, 1)}%",
                "file_name":      d.get("meaningful_name", ""),
                "file_type":      d.get("type_description", ""),
                "file_size":      d.get("size", 0),
                "first_seen":     d.get("first_submission_date", ""),
                "last_seen":      d.get("last_analysis_date", ""),
                "tags":           d.get("tags", [])[:5],
                "popular_threat_names": d.get("popular_threat_classification",{})
                                         .get("suggested_threat_label",""),
            }
            if malicious >= 10:
                result["risk_score"] = 10
                result["verdict"] = "MALICIOUS"
            elif malicious >= 3:
                result["risk_score"] = 6
                result["verdict"] = "MALICIOUS"
            elif malicious >= 1:
                result["risk_score"] = 3
                result["verdict"] = "SUSPICIOUS"
            else:
                result["verdict"] = "CLEAN"

            vt = result["sources"]["virustotal"]
            result["summary"] = (
                f"Hash [{result['verdict']}] {vt.get('file_name','')} "
                f"({vt.get('file_type','')}, {vt.get('file_size',0)} bytes) | "
                f"VT: {malicious}/{total} | {vt.get('popular_threat_names','')}"
            )
    except Exception as e:
        result["error"] = str(e)
    return result
```

## Bulk Enrichment for Triage

```python
def bulk_enrich(indicators: list[dict]) -> list[dict]:
    """
    Enrich a list of indicators in bulk.
    indicators: [{"type": "ip"|"domain"|"hash", "value": "..."}]
    Returns enriched results sorted by risk score (highest first).
    """
    import time
    results = []
    for ind in indicators:
        t = ind.get("type","").lower()
        v = ind.get("value","")
        if t == "ip":
            r = enrich_ip(v)
        elif t == "domain":
            r = enrich_domain(v)
        elif t in ("hash","md5","sha256","sha1"):
            r = enrich_hash(v)
        else:
            r = {"value": v, "verdict": "UNKNOWN", "error": f"Unknown type: {t}"}
        r["type"] = t
        results.append(r)
        time.sleep(0.25)  # Respect free tier rate limits

    return sorted(results, key=lambda x: x.get("risk_score", 0), reverse=True)
```

## Enrichment Summary Card (for L1 display)

```python
def enrichment_card(result: dict) -> str:
    """Format enrichment result as a concise card for L1 triage display."""
    verdict_emoji = {"MALICIOUS": "🔴", "SUSPICIOUS": "🟡",
                     "CLEAN": "✅", "UNKNOWN": "⚪", "NOT_FOUND": "⚪"}.get(
        result.get("verdict","UNKNOWN"), "⚪")

    lines = [f"{verdict_emoji} **{result.get('ip') or result.get('domain') or result.get('hash','')}**"
             f" — {result.get('verdict','UNKNOWN')} (score: {result.get('risk_score',0)}/10)"]

    if "summary" in result:
        lines.append(f"  {result['summary']}")

    geo = result.get("sources",{}).get("geoip",{})
    if geo.get("country"):
        lines.append(f"  📍 {geo.get('city','')}, {geo.get('country','')} | {geo.get('org','')}")

    shodan = result.get("sources",{}).get("shodan",{})
    if shodan.get("open_ports"):
        lines.append(f"  🔓 Open ports: {shodan['open_ports'][:8]}")
    if shodan.get("vulns"):
        lines.append(f"  ⚠️  Known CVEs: {', '.join(shodan['vulns'][:3])}")

    ab = result.get("sources",{}).get("abuseipdb",{})
    if ab.get("is_tor"):
        lines.append(f"  🧅 TOR exit node")
    if ab.get("total_reports",0) > 0:
        lines.append(f"  📋 AbuseIPDB: {ab['total_reports']} reports, {ab.get('abuse_score',0)}% confidence")

    return "\n".join(lines)
```
