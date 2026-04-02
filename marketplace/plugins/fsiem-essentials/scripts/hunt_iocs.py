#!/usr/bin/env python3
"""
FortiSIEM IOC Hunter
Usage:
  python3 hunt_iocs.py --report threat_report.txt --days 30
  python3 hunt_iocs.py --iocs "1.2.3.4 evil.com d41d8cd98f00b204e9800998ecf8427e" --days 7
  python3 hunt_iocs.py --ip 185.220.101.5
  python3 hunt_iocs.py --domain malicious-c2.net

Requires env vars: FSIEM_HOST, FSIEM_USER, FSIEM_PASS, FSIEM_ORG
"""
import os, sys, re, time, base64, argparse, json
import requests, xml.etree.ElementTree as ET
requests.packages.urllib3.disable_warnings()



def check_xml_response(resp) -> str:
    """
    Parse XML response from FortiSIEM.
    FortiSIEM sometimes returns HTTP 200 with an error body — always check.
    Returns the response text if OK, raises RuntimeError if error detected.
    """
    text = resp.text.strip()
    if not text:
        raise RuntimeError("Empty response from FortiSIEM")
    # Common error patterns in FortiSIEM XML responses
    lower = text.lower()
    if any(p in lower for p in ["<exception>", "<error>", "authentication failed",
                                  "access denied", "invalid session", "no permission"]):
        raise RuntimeError(f"FortiSIEM API error (HTTP {resp.status_code}): {text[:400]}")
    return text


def check_env():
    """Check required environment variables and exit with clear message if missing."""
    required = {
        "FSIEM_HOST": "Full URL to FortiSIEM Supervisor (e.g. https://192.168.1.100)",
        "FSIEM_USER": "FortiSIEM username (e.g. admin)",
        "FSIEM_PASS": "FortiSIEM password",
        "FSIEM_ORG":  "Organization name (use 'super' for Enterprise deployments)",
    }
    missing = [(k, v) for k, v in required.items() if not __import__("os").environ.get(k)]
    if missing:
        print("ERROR: Missing required environment variables:")
        for var, desc in missing:
            print(f"  export {var}=<{desc}>")
        __import__("sys").exit(1)


def auth_headers():
    creds = f"{os.environ['FSIEM_USER']}/{os.environ['FSIEM_ORG']}:{os.environ['FSIEM_PASS']}"
    return {"Authorization": f"Basic {base64.b64encode(creds.encode()).decode()}", "Content-Type": "text/xml"}

def run_query(xml_str, max_results=500):
    host = os.environ["FSIEM_HOST"]
    h = auth_headers()
    r = requests.post(f"{host}/phoenix/rest/query/eventQuery", data=xml_str, headers=h, verify=False, timeout=30)
    r.raise_for_status()
    qid = r.text.strip()
    for _ in range(90):
        p = requests.get(f"{host}/phoenix/rest/query/progress/{qid}", headers=h, verify=False, timeout=10)
        if int(p.text.strip() or "0") >= 100:
            break
        time.sleep(2)
    r2 = requests.get(f"{host}/phoenix/rest/query/events/{qid}/0/{max_results}", headers=h, verify=False, timeout=30)
    root = ET.fromstring(r2.text)
    events = []
    for ev in root.findall(".//event"):
        d = {a.findtext("name",""): a.findtext("value","") for a in ev.findall("attributes/attribute")}
        events.append(d)
    return events

def hunt_ip(ip, days):
    q = f"""<Reports><Report><n>Hunt IP {ip}</n>
    <SelectClause><AttrList>eventTime,eventType,srcIpAddr,destIpAddr,destPort,user,rawEventMsg</AttrList></SelectClause>
    <ReportInterval><Window>Last {days} days</Window></ReportInterval>
    <PatternClause><SubPattern><Filters>
      <Filter><n>rawEventMsg</n><Operator>CONTAIN</Operator><Value>{ip}</Value></Filter>
    </Filters></SubPattern></PatternClause></Report></Reports>"""
    return run_query(q)

def hunt_domain(domain, days):
    q = f"""<Reports><Report><n>Hunt Domain {domain}</n>
    <SelectClause><AttrList>eventTime,eventType,srcIpAddr,destIpAddr,rawEventMsg</AttrList></SelectClause>
    <ReportInterval><Window>Last {days} days</Window></ReportInterval>
    <PatternClause><SubPattern><Filters>
      <Filter><n>rawEventMsg</n><Operator>CONTAIN</Operator><Value>{domain}</Value></Filter>
    </Filters></SubPattern></PatternClause></Report></Reports>"""
    return run_query(q)

def hunt_hash(hash_val, days):
    q = f"""<Reports><Report><n>Hunt Hash {hash_val[:16]}</n>
    <SelectClause><AttrList>eventTime,eventType,hostName,fileName,rawEventMsg</AttrList></SelectClause>
    <ReportInterval><Window>Last {days} days</Window></ReportInterval>
    <PatternClause><SubPattern><Filters>
      <Filter><n>rawEventMsg</n><Operator>CONTAIN</Operator><Value>{hash_val}</Value></Filter>
    </Filters></SubPattern></PatternClause></Report></Reports>"""
    return run_query(q)

def extract_iocs(text):
    private = re.compile(r'^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|127\.)')
    ips = [ip for ip in set(re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', text)) if not private.match(ip)]
    domains = [d for d in set(re.findall(r'\b(?:[a-z0-9\-]+\.)+(?:com|net|org|io|cc|xyz|ru|cn|biz)\b', text, re.I))
               if len(d) > 8]
    md5s = list(set(re.findall(r'\b[0-9a-f]{32}\b', text, re.I)))
    sha256s = list(set(re.findall(r'\b[0-9a-f]{64}\b', text, re.I)))
    return {"ips": ips, "domains": domains, "hashes": md5s + sha256s}

def main():
    parser = argparse.ArgumentParser(description="FortiSIEM IOC Hunter")
    parser.add_argument("--report", help="Path to threat report text file")
    parser.add_argument("--iocs", help="Space-separated IOCs (IPs, domains, hashes)")
    parser.add_argument("--ip", help="Single IP to hunt")
    parser.add_argument("--domain", help="Single domain to hunt")
    parser.add_argument("--days", type=int, default=30, help="Days to search back (default: 30)")
    parser.add_argument("--json", action="store_true", help="Output JSON")
    args = parser.parse_args()
    if hasattr(args, 'command') and not args.command:
        pass
    else:
        check_env()

    results = {}

    if args.ip:
        print(f"Hunting IP: {args.ip}")
        events = hunt_ip(args.ip, args.days)
        results[args.ip] = {"type": "ip", "count": len(events), "events": events[:3]}
        print(f"  Found {len(events)} events")

    elif args.domain:
        print(f"Hunting domain: {args.domain}")
        events = hunt_domain(args.domain, args.days)
        results[args.domain] = {"type": "domain", "count": len(events), "events": events[:3]}
        print(f"  Found {len(events)} events")

    else:
        if args.report:
            with open(args.report) as f:
                text = f.read()
            iocs = extract_iocs(text)
            print(f"Extracted: {len(iocs['ips'])} IPs, {len(iocs['domains'])} domains, {len(iocs['hashes'])} hashes")
        elif args.iocs:
            text = args.iocs
            iocs = extract_iocs(text)
        else:
            parser.print_help()
            sys.exit(1)

        all_iocs = ([(ip, "ip") for ip in iocs["ips"]] +
                    [(d, "domain") for d in iocs["domains"]] +
                    [(h, "hash") for h in iocs["hashes"]])

        hits = []
        for ioc, ioc_type in all_iocs:
            try:
                if ioc_type == "ip":
                    events = hunt_ip(ioc, args.days)
                elif ioc_type == "domain":
                    events = hunt_domain(ioc, args.days)
                else:
                    events = hunt_hash(ioc, args.days)
                results[ioc] = {"type": ioc_type, "count": len(events)}
                if events:
                    hits.append(ioc)
                    print(f"  🔴 HIT: {ioc_type} {ioc} — {len(events)} events")
                else:
                    print(f"  ✅ Clean: {ioc}")
            except Exception as e:
                print(f"  ⚠️  Error hunting {ioc}: {e}")

        print(f"\nSummary: {len(hits)}/{len(all_iocs)} IOCs found in environment")
        if hits:
            print("Hits requiring action:")
            for h in hits:
                print(f"  - {h}")

    if args.json:
        print(json.dumps(results, indent=2))

if __name__ == "__main__":
    main()
