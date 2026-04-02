#!/usr/bin/env python3
"""
FortiSIEM UEBA Report Generator
Builds a 30-day behavioral baseline for a user or entity and flags anomalies.

Usage:
  python3 ueba_report.py --user jsmith
  python3 ueba_report.py --user "DOMAIN\\administrator" --baseline-days 60 --recent-days 14
  python3 ueba_report.py --ip 10.0.0.50

Requires env vars: FSIEM_HOST, FSIEM_USER, FSIEM_PASS, FSIEM_ORG
"""
import os, sys, time, base64, math, argparse, json
from collections import Counter
from datetime import datetime
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

def run_query(xml_str, max_results=2000):
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
    return [{a.findtext("name",""): a.findtext("value","")
             for a in ev.findall("attributes/attribute")}
            for ev in root.findall(".//event")]

def query_user_events(identifier, id_type, days):
    attr = "user" if id_type == "user" else "srcIpAddr"
    q = f"""<Reports><Report><n>UEBA {id_type} {identifier}</n>
    <SelectClause><AttrList>eventTime,eventType,srcIpAddr,destIpAddr,hostName,user,fileName,sentBytes</AttrList></SelectClause>
    <ReportInterval><Window>Last {days} days</Window></ReportInterval>
    <PatternClause><SubPattern><Filters>
      <Filter><n>{attr}</n><Operator>CONTAIN</Operator><Value>{identifier}</Value></Filter>
    </Filters></SubPattern></PatternClause></Report></Reports>"""
    return run_query(q)

def build_baseline(events):
    known_ips = Counter()
    known_hosts = Counter()
    login_hours = Counter()
    daily = Counter()
    for e in events:
        if "login" in e.get("eventType","").lower() and "fail" not in e.get("eventType","").lower():
            known_ips[e.get("srcIpAddr","")] += 1
            known_hosts[e.get("hostName","") or e.get("destIpAddr","")] += 1
            try:
                t = datetime.strptime(e["eventTime"][:19], "%Y-%m-%d %H:%M:%S")
                login_hours[t.hour] += 1
                daily[t.strftime("%Y-%m-%d")] += 1
            except (KeyError, ValueError):
                pass
    days = max(len(daily), 1)
    return {
        "known_ips": dict(known_ips.most_common(20)),
        "known_hosts": dict(known_hosts.most_common(10)),
        "typical_hours": sorted([h for h, c in login_hours.items() if c >= days * 0.1]),
        "avg_logins_per_day": round(sum(daily.values()) / days, 1),
    }

def detect_anomalies(recent, baseline, baseline_set):
    anomalies = []
    seen = set()
    for e in recent:
        flags = []
        ip = e.get("srcIpAddr","")
        host = e.get("hostName","") or e.get("destIpAddr","")
        user = e.get("user","")
        et = e.get("eventType","")
        ts = e.get("eventTime","")

        if ip and ip not in baseline["known_ips"]:
            flags.append(f"NEW IP: {ip}")
        try:
            t = datetime.strptime(ts[:19], "%Y-%m-%d %H:%M:%S")
            if "login" in et.lower() and t.hour not in baseline["typical_hours"] and baseline["typical_hours"]:
                flags.append(f"UNUSUAL HOUR: {t.hour}:00")
            if t.weekday() >= 5:
                flags.append("WEEKEND ACTIVITY")
        except (ValueError, KeyError):
            pass
        pair = (user or ip, host)
        if pair not in baseline_set and pair not in seen and host:
            flags.append(f"FIRST-TIME ACCESS: {host}")
        seen.add(pair)

        if flags:
            anomalies.append({"event": e, "flags": flags, "score": len(flags) * 3})
    return sorted(anomalies, key=lambda x: x["score"], reverse=True)

def z_score_analysis(events, group_by="hostName"):
    counts = Counter(e.get(group_by,"") for e in events)
    if len(counts) < 3:
        return []
    vals = list(counts.values())
    mean = sum(vals) / len(vals)
    std = math.sqrt(sum((v-mean)**2 for v in vals) / len(vals)) or 1
    return sorted([
        {"entity": k, "count": v, "z_score": round((v-mean)/std, 2), "mean": round(mean,1)}
        for k, v in counts.items() if abs((v-mean)/std) >= 2.5
    ], key=lambda x: abs(x["z_score"]), reverse=True)

def main():
    parser = argparse.ArgumentParser(description="FortiSIEM UEBA Report")
    parser.add_argument("--user", help="Username to analyze")
    parser.add_argument("--ip", help="Host IP to analyze")
    parser.add_argument("--baseline-days", type=int, default=30)
    parser.add_argument("--recent-days", type=int, default=7)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    if hasattr(args, 'command') and not args.command:
        pass
    else:
        check_env()

    if not args.user and not args.ip:
        parser.print_help(); sys.exit(1)

    identifier = args.user or args.ip
    id_type = "user" if args.user else "ip"
    print(f"UEBA Analysis: {id_type}={identifier}")
    print(f"Baseline: {args.baseline_days} days | Recent: {args.recent_days} days\n")

    print("Fetching baseline events...")
    baseline_events = query_user_events(identifier, id_type, args.baseline_days)
    print(f"  {len(baseline_events)} baseline events")

    print("Fetching recent events...")
    recent_events = query_user_events(identifier, id_type, args.recent_days)
    print(f"  {len(recent_events)} recent events\n")

    baseline = build_baseline(baseline_events)
    baseline_set = {(e.get("user","") or e.get("srcIpAddr",""), e.get("hostName","") or e.get("destIpAddr",""))
                    for e in baseline_events}
    anomalies = detect_anomalies(recent_events, baseline, baseline_set)
    z_anomalies = z_score_analysis(recent_events)

    total_score = sum(a["score"] for a in anomalies) + sum(abs(z["z_score"]) for z in z_anomalies)
    risk = "HIGH" if total_score > 20 else "MEDIUM" if total_score > 10 else "LOW"

    print(f"{'='*60}")
    print(f"RISK LEVEL: {risk} (score: {total_score:.1f})")
    print(f"{'='*60}")
    print(f"\nBaseline Profile:")
    print(f"  Known IPs: {list(baseline['known_ips'].keys())[:5]}")
    print(f"  Typical hours: {baseline['typical_hours']}")
    print(f"  Avg logins/day: {baseline['avg_logins_per_day']}")

    if anomalies:
        print(f"\nAnomalies Detected ({len(anomalies)}):")
        for a in anomalies[:10]:
            print(f"  Score {a['score']}: {', '.join(a['flags'])}")
            print(f"    {a['event'].get('eventTime','')} | {a['event'].get('eventType','')} | {a['event'].get('srcIpAddr','')}")

    if z_anomalies:
        print(f"\nVolume Anomalies (Z-score >= 2.5):")
        for z in z_anomalies[:5]:
            print(f"  {z['entity']}: {z['count']} events (mean={z['mean']}, z={z['z_score']})")

    print(f"\nRecommendation: ", end="")
    if risk == "HIGH":
        print("ESCALATE TO TIER 2 IMMEDIATELY")
    elif risk == "MEDIUM":
        print("Monitor and investigate further")
    else:
        print("No action required")

    if args.json:
        print(json.dumps({"risk": risk, "score": total_score, "anomalies": [
            {"flags": a["flags"], "score": a["score"]} for a in anomalies
        ], "volume_anomalies": z_anomalies}, indent=2))

if __name__ == "__main__":
    main()
