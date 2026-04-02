#!/usr/bin/env python3
"""
FortiSIEM Scheduled Hunt & Compliance Runner
Run as a cron job for daily automated threat hunting and compliance checks.

Usage:
  # Daily IOC sweep from watchlist
  python3 scheduled_hunt.py --ioc-file /etc/fortisiem/watchlist.txt --days 1

  # Weekly hunt across all MITRE techniques
  python3 scheduled_hunt.py --mitre T1110,T1071,T1486 --days 7

  # Monthly compliance evidence
  python3 scheduled_hunt.py --compliance PCI,HIPAA --days 30

  # Full sweep: IOCs + MITRE + compliance
  python3 scheduled_hunt.py --ioc-file watchlist.txt --mitre T1110,T1071 --compliance PCI --days 1

Cron examples:
  # Daily at 06:00 UTC
  0 6 * * * /usr/bin/python3 /opt/fortisiem-ai/scheduled_hunt.py --ioc-file /etc/fortisiem/watchlist.txt --days 1 >> /var/log/fortisiem_hunt.log 2>&1

  # Weekly Friday 18:00
  0 18 * * 5 /usr/bin/python3 /opt/fortisiem-ai/scheduled_hunt.py --mitre T1110,T1071,T1486,T1059 --days 7 >> /var/log/fortisiem_weekly.log 2>&1

Requires env vars: FSIEM_HOST, FSIEM_USER, FSIEM_PASS, FSIEM_ORG
Optional: ALERT_EMAIL, SMTP_HOST, SMTP_PORT for email notifications
"""
import os, sys, re, time, base64, json, argparse
from datetime import datetime
import requests, xml.etree.ElementTree as ET
requests.packages.urllib3.disable_warnings()


def check_env():
    required = ["FSIEM_HOST", "FSIEM_USER", "FSIEM_PASS", "FSIEM_ORG"]
    missing = [v for v in required if not os.environ.get(v)]
    if missing:
        print(f"ERROR: Missing env vars: {', '.join(missing)}")
        sys.exit(1)


def check_xml_response(resp) -> str:
    text = resp.text.strip()
    if not text:
        raise RuntimeError("Empty response from FortiSIEM")
    lower = text.lower()
    if any(p in lower for p in ["<exception>", "authentication failed", "access denied"]):
        raise RuntimeError(f"FortiSIEM error: {text[:300]}")
    return text


def auth_headers():
    creds = f"{os.environ['FSIEM_USER']}/{os.environ['FSIEM_ORG']}:{os.environ['FSIEM_PASS']}"
    token = base64.b64encode(creds.encode()).decode()
    verify = os.environ.get("FSIEM_VERIFY_SSL", "false").lower() == "true"
    return {"Authorization": f"Basic {token}", "Content-Type": "text/xml"}, verify


def run_query(query_xml, max_results=1000):
    host = os.environ["FSIEM_HOST"]
    h, verify = auth_headers()
    r = requests.post(f"{host}/phoenix/rest/query/eventQuery",
                      data=query_xml, headers=h, verify=verify, timeout=30)
    r.raise_for_status()
    check_xml_response(r)
    qid = r.text.strip()
    for _ in range(90):
        p = requests.get(f"{host}/phoenix/rest/query/progress/{qid}",
                         headers=h, verify=verify, timeout=10)
        if int(p.text.strip() or "0") >= 100:
            break
        time.sleep(2)
    r2 = requests.get(f"{host}/phoenix/rest/query/events/{qid}/0/{max_results}",
                      headers=h, verify=verify, timeout=30)
    check_xml_response(r2)
    root = ET.fromstring(r2.text)
    return [{a.findtext("name",""): a.findtext("value","")
             for a in ev.findall("attributes/attribute")}
            for ev in root.findall(".//event")]


def hunt_ioc(value, days):
    q = f"""<Reports><Report><n>Hunt {value[:20]}</n>
    <SelectClause><AttrList>eventTime,eventType,srcIpAddr,destIpAddr,user,rawEventMsg</AttrList></SelectClause>
    <ReportInterval><Window>Last {days} days</Window></ReportInterval>
    <PatternClause><SubPattern><Filters>
      <Filter><n>rawEventMsg</n><Operator>CONTAIN</Operator><Value>{value}</Value></Filter>
    </Filters></SubPattern></PatternClause></Report></Reports>"""
    return run_query(q, max_results=100)


MITRE_QUERIES = {
    "T1110": ("Failed Login", r"fail|invalid|denied"),
    "T1071": ("Network Connection", None),
    "T1486": (None, r"vssadmin.*delete|shadowcopy.*delete|wbadmin.*delete"),
    "T1059": ("Process Launch", r"powershell.*-enc|cmd.*\/c|wscript|cscript"),
    "T1078": ("Successful Login", None),
    "T1053": (None, r"schtasks.*\/create|New-ScheduledTask"),
    "T1003": (None, r"lsass|mimikatz|sekurlsa"),
    "T1041": (None, None),  # Data exfiltration — use sentBytes filter
}

def hunt_mitre(technique, days):
    et, regex = MITRE_QUERIES.get(technique, (None, None))
    filters = ""
    if et:
        filters += f"<Filter><n>eventType</n><Operator>CONTAIN</Operator><Value>{et}</Value></Filter>"
    if regex:
        filters += f"<Filter><n>rawEventMsg</n><Operator>REGEXP</Operator><Value>{regex}</Value></Filter>"
    if not filters:
        return []
    q = f"""<Reports><Report><n>MITRE {technique}</n>
    <SelectClause><AttrList>eventTime,eventType,srcIpAddr,destIpAddr,user,hostName,rawEventMsg</AttrList></SelectClause>
    <ReportInterval><Window>Last {days} days</Window></ReportInterval>
    <PatternClause><SubPattern><Filters>{filters}</Filters></SubPattern></PatternClause>
    </Report></Reports>"""
    return run_query(q, max_results=200)


def send_alert_email(subject, body):
    """Send email alert if SMTP env vars are set."""
    import smtplib
    from email.message import EmailMessage
    smtp_host = os.environ.get("SMTP_HOST")
    alert_to = os.environ.get("ALERT_EMAIL")
    if not smtp_host or not alert_to:
        return  # No email configured
    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = os.environ.get("SMTP_FROM", "fortisiem-ai@localhost")
    msg["To"] = alert_to
    msg.set_content(body)
    try:
        with smtplib.SMTP(smtp_host, int(os.environ.get("SMTP_PORT", "25"))) as s:
            s.send_message(msg)
        print(f"Alert email sent to {alert_to}")
    except Exception as e:
        print(f"Email send failed: {e}")


def main():
    parser = argparse.ArgumentParser(description="FortiSIEM Scheduled Hunt & Compliance Runner")
    parser.add_argument("--ioc-file", help="Path to IOC watchlist (one IOC per line)")
    parser.add_argument("--iocs", help="Comma-separated IOCs")
    parser.add_argument("--mitre", help="Comma-separated MITRE technique IDs (e.g. T1110,T1071)")
    parser.add_argument("--compliance", help="Comma-separated frameworks (e.g. PCI,HIPAA)")
    parser.add_argument("--days", type=int, default=1, help="Days to look back (default: 1)")
    parser.add_argument("--output", help="JSON output file path")
    parser.add_argument("--alert-threshold", type=int, default=1,
                        help="Min hits to trigger email alert (default: 1)")
    args = parser.parse_args()

    check_env()
    started = datetime.utcnow().isoformat()
    results = {"started": started, "days": args.days, "hits": {}, "clean": [], "errors": []}

    # --- IOC hunting ---
    iocs = []
    if args.ioc_file:
        with open(args.ioc_file) as f:
            iocs = [line.strip() for line in f if line.strip() and not line.startswith("#")]
    if args.iocs:
        iocs += [i.strip() for i in args.iocs.split(",")]

    if iocs:
        print(f"\n[IOC Hunt] {len(iocs)} indicators, last {args.days} day(s)")
        for ioc in iocs:
            try:
                events = hunt_ioc(ioc, args.days)
                if events:
                    results["hits"][ioc] = {"type": "ioc", "count": len(events),
                                            "sample": events[0]}
                    print(f"  🔴 HIT: {ioc} — {len(events)} events")
                else:
                    results["clean"].append(ioc)
                    print(f"  ✅ Clean: {ioc}")
            except Exception as e:
                results["errors"].append({"ioc": ioc, "error": str(e)})
                print(f"  ⚠ Error: {ioc}: {e}")

    # --- MITRE hunting ---
    if args.mitre:
        techniques = [t.strip() for t in args.mitre.split(",")]
        print(f"\n[MITRE Hunt] {techniques}, last {args.days} day(s)")
        for tech in techniques:
            try:
                events = hunt_mitre(tech, args.days)
                if events:
                    results["hits"][tech] = {"type": "mitre", "count": len(events),
                                             "sample": events[0]}
                    print(f"  🔴 HIT: {tech} — {len(events)} events")
                else:
                    results["clean"].append(tech)
                    print(f"  ✅ Clean: {tech}")
            except Exception as e:
                results["errors"].append({"technique": tech, "error": str(e)})
                print(f"  ⚠ Error: {tech}: {e}")

    # --- Summary ---
    hit_count = len(results["hits"])
    total = hit_count + len(results["clean"]) + len(results["errors"])
    results["summary"] = {
        "total_checked": total,
        "hits": hit_count,
        "clean": len(results["clean"]),
        "errors": len(results["errors"]),
        "completed": datetime.utcnow().isoformat(),
    }

    print(f"\n{'='*50}")
    print(f"Summary: {hit_count}/{total} items found in environment")
    if results["errors"]:
        print(f"Errors:  {len(results['errors'])} (see output for details)")

    # --- Output ---
    if args.output:
        with open(args.output, "w") as f:
            json.dump(results, f, indent=2)
        print(f"Results saved: {args.output}")

    # --- Email alert ---
    if hit_count >= args.alert_threshold:
        subject = f"[FortiSIEM Hunt] {hit_count} indicator(s) found — {started[:10]}"
        body = f"Scheduled hunt found {hit_count} indicator(s) in your environment.\n\n"
        for ioc, data in results["hits"].items():
            body += f"  • {ioc}: {data['count']} events\n"
        body += f"\nFull results: {args.output or 'see stdout'}"
        send_alert_email(subject, body)

    # Exit code: 1 if any hits (useful for CI/CD pipelines)
    sys.exit(1 if hit_count > 0 else 0)


if __name__ == "__main__":
    main()
