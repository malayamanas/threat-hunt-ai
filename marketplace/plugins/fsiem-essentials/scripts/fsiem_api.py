#!/usr/bin/env python3
"""
FortiSIEM API Helper Script
Provides a Python SDK-style interface to the FortiSIEM REST API.
Used by fsiem-essentials plugin for all API operations.

Usage:
    python3 fsiem_api.py incidents --hours 24 --severity HIGH
    python3 fsiem_api.py query --ip 10.0.0.1
    python3 fsiem_api.py hunt --ip 1.2.3.4
    python3 fsiem_api.py cmdb --ip 10.0.0.1
"""

import os
import sys
import json
import time
import base64
import argparse
import ssl
import re
import urllib.request
import urllib.error
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta
from typing import Optional


# --- Configuration -----------------------------------------------------------

def check_env():
    """Check required environment variables and exit with clear message if missing."""
    required = {
        "FSIEM_HOST": "Full URL to FortiSIEM (e.g. https://soc.example.com)",
        "FSIEM_USER": "FortiSIEM username (e.g. admin)",
        "FSIEM_PASS": "FortiSIEM password",
        "FSIEM_ORG":  "Organization name ('super' for Enterprise deployments)",
    }
    missing = [(k, v) for k, v in required.items() if not os.environ.get(k)]
    if missing:
        print("ERROR: Missing required environment variables:")
        for var, desc in missing:
            print(f"  export {var}=<{desc}>")
        sys.exit(1)


def get_config():
    return {
        "host": os.environ.get("FSIEM_HOST", "").rstrip("/"),
        "user": os.environ.get("FSIEM_USER", "admin"),
        "org": os.environ.get("FSIEM_ORG", "super"),
        "password": os.environ.get("FSIEM_PASS", ""),
        "verify_ssl": os.environ.get("FSIEM_VERIFY_SSL", "false").lower() == "true",
    }


def _ssl_context(cfg=None):
    cfg = cfg or get_config()
    ctx = ssl.create_default_context()
    if not cfg["verify_ssl"]:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    return ctx


def auth_header(cfg=None) -> dict:
    """
    Build FortiSIEM Basic Auth header.
    Default: org/user:password (e.g. super/admin:pass).
    The AUTH_FORMAT env var can force a format: 'org_user' or 'user_org'.
    """
    cfg = cfg or get_config()
    fmt = os.environ.get("FSIEM_AUTH_FORMAT", "").lower()
    if fmt == "user_org":
        credentials = f"{cfg['user']}/{cfg['org']}:{cfg['password']}"
    else:
        # Default: org/user (discovered to work on many FortiSIEM deployments)
        credentials = f"{cfg['org']}/{cfg['user']}:{cfg['password']}"
    token = base64.b64encode(credentials.encode()).decode()
    return {"Authorization": f"Basic {token}", "Content-Type": "text/xml"}


def auth_token(cfg=None) -> str:
    """Return just the base64 auth token string."""
    cfg = cfg or get_config()
    fmt = os.environ.get("FSIEM_AUTH_FORMAT", "").lower()
    if fmt == "user_org":
        credentials = f"{cfg['user']}/{cfg['org']}:{cfg['password']}"
    else:
        credentials = f"{cfg['org']}/{cfg['user']}:{cfg['password']}"
    return base64.b64encode(credentials.encode()).decode()


def base_url(cfg=None) -> str:
    cfg = cfg or get_config()
    return f"{cfg['host']}/phoenix/rest"


def api_get(path: str, params: dict = None, cfg=None) -> tuple:
    """GET request. Returns (status_code, response_body)."""
    cfg = cfg or get_config()
    url = f"{base_url(cfg)}{path}"
    if params:
        qs = "&".join(f"{k}={v}" for k, v in params.items() if v is not None)
        if qs:
            url += f"?{qs}"
    req = urllib.request.Request(url)
    token = auth_token(cfg)
    req.add_header("Authorization", f"Basic {token}")
    ctx = _ssl_context(cfg)
    try:
        resp = urllib.request.urlopen(req, context=ctx, timeout=30)
        return resp.status, resp.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", errors="replace")


def api_post(path: str, body: str, content_type="text/xml", cfg=None) -> tuple:
    """POST request. Returns (status_code, response_body)."""
    cfg = cfg or get_config()
    url = f"{base_url(cfg)}{path}"
    req = urllib.request.Request(url, data=body.encode("utf-8"), method="POST")
    token = auth_token(cfg)
    req.add_header("Authorization", f"Basic {token}")
    req.add_header("Content-Type", content_type)
    ctx = _ssl_context(cfg)
    try:
        resp = urllib.request.urlopen(req, context=ctx, timeout=60)
        return resp.status, resp.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", errors="replace")


def api_get_json(path: str, params: dict = None, cfg=None) -> dict:
    """GET that returns parsed JSON."""
    status, body = api_get(path, params, cfg)
    if status >= 400:
        raise RuntimeError(f"HTTP {status}: {body[:300]}")
    return json.loads(body)


# --- Incidents (uses /pub/incident JSON API) ---------------------------------

def list_incidents(hours_back=24, severity=None, status=None, max_results=500, cfg=None) -> list:
    """
    Fetch incidents from FortiSIEM /pub/incident endpoint.
    Returns list of incident dicts with normalized field names.
    """
    cfg = cfg or get_config()
    now_ms = int(datetime.now().timestamp() * 1000)
    start_ms = int((datetime.now() - timedelta(hours=hours_back)).timestamp() * 1000)
    params = {"timeFrom": start_ms, "timeTo": now_ms}
    data = api_get_json("/pub/incident", params, cfg)
    incidents = data.get("data", [])

    # Filter by severity if specified
    if severity:
        sev_upper = severity.upper()
        incidents = [i for i in incidents if i.get("eventSeverityCat", "").upper() == sev_upper]

    # Filter by status if specified (0=Active, 1=Auto-Cleared, 2=Manually-Cleared)
    STATUS_MAP = {"active": 0, "cleared": 1, "manually_cleared": 2}
    if status and status.lower() in STATUS_MAP:
        target = STATUS_MAP[status.lower()]
        incidents = [i for i in incidents if i.get("incidentStatus") == target]

    return incidents[:max_results]


def get_incident_detail(incident_id, cfg=None) -> dict:
    """Fetch single incident detail by ID."""
    cfg = cfg or get_config()
    data = api_get_json(f"/pub/incident", {"incidentId": incident_id}, cfg)
    items = data.get("data", [])
    return items[0] if items else {}


def get_incident_events(incident_id, cfg=None) -> list:
    """Fetch triggering events for an incident."""
    cfg = cfg or get_config()
    data = api_get_json(f"/pub/incident/triggeringEvents", {"incidentId": incident_id}, cfg)
    return data.get("data", [])


def update_incident(incident_id: str, status: str, comment: str = "", cfg=None) -> bool:
    """Update incident status. Status: Active, Cleared, InProgress, False Positive."""
    xml_body = f"""<incidentStatusChange>
  <incidentId>{incident_id}</incidentId>
  <incidentStatus>{status}</incidentStatus>
  <comment>{comment}</comment>
</incidentStatusChange>"""
    code, body = api_post("/incident/updateIncidentStatus", xml_body, cfg=cfg)
    return code == 200


# --- Event Query (async submit -> poll -> results) ---------------------------

def query_submit(query_xml: str, cfg=None) -> str:
    """
    Submit event query, return queryId.
    FortiSIEM queryId = 'requestId,expireTime' (comma-separated).
    The progress and results endpoints require this combined format.
    """
    code, body = api_post("/query/eventQuery", query_xml, cfg=cfg)
    if code >= 400:
        raise RuntimeError(f"Query submit failed (HTTP {code}): {body[:300]}")
    body = body.strip()
    try:
        root = ET.fromstring(body)
        request_id = root.get("requestId", "")
        expire_time = root.findtext(".//expireTime", "")
        error_code = root.findtext(".//error", "")
        error_desc = root.findtext(".//description", "")

        # Check for submit errors
        err_elem = root.find(".//error")
        if err_elem is not None:
            ec = err_elem.get("code", "0")
            if ec != "0":
                raise RuntimeError(f"Query submit error (code {ec}): {error_desc}")

        # Build combined queryId: requestId,expireTime
        if request_id and expire_time:
            combined = f"{request_id},{expire_time}"
            return combined
        elif request_id:
            return request_id
    except ET.ParseError:
        pass
    # Plain text queryId fallback
    if body.isdigit():
        return body
    raise ValueError(f"Could not extract queryId from: {body[:300]}")


def query_poll(query_id: str, timeout: int = 120, cfg=None) -> bool:
    """
    Poll until query completes. Returns True when done.
    query_id should be in 'requestId,expireTime' format.
    """
    cfg = cfg or get_config()
    deadline = time.time() + timeout
    while time.time() < deadline:
        code, body = api_get(f"/query/progress/{query_id}", cfg=cfg)
        body = body.strip()

        # Parse progress from XML response
        progress = 0
        try:
            root = ET.fromstring(body)
            # Check for errors first
            err_elem = root.find(".//error")
            if err_elem is not None:
                err_code = err_elem.get("code", "0")
                err_desc = root.findtext(".//description", "")
                if err_code != "0" and "Invalid query" in err_desc:
                    raise RuntimeError(f"Invalid queryId '{query_id}': {err_desc}")
            # Get progress value
            prog_text = root.findtext(".//progress", "0")
            progress = int(prog_text)
        except ET.ParseError:
            # Try plain text
            try:
                progress = int(body)
            except ValueError:
                progress = 0

        if progress >= 100:
            return True
        time.sleep(2)
    raise TimeoutError(f"Query {query_id} timed out after {timeout}s")


def query_results(query_id: str, start=0, end=200, cfg=None) -> list:
    """
    Get results for a completed query. Handles both XML and JSON responses.
    API path: /query/events/{queryId}/{offset}/{limit}
    - offset: first object index (starts at 0)
    - limit: number of objects to retrieve
    """
    cfg = cfg or get_config()
    limit = end if start == 0 else end - start
    code, body = api_get(f"/query/events/{query_id}/{start}/{limit}", cfg=cfg)
    if code >= 400:
        raise RuntimeError(f"Results fetch failed (HTTP {code}): {body[:300]}")
    return _parse_event_response(body)


def query_results_all(query_id: str, page_size: int = 500, max_total: int = 10000, cfg=None) -> list:
    """
    Fetch ALL results using offset/limit pagination.
    Tracks currentOffset, stops when (totalCount - currentOffset) < limit.
    """
    all_events = []
    offset = 0
    while offset < max_total:
        cfg = cfg or get_config()
        code, body = api_get(f"/query/events/{query_id}/{offset}/{page_size}", cfg=cfg)
        if code >= 400:
            break
        # Parse events
        page = _parse_event_response(body)
        all_events.extend(page)
        if len(page) < page_size:
            break
        offset += page_size
    return all_events[:max_total]


def query_run(query_xml: str, max_results=200, timeout=120, cfg=None) -> list:
    """Full async query flow: submit -> poll -> results."""
    qid = query_submit(query_xml, cfg)
    query_poll(qid, timeout=timeout, cfg=cfg)
    return query_results(qid, start=0, end=max_results, cfg=cfg)


def _parse_event_response(body: str) -> list:
    """Parse event results from either JSON or XML response."""
    # Try JSON first
    try:
        data = json.loads(body)
        if isinstance(data, list):
            return data
        if isinstance(data, dict):
            return data.get("data", data.get("events", []))
    except (json.JSONDecodeError, ValueError):
        pass
    # Fall back to XML
    try:
        root = ET.fromstring(body)
        # Check for error
        err_desc = root.findtext(".//description", "")
        if "Invalid query" in err_desc:
            return []
        events = []
        for event in root.findall(".//event"):
            ev = {}
            # Format 1: <attribute name="fieldName">value</attribute>
            for attr in event.findall("attributes/attribute"):
                attr_name = attr.get("name", "")
                attr_value = attr.text or ""
                if attr_name:
                    ev[attr_name] = attr_value
            # Format 2: <attribute><name>X</name><value>Y</value></attribute>
            if not ev:
                for attr in event.findall("attributes/attribute"):
                    n = attr.findtext("name", "")
                    v = attr.findtext("value", "")
                    if n:
                        ev[n] = v
            # Fallback: direct child elements
            if not ev:
                ev = {child.tag: (child.text or "") for child in event}
            # Also grab top-level event fields
            for field in ["eventType", "receiveTime", "id", "custId"]:
                val = event.findtext(field)
                if val and field not in ev:
                    ev[field] = val
            events.append(ev)
        return events
    except ET.ParseError:
        return []


def build_query(
    src_ips=None, dest_ips=None, event_types=None,
    usernames=None, hostnames=None, free_text=None,
    time_window="Last 1 hour", limit=200, attributes=None
) -> str:
    """
    Build FortiSIEM query XML from parameters.
    Constructs proper XML with SingleEvtConstr constraints.
    """
    if attributes is None:
        attributes = "phRecvTime,eventType,reptDevIpAddr,srcIpAddr,destIpAddr,user,hostName,rawEventMsg"

    # Build constraint conditions
    conditions = []
    if src_ips:
        ip_conds = " OR ".join(f"srcIpAddr = {ip}" for ip in src_ips)
        conditions.append(f"({ip_conds})")
    if dest_ips:
        ip_conds = " OR ".join(f"destIpAddr = {ip}" for ip in dest_ips)
        conditions.append(f"({ip_conds})")
    if event_types:
        et_conds = " OR ".join(f'eventType CONTAIN "{et}"' for et in event_types)
        conditions.append(f"({et_conds})")
    if usernames:
        u_conds = " OR ".join(f'user CONTAIN "{u}"' for u in usernames)
        conditions.append(f"({u_conds})")
    if hostnames:
        h_conds = " OR ".join(f'hostName CONTAIN "{h}"' for h in hostnames)
        conditions.append(f"({h_conds})")
    if free_text:
        conditions.append(f'rawEventMsg CONTAIN "{free_text}"')

    constraint = " AND ".join(conditions) if conditions else "eventType IS NOT NULL"

    window_minutes = _parse_time_window(time_window) if isinstance(time_window, str) else 60
    window_seconds = window_minutes * 60

    return f"""<Reports>
<Report id="fsiem-ai-query" group="report">
<Name>FortiSIEM AI Query</Name>
<CustomerScope groupByEachCustomer="true"><Include all="true"/></CustomerScope>
<SelectClause numEntries="{limit}">
<AttrList>{attributes}</AttrList>
</SelectClause>
<ReportInterval><Window unit="Minute" val="{window_minutes}"/></ReportInterval>
<PatternClause window="{window_seconds}">
<SubPattern id="1" name="Filter">
<SingleEvtConstr><constraint><![CDATA[{constraint}]]></constraint></SingleEvtConstr>
</SubPattern>
</PatternClause>
</Report>
</Reports>"""


def _parse_time_window(window_str: str) -> int:
    """Convert 'Last N hours/days/minutes' to minutes."""
    m = re.match(r"Last\s+(\d+)\s+(minute|hour|day|week)s?", window_str, re.IGNORECASE)
    if not m:
        return 60  # default 1 hour
    val, unit = int(m.group(1)), m.group(2).lower()
    multipliers = {"minute": 1, "hour": 60, "day": 1440, "week": 10080}
    return val * multipliers.get(unit, 60)


# --- CMDB --------------------------------------------------------------------

def cmdb_get_device(ip: str = None, hostname: str = None, cfg=None) -> dict:
    cfg = cfg or get_config()
    params = {}
    if ip:
        params["ip"] = ip
    if hostname:
        params["hostname"] = hostname
    code, body = api_get("/cmdbDeviceInfo/device", params, cfg)
    if code >= 400:
        return {}
    try:
        root = ET.fromstring(body)
        dev = root.find(".//device")
        return {tag.tag: tag.text for tag in dev} if dev is not None else {}
    except ET.ParseError:
        return {}


def cmdb_list_devices(ip_range: str = None, org: str = None, cfg=None) -> list:
    cfg = cfg or get_config()
    code, body = api_get("/cmdbDeviceInfo/devices", {"includeDetails": "false"}, cfg)
    if code >= 400:
        return []
    try:
        root = ET.fromstring(body)
        devices = []
        for dev in root.findall(".//device"):
            d = {}
            d["name"] = dev.get("name", "")
            d["ip"] = dev.get("accessIp", "")
            d["type"] = dev.get("deviceType", "")
            devices.append(d)
        return devices
    except ET.ParseError:
        return []


# --- Connectivity Test -------------------------------------------------------

def test_connectivity(cfg=None) -> tuple:
    """Test API connectivity. Returns (success: bool, message: str)."""
    cfg = cfg or get_config()
    try:
        code, body = api_get("/config/Domain", cfg=cfg)
        if code == 200 and "domain" in body.lower():
            return True, "Connected successfully"
        elif code == 401:
            # Try alternate auth format
            alt_cfg = dict(cfg)
            os.environ["FSIEM_AUTH_FORMAT"] = "user_org"
            code2, body2 = api_get("/config/Domain", cfg=alt_cfg)
            os.environ.pop("FSIEM_AUTH_FORMAT", None)
            if code2 == 200:
                return True, "Connected (user/org format)"
            return False, f"Authentication failed (HTTP {code})"
        else:
            return False, f"Unexpected response (HTTP {code}): {body[:200]}"
    except Exception as e:
        return False, f"Connection error: {e}"


# --- CLI ---------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="FortiSIEM API CLI")
    sub = parser.add_subparsers(dest="command")

    # incidents
    p_inc = sub.add_parser("incidents", help="List incidents")
    p_inc.add_argument("--hours", type=int, default=24)
    p_inc.add_argument("--severity", default=None)
    p_inc.add_argument("--status", default=None)
    p_inc.add_argument("--max", type=int, default=50)

    # query
    p_qry = sub.add_parser("query", help="Run event query")
    p_qry.add_argument("--xml", help="Path to query XML file")
    p_qry.add_argument("--ip", help="Source IP to query")
    p_qry.add_argument("--user", help="Username to query")
    p_qry.add_argument("--event-type", help="Event type filter")
    p_qry.add_argument("--window", default="Last 1 hour")
    p_qry.add_argument("--max", type=int, default=100)

    # hunt
    p_hunt = sub.add_parser("hunt", help="Threat hunt")
    p_hunt.add_argument("--ip", help="IP to hunt")
    p_hunt.add_argument("--domain", help="Domain to hunt")
    p_hunt.add_argument("--user", help="Username to hunt")
    p_hunt.add_argument("--days", type=int, default=7)

    # cmdb
    p_cmdb = sub.add_parser("cmdb", help="Query CMDB")
    p_cmdb.add_argument("--ip", help="Device IP")
    p_cmdb.add_argument("--hostname", help="Device hostname")
    p_cmdb.add_argument("--range", help="IP range")

    # test
    sub.add_parser("test", help="Test connectivity")

    args = parser.parse_args()

    if args.command:
        check_env()

    cfg = get_config()
    if not cfg["host"]:
        print("ERROR: FSIEM_HOST not set", file=sys.stderr)
        sys.exit(1)

    if args.command == "test":
        ok, msg = test_connectivity(cfg)
        print(f"{'OK' if ok else 'FAIL'}: {msg}")
        sys.exit(0 if ok else 1)

    elif args.command == "incidents":
        results = list_incidents(
            hours_back=args.hours,
            severity=args.severity,
            status=args.status,
            max_results=args.max,
            cfg=cfg
        )
        print(json.dumps(results, indent=2, default=str))

    elif args.command == "query":
        if args.xml:
            with open(args.xml) as f:
                xml = f.read()
        else:
            xml = build_query(
                src_ips=[args.ip] if args.ip else None,
                usernames=[args.user] if args.user else None,
                event_types=[args.event_type] if args.event_type else None,
                time_window=args.window,
                limit=args.max
            )
        events = query_run(xml, max_results=args.max, cfg=cfg)
        print(json.dumps(events, indent=2, default=str))

    elif args.command == "hunt":
        window = f"Last {args.days * 24 * 60} minutes"
        if args.ip:
            xml = build_query(src_ips=[args.ip], time_window=window, limit=500)
        elif args.user:
            xml = build_query(usernames=[args.user], time_window=window, limit=500)
        elif args.domain:
            xml = build_query(free_text=args.domain, time_window=window, limit=500)
        else:
            print("Specify --ip, --domain, or --user")
            sys.exit(1)
        events = query_run(xml, max_results=500, cfg=cfg)
        print(f"Found {len(events)} events")
        print(json.dumps(events[:20], indent=2, default=str))

    elif args.command == "cmdb":
        if args.range:
            devices = cmdb_list_devices(ip_range=args.range, cfg=cfg)
        else:
            device = cmdb_get_device(ip=args.ip, hostname=args.hostname, cfg=cfg)
            devices = [device] if device else []
        print(json.dumps(devices, indent=2, default=str))

    else:
        parser.print_help()


if __name__ == "__main__":
    main()
