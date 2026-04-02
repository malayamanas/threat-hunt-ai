---
name: fsiem-event-query
description: Run async event queries against FortiSIEM (submit → poll → results). Use when searching for events, logs, or activity in FortiSIEM.
---
# Skill: Event Querying (Async)
# FortiSIEM event queries use a 3-step async flow

## Overview

FortiSIEM event queries work asynchronously:
1. **Submit** – POST query XML → receive `queryId`
2. **Poll** – GET progress until `progress == 100`
3. **Results** – GET paginated results using `queryId`

---

## Query XML Structure

```xml
<Reports>
  <Report>
    <n>Query Name</n>
    <Description>Optional description</Description>
    <SelectClause>
      <AttrList>reptDevIpAddr,eventType,srcIpAddr,destIpAddr,user,msg,rawEventMsg</AttrList>
    </SelectClause>
    <ReportInterval>
      <Window>Last 1 hour</Window>
      <!-- OR use absolute times: -->
      <!-- <StartTime>2024-01-01T00:00:00Z</StartTime> -->
      <!-- <EndTime>2024-01-01T01:00:00Z</EndTime> -->
    </ReportInterval>
    <PatternClause>
      <SubPattern>
        <Filters>
          <Filter>
            <n>eventType</n>
            <Operator>CONTAINS</Operator>
            <Value>Failed Login</Value>
          </Filter>
        </Filters>
      </SubPattern>
    </PatternClause>
    <OrderByClause>eventTime DESC</OrderByClause>
  </Report>
</Reports>
```

---

## fsiem_query_submit

```python
import requests
import xml.etree.ElementTree as ET
import time

def fsiem_query_submit(query_xml: str) -> str:
    """
    Submit an event query and return the queryId.
    
    Args:
        query_xml: FortiSIEM query XML string
    Returns:
        queryId string to use for polling and results
    """
    from .auth import fsiem_auth_header, fsiem_base_url, fsiem_verify_ssl
    
    url = f"{fsiem_base_url()}/query/eventQuery"
    resp = requests.post(
        url,
        data=query_xml,
        headers={**fsiem_auth_header(), "Content-Type": "text/xml"},
        verify=fsiem_verify_ssl()
    )
    resp.raise_for_status()
    # Response body is just the queryId as plain text
    query_id = resp.text.strip()
    if not query_id or not query_id.isdigit():
        raise ValueError(f"Unexpected queryId response: {resp.text}")
    return query_id
```

---

## fsiem_query_poll

```python
def fsiem_query_poll(query_id: str, timeout_seconds: int = 120) -> bool:
    """
    Poll until query completes (progress reaches 100) or timeout.
    
    Returns True when complete, raises TimeoutError if not done in time.
    """
    from .auth import fsiem_auth_header, fsiem_base_url, fsiem_verify_ssl
    
    url = f"{fsiem_base_url()}/query/progress/{query_id}"
    deadline = time.time() + timeout_seconds
    
    while time.time() < deadline:
        resp = requests.get(url,
                            headers=fsiem_auth_header(),
                            verify=fsiem_verify_ssl())
        resp.raise_for_status()
        
        # Response is plain integer 0-100
        progress = int(resp.text.strip())
        if progress >= 100:
            return True
        time.sleep(2)
    
    raise TimeoutError(f"Query {query_id} did not complete within {timeout_seconds}s")
```

---

## fsiem_query_results

```python
def fsiem_query_results(
    query_id: str,
    start: int = 0,
    end: int = 100
) -> list[dict]:
    """
    Retrieve results for a completed query.
    
    Args:
        query_id: ID from fsiem_query_submit
        start: Result start index (0-based)
        end: Result end index (exclusive)
    Returns:
        List of event dicts
    """
    from .auth import fsiem_auth_header, fsiem_base_url, fsiem_verify_ssl
    
    url = f"{fsiem_base_url()}/query/events/{query_id}/{start}/{end}"
    resp = requests.get(url,
                        headers=fsiem_auth_header(),
                        verify=fsiem_verify_ssl())
    resp.raise_for_status()
    
    root = ET.fromstring(resp.text)
    events = []
    for event in root.findall(".//event"):
        event_dict = {}
        for attr in event.findall("attributes/attribute"):
            name = attr.findtext("name", "")
            value = attr.findtext("value", "")
            event_dict[name] = value
        events.append(event_dict)
    return events
```

---

## fsiem_query_count

```python
def fsiem_query_count(query_id: str) -> int:
    """Get the total number of results for a completed query."""
    from .auth import fsiem_auth_header, fsiem_base_url, fsiem_verify_ssl
    
    url = f"{fsiem_base_url()}/query/progress/{query_id}"
    resp = requests.get(url, headers=fsiem_auth_header(), verify=fsiem_verify_ssl())
    resp.raise_for_status()
    # After completion, also fetch count from the events endpoint metadata
    url_count = f"{fsiem_base_url()}/query/events/{query_id}/0/1"
    resp2 = requests.get(url_count, headers=fsiem_auth_header(), verify=fsiem_verify_ssl())
    root = ET.fromstring(resp2.text)
    total = root.get("totalCount") or root.findtext(".//totalCount")
    return int(total) if total else 0
```

---

## fsiem_query_full (Convenience)

```python
def fsiem_query_full(
    query_xml: str,
    max_results: int = 200,
    timeout_seconds: int = 120
) -> list[dict]:
    """
    Execute the complete FortiSIEM async query flow:
    submit → poll → retrieve results.
    
    Args:
        query_xml: FortiSIEM query XML
        max_results: Max events to retrieve
        timeout_seconds: Max wait time for query completion
    Returns:
        List of event dicts
    """
    query_id = fsiem_query_submit(query_xml)
    fsiem_query_poll(query_id, timeout_seconds=timeout_seconds)
    return fsiem_query_results(query_id, start=0, end=max_results)
```

---

## fsiem_build_query_xml (AI Helper)

```python
def fsiem_build_query_xml(
    event_types: list[str] = None,
    src_ips: list[str] = None,
    dest_ips: list[str] = None,
    usernames: list[str] = None,
    hostnames: list[str] = None,
    time_window: str = "Last 1 hour",
    attributes: list[str] = None,
    free_text: str = None,
    limit: int = 1000
) -> str:
    """
    Build a FortiSIEM query XML from structured parameters.
    Use this to construct queries without writing raw XML.
    """
    if attributes is None:
        attributes = ["reptDevIpAddr", "eventType", "srcIpAddr", "destIpAddr",
                      "user", "hostName", "msg", "rawEventMsg", "eventTime"]
    
    attr_list = ",".join(attributes)
    
    filters = []
    if event_types:
        for et in event_types:
            filters.append(f"""<Filter>
              <n>eventType</n>
              <Operator>CONTAINS</Operator>
              <Value>{et}</Value>
            </Filter>""")
    if src_ips:
        for ip in src_ips:
            filters.append(f"""<Filter>
              <n>srcIpAddr</n>
              <Operator>CONTAIN</Operator>
              <Value>{ip}</Value>
            </Filter>""")
    if dest_ips:
        for ip in dest_ips:
            filters.append(f"""<Filter>
              <n>destIpAddr</n>
              <Operator>CONTAIN</Operator>
              <Value>{ip}</Value>
            </Filter>""")
    if usernames:
        for u in usernames:
            filters.append(f"""<Filter>
              <n>user</n>
              <Operator>CONTAIN</Operator>
              <Value>{u}</Value>
            </Filter>""")
    if hostnames:
        for h in hostnames:
            filters.append(f"""<Filter>
              <n>hostName</n>
              <Operator>CONTAIN</Operator>
              <Value>{h}</Value>
            </Filter>""")
    if free_text:
        filters.append(f"""<Filter>
          <n>rawEventMsg</n>
          <Operator>CONTAIN</Operator>
          <Value>{free_text}</Value>
        </Filter>""")
    
    filter_block = "\n".join(filters) if filters else ""
    
    return f"""<Reports>
  <Report>
    <n>AI Generated Query</n>
    <Description>Query built by FortiSIEM AI plugin</Description>
    <SelectClause>
      <AttrList>{attr_list}</AttrList>
    </SelectClause>
    <ReportInterval>
      <Window>{time_window}</Window>
    </ReportInterval>
    <PatternClause>
      <SubPattern>
        <Filters>
          {filter_block}
        </Filters>
      </SubPattern>
    </PatternClause>
    <OrderByClause>eventTime DESC</OrderByClause>
    <TopN>{limit}</TopN>
  </Report>
</Reports>"""
```

---

## Common Query Templates

### Failed Logins
```python
query = fsiem_build_query_xml(
    event_types=["Failed Login", "Authentication Failed"],
    time_window="Last 1 hour"
)
```

### All Events from an IP
```python
query = fsiem_build_query_xml(
    src_ips=["10.0.0.50"],
    time_window="Last 24 hours"
)
```

### Firewall Denies from External IPs
```python
query = fsiem_build_query_xml(
    event_types=["Firewall Deny"],
    time_window="Last 4 hours"
)
# Post-filter results for srcIpAddr not in RFC1918
```

---

## Time Window Values
- `"Last 15 minutes"`
- `"Last 1 hour"`
- `"Last 4 hours"`
- `"Last 24 hours"`
- `"Last 7 days"`
- `"Last 30 days"`
- Or use absolute: `<StartTime>`/`<EndTime>` in epoch milliseconds
