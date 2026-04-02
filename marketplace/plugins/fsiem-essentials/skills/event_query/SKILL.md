---
name: fsiem-event-query
description: Run async event queries against FortiSIEM (submit → poll → results). Use when searching for events, logs, or activity in FortiSIEM.
---

# FortiSIEM Event Querying

FortiSIEM event queries are **asynchronous** — always three steps:
1. **Submit** `POST /query/eventQuery` → receive `queryId`
2. **Poll** `GET /query/progress/{queryId}` → wait for `100`
3. **Results** `GET /query/events/{queryId}/{start}/{end}` → retrieve events

## Key Functions

- `fsiem_query_submit(query_xml)` → queryId
- `fsiem_query_poll(query_id, timeout_seconds=120)` → True when done
- `fsiem_query_results(query_id, start, end)` → list of event dicts
- `fsiem_query_full(query_xml, max_results=200)` — convenience: runs all three steps
- `fsiem_build_query_xml(src_ips, event_types, time_window, ...)` — build XML from params

## Quick Example

```python
xml = fsiem_build_query_xml(
    src_ips=["10.0.0.5"],
    event_types=["Failed Login"],
    time_window="Last 1 hour"
)
events = fsiem_query_full(xml, max_results=100)
```

## Time Window Values
`"Last 15 minutes"` | `"Last 1 hour"` | `"Last 24 hours"` | `"Last 7 days"`

## Additional Resources
- Full query XML structure and all function signatures: [reference.md](reference.md)
