# Hunt with FortiSIEM — Troubleshooting Guide

## Installation Issues

### Plugin not found after install
```
✘ fsiem-essentials@fsiem-marketplace — Plugin directory not found
```
**Cause**: Wrong path passed to `plugin marketplace add`.
**Fix**: Point to the `marketplace/` subdirectory, not the repo root:
```bash
/plugin marketplace add /path/to/fortisiem-ai/marketplace
# NOT: /plugin marketplace add /path/to/fortisiem-ai
```

### Skills not showing after `/reload-plugins`
**Fix**: Restart the session fully — `/reload-plugins` may require a full restart for newly installed skills to appear in autocomplete.

---

## Authentication Errors

### `KeyError: 'FSIEM_HOST'` or `KeyError: 'FSIEM_PASS'`
**Cause**: Environment variables not set.
**Fix**:
```bash
export FSIEM_HOST="https://your-fortisiem-host"
export FSIEM_USER="admin"
export FSIEM_PASS="yourpassword"
export FSIEM_ORG="super"
```

### HTTP 401 Unauthorized
**Cause**: Wrong credentials or wrong auth format.
**Verify**:
```bash
# Test auth directly
curl -k -u "admin/super:yourpassword" \
  "https://your-fsiem-host/phoenix/rest/config/Domain"
```
If this fails, check username, org, and password.

### HTTP 403 Forbidden
**Cause**: Account lacks required permissions.
**Fix**: Ensure the account has at minimum: Incident View, Analytics View, CMDB View. See `CONFIG.md` for full permissions list.

### `authentication failed` in XML response body (despite HTTP 200)
**Cause**: FortiSIEM returns HTTP 200 with an error XML body for auth failures on some endpoints.
**Fix**: Check the actual response body, not just the HTTP status code. The `check_xml_response()` function in scripts handles this automatically.

---

## Query / API Errors

### Query returns 0 results unexpectedly
1. Verify the time window covers when events occurred
2. Check that the reporting device is actually sending logs to FortiSIEM
3. Test the query manually in FortiSIEM GUI: **Analytics → Search**
4. Confirm `eventType` values match exactly — they're case-sensitive and platform-specific

### `TimeoutError: Query did not complete within 120s`
**Cause**: Large queries against a busy FortiSIEM can take > 2 minutes.
**Fix**: Increase timeout or narrow the time window:
```python
fsiem_query_full(xml, timeout_seconds=300)  # 5 minutes
```

### Query truncating at 200 results
**Cause**: Default `max_results=200` in `query_results()`.
**Fix**: Use `query_results_all()` in `fsiem_api.py` for complete result sets:
```python
events = query_results_all(query_id, page_size=500, max_total=10000)
```

### `xml.etree.ElementTree.ParseError`
**Cause**: FortiSIEM returned non-XML (HTML error page, proxy intercept page, etc.).
**Fix**:
1. Check the raw response: `print(resp.text[:500])`
2. Verify `FSIEM_HOST` is the Supervisor IP/URL, not a Collector
3. Check if a proxy or WAF is intercepting the request

---

## SSL / Network Errors

### `SSLError: certificate verify failed`
```bash
# Option 1: Disable for lab/dev
export FSIEM_VERIFY_SSL="false"

# Option 2: Install FortiSIEM CA (production)
export REQUESTS_CA_BUNDLE=/path/to/fortisiem-ca.crt
export FSIEM_VERIFY_SSL="true"
```

### `ConnectionRefusedError` or `Connection timed out`
1. Verify `FSIEM_HOST` is reachable: `curl -k https://your-fsiem-host/phoenix/`
2. Check firewall rules — the API runs on port 443 (HTTPS)
3. Confirm the FortiSIEM Supervisor is running (not a Collector node)

---

## Docker Issues

### Container can't reach FortiSIEM
**Cause**: `network_mode: host` may not work in all Docker environments.
**Fix**: Ensure the Docker host can reach the FortiSIEM Supervisor and that `FSIEM_HOST` is the correct IP/hostname.

### OAuth not completing in container
**Cause**: OAuth callback requires the host browser to reach the container.
**Fix**: `network_mode: host` must be enabled in `docker-compose.yml`. This is already set but won't work in some corporate network environments — use the container with a pre-authenticated config volume mount instead.

---

## Common Skill/Command Issues

### `/fsiem-incidents` returns empty
1. Check that incidents exist in the time window: `hours_back` defaults to 24
2. Verify the service account has Incident → View permission
3. Try with explicit severity: `/fsiem-incidents --hours 72`

### `/fsiem-rule-create` deployed but rule not appearing
1. Run `/fsiem-rules list` to confirm
2. Check FortiSIEM GUI: **Rules → Rule Library** — it may be in `inactive` state
3. Manually enable: `/fsiem-rules enable "Your Rule Name"`

### UEBA analysis shows no anomalies for a clearly suspicious user
1. The 30-day baseline may not have enough data (new account)
2. Try reducing `--baseline-days` to 7 if the account is newer
3. Check if the user's events are reaching FortiSIEM — query raw events first with `/fsiem-query all events for user X last 30 days`

---

## Getting Help

- FortiSIEM API docs: https://docs.fortinet.com/document/fortisiem/7.4.0/integration-api-guide
- FortiSIEM community: https://community.fortinet.com
- Open a GitHub issue with: FortiSIEM version, Plugin version, full error message, and the API endpoint being called

---

## Enrichment API Errors

### `VT_API_KEY not set — hash enrichment requires VirusTotal`
**Fix**: Get a free key at https://virustotal.com/gui/join-us (4 req/min free tier)
```bash
export VT_API_KEY="your-api-key"
```
All enrichment functions degrade gracefully if API keys are absent — IP GeoIP still works without any keys.

### `AbuseIPDB` returns 429 Too Many Requests
**Cause**: Free tier is 1,000 checks/day. Bulk enrichment against large incident queues can hit this.
**Fix**: Add caching around `enrich_ip()` — cache results for 24h by IP:
```python
import functools
@functools.lru_cache(maxsize=512)
def enrich_ip_cached(ip):
    return enrich_ip(ip)
```

### Domain enrichment returns no WHOIS data
**Cause**: Not all domains are in RDAP (newer ccTLDs). This is expected — fall back to VirusTotal results.

### Shodan returns `403 Forbidden`
**Cause**: Free Shodan accounts cannot query IP details via API.
**Fix**: Either subscribe to Shodan ($49/mo) or set `SHODAN_API_KEY` to empty — the function skips Shodan silently.
