# Rule Creation — Rules 9-15, Deployment, and Validation

Continued from [SKILL.md](SKILL.md).

### 9. DNS Tunneling
```xml
<Rule>
  <n>Security/Malware: DNS Tunneling — High Volume Long Queries (>=200 queries/hour)</n>
  <Active>true</Active><Severity>HIGH</Severity>
  <Category>Security/Malware</Category><Technique>T1071.004</Technique>
  <Pattern><Operator>Filter</Operator><SubPatterns><SubPattern>
    <n>dns_tunnel</n>
    <Filters>
      <Filter><n>eventType</n><Operator>CONTAIN</Operator><Value>DNS</Value></Filter>
      <Filter><n>rawEventMsg</n><Operator>REGEXP</Operator><Value>[a-zA-Z0-9]{30,}\.</Value></Filter>
    </Filters>
    <GroupByAttr>srcIpAddr</GroupByAttr>
    <SingleEvt>false</SingleEvt>
    <Count><FilterAttribute>srcIpAddr</FilterAttribute><Operator>&gt;=</Operator><Value>200</Value></Count>
    <TimeWindow><Value>3600</Value></TimeWindow>
  </SubPattern></SubPatterns></Pattern>
  <IncidentTitle>DNS Tunneling Suspect: @@srcIpAddr@@ sent @@COUNT@@ unusual DNS queries in 1 hour</IncidentTitle>
  <Remediation>Capture DNS traffic from @@srcIpAddr@@. Check processes making DNS calls (Wireshark or tcpdump). Look for iodine, dnscat2, or similar tools. Block @@srcIpAddr@@ DNS except to internal DNS resolver.</Remediation>
</Rule>
```

### 10. Kerberoasting
```xml
<Rule>
  <n>Security/Access: Kerberoasting — Bulk Service Ticket Requests (>=5 SPNs in 10min)</n>
  <Active>true</Active><Severity>HIGH</Severity>
  <Category>Security/Access</Category><Technique>T1558.003</Technique>
  <Pattern><Operator>Filter</Operator><SubPatterns><SubPattern>
    <n>kerberoast</n>
    <Filters>
      <Filter><n>eventType</n><Operator>CONTAIN</Operator><Value>Kerberos Service Ticket</Value></Filter>
      <Filter><n>rawEventMsg</n><Operator>REGEXP</Operator><Value>(?i)(RC4|0x17)</Value></Filter>
    </Filters>
    <GroupByAttr>srcIpAddr,user</GroupByAttr>
    <SingleEvt>false</SingleEvt>
    <Count><FilterAttribute>rawEventMsg</FilterAttribute><Operator>&gt;=</Operator><Value>5</Value></Count>
    <TimeWindow><Value>600</Value></TimeWindow>
  </SubPattern></SubPatterns></Pattern>
  <IncidentTitle>Kerberoasting: @@user@@ from @@srcIpAddr@@ requested @@COUNT@@ service tickets (RC4)</IncidentTitle>
  <Remediation>Investigate @@user@@ account — was it recently compromised? Review the service accounts targeted. Rotate passwords for targeted SPNs. Check for offline cracking tools on @@srcIpAddr@@.</Remediation>
</Rule>
```

### 11. New Admin Login from External IP
```xml
<Rule>
  <n>Security/Access: Admin Account Login from External/Unexpected IP</n>
  <Active>true</Active><Severity>CRITICAL</Severity>
  <Category>Security/Access</Category><Technique>T1078.002</Technique>
  <Pattern><Operator>Filter</Operator><SubPatterns><SubPattern>
    <n>external_admin_login</n>
    <Filters>
      <Filter><n>eventType</n><Operator>IN</Operator><Value>Successful Login,VPN Login</Value></Filter>
      <Filter><n>user</n><Operator>REGEXP</Operator><Value>(?i)(admin|administrator|root|svc_|sa)</Value></Filter>
      <Filter><n>srcIpAddr</n><Operator>NOT REGEXP</Operator><Value>^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.)</Value></Filter>
    </Filters>
    <SingleEvt>true</SingleEvt>
  </SubPattern></SubPatterns></Pattern>
  <IncidentTitle>CRITICAL: Admin @@user@@ logged in from external IP @@srcIpAddr@@</IncidentTitle>
  <Remediation>Immediately verify with the account owner. If unrecognized: disable account, force password reset, revoke sessions. Review all actions by @@user@@ in the last 24h. Check for persistence mechanisms.</Remediation>
</Rule>
```

### 12. Port Scan Detection
```xml
<Rule>
  <n>Security/Recon: Port Scan — Single Source Hitting Many Ports (>=20 ports in 60s)</n>
  <Active>true</Active><Severity>MEDIUM</Severity>
  <Category>Security/Recon</Category><Technique>T1046</Technique>
  <Pattern><Operator>Filter</Operator><SubPatterns><SubPattern>
    <n>port_scan</n>
    <Filters>
      <Filter><n>eventType</n><Operator>IN</Operator><Value>Firewall Deny,Connection Refused,Network Connection</Value></Filter>
    </Filters>
    <GroupByAttr>srcIpAddr,destIpAddr</GroupByAttr>
    <SingleEvt>false</SingleEvt>
    <Count><FilterAttribute>destPort</FilterAttribute><Operator>&gt;=</Operator><Value>20</Value></Count>
    <TimeWindow><Value>60</Value></TimeWindow>
  </SubPattern></SubPatterns></Pattern>
  <IncidentTitle>Port Scan: @@srcIpAddr@@ scanned @@COUNT@@ ports on @@destIpAddr@@</IncidentTitle>
  <Remediation>Verify if @@srcIpAddr@@ is an authorized vulnerability scanner. If not: block at perimeter firewall. Check if @@destIpAddr@@ was successfully connected to on any port.</Remediation>
</Rule>
```

### 13. Impossible Travel (Login from Two Locations)
```xml
<Rule>
  <n>Security/Access: Impossible Travel — Same User from 2 Different External IPs within 1 hour</n>
  <Active>true</Active><Severity>HIGH</Severity>
  <Category>Security/Access</Category><Technique>T1078</Technique>
  <Pattern><Operator>Filter</Operator><SubPatterns><SubPattern>
    <n>multi_ip_login</n>
    <Filters>
      <Filter><n>eventType</n><Operator>IN</Operator><Value>Successful Login,VPN Login,Web Login</Value></Filter>
      <Filter><n>srcIpAddr</n><Operator>NOT REGEXP</Operator><Value>^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.)</Value></Filter>
    </Filters>
    <GroupByAttr>user</GroupByAttr>
    <SingleEvt>false</SingleEvt>
    <Count><FilterAttribute>srcIpAddr</FilterAttribute><Operator>&gt;=</Operator><Value>2</Value></Count>
    <TimeWindow><Value>3600</Value></TimeWindow>
  </SubPattern></SubPatterns></Pattern>
  <IncidentTitle>Impossible Travel: @@user@@ logged in from @@COUNT@@ different external IPs within 1 hour</IncidentTitle>
  <Remediation>Contact @@user@@ immediately. If unrecognized login: disable account, revoke all sessions, force MFA re-enrollment. Check if VPN split-tunneling could explain this. Review actions on both sessions.</Remediation>
</Rule>
```

### 14. Malware Hash Match (Single Event IOC)
```xml
<Rule>
  <n>Security/Malware: Known Malware File Hash Detected</n>
  <Active>true</Active><Severity>CRITICAL</Severity>
  <Category>Security/Malware</Category><Technique>T1204</Technique>
  <Pattern><Operator>Filter</Operator><SubPatterns><SubPattern>
    <n>hash_match</n>
    <Filters>
      <Filter><n>eventType</n><Operator>IN</Operator><Value>File Created,Process Launch,Malware Detected</Value></Filter>
      <Filter><n>rawEventMsg</n><Operator>REGEXP</Operator><Value>INSERT_HASH_HERE</Value></Filter>
    </Filters>
    <SingleEvt>true</SingleEvt>
  </SubPattern></SubPatterns></Pattern>
  <IncidentTitle>CRITICAL: Known Malware Hash on @@hostName@@ (file: @@fileName@@)</IncidentTitle>
  <Remediation>IMMEDIATE: Isolate @@hostName@@. Preserve disk image if possible. Kill process @@processName@@. Submit hash to VirusTotal for full analysis. Check all other hosts that accessed same file share.</Remediation>
</Rule>
```

### 15. Scheduled Task / Persistence Created
```xml
<Rule>
  <n>Security/Exploit: Scheduled Task Created by Non-Admin Account (T1053.005)</n>
  <Active>true</Active><Severity>HIGH</Severity>
  <Category>Security/Exploit</Category><Technique>T1053.005</Technique>
  <Pattern><Operator>Filter</Operator><SubPatterns><SubPattern>
    <n>schtask_persist</n>
    <Filters>
      <Filter><n>rawEventMsg</n><Operator>REGEXP</Operator><Value>(?i)(schtasks.*\/create|New-ScheduledTask|at\.exe)</Value></Filter>
      <Filter><n>user</n><Operator>NOT REGEXP</Operator><Value>(?i)(SYSTEM|NT AUTHORITY|admin)</Value></Filter>
    </Filters>
    <SingleEvt>true</SingleEvt>
  </SubPattern></SubPatterns></Pattern>
  <IncidentTitle>Suspicious Scheduled Task Created by @@user@@ on @@hostName@@</IncidentTitle>
  <Remediation>Review the scheduled task: schtasks /query /fo LIST /v on @@hostName@@. Delete if unauthorized. Check what command the task runs. Investigate @@user@@ for signs of compromise.</Remediation>
</Rule>
```

## Deployment Workflow

```python
import requests, base64, os, xml.etree.ElementTree as ET

def deploy_rule(rule_xml: str) -> dict:
    """Deploy a rule to FortiSIEM and return result."""
    host = os.environ["FSIEM_HOST"]
    user = os.environ["FSIEM_USER"]
    org  = os.environ["FSIEM_ORG"]
    pw   = os.environ["FSIEM_PASS"]

    token = base64.b64encode(f"{user}/{org}:{pw}".encode()).decode()
    headers = {"Authorization": f"Basic {token}", "Content-Type": "text/xml"}

    resp = requests.post(
        f"{host}/phoenix/rest/rules",
        data=rule_xml,
        headers=headers,
        verify=False
    )
    return {"status": resp.status_code, "body": resp.text[:500]}

def validate_rule_xml(rule_xml: str) -> list:
    """Check rule XML for common mistakes before deploying."""
    errors = []
    try:
        root = ET.fromstring(rule_xml)
    except ET.ParseError as e:
        return [f"XML parse error: {e}"]

    if root.findtext("n") is None:
        errors.append("Missing <n> (rule name)")
    if root.findtext("Severity") not in ("CRITICAL","HIGH","MEDIUM","LOW","INFO"):
        errors.append("Invalid or missing <Severity>")
    if root.find(".//SubPattern") is None:
        errors.append("No <SubPattern> found in <Pattern>")
    if root.findtext("IncidentTitle") is None:
        errors.append("Missing <IncidentTitle>")
    if root.findtext("Remediation") is None:
        errors.append("Missing <Remediation> — required for on-call analyst")

    # Check for common XML escaping issues
    for bad, good in [(">=", "&gt;="), ("<=", "&lt;="), (">", "&gt;"), ("<", "&lt;")]:
        if bad in rule_xml and good not in rule_xml:
            errors.append(f"Operator '{bad}' must be XML-escaped as '{good}' inside element content")

    return errors
```

## Before Deploying: Testing Checklist

- [ ] XML validates (no parse errors)
- [ ] Rule name is unique and descriptive
- [ ] Remediation text written for on-call analyst
- [ ] MITRE technique mapped
- [ ] Tested against historical data (will it have fired in the last 30 days?)
- [ ] Threshold tuned to avoid alert fatigue (< 5 incidents/day target)
- [ ] Exclusions added for known good sources
- [ ] Severity appropriate (CRITICAL = truly critical)
