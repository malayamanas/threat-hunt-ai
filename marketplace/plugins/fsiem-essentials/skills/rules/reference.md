---
name: fsiem-rules
description: Build, deploy, enable, and tune FortiSIEM correlation rules. Use when creating or managing detection rules or MITRE ATT&CK mappings.
---
# Skill: Correlation Rule Engineering
# Build, test, and deploy FortiSIEM correlation rules

## Overview
FortiSIEM correlation rules define conditions under which incidents are triggered.
Rules are XML-based and can be managed via the REST API.

---

## Rule XML Structure

```xml
<Rule>
  <n>Rule Name</n>
  <Description>Rule description</Description>
  <Active>true</Active>
  <Severity>HIGH</Severity>
  <Category>Security/Exploit</Category>
  <SubCategory>Attack</SubCategory>
  <Technique>T1110</Technique>
  <Pattern>
    <Operator>Filter</Operator>
    <SubPatterns>
      <SubPattern>
        <n>e1</n>
        <Filters>
          <Filter>
            <n>eventType</n>
            <Operator>CONTAIN</Operator>
            <Value>Failed Login</Value>
          </Filter>
        </Filters>
        <GroupByAttr>srcIpAddr,user</GroupByAttr>
        <SingleEvt>false</SingleEvt>
        <Count>
          <FilterAttribute>srcIpAddr</FilterAttribute>
          <Operator>>=</Operator>
          <Value>10</Value>
        </Count>
        <TimeWindow>
          <Value>300</Value>
        </TimeWindow>
      </SubPattern>
    </SubPatterns>
  </Pattern>
  <Remediation>Investigate source IP for brute force activity</Remediation>
  <IncidentTitle>Brute Force: @@srcIpAddr@@ targeting @@destIpAddr@@</IncidentTitle>
</Rule>
```

---

## fsiem_rule_build_brute_force

```python
def fsiem_rule_build_brute_force(
    threshold: int = 10,
    window_seconds: int = 300,
    event_type_filter: str = "Failed Login",
    severity: str = "HIGH",
    rule_name: str = None
) -> str:
    """
    Generate XML for a brute force detection rule.
    
    Args:
        threshold: Number of events to trigger (default 10)
        window_seconds: Time window in seconds (default 300 = 5 min)
        event_type_filter: Event type to match
        severity: HIGH, MEDIUM, LOW
        rule_name: Override rule name
    Returns:
        Rule XML string ready for submission
    """
    name = rule_name or f"Brute Force: {event_type_filter} (>={threshold} in {window_seconds}s)"
    
    return f"""<Rule>
  <n>{name}</n>
  <Description>Detects brute force attacks based on {threshold}+ {event_type_filter} events within {window_seconds} seconds from the same source IP.</Description>
  <Active>true</Active>
  <Severity>{severity}</Severity>
  <Category>Security/Access</Category>
  <SubCategory>Brute Force</SubCategory>
  <Technique>T1110</Technique>
  <Pattern>
    <Operator>Filter</Operator>
    <SubPatterns>
      <SubPattern>
        <n>brute_force_events</n>
        <Filters>
          <Filter>
            <n>eventType</n>
            <Operator>CONTAIN</Operator>
            <Value>{event_type_filter}</Value>
          </Filter>
        </Filters>
        <GroupByAttr>srcIpAddr,destIpAddr</GroupByAttr>
        <SingleEvt>false</SingleEvt>
        <Count>
          <FilterAttribute>srcIpAddr</FilterAttribute>
          <Operator>&gt;=</Operator>
          <Value>{threshold}</Value>
        </Count>
        <TimeWindow>
          <Value>{window_seconds}</Value>
        </TimeWindow>
      </SubPattern>
    </SubPatterns>
  </Pattern>
  <Remediation>Investigate source IP @@srcIpAddr@@ for brute force activity. Consider blocking at firewall.</Remediation>
  <IncidentTitle>Brute Force from @@srcIpAddr@@ ({threshold}+ failures in {window_seconds}s)</IncidentTitle>
</Rule>"""
```

---

## fsiem_rule_build_beaconing

```python
def fsiem_rule_build_beaconing(
    interval_seconds: int = 60,
    tolerance_seconds: int = 10,
    min_count: int = 10,
    severity: str = "HIGH"
) -> str:
    """Generate XML for a C2 beaconing detection rule."""
    return f"""<Rule>
  <n>C2 Beaconing: Periodic Outbound Connections</n>
  <Description>Detects potential C2 beaconing behavior – regular outbound connections at ~{interval_seconds}s intervals.</Description>
  <Active>true</Active>
  <Severity>{severity}</Severity>
  <Category>Security/Malware</Category>
  <SubCategory>C2 Beaconing</SubCategory>
  <Technique>T1071</Technique>
  <Pattern>
    <Operator>Filter</Operator>
    <SubPatterns>
      <SubPattern>
        <n>outbound_conn</n>
        <Filters>
          <Filter>
            <n>eventType</n>
            <Operator>CONTAIN</Operator>
            <Value>Network Connection</Value>
          </Filter>
          <Filter>
            <n>destPort</n>
            <Operator>IN</Operator>
            <Value>80,443,8080,8443</Value>
          </Filter>
        </Filters>
        <GroupByAttr>srcIpAddr,destIpAddr</GroupByAttr>
        <SingleEvt>false</SingleEvt>
        <Count>
          <FilterAttribute>srcIpAddr</FilterAttribute>
          <Operator>&gt;=</Operator>
          <Value>{min_count}</Value>
        </Count>
        <TimeWindow>
          <Value>{interval_seconds * min_count + tolerance_seconds * min_count}</Value>
        </TimeWindow>
      </SubPattern>
    </SubPatterns>
  </Pattern>
  <Remediation>Investigate host @@srcIpAddr@@ for potential C2 implant. Capture traffic to @@destIpAddr@@.</Remediation>
  <IncidentTitle>Potential C2 Beaconing from @@srcIpAddr@@ to @@destIpAddr@@</IncidentTitle>
</Rule>"""
```

---

## fsiem_rule_build_from_mitre

```python
MITRE_RULE_TEMPLATES = {
    "T1059": {   # Command and Scripting Interpreter
        "name": "Suspicious Script Execution",
        "event_types": ["Process Launch", "Command Execution"],
        "filter_value": "powershell|cmd|wscript|cscript|bash|python",
        "category": "Security/Exploit",
        "severity": "HIGH",
        "remediation": "Review process launch events from @@srcIpAddr@@. Check for encoded commands.",
    },
    "T1078": {   # Valid Accounts
        "name": "Anomalous Account Usage",
        "event_types": ["Successful Login"],
        "filter_value": "admin|service|svc",
        "category": "Security/Access",
        "severity": "MEDIUM",
        "remediation": "Verify that account @@user@@ login from @@srcIpAddr@@ is authorized.",
    },
    "T1486": {   # Data Encrypted for Impact (Ransomware)
        "name": "Ransomware: Mass File Operations",
        "event_types": ["File Create", "File Modify"],
        "filter_value": ".encrypted|.locked|.ransom|DECRYPT",
        "category": "Security/Malware",
        "severity": "CRITICAL",
        "remediation": "CRITICAL: Isolate host @@srcIpAddr@@ immediately. Potential ransomware.",
    },
    "T1110": {   # Brute Force
        "name": "Brute Force Authentication",
        "event_types": ["Failed Login"],
        "filter_value": "",
        "category": "Security/Access",
        "severity": "HIGH",
        "remediation": "Block source IP @@srcIpAddr@@ and reset affected accounts.",
    },
}

def fsiem_rule_build_from_mitre(technique_id: str) -> str:
    """
    Generate a FortiSIEM correlation rule for a MITRE ATT&CK technique.
    
    Args:
        technique_id: e.g. "T1110", "T1059", "T1486"
    Returns:
        Rule XML string
    """
    t = MITRE_RULE_TEMPLATES.get(technique_id)
    if not t:
        raise ValueError(f"No template for {technique_id}. Build manually with fsiem_rule_build_brute_force or custom XML.")
    
    filter_block = ""
    for et in t["event_types"]:
        filter_block += f"""<Filter>
          <n>eventType</n>
          <Operator>CONTAIN</Operator>
          <Value>{et}</Value>
        </Filter>"""
    
    if t["filter_value"]:
        filter_block += f"""<Filter>
          <n>rawEventMsg</n>
          <Operator>REGEXP</Operator>
          <Value>{t["filter_value"]}</Value>
        </Filter>"""
    
    return f"""<Rule>
  <n>MITRE {technique_id}: {t["name"]}</n>
  <Description>Detects {t["name"]} mapped to MITRE ATT&amp;CK technique {technique_id}.</Description>
  <Active>true</Active>
  <Severity>{t["severity"]}</Severity>
  <Category>{t["category"]}</Category>
  <Technique>{technique_id}</Technique>
  <Pattern>
    <Operator>Filter</Operator>
    <SubPatterns>
      <SubPattern>
        <n>detection</n>
        <Filters>
          {filter_block}
        </Filters>
        <GroupByAttr>srcIpAddr</GroupByAttr>
        <SingleEvt>false</SingleEvt>
        <Count>
          <FilterAttribute>srcIpAddr</FilterAttribute>
          <Operator>&gt;=</Operator>
          <Value>5</Value>
        </Count>
        <TimeWindow>
          <Value>300</Value>
        </TimeWindow>
      </SubPattern>
    </SubPatterns>
  </Pattern>
  <Remediation>{t["remediation"]}</Remediation>
  <IncidentTitle>MITRE {technique_id} Detected on @@srcIpAddr@@</IncidentTitle>
</Rule>"""
```

---

## fsiem_rule_build_from_ioc

```python
def fsiem_rule_build_from_ioc(
    ioc_type: str,     # "ip", "domain", "hash", "url"
    ioc_value: str,
    severity: str = "HIGH",
    source: str = "Threat Intel"
) -> str:
    """
    Generate a rule to detect a specific IOC.
    
    Args:
        ioc_type: "ip", "domain", "hash", or "url"
        ioc_value: The IOC value to detect
        severity: Rule severity
        source: Where the IOC came from (for documentation)
    """
    if ioc_type == "ip":
        filter_block = f"""<Filter>
          <n>srcIpAddr</n>
          <Operator>CONTAIN</Operator>
          <Value>{ioc_value}</Value>
        </Filter>"""
        ioc_desc = f"IP {ioc_value}"
    elif ioc_type == "domain":
        filter_block = f"""<Filter>
          <n>rawEventMsg</n>
          <Operator>CONTAIN</Operator>
          <Value>{ioc_value}</Value>
        </Filter>"""
        ioc_desc = f"domain {ioc_value}"
    elif ioc_type == "hash":
        filter_block = f"""<Filter>
          <n>fileHash</n>
          <Operator>CONTAIN</Operator>
          <Value>{ioc_value}</Value>
        </Filter>"""
        ioc_desc = f"file hash {ioc_value}"
    else:
        filter_block = f"""<Filter>
          <n>rawEventMsg</n>
          <Operator>CONTAIN</Operator>
          <Value>{ioc_value}</Value>
        </Filter>"""
        ioc_desc = f"URL/string {ioc_value}"
    
    return f"""<Rule>
  <n>IOC Detection: {ioc_type.upper()} {ioc_value[:30]}</n>
  <Description>Detects activity matching IOC {ioc_desc} from {source}.</Description>
  <Active>true</Active>
  <Severity>{severity}</Severity>
  <Category>Security/Malware</Category>
  <SubCategory>IOC Match</SubCategory>
  <Pattern>
    <Operator>Filter</Operator>
    <SubPatterns>
      <SubPattern>
        <n>ioc_match</n>
        <Filters>
          {filter_block}
        </Filters>
        <SingleEvt>true</SingleEvt>
      </SubPattern>
    </SubPatterns>
  </Pattern>
  <Remediation>IOC match detected ({ioc_desc}). Investigate immediately and isolate affected hosts.</Remediation>
  <IncidentTitle>IOC Match: {ioc_value[:50]} on @@srcIpAddr@@</IncidentTitle>
</Rule>"""
```

---

## Rule Deployment

```python
def fsiem_rule_create(rule_xml: str) -> dict:
    """Deploy a new correlation rule to FortiSIEM."""
    from .auth import fsiem_auth_header, fsiem_base_url, fsiem_verify_ssl
    import requests, xml.etree.ElementTree as ET
    
    url = f"{fsiem_base_url()}/rules"
    resp = requests.post(url, data=rule_xml,
                         headers={**fsiem_auth_header(), "Content-Type": "text/xml"},
                         verify=fsiem_verify_ssl())
    resp.raise_for_status()
    return {"status": resp.status_code, "response": resp.text}


def fsiem_rule_enable(rule_name: str) -> bool:
    """Enable a correlation rule by name."""
    from .auth import fsiem_auth_header, fsiem_base_url, fsiem_verify_ssl
    import requests
    
    url = f"{fsiem_base_url()}/rules/enable"
    resp = requests.post(url, params={"name": rule_name},
                         headers=fsiem_auth_header(),
                         verify=fsiem_verify_ssl())
    return resp.status_code == 200


def fsiem_rule_disable(rule_name: str) -> bool:
    """Disable a correlation rule by name."""
    from .auth import fsiem_auth_header, fsiem_base_url, fsiem_verify_ssl
    import requests
    
    url = f"{fsiem_base_url()}/rules/disable"
    resp = requests.post(url, params={"name": rule_name},
                         headers=fsiem_auth_header(),
                         verify=fsiem_verify_ssl())
    return resp.status_code == 200
```
