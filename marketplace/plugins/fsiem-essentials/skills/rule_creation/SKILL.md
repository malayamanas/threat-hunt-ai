---
name: fsiem-rule-create
description: Design, validate, and deploy FortiSIEM correlation rules from scratch. Use when building a new detection rule, converting a hunt finding into a rule, or implementing MITRE ATT&CK coverage. Guides through design → XML → test → deploy.
---

# FortiSIEM Rule Creation — Full Workflow

## Rule Design Questions (Answer Before Writing XML)

1. **What behavior am I detecting?** (Be specific: "10+ failed logins from same IP within 5 minutes")
2. **What event types contain this?** (Check `eventType` in FortiSIEM)
3. **What threshold separates malicious from normal?** (count, rate, time window)
4. **What do I group by?** (`srcIpAddr` for external threats, `user` for insider)
5. **What severity?** (CRITICAL=isolate now, HIGH=same-day, MEDIUM=this week, LOW=FYI)
6. **What should the analyst do when this fires?** (Write the remediation text)
7. **MITRE ATT&CK technique?** (Map before deploying)

## Complete Rule XML Template

```xml
<Rule>
  <n>CATEGORY: Threat Description (Threshold in Window)</n>
  <Description>
    Detects [behavior] by monitoring [event types].
    Fires when [threshold] events occur within [window] seconds
    grouped by [attribute]. MITRE: [technique].
  </Description>
  <Active>true</Active>
  <Severity>HIGH</Severity>
  <!--
    CRITICAL = immediate action required
    HIGH     = respond same day
    MEDIUM   = respond this week
    LOW      = informational / tuning
    INFO     = audit / compliance
  -->

  <Category>Security/Access</Category>
  <!--
    Security/Access      Security/Malware    Security/Exploit
    Security/Recon       Security/Compliance Network/Anomaly
    System/Change        System/Availability
  -->
  <SubCategory>Brute Force</SubCategory>
  <Technique>T1110</Technique>

  <Pattern>
    <Operator>Filter</Operator>
    <!--
      Filter   = all events match filters (most common)
      Sequence = events must occur in order
      Absence  = alert when expected event does NOT occur
    -->
    <SubPatterns>
      <SubPattern>
        <n>failed_auth_events</n>
        <Filters>

          <!-- STRING MATCH -->
          <Filter>
            <n>eventType</n>
            <Operator>CONTAIN</Operator>
            <Value>Failed Login</Value>
          </Filter>

          <!-- MULTIPLE VALUES -->
          <Filter>
            <n>destPort</n>
            <Operator>IN</Operator>
            <Value>22,23,80,443,3389,5985</Value>
          </Filter>

          <!-- REGEX -->
          <Filter>
            <n>rawEventMsg</n>
            <Operator>REGEXP</Operator>
            <Value>(?i)(fail|invalid|error|denied)</Value>
          </Filter>

          <!-- EXCLUSION (whitelist known scanners) -->
          <Filter>
            <n>srcIpAddr</n>
            <Operator>NOT IN</Operator>
            <Value>10.0.0.5,10.0.0.6</Value>
          </Filter>

          <!-- NUMERIC THRESHOLD -->
          <Filter>
            <n>destPort</n>
            <Operator>&gt;=</Operator>
            <Value>1024</Value>
          </Filter>

        </Filters>

        <!-- GROUP BY: the pivot attribute for counting -->
        <GroupByAttr>srcIpAddr,destIpAddr</GroupByAttr>

        <!-- AGGREGATE vs SINGLE EVENT -->
        <SingleEvt>false</SingleEvt>
        <!-- true  = fire on every matching event (IOC match, critical single event)  -->
        <!-- false = aggregate and count before firing -->

        <!-- COUNT THRESHOLD (only for SingleEvt=false) -->
        <Count>
          <FilterAttribute>srcIpAddr</FilterAttribute>
          <Operator>&gt;=</Operator>
          <Value>10</Value>
        </Count>

        <!-- TIME WINDOW in seconds (only for SingleEvt=false) -->
        <TimeWindow>
          <Value>300</Value>
          <!-- Common windows:
            60    = 1 minute  (fast attacks: brute force, scanning)
            300   = 5 minutes (most detections)
            3600  = 1 hour    (slow attacks: slow scan, low-and-slow)
            86400 = 1 day     (behavioral baseline)
          -->
        </TimeWindow>

      </SubPattern>
    </SubPatterns>
  </Pattern>

  <!-- INCIDENT TITLE: @@attr@@ inserts live values -->
  <IncidentTitle>Brute Force from @@srcIpAddr@@ to @@destIpAddr@@ (@@COUNT@@ attempts in 5 min)</IncidentTitle>

  <!-- REMEDIATION: what the on-call analyst does at 3am -->
  <Remediation>
    1. Check if @@srcIpAddr@@ is an internal scanner or authorized pen test host.
    2. If external: block at perimeter firewall and review any successful logins from this IP.
    3. If internal: identify the host, check for malware or misconfigured application.
    4. Reset any accounts that had successful logins from @@srcIpAddr@@ in the same window.
    5. If attack continues, escalate to Tier 2.
  </Remediation>

</Rule>
```

## Attribute Reference (Most-Used)

| Attribute | Description | Example |
|---|---|---|
| `eventType` | Normalized event category | `Failed Login`, `Network Connection` |
| `srcIpAddr` | Source IP address | `192.168.1.50` |
| `destIpAddr` | Destination IP | `8.8.8.8` |
| `srcPort` | Source port | `54321` |
| `destPort` | Destination port | `443` |
| `user` | Username | `DOMAIN\jsmith` |
| `hostName` | Source hostname | `workstation-01` |
| `reptDevIpAddr` | Reporting device IP | `10.0.0.1` |
| `rawEventMsg` | Full raw log message | (full syslog line) |
| `fileName` | File involved | `mimikatz.exe` |
| `processName` | Process name | `powershell.exe` |
| `domain` | Domain name | `evil.example.com` |
| `sentBytes` | Bytes sent | `1048576` |
| `recvBytes` | Bytes received | `2048` |

## 15 Production-Ready Rules

### 1. SSH Brute Force
```xml
<Rule>
  <n>Security/Access: SSH Brute Force (>=20 failures in 60s)</n>
  <Active>true</Active><Severity>HIGH</Severity>
  <Category>Security/Access</Category><Technique>T1110</Technique>
  <Pattern><Operator>Filter</Operator><SubPatterns><SubPattern>
    <n>ssh_failures</n>
    <Filters>
      <Filter><n>eventType</n><Operator>CONTAIN</Operator><Value>Failed Login</Value></Filter>
      <Filter><n>destPort</n><Operator>=</Operator><Value>22</Value></Filter>
    </Filters>
    <GroupByAttr>srcIpAddr,destIpAddr</GroupByAttr>
    <SingleEvt>false</SingleEvt>
    <Count><FilterAttribute>srcIpAddr</FilterAttribute><Operator>&gt;=</Operator><Value>20</Value></Count>
    <TimeWindow><Value>60</Value></TimeWindow>
  </SubPattern></SubPatterns></Pattern>
  <IncidentTitle>SSH Brute Force: @@srcIpAddr@@ → @@destIpAddr@@ (@@COUNT@@ attempts)</IncidentTitle>
  <Remediation>Block @@srcIpAddr@@ at firewall. Check for any successful SSH logins from this IP. Review auth.log on @@destIpAddr@@.</Remediation>
</Rule>
```

### 2. RDP Brute Force
```xml
<Rule>
  <n>Security/Access: RDP Brute Force (>=10 failures in 120s)</n>
  <Active>true</Active><Severity>HIGH</Severity>
  <Category>Security/Access</Category><Technique>T1110.001</Technique>
  <Pattern><Operator>Filter</Operator><SubPatterns><SubPattern>
    <n>rdp_failures</n>
    <Filters>
      <Filter><n>eventType</n><Operator>IN</Operator><Value>Failed Login,RDP Authentication Failure</Value></Filter>
      <Filter><n>destPort</n><Operator>=</Operator><Value>3389</Value></Filter>
    </Filters>
    <GroupByAttr>srcIpAddr,destIpAddr</GroupByAttr>
    <SingleEvt>false</SingleEvt>
    <Count><FilterAttribute>srcIpAddr</FilterAttribute><Operator>&gt;=</Operator><Value>10</Value></Count>
    <TimeWindow><Value>120</Value></TimeWindow>
  </SubPattern></SubPatterns></Pattern>
  <IncidentTitle>RDP Brute Force: @@srcIpAddr@@ → @@destIpAddr@@ (@@COUNT@@ failures)</IncidentTitle>
  <Remediation>Block @@srcIpAddr@@. Enable NLA on @@destIpAddr@@. Check Windows Security Event Log (Event 4625).</Remediation>
</Rule>
```

### 3. C2 Beaconing (Regular Outbound)
```xml
<Rule>
  <n>Security/Malware: C2 Beaconing — Regular Outbound Connections (>=50/day same dest)</n>
  <Active>true</Active><Severity>HIGH</Severity>
  <Category>Security/Malware</Category><Technique>T1071.001</Technique>
  <Pattern><Operator>Filter</Operator><SubPatterns><SubPattern>
    <n>beaconing</n>
    <Filters>
      <Filter><n>eventType</n><Operator>IN</Operator><Value>Network Connection,HTTP Request,HTTPS Request</Value></Filter>
      <Filter><n>srcIpAddr</n><Operator>REGEXP</Operator><Value>^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.)</Value></Filter>
      <Filter><n>destIpAddr</n><Operator>NOT REGEXP</Operator><Value>^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.)</Value></Filter>
    </Filters>
    <GroupByAttr>srcIpAddr,destIpAddr</GroupByAttr>
    <SingleEvt>false</SingleEvt>
    <Count><FilterAttribute>destIpAddr</FilterAttribute><Operator>&gt;=</Operator><Value>50</Value></Count>
    <TimeWindow><Value>86400</Value></TimeWindow>
  </SubPattern></SubPatterns></Pattern>
  <IncidentTitle>Potential C2: @@srcIpAddr@@ beaconing to @@destIpAddr@@ (@@COUNT@@ connections today)</IncidentTitle>
  <Remediation>Capture traffic from @@srcIpAddr@@ to @@destIpAddr@@. Check process responsible (netstat -b). Isolate host if confirmed. Look up @@destIpAddr@@ in threat intel.</Remediation>
</Rule>
```

### 4. Lateral Movement via SMB
```xml
<Rule>
  <n>Security/Exploit: Lateral Movement — Internal Host Accessing Many SMB Targets (>=5 in 1h)</n>
  <Active>true</Active><Severity>HIGH</Severity>
  <Category>Security/Exploit</Category><Technique>T1021.002</Technique>
  <Pattern><Operator>Filter</Operator><SubPatterns><SubPattern>
    <n>smb_lateral</n>
    <Filters>
      <Filter><n>destPort</n><Operator>IN</Operator><Value>445,139</Value></Filter>
      <Filter><n>eventType</n><Operator>IN</Operator><Value>Network Connection,SMB Connection,Successful Login</Value></Filter>
      <Filter><n>srcIpAddr</n><Operator>REGEXP</Operator><Value>^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.)</Value></Filter>
    </Filters>
    <GroupByAttr>srcIpAddr</GroupByAttr>
    <SingleEvt>false</SingleEvt>
    <Count><FilterAttribute>destIpAddr</FilterAttribute><Operator>&gt;=</Operator><Value>5</Value></Count>
    <TimeWindow><Value>3600</Value></TimeWindow>
  </SubPattern></SubPatterns></Pattern>
  <IncidentTitle>Lateral Movement: @@srcIpAddr@@ accessed @@COUNT@@ SMB targets in 1 hour</IncidentTitle>
  <Remediation>Investigate @@srcIpAddr@@ for signs of compromise. Check for PsExec, Cobalt Strike, or other remote execution tools. Block outbound SMB at host firewall. Check Domain Controller for pass-the-hash activity.</Remediation>
</Rule>
```

### 5. PowerShell Encoded Command
```xml
<Rule>
  <n>Security/Exploit: PowerShell Encoded Command Execution (T1059.001)</n>
  <Active>true</Active><Severity>HIGH</Severity>
  <Category>Security/Exploit</Category><Technique>T1059.001</Technique>
  <Pattern><Operator>Filter</Operator><SubPatterns><SubPattern>
    <n>ps_encoded</n>
    <Filters>
      <Filter><n>processName</n><Operator>REGEXP</Operator><Value>(?i)powershell</Value></Filter>
      <Filter><n>rawEventMsg</n><Operator>REGEXP</Operator><Value>(?i)(-enc|-encodedcommand|-e\s+[A-Za-z0-9+/]{20})</Value></Filter>
    </Filters>
    <SingleEvt>true</SingleEvt>
  </SubPattern></SubPatterns></Pattern>
  <IncidentTitle>Encoded PowerShell on @@hostName@@ by @@user@@</IncidentTitle>
  <Remediation>Review PowerShell transcript logs on @@hostName@@. Decode the base64 payload: [System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String('PAYLOAD')). Check for follow-on downloads or process spawning.</Remediation>
</Rule>
```

### 6. Ransomware — Shadow Copy Deletion
```xml
<Rule>
  <n>Security/Malware: Ransomware Indicator — Shadow Copy Deletion (T1490)</n>
  <Active>true</Active><Severity>CRITICAL</Severity>
  <Category>Security/Malware</Category><Technique>T1490</Technique>
  <Pattern><Operator>Filter</Operator><SubPatterns><SubPattern>
    <n>shadow_delete</n>
    <Filters>
      <Filter><n>rawEventMsg</n><Operator>REGEXP</Operator><Value>(?i)(vssadmin.*delete|wmic.*shadowcopy.*delete|wbadmin.*delete|bcdedit.*recoveryenabled)</Value></Filter>
    </Filters>
    <SingleEvt>true</SingleEvt>
  </SubPattern></SubPatterns></Pattern>
  <IncidentTitle>CRITICAL: Shadow Copy Deletion on @@hostName@@ — Possible Ransomware</IncidentTitle>
  <Remediation>IMMEDIATE: Isolate @@hostName@@ from network. Do NOT power off (preserve memory). Activate IR playbook. Check for encrypted files on @@hostName@@ and any network shares it accessed in the last hour. Notify CISO.</Remediation>
</Rule>
```

### 7. Data Exfiltration — Large Outbound Transfer
```xml
<Rule>
  <n>Security/Compliance: Large Outbound Data Transfer (>100MB to external)</n>
  <Active>true</Active><Severity>MEDIUM</Severity>
  <Category>Security/Compliance</Category><Technique>T1041</Technique>
  <Pattern><Operator>Filter</Operator><SubPatterns><SubPattern>
    <n>large_transfer</n>
    <Filters>
      <Filter><n>sentBytes</n><Operator>&gt;=</Operator><Value>104857600</Value></Filter>
      <Filter><n>destIpAddr</n><Operator>NOT REGEXP</Operator><Value>^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.)</Value></Filter>
    </Filters>
    <SingleEvt>true</SingleEvt>
  </SubPattern></SubPatterns></Pattern>
  <IncidentTitle>Large Outbound Transfer: @@srcIpAddr@@ sent @@sentBytes@@ bytes to @@destIpAddr@@</IncidentTitle>
  <Remediation>Verify with user/business owner if this transfer is expected. Check what application initiated the connection. Review DLP logs if available. If unauthorized, block @@destIpAddr@@ and preserve logs.</Remediation>
</Rule>
```

### 8. Account Created Outside Business Hours
```xml
<Rule>
  <n>Security/Compliance: Admin Account Created Outside Business Hours</n>
  <Active>true</Active><Severity>HIGH</Severity>
  <Category>Security/Compliance</Category><Technique>T1136</Technique>
  <Pattern><Operator>Filter</Operator><SubPatterns><SubPattern>
    <n>after_hours_account</n>
    <Filters>
      <Filter><n>eventType</n><Operator>IN</Operator><Value>User Account Created,Admin Account Created,Group Member Added</Value></Filter>
      <Filter><n>rawEventMsg</n><Operator>REGEXP</Operator><Value>(?i)(admin|administrator|domain admin|privilege)</Value></Filter>
    </Filters>
    <SingleEvt>true</SingleEvt>
  </SubPattern></SubPatterns></Pattern>
  <IncidentTitle>Privileged Account Created by @@user@@ on @@hostName@@</IncidentTitle>
  <Remediation>Verify with IT if this account creation was authorized via change management. Disable account if unauthorized. Review what @@user@@ did in the 30 minutes before and after this event.</Remediation>
</Rule>
```


## Additional Rules (9-15) and Deployment
See [reference.md](reference.md) for:
- Rules 9-15 (DNS Tunneling, Kerberoasting, External Admin Login, Port Scan, Impossible Travel, Malware Hash, Scheduled Task)
- Python deployment workflow
- XML validation function
- Pre-deploy checklist
