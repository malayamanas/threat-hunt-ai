---
name: fsiem-playbook
description: Run a structured SOC response playbook for common incident types in FortiSIEM. Use when an incident fires and you need step-by-step guidance — ransomware, account compromise, data exfiltration, malware, phishing. Each playbook includes FortiSIEM queries to run, decisions to make, and actions to take.
---

# FortiSIEM SOC Playbooks

Select the playbook that matches the incident type. Each playbook is self-contained with all FortiSIEM queries needed.

---

## PLAYBOOK 1: Ransomware Response

**Trigger**: Shadow copy deletion, mass file modification, ransom note detected, or user reports

### Phase 1 — Confirm

> **Before running queries**: replace ALL-CAPS placeholder values with actual incident data.
 (first 5 minutes)

Run these queries immediately (replace ALL-CAPS placeholders with actual values):

```xml
<!-- Query 1: Shadow copy deletion -->
<Reports><Report>
  <n>PB-Ransomware: Shadow Copy Events</n>
  <SelectClause><AttrList>eventTime,hostName,user,rawEventMsg</AttrList></SelectClause>
  <ReportInterval><Window>Last 1 hour</Window></ReportInterval>
  <PatternClause><SubPattern><Filters>
    <Filter><n>rawEventMsg</n><Operator>REGEXP</Operator>
      <Value>(?i)(vssadmin|shadowcopy|wbadmin.*delete|bcdedit.*recoveryenabled.*no)</Value>
    </Filter>
  </Filters></SubPattern></PatternClause>
</Report></Reports>

<!-- Query 2: Mass file modifications -->
<Reports><Report>
  <n>PB-Ransomware: Mass File Changes</n>
  <SelectClause><AttrList>eventTime,hostName,user,fileName,COUNT(*)</AttrList></SelectClause>
  <ReportInterval><Window>Last 1 hour</Window></ReportInterval>
  <PatternClause><SubPattern>
    <Filters>
      <Filter><n>eventType</n><Operator>IN</Operator><Value>File Modified,File Renamed,File Created</Value></Filter>
      <Filter><n>fileName</n><Operator>REGEXP</Operator>
        <Value>(?i)\.(encrypted|locked|ransom|crypt|enc|WNCRY|zepto|locky)$</Value>
      </Filter>
    </Filters>
    <GroupByAttr>hostName</GroupByAttr>
    <SingleEvt>false</SingleEvt>
    <Count><FilterAttribute>fileName</FilterAttribute><Operator>&gt;=</Operator><Value>10</Value></Count>
    <TimeWindow><Value>300</Value></TimeWindow>
  </SubPattern></PatternClause>
</Report></Reports>
```

**Decision**:
- Hits found → **CONFIRMED RANSOMWARE** → proceed to Phase 2 immediately
- No hits → check endpoint AV logs, interview user, investigate alternate hypothesis

### Phase 2 — Contain (minutes 5-15)

**Immediate actions** (do not wait for full investigation):
1. **Isolate** affected host(s) from network — pull network cable or block at switch level
2. **Preserve** — do NOT power off (memory evidence) unless disk encryption is actively progressing
3. **Identify patient zero** — which host started first?

```xml
<!-- Find initial infection vector (earliest mass file changes) -->
<Reports><Report>
  <n>PB-Ransomware: Patient Zero</n>
  <SelectClause><AttrList>eventTime,hostName,srcIpAddr,fileName,user</AttrList></SelectClause>
  <ReportInterval><Window>Last 24 hours</Window></ReportInterval>
  <PatternClause><SubPattern><Filters>
    <Filter><n>eventType</n><Operator>IN</Operator><Value>File Modified,File Created,File Renamed</Value></Filter>
    <Filter><n>fileName</n><Operator>REGEXP</Operator>
      <Value>(?i)\.(encrypted|locked|crypt|enc|WNCRY)$</Value>
    </Filter>
  </Filters></SubPattern></PatternClause>
</Report></Reports>

<!-- Find what hosts communicated with patient zero (lateral movement) -->
<Reports><Report>
  <n>PB-Ransomware: Lateral Movement from Patient Zero</n>
  <SelectClause><AttrList>eventTime,srcIpAddr,destIpAddr,destPort,eventType</AttrList></SelectClause>
  <ReportInterval><Window>Last 24 hours</Window></ReportInterval>
  <PatternClause><SubPattern><Filters>
    <Filter><n>srcIpAddr</n><Operator>CONTAIN</Operator><Value>PATIENT_ZERO_IP</Value>  <!-- Replace with IP identified in Query 1 --></Filter>
    <Filter><n>destPort</n><Operator>IN</Operator><Value>445,139,3389,22,5985</Value></Filter>
  </Filters></SubPattern></PatternClause>
</Report></Reports>
```

4. **Identify spread** — which network shares were accessed from patient zero?
5. **Block** ransomware C2 IPs/domains at firewall if identified

### Phase 3 — Eradicate & Recover

1. Identify ransomware family (ransom note, encrypted file extension, ID Ransomware)
2. Check NoMoreRansom.org for decryptors
3. Restore from last known good backup
4. Patch the initial access vector before reconnecting
5. Deploy detection rule (Shadow Copy Deletion rule from rule_creation skill)
6. Document full timeline for post-incident report

---

## PLAYBOOK 2: Account Compromise

**Trigger**: Login from unexpected location, impossible travel, alert from user, MFA bypass

### Phase 1 — Confirm

```xml
<!-- Full account activity - last 7 days -->
<Reports><Report>
  <n>PB-AccountCompromise: Full Activity</n>
  <SelectClause><AttrList>eventTime,eventType,srcIpAddr,destIpAddr,hostName,rawEventMsg</AttrList></SelectClause>
  <ReportInterval><Window>Last 7 days</Window></ReportInterval>
  <PatternClause><SubPattern><Filters>
    <Filter><n>user</n><Operator>CONTAIN</Operator><Value>TARGET_USERNAME</Value>  <!-- Replace with the username under investigation --></Filter>
  </Filters></SubPattern></PatternClause>
</Report></Reports>

<!-- Logins from multiple IPs (impossible travel) -->
<Reports><Report>
  <n>PB-AccountCompromise: Source IPs</n>
  <SelectClause><AttrList>srcIpAddr,eventType,COUNT(*),eventTime</AttrList></SelectClause>
  <ReportInterval><Window>Last 7 days</Window></ReportInterval>
  <PatternClause><SubPattern>
    <Filters>
      <Filter><n>user</n><Operator>CONTAIN</Operator><Value>TARGET_USERNAME</Value></Filter>
      <Filter><n>eventType</n><Operator>IN</Operator><Value>Successful Login,VPN Login,Web Login</Value></Filter>
    </Filters>
    <GroupByAttr>srcIpAddr</GroupByAttr>
    <SingleEvt>false</SingleEvt>
  </SubPattern></PatternClause>
</Report></Reports>
```

**Red flags to look for**:
- Login from new country/IP range
- Login at unusual time (2-5 AM local)
- Immediate data access after login (no browsing pattern)
- MFA device recently registered
- Password change immediately before suspicious activity

### Phase 2 — Contain

1. **Disable the account** immediately (contact user through out-of-band channel to verify)
2. **Revoke all active sessions** (force logout everywhere)
3. **Reset password** and MFA enrollment
4. **Preserve logs** — screenshot SIEM findings before any cleanup

```xml
<!-- What did the attacker access? -->
<Reports><Report>
  <n>PB-AccountCompromise: Files and Systems Accessed</n>
  <SelectClause><AttrList>eventTime,eventType,destIpAddr,hostName,fileName,rawEventMsg</AttrList></SelectClause>
  <ReportInterval><Window>Last 7 days</Window></ReportInterval>
  <PatternClause><SubPattern><Filters>
    <Filter><n>user</n><Operator>CONTAIN</Operator><Value>TARGET_USERNAME</Value></Filter>
    <Filter><n>srcIpAddr</n><Operator>CONTAIN</Operator><Value>SUSPICIOUS_IP</Value>  <!-- Replace with the attacker IP from login analysis --></Filter>
  </Filters></SubPattern></PatternClause>
</Report></Reports>
```

### Phase 3 — Investigate Blast Radius

- What data was accessed/downloaded during the compromised session?
- Did the attacker move laterally to other accounts?
- Were any new accounts, rules, or forwarding rules created?
- Was sensitive data emailed externally?

---

## PLAYBOOK 3: Data Exfiltration

**Trigger**: Large outbound transfer alert, DLP alert, user reports, competitor intel

### Phase 1 — Confirm & Scope

```xml
<!-- Large outbound transfers - last 30 days -->
<Reports><Report>
  <n>PB-Exfil: Large Outbound Transfers</n>
  <SelectClause><AttrList>eventTime,srcIpAddr,destIpAddr,destPort,sentBytes,user</AttrList></SelectClause>
  <ReportInterval><Window>Last 30 days</Window></ReportInterval>
  <PatternClause><SubPattern><Filters>
    <Filter><n>sentBytes</n><Operator>&gt;=</Operator><Value>10485760</Value></Filter>
    <Filter><n>destIpAddr</n><Operator>NOT REGEXP</Operator>
      <Value>^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.)</Value>
    </Filter>
  </Filters></SubPattern></PatternClause>
</Report></Reports>

<!-- Cloud storage uploads (Dropbox, GDrive, OneDrive, Box, WeTransfer) -->
<Reports><Report>
  <n>PB-Exfil: Cloud Storage Activity</n>
  <SelectClause><AttrList>eventTime,srcIpAddr,user,destIpAddr,rawEventMsg,sentBytes</AttrList></SelectClause>
  <ReportInterval><Window>Last 30 days</Window></ReportInterval>
  <PatternClause><SubPattern><Filters>
    <Filter><n>rawEventMsg</n><Operator>REGEXP</Operator>
      <Value>(?i)(dropbox|drive\.google|onedrive|box\.com|wetransfer|mega\.nz|sendspace|mediafire)</Value>
    </Filter>
  </Filters></SubPattern></PatternClause>
</Report></Reports>

<!-- Email with large attachments to external addresses -->
<Reports><Report>
  <n>PB-Exfil: Large Email Attachments External</n>
  <SelectClause><AttrList>eventTime,user,rawEventMsg,sentBytes</AttrList></SelectClause>
  <ReportInterval><Window>Last 30 days</Window></ReportInterval>
  <PatternClause><SubPattern><Filters>
    <Filter><n>eventType</n><Operator>CONTAIN</Operator><Value>Email</Value></Filter>
    <Filter><n>sentBytes</n><Operator>&gt;=</Operator><Value>5242880</Value></Filter>
    <Filter><n>rawEventMsg</n><Operator>NOT REGEXP</Operator>
      <Value>(?i)@(yourcompany\.com|internal\.com)</Value>
    </Filter>
  </Filters></SubPattern></PatternClause>
</Report></Reports>
```

### Phase 2 — Identify the Actor

- Insider threat vs. external attacker?
- Correlate timing with employee offboarding, disciplinary actions, HR notices
- Check if user accessed unusual file shares before exfiltration
- Is the destination a personal cloud account or attacker-controlled server?

### Phase 3 — Legal & Containment

1. **Do NOT alert the suspect** — preserve evidence chain
2. Notify Legal/HR before taking action (for insider threat)
3. Preserve all logs (legal hold)
4. Block destination IPs/domains at perimeter
5. Identify and enumerate all data that was exfiltrated
6. Determine if regulated data (PII, PHI, PCI) was involved → breach notification obligations

---

## PLAYBOOK 4: Malware Detection

**Trigger**: AV alert, EDR alert, suspicious process, IOC match

### Triage Queries

> Replace ALL-CAPS values (`AFFECTED_HOST`, `AFFECTED_HOST_IP`) with actual incident data before running.


```xml
<!-- Process execution anomalies on affected host -->
<Reports><Report>
  <n>PB-Malware: Process Activity on Host</n>
  <SelectClause><AttrList>eventTime,processName,user,rawEventMsg,hostName</AttrList></SelectClause>
  <ReportInterval><Window>Last 24 hours</Window></ReportInterval>
  <PatternClause><SubPattern><Filters>
    <Filter><n>hostName</n><Operator>CONTAIN</Operator><Value>AFFECTED_HOST</Value>  <!-- Replace with hostname of affected system --></Filter>
    <Filter><n>eventType</n><Operator>IN</Operator><Value>Process Launch,Process Execution</Value></Filter>
    <Filter><n>processName</n><Operator>REGEXP</Operator>
      <Value>(?i)(powershell|wscript|cscript|mshta|regsvr32|rundll32|certutil|bitsadmin|cmd)</Value>
    </Filter>
  </Filters></SubPattern></PatternClause>
</Report></Reports>

<!-- Network connections from affected host -->
<Reports><Report>
  <n>PB-Malware: Outbound Connections from Host</n>
  <SelectClause><AttrList>eventTime,destIpAddr,destPort,processName,sentBytes</AttrList></SelectClause>
  <ReportInterval><Window>Last 24 hours</Window></ReportInterval>
  <PatternClause><SubPattern><Filters>
    <Filter><n>srcIpAddr</n><Operator>CONTAIN</Operator><Value>AFFECTED_HOST_IP</Value>  <!-- Replace with IP of affected system --></Filter>
    <Filter><n>destIpAddr</n><Operator>NOT REGEXP</Operator>
      <Value>^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.)</Value>
    </Filter>
  </Filters></SubPattern></PatternClause>
</Report></Reports>

<!-- Persistence mechanisms -->
<Reports><Report>
  <n>PB-Malware: Persistence on Host</n>
  <SelectClause><AttrList>eventTime,rawEventMsg,user,processName</AttrList></SelectClause>
  <ReportInterval><Window>Last 24 hours</Window></ReportInterval>
  <PatternClause><SubPattern><Filters>
    <Filter><n>hostName</n><Operator>CONTAIN</Operator><Value>AFFECTED_HOST</Value></Filter>
    <Filter><n>rawEventMsg</n><Operator>REGEXP</Operator>
      <Value>(?i)(schtasks.*\/create|HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run|startup|service.*install)</Value>
    </Filter>
  </Filters></SubPattern></PatternClause>
</Report></Reports>
```

**Containment**: Isolate host → preserve memory → reimage from clean baseline → verify backup integrity → reconnect

---


## Playbook 5: Insider Threat
See [reference.md](reference.md) for the full insider threat playbook with covert investigation queries.
