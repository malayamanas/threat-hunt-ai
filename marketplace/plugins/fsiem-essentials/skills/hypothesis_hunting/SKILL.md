---
name: fsiem-hypothesis-hunt
description: Run structured hypothesis-driven threat hunts in FortiSIEM. Use when given a hypothesis like "there may be C2 beaconing", "an insider may be exfiltrating data", or any proactive hunt scenario. Produces a full hunt report with findings, evidence, and next steps.
---

# Hypothesis-Driven Threat Hunting

Threat hunting is proactive — you start with a hypothesis based on threat intelligence, anomaly signals, or MITRE ATT&CK, then systematically search for evidence. This skill drives the full lifecycle.

## The Hunt Lifecycle

```
1. HYPOTHESIS  →  2. DATA SOURCES  →  3. QUERIES  →  4. ANALYSIS  →  5. REPORT
   (What are       (What logs cover     (FortiSIEM      (Triage         (Document
    we looking      this technique?)     event queries)   findings)       everything)
    for?)
```

## Step 1 — Formulate the Hypothesis

A good hypothesis has three parts: **who/what**, **behavior**, **timeframe**.

Examples:
- "An internal host is beaconing to C2 infrastructure (regular outbound connections at fixed intervals) over the past 30 days"
- "A privileged account has been used from an unusual geographic location in the past 7 days"
- "A workstation is performing lateral movement via SMB/WMI to servers it has never accessed before"
- "Data is being exfiltrated via DNS tunneling — unusually long DNS queries or high query volume"

When the user gives you a hunt goal, restate it as a formal hypothesis before executing.

## Step 2 — Map to FortiSIEM Event Types

| Technique | FortiSIEM Event Types to Query |
|---|---|
| C2 Beaconing | `Network Connection`, `HTTP Request`, `DNS Query` |
| Lateral Movement | `Successful Login`, `SMB Connection`, `WMI Execution`, `RDP Connection` |
| Data Exfiltration | `File Copy`, `Large Outbound Transfer`, `DNS Query`, `HTTP POST` |
| Privilege Escalation | `Privilege Use`, `Process Launch`, `Token Manipulation` |
| Credential Dumping | `Process Launch`, `Registry Access`, `LSASS Access` |
| Persistence | `Scheduled Task`, `Registry Modification`, `Startup Item`, `Service Install` |
| Discovery/Recon | `Port Scan`, `Ping Sweep`, `LDAP Query`, `WMI Query` |
| Initial Access | `Failed Login`, `Phishing Email`, `Web Attack`, `VPN Login` |

## Step 3 — Execute Queries

Use `fsiem-event-query` skill to run the queries. Always:
- Search at minimum 7 days (30 days for slow/low hunts)
- Use multiple overlapping queries to triangulate
- Group results by source IP, user, or host to find outliers

### Query Templates by Hypothesis

**C2 Beaconing Hunt:**
```xml
<Reports><Report>
  <n>C2 Beaconing Hunt - Outbound Connections</n>
  <SelectClause><AttrList>srcIpAddr,destIpAddr,destPort,COUNT(*)</AttrList></SelectClause>
  <ReportInterval><Window>Last 30 days</Window></ReportInterval>
  <PatternClause><SubPattern>
    <Filters>
      <Filter><n>destPort</n><Operator>IN</Operator><Value>80,443,8080,8443,4444,1234,9999</Value></Filter>
      <Filter><n>srcIpAddr</n><Operator>REGEXP</Operator><Value>^10\.|^172\.(1[6-9]|2[0-9]|3[01])\.|^192\.168\.</Value></Filter>
    </Filters>
    <GroupByAttr>srcIpAddr,destIpAddr,destPort</GroupByAttr>
    <SingleEvt>false</SingleEvt>
    <Count><FilterAttribute>srcIpAddr</FilterAttribute><Operator>>=</Operator><Value>50</Value></Count>
    <TimeWindow><Value>86400</Value></TimeWindow>
  </SubPattern></PatternClause>
</Report></Reports>
```

**Lateral Movement Hunt:**
```xml
<Reports><Report>
  <n>Lateral Movement - Internal Host Logins</n>
  <SelectClause><AttrList>srcIpAddr,destIpAddr,user,eventType,eventTime</AttrList></SelectClause>
  <ReportInterval><Window>Last 7 days</Window></ReportInterval>
  <PatternClause><SubPattern>
    <Filters>
      <Filter><n>eventType</n><Operator>IN</Operator><Value>Successful Login,Remote Login,WMI Execution,SMB Connection,RDP Connection</Value></Filter>
      <Filter><n>srcIpAddr</n><Operator>REGEXP</Operator><Value>^10\.|^172\.|^192\.168\.</Value></Filter>
      <Filter><n>destIpAddr</n><Operator>REGEXP</Operator><Value>^10\.|^172\.|^192\.168\.</Value></Filter>
    </Filters>
    <GroupByAttr>srcIpAddr,user</GroupByAttr>
    <SingleEvt>false</SingleEvt>
    <Count><FilterAttribute>destIpAddr</FilterAttribute><Operator>>=</Operator><Value>3</Value></Count>
    <TimeWindow><Value>3600</Value></TimeWindow>
  </SubPattern></PatternClause>
</Report></Reports>
```

**DNS Tunneling Hunt:**
```xml
<Reports><Report>
  <n>DNS Tunneling Hunt</n>
  <SelectClause><AttrList>srcIpAddr,destIpAddr,rawEventMsg,COUNT(*)</AttrList></SelectClause>
  <ReportInterval><Window>Last 7 days</Window></ReportInterval>
  <PatternClause><SubPattern>
    <Filters>
      <Filter><n>eventType</n><Operator>CONTAIN</Operator><Value>DNS</Value></Filter>
      <Filter><n>rawEventMsg</n><Operator>REGEXP</Operator><Value>.{40,}</Value></Filter>
    </Filters>
    <GroupByAttr>srcIpAddr</GroupByAttr>
    <SingleEvt>false</SingleEvt>
    <Count><FilterAttribute>srcIpAddr</FilterAttribute><Operator>>=</Operator><Value>100</Value></Count>
    <TimeWindow><Value>3600</Value></TimeWindow>
  </SubPattern></PatternClause>
</Report></Reports>
```

**Data Exfiltration Hunt:**
```xml
<Reports><Report>
  <n>Data Exfiltration - Large Outbound</n>
  <SelectClause><AttrList>srcIpAddr,destIpAddr,destPort,sentBytes,eventTime</AttrList></SelectClause>
  <ReportInterval><Window>Last 7 days</Window></ReportInterval>
  <PatternClause><SubPattern>
    <Filters>
      <Filter><n>sentBytes</n><Operator>>=</Operator><Value>104857600</Value></Filter>
      <Filter><n>destIpAddr</n><Operator>NOT REGEXP</Operator><Value>^10\.|^172\.|^192\.168\.</Value></Filter>
    </Filters>
  </SubPattern></PatternClause>
</Report></Reports>
```

## Step 4 — Analyze Results

For each result set, evaluate:

1. **Frequency**: Is this event rate normal for this host/user?
2. **Timing**: Does this happen at regular intervals (beaconing) or off-hours?
3. **Volume**: Is the data volume anomalous?
4. **Destinations**: Are the destinations new, rare, or known-bad?
5. **Pattern**: Does the pattern match MITRE ATT&CK technique behavior?

**Scoring rubric** (use to prioritize findings):
- NEW destination never seen before: +3
- Off-hours activity (outside 07:00-19:00 local): +2
- High frequency/regularity: +2
- Destination in threat intel feed: +5
- Admin account involved: +2
- Pattern matches known TTPs: +3

Score >= 5 = escalate immediately
Score 3-4 = investigate further
Score < 3 = document and monitor

## Step 5 — Hunt Report Template

Always produce a structured report:

```markdown
## Threat Hunt Report
**Hypothesis**: [your hypothesis]
**Analyst**: [name]
**Date**: [date]
**Hunt Period**: [start] to [end]

### Executive Summary
[2-3 sentences: what was hunted, what was found]

### Queries Executed
| Query | Time Window | Records | Hits |
|---|---|---|---|
| C2 Beaconing - Outbound | 30 days | 15,243 | 3 |

### Findings
#### Finding 1: [Host/User/IP]
- **Score**: 7/10
- **Evidence**: [specific events, IPs, timestamps]
- **MITRE Technique**: [T-number and name]
- **Disposition**: True Positive / False Positive / Needs Investigation

### Conclusion
[Confirmed threat / No threat found / Inconclusive]

### Recommended Rules
[List any new FortiSIEM rules that should be created based on findings]

### Next Steps
1. [Action 1]
2. [Action 2]
```

## MITRE ATT&CK Hypothesis Library

Quick-start hypotheses aligned to common techniques:

| Hypothesis | MITRE | Key Indicator |
|---|---|---|
| Credential brute force underway | T1110 | >10 failed logins/5min same source |
| C2 via HTTP/S | T1071.001 | Regular outbound connections, fixed interval |
| Living off the land (LOLBins) | T1059 | PowerShell/WMI/certutil with encoded args |
| Pass the hash / pass the ticket | T1550 | Logins with no preceding auth event |
| Kerberoasting | T1558.003 | Service ticket requests for many SPNs |
| Scheduled task persistence | T1053 | schtasks.exe with /create flag |
| LSASS credential dump | T1003.001 | Access to lsass.exe from non-system process |
| Shadow copy deletion (ransomware) | T1490 | vssadmin delete or wmic shadowcopy delete |
| DNS tunneling | T1071.004 | Long subdomain queries, high query rate |
| Data staged in unusual location | T1074 | Large files written to temp/public dirs |

## Additional Resources
- Full Python implementations: [reference.md](reference.md)
