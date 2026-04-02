# Playbooks — Insider Threat (Playbook 5)

Continued from [SKILL.md](SKILL.md).

## PLAYBOOK 5: Insider Threat

**Trigger**: DLP alert, departing employee, anomalous access, tip from HR/manager

### Covert Investigation Queries

```python
def insider_threat_queries(username: str, days_back: int = 90) -> list:
    """
    Returns list of query XMLs for insider threat investigation.
    Use with run_query() from ioc_management skill.
    IMPORTANT: Run these queries without alerting the suspect.
    """
    window = f"Last {days_back} days"
    return [
        # Unusual after-hours access
        f"""<Reports><Report>
          <n>Insider: After-Hours Activity</n>
          <SelectClause><AttrList>eventTime,eventType,srcIpAddr,hostName,rawEventMsg</AttrList></SelectClause>
          <ReportInterval><Window>{window}</Window></ReportInterval>
          <PatternClause><SubPattern><Filters>
            <Filter><n>user</n><Operator>CONTAIN</Operator><Value>{username}</Value></Filter>
            <Filter><n>eventType</n><Operator>IN</Operator><Value>Successful Login,File Access,VPN Login</Value></Filter>
          </Filters></SubPattern></PatternClause>
        </Report></Reports>""",

        # Sensitive data access
        f"""<Reports><Report>
          <n>Insider: Sensitive File Access</n>
          <SelectClause><AttrList>eventTime,fileName,hostName,eventType</AttrList></SelectClause>
          <ReportInterval><Window>{window}</Window></ReportInterval>
          <PatternClause><SubPattern><Filters>
            <Filter><n>user</n><Operator>CONTAIN</Operator><Value>{username}</Value></Filter>
            <Filter><n>fileName</n><Operator>REGEXP</Operator>
              <Value>(?i)(confidential|secret|restricted|payroll|salary|acquisition|password|vpn|ssh)</Value>
            </Filter>
          </Filters></SubPattern></PatternClause>
        </Report></Reports>""",

        # USB/removable media usage
        f"""<Reports><Report>
          <n>Insider: Removable Media</n>
          <SelectClause><AttrList>eventTime,rawEventMsg,hostName</AttrList></SelectClause>
          <ReportInterval><Window>{window}</Window></ReportInterval>
          <PatternClause><SubPattern><Filters>
            <Filter><n>user</n><Operator>CONTAIN</Operator><Value>{username}</Value></Filter>
            <Filter><n>rawEventMsg</n><Operator>REGEXP</Operator>
              <Value>(?i)(usb|removable|external.*drive|disk.*insert)</Value>
            </Filter>
          </Filters></SubPattern></PatternClause>
        </Report></Reports>""",

        # Bulk download / data staging
        f"""<Reports><Report>
          <n>Insider: Bulk Data Access</n>
          <SelectClause><AttrList>eventTime,fileName,COUNT(*),sentBytes</AttrList></SelectClause>
          <ReportInterval><Window>{window}</Window></ReportInterval>
          <PatternClause><SubPattern>
            <Filters>
              <Filter><n>user</n><Operator>CONTAIN</Operator><Value>{username}</Value></Filter>
              <Filter><n>eventType</n><Operator>IN</Operator><Value>File Copy,File Read,File Download</Value></Filter>
            </Filters>
            <GroupByAttr>user</GroupByAttr>
            <SingleEvt>false</SingleEvt>
            <Count><FilterAttribute>fileName</FilterAttribute><Operator>&gt;=</Operator><Value>50</Value></Count>
            <TimeWindow><Value>3600</Value></TimeWindow>
          </SubPattern></PatternClause>
        </Report></Reports>""",
    ]
```

---

## Playbook Execution Tracker

When running any playbook, track:

```markdown
## Playbook Execution Record
**Incident ID**: [FortiSIEM incident ID]
**Playbook**: [Ransomware / Account Compromise / Exfil / Malware / Insider]
**Analyst**: [name]
**Started**: [timestamp]

### Phase Completion
- [ ] Phase 1 — Confirm (target: <5 min)
- [ ] Phase 2 — Contain (target: <15 min)
- [ ] Phase 3 — Eradicate/Investigate (target: <4 hours)

### Key Findings
[Fill as investigation progresses]

### Evidence Preserved
- [ ] SIEM logs exported
- [ ] Memory captured
- [ ] Disk image taken
- [ ] Network captures saved

### Actions Taken
[List every action with timestamp]

### Communication Log
[Who was notified, when, and what was said]

### Closed
**Resolution**: [True Positive / False Positive / Inconclusive]
**Root Cause**: [Initial access vector]
**Lessons Learned**: [What rule/process would have caught this earlier?]
```
