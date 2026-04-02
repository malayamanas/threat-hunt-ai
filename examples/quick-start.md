# Quick Start Examples

## Setup

```bash
# 1. Install the plugin
git clone https://github.com/AiStudio-TechOwl/fortisiem-ai.git
cd your-project
/plugin marketplace add /path/to/fortisiem-ai/marketplace
/plugin install fsiem-essentials@fsiem-marketplace

# 2. Set credentials
export FSIEM_HOST="https://your-fortisiem-host"
export FSIEM_USER="admin"
export FSIEM_PASS="yourpassword"
export FSIEM_ORG="super"

# 3. Initialize
/init-fsiem
```

## Common Workflows

### L1 Triage — Process the Alert Queue
```
/fsiem-l1-triage
```
Automatically loads open incidents, classifies each as TP/FP/Benign, enriches external IPs, and generates a shift handover report.

### Hunt for an IOC
```
/fsiem-hunt 185.220.101.5
/fsiem-hunt T1486
/fsiem-hunt evil-domain.com
```
Searches FortiSIEM event data for the given IP, MITRE technique, or domain.

### Investigate an Incident
```
/fsiem-l2-investigate 12345
```
Builds a full attack timeline, enriches indicators, maps blast radius, and produces an investigation report.

### Create a Detection Rule
```
/fsiem-rule-create brute force RDP login
```
Designs a correlation rule with XML, maps it to MITRE ATT&CK, tests against historical data, and deploys.

### Run a Hypothesis Hunt
```
/fsiem-hypothesis-hunt "C2 beaconing from internal hosts using DNS tunneling"
```
Structures the hypothesis, generates FortiSIEM queries, runs them, and produces a hunt report.

### Check Device Health
```
/fsiem-health
```
Detects silent devices, lagging collectors, and parser failures.

### Query Events in Plain English
```
/fsiem-query all failed logins from 10.0.0.0/8 in the last 4 hours
```
Translates natural language to FortiSIEM XML query, submits, polls, and returns results.

### Generate a Report
```
/fsiem-report-generate executive summary for last 7 days
/fsiem-report-generate shift handover
```

### Multi-Org Sweep (MSSP)
```
/fsiem-multiorg sweep all orgs for high severity incidents
```
Runs queries across all organizations in a Service Provider deployment.
