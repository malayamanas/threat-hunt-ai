---
name: fsiem-l3-reference
description: Full MITRE ATT&CK technique library and campaign mapping implementation for fsiem-l3-hunt. Reference for the 24-technique dict and map_attack_campaign function.
---

# L3 Threat Intel — Full ATT&CK Reference

Full Python implementation for MITRE ATT&CK mapping. See [SKILL.md](SKILL.md) for the main workflow.

## Step 2 — MITRE ATT&CK Campaign Mapping

```python
# Full ATT&CK technique library with FortiSIEM query patterns
ATTACK_TECHNIQUES = {
    # Initial Access
    "T1078": {"name": "Valid Accounts",       "tactic": "Initial Access",
              "query_filter": "Successful Login", "regex": None},
    "T1190": {"name": "Exploit Public App",   "tactic": "Initial Access",
              "query_filter": "Web Attack",   "regex": r"sql.*inject|xss|path.*traversal|rce"},
    "T1566": {"name": "Phishing",             "tactic": "Initial Access",
              "query_filter": "Email",        "regex": r"malicious.*attach|phish"},
    # Execution
    "T1059": {"name": "Command Scripting",    "tactic": "Execution",
              "query_filter": "Process Launch","regex": r"powershell.*(-enc|-e |-nop|-w h)|cmd.*\/c|wscript|cscript"},
    "T1053": {"name": "Scheduled Task",       "tactic": "Persistence",
              "query_filter": "Process Launch","regex": r"schtasks.*\/create|New-ScheduledTask|at\.exe"},
    # Persistence
    "T1547": {"name": "Boot/Logon Autostart", "tactic": "Persistence",
              "query_filter": "Registry Modified","regex": r"Run|RunOnce|Services"},
    "T1136": {"name": "Create Account",       "tactic": "Persistence",
              "query_filter": "User Management","regex": r"net user.*\/add|New-LocalUser|useradd"},
    # Privilege Escalation
    "T1055": {"name": "Process Injection",    "tactic": "Privilege Escalation",
              "query_filter": "Process Launch","regex": r"CreateRemoteThread|VirtualAllocEx|WriteProcessMemory"},
    "T1548": {"name": "Abuse Elevation",      "tactic": "Privilege Escalation",
              "query_filter": "Privilege Use", "regex": r"sudo|runas|UAC bypass"},
    # Defense Evasion
    "T1027": {"name": "Obfuscated Files",     "tactic": "Defense Evasion",
              "query_filter": "Process Launch","regex": r"frombase64|encodedcommand|char\([0-9]+\)"},
    "T1562": {"name": "Impair Defenses",      "tactic": "Defense Evasion",
              "query_filter": "Service Control","regex": r"net stop|sc stop|taskkill.*defender|wscript.*off"},
    # Credential Access
    "T1003": {"name": "OS Credential Dumping","tactic": "Credential Access",
              "query_filter": "Process Launch","regex": r"lsass|procdump|mimikatz|sekurlsa|hashdump"},
    "T1110": {"name": "Brute Force",          "tactic": "Credential Access",
              "query_filter": "Failed Login",  "regex": None},
    "T1558": {"name": "Steal Kerberos Tickets","tactic": "Credential Access",
              "query_filter": "Kerberos",      "regex": r"kerberoast|asreproast|TGS.*request"},
    # Discovery
    "T1046": {"name": "Network Scan",         "tactic": "Discovery",
              "query_filter": "Port Scan",     "regex": None},
    "T1082": {"name": "System Info Discovery","tactic": "Discovery",
              "query_filter": "Process Launch","regex": r"systeminfo|hostname|whoami|ipconfig|ifconfig"},
    "T1087": {"name": "Account Discovery",    "tactic": "Discovery",
              "query_filter": "Process Launch","regex": r"net user|net group|Get-ADUser|ldapsearch"},
    # Lateral Movement
    "T1021": {"name": "Remote Services",      "tactic": "Lateral Movement",
              "query_filter": "Remote Login",  "regex": None},
    "T1550": {"name": "Pass the Hash/Ticket", "tactic": "Lateral Movement",
              "query_filter": "Successful Login","regex": r"pass.*hash|overpass|pass.*ticket"},
    # Collection
    "T1074": {"name": "Data Staged",          "tactic": "Collection",
              "query_filter": "File Created",  "regex": r"\.zip|\.7z|\.rar|\.tar"},
    "T1056": {"name": "Input Capture",        "tactic": "Collection",
              "query_filter": "Process Launch","regex": r"keylog|GetAsyncKeyState|SetWindowsHook"},
    # Exfiltration
    "T1041": {"name": "Exfil over C2",        "tactic": "Exfiltration",
              "query_filter": "Network Connection","regex": None},
    "T1048": {"name": "Exfil Alt Protocol",   "tactic": "Exfiltration",
              "query_filter": "DNS",           "regex": r"[a-z0-9]{20,}\."},
    # Impact
    "T1486": {"name": "Data Encrypted (Ransomware)","tactic": "Impact",
              "query_filter": "File Modified", "regex": r"vssadmin.*delete|shadow.*delete|\.locked|\.encrypted"},
    "T1490": {"name": "Inhibit Recovery",     "tactic": "Impact",
              "query_filter": "Process Launch","regex": r"vssadmin.*delete|wbadmin.*delete|bcdedit.*recover"},
}

def map_attack_campaign(events: list) -> dict:
    """
    Map a set of events to MITRE ATT&CK techniques.
    Returns a campaign profile with tactic coverage.
    """
    matched = {}
    for tech_id, tech in ATTACK_TECHNIQUES.items():
        hits = []
        for e in events:
            raw = (e.get("rawEventMsg","") + " " + e.get("eventType","")).lower()
            et = e.get("eventType","").lower()
            if tech["query_filter"].lower() in et:
                if tech["regex"] is None or re.search(tech["regex"], raw, re.IGNORECASE):
                    hits.append(e)
        if hits:
            matched[tech_id] = {
                "name": tech["name"],
                "tactic": tech["tactic"],
                "hit_count": len(hits),
                "first_seen": min((e.get("eventTime","") for e in hits), default=""),
                "last_seen":  max((e.get("eventTime","") for e in hits), default=""),
                "sample_event": hits[0] if hits else {},
            }

    # Derive campaign sophistication score
    tactics_covered = set(v["tactic"] for v in matched.values())
    sophistication = (
        "APT-LEVEL"    if len(tactics_covered) >= 6 else
        "ADVANCED"     if len(tactics_covered) >= 4 else
        "INTERMEDIATE" if len(tactics_covered) >= 2 else
        "BASIC"
    )

    return {
        "techniques_detected": matched,
        "tactics_covered": list(tactics_covered),
        "technique_count": len(matched),
        "sophistication": sophistication,
        "kill_chain_stages": len(tactics_covered),
    }
```

