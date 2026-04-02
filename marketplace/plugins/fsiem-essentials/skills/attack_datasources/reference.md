---
name: fsiem-attack-datasources-reference
description: Full ATTACK_DATASOURCE_MAP — ATT&CK technique to FortiSIEM event type mappings for all 15+ techniques. See SKILL.md for the analysis functions.
---

# ATT&CK Data Source Map — Full Reference

Full technique → data source → FortiSIEM event type mappings.
See [SKILL.md](SKILL.md) for the analysis and reporting functions.

---
name: fsiem-attack-datasources
description: Map MITRE ATT&CK techniques to their required data sources, then check which data sources are actually present in FortiSIEM. Answers "what logs do I need to detect T1110" and "which techniques are undetectable because the data isn't in your SIEM." Based on actual ATT&CK data source components, not keyword matching. Use when asked about detection coverage, data source gaps, or what logs to enable.
---

# ATT&CK Data Source Coverage for FortiSIEM

Anton Ovrutsky's key insight: ATT&CK has a **Data Source** component that tells you exactly what logs you need to detect each technique. This skill uses that data to show you which techniques you *cannot* detect because FortiSIEM doesn't have the required logs — not because you lack rules.

## The ATT&CK Data Source Model

```
Technique (T1110)
  └─ Data Source: User Account
       └─ Data Component: User Account Authentication
            └─ Collection Layer: Windows Security Log (EventID 4625/4624)
                                  Linux /var/log/auth.log
                                  RADIUS/TACACS logs
                                  Azure AD Sign-in logs
```

FortiSIEM needs to be ingesting at least one of those collection sources for the technique to be detectable.

## Embedded ATT&CK Data Source Library

```python
# ATT&CK v14 data source mappings — techniques mapped to required data components
# and the FortiSIEM event types / parser names that satisfy them
# Structure: technique_id → {data_component → [fortisiem_event_types]}

ATTACK_DATASOURCE_MAP = {

    # ── INITIAL ACCESS ─────────────────────────────────────────────────────
    "T1078": {
        "name": "Valid Accounts",
        "tactic": "Initial Access / Persistence / Defense Evasion",
        "data_components": {
            "User Account: User Account Authentication": {
                "fortisiem_event_types": [
                    "Successful Login", "Failed Login", "Win-Security-4624",
                    "Win-Security-4625", "Win-Security-4648", "RADIUS-Auth",
                    "Cisco-VPN-Auth", "Fortinet-VPN-Login",
                ],
                "collection_sources": ["Windows Security Log", "VPN Logs", "RADIUS/TACACS"],
                "coverage": "FULL",
            },
            "Logon Session: Logon Session Creation": {
                "fortisiem_event_types": ["Win-Security-4624", "Win-Security-4634"],
                "collection_sources": ["Windows Security Log"],
                "coverage": "FULL",
            },
        },
        "priority": "CRITICAL",
    },


    "T1133": {
        "name": "External Remote Services (VPN/RDP/Citrix)",
        "tactic": "Initial Access / Persistence",
        "data_components": {
            "Network Traffic: Network Traffic Flow": {
                "fortisiem_event_types": [
                    "VPN-Login", "VPN-Auth", "Fortinet-VPN", "Cisco-AnyConnect",
                    "Palo-GlobalProtect", "Win-Security-4624-Type3",
                ],
                "collection_sources": ["VPN Gateway Logs", "Firewall", "RADIUS/TACACS"],
                "coverage": "FULL",
            },
            "User Account: User Account Authentication": {
                "fortisiem_event_types": [
                    "Win-Security-4624", "Win-Security-4625", "RADIUS-Auth",
                    "TACACS-Auth", "SAML-SSO-Login",
                ],
                "collection_sources": ["VPN/Gateway Logs", "RADIUS", "AD Authentication"],
                "coverage": "FULL",
                "gap_note": "Must correlate VPN success + geo-anomaly for meaningful signal. Raw auth success alone is too noisy.",
            },
            "Application Log: Application Log Content": {
                "fortisiem_event_types": [
                    "VPN-Session-Create", "VPN-Session-End", "VPN-Config-Change",
                ],
                "collection_sources": ["VPN Appliance Logs (Fortinet/Cisco/Palo)"],
                "coverage": "PARTIAL",
            },
        },
        "priority": "CRITICAL",
        "gap_note": "Primary VPN technique — T1078 (stolen creds) + T1133 (VPN access) is the most common APT initial access chain.",
    },

    "T1190": {
        "name": "Exploit Public-Facing Application",
        "tactic": "Initial Access",
        "data_components": {
            "Application Log: Application Log Content": {
                "fortisiem_event_types": [
                    "Web-Attack", "WAF-Alert", "IDS-Exploit",
                    "Apache-Error", "IIS-Error", "Nginx-4xx",
                ],
                "collection_sources": ["Web Server Logs", "WAF", "IDS/IPS"],
                "coverage": "FULL",
            },
            "Network Traffic: Network Traffic Content": {
                "fortisiem_event_types": ["IDS-Alert", "DPI-Event", "Snort-Alert"],
                "collection_sources": ["IDS/IPS", "Network DPI"],
                "coverage": "PARTIAL",
            },
        },
        "priority": "CRITICAL",
    },

    "T1566": {
        "name": "Phishing",
        "tactic": "Initial Access",
        "data_components": {
            "Application Log: Application Log Content": {
                "fortisiem_event_types": [
                    "Email-Received", "Email-Attachment", "Proofpoint-Alert",
                    "Mimecast-Alert", "O365-Email", "Exchange-Transport",
                ],
                "collection_sources": ["Email Gateway Logs", "O365/Exchange"],
                "coverage": "PARTIAL",
            },
            "Network Traffic: Network Traffic Flow": {
                "fortisiem_event_types": ["Proxy-Access", "DNS-Query", "URL-Filter"],
                "collection_sources": ["Web Proxy", "DNS Logs"],
                "coverage": "PARTIAL",
            },
        },
        "priority": "HIGH",
        "gap_note": "Requires email gateway log ingestion (Proofpoint/Mimecast/O365). Not default in many FortiSIEM deployments.",
    },

    # ── EXECUTION ──────────────────────────────────────────────────────────
    "T1059": {
        "name": "Command and Scripting Interpreter",
        "tactic": "Execution",
        "data_components": {
            "Process: Process Creation": {
                "fortisiem_event_types": [
                    "Sysmon-1", "Win-Security-4688", "Process-Launch",
                    "Process-Create", "FortiEDR-Process",
                ],
                "collection_sources": ["Sysmon", "Windows Security Audit", "EDR"],
                "coverage": "FULL",
            },
            "Command: Command Execution": {
                "fortisiem_event_types": [
                    "Win-Powershell-4104", "Win-Powershell-4103",
                    "Script-Block-Logging",
                ],
                "collection_sources": ["PowerShell Script Block Logging"],
                "coverage": "PARTIAL",
                "gap_note": "Requires PowerShell Script Block Logging enabled (HKLM\\...\\PowerShell\\ScriptBlockLogging)",
            },
        },
        "priority": "CRITICAL",
    },

    # ── PERSISTENCE ────────────────────────────────────────────────────────
    "T1053": {
        "name": "Scheduled Task/Job",
        "tactic": "Persistence",
        "data_components": {
            "Scheduled Job: Scheduled Job Creation": {
                "fortisiem_event_types": [
                    "Win-Security-4698", "Win-Security-4702", "Sysmon-1",
                    "Process-Launch",
                ],
                "collection_sources": ["Windows Security Log", "Sysmon"],
                "coverage": "FULL",
            },
            "Process: Process Creation": {
                "fortisiem_event_types": ["Sysmon-1", "Win-Security-4688"],
                "collection_sources": ["Sysmon", "Windows Security Audit"],
                "coverage": "FULL",
            },
        },
        "priority": "HIGH",
    },

    "T1547": {
        "name": "Boot/Logon Autostart Execution",
        "tactic": "Persistence",
        "data_components": {
            "Windows Registry: Windows Registry Key Modification": {
                "fortisiem_event_types": [
                    "Win-Security-4657", "Sysmon-12", "Sysmon-13",
                    "Registry-Modified",
                ],
                "collection_sources": ["Windows Security Audit", "Sysmon"],
                "coverage": "PARTIAL",
                "gap_note": "Requires Windows Registry Auditing enabled or Sysmon Rule 12/13",
            },
        },
        "priority": "MEDIUM",
    },

    # ── PRIVILEGE ESCALATION / DEFENSE EVASION ────────────────────────────
    "T1055": {
        "name": "Process Injection",
        "tactic": "Defense Evasion / Privilege Escalation",
        "data_components": {
            "Process: Process Access": {
                "fortisiem_event_types": ["Sysmon-10", "EDR-Process-Access"],
                "collection_sources": ["Sysmon", "EDR"],
                "coverage": "PARTIAL",
                "gap_note": "Sysmon Event 10 (ProcessAccess) required. High noise — needs filtering.",
            },
            "Process: OS API Execution": {
                "fortisiem_event_types": ["EDR-API-Call", "FortiEDR-Injection"],
                "collection_sources": ["EDR with API monitoring"],
                "coverage": "LOW",
                "gap_note": "Requires EDR with API-level monitoring (CrowdStrike, SentinelOne, FortiEDR)",
            },
        },
        "priority": "HIGH",
    },

    "T1562": {
        "name": "Impair Defenses",
        "tactic": "Defense Evasion",
        "data_components": {
            "Windows Registry: Windows Registry Key Modification": {
                "fortisiem_event_types": ["Sysmon-12", "Sysmon-13", "Win-Security-4657"],
                "collection_sources": ["Sysmon", "Windows Security Audit"],
                "coverage": "PARTIAL",
            },
            "Service: Service Metadata": {
                "fortisiem_event_types": [
                    "Win-System-7036", "Win-System-7045", "Service-Stopped",
                ],
                "collection_sources": ["Windows System Log"],
                "coverage": "FULL",
            },
        },
        "priority": "HIGH",
    },

    # ── CREDENTIAL ACCESS ──────────────────────────────────────────────────
    "T1110": {
        "name": "Brute Force",
        "tactic": "Credential Access",
        "data_components": {
            "User Account: User Account Authentication": {
                "fortisiem_event_types": [
                    "Failed Login", "Win-Security-4625", "Win-Security-4740",
                    "RADIUS-Auth-Fail", "SSH-Auth-Fail", "VPN-Auth-Fail",
                ],
                "collection_sources": ["Windows Security Log", "VPN/RADIUS", "SSH Logs"],
                "coverage": "FULL",
            },
            "Application Log: Application Log Content": {
                "fortisiem_event_types": [
                    "Web-Auth-Fail", "OWA-Auth-Fail", "ADFS-Auth-Fail",
                ],
                "collection_sources": ["Web Application Logs", "ADFS Logs"],
                "coverage": "PARTIAL",
            },
        },
        "priority": "CRITICAL",
    },

    "T1003": {
        "name": "OS Credential Dumping",
        "tactic": "Credential Access",
        "data_components": {
            "Process: Process Access": {
                "fortisiem_event_types": ["Sysmon-10", "EDR-LSASS-Access"],
                "collection_sources": ["Sysmon (Event 10)", "EDR"],
                "coverage": "PARTIAL",
                "gap_note": "CRITICAL gap. Requires Sysmon Event 10 filtering for lsass.exe TargetImage.",
            },
            "Process: OS API Execution": {
                "fortisiem_event_types": ["EDR-API-Credential", "Win-Security-4663"],
                "collection_sources": ["EDR", "Windows Security Audit"],
                "coverage": "LOW",
            },
            "File: File Access": {
                "fortisiem_event_types": [
                    "Win-Security-4663", "Sysmon-11",
                ],
                "collection_sources": ["Windows Security Object Access Audit"],
                "coverage": "PARTIAL",
            },
        },
        "priority": "CRITICAL",
    },

    "T1558": {
        "name": "Steal or Forge Kerberos Tickets",
        "tactic": "Credential Access",
        "data_components": {
            "Active Directory: Active Directory Credential Request": {
                "fortisiem_event_types": [
                    "Win-Security-4769", "Win-Security-4768", "Win-Security-4771",
                ],
                "collection_sources": ["Domain Controller Security Log"],
                "coverage": "FULL",
                "gap_note": "Requires Domain Controller log ingestion into FortiSIEM",
            },
        },
        "priority": "HIGH",
    },

    # ── DISCOVERY ─────────────────────────────────────────────────────────
    "T1046": {
        "name": "Network Service Scanning",
        "tactic": "Discovery",
        "data_components": {
            "Network Traffic: Network Traffic Flow": {
                "fortisiem_event_types": [
                    "Port-Scan", "Network-Scan", "IDS-Scan",
                    "Firewall-Deny-Multiple",
                ],
                "collection_sources": ["IDS/IPS", "Firewall Logs", "NetFlow"],
                "coverage": "FULL",
            },
        },
        "priority": "MEDIUM",
    },

    "T1087": {
        "name": "Account Discovery",
        "tactic": "Discovery",
        "data_components": {
            "Process: Process Creation": {
                "fortisiem_event_types": ["Sysmon-1", "Win-Security-4688"],
                "collection_sources": ["Sysmon", "Windows Security Audit"],
                "coverage": "FULL",
            },
            "Active Directory: Active Directory Object Access": {
                "fortisiem_event_types": ["Win-Security-4661", "LDAP-Query"],
                "collection_sources": ["Domain Controller Security Log"],
                "coverage": "PARTIAL",
            },
        },
        "priority": "MEDIUM",
    },

    # ── LATERAL MOVEMENT ──────────────────────────────────────────────────
    "T1021": {
        "name": "Remote Services",
        "tactic": "Lateral Movement",
        "data_components": {
            "Logon Session: Logon Session Creation": {
                "fortisiem_event_types": [
                    "Win-Security-4624", "Win-Security-4648",
                    "RDP-Login", "SSH-Login",
                ],
                "collection_sources": ["Windows Security Log", "SSH/RDP Logs"],
                "coverage": "FULL",
            },
            "Network Traffic: Network Connection Creation": {
                "fortisiem_event_types": [
                    "Sysmon-3", "Firewall-Allow", "NetFlow",
                ],
                "collection_sources": ["Sysmon", "Firewall", "NetFlow"],
                "coverage": "FULL",
            },
        },
        "priority": "HIGH",
    },

    "T1550": {
        "name": "Use Alternate Authentication Material",
        "tactic": "Lateral Movement",
        "data_components": {
            "Active Directory: Active Directory Credential Request": {
                "fortisiem_event_types": ["Win-Security-4769", "Win-Security-4624"],
                "collection_sources": ["Domain Controller Security Log"],
                "coverage": "PARTIAL",
                "gap_note": "Pass-the-hash shows as Type 3 logon without preceding 4776. Requires correlation rule.",
            },
            "User Account: User Account Authentication": {
                "fortisiem_event_types": ["Win-Security-4624", "Win-Security-4648"],
                "collection_sources": ["Windows Security Log"],
                "coverage": "PARTIAL",
            },
        },
        "priority": "HIGH",
    },

    # ── COLLECTION / EXFILTRATION / IMPACT ────────────────────────────────
    "T1041": {
        "name": "Exfiltration Over C2 Channel",
        "tactic": "Exfiltration",
        "data_components": {
            "Network Traffic: Network Traffic Flow": {
                "fortisiem_event_types": [
                    "Firewall-Allow-Outbound", "NetFlow", "Proxy-Access",
                    "DNS-Query",
                ],
                "collection_sources": ["Firewall", "NetFlow/IPFIX", "Web Proxy"],
                "coverage": "FULL",
            },
            "Network Traffic: Network Traffic Content": {
                "fortisiem_event_types": ["IDS-Alert", "DPI-Event"],
                "collection_sources": ["IDS/IPS with DPI"],
                "coverage": "PARTIAL",
            },
        },
        "priority": "HIGH",
    },

    "T1486": {
        "name": "Data Encrypted for Impact",
        "tactic": "Impact",
        "data_components": {
            "File: File Modification": {
                "fortisiem_event_types": [
                    "Sysmon-11", "File-Modified", "Win-Security-4663",
                ],
                "collection_sources": ["Sysmon", "Windows File Audit"],
                "coverage": "PARTIAL",
                "gap_note": "File modification audit is noisy. Target: mass modifications in short time.",
            },
            "Process: Process Creation": {
                "fortisiem_event_types": ["Sysmon-1", "Win-Security-4688"],
                "collection_sources": ["Sysmon", "Windows Security Audit"],
                "coverage": "FULL",
                "gap_note": "Hunt for vssadmin.exe, wbadmin.exe, bcdedit.exe child processes",
            },
        },
        "priority": "CRITICAL",
    },
}
```

