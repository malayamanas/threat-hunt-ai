---
name: fsiem-apt-profiles
description: APT group TTP profiles for proactive threat hunting — APT28, APT29, Lazarus, FIN7, Sandworm, APT41, and others. Each profile contains the group's known FortiSIEM hunt queries, C2 infrastructure characteristics, and specific detection patterns. Use when building a proactive hunt program targeting actors relevant to your industry and geography.
---

# APT Group Hunt Profiles

For each group: who they target, what TTPs they use, and the specific FortiSIEM queries that find their activity.

## APT Group Selection by Sector

```python
SECTOR_APT_MAP = {
    "financial":       ["Lazarus", "FIN7", "APT38", "Carbanak"],
    "government":      ["APT28", "APT29", "APT41", "Turla"],
    "healthcare":      ["APT41", "FIN7", "DarkSide"],
    "energy":          ["Sandworm", "APT33", "TEMP.Veles"],
    "defence":         ["APT28", "APT29", "APT10", "APT40"],
    "technology":      ["APT41", "APT10", "Winnti", "APT29"],
    "retail":          ["FIN7", "FIN8", "Magecart"],
    "critical_infra":  ["Sandworm", "APT33", "XENOTIME"],
}

def get_apt_profiles_for_sector(sector: str) -> list:
    """Return relevant APT groups for a given sector."""
    groups = SECTOR_APT_MAP.get(sector.lower(), ["APT28", "APT29", "FIN7"])
    return [APT_PROFILES[g] for g in groups if g in APT_PROFILES]
```

## Full APT Profile Library

```python
from datetime import datetime

APT_PROFILES = {

    "APT28": {
        "name":         "APT28 (Fancy Bear / Sofacy)",
        "nation":       "Russia (GRU)",
        "sectors":      ["Government", "Defence", "Media", "Political"],
        "motivation":   "Espionage / Intelligence collection",
        "active_since": "2004",

        "key_ttps": {
            "T1078": "Credential theft via phishing → valid account reuse",
            "T1566": "Spearphishing with weaponized Office docs",
            "T1059": "X-Agent implant uses PowerShell for execution",
            "T1071": "X-Tunnel for encrypted C2 (HTTP/S)",
            "T1003": "Mimikatz variant for credential harvesting",
            "T1550": "Pass-the-hash across domain",
            "T1021": "RDP lateral movement after credential theft",
        },

        "infrastructure_signatures": {
            "c2_characteristics": [
                "Uses legitimate cloud services (OneDrive, Dropbox) as C2",
                "HTTPS C2 with valid-looking domains mimicking Microsoft/Google",
                "Short-lived VPS in Eastern Europe (RU, UA, BY, RO)",
                "Let's Encrypt certificates (free, throwaway)",
            ],
            "malware_user_agents": [
                "Mozilla/5.0 (compatible; MSIE 9.0; Windows Phone OS 7.5)",
                "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)",
            ],
            "c2_uri_patterns": ["/wp-content/", "/api/v1/", "/jquery/", "/bootstrap/"],
        },

        "fortisiem_hunt_queries": {
            "vpn_from_eastern_europe": """<Reports><Report><n>APT28 VPN Hunt</n>
              <SelectClause><AttrList>eventTime,user,srcIpAddr,srcCountry,destIpAddr</AttrList></SelectClause>
              <ReportInterval><Window>Last 30 days</Window></ReportInterval>
              <PatternClause><SubPattern><Filters>
                <Filter><n>eventType</n><Operator>IN</Operator>
                  <Value>VPN-Login,Win-Security-4624,Successful Login</Value></Filter>
                <Filter><n>srcCountry</n><Operator>IN</Operator>
                  <Value>RU,UA,BY,RO,MD</Value></Filter>
              </Filters></SubPattern></PatternClause></Report></Reports>""",

            "xtunnel_c2_pattern": """<Reports><Report><n>APT28 X-Tunnel Hunt</n>
              <SelectClause><AttrList>srcIpAddr,destIpAddr,destPort,sentBytes,eventTime</AttrList></SelectClause>
              <ReportInterval><Window>Last 30 days</Window></ReportInterval>
              <PatternClause><SubPattern><Filters>
                <Filter><n>eventType</n><Operator>IN</Operator>
                  <Value>Network Connection,Firewall Allow</Value></Filter>
                <Filter><n>destPort</n><Operator>IN</Operator>
                  <Value>443,80,8080,8443</Value></Filter>
                <Filter><n>sentBytes</n><Operator>&gt;=</Operator><Value>1048576</Value></Filter>
              </Filters></SubPattern></PatternClause></Report></Reports>""",

            "credential_theft_chain": """<Reports><Report><n>APT28 Cred Chain</n>
              <SelectClause><AttrList>eventTime,user,processName,hostName,rawEventMsg</AttrList></SelectClause>
              <ReportInterval><Window>Last 14 days</Window></ReportInterval>
              <PatternClause><SubPattern><Filters>
                <Filter><n>rawEventMsg</n><Operator>REGEXP</Operator>
                  <Value>mimikatz|sekurlsa|lsass.*access|procdump.*lsass</Value></Filter>
              </Filters></SubPattern></PatternClause></Report></Reports>""",
        },
    },

    "APT29": {
        "name":         "APT29 (Cozy Bear / The Dukes)",
        "nation":       "Russia (SVR)",
        "sectors":      ["Government", "Think Tanks", "Healthcare", "Technology"],
        "motivation":   "Long-term espionage / intelligence",
        "active_since": "2008",

        "key_ttps": {
            "T1059": "Heavy PowerShell + WMI — living off the land, no custom malware",
            "T1053": "Scheduled tasks for persistence (disguised as legitimate tasks)",
            "T1078": "Stolen service account credentials for long dwell",
            "T1021": "WMI lateral movement (wmic /node:)",
            "T1041": "Slow exfiltration via HTTPS to cloud storage",
            "T1036": "Masquerading — malware named after legitimate Windows binaries",
            "T1070": "Event log clearing after operations",
        },

        "key_characteristic": "Does NOT use custom malware. Exclusively LOLBins (PowerShell, WMI, certutil, bitsadmin). Detection requires behavioral analysis, not signatures.",

        "infrastructure_signatures": {
            "c2_characteristics": [
                "Compromised legitimate websites as C2 relay (watering hole infrastructure)",
                "Google Drive, OneDrive used for data staging",
                "Very slow C2 polling (hours between beacons) to avoid detection",
                "HTTPS only, certificate pinning in implants",
            ],
        },

        "fortisiem_hunt_queries": {
            "wmi_lateral_movement": """<Reports><Report><n>APT29 WMI Lateral</n>
              <SelectClause><AttrList>eventTime,user,processName,hostName,rawEventMsg</AttrList></SelectClause>
              <ReportInterval><Window>Last 14 days</Window></ReportInterval>
              <PatternClause><SubPattern><Filters>
                <Filter><n>processName</n><Operator>CONTAIN</Operator><Value>wmic</Value></Filter>
                <Filter><n>rawEventMsg</n><Operator>CONTAIN</Operator><Value>/node:</Value></Filter>
              </Filters></SubPattern></PatternClause></Report></Reports>""",

            "scheduled_task_persistence": """<Reports><Report><n>APT29 Persistence</n>
              <SelectClause><AttrList>eventTime,user,processName,hostName,rawEventMsg</AttrList></SelectClause>
              <ReportInterval><Window>Last 30 days</Window></ReportInterval>
              <PatternClause><SubPattern><Filters>
                <Filter><n>eventType</n><Operator>IN</Operator>
                  <Value>Win-Security-4698,Scheduled Task Created</Value></Filter>
                <Filter><n>user</n><Operator>NOT_REGEXP</Operator>
                  <Value>SYSTEM|Administrator|NETWORK SERVICE</Value></Filter>
              </Filters></SubPattern></PatternClause></Report></Reports>""",

            "event_log_clearing": """<Reports><Report><n>APT29 Log Clear</n>
              <SelectClause><AttrList>eventTime,user,hostName,rawEventMsg</AttrList></SelectClause>
              <ReportInterval><Window>Last 7 days</Window></ReportInterval>
              <PatternClause><SubPattern><Filters>
                <Filter><n>eventType</n><Operator>IN</Operator>
                  <Value>Win-Security-1102,Win-System-104,Audit Log Cleared</Value></Filter>
              </Filters></SubPattern></PatternClause></Report></Reports>""",

            "lotl_execution_chain": """<Reports><Report><n>APT29 LOtL Hunt</n>
              <SelectClause><AttrList>eventTime,processName,parentProcessName,user,hostName,rawEventMsg</AttrList></SelectClause>
              <ReportInterval><Window>Last 14 days</Window></ReportInterval>
              <PatternClause><SubPattern><Filters>
                <Filter><n>processName</n><Operator>REGEXP</Operator>
                  <Value>certutil.*-decode|bitsadmin.*/transfer|wmic.*process|mshta.exe</Value></Filter>
              </Filters></SubPattern></PatternClause></Report></Reports>""",
        },
    },

    "Lazarus": {
        "name":         "Lazarus Group (Hidden Cobra)",
        "nation":       "North Korea (RGB Bureau 121)",
        "sectors":      ["Financial", "Cryptocurrency", "Defence", "Media"],
        "motivation":   "Financial theft / sanctions evasion / espionage",
        "active_since": "2009",

        "key_ttps": {
            "T1566": "Spearphishing with job-themed lures (LinkedIn recruitment)",
            "T1059": "Custom loaders + PowerShell droppers",
            "T1041": "Large financial transfers via SWIFT / crypto wallets",
            "T1105": "Multi-stage dropper delivery via cloud storage",
            "T1003": "Credential harvesting targeting finance systems",
            "T1078": "Targeting of VPN and remote access credentials",
        },

        "key_characteristic": "Financial focus — specifically targeting SWIFT terminals, trading platforms, crypto exchanges. Look for access to financial application servers.",

        "infrastructure_signatures": {
            "c2_characteristics": [
                "Compromised legitimate servers in South Korea, India, Southeast Asia",
                "HTTPS C2 with domains mimicking financial institutions",
                "TOR for anonymization",
                "Custom C2 protocols (not standard Cobalt Strike/Metasploit)",
            ],
        },

        "fortisiem_hunt_queries": {
            "financial_system_access": """<Reports><Report><n>Lazarus Financial Access</n>
              <SelectClause><AttrList>eventTime,user,srcIpAddr,hostName,rawEventMsg</AttrList></SelectClause>
              <ReportInterval><Window>Last 30 days</Window></ReportInterval>
              <PatternClause><SubPattern><Filters>
                <Filter><n>hostName</n><Operator>REGEXP</Operator>
                  <Value>swift|payment|finance|treasury|trading|pos-</Value></Filter>
                <Filter><n>user</n><Operator>NOT_REGEXP</Operator>
                  <Value>svc_|service|system</Value></Filter>
              </Filters></SubPattern></PatternClause></Report></Reports>""",

            "external_access_to_finance": """<Reports><Report><n>Lazarus External Finance</n>
              <SelectClause><AttrList>eventTime,srcIpAddr,destIpAddr,user,sentBytes</AttrList></SelectClause>
              <ReportInterval><Window>Last 14 days</Window></ReportInterval>
              <PatternClause><SubPattern><Filters>
                <Filter><n>sentBytes</n><Operator>&gt;=</Operator><Value>5242880</Value></Filter>
                <Filter><n>destIpAddr</n><Operator>NOT_IN</Operator>
                  <Value>10.0.0.0/8,172.16.0.0/12,192.168.0.0/16</Value></Filter>
              </Filters></SubPattern></PatternClause></Report></Reports>""",
        },
    },

    "FIN7": {
        "name":         "FIN7 (Carbanak / Navigator)",
        "nation":       "Criminal (Eastern European origin)",
        "sectors":      ["Retail", "Hospitality", "Financial", "Restaurant chains"],
        "motivation":   "Financial — card data theft, ransomware deployment",
        "active_since": "2013",

        "key_ttps": {
            "T1566": "Highly tailored spearphishing with custom CARBANAK backdoor",
            "T1059": "PowerShell + VBScript payload delivery",
            "T1055": "Process injection into legitimate processes",
            "T1041": "Exfiltration via HTTPS to adversary-controlled servers",
            "T1486": "REVIL/Darkside ransomware deployment in later campaigns",
            "T1505": "Web shells on internet-facing servers",
        },

        "key_characteristic": "Targets Point-of-Sale systems. POS machines making outbound connections = immediate P1.",

        "fortisiem_hunt_queries": {
            "pos_outbound_connections": """<Reports><Report><n>FIN7 POS Hunt</n>
              <SelectClause><AttrList>eventTime,srcIpAddr,destIpAddr,destPort,sentBytes</AttrList></SelectClause>
              <ReportInterval><Window>Last 14 days</Window></ReportInterval>
              <PatternClause><SubPattern><Filters>
                <Filter><n>srcIpAddr</n><Operator>REGEXP</Operator>
                  <Value>pos-|register-|terminal-|checkout</Value></Filter>
                <Filter><n>destIpAddr</n><Operator>NOT_IN</Operator>
                  <Value>10.0.0.0/8,172.16.0.0/12,192.168.0.0/16</Value></Filter>
              </Filters></SubPattern></PatternClause></Report></Reports>""",

            "carbanak_c2_pattern": """<Reports><Report><n>FIN7 CARBANAK C2</n>
              <SelectClause><AttrList>srcIpAddr,destIpAddr,destPort,sentBytes,COUNT(eventId) AS conns</AttrList></SelectClause>
              <ReportInterval><Window>Last 7 days</Window></ReportInterval>
              <PatternClause><SubPattern><Filters>
                <Filter><n>destPort</n><Operator>IN</Operator><Value>443,80</Value></Filter>
                <Filter><n>destIpAddr</n><Operator>NOT_IN</Operator>
                  <Value>10.0.0.0/8,172.16.0.0/12,192.168.0.0/16</Value></Filter>
              </Filters></SubPattern></PatternClause></Report></Reports>""",
        },
    },

    "Sandworm": {
        "name":         "Sandworm (Voodoo Bear)",
        "nation":       "Russia (GRU Unit 74455)",
        "sectors":      ["Energy", "Critical Infrastructure", "Government", "Media"],
        "motivation":   "Sabotage / disruption / intelligence",
        "active_since": "2007",

        "key_ttps": {
            "T1566": "Spearphishing targeting ICS/SCADA operators",
            "T1078": "Valid account reuse via credential theft",
            "T1489": "Service disruption — stopping critical services",
            "T1490": "Shadow copy deletion before destructive operations",
            "T1561": "Disk wiping (NotPetya, Industroyer2)",
            "T1021": "RDP lateral movement to OT network segments",
        },

        "key_characteristic": "Most destructive APT in history. NotPetya, BlackEnergy, Industroyer. If you're in energy/utilities — this is your #1 threat.",

        "fortisiem_hunt_queries": {
            "destructive_preparation": """<Reports><Report><n>Sandworm Destruction Prep</n>
              <SelectClause><AttrList>eventTime,processName,user,hostName,rawEventMsg</AttrList></SelectClause>
              <ReportInterval><Window>Last 7 days</Window></ReportInterval>
              <PatternClause><SubPattern><Filters>
                <Filter><n>rawEventMsg</n><Operator>REGEXP</Operator>
                  <Value>vssadmin.*delete|wbadmin.*delete|bcdedit.*off|
                         format.*c:|cipher.*/w:|sdelete</Value></Filter>
              </Filters></SubPattern></PatternClause></Report></Reports>""",

            "ot_network_rdp": """<Reports><Report><n>Sandworm OT RDP</n>
              <SelectClause><AttrList>eventTime,user,srcIpAddr,destIpAddr,hostName</AttrList></SelectClause>
              <ReportInterval><Window>Last 30 days</Window></ReportInterval>
              <PatternClause><SubPattern><Filters>
                <Filter><n>eventType</n><Operator>IN</Operator><Value>RDP Login,Win-Security-4624</Value></Filter>
                <Filter><n>destIpAddr</n><Operator>REGEXP</Operator>
                  <Value>ot-|scada-|ics-|plc-|hmi-|historian</Value></Filter>
              </Filters></SubPattern></PatternClause></Report></Reports>""",
        },
    },
}

def run_apt_hunt(group_name: str, days_back: int = 30) -> str:
    """
    Run all hunt queries for a specific APT group and produce a report.
    """
    import os, base64, requests, xml.etree.ElementTree as ET, time as time_mod
    profile = APT_PROFILES.get(group_name)
    if not profile:
        available = list(APT_PROFILES.keys())
        return f"Group '{group_name}' not found. Available: {available}"

    lines = [
        f"# APT Hunt Report: {profile['name']}",
        f"**Nation**: {profile['nation']} | **Motivation**: {profile['motivation']}",
        f"**Target Sectors**: {', '.join(profile['sectors'])}",
        f"**Generated**: {datetime.now().strftime('%Y-%m-%d %H:%M')}",
        "",
        f"## Key Characteristic",
        profile.get("key_characteristic", "See TTPs below"),
        "",
        "## Hunt Query Results",
        "",
    ]

    host = os.environ["FSIEM_HOST"]
    _creds = f"{os.environ['FSIEM_USER']}/{os.environ['FSIEM_ORG']}:{os.environ['FSIEM_PASS']}"
    h_headers = {"Authorization": f"Basic {base64.b64encode(_creds.encode()).decode()}",
                 "Content-Type": "text/xml"}
    v = os.environ.get("FSIEM_VERIFY_SSL","false").lower() == "true"

    total_findings = 0
    for query_name, query_xml in profile["fortisiem_hunt_queries"].items():
        lines.append(f"### {query_name.replace('_',' ').title()}")
        try:
            r = requests.post(f"{host}/phoenix/rest/query/eventQuery",
                              data=query_xml, headers=h_headers, verify=v, timeout=30)
            r.raise_for_status()
            qid = r.text.strip()
            for _ in range(60):
                p = requests.get(f"{host}/phoenix/rest/query/progress/{qid}",
                                  headers=h_headers, verify=v, timeout=10)
                if int(p.text.strip() or "0") >= 100: break
                time_mod.sleep(2)
            r2 = requests.get(f"{host}/phoenix/rest/query/events/{qid}/0/50",
                               headers=h_headers, verify=v, timeout=30)
            root = ET.fromstring(r2.text)
            events = [{a.findtext("name",""): a.findtext("value","")
                       for a in ev.findall("attributes/attribute")}
                      for ev in root.findall(".//event")]
            if events:
                total_findings += len(events)
                lines.append(f"🔴 **{len(events)} results found**")
                for e in events[:5]:
                    row = " | ".join(f"{k}: {v}" for k, v in e.items()
                                    if v and k in ("eventTime","user","srcIpAddr","hostName","processName"))
                    lines.append(f"  - {row[:120]}")
            else:
                lines.append("✅ No results")
        except Exception as ex:
            lines.append(f"⚠️ Query failed: {ex}")
        lines.append("")

    lines += [
        f"## Summary",
        f"**Total findings**: {total_findings}",
        f"{'🔴 ESCALATE to L3 investigation immediately' if total_findings > 0 else '✅ No indicators of '+group_name+' activity found'}",
        "",
        "## Known TTPs for Detection Rule Creation",
    ]
    for tech_id, description in profile["key_ttps"].items():
        lines.append(f"- **{tech_id}**: {description}")

    return "\n".join(lines)
```
