#!/usr/bin/env python3
"""
FortiSIEM Investigation PDF Report Generator
Reads investigation JSON (from investigation_pipeline.py) and generates a
professional PDF with all L1/L2/L3 findings.

Usage:
    python3 report_pdf.py --input investigation.json --output report.pdf

Requires: fpdf2 (pip install fpdf2)
"""

import json
import sys
import os
import re
import argparse
from datetime import datetime

try:
    from fpdf import FPDF
except ImportError:
    print("ERROR: fpdf2 not installed. Run: pip3 install fpdf2")
    sys.exit(1)


# --- Color palette ---
NAVY = (20, 40, 80)
DARK_BLUE = (40, 60, 100)
LIGHT_BG = (230, 235, 245)
GREEN = (0, 100, 50)
RED = (180, 0, 0)
ORANGE = (200, 80, 0)
DARK_GRAY = (30, 30, 30)
MED_GRAY = (80, 80, 80)
LIGHT_GRAY = (128, 128, 128)

SEV_COLORS = {
    "CRITICAL": (180, 0, 0),
    "HIGH": (200, 80, 0),
    "MEDIUM": (200, 160, 0),
    "LOW": (0, 130, 0),
}


def _safe(text) -> str:
    """Replace unicode chars with ASCII for latin-1 PDF encoding."""
    if not isinstance(text, str):
        text = str(text)
    return (text
        .replace("\u2014", "--")
        .replace("\u2013", "-")
        .replace("\u2019", "'")
        .replace("\u2018", "'")
        .replace("\u201c", '"')
        .replace("\u201d", '"')
        .replace("\u2022", "*")
        .replace("\u25cf", "*")
        .replace("\u2192", "->")
        .replace("\u2190", "<-")
        .replace("\u2191", "^")
        .replace("\u2193", "v")
        .replace("\u2714", "[OK]")
        .replace("\u2716", "[X]")
        .replace("\u26a0", "[!]")
        .replace("\u2705", "[OK]")
        .replace("\u274c", "[X]")
        .replace("\U0001f534", "[!]")
    )


class InvestigationReport(FPDF):
    def __init__(self, data: dict):
        super().__init__()
        self.data = data
        self.alias_nb_pages()
        self.set_auto_page_break(auto=True, margin=20)

    def header(self):
        if self.page_no() == 1:
            return  # Cover page has no header
        self.set_font("Helvetica", "B", 9)
        self.set_text_color(*NAVY)
        inc = self.data.get("incident", {})
        self.cell(0, 6, _safe(
            f"Incident #{inc.get('id','')} | {inc.get('organization','')} | "
            f"TLP:AMBER | CONFIDENTIAL"
        ), new_x="LMARGIN", new_y="NEXT", align="C")
        self.set_draw_color(*NAVY)
        self.line(10, self.get_y(), 200, self.get_y())
        self.ln(3)

    def footer(self):
        self.set_y(-15)
        self.set_font("Helvetica", "I", 8)
        self.set_text_color(*LIGHT_GRAY)
        self.cell(0, 10, _safe(
            f"Page {self.page_no()}/{{nb}} | "
            f"Generated {datetime.now().strftime('%Y-%m-%d %H:%M')} | "
            f"FortiSIEM AI Investigation Pipeline v2.0"
        ), align="C")

    # --- Helper methods ---

    def section_title(self, num, title, color=NAVY):
        self.set_font("Helvetica", "B", 14)
        self.set_text_color(*color)
        self.cell(0, 10, _safe(f"{num}. {title}"), new_x="LMARGIN", new_y="NEXT")
        self.set_draw_color(*color)
        self.line(10, self.get_y(), 200, self.get_y())
        self.ln(4)

    def subsection(self, title, color=DARK_BLUE):
        self.set_font("Helvetica", "B", 11)
        self.set_text_color(*color)
        self.cell(0, 7, _safe(title), new_x="LMARGIN", new_y="NEXT")
        self.ln(2)

    def body(self, text):
        self.set_font("Helvetica", "", 10)
        self.set_text_color(*DARK_GRAY)
        self.multi_cell(0, 5, _safe(text))
        self.ln(2)

    def kv(self, key, value, bold_value=False):
        self.set_font("Helvetica", "B", 10)
        self.set_text_color(*MED_GRAY)
        self.cell(50, 6, _safe(key))
        self.set_font("Helvetica", "B" if bold_value else "", 10)
        self.set_text_color(*DARK_GRAY)
        self.cell(0, 6, _safe(str(value)), new_x="LMARGIN", new_y="NEXT")

    def table(self, headers, rows, widths=None):
        if not widths:
            w = 190 / len(headers)
            widths = [w] * len(headers)
        # Header
        self.set_font("Helvetica", "B", 8)
        self.set_fill_color(*LIGHT_BG)
        self.set_text_color(*NAVY)
        for i, h in enumerate(headers):
            self.cell(widths[i], 7, _safe(h), border=1, align="C", fill=True)
        self.ln()
        # Rows
        self.set_font("Helvetica", "", 8)
        self.set_text_color(*DARK_GRAY)
        for row in rows:
            for i, val in enumerate(row):
                max_chars = int(widths[i] * 0.5)
                self.cell(widths[i], 6, _safe(str(val)[:max_chars]), border=1)
            self.ln()

    def severity_text(self, severity):
        color = SEV_COLORS.get(severity.upper(), MED_GRAY)
        self.set_font("Helvetica", "B", 10)
        self.set_text_color(*color)
        self.cell(0, 6, _safe(severity), new_x="LMARGIN", new_y="NEXT")
        self.set_text_color(*DARK_GRAY)

    # --- Page builders ---

    def build_cover(self):
        self.add_page()
        # Title block
        self.ln(25)
        self.set_fill_color(*NAVY)
        self.rect(0, 45, 210, 50, "F")
        self.set_y(50)
        self.set_font("Helvetica", "B", 28)
        self.set_text_color(255, 255, 255)
        self.cell(0, 15, "INCIDENT INVESTIGATION", new_x="LMARGIN", new_y="NEXT", align="C")
        self.set_font("Helvetica", "", 18)
        self.cell(0, 12, "REPORT", new_x="LMARGIN", new_y="NEXT", align="C")

        inc = self.data.get("incident", {})
        self.ln(20)
        self.set_text_color(*DARK_GRAY)
        self.set_font("Helvetica", "", 14)
        self.cell(0, 8, _safe(f"Incident #{inc.get('id', '')}"), new_x="LMARGIN", new_y="NEXT", align="C")
        self.set_font("Helvetica", "", 12)
        self.cell(0, 8, _safe(inc.get("title", "")), new_x="LMARGIN", new_y="NEXT", align="C")

        # Severity badge
        self.ln(5)
        sev = inc.get("severity", "MEDIUM")
        color = SEV_COLORS.get(sev, ORANGE)
        self.set_fill_color(*color)
        self.set_text_color(255, 255, 255)
        self.set_font("Helvetica", "B", 14)
        badge_text = f" SEVERITY: {sev} ({inc.get('severity_score', '?')}/10) "
        badge_w = self.get_string_width(badge_text) + 10
        self.cell(badge_w, 10, _safe(badge_text), new_x="LMARGIN", new_y="NEXT", align="C",
                  fill=True, center=True)

        # Metadata
        self.ln(15)
        self.set_text_color(*DARK_GRAY)
        meta = [
            ("Organization", inc.get("organization", "")),
            ("Sector", self.data.get("l3_threat_intel", {}).get("diamond_model", {}).get("victim", {}).get("sector", "")),
            ("Date", self.data.get("metadata", {}).get("generated_at", "")[:10]),
            ("Classification", "TLP:AMBER -- Limited Distribution"),
            ("MITRE ATT&CK", _format_mitre_cover(self.data)),
            ("Analyst Tiers", " -> ".join(self.data.get("metadata", {}).get("tiers_executed", []))),
        ]
        for k, v in meta:
            self.kv(k, v)

    def build_executive_summary(self):
        self.add_page()
        self.section_title(1, "EXECUTIVE SUMMARY")

        inc = self.data["incident"]
        l1 = self.data["l1_triage"]
        l3 = self.data["l3_threat_intel"]

        self.body(
            f"On {inc.get('first_seen', 'N/A')}, FortiSIEM detected "
            f"'{inc.get('title', '')}' on {inc.get('reporting_device', 'a device')} "
            f"({inc.get('reporting_ip', '')}) within {inc.get('organization', '')}. "
            f"The incident generated {inc.get('event_count', 0)} events and was classified "
            f"as {inc.get('severity', 'UNKNOWN')} severity.\n\n"
            f"L1 Triage classified this as {l1.get('disposition', 'UNKNOWN')} with "
            f"{l1.get('confidence', 0)}% confidence. "
            f"L2 Investigation found {self.data['l2_investigation']['correlated_incidents']['total_same_org']} "
            f"correlated incidents in the same organization. "
            f"L3 Threat Intel mapped {l3['mitre_mapping']['total_techniques']} MITRE ATT&CK techniques "
            f"and assessed a combined risk score of {l3['risk_score']['combined']}/10 "
            f"({l3['risk_score']['level']}).\n\n"
            f"VERDICT: {l1.get('disposition', 'UNKNOWN')} -- "
            f"Risk Level: {l3['risk_score']['level']}."
        )

        # Quick stats table
        self.subsection("Key Metrics")
        self.table(
            ["Metric", "Value"],
            [
                ["Incident Severity", f"{inc.get('severity', '')} ({inc.get('severity_score', '')}/10)"],
                ["Event Count", str(inc.get("event_count", 0))],
                ["L1 Disposition", f"{l1.get('disposition', '')} ({l1.get('confidence', '')}%)"],
                ["Correlated Incidents", str(self.data["l2_investigation"]["correlated_incidents"]["total_same_org"])],
                ["MITRE Techniques", str(l3["mitre_mapping"]["total_techniques"])],
                ["Risk Score", f"{l3['risk_score']['combined']}/10 ({l3['risk_score']['level']})"],
                ["Attribution", l3["attribution"]["status"]],
            ],
            [60, 130]
        )

    def build_l1_triage(self):
        self.add_page()
        self.section_title(2, "L1 TRIAGE", GREEN)

        inc = self.data["incident"]
        l1 = self.data["l1_triage"]

        # Incident details as compact table
        self.subsection("2.1 Incident Details")
        detail_rows = [
            ["Incident ID", f"#{inc.get('id', '')}", "Severity", f"{inc.get('severity', '')} ({inc.get('severity_score', '')}/10)"],
            ["Rule", inc.get("rule", "")[:45], "Status", inc.get("status", "")],
            ["Organization", inc.get("organization", ""), "Tag", inc.get("tag", "")],
            ["Device", f"{inc.get('reporting_device', '')} ({inc.get('reporting_ip', '')})", "Events", str(inc.get("event_count", 0))],
            ["First Seen", inc.get("first_seen", ""), "Last Seen", inc.get("last_seen", "")],
            ["MITRE", _format_mitre_short(inc)[:40], "Tactic", inc.get("mitre_tactic", "")],
        ]
        self.set_font("Helvetica", "", 9)
        for row in detail_rows:
            self.set_font("Helvetica", "B", 9)
            self.set_text_color(*MED_GRAY)
            self.cell(30, 5, _safe(row[0]))
            self.set_font("Helvetica", "", 9)
            self.set_text_color(*DARK_GRAY)
            self.cell(65, 5, _safe(str(row[1])[:35]))
            self.set_font("Helvetica", "B", 9)
            self.set_text_color(*MED_GRAY)
            self.cell(25, 5, _safe(row[2]))
            self.set_font("Helvetica", "", 9)
            self.set_text_color(*DARK_GRAY)
            self.cell(0, 5, _safe(str(row[3])[:35]), new_x="LMARGIN", new_y="NEXT")
        self.body(f"Title: {inc.get('title', '')}")

        # Signals
        self.subsection("2.2 Quick-Check Signals")
        signal_rows = []
        for s in l1.get("signals", []):
            signal_rows.append([
                s.get("type", ""),
                s.get("detail", ""),
                str(s.get("weight", 0)),
            ])
        if signal_rows:
            self.table(["Signal Type", "Detail", "Weight"], signal_rows, [42, 118, 30])

        # Event patterns
        patterns = l1.get("event_patterns", {})
        if patterns:
            self.ln(2)
            self.subsection("2.3 Event Pattern Analysis")
            if patterns.get("unique_macs"):
                self.kv("Unique MACs", ", ".join(m["mac"] for m in patterns["unique_macs"][:5]))
            if patterns.get("affected_vlans"):
                self.kv("Affected VLANs", f"{len(patterns['affected_vlans'])} -- {', '.join(patterns['affected_vlans'][:10])}")
            if patterns.get("port_movements"):
                self.kv("Port Movements", ", ".join(m["movement"] for m in patterns["port_movements"][:3]))
            self.kv("Time Span", f"{patterns.get('time_span_minutes', 0)} minutes")
            self.kv("Total Events", str(patterns.get("total_events", 0)))

            if patterns.get("raw_samples"):
                self.ln(1)
                self.set_font("Helvetica", "B", 9)
                self.set_text_color(*DARK_BLUE)
                self.cell(0, 5, "Sample Raw Events:", new_x="LMARGIN", new_y="NEXT")
                self.set_font("Helvetica", "", 7)
                self.set_text_color(*DARK_GRAY)
                for sample in patterns["raw_samples"][:3]:
                    self.multi_cell(190, 4, _safe(sample[:140]))

        # Disposition - keep compact to avoid page break
        self.ln(2)
        self.subsection("2.4 L1 Disposition")
        sla = l1.get("sla", {})
        disp_rows = [
            ["Classification", l1.get("disposition", ""), "Confidence", f"{l1.get('confidence', 0)}%"],
            ["TP Score", str(l1.get("tp_score", 0)), "FP Score", str(l1.get("fp_score", 0))],
            ["Priority", l1.get("priority", ""), "Escalated To", l1.get("escalate_to", "N/A")],
        ]
        for row in disp_rows:
            self.set_font("Helvetica", "B", 10)
            self.set_text_color(*MED_GRAY)
            self.cell(35, 6, _safe(row[0]))
            self.set_font("Helvetica", "B", 10)
            self.set_text_color(*DARK_GRAY)
            self.cell(60, 6, _safe(str(row[1])))
            self.set_font("Helvetica", "B", 10)
            self.set_text_color(*MED_GRAY)
            self.cell(35, 6, _safe(row[2]))
            self.set_font("Helvetica", "", 10)
            self.set_text_color(*DARK_GRAY)
            self.cell(0, 6, _safe(str(row[3])), new_x="LMARGIN", new_y="NEXT")
        if sla:
            self.kv("SLA Targets", f"Ack: {sla.get('ack','')}m | Triage: {sla.get('triage','')}m | Close: {sla.get('close','')}m")

    def build_l2_investigation(self):
        self.add_page()
        self.section_title(3, "L2 DEEP INVESTIGATION", (0, 60, 120))

        l2 = self.data["l2_investigation"]

        # Actor details
        actor = l2.get("actor", {})
        if actor and actor.get("username"):
            self.subsection("3.1 Actor / Subject")
            for k, label in [
                ("username", "Username"), ("domain", "Domain"),
                ("security_id", "Security ID"), ("logon_id", "Logon ID"),
                ("source_ip", "Source IP"), ("hostname", "Hostname"),
                ("device_type", "Device Type"), ("event_id", "Event ID"),
                ("action", "Action Performed"),
            ]:
                val = actor.get(k, "")
                if val:
                    self.kv(label, str(val))
            self.ln(2)

        # Incident timeline
        self.subsection("3.2 Incident Timeline")
        timeline = l2.get("timeline", [])
        if timeline:
            t_rows = []
            for t in timeline:
                t_rows.append([
                    t.get("time_start", "")[-8:],  # HH:MM:SS
                    t.get("time_end", "")[-8:],
                    t.get("severity", ""),
                    str(t.get("incident_id", "")),
                    str(t.get("count", "")),
                    t.get("title", ""),
                ])
            self.table(
                ["Start", "End", "Sev", "ID", "Count", "Title"],
                t_rows,
                [20, 20, 16, 22, 14, 98]
            )
        else:
            self.body("No timeline data available.")

        # Event-level forensic timeline from queried events
        event_tl = l2.get("event_timeline", [])
        if event_tl:
            self.ln(3)
            self.subsection("3.3 Event Timeline (from device logs)")
            et_rows = []
            for entry in event_tl[:25]:
                time_short = entry.get("time", "")
                # Extract just HH:MM:SS from timestamp
                m_time = re.search(r'(\d{2}:\d{2}:\d{2})', time_short)
                ts = m_time.group(1) if m_time else time_short[:8]
                cnt = entry.get("count", 1)
                cnt_str = f"x{cnt}" if cnt > 1 else ""
                et_rows.append([
                    ts,
                    entry.get("phase", ""),
                    entry.get("event_type", "")[:30],
                    entry.get("user", ""),
                    cnt_str,
                    entry.get("detail", "")[:35],
                ])
            self.table(
                ["Time", "Phase", "Event Type", "User", "Cnt", "Detail"],
                et_rows,
                [18, 16, 50, 20, 12, 74]
            )

        # Correlated incidents -- same device
        self.ln(3)
        corr = l2.get("correlated_incidents", {})
        same_dev = corr.get("same_device", [])
        if same_dev:
            self.subsection(f"3.3 Correlated Incidents -- Same Device ({corr.get('total_same_device', 0)})")
            rows = []
            for ci in same_dev[:10]:
                rows.append([
                    str(ci.get("id", "")),
                    ci.get("severity", ""),
                    str(ci.get("count", "")),
                    ci.get("status", ""),
                    ci.get("title", ""),
                ])
            self.table(["ID", "Sev", "Count", "Status", "Title"], rows, [22, 16, 14, 25, 113])

        # Correlated incidents -- same org
        same_org = corr.get("same_org", [])
        if same_org:
            self.ln(3)
            self.subsection(f"3.4 Correlated Incidents -- Same Org ({corr.get('total_same_org', 0)})")
            rows = []
            for ci in same_org[:15]:
                rows.append([
                    str(ci.get("id", "")),
                    ci.get("severity", ""),
                    str(ci.get("count", "")),
                    ci.get("last_seen", "")[-8:],
                    ci.get("source_ip", ""),
                    ci.get("title", ""),
                ])
            self.table(
                ["ID", "Sev", "Count", "Time", "Source IP", "Title"],
                rows,
                [22, 14, 14, 20, 30, 90]
            )

        # Blast radius
        self.ln(3)
        blast = l2.get("blast_radius", {})
        self.subsection("3.5 Blast Radius Assessment")
        self.kv("Scope Level", blast.get("scope_level", ""), bold_value=True)
        self.kv("Total Incidents", str(blast.get("total_incidents", 0)))
        self.kv("Total Events", str(blast.get("total_events", 0)))
        self.kv("Unique Source IPs", f"{len(blast.get('unique_source_ips', []))} -- {', '.join(blast.get('unique_source_ips', [])[:8])}")
        self.kv("Unique Rules", str(len(blast.get("unique_rules", []))))
        for rule in blast.get("unique_rules", []):
            self.set_font("Helvetica", "", 9)
            self.set_text_color(*DARK_GRAY)
            self.cell(50, 5, "")
            self.cell(0, 5, _safe(f"- {rule}"), new_x="LMARGIN", new_y="NEXT")
        sev_bd = blast.get("severity_breakdown", {})
        sev_str = " | ".join(f"{k}: {v}" for k, v in sorted(sev_bd.items(), key=lambda x: {"CRITICAL":0,"HIGH":1,"MEDIUM":2,"LOW":3}.get(x[0],4)))
        self.kv("Severity Breakdown", sev_str)

        # Lateral spread check
        spread = l2.get("lateral_spread", [])
        if spread:
            self.ln(3)
            self.subsection("3.6 Lateral Spread Check")
            for s in spread:
                mal_ip = s.get("malicious_ip", "")
                other_count = s.get("total_incidents", 0)
                hosts = s.get("other_internal_hosts", [])
                self.kv("Malicious IP", mal_ip)
                self.kv("Other Incidents", str(other_count))
                if hosts:
                    self.kv("Other Affected Hosts", ", ".join(hosts[:10]))
                    # Show the other incidents
                    other_incs = s.get("other_incidents", [])
                    if other_incs:
                        rows = []
                        for oi in other_incs[:10]:
                            rows.append([
                                str(oi.get("id", "")),
                                oi.get("org", ""),
                                oi.get("severity", ""),
                                oi.get("last_seen", "")[-8:],
                                oi.get("title", ""),
                            ])
                        self.table(["ID", "Org", "Sev", "Time", "Title"], rows, [22, 35, 16, 20, 97])
                else:
                    self.body(f"No other internal hosts found communicating with {mal_ip}")

        # Event queries
        queries = l2.get("event_queries", [])
        if queries:
            self.ln(3)
            self.subsection("3.7 Event Queries Executed")
            for q in queries:
                self.kv("Query", q.get("description", ""))
                self.kv("Results", str(q.get("result_count", 0)))
                if q.get("error"):
                    self.kv("Error", q["error"])

    def build_l3_threat_intel(self):
        self.add_page()
        self.section_title(4, "L3 THREAT INTELLIGENCE", RED)

        l3 = self.data["l3_threat_intel"]

        # MITRE ATT&CK
        self.subsection("4.1 MITRE ATT&CK Mapping")
        mitre = l3.get("mitre_mapping", {})

        primary = mitre.get("primary", [])
        if primary:
            self.set_font("Helvetica", "B", 10)
            self.set_text_color(*DARK_BLUE)
            self.cell(0, 6, "Primary Techniques (confirmed):", new_x="LMARGIN", new_y="NEXT")
            rows = [[t.get("id",""), t.get("name",""), t.get("tactic",""), t.get("confidence","")] for t in primary]
            self.table(["ID", "Name", "Tactic", "Confidence"], rows, [25, 65, 65, 35])

        related = mitre.get("related", [])
        if related:
            self.ln(3)
            self.set_font("Helvetica", "B", 10)
            self.set_text_color(*DARK_BLUE)
            self.cell(0, 6, "Related Techniques (investigate):", new_x="LMARGIN", new_y="NEXT")
            rows = [[t.get("id",""), t.get("name",""), t.get("tactic",""), t.get("evidence","")] for t in related]
            self.table(["ID", "Name", "Tactic", "Evidence"], rows, [25, 55, 50, 60])

        self.kv("Tactics Covered", ", ".join(mitre.get("tactics_covered", [])))

        # Diamond Model
        self.ln(3)
        self.subsection("4.2 Diamond Model Analysis")
        dm = l3.get("diamond_model", {})

        for vertex, title in [("adversary", "Adversary"), ("capability", "Capability"),
                               ("infrastructure", "Infrastructure"), ("victim", "Victim")]:
            self.set_font("Helvetica", "B", 10)
            self.set_text_color(*NAVY)
            self.cell(0, 7, _safe(f"{title}:"), new_x="LMARGIN", new_y="NEXT")
            vertex_data = dm.get(vertex, {})
            for k, v in vertex_data.items():
                self.kv(f"  {k.replace('_', ' ').title()}", str(v))

        # Risk Score
        self.ln(3)
        self.subsection("4.3 Risk Score Breakdown")
        rs = l3.get("risk_score", {})
        score_rows = []
        for key in ["attack_feasibility", "asset_criticality", "evidence_confidence", "blast_radius"]:
            item = rs.get(key, {})
            score_rows.append([
                key.replace("_", " ").title(),
                f"{item.get('score', '?')}/10",
                item.get("reason", ""),
            ])
        score_rows.append(["COMBINED", f"{rs.get('combined', '?')}/10", rs.get("level", "")])
        self.table(["Factor", "Score", "Reason"], score_rows, [45, 20, 125])

        # Attribution
        self.ln(3)
        self.subsection("4.4 Attribution Assessment")
        attr = l3.get("attribution", {})
        self.kv("Status", attr.get("status", ""), bold_value=True)
        self.kv("Assessment", attr.get("assessment", ""))
        self.kv("Likely Actor Type", attr.get("likely_actor_type", ""))

    def build_recommendations(self):
        self.add_page()
        self.section_title(5, "RECOMMENDATIONS")

        recs = self.data["l3_threat_intel"].get("recommendations", {})

        for timeframe, title, color in [
            ("immediate", "5.1 Immediate Actions (0-1 hour)", RED),
            ("short_term", "5.2 Short-Term Actions (1-24 hours)", ORANGE),
            ("long_term", "5.3 Long-Term Actions (1-7 days)", NAVY),
        ]:
            items = recs.get(timeframe, [])
            if items:
                self.subsection(title)
                for i, rec in enumerate(items, 1):
                    self.body(f"{i}. {rec}")

        # IOC Table
        self.ln(3)
        self.subsection("5.4 Indicators of Compromise (IOCs)")
        iocs = self.data["l3_threat_intel"].get("iocs", [])
        if iocs:
            rows = [[i.get("type",""), i.get("value",""), i.get("context",""), i.get("action","")] for i in iocs]
            self.table(["Type", "Value", "Context", "Action"], rows, [25, 45, 60, 60])

    def build_signoff(self):
        self.ln(10)
        self.set_draw_color(*NAVY)
        self.line(10, self.get_y(), 200, self.get_y())
        self.ln(5)
        self.set_font("Helvetica", "I", 10)
        self.set_text_color(*LIGHT_GRAY)
        self.cell(0, 6, "--- End of Report ---", new_x="LMARGIN", new_y="NEXT", align="C")
        self.cell(0, 6, _safe(
            f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} | "
            f"FortiSIEM AI Investigation Pipeline v2.0"
        ), new_x="LMARGIN", new_y="NEXT", align="C")
        self.cell(0, 6, _safe(
            f"Tiers executed: {' -> '.join(self.data.get('metadata',{}).get('tiers_executed',[]))}"
        ), new_x="LMARGIN", new_y="NEXT", align="C")

    def generate(self, output_path: str):
        """Build all pages and save PDF."""
        self.build_cover()
        self.build_executive_summary()
        self.build_l1_triage()
        self.build_l2_investigation()
        self.build_l3_threat_intel()
        self.build_recommendations()
        self.build_signoff()
        self.output(output_path)
        size_kb = os.path.getsize(output_path) / 1024
        print(f"PDF saved: {output_path} ({self.pages_count} pages, {size_kb:.1f} KB)")


def _format_mitre_short(inc: dict) -> str:
    """Extract a short MITRE string from incident data."""
    raw = inc.get("mitre_technique", "")
    if isinstance(raw, str):
        try:
            parsed = json.loads(raw)
            if isinstance(parsed, list) and parsed:
                return f"{parsed[0].get('techniqueid','')} -- {parsed[0].get('name','')}"
        except (json.JSONDecodeError, ValueError):
            pass
    return str(raw)[:80] if raw else "N/A"


def _format_mitre_cover(data: dict) -> str:
    """Get MITRE string for cover page -- uses L3 result when incident field is empty."""
    # Try incident field first
    inc = data.get("incident", {})
    result = _format_mitre_short(inc)
    if result != "N/A":
        return result
    # Fall back to L3 primary techniques
    l3 = data.get("l3_threat_intel", {})
    primary = l3.get("mitre_mapping", {}).get("primary", [])
    if primary:
        t = primary[0]
        return f"{t.get('id', '')} -- {t.get('name', '')}"
    return "N/A"


# --- Main ---

def main():
    parser = argparse.ArgumentParser(description="FortiSIEM Investigation PDF Report Generator")
    parser.add_argument("--input", required=True, help="Investigation JSON file from investigation_pipeline.py")
    parser.add_argument("--output", default=None, help="Output PDF path")
    args = parser.parse_args()

    with open(args.input) as f:
        data = json.load(f)

    if not args.output:
        inc_id = data.get("metadata", {}).get("incident_id", "unknown")
        args.output = f"Investigation_{inc_id}_Report.pdf"

    report = InvestigationReport(data)
    report.generate(args.output)


if __name__ == "__main__":
    main()
