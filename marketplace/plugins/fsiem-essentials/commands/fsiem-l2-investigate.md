---
name: fsiem-l2-investigate
description: L2 deep incident investigation. Opens a formal investigation, builds a full attack timeline, maps blast radius, enriches all external IPs and indicators, correlates lateral movement, and generates a structured investigation report. Use when L1 escalates a True Positive or when requested to investigate a specific incident ID.
---
# Command: /fsiem-l2-investigate

## Usage
- `/fsiem-l2-investigate 10432` — full L2 investigation of incident 10432
- `/fsiem-l2-investigate 10432 --analyst "Jane Smith"` — with named analyst
- `/fsiem-l2-investigate 10432 --hours 48` — extend timeline window to 48h

## Workflow
1. `l2_open_investigation(id, analyst, l1_notes)` — open investigation record
2. `build_attack_timeline(id, src_ips, hosts, users, hours)` — pull all related events
3. `determine_blast_radius(timeline, initial_src)` — scope lateral movement, exfil
4. Enrich all external IPs via `skills/enrichment/`
5. Run targeted hunts for observed TTPs via `skills/hypothesis_hunting/`
6. `generate_l2_report(inv, blast_radius, timeline, enrichments, disposition)` — produce report

## Output Report Sections
1. Incident summary (FortiSIEM metadata)
2. Scope assessment (hosts, users, data transferred, lateral movement map)
3. Attack timeline (key events in chronological order)
4. Root cause analysis
5. Containment actions taken
6. Recommendations
7. IOC table (for detection rules)
8. L3 escalation notes (if needed)

## Escalate to L3 when
- Suspected APT / nation-state actor
- > 20 hosts compromised or 30+ days dwell time
- Novel malware or zero-day suspected
- Exfiltration of regulated data confirmed
