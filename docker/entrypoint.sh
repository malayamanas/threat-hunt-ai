#!/bin/bash
set -e

echo ""
echo "╔══════════════════════════════════════════════════════╗"
echo "║      Hunt with FortiSIEM — AI Environment             ║"
echo "╚══════════════════════════════════════════════════════╝"
echo ""

# Validate required env vars
if [ -z "$FSIEM_HOST" ] || [ "$FSIEM_HOST" = "https://your-fortisiem-host" ]; then
    echo "⚠️  WARNING: FSIEM_HOST is not set."
    echo "   Set it in docker-compose.yml or export FSIEM_HOST=https://your-fortisiem"
    echo ""
fi

if [ -z "$FSIEM_PASS" ]; then
    echo "⚠️  WARNING: FSIEM_PASS is not set. API calls will fail."
    echo ""
fi

# Show connection info
echo "FortiSIEM Connection:"
echo "  Host : ${FSIEM_HOST}"
echo "  User : ${FSIEM_USER}/${FSIEM_ORG}"
echo "  SSL  : ${FSIEM_VERIFY_SSL}"
echo ""

# Install plugin if not already installed
cd /home/fsiem
if ! claude plugin list 2>/dev/null | grep -q "fsiem-essentials"; then
    echo "Installing fsiem-essentials plugin..."
    claude plugin marketplace add /home/fsiem/fortisiem-ai/marketplace 2>/dev/null || true
    claude plugin install fsiem-essentials@fsiem-marketplace 2>/dev/null || true
fi

echo "Available commands:"
echo "  /init-fsiem           Initialize session"
echo ""
echo "  Incident Response:"
echo "  /fsiem-incidents      List and triage incidents"
echo "  /fsiem-investigate    Full investigation for an incident"
echo "  /fsiem-playbook       IR playbook (ransomware/compromise/exfil/malware/insider)"
echo ""
echo "  Threat Hunting:"
echo "  /fsiem-hunt           Hunt for an IOC or MITRE technique"
echo "  /fsiem-hypothesis-hunt Structured hypothesis-driven hunt"
echo "  /fsiem-ioc            Hunt IOCs from a threat report"
echo "  /fsiem-ueba           Behavioral analysis for a user or host"
echo ""
echo "  Detection Engineering:"
echo "  /fsiem-rule-create    Design and deploy a correlation rule"
echo "  /fsiem-rules          List, enable, disable, tune rules"
echo ""
echo "  Event & Asset Operations:"
echo "  /fsiem-query          Run an event query"
echo "  /fsiem-cmdb           Query device inventory"
echo "  /fsiem-report         Generate health report"
echo ""
echo "Starting AI assistant..."
echo ""

exec claude "$@"
