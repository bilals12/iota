"""
Detect unapproved outbound DNS traffic.

Monitors for DNS traffic from internal IPs to external DNS servers
that are not in the approved list.
"""

import sys
import os
from ipaddress import ip_network

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "helpers"))
from iota_helpers import aws_rule_context

APPROVED_DNS_SERVERS = {
    "1.1.1.1",
    "8.8.8.8",
}


def rule(event):
    """Detect unapproved outbound DNS traffic"""
    dstport = event.get("dstPort") or event.get("dstport")
    if dstport not in [53, 5353]:
        return False

    srcaddr = event.get("srcAddr") or event.get("srcaddr", "0.0.0.0/32")
    try:
        if ip_network(srcaddr).is_global:
            return False
    except (ValueError, TypeError):
        return False

    dstaddr = event.get("dstAddr") or event.get("dstaddr", "192.168.0.1/32")
    try:
        if ip_network(dstaddr).is_private:
            return False
    except (ValueError, TypeError):
        return False

    if not dstaddr or dstaddr in APPROVED_DNS_SERVERS:
        return False

    return True


def title(event):
    """Generate alert title"""
    srcaddr = event.get("srcAddr") or event.get("srcaddr", "UNKNOWN")
    dstaddr = event.get("dstAddr") or event.get("dstaddr", "UNKNOWN")
    return f"Unapproved outbound DNS traffic from {srcaddr} to {dstaddr}"


def severity():
    """Return alert severity"""
    return "MEDIUM"


def alert_context(event):
    """Additional context for the alert"""
    context = aws_rule_context(event)
    context["srcAddr"] = event.get("srcAddr") or event.get("srcaddr")
    context["dstAddr"] = event.get("dstAddr") or event.get("dstaddr")
    context["srcPort"] = event.get("srcPort") or event.get("srcport")
    context["dstPort"] = event.get("dstPort") or event.get("dstport")
    context["protocol"] = event.get("protocol")
    context["action"] = event.get("action")
    return context
