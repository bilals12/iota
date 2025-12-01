"""
Detect inbound traffic to blocklisted ports from external IPs.

Monitors for traffic to controlled ports (SSH, RDP) from non-private IP space
destined for internal IP addresses.
"""

import sys
import os
from ipaddress import ip_network

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "helpers"))
from iota_helpers import aws_rule_context

CONTROLLED_PORTS = {
    22,
    3389,
}


def rule(event):
    """Detect inbound traffic to blocklisted ports"""
    dstport = event.get("dstPort") or event.get("dstport")
    if dstport not in CONTROLLED_PORTS:
        return False

    srcaddr = event.get("srcAddr") or event.get("srcaddr", "0.0.0.0/32")
    try:
        if not ip_network(srcaddr).is_global:
            return False
    except (ValueError, TypeError):
        return False

    dstaddr = event.get("dstAddr") or event.get("dstaddr", "1.0.0.0/32")
    try:
        return not ip_network(dstaddr).is_global
    except (ValueError, TypeError):
        return False


def title(event):
    """Generate alert title"""
    dstport = event.get("dstPort") or event.get("dstport", "UNKNOWN")
    dstaddr = event.get("dstAddr") or event.get("dstaddr", "UNKNOWN")
    return (
        f"Inbound traffic to blocklisted port {dstport} from external IP to {dstaddr}"
    )


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
