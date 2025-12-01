"""
Detect SSH access from external IPs to internal resources.

Monitors for SSH (port 22) traffic from non-private IP space
destined for internal IP addresses.
"""

import sys
import os
from ipaddress import ip_network

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "helpers"))
from iota_helpers import aws_rule_context


def rule(event):
    """Detect SSH access from external IPs"""
    dstport = event.get("dstPort") or event.get("dstport")
    if dstport != 22:
        return False

    action = event.get("action")
    if action != "ACCEPT":
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
    srcaddr = event.get("srcAddr") or event.get("srcaddr", "UNKNOWN")
    dstaddr = event.get("dstAddr") or event.get("dstaddr", "UNKNOWN")
    return f"SSH access from external IP {srcaddr} to internal resource {dstaddr}"


def severity():
    """Return alert severity"""
    return "HIGH"


def alert_context(event):
    """Additional context for the alert"""
    context = aws_rule_context(event)
    context["srcAddr"] = event.get("srcAddr") or event.get("srcaddr")
    context["dstAddr"] = event.get("dstAddr") or event.get("dstaddr")
    context["srcPort"] = event.get("srcPort") or event.get("srcport")
    context["dstPort"] = event.get("dstPort") or event.get("dstport")
    context["protocol"] = event.get("protocol")
    context["action"] = event.get("action")
    context["bytes"] = event.get("bytes")
    context["packets"] = event.get("packets")
    return context
