"""
Detect suspicious user agents in ALB logs.

Monitors for suspicious or unusual user agents that may indicate
automated attacks or malicious activity.
"""

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "helpers"))
from iota_helpers import pattern_match, aws_rule_context

SUSPICIOUS_USER_AGENTS = [
    "sqlmap",
    "nikto",
    "nmap",
    "masscan",
    "zmap",
    "masscan",
    "dirb",
    "gobuster",
    "wfuzz",
    "burp",
    "acunetix",
    "nessus",
    "openvas",
    "w3af",
    "scanner",
    "bot",
    "crawler",
    "spider",
]


def rule(event):
    """Detect suspicious user agents"""
    user_agent = event.get("userAgent", "").lower()
    if not user_agent:
        return False

    return pattern_match(user_agent, SUSPICIOUS_USER_AGENTS)


def title(event):
    """Generate alert title"""
    user_agent = event.get("userAgent", "UNKNOWN")
    client_ip = event.get("clientIP", "UNKNOWN")
    return f"Suspicious user agent detected: {user_agent} from {client_ip}"


def severity():
    """Return alert severity"""
    return "MEDIUM"


def alert_context(event):
    """Additional context for the alert"""
    context = aws_rule_context(event)
    context["clientIP"] = event.get("clientIP")
    context["userAgent"] = event.get("userAgent")
    context["requestMethod"] = event.get("requestMethod")
    context["requestURL"] = event.get("requestURL")
    context["elbStatusCode"] = event.get("elbStatusCode")
    context["targetStatusCode"] = event.get("targetStatusCode")
    return context
