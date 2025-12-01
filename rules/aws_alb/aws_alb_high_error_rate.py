"""
Detect high error rate in ALB logs.

Monitors for high rates of 4xx and 5xx errors that may indicate
attacks or application issues.
"""

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "helpers"))
from iota_helpers import aws_rule_context


def rule(event):
    """Detect high error rate"""
    elb_status = event.get("elbStatusCode")
    target_status = event.get("targetStatusCode")

    if not elb_status and not target_status:
        return False

    if elb_status and 400 <= elb_status < 600:
        return True

    if target_status and 400 <= target_status < 600:
        return True

    return False


def title(event):
    """Generate alert title"""
    elb_status = event.get("elbStatusCode", "N/A")
    target_status = event.get("targetStatusCode", "N/A")
    client_ip = event.get("clientIP", "UNKNOWN")
    return f"High error rate detected: ELB={elb_status}, Target={target_status} from {client_ip}"


def severity():
    """Return alert severity"""
    return "LOW"


def alert_context(event):
    """Additional context for the alert"""
    context = aws_rule_context(event)
    context["clientIP"] = event.get("clientIP")
    context["elbStatusCode"] = event.get("elbStatusCode")
    context["targetStatusCode"] = event.get("targetStatusCode")
    context["requestMethod"] = event.get("requestMethod")
    context["requestURL"] = event.get("requestURL")
    context["userAgent"] = event.get("userAgent")
    return context
