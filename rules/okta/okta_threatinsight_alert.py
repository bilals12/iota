"""
Detect Okta ThreatInsight security threat detection.

ThreatInsight uses machine learning to identify potentially malicious
authentication activity.
"""

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "helpers"))
from iota_helpers import deep_get, okta_alert_context, get_actor_user


def _severity_from_threat_string(threat_detection):
    """Extract highest severity from threat detection string."""
    if not threat_detection:
        return "MEDIUM"

    if "CRITICAL" in threat_detection:
        return "CRITICAL"
    if "HIGH" in threat_detection:
        return "HIGH"
    if "MEDIUM" in threat_detection:
        return "MEDIUM"
    if "LOW" in threat_detection:
        return "LOW"
    if "INFO" in threat_detection:
        return "INFO"
    return "MEDIUM"


def rule(event):
    """Detect ThreatInsight security alerts."""
    return event.get("eventType") == "security.threat.detected"


def title(event):
    """Generate alert title."""
    actor = get_actor_user(event)
    return f"Okta ThreatInsight detected threat for [{actor}]"


def severity(event):
    """Return alert severity based on threat detection."""
    outcome = deep_get(event, "outcome", "result", default="")
    if outcome == "DENY":
        return "INFO"

    threat_detection = deep_get(
        event, "debugContext", "debugData", "threatDetections", default=""
    )
    return _severity_from_threat_string(threat_detection)


def alert_context(event):
    """Additional context for the alert."""
    context = okta_alert_context(event)
    context["threatDetections"] = deep_get(
        event, "debugContext", "debugData", "threatDetections"
    )
    return context
