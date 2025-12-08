"""
Detect AWS Config being disabled or deleted.

Config tracks resource changes - disabling it is suspicious.
"""

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "helpers"))
from iota_helpers import deep_get, is_successful, aws_rule_context


def rule(event):
    """Detect Config service being disabled or deleted"""
    return is_successful(event) and event.get("eventName") in [
        "DeleteConfigurationRecorder",
        "DeleteDeliveryChannel",
        "StopConfigurationRecorder",
    ]


def title(event):
    """Generate alert title"""
    event_name = event.get("eventName", "UNKNOWN")
    actor_arn = deep_get(event, "userIdentity", "arn", default="UNKNOWN")
    return f"AWS Config {event_name} by [{actor_arn}]"


def severity():
    """Return alert severity"""
    return "HIGH"


def alert_context(event):
    """Additional context for the alert"""
    context = aws_rule_context(event)
    context["configurationRecorder"] = deep_get(
        event, "requestParameters", "configurationRecorderName"
    )
    context["deliveryChannel"] = deep_get(
        event, "requestParameters", "deliveryChannelName"
    )
    return context
