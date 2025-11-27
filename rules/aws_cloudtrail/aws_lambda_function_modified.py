"""
Detect Lambda function code or configuration changes.

Lambda modifications can indicate backdoors or malicious code injection.
"""
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "helpers"))
from iota_helpers import deep_get, is_successful, aws_rule_context


def rule(event):
    """Detect Lambda function modifications"""
    return is_successful(event) and event.get("eventName") in [
        "UpdateFunctionCode20150331v2",
        "UpdateFunctionConfiguration20150331v2",
        "AddPermission20150331v2",
        "CreateFunction20150331v2",
    ]


def title(event):
    """Generate alert title"""
    event_name = event.get("eventName", "UNKNOWN").replace("20150331v2", "")
    function_name = deep_get(event, "requestParameters", "functionName", default="UNKNOWN")
    actor_arn = deep_get(event, "userIdentity", "arn", default="UNKNOWN")
    return f"Lambda function [{function_name}] {event_name} by [{actor_arn}]"


def severity():
    """Return alert severity"""
    # CreateFunction and UpdateFunctionCode are higher risk
    event_name = event.get("eventName", "")
    if "UpdateFunctionCode" in event_name or "CreateFunction" in event_name:
        return "HIGH"
    return "MEDIUM"


def alert_context(event):
    """Additional context for the alert"""
    context = aws_rule_context(event)
    context["functionName"] = deep_get(event, "requestParameters", "functionName")
    context["runtime"] = deep_get(event, "requestParameters", "runtime")
    context["role"] = deep_get(event, "requestParameters", "role")
    # Check if adding permissions
    if "AddPermission" in event.get("eventName", ""):
        context["principal"] = deep_get(event, "requestParameters", "principal")
        context["action"] = deep_get(event, "requestParameters", "action")
    return context
