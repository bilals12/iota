"""
Detect root user console logins.

Root user access should be avoided - detects when root successfully logs into the console.
"""
import sys
import os

# Add helpers to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "helpers"))
from iota_helpers import deep_get, is_successful, get_account_id


def rule(event):
    """Detect successful root console login"""
    return (
        event.get("eventName") == "ConsoleLogin"
        and deep_get(event, "userIdentity", "type") == "Root"
        and deep_get(event, "responseElements", "ConsoleLogin") == "Success"
    )


def title(event):
    """Generate alert title"""
    source_ip = event.get("sourceIPAddress", "unknown")
    account = get_account_id(event)
    return f"AWS root login detected from {source_ip} in account [{account}]"


def severity():
    """Return alert severity"""
    return "CRITICAL"


def alert_context(event):
    """Additional context for the alert"""
    return {
        "sourceIPAddress": event.get("sourceIPAddress"),
        "userAgent": event.get("userAgent"),
        "eventTime": event.get("eventTime"),
        "mfaUsed": deep_get(event, "additionalEventData", "MFAUsed"),
        "recipientAccountId": event.get("recipientAccountId"),
    }
