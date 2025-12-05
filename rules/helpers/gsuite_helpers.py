"""
Google Workspace (GSuite) helper functions for iota detection rules
"""

import sys
import os

sys.path.insert(0, os.path.dirname(__file__))
from iota_helpers import deep_get


def gsuite_alert_context(event):
    """Generate standard GSuite alert context"""
    return {
        "applicationName": deep_get(event, "id", "applicationName"),
        "customerId": deep_get(event, "id", "customerId"),
        "time": deep_get(event, "id", "time"),
        "actor": event.get("actor", {}),
        "ipAddress": event.get("ipAddress"),
        "ownerDomain": event.get("ownerDomain"),
        "events": event.get("events", []),
    }


def get_gsuite_actor(event):
    """Get actor information from GSuite event"""
    return {
        "email": deep_get(event, "actor", "email"),
        "profileId": deep_get(event, "actor", "profileId"),
        "callerType": deep_get(event, "actor", "callerType"),
    }


def get_gsuite_event_name(event, index=0):
    """Get event name from GSuite events array"""
    events = event.get("events", [])
    if not events or index >= len(events):
        return None
    return events[index].get("name")


def get_gsuite_event_type(event, index=0):
    """Get event type from GSuite events array"""
    events = event.get("events", [])
    if not events or index >= len(events):
        return None
    return events[index].get("type")


def get_gsuite_parameter(event, param_name, event_index=0):
    """Get a specific parameter value from GSuite event"""
    events = event.get("events", [])
    if not events or event_index >= len(events):
        return None

    parameters = events[event_index].get("parameters", [])
    for param in parameters:
        if param.get("name") == param_name:
            # GSuite parameters can have value, intValue, boolValue, multiValue
            return (
                param.get("value")
                or param.get("intValue")
                or param.get("boolValue")
                or param.get("multiValue")
            )
    return None


def is_gsuite_login_event(event):
    """Check if event is a login-related event"""
    app_name = deep_get(event, "id", "applicationName")
    return app_name == "login"


def is_gsuite_admin_event(event):
    """Check if event is an admin event"""
    app_name = deep_get(event, "id", "applicationName")
    return app_name == "admin"


def is_gsuite_login_success(event):
    """Check if GSuite login was successful"""
    event_name = get_gsuite_event_name(event)
    return event_name == "login_success"


def is_gsuite_login_failure(event):
    """Check if GSuite login failed"""
    event_name = get_gsuite_event_name(event)
    return event_name == "login_failure"


def get_gsuite_ip(event):
    """Extract source IP from GSuite event"""
    return event.get("ipAddress")
