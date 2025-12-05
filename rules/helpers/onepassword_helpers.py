"""
1Password helper functions for iota detection rules
"""

import sys
import os

sys.path.insert(0, os.path.dirname(__file__))
from iota_helpers import deep_get


def onepassword_alert_context(event):
    """Generate standard 1Password alert context"""
    return {
        "uuid": event.get("uuid"),
        "timestamp": event.get("timestamp"),
        "category": event.get("category"),
        "type": event.get("type"),
        "country": event.get("country"),
        "targetUser": event.get("target_user", {}),
        "client": event.get("client", {}),
        "sourceIPAddress": deep_get(event, "client", "ip_address"),
        "appName": deep_get(event, "client", "app_name"),
    }


def get_onepassword_user(event):
    """Get target user information from 1Password event"""
    return {
        "email": deep_get(event, "target_user", "email"),
        "name": deep_get(event, "target_user", "name"),
        "uuid": deep_get(event, "target_user", "uuid"),
    }


def get_onepassword_client(event):
    """Get client information from 1Password event"""
    return {
        "appName": deep_get(event, "client", "app_name"),
        "appVersion": deep_get(event, "client", "app_version"),
        "ipAddress": deep_get(event, "client", "ip_address"),
        "osName": deep_get(event, "client", "os_name"),
        "osVersion": deep_get(event, "client", "os_version"),
        "platformName": deep_get(event, "client", "platform_name"),
        "platformVersion": deep_get(event, "client", "platform_version"),
    }


def is_onepassword_success(event):
    """Check if 1Password sign-in was successful"""
    return event.get("category") == "success"


def is_onepassword_failure(event):
    """Check if 1Password sign-in failed"""
    category = event.get("category", "")
    return category in ["credentials_failed", "mfa_failed", "firewall_failed"]


def get_onepassword_ip(event):
    """Extract source IP from 1Password event"""
    return deep_get(event, "client", "ip_address")
