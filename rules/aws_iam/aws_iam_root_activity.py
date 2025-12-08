def rule(event):
    user_identity = event.get("userIdentity", {})
    if user_identity.get("type") != "Root":
        return False
    if event.get("eventName") in {"ConsoleLogin"}:
        return False
    return True


def title(event):
    action = event.get("eventName", "unknown")
    return f"Root account activity: {action}"


def severity(event):
    action = event.get("eventName", "")
    if (
        action.startswith("Create")
        or action.startswith("Delete")
        or action.startswith("Put")
    ):
        return "CRITICAL"
    if action.startswith("Update") or action.startswith("Modify"):
        return "HIGH"
    return "MEDIUM"


def dedup(event):
    return event.get("eventName", "")


def alert_context(event):
    return {
        "eventName": event.get("eventName"),
        "eventSource": event.get("eventSource"),
        "sourceIPAddress": event.get("sourceIPAddress"),
        "userAgent": event.get("userAgent"),
        "awsRegion": event.get("awsRegion"),
        "requestParameters": event.get("requestParameters"),
    }
