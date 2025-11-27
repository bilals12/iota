def rule(event):
    return (
        event.get("eventName") == "ConsoleLogin"
        and event.get("userIdentity", {}).get("type") == "Root"
    )

def title(event):
    return f"root login from {event.get('sourceIPAddress')}"

def severity():
    return "HIGH"
