def rule(event):
    return (
        event.get("eventSource") == "s3.amazonaws.com"
        and event.get("eventName") in ["GetBucketAcl", "GetBucketPolicy", "GetBucketLocation"]
    )

def title(event):
    return f"s3 bucket access: {event.get('eventName')} on {event.get('requestParameters', {}).get('bucketName', 'unknown')}"

def severity():
    return "INFO"
