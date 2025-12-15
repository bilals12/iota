"""
Detect potential ransomware note uploads to S3.

Ransomware attackers drop notes with distinctive filenames like HOW_TO_DECRYPT_FILES.txt,
RANSOM_NOTE.txt, FILES_ENCRYPTED.html to inform victims about encryption and payment.
"""

import re
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "helpers"))
from iota_helpers import deep_get, is_successful, aws_rule_context, get_actor_user

RANSOM_NOTE_PATTERNS = [
    r"(?i)(ransom|payment)[_-]?(note|info|instructions?).*\.(txt|html?)$",
    r"(?i)how[_-]?to[_-]?(decrypt|restore|recover)[_-]?(your[_-]?)?files.*\.(txt|html?)$",
    r"(?i)decrypt[_-]?(instructions?|guide|info|your[_-]?files).*\.(txt|html?)$",
    r"(?i)restore[_-]?(instructions?|guide|info|your[_-]?files).*\.(txt|html?)$",
    r"(?i)recovery[_-]?(instructions?|key|guide).*\.(txt|html?)$",
    r"(?i)(all[_-]?)?files?[_-]?(have[_-]?been[_-]?)?(encrypted|locked).*\.(txt|html?)$",
    r"(?i)your[_-]?files?[_-]?(are|have[_-]?been)[_-]?(encrypted|locked).*\.(txt|html?)$",
    r"(?i)data[_-]?(has[_-]?been[_-]?)?(encrypted|locked).*\.(txt|html?)$",
    r"(?i)unlock[_-]?(instructions?|guide|your[_-]?files).*\.(txt|html?)$",
    r"(?i)help[_-]?(restore|decrypt|recover)[_-]?(your[_-]?)?files.*\.(txt|html?)$",
    r"(?i)readme[_-]?(decrypt|ransom|locked).*\.(txt|html?)$",
]

COMPILED_PATTERNS = [re.compile(pattern) for pattern in RANSOM_NOTE_PATTERNS]


def _extract_filename(event):
    """Extract filename from S3 PutObject event."""
    key = deep_get(event, "requestParameters", "key", default="")
    if not key:
        resources = event.get("resources", [])
        for resource in resources:
            if resource.get("type") == "AWS::S3::Object":
                arn = resource.get("arn", "")
                if "/" in arn:
                    key = arn.split("/", 1)[1]
                    break
    return key.split("/")[-1] if "/" in key else key


def rule(event):
    """Detect ransomware note uploads."""
    if event.get("eventName") != "PutObject":
        return False

    if not is_successful(event):
        return False

    filename = _extract_filename(event)
    if not filename:
        return False

    return any(pattern.match(filename) for pattern in COMPILED_PATTERNS)


def title(event):
    """Generate alert title."""
    bucket = deep_get(event, "requestParameters", "bucketName", default="UNKNOWN")
    filename = _extract_filename(event)
    actor = get_actor_user(event)
    return f"Potential ransomware note [{filename}] uploaded to S3 bucket [{bucket}] by [{actor}]"


def severity(event):
    """Return alert severity."""
    return "HIGH"


def alert_context(event):
    """Additional context for the alert."""
    context = aws_rule_context(event)
    context["bucketName"] = deep_get(event, "requestParameters", "bucketName")
    context["objectKey"] = deep_get(event, "requestParameters", "key")
    context["filename"] = _extract_filename(event)
    return context
