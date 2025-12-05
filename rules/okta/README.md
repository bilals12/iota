# Okta Detection Rules

Detection rules for Okta SystemLog events.

## Rules

| Rule | Description | Severity |
|------|-------------|----------|
| `okta_admin_role_assigned` | Detects admin privilege grants. Higher severity for Super Administrator. | INFO/HIGH |
| `okta_api_key_created` | Detects API token creation. | INFO |
| `okta_user_mfa_reset` | Detects MFA factor reset. | INFO |
| `okta_brute_force_by_ip` | Detects failed login attempts exceeding threshold (20) from single IP. | INFO |
| `okta_support_access` | Detects Okta support access to tenant. | MEDIUM |

## Log Source

These rules process `Okta.SystemLog` events.

## EventBridge Integration

When using Okta Log Streaming via EventBridge, the events will be wrapped in an EventBridge envelope:

```json
{
  "version": "0",
  "id": "event-id",
  "detail-type": "Okta Log Event",
  "source": "aws.partner/okta.com/turo/...",
  "detail": {
    // Actual Okta SystemLog event
    "uuid": "...",
    "published": "...",
    "eventType": "user.session.start",
    ...
  }
}
```

The iota parser extracts the `detail` field for rule evaluation.
