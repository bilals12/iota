# Google Workspace (GSuite) Detection Rules

Detection rules for Google Workspace Reports events.

## Rules

| Rule | Description | Severity |
|------|-------------|----------|
| `gsuite_brute_force_by_ip` | Detects failed login attempts exceeding threshold (20) from single IP. | INFO |
| `gsuite_user_suspended` | Detects admin suspending user accounts. | INFO |
| `gsuite_admin_role_assigned` | Detects admin role assignment. Higher severity for super admin roles. | INFO/HIGH |
| `gsuite_2sv_disabled` | Detects 2-Step Verification (MFA) being disabled. | MEDIUM |

## Log Source

These rules process `GSuite.Reports` events (also called `GSuite.ActivityEvent`).

## Event Types

Google Workspace logs are organized by application:

- **login**: Authentication events (`login_success`, `login_failure`, `2sv_disable`, etc.)
- **admin**: Admin console actions (`SUSPEND_USER`, `ASSIGN_ROLE`, etc.)
- **drive**: Google Drive activity
- **calendar**: Calendar events
- **token**: OAuth token events

## Log Schema

GSuite Reports events include:

```json
{
  "id": {
    "applicationName": "login|admin|drive|...",
    "customerId": "customer-id",
    "time": "2024-01-15T10:30:00Z",
    "uniqueQualifier": "unique-id"
  },
  "actor": {
    "email": "user@example.com",
    "profileId": "profile-id"
  },
  "ipAddress": "1.2.3.4",
  "events": [
    {
      "name": "login_success",
      "type": "login",
      "parameters": [
        {"name": "login_type", "value": "google_password"}
      ]
    }
  ]
}
```
