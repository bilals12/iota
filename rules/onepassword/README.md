# 1Password Detection Rules

Detection rules for 1Password SignInAttempt events.

## Rules

| Rule | Description | Severity |
|------|-------------|----------|
| `onepassword_unusual_client` | Detects non-standard 1Password clients. Customize `CLIENT_ALLOWLIST`. | MEDIUM |
| `onepassword_brute_force` | Detects failed sign-in attempts exceeding threshold (20) from single IP. | INFO |
| `onepassword_login_from_new_country` | Detects logins from unusual countries. Customize `COUNTRY_ALLOWLIST`. | MEDIUM |

## Log Source

These rules process `OnePassword.SignInAttempt` events.

## Configuration

### Client Allowlist

The `onepassword_unusual_client` rule has a default allowlist of standard 1Password clients. To baseline your environment, query your 1Password logs for unique client names:

```sql
SELECT DISTINCT client.app_name FROM onepassword_signinattempt
```

### Country Allowlist

The `onepassword_login_from_new_country` rule has a default allowlist. Customize `COUNTRY_ALLOWLIST` based on where your employees are located.

## Log Schema

1Password SignInAttempt events include:

```json
{
  "uuid": "event-uuid",
  "timestamp": "2024-01-15T10:30:00Z",
  "category": "success|credentials_failed|mfa_failed|firewall_failed",
  "type": "credentials_ok|password_secret_bad|...",
  "country": "US",
  "target_user": {
    "email": "user@example.com",
    "name": "User Name",
    "uuid": "user-uuid"
  },
  "client": {
    "app_name": "1Password for Mac",
    "app_version": "...",
    "ip_address": "1.2.3.4",
    "os_name": "MacOSX",
    "os_version": "14.0"
  }
}
```
