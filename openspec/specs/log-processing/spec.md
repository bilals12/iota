---
version: 1.0.0
status: active
owner: bilals12
---

# Capability: Log Processing

Adaptive log classification and parsing for multiple log sources.

## Requirements

### Requirement: Adaptive Classification

The system SHALL automatically identify log types using a penalty-based priority queue.

#### Scenario: Successful classification

- **GIVEN** an unknown log line
- **WHEN** the adaptive classifier processes it
- **THEN** it SHALL try parsers in priority order
- **AND** return the first successful parse result
- **AND** promote that parser's priority

#### Scenario: Failed classification attempt

- **GIVEN** a parser that fails to parse the log line
- **WHEN** classification is attempted
- **THEN** that parser SHALL receive a penalty
- **AND** its priority SHALL decrease for future attempts

#### Scenario: Classification with hint

- **GIVEN** a log line with known type hint (e.g., from EventBridge metadata)
- **WHEN** `ClassifyWithHint(line, hint)` is called
- **THEN** the hinted parser SHALL be tried first

### Requirement: CloudTrail Parsing

The system SHALL parse AWS CloudTrail JSON logs.

#### Scenario: CloudTrail file with Records array

- **GIVEN** a JSON file with `{"Records": [...]}`
- **WHEN** the file is processed
- **THEN** each record SHALL be parsed as a CloudTrail event
- **AND** `eventID`, `eventTime`, `eventName` SHALL be extracted

#### Scenario: CloudTrail JSONL format

- **GIVEN** a JSONL file with one event per line
- **WHEN** the file is processed
- **THEN** each line SHALL be parsed independently

### Requirement: VPC Flow Log Parsing

The system SHALL parse AWS VPC Flow Logs in space-delimited format.

#### Scenario: VPC Flow Log v2

- **GIVEN** a VPC Flow Log line
- **WHEN** parsed
- **THEN** fields SHALL be extracted: `srcaddr`, `dstaddr`, `srcport`, `dstport`, `protocol`, `action`

### Requirement: ALB Log Parsing

The system SHALL parse AWS Application Load Balancer logs.

#### Scenario: ALB access log

- **GIVEN** an ALB access log line
- **WHEN** parsed
- **THEN** fields SHALL include: `client_ip`, `target_ip`, `request_url`, `user_agent`, `elb_status_code`

### Requirement: EventBridge Envelope Unwrapping

The system SHALL extract log payloads from EventBridge envelopes.

#### Scenario: Okta event via EventBridge

- **GIVEN** an EventBridge message with `source: "aws.partner/okta.com"`
- **WHEN** processed
- **THEN** the `detail` field SHALL be extracted as the Okta event
- **AND** log type SHALL be set to `Okta.SystemLog`

#### Scenario: 1Password event via EventBridge

- **GIVEN** an EventBridge message with `detail-type: "1Password SignInAttempt"`
- **WHEN** processed
- **THEN** the `detail` field SHALL be extracted
- **AND** log type SHALL be set to `OnePassword.SignInAttempt`

### Requirement: Supported Log Types

The system SHALL support the following log types:

| Log Type | Format | Source |
|----------|--------|--------|
| AWS.CloudTrail | JSON | S3 |
| AWS.VPCFlow | Space-delimited | S3 |
| AWS.ALB | Space-delimited | S3 |
| AWS.S3ServerAccess | Space-delimited | S3 |
| AWS.AuroraMySQLAudit | CSV | S3 |
| Okta.SystemLog | JSON | EventBridge |
| GSuite.Reports | JSON | EventBridge |
| OnePassword.SignInAttempt | JSON | EventBridge |

## Current Implementation

- **Location**: `internal/logprocessor/`, `internal/classifier/`
- **Parsers**: `internal/logprocessor/cloudtrail.go`, `internal/logprocessor/vpcflow.go`, etc.
