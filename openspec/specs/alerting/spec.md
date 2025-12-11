---
version: 1.0.0
status: active
owner: bilals12
---

# Capability: Alerting

Alert deduplication, state management, and forwarding to external systems.

## Requirements

### Requirement: Alert Deduplication

The system SHALL prevent duplicate alerts using SQLite and Bloom filter.

#### Scenario: First occurrence of alert

- **GIVEN** a new alert with unique `rule_id` + `dedup_string` combination
- **WHEN** the alert is processed
- **THEN** the alert SHALL be forwarded
- **AND** recorded in the state database

#### Scenario: Duplicate alert within window

- **GIVEN** an alert matching an existing unresolved alert
- **WHEN** the alert is processed
- **THEN** the alert SHALL NOT be forwarded
- **AND** the existing alert's count MAY be incremented

#### Scenario: Alert after resolution

- **GIVEN** an alert matching a previously resolved alert
- **WHEN** the alert is processed
- **THEN** a new alert record SHALL be created
- **AND** the alert SHALL be forwarded

### Requirement: Bloom Filter Deduplication

The system SHALL use a Bloom filter for efficient event deduplication.

#### Scenario: Event already processed

- **GIVEN** an event with `eventID` already in the Bloom filter
- **WHEN** the event is received
- **THEN** the event SHALL be skipped
- **AND** processing SHALL continue with next event

#### Scenario: New event

- **GIVEN** an event with `eventID` not in the Bloom filter
- **WHEN** the event is processed
- **THEN** the `eventID` SHALL be added to the Bloom filter
- **AND** the event SHALL be processed normally

#### Scenario: Bloom filter persistence

- **GIVEN** a configured `--bloom-file` path
- **WHEN** the system starts
- **THEN** the Bloom filter SHALL be loaded from disk
- **AND** periodically saved during operation

### Requirement: State Database

The system SHALL maintain alert state in SQLite.

#### Scenario: Database schema

- **GIVEN** the state database
- **WHEN** initialized
- **THEN** it SHALL contain an `alerts` table with:
  - `id`: Primary key
  - `rule_id`: Detection rule identifier
  - `dedup_string`: Deduplication key
  - `first_seen`: Timestamp of first occurrence
  - `last_seen`: Timestamp of most recent occurrence
  - `count`: Number of occurrences
  - `resolved_at`: Resolution timestamp (nullable)

### Requirement: Slack Forwarding

The system SHALL support forwarding alerts to Slack webhooks.

#### Scenario: Slack alert delivery

- **GIVEN** a `--slack-webhook` URL is configured
- **WHEN** a new alert is generated
- **THEN** a formatted message SHALL be POSTed to the webhook
- **AND** include rule_id, title, severity, and event summary

#### Scenario: Slack delivery failure

- **GIVEN** a Slack webhook that returns an error
- **WHEN** delivery fails
- **THEN** the error SHALL be logged
- **AND** the alert SHALL still be written to stdout

### Requirement: Stdout Output

The system SHALL always output alerts as JSON to stdout.

#### Scenario: Alert output

- **GIVEN** any alert
- **WHEN** generated
- **THEN** it SHALL be written to stdout as a JSON object
- **AND** be parseable by downstream tools (jq, fluent-bit, etc.)

## Current Implementation

- **Location**: `internal/alerts/`, `internal/state/`, `internal/bloom/`
- **Database**: SQLite via `modernc.org/sqlite`
- **Bloom Filter**: `github.com/bits-and-blooms/bloom/v3`
