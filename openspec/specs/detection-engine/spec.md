---
version: 1.0.0
status: active
owner: bilals12
---

# Capability: Detection Engine

Core detection pipeline that evaluates security events against Python rules and generates alerts.

## Requirements

### Requirement: Python Rule Evaluation

The system SHALL execute Python detection rules against normalized events and return matches.

#### Scenario: Rule matches event

- **GIVEN** a normalized CloudTrail event
- **WHEN** the event matches a rule's `rule(event)` function (returns True)
- **THEN** the system SHALL generate an alert with title from `title(event)`
- **AND** severity from `severity(event)`
- **AND** include the full event payload

#### Scenario: Rule does not match

- **GIVEN** a normalized event
- **WHEN** the rule's `rule(event)` function returns False
- **THEN** no alert SHALL be generated for that rule

#### Scenario: Rule execution error

- **GIVEN** a rule that raises an exception
- **WHEN** the rule is evaluated
- **THEN** the error SHALL be logged
- **AND** processing SHALL continue with remaining rules

### Requirement: Rule Discovery

The system SHALL automatically discover and load Python rules from the rules directory.

#### Scenario: Loading rules from directory

- **GIVEN** a rules directory path
- **WHEN** the engine initializes
- **THEN** it SHALL recursively find all `.py` files
- **AND** load rules that define `rule()`, `title()`, and `severity()` functions

#### Scenario: Rule filtering by log type

- **GIVEN** rules organized in `rules/{log_type}/` directories
- **WHEN** processing an event with known log type
- **THEN** only rules matching that log type SHALL be evaluated

### Requirement: Batch Processing

The system SHALL support processing events in batches for efficiency.

#### Scenario: Batch analysis

- **GIVEN** a batch of events
- **WHEN** `engine.Analyze(events)` is called
- **THEN** all events SHALL be evaluated against applicable rules
- **AND** all matches SHALL be returned as a single result set

### Requirement: Alert Output

The system SHALL output alerts as structured JSON to stdout.

#### Scenario: Alert JSON format

- **GIVEN** a rule match
- **WHEN** the alert is generated
- **THEN** output SHALL include:
  - `rule_id`: Rule identifier (filename without extension)
  - `title`: Human-readable title from `title(event)`
  - `severity`: CRITICAL/HIGH/MEDIUM/LOW/INFO
  - `dedup`: Deduplication key
  - `event`: Full event payload

## Current Implementation

- **Location**: `internal/engine/engine.go`, `engines/iota/engine.py`
- **Rule Count**: 73 rules across 5 log types
- **Execution**: Python subprocess via `exec.Command`
