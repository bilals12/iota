---
version: 1.0.0
status: active
owner: bilals12
---

# Capability: Transform Pipeline

Substation-inspired message abstraction and config-driven detection pipeline.

## Requirements

### Requirement: Message Abstraction

The system SHALL represent data as Messages with data, metadata, and control fields.

#### Scenario: Message creation

- **GIVEN** raw JSON data
- **WHEN** a Message is created
- **THEN** it SHALL contain:
  - `data`: The raw JSON payload
  - `meta`: Metadata about the message (source, type, timestamps)
  - `ctrl`: Control signals (skip, error, etc.)

#### Scenario: JSON path access

- **GIVEN** a Message with JSON data
- **WHEN** `GetValue(path)` is called
- **THEN** it SHALL return the value at that JSON path using gjson syntax

#### Scenario: JSON path mutation

- **GIVEN** a Message
- **WHEN** `SetValue(path, value)` is called
- **THEN** the data SHALL be modified at that path using sjson

### Requirement: Condition Interface

The system SHALL support conditions for filtering and routing messages.

#### Scenario: String condition

- **GIVEN** a `string.contains` condition with path and value
- **WHEN** evaluated against a Message
- **THEN** it SHALL return true if the path value contains the substring

#### Scenario: Meta conditions

- **GIVEN** an `all` meta-condition with child conditions
- **WHEN** evaluated
- **THEN** it SHALL return true only if ALL child conditions are true

#### Scenario: Utility conditions

- **GIVEN** an `exists` condition with a path
- **WHEN** evaluated
- **THEN** it SHALL return true if the path exists in the message

### Requirement: Transform Interface

The system SHALL support transforms for modifying and routing messages.

#### Scenario: Object transforms

- **GIVEN** an `object.copy` transform with source and target paths
- **WHEN** applied to a Message
- **THEN** the value at source SHALL be copied to target

#### Scenario: Detection transform

- **GIVEN** a `detect` transform with a condition and alert configuration
- **WHEN** the condition matches
- **THEN** an alert Message SHALL be created and forwarded

#### Scenario: Send transforms

- **GIVEN** a `send.stdout` transform
- **WHEN** applied to a Message
- **THEN** the message SHALL be written to stdout

### Requirement: Pipeline Orchestration

The system SHALL support chaining transforms into pipelines.

#### Scenario: Sequential transform execution

- **GIVEN** a Pipeline with transforms [A, B, C]
- **WHEN** a Message is processed
- **THEN** transforms SHALL execute in order: A → B → C
- **AND** each transform receives output of previous

#### Scenario: Transform that drops messages

- **GIVEN** a transform that returns empty result
- **WHEN** processed
- **THEN** the message SHALL not continue to subsequent transforms

### Requirement: Jsonnet Configuration

The system SHALL support Jsonnet for defining detection pipelines.

#### Scenario: Loading Jsonnet config

- **GIVEN** a `.jsonnet` file defining a pipeline
- **WHEN** loaded
- **THEN** it SHALL be evaluated to JSON
- **AND** transforms SHALL be instantiated from the config

#### Scenario: Jsonnet DSL library

- **GIVEN** the `iota.libsonnet` library
- **WHEN** imported in a Jsonnet file
- **THEN** it SHALL provide helper functions for:
  - `detect(condition, alert)` - Detection rule definition
  - `alert(rule_id, title, severity)` - Alert configuration
  - `cnd.string.contains(path, value)` - Condition builders
  - `send.stdout()` - Output transforms

### Requirement: Enrichment Transforms

The system SHALL support enrichment transforms for threat intelligence.

#### Scenario: DNS reverse lookup

- **GIVEN** an `enrich.dns_reverse` transform with IP path
- **WHEN** applied
- **THEN** the hostname SHALL be resolved and added to metadata

#### Scenario: GeoIP lookup

- **GIVEN** an `enrich.geoip` transform with IP path
- **WHEN** applied
- **THEN** geographic information SHALL be added to metadata

## Current Implementation

- **Location**: `pkg/message/`, `pkg/condition/`, `pkg/transform/`, `pkg/pipeline/`
- **Config**: `pkg/config/jsonnet.go`, `pkg/config/iota.libsonnet`
- **Examples**: `examples/pipeline/cloudtrail_detection.jsonnet`
