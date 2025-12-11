---
version: 1.0.0
status: active
owner: bilals12
---

# Capability: Deployment

Operating modes, infrastructure, and Kubernetes deployment.

## Requirements

### Requirement: SQS Mode

The system SHALL support processing S3-based logs via SQS notifications.

#### Scenario: S3 event notification

- **GIVEN** an S3 object creation triggers SNS → SQS
- **WHEN** iota receives the SQS message
- **THEN** it SHALL extract bucket and key from the notification
- **AND** download the object from S3
- **AND** process through the detection pipeline

#### Scenario: Compressed log files

- **GIVEN** a `.gz` compressed log file in S3
- **WHEN** downloaded
- **THEN** it SHALL be decompressed before processing

#### Scenario: SQS message deletion

- **GIVEN** a successfully processed SQS message
- **WHEN** processing completes without error
- **THEN** the message SHALL be deleted from the queue

### Requirement: EventBridge Mode

The system SHALL support processing streaming SaaS logs via EventBridge.

#### Scenario: EventBridge event

- **GIVEN** an EventBridge event routed to SQS
- **WHEN** iota receives the message
- **THEN** it SHALL extract the event from the SQS body
- **AND** unwrap the EventBridge envelope
- **AND** process the `detail` payload

#### Scenario: Log type detection from EventBridge

- **GIVEN** an EventBridge event with `source` and `detail-type`
- **WHEN** processed
- **THEN** the log type SHALL be determined from metadata
- **AND** the appropriate parser SHALL be used

### Requirement: Health Checks

The system SHALL expose HTTP health check endpoints for Kubernetes probes.

#### Scenario: Liveness probe

- **GIVEN** the health server is running
- **WHEN** GET `/health` is requested
- **THEN** it SHALL return 200 OK if the process is alive

#### Scenario: Readiness probe

- **GIVEN** the health server is running
- **WHEN** GET `/ready` is requested
- **THEN** it SHALL return 200 OK if ready to process messages
- **AND** return 503 if not ready

### Requirement: Prometheus Metrics

The system SHALL expose Prometheus metrics when enabled.

#### Scenario: Metrics endpoint

- **GIVEN** `ENABLE_METRICS=true` environment variable
- **WHEN** GET `/metrics` is requested
- **THEN** Prometheus-formatted metrics SHALL be returned

### Requirement: Terraform Module

The system SHALL provide a Terraform module for infrastructure deployment.

#### Scenario: Module inputs

- **GIVEN** the Terraform module
- **WHEN** applied
- **THEN** it SHALL accept:
  - `cluster_name`: EKS cluster name
  - `namespace`: Kubernetes namespace
  - `sqs_queue_url`: SQS queue URL
  - `s3_bucket`: CloudTrail bucket name

#### Scenario: IRSA configuration

- **GIVEN** the Terraform module
- **WHEN** applied
- **THEN** it SHALL create an IAM role for the service account
- **AND** configure IRSA trust relationship

### Requirement: Multi-Architecture Docker Images

The system SHALL provide Docker images for multiple architectures.

#### Scenario: Image architectures

- **GIVEN** a Docker image build
- **WHEN** published to Docker Hub
- **THEN** it SHALL include manifests for:
  - `linux/amd64`
  - `linux/arm64`

## Current Implementation

- **Location**: `cmd/iota/main.go`, `cmd/iota/sqs_handler.go`, `cmd/iota/eventbridge_handler.go`
- **Terraform**: `terraform/`
- **Docker**: `Dockerfile`, `.github/workflows/`
- **Health Server**: `internal/api/health.go`
