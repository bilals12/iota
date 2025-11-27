.PHONY: build test clean docker-build docker-push helm-package terraform-init

# Build the detection engine
build:
	@echo "Building iota..."
	@mkdir -p bin
	@CGO_ENABLED=1 go build -o bin/iota ./cmd/iota
	@echo "✓ Built bin/iota"

# Run tests
test:
	@go test -v ./...

# Clean build artifacts
clean:
	@rm -rf bin/
	@echo "✓ Cleaned build artifacts"

# Docker build
docker-build:
	@echo "Building Docker image..."
	@docker build -t iota:latest .
	@echo "✓ Built iota:latest"

# Docker push (requires image_repo variable)
docker-push:
	@if [ -z "$(IMAGE_REPO)" ]; then \
		echo "ERROR: IMAGE_REPO not set"; \
		echo "Usage: make docker-push IMAGE_REPO=123456789012.dkr.ecr.us-east-1.amazonaws.com/iota IMAGE_TAG=v0.1.0"; \
		exit 1; \
	fi
	@docker tag iota:latest $(IMAGE_REPO):$(IMAGE_TAG)
	@docker push $(IMAGE_REPO):$(IMAGE_TAG)
	@echo "✓ Pushed $(IMAGE_REPO):$(IMAGE_TAG)"

# Helm package
helm-package:
	@echo "Packaging Helm chart..."
	@helm package helm/iota
	@echo "✓ Packaged helm/iota"

# Terraform init
terraform-init:
	@echo "Initializing Terraform..."
	@cd terraform && terraform init
	@echo "✓ Terraform initialized"

# Run detection engine (once mode)
run-once:
	@./bin/iota --mode=once --jsonl=testdata/events/test-01.jsonl --rules=rules/aws_cloudtrail --python=python3 --engine=engines/iota/engine.py

# Run detection engine (watch mode)
run-watch:
	@./bin/iota --mode=watch --events-dir=./testdata/events --rules=rules/aws_cloudtrail --python=python3 --engine=engines/iota/engine.py

# Run all checks before commit
pre-commit: test build
	@echo "✓ All pre-commit checks passed"
