# Zero-Trust Software Supply Chain Admission Webhook Makefile

MODULE := github.com/ekrmcakir/zero-trust-supply-chain-webhook
IMAGE_NAME ?= ghcr.io/ekrmcakir/zero-trust-supply-chain-webhook
VERSION ?= 1.0.0
COMMIT ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
BUILD_DATE ?= $(shell date -u +'%Y-%m-%dT%H:%M:%SZ')
LDFLAGS ?= -X main.Version=$(VERSION) -X main.GitCommit=$(COMMIT) -X main.BuildDate=$(BUILD_DATE) -s -w

.PHONY: all build test lint docker-build run-local clean certs

all: build test

## Build binary
build:
	@echo "==> Building zero-trust admission webhook..."
	CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o bin/webhook ./cmd/webhook

## Run unit tests
test:
	@echo "==> Running unit tests..."
	go test -v -race -coverprofile=coverage.out ./pkg/...

## Display coverage in browser
coverage: test
	go tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report generated at coverage.html"

## Build Docker image
docker-build:
	@echo "==> Building container image $(IMAGE_NAME):$(VERSION)..."
	docker build -t $(IMAGE_NAME):$(VERSION) -t $(IMAGE_NAME):latest .

## Generate development TLS certificates
certs:
	@echo "==> Generating self-signed TLS certificates for local testing..."
	bash scripts/generate-certs.sh

## Run locally (requires certs generated)
run-local: build
	@echo "==> Running admission webhook locally on port 8443..."
	./bin/webhook --config=pkg/config/testdata/sample-config.yaml --tls-cert-file=certs/tls.crt --tls-key-file=certs/tls.key

## Clean build artifacts
clean:
	@echo "==> Cleaning up build artifacts..."
	rm -rf bin/ coverage.out coverage.html certs/
