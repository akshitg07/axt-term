# AXT-Term — developer entrypoint.
#
# Every routine task is a target here so nobody has to remember two toolchains.
# `make help` lists everything.

SHELL := /bin/bash
.DEFAULT_GOAL := help

BACKEND    := backend
FRONTEND   := frontend
BIN_DIR    := $(BACKEND)/bin

VERSION    ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT     ?= $(shell git rev-parse HEAD 2>/dev/null || echo none)
BUILD_DATE ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)

LDFLAGS := -s -w \
	-X github.com/axt-term/axt-term/backend/internal/buildinfo.Version=$(VERSION) \
	-X github.com/axt-term/axt-term/backend/internal/buildinfo.Commit=$(COMMIT) \
	-X github.com/axt-term/axt-term/backend/internal/buildinfo.Date=$(BUILD_DATE)

.PHONY: help
help: ## Show this help
	@grep -hE '^[a-zA-Z0-9_-]+:.*?## ' $(MAKEFILE_LIST) \
		| awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2}'

# ---------------------------------------------------------------- backend ----

.PHONY: build
build: ## Build the server binary
	cd $(BACKEND) && go build -trimpath -ldflags "$(LDFLAGS)" -o bin/axt-term ./cmd/axt-term

.PHONY: build-tools
build-tools: ## Build the admin and docs tooling
	cd $(BACKEND) && go build -trimpath -ldflags "$(LDFLAGS)" -o bin/axt-docgen ./cmd/axt-docgen

.PHONY: run
run: ## Run the server against ./data with development defaults
	cd $(BACKEND) && \
		AXT_ENV=development \
		AXT_LOG_LEVEL=debug \
		AXT_LOG_FORMAT=text \
		AXT_DATA_DIR=../data \
		AXT_PUBLIC_URL=http://localhost:8080 \
		go run ./cmd/axt-term

.PHONY: test
test: ## Run backend unit tests
	cd $(BACKEND) && go test ./...

.PHONY: test-race
test-race: ## Run backend tests with the race detector
	cd $(BACKEND) && go test -race -count=1 ./...

.PHONY: cover
cover: ## Run tests and report coverage
	cd $(BACKEND) && go test -coverprofile=coverage.out ./... && go tool cover -func=coverage.out | tail -1

.PHONY: test-integration
test-integration: ## Run integration tests against a real sshd container (M5+)
	cd $(BACKEND) && go test -tags=integration -count=1 ./test/integration/...

.PHONY: lint
lint: ## Run golangci-lint
	cd $(BACKEND) && golangci-lint run ./...

.PHONY: fmt
fmt: ## Format Go sources
	cd $(BACKEND) && gofmt -w -s . && go vet ./...

.PHONY: fmt-check
fmt-check: ## Fail if any Go source is unformatted
	@out="$$(cd $(BACKEND) && gofmt -l -s .)"; \
	if [ -n "$$out" ]; then echo "unformatted files:"; echo "$$out"; exit 1; fi

.PHONY: tidy
tidy: ## Tidy go.mod
	cd $(BACKEND) && go mod tidy

.PHONY: vet
vet: ## Run go vet
	cd $(BACKEND) && go vet ./...

# --------------------------------------------------------------- frontend ----
# Frontend targets become active in M7.

.PHONY: web-install
web-install: ## Install frontend dependencies
	@if [ -f $(FRONTEND)/package.json ]; then cd $(FRONTEND) && npm ci; \
	else echo "frontend not scaffolded yet (M7)"; fi

.PHONY: web-dev
web-dev: ## Run the Vite dev server
	@if [ -f $(FRONTEND)/package.json ]; then cd $(FRONTEND) && npm run dev; \
	else echo "frontend not scaffolded yet (M7)"; fi

.PHONY: web-build
web-build: ## Build the SPA for embedding
	@if [ -f $(FRONTEND)/package.json ]; then cd $(FRONTEND) && npm run build; \
	else echo "frontend not scaffolded yet (M7)"; fi

.PHONY: web-test
web-test: ## Run frontend tests
	@if [ -f $(FRONTEND)/package.json ]; then cd $(FRONTEND) && npm run test -- --run; \
	else echo "frontend not scaffolded yet (M7)"; fi

.PHONY: types
types: ## Generate frontend API types from Go structs
	@command -v tygo >/dev/null || { echo "install tygo: go install github.com/gzuidhof/tygo@latest"; exit 1; }
	tygo generate --config tools/tygo.yaml

# ------------------------------------------------------------------- docs ----

.PHONY: docs-config
docs-config: ## Regenerate docs/configuration.md from the config declarations
	cd $(BACKEND) && go run ./cmd/axt-docgen config > ../docs/configuration.md
	@echo "wrote docs/configuration.md"

.PHONY: docs-check
docs-check: docs-config ## Fail if generated docs are stale
	@git diff --exit-code -- docs/configuration.md \
		|| { echo "docs/configuration.md is stale; commit the regenerated file"; exit 1; }

# ------------------------------------------------------------------- CI/CD ----

.PHONY: ci
ci: fmt-check vet test docs-check ## Everything CI runs

.PHONY: docker-build
docker-build: ## Build the production image
	docker build -f deploy/Dockerfile -t axt-term:$(VERSION) \
		--build-arg VERSION=$(VERSION) --build-arg COMMIT=$(COMMIT) --build-arg BUILD_DATE=$(BUILD_DATE) .

.PHONY: up
up: ## Start the Docker Compose stack
	docker compose up -d

.PHONY: down
down: ## Stop the Docker Compose stack
	docker compose down

.PHONY: logs
logs: ## Follow container logs
	docker compose logs -f

.PHONY: clean
clean: ## Remove build artifacts
	rm -rf $(BIN_DIR) $(BACKEND)/coverage.out $(FRONTEND)/dist
