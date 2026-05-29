# traefikoidc — Makefile
# Run `make help` for available targets.

GO            ?= go
GOPATH        := $(shell $(GO) env GOPATH)
# Pin to the yaegi version bundled by the deployed Traefik so yaegi-validate
# tests the real interpreter, not a newer one that may support more. Traefik
# v3.7.1 vendors yaegi v0.16.1 (Go ~1.22 stdlib surface). Bump when Traefik is.
YAEGI_VERSION ?= v0.16.1
TEST_TIMEOUT  ?= 480s

.DEFAULT_GOAL := help

.PHONY: help
help: ## Show this help
	@grep -hE '^[a-zA-Z0-9_-]+:.*## ' $(MAKEFILE_LIST) | awk 'BEGIN{FS=":.*## "}{printf "  \033[36m%-16s\033[0m %s\n", $$1, $$2}'

.PHONY: build
build: ## Compile all packages (native toolchain)
	$(GO) build ./...

.PHONY: fmt
fmt: ## Format sources with gofmt
	gofmt -w $$(git ls-files '*.go' | grep -v '^vendor/')

.PHONY: vet
vet: ## Run go vet
	$(GO) vet ./...

.PHONY: lint
lint: ## Run golangci-lint if available
	@command -v golangci-lint >/dev/null 2>&1 && golangci-lint run ./... || echo "golangci-lint not installed; skipping"

.PHONY: test
test: ## Run the test suite
	$(GO) test ./... -count=1 -timeout $(TEST_TIMEOUT)

.PHONY: vendor
vendor: ## Refresh and vendor dependencies
	$(GO) mod tidy && $(GO) mod vendor

# yaegi-validate interprets the plugin under the yaegi interpreter the same way
# Traefik loads it. Native `go build`/`go test` use the standard compiler and do
# NOT catch yaegi-only incompatibilities (unsupported stdlib symbols, reflection
# edge cases). This target does. Importing the package forces yaegi to interpret
# every file in it plus its vendored deps; CreateConfig + New exercise the
# instantiation path. Pin YAEGI_VERSION to match Traefik's bundled yaegi if you
# need exact parity.
.PHONY: yaegi-validate
yaegi-validate: ## Verify the plugin loads under Traefik's yaegi interpreter
	@command -v yaegi >/dev/null 2>&1 || { echo ">> installing yaegi@$(YAEGI_VERSION)"; $(GO) install github.com/traefik/yaegi/cmd/yaegi@$(YAEGI_VERSION); }
	@echo ">> interpreting plugin under yaegi (as Traefik does)"
	@DO_NOT_TRACK=1 GOFLAGS=-mod=vendor $$(command -v yaegi || echo "$(GOPATH)/bin/yaegi") run ./cmd/yaegicheck/main.go

.PHONY: check
check: vet test yaegi-validate ## vet + tests + yaegi load validation
