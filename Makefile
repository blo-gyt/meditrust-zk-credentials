CARGO ?= cargo
STELLAR ?= stellar
CONTRACTS := meditrust-credentials meditrust-verifier

.DEFAULT_GOAL := help

.PHONY: help
help: ## Show available targets
	@grep -hE '^[a-zA-Z0-9_-]+:.*?## ' $(MAKEFILE_LIST) \
		| awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-16s\033[0m %s\n", $$1, $$2}'

.PHONY: fmt
fmt: ## Format all sources
	$(CARGO) fmt --all

.PHONY: fmt-check
fmt-check: ## Verify formatting
	$(CARGO) fmt --all -- --check

.PHONY: clippy
clippy: ## Lint all targets, warnings are errors
	$(CARGO) clippy --workspace --all-targets -- -D warnings

.PHONY: test
test: ## Run the unit test suites
	$(CARGO) test --workspace

.PHONY: test-all
test-all: ## Run every test, including artifact-gated ones
	$(CARGO) test --workspace -- --include-ignored

.PHONY: check
check: fmt-check clippy test ## Everything CI runs

.PHONY: build
build: ## Build deployable wasm for every contract
	@for package in $(CONTRACTS); do \
		echo "==> building $$package"; \
		$(STELLAR) contract build --package $$package || exit 1; \
	done

.PHONY: clean
clean: ## Remove build output
	$(CARGO) clean
