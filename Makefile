MAKEFLAGS += --no-print-directory

.DEFAULT_GOAL := help

.PHONY: build clean help quality test

help: ## Show available targets
	@echo "yespower - Available targets"
	@echo ""
	@grep -hE '^[a-zA-Z_-]+:.*## ' $(MAKEFILE_LIST) \
		| sort \
		| awk 'BEGIN {FS = ":.*## "} {printf "  %-15s %s\n", $$1, $$2}'

build: ## Build library
	@./.make/build.sh

test: ## Run tests
	@./.make/test.sh

quality: ## Run all quality checks
	@./.make/quality.sh

clean: ## Remove build artifacts
	@./.make/clean.sh
