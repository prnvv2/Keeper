# Keeper — development tasks.
#
#   make dev     install everything
#   make test    run all four test suites
#   make lint    ruff + mypy + tsc
#
# Windows: run these under Git Bash, or use the underlying commands directly.

.DEFAULT_GOAL := help
.PHONY: help dev test lint fmt clean \
        test-python test-typescript test-control-plane test-integration \
        run-control-plane run-dashboard demo validate-policies \
        docker-build docker-up docker-down audit

PY ?= python
VENV := .venv
BIN := $(VENV)/bin
ifeq ($(OS),Windows_NT)
BIN := $(VENV)/Scripts
endif

help: ## Show this help
	@grep -hE '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) \
	  | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-22s\033[0m %s\n", $$1, $$2}'

# --- setup -----------------------------------------------------------------

dev: ## Install both SDKs, the control plane and the dashboard
	$(PY) -m venv $(VENV)
	$(BIN)/pip install --upgrade pip
	$(BIN)/pip install -e "sdk/python[dev,yaml,metrics]" -e "control-plane[dev]"
	cd sdk/typescript && npm install --no-fund --no-audit
	cd dashboard && npm install --no-fund --no-audit
	@echo ""
	@echo "Ready. Try:  make test  |  make run-control-plane  |  make demo"

# --- tests -----------------------------------------------------------------

test: test-python test-typescript test-control-plane ## Run every test suite

test-python: ## Python SDK tests
	$(BIN)/pytest sdk/python/tests -q

test-typescript: ## TypeScript SDK tests
	cd sdk/typescript && npm test

test-control-plane: ## Control-plane tests, including the end-to-end integration test
	$(BIN)/pytest control-plane/tests -q

test-integration: ## Just the end-to-end test: real SDK against a real control plane
	$(BIN)/pytest control-plane/tests/test_integration.py -q -p no:warnings

coverage: ## Python coverage report
	$(BIN)/pytest sdk/python/tests control-plane/tests \
	  --cov=keeper_firewall --cov=keeper_control --cov-report=term-missing

# --- quality ---------------------------------------------------------------

lint: ## ruff + mypy + tsc
	$(BIN)/ruff check sdk/python control-plane
	$(BIN)/mypy sdk/python/keeper_firewall
	cd sdk/typescript && npm run typecheck
	cd dashboard && npx tsc --noEmit

fmt: ## Autoformat what can be autoformatted
	$(BIN)/ruff check --fix sdk/python control-plane
	$(BIN)/ruff format sdk/python control-plane

audit: ## Dependency and secret scanning, as CI runs it
	$(BIN)/pip install pip-audit
	$(BIN)/pip-audit --strict
	cd sdk/typescript && npm audit --audit-level=high
	cd dashboard && npm audit --audit-level=high

validate-policies: ## Every shipped policy through the real parser
	@for f in policies/default.yaml policies/templates/*.yaml; do \
	  echo "== $$f"; $(BIN)/keeper policy validate "$$f" | head -1; \
	done

# --- running ---------------------------------------------------------------

run-control-plane: ## Control plane on :8080, SQLite, dev keys
	KEEPER_CP_INGEST_API_KEYS=dev-ingest-key \
	KEEPER_CP_ADMIN_API_KEYS=dev-admin-key \
	KEEPER_CP_ENVIRONMENT=development \
	$(BIN)/python -m keeper_control

run-dashboard: ## Dashboard dev server on :5173, proxying to :8080
	cd dashboard && npm run dev

demo: ## Generate traffic against a running control plane
	KEEPER_ENDPOINT=http://localhost:8080 \
	KEEPER_API_KEY=dev-ingest-key \
	$(BIN)/python examples/python/quickstart.py

examples: ## Run every credential-free example
	$(BIN)/python examples/python/quickstart.py
	$(BIN)/python examples/python/agent_with_tools.py
	$(BIN)/python examples/python/custom_detector.py

# --- docker ----------------------------------------------------------------

docker-build: ## Build both images
	docker build -f deploy/docker/Dockerfile.control-plane -t keeper/control-plane:0.1.0 .
	docker build -f deploy/docker/Dockerfile.dashboard -t keeper/dashboard:0.1.0 .

docker-up: ## Control plane + dashboard + Postgres
	cd deploy/docker && docker compose up -d
	@echo "control plane: http://localhost:8080/docs"
	@echo "dashboard:     http://localhost:8081"

docker-down: ## Stop the stack
	cd deploy/docker && docker compose down

# --- housekeeping ----------------------------------------------------------

build: ## Build distributable artefacts
	$(BIN)/pip install build
	$(BIN)/python -m build sdk/python
	cd sdk/typescript && npm run build
	cd dashboard && npm run build

clean: ## Remove build artefacts and caches
	rm -rf sdk/python/dist sdk/python/build sdk/typescript/dist dashboard/dist
	rm -rf .pytest_cache .mypy_cache .ruff_cache htmlcov .coverage
	find . -type d -name __pycache__ -prune -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name "*.egg-info" -prune -exec rm -rf {} + 2>/dev/null || true
