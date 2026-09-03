# Autonomous Security & Intelligence Assistant
#
# `make help` lists everything. The four gates CI enforces are `make lint`,
# `make format-check`, `make typecheck` and `make test`; `make check` runs all
# four in the same order CI does, so a clean `make check` means a green PR.

PYTHON  ?= python3
VENV    ?= .venv
BIN     := $(VENV)/bin
SRC     := src/
TESTS   := tests/
HOST    ?= 127.0.0.1
PORT    ?= 8443

.DEFAULT_GOAL := help
.PHONY: help setup setup-all test test-fast lint format format-check typecheck \
        check run-dashboard run-daemon sandbox-network secret clean

help: ## Show this help
	@grep -hE '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) \
	  | awk 'BEGIN{FS=":.*?## "}{printf "  \033[36m%-18s\033[0m %s\n", $$1, $$2}'

# --- environment -------------------------------------------------------------
setup: ## Create a venv and install runtime + dev dependencies
	$(PYTHON) -m venv $(VENV)
	$(BIN)/pip install --upgrade pip
	$(BIN)/pip install -r requirements-dev.txt
	@echo
	@echo "Ready. Activate with:  source $(BIN)/activate"
	@echo "Optional module extras:  make setup-all"

setup-all: setup ## Also install every optional feature extra
	$(BIN)/pip install -r requirements-dev.txt \
	  dnspython python-whois phonenumbers tldextract networkx \
	  shodan python-nmap playwright psutil
	@echo
	@echo "Extras installed. For the URL sandbox also run:  make sandbox-network"

# --- gates (the four CI enforces) --------------------------------------------
test: ## Run the full test suite
	$(BIN)/pytest $(TESTS)

test-fast: ## Run unit tests only, stopping at the first failure
	$(BIN)/pytest $(TESTS)/unit -x -q

lint: ## ruff check
	$(BIN)/ruff check $(SRC) $(TESTS)

format: ## Apply ruff format
	$(BIN)/ruff format $(SRC) $(TESTS)

format-check: ## Verify formatting without changing files
	$(BIN)/ruff format --check $(SRC) $(TESTS)

typecheck: ## mypy --strict
	$(BIN)/mypy $(SRC)

check: lint format-check typecheck test ## Run every gate, in CI's order
	@echo
	@echo "All gates passed."

# --- running -----------------------------------------------------------------
run-dashboard: ## Serve the web dashboard (needs DASHBOARD_SECRET_KEY)
	@test -n "$$DASHBOARD_SECRET_KEY" || { \
	  echo "DASHBOARD_SECRET_KEY is not set. Generate one with:"; \
	  echo "    export DASHBOARD_SECRET_KEY=\$$(make -s secret)"; \
	  exit 2; }
	$(BIN)/python -m security_assistant dashboard --host $(HOST) --port $(PORT)

run-daemon: ## Run the background daemon (dry run unless EXECUTE=1)
	$(BIN)/python -m security_assistant run-daemon $(if $(EXECUTE),--execute,)

# --- helpers -----------------------------------------------------------------
sandbox-network: ## Create the egress-controlled Docker network for URL detonation
	@docker network inspect sandbox-egress >/dev/null 2>&1 \
	  && echo "sandbox-egress already exists" \
	  || docker network create sandbox-egress
	@echo "Restrict this network's egress so it has no route to this host."

secret: ## Print a fresh DASHBOARD_SECRET_KEY
	@$(PYTHON) -c "import secrets; print(secrets.token_urlsafe(48))"

clean: ## Remove caches and build artefacts
	find . -type d -name __pycache__ -prune -exec rm -rf {} +
	rm -rf .pytest_cache .mypy_cache .ruff_cache htmlcov .coverage dist build
