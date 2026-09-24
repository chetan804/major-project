# ---------------------------------------------------------------------------
# EcoMind-AI — developer and CI entry points
#
# One canonical way to run each thing, so that "it works on my machine" means
# something: every target below is the same command CI runs.
#
# The gate is `make gate`: lint, type check, secret scan and the test suite. A
# phase is not complete until it passes (master prompt, section 60).
# ---------------------------------------------------------------------------

SHELL := /bin/bash
.DEFAULT_GOAL := help

REPO_ROOT := $(shell pwd)
VENV      ?= $(REPO_ROOT)/.venv

# Pick a Python that exists: the virtualenv when it has been created, otherwise
# whatever `python3` resolves to. Without this, CI (which installs into the
# runner's interpreter rather than a venv) cannot use any target here, and the
# workflow ends up duplicating the commands instead of calling them — which is how
# the database URL resolution came to be written twice and diverge.
PY        ?= $(shell if [ -x "$(VENV)/bin/python" ]; then echo "$(VENV)/bin/python"; else echo python3; fi)
PYTEST    := $(PY) -m pytest
RUFF      := $(PY) -m ruff
MYPY      := $(PY) -m mypy
ALEMBIC   := $(PY) -m alembic

BACKEND   := backend
FRONTEND  := frontend

# ---------------------------------------------------------------------------
# Database target for the make targets
#
# `.env` deliberately does not pin a database URL: a developer's `.env` should
# describe *their* setup, and a committed default of `localhost:5432` is exactly
# the kind of value that silently points a migration at the wrong server. The
# cluster this repository actually provisions is reachable over a unix socket,
# so the targets below resolve it here and pass it explicitly.
#
# `?=` means an exported DATABASE_URL or MIGRATION_DATABASE_URL wins, so CI,
# staging and a one-off `make migrate DATABASE_URL=...` all work unchanged.
# ---------------------------------------------------------------------------
DATABASE_URL           ?= $(shell $(PY) scripts/pg_server.py url 2>/dev/null)
MIGRATION_DATABASE_URL ?= $(shell $(PY) scripts/pg_server.py sync-url 2>/dev/null)
export DATABASE_URL
export MIGRATION_DATABASE_URL

# Test subsets, by the markers registered in backend/pyproject.toml.
UNIT_TESTS := -m unit
DB_TESTS   := -m db
API_TESTS  := -m "api or security"
ARCH_TESTS := -m architecture

.PHONY: help
help: ## Show this help.
	@echo "EcoMind-AI make targets:"
	@grep -hE '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) \
		| awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-18s\033[0m %s\n", $$1, $$2}'

# ---------------------------------------------------------------------------
# Setup and environment
# ---------------------------------------------------------------------------
.PHONY: bootstrap
bootstrap: ## Create the venv, install dependencies, start PostgreSQL, run migrations.
	./scripts/bootstrap.sh

.PHONY: install
install: ## (Re)install python dependencies into the venv.
	$(PY) -m pip install --quiet --upgrade pip
	$(PY) -m pip install --quiet -r $(BACKEND)/requirements/dev.txt

.PHONY: db-start
db-start: ## Start the local PostgreSQL cluster (real PostgreSQL 16, no Docker).
	$(PY) scripts/pg_server.py start

.PHONY: db-stop
db-stop: ## Stop the local PostgreSQL cluster.
	$(PY) scripts/pg_server.py stop

.PHONY: db-status
db-status: ## Report whether the cluster is running, and where its socket is.
	$(PY) scripts/pg_server.py status

.PHONY: env-check
env-check: ## Verify the runtime and dependencies actually available here.
	$(PY) scripts/verify_environment.py

# ---------------------------------------------------------------------------
# Database migrations
# ---------------------------------------------------------------------------
.PHONY: migrate
migrate: ## Apply all pending migrations.
	cd $(BACKEND) && $(ALEMBIC) upgrade head

.PHONY: migrate-down
migrate-down: ## Revert the most recent migration.
	cd $(BACKEND) && $(ALEMBIC) downgrade -1

.PHONY: migration
migration: ## Autogenerate a migration. Usage: make migration MSG="add bins table"
	@test -n "$(MSG)" || { echo 'MSG is required, e.g. make migration MSG="add bins table"'; exit 2; }
	cd $(BACKEND) && $(ALEMBIC) revision --autogenerate -m "$(MSG)"

.PHONY: migrate-check
migrate-check: ## Fail if models and migrations have drifted apart. Non-destructive.
	cd $(BACKEND) && $(ALEMBIC) check

.PHONY: migrate-verify
migrate-verify: ## Prove migrations apply, reverse and re-apply. DESTRUCTIVE: drops every table.
	@echo "This drops every table in $$MIGRATION_DATABASE_URL and re-applies from scratch."
	cd $(BACKEND) && $(ALEMBIC) upgrade head
	cd $(BACKEND) && $(ALEMBIC) check
	cd $(BACKEND) && $(ALEMBIC) downgrade base
	cd $(BACKEND) && $(ALEMBIC) upgrade head
	cd $(BACKEND) && $(ALEMBIC) heads

# ---------------------------------------------------------------------------
# Static analysis
# ---------------------------------------------------------------------------
.PHONY: lint
lint: ## Lint and check formatting.
	cd $(BACKEND) && $(RUFF) check .
	cd $(BACKEND) && $(RUFF) format --check .

.PHONY: format
format: ## Apply lint autofixes and formatting.
	cd $(BACKEND) && $(RUFF) check --fix .
	cd $(BACKEND) && $(RUFF) format .

.PHONY: typecheck
typecheck: ## Static type check the application package.
	cd $(BACKEND) && $(MYPY)

.PHONY: secrets
secrets: ## Fail if a credential is present in the repository.
	$(PY) scripts/check_secrets.py

.PHONY: audit
audit: lint typecheck secrets ## Every static check, with no tests.

# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------
.PHONY: test
test: ## Run the whole test suite.
	cd $(BACKEND) && $(PYTEST)

.PHONY: test-unit
test-unit: ## Pure-logic tests: no database, no HTTP.
	cd $(BACKEND) && $(PYTEST) $(UNIT_TESTS)

.PHONY: test-db
test-db: ## Tests that require the real PostgreSQL cluster.
	cd $(BACKEND) && $(PYTEST) $(DB_TESTS)

.PHONY: test-api
test-api: ## HTTP and security tests.
	cd $(BACKEND) && $(PYTEST) $(API_TESTS)

.PHONY: test-arch
test-arch: ## Structural rules: layering, route inventory, secret scanner.
	cd $(BACKEND) && $(PYTEST) $(ARCH_TESTS)

.PHONY: coverage
coverage: ## Run the suite with a coverage report.
	cd $(BACKEND) && $(PYTEST) --cov=app --cov-report=term-missing

# ---------------------------------------------------------------------------
# The gate
# ---------------------------------------------------------------------------
.PHONY: gate
gate: audit migrate-check test ## Everything a phase must pass before its report is written.

# Reversibility is deliberately NOT part of `gate`: `migrate-verify` drops every
# table, and a developer running the gate against their development database must
# not lose it. The round trip is proven against the throwaway test database by
# backend/tests/db/test_migrations.py, which runs on every `make test`.

# ---------------------------------------------------------------------------
# Running
# ---------------------------------------------------------------------------
.PHONY: run
run: ## Start the API server on :8000 with reload.
	cd $(BACKEND) && $(PY) -m uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload

.PHONY: run-prod
run-prod: ## Start the API server without reload, as production would.
	cd $(BACKEND) && $(PY) -m uvicorn app.main:app --host 0.0.0.0 --port 8000

# ---------------------------------------------------------------------------
# Housekeeping
# ---------------------------------------------------------------------------
.PHONY: clean
clean: ## Remove caches and build output. Leaves .venv and .runtime alone.
	find . -type d -name __pycache__ -prune -exec rm -rf {} + 2>/dev/null || true
	rm -rf $(BACKEND)/.pytest_cache $(BACKEND)/.mypy_cache $(BACKEND)/.ruff_cache
	rm -rf $(FRONTEND)/dist $(FRONTEND)/node_modules/.vite

.PHONY: clean-all
clean-all: clean ## Also remove the venv and the local database cluster.
	rm -rf $(VENV) .runtime
