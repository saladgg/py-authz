# ==========================================================
# py-authz - Makefile
# ----------------------------------------------------------
# Unified interface for development, testing, and Docker
# workflows. Run `make help` to see available targets.
# ==========================================================

.DEFAULT_GOAL := help

# ----------------------------------------------------------
# Variables
# ----------------------------------------------------------

SOURCE       := py_authz
VENV_PYTHON  := .venv/bin/python

# ----------------------------------------------------------
# Help
# ----------------------------------------------------------

.PHONY: help
help: ## Show this help message
	@echo ""
	@echo "  py-authz"
	@echo "  ===================="
	@echo ""
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-18s\033[0m %s\n", $$1, $$2}'
	@echo ""

# ----------------------------------------------------------
# Environment Setup
# ----------------------------------------------------------

.PHONY: venv
venv: ## Create a virtual environment with Python 3.13
	uv venv --python 3.13 --python-preference only-managed

.PHONY: install
install: ## Install production dependencies
	uv sync

.PHONY: install-dev
install-dev: ## Install dev + test dependencies
	uv sync --group dev

.PHONY: install-test
install-test: ## Install test dependencies only
	uv sync --group test

.PHONY: update
update: ## Upgrade all dependency versions in the lockfile
	uv lock --upgrade

# ----------------------------------------------------------
# Code Quality (target dirs configured in pyproject.toml)
# ----------------------------------------------------------


.PHONY: format
format: ## Format and fix
	uv run ruff format
	uv run ruff check --fix

.PHONY: format-check
format-check: ## Check formatting without changes
	uv run ruff format --check

.PHONY: lint
lint: ## Run linter and type checker
	uv run mypy

.PHONY: audit
audit: ## Scan dependencies for known vulnerabilities (see SEC2-8)
	uv run pip-audit

# ----------------------------------------------------------
# Testing
# ----------------------------------------------------------

.PHONY: test
test: ## Run test suite with coverage
	uv run pytest

.PHONY: test-integration
test-integration: ## Run tests/live against a real OpenFGA + Keycloak + Redis + Postgres stack (docker compose)
	docker compose up -d openfga keycloak redis postgres
	@echo "Waiting for OpenFGA + Keycloak + Redis + Postgres to become reachable..."
	@i=0; until curl -sf http://localhost:8082/healthz >/dev/null 2>&1; do \
		i=$$((i+1)); if [ $$i -ge 60 ]; then echo "OpenFGA did not become healthy in time"; exit 1; fi; \
		sleep 1; \
	done
	@i=0; until curl -sf http://localhost:8081/realms/py-authz/.well-known/openid-configuration >/dev/null 2>&1; do \
		i=$$((i+1)); if [ $$i -ge 60 ]; then echo "Keycloak did not become reachable in time"; exit 1; fi; \
		sleep 1; \
	done
	@i=0; until docker exec redis redis-cli ping >/dev/null 2>&1; do \
		i=$$((i+1)); if [ $$i -ge 60 ]; then echo "Redis did not become ready in time"; exit 1; fi; \
		sleep 1; \
	done
	@i=0; until docker exec postgres pg_isready -U py_authz >/dev/null 2>&1; do \
		i=$$((i+1)); if [ $$i -ge 60 ]; then echo "Postgres did not become ready in time"; exit 1; fi; \
		sleep 1; \
	done
	FGA_API_URL=http://localhost:8082 \
	KEYCLOAK_ISSUER=http://localhost:8081/realms/py-authz \
	KEYCLOAK_AUDIENCE=py-authz-demo \
	REDIS_URL=redis://localhost:6380/0 \
	POSTGRES_DSN=postgres://py_authz:py_authz@localhost:5433/py_authz \
	uv run pytest tests/live -q --no-cov


# ----------------------------------------------------------
# py-authz installation options
# ----------------------------------------------------------
# NOTE: these target PyPI, which py-authz is not yet published to (see
# REL-9 in docs/todos/) — they will fail with "No matching distribution
# found" until that ships. If you have access to this (currently private)
# repo, install a tagged release from Git instead — see README.md's
# Installation section for the working `pip install ... @ git+https://...`
# form.

.PHONY: install-core install-extras install-all

install-core: ## Install py-authz (core only, no extras)
	pip install py-authz

install-extras: ## Install py-authz with fastapi + redis + postgres + cli + keycloak
	pip install "py-authz[fastapi,redis,postgres,cli,keycloak]"

install-all: ## Install py-authz with every extra
	pip install "py-authz[all]"

# ----------------------------------------------------------
# Docker
# ----------------------------------------------------------
# Services started by `make docker-up`:
#   openfga   Fine-grained authz server → http://localhost:8082
#             Playground UI             → http://localhost:3000
#             Hosted playground         → https://play.fga.dev/sandbox/?fga_api_host=127.0.0.1:8082&fga_api_scheme=http
#   keycloak  Identity provider (JWT)   → http://localhost:8081
#             Admin console             → http://localhost:8081/admin  (admin / admin)
#             Seeded realm              → py-authz  (user: alice / alice, client: py-authz-demo)
#
# Prerequisites: copy .env.example → .env before first run.

.PHONY: docker-up docker-down docker-clean

docker-up: ## Start OpenFGA + Keycloak in the foreground
	docker compose up

docker-down: ## Stop services and remove volumes
	docker compose down -v

docker-clean: ## Stop, remove orphans, and prune the builder cache
	docker compose down -v --remove-orphans
	docker builder prune -f
