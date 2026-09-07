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
		awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-22s\033[0m %s\n", $$1, $$2}'
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

.PHONY: check
check: format-check lint audit test ## Run format-check + lint + audit + test — mirrors CI's lint-test job in one shot

# ----------------------------------------------------------
# Testing
# ----------------------------------------------------------

.PHONY: test
test: ## Run test suite with coverage
	uv run pytest

.PHONY: test-fast
test-fast: ## Run the test suite without coverage instrumentation (quicker local iteration)
	uv run pytest --no-cov

.PHONY: test-cov-html
test-cov-html: ## Run tests and generate an HTML coverage report at htmlcov/index.html
	uv run pytest --cov-report=html
	@echo "Coverage report: htmlcov/index.html"

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
# Control-Plane API (py_authz/control_plane/) — see docs/control_plane.md
# ----------------------------------------------------------

.PHONY: install-control-plane
install-control-plane: ## Install only the control-plane API's own dependency group
	uv sync --group control-plane

.PHONY: run-control-plane
run-control-plane: ## Run the control-plane API (dev/reload) against .env's §3 config — see docs/control_plane.md
	uv run uvicorn examples.14_control_plane_api:app --reload

# ----------------------------------------------------------
# Control Panel (control-panel/) — the Next.js frontend for the
# control-plane API above. Requires pnpm; see control-panel/README.md.
# ----------------------------------------------------------

.PHONY: panel-install panel-dev panel-build panel-lint

panel-install: ## Install the control-panel frontend's dependencies
	cd control-panel && pnpm install

panel-dev: ## Run the control-panel frontend in dev mode (http://localhost:3001)
	cd control-panel && pnpm dev

panel-build: ## Build the control-panel frontend for production
	cd control-panel && pnpm build

panel-lint: ## Lint the control-panel frontend
	cd control-panel && pnpm lint

# ----------------------------------------------------------
# Docker
# ----------------------------------------------------------
# Services started by `make docker-up` (all of docker-compose.yml —
# openfga, keycloak, redis, postgres):
#   openfga   Fine-grained authz server → http://localhost:8082
#             Playground UI             → http://localhost:3000
#             Hosted playground         → https://play.fga.dev/sandbox/?fga_api_host=127.0.0.1:8082&fga_api_scheme=http
#   keycloak  Identity provider (JWT)   → http://localhost:8081
#             Admin console             → http://localhost:8081/admin  (admin / admin)
#             Seeded realm              → py-authz  (user: alice / alice, client: py-authz-demo)
#   redis     tests/live/, control-plane cache/rate-limiting → localhost:6380
#   postgres  tests/live/, control-plane storage             → localhost:5433
#
# Prerequisites: copy .env.example → .env before first run — grouped into
# §1 (OpenFGA/Keycloak, for examples/ + the CLI), §2 (tests/live), and §3
# (the control-plane API, py_authz/control_plane/ — see
# docs/control_plane.md). Most sessions only need one group.

.PHONY: docker-up docker-up-bg docker-down docker-clean docker-ps docker-logs

docker-up: ## Start openfga + keycloak + redis + postgres in the foreground
	docker compose up

docker-up-bg: ## Same as docker-up, but detached (-d) — frees up the terminal
	docker compose up -d

docker-down: ## Stop services and remove volumes
	docker compose down -v

docker-clean: ## Stop, remove orphans, and prune the builder cache
	docker compose down -v --remove-orphans
	docker builder prune -f

docker-ps: ## Show the status of this project's docker compose services
	docker compose ps

docker-logs: ## Tail logs from every running docker compose service
	docker compose logs -f
