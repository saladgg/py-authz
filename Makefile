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

# Connection settings for tests/live/ against the docker-compose stack
# (ports match docker-compose.yml). Shared by test-integration/test-live.
LIVE_ENV := \
	FGA_API_URL=http://localhost:8082 \
	KEYCLOAK_ISSUER=http://localhost:8081/realms/py-authz \
	KEYCLOAK_AUDIENCE=py-authz-demo \
	REDIS_URL=redis://localhost:6380/0 \
	POSTGRES_DSN=postgres://py_authz:py_authz@localhost:5433/py_authz

# Second interpreter CI's lint-test matrix runs (see .github/workflows/ci.yml).
PY ?= 3.14

# Where the control-plane API listens when run locally (run-control-plane).
CONTROL_PLANE_URL ?= http://localhost:8000

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
install-dev: ## Install dev + test dependencies (fails if uv.lock is stale — see SEC3-15)
	uv sync --locked --group dev

.PHONY: install-test
install-test: ## Install test dependencies only
	uv sync --locked --group test

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
lint: ## Run linter (ruff, incl. the bandit-equivalent `S` rules) and type checker
	uv run ruff check
	uv run mypy

.PHONY: check-dist
check-dist: ## Build the wheel and assert every install extra is in its metadata (ARCH3-1)
	rm -rf dist/
	uv build --wheel --out-dir dist/
	uv run python scripts/check_dist.py dist/

.PHONY: audit
audit: ## Scan dependencies for known vulnerabilities (see SEC2-8)
	# --skip-editable: the project itself is installed editable and is not on
	# PyPI yet, so pip-audit can only report it as "could not be audited" —
	# noise that buried the real findings when this step failed.
	uv run pip-audit --skip-editable

.PHONY: check
check: format-check lint audit test check-dist ## Mirror CI's lint-test job: format-check + lint + audit + test + check-dist

.PHONY: check-all
check-all: check panel-check ## Everything CI runs except the live integration job (Python + control panel)

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

.PHONY: test-py
test-py: ## Run the unit suite on another Python (default PY=3.14, as in CI's matrix), in its own venv
	UV_PROJECT_ENVIRONMENT=.venv-py$(PY) uv run --locked --group dev --python $(PY) \
		pytest --no-cov tests --ignore=tests/live

.PHONY: services-up
services-up: ## Start openfga + keycloak + redis + postgres (detached) and wait until each is ready
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

.PHONY: test-integration
test-integration: services-up test-live ## Start the docker-compose stack, then run tests/live against it (what CI runs)

.PHONY: test-live
test-live: ## Run tests/live against an already-running stack (see services-up) — no docker restart
	$(LIVE_ENV) uv run pytest tests/live -q --no-cov


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
install-control-plane: ## Install the control-plane API's dependencies (the `control-plane` extra)
	uv sync --extra control-plane

.PHONY: run-control-plane
run-control-plane: ## Run the control-plane API (dev/reload) against .env's §3 config — see docs/control_plane.md
	uv run uvicorn examples.14_control_plane_api:app --reload

.PHONY: control-plane-ready
control-plane-ready: ## Probe a running control-plane API: /livez, then /readyz (503 + failing check if a dependency is down)
	@curl -s -w "  [/livez %{http_code}]\n" $(CONTROL_PLANE_URL)/livez
	@curl -s -w "  [/readyz %{http_code}]\n" $(CONTROL_PLANE_URL)/readyz

# ----------------------------------------------------------
# Control Panel (control-panel/) — the Next.js frontend for the
# control-plane API above. Requires pnpm; see control-panel/README.md.
# ----------------------------------------------------------

.PHONY: panel-install panel-dev panel-build panel-lint panel-typecheck panel-test panel-audit panel-check

panel-install: ## Install the control-panel frontend's dependencies (exactly as locked)
	cd control-panel && pnpm install --frozen-lockfile

panel-dev: ## Run the control-panel frontend in dev mode (http://localhost:3001)
	cd control-panel && pnpm dev

panel-build: ## Build the control-panel frontend for production
	cd control-panel && pnpm build

panel-lint: ## Lint the control-panel frontend
	cd control-panel && pnpm lint

panel-typecheck: ## Type-check the control-panel frontend (tsc --noEmit)
	cd control-panel && pnpm typecheck

panel-test: ## Run the control-panel unit tests (vitest)
	cd control-panel && pnpm test

panel-audit: ## Scan the control-panel's production dependencies for known vulnerabilities
	cd control-panel && pnpm audit --prod

panel-check: panel-install panel-lint panel-typecheck panel-test panel-build panel-audit ## Mirror CI's control-panel job

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
