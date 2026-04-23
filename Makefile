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

# ----------------------------------------------------------
# Testing
# ----------------------------------------------------------

.PHONY: test
test: ## Run test suite with coverage
	uv run pytest 


# ----------------------------------------------------------
# py-authz installation options
# ----------------------------------------------------------

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


