# ==========================================================
# django-authz - Makefile
# ==========================================================

.DEFAULT_GOAL := help

.PHONY: help
help:
	@echo "Available commands:"
	@echo "  make install        Install production dependencies"
	@echo "  make install-dev    Install dev dependencies"
	@echo "  make install-test   Install test dependencies"
	@echo "  make run            Run development server"
	@echo "  make prod           Run production server"
	@echo "  make lint           Run ruff"
	@echo "  make format         Format code"
	@echo "  make check          CI formatting checks"
	@echo "  make test           Run tests"
	@echo ""
	@echo "Docker (dev stack: demo:8000  keycloak:8080  openfga:8081):"
	@echo "  make docker-build   Build the demo image"
	@echo "  make docker-up      Start the full dev stack"
	@echo "  make docker-down    Stop and remove volumes"
	@echo "  make docker-logs    Tail logs for all services"
	@echo "  make docker-shell   Open a shell in the demo container"



# ----------------------------------------------------------
# Dependency Management
# ----------------------------------------------------------
# Use `only-managed` to bypass sudo installed system python

VENV_PYTHON := .venv/bin/python

.PHONY: venv_setup
venv_setup:
	uv venv --python 3.14 --python-preference only-managed &
	source .venv/bin/activate

.PHONY: install install-dev install-test update

# Main install (production / default dependencies)
install:
	uv sync

# Development dependencies (main + dev group)
install-dev:
	uv sync --group dev

# Test/CI dependencies (main + test group, no dev)
install-test:
	uv sync --group test

# Update dependencies (upgrade versions in lockfile)
update:
	uv lock --upgrade

# ----------------------------------------------------------
# Linting & Formatting
# ----------------------------------------------------------

SOURCE = django_authz

.PHONY: format format-check lint fix test


format:
	uv run ruff format $(SOURCE) 

format-check:
	uv run ruff format --check $(SOURCE)

lint:
	uv run ruff check $(SOURCE) 
	uv run mypy $(SOURCE) 

fix:
	uv run ruff check $(SOURCE) --fix 

test:
	uv run pytest --cov=$(SOURCE) --cov-report=term-missing

.PHONY: all
all: format-check lint fix test


# ----------------------------------------------------------
# Docker
# ----------------------------------------------------------
# Manages the local development stack defined in docker-compose.yml.
#
# Services started by `docker-up`:
#   demo      Django demo application   → http://localhost:8000
#   keycloak  Identity provider (JWT)   → http://localhost:8080
#   openfga   Fine-grained authz server → http://localhost:8081
#             OpenFGA playground UI     → http://localhost:3000
#
# Prerequisites: copy .env.example → .env before first run.

.PHONY: docker-build docker-up docker-down docker-logs docker-shell

docker-build:
	docker build -t django-authz-demo .

docker-up:
	docker compose up --build

docker-down:
	docker compose down -v

docker-logs:
	docker compose logs -f

docker-shell:
	docker compose exec demo /bin/sh


# ----------------------------------------------------------
# Clean
# ----------------------------------------------------------

.PHONY: clean
clean:
	# Remove all Python cache directories
	find . -type d -name "__pycache__" -exec rm -rf {} +
	find . -type d -name "*.pyc" -delete
	find . -type d -name ".pytest_cache" -exec rm -rf {} +
	find . -type d -name ".ruff_cache" -exec rm -rf {} +
	find . -type d -name ".mypy_cache" -exec rm -rf {} +
	find . -type d -name ".coverage" -delete
	find . -type d -name "htmlcov" -exec rm -rf {} +
	find . -type d -name ".tox" -exec rm -rf {} +
	find . -type d -name ".eggs" -exec rm -rf {} +
	find . -type d -name "*.egg-info" -exec rm -rf {} +
