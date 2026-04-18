# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project

py-authz is a framework-agnostic Python authorization library built on OpenFGA. It provides an async-first core with optional adapters for FastAPI and Keycloak, pluggable storage (PostgreSQL, Redis), caching, audit logging, and multi-tenant support.

## Commands

```bash
make venv            # Create .venv with Python 3.13 (via uv)
make install-dev     # Install all deps including dev tools
make format          # Auto-format with ruff (format + check --fix)
make format-check    # Check formatting without modifying
make lint            # Type-check with mypy
make test            # Run full test suite with coverage

# Run a single test file or test
uv run pytest tests/core/test_enforcement.py
uv run pytest tests/core/test_enforcement.py -k "test_name"
```

Pre-commit hooks run black, ruff, isort, end-of-file-fixer, and trailing-whitespace on commit.

## Architecture

**Layered design** — framework-agnostic core with optional adapters:

```
adapters/ (FastAPI, Keycloak)  →  api.py (Authz, MultiTenantAuthz)
    →  core/enforcement.py (AuthzEngine)  →  clients/openfga.py (HTTP to OpenFGA)
```

- **`py_authz/api.py`** — `Authz` (single-tenant) and `MultiTenantAuthz` (multi-tenant) are the public entry points. `Authz.enforce()`, `.can()`, `.require()` delegate to the engine.
- **`py_authz/core/enforcement.py`** — `AuthzEngine` orchestrates: validate request → check cache → call OpenFGA → cache result → audit. Accepts optional `BaseCache` and audit logger.
- **`py_authz/core/types.py`** — Frozen dataclasses `Identity`, `Resource`, `AuthzRequest`. Immutable by design.
- **`py_authz/modeling/base.py`** — `ResourceModel` (metaclass-based) and `Relation` define authorization models declaratively. Models auto-register via metaclass into `modeling/registry.py`.
- **`py_authz/modeling/generator.py`** — `OpenFGAModelGenerator` converts registered ResourceModels into OpenFGA JSON schema (v1.1).
- **`py_authz/core/model_sync.py`** — `ModelSync` diffs local model against OpenFGA and uploads only if changed.
- **`py_authz/core/model_diff.py`** — `ModelDiffer` normalizes and compares models (handles field ordering).
- **`py_authz/core/tenant_manager.py`** — Provisions tenants atomically: create store → sync model → persist mapping. Uses distributed locks.
- **`py_authz/core/migrations_manager.py`** — `MigrationManager` applies model updates across all tenants.
- **`py_authz/clients/openfga.py`** — `OpenFGAClient` wraps httpx with retry logic (exponential backoff on timeout/connection errors).
- **`py_authz/adapters/fastapi.py`** — `require_dependency()` (FastAPI Depends) and `require_fastapi()` (decorator) for route-level enforcement. `request_context_middleware` propagates request IDs.
- **`py_authz/adapters/keycloak.py`** — `KeycloakJWTValidator` fetches JWKS and validates RS256 JWTs, returning `Identity`.
- **`py_authz/cache/`** — `BaseCache` ABC with `InMemoryCache` (dev/test) and `RedisCache` (production).
- **`py_authz/storage/`** — `TenantStore` and `ModelRegistry` abstractions with PostgreSQL and Redis implementations.

## Conventions

- **Async-only**: all public methods are async. Tests use `pytest-asyncio` with `asyncio_mode = "auto"`.
- **Optional dependencies**: extras like fastapi, redis, postgres, cli are loaded on-demand via `utils/deps.py` with helpful ImportError messages. Core has minimal deps (openfga-sdk, httpx, attrs).
- **Ruff**: line length 100, rules `E, F, I, UP, B, C4, SIM`.
- **mypy**: configured with pydantic plugin; several error codes disabled (see pyproject.toml `[tool.mypy]`).
- **Exception hierarchy**: all custom exceptions inherit from `AuthzError` in `core/exceptions.py`. Use specific subclasses (`AuthorizationDenied`, `ServiceTimeout`, etc.).
- **Testing**: mocks in `tests/conftest.py` provide `MockOpenFGAClient`, pre-built `Identity`/`Resource` fixtures, and an `AuthzEngine` wired to in-memory cache.
