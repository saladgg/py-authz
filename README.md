# py-authz

[![CI](https://github.com/saladgg/py-authz/actions/workflows/ci.yml/badge.svg)](https://github.com/saladgg/py-authz/actions/workflows/ci.yml)
[![Release](https://github.com/saladgg/py-authz/actions/workflows/release.yml/badge.svg)](https://github.com/saladgg/py-authz/actions/workflows/release.yml)
[![Python](https://img.shields.io/badge/python-3.13%2B-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Version](https://img.shields.io/badge/version-1.0.0-blueviolet.svg)](CHANGELOG.md)
[![Status](https://img.shields.io/badge/status-production-brightgreen.svg)](https://pypi.org/project/py-authz/)
[![OpenFGA](https://img.shields.io/badge/OpenFGA-compatible-6c5ce7.svg)](https://openfga.dev)
[![Keycloak](https://img.shields.io/badge/Keycloak-JWT-7c69ef.svg)](https://www.keycloak.org)
[![FastAPI](https://img.shields.io/badge/FastAPI-adapter-009688.svg)](https://fastapi.tiangolo.com)
[![Code style: ruff](https://img.shields.io/badge/code%20style-ruff-ff69b4.svg)](https://docs.astral.sh/ruff/)
[![Type checker: mypy](https://img.shields.io/badge/type%20checker-mypy-blue.svg)](https://mypy.readthedocs.io)
[![Package manager: uv](https://img.shields.io/badge/pkg%20manager-uv-de5f7c.svg)](https://github.com/astral-sh/uv)
[![Conventional Commits](https://img.shields.io/badge/Conventional%20Commits-1.0.0-fe5196.svg)](https://www.conventionalcommits.org)

**py-authz** is a framework-agnostic, async-first authorization library for Python powered by [OpenFGA](https://openfga.dev), with optional identity provider integrations (e.g., Keycloak). It provides a clean public API, a declarative modeling layer, pluggable caching and storage, optional adapters for FastAPI and Keycloak, audit logging, and first-class multi-tenant support.

> "Is this user allowed to do X on Y?" — in one line, anywhere in your stack.

---

## Table of Contents

- [Features](#features)
- [Architecture](#architecture)
- [Installation](#installation)
- [Quickstart](#quickstart)
- [Declarative Modeling](#declarative-modeling)
- [FastAPI Integration](#fastapi-integration)
- [Keycloak JWT Validation](#keycloak-jwt-validation)
- [Caching](#caching)
- [Multi-Tenancy](#multi-tenancy)
- [CLI](#cli)
- [Project Layout](#project-layout)
- [Development](#development)
- [Testing](#testing)
- [Release Process](#release-process)
- [License](#license)

---

## Features

- **Async-first core** — every public method is a coroutine; designed for modern Python stacks.
- **Framework-agnostic** — a minimal core (`openfga-sdk`, `httpx`, `attrs`) with optional adapters, so the library fits any web framework.
- **Declarative modeling** — define resources and relations as Python classes; the generator emits an [OpenFGA v1.1](https://openfga.dev/docs/concepts) schema for you.
- **Model sync & diff** — ships a `ModelSync` that diffs the local model against OpenFGA and uploads only when something changed.
- **Pluggable caching** — `InMemoryCache` for dev/tests, `RedisCache` for production, or roll your own via `BaseCache`.
- **Pluggable storage** — PostgreSQL and Redis backends for the tenant store and model registry.
- **Multi-tenant** — `MultiTenantAuthz` resolves tenants to OpenFGA stores and can auto-provision new tenants atomically.
- **FastAPI adapter** — `require_dependency` (Depends-style) and `require_fastapi` (decorator) plus a request-context middleware.
- **Keycloak adapter** — `KeycloakJWTValidator` fetches JWKS and validates RS256 tokens into `Identity` objects.
- **Audit logging** — optional structured audit trail of every authorization decision.
- **Retry & resilience** — the OpenFGA HTTP client uses `httpx` with exponential backoff on transient errors.
- **Strong typing** — full `mypy` coverage and `ruff` (E, F, I, UP, B, C4, SIM) on every push.
- **CLI tooling** — `py-authz generate-model` and `py-authz sync` for CI pipelines.

---

## Architecture

Layered design — a framework-agnostic core with optional adapters:

```
adapters/ (FastAPI, Keycloak)  →  api.py (Authz, MultiTenantAuthz)
    →  core/enforcement.py (AuthzEngine)  →  clients/openfga.py (HTTP to OpenFGA)
```

```
            ┌────────────────────────┐
            │  Authz (public API)    │  ← enforce / can / require / sync_model
            └──────────┬─────────────┘
                       │
            ┌──────────▼─────────────┐
            │  AuthzEngine           │  ← validate → cache? → OpenFGA → audit? → return
            └──────────┬─────────────┘
                       │
            ┌──────────▼─────────────┐
            │  OpenFGAClient (HTTP)  │
            └────────────────────────┘

     modeling/   — ResourceModel + Relation → generated OpenFGA schema
     cache/      — InMemoryCache, RedisCache (pluggable via BaseCache)
     storage/    — TenantStore, ModelRegistry (Postgres, Redis, hybrid)
     adapters/   — FastAPI decorators, Keycloak JWT validator
     core/       — tenant manager, resolver, migrations, locks
```

Key components:

| Module | Purpose |
| ------ | ------- |
| [`py_authz/api.py`](py_authz/api.py) | `Authz` (single-tenant) and `MultiTenantAuthz` public entry points. |
| [`py_authz/core/enforcement.py`](py_authz/core/enforcement.py) | `AuthzEngine` — validate → cache → OpenFGA → audit. |
| [`py_authz/core/types.py`](py_authz/core/types.py) | Frozen `Identity`, `Resource`, `AuthzRequest` dataclasses. |
| [`py_authz/modeling/base.py`](py_authz/modeling/base.py) | `ResourceModel` metaclass + `Relation` declarative API. |
| [`py_authz/modeling/generator.py`](py_authz/modeling/generator.py) | Emits OpenFGA JSON schema from registered models. |
| [`py_authz/core/model_sync.py`](py_authz/core/model_sync.py) | Diffs local model against OpenFGA and uploads on change. |
| [`py_authz/core/tenant_manager.py`](py_authz/core/tenant_manager.py) | Atomic tenant provisioning with distributed locks. |
| [`py_authz/clients/openfga.py`](py_authz/clients/openfga.py) | `httpx`-backed OpenFGA client with retries. |
| [`py_authz/adapters/fastapi.py`](py_authz/adapters/fastapi.py) | Depends + decorator enforcement, request-id middleware. |
| [`py_authz/adapters/keycloak.py`](py_authz/adapters/keycloak.py) | `KeycloakJWTValidator` (JWKS + RS256). |

---

## Installation

Requires **Python 3.13+**.

> **Not yet on PyPI, and this repo is currently private.** The commands
> below are how installation will work once `py-authz` is published to
> PyPI (tracked as REL-9 in [`docs/todos/`](docs/todos/)) — until then,
> `pip install py-authz` will fail with "No matching distribution found".
> If you have access to this repository, install a tagged release
> directly from Git instead (requires your GitHub credentials to be
> configured for `git`, e.g. via SSH or a PAT):
>
> ```bash
> pip install "py-authz[all] @ git+https://github.com/saladgg/py-authz.git@v1.2.0"
> ```
>
> Swap `[all]` for any extra below, and `v1.2.0` for the tag you want
> (see [Releases](https://github.com/saladgg/py-authz/releases)).

```bash
# Core only (OpenFGA SDK, httpx, attrs)
pip install py-authz

# With FastAPI adapter
pip install "py-authz[fastapi]"

# With Redis cache
pip install "py-authz[redis]"

# With Postgres storage / audit
pip install "py-authz[postgres]"

# CLI tooling
pip install "py-authz[cli]"

# Everything
pip install "py-authz[all]"
```

Using [`uv`](https://github.com/astral-sh/uv) (recommended for development):

```bash
make venv          # .venv with Python 3.13
make install-dev   # dev + test dependencies
```

You will also need an OpenFGA instance. A dev compose file is bundled:

```bash
docker compose up -d openfga
curl http://localhost:8080/healthz
```

---

## Quickstart

A minimal authorization check:

```python
import asyncio
import os

from py_authz import Authz, Identity, Resource
from py_authz.clients.openfga import OpenFGAClient
from py_authz.core.enforcement import AuthzEngine


async def main() -> None:
    client = OpenFGAClient(
        api_url=os.environ["FGA_API_URL"],
        store_id=os.environ["FGA_STORE_ID"],
        model_id=os.environ["FGA_MODEL_ID"],
    )
    engine = AuthzEngine(fga_client=client)
    authz = Authz(engine)

    alice = Identity(id="user:alice")
    roadmap = Resource(type="document", id="roadmap")

    # Returns bool
    allowed = await authz.enforce("editor", alice, roadmap)

    # Raises AuthorizationDenied on failure
    await authz.require("viewer", alice, roadmap)

    await client.aclose()


asyncio.run(main())
```

See [`examples/`](examples/) for end-to-end, runnable slices covering quickstart, modeling, caching, FastAPI, Keycloak, and multi-tenant.

---

## Declarative Modeling

Define resources and relations as Python classes — the generator emits an OpenFGA schema and `ModelSync` uploads it only when it changed.

```python
from py_authz.modeling.base import Relation, ResourceModel
from py_authz.modeling.registry import registry


class Document(ResourceModel):
    type = "document"

    owner = Relation("owner")
    editor = Relation("editor", union=["owner"])  # owner implies editor
    viewer = Relation("viewer", union=["editor"])  # editor implies viewer


registry.register(Document)
```

Type-safe checks with `Relation` objects:

```python
allowed = await authz.can(Document.viewer, alice, Document(id="roadmap"))
```

Push the model to OpenFGA when it changes:

```python
new_model_id = await authz.sync_model()
```

---

## FastAPI Integration

Two styles — pick whichever fits your codebase.

**Decorator:**

```python
from fastapi import FastAPI, Request
from py_authz.adapters.fastapi import require_fastapi, request_context_middleware

app = FastAPI()
app.middleware("http")(request_context_middleware)


@app.patch("/documents/{doc_id}")
@require_fastapi(
    authz,
    Document.editor,
    resource_getter=lambda request, doc_id: Document(id=doc_id),
)
async def update_document(request: Request, doc_id: str):
    return {"id": doc_id, "updated": True}
```

**Depends:**

```python
from fastapi import Depends
from py_authz.adapters.fastapi import require_dependency


@app.get("/documents/{doc_id}")
async def read_document(
    doc_id: str,
    _: None = Depends(
        require_dependency(
            authz,
            Document.viewer,
            resource_getter=lambda request, doc_id: Document(id=doc_id),
        )
    ),
):
    return {"id": doc_id}
```

The bundled `request_context_middleware` attaches an `X-Request-ID` header and propagates it to authz logs via a context var.

---

## Keycloak JWT Validation

`KeycloakJWTValidator` fetches JWKS once and validates RS256 tokens into a normalized `Identity`.

```python
from py_authz.adapters.keycloak import KeycloakJWTValidator

validator = KeycloakJWTValidator(
    issuer="https://auth.example.com/realms/myrealm",
    audience="my-client-id",
)

payload = await validator.validate(token)
identity = validator.to_identity(payload)  # Identity(id="user:<sub>")
```

> Your OpenFGA tuples must use the same user string (`user:<sub>`), or override `to_identity` to normalize.

---

## Caching

Any `BaseCache` implementation plugs into the engine. A cache hit short-circuits the OpenFGA call.

```python
from py_authz.cache.memory import InMemoryCache
from py_authz.cache.redis import RedisCache

engine = AuthzEngine(fga_client=client, cache=InMemoryCache())
# or for production:
engine = AuthzEngine(fga_client=client, cache=RedisCache(url="redis://localhost:6379"))
```

Cache keys are deterministic (`<user>:<action>:<type>:<id>`) so invalidation is straightforward.

---

## Multi-Tenancy

`MultiTenantAuthz` resolves a tenant to its OpenFGA store, optionally auto-provisioning missing tenants with distributed locks.

```python
from py_authz.api import MultiTenantAuthz

mt = MultiTenantAuthz(
    api_url=os.environ["FGA_API_URL"],
    model_id=None,  # resolved per-tenant
    tenant_resolver=my_resolver,  # e.g. PostgresTenantStore
    tenant_manager=my_manager,  # optional auto-provisioning
)

authz = await mt.for_tenant("acme-corp")
await authz.enforce("editor", alice, roadmap)
```

Apply model migrations across every tenant:

```python
from py_authz.core.migrations_manager import MigrationManager

await MigrationManager(store, client_factory).apply_all()
```

---

## CLI

Installed as the `py-authz` script (requires the `cli` extra):

```bash
# Generate the OpenFGA schema from your registered models
py-authz generate-model --module myapp.authz.models --output model.json

# Diff + sync to a running OpenFGA instance
py-authz sync --module myapp.authz.models --api-url http://localhost:8080 --store-id $STORE_ID
```

---

## Project Layout

```
py-authz/
├── py_authz/
│   ├── api.py                # Authz, MultiTenantAuthz (public entry points)
│   ├── core/                 # Engine, types, exceptions, tenant manager, migrations
│   ├── clients/              # OpenFGA HTTP client (httpx + retries)
│   ├── modeling/             # ResourceModel, Relation, generator, registry
│   ├── cache/                # BaseCache, InMemoryCache, RedisCache
│   ├── storage/              # TenantStore / ModelRegistry (Postgres, Redis, hybrid)
│   ├── audit/                # Audit event types + Postgres logger
│   ├── adapters/             # FastAPI, Keycloak integrations
│   ├── validation/           # Request validation hooks
│   ├── cli/                  # py-authz CLI (env-var config via cli/config.py)
│   └── utils/                # deps loader, logging, retry
├── tests/                    # Mirrors source layout; pytest-asyncio auto mode
├── examples/                 # Runnable end-to-end examples
├── docs/                     # Getting started + architecture notes
├── .github/workflows/        # CI + semantic-release
├── docker-compose.yml        # Dev OpenFGA instance
├── Makefile                  # venv / install / format / lint / test
└── pyproject.toml
```

---

## Development

```bash
make venv            # .venv with Python 3.13 (via uv)
make install-dev     # install all dependencies including dev tools
make format          # ruff format + ruff check --fix
make format-check    # ruff format --check
make lint            # mypy
make test            # pytest with coverage
```

Pre-commit hooks run `black`, `ruff`, `isort`, `end-of-file-fixer`, and `trailing-whitespace` on commit.

**Conventions:**

- Async-only — every public method is a coroutine.
- Line length 100, ruff rules `E, F, I, UP, B, C4, SIM`.
- All custom exceptions inherit from `AuthzError` in [`core/exceptions.py`](py_authz/core/exceptions.py).
- Optional dependencies are loaded on-demand via [`utils/deps.py`](py_authz/utils/deps.py) with helpful `ImportError` messages.

---

## Testing

```bash
# Full suite + coverage
make test

# Single file
uv run pytest tests/core/test_enforcement.py

# Single test
uv run pytest tests/core/test_enforcement.py -k "test_name"
```

`tests/conftest.py` provides a `MockOpenFGAClient`, pre-built `Identity`/`Resource` fixtures, and an `AuthzEngine` wired to an in-memory cache for fast unit tests.

---

## Release Process

Releases are fully automated via [`python-semantic-release`](https://python-semantic-release.readthedocs.io). Merges to `main` with [Conventional Commits](https://www.conventionalcommits.org) trigger:

1. Version bump in `pyproject.toml`.
2. `CHANGELOG.md` generation.
3. Git tag + GitHub release.
4. `python -m build` sdist/wheel attached to the release.

Commit tags: `feat` (minor), `fix` / `perf` / `refactor` (patch), plus `docs`, `chore`, `build`, `ci`, `test`, `style` (no release).

---

## License

[MIT](LICENSE) © Salad Guyo
