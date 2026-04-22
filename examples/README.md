# py-authz examples

End-to-end, runnable examples of the library. Each file is a focused slice:
quickstart → modeling → caching → HTTP → auth → multi-tenant. They share one
domain (documents and folders) and one seed dataset so you can swap between
them without rebuilding context.

## What you'll find here

| File                      | What it shows                                               |
| ------------------------- | ----------------------------------------------------------- |
| `models.py`               | `ResourceModel` + `Relation` definitions shared by all examples |
| `seed.py`                 | Creates an OpenFGA store, uploads the model, writes seed tuples |
| `01_quickstart.py`        | Minimal `Authz.enforce` / `.require` check                  |
| `02_models_and_sync.py`   | Generate model from Python, sync to OpenFGA, typed `.can()` |
| `03_caching.py`           | Plug in `InMemoryCache` / `RedisCache`                      |
| `04_fastapi_app.py`       | FastAPI routes protected by `require_fastapi` (stubbed auth)|
| `05_keycloak_fastapi.py`  | Real Keycloak JWT validation via `KeycloakAuthMiddleware`   |
| `06_multitenant.py`       | `MultiTenantAuthz` with auto-provisioning per tenant        |
| `07_explain_and_bulk.py`  | `engine.explain`, `engine.bulk_enforce`, `authz.grant/revoke` |

## Prerequisites

**OpenFGA running locally.** From the repo root:

```bash
docker compose up -d openfga        # starts OpenFGA on :8080
curl http://localhost:8080/healthz  # sanity check
```

Note: the bundled `openfga` service uses an in-memory store, so data is wiped
on container restart — re-run `seed.py` afterwards.

**Install the library with the extras you need:**

```bash
# From the repo root (uses uv):
uv sync --group all

# Or with pip, from a fresh venv:
pip install -e ".[all]"

# Keycloak example additionally needs PyJWT with crypto:
pip install "pyjwt[crypto]"
```

The extras map to groups in `pyproject.toml`: `fastapi`, `redis`, `postgres`,
`cli`, `all`. Only install what each example needs; the core library has no
optional deps.

## One-time seed

Run once after starting OpenFGA. This creates a store, syncs the model, and
writes tuples for `alice` (owner), `bob` (editor), `carol` (viewer), and
`dave` (viewer of a different doc):

```bash
uv run python examples/seed.py
```

It prints three env vars — **export them in the shell you run the examples
from**:

```bash
export FGA_API_URL=http://localhost:8080
export FGA_STORE_ID=01HXYZ...
export FGA_MODEL_ID=01HXYZ...
```

## Running each example

```bash
# Quickstart — two boolean checks and a .require()
uv run python examples/01_quickstart.py

# Generate + sync model, then check with typed Relation objects
uv run python examples/02_models_and_sync.py

# Caching: one cold hit vs 100 warm hits
uv run python examples/03_caching.py

# FastAPI (fake auth via X-User-Id header)
uv run uvicorn examples.04_fastapi_app:app --reload
# then:
curl -H "X-User-Id: alice" http://localhost:8000/documents/roadmap
curl -H "X-User-Id: carol" -X PATCH http://localhost:8000/documents/roadmap  # 403

# Keycloak + FastAPI (needs a real realm)
export KEYCLOAK_ISSUER=https://auth.example.com/realms/myrealm
export KEYCLOAK_AUDIENCE=my-client-id
uv run uvicorn examples.05_keycloak_fastapi:app --reload

# Multi-tenant: provisions two fresh stores and contrasts their decisions
uv run python examples/06_multitenant.py

# Explain a decision, run bulk checks, grant/revoke via the high-level API
uv run python examples/07_explain_and_bulk.py
```

## How the pieces fit

```
            ┌────────────────────────┐
            │  Authz (public API)    │  ← enforce / can / require / sync_model
            └──────────┬─────────────┘
                       │
            ┌──────────▼─────────────┐
            │  AuthzEngine           │  ← cache? → OpenFGA → audit? → return
            └──────────┬─────────────┘
                       │
            ┌──────────▼─────────────┐
            │  OpenFGAClient (HTTP)  │
            └────────────────────────┘

     modeling/   — ResourceModel + Relation → generated OpenFGA schema
     cache/      — InMemoryCache, RedisCache (pluggable)
     adapters/   — FastAPI decorators, Keycloak JWT validator
     core/       — tenant manager, resolver, model sync/diff
```

## Modeling notes

`ResourceModel` subclasses declare one `Relation` per permission.
`union=[...]` lets you say "editor implies viewer". `inherits=[...]` works
similarly but is meant for computed usersets (e.g., inherit folder
permissions). `subjects=[...]` (default `["user"]`) declares who can hold
the relation.

After defining a model, call `registry.register(YourModel)` — the generator
only picks up registered classes.

## Gotchas

- **`sub` vs OpenFGA user id.** `KeycloakJWTValidator.to_identity` produces
  `user:<sub>`. Your tuples must use that exact user string, or override
  `to_identity` to normalize.
- **Model must be synced before checks.** If `FGA_MODEL_ID` is stale, checks
  silently return `False`. Run `seed.py` or `authz.sync_model()` after any
  `ResourceModel` change.
- **`InMemoryCache` is per-process.** Fine for a single-worker dev server;
  switch to `RedisCache` for multi-worker / multi-instance deployments.
- **OpenFGA compose service is ephemeral.** Its default in-memory datastore
  drops everything on restart — you'll need to re-seed.
- **Tuple writes go through the library.** Use `OpenFGAClient.write_tuples`
  for raw writes, or `Authz.grant / revoke / grant_many / revoke_many` for
  the ergonomic form. Seed and multi-tenant examples use these; no direct
  HTTP calls are needed.
- **`explain` / `bulk_enforce` live on `AuthzEngine`, not `Authz`.** Grab
  `authz._engine` or keep the engine around if you need them — see
  `07_explain_and_bulk.py`.

