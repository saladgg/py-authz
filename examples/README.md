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
| `08_list_objects.py`      | Inverse query — "which documents can alice view?"           |
| `09_contextual_and_abac.py` | Per-request `contextual_tuples` and ABAC `context`        |
| `10_unit_testing.py`      | `make_fake_authz()` — unit-test authz without OpenFGA       |
| `11_hierarchical_permissions.py` | `Relation(from_parent=...)` — a folder viewer inherits document viewer |
| `12_multitenant_fastapi.py` | `MultiTenantAuthz` + FastAPI together — `Authz` resolved per request by tenant |
| `13_fail_open_fastapi.py` | `fail_open=True` — a route that stays available during an OpenFGA outage, contrasted with the fail-closed default |
| `14_control_plane_api.py` | `py_authz.control_plane` — the optional HTTP management API (tenants, models, migrations, service accounts, audit, RBAC); see `docs/control_plane.md` |

## Prerequisites

**OpenFGA running locally.** From the repo root:

```bash
docker compose up -d openfga        # starts OpenFGA on :8082
curl http://localhost:8082/healthz  # sanity check
```

Note: the bundled `openfga` service uses an in-memory store, so data is wiped
on container restart — re-run `seed.py` afterwards.

**Install the library with the extras you need:**

```bash
# From the repo root (uses uv):
uv sync --extra all

# Or with pip, from a fresh venv:
pip install -e ".[all]"

# Keycloak example additionally needs PyJWT with crypto:
pip install "pyjwt[crypto]"
```

The extras are `[project.optional-dependencies]` in `pyproject.toml`: `fastapi`, `redis`, `postgres`,
`keycloak`, `cli`, `all`, `control-plane`. Only install what each example needs; the core library has no
optional deps.

## One-time seed

Run once after starting OpenFGA. This creates a store, syncs the model, and
writes tuples for `alice` (owner), `bob` (editor), `carol` (viewer), `dave`
(viewer of a different doc), and links `document:budget` to
`folder:engineering` via `parent` with no direct grants of its own — see
`11_hierarchical_permissions.py`:

```bash
uv run python examples/seed.py
```

It prints three env vars — **export them in the shell you run the examples
from**:

```bash
export FGA_API_URL=http://localhost:8082
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

# List all objects a user has a given relation on (inverse query)
uv run python examples/08_list_objects.py

# Per-request contextual tuples + ABAC context (cache-bypassing)
uv run python examples/09_contextual_and_abac.py

# In-memory fake — no OpenFGA needed (env vars not required)
uv run python examples/10_unit_testing.py

# Hierarchical permissions: folder viewer → document viewer, via a parent
# relation (tupleToUserset) — no direct grant on document:budget at all
uv run python examples/11_hierarchical_permissions.py

# Multi-tenant FastAPI: Authz resolved per request by X-Tenant-ID header
uv run uvicorn examples.12_multitenant_fastapi:app --reload
# then:
curl -H "X-Tenant-ID: acme" -H "X-User-Id: alice" http://localhost:8000/documents/report
curl -H "X-Tenant-ID: globex" -H "X-User-Id: alice" http://localhost:8000/documents/report  # → 403

# fail_open=True: a fail-closed and a fail-open route side by side —
# stop OpenFGA (`docker compose stop openfga`) to see them diverge
uv run uvicorn examples.13_fail_open_fastapi:app --reload
# then:
curl -H "X-User-Id: alice" http://localhost:8000/documents/roadmap
curl -H "X-User-Id: alice" http://localhost:8000/documents/roadmap/lenient

# Control-plane API: the optional HTTP management API — needs OpenFGA +
# Postgres + Redis + Keycloak all running (`docker compose up -d openfga
# keycloak redis postgres`) and several env vars; see `docs/control_plane.md`
# for the full setup (RBAC store creation, break-glass bootstrap, tokens)
uv run uvicorn examples.14_control_plane_api:app --reload
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

- **`union=[...]`** lets you say "editor implies viewer" — another
  relation *on the same object* that also grants this one (OpenFGA
  `computedUserset`).
- **`inherits=[...]`** is currently an alias of `union` — same shape,
  same rewrite, kept only for backward compatibility. If you're modeling
  "inherit from a *different*, parent object" (a document inheriting a
  folder's `viewer`), that's `from_parent`, not `inherits` — they're
  different OpenFGA mechanisms.
- **`from_parent=(tupleset_relation, computed_relation)`** is the real
  cross-object mechanism (OpenFGA `tupleToUserset`) — see
  `models.py`'s `Document.viewer` and
  `11_hierarchical_permissions.py`. When it's the *only* thing set on a
  relation (no explicit `subjects`), `subjects` defaults to `[]` rather
  than `["user"]`: a purely-inherited relation isn't directly assignable
  by default. Pass `subjects=["user"]` explicitly if you want both.
- **`subjects=[...]`** (default `["user"]`, or `[]` when `from_parent` is
  set with no explicit `subjects` — see above) declares who can hold the
  relation directly.

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

