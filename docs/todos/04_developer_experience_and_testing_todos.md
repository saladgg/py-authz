# py-authz — Developer Experience & Test Coverage Backlog

Execution checklist for
[`04_developer_experience_and_testing.md`](04_developer_experience_and_testing.md).
IDs match that file.

> **Status (2026-09-01):** Tier 0 shipped (DX-9, DX-1) — and DX-9
> immediately paid for itself: running the new live suite against a real
> OpenFGA store surfaced two more previously-undiscovered bugs (a deeper
> ARCH-1 fix, and ARCH-10 — `grant`/`revoke` crashing on a `ResourceModel`
> argument), both fixed same day; see
> `01_architecture_and_modeling_todos.md`. DX-9's Postgres deferral was
> closed later, alongside REL-3/REL-4. Tier 1 shipped too (DX-2, DX-3,
> DX-5) — and implementing DX-5 surfaced a second bonus bug, filed and
> fixed as DX-10: the shipped `py-authz sync` CLI command crashed on
> every real invocation. Tier 2 (DX-4, DX-6, DX-8) is shipped as well —
> DX-8's branch-protection half needs a repo admin to flip a GitHub
> setting, see its entry below. DX-7 has no standalone work item — it's
> tracked under ARCH-4/ARCH-8 in `01_architecture_and_modeling_
> todos.md`; listed here for cross-reference only, not as a separate
> checkbox. **Nothing left open in this file** beyond that one
> admin-only setting.

---

## Tier 0 — Highest leverage ✅

- [x] **DX-9 — Add a real integration-test job against live
  OpenFGA/Keycloak/Redis, later Postgres too (2026-09-01, alongside
  REL-3/REL-4).** New
  `tests/live/` package: `conftest.py` (`requires_openfga`/
  `requires_keycloak`/`requires_redis` skip-if marks, `live_client`
  fixture creating a fresh OpenFGA store per test), `test_model_sync_live.
  py` (idempotency — the actual ARCH-1 regression test), `test_tuples_
  live.py` (grant/check/revoke round trip + `list_objects`, the actual
  ARCH-10 regression test), `test_keycloak_live.py` (real direct-grant
  token, validated end to end, plus a wrong-audience rejection test), and
  `test_redis_storage_live.py` (the actual REL-1/REL-2 regression test,
  composing `HybridTenantStore` with the real `RedisTenantStore`).
  `docker-compose.yml` gains a `redis` service (host port 6380, to avoid
  colliding with a commonly-already-running local Redis on 6379). New
  `make test-integration` target boots `openfga`/`keycloak`/`redis`,
  waits for reachability (OpenFGA `/healthz`, Keycloak's realm OIDC
  discovery endpoint — not Keycloak's own `/health/ready`, which isn't
  reachable on the port this compose file publishes), then runs
  `tests/live`. New `integration-test` job in
  `.github/workflows/ci.yml` (runs under the existing push-to-main
  trigger — gating it on pull requests too is DX-8, not done here). Every
  live test skips (not fails) when its env var isn't set, confirmed by
  running the full suite with no services up (`9 skipped`) and by
  running `make test-integration` twice end to end against a real,
  freshly-created stack (`9 passed` both times).
  **Postgres deferral closed 2026-09-01**: `docker-compose.yml` gains a
  `postgres` service (host port 5433), `tests/live/conftest.py` gains
  `requires_postgres`/`postgres_dsn`/`postgres_schema` fixtures (the last
  applies the bundled schema once and truncates after each test), and two
  new files — `test_postgres_storage_live.py`
  (`PostgresTenantStore`/`PostgresModelRegistry` round-trip, upsert,
  `list_tenant_ids`, pre-connect `ConfigurationError`) and
  `test_audit_postgres_live.py` (the REL-4 regression test — a real
  `jsonb` round trip through `asyncpg`) — confirmed passing (`6 passed`)
  against a real Postgres container. `make test-integration` now boots
  and waits on all four services.
- [x] **DX-1 — Accept async `resource_getter`/`user_getter` in the
  FastAPI adapter.** `adapters/fastapi.py` gains a `MaybeAsync[T]` type
  alias (PEP 695 generic, `T | Awaitable[T]`) and a `_resolve()` helper
  that awaits the getter's result via `inspect.isawaitable` when it's
  awaitable, otherwise returns it as-is — used in both
  `require_dependency` and `require_fastapi`. `tests/adapters/
  test_fastapi_extras.py` adds an async-getters test for the dependency
  path and a full-request (`TestClient`) test for the decorator path.

## Tier 1 — API completeness ✅

- [x] **DX-2 — Address the grant/revoke cache-staleness gap.** Shipped
  the auto-invalidate option: `Authz._invalidate_cache()` (via
  `AuthzRequest.cache_key()`) invalidates the exact granted/revoked
  (identity, relation, resource) triple in `grant`/`revoke`/`grant_many`/
  `revoke_many`, documented as deliberately not covering other relations
  implied through the model's union graph. `tests/api/test_grant_revoke.
  py` adds coverage for all four methods, a `ResourceModel`-argument
  case, a no-cache-configured no-op case, and a test confirming the
  documented scope limit (an unrelated relation's cache entry is left
  alone).
- [x] **DX-3 — Thread `context`/`contextual_tuples` through `Authz.can()`
  and `Authz.require()`.** Both gained the keyword-only parameters,
  threaded to `enforce()` unchanged. `tests/api/test_api.py` adds
  coverage for both methods forwarding `context`/`contextual_tuples`, plus
  a test confirming a contextual `can()` call still bypasses the cache.
- [x] **DX-5 — Add a multi-tenant CLI command and validate in
  `generate-model`.** New `py-authz migrate [--all-tenants | --tenant ...]
  --backend {memory,postgres,redis} --conn ...` wrapping
  `MigrationManager.migrate_all()`. Required adding
  `TenantStore.list_tenant_ids()` (previously missing entirely) to
  `InMemoryTenantStore`/`PostgresTenantStore`/`RedisTenantStore`/
  `HybridTenantStore`. `generate-model` now validates via
  `DefaultModelValidator` by default, with `--no-validate` to opt out.
  Also fixed, found while touching `MigrationManager`: a per-tenant
  `OpenFGAClient` leak (see the note under REL-7 in
  `03_reliability_and_operations.md`). **Confirmed against a real
  OpenFGA + Redis stack** — see DX-10 below, which this same validation
  pass discovered.
- [x] **DX-10 — Fix the shipped `py-authz sync` CLI command crashing on
  every real invocation.** `anyio.run(sync_command, store_id=..., ...)`
  passed keyword arguments straight to `anyio.run` itself — a call shape
  real `anyio.run(func, *args, backend=..., backend_options=...)` doesn't
  support at all. Fixed by baking every argument into a zero-arg
  `functools.partial` before calling `anyio.run`, for both `sync` and the
  new `migrate`. Rewrote `tests/cli/test_main.py`'s `fake_anyio_run` to
  mirror the real single-callable contract instead of accepting and
  forwarding kwargs (the shape that let this ship undetected).
  **Confirmed against a real OpenFGA instance**: `py-authz sync
  --store-id ... --api-url ...` now runs to completion (previously:
  `TypeError` before doing anything), and a second run reuses the same
  model id.

## Tier 2 — Polish ✅

- [x] **DX-4 — Document `list_objects` result-size behavior.** New
  "Known sharp edges" entry in `docs/architecture.md` covering OpenFGA's
  actual behavior (`--listObjectsMaxResults`/`--listObjectsDeadline`, and
  the non-deterministic partial-result risk the deadline creates with no
  in-response signal), when the call is/isn't appropriate, and the
  recommended alternative for large result sets (page your own resource
  table + `check()`/`batch_check()`, or bound the query by a smaller
  scope) — no `limit` parameter was added, since OpenFGA's API exposes no
  cursor to build one on top of.
- [x] **DX-6 — Add top-level CLI error handling.** `cli/main.py` wraps
  dispatch in `try/except AuthzError`, printing `Error: {message}` to
  stderr and exiting with a code by failure class:
  `ConfigurationError` → 2, `InvalidAuthzRequest` → 3,
  `ExternalServiceError` (incl. subclasses) → 4, any other `AuthzError` →
  1. A non-`AuthzError` exception is left uncaught and still shows its
  full traceback. `tests/cli/test_main.py` adds a parametrized test over
  all four codes plus one confirming non-`AuthzError` exceptions still
  propagate. **Confirmed live**: `py-authz sync` against an unreachable
  OpenFGA host now prints a one-line `Error: ...` and exits `4`, not a
  raw traceback.
- [x] **DX-8 — Gate CI on pull requests; resolve the Python-version
  classifier mismatch.** `.github/workflows/ci.yml` now also triggers on
  `pull_request: branches: [main]`. The false
  `Programming Language :: Python :: 3.12` classifier is removed from
  `pyproject.toml` (`requires-python = ">=3.13"` already makes 3.12
  impossible). **Branch-protecting `main` on these checks is not
  done** — that's a GitHub repository setting a repo admin must enable
  under Settings → Branches, not something this audit's file changes can
  configure.

---

## Next step

Every tier in this file is shipped. DX-8's branch-protection half still
needs a repo admin to flip a GitHub setting (see its entry above) —
that's the only thing left open anywhere in this backlog.
