# py-authz — Reliability, Storage & Release Operations Backlog

Execution checklist for
[`03_reliability_and_operations.md`](03_reliability_and_operations.md).
IDs match that file.

> **Status (2026-09-01):** Tier 0 shipped (REL-1, REL-2), plus a related
> third bug in `HybridTenantStore.get()` itself that REL-2's fix surfaced
> (see the findings doc). All three confirmed against a real Redis
> instance via `tests/live/test_redis_storage_live.py` (DX-9, see
> `04_developer_experience_and_testing_todos.md`), not just mocks. Tier 1
> shipped too (REL-5, REL-6), both confirmed against a real Redis instance
> via `tests/live/test_locks_live.py`. Tier 2 (REL-3, REL-4) is shipped as
> well, confirmed against a real Postgres instance via
> `tests/live/test_postgres_storage_live.py` and
> `tests/live/test_audit_postgres_live.py`. Tier 3 (REL-7, REL-8) is
> shipped too — REL-8 confirmed against a real OpenFGA instance via a new
> live test. Tier 4 (REL-9) is shipped from the repo's side (a
> `publish-pypi` workflow job, OIDC trusted publishing) — the only thing
> left open in this entire backlog is external: a PyPI project owner must
> register this repo as a trusted publisher before it can actually
> succeed.

---

## Tier 0 — Shipped components that were never tested together (fast wins) ✅

- [x] **REL-1 — Fix the `HybridTenantStore` / `RedisTenantStore` signature
  mismatch.** `RedisTenantStore.set`/`RedisModelRegistry.set` gained an
  `ex: int | None = None` parameter, forwarded to the underlying client.
  `tests/storage/test_redis_storage.py` adds tests asserting the `ex`
  kwarg is accepted and forwarded. `tests/storage/test_hybrid.py` adds
  `test_hybrid_store_composes_with_real_redis_tenant_store`, which
  constructs `HybridTenantStore` from the *actual* `RedisTenantStore`
  class (via a `redis-py`-shaped fake client) instead of a bespoke
  Hybrid-only double — this is the composition that was broken.
  **Confirmed against a real Redis** in
  `tests/live/test_redis_storage_live.py::
  test_hybrid_store_composes_with_real_redis_tenant_store`.
- [x] **REL-2 — Decode Redis bytes in `RedisTenantStore.get` /
  `RedisModelRegistry.get`.** Both now decode bytes to `str` (matching
  `cache/redis.py`'s existing correct pattern), tolerating a plain `str`
  too (for test doubles). `tests/storage/test_redis_storage.py`'s
  `FakeAsyncRedis` now byte-encodes on `set()`, so it actually mimics
  real `redis-py` and would catch this class of bug in the future.
  **Also required fixing `HybridTenantStore.get()`** (see the findings
  doc's note under REL-2): it previously called `.decode()` on whatever
  `redis_store.get()` returned, which only worked for a raw bytes-
  returning client — now that `RedisTenantStore.get()` returns an
  already-decoded `str`, `HybridTenantStore` no longer calls `.decode()`
  itself, and its docstring now states the `TenantStore`-shaped contract
  both constructor arguments are expected to satisfy.
  `tests/storage/test_hybrid.py`'s `InMemoryRedis` double updated to
  match (decode-on-get, not raw-bytes-on-get) since it was mimicking the
  wrong thing (a raw client) for what `HybridTenantStore` actually
  composes with (a `TenantStore`-shaped wrapper).

## Tier 1 — Provisioning critical-section correctness ✅

- [x] **REL-5 — Stop `TenantManager.provision()` masking its own
  exception.** `store_id` is now initialized to `None` before the `try`;
  the `finally`/log path no longer references it before it's assigned.
  Failures now log via `logger.exception(...)` and re-raise the real
  exception instead of risking `UnboundLocalError`.
  `tests/core/test_tenant_manager.py` adds the missing test using
  `FakeOpenFGAClient.create_store_error` (via a monkeypatched
  `create_store` that raises before `store_id` would ever be assigned).
- [x] **REL-6 — Add lock renewal to provisioning locks.**
  `RedisLockManager.lock()` now runs a background renewal loop
  (`renew_interval`, default `ttl / 3`) for the duration of the `async
  with` body, via a new `RedisLock.renew()` (compare-and-`EXPIRE`,
  mirroring `release`'s compare-and-`DEL`). Renewal failure (lock already
  lost) logs a warning and stops quietly rather than raising into the
  running critical section — documented as advisory, not a hard
  cancellation mechanism. `tests/core/test_locks.py` adds renewal
  coverage (extends TTL only when still owned, survives a lost lock
  without crashing, keeps a key alive past its initial TTL). **Confirmed
  against a real Redis** in new `tests/live/test_locks_live.py`
  (acquire/release/renew round trips, and the actual scenario this fixes:
  a critical section sleeping past the lock's initial TTL, with the key
  confirmed still present via `EXISTS` throughout).

## Tier 2 — Production-readiness for the Postgres backends ✅

- [x] **REL-3 — Give the Postgres-backed stores real connection
  lifecycle + shipped schema.** `PostgresTenantStore`,
  `PostgresModelRegistry` (`storage/postgres.py`), and
  `PostgresAuditLogger` (`audit/postgres.py`) all gained: idempotent
  `connect()`, `close()` (no-op if never connected), `__aenter__`/
  `__aexit__` for `async with Cls(dsn) as store: ...`, and a
  `_require_pool()` guard raising `ConfigurationError` with an actionable
  message instead of a bare `AttributeError` on first use before
  connecting. DDL shipped as three versioned, idempotent SQL files
  (`storage/sql/0001_tenants.sql`, `0002_tenant_models.sql`,
  `0003_audit_logs.sql` — the last one entirely new, `audit_logs` had no
  DDL anywhere before this) applied via new
  `storage/schema.py:apply_schema(dsn)`. Bundling the `.sql` files into
  the wheel needed an explicit `[tool.setuptools.package-data]` entry in
  `pyproject.toml` (this repo has no `MANIFEST.in`); verified by actually
  building a wheel and inspecting its contents for the three files.
  `tests/storage/test_postgres.py` adds a parametrized
  `TestConnectionLifecycle` class (both store classes share the contract)
  plus `tests/storage/test_schema.py` for `apply_schema()`. New
  `docker-compose.yml` `postgres` service (host port 5433, avoiding a
  locally-installed Postgres on 5432) and `tests/live/test_postgres_storage_live.py`
  confirmed the whole lifecycle + upsert + `list_tenant_ids` +
  pre-connect `ConfigurationError` against a real Postgres container.
- [x] **REL-4 — Fix `reason_data` serialization in
  `PostgresAuditLogger.log()`.** Now does
  `reason_data = None if event.reason_data is None else
  json.dumps(event.reason_data)` before binding — `None` stays `None`,
  everything else becomes JSON text the `jsonb` column accepts.
  `tests/audit/test_postgres.py` updated (the `reason_data` assertion now
  expects the JSON string, not the raw dict) plus a new
  `test_log_preserves_none_reason_data`. **Confirmed against a real
  Postgres** in new `tests/live/test_audit_postgres_live.py`: writes a
  real `AuditEvent` with a non-trivial `reason_data` dict through a real
  `asyncpg` connection, reads the row back, and asserts the `jsonb`
  column round-trips to the original dict — the pre-fix code raised
  `asyncpg.exceptions.DataError` on this exact write.

## Tier 3 — Multi-tenant + OpenFGA-client hardening ✅

- [x] **REL-7 — Add lifecycle management to `MultiTenantAuthz`.** New
  `Authz.aclose()` releases the underlying `OpenFGAClient`'s connection
  pool (duck-typed via `hasattr(fga_client, "aclose")`, tolerating a
  caller-supplied client without one). New `MultiTenantAuthz.aclose()`
  calls it across every cached tenant and clears `self._cache`. No
  LRU/TTL eviction was added — the class's docstring instead documents
  the unbounded cache as intentional for a small, fixed tenant count,
  with concrete guidance for deployments outside that shape.
  `examples/12_multitenant_fastapi.py`'s `lifespan` now calls
  `mt.aclose()` on shutdown, demonstrating the wiring.
  `tests/api/test_multi_tenant.py` adds coverage: closing every cached
  client, a no-op on an empty cache, `Authz.aclose()` closing its own
  client, and tolerating a client with no `aclose()` at all.
- [x] **REL-8 — Chunk `write_tuples()` writes/deletes to OpenFGA's
  100-item limit.** `OpenFGAClient.write_tuples()` now batches `writes`/
  `deletes` into groups of at most 100 combined operations, issuing one
  sequential `Write` request per batch; the existing single-request
  behavior (including the empty-payload case) is unchanged when
  everything already fits in one batch. Documented as non-atomic across
  batches. `tests/clients/test_write_tuples.py` adds tests for the exact
  boundary (100 in one request, 101 in two) and a 120-combined-operation
  case. **Confirmed against a real OpenFGA instance**: new
  `tests/live/test_tuples_live.py::test_grant_many_over_100_tuples_is_chunked_against_real_openfga`
  grants 120 tuples via `grant_many()` and confirms every one is
  queryable — the pre-fix code raised `ExternalServiceError` from
  OpenFGA's real 400 response on this exact call.

## Tier 4 — Release process ✅ (code side — one external step remains)

- [x] **REL-9 — Publish to PyPI (or fix every install instruction until
  it's published).** `.github/workflows/release.yml` gained a
  `publish-pypi` job, gated on the `release` job actually cutting a new
  tag (detected via a before/after `git describe --tags` comparison,
  since semantic-release's plain CLI gives no simpler signal), that
  downloads the `dist/` artifact and uploads it to PyPI via
  `pypa/gh-action-pypi-publish` with OIDC trusted publishing — no
  long-lived API token. **Discovered while shipping this: the repository
  is currently private** (`gh repo view` → `isPrivate: true`), which
  means the originally-suggested interim fix ("point install instructions
  at the GitHub-release wheel URL") doesn't work either — confirmed by
  actually requesting one and getting a 404, since a private repo's
  release assets aren't anonymously downloadable. `README.md`'s
  Installation section and the `Makefile`'s `install-*` targets now say
  PyPI isn't available yet and give the command that actually works for
  someone with repo access:
  `pip install "py-authz[...] @ git+https://github.com/saladgg/py-authz.git@vX.Y.Z"`.
  **Not done, and outside this audit's reach**: trusted publishing needs
  a PyPI project owner to register this repo/workflow/environment as a
  trusted publisher on PyPI's side (and create the `py-authz` project
  there, or use its "pending publisher" flow, if it doesn't exist yet).
  Until that one-time setup happens, `publish-pypi` will run on the next
  real release and fail with an auth error at the publish step — expected,
  and self-resolving once the trusted publisher is registered, with no
  further code changes needed here.

---

## Next step

Every tier in this backlog is shipped from the repository's side. The one
thing left open anywhere in this file is external: a PyPI project owner
needs to register this repo as a trusted publisher before `publish-pypi`
can actually succeed (see REL-9's entry above).
