# py-authz — Architecture & Modeling Backlog (Round 2)

Execution checklist for
[`05_architecture_and_modeling.md`](05_architecture_and_modeling.md). IDs
match that file.

> **Status (2026-09-02):** Tiers 0–2 shipped. `ARCH2-1` through `ARCH2-12`
> and `ARCH2-14`/`ARCH2-16`/`ARCH2-17`/`ARCH2-18` are done — `ARCH2-3`
> shipped together with `06`'s `SEC2-4`; `ARCH2-5` also covers `07`'s
> REL2-9; `ARCH2-9` also resolves `06`'s SEC2-6 and `08`'s DX2-10.
> `ARCH2-19` (Tier 4) also landed as a side effect. Only Tier 3 (the
> larger modeling-expressiveness gap, ARCH2-13) and the rest of Tier 4
> remain open.

---

## Tier 0 — Audit-trail blind spots (ship together) ✅

- [x] **ARCH2-1 — Dispatch an `AuditEvent` from the cache-hit branch of
  `enforce()`, with `cache_hit=True` correctly reflected.** Event
  construction factored into `AuthzEngine._audit_decision()`, called from
  both the cache-hit and cache-miss branches. New test
  `test_audit_logger_called_on_cache_hit`
  (`tests/core/test_enforcement_audit_and_cache.py`) confirms a
  cache-hit `enforce()` call still produces an audit record with
  `cache_hit: True`.
- [x] **ARCH2-2 — Wire audit logging and metrics into
  `grant`/`revoke`/`grant_many`/`revoke_many`.** New
  `AuthzEngine.record_write()` (metrics counter +
  `AuditEvent(reason_data={"operation": ..., "relation": ...})`), called
  once per tuple from all four `Authz` methods. New tests in
  `tests/api/test_grant_revoke.py` cover all four plus the
  no-audit-logger/no-metrics no-op case.
- [x] **ARCH2-3 — Add `cache`, `audit_logger`, `metrics`, and
  `raise_on_denied` as `MultiTenantAuthz.__init__` parameters**, forwarded
  into every `AuthzEngine` built by `for_tenant()`. **Shipped together
  with `06`'s `SEC2-4`** (cache-key tenant namespacing) as planned — each
  engine also gets `cache_namespace=store_id`, so a `cache` shared across
  tenants can't leak a decision cross-tenant. New tests in
  `tests/api/test_multi_tenant.py` cover forwarding, per-tenant
  namespacing, and the backward-compatible all-`None` default.

## Tier 1 — Failure paths that crash instead of degrading ✅

- [x] **ARCH2-4 — Give lock-acquisition timeouts an `AuthzError`
  subclass.** New `LockAcquisitionTimeout(ExternalServiceError)`, raised
  by `RedisLock.acquire()`. `RedisLockManager.lock()` gained
  `acquire_timeout`/`acquire_retry_interval` parameters. Also restructured
  `adapters/fastapi.py`'s `_enforce()` to resolve `authz` *inside* its
  try/except (previously done before it, so a resolver's own
  `ExternalServiceError` — e.g. this one, from a contended provisioning
  lock — bypassed the fail-open/fail-closed handling entirely).
- [x] **ARCH2-5 — Normalize the "expected user error" exception cluster
  to `AuthzError` subclasses.** `migrate_tenant()` → `TenantNotFoundError`;
  `get_env`/`load_module()` → `ConfigurationError`; new
  `ModelValidationError(ConfigurationError)` replaces bare `ValueError` in
  `validation/default.py`. `cli/main.py`'s `_EXIT_CODES` gained
  `(TenantNotFoundError, 3)`. All affected tests updated. **Resolves
  `07`'s REL2-9** (same fix, narrower framing there).
- [x] **ARCH2-6 — Make `authorize()`'s sync wrapper safe to call from
  inside a running event loop.** Falls back to a dedicated thread (its own
  event loop, via `concurrent.futures.ThreadPoolExecutor`) when
  `asyncio.get_running_loop()` finds one already running and
  `anyio.from_thread.run()` isn't usable. New regression test calls the
  sync-wrapped function from inside `asyncio.run(...)`.
- [x] **ARCH2-7 — Give IdP-reachability failures the same fail-open/
  fail-closed treatment as OpenFGA outages (SEC-5).** New
  `IdentityProviderUnavailable(ExternalServiceError)`, raised by
  `_resolve_jwks_url()`/`_fetch_jwks()` on any `httpx.HTTPError`;
  `KeycloakAuthMiddleware` now maps it to a 503. `OIDCJWTValidator.
  to_identity()` also now carries the full token payload as
  `Identity.attributes` (used by `06`'s SEC2-2). New tests cover
  discovery/JWKS failures and the middleware's 503.

## Tier 2 — Model sync, migrations & tenant management ✅

- [x] **ARCH2-8 — Add `OpenFGAClient.delete_store()` and call it from
  `TenantManager.provision()`** when `ModelSync.sync()`/`tenant_store.set()`
  fail after `create_store()` succeeds, closing the orphaned-store gap.
  Also made `_request()` tolerate a no-body (204) response, which
  `delete_store()` gets back.
- [x] **ARCH2-9 — Guard `MultiTenantAuthz.for_tenant()`'s cache
  population with a lock**, closing the check-then-act race that leaks
  `OpenFGAClient` connection pools under concurrent first-resolution.
  Went with one whole-critical-section lock (not per-tenant) to avoid a
  second unbounded structure. New concurrency test: 10 concurrent
  `for_tenant()` calls for the same new tenant construct exactly one
  client. **Also resolves `06`'s SEC2-6 and `08`'s DX2-10.**
- [x] **ARCH2-10 — Give `MigrationManager.migrate_all()` per-tenant
  failure isolation.** New `MigrationBatchResult(succeeded, failed)`
  return type (breaking change, `cli/commands/migrate.py` updated);
  fanned out with an `anyio.Semaphore`-bounded worker pool mirroring
  `bulk_enforce()`'s DX2-1 fix.
- [x] **ARCH2-11 — Canonicalize list order in `ModelDiffer.normalize()`**
  via a new generic `_canonicalize_lists()` (sorts every list by each
  item's own canonical JSON form). New tests cover `type_definitions`,
  `directly_related_user_types`, and `union.child` order.
- [x] **ARCH2-12 — Make `DefaultModelValidator` reject dangling relation
  references.** `detect_cycles()`'s `visit()` now checks `node not in
  relations` up front, raising `ModelValidationError` instead of silently
  treating the typo as a dead end.
- [x] **ARCH2-14 — Ship a `StoreBackedResolver(TenantStore) ->
  TenantResolver` adapter** in `core/tenant_resolver.py`; both examples'
  duplicated `_StoreBackedResolver` classes deleted in favor of it.
- [x] **ARCH2-15 — See `07`'s REL2-3** (`OpenFGAClient._request()` has no
  retry) — fixed there (shipped in Tier 1); this file's finding was a
  cross-reference only.
- [x] **ARCH2-16 — Rename `modeling/registry.py`'s `ModelRegistry`** to
  `ResourceModelRegistry`, following the ARCH-8 precedent. All internal
  references updated (breaking rename for direct importers).
- [x] **ARCH2-17 — Remove `MigrationManager`'s second "current model"
  source of truth.** New `ModelSync.last_sync_changed` attribute, set
  from `sync()`'s own real-time OpenFGA comparison; `migrate_tenant()`
  reads that instead of comparing against a separately-tracked registry
  value beforehand.
- [x] **ARCH2-18 — Add an optional `client=` constructor parameter to
  `RedisCache`, `RedisTenantStore`, and `RedisModelRegistry`**. The latter
  two also gained optional `url` (raising `ConfigurationError` if neither
  `url` nor `client` is given) and a `close()` method (needed by `07`'s
  REL2-8). `tests/cache/test_redis.py`'s fixture updated to use the
  constructor instead of reaching into `cache._client`.

## Tier 3 — Larger modeling gap (separate, larger effort)

- [ ] **ARCH2-13 — Add `intersection=[...]`/`exclude=...` support to
  `Relation` and the generator**, and consider letting `from_parent` take
  multiple `(relation, parent_relation)` pairs. Larger, standalone effort;
  sequence after Tier 0–2. `validation/default.py`'s
  `_referenced_relations()` already anticipates these shapes — verify its
  handling once the generator can actually produce them.

## Tier 4 — Low-effort cleanups (batch together)

- [x] **ARCH2-19** — delete the redundant `from py_authz.api import Authz`
  self-import in `api.py`. **Shipped 2026-09-02**, incidentally, while
  editing `for_tenant()` for `06`'s SEC2-3.
- [ ] **ARCH2-20** — add a shared `OpenFGAClient.for_tenant(...)` factory
  used by `TenantManager`, `MultiTenantAuthz`, and `MigrationManager`
  instead of three independent construction call sites.
- [ ] **ARCH2-21** — delete `core/tenant.py`'s unused `TenantContext`, or
  wire it in if it's meant to replace ad hoc `(tenant_id, store_id)` pairs.
- [ ] **ARCH2-22** — decide and implement: either `Authz.can()`'s
  `Relation` branch accepts a plain `Resource` (matching `grant`/`revoke`),
  or the asymmetry is documented explicitly.
- [ ] **ARCH2-23** — document that `Relation` instances must not be shared
  via inheritance across `ResourceModel` subclasses, or fix
  `_relation_map()` to re-bind inherited relations per subclass.

---

## Next step

Tiers 0–2 are shipped. What's left: Tier 3 (`ARCH2-13` — the larger
`intersection`/`difference`/multi-parent modeling gap, a standalone,
larger-effort item) and the rest of Tier 4 (`ARCH2-20` through
`ARCH2-23`, all small, independent cleanups safe to batch together in any
order).
