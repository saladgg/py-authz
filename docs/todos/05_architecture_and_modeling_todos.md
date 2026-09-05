# py-authz — Architecture & Modeling Backlog (Round 2)

Execution checklist for
[`05_architecture_and_modeling.md`](05_architecture_and_modeling.md). IDs
match that file.

> **Status (2026-09-05):** All tiers shipped — this backlog is fully
> closed. `ARCH2-1` through `ARCH2-12` and `ARCH2-14`/`ARCH2-16`/
> `ARCH2-17`/`ARCH2-18` are done — `ARCH2-3` shipped together with `06`'s
> `SEC2-4`; `ARCH2-5` also covers `07`'s REL2-9; `ARCH2-9` also resolves
> `06`'s SEC2-6 and `08`'s DX2-10. `ARCH2-19` through `ARCH2-23` (all of
> Tier 4) are done. `ARCH2-13` (Tier 3, the larger modeling-expressiveness
> gap) shipped last, same day, confirmed against a real OpenFGA server.

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

## Tier 3 — Larger modeling gap (separate, larger effort) ✅

- [x] **ARCH2-13 — Add `intersection=[...]`/`exclude=...` support to
  `Relation` and the generator**, and consider letting `from_parent` take
  multiple `(relation, parent_relation)` pairs. **Shipped 2026-09-05.**
  `Relation` gained `intersection: list[str] | None` (≥2 relation names,
  ANDed — OpenFGA's `intersection` rewrite) and `exclude: str | None`
  (OpenFGA's `difference` rewrite: "this relation-def, minus `exclude`").
  Design choices:
    - `intersection` **composes** with `this`/`union`/`inherits`/
      `from_parent` — it becomes just another child ORed alongside them
      in the emitted `union` (mirroring OpenFGA's own grammar, where
      `intersection` can itself be a child of `union`), not a full
      replacement. Requires at least 2 relation names or
      `_build_relation()` raises `ModelValidationError` at generation
      time (an "AND" of fewer than 2 is meaningless).
    - `exclude` is genuinely a two-operand `difference` (`base`/
      `subtract`), so unlike `intersection` it wraps the *entire* rewrite
      built from everything else rather than being one more `union`
      child — `exclude="banned"` reads as "this relation, minus banned"
      at the call site. Raises `ModelValidationError` at generation time
      for: excluding a relation with no base to subtract from, excluding
      the relation itself, or excluding a relation also named in that
      same relation's `union`/`inherits`/`intersection` (contradictory:
      both included and excluded).
    - `from_parent: tuple[str, str] | list[tuple[str, str]] | None` — now
      also accepts a list of `(tupleset_relation, computed_relation)`
      pairs, each becoming its own `tupleToUserset` child ORed together
      (e.g. "viewer via parent folder OR via parent workspace"). The
      single-tuple call sites (all pre-existing models/examples/tests)
      keep working unchanged — a new `from_parent_pairs()` helper in
      `modeling/base.py` normalizes both shapes, shared by the generator
      and by `testkit.InMemoryFGAClient` (updated to evaluate
      `intersection`/`exclude`/multi-`from_parent` identically to the
      real generator, so fake-backed unit tests stay trustworthy).
    - Found and fixed a real, adjacent bug while wiring this up:
      `DefaultModelValidator.validate()`'s basic rewrite-shape check
      didn't recognize a bare top-level `intersection`/`difference` key
      as valid — it would have rejected the generator's own new output
      as "no valid rewrite". Fixed alongside.
    - `validation/default.py`'s `_referenced_relations()`/`detect_cycles()`
      (added for ARCH-3/ARCH2-12, previously dead code for these shapes)
      is now exercised by real generator output — new tests in
      `tests/validation/test_default.py` build actual
      `intersection`/`difference`/multi-`from_parent` models via
      `OpenFGAModelGenerator` and confirm a cycle reachable only through
      each new branch is still detected, and that a realistic acyclic
      model using all three passes full validation end to end.
    - No new `examples/` file — the todo's core ask (modeling support +
      validator correctness) is covered by the unit/live tests;
      `examples/11_hierarchical_permissions.py` remains the reference
      example for `from_parent`, and adding a second example for the
      newer features didn't seem to add enough beyond the tests to
      justify the scope.
    - **Confirmed against a real OpenFGA server** (`docker compose up -d
      openfga`, `v1.19.0`, same as ARCH-2's precedent): new
      `tests/live/test_intersection_exclude_live.py` builds a
      `Document` model using all three features together (`intersection`
      of `editor`+`verified`, `exclude` of `banned` from `safe_viewer`,
      and `viewer` reachable via either a parent folder or parent
      workspace), syncs it to a real store via `ModelSync`, and passes 5
      live `check()`-backed assertions: intersection denies with only one
      side held and allows with both; a plain grant is allowed and then
      denied once also `banned`; and a subject is allowed via either
      parent relation but denied via neither. All 5 passed.

## Tier 4 — Low-effort cleanups (batch together) ✅

- [x] **ARCH2-19** — delete the redundant `from py_authz.api import Authz`
  self-import in `api.py`. **Shipped 2026-09-02**, incidentally, while
  editing `for_tenant()` for `06`'s SEC2-3.
- [x] **ARCH2-20** — add a shared `OpenFGAClient.for_tenant(...)` factory
  used by `TenantManager`, `MultiTenantAuthz`, and `MigrationManager`
  instead of three independent construction call sites. New
  `OpenFGAClient.for_tenant(...)` classmethod (covers `api_url`/
  `store_id`/`model_id`/`timeout`/`max_retries`/`http_client` — the full
  constructor surface) replaces all three (four, counting
  `MigrationManager.dry_run_tenant()`) hand-built call sites. New tests
  in `tests/clients/test_openfga.py` confirm it builds an equivalent
  client; existing call-site tests' fakes gained a matching `for_tenant`
  classmethod.
- [x] **ARCH2-21** — delete `core/tenant.py`'s unused `TenantContext`, or
  wire it in if it's meant to replace ad hoc `(tenant_id, store_id)` pairs.
  **Deleted** — confirmed genuinely dead (referenced nowhere but its own
  standalone test, which was deleted alongside it); no single call site
  anywhere in the codebase passes a `(tenant_id, store_id)` pair together
  as a unit, so there was no clean integration point to wire it into.
- [x] **ARCH2-22** — decide and implement: either `Authz.can()`'s
  `Relation` branch accepts a plain `Resource` (matching `grant`/`revoke`),
  or the asymmetry is documented explicitly. **Unified**, not just
  documented — `can()`'s `Relation` branch now accepts a plain `Resource`
  too, whose `.type` is checked against `relation.resource_cls.type`
  (raising `TypeError` on a mismatch; an unbound `Relation` can't check,
  so any `Resource` passes through, matching `list_objects()`'s existing
  handling of unbound relations). New tests in
  `tests/api/test_relation_api.py` cover the matching-type accept,
  mismatched-type reject, and unbound-relation pass-through cases.
- [x] **ARCH2-23** — document that `Relation` instances must not be shared
  via inheritance across `ResourceModel` subclasses, or fix
  `_relation_map()` to re-bind inherited relations per subclass. **Fixed**
  (real bug, not docs-only): confirmed a `Relation` inherited without
  being redeclared is the literal same object across every subclass that
  inherits it, so `.resource_cls` stays pinned to whichever class the
  metaclass bound first — the actual fix landed in
  `ResourceModelMeta.__new__` (not `_relation_map()` itself, which never
  reads `.resource_cls`) since that's where binding happens: it now gives
  every subclass an independent copy of each inherited `Relation`, bound
  to that subclass. New tests in `tests/modeling/test_base.py` cover two
  sibling subclasses of a shared base each getting distinct,
  correctly-bound copies.

---

## Next step

All tiers (0–4) are shipped, `ARCH2-13` (Tier 3) last, on 2026-09-05. This
backlog is fully closed — nothing left to sequence here.
