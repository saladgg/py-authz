# py-authz — Architecture & Modeling Audit (Round 2)

**Date:** 2026-09-02 · repo as of `audit2` (post-1.3.0, after all of `01`–`04`
shipped).
**Scope:** core layering (`api.py`, `core/enforcement.py`, `core/types.py`,
`core/context.py`), tenant management (`core/tenant*.py`), the declarative
modeling layer (`modeling/*`, `validation/default.py`), model sync/diff
(`core/model_sync.py`, `model_diff.py`, `model_registry.py`), migrations
(`core/migrations_manager.py`), locks (`core/locks.py`), adapters, and the
config/metrics/retry scaffolding.
**Method:** read `docs/todos/01_architecture_and_modeling*.md` in full
first to confirm ARCH-1…10 are genuinely shipped in the current tree (they
are), then re-audited the same surfaces for defects that survived or were
introduced by that remediation. Nothing below re-files an `01` finding.

This is the second audit filed against this repository's architecture and
modeling layer. No 🔴 CRITICAL issues were found in this pass — the
CRITICAL-shaped bugs from the first audit (broken sync, undetected cycles)
are gone and stayed gone.

A recurring theme: the exception-hierarchy discipline `01`/`02` established
(raise an `AuthzError` subclass, never a bare built-in) wasn't applied
uniformly to sibling code shipped the same day (`ARCH2-5`), and `01`'s
`tupleToUserset` fix (ARCH-2) leaves a same-shaped scope gap for
`intersection`/`difference` that the validator already anticipates but the
generator still can't produce (`ARCH2-13`). Separately, `MultiTenantAuthz`
has fallen behind single-tenant `Authz` in three independent ways — no
cache/audit/metrics wiring, a construction race, and a missing
resolver/store adapter (`ARCH2-3`, `ARCH2-9`, `ARCH2-14`).

---

## Audit logging has two hard, silent blind spots

### 🟠 HIGH

**ARCH2-1. Cache hits are never audit-logged, and the audit event's own
`cache_hit` field is permanently dead.** `AuthzEngine.enforce()`
(`core/enforcement.py:147-176`) returns early on a cache hit — before ever
reaching the `if self.audit_logger:` block at line 224, which only runs on
the non-cache-hit path (177-241). That block's own
`reason_data={"cache_hit": cache_hit, ...}` (line 235) is consequently
always `False` in the only place it's ever recorded, since the branch
where `cache_hit` is `True` never reaches it. SEC-3 hardened audit logging
specifically so it could be relied on as a compliance trail; once a
`(user, relation, resource)` decision is cached, every subsequent real
access decision within the TTL produces **zero** audit records — a
systemic gap for any deployment running caching and audit logging
together, which the docs present as a normal combination.
→ Dispatch an `AuditEvent` from the cache-hit branch too, with
`cache_hit=True` correctly reflected; factor event construction into one
helper called from both branches. **Effort: S.**
*(No test covers this: `tests/core/test_enforcement_audit_and_cache.py`'s
audit test runs with `cache=None`, so it actually locks in the dead
`cache_hit: False` value rather than catching the bug.)*
→ **Shipped 2026-09-02.** New `AuthzEngine._audit_decision()` helper is
called from both the cache-hit and live-check branches of `enforce()`.
New test `test_audit_logger_called_on_cache_hit`
(`tests/core/test_enforcement_audit_and_cache.py`) asserts two audit
events across two `enforce()` calls for the same request, the second with
`reason_data == {"cache_hit": True, ...}`.

**ARCH2-2. `Authz.grant`/`revoke`/`grant_many`/`revoke_many` bypass audit
logging and metrics entirely.** These four methods (`api.py:284-368`) call
`self._engine.fga_client.write_tuples(...)` directly, never through
`AuthzEngine.enforce()` — the only place an `AuditEvent`/metrics increment
is ever produced. The highest-value events for an audit trail — who
granted or revoked a permission — are never recorded via the documented
`Authz` API, and `docs/architecture.md`'s audit-logging section only
discusses `enforce()`, so the gap is invisible until someone goes looking
for a permission-change record that was never written.
→ Have `grant`/`revoke`/`grant_many`/`revoke_many` (or a new
`AuthzEngine` method they delegate to, instead of touching `fga_client`
directly) dispatch an `AuditEvent`/metrics increment the same way
`enforce()` does. **Effort: M.** *(No test covers this —
`tests/api/test_grant_revoke.py` has no `audit`/`metrics` reference at
all.)*
→ **Shipped 2026-09-02.** New `AuthzEngine.record_write()` records a
metrics counter (`authz_grant_total`/`authz_revoke_total`) and dispatches
an `AuditEvent` (`reason_data={"operation": ..., "relation": ...}`,
`allowed=True`); `Authz.grant`/`revoke`/`grant_many`/`revoke_many` call it
once per tuple written. New tests in `tests/api/test_grant_revoke.py`
cover all four methods plus the no-audit-logger/no-metrics no-op case.

**ARCH2-3. `MultiTenantAuthz` never wires `cache`, `audit_logger`, or
`metrics` into any tenant's engine.** `MultiTenantAuthz.__init__`
(`api.py:413-424`) takes only `api_url`, `model_id`, `tenant_resolver`,
`tenant_manager`; `for_tenant()` (`api.py:460-466`) constructs
`AuthzEngine(fga_client=client)` with every other constructor argument
left at its default. Every capability the first audit shipped — resilient
audit logging (SEC-3), decision metrics (ARCH-6) — is available to a
hand-built single-tenant `Authz(AuthzEngine(...))` and categorically
unavailable through the library's other flagship feature: multi-tenancy
gets zero caching, zero audit trail, and zero metrics for every tenant,
silently, with no parameter to fix it.
→ Add `cache`, `audit_logger`, `metrics` (and `raise_on_denied`) as
`MultiTenantAuthz.__init__` parameters, forwarded into every `AuthzEngine`
it builds. **Effort: S.** *(Confirmed absent: no test in
`tests/api/test_multi_tenant.py` passes any of these.)*
→ **Shipped 2026-09-02, together with `06`'s SEC2-4 as planned.**
`MultiTenantAuthz.__init__` now accepts `cache`, `audit_logger`,
`metrics`, `raise_on_denied`, forwarded into every `AuthzEngine`
`for_tenant()` builds — and each engine is also given
`cache_namespace=store_id` (SEC2-4's fix, pulled forward here since it's
a hard prerequisite for safely wiring a shared `cache` at all), so a
`cache` shared across tenants can never leak a decision cross-tenant. New
tests in `tests/api/test_multi_tenant.py` cover the forwarding, the
per-tenant namespace, and the backward-compatible all-`None` default; a
new engine-level test in `tests/core/test_enforcement_audit_and_cache.py`
(`test_cache_namespace_isolates_engines_sharing_one_cache_backend`)
proves two engines sharing one cache backend but different namespaces
never read back each other's decisions.

---

## Failure paths that still crash instead of degrading

### 🟠 HIGH

**ARCH2-4. Lock-acquisition timeout is a bare `TimeoutError` — invisible
to both the FastAPI fail-open/fail-closed contract and the CLI's error
handling.** `RedisLock.acquire()` (`core/locks.py:59`) raises
`TimeoutError(f"Failed to acquire lock: {key}")` on timeout (default 5s,
not exposed as a configurable parameter by `RedisLockManager.lock()`).
`adapters/fastapi.py`'s `_enforce()` helper (SEC-5's fix) catches only
`ExternalServiceError`; `cli/main.py`'s top-level handler (DX-6's fix)
catches only `AuthzError`. `TimeoutError` is a bare built-in and satisfies
neither. A lock-acquisition timeout during per-request tenant resolution
(`MultiTenantAuthz.for_tenant()` → `TenantManager.provision()`) under
load — exactly the scenario REL-6 was about — surfaces as an unhandled
500 through FastAPI instead of the documented 503, and as a raw traceback
through the CLI instead of a categorized exit code.
→ Wrap it in a dedicated `AuthzError` subclass (e.g.
`LockAcquisitionTimeout(ExternalServiceError)`), or have
`TenantManager.provision()` catch and re-raise it as one; expose
`timeout`/`retry_interval` through `RedisLockManager.lock()`.
**Effort: S.** *(`tests/core/test_locks.py::test_acquire_times_out_when_key_held`
confirms the raw `TimeoutError` but nothing traces it through
`TenantManager`, the FastAPI adapter, or the CLI.)*
→ **Shipped 2026-09-02.** New `LockAcquisitionTimeout(ExternalServiceError)`
raised by `RedisLock.acquire()` instead of a bare `TimeoutError`;
`RedisLockManager.lock()` gained `acquire_timeout`/`acquire_retry_interval`
parameters forwarded to it. `adapters/fastapi.py`'s `_enforce()` was also
restructured to resolve `authz` (where a `MultiTenantAuthz` resolver's
`for_tenant()` → `TenantManager.provision()` call lives) *inside* its
try/except, not before it — so this failure (and any other
`ExternalServiceError`) reaching tenant resolution now actually gets the
documented 503/fail-open treatment instead of bypassing it entirely.

**ARCH2-5. A cluster of "expected user error" paths raise non-`AuthzError`
exceptions — the exact DX-6 failure class DX-6 shipped to fix, reintroduced
in sibling code the first audit didn't reach.**
- `core/migrations_manager.py:53` — `raise ValueError(f"Tenant not found:
  {tenant_id}")` for `py-authz migrate --tenant <typo>`, despite
  `TenantNotFoundError(AuthzError)` (`core/exceptions.py:162-179`) existing
  for exactly this condition and already used correctly by
  `core/tenant_resolver.py`.
- `cli/config.py:7-8` — `get_env(..., required=True)` raises a bare
  `RuntimeError` for a missing env var; used by both `sync_command` and
  `migrate_command` for `FGA_STORE_ID`/`FGA_API_URL`/`TENANT_STORE_CONN` —
  the single most likely first-run CLI mistake.
- `cli/utils.py`'s `load_module()` raises a bare `RuntimeError` for a bad
  `--module` path.
- `validation/default.py` raises a bare `ValueError` for a malformed/cyclic
  model — now reachable directly from `generate-model`'s default-on
  validation (DX-5).

`cli/main.py`'s `except AuthzError as exc:` is the *only* exception
handler wrapping CLI dispatch — none of the above are caught by it, so
each still produces a raw Python traceback and undifferentiated exit code
1 for what is, in every case, an anticipated user mistake, not a bug.
→ Raise `TenantNotFoundError` in `migrate_tenant()`; make `get_env`'s
failure and `load_module()`'s failure `ConfigurationError`; wrap/translate
the validator's `ValueError` into an `AuthzError` subtype in
`generate_command`/`main()`. **Effort: S.** *(Actively locked in as
current behavior by `tests/core/test_migrations_manager.py:54`
(`pytest.raises(ValueError, ...)`), `tests/cli/test_config.py:21`
(`pytest.raises(RuntimeError, ...)`), and
`tests/cli/test_generate_command.py:59-60` — none drive these through the
actual CLI entry point.)*
→ **Shipped 2026-09-02.** `migrate_tenant()` now raises
`TenantNotFoundError`; `get_env(required=True)`'s and `load_module()`'s
failures now raise `ConfigurationError`; `validation/default.py`'s
validator and `detect_cycles()` now raise the new
`ModelValidationError(ConfigurationError)` instead of bare `ValueError`.
`cli/main.py`'s `_EXIT_CODES` also gained an explicit
`(TenantNotFoundError, 3)` entry. All affected tests updated to expect
the new `AuthzError` subclasses (this is a breaking change for anyone
catching the old bare `ValueError`/`RuntimeError` types directly).

**ARCH2-6. `modeling.decorators.authorize()`'s sync wrapper crashes when
called from inside an already-running event loop.**
`modeling/decorators.py:57-65`:
```python
try:
    allowed = anyio.from_thread.run(_check)
except RuntimeError:
    allowed = anyio.run(_check)
```
`anyio.from_thread.run()` only works from an anyio worker thread, so it
raises `RuntimeError` in the ordinary (non-worker-thread) case; the
fallback `anyio.run()` (→ `asyncio.run()`) itself raises a *second*
`RuntimeError` ("Already running asyncio in this thread") if the
sync-decorated function is invoked from code already executing inside a
running loop on that thread — reproduced directly. `authorize()` is
documented to support async and sync functions interchangeably; this is a
real footgun for the mixed sync/async style the library otherwise
markets, with no graceful degradation, just a crash.
→ Detect a running loop via `asyncio.get_running_loop()` and, if present,
hop to a helper thread (e.g. `asyncio.run_coroutine_threadsafe`) instead
of calling `anyio.run()` directly; or explicitly document/guard against
calling the sync form from inside an active loop. **Effort: S.**
*(`tests/modeling/test_decorators.py`/`test_decorators_extended.py` only
call the sync wrapper from top-level, no-loop-running code.)*
→ **Shipped 2026-09-02.** When `anyio.from_thread.run()` fails (not in an
anyio worker thread) and a loop is already running on the current thread,
the check now runs on a dedicated thread with its own event loop
(`concurrent.futures.ThreadPoolExecutor`) instead of calling `anyio.run()`
directly. New test
`test_sync_decorator_works_when_called_from_inside_a_running_event_loop`
confirms a sync-wrapped handler called from inside `asyncio.run(...)` no
longer crashes.

**ARCH2-7. An unreachable identity provider crashes every authenticated
request instead of a clean 401/503.** `OIDCJWTValidator.validate()`
(`adapters/oidc.py:140-183`) only catches `jwt.ExpiredSignatureError`/
`InvalidAudienceError`/`InvalidTokenError`. `_resolve_jwks_url()`/
`_fetch_jwks()` make raw `httpx.AsyncClient().get(...)` calls with no
exception handling — a `ConnectError`/`TimeoutException`/`HTTPStatusError`
(IdP down, DNS failure, 5xx) propagates straight out.
`KeycloakAuthMiddleware.dispatch()` (`adapters/keycloak_fastapi.py:31-41`)
only catches `AuthenticationError`, so the raw `httpx` exception escapes
the middleware too — every request carrying a `Bearer` token gets an
unhandled 500 for as long as the IdP is unreachable. This is the same "a
dependency's failure shouldn't halt the core decision" pattern SEC-1/SEC-5
fixed for OpenFGA and Keycloak key rotation, left unaddressed for the
IdP's own reachability, with no `ExternalServiceError`-equivalent on the
auth path at all — so there's no way to even choose fail-open/fail-closed
here.
→ Wrap the discovery/JWKS HTTP calls in a try/except mapping to
`AuthenticationError` or a new `IdentityProviderUnavailable`-style
exception; have the middleware translate it to 503, mirroring
`adapters/fastapi.py`'s handling of `ExternalServiceError`. **Effort:
S–M.** *(No test exercises a failing HTTP call in either
`test_oidc.py` or `test_keycloak.py` — only bad-token outcomes.)*
→ **Shipped 2026-09-02.** New `IdentityProviderUnavailable
(ExternalServiceError)`, raised by `_resolve_jwks_url()`/`_fetch_jwks()`
on any `httpx.HTTPError` (network error, timeout, or non-2xx discovery/
JWKS response). `KeycloakAuthMiddleware.dispatch()` now also catches
`ExternalServiceError` and raises a 503 ("Identity provider unavailable"),
alongside its existing 401 for `AuthenticationError`. As a related,
useful side effect, `OIDCJWTValidator.to_identity()` now carries the full
decoded token payload as `Identity.attributes` — this is what `06`'s
SEC2-2 fix (`tenant_from_verified_claim`) reads from. New tests cover
discovery/JWKS network failures, an HTTP-status failure, and the
middleware's 503.

---

## Model sync, migrations & tenant management

### 🟡 MEDIUM

**ARCH2-8. `TenantManager.provision()` leaks an orphaned OpenFGA store on
partial failure, and there's no client primitive to clean it up.**
`core/tenant_manager.py:63-78` — if `ModelSync.sync()` or
`tenant_store.set()` raises after `create_store()` succeeds, the store
mapping is correctly left unpersisted, but the real OpenFGA store created
moments earlier is never deleted, and `clients/openfga.py` has no
`delete_store()` method at all.
→ Add `OpenFGAClient.delete_store()` and call it on post-`create_store()`
failure, or document the orphan risk for periodic reconciliation.
**Effort: M.** *(`tests/core/test_tenant_manager.py`'s
`test_provision_closes_client_when_sync_raises`/
`test_provision_propagates_and_closes_client_when_create_store_raises`
assert client cleanup but nothing about the orphaned store.)*
→ **Shipped 2026-09-02.** New `OpenFGAClient.delete_store()`
(`DELETE /stores/{id}`, tolerating the empty-body 204 response
`_request()` previously choked on when parsed as JSON — fixed in the same
pass). `TenantManager.provision()` now calls it in its `except` block
whenever `store_id` was assigned before the failure, best-effort (a
cleanup failure logs and doesn't mask the original exception). New tests
cover the cleanup call, cleanup-failure-doesn't-mask-original-exception,
and `delete_store()` itself tolerating a no-body response.

**ARCH2-9. `MultiTenantAuthz.for_tenant()` has a check-then-act cache race
that silently leaks an `OpenFGAClient` per concurrent first resolution.**
`api.py:440-441` — `if tenant_id in self._cache: return
self._cache[tenant_id]` is unguarded. Two concurrent `for_tenant("new
-tenant")` calls (normal under load, and exactly the shape ARCH-4 wired
up) can both miss the cache and each construct a fresh `OpenFGAClient`;
whichever write to `self._cache[tenant_id]` loses is silently discarded
with its `httpx.AsyncClient` pool never closed — `aclose()` only iterates
`self._cache.values()` and can't see it. *(Independently flagged by both
the security round-2 pass as SEC2-M2 and the DX round-2 pass as a
concurrency gap — filed here once, as the concurrency/architecture root
cause; see those files for the security- and test-coverage framing.)*
→ Guard cache population with a per-tenant (or whole-critical-section)
`asyncio.Lock`. **Effort: S–M.** *(No test in
`tests/api/test_multi_tenant.py` exercises concurrent `for_tenant()`
calls.)*
→ **Shipped 2026-09-02.** Went with the whole-critical-section option: a
single `self._resolution_lock` guards the entire check-then-act resolve/
provision/construct sequence, with a re-check of `self._cache` after
acquiring it (another caller may have finished while this one waited).
One lock for the whole cache, not per-tenant, is a deliberate tradeoff —
it briefly serializes concurrent *misses* for different tenants too, but
avoids a second unbounded structure (one lock per distinct `tenant_id`
ever seen) that would undermine `06`'s SEC2-3 cache-size bound; cache
*hits* never touch the lock. New concurrency test: 10 concurrent
`for_tenant()` calls for the same never-yet-cached tenant construct
exactly one `OpenFGAClient` and resolve exactly once. **Also resolves
`06`'s SEC2-6 and `08`'s DX2-10.**

**ARCH2-10. `MigrationManager.migrate_all()` has no per-tenant failure
isolation.** `core/migrations_manager.py:36-42` loops with no try/except
around each `migrate_tenant()` call; the first failure aborts the whole
batch, discarding results already computed and skipping every tenant
after it.
→ Catch per-tenant exceptions, collect a success/error map, return/report
both instead of raising on the first failure. **Effort: S–M.**
*(`tests/core/test_migrations_manager.py::test_migrate_all_iterates_tenants`
only covers all-succeed.)*
→ **Shipped 2026-09-02.** `migrate_all()` now fans out with an
`anyio.Semaphore`-bounded worker pool (mirroring `bulk_enforce()`'s DX2-1
fix) and returns a new `MigrationBatchResult(succeeded, failed)` instead
of a plain `dict` — a per-tenant exception is captured in `failed`
instead of aborting the batch. **Breaking change**: callers of
`migrate_all()` must update from `dict[str, str]` to
`MigrationBatchResult`; `cli/commands/migrate.py` updated accordingly
(prints failures to stderr, raises a summary `ExternalServiceError` if
any tenant failed — see `07`'s REL2-10). New test confirms one failing
tenant doesn't affect the others' results.

**ARCH2-11. `ModelDiffer.normalize()` canonicalizes dict key order but not
list order — a residual false-positive-diff risk in the ARCH-1 fix.**
`core/model_diff.py:74-82` — `json.dumps(cleaned, sort_keys=True)` sorts
dict keys at every level but never reorders `type_definitions`,
`union.child`, or `directly_related_user_types`, all lists. If OpenFGA's
echoed order ever diverges from local generation order in a case the one
round-trip `tests/live/test_model_sync_live.py` doesn't happen to exercise
— or local registration order shifts for schema-irrelevant reasons —
`is_equal()` reports "changed" and triggers an unnecessary re-upload,
undermining ARCH-1's "cheap and idempotent" goal.
→ Sort `type_definitions`/`directly_related_user_types` by `type`, and
canonicalize `union.child` order, before serializing. **Effort: S.**
*(`tests/core/test_model_diff.py::test_normalize_sorts_nested_keys` only
covers dict-key reordering.)*
→ **Shipped 2026-09-02.** New `_canonicalize_lists()` recursively sorts
every list in the schema-only dict (each item by its own
`json.dumps(sort_keys=True)` form, not a field-specific key, since not
every list shares one natural sort field) before the final serialization
— applied generically rather than special-casing `type_definitions`/
`directly_related_user_types`/`union.child` individually, since no list
in an OpenFGA model's schema has order-dependent semantics. New tests
cover `type_definitions` order, `directly_related_user_types` order, and
`union.child` order all comparing equal when reordered, plus a control
test confirming genuinely different content still compares unequal.

**ARCH2-12. `DefaultModelValidator` doesn't verify that a
`computedUserset`/`tupleToUserset` reference names a relation that
actually exists.** If a `union=`/`inherits=`/`from_parent=` reference has
a typo, `relations.get(child)` returns `None` and
`_referenced_relations(None)` returns `[]` — the cycle-detection walk
silently terminates as if there were no further dependency instead of
flagging the dangling reference. A model with this defect passes
`generate-model`'s now-default validation (DX-5) and fails only once
uploaded to a real OpenFGA server.
→ After building each type's relation map, verify every referenced
relation name exists; raise a clear, specific error naming the missing
one. **Effort: S.** *(No test in `tests/validation/test_default.py`
covers this.)*
→ **Shipped 2026-09-02.** `detect_cycles()`'s `visit()` now checks
`node not in relations` before anything else, raising `ModelValidationError
(f"Relation references unknown relation '{node}'")` instead of silently
falling through `_referenced_relations(None) == []` and treating the typo
as a dead end. New tests cover both the bare `detect_cycles()` call and
the full `validate()` end-to-end path.

**ARCH2-13. The generator still can't express `intersection`/
`difference`, and `from_parent` supports only one parent relation.**
`OpenFGAModelGenerator._build_relation()` (`modeling/generator.py:94-158`)
only emits `this`, `computedUserset` (`union`/`inherits`), and a single
`tupleToUserset` (`Relation.from_parent: tuple[str, str] | None` —
exactly one pair). There's no way to express "editor AND verified" or
"editor AND NOT banned," nor "viewer via parent folder OR viewer via
parent workspace." Notably, `validation/default.py`'s
`_referenced_relations()` (added for ARCH-3) already recurses into
`intersection`/`difference` shapes — dead code today since the generator
can never produce them. Same class of scope gap ARCH-2 fixed for
hierarchy; exclusion rules and multi-source hierarchy are common
real-world shapes that still require hand-written OpenFGA JSON.
→ Add `intersection=[...]`/`exclude=...` parameters to `Relation`;
consider letting `from_parent` take multiple pairs. **Effort: L.**
*(Confirmed via repo-wide grep: `intersection`/`difference`/`exclusion`
appear nowhere outside the validator's dead branches.)*

**ARCH2-14. `TenantResolver` and `TenantStore` are incompatible interfaces
with no shipped adapter — every consumer hand-rolls the same glue.**
`TenantStore.get()` returns `str | None` on a miss; `TenantResolver.
resolve()` must raise `TenantNotFoundError` on a miss (relied on by
`api.py:445`). The library ships three `TenantStore` implementations and
zero adapters bridging them to `TenantResolver` —
`examples/06_multitenant.py:73-85` and
`examples/12_multitenant_fastapi.py:55-67` both hand-write an identical
`_StoreBackedResolver` to close the gap. This is the residual "coupling
between resolver and store" SEC-4 didn't address (SEC-4 fixed the
failure-mode *interaction*, not the missing *composition path*).
→ Ship a small `StoreBackedResolver(TenantStore) -> TenantResolver`
adapter in `core/tenant_resolver.py`; point both examples at it.
**Effort: S.**
→ **Shipped 2026-09-02.** `StoreBackedResolver` added to
`core/tenant_resolver.py` exactly as specified; both examples' duplicated
`_StoreBackedResolver` classes deleted in favor of it. New unit tests
cover the resolve/not-found paths directly.

**ARCH2-15. `OpenFGAClient._request()` has no retry and a weaker exception
mapping than `check()`.** See
[`07_reliability_and_operations.md`](07_reliability_and_operations.md)'s
`REL2-3` for the full write-up (retry gap affecting `write_tuples()`,
`create_store()`, `get_latest_model()`, `list_objects()`) — filed there in
full since it's primarily a resilience/operations concern; noted here
because it's also the "disconnected scaffolding" pattern this file's
`ARCH2` findings are about: `retry_async` (ARCH-6's own scaffolding) was
wired into `check()` only, never generalized to the client's other calls.

**ARCH2-16. Two unrelated classes are both named `ModelRegistry`.**
`core/model_registry.py` defines `class ModelRegistry(Protocol)` (tracks a
tenant's active `model_id`, used by `MigrationManager`);
`modeling/registry.py` defines an unrelated `class ModelRegistry` (tracks
registered `ResourceModel` classes for generation). Same defect class as
ARCH-8 (`Authz.require`/`decorators.require` naming collision, already
fixed by renaming to `authorize`) — that sweep evidently didn't check this
pair.
→ Rename one (e.g. `modeling/registry.py`'s to
`ResourceModelRegistry`), following the ARCH-8 precedent. **Effort: S.**
→ **Shipped 2026-09-02.** `modeling/registry.py`'s class renamed to
`ResourceModelRegistry` exactly as suggested; `core/model_registry.py`'s
`ModelRegistry` Protocol untouched. All internal references
(`testkit.py`, tests) updated — a breaking rename for anyone importing
`py_authz.modeling.registry.ModelRegistry` directly by that name.

**ARCH2-17. `MigrationManager` keeps a second, independent "current
model" source of truth that can drift from reality.**
`migrate_tenant()` (`core/migrations_manager.py:44-80`) compares
`current_model` (read from `self.model_registry`, written only by
`MigrationManager` itself) against the actual result of `ModelSync.sync()`
(which diffs against OpenFGA directly). If a tenant's model is ever synced
via any other path (`Authz.sync_model()`, `py-authz sync`),
`model_registry` is never updated — the next `migrate_tenant()` run sees a
stale `current_model`, logs a false "migration_success" instead of
"migration_noop," and unconditionally overwrites the registry. Doesn't
cause an incorrect authorization decision (the real gate is `ModelSync`'s
own diff against OpenFGA), but makes the noop/success signal unreliable
once more than one code path can touch a tenant's model.
→ Derive "did anything change" solely from `ModelSync.sync()`'s own
noop-vs-changed signal, or drop the separate `model_registry` tracking.
**Effort: M.**
→ **Shipped 2026-09-02.** `ModelSync` gained a `last_sync_changed: bool |
None` attribute, set on every `sync()` call from its own real-time
comparison against OpenFGA; `migrate_tenant()` now reads that instead of
comparing against `self.model_registry.get(tenant_id)` beforehand —
`model_registry` is now a write-target only, never read back for the
noop/success decision. New regression test seeds a registry that was
never told about the "current" model and confirms the noop/changed
signal still comes out correct (driven by the syncer, not the stale
registry read).

**ARCH2-18. Redis-backed classes have no client-injection constructor,
unlike `OpenFGAClient`.** `RedisCache.__init__`, `RedisTenantStore.
__init__`/`RedisModelRegistry.__init__` all hardcode `redis.from_url(url)`
with no way to pass an existing client, unlike `OpenFGAClient
(http_client=...)`. The test suite works around this by reaching into a
private attribute post-construction (`tests/cache/test_redis.py:34`:
`cache._client = mock`) — a host app that already owns a Redis pool (the
normal production case) can't hand it to these classes either.
→ Add an optional `client=` constructor parameter to all three classes,
mirroring `OpenFGAClient`'s pattern. **Effort: S.**
→ **Shipped 2026-09-02.** `RedisCache`, `RedisTenantStore`, and
`RedisModelRegistry` all gained a `client=` keyword parameter; the latter
two also made `url` optional (`str | None = None`) and raise
`ConfigurationError` if neither `url` nor `client` is given. Both
`RedisTenantStore`/`RedisModelRegistry` also gained a `close()` method as
part of the same pass (see `07`'s REL2-8, which needed it).
`tests/cache/test_redis.py`'s fixture updated to use `client=` instead of
the private-attribute workaround; new tests cover injection, the
`url`-or-`client` requirement, and `close()`.

---

## 🟢 LOW

**ARCH2-19. Redundant self-import in `api.py`.** `api.py:468` —
`MultiTenantAuthz.for_tenant()` does `from py_authz.api import Authz`
inside `api.py` itself, where `Authz` is already defined at module scope.
Works, reads like a leftover circular-import workaround. → Delete the
import line. **Effort: S.**
→ **Shipped 2026-09-02** (incidentally, while editing `for_tenant()` for
`06`'s SEC2-3).

**ARCH2-20. Tenant/client construction duplicated ad hoc across three
call sites instead of one shared factory.** `TenantManager.provision()`,
`MultiTenantAuthz.for_tenant()`, and `MigrationManager.migrate_tenant()`
each independently hand-construct an `OpenFGAClient(api_url=...,
store_id=..., model_id=...)`. → A small
`OpenFGAClient.for_tenant(...)` factory used by all three, so a future
required constructor parameter doesn't need updating in three places.
**Effort: S.**

**ARCH2-21. `core/tenant.py:TenantContext` is unused dead code.** Defined
at `core/tenant.py:4-11`, referenced nowhere outside its own standalone
test — the same class of leftover as the already-removed ARCH-5/ARCH-6
stubs, missed in this file. → Delete, or wire it in if meant to replace ad
hoc `(tenant_id, store_id)` pairs passed around elsewhere. **Effort: S.**

**ARCH2-22. `Authz.can()`'s `Relation` branch rejects a plain `Resource`,
inconsistent with `grant`/`revoke`'s dual support.** `api.py:141-147`
raises `TypeError` if a `Relation` action's resource isn't a
`ResourceModel` (locked in by
`tests/api/test_relation_api.py::test_can_with_relation_rejects_non_resource_model`),
while `grant`/`revoke`'s `_to_fga_object()` accepts either shape. → Accept
a `Resource` too when its `.type` matches `relation.resource_cls.type`,
or document the asymmetry explicitly. **Effort: S.**

**ARCH2-23. `_relation_map()`'s `dir(model)`-based walk can silently
mis-bind an inherited `Relation` if `ResourceModel` subclassing is ever
used.** `OpenFGAModelGenerator._relation_map()` walks `dir(model)`
(includes inherited attributes, alphabetical rather than declaration
order), while `ResourceModelMeta.__new__` only calls `.bind(cls)` on
attributes in a class's own `namespace`. Latent — no `ResourceModel` in
this repo currently subclasses another — but a shared base `Relation`
(e.g. a common `owner = Relation("owner")` mixin) would keep
`.resource_cls` pinned to the base class. → Document that `Relation`
instances must not be shared via inheritance across `ResourceModel`
subclasses, or have `_relation_map` re-bind inherited relations per
subclass. **Effort: S.**

---

## Areas checked and found sound

`core/context.py`'s `contextvars` wrapper; `Authz`/`AuthzEngine`
delegation for `enforce()`/`can()`/`require()`/`list_objects()` (no
duplicated business logic; SEC-6's per-call `raise_on_denied` threading
verified correct end-to-end); `core/locks.py` post-REL-6 (atomic
compare-and-extend renewal, correct release-on-exception, no reentrancy
issue); `core/model_sync.py`/`model_diff.py`'s `_strip_server_defaults`
(no case found where it strips something meaningful);
`validation/default.py`'s cycle detection post-ARCH-3 (self-loops,
indirect cycles, cycles nested in `union`, correct exclusion of
`tupleToUserset`'s cross-type reference); `audit/base.py`/`cache/base.py`
(clean, minimal `Protocol`/`ABC` definitions).

---

## Next step

Nothing in this file is shipped yet — this is a freshly filed backlog.
[`05_architecture_and_modeling_todos.md`](05_architecture_and_modeling_todos.md).
