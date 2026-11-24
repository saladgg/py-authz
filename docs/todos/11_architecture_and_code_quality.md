# py-authz — Architecture, Correctness & Code Quality Audit (Round 3)

**Date:** 2026-11-24 · repo as of `6a54c93` (1.6.0).
**Scope:** packaging and dependency metadata, the modeling layer
(generator, validator, diff), the `Authz` facades, the OpenFGA client's
error model, the sync decorator, the testkit, and the control plane's
composition of library pieces (duplication, layering, dead persistence).
**Method:** read `01`, `05` and `09` plus `docs/architecture.md` first.
Baseline: `ruff check` clean, `mypy` clean (88 files), 729 unit tests
passing, 96% line+branch coverage. Findings marked **REPRODUCED** were
confirmed with scratch scripts or a scratch `uv build`. Correctness bugs
come first, then refactoring candidates.

---

## A. Correctness bugs

### 🔴 CRITICAL

**ARCH3-1. Every documented install extra is missing from the published
package metadata: `pip install "py-authz[control-plane]"` (or
`[fastapi]`, `[redis]`, `[postgres]`, `[keycloak]`, `[cli]`, `[all]`)
installs the core only.** `pyproject.toml:33` declares all of them under
`[dependency-groups]` (PEP 735). There's no
`[project.optional-dependencies]`. Dependency groups are a local
development feature (`uv sync --group …`) and are never written to wheel
metadata. A scratch `uv build` produced a `METADATA` with **zero
`Provides-Extra` lines**: `Requires-Dist` lists only `openfga-sdk`,
`httpx<1,>=0.28.1` and `attrs`. REPRODUCED.
→ **Consequence:** pip prints "does not provide the extra" and the user
hits `ImportError` at runtime. Then `utils/deps.py`'s error message
(`:16,28,40,60`) tells them to run the exact command that just failed.
Affected instructions:
- `README.md` install section
- `docs/getting_started.md:15-20`
- `docs/control_plane.md:29`
- `examples/README.md` (`pip install -e ".[all]"`)
- the `py-authz-control-plane` entry-point comment (`pyproject.toml:155`)

The SEC2-10 upper bounds on `pyjwt` never reach a consumer. Nobody noticed
because every development path uses `uv sync --group`. The PyPI publish
that `03`'s REL-9 set up would ship this broken metadata.
→ **Fix:** move `fastapi`, `redis`, `postgres`, `keycloak`, `cli`, `all`
and `control-plane` to `[project.optional-dependencies]` (self-references
like `"py-authz[fastapi]"` are allowed there). Keep `test`/`dev` as groups
that include the extras. Add a CI step that builds the wheel and asserts
`Provides-Extra: control-plane` (and the rest) appear in its `METADATA`.
**Effort: S.** *(No test.)*

### 🟠 HIGH

**ARCH3-2. The sync `@authorize` decorator fails every other call
against a real client.** `modeling/decorators.py:84` calls
`allowed = anyio.run(_check)`, which creates a **new event loop on every
call**. The `httpx.AsyncClient` in `OpenFGAClient` (`clients/openfga.py:98`)
keeps pooled connections bound to the first loop, so the next call hits a
connection from a closed loop. REPRODUCED against a local HTTP stub: call
0 ok, call 1 `ExternalServiceError(... RuntimeError('Event loop is
closed'))`, call 2 ok. Checks fail closed by default, so in any WSGI
(Django/Flask) app a legitimately allowed user is denied on alternating
requests.
→ ARCH2-6 only fixed the "a loop is already running" sub-case.
`tests/modeling/test_decorators.py:10-14` uses a `MockAuthz`, so no real
client is ever involved.
→ **Fix:** a `SyncAuthz` facade that owns **one** long-lived event loop
on a daemon thread and submits work with `asyncio.run_coroutine_threadsafe`.
The decorator's sync path delegates to it. Regression test using the real
`OpenFGAClient` with `httpx.MockTransport`. This is also the foundation for
`13`'s DX3-18 (Django/Flask adapters). **Effort: M.**

**ARCH3-3. Model "unchanged" detection ignores `conditions` and
collapses `user` vs `user:*`, so `ModelSync` skips uploading real
semantic changes.** `core/model_diff.py:97`:
`SCHEMA_FIELDS = ("schema_version", "type_definitions")` leaves out the
top-level `conditions`. `_strip_server_defaults` drops every empty `{}`
except under `_PRESERVE_EVEN_IF_EMPTY` (`this`/`child`), so
`{"type":"user","wildcard":{}}` becomes `{"type":"user"}`. REPRODUCED:
`is_equal(model, model_with_user_wildcard)` and
`is_equal(model, model_plus_conditions)` both return `True`.
→ **Consequence:** `ModelSync.sync()`, and through it `/models/sync`,
migrations, `--dry-run` and rollback (`model_factory=lambda:
version.schema_json`), reports "unchanged" for a model whose only change
is a public wildcard or an ABAC condition, and the new semantics never
reach OpenFGA. The generator can't emit these shapes yet (see `13`'s
DX3-17), but rollback and hand-written models can, and DX3-17 will make
this immediately reachable.
→ **Fix:** add `"conditions"` to `SCHEMA_FIELDS` and add `"wildcard"` to
`_PRESERVE_EVEN_IF_EMPTY`. Better: strip only the specific known server
defaults (`object: ""`, `condition: ""`, `module: ""`,
`source_info: null`) instead of every empty value. **Effort: S.**

**ARCH3-4. `Relation(subjects=[])` silently becomes `["user"]`, so
every `intersection`/`exclude` relation is also directly grantable,
which bypasses its AND/BUT-NOT semantics.** `modeling/base.py:149`:
`self.subjects = subjects or ["user"]`. REPRODUCED:
`Relation("can_edit", subjects=[], intersection=["editor","verified"])`
generates `union[this, intersection(...)]` with
`directly_related_user_types=[{"type":"user"}]`.
→ **Consequence:** a purely computed relation can't be declared. One
direct tuple `user:x can_edit doc:1` grants access regardless of
`verified` or of an `exclude=` list. This is the exact semantics ARCH2-13
was added to express.
→ **Fix:** `self.subjects = ["user"] if subjects is None else
list(subjects)`, and emit no `this` branch when `subjects == []`.
Consider defaulting to no direct subjects whenever
`intersection`/`exclude` is given, with a changelog note. **Effort: S.**

### 🟡 MEDIUM

**ARCH3-5. `Authz.enforce`/`require`/`can` crash on a `ResourceModel`
instance when the action is a string.** `api.py:180-182`: the string
branch does `resource_obj = resource` without normalizing, and
`enforce`/`require` never call `_to_resource`. That helper's own
docstring (`api.py:15-18`) claims these methods "already accept" a
`ResourceModel`. REPRODUCED: `can("viewer", alice, Doc(id="1"))` raises
`AttributeError: 'Doc' object has no attribute 'to_fga_object'`, which is
not an `AuthzError`, so the documented "catch `AuthzError` at boundaries"
pattern misses it. ARCH2-22 fixed only the `Relation` branch.
→ Normalize via `_to_resource()` at the top of `enforce()`. Everything
else delegates to it. **Effort: S.**

**ARCH3-6. The validator and generator accept models OpenFGA rejects.**
REPRODUCED. `DefaultModelValidator.validate` passes:
- a misspelled tupleset in `from_parent=("parnet","viewer")`, because
  `validation/default.py:51-54` deliberately skips `tupleToUserset`,
  including the same-type `tupleset.relation`;
- an unknown subject type (`subjects=["grup"]`);
- a `ResourceModel` with `type="user"`, which yields
  `['user','doc','user']` because `generator.py:59` always prepends
  `{"type":"user"}`.

`generator.py:75` also emits `{"type": "team#member"}` verbatim instead of
`{"type":"team","relation":"member"}`.
→ **Consequence:** these fail only at upload. In
`TenantManager.provision()`, that means create store → fail → delete
store on every auto-provision attempt.
→ **Fix:** validate tupleset relations on the same type, subject types
and computed relations against the type set, and reject duplicate types.
Parse `type#relation` and `type:*` (shared with `13`'s DX3-17).
**Effort: M.**

**ARCH3-7. OpenFGA 4xx responses surface as 503 "service unavailable".**
`clients/openfga.py:236` and `:291` map every `HTTPStatusError` to
`ExternalServiceError`, and `control_plane/errors.py` maps that to 503.
An unknown relation or type in `POST /grants`, a user without a type
prefix, a duplicate tuple, or an invalid model on rollback all return
503, so callers and the panel retry pointlessly and on-call sees false
outages. This is also how SEC3-3 manifests (`10`).
→ Add `UpstreamRequestRejected(InvalidAuthzRequest)` (or carry
`status_code` on `ExternalServiceError`) for 400/404/409/422, mapped to
400/409. Keep 503 for 5xx and transport errors. **Effort: S.**

**ARCH3-8. `AuthzEngine.explain()` never produces a path in
production.** `core/enforcement.py:651`:
`if hasattr(self.fga_client, "explain"):`. `OpenFGAClient` has no
`explain` method. The only implementation is the test double in
`tests/conftest.py:68-88`, whose `__getattr__` "conditionally exposes"
one. In production, `explain()` is `check()` plus a templated reason with
`path=None`, while `docs/getting_started.md:219` and
`examples/07_explain_and_bulk.py:6` promise "why a decision was made".
→ Implement `OpenFGAClient.expand()` (OpenFGA `/expand`) and build the
path from it, with a live test. Otherwise, document `explain()` as
check-only and remove the `hasattr` branch. **Effort: M.**

**ARCH3-9. `testkit.InMemoryFGAClient` diverges from OpenFGA in ways
that hide real bugs.**
- `testkit.py:218-220` (`_lookup_relation`) uses `getattr(model, name)`,
  which looks up the Python **attribute** name, not `Relation.name`.
  REPRODUCED: with `view = Relation("viewer", union=["editor"])` (the
  README's own style) and `editor` granted, `can("viewer", …)` returns
  **False**, while real OpenFGA returns True.
- It accepts writes for undefined types and relations, and duplicate
  writes, which are all 400s in real OpenFGA. That's what masks
  `10`'s SEC3-3 and ARCH3-10 below.

→ Look relations up by `.name` (reuse the generator's relation map). Add
`strict=True`, which validates types and relations and rejects duplicate
writes and missing deletes like OpenFGA does. Use it in
`tests/control_plane/conftest.py`. **Effort: S–M.**

**ARCH3-10. Grant/revoke aren't idempotent.** `write_tuples`
(`clients/openfga.py:482`) never sets OpenFGA's
`on_duplicate: "ignore"` / `on_missing: "ignore"` write options (OpenFGA
≥ 1.8; compose pins v1.19). Granting an existing tuple, or revoking a
missing one, raises (and is a 503 per ARCH3-7). Combined with retries on
read timeout (`12`'s REL3-6), a write that already succeeded fails on
retry with "tuple already exists".
→ Send the write options (feature-flagged for older servers), or treat
those specific 400 codes as success. **Effort: S.**

---

## B. Refactoring candidates

### 🟠 HIGH

**ARCH3-11. Each tenant gets its own `httpx` pool against the same
OpenFGA URL; OpenFGA connections can't be configured (no auth, no
timeouts, no retries in multi-tenant mode); and LRU eviction closes an
`Authz` that's still in use.**
- `api.py:635-639` builds `OpenFGAClient.for_tenant(api_url, store_id,
  model_id)` per tenant.
- `TenantManager`, `MigrationManager` and the control-plane routes each
  build throwaway clients from a bare `api_url`.
- `for_tenant` (`openfga.py:102-143`) passes through no headers,
  credentials, timeout or retry settings.
- `api.py:656-661` evicts with `popitem(last=False)` then
  `ensure_future(evicted.aclose())` while a request may still hold that
  `Authz`. REPRODUCED with `max_cached_tenants=1`: fetch `a`, fetch `b`,
  then `a.enforce()` raises `ExternalServiceError(RuntimeError('Cannot
  send a request, as the client has been closed.'))`.

→ **Consequence:** up to 1000 connection pools; no way to reach an
authenticated OpenFGA (the root cause of `10`'s SEC3-5); sporadic 503s
under tenant churn.
→ **Fix:** introduce `OpenFGAConnection` (one shared `AsyncClient` plus
credentials, timeouts and retry policy) injected into `Authz`,
`MultiTenantAuthz`, `TenantManager`, `MigrationManager` and the control
plane. `client.with_store(store_id, model_id)` returns a lightweight view
with no pool of its own, so eviction never closes anything shared.
**Effort: M–L.**

**ARCH3-12. "Sync a model" is implemented in five places with
different side effects.** `ModelSync(` is constructed in `api.py:300`,
`core/tenant_manager.py:85`, `core/migrations_manager.py:90`,
`cli/commands/sync.py:30`, `control_plane/routes/models.py:83,141` and
`control_plane/app.py`. The dry-run diff is copy-pasted between
`migrations_manager.py:136-138` and `routes/models.py:76-79`. The paths
disagree:

| Path | Validator | Writes `tenant_models` | Writes `model_versions` |
|---|---|---|---|
| CLI `sync` | yes | — | — |
| `MigrationManager` (`/migrations`) | no | yes | no |
| `/models/sync` | no | no | yes |
| `/rollback` | no | no | yes |
| `TenantManager.provision` | no | no | no |

Nothing invalidates the decision cache after a model change.
`TenantManager`/`MigrationManager` can't take a `model_factory` or
validator, so an adopter whose model isn't the global registry can't
provision or migrate it.
→ One `ModelLifecycle` service (validator on by default, model factory,
registry, version store, post-sync cache invalidation, `plan()` for dry
runs) used by all five callers. **Effort: M.**

### 🟡 MEDIUM

**ARCH3-13. `ModelRegistry` / `tenant_models` is written but never
read, and `MultiTenantAuthz(model_id=...)` is misleading.**
`model_registry.set` is called only from `migrations_manager.py:106`, and
`model_registry.get` has **no caller** in `py_authz`. `MultiTenantAuthz`
takes one global `model_id` for all tenants (`api.py:552`), but OpenFGA
model ids are per store, so any non-`None` value is wrong for every
tenant but one. `README.md:338` says `model_id=None,  # resolved
per-tenant`, which isn't true: OpenFGA just uses each store's latest
model.
→ **Consequence:** no model pinning, so a migration takes effect
mid-flight on every replica.
→ Either resolve `model_registry.get(tenant_id)` in `for_tenant()` (and
write it in provision), or remove `model_id` from `MultiTenantAuthz` and
the dead registry write, and fix the README. **Effort: M.**

**ARCH3-14. Dependency declarations don't match imports.**
- `openfga-sdk` is a hard core dependency (`pyproject.toml:23`) but is
  **never imported** (`grep -rn openfga_sdk py_authz tests examples`
  returns nothing). Every install pulls in aiohttp, urllib3,
  opentelemetry-api and python-dateutil for nothing, contradicting the
  README's "minimal core" claim.
- `anyio` is imported by core modules (`core/enforcement.py`,
  `core/migrations_manager.py`, `modeling/decorators.py`) but declared
  only in the `cli` group. It works today only because `httpx` depends
  on it.

→ Drop `openfga-sdk`, add `anyio` to core dependencies, and fix the
README. **Effort: S.**

**ARCH3-15. `/health` probes the RBAC store under the name "product
client".** `control_plane/app.py:170`:
`app.state.product_fga_client = rbac_fga_client`. `deps.py` documents it
as the *product* instance, and `settings.py:103` allows the two URLs to
differ. Health reports "ok" while the product OpenFGA is down. Fold the
fix into `12`'s REL3-7 (readiness rework): probe both, rename the state
keys, fix the docstring. **Effort: S.**

### 🟢 LOW

**ARCH3-16. `AuditEvent.tenant_id` actually holds the store id.**
`core/enforcement.py` (`_audit_decision`, `record_write`) sets
`tenant_id=getattr(self.fga_client, "store_id", None)`. Every consumer
has to translate back: `routes/audit.py` does, `routes/cache.py` doesn't
(the root of `10`'s SEC3-6). A re-provisioned tenant's history becomes
unfindable by tenant, and RBAC-store decisions land in the same table
under the RBAC store id. → Give `AuthzEngine` an optional `tenant_id`
(set by `MultiTenantAuthz`) and record both columns (additive migration
`0009`). **Effort: M.**

**ARCH3-17. Smaller boundary and layering issues** (each S):
- `ModelSync._upload_model` reaches into the private `OpenFGAClient._post`
  (`model_sync.py:80`). Add a public `write_authorization_model()`.
- The control plane imports the CLI package
  (`app.py:22 from py_authz.cli.utils import load_module`). Move
  `load_module` to `py_authz/utils/`.
- `schemas.TupleRef.to_fga_object` duplicates `core.types.Resource` and
  is passed duck-typed into `Authz.grant` (`routes/tuples.py`).
- `grant_many`/`revoke_many` lack the `reason`/`actor` parameters that
  `grant`/`revoke` have, so bulk changes lose the CP-18 audit context.
- `py_authz/__init__.py` exports only `Authz`, `Identity`, `Resource` and
  `ContextualTuple`: no `MultiTenantAuthz`, no exception classes, no
  `__version__`.
- `cli/commands/migrate.py`'s `migrate_command` has cyclomatic
  complexity 20. Split argument resolution from execution.

**ARCH3-18. Control-panel architecture** (each S):
- `lib/types.ts` is hand-mirrored and already drifting. Add response
  models to the FastAPI routes (they return untyped `dict`s today, so the
  OpenAPI schema has no response shapes) and generate the TS types from
  `/openapi.json`.
- Reads and polling (`getMigrationJob`, `listRoles`, `listTuples`) go
  through Server Actions, which Next runs one at a time per client, so
  the 2-second job poller blocks user mutations. Use Route Handlers or a
  server-component refresh for reads.
- `lib/actions.ts` `run()` forwards raw `error.message` for non-`ApiError`
  errors to the browser, which can leak the internal API URL or
  `ECONNREFUSED` details.

---

## Areas checked, no issue

- Wheel contents: `py.typed`, all `storage/sql/*.sql`, `control_plane/`.
- `write_tuples` chunks at 100 combined operations correctly.
- `retry_async` backoff and propagation are correct (its only problem is
  the idempotency issue in ARCH3-10 / REL3-6).
- `errors.py` exception mapping is ordered most-specific-first.
- `cache_key()` is injective and per-engine namespacing is correct (the
  SEC3-6 bug is only in the route).
- Naive `datetime.now()` audit timestamps are encoded correctly by
  asyncpg's `timestamptz` encoder.
- ARCH2-23 rebind-copy logic, `difference`/`intersection` generator
  nesting, and `detect_cycles` recursion are correct.
- `TenantManager.provision` cleanup and its double-checked lock (when a
  lock manager is given; see `12`'s REL3-2).
- Control-plane auth dispatch (`pasa_` prefix vs JWT) is unambiguous.
- Rollback is a forward re-sync recorded as a new version, as documented.
- The server/client boundary in the panel is sound: `api.ts` is
  `server-only`, and no client file imports `session`/`env`/`oidc`/`crypto`.
