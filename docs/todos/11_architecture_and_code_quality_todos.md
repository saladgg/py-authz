# py-authz — Architecture, Correctness & Code Quality Backlog (Round 3)

Execution checklist for
[`11_architecture_and_code_quality.md`](11_architecture_and_code_quality.md).
IDs match that file.

> **Status (2026-11-24):** Tier 0 shipped (ARCH3-1, ARCH3-14), plus
> ARCH3-9 from Tier 2, pulled forward to back `10`'s service-account fix.
> Tier 1 (ARCH3-2/3/4/5) shipped in the second batch (2026-11-24).
> Remaining tiers open.

---

## Tier 0 — Packaging (ship first, before any PyPI publish) ✅

- [x] **ARCH3-1 — Move user-facing extras to
  `[project.optional-dependencies]`.** Keep `test`/`dev` as dependency
  groups that include them. Add a CI step: `uv build` and then assert
  that `Provides-Extra:` lines for every extra are present in the wheel
  `METADATA`.
  Shipped: `fastapi`, `redis`, `postgres`, `keycloak`, `cli`, `all` and
  `control-plane` are real extras. `all`/`control-plane` self-reference
  (`py-authz[fastapi,redis,postgres,keycloak]`), and the `test` group
  pulls `py-authz[all,control-plane]`. New `make check-dist` (wired into
  CI) builds the wheel and runs `scripts/check_dist.py`, which fails if
  any declared extra is missing from `Provides-Extra`, if `openfga-sdk`
  reappears as a runtime dependency, or if `py.typed` or the SQL files
  stop shipping. Confirmed: the built wheel now lists all 7 extras.
  `make install-control-plane` and `examples/README.md` switched from
  `--group` to `--extra`.
- [x] **ARCH3-14 — Drop the unused `openfga-sdk`; declare `anyio` in
  core.** Update the README's "minimal core" line.
  Shipped: the core is now `httpx`, `attrs`, `anyio`. `uv lock` dropped
  aiohttp, yarl, propcache, python-dateutil, six and friends. README,
  `docs/architecture.md` and `docs/getting_started.md` updated. The
  `cli` extra is kept as an empty alias so existing install commands
  still work.

## Tier 1 — Authorization-semantics correctness ✅

- [x] **ARCH3-4 — `subjects=[]` means "no direct subjects".** Emit no
  `this` branch. Changelog note: intersection/exclude relations stop
  being directly grantable when declared that way.
  Shipped:
  - An explicit `subjects=[]` is honoured.
  - A relation defined by `intersection` (like `from_parent` before it)
    now defaults to no direct subjects. **Behaviour change:** add
    `subjects=["user"]` to keep an intersection relation directly
    grantable. `exclude` keeps the `["user"]` default, since it's
    normally layered on a directly-granted base.
  - A relation nothing can hold (`subjects=[]` and no rewrite) now
    raises `ModelValidationError` at generation time, instead of
    emitting an empty rewrite OpenFGA rejects.
  - Two tests that worked around the old bug by assigning `.subjects`
    directly were cleaned up.
- [x] **ARCH3-3 — Diff compares `conditions` and preserves `wildcard`.**
  Strip only the known server defaults. Regression tests for both cases.
  Shipped: `conditions` is added to `SCHEMA_FIELDS`, and `wildcard` to
  `_PRESERVE_EVEN_IF_EMPTY`. The generic zero-value stripping was kept
  rather than swapped for an allow-list: it's applied symmetrically to
  both sides, so only semantically meaningful empties needed
  protecting. Absent and empty `conditions` still compare equal.
  Verified against a real OpenFGA: a wildcard model round-trips as
  equal, and a second sync reuses the model instead of re-uploading. All
  36 live tests still pass.
- [x] **ARCH3-2 — `SyncAuthz` with one long-lived background loop;
  decorator delegates to it.** Regression test with the real
  `OpenFGAClient` and `httpx.MockTransport`, called ≥ 3 times.
  Shipped:
  - New `py_authz/sync.py` with `SyncAuthz`: one event loop on a daemon
    thread and `run_coroutine_threadsafe`. Thread-safe, with a per-call
    timeout, and closes idempotently (also as a context manager). It
    exposes typed `can`/`require` plus every other `Authz` coroutine
    method via `__getattr__`. Exported from `py_authz`.
  - The decorator keeps the anyio-worker fast path. Otherwise it uses
    one shared `SyncAuthz` per wrapped `Authz` (weakly keyed), and also
    accepts a `SyncAuthz` directly.
  - The regression test uses a real local HTTP server rather than
    `MockTransport`, because only a real socket reproduces the
    loop-bound pool failure. Five sequential calls fail on the old code
    and pass now. Also added: a 40-call, 8-thread concurrency test and a
    closed-state test.
  - README gained a "Synchronous Code" section.
- [x] **ARCH3-5 — `enforce()` normalizes `ResourceModel` instances.**
  `Authz.enforce()` passes `resource` through `_to_resource()`, so
  `require()` and string-action `can()` get it too; the signatures now
  say `Resource | ResourceModel`. Regression test under strict mode
  covers all three.

## Tier 2 — Error model and upstream semantics

- [ ] **ARCH3-7 — Distinguish upstream 4xx (→ 400/409) from 5xx and
  transport errors (→ 503).**
- [ ] **ARCH3-10 — Idempotent writes (`on_duplicate`/`on_missing`
  ignore).** Ship with `12`'s REL3-6.
- [x] **ARCH3-9 — Testkit looks relations up by `.name`; add
  `strict=True`; use strict mode in control-plane tests.** Expect this to
  surface `10`'s SEC3-3 in unit tests. That's the point.
  Shipped:
  - `_lookup_relation` matches on `Relation.name` (walking the MRO).
  - `InMemoryFGAClient(strict=True)` and `make_fake_authz(strict=True)`
    reject, with `ExternalServiceError` (the same class the real client
    raises on a 400):
    - an unknown user or object type, or an unknown relation;
    - a subject type the relation doesn't allow (handles `type:*` and
      `type#rel` forms);
    - duplicate writes;
    - deletes of tuples that don't exist.
  - Write batches are validated atomically.
  - All six control-plane RBAC fixtures now use strict mode with the
    full `RBAC_MODELS`.
  - Confirmed strict mode rejects the pre-fix `service:` principal with
    "type 'service' not found". Non-strict stays permissive for backwards
    compatibility. Seven new tests in `tests/test_testkit.py`.
- [ ] **ARCH3-6 — Validator: tupleset, subject-type and duplicate-type
  checks; generator parses `type#relation` and `type:*`.**
- [ ] **ARCH3-8 — Real `explain()` via `/expand`, or document it as
  check-only.**

## Tier 3 — Structural refactors (each its own PR)

- [ ] **ARCH3-11 — `OpenFGAConnection` (shared pool, credentials,
  timeouts, retries) plus `with_store()` views; eviction no longer closes
  shared state.** Unblocks `10`'s SEC3-5.
- [ ] **ARCH3-12 — A single `ModelLifecycle` service used by the CLI,
  `TenantManager`, `MigrationManager` and the control-plane routes;
  validator on; cache invalidation after sync.**
- [ ] **ARCH3-13 — Make `ModelRegistry` real (per-tenant model pinning)
  or remove it, along with `MultiTenantAuthz(model_id=)`; fix the
  README.**
- [ ] **ARCH3-15 — Fold into `12`'s REL3-7.**

## Tier 4 — Polish

- [ ] **ARCH3-16 — Record both `tenant_id` and `store_id` on audit
  events** (migration `0009`).
- [ ] **ARCH3-17 — Boundary cleanups** (public
  `write_authorization_model`, move `load_module`, drop `TupleRef`
  duck-typing, `reason`/`actor` on bulk operations, richer `__init__`
  exports plus `__version__`, split `migrate_command`).
- [ ] **ARCH3-18 — Panel: generated types from OpenAPI response models;
  reads off Server Actions; no raw error messages to the browser.**
