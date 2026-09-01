# py-authz — Developer Experience & Test Coverage Audit

**Date:** 2026-08-31 · repo as of `revive_authz` (post-1.2.0).
**Scope:** the day-to-day experience of actually integrating this library —
the FastAPI adapter's ergonomics, the high-level `Authz` API's
completeness relative to the engine it wraps, the CLI, and the test
suite's realism relative to what it claims to protect against.
**Method:** worked through the adapters and `Authz` facade the way an
integrator would (protecting a route that needs an async resource lookup,
granting a permission and immediately checking it, running the CLI against
a multi-tenant setup), and separately audited how much of the test suite
actually exercises real dependencies versus mocks, since that ratio
explains several defects filed elsewhere in this audit.

This is the first audit filed against this repository.

---

## Adapter & API ergonomics

### 🔴 CRITICAL

**DX-10. The shipped `py-authz sync` CLI command crashed immediately on
every real invocation — masked by a test double more permissive than the
real dependency it stood in for.** `cli/main.py` called `anyio.run(
sync_command, store_id=args.store_id, api_url=args.api_url, model_id=
args.model_id, force=args.force)` — but `anyio.run`'s actual signature is
`run(func, *args, backend=..., backend_options=...)`; it has no mechanism
to forward arbitrary keyword arguments to `func` at all. Every real
invocation of `py-authz sync` — the command the README, `todos.md`, and
every "CI pipeline" mention of this library point at — raised `TypeError:
run() got an unexpected keyword argument 'store_id'` before doing
anything else. `tests/cli/test_main.py`'s own `fake_anyio_run(func,
**kwargs): asyncio.run(func(**kwargs))` accepted and forwarded those
kwargs — a shape real `anyio.run` doesn't have — so the test suite never
saw the mismatch. *Found while implementing DX-5's `migrate` command,
which was about to repeat the identical broken pattern; caught by
actually running the CLI against a live OpenFGA instance rather than
trusting the (mocked) test suite — the same class of gap DX-9 exists to
close, just outside `tests/live/`'s current scope (nothing there
exercises the CLI entry point itself).*
→ Bake every argument into a zero-argument `functools.partial` before
calling `anyio.run` — it only ever needs to invoke a no-arg callable.
Fixed for both `sync` and the new `migrate` command. Rewrote the test
fixture's `fake_anyio_run` to mirror the real single-callable contract
(and documented why the old, kwargs-accepting shape was itself the bug).
Confirmed against a real OpenFGA instance: `py-authz sync --store-id ...
--api-url ...` now runs to completion instead of crashing, and a second
invocation reuses the same model id (confirming ARCH-1's fix holds
through the actual CLI path, not just `ModelSync` called directly).
**Effort: S.**

### 🟠 HIGH

**DX-1. `resource_getter`/`user_getter` in the FastAPI adapter must be
synchronous, ruling out the most common real case.** `require_dependency`/
`require_fastapi` (`adapters/fastapi.py:44-151`) call `resource_getter(
request, **kwargs)`/`user_getter(request)` directly, never `await`ed — but
authorizing a specific resource almost always requires an async lookup
first (does this document exist, who owns it, what folder is it in for a
hierarchy check). The moment loading the resource needs `await`, this
adapter can't express it: callers either duplicate the fetch inside the
route handler and awkwardly thread the result into a synchronous closure,
or bypass the adapter's `resource_getter` hook entirely and inline the
`authz.can()` call by hand — defeating the point of having the decorator/
dependency at all. `modeling.decorators.require()` already solves this
correctly for the wrapped function itself (it checks
`inspect.iscoroutinefunction`), just not for the getters.
→ Accept sync or async callables for both `resource_getter` and
`user_getter` in the FastAPI adapter, detecting via
`inspect.iscoroutinefunction` and awaiting when appropriate. **Effort: S.**
→ **Shipped 2026-08-31.** Both getters now accept sync or `async def`
callables (`adapters/fastapi.py`'s `_resolve()`, detecting via
`inspect.isawaitable` on the *result* rather than
`inspect.iscoroutinefunction` on the callable, which also covers e.g. a
sync function wrapping an already-created coroutine). See
`04_developer_experience_and_testing_todos.md` for test coverage.

**DX-9. The test suite is 100% mock-based — nothing runs against a real
OpenFGA, Keycloak, Postgres, or Redis, in CI or anywhere else.**
`tests/integration/test_openfga_integration.py`'s own docstring says so
directly: "Mocked 'integration' tests... use a scripted httpx-compatible
client so the suite runs offline." `.github/workflows/ci.yml` never starts
the bundled `docker-compose.yml` stack (OpenFGA + Keycloak), and there is
no equivalent compose service for Postgres/Redis at all. This is the root
cause tying together several of the sharpest findings elsewhere in this
audit — every one of these would have been caught immediately by a real
end-to-end run:
- ARCH-1 (`01_architecture_and_modeling.md`) — `ModelSync` reading the
  wrong field name from OpenFGA's actual list-models response shape.
- ARCH-3 — `detect_cycles` never exercised through the real validator
  with real generator output.
- REL-1/REL-2 (`03_reliability_and_operations.md`) — `HybridTenantStore`/
  `RedisTenantStore` incompatibility and undecoded bytes, both masked by
  bespoke per-file mocks more forgiving than the real dependency.
- REL-4 — `asyncpg` dict-to-`jsonb` serialization, never run against a
  real connection.

None of these are exotic edge cases; they're the first thing that breaks
when the mocked HTTP/DB layer's assumed response shape doesn't match
reality. A library whose entire value proposition is "talks correctly to
OpenFGA and Keycloak" has no test that actually confirms it does.
→ Add a `make test-integration` / dedicated CI job that boots
`docker-compose.yml`'s `openfga` service (plus `postgres`/`redis` once
added for REL-3/REL-4) and runs a small, focused suite of true integration
tests against them — model sync round-trips, tuple writes, a full
Keycloak JWT validation against a real token, the Postgres/Redis storage
backends — on every PR, not just locally. **Effort: L.**
→ **Shipped 2026-08-31** for OpenFGA + Keycloak + Redis (Postgres deferred
until REL-3 gives it a real connection lifecycle — no point building a
live Postgres test against an API this audit already knows needs to
change). New `tests/live/` package (`conftest.py` + 4 test files),
`make test-integration` (boots `docker-compose.yml`'s `openfga`/
`keycloak`/`redis` — the latter newly added — waits for reachability, runs
`pytest tests/live`), and a new `integration-test` CI job in
`.github/workflows/ci.yml`. Every test skips cleanly (not fails) when its
service isn't configured, so plain `pytest`/`make test` stays fast and
offline.
→ **Postgres deferral closed 2026-09-01**, alongside REL-3/REL-4: a new
`docker-compose.yml` `postgres` service, `requires_postgres`/
`postgres_dsn`/`postgres_schema` fixtures in `tests/live/conftest.py`, and
two new files — `tests/live/test_postgres_storage_live.py` and
`tests/live/test_audit_postgres_live.py` — confirmed against a real
Postgres container. `make test-integration` now boots all four services.
**This worked exactly as predicted — running it immediately found two
more real, previously-undiscovered bugs no mock had caught:** the
ARCH-1 fix's first version (top-level `id` only) still failed against a
real store, needing the deeper zero-value-stripping fix described in
ARCH-1's entry; and `Authz.grant/revoke/grant_many/revoke_many` crashed
outright on a `ResourceModel` argument — exactly the calling convention
the README and `examples/06_multitenant.py` document — now fixed as
ARCH-10. See `01_architecture_and_modeling.md`/`_todos.md` for both.

### 🟡 MEDIUM

**DX-2. Granting/revoking a permission doesn't invalidate the cache, and
nothing warns about it where a user would actually look.** `Authz.grant()`
/`revoke()`/`grant_many()`/`revoke_many()` (`api.py:203-278`) write
directly to OpenFGA via `write_tuples()` with no corresponding
`cache.delete(...)` call — the very next `enforce()` for that
(user, action, resource) can return a stale cached result until the TTL
expires. `docs/architecture.md:266-268` calls this out as a "known sharp
edge," but that's a separate document from the one a user reads first —
`Authz.grant()`'s own docstring (`api.py:208-211`, "Grant a relation
between a user and resource.") says nothing about caching at all.
→ Either have `grant`/`revoke` invalidate the corresponding cache key(s)
automatically (the information needed to compute the same `cache_key()`
used by `AuthzRequest` is available at the call site), or at minimum add
the warning directly to the `grant`/`revoke`/`grant_many`/`revoke_many`
docstrings, not only the separate architecture doc. **Effort: S
(docstrings) / M (auto-invalidate).**
→ **Shipped 2026-08-31 (the auto-invalidate option).** `Authz.grant`/
`revoke`/`grant_many`/`revoke_many` now invalidate the cache entry for
the exact (identity, relation, resource) triple just written, via a
shared `_invalidate_cache()` helper reusing `AuthzRequest.cache_key()`
(no format duplication, and a no-op when no cache is configured).
Deliberately scoped and documented: only the exact granted/revoked
relation is invalidated, not other relations implied by it through the
model's union graph (e.g. granting "owner" doesn't proactively invalidate
a cached "editor"/"viewer" check) — the engine has no static knowledge of
that graph. Docstrings state this scope explicitly.

**DX-3. `Authz.can()`/`require()` silently drop `context`/
`contextual_tuples`, even though `enforce()` supports both.** `Authz.can()`
(`api.py:82-116`) and `Authz.require()` (`api.py:118-144`) — the two most
ergonomic entry points, and the ones the FastAPI adapter and
`modeling.decorators.require()` actually call — have no way to pass ABAC
`context` or per-request `contextual_tuples` through to `enforce()`. Only
the lower-level `engine.enforce(AuthzRequest(...))` path can do
ABAC/ephemeral-tuple checks today, meaning the typed, `Relation`-based API
this library markets as its primary interface can't be used for two
features (contextual tuples, ABAC conditions) the README lists as
headline capabilities.
→ Add `context`/`contextual_tuples` keyword-only parameters to `can()`
and `require()`, threaded through to the underlying `enforce()` call.
**Effort: S.**
→ **Shipped 2026-08-31.** Both gained keyword-only `context`/
`contextual_tuples` parameters, threaded through to `enforce()`
unchanged. Confirmed the contextual path still correctly bypasses the
cache when called through `can()` (not just the lower-level engine call)
— `AuthzRequest.is_cacheable()` already handled this; the fix was purely
about `can()`/`require()` actually constructing the request with that
state populated.

**DX-4. `list_objects` has no result-size guard or pagination
awareness.** A relation with a large fan-out (e.g. "which documents can
this org-admin view" in a sizeable organization) returns the entire
matching set in one response, with no documented ceiling and no streaming
— a caller building a paginated list UI on top of `Authz.list_objects()`
has to implement their own slicing after the fact, with no protection
against an unexpectedly enormous response landing in memory at once.
→ Document OpenFGA's own result-count behavior/limits for `list-objects`
in `docs/architecture.md`; consider a `limit`/pagination passthrough if
and when the underlying OpenFGA API exposes one for this endpoint.
**Effort: S (docs) / M (real support).**
→ **Shipped (docs).** New "Known sharp edges" entry in
`docs/architecture.md` explaining OpenFGA's actual behavior here
(`--listObjectsMaxResults`/`--listObjectsDeadline`, and the
non-deterministic partial-result risk the deadline creates with no
in-response signal), when this call is and isn't appropriate, and the
recommended alternative for genuinely large result sets (page your own
resource table and `check()`/`batch_check()` per page, or bound the
query by a smaller scope like tenant/folder) rather than a `limit`
parameter this library can't actually implement — OpenFGA's
`list-objects` API exposes no cursor to paginate against.

**DX-5. The CLI has no multi-tenant operation, and `generate-model` skips
validation that `sync` performs.** `py-authz sync`
(`cli/commands/sync.py`) only ever targets one `--store-id` — there is no
CLI command wrapping `core/migrations_manager.py`'s `MigrationManager.
migrate_all()` for an operator rolling a model change out across every
tenant; they must write a bespoke script even though the library ships
the exact class for this. Separately, `generate-model`
(`cli/commands/generate.py`) never runs `DefaultModelValidator`, unlike
`sync` — a malformed model (including the undetectable cycles from ARCH-3)
can be "generated" and committed to version control or fed into CI
without ever failing fast.
→ Add `py-authz migrate --all-tenants` backed by `MigrationManager`; run
the validator in `generate-model` too (with a `--no-validate` escape
hatch if needed for iterating on an intentionally in-progress model).
**Effort: M.**
→ **Shipped 2026-08-31.** New `py-authz migrate` command
(`cli/commands/migrate.py`) wrapping `MigrationManager.migrate_all()`,
with `--backend {memory,postgres,redis}` + `--conn` selecting where
tenant→store mappings and model versions live, `--all-tenants` or
repeatable `--tenant` for an explicit subset. `generate-model` now runs
`DefaultModelValidator` by default, with `--no-validate` to opt out.
Building this required a real, previously-missing capability:
`TenantStore.list_tenant_ids()` — nothing could enumerate "every tenant
this store knows about" before now — implemented for
`InMemoryTenantStore`/`PostgresTenantStore` (`SELECT tenant_id FROM
tenants`)/`RedisTenantStore` (`SCAN` over `tenant:*:store`), with
`HybridTenantStore` delegating to Postgres (the source of truth; Redis is
only a TTL-bounded cache of individual lookups). Also fixed, found while
touching this code: `MigrationManager.migrate_tenant()` never closed the
per-tenant `OpenFGAClient` it created — a real leak, and a worse one here
than `MultiTenantAuthz`'s equivalent (REL-7, `03_reliability_and_
operations.md`) specifically because this command's whole point is
looping over every tenant in one process. **Confirmed against a real
OpenFGA + Redis stack**: seeded two tenants' mappings directly in Redis,
ran `migrate --all-tenants --backend redis`, confirmed both were found
and migrated, and that a second run was a true no-op (same model ids) —
this is also what surfaced DX-10 below.

### 🟢 LOW

**DX-6. The CLI has no top-level error handling or meaningful exit
codes.** `cli/main.py:56-65` calls `anyio.run(sync_command, ...)` with
nothing wrapping the dispatch — an `ExternalServiceError`/
`ConfigurationError` from `sync_command` propagates as a raw Python
traceback to the terminal, with no way for an automated CI pipeline to
branch on failure class (network vs. config vs. validation) beyond a
generic non-zero exit.
→ Wrap the dispatch in `try/except AuthzError` with a friendly message
and distinct exit codes per failure category. **Effort: S.**
→ **Shipped.** `cli/main.py` now wraps command dispatch in
`try/except AuthzError`, printing `Error: {message}` to stderr and
exiting with a code selected from the exception's most specific matching
type: `ConfigurationError` → 2, `InvalidAuthzRequest` → 3,
`ExternalServiceError` (and subclasses, e.g. `ServiceUnavailable`) → 4,
any other `AuthzError` → 1. A non-`AuthzError` exception (a genuine bug,
not a categorized failure) is deliberately left uncaught and still
surfaces its full traceback. `tests/cli/test_main.py` adds a
parametrized regression test over all four exit codes plus one
confirming non-`AuthzError` exceptions still propagate. **Confirmed live**:
running `py-authz sync` against an unreachable OpenFGA host now prints
`Error: Unable to connect to OpenFGA for GET
/stores/.../authorization-models` and exits `4`, instead of a raw
`httpx`/`ExternalServiceError` traceback.

**DX-7. Dead code and a naming collision, both easy but worth cleaning
up.** `adapters/fastapi.py:tenant_from_request()` is never called from
anywhere in the repository (see ARCH-4 in
`01_architecture_and_modeling.md`, which gives it a real home once the
multi-tenant FastAPI wiring lands). `modeling.decorators.require()`
collides in name with `Authz.require()` (ARCH-8, same file) — listed here
once for completeness, tracked and sized there.
→ No new work beyond what ARCH-4/ARCH-8 already schedule; this entry
exists so the DX angle on both isn't lost. **Effort: —.**

**DX-8. CI runs only after merge, not before, and has no version
matrix.** `.github/workflows/ci.yml:3-5` triggers solely on
`push: branches: [main]` — there's no `pull_request` trigger, so lint,
type-check, and tests all run *after* code has already landed on `main`,
not as a merge gate. It also runs a single OS/Python combination
(`ubuntu-latest`, whatever `uv` resolves from `requires-python = ">=3.13"`)
despite `pyproject.toml`'s classifiers claiming Python 3.12 support — a
claim that `requires-python = ">=3.13"` makes literally impossible, and
that no CI job tests either way.
→ Add `pull_request` to the workflow trigger and branch-protect `main` on
it; either drop the false Python 3.12 classifier or add a real version
matrix that includes it. **Effort: S.**
→ **Shipped (partially — one part needs a repo admin).**
`.github/workflows/ci.yml` now triggers on `pull_request: branches:
[main]` as well as `push`, so both jobs (lint/test and the live
integration suite) run as PR checks, not just after merge. The false
`Programming Language :: Python :: 3.12` classifier is removed from
`pyproject.toml` — `requires-python = ">=3.13"` already makes 3.12
support impossible, so a version matrix including it would fail by
design; dropping the claim was the correct fix, not adding one. **Not
done**: branch-protecting `main` on these checks is a GitHub repository
setting, not a file this audit can change — a repo admin needs to enable
"Require status checks to pass" for the `Lint & Test` (and optionally
`Live Integration Tests`) jobs under Settings → Branches, or this trigger
change is enforced by convention only, not actually blocking a merge.

---

## Next step

Every item in this file is shipped: DX-9, DX-1, DX-2, DX-3, DX-5, DX-10
(found via DX-5's own validation), and DX-4/DX-6/DX-8. DX-8's branch
protection half needs a repo admin to flip a GitHub setting (see its
entry above) — nothing else is open. DX-7 has no standalone work item
(tracked under ARCH-4/ARCH-8). Nothing left open in this file. Full
checklist:
[`04_developer_experience_and_testing_todos.md`](04_developer_experience_and_testing_todos.md).
