# py-authz — Reliability, Storage & Release Operations Audit

**Date:** 2026-08-31 · repo as of `revive_authz` (post-1.2.0).
**Scope:** everything that has to keep working unattended in production —
`storage/` (Postgres/Redis/hybrid tenant + model persistence),
`core/locks.py` (distributed locking), `core/tenant_manager.py`
(provisioning lifecycle), `MultiTenantAuthz`'s resource lifecycle,
`clients/openfga.py`'s write path, and the release/packaging pipeline.
**Method:** read each storage/lock/client implementation directly against
the other classes and callers it's meant to compose with (not just its
own unit tests), since several defects below only surface when two
shipped components are wired together — exactly the kind of bug an
audit-by-reading-in-isolation misses and an audit-by-composing catches.

This is the first audit filed against this repository.

---

## Storage layer

### 🔴 CRITICAL

**REL-1. `HybridTenantStore` is incompatible with the `RedisTenantStore`
it's documented to pair with.** `HybridTenantStore.set()`
(`storage/hybrid.py:22-24`) calls `self.redis.set(tenant_id, store_id,
ex=300)` — but `RedisTenantStore.set()` (`storage/redis.py:13-14`) has the
signature `set(self, tenant_id, store_id)`, with no `ex`/ttl parameter at
all. Constructing `HybridTenantStore(pg_store=PostgresTenantStore(...),
redis_store=RedisTenantStore(...))` exactly as the class's own docstring
("Redis (cache) + Postgres (source of truth)") suggests, then calling
`.set(...)`, raises `TypeError: set() got an unexpected keyword argument
'ex'` on the very first write. Neither class's own test file catches this:
`tests/storage/test_hybrid.py`'s `InMemoryRedis.set(self, key, value,
ex=None)` and `tests/storage/test_redis_storage.py`'s
`FakeAsyncRedis.set(self, key, value)` are two different bespoke doubles,
each shaped to make its own file's tests pass — nothing tests the two real
classes composed together, which is the only way `HybridTenantStore` is
meant to be used.
→ Add `ex`/`ttl` parameters to `RedisTenantStore.set`/
`RedisModelRegistry.set`. Add an integration-style test that constructs
`HybridTenantStore` from the two real (or realistically-faked) classes and
exercises `get`/`set` end to end. **Effort: S.**

**REL-2. `RedisTenantStore.get()` / `RedisModelRegistry.get()` return raw
bytes, not `str`.** Neither method (`storage/redis.py:10-11, 21-22`) calls
`.decode()` on the value returned by the real `redis.asyncio` client,
which returns `bytes`. Every caller — `MultiTenantAuthz.for_tenant()`
via a `TenantResolver`, `OpenFGAClient(store_id=...)` — expects a `str`.
This is masked in `tests/storage/test_redis_storage.py` because its
`FakeAsyncRedis.set()` stores whatever Python object it's handed (a plain
`str`) instead of encoding to `bytes` the way real `redis-py` does, so
`get()` in that test never actually returns `bytes` — the test double is
more forgiving than the real dependency it stands in for.
→ Decode in both `get()` methods, mirroring the correct pattern already
used in `cache/redis.py:68` (`value.decode() == "1"`). Update the test
double to byte-encode on `set()` so this class of bug is caught in the
future. **Effort: S.**

> **Fixing this surfaced a third, related bug in the same family:**
> `HybridTenantStore.get()` (`storage/hybrid.py:13`, pre-fix) itself called
> `cached.decode()` on whatever `self.redis.get(tenant_id)` returned —
> which only worked if `redis_store` were a *raw* `redis.asyncio.Redis`
> client (bytes-returning), not the `RedisTenantStore` wrapper the class's
> own docstring says it composes with. Once REL-2's fix makes
> `RedisTenantStore.get()` return an already-decoded `str`,
> `HybridTenantStore.get()`'s `.decode()` call would itself raise
> `AttributeError: 'str' object has no attribute 'decode'`. Fixed
> alongside REL-1/REL-2: `HybridTenantStore` now documents and expects
> both `pg_store`/`redis_store` to conform to the `TenantStore`-shaped
> contract (`get() -> str | None`) rather than assuming a raw client.

### 🟠 HIGH

**REL-3. The Postgres-backed stores have no connection lifecycle
management and ship no schema.** `PostgresTenantStore`,
`PostgresModelRegistry` (`storage/postgres.py`), and `PostgresAuditLogger`
(`audit/postgres.py`) all require an easy-to-forget explicit `.connect()`
before any use — calling `get`/`set`/`log` first raises a bare
`AttributeError: 'NoneType' object has no attribute 'acquire'` instead of
a clear `ConfigurationError`. None of the three expose a `close()`/
`disconnect()` to release the underlying `asyncpg.Pool` — a real leak in
any long-running process, and guaranteed in one-shot uses (CLI commands,
`MigrationManager` runs) that construct one, use it, and exit without ever
releasing it. There is also no schema tooling anywhere in the repository:
the `tenants`/`tenant_models` DDL exists only as a **module-docstring
comment** (`storage/postgres.py:3-15`), and the `audit_logs` table's DDL
doesn't exist at all — a user adopting `PostgresAuditLogger` must
reverse-engineer its column list from `audit/postgres.py:19-30`.
→ Provide an async factory/context-manager pattern that guarantees the
pool exists before use and is released after
(`async with PostgresTenantStore.connect(dsn) as store:`), and ship the
DDL as versioned SQL files (or a small bundled migration runner) instead
of a comment. **Effort: M.**
→ **Shipped.** `PostgresTenantStore`, `PostgresModelRegistry`
(`storage/postgres.py`), and `PostgresAuditLogger` (`audit/postgres.py`)
now share one lifecycle contract: idempotent `connect()`, `close()` that
releases the pool and is a no-op if never connected, `__aenter__`/
`__aexit__` for `async with Cls(dsn) as store: ...`, and a `_require_pool()`
guard so calling `get`/`set`/`log` before connecting raises a clear
`ConfigurationError` ("not connected — call `await store.connect()`
first...") instead of a bare `AttributeError`. The DDL shipped as three
versioned, idempotent SQL files
(`storage/sql/0001_tenants.sql`/`0002_tenant_models.sql`/
`0003_audit_logs.sql`, the last one new — `audit_logs` previously had no
DDL anywhere) plus `storage/schema.py:apply_schema(dsn)` to apply them in
order (documented as a dev/test convenience, not a replacement for a real
migration tool in production). Bundling the `.sql` files into the wheel
needed an explicit `[tool.setuptools.package-data]` entry in
`pyproject.toml` — this repo has no `MANIFEST.in`, so
`include-package-data = true` alone silently drops non-`.py` files from a
built wheel; verified by actually building a wheel and inspecting its
contents. New `docker-compose.yml` `postgres` service (host port 5433) and
`tests/live/test_postgres_storage_live.py` validate the whole thing —
`connect`/`get`/`set`/upsert/`list_tenant_ids`/pre-connect
`ConfigurationError` — against a real Postgres instance.

**REL-4. `PostgresAuditLogger.log()` likely fails on any non-trivial
`reason_data`.** `AuditEvent.reason_data` is typed `Any`
(`audit/types.py:21`) and `AuthzEngine` populates it with a Python `dict`
(`core/enforcement.py:195-198`), but `PostgresAuditLogger.log()`
(`audit/postgres.py:39`) passes it straight through as a positional
`asyncpg` bind parameter with no `json.dumps(...)` conversion and no
registered type codec — `asyncpg` does not auto-serialize a `dict` into a
`json`/`jsonb` column. Combined with REL-3 (no shipped schema for
`audit_logs`), it's not even verifiable from the repository whether that
column is `jsonb`, `json`, or `text`; whichever it is, the direct
dict-to-`execute` path is very likely to raise on first real use, and
nothing in `tests/audit/test_postgres.py` exercises this against a real
or realistically-typed connection.
→ `json.dumps(event.reason_data)` before binding, or register a
`codecs.set_type_codec` for the target column type on pool creation. Add
a docker-compose-backed integration test (ties to REL-9) that writes and
reads back a real audit row. **Effort: S.**
→ **Shipped.** `PostgresAuditLogger.log()` now does
`reason_data = None if event.reason_data is None else
json.dumps(event.reason_data)` before binding — `None` stays `None` (a
genuinely absent value), everything else becomes a JSON string the
`audit_logs.reason_data jsonb` column (shipped as part of REL-3's schema
work) accepts. `tests/live/test_audit_postgres_live.py` is the
regression test this finding specifically asked for: it writes a real
`AuditEvent` with a non-trivial `reason_data` dict through a real
`asyncpg` connection, reads the row back, and asserts the `jsonb` column
round-trips to the original dict — confirmed passing against a real
Postgres container (the pre-fix code raised `asyncpg.exceptions.DataError`
on this exact write).

**REL-5. `TenantManager.provision()` can mask its own root-cause exception
with an `UnboundLocalError`.** The `finally` block
(`tenant_manager.py:68-70`) references `store_id` in its log line before
`client.aclose()`. If `client.create_store(name=tenant_id)` itself raises
(`tenant_manager.py:59`), `store_id` is never assigned — the `finally`
clause's f-string then raises `UnboundLocalError: local variable
'store_id' referenced before assignment`, **replacing** the original,
actionable exception (e.g. "OpenFGA unreachable") with the least helpful
possible error, at the exact moment (tenant provisioning failure) an
operator most needs a clear signal. Confirmed untested:
`tests/core/test_tenant_manager.py`'s `FakeOpenFGAClient` has a
`create_store_error` field built for precisely this scenario, but no test
in the file ever sets it — only the "`ModelSync.sync()` raises" path
(where `store_id` is already assigned) is covered.
→ Assign `store_id = None` before the `try`; guard the log line and the
`aclose()` call so a `create_store()` failure surfaces its real exception.
Add the missing test using `create_store_error`. **Effort: S.**

**REL-6. Distributed provisioning locks have a fixed TTL with no renewal —
the exact race they exist to prevent can reoccur under load.**
`RedisLock.acquire()`'s default `ttl` is 30s (`core/locks.py:28`), and
`TenantManager._provision_lock()` never forwards a custom `ttl` to
`lock_manager.lock(...)` (`tenant_manager.py:78` — always the 30s
default). The work done under the lock — creating an OpenFGA store *and*
running a full model sync round-trip — has no guaranteed upper bound. If
that work takes longer than the lock's TTL (a slow/loaded OpenFGA
instance, network latency), Redis expires the key while the original
holder is still working, and a second concurrent request can acquire the
now-"released" lock and start a duplicate provision — reintroducing the
race the lock was built to prevent.
→ Either size the TTL to a safe multiple of expected provisioning
latency and make it configurable end-to-end, or add a background renewal
task that re-extends the TTL for as long as the critical section runs.
**Effort: M.**

**REL-7. `MultiTenantAuthz` never closes the clients it creates, and its
per-tenant cache has no eviction.** `for_tenant()` (`api.py:301-328`)
constructs a fresh `httpx.AsyncClient`-backed `OpenFGAClient` for every
new tenant and caches the wrapping `Authz` forever in `self._cache` — there
is no `aclose()`/shutdown method on `MultiTenantAuthz` at all. Every
distinct tenant a long-running process ever sees accumulates one open HTTP
connection pool and one cached `Authz`/`AuthzEngine`/`OpenFGAClient`
triple for the process's entire lifetime. For any deployment with more
than a small, fixed tenant count — which is the entire premise of
multi-tenant SaaS — this is an unbounded socket and memory leak.
→ Add `MultiTenantAuthz.aclose()` that closes every cached client, wired
into the host app's shutdown hook; add either an LRU/TTL eviction policy
on `self._cache` or explicit documentation that today's cache is only
suitable for a small, bounded tenant count. **Effort: M.**
→ **Shipped.** `Authz.aclose()` releases the underlying `OpenFGAClient`'s
connection pool (duck-typed on `hasattr(fga_client, "aclose")`, so a
caller-supplied fake client without one is tolerated).
`MultiTenantAuthz.aclose()` calls it on every cached tenant's `Authz` and
clears `self._cache`. No LRU/TTL eviction was added — `MultiTenantAuthz`'s
docstring now states plainly that the cache is unbounded by design and
meant for a small, fixed tenant count, with concrete guidance for anyone
outside that shape (wrap `for_tenant()` with your own bounded cache, or
skip caching if `tenant_resolver` is cheap). `examples/12_multitenant_fastapi.py`
now calls `mt.aclose()` in its `lifespan`'s shutdown phase, demonstrating
the intended wiring.

> **The same leak pattern was found (and fixed) in a second place while
> implementing DX-5's `migrate` CLI command**
> (`04_developer_experience_and_testing.md`):
> `MigrationManager.migrate_tenant()` (`core/migrations_manager.py`)
> constructed a per-tenant `OpenFGAClient` and never closed it either —
> arguably worse here, since that command's entire point is looping over
> every tenant in one process run. Fixed there directly (`try/finally:
> await client.aclose()`); this entry (`MultiTenantAuthz`) is still open.

**REL-8. `write_tuples()` has no chunking against OpenFGA's per-request
tuple limit.** OpenFGA caps a single `Write` request at 100 combined
tuple operations. `Authz.grant_many()`/`revoke_many()`
(`api.py:242-278`) pass an arbitrarily long list straight through to
`OpenFGAClient.write_tuples()` (`clients/openfga.py:299-322`) with no
batching. A caller granting permissions in bulk — seeding a new tenant,
an org-wide role change — over roughly 100 tuples gets an opaque
`ExternalServiceError` from OpenFGA's 400 response instead of automatic
chunking or even a clear "batch this yourself" error.
→ Chunk `writes`/`deletes` into ≤100-item batches inside `write_tuples()`
(or in `grant_many`/`revoke_many`), returning one logical result for the
whole call. **Effort: S.**
→ **Shipped.** `OpenFGAClient.write_tuples()` now chunks `writes`/
`deletes` into batches of at most 100 combined operations (OpenFGA's own
limit), issuing one sequential `Write` request per chunk — the "both fit
in one request" case (including the empty-payload case an existing test
locked in) is unchanged, so this is purely additive for the >100 case.
Documented as **not** atomic across chunks (each chunk is its own atomic
Write; a mid-sequence failure leaves earlier chunks applied), matching
what OpenFGA itself would require for a request that size anyway.
**Confirmed against a real OpenFGA instance**: new
`tests/live/test_tuples_live.py::test_grant_many_over_100_tuples_is_chunked_against_real_openfga`
grants 120 tuples in one `grant_many()` call and confirms every one is
queryable via `list_objects` — before this fix, OpenFGA's real server
rejects a >100-item Write with a 400, surfaced here as
`ExternalServiceError`.

### 🟡 MEDIUM

**REL-9. Nothing is published to PyPI — the README's own install
instructions don't work.** `pip install py-authz` (`README.md:113`) and
the PyPI badge (`README.md:8`, linking to
`https://pypi.org/project/py-authz/`) imply PyPI availability, but
`release.yml` only creates a GitHub Release with the sdist/wheel attached
(`upload_to_vcs_release = true`; no `pypa/gh-action-pypi-publish` step, no
`id-token: write` for trusted publishing) — **there is no PyPI package at
all**. The only install path that actually works today is the one the
maintainer's own scratch notes describe (`todos.md`): a direct
`pip install` against a GitHub release asset URL. Every `pip install
py-authz[...]` instruction across the README, `examples/README.md`, and
the Makefile's `install-core`/`install-extras`/`install-all` targets is
currently broken for a fresh consumer following the docs as written.
→ Publish to PyPI as part of the release workflow (trusted publishing via
OIDC is the modern, secretless approach and avoids managing a long-lived
API token), or, until that ships, rewrite every install instruction in the
repo to the working GitHub-release wheel URL so the docs aren't actively
wrong. **Effort: M.**
→ **Shipped (partially — the PyPI side needs a repo/PyPI-org admin).**
Discovered while fixing this: **this repository is currently private**
(`gh repo view` confirms `isPrivate: true`), which means the originally
suggested interim fix — "rewrite every install instruction to the working
GitHub-release wheel URL" — doesn't actually work either: a private
repo's release assets 404 for an unauthenticated `pip install` (confirmed
by actually requesting one). The real interim install path for anyone
with repo access is a Git URL, not a release-asset URL.
`.github/workflows/release.yml` gained a `publish-pypi` job: it runs only
when the `release` job's semantic-release step actually cut a new tag
(detected by comparing `git describe --tags` before/after, exposed as a
job output — semantic-release's CLI itself gives no simpler "did it
release" signal here), downloads the `dist/` artifact `semantic-release
publish`'s `build_command` already produced, and uploads it to PyPI via
`pypa/gh-action-pypi-publish` using OIDC trusted publishing
(`permissions: id-token: write`, `environment: pypi`) — no long-lived API
token to manage or leak. **Not done, and can't be from here**: trusted
publishing requires a PyPI project owner to register this exact
repo/workflow/environment as a trusted publisher on PyPI's side (and, if
`py-authz` doesn't exist there yet, either create it or use PyPI's
"pending publisher" flow) — that's an action on an external account this
audit has no access to. Until that registration happens, `publish-pypi`
will run on the next real release and fail at the publish step with an
authentication error; that's expected and will resolve itself the moment
the trusted publisher is configured, with no further code changes needed.
Meanwhile, `README.md`'s Installation section and the `Makefile`'s
`install-*` targets now state plainly that PyPI isn't available yet and
give the actual working command for someone with repo access
(`pip install "py-authz[...] @ git+https://github.com/saladgg/py-authz.git@vX.Y.Z"`).

---

## Next step

REL-1 through REL-9 are all shipped from this repository's side. REL-9's
PyPI-publish workflow is wired up and will fire on the next real release,
but it cannot complete until a PyPI project owner registers this repo as
a trusted publisher — that one external, account-level step is the only
thing left open anywhere in this backlog. Full checklist:
[`03_reliability_and_operations_todos.md`](03_reliability_and_operations_todos.md).
