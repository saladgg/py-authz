# py-authz — Reliability, Storage & Operations Audit (Round 2)

**Date:** 2026-09-02 · repo as of `audit2` (post-1.3.0, after all of `01`–`04`
shipped).
**Scope:** storage backends (`storage/postgres.py`, `redis.py`,
`hybrid.py`), distributed locks (`core/locks.py`), the OpenFGA client
(`clients/openfga.py`), the audit backend (`audit/postgres.py`), the
caching layer (`cache/memory.py`, `redis.py`), CLI operational commands,
observability (`core/metrics.py`, `core/logging.py`), CI/CD & release
(`.github/workflows/*.yml`, `Makefile`, `docker-compose.yml`,
`.pre-commit-config.yaml`), and hot-path performance in
`core/enforcement.py`.
**Method:** read `docs/todos/03_reliability_and_operations*.md` in full
first to confirm REL-1…9 are genuinely shipped in the current tree (they
are), then re-audited the same surfaces for defects that survived or were
introduced by that remediation. Nothing below re-files a `03` finding.

This is the second audit filed against this repository's reliability and
operations surface. No 🔴 CRITICAL issues were found — the CRITICAL-shaped
bugs from the first audit (signature mismatches, broken sync, silent data
corruption) are gone and stayed gone. Everything below is HIGH-severity
availability/observability gaps, not correctness/data-loss bugs.

---

## 🟠 HIGH

**REL2-1. CI's "Format check" step doesn't check anything — it silently
reformats and always passes.** `.github/workflows/ci.yml:24-25`:
```yaml
    - name: Format check
      run: make format
```
`Makefile:60-67` defines both targets side by side:
```makefile
format: ## Format and fix
    uv run ruff format
    uv run ruff check --fix

format-check: ## Check formatting without changes
    uv run ruff format --check
```
CI calls the **mutating** `format` target (both subcommands rewrite files
and exit 0 as long as the result parses), not the non-mutating
`format-check` target that exists specifically for this purpose and sits
right next to it — `grep -rn "format-check"` only matches its own
definition; nothing in the repo ever invokes it. A PR with badly-formatted
or lint-violating (but auto-fixable) code passes this CI job every time:
`ruff format`/`ruff check --fix` just silently correct the ephemeral CI
checkout and exit success, and the actual PR diff is never validated. The
job's name and step name ("Format check") both imply a gate that isn't
actually there.
→ Change the CI step to `run: make format-check` (keep `make format` for
local dev use). **Effort: S.**
→ **Shipped 2026-09-02.** `.github/workflows/ci.yml`'s "Format check"
step now runs `make format-check` (non-mutating), not `make format`.

**REL2-2. `HybridTenantStore` fails closed on Redis errors instead of
degrading to Postgres — inverting the reliability benefit it exists for.**
`storage/hybrid.py:19-33`:
```python
async def get(self, tenant_id: str):
    cached = await self.redis.get(tenant_id)  # unguarded
    if cached:
        return cached
    store_id = await self.pg.get(tenant_id)
    ...


async def set(self, tenant_id: str, store_id: str):
    await self.pg.set(tenant_id, store_id)  # source of truth, succeeds
    await self.redis.set(tenant_id, store_id, ex=300)  # unguarded, no try/except
```
Neither call has error handling. The class's own docstring says "Redis
(cache) + Postgres (source of truth)," implying Postgres should be able to
serve on its own if Redis is unavailable — but a `ConnectionError`/timeout
from Redis propagates straight out of both methods. Two concrete
scenarios: (1) **Reads:** a Redis blip makes every tenant lookup fail even
though Postgres is completely healthy — a pure `PostgresTenantStore` alone
would have weathered this; wrapping it in `HybridTenantStore` makes tenant
resolution *less* available. (2) **Writes:** `TenantManager.provision()`
calls `tenant_store.set()` after `create_store()`/`syncer.sync()` have
already succeeded; if the Postgres write succeeds but the Redis write then
raises, `provision()`'s `except Exception:` logs `provision_failed` and
**re-raises**, even though the tenant was fully and correctly provisioned.
The caller sees a hard failure for an operation that actually succeeded
(a retry self-heals via `get()`'s Postgres fallback, so no data
corruption — but the false-negative failure signal is real operational
noise on exactly the hardened path REL-5/REL-6 focused on).
→ Wrap the Redis calls in `get()`/`set()` in try/except, log-and-continue
on cache failure, and fall through to/return the Postgres result.
**Effort: S.** *(No test covers this — `tests/storage/test_hybrid.py`
covers a cache *miss*, never a cache *error*.)*
→ **Shipped 2026-09-02.** `HybridTenantStore.get()`/`.set()` now route
their Redis calls through private `_redis_get()`/`_redis_set()` helpers
that catch any exception, log it (structured, via `json.dumps`), and
degrade to the Postgres result — a Redis outage can no longer make a
`get()` fail or a `set()` falsely report failure when Postgres itself
succeeded. New tests in `tests/storage/test_hybrid.py`
(`test_get_falls_back_to_pg_when_redis_get_raises`,
`test_set_succeeds_when_redis_set_raises`, and two more) cover both
methods with a Redis double that always raises.

**REL2-3. `OpenFGAClient`'s retry/backoff is wired to `check()` only —
every write and read-list operation gets zero retries on the exact same
transient errors.** `check()` (`clients/openfga.py:166-170`) is the only
caller of `retry_async`. `_request()` (lines 208-230) — the shared helper
behind `get_latest_model`, `create_store`, `list_objects`, and
`write_tuples` (including the REL-8-fixed chunked writes) — calls
`self._client.request(...)` directly with no retry wrapper at all.
Confirmed by test: `tests/clients/test_write_tuples.py::test_write_tuples
_maps_timeout`/`_maps_connect_error` assert a single transient error
causes `write_tuples()` to fail **immediately** — locking in "no retry" as
current, intended-looking behavior, even though `check()` a few lines away
would have retried the identical exception. A bulk grant via
`grant_many()` (REL-8's own fix target) issues chunked `write_tuples()`
calls; the exact transient blip `check()` would silently absorb causes
`write_tuples()` — and `create_store()`, used on every tenant-provisioning
call — to fail outright on the first hiccup. REL-8's chunking work makes
this *worse* in effect: a multi-chunk write now has more opportunities
(one per chunk) to hit a transient blip and abandon a partially-applied,
non-atomic write (acknowledged as possible by `write_tuples()`'s own
docstring, but with no retry to reduce how often it happens). Secondary
gap: `_request()`'s except clauses don't include `check()`'s catch-all
`except Exception:` fallback — a `json.JSONDecodeError` or
`httpx.RemoteProtocolError` propagates raw instead of being classified as
`ExternalServiceError`. *(Also flagged, in brief, from the architecture
angle as `ARCH2-15` in
[`05_architecture_and_modeling.md`](05_architecture_and_modeling.md) —
fix here, in full.)*
→ Route `_request()`'s HTTP call through the same
`retry_async(..., retryable=(httpx.TimeoutException, httpx.ConnectError))`
used by `check()`; add a catch-all exception handler matching `check()`'s.
For `write_tuples()`, retry per-chunk (not the whole multi-chunk
operation) so a transient failure on chunk 3 doesn't force re-sending
already-applied chunks 1-2. **Effort: M.**
→ **Shipped 2026-09-02.** `_request()` now routes its HTTP call through
the same `retry_async(...)` `check()` uses, plus a catch-all
`except Exception` mapping to `ExternalServiceError`, matching `check()`'s
own fallback. Per-chunk retry for `write_tuples()` falls out naturally —
each chunk's `_post()`/`_request()` call retries independently, so a
transient failure on one chunk never re-sends chunks that already
succeeded. New tests cover a retry-then-succeed case and the catch-all
mapping; the two existing "no retry" tests were made explicit
(`max_retries=0`) rather than accidentally-deterministic.

**REL2-4. Background audit-write tasks have no bound and no timeout on the
underlying Postgres call — sustained audit-sink degradation grows the task
set unboundedly.** `core/enforcement.py:275-277` (the SEC-3 fix):
```python
task = asyncio.ensure_future(self._log_audit_event(event))
self._background_audit_tasks.add(task)
task.add_done_callback(self._background_audit_tasks.discard)
```
`audit/postgres.py:30`: `self._pool = await asyncpg.create_pool(self.dsn)`
— no `command_timeout`, and `pool.acquire()` (`audit/postgres.py:60`) is
called with no `timeout=` either, so it blocks indefinitely if the pool is
exhausted or the write hangs. SEC-3's fix correctly took the audit write
off the synchronous `enforce()` hot path, but added no upper bound on how
many such background tasks can be in flight, and the thing they await has
no query/acquire timeout anywhere in its lifecycle. If the audit-sink
Postgres instance becomes unresponsive in a way that doesn't immediately
refuse the TCP connection (a network partition after connect, a long-held
lock, an overloaded replica), `conn.execute()` hangs forever rather than
timing out. Every `enforce()` call during that window spawns one more
never-completing task; `_background_audit_tasks` (and the
connections/coroutine memory backing each one) grows without bound for as
long as the outage lasts and the process keeps serving authorization
checks.
→ Set `command_timeout` on `asyncpg.create_pool(...)` (and/or pass
`timeout=` to `pool.acquire()`), and cap `_background_audit_tasks`'s size
(drop-and-log-a-warning past N in-flight audit writes, or use a bounded
queue with a dedicated drain worker instead of one ad-hoc task per
`enforce()` call). **Effort: M.** *(No test simulates an audit logger call
that never returns.)*
→ **Shipped 2026-09-02.** `PostgresAuditLogger` gained a
`command_timeout` parameter (default 5.0s), forwarded to both
`asyncpg.create_pool(...)` and `pool.acquire(timeout=...)`.
`AuthzEngine` gained `max_background_audit_tasks` (default 1000): once
that many writes are in flight, `_dispatch_audit_event()` drops (and
logs) further writes instead of adding another task to an
already-saturated backlog. New tests cover the pool-timeout wiring and,
using an audit logger that never returns, that the background-task set
stops growing at the configured cap.

---

## 🟡 MEDIUM

**REL2-5. `InMemoryCache` and the `Metrics` singleton both grow without
bound in a long-running process.**
`cache/memory.py:36,68-80` — `self._store: dict[str, tuple[bool, float]]
= {}`; expired entries are only purged lazily, on a subsequent `get()` for
that *same* key. A key written once and never read again stays forever —
no background reaper, no max-size/LRU eviction.
`core/metrics.py:22-25,28` — `observe()` does `self.durations.setdefault
(name, []).append(value)`; `AuthzEngine._record_metrics()`
(`enforcement.py:243-252`) calls this on **every** `enforce()` call when a
`metrics` object is injected, including the ready-to-use module-level
`metrics` singleton. `durations["authz_check_duration_ms"]` is a plain
list that only ever grows — nothing in the repo reads, drains, or
truncates it. Both are marketed as usable out-of-the-box components
(`InMemoryCache`'s docstring lists "small-scale applications"; `metrics`
is a plug-and-play module singleton), so wired into any process handling
sustained traffic, both leak memory for the life of the process — distinct
from the already-disclosed, deliberately-scoped "`MultiTenantAuthz`
cache is unbounded by design for a small tenant count" note.
→ `InMemoryCache`: add a max-size bound with LRU eviction or a periodic/
opportunistic sweep of expired keys independent of read access.
`Metrics.observe()`: cap `durations[name]`'s length (ring buffer) or
document explicitly that a caller must periodically drain/reset it before
using the singleton in production. **Effort: S–M.**
→ **Shipped 2026-09-02.** `InMemoryCache` now takes `max_size` (default
10,000) and uses an `OrderedDict` for combined TTL + LRU eviction
(`move_to_end()` on every access/write, `popitem(last=False)` once over
cap). `Metrics.observe()` now takes `max_observations_per_metric`
(default 10,000) and trims the oldest observation once a metric's bucket
exceeds it. `max_size=None`/`max_observations_per_metric=None` restores
the old unbounded behavior. New tests cover LRU eviction, LRU-refresh on
read, the observation cap, and the unbounded opt-outs.

**REL2-6. No cache-stampede protection on `enforce()`'s hot path.**
`core/enforcement.py:149-195` — on a cache miss, `enforce()` calls
`self.fga_client.check(...)` directly with no per-key coalescing/locking;
N concurrent `enforce()` calls for the identical `(user, action,
resource)` during the same cold window all independently call OpenFGA and
independently write the cache afterward. Not correctness-breaking (each
`check()` is idempotent), but a real, avoidable load amplification against
the exact dependency this library exists to protect, right after a cache
flush/restart or the instant a hot key's TTL expires.
→ Add single-flight de-duplication per cache key (an
`asyncio.Lock`/`Future` keyed on `cache_key()`, or a small in-flight-
requests map) so concurrent misses on the same key share one upstream
call. **Effort: M.**
→ **Shipped 2026-09-02.** New `AuthzEngine._check_upstream()`/
`_check_and_cache()`: a cache miss now checks `self._inflight_checks`
(keyed by the scoped cache key) for an already-running upstream `Task`
and awaits it instead of issuing a redundant `fga_client.check()` call;
the first caller for a key installs the task, and every caller shares its
result. Only applied when caching actually applies (`cache` configured
and the request is cacheable) — an uncacheable request or a cacheless
engine still calls straight through. New test: 10 concurrent `enforce()`
calls for the identical uncached request result in exactly one upstream
`check()` call; a companion test confirms distinct keys are never
coalesced together.

**REL2-7. `RedisLockManager`'s renewal loop dies silently on a transient
Redis error (not just "lock lost"), reopening REL-6's race with no timely
warning.** `core/locks.py:133-145`:
```python
async def _renew_loop() -> None:
    while True:
        try:
            await asyncio.wait_for(stop_event.wait(), timeout=interval)
            return
        except TimeoutError:
            renewed = await self._lock.renew(key, lock_id, ttl)  # can raise
            if not renewed:
                logger.warning(...)
                return
```
Only `asyncio.TimeoutError` is caught. If `self._lock.renew(...)` itself
raises — e.g. `redis.exceptions.ConnectionError` during a Redis network
blip, as opposed to the lock having legitimately expired — that exception
propagates out of `_renew_loop` uncaught, and the renewal task simply
stops, with no warning logged **until the surrounding critical section
finally exits** (too late to matter), unlike the "lock genuinely lost"
path which logs immediately. REL-6 shipped background renewal specifically
so a slow critical section doesn't lose its lock mid-operation — this
finding shows that guarantee only holds against "renewal completed and
found the lock gone," not "Redis itself hiccuped during renewal." During
that undetected gap, the exact race REL-6 exists to prevent (TTL expires,
a second caller acquires the "released" lock) can recur.
→ Catch broader transient exceptions inside `_renew_loop`'s per-iteration
renewal call, log a warning immediately (not just on task teardown), and
either retry the renewal within the same interval or treat repeated
renewal errors the same as "lock lost" for logging purposes. **Effort:
S.** *(`tests/core/test_locks.py::test_manager_lock_renewal_survives_lost
_lock_without_crashing` covers only the "renew returns False" path — no
test makes `renew()` raise.)*
→ **Shipped 2026-09-02.** `_renew_loop()`'s per-iteration `self._lock.
renew(...)` call is now wrapped in its own try/except: a transient
exception is logged immediately (`logger.exception`, not just on task
teardown) and the loop `continue`s to retry on the next interval, instead
of the exception escaping uncaught and silently killing the renewal task.
New test makes `renew()` raise twice (simulating a transient Redis
outage) then succeed, and confirms the critical section's lock is still
renewed and released cleanly.

**REL2-8. `py-authz migrate` leaks its Postgres/Redis tenant-store and
model-registry connections on every invocation.**
`cli/commands/migrate.py:40-78` (`migrate_command`) calls `_build_backends
(backend, conn)` (which for `--backend postgres` does `await
tenant_store.connect(); await model_registry.connect()`) and, after
`manager.migrate_all(ids)` completes, **never calls
`tenant_store.close()`/`model_registry.close()`** — no `try`/`finally`
around the function body, unlike `MigrationManager.migrate_tenant()`,
which does correctly close the per-tenant `OpenFGAClient` it owns. Each
`py-authz migrate --backend postgres` run opens an `asyncpg` pool (default
up to 10 connections) never released before process exit — harmless for a
one-off invocation, but a real leak in any wrapper that invokes
`migrate_command` repeatedly in-process (a scheduled job runner, a script
looping over environments) rather than exec'ing a fresh interpreter each
time. The `--backend redis` path compounds this: `RedisTenantStore`/
`RedisModelRegistry` don't even expose a `close()` method at all (see also
`ARCH2-18` in
[`05_architecture_and_modeling.md`](05_architecture_and_modeling.md) for
the related client-injection gap on these same classes).
→ Wrap `migrate_command`'s body in `try/finally` and call
`tenant_store.close()`/`model_registry.close()` (duck-typed via
`hasattr`, matching the REL-7 `Authz.aclose()` pattern) in the `finally`.
Add a `close()` no-op-safe method to `RedisTenantStore`/
`RedisModelRegistry` for symmetry. **Effort: S.**
→ **Shipped 2026-09-02.** `migrate_command`'s body now runs in a
`try/finally` calling a new `_close_backends()` helper (duck-typed via
`hasattr(..., "close")`) on both `tenant_store`/`model_registry`.
`RedisTenantStore`/`RedisModelRegistry` gained `close()` (shipped
alongside `05`'s ARCH2-18, which needed the same edit). New tests confirm
backends are closed on both the success and no-tenants-found paths.

**REL2-9. CLI exit-code mapping is incomplete for the most common
real-world CLI misconfigurations.** `cli/config.py:8`'s
`get_env(..., required=True)` and `cli/utils.py:15`'s `load_module()` both
raise plain `RuntimeError`; `core/migrations_manager.py:53` raises plain
`ValueError` for an unknown `--tenant`. `cli/main.py`'s `except AuthzError
as exc:` only catches `AuthzError` subclasses — by design (the comment
there frames anything else as "a genuine bug"), but that design choice
misclassifies the single most common real operator mistakes (forgetting
`FGA_API_URL`/`TENANT_STORE_CONN`, typo'ing `--tenant`) as bugs rather
than the `ConfigurationError`/`InvalidAuthzRequest` categories the
exit-code system exists to distinguish. *(This is the CLI-specific slice
of a broader pattern; see `ARCH2-5` in
[`05_architecture_and_modeling.md`](05_architecture_and_modeling.md) for
the fuller cluster, which also covers `validation/default.py` — fix both
together, in `05`'s todos.)*
→ Change `get_env(required=True)` to raise `ConfigurationError`,
`load_module()`'s failure to raise `ConfigurationError`, and
`migrate_tenant()`'s "tenant not found" to raise `InvalidAuthzRequest` (or
`TenantNotFoundError`) — all already-defined `AuthzError` subclasses with
exit codes assigned. **Effort: S.**
→ **Shipped 2026-09-02** as part of `05`'s ARCH2-5 (the fuller cluster,
which also covers `validation/default.py`'s bare `ValueError`) — fixed
there in full; see that file's todos for what changed.

**REL2-10. No dry-run or confirmation step for `migrate`/`sync`, and
`migrate --all-tenants` runs fully sequentially.** Neither `argparse`
subparser defines a `--dry-run` flag; `migrate_command`/`sync_command`
have no confirmation prompt before mutating every tenant's live OpenFGA
model. `core/migrations_manager.py:28-42`'s `migrate_all` is a plain
sequential `for` loop — one full model-sync HTTP round trip per tenant,
with no concurrency, in contrast to `AuthzEngine.bulk_enforce()`'s
`anyio.Semaphore`-bounded worker pool for the same "many independent
per-tenant operations" shape. `migrate --all-tenants` is a genuinely
destructive, hard-to-undo operation (overwrites every tenant's live
authorization model) with no preview and no interactive confirmation
before running against production; its sequential execution also means a
deployment with hundreds/thousands of tenants takes proportionally longer
to migrate, with no `--concurrency` knob.
→ Add `--dry-run` (print what would change per tenant without calling
`ModelSync.sync()`) and a `--yes`/confirmation gate for `--all-tenants`;
add bounded concurrency to `migrate_all()` mirroring `bulk_enforce()`'s
pattern. **Effort: M.**
→ **Shipped 2026-09-02.** New `MigrationManager.dry_run_tenant()`/
`dry_run_all()` (diff-only, never uploads or persists), wired to a new
`--dry-run` CLI flag. `--all-tenants` without `--yes` now prompts for
confirmation interactively, or — since blocking on `input()` forever in a
non-interactive context (CI) would be worse than the original gap —
raises `ConfigurationError` immediately when `sys.stdin.isatty()` is
`False`, requiring `--yes` explicitly there. `migrate_all()`'s bounded
concurrency shipped together with `05`'s ARCH2-10. New tests cover the
dry-run report, the TTY-vs-non-TTY confirmation paths, and decline/abort.

**REL2-11. `asyncpg` pools are created with zero timeout/sizing
configuration anywhere they're constructed.** All three call sites use the
bare form: `storage/postgres.py:37,96`, `audit/postgres.py:30`,
`storage/schema.py:42` — `await asyncpg.create_pool(self.dsn)`, no
`min_size`/`max_size`/`command_timeout`/`max_inactive_connection_lifetime`,
and no `timeout=` on any `pool.acquire()` call, nor exposed as a
constructor parameter. In production, a Postgres instance under load, a
network partition after the initial TCP handshake, or a long-held lock
will cause calls to hang indefinitely rather than fail fast — no bound on
how long `enforce()`'s background audit write (`REL2-4`) or a
`PostgresTenantStore.get()` call can block. Pool size also defaults to
`asyncpg`'s own default (`min_size=10, max_size=10`) regardless of the
host application's actual concurrency needs.
→ Accept `pool_min_size`/`pool_max_size`/`command_timeout` (or a raw
`**pool_kwargs`) on `PostgresTenantStore`/`PostgresModelRegistry`/
`PostgresAuditLogger`'s constructors and forward them to `create_pool()`;
pass an explicit `timeout=` to `pool.acquire()` calls on any
latency-sensitive path. **Effort: S.**
→ **Shipped 2026-09-02** for `PostgresTenantStore`/`PostgresModelRegistry`
(`storage/postgres.py`) — both gained `pool_min_size`/`pool_max_size`
(default 10/10, matching asyncpg's own prior implicit default) and
`command_timeout` (default 5.0s), forwarded to `create_pool()` and every
`pool.acquire(timeout=...)` call. `PostgresAuditLogger` was already fixed
in Tier 1 (REL2-4). `storage/schema.py`'s one-shot `apply_schema()` left
as-is — a handful of DDL statements run once at dev/test setup, not a
long-lived pool in the same risk category. New tests confirm both classes
forward the sizing/timeout kwargs correctly.

**REL2-12. `release.yml` installs its release toolchain with no version
pin.** `.github/workflows/release.yml:37`: `run: pip install
python-semantic-release build` — no `==` pin, no lockfile, on the workflow
that cuts every real release and publishes to PyPI (REL-9's own new job
depends on this one succeeding first). An upstream major-version release
of `python-semantic-release` can silently break the release pipeline the
next time it runs, with no signal until an actual release attempt fails —
and because this repo's own lockfile doesn't govern this workflow's Python
environment, `uv.lock` updates don't protect it either.
→ Pin `python-semantic-release` and `build` to specific versions (or a
compatible-release `~=` range) matching what's actually been validated.
**Effort: S.**
→ **Shipped 2026-09-02.** Pinned to `python-semantic-release==10.6.2
build==1.6.0` — the actual current released versions (checked live via
`uvx`, not guessed) at the time of this fix.

---

## 🟢 LOW

**REL2-13. Stale `.pre-commit-config.yaml` doesn't match the
CI-enforced toolchain.** Runs `black` (24.4.2) and `isort` (5.13.2) hooks
in addition to `ruff --fix`, while `pyproject.toml`'s `[tool.ruff.lint]
select` already includes `"I"` (import sorting), and the Makefile/CI
(per `REL2-1`) only ever invoke `ruff format`/`ruff check`, never `black`
or `isort`. A contributor's local pre-commit run can reformat/reorder code
differently than `ruff format`/the `"I"` ruleset would, creating spurious
pre-commit-vs-CI diffs once `REL2-1` is fixed. → Drop the `black`/`isort`
hooks, replace with `ruff format`/`ruff check --fix` pre-commit hooks,
matching the Makefile exactly. **Effort: S.**

**REL2-14. `make test-integration` doesn't wait for Redis readiness
before running live tests.** `Makefile:82-102` polls OpenFGA/Keycloak/
Postgres readiness before running `pytest tests/live`, but has no
equivalent wait for `redis`, which `test_redis_storage_live.py`/
`test_locks_live.py` depend on. Low risk in practice (`redis:7-alpine`
starts fast), but it's the one service with no readiness gate, and CI
runners are exactly the contended environment where that gap is most
likely to flake. → Add a `redis-cli -h ... ping` polling loop alongside
the other three. **Effort: S.**

**REL2-15. `docker-compose.yml` defines no `healthcheck:` on any
service.** Readiness is entirely reimplemented externally via the
Makefile's curl/`pg_isready` polling loops. Fine as long as `make
test-integration` is the only entry point, but `docker compose up -d` run
directly gives no `docker compose ps`-visible health status, and
`depends_on: condition: service_healthy` isn't usable. → Add native
`healthcheck:` blocks (reusing the same probes) so `docker compose ps`
and `depends_on` work without the Makefile's bespoke polling. **Effort:
S.**

**REL2-16. `enforce()` builds its structured log line unconditionally,
regardless of effective log level.** `core/enforcement.py:155-169,202-216`
both call `logger.info(json.dumps({...}))`; `json.dumps` on the full event
dict runs eagerly every call, even when the effective log level is above
`INFO` and the string would be discarded unused — avoidable CPU/allocation
overhead on a hot path meant to run on every authorization decision. →
Guard with `if logger.isEnabledFor(logging.INFO):` before building/
dumping the payload, or pass structured `extra=` fields and let a
formatter serialize only when actually emitted. **Effort: S.**

**REL2-17. No documented retention/rotation for `audit_logs`, and
`list_tenant_ids()` has no pagination.** `storage/sql/0003_audit_logs.sql`
already discloses, in a comment, that the table "grows without bound under
normal operation" and that retention/partitioning is "deliberately out of
scope" — an intentional, disclosed boundary, not a silent gap.
`list_tenant_ids()` (`storage/postgres.py`, `storage/redis.py`) loads the
entire tenant-id set into a Python list with no `LIMIT`/cursor pagination;
tenant counts are typically small (bounded by paying customers, not end
users), so this is unlikely to be a practical problem soon. Flagged for
completeness. → Ship an optional retention/partitioning migration (or
documentation pointer) for `audit_logs`; add offset/cursor pagination to
`list_tenant_ids()` if/when tenant counts grow large. **Effort: M
(retention), S (pagination).**

---

## Areas checked and found adequate — no new findings

`RedisLock.acquire()`/`release()` correctness and lock key construction
(TTL/NX semantics and the compare-and-delete Lua script are correct; no
key-collision risk — `py_authz:provision:{tenant_id}` namespacing is
consistent); CI running live/integration tests (`ci.yml`'s
`integration-test` job genuinely runs `tests/live/` against real Docker
Compose services in CI, matching what DX-9/REL-9 shipped); CI dependency
caching (`astral-sh/setup-uv@v5` with `enable-cache: true` present in both
jobs); `write_tuples()`'s chunking logic itself (correct and well-tested —
the gap found here, `REL2-3`, is specifically the *retry* layer around it,
not the chunking); `Authz.require()`/engine state concurrency (still
per-call, not mutated shared state); PyPI trusted-publisher OIDC wiring in
`release.yml` (structurally sound — the only gap, external
trusted-publisher registration, is already known and out of this repo's
control per REL-9).

---

## Next step

Nothing in this file is shipped yet — this is a freshly filed backlog.
[`07_reliability_and_operations_todos.md`](07_reliability_and_operations_todos.md).
