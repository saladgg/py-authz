# py-authz — Reliability, Performance & Operations Audit (Round 3)

**Date:** 2026-11-24 · repo as of `6a54c93` (1.6.0).
**Scope:** the enforcement hot path (coalescing, caching), the OpenFGA
client's retry semantics, Redis/Postgres resource use, the control
plane's lifespan, job runner, health and schema management, CI and
release workflows, container/compose setup, and observability.
**Method:** read `03`, `07` and `09` first. The unit suite passes (729).
Findings marked **REPRODUCED** were confirmed with scratch scripts. The
only overlap with `09` is its deliberately deferred multi-replica work
queue. REL3-3 is narrower than that: it happens with a single replica.

---

## Reliability

### 🟠 HIGH

**REL3-1. Cancelling one caller cancels every other request coalesced
onto the same in-flight OpenFGA check.** `core/enforcement.py:318-331`
(`_check_upstream`): waiters do `return await existing` (`:320`); the
owner does `task = asyncio.ensure_future(...)` (`:322`), then
`return await task` (`:325`). Neither await is shielded.
→ **Scenario:** requests A and B coalesce on one key and A's client
disconnects, or A hits a uvicorn or `anyio.move_on_after` timeout. The
shared task is cancelled, and B, an unrelated request, gets
`CancelledError`. That's a `BaseException`, so it escapes both
`except AuthzError` and the `fail_open` policy. REPRODUCED: `results:
['CancelledError', 'CancelledError']`. REL2-6's coalescing made this
possible. Under load on hot keys, one flaky client fans out failures.
→ **Fix:** `await asyncio.shield(task)` in both branches. The task
already removes itself from `_inflight_checks` when done, so its cache
write still lands. **Effort: S.** *(No test; REL2-6's tests cover
coalescing only.)*

**REL3-2. The control plane provisions tenants without a lock, so
concurrent requests create duplicate, orphaned OpenFGA stores.**
`control_plane/app.py:105-107` builds `TenantManager(api_url=...,
tenant_store=...)` with no `lock_manager`, even when `redis_url` is set.
`core/tenant_manager.py` skips locking entirely when
`lock_manager is None`.
→ **Scenario:** a double-clicked "Create tenant", or two replicas.
REPRODUCED: `returned: ['store0', 'store1']`, mapping `{'acme':
'store1'}`. Caller 1 is told `store0`, which is now permanently orphaned
in OpenFGA.
→ **Fix:** wire `RedisLockManager` when Redis is configured; otherwise an
in-process per-tenant `asyncio.Lock`. Also make the tenant-store insert
`ON CONFLICT DO NOTHING` and re-read, so the losing caller cleans up its
store. **Effort: S.**

**REL3-3. Jobs can stay `pending`/`running` forever; shutdown can hang
on a long job; an all-failed migration is reported `succeeded`.**
`control_plane/jobs.py:211-222`:
- `_run` calls `await self.store.mark_running(job_id)` (`:212`) outside
  the `try`.
- It catches only `except Exception` (`:216`), so `CancelledError`
  escapes without a status write.
- The `mark_finished` inside the except branch has no protection of its
  own.
- `aclose()` (`:228`) runs `asyncio.gather(*self._tasks)` with no timeout.
- Nothing at startup reaps rows orphaned by a previous process.

`routes/migrations.py:75-78`: a `migrate_all` where every tenant lands in
`failed` still ends `SUCCEEDED`.
→ REPRODUCED:
- `mark_running` fails → the row stays `pending` and the work never runs.
- `mark_finished` fails after a work error → the row stays `running`.
- `aclose()` blocks indefinitely on a long job.

A deploy during an all-tenant migration leaves a `running` row forever,
and `job-status-poller.tsx` polls it every 2 s indefinitely (each poll
costs a JWT validation, an operator upsert, an RBAC check and an audit
insert).
→ **Fix:**
- Wrap everything in `try … except BaseException`, with the status write
  in a `finally` under `asyncio.shield`.
- Add `started_at`/`heartbeat_at` columns. On startup,
  `UPDATE … SET status='failed', result_json='{"error":"interrupted"}'
  WHERE status IN ('pending','running')` (scoped by instance id once
  multi-replica).
- Bound `aclose()` (e.g. 30 s), then cancel and mark failed.
- Add a `partial`/`failed` outcome when `batch.failed` is non-empty, plus
  a `cancelled` status.
- Have the poller stop after N minutes.

**Effort: M.**

**REL3-4. After deprovisioning, the control plane keeps routing to the
deleted store.** `routes/tenants.py:65-76` calls only
`tenant_manager.deprovision`. `MultiTenantAuthz` keeps its
`_cache: OrderedDict` entry (tenant → `Authz` bound to the old store id),
and there's no `evict()`.
→ **Scenario:** deprovision `acme`, then re-provision `acme` with a new
store. `GET /tenants/acme/tuples` and grants keep hitting the deleted
store (OpenFGA 404 → 503) until restart or LRU eviction, on every
replica.
→ **Fix:** `MultiTenantAuthz.evict(tenant_id)`, called from both the
deprovision and provision routes, plus
`cache.delete_by_fragment(f"{store_id}:")` (using `10`'s SEC3-6 fixed
matcher). Pairs with SEC3-7's RBAC cleanup. **Effort: S.**

**REL3-5. Redis clients have no socket timeouts, so a black-holed Redis
stalls every authorization check.** `cache/redis.py:52`,
`storage/redis.py:13` and `control_plane/app.py:127` call
`redis.from_url(url)` with no `socket_timeout` or
`socket_connect_timeout` (redis-py's default is `None`). `enforce()`
awaits `self.cache.get(cache_key)` inline. REL2-2's and DX2's graceful
degradation catches **raised** errors, not hangs.
→ **Scenario:** a network partition where SYNs are dropped rather than
refused. Every `enforce()` blocks indefinitely, and so do the
`HybridTenantStore` Redis leg and `RedisRateLimiter`, so SA auth hangs
too.
→ **Fix:** default `socket_timeout=0.5`, `socket_connect_timeout=0.5`,
`health_check_interval=30` when building from a URL (overridable).
Optionally wrap cache calls in `asyncio.timeout()`. **Effort: S.**

**REL3-6. The OpenFGA client retries non-idempotent POSTs after a read
timeout.** `clients/openfga.py:211` and `:267`:
`retryable=(httpx.TimeoutException, httpx.ConnectError)` for every
method, including `create_store` (`POST /stores`, `:332`) and
`write_tuples` (`POST /write`, `:482`). `TimeoutException` includes
`ReadTimeout`, which can fire after the server has committed.
→ **Scenario:** a retried `create_store` creates a second, orphaned store.
A retried write gets "tuple already exists", so `grant()` raises even
though it succeeded, and every manual retry fails the same way.
→ **Fix:** for POST/DELETE, retry only `ConnectError`/`ConnectTimeout`
(the request never reached the server). Pair with `11`'s ARCH3-10
(idempotent write options) so writes become safely retryable.
**Effort: S.** *(REL2-3's tests assert that retries happen; add the
negative case.)*

**REL3-7. `/health` always returns 200, checks neither Postgres nor
Redis, probes the wrong OpenFGA, and can take more than 6 s.**
`routes/health.py:29-38` returns a plain dict, `{"status": "ok" if
healthy else "degraded"}`, so the status code is always 200
(`tests/control_plane/test_health_routes.py` asserts 200 when degraded).
The only probe is `get_latest_model()` on the RBAC client (see `11`'s
ARCH3-15) through the retrying client: worst case 3 × 2 s timeouts plus
backoff, past a typical 1 s probe timeout.
→ **Scenario:** Postgres is down, so every route 500s, but the load
balancer keeps routing because `/health` is 200.
→ **Fix:** split `/livez` (process alive) from `/readyz` (`SELECT 1` on
the pool, Redis `PING` if configured, OpenFGA product and RBAC with
`max_retries=0` and a 500 ms timeout, all under `asyncio.timeout`).
Return 503 on any failure, with no exception text (see `10`'s SEC3-11).
**Effort: S.**

### 🟡 MEDIUM

**REL3-8. Shutdown closes the audit pool without flushing in-flight
audit writes.** `app.py:185-195` (`_teardown`) closes
`multi_tenant_authz`, the RBAC client, the job runner, then
`_audit_logger`, and never calls `engine.flush_audit_logs()`.
`Authz.aclose()` (`api.py:494-507`) also only closes HTTP. A rolling
deploy right after a manual grant drops the audit row that carries the
mandatory `reason`/`actor` (CP-8/CP-18). → `Authz.aclose()` flushes with
a bound (e.g. 5 s), and teardown flushes every engine before closing the
logger. **Effort: S.**

**REL3-9. Migration dry run: one bad tenant gives a raw 500 and aborts
the whole preview.** `core/migrations_manager.py:165-174`
(`dry_run_all`) runs workers in a task group with no per-worker
isolation, unlike `migrate_all` (fixed in ARCH2-10).
`routes/migrations.py:71` runs it inline on the request. REPRODUCED:
`ExceptionGroup(TenantNotFoundError('ghost'))` → unhandled 500.
→ Capture errors per tenant and return `{would_change, failed}`. Run
large dry runs as a job too. **Effort: S.**

**REL3-10. Startup DDL runs on every boot with no lock, no version table,
and a blocking index build.** `app.py:87` calls `await
apply_schema(settings.postgres_dsn)` on every startup, which contradicts
`storage/schema.py:12-18` ("prefer applying this … rather than calling
`apply_schema()` at application startup"). There's no
`schema_migrations` table and no `pg_advisory_lock`.
`0008_audit_logs_timestamp_idx.sql` is a plain `CREATE INDEX`.
→ **Scenario:** upgrading a deployment with a large `audit_logs` builds
the index under a SHARE lock and blocks every audit INSERT. Background
audit tasks hit the 1000 cap and are dropped, and readiness hangs. Two
replicas booting together race on catalog entries. Any future
`ALTER TABLE` can't be expressed idempotently.
→ **Fix:** a `schema_migrations(version, applied_at)` table, a
`pg_advisory_lock` around `apply_schema`, `CREATE INDEX CONCURRENTLY`
(outside a transaction) for large tables,
`CONTROL_PLANE_APPLY_SCHEMA=false` for production, and a
`py-authz db migrate` CLI command. **Effort: M.**

**REL3-11. `CONTROL_PLANE_MIGRATION_CONCURRENCY` is parsed but never
used.** `settings.py:89,116` are the only references.
`routes/migrations.py:71,75` call `dry_run_all`/`migrate_all` with their
default of 10. → Pass `concurrency=settings.migration_concurrency`.
**Effort: S.**

### 🟢 LOW

**REL3-12. A partial `_wire` failure leaks pools, and one failing close
skips the rest of teardown.** `_lifespan` (`app.py:198-204`) awaits
`_wire()` before its `try`, so a failure partway (for example the RBAC
sync) never closes the pools opened earlier. In `_teardown`, an exception
in any close skips every close after it. → Use `contextlib.AsyncExitStack`.
**Effort: S.**

---

## Performance

### 🟠 HIGH

**REL3-13. Argon2 verification runs on the event loop for every
service-account request.** `control_plane/auth.py:84` calls
`verify_secret(...)` synchronously, with `time_cost=3` and
`memory_cost=19 MiB` (`security.py`). There's no `to_thread` and no
verified-token cache, and every request also does
`store.touch_last_used()`, a Postgres UPDATE (`:89`). REPRODUCED: about
26 ms per verify, and the loop stalled up to 81 ms with 5 concurrent
verifies. A CI SA polling `GET /migrations/{id}` at 30–40 rps saturates
the loop and adds latency to every operator request and to `/health`.
→ **Fix:** `await anyio.to_thread.run_sync(verify_secret, …)`; a
30–60 s in-memory cache keyed by `sha256(token)`, cleared on rotate and
revoke; throttle `touch_last_used` to once per minute. **Effort: S.**

**REL3-14. One control-plane replica opens about 60 Postgres connections
at boot, with no knobs.** Every pool uses `min_size == max_size`:

| Pool | Connections |
|---|---|
| tenant store | 10 |
| model registry | 10 |
| audit query | 10 |
| audit logger (asyncpg default, `audit/postgres.py:46`) | 10 |
| service accounts | 5 |
| operators | 5 |
| model versions | 5 |
| jobs | 5 |

That's 60 in total. `apply_schema` (`storage/schema.py:55`) opens another
default pool of 10 to run DDL on one connection. `ControlPlaneSettings`
has no pool-size settings.
→ **Scenario:** Postgres defaults to `max_connections=100`. Two replicas,
or one rolling deploy (60 old + 60 new + 10 DDL), give "too many clients"
errors: the control plane crash-loops, and audit writes fail for product
services sharing the database.
→ **Fix:** one shared `asyncpg.Pool` across all control-plane stores
(same DSN), `min=1`, `max` configurable via env; a single connection for
`apply_schema`. **Effort: M.**

### 🟡 MEDIUM

**REL3-15. List endpoints have no limit cap, audit uses OFFSET paging,
and audit filters lack indexes.** `routes/audit.py:26-27`
(`limit: int = 50, offset: int = 0`) has no `Query(ge=, le=)`. The same
is true of `/migrations` (`:100`), `/tenants` (`:43`), model history
(`models.py:107`) and tuple `page_size` (`tuples.py:28`). There's no
`le=` anywhere in `control_plane/`. `audit/postgres.py` orders by
`"timestamp" DESC, id DESC LIMIT … OFFSET …`, and the only indexes are
`(tenant_id, timestamp DESC)` and `(timestamp)`.
→ `?limit=100000000` loads the whole table into API memory. A negative
value surfaces as an asyncpg error (500). A user- or resource-filtered
query without a tenant walks the timestamp index across millions of rows,
and deep pages cost O(offset).
→ **Fix:** `Query(ge=1, le=500)` / `ge=0` everywhere; keyset pagination
on `(timestamp, id)`; indexes `(user_id, "timestamp" DESC)` and
`(resource, "timestamp" DESC)` via `CONCURRENTLY` (REL3-10). **Effort: M.**

**REL3-16. Every authorization decision does its own pooled INSERT.**
`core/enforcement.py:515` spawns one task per decision (cache hits
included), and `audit/postgres.py:76-101` does one `acquire` and one
`INSERT` per event. At a few thousand checks per second, 10 connections
saturate and the REL2-4 cap (`max_background_audit_tasks=1000`) starts
dropping events with only a warning log.
→ A queue-backed batch writer (`copy_records_to_table`, flushing every N
events or M ms) and an `audit_events_dropped_total` metric. **Effort: M.**

**REL3-17. OpenFGA client tuning gaps.**
- `list_objects` shares the 2 s default timeout and the read-timeout
  retries (`openfga.py:66`), even though OpenFGA's own list-objects
  deadline is 3 s. On large stores, every call times out client-side and
  is retried twice, tripling load on OpenFGA's most expensive endpoint.
- OpenFGA's result cap (default 1000) truncates silently, and nothing is
  surfaced to the caller.
- `get_latest_model` (`:315`) fetches a full page of models (no
  `page_size=1`) on every sync, dry run and health probe.
- 429/503 responses aren't retried, and backoff (`utils/retry.py`) has no
  jitter.

→ A per-operation timeout for list-objects, with no read-timeout retry;
document or surface truncation (or use streamed list-objects);
`?page_size=1`; retry 429/503 with full jitter. **Effort: S.**

**REL3-18. Cache stats and invalidation scan the keyspace with COUNT=10
and delete one key per round trip.** `cache/redis.py:112,144,176` call
`scan_iter(match=…)` with the default count, then do a per-key `DELETE`.
`GET /cache/stats` counts every key on each dashboard load. With 1M keys,
one request makes about 100k SCANs and up to 1M DELETEs.
→ `scan_iter(count=1000)` with pipelined `UNLINK` batches; cache the stat
or approximate it from `INFO keyspace`. **Effort: S.**

### 🟢 LOW

**REL3-19. Per-request writes and serial checks on the control-plane
auth path.** `auth.py:55` upserts `operators` on every operator request.
`effective_system_role` (`auth.py:302`) runs up to 5 sequential OpenFGA
checks, and the RBAC engine has no cache. → Upsert only when `last_seen`
is older than N minutes; run role checks concurrently or as one
`BatchCheck` (see `13`'s DX3-19); give the RBAC engine a short-TTL cache.
**Effort: S.**

---

## Operations

### 🟠 HIGH

**REL3-20. The release workflow isn't gated on CI.** `release.yml`
triggers on `push: branches: [main]` independently of `ci.yml`, with no
`needs`, no `workflow_run` and no concurrency group. A red `main` (merge
race, flaky integration) still gets tagged and released, and it would be
uploaded to PyPI once trusted publishing is registered. Two quick merges
race `semantic-release` on tag push.
→ Trigger on `workflow_run` of CI with `conclusion == 'success'`, or move
the release job into `ci.yml` with `needs: [lint-test, integration-test]`.
Add `concurrency: {group: release, cancel-in-progress: false}`.
**Effort: S.**

### 🟡 MEDIUM

**REL3-21. CI no longer runs `ruff check`, a regression introduced while
fixing REL2-1.** `Makefile:66-67` defines `format-check` as `ruff format
--check` only, and `:70-71` defines `lint` as `mypy` only. The only
`ruff check` left is inside the mutating `make format` (`:63`), which
REL2-1 rightly removed from CI. So the `S` (bandit) rules SEC2-8 added,
and that the code relies on via `# noqa: S608`, aren't enforced. README
and CONTRIBUTING both claim they are. → Add `uv run ruff check` to
`make lint`. **Effort: S.**

**REL3-22. CI hygiene.** Neither job has `timeout-minutes` (default
360 min; the Docker-based integration job can hang). There's no
`concurrency: cancel-in-progress` for PR pushes and no Python version
matrix (only 3.13; nothing tests 3.14 — see `13`'s DX3-11 on 3.12).
→ `timeout-minutes: 15/30`, a per-ref concurrency group, and a matrix.
**Effort: S.**

**REL3-23. No container images; the dev OpenFGA is in-memory.** There's
no `Dockerfile` anywhere. `docker-compose.yml` runs only OpenFGA,
Keycloak, Redis and Postgres. OpenFGA has no `OPENFGA_DATASTORE_ENGINE`,
so it uses the in-memory datastore. Postgres has no named volume, and
`keycloak:26.0` is a floating minor tag (the other images follow SEC2-9's
patch pinning).
→ `docker compose restart openfga` wipes every store, including the RBAC
store named by `CONTROL_PLANE_FGA_STORE_ID`, so the control plane can't
boot and the `tenants` rows point at nothing.
→ **Fix:** OpenFGA on the existing Postgres (plus a `migrate` init
service), a named volume, a patch-pinned Keycloak tag, and reference
Dockerfiles: a Python slim image running non-root uvicorn with
`--timeout-graceful-shutdown`, and a Next.js `output: "standalone"`
image. Add compose services with healthchecks on `/readyz` (REL3-7).
**Effort: M.**

**REL3-24. Metrics are JSON-only behind auth, and `observe()` is O(n)
once full.** `core/metrics.py:43` uses `bucket.pop(0)` on a
10k-element list, so every observation shifts 10k floats on the hot
path. `/api/v1/metrics` returns JSON count/sum/avg (no percentiles) and
requires the `auditor` role, so Prometheus can't scrape it. There's no
request-duration metric for the control plane itself, and request logs
carry no request id even though `core/context.get_request_id` exists.
→ **Fix:** `collections.deque(maxlen=…)`; an optional `prometheus_client`
`Metrics` implementation (histograms labeled by relation, object type and
decision) served in text format on a network-restricted `/metrics`;
`request_id` in `logging_middleware.py`. Tracing is `13`'s DX3-20.
**Effort: M.**

### 🟢 LOW

**REL3-25. `InMemoryRateLimiter` never prunes keys that don't reach
lockout** (`rate_limit.py:75-83`). Covered by `10`'s SEC3-9; listed here
for completeness.

---

## Areas checked, no issue

- `HybridTenantStore` degradation paths and delete ordering (Postgres
  first, Redis best-effort).
- `PostgresTenantStore`/`PostgresModelRegistry` upserts, acquire
  timeouts, `list_tenant_ids` pagination.
- `RedisLockManager` compare-and-delete/expire scripts, renewal-loop
  resilience, stop-event shutdown.
- `write_tuples` chunking (100); `MultiTenantAuthz` LRU bound (apart from
  the eviction issue in `11`'s ARCH3-11).
- `RedisRateLimiter` INCR/EXPIRE semantics; the background-audit
  backpressure cap; `PostgresAuditLogger` `command_timeout`.
- OIDC JWKS caching and refresh lock; compose healthchecks;
  `make test-integration` readiness loops; pinned action SHAs and the
  pinned semantic-release.
