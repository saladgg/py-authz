# py-authz — Reliability, Performance & Operations Backlog (Round 3)

Execution checklist for
[`12_reliability_performance_and_operations.md`](12_reliability_performance_and_operations.md).
IDs match that file.

> **Status (2026-11-25):** Tier 0 shipped (REL3-1, REL3-11, REL3-20,
> REL3-21), plus REL3-22 (CI hygiene) pulled forward since it touched
> the same workflow. Second batch (2026-11-24): REL3-2, REL3-4, REL3-5 and
> REL3-18, then Tiers 1–2 in full and REL3-15/17 (partly). **Still open:**
> REL3-10 (schema migrations), REL3-16 (batched audit writes), REL3-19,
> REL3-23 (images/compose), REL3-24 (metrics; batch 3 shipped the deque
> and request ids, the Prometheus exporter is left), plus the noted
> remainders of REL3-14/15/17.

---

## Tier 0 — Gates and one-liners (ship first) ✅

- [x] **REL3-21 — `uv run ruff check` back in CI** (via `make lint`).
  `make lint` now runs `ruff check` then `mypy`. README and CONTRIBUTING
  rule lists now include `S`.
- [x] **REL3-20 — Gate the release on green CI; add a release
  concurrency group.**
  `release.yml` now triggers on `workflow_run` of CI (`completed`,
  `main`). The job runs only when that run concluded `success` on a
  `push` event. It checks out `main` (semantic-release needs a branch,
  not a detached SHA) and skips if `main` has moved past the commit CI
  verified, since the newer commit's own CI run will release it. Also
  added `concurrency: {group: release, cancel-in-progress: false}` and
  job timeouts. Not verifiable locally: confirm on the first merge to
  `main`.
- [x] **REL3-1 — `asyncio.shield` on both coalescing awaits.**
  Regression test: cancel the owner, the waiter still gets a result.
  Both awaits are shielded. The in-flight entry is now removed by a
  done-callback on the task itself, not by the owning caller's
  `finally`, so a cancelled owner no longer evicts an entry others are
  still coalescing on. The callback also retrieves the exception, so an
  owner-less failure doesn't log "never retrieved". Two new tests (cancel
  the owner, cancel a waiter) fail on the old code and pass now. The
  first also asserts the shared check still populates the cache.
- [x] **REL3-11 — Pass `migration_concurrency` through.**
  New `get_migration_concurrency` dependency, passed to both
  `dry_run_all` and `migrate_all`. Regression test
  `test_migration_concurrency_setting_is_passed_through`.

## Tier 1 — Data-integrity and hang risks

- [x] **REL3-2 — Lock tenant provisioning in the control plane**
  (`RedisLockManager` or a per-tenant `asyncio.Lock`, plus an
  `ON CONFLICT` insert).
  Shipped:
  - `_wire()` passes `RedisLockManager` when Redis is configured,
    otherwise the new `core.locks.InProcessLockManager`, which drops
    idle keys so it doesn't grow without bound. `TenantManager`'s
    existing re-check under the lock does the rest.
  - Tests: the unlocked case reproduces two stores; with the in-process
    lock, 5 concurrent provisions create one store; and a wiring check.
  - The `ON CONFLICT` insert was not added: the lock plus re-check
    already makes the loser reuse the winner's store.
- [x] **REL3-6 — Retry non-idempotent calls only on connect errors.**
  Ship with `11`'s ARCH3-10.
  Shipped: `_request(idempotent=...)`. Non-idempotent calls retry only
  `ConnectError`/`ConnectTimeout`/`PoolTimeout`. `create_store` and
  `write_authorization_model` are non-idempotent; writes count as
  idempotent when `idempotent_writes` is on. Tests cover both sides.
- [x] **REL3-5 — Default Redis socket/connect timeouts and a health-check
  interval.**
  `utils.deps.REDIS_CLIENT_DEFAULTS` (0.5 s socket, 0.5 s connect, 30 s
  health check) applies to every client built from a URL (`RedisCache`,
  `RedisTenantStore`/`RedisModelRegistry`, and the control plane). The
  control plane now opens **one** shared Redis client for the cache, the
  rate limiter and the provisioning lock, and closes it once.
- [x] **REL3-3 — Job runner: `BaseException`-safe status writes, startup
  reaper, bounded `aclose()`, partial/failed outcome, poller give-up.**
  Shipped: status is written in a shielded `finally` on every exit path,
  with `cancelled` on CancelledError and `failed` if `mark_running`
  fails. `JobStore.fail_interrupted()` reaps orphans at startup (assumes
  a single replica, as documented). `aclose()` waits up to 30 s, then
  cancels. Batch results with failures end `partial`/`failed`. The panel
  treats those as terminal and stops polling after 10 minutes. An
  existing test that asserted an all-failed migration was `succeeded`
  was corrected.
- [x] **REL3-4 — `MultiTenantAuthz.evict()` on deprovision/provision,
  plus a store-scoped cache purge.** Ship with `10`'s SEC3-6/SEC3-7.
  `MultiTenantAuthz.evict(tenant_id)` pops the entry under the
  resolution lock, closes it, and returns whether one was cached. The
  create, provision and deprovision routes evict, and deprovision also
  purges `f"{store_id}:"` from the cache. The library test shows
  re-resolution onto the new store; the route tests cover evict and
  purge.

## Tier 2 — Probes, shutdown, capacity

- [x] **REL3-7 — `/livez` + `/readyz` (Postgres, Redis, both OpenFGAs,
  no retries, 503 on failure).** Absorbs `11`'s ARCH3-15. Fix the test
  that asserts 200 when degraded.
  Shipped: `/livez`, plus `/readyz` (and `/health` as an alias) checking
  Postgres `SELECT 1`, Redis `PING` and OpenFGA `/healthz` concurrently,
  1 s each with no retries; any failure returns 503 with no exception
  text. The live test asserts all three checks are `ok` against the real
  stack.
- [x] **REL3-13 — Argon2 off the event loop; verified-token cache;
  throttle `touch_last_used`.**
  Shipped: argon2 runs in a worker thread. Successful verifications are
  cached against `(sha256(token), stored hash)`, so rotate/revoke
  invalidate immediately on every replica, with no TTL window.
  `touch_last_used` is throttled to once a minute.
- [x] **REL3-14 — One shared, configurable Postgres pool; one connection
  for DDL.**
  Partly shipped: per-store pools now start at 1 and grow to a
  configurable max (`CONTROL_PLANE_PG_POOL_MIN_SIZE`/`MAX_SIZE`, default
  1/5), down from about 60 fixed connections. `apply_schema` uses one
  connection, and `CONTROL_PLANE_APPLY_SCHEMA` can turn startup DDL off.
  Not done: one pool shared across all eight stores, which needs pool
  injection in each store class.
- [x] **REL3-8 — Flush audit on `aclose()`/teardown before closing the
  logger.**
  Shipped: `Authz.aclose(flush_audit_timeout=5)` flushes background
  audit writes first. The lifespan closes the audit logger only after
  every engine has flushed. Unit-tested.
- [x] **REL3-9 — Per-tenant isolation in `dry_run_all`.**
  Shipped: new `MigrationManager.dry_run_batch()` returns a
  `DryRunBatchResult(would_change, failed)`; the route and CLI use it.
  `dry_run_all()` keeps its contract but raises the first real error
  instead of an `ExceptionGroup`.
- [x] **REL3-12 — `AsyncExitStack` lifespan.**
  Shipped: the lifespan is built on `AsyncExitStack`, and each resource
  registers its cleanup when opened. Verified against real Postgres: 3
  startups that failed partway leaked 0 connections.

## Tier 3 — Schema management and data-path scale

- [ ] **REL3-10 — `schema_migrations` table + advisory lock +
  `CONCURRENTLY` indexes + `CONTROL_PLANE_APPLY_SCHEMA` + a
  `py-authz db migrate` command.**
- [x] **REL3-15 — Bounded `limit`/`offset` on every list route; keyset
  audit pagination; user/resource indexes.**
  Partly shipped: every list endpoint bounds `limit` (1..500) and
  `offset` (≥ 0), and tuple `page_size` is capped at 100. Tests run as a
  fully authorized caller. Not done: keyset audit pagination and the
  `user_id`/`resource` indexes, which wait on REL3-10's migration story
  (a plain `CREATE INDEX` at boot would block audit writes on a large
  table).
- [ ] **REL3-16 — Batched audit writer plus a dropped-events metric.**
- [x] **REL3-17 — list-objects timeout and truncation; `page_size=1`;
  429/503 retry with jitter.**
  Shipped: 429/502/503/504 are retried for idempotent calls, backoff is
  jittered, `list_objects` has its own 10 s timeout with no read-timeout
  retry, and `get_latest_model` uses `page_size=1`. Not done: surfacing
  list-objects truncation.
- [x] **REL3-18 — `SCAN COUNT 1000` plus pipelined `UNLINK`.**
  `RedisCache._delete_matching()` scans with `COUNT 1000` and UNLINKs
  in batches of 500. Used by `clear()`, `delete_by_fragment()` and
  `delete_by_prefix()`; `count_keys()` uses the large count too. Tested.
- [ ] **REL3-19 — Throttled operator upsert; concurrent or batched role
  checks; RBAC cache.**

## Tier 4 — Operability

- [x] **REL3-22 — CI timeouts, concurrency, Python matrix.**
  Pulled forward into Tier 0. Timeouts are 20 min (lint-test) and 30 min
  (integration). The per-ref concurrency group cancels superseded runs,
  except on `main`, where each run gates a release. `lint-test` runs a
  3.13/3.14 matrix: all 729 unit tests were run on 3.14 locally first
  and pass. Install also uses `uv sync --locked` (part of `10`'s
  SEC3-15), and `uv.lock` was refreshed (it was stale at 1.5.0).
- [ ] **REL3-23 — Persistent OpenFGA datastore, Postgres volume, pinned
  Keycloak; reference Dockerfiles (API + panel) with compose services.**
- [ ] **REL3-24 — `deque` metrics, an optional Prometheus exporter,
  request id in logs.**
  Partly shipped (batch 3): `Metrics.observe()` uses `deque(maxlen)`;
  control-plane request logs carry `request_id` (a safe caller
  `X-Request-ID` is reused) and echo it as a response header. Still open:
  the optional Prometheus exporter and a control-plane request-duration
  metric.
- [x] **REL3-25 — See `10`'s SEC3-9.**
  Shipped with `10`'s SEC3-9.
