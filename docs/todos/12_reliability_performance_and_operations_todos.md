# py-authz — Reliability, Performance & Operations Backlog (Round 3)

Execution checklist for
[`12_reliability_performance_and_operations.md`](12_reliability_performance_and_operations.md).
IDs match that file.

> **Status (2026-11-24):** Tier 0 shipped (REL3-1, REL3-11, REL3-20,
> REL3-21), plus REL3-22 (CI hygiene) pulled forward since it touched
> the same workflow. Remaining tiers open.

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

- [ ] **REL3-2 — Lock tenant provisioning in the control plane**
  (`RedisLockManager` or a per-tenant `asyncio.Lock`, plus an
  `ON CONFLICT` insert).
- [ ] **REL3-6 — Retry non-idempotent calls only on connect errors.**
  Ship with `11`'s ARCH3-10.
- [ ] **REL3-5 — Default Redis socket/connect timeouts and a health-check
  interval.**
- [ ] **REL3-3 — Job runner: `BaseException`-safe status writes, startup
  reaper, bounded `aclose()`, partial/failed outcome, poller give-up.**
- [ ] **REL3-4 — `MultiTenantAuthz.evict()` on deprovision/provision,
  plus a store-scoped cache purge.** Ship with `10`'s SEC3-6/SEC3-7.

## Tier 2 — Probes, shutdown, capacity

- [ ] **REL3-7 — `/livez` + `/readyz` (Postgres, Redis, both OpenFGAs,
  no retries, 503 on failure).** Absorbs `11`'s ARCH3-15. Fix the test
  that asserts 200 when degraded.
- [ ] **REL3-13 — Argon2 off the event loop; verified-token cache;
  throttle `touch_last_used`.**
- [ ] **REL3-14 — One shared, configurable Postgres pool; one connection
  for DDL.**
- [ ] **REL3-8 — Flush audit on `aclose()`/teardown before closing the
  logger.**
- [ ] **REL3-9 — Per-tenant isolation in `dry_run_all`.**
- [ ] **REL3-12 — `AsyncExitStack` lifespan.**

## Tier 3 — Schema management and data-path scale

- [ ] **REL3-10 — `schema_migrations` table + advisory lock +
  `CONCURRENTLY` indexes + `CONTROL_PLANE_APPLY_SCHEMA` + a
  `py-authz db migrate` command.**
- [ ] **REL3-15 — Bounded `limit`/`offset` on every list route; keyset
  audit pagination; user/resource indexes.**
- [ ] **REL3-16 — Batched audit writer plus a dropped-events metric.**
- [ ] **REL3-17 — list-objects timeout and truncation; `page_size=1`;
  429/503 retry with jitter.**
- [ ] **REL3-18 — `SCAN COUNT 1000` plus pipelined `UNLINK`.**
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
- [ ] **REL3-25 — See `10`'s SEC3-9.**
