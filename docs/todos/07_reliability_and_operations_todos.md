# py-authz — Reliability, Storage & Operations Backlog (Round 2)

Execution checklist for
[`07_reliability_and_operations.md`](07_reliability_and_operations.md).
IDs match that file.

> **Status (2026-09-05):** All tiers shipped — Tiers 0–2 (`REL2-1`
> through `REL2-12`) on 2026-09-02, and Tier 3 (`REL2-13` through
> `REL2-17`) on 2026-09-05. Nothing left open in this file.

---

## Tier 0 — Quick, high-value fixes (ship first) ✅

- [x] **REL2-1 — Fix CI's format check**: `ci.yml`'s "Format check" step
  now runs `make format-check` instead of `make format`, so it actually
  fails on unformatted/un-autofixed code instead of silently rewriting
  the ephemeral checkout and always passing.
- [x] **REL2-2 — Make `HybridTenantStore` degrade gracefully on Redis
  errors.** Redis calls in `get()`/`set()` now go through
  `_redis_get()`/`_redis_set()` helpers that catch, log, and degrade to
  the Postgres result. New tests in `tests/storage/test_hybrid.py` make
  the injected Redis double raise on `get`/`set` and assert Postgres is
  still correctly used (and that `set()` no longer falsely reports
  failure when only the Redis half failed).

## Tier 1 — Availability hardening on the enforcement/audit hot path ✅

- [x] **REL2-3 — Extend retry/backoff to `OpenFGAClient._request()`.**
  Routed through the same `retry_async(...)` used by `check()`, plus a
  catch-all `except Exception` matching `check()`'s fallback. Per-chunk
  retry for `write_tuples()` falls out naturally since each chunk's
  `_post()` call retries independently. New tests cover a
  retry-then-succeed case and the catch-all mapping; the two existing
  "no retry" tests now pass `max_retries=0` explicitly.
- [x] **REL2-4 — Bound and time-out the background audit-write path.**
  `PostgresAuditLogger` gained `command_timeout` (default 5.0s), forwarded
  to `create_pool()` and `pool.acquire(timeout=...)`. `AuthzEngine` gained
  `max_background_audit_tasks` (default 1000) — past that many in-flight
  writes, further ones are dropped and logged rather than queued. New
  tests cover the pool-timeout wiring and the background-task cap under a
  never-returning audit logger.

## Tier 2 — Independent reliability fixes ✅

- [x] **REL2-5 — Bound `InMemoryCache` and `Metrics`.** `InMemoryCache`
  gained `max_size` (default 10,000, LRU eviction via `OrderedDict`);
  `Metrics.observe()` gained `max_observations_per_metric` (default
  10,000, oldest trimmed first). `None` opts back into unbounded.
- [x] **REL2-6 — Add single-flight cache-stampede protection to
  `enforce()`.** New `_inflight_checks` map of scoped cache key → running
  `Task`; concurrent misses on the same key await the same task instead
  of each calling through. New tests confirm 10 concurrent misses on one
  key produce exactly one upstream call, and that distinct keys are never
  coalesced together.
- [x] **REL2-7 — Make `RedisLockManager`'s renewal loop resilient to
  transient Redis errors.** The per-iteration `renew()` call is now
  wrapped in its own try/except: logs immediately and retries next
  interval instead of silently dying. New test makes `renew()` raise
  twice then succeed.
- [x] **REL2-8 — Close backend connections in `migrate_command`.** New
  `_close_backends()` helper, called in a `try/finally` around the whole
  command body; `RedisTenantStore`/`RedisModelRegistry` gained `close()`
  (shipped alongside `05`'s ARCH2-18).
- [x] **REL2-9 — See `05`'s ARCH2-5** (CLI/migration exception-hierarchy
  cluster, which subsumes this file's narrower CLI-only framing) — fixed
  there (shipped 2026-09-02); this file's finding was a cross-reference
  only.
- [x] **REL2-10 — Add `--dry-run` and a confirmation gate to `migrate`;
  add bounded concurrency to `migrate_all()`.** New `MigrationManager.
  dry_run_tenant()`/`dry_run_all()` wired to a `--dry-run` flag;
  `--all-tenants` without `--yes` prompts interactively or refuses
  (`ConfigurationError`) when `sys.stdin` isn't a TTY; `migrate_all()`
  bounded concurrency shipped together with `05`'s ARCH2-10. (`sync`
  wasn't touched — it operates on one model upload, not a per-tenant
  batch, so a confirmation gate/dry-run there is a separate, smaller
  future item if wanted.)
- [x] **REL2-11 — Expose Postgres pool sizing/timeouts.**
  `PostgresTenantStore`/`PostgresModelRegistry` gained `pool_min_size`/
  `pool_max_size`/`command_timeout`, forwarded to `create_pool()` and
  every `pool.acquire(timeout=...)` call. `PostgresAuditLogger` already
  covered in Tier 1 (REL2-4).
- [x] **REL2-12 — Pin `release.yml`'s `pip install python-semantic-release
  build` line.** Pinned to the actual current released versions
  (`python-semantic-release==10.6.2 build==1.6.0`, checked live via `uvx`).

## Tier 3 — Low-effort operational polish (batch together) ✅

- [x] **REL2-13** — replace `.pre-commit-config.yaml`'s `black`/`isort`
  hooks with `ruff format`/`ruff check --fix`, matching the Makefile.
  `.pre-commit-config.yaml` now mirrors `ruff-pre-commit` at `v0.16.5`
  (matching the `ruff>=0.16.5` pin in `pyproject.toml`) with the standard
  `ruff --fix` + `ruff-format` hooks; the `black`/`isort` entries are gone.
- [x] **REL2-14** — add a Redis readiness poll (`redis-cli ping`) to
  `make test-integration`'s wait loop, alongside the existing OpenFGA/
  Keycloak/Postgres checks. New `docker exec redis redis-cli ping`
  polling loop added between the Keycloak and Postgres checks, same
  60-retry/1s-sleep style as the others.
- [x] **REL2-15** — add native `healthcheck:` blocks to every service in
  `docker-compose.yml`. `openfga` uses `grpc_health_probe` (the image ships
  no shell/curl/wget, but does ship this binary, confirmed live);
  `keycloak` uses a bash `/dev/tcp` probe against its management-interface
  `/health/ready` endpoint (also no curl in that image, confirmed live);
  `redis` uses `redis-cli ping`; `postgres` uses `pg_isready`. All four
  confirmed working against real containers before landing.
- [x] **REL2-16** — guard `enforce()`'s structured log calls with
  `logger.isEnabledFor(logging.INFO)` before building/serializing the
  payload. Both `logger.info(json.dumps(...))` call sites in `enforce()`
  (the cache-hit branch and the post-upstream-check branch) are now
  wrapped in `if logger.isEnabledFor(logging.INFO):`, with no change to
  what's logged when INFO is enabled.
- [x] **REL2-17** — ship an optional retention/partitioning migration (or
  documentation pointer) for `audit_logs`; add cursor/offset pagination to
  `list_tenant_ids()` if/when needed. New
  `py_authz/storage/sql/audit_logs_retention.example.sql` (not applied by
  `apply_schema()`) documents a periodic-delete query and a native-
  partitioning migration sketch, linked from `0003_audit_logs.sql`'s
  existing scope-disclosure comment.
  `PostgresTenantStore.list_tenant_ids()` gained `limit`/`offset` keyword
  arguments (SQL `LIMIT`/`OFFSET`, `None`/`0` defaults preserving the old
  unconditional behavior); `HybridTenantStore.list_tenant_ids()` forwards
  both straight through to its Postgres backend; `RedisTenantStore.
  list_tenant_ids()` gained a `limit` that stops its `SCAN` loop early
  (no `offset` there — `SCAN` gives no cross-call ordering guarantee for
  one to mean anything); `InMemoryTenantStore` gained matching `limit`/
  `offset` support for test/dev parity. New tests cover pagination on all
  four.

---

## Next step

Nothing is left open in this file — all four tiers (`REL2-1` through
`REL2-17`) are shipped.
