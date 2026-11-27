# Upgrading

What you have to do, or should know, when moving between releases.
`CHANGELOG.md` lists every change; this page lists only the ones that can
break or surprise an existing deployment. Newest first.

## Unreleased

- **Schema migrations are versioned** (REL3-10). `apply_schema()` records
  each file in a new `schema_migrations` table and runs it only once,
  under an advisory lock. On an existing database, the first run re-runs
  0001-0008 (all `IF NOT EXISTS`, so nothing changes) and records them.
  New: `py-authz db migrate` and `py-authz db status [--check]`. For
  production, set `CONTROL_PLANE_APPLY_SCHEMA=false` and run
  `py-authz db migrate` as a deploy step. `apply_schema()` now returns the
  versions it applied.
- **New migrations 0009 and 0010.** `0009` adds a nullable
  `audit_logs.store_id` (catalog-only, with a 5 s `lock_timeout`). `0010`
  adds `(user_id, timestamp, id)` and `(resource, timestamp, id)` indexes,
  built `CONCURRENTLY` so audit writes keep flowing. `0008` is now built
  `CONCURRENTLY` too. If you apply the files with your own tool, run
  0008 and 0010 outside a transaction, one statement at a time.
- **`AuditEvent.tenant_id` is now the tenant id; the store id moved to
  the new `AuditEvent.store_id`** (ARCH3-16). `tenant_id` used to hold the
  OpenFGA store id. Engines built by `MultiTenantAuthz` set both; a
  standalone `AuthzEngine` records `tenant_id=None` unless you pass
  `AuthzEngine(tenant_id=...)`. A custom `AuditLogger`, or anything that
  reads `audit_logs.tenant_id` directly, should switch to `store_id` where
  it meant the store. Rows written before the upgrade keep the store id in
  `tenant_id`; `GET /audit-logs?tenant_id=` still finds them, and
  `storage/sql/audit_logs_backfill_0009.example.sql` rewrites them if you
  want the columns consistent.
- **`GET /audit-logs` no longer 404s for an unknown tenant.** It returns
  that tenant id's rows, so a deprovisioned tenant's history stays
  readable. The response gains `next_cursor`; pass it back as `cursor`
  for keyset paging (REL3-15). `offset` still works, but not together
  with `cursor`. Rows include `store_id`.
- **The control plane batches audit writes** (REL3-16) through the new
  `BatchingAuditLogger`, which COPYs up to 500 events at a time.
  `PostgresAuditLogger.log()` now uses COPY too, and gains `log_many()`.
  Dropped events are counted in `audit_events_dropped_total` (queue full
  or engine backpressure) and failed writes in `audit_events_failed_total`.
  `AuthzEngine.flush_audit_logs()` also flushes a logger that has an
  async `flush()`.
- **The control plane caches RBAC decisions for 5 s** (REL3-19). A role
  grant or revoke takes effect at once on the replica that made it, and
  within `CONTROL_PLANE_RBAC_CACHE_TTL` seconds on the others. Set it to
  `0` for the old behaviour. `GET /auth/me` now records an operator's
  login at most every `CONTROL_PLANE_OPERATOR_LOGIN_INTERVAL` seconds;
  `OperatorStore.record_login()` returns `None` when it skips.
- **`AuthzEngine` takes `cache_ttl`** (default 60, unchanged) and
  `invalidate_identity_on_write`. `InMemoryCache` gains
  `delete_by_prefix()`.
- **`AuthzEngine.list_objects()` warns when a result reaches the server's
  cap** (REL3-17), and counts it in `authz_list_objects_truncated_total`.
  If your OpenFGA sets `OPENFGA_LIST_OBJECTS_MAX_RESULTS`, pass the same
  value as `OpenFGAClient(list_objects_max_results=...)`.
- **`testkit.InMemoryFGAClient` honours `user:*` wildcard tuples** in
  `check()`, as real OpenFGA does. A test that wrote a wildcard tuple and
  expected a denial was relying on the old bug.
- **New `prometheus` extra** (REL3-24, also in `all`):
  `py_authz.core.prometheus.PrometheusMetrics`. The control plane serves
  it at `/metrics` with `CONTROL_PLANE_PROMETHEUS_METRICS=true`, and now
  records request count, 5xx count and duration.
- **Model validation is stricter (ARCH3-6).** `DefaultModelValidator` (run
  by `py-authz generate-model`, `py-authz sync` and `ModelSync`) now
  rejects models that real OpenFGA would reject at upload: duplicate
  types, a `from_parent` tupleset that isn't a relation on the type, a
  computed relation that none of the tupleset's subject types define, and
  subject types (or `type#relation` usersets) the model doesn't define.
  Such a model used to fail only at upload; it now fails locally first.
- **Generator output changed for userset and wildcard subjects.**
  `Relation(subjects=["team#member"])` now emits `{"type": "team",
  "relation": "member"}` and `"user:*"` emits a wildcard. Both used to be
  emitted verbatim and rejected by OpenFGA, so no working model changes.
  A `ResourceModel` with `type = "user"` no longer produces a second
  `user` type, and two models with the same `type` are an error.
- **`Metrics.durations` values are `collections.deque`s**, not lists
  (REL3-24). Iteration, `len()` and `sum()` work as before; compare with
  `list(...)` if you compared against a list literal.
- **`InMemoryCache` TTLs use `time.monotonic()`** (DX3-5), so a wall-clock
  change no longer expires or resurrects entries.
- **Service-account lockout is per (account, client network)** (SEC3-13).
  Behind a reverse proxy, run uvicorn with `--proxy-headers
  --forwarded-allow-ips=<proxy>`, or every request looks like it comes
  from the proxy's network and the lockout behaves per account, as before.
- **`load_module` moved** to `py_authz.utils.modules`. The old
  `py_authz.cli.utils` import still works.
- **Python 3.12 is supported** (`requires-python` lowered from 3.13).
- **`project.version` is a plain PEP 440 version** (`2.0.0`, not
  `v2.0.0`). Tags stay `vX.Y.Z`.

## 2.0.0

- **`Relation(intersection=[...])` without `subjects` is no longer directly
  grantable** (ARCH3-4). Pass `subjects=["user"]` to keep the old
  behaviour. An explicit `subjects=[]` is now honoured. A relation defined
  only by `from_parent` or `intersection` has no direct subjects unless you
  pass them.
- **Service-account principals changed** from `service:<name>` to
  `service_account:<id>` (SEC3-2, SEC3-3), and scopes must be `Scope` enum
  values. Re-grant RBAC roles to existing service accounts under their new
  principal (`service_account:<id>`); grants under the old `service:`
  principal are no longer read.
- **`py-authz migrate --backend` has no default** (DX3-8). Pass `postgres`
  or `redis` (or set `TENANT_STORE_BACKEND`). `--all-tenants` that finds no
  tenants exits non-zero unless you pass `--allow-empty`.
- **The control plane's `/docs`, `/redoc` and `/openapi.json` are off by
  default** (SEC3-11). Set `CONTROL_PLANE_EXPOSE_DOCS=true` to serve them.
- **Model sync now compares conditions and wildcards** (ARCH3-3). The first
  sync after upgrading may upload a new model version for a store whose
  model only differed in those.
- **The `keycloak` extra requires `pyjwt>=2.15.0`.**

## 1.6.0

- **New Postgres tables** for the control plane: `operators`,
  `service_accounts`, `model_versions`, `control_plane_jobs`
  (`py_authz/storage/sql/0004`–`0007`), plus an index on
  `audit_logs(timestamp)` (`0008`). `apply_schema()` creates them; apply
  them out of band if you set `apply_schema_on_startup` to false.

## 1.4.0

- **The cache-key format changed** to length-prefixed fields
  (`AuthzRequest.cache_key()`), so entries written by an older version are
  never read again; they age out by TTL. Flush a shared Redis cache on
  upgrade if you'd rather not wait. The format is opaque: don't parse it.
