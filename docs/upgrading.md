# Upgrading

What you have to do, or should know, when moving between releases.
`CHANGELOG.md` lists every change; this page lists only the ones that can
break or surprise an existing deployment. Newest first.

## Unreleased

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
