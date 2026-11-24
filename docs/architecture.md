# Architecture

A deeper look at how py-authz is put together, how a request flows through
it, and where each extension point plugs in. The root README has a high-level
diagram; this doc is for readers who want to understand or extend the library.

---

## Design goals

1. **Framework-agnostic core.** Nothing under `py_authz/core/`, `py_authz/clients/`,
   or `py_authz/modeling/` imports a web framework. Web integrations live in
   `adapters/` and are pulled in lazily.
2. **Async-only.** Every public method is a coroutine. Callers own the event
   loop; the library never creates one for you.
3. **Minimal core deps.** `httpx`, `attrs`, `anyio`. Anything else —
   FastAPI, Redis, Postgres, Keycloak JWT — is an optional extra and is
   guarded by `utils/deps.py`.
4. **Explicit over implicit.** No globals for the engine, no thread-locals for
   the user. Pass the `Authz` instance around; carry `Identity` on
   `request.state` for HTTP. Configuration is code-first, too: there's no
   library-wide settings object or env-var-driven construction path —
   you build `OpenFGAClient`/`AuthzEngine`/etc. explicitly with whatever
   values you resolve yourself. The one exception is the CLI
   (`cli/config.py:get_env`), which is a standalone process, not a
   library import into a host app that already owns its own
   configuration story.
5. **Safe defaults, pluggable everything.** The cache, the tenant store, the
   JWT validator, the user getter — all swappable.

---

## Layers

```
┌─────────────────────────────────────────────────┐
│  adapters/     FastAPI, Keycloak                │
│  api.py        Authz, MultiTenantAuthz          │  ← public surface
├─────────────────────────────────────────────────┤
│  core/         AuthzEngine, tenant manager,     │
│                model sync/diff, migrations,     │  ← orchestration
│                exceptions, context (request-id) │
├─────────────────────────────────────────────────┤
│  modeling/     ResourceModel, Relation,         │  ← declarative schema
│                registry, generator              │
├─────────────────────────────────────────────────┤
│  clients/      OpenFGAClient (httpx + retries)  │  ← transport
├─────────────────────────────────────────────────┤
│  cache/        BaseCache, InMemoryCache,        │
│                RedisCache                       │
│  storage/      TenantStore, ModelRegistry       │  ← pluggable side-effects
│                (Postgres, Redis, hybrid)        │
│  audit/        AuditEvent + Postgres logger     │
└─────────────────────────────────────────────────┘
```

Dependencies flow downward only. `adapters/` imports `api.py`; `api.py`
imports `core/`; nothing in `core/` imports `adapters/`.

---

## Request lifecycle: a single `enforce` call

```
Authz.enforce(action, user, resource)
    │
    ├─ build AuthzRequest(identity, action, resource, context)
    │
    └→ AuthzEngine.enforce(request)
            │
            ├─ validate request (identity.id, action, resource.type/id)
            │
            ├─ cache.get(request.cache_key())        ← optional
            │     └── hit? log + return
            │
            ├─ fga_client.check(user, relation, object)   ← HTTP POST /stores/{id}/check
            │
            ├─ cache.set(request.cache_key(), allowed)    ← optional
            │
            ├─ structured log (request_id, tenant, user, relation, resource,
            │                  allowed, cache_hit, latency_ms)
            │
            ├─ dispatch audit_logger.log(event) as a          ← optional,
            │  background task (fire-and-forget; failures         backgrounded
            │  are caught and logged, never affect the result)
            │
            └─ raise AuthorizationDenied if !allowed and raise_on_denied
                else return allowed
```

Cache key: `"{user}:{action}:{type}:{id}"` — deterministic, so invalidation
from outside the engine is trivial. `AuthzEngine.invalidate(request)` removes
the entry for a given request.

---

## The modeling layer

`ResourceModel` uses a metaclass (`ResourceModelMeta`) to bind every
`Relation` attribute back to its owning class. That's what lets
`Document.editor` know it belongs to `Document`, so typed checks like
`authz.can(Document.editor, alice, doc)` work.

The metaclass does **not** auto-register the class itself — you must call
`registry.register(YourModel)`. This is intentional: tests often define
throwaway models that shouldn't pollute the global registry.

`OpenFGAModelGenerator.generate()` walks the registry and emits the OpenFGA
v1.1 JSON schema. `ModelSync.sync()` wraps it:

1. Generate local model.
2. Fetch current model from OpenFGA via `get_latest_model()`.
3. Normalize both with `ModelDiffer` (handles field ordering).
4. If equal and not `force=True`, return the existing `model_id`.
5. Otherwise POST the new model and return the fresh `model_id`.

This keeps deploy-time sync cheap and idempotent: running it on every
rollout is the intended pattern.

---

## OpenFGA client

`OpenFGAClient` is intentionally thin:

| Method | Endpoint |
| --- | --- |
| `check(user, relation, object)` | `POST /stores/{store_id}/check` |
| `write_tuples(writes, deletes=None)` | `POST /stores/{store_id}/write` |
| `get_latest_model()` | `GET /stores/{store_id}/authorization-models` |
| `create_store(name)` | `POST /stores` |
| `aclose()` | closes the underlying `httpx.AsyncClient` |

Retries are bounded and simple: timeouts and connection errors retry up to
`max_retries` with exponential backoff (100ms × 2^n). HTTP error responses
map to domain exceptions (`ServiceTimeout`, `ServiceUnavailable`,
`ExternalServiceError`) so callers can catch at the right granularity without
knowing about `httpx`.

`store_id` and `model_id` are mutable attributes — `TenantManager` relies on
that to create a store, then point the same client at it for model sync.

---

## Caching

`BaseCache` is a tiny ABC: `get`, `set`, `delete`, `clear`, all async.

| Implementation | When to use |
| --- | --- |
| `InMemoryCache` | dev, tests, or a single-worker process. TTL-based; thread-safe via `asyncio.Lock`. |
| `RedisCache` | multi-worker or multi-instance deployments. Prefixed keys (`py_authz:` by default), TTL via Redis `EX`. |

The engine is agnostic — if your custom cache implements the four methods,
it plugs in.

### Invalidation

There's no global "permission changed" event. If you revoke a permission,
call `AuthzEngine.invalidate(request)` with the same request shape, or delete
the key directly (`InMemoryCache.delete` / `RedisCache.delete`) using the
deterministic key format. For bulk invalidation patterns (e.g. "all keys for
this user"), use `RedisCache` and issue a `SCAN`-based delete out-of-band.

---

## Extension points

### `TenantResolver` + `TenantStore` + `TenantManager`

Multi-tenant mode separates three responsibilities:

- **`TenantResolver`** — given a `tenant_id`, return the OpenFGA `store_id`.
  `StaticTenantResolver` is a dict for tests; in production wrap your
  `TenantStore` so resolution is DB-backed.
- **`TenantStore`** — persistence for tenant → store mappings. Ships with
  `InMemoryTenantStore`; add Postgres/Redis implementations as you need them.
- **`TenantManager`** — provisions a new tenant atomically: create OpenFGA
  store → sync model → write mapping. Accepts an optional `lock_manager` so
  two concurrent requests for the same new tenant don't race; see
  `core/locks.py` for the distributed-lock interface.

`MultiTenantAuthz.for_tenant(tenant_id)` first consults the resolver; if it
raises, and a `tenant_manager` is configured, the manager provisions the
tenant. The returned `Authz` is cached per tenant on the `MultiTenantAuthz`
instance.

### `KeycloakJWTValidator.to_identity`

Override this when your OpenFGA user strings don't match the JWT `sub` claim:

```python
class AppValidator(KeycloakJWTValidator):
    def to_identity(self, payload):
        return Identity(id=f"user:{payload['preferred_username']}")
```

### FastAPI `user_getter` / `resource_getter`

`require_fastapi` and `require_dependency` both accept these hooks. The
defaults read `request.state.user` (set by the Keycloak middleware or your
own auth middleware) and build the resource from path/query params.

### Audit logging

Pass an `audit_logger` to `AuthzEngine`. It must expose an async `log(event)`
method receiving an `AuditEvent` (see `audit/types.py`). The engine dispatches
it as a background task after every decision — the write is never awaited
inline, so a slow or unhealthy audit sink adds no latency to (and cannot
fail) the authorization decision itself; failures inside `log()` are caught
and logged, never raised back to the caller. Call
`AuthzEngine.flush_audit_logs()` if you need to await any in-flight writes
(e.g. in tests, or before process shutdown) — a process that exits
immediately after its last `enforce()` call may otherwise drop the final
write(s). The bundled Postgres logger is in `audit/`.

---

## Newer APIs

Added alongside the core flow and worth knowing about:

- **`AuthzEngine.explain(request) -> AuthzExplanation`** — returns
  `allowed`, a human-readable `reason`, an optional `path`, and raw
  `details` from OpenFGA's explain endpoint (if the client supports it).
  Useful for "why was this denied?" UIs and debugging.
- **`AuthzEngine.bulk_enforce(requests, *, concurrency=10)`** — fans out to
  OpenFGA with bounded concurrency using an `anyio.Semaphore`. Returns a list
  of `BulkAuthzResult` in completion order (not input order).
- **`Authz.grant / revoke / grant_many / revoke_many`** — high-level tuple
  management, backed by `OpenFGAClient.write_tuples`. No need to drop to
  raw HTTP for permission changes.

These aren't on the `Authz` facade (except grant/revoke) yet; grab the engine
directly when you need explain or bulk.

---

## Exception hierarchy

All custom exceptions inherit from `AuthzError`:

```
AuthzError
├── AuthenticationError      — JWT/token problems
├── AuthorizationDenied      — raised by require() or raise_on_denied
├── InvalidAuthzRequest      — malformed AuthzRequest
├── ExternalServiceError     — catch-all for OpenFGA API failures
│   ├── ServiceUnavailable   — cannot connect
│   └── ServiceTimeout       — request timed out
├── ConfigurationError       — missing/invalid configuration
└── TenantNotFoundError      — raised by a TenantResolver for "no such
                               tenant yet"; the only exception
                               MultiTenantAuthz.for_tenant() treats as
                               license to auto-provision
```

Catch `AuthzError` at framework boundaries if you want one net for every
authorization failure; catch the specific subclass if you want different
behavior per failure mode (e.g. 401 vs 403 vs 503).

---

## Observability

- **Request-id propagation.** `request_context_middleware` (FastAPI adapter)
  generates an `X-Request-ID` per request and stores it in a `contextvars`
  `ContextVar` in `core/context.py`. The engine reads that var and tags every
  log line with `request_id`.
- **Structured logs.** The engine emits one JSON log per decision with
  `event`, `request_id`, `tenant`, `user`, `relation`, `resource`, `allowed`,
  `cache_hit`, `latency_ms`. Parse it with whatever log pipeline you already
  use.
- **Metrics.** Pass `metrics=` to `AuthzEngine` (e.g. the module-level
  `core/metrics.py:metrics` singleton, or your own object implementing
  `incr(name, amount=1)`/`observe(name, value)`) and `enforce()` records
  `authz_check_total`/`authz_allowed_total`/`authz_denied_total`/
  `authz_cache_hit_total` counters plus an `authz_check_duration_ms`
  observation per call. Like `cache`/`audit_logger`, this is an optional,
  explicitly-injected dependency — nothing is recorded unless you pass it
  in. Export `counters`/`durations` to your real metrics backend on
  whatever schedule suits it.

---

## Known sharp edges

- **`store_id` and `model_id` are mutable on `OpenFGAClient`.** Convenient
  (the tenant manager relies on it) but don't share a client between tenants.
- **Cache invalidation covers only the exact relation just written.**
  `Authz.grant`/`revoke`/`grant_many`/`revoke_many` invalidate the cache
  entry for the exact (identity, relation, resource) triple they just
  wrote — but not other relations implied by it through the model's
  union graph (e.g. granting `"owner"` doesn't proactively invalidate a
  cached `"editor"`/`"viewer"` check for the same resource), and not
  permission changes made outside these methods (e.g. another service
  writing tuples directly). Use short TTLs for eventual consistency on
  either case.
- **`InMemoryTenantStore` is process-local.** Only for tests / single-box
  dev. Multi-instance deployments need a persistent store.
- **`bulk_enforce` returns results out of input order.** Pair each result
  with `result.request` rather than zipping with the input list.
- **`list_objects` has no result-size guard, pagination, or a documented
  ceiling of its own — it inherits OpenFGA's.** `Authz.list_objects()` /
  `OpenFGAClient.list_objects()` wrap OpenFGA's `POST /list-objects`
  endpoint directly and return the entire response in one call. OpenFGA
  itself does not paginate this endpoint — it evaluates the model against
  every candidate object of the given type and returns all matches (or
  errors past its own configured limits: `--listObjectsMaxResults`, 0 =
  unlimited by default, and `--listObjectsDeadline`, 3s by default, which
  can make the endpoint return a *partial*, non-deterministic result if
  evaluation takes too long, without any signal in the response
  distinguishing "these are all the results" from "we ran out of time").
  Practically: this call is appropriate for "which of my org's ~dozens of
  projects can this user see" kinds of relations, not for "which of the
  10 million rows in this multi-tenant table can this admin see" —
  fan-out at that scale needs either OpenFGA's `--listObjectsMaxResults`
  tuned deliberately (and the resulting truncation handled), or (better,
  for genuinely large result sets) inverting the query: page through your
  own resource table and `check()`/`batch_check()` each page, or model
  the boundary you actually want to paginate (e.g. by tenant/folder) so a
  single `list_objects` call never needs to enumerate more than a bounded
  set. This library adds no `limit`/pagination parameter of its own,
  since OpenFGA's `list-objects` API doesn't expose a cursor to build one
  on top of — if/when it does, that's the natural place to add one here.
- **The library doesn't rate-limit its own outbound calls.** Nothing
  throttles calls into OpenFGA's `check`/`list-objects` endpoints or a
  JWKS endpoint on the library side — that's your host app's job (a
  reverse proxy, an API gateway, or a request-level limiter in front of
  routes that trigger authz checks). The one piece of rate-limiting the
  library does own is narrow and specific: `KeycloakJWTValidator`/
  `OIDCJWTValidator`'s `jwks_refresh_cooldown` caps how often an
  unrecognized `kid` can force a JWKS refetch (see SEC-1) — that's a
  self-protection mechanism for one internal code path, not a general
  rate-limiting feature.
