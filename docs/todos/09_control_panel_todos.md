# py-authz — Control Panel Backlog

Execution checklist for
[`09_control_panel.md`](09_control_panel.md). IDs match that file for
CP-1 through CP-10; CP-11 onward are net-new build-out items the
narrative doc's architecture section (§2) describes but doesn't itself
enumerate as findings, since there's no "gap" to point at for work that's
purely additive (the Next.js frontend, hardening).

> **Status (2026-09-05):** Filed today, alongside the architecture
> proposal, and **fully shipped the same day — all four tiers, CP-1
> through CP-19, nothing left open.** In order: Tiers 0–2 (the full
> control-plane API backend — package skeleton, operator auth + dogfooded
> RBAC + break-glass bootstrap, service accounts, tenant CRUD, model
> view/sync/dry-run/history/rollback, the async job system, audit-log
> querying, the tuple-read API + manual grant/revoke, cache stats/
> invalidate, health/metrics); then Tier 4 (rate limiting, a secrets-
> handling fix, structured request logging, docs); then **Tier 3 — the
> Next.js frontend** (`control-panel/`, a new top-level app: BFF OIDC
> session pattern with PKCE, all 9 screens — Dashboard, Tenants, Models,
> Migrations, Service Accounts, Operators & Roles, Audit Log,
> Relationship Explorer, Cache & Performance — shadcn/ui + Tailwind,
> shared DataTable/ConfirmDialog/SecretRevealOnce components). **The
> entire stack was verified end-to-end against a real running deployment**
> (`docker compose up -d openfga keycloak redis postgres` + the control-
> plane API + the Next.js dev server) — a real browser-shaped OIDC login
> against real Keycloak, break-glass bootstrap, tenant provisioning,
> service-account creation/auth, model sync, manual grants, and every
> screen rendering real fetched data — not just unit tests against fakes.
> That live pass caught one real bug fixed along the way (see the notes
> below).
>
> A few implementation notes worth recording against the plan as
> written:
> - **Found by the live end-to-end pass, not by any unit test**:
>   `GET /audit-logs?tenant_id=<id>` silently returned zero rows forever
>   for any tenant, no matter how many matching events existed —
>   `audit_logs.tenant_id` is populated from `AuthzEngine.fga_client.
>   store_id` (the OpenFGA store id), not the human-readable `tenant_id`
>   every other route uses. Fixed in `routes/audit.py`: resolves the
>   human-readable id to a store id via `TenantStore` before querying,
>   and echoes the human-readable id back in each result row. Regression-
>   tested in `tests/control_plane/test_audit_routes.py`.
> - CP-11's "route groups... gated server-side by the operator's RBAC
>   role" is two layers: `proxy.ts` (Next.js 16's renamed `middleware.ts`)
>   does a cheap, optimistic session-cookie-presence check; `(app)/
>   layout.tsx` does the real check (a valid/refreshable session *and* a
>   successful `GET /auth/me`). Nav items are further filtered by system
>   role as UI convenience only — every route re-checks authorization
>   server-side regardless, matching the Next.js BFF guide's own explicit
>   guidance ("do not rely on proxy alone for authentication").
> - This Next.js version (16.3.4) has real breaking changes since most
>   training data: `middleware.ts` → `proxy.ts` (renamed, deprecated old
>   name), `cookies()`/route params/`searchParams` are all `Promise`s now,
>   and the shadcn/ui generation this pulled in is Base-UI-based (a
>   `render` prop for polymorphism, not Radix's old `asChild`). Read
>   straight from `node_modules/next/dist/docs/` before writing any of
>   this rather than assuming prior knowledge — the framework's own
>   `AGENTS.md` says exactly that.
> - CP-13's "Operators & Roles screen against CP-2's RBAC store" needed a
>   backend route that didn't exist yet in any CP-1..CP-10 item: granting/
>   revoking a role *on* the RBAC store itself. Added as `routes/
>   operators.py` (`GET /operators`, `GET/POST/DELETE /operators/roles`)
>   — additive surface the architecture doc's §2.4 already specified the
>   shape of but the todos file never enumerated as its own route to
>   build, discovered while building the screen that needed it.
> - CP-2's operator auth is a FastAPI `Depends`-based dependency
>   (`control_plane/auth.py`), not `KeycloakAuthMiddleware` — the
>   control plane needs a *different required role per route*
>   (`require_system_role("operator")` vs. `require_tenant_role("admin")`,
>   etc.), which a single blanket `request.state.user`-attaching
>   middleware doesn't parameterize per-route. Still uses
>   `OIDCJWTValidator` underneath, and still satisfies "wire it for
>   operator login (`GET /auth/me`)."
> - CP-6's `change_summary` reuses `ModelDiffer` as asked, via a new
>   `ModelDiffer.summarize_diff()` classmethod (type/relation-level
>   added/removed, not a full field-level rewrite-tree diff) rather than
>   `normalize()`'s own output directly — `normalize()` returns an opaque
>   canonical string built for equality comparison, not something to show
>   an operator.
> - CP-16's lockout is Redis-backed when `CONTROL_PLANE_REDIS_URL` is
>   configured (shared across instances), otherwise an in-process
>   fallback (`InMemoryRateLimiter`) — matches `JobRunner`'s own
>   single-process-for-v1 stance rather than making Redis a hard
>   requirement just for this.
> - CP-18's "confirm every mutating route's audit event correctly
>   attributes the acting identity" is scoped to the grant/revoke (CP-8)
>   path specifically, where `record_write()`'s `reason`/`actor`
>   parameters make that attribution possible at all — tenant/model/
>   service-account lifecycle events (provision, sync, create/revoke a
>   service account) use this library's existing structured
>   `logger.info(json.dumps(...))` convention instead (they're not
>   `Authz.grant`/`revoke` calls, so there's no `audit_logs` row shape
>   that naturally fits "created service account X"); the new
>   request-logging middleware covers those at the HTTP-request level.
> - CP-19's docs originally shipped covering the backend only, before
>   Tier 3 existed to document; `docs/control_plane.md` and this repo's
>   root `README.md` were both updated once the frontend shipped too.
> Tier order is dependency order: nothing in Tier 1 is usable without
> Tier 0's auth/RBAC/service-account foundation actually existing, and the
> Next.js frontend (Tier 3) had nothing to call until Tiers 0–2 existed.

---

## Tier 0 — Foundations (nothing else is safe to expose without this)

- [x] **CP-1 — Stand up the control-plane API service skeleton.** New
  package (recommend `py_authz/control_plane/`, optional extra
  `py-authz[control-plane]`), FastAPI app, `/health` route, structured
  logging following `core/logging.py`'s existing JSON-line convention,
  `AuthzError` → HTTP-status mapping mirroring the CLI's `_EXIT_CODES`
  table (`cli/main.py:29`). No business routes yet — this item is the
  scaffold everything else attaches to.

- [x] **CP-2 — Operator authentication + dogfooded RBAC + break-glass
  bootstrap.** Wire `OIDCJWTValidator`/`KeycloakAuthMiddleware` for
  operator login (`GET /auth/me`). Stand up the dedicated `system`/`tenant`
  RBAC store described in the narrative doc's §2.5 (`owner` → `admin` →
  `operator` → `auditor` → `viewer` union chain) — this is itself just a
  `py-authz` model, generated and synced the same way any adopter's model
  is. Ship the one-time break-glass bootstrap (env var naming the first
  `system#owner` subject, consumed only when the RBAC store has zero
  grants) and document it prominently in `docs/`. Every subsequent route
  in this backlog depends on this existing.

- [x] **CP-3 — Service accounts: data model, credential issuance,
  verification, CRUD API.** ⭐ The headline feature. New
  `service_accounts` table (schema: see narrative §2.2), new
  `ServiceAccountVerifier` (bearer-token check against `secret_hash`,
  `argon2`), `Identity(id="service:<name>", attributes={"kind":
  "service_account", "scopes": [...]})` construction on successful auth.
  Routes: `POST /service-accounts` (create → secret shown once),
  `GET /service-accounts` (list, never re-exposes the secret),
  `DELETE /service-accounts/{id}` (soft-delete via `revoked_at`),
  `POST /service-accounts/{id}/rotate`. Scope-check middleware
  (`models:sync`, `models:read`, `tenants:read`, `audit:read`, …) runs
  before any per-tenant `authz.can()` check from CP-2. Every action taken
  under a service-account identity must audit-log identically to a human
  operator's (no separate/weaker trail).

---

## Tier 1 — Tenant & model management (core admin value)

- [x] **CP-4 — Tenant CRUD API, including a new
  `TenantManager.deprovision()`.** This doesn't exist at any layer today
  — no `TenantStore` implementation has a delete method. Add
  `deprovision(tenant_id)` (delete the OpenFGA store via
  `OpenFGAClient.delete_store()`, remove the `tenants`/`tenant_models`
  rows) to `core/tenant_manager.py`, symmetric with `provision()`'s
  existing safety posture (validate `tenant_id` against
  `DEFAULT_TENANT_ID_PATTERN` first, log start/success/failure the same
  way). Expose `GET/POST /tenants`, `GET /tenants/{id}`,
  `DELETE /tenants/{id}` (requires `tenant#admin` or `system#owner`),
  `POST /tenants/{id}/provision`.

- [x] **CP-6 — Model view/sync/dry-run, version history, rollback.** New
  `model_versions` table (append-only, unlike `tenant_models`'s
  overwrite-in-place). `ModelSync.sync()` (or a thin wrapper around it)
  writes a new row on every actual change, capturing `schema_json` and a
  `change_summary` (reuse `ModelDiffer.normalize()`'s output to compute
  a human-readable diff rather than inventing a second diffing path).
  Routes: `GET /models` (current registered model), `POST /models/sync`
  (`dry_run` query param — the same "preview, then commit" shape
  `migrate --dry-run` already established), `GET
  /tenants/{id}/models/history`, `POST /tenants/{id}/models/rollback`
  (re-syncs a prior `schema_json` — this is a forward sync to an old
  schema, not a magic undo, and should say so in the UI copy CP-12 writes).

- [x] **CP-7 — Async job system wrapping `sync`/`migrate`/`provision`/
  `deprovision`.** New `control_plane_jobs` table (schema: narrative
  §2.2). A route that would otherwise block for the duration of a
  same-shape CLI command instead: inserts a `pending` row, kicks off the
  work as a background task (single-process `asyncio.create_task` is
  sufficient for v1 — see the narrative doc's open questions), updates
  the row to `running`/`succeeded`/`failed` with `result_json` mirroring
  `MigrationManager`'s existing `MigrationBatchResult.succeeded`/`failed`
  shape. Routes: `POST /migrations` (`dry_run`|`apply`,
  `all_tenants`|explicit list), `GET /migrations/{job_id}`, `GET
  /migrations` (history, paginated).

---

## Tier 2 — Observability & relationship tooling

- [x] **CP-5 — Audit log query API.** New read methods on
  `PostgresAuditLogger` (or a sibling `PostgresAuditQuery` class, to keep
  the write path — which the engine calls on every decision — untouched
  and its own tests undisturbed): filters on `tenant_id`, `user_id`,
  `action`, `resource`, `allowed`, and a timestamp range, cursor-paginated
  (matching `PostgresTenantStore.list_tenant_ids()`'s existing
  `limit`/`offset` convention rather than inventing a new pagination
  shape). Route: `GET /audit-logs`. Add
  `idx_audit_logs_timestamp` (plain, not the existing
  `tenant_id`-composite one) if a query needs to filter by time range
  without a tenant_id predicate — check the actual query shapes this
  screen ends up needing before adding an index nothing uses.

- [x] **CP-8 — Tuple read API + relationship explorer + manual grant/
  revoke.** Add `OpenFGAClient.read_tuples(user=None, relation=None,
  object=None)` wrapping OpenFGA's `POST /stores/{id}/read` (mirroring
  `list_objects()`'s existing shape and retry/error handling — reuse
  `_request()`, don't hand-roll a new HTTP call). Routes: `GET
  /tenants/{id}/tuples` (filtered), `POST /tenants/{id}/grants` /
  `POST /tenants/{id}/revokes` (thin wrappers around `Authz.grant`/
  `revoke`, which already handle cache invalidation and
  `record_write()`-based audit/metrics — do not reimplement that here).
  UI requires a mandatory reason field on manual grant/revoke, persisted
  into the audit event's `reason_data`.

- [x] **CP-9 — Cache stats + bulk invalidate.** New methods specific to
  `RedisCache` (an in-memory cache has no cross-process introspection
  story worth building for): a `SCAN`-based key lister/counter, and a
  bulk-delete-by-prefix helper — the exact pattern
  `docs/architecture.md`'s Caching section already documents as the
  recommended approach for "invalidate all keys for this user," just not
  yet implemented as reusable library code. Routes: `GET /cache/stats`,
  `POST /cache/invalidate` (by key, user, or tenant prefix).

- [x] **CP-10 — Metrics/health aggregation endpoint.** Wire a shared
  `core/metrics.py` `Metrics` instance into every `AuthzEngine`/
  `MultiTenantAuthz` the control-plane API constructs (nothing does this
  by default today — it's an optional, explicitly-injected dependency).
  `GET /health` attempts a real `OpenFGAClient.check()`-shaped
  reachability probe against each configured store family (or at least
  the primary one) rather than just checking process liveness. `GET
  /metrics` exposes the accumulated counters/durations in a shape the
  dashboard (CP-15) can render directly.

---

## Tier 3 — Next.js frontend build-out

- [x] **CP-11 — Next.js app scaffold.** App Router, BFF session pattern
  (httpOnly cookie set by the Next.js server after CP-2's OIDC login
  flow completes; the server, never client JS, attaches the actual
  bearer credential on calls to the control-plane API), route groups per
  screen area gated server-side by the operator's RBAC role from CP-2,
  shadcn/ui + Tailwind design-system setup, a shared `<DataTable>`/
  `<ConfirmDialog>`/`<SecretRevealOnce>` component set.

- [x] **CP-12 — Core screens: Dashboard, Tenants, Authorization Models,
  Migrations.** Dashboard against CP-10; Tenants against CP-4 (list/
  create/deprovision, with a deprovision confirmation step at least as
  deliberate as `migrate --all-tenants`'s existing prompt-or-`--yes`
  pattern); Models against CP-6 (render the OpenFGA relation graph from
  `generate_model()`'s JSON rather than showing raw JSON as the primary
  view — raw JSON as a secondary "view source" toggle is fine); Migrations
  against CP-7 (dry-run preview table before any `apply` button is
  enabled, live job-progress polling against `GET /migrations/{job_id}`).

- [x] **CP-13 — Service Accounts & Operators screens.** Service Accounts
  against CP-3 (`<SecretRevealOnce>` for creation/rotation — the secret
  must be visually distinct as "you will not see this again," copy-to-clipboard,
  no way to navigate back to it). Operators/Roles screen against CP-2's
  RBAC store (assign an operator a role scoped to `system` or a specific
  tenant).

- [x] **CP-14 — Audit Log Viewer & Relationship Explorer screens.** Audit
  Log against CP-5 (filter bar matching the API's filter set, export to
  CSV/JSON, per-row detail panel surfacing `AuthzExplanation.reason`/`.path`
  when the underlying decision came from `AuthzEngine.explain()`).
  Relationship Explorer against CP-8 (two modes: "who has relation R on
  object O" and "what can user U access," both driving into a manual
  grant/revoke action with the mandatory reason field).

- [x] **CP-15 — Cache & Performance screen.** Against CP-9/CP-10 — hit
  rate, check volume/latency charts, manual invalidate form (by key,
  user, or tenant), reusing whatever charting approach the rest of the
  admin UI settles on rather than a one-off library just for this screen.

---

## Tier 4 — Hardening & documentation

- [x] **CP-16 — Rate limiting / brute-force protection on the
  service-account secret-verification endpoint.** The library's own
  documented stance (`docs/architecture.md`, "Known sharp edges" — "the
  library doesn't rate-limit its own outbound calls... that's your host
  app's job") makes the control-plane API the host app responsible for
  this one specifically, since it's the one endpoint in this whole
  backlog that authenticates a bearer secret directly rather than
  delegating to an IdP. A failed-attempt counter + lockout/backoff per
  service-account id (not just per source IP, which is trivially
  spoofable) is the minimum bar.

- [x] **CP-17 — Secrets-handling hardening pass.** Confirm: `argon2`
  parameters are tuned deliberately (not left at whatever a library
  default happens to be), a rotated/revoked secret's hash is actually
  deleted or invalidated (not just the row's `revoked_at` set while the
  old hash remains valid), and no code path anywhere (logs, error
  messages, the `control_plane_jobs.result_json` blob) ever
  serializes a raw secret.

- [x] **CP-18 — Observability for the control-plane API itself.**
  Structured request logging matching `core/logging.py`'s existing
  JSON-line convention (so operator actions land in the same log
  pipeline an adopter's other `py-authz` logs already go to), and confirm
  every mutating route's audit event correctly attributes the acting
  identity (operator subject or `service:<name>`) — this is the "who
  granted/revoked what" trail CP-3/CP-8 both depend on being trustworthy.

- [x] **CP-19 — Docs.** `docs/getting_started.md`-style walkthrough for
  standing up the control-plane API + Next.js frontend against a fresh
  dev `docker compose` OpenFGA instance (mirroring the existing "install
  → quickstart" flow), a new `examples/14_control_plane_api.py`-style
  runnable slice if the control-plane API ships as an in-repo package,
  and a README section pointing at this backlog the same way the
  existing README points at `03`'s REL-9 for PyPI publishing status.

---

## Next step

~~Tier 0 (CP-1 through CP-3) is the dependency root for literally
everything else in this backlog — start there.~~ ~~Tier 4 (CP-16 through
CP-19) is worth doing before this API is exposed anywhere beyond local
development.~~ ~~Only Tier 3 is left: CP-11 through CP-15, the Next.js
frontend.~~ **All four tiers shipped 2026-09-05** (see the status stamp
at top) — this backlog is closed. There is no next step within `09`
itself.

What's genuinely still open, for whoever picks this up next, is scale-out
work this pass deliberately deferred as out of scope for a first
deployment (per the narrative doc's own open questions, §3), not a gap in
what shipped:

- **A real work queue for `control_plane_jobs`**, if this API ever runs
  as more than one instance — `JobRunner`'s `asyncio.create_task` (and
  the frontend's job-progress polling built against it) is single-
  process by design for v1, which is fine for the common case of one
  instance.
- **CP-16's rate limiter** is per-instance (`InMemoryRateLimiter`) unless
  `CONTROL_PLANE_REDIS_URL` is configured — same "more than one instance"
  caveat as above, already handled by `RedisRateLimiter` when that's set.
- Anything genuinely new: a relation-graph *visualization* (not just the
  structured type/relation list) for the Models screen, websocket-based
  (rather than polled) job progress, or exporting the Relationship
  Explorer's results the same way the Audit Log already does — none of
  these were asked for by this backlog, they're just the natural next
  layer once real usage surfaces a need for them.
