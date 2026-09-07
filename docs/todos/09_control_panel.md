# py-authz — Control Panel Architecture & Gap Analysis

**Date:** 2026-09-05 · repo as of `7dc5939` (branch `control_panel`, tag
`v1.5.0`).
**Scope:** the full public surface a Next.js administration UI would need
to sit on top of — `py_authz/api.py`, `core/` (enforcement, tenant
manager, migrations manager, model sync/diff), `modeling/` (declarative
models + generator), `storage/` (Postgres/Redis tenant + model
registries), `audit/`, `adapters/` (FastAPI, Keycloak/OIDC), `cli/`, plus
`examples/` and `docs/`.
**Method:** full read of the public API, storage/audit schemas, CLI
commands, adapters, and test suite, cross-referenced against
`docs/architecture.md` and the eight existing audits (`01`–`08`) so this
doc doesn't re-litigate a finding one of them already owns.

This is a different kind of document from `01`–`08`: those are defect
audits against library behavior that already exists. This one is a
**gap analysis + architecture proposal** for something that does not
exist yet — a web-based control panel for operating a py-authz
deployment, and the backend surface it needs. Section 1 catalogs what's
missing today (severity-tagged `CP-N` findings, same convention as the
other backlogs); Section 2 proposes the target architecture; the paired
[`09_control_panel_todos.md`](09_control_panel_todos.md) turns both into
an execution plan. One design decision drives most of what follows: **the
control panel is a UI on top of a new HTTP management API, and that API
is a UI on top of `py-authz`'s existing Python surface** — nothing here
proposes reimplementing `AuthzEngine`, `ModelSync`, `TenantManager`, or
`MigrationManager`; it proposes exposing them.

---

## 1. Current-state gaps

Severity here means "how much this blocks the control panel from doing
anything useful," not "how exploitable is this bug" (`01`–`08`'s
convention) — none of these are defects in the library as shipped; they're
absences, because nothing has ever needed this surface before.

### 🔴 CRITICAL

**CP-1. There is no HTTP/REST surface anywhere in this repository —
every management operation is a direct Python call or a CLI
invocation.** Confirmed exhaustively: tenant provisioning
(`TenantManager.provision()`, `core/tenant_manager.py:62`), model
generation/sync (`generate_model()`, `ModelSync.sync()`), cross-tenant
migration (`MigrationManager.migrate_all()`, `core/migrations_manager.py`),
and audit logging are all Python-API-only or CLI-only (`generate-model`,
`sync`, `migrate` in `cli/main.py`). None of the four example FastAPI
apps (`examples/04`, `05`, `12`, `13`) exposes anything beyond
end-user-facing document routes — grepping `examples/` and `py_authz/`
for "admin"/"management" as an HTTP concept returns nothing. A Next.js
frontend cannot call any of this today; a new backend service is not
optional, it's the prerequisite for everything else in this doc.
→ Addressed by CP-1 in the todos file (control-plane API skeleton).

**CP-2. The library has no concept of an "operator" distinct from an
end-user `Identity`, and no permission model for who may provision
tenants, roll out models, or trigger a cross-tenant migration.**
`Identity` (`core/types.py:6`) is one undifferentiated dataclass used
identically for the subject of an authorization check. `TenantManager`,
`MigrationManager`, and `ModelSync` are plain Python objects with no
authorization check of their own — whatever process can construct them
(or run the CLI, which has zero auth of any kind) can provision tenants
and push a model to every tenant the store knows about. Standing up an
HTTP API in front of these without first answering "who is allowed to
call it, and for which tenants" would just make an already-unauthenticated
capability network-reachable.
→ Addressed by CP-2 (operator auth + RBAC, dogfooding py-authz itself —
see §2.5).

**CP-3. There is no service-account / machine-identity concept anywhere
in the codebase.** Exhaustive `grep -rniE
"service.?account|machine.?identity|api.?key|apikey|client.?credentials|\bm2m\b"`
across every `.py`/`.md` file in the repo returns **zero matches**. The
only trace of the idea at all is a single docstring example string on
`Identity` (`core/types.py:16`: `Example: "user:123", "service:billing-api"`)
— unenforced, undifferentiated, and never referenced by any adapter.
`OIDCJWTValidator.to_identity()`/`KeycloakJWTValidator` always build
`Identity(id=f"user:{sub}", ...)` from a human-oriented `sub` claim
(`adapters/oidc.py:279`); there is no client-credentials grant, no API
key, no signed machine token anywhere in `adapters/`. This is the
capability explicitly called out as must-not-miss for the control panel,
and it is a from-scratch build.
→ Addressed by CP-3 (highest-priority net-new feature; see §2.6).

### 🟠 HIGH

**CP-4. Tenants can be provisioned but never deprovisioned — not even at
the Python level.** `TenantManager` (`core/tenant_manager.py`) has
`provision()` and nothing else; no `TenantStore` implementation
(`InMemoryTenantStore`, `PostgresTenantStore`, `RedisTenantStore`,
`HybridTenantStore`) has a `delete`/`remove` method. "Deactivate a
customer" is a basic tenant-management operation and is currently
impossible without hand-writing SQL against `tenants`/`tenant_models` and
separately calling `OpenFGAClient.delete_store()` yourself.
→ CP-4 in the todos file.

**CP-5. The audit logger is write-only.** `AuditLogger`'s Protocol
(`audit/base.py`) declares only `log()`; `PostgresAuditLogger`
(`audit/postgres.py`) implements exactly that and nothing else — there is
no query method against the `audit_logs` table (schema:
`py_authz/storage/sql/0003_audit_logs.sql`, indexed only on
`(tenant_id, timestamp DESC)`). "Show me the audit trail" — the single
most obviously useful control-panel screen for a compliance-minded
adopter — requires new read methods that don't exist in any form today.
→ CP-5.

**CP-6. Authorization model definitions live only in Python source, with
no version history and no rollback.** `ResourceModel`/`Relation`
registration (`modeling/registry.py`) is a Python-import-time side
effect — the CLI's `--module` flag exists solely to trigger it
(`cli/main.py`). `PostgresModelRegistry`/`RedisModelRegistry` store
exactly one `model_id` per tenant (`tenant_models` table:
`tenant_id TEXT PRIMARY KEY, model_id TEXT NOT NULL` —
`storage/sql/0002_tenant_models.sql`), overwritten on every sync/migrate,
with no history table and no way to see *what changed* between two model
IDs beyond re-running `ModelDiffer` by hand. A "view model history / roll
back to the previous version" screen has nothing to read from.
→ CP-6.

### 🟡 MEDIUM

**CP-7. The three CLI commands that map most directly onto control-panel
actions (`generate-model`, `sync`, `migrate`) are synchronous, blocking,
unauthenticated, and leave no run history.** `migrate_command()`
(`cli/commands/migrate.py`) runs to completion in-process and prints to
stdout/stderr; nothing persists "who ran this, when, against which
tenants, what was the result" anywhere queryable. Wrapping these directly
in a request handler would mean an HTTP request blocks for as long as an
all-tenants migration takes (potentially minutes) with no way to check
progress from another tab or after a page reload.
→ CP-7 (async job system).

**CP-8. There is no tuple-read API.** `OpenFGAClient` (`clients/openfga.py`)
has `write_tuples()` but no counterpart wrapping OpenFGA's `POST
/stores/{id}/read` — the library can grant/revoke tuples and check/list
objects, but cannot answer "what relationships actually exist on this
object" or "what does this user hold, full stop" without either
`list_objects()` per relation-name-you-already-suspect or reaching
OpenFGA directly outside the library. A "who has access to X" /
"what can Y access" relationship explorer needs this.
→ CP-8.

**CP-9. Cache introspection is effectively nonexistent.** `BaseCache`
(`cache/base.py`) is `get`/`set`/`delete`/`clear` — a single-key or
clear-everything interface, no "list keys," no "invalidate by
pattern/user/tenant," no hit-rate accounting beyond what
`core/metrics.py`'s optional `Metrics` object records if a caller wires
it in (nothing does, by default). A "cache stats + bulk invalidate"
screen needs new methods on top of `RedisCache` specifically (`SCAN`-based,
per `docs/architecture.md`'s own noted pattern for bulk invalidation).
→ CP-9.

### 🟢 LOW

**CP-10. There's no aggregated health/metrics surface to build a
dashboard against.** `core/metrics.py`'s `Metrics` object accumulates
counters/durations in-process only if a caller explicitly passes
`metrics=` into `AuthzEngine`/`MultiTenantAuthz` — nothing exports it
anywhere, and there's no equivalent for "is OpenFGA reachable right now"
beyond attempting a real call and seeing if it raises
`ServiceUnavailable`. A dashboard's first screen ("is everything up, how
many checks/sec, what's the cache hit rate") needs a purpose-built
aggregation endpoint.
→ CP-10.

---

## 2. Target architecture

### 2.1 System shape

```
┌──────────────────────────────┐
│  Next.js control panel        │  ← browser: operators only, never
│  (App Router, BFF session)   │    holds OpenFGA/Postgres credentials
└──────────────┬────────────────┘
               │ HTTPS, operator session cookie
┌──────────────▼────────────────┐
│  Control-plane API (new)      │  ← FastAPI service, new package.
│  auth · RBAC · service accts  │    Only this tier holds infra creds.
│  tenants · models · migrations│
│  audit query · tuples · cache │
└──────────────┬────────────────┘
               │ imports, as a library — no HTTP hop
┌──────────────▼────────────────┐
│  py_authz (this library,      │  ← Authz / MultiTenantAuthz /
│  unchanged core + additions)  │    TenantManager / ModelSync /
│                                │    MigrationManager / audit query
└──────────────┬────────────────┘
               │
     ┌─────────┼─────────┬───────────────┐
     ▼         ▼         ▼               ▼
  OpenFGA   Postgres    Redis      OIDC/Keycloak
 (tuples,  (tenants,   (cache,     (operator +
  models)   models,     locks)      end-user auth)
            audit,
            new: operators,
            service_accounts,
            model_versions,
            jobs)
```

Two boundaries matter and must be enforced structurally, not just by
convention:

1. **The browser never talks to OpenFGA, Postgres, or Redis directly, and
   never holds a service-account credential.** Every control-panel action
   goes through the control-plane API over an operator's authenticated
   session (a BFF pattern — see §2.7). This mirrors the library's own
   "framework-agnostic core, adapters at the edge" philosophy
   (`docs/architecture.md` §Design goals #1): the control-plane API is
   just another adapter, this time HTTP-shaped instead of FastAPI-decorator-shaped.
2. **The control-plane API never reimplements engine logic.** It is a
   thin HTTP shell around `Authz`, `MultiTenantAuthz`, `TenantManager`,
   `ModelSync`, `MigrationManager`, and (new) an audit-query class and a
   service-account store. This keeps the actual authorization semantics
   (caching, model diffing, cycle detection, tuple chunking, retry/backoff)
   in exactly one place — the same place every other consumer of
   `py-authz` gets them from.

Where should this live? Recommend starting **inside this repo**, as a new
top-level package (e.g. `py_authz/control_plane/`, installable as a new
optional extra `py-authz[control-plane]`) rather than a separate
repository — the same way `adapters/` started as part of the core
library rather than a separate package, and split out only if/when it
needs its own release cadence. The Next.js frontend is a genuinely
separate deployable (a new top-level `control-panel/` directory,
scaffolded independently, calling the control-plane API over HTTP) —
there's no reason to vendor a JS toolchain into a Python package's
release process.

### 2.2 New data model

All new state lives in the **same Postgres instance** `PostgresTenantStore`/
`PostgresModelRegistry`/`PostgresAuditLogger` already use, as new tables
applied the same way (`storage/schema.py`'s `apply_schema()` pattern —
new versioned SQL files, `000N_*.sql`, idempotent `CREATE TABLE IF NOT
EXISTS`). No new database to operate.

| Table | Purpose |
| --- | --- |
| `operators` | Human control-panel users: `id`, `subject` (verified OIDC `sub`), `email`, `created_at`. Roles come from the dogfooded RBAC store (§2.5), not a column here. |
| `service_accounts` | `id`, `name`, `description`, `secret_hash` (argon2, never the plaintext), `scopes` (text[] — coarse-grained, e.g. `models:sync`, `tenants:read`), `created_by`, `created_at`, `last_used_at`, `revoked_at`. |
| `model_versions` | `tenant_id` (nullable — `NULL` for the global/single-tenant case), `model_id`, `schema_json`, `created_at`, `created_by` (operator or service account id), `change_summary`. Append-only — `tenant_models` keeps meaning "current," this is the history `tenant_models` never had (CP-6). |
| `control_plane_jobs` | `id`, `kind` (`sync` \| `migrate` \| `provision` \| `deprovision`), `status` (`pending` \| `running` \| `succeeded` \| `failed`), `params_json`, `result_json`, `initiated_by`, `started_at`, `finished_at`. Backs the async job system (CP-7). |

`audit_logs` itself needs no schema change — only new *read* methods
(CP-5) against the existing table.

### 2.3 Control-plane API surface (sketch)

REST, versioned under `/api/v1`. Every route below other than `/health`
requires an authenticated operator session **or** a service-account
bearer token with a matching scope (§2.6).

| Area | Routes |
| --- | --- |
| Auth | `POST /auth/login` (redirects into OIDC/Keycloak), `POST /auth/logout`, `GET /auth/me` (operator identity + effective roles) |
| Service accounts | `GET/POST /service-accounts`, `DELETE /service-accounts/{id}`, `POST /service-accounts/{id}/rotate` (returns the new secret exactly once) |
| Tenants | `GET/POST /tenants`, `GET /tenants/{id}`, `DELETE /tenants/{id}` (CP-4), `POST /tenants/{id}/provision` |
| Models | `GET /models` (current registered Python model), `POST /models/sync` (wraps `ModelSync.sync`, `dry_run` query param), `GET /tenants/{id}/models/history`, `POST /tenants/{id}/models/rollback` |
| Migrations | `POST /migrations` (`dry_run` \| `apply`, `all_tenants` \| explicit list — wraps `MigrationManager`), `GET /migrations/{job_id}`, `GET /migrations` (history, from `control_plane_jobs`) |
| Audit | `GET /audit-logs` (filters: `tenant_id`, `user_id`, `action`, `resource`, `allowed`, date range; cursor-paginated) |
| Relationships | `GET /tenants/{id}/tuples` (filters: `user`, `relation`, `object` — wraps a new `OpenFGAClient.read_tuples()`), `POST /tenants/{id}/grants`, `POST /tenants/{id}/revokes` (wrap `Authz.grant`/`revoke`, always audited) |
| Cache | `GET /cache/stats`, `POST /cache/invalidate` (by key, user, or tenant) |
| Health | `GET /health` (OpenFGA/Postgres/Redis reachability), `GET /metrics` (aggregated `core/metrics.py` counters) |

Every mutating route's handler calls exactly one `py_authz` public method
— the API layer's job is authn/authz, request validation, and shaping the
response, never reimplementing what `TenantManager`/`ModelSync`/
`MigrationManager` already do correctly (including their existing
safety behavior: `TenantManager.provision()`'s tenant-id pattern
validation, `migrate`'s dry-run/confirm flow, `write_tuples()`'s
100-tuple chunking).

### 2.4 Control panel screens & workflows

| Screen | Backs onto | Primary workflow |
| --- | --- | --- |
| **Dashboard** | `/health`, `/metrics` | At-a-glance system health, recent failed jobs, tenant count |
| **Tenants** | `/tenants` | List, search, create (provision), drill into one tenant's store/model/job history, deprovision with a confirmation step mirroring the CLI's `migrate --all-tenants` confirm-or-`--yes` pattern |
| **Authorization Models** | `/models`, `/tenants/{id}/models/*` | View current model (rendered from the same JSON `generate_model()` emits — a relation graph, not raw JSON, is the actual UX goal here), diff current vs. registered-in-code, version history, rollback, "sync now" with a dry-run preview before committing |
| **Migrations** | `/migrations` | Trigger a rollout (dry-run preview table first, always — CP-7/REL2-10's existing safety convention carried into the UI), live job progress, per-tenant success/failure breakdown, retry just the failed tenants |
| **Service Accounts** ⭐ | `/service-accounts` | Create (name + scopes → secret shown exactly once), list (name, scopes, last-used, created-by), revoke, rotate. This is the headline ask — see §2.6. |
| **Operators & Roles** | dogfooded RBAC store (§2.5) | Who can use the control panel and for what — assign an operator `owner`/`admin`/`auditor`/`viewer` on a tenant or the whole system |
| **Relationship Explorer** | `/tenants/{id}/tuples`, `/grants`, `/revokes` | "Who has `viewer` on `document:roadmap`?" / "What can `user:alice` access?" (via `list_objects` + the new tuple-read API), manual grant/revoke with a mandatory reason field feeding the audit trail |
| **Audit Log** | `/audit-logs` | Filter/search/export the existing `audit_logs` table; per-decision detail surfaces `AuthzExplanation` (`AuthzEngine.explain()`) when available |
| **Cache & Performance** | `/cache/*`, `/metrics` | Hit rate, check volume/latency, manual invalidate by user/tenant |

### 2.5 Permission model for the control panel itself

Rather than inventing a bespoke RBAC engine for "who can manage the
manager," **dogfood py-authz**: run a dedicated OpenFGA store (or a
reserved type namespace inside an existing one) whose resource types are
`system` and `tenant`, with relations `owner` → `admin` → `operator` →
`auditor` → `viewer` (a union chain, exactly the pattern
`docs/getting_started.md`'s own `Document` example teaches). `system#owner`
manages service accounts and other operators' roles; `tenant#admin`
manages that tenant's models/migrations/grants; `tenant#auditor` gets
read-only access to that tenant's audit log and relationship explorer.
This both proves the library on its own hardest use case and means the
control-plane API's authorization checks are `authz.can(...)` calls
identical in shape to everything else it wraps.

**Bootstrap problem:** the very first operator can't be granted a role by
an operator who doesn't exist yet. Resolve with a one-time, explicitly
documented break-glass step — an environment variable naming the first
`system#owner` subject, consumed only if the `operators`/RBAC store is
empty, the same shape as any "first superuser" bootstrap in comparable
admin tools. Document this loudly; it's a deliberate, narrow escape
hatch, not a general auth bypass.

### 2.6 Service accounts (headline feature)

This is the one gap (CP-3) explicitly called out as must-not-miss, and
the one with zero existing scaffolding anywhere in the library, so it
gets a full design, not just a checklist item:

- **Identity shape.** A service account authenticates to the
  control-plane API's routes (and, longer-term, to any host application
  wanting non-human callers) as `Identity(id="service:<name>",
  attributes={"kind": "service_account", "scopes": [...]})` — using
  exactly the string shape `core/types.py:16`'s docstring already
  gestures at, finally backed by real code.
- **Credential.** Client-secret style: creating a service account returns
  a secret exactly once (never retrievable again, only `secret_hash`
  persisted, `argon2` — never plaintext, never a reversible encoding).
  Authentication is `Authorization: Bearer <secret>` against a new,
  narrow verifier (not the OIDC/Keycloak JWT path — this has no
  issuer/JWKS, it's a direct credential check against
  `service_accounts.secret_hash`), analogous in shape to
  `OIDCJWTValidator` but deliberately simpler.
- **Scopes, not per-tenant RBAC.** Service accounts are for automation
  (CI pipelines calling `sync`/`migrate` via the API instead of the raw
  CLI, a backing service needing `audit:read`) — coarser-grained OAuth-style
  scopes (`models:sync`, `models:read`, `tenants:read`, `audit:read`, …)
  checked in API middleware *before* any per-tenant `authz.can()` check
  from §2.5, not instead of it.
- **Lifecycle.** Create (name + scopes → secret), list (name, scopes,
  last-used, never the secret again), rotate (issues a new secret,
  invalidates the old one, same id), revoke (soft-delete —
  `revoked_at`, never a hard delete, so past audit-log entries attributing
  actions to this service account remain meaningful).
- **Audit.** Every action taken by a service account is audit-logged with
  its `service:<name>` identity, identically to a human operator's —
  no separate, weaker trail for automation.

### 2.7 Next.js frontend architecture

- **App Router**, server components as the default for data fetching
  against the control-plane API — the browser holds only an httpOnly
  session cookie (BFF pattern: the Next.js server, not client-side JS,
  attaches the actual bearer credential when calling the control-plane
  API). Service-account secrets never reach the browser under any
  circumstance — they exist for machine-to-API calls only.
- **Route groups per screen area** (`(dashboard)`, `(tenants)`, `(models)`,
  `(migrations)`, `(service-accounts)`, `(audit)`), each gated server-side
  by the operator's role from §2.5 — navigation hides sections an
  operator lacks access to, but the *server* route handler is what
  actually enforces it, never the client-side hide alone.
- **Data fetching/caching:** React Query (or SWR) for client-interactive
  screens (job progress polling, relationship explorer search-as-you-type);
  server components for everything that's a straightforward list/detail
  view.
- **Design system:** shadcn/ui (Radix + Tailwind) — accessible primitives
  out of the box, consistent with a component-driven admin UI; a shared
  `<DataTable>`/`<ConfirmDialog>`/`<SecretRevealOnce>` set covers most of
  the screens in §2.4 (the last one specifically for service-account
  secrets and any one-time-reveal flow).
- **Real-time-ish updates:** job progress (migrations, model sync) is
  polling-based against `GET /migrations/{job_id}` rather than a
  websocket for the first version — simpler, and `control_plane_jobs`
  already gives every poll a consistent row to read.

### 2.8 Integration boundaries (explicit, so nothing accidentally leaks)

- Next.js ↔ control-plane API: HTTPS + operator session cookie (browser)
  or service-account bearer token (machine caller). Never OpenFGA/DB
  credentials in the browser, ever.
- Control-plane API ↔ `py_authz`: in-process Python import, not a network
  hop — the control-plane API *is* a `py-authz` host application, using
  the public `Authz`/`MultiTenantAuthz`/`TenantManager`/`ModelSync`/
  `MigrationManager` surface like any other adopter would.
- Control-plane API ↔ OpenFGA/Postgres/Redis: exactly the credentials
  `py_authz`'s existing storage/client classes already need — no new
  infrastructure surface, no new credential type to manage beyond what
  operating this library already requires.

---

## 3. Open questions / constraints to settle before Tier 3 (frontend) starts

- **Single control-plane API instance vs. one per environment/region** —
  affects whether `control_plane_jobs` needs a work-queue (e.g. a simple
  Postgres-backed queue) or a single-process `asyncio` task is enough for
  v1. Recommend the latter for v1 given the existing library's own
  `anyio.Semaphore`-bounded concurrency patterns (`bulk_enforce`,
  `MigrationManager.migrate_all`) are already single-process-appropriate.
- **Does the control-plane API get its own `AuthzError`-shaped exception
  hierarchy, or reuse `py_authz.core.exceptions.AuthzError` and its
  subclasses directly?** Recommend reuse + a thin HTTP-status mapping
  table, mirroring the CLI's existing `_EXIT_CODES` convention
  (`cli/main.py:29`) instead of inventing a parallel one.
- **Rate limiting / brute-force protection on the service-account secret
  verification endpoint** — the library's own stance (`docs/architecture.md`,
  "Known sharp edges") is that it doesn't rate-limit itself and expects
  the host app to; the control-plane API *is* that host app for this
  endpoint specifically, so this can't be deferred to "someone else's
  problem" the way it can for `check()`/`list-objects`.
- **Does `operators`/`service_accounts`/the dogfooded RBAC store live in
  the same Postgres database as tenant/model/audit data, or a separate
  schema?** Recommend same database, new tables (or a `control_plane`
  schema) — one less piece of infrastructure to stand up, consistent with
  how `PostgresTenantStore`/`PostgresModelRegistry`/`PostgresAuditLogger`
  already share one DSN today.

---

## Next step

See [`09_control_panel_todos.md`](09_control_panel_todos.md) for the
tiered execution plan — CP-1 through CP-10 above map directly onto Tier
0–2 items there; Tiers 3–4 cover the Next.js build-out and hardening this
doc's architecture section describes but doesn't itself enumerate as
findings.
