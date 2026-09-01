# Audit backlogs

Each numbered pair is one audit: `NN_<topic>.md` holds the findings with
evidence and code references; `NN_<topic>_todos.md` is the execution
checklist (IDs match across the pair, and each todos file carries a status
stamp at the top). Ship order within a backlog is its phase order.

This is the first audit pass filed against py-authz. It was requested as
a comprehensive, ground-up review of the whole library against its stated
goal — a reusable, production-ready authorization framework for Python
built around OpenFGA and Keycloak — covering architecture, the
authorization model, security, extensibility, developer experience,
integrations, testing, and operational readiness. Findings are grouped
into four backlogs by concern area rather than by feature, since this
audit has no prior backlog to check against or avoid re-filing.

| Pair | Topic | Status stamp lives in |
| ---- | ----- | --------------------- |
| 01 | Architecture & modeling — core layered design, the declarative modeling layer, model sync/diff, and disconnected scaffolding (config, metrics, retry) | [`01_architecture_and_modeling_todos.md`](01_architecture_and_modeling_todos.md) — **filed 2026-08-31; all three tiers shipped same day (ARCH-1 through ARCH-9, plus ARCH-10 found along the way) — nothing left open** |
| 02 | Security & identity — Keycloak JWT validation, failure-mode isolation (audit logging, tenant resolution), concurrency safety, licensing | [`02_security_and_identity_todos.md`](02_security_and_identity_todos.md) — **filed 2026-08-31; all three tiers shipped same day (SEC-1 through SEC-8) — nothing left open** |
| 03 | Reliability, storage & release operations — Postgres/Redis/hybrid storage backends, distributed locking, resource lifecycle, OpenFGA client hardening, PyPI publishing | [`03_reliability_and_operations_todos.md`](03_reliability_and_operations_todos.md) — **filed 2026-08-31; all tiers shipped (REL-1 through REL-9) — the only thing left open in this backlog is external: a PyPI project owner must register this repo as a trusted publisher (REL-9)** |
| 04 | Developer experience & test coverage — FastAPI adapter ergonomics, the `Authz` facade's completeness, the CLI, and the mock-only test suite | [`04_developer_experience_and_testing_todos.md`](04_developer_experience_and_testing_todos.md) — **filed 2026-08-31; all tiers shipped (DX-1 through DX-6, DX-8, DX-9, DX-10) — nothing left open except one GitHub branch-protection setting only a repo admin can flip (DX-8)** |

Conventions: findings are severity-tagged (🔴/🟠/🟡/🟢) with per-item
effort estimates and `file:line` evidence; each finding cites whether an
existing test covers (or fails to cover) the behavior, since several of
the sharpest defects in this audit are ones the test suite's own mocking
choices actively mask. Cross-references between the four files are called
out inline where a fix in one enables or depends on a fix in another
(most notably: `04`'s DX-9 — the mock-only test suite — is the shared
root cause behind confirmed bugs filed in `01` and `03`).

## Headline findings, if you read nothing else

- **`ModelSync`'s "skip if unchanged" path was very likely broken against
  a real OpenFGA server**, and had never been tested against one (`01`
  ARCH-1) — the single most concerning finding in this audit, since it was
  a silent defect in a feature both the README and architecture doc
  describe as already working. **Fixed and confirmed against a real
  OpenFGA store** — and the fix needed a second, deeper pass once live
  testing (DX-9, below) showed the first version still wasn't idempotent
  against a real server's response shape.
- **The declarative modeling layer could not express hierarchical/nested
  resource permissions** (`tupleToUserset`) despite documentation implying
  it could (`01` ARCH-2) — a real scope gap for the shape of authorization
  model most real applications need. **Decided (implement it) and
  shipped** as `Relation(from_parent=...)`, confirmed against a real
  OpenFGA server with an actual folder→document example.
- **Model-validation cycle detection didn't detect cycles** (`01`
  ARCH-3) — correct in isolation, silently disconnected from what it was
  actually called with. **Fixed** — cycle detection now walks the real
  rewrite tree instead of a hand-built shape its own tests used but its
  caller never produced.
- **A Keycloak key rotation caused an outage with no recovery short of a
  restart** (`02` SEC-1), and **an unhealthy audit sink could take down
  all authorization decisions** (`02` SEC-3) — both were "a dependency's
  failure shouldn't corrupt or halt the core decision" gaps, previously
  the most important production-readiness property this library was
  missing. **Both fixed**, along with a related tenant-provisioning
  safety gap (`02` SEC-4) and, in the same pass, generic OIDC support
  (Auth0/Okta/Cognito, not just Keycloak) plus a fail-open/fail-closed
  policy for the FastAPI adapter when OpenFGA itself is down (`02` SEC-2,
  SEC-5) — both confirmed against a real Keycloak realm and a real
  FastAPI request.
- **Two of the library's own shipped storage classes
  (`HybridTenantStore` + `RedisTenantStore`) crashed when composed
  together exactly as documented** (`03` REL-1) — never caught because
  each was only ever tested against a bespoke, more-forgiving mock of the
  other. **Fixed and confirmed against a real Redis instance.**
- **The entire test suite was mock-based; nothing ran against a live
  OpenFGA, Keycloak, Postgres, or Redis** (`04` DX-9) — the root cause
  tying several of the above together, and the single highest-leverage
  fix in this audit. **Shipped in full** (OpenFGA + Keycloak + Redis +
  Postgres, the last one landing alongside `03`'s REL-3/REL-4) — and it
  paid for itself repeatedly: running it surfaced three more
  previously-unknown, real bugs the whole mocked suite had missed (the
  deeper ARCH-1 fix above, `Authz.grant`/`revoke` crashing outright on the
  exact `ResourceModel` argument the README documents — now `01`'s
  ARCH-10 — and REL-4's `PostgresAuditLogger.log()` raising
  `asyncpg.exceptions.DataError` on its very first real write).
- **The Postgres-backed stores had no connection lifecycle, no shipped
  schema, and would corrupt any non-trivial audit log entry** (`03`
  REL-3, REL-4) — calling `get`/`set`/`log` before an easy-to-forget
  `.connect()` raised a bare `AttributeError`, nothing released the pool,
  the `audit_logs` table's DDL didn't exist anywhere in the repository,
  and `reason_data` dicts were passed straight to `asyncpg` with no JSON
  encoding. **Both fixed**: idempotent `connect()`/`close()`/async
  context manager across all three Postgres classes, DDL shipped as
  versioned SQL files applied via `apply_schema()`, and `reason_data`
  now `json.dumps()`-ed before binding — confirmed against a real
  Postgres instance, including a wheel-build check to make sure the new
  `.sql` files actually ship (they don't, by default, in a repo with no
  `MANIFEST.in`).
- **`MultiTenantAuthz` leaked one open HTTP connection pool per tenant
  forever, and bulk grants over 100 tuples hit an opaque OpenFGA 400**
  (`03` REL-7, REL-8). **Both fixed**: `Authz.aclose()`/
  `MultiTenantAuthz.aclose()` release cached clients on shutdown (wired
  into the multi-tenant FastAPI example), and `write_tuples()` now chunks
  bulk writes into ≤100-item batches — **confirmed against a real
  OpenFGA instance**, granting 120 tuples in one `grant_many()` call
  where the pre-fix code raised `ExternalServiceError` on OpenFGA's real
  rejection.
- **The shipped `py-authz sync` CLI command crashed on every real
  invocation** (`04` DX-10, found while shipping DX-5's `migrate`
  command) — `anyio.run(..., store_id=..., ...)` passed keyword arguments
  to a function that doesn't accept them, masked by a test double more
  permissive than the real `anyio.run`. **Fixed and confirmed against a
  real OpenFGA instance** — the command actually runs to completion now,
  for the first time.
- **A provisioning lock's fixed TTL could expire mid-operation under
  load, letting two callers provision the same tenant twice** (`03`
  REL-6) — **fixed** with background lock renewal, confirmed against a
  real Redis instance to actually keep a key alive past its initial TTL
  for as long as the critical section runs.
- **Multi-tenancy and the FastAPI adapter had never been composed, and
  the adapter's shape didn't allow it** (`01` ARCH-4) — **fixed**: `authz`
  now accepts a per-request resolver callable, not just a static
  instance. Confirmed against a real OpenFGA server with a new example
  serving two tenants off one route (200 vs. 403 by `X-Tenant-ID`).
- **`Authz.require()` mutated shared, concurrently-used engine state to
  change behavior** (`02` SEC-6) — the last of the concurrency-unsafe
  patterns this audit found. **Fixed**: `raise_on_denied` is now a
  per-call parameter; a 50-way concurrent `enforce()`/`require()` test
  against one shared engine confirms neither can affect the other.
- **The CLI had no top-level error handling and CI only ran after code
  had already landed on `main`** (`04` DX-6, DX-8) — a categorized
  failure (bad config, an OpenFGA outage) surfaced as a raw traceback
  with no way for automation to branch on failure class, and lint/type/
  test all ran as a post-merge check, not a gate. **Both fixed**: the CLI
  now maps `AuthzError` subclasses to distinct exit codes with a friendly
  one-line message (confirmed live against an unreachable OpenFGA host),
  and CI now also triggers on `pull_request`. One part is left
  deliberately open: actually branch-protecting `main` on these checks is
  a GitHub repository setting, not a file change — it needs a repo admin.
- **Nothing was ever published to PyPI, and the README's own install
  instructions didn't work** (`03` REL-9) — discovered while fixing this:
  **the repository is currently private**, which meant the audit's own
  originally-suggested interim fix (point install instructions at a
  GitHub-release wheel URL) doesn't work either — a private repo's
  release assets 404 for an anonymous download, confirmed by actually
  requesting one. **Shipped from the repo's side**: a `publish-pypi`
  workflow job using OIDC trusted publishing (no long-lived API token),
  gated on an actual release having happened; the README/Makefile now
  document the Git-URL install that works today for anyone with repo
  access. **Left open, and outside this audit's reach**: a PyPI project
  owner must register this repo as a trusted publisher before the new
  job can actually succeed — a one-time action on an external account.
