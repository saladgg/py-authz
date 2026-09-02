# Audit backlogs

Each numbered pair is one audit: `NN_<topic>.md` holds the findings with
evidence and code references; `NN_<topic>_todos.md` is the execution
checklist (IDs match across the pair, and each todos file carries a status
stamp at the top). Ship order within a backlog is its phase order.

Two audit passes have been filed against py-authz so far, each requested
as a comprehensive, ground-up review of the whole library against its
stated goal — a reusable, production-ready authorization framework for
Python built around OpenFGA and Keycloak — covering architecture, the
authorization model, security, extensibility, developer experience,
integrations, testing, and operational readiness. Both group findings
into four backlogs by concern area rather than by feature. `01`–`04`
below is the first pass (filed 2026-08-31, fully shipped); `05`–`08`,
further down, is the second pass (filed 2026-09-02 against the resulting
1.3.0 tree, not yet executed).

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

## Second audit pass (filed 2026-09-02, backlogs `05`–`08`)

Everything above (`01`–`04`) shipped in full on 2026-08-31 and the
library moved from 1.2.0 to 1.3.0. This second pass is a fresh,
ground-up re-audit of the resulting 1.3.0 tree, run the same way as the
first: comprehensive, covering security, architecture, reliability,
performance, and developer experience, with each of the four backlogs
below first reading the corresponding `01`–`04` pair in full to confirm
those fixes are genuinely shipped and durable (they are) before looking
for anything new. Nothing in `05`–`08` re-files a `01`–`04` finding —
every item is new, or is a regression/gap that survived that
remediation. **Execution began the same day it was filed: Tiers 0–2 of
each backlog (where a backlog has one) shipped 2026-09-02**, plus several
cross-referenced Tier 4 items that landed as side effects of that work.
Everything past Tier 2 remains open.

| Pair | Topic | Status stamp lives in |
| ---- | ----- | --------------------- |
| 05 | Architecture & modeling — audit-trail blind spots (cache hits and the grant/revoke path are never logged), `MultiTenantAuthz` lagging single-tenant `Authz` in capability, model-sync/migration correctness, and a residual modeling-expressiveness gap (`intersection`/`difference`) | [`05_architecture_and_modeling_todos.md`](05_architecture_and_modeling_todos.md) — **filed 2026-09-02; Tiers 0–2 shipped same day (ARCH2-1 through ARCH2-12, ARCH2-14, ARCH2-16 through ARCH2-18), plus ARCH2-19 as a side effect — only Tier 3 (the larger modeling-expressiveness gap) and the rest of Tier 4 open** |
| 06 | Security & identity — a reproducible cache-key collision that poisons cached authorization decisions, a cross-tenant bypass via an unauthenticated tenant header, unbounded tenant auto-provisioning, and CI/supply-chain hardening | [`06_security_and_identity_todos.md`](06_security_and_identity_todos.md) — **filed 2026-09-02; Tiers 0–2 shipped same day (SEC2-1 through SEC2-4, SEC2-6) — only Tier 3 (CI/supply-chain hardening) open** |
| 07 | Reliability, storage & operations — a CI format-check step that silently reformats instead of gating, a storage backend that fails closed instead of degrading, retry/backoff coverage gaps, and unbounded background-task/cache growth | [`07_reliability_and_operations_todos.md`](07_reliability_and_operations_todos.md) — **filed 2026-09-02; Tiers 0–2 shipped same day (REL2-1 through REL2-12) — only Tier 3 (low-effort operational polish) open** |
| 08 | Developer experience & test coverage — a `bulk_enforce()` exception-contract break that silently discards partial results, mypy checks disabled specifically to hide 4 real type errors, a missing `py.typed` marker, and several docs/example inaccuracies | [`08_developer_experience_and_testing_todos.md`](08_developer_experience_and_testing_todos.md) — **filed 2026-09-02; Tiers 0–2 shipped same day (DX2-1 through DX2-5), plus DX2-10/DX2-12 as side effects — Tiers 3, 5, 6, and the rest of Tier 4 open** |

Cross-references between these four files (and back into `01`–`04` where
relevant) are called out inline, same convention as the first pass — most
notably a `MultiTenantAuthz.for_tenant()` concurrency race independently
flagged by three of the four backlogs (fixed once, in `05`'s `ARCH2-9`),
and a cache-key-namespacing dependency between `06`'s `SEC2-4` and `05`'s
`ARCH2-3` that determines shipping order.

### Headline findings from this pass, if you read nothing else

- **`AuthzRequest.cache_key()` is not injective** (`06` SEC2-1) — the
  single most concrete, easiest-to-reproduce defect in this pass. Four
  variable-length strings are joined with a bare `:` separator; two
  unrelated `(identity, action, resource)` tuples following the library's
  own documented `"doc:456"`-style resource-ID convention can produce the
  identical cache key, so one cached `True` decision silently authorizes
  an unrelated request. No attacker required to trigger it — just the
  library's own recommended ID shape.
- **The shipped multi-tenant FastAPI helper trusts an unauthenticated
  `X-Tenant-ID` header with no binding to the validated identity** (`06`
  SEC2-2), and **tenant auto-provisioning has no validation or cap on the
  tenant string it's given** (`06` SEC2-3) — composed together, any
  authenticated caller can select an arbitrary tenant's OpenFGA store by
  changing one header, and can force unbounded store creation and process
  memory growth by sending distinct garbage tenant IDs.
- **`AuthzEngine.bulk_enforce()` raises a bare `ExceptionGroup` on partial
  failure and discards every already-computed result** (`08` DX2-1) —
  reproduced directly. `ExceptionGroup` isn't an `AuthzError` subclass, so
  the documented "catch `AuthzError` at framework boundaries" pattern
  doesn't catch it, and a caller loses a whole batch's results over one
  bad request.
- **Cache hits are never audit-logged, and `Authz.grant`/`revoke` bypass
  audit logging and metrics entirely** (`05` ARCH2-1, ARCH2-2) — the audit
  trail SEC-3 hardened in the first pass has two systemic blind spots:
  once a decision is cached, no further audit records are written for it
  within the TTL, and the highest-value events for a compliance trail
  (who granted/revoked what) were never wired to audit/metrics at all.
- **CI's own "Format check" step doesn't check anything** (`07` REL2-1) —
  it runs the mutating `make format` target instead of the non-mutating
  `make format-check` target that already exists right next to it, so a
  PR with unformatted or auto-fixable-lint-violating code passes every
  time.
- **mypy's config disables the two error codes that would catch real,
  present bugs** (`08` DX2-2) — with `arg-type`/`union-attr` force
  re-enabled, 4 genuine type errors surface, including a nominal-typing
  mismatch in the library's own official `testkit.make_fake_authz()`
  helper. `make lint`/CI report a clean pass; the config was tuned to make
  mypy succeed, not to make the code correct under mypy.
- **`HybridTenantStore` fails closed on a Redis blip instead of degrading
  to its documented Postgres source of truth** (`07` REL2-2) — inverting
  the reliability benefit composing the two backends is supposed to
  provide; a healthy Postgres instance can't serve tenant lookups if
  Redis alone hiccups.
- **`OpenFGAClient`'s retry/backoff (from the first pass's ARCH-6) was
  wired to `check()` only** (`07` REL2-3) — every write, list, and
  store-creation call gets zero retries on the identical transient errors
  `check()` already handles gracefully, and REL-8's chunked bulk-write fix
  means a multi-chunk write now has more opportunities to hit one and
  abandon a partially-applied write.
- **No `py.typed` marker ships with the package** (`08` DX2-3) despite the
  library being fully type-hinted — a PEP 561 gap that makes every type
  hint in `py_authz/` invisible to a downstream consumer's own type
  checker, worth fixing before the PyPI publish `03`'s REL-9 set up.

All of the above (Tier 0 and Tier 1 across all four backlogs) shipped
2026-09-02, along with Tier 2: `05`'s remaining model-sync/migration/
tenant-management findings (an orphaned-store cleanup path, the
`MultiTenantAuthz.for_tenant()` concurrency fix, per-tenant migration
failure isolation, model-diff/validator correctness, the
`StoreBackedResolver` adapter, the `ModelRegistry` naming collision, and
Redis client injection), `07`'s remaining reliability findings (bounded
cache/metrics growth, cache-stampede coalescing, lock-renewal resilience,
closed CLI connections, `migrate --dry-run`/confirmation, Postgres pool
sizing, and a pinned release toolchain), and `08`'s cache/IdP fail-safety
findings (a cache outage can no longer take down `enforce()`, and a
token with no `kid` header fails cleanly instead of crashing). See each
backlog's own todos file for the per-item detail.
