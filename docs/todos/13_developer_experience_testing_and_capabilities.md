# py-authz — Developer Experience, Testing & Missing Capabilities Audit (Round 3)

**Date:** 2026-11-24 · repo as of `6a54c93` (1.6.0).
**Scope:** test-suite gaps (including per-module coverage), the CLI,
README/docs/examples accuracy, the control panel's own DX (CI, tests,
error states, accessibility), and the capabilities a production OpenFGA
framework is expected to have but this one lacks.
**Method:** read `04`, `08` and `09` first. Baseline: 729 unit tests pass
in about 8 s at 96% line+branch coverage; `ruff check`, `mypy`,
`pnpm lint` and `tsc --noEmit` are all clean. Findings marked
**REPRODUCED** were confirmed with scratch scripts. Packaging (the
missing extras) is filed once, in `11`'s ARCH3-1, and isn't repeated
here.

**Per-module coverage below 100%:**

| Module | Cover | Uncovered |
|---|---|---|
| `control_plane/app.py` | **47%** | `_wire`, `_teardown`, `_lifespan` |
| `cache/base.py` | 71% | abstract stubs |
| `control_plane/__main__.py` | 75% | entry point |
| `utils/deps.py` | 82% | `require_postgres` error path |
| `cli/commands/migrate.py` | 86% | the Postgres/Redis backend builders (the only real backends) |
| `adapters/fastapi.py` | 90% | `:237-243` |
| `cli/main.py` | 92% | |
| `core/enforcement.py` | 96% | |
| `api.py` | 96% | |

Every `control_plane/routes/*` module is at 100%, and that number
overstates confidence: those routes are exercised against
`InMemoryFGAClient`, which is permissive in exactly the ways that hide
`10`'s SEC3-3 (see `11`'s ARCH3-9).

---

## A. Testing gaps

**DX3-1 🟠 The live control-plane tests never send an authenticated
request.** `tests/live/test_control_plane_live.py:66-115` has two tests,
both lifespan wiring plus `/health` → 200. Nothing in CI exercises a real
Keycloak token through `OIDCJWTValidator` → break-glass → a real OpenFGA
RBAC check → a route. `09`'s status note says its one real bug was "found
by the live end-to-end pass", and that pass was manual and not committed.
A committed version would have caught `10`'s SEC3-3.
→ **Fix:** extend the live test. Get a password-grant token for the
seeded `alice`, set `break_glass_subject`, then:
- `/auth/me` reports `owner`
- `POST /tenants` succeeds
- `POST /tenants/acme/grants` succeeds
- `GET /audit-logs?tenant_id=acme` returns the row (09's regression)
- create an SA, grant it a role, authenticate as it, call a scoped route
- try the cache invalidation from SEC3-6 and check `deleted > 0`

**Effort: M.**

**DX3-2 🟡 No control-plane test checks cross-tenant isolation.**
`grep -rn globex tests/control_plane` returns nothing. Every route test
covers "no role vs. role on the same tenant". → A parametrized test over
every tenant-scoped route: grant `admin` on `acme`, call it for `globex`,
expect 403. This is the highest-value property of a multi-tenant admin
API. **Effort: S.**

**DX3-3 🟡 JWT validation is tested by mocking `jwt.decode` itself.**
`tests/adapters/test_oidc.py:150-155,286-294` (and the matching code in
`test_keycloak.py`) monkeypatch `jwt.decode`/`get_unverified_header`. The
`ALGORITHMS = ["RS256"]` allow-list (`adapters/oidc.py:36`), `alg: none`,
HS256 key confusion, wrong `iss`, missing `exp` (`10`'s SEC3-8), `nbf`
and `typ` are never tested with real signed tokens.
→ Generate an RSA key with `cryptography`, serve the JWKS through
`httpx.MockTransport`, and assert that each forged token raises
`AuthenticationError`. **Effort: S.**

**DX3-4 🟡 No coverage floor.** `pyproject.toml` `addopts` and
`[tool.coverage.report]` set no `fail_under`, which is how
`control_plane/app.py` sits at 47%. → `fail_under = 95`. Cover
`_wire`/`_teardown` with patched store classes. **Effort: S.**

**DX3-5 🟡 Timing-dependent tests.** `tests/cache/test_memory.py:17` uses
a real `asyncio.sleep(1.1)`, because `cache/memory.py:74,91` uses
`time.time()`, which is neither injectable nor monotonic.
`tests/core/test_locks.py:133,165,193` sleep 0.15–0.22 s and then assert
renewal counts. `tests/control_plane/test_migrations_routes.py:200-225`
polls 50 × 10 ms.
→ An injectable monotonic clock for `InMemoryCache`; `asyncio.Event`-driven
renewal assertions; await the job task directly. **Effort: S.**

**DX3-6 🟢 Examples aren't exercised in CI.** All 14 examples import
cleanly today (05 and 14 need env vars by design), but nothing would
catch drift like DX3-9's snippet. → A parametrized import test over
`examples/[0-9]*.py`; in the live job, run `seed.py` followed by examples
01, 07, 08 and 11. **Effort: S.**

**DX3-7 🟠 The control panel has no CI job and zero tests.**
`.github/workflows/ci.yml` has no Node/pnpm job, and there are no
`*.test.*` files. `package.json` has no `typecheck`/`test` script and no
`engines` field. The security-critical BFF code (`lib/crypto.ts`
AES-GCM sealing, `lib/session.ts` refresh, `lib/oidc.ts` PKCE/state,
the CSV export in `10`'s SEC3-10) has no tests.
→ **Fix:** a `panel` CI job (`pnpm install --frozen-lockfile`,
`pnpm lint`, `tsc --noEmit`, `next build`, `pnpm audit --prod`); a
`vitest` suite for `lib/` and the export route. Dependabot npm is in
`10`'s SEC3-15. **Effort: S (CI), M (tests).**

---

## B. CLI, docs and examples

**DX3-8 🟠 `py-authz migrate` defaults to `--backend memory`, so a CI job
that forgets `--backend` exits 0 having migrated nothing.**
`cli/main.py:216` sets `default="memory"`. REPRODUCED:
`py-authz migrate --all-tenants --yes` prints "No tenants found — nothing
to migrate." with exit code 0. The real backend builders
(`cli/commands/migrate.py:26-39`) are untested, and a
`model_registry.connect()` failure after `tenant_store.connect()` leaks
the pool.
→ **Fix:**
- No default: `--backend` is required, or read from
  `TENANT_STORE_BACKEND`.
- `memory` prints a warning.
- `--all-tenants` with 0 tenants exits non-zero unless `--allow-empty`
  is passed.
- Test the builders with patched asyncpg/redis.

**Effort: S.**

**DX3-9 🟡 The README's multi-tenancy snippet crashes and misdescribes
model resolution.** `README.md:339`:
`tenant_resolver=my_resolver,  # e.g. PostgresTenantStore`. Stores expose
`.get()`, while resolvers need `.resolve()` (`core/tenant_resolver.py:18`).
REPRODUCED: `AttributeError: 'InMemoryTenantStore' object has no attribute
'resolve'`. The `model_id=None  # resolved per-tenant` comment on the line
before is false (see `11`'s ARCH3-13).
→ Use `StoreBackedResolver(PostgresTenantStore(dsn))` (the pattern
`control_plane/app.py` itself uses) and fix the comment. **Effort: S.**

**DX3-10 🟡 Version and metadata drift.**
- The `README.md:7` badge says 1.4.0, and the git-install pin
  (`:122,125`) is `@v1.4.0`. The project is at 1.6.0, and `08` fixed this
  same drift once already.
- `pyproject.toml:3` is `version = "v1.6.0"`, produced by semantic-release
  `version_toml = "pyproject.toml:project.version:tf"` (around `:214`).
  Use `:nf` for a canonical `1.6.0`.
- The `Documentation` URL (`/docs`) 404s; it should be `/tree/main/docs`.
- The `Homepage` line still has a `# todo` comment.
- `Development Status :: 5 - Production/Stable` is a stretch for a
  package that is unpublished and private.
- `CHANGELOG.md` has one line per release, with no breaking-change or
  upgrade notes. 1.4–1.6 changed cache-key formats and added tables.

→ Have semantic-release's `version_variables` rewrite the README badge
and pin (or use a `@vX.Y.Z` placeholder), switch to `:nf`, fix the URLs,
and add "Upgrade notes" sections. **Effort: S.**

**DX3-11 🟡 `requires-python = ">=3.13"` is stricter than the code
needs.** Every file compiles on CPython 3.12. On 3.11 only
`adapters/fastapi.py:20` (`type` alias) and `utils/retry.py:13` (PEP 695)
fail. 3.12 is still the most widely deployed version. → Lower the floor
to 3.12 after a 3.12 runtime pass, and add 3.12/3.13/3.14 to the CI
matrix (`12`'s REL3-22). **Effort: S.**

**DX3-12 🟢 Smaller doc inaccuracies.** `README.md:325` documents the
cache key as `<user>:<action>:<type>:<id>`. The real key is
length-prefixed and `|`-joined (`core/types.py:144`), and its docstring
says not to parse it. README:57 lists the ruff rules without `S` and
claims CI runs them (see `12`'s REL3-21). **Effort: S.**

---

## C. Control-panel UX

**DX3-13 🟡 No error boundaries or loading states. A backend failure or
an expired token crashes the whole shell, including Logout.** There's no
`error.tsx`, `global-error.tsx`, `loading.tsx` or `not-found.tsx` under
`src/app`. `(app)/layout.tsx:18` calls `apiFetch("/api/v1/auth/me")`
with no catch. `lib/api.ts:77` runs `JSON.parse` on any body, so a proxy's
HTML 502 throws `SyntaxError` instead of `ApiError`.
→ **Fix:**
- A 401 in the layout redirects to logout.
- `(app)/error.tsx` with retry and logout.
- `loading.tsx` skeletons (the Skeleton component already exists).
- A guarded parse that wraps failures in `ApiError`.

**Effort: S.**

**DX3-14 🟡 API failures render as empty data, and lists are silently
truncated.** `explorer/page.tsx:12-14` catches with
`.catch(() => ({ items: [] }))`, so a 500 reads as "no tenants".
`dashboard/page.tsx`, `migrations/page.tsx` and `operators/page.tsx` do
the same. Hard-coded `limit=500`/`1000` with no pagination means the
dashboard's tenant count caps at 1000. → An inline `Alert` on non-403
errors; a server `total` and real pagination (pairs with `12`'s REL3-15).
**Effort: S.**

**DX3-15 🟡 No navigation below the `md` breakpoint.**
`(app)/layout.tsx:22` renders the sidebar `hidden md:block`, and the
generated `components/ui/sheet.tsx` is unused. → A header menu button
that opens a Sheet containing `NavSidebar`. **Effort: S.**

**DX3-16 🟢 Accessibility and package hygiene.**
- Unassociated labels (no `htmlFor`/`id`) in `cache-invalidate-form.tsx`,
  `relationship-explorer.tsx` and `audit-filter-bar.tsx`.
- The active nav item is marked by color only; it needs
  `aria-current="page"` (`nav-sidebar.tsx`).
- The `shadcn` CLI is listed under runtime `dependencies`.
- `@types/node` is `^20` with no `engines` pin.

**Effort: S.**

---

## D. Missing capabilities, by value

**DX3-17 🟠 The modeling DSL can't express OpenFGA conditions, public
wildcards or userset subjects, so the ABAC `context` passthrough is
unusable with generated models.** `modeling/generator.py:84-86` emits
only `{"type": subject_type}`. `Relation(...)` has no parameter for
`user:*`, `group#member` or a `condition`. `OpenFGAClient._tuple` can't
write a conditional tuple. `testkit.py:18` says "no conditions/ABAC", and
`examples/09_contextual_and_abac.py` concedes `context` is "a no-op" with
the bundled model. Public sharing, group membership and time-bound grants
are the most common real-world patterns.
→ **Fix:**
- Parse `subjects=["user", "user:*", "group#member"]` (shared with `11`'s
  ARCH3-6).
- A `Condition(name, expression, params)` declaration and a `condition=`
  option on subjects.
- `grant(..., condition=ConditionRef(name, context))`.
- Teach the testkit wildcards, usersets and (where feasible) conditions.

Requires `11`'s ARCH3-3 first, otherwise model sync will skip these
changes. **Effort: L.**

**DX3-18 🟠 No first-class support for sync frameworks.** `adapters/`
has only FastAPI, Keycloak and OIDC. The only sync entry point is the
decorator broken by `11`'s ARCH3-2, yet README:17 calls the library
"framework-agnostic". → On top of ARCH3-2's `SyncAuthz`:
- a Django decorator and a DRF `BasePermission`
- a Flask `before_request` helper and decorator
- a plain ASGI middleware (covers Starlette, Litestar and Quart)

**Effort: M.**

**DX3-19 🟡 Unexposed OpenFGA query APIs.** `grep -rn
"consistency|list_users|batch_check|read_changes|expand" py_authz`
returns nothing.
- **Consistency:** `HIGHER_CONSISTENCY` is needed for read-after-write
  right after `grant()`.
- **ListUsers:** "who can view X" today means a raw tuple read that
  ignores inheritance.
- **BatchCheck:** `bulk_enforce` (`core/enforcement.py:770-782`) fans out
  N `/check` calls, while OpenFGA v1.19 supports `/batch-check`.
- **Expand:** needed by `11`'s ARCH3-8.
- **ReadChanges:** cache invalidation for tuples written by other systems.

→ Add each one to `OpenFGAClient`, then to `Authz`/`AuthzEngine`.
**Effort: M.**

**DX3-20 🟡 No distributed tracing.** There are no spans around check,
list-objects, write or cache calls, and no W3C `traceparent` on outbound
OpenFGA requests. `request_context_middleware` only propagates
`X-Request-ID`. → An optional `py-authz[otel]` extra: spans in
`AuthzEngine`/`OpenFGAClient`, `opentelemetry-instrumentation-httpx`
compatibility, and control-plane FastAPI instrumentation. Metrics export
is `12`'s REL3-24. **Effort: M.**

**DX3-21 🟡 No model-testing tooling.** The CLI has `generate-model`,
`sync` and `migrate` only. `generate-model` emits JSON only, with no DSL
output. Model changes can't be asserted in CI, which OpenFGA users
normally do with `fga model test` YAML suites.
→ `py-authz generate-model --format dsl`; `py-authz test model.fga.yaml`
(against the testkit, or an ephemeral store when `FGA_API_URL` is set);
`py-authz check <user> <relation> <object>`; `py-authz diff` (no
upload). **Effort: M.**

**DX3-22 🟢 Audit retention is DIY.** Only
`storage/sql/audit_logs_retention.example.sql` exists. → A
`py-authz audit purge --older-than 90d` command (batched deletes), and,
once the table is large, a documented partitioning recipe. **Effort: S–M.**

---

## Areas checked, no issue

- `.env.example` section 3 matches every `ControlPlaneSettings.from_env()`
  variable and default; `control-panel/.env.local.example` matches all of
  `lib/env.ts`.
- Every import shown in the README and docs resolves; README CLI flags
  match `--help`.
- `docs/control_plane.md`'s curl walkthrough uses the correct `/api/v1/…`
  paths.
- `list_objects`, contextual tuples, `context` passthrough and
  `fail_open` exist and are tested.
- Every control-plane route has "no role → 403" tests (single-tenant
  only; see DX3-2), plus good SA lockout, revocation and scope negative
  tests (against a synthetic route; see `10`'s SEC3-1).
- `tests/live` skips cleanly without env vars; there are no `time.sleep`
  calls in tests.
- No `process.env` leaks into client components.
