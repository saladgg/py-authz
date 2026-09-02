# py-authz — Security & Identity Audit (Round 2)

**Date:** 2026-09-02 · repo as of `audit2` (post-1.3.0, after all of `01`–`04`
shipped).
**Scope:** the cache key that gates every cached authorization decision;
multi-tenancy's trust boundary (`api.py`'s `MultiTenantAuthz`, the shipped
FastAPI tenant-resolution helper); SQL/injection surfaces; secrets/config
hygiene; supply chain (dependency versions, CI Action pinning, scanning
tooling); log injection.
**Method:** read `docs/todos/02_security_and_identity*.md` in full first to
confirm SEC-1…8 are genuinely shipped in the current tree (they are, and
hold up under re-testing — see "Areas checked" at the end), then re-audited
the same trust boundary plus the newer surfaces (`MultiTenantAuthz`,
`cache_key()`) the first pass didn't focus on. Three parallel read-only
sub-checks (SQL injection, multi-tenancy/cache, supply-chain/config) were
run and cross-verified against source directly. Nothing below re-files a
`02` finding.

This is the second audit filed against this repository's security surface.
Its headline finding is a genuine, easy-to-reproduce cache-poisoning
primitive that requires no attacker at all to trigger by accident — just
following the library's own documented resource-ID convention.

---

## 🔴 CRITICAL

**SEC2-1. `AuthzRequest.cache_key()` is not injective — distinct
`(identity, action, resource)` tuples can collide onto the same cache
entry, poisoning cached allow/deny decisions.** `core/types.py:134`:
```python
return f"{self.identity.id}:{self.action}:{self.resource.type}:{self.resource.id}"
```
Four variable-length, unvalidated strings are joined with the same bare
`:` separator, with no escaping or length-framing. Read/written at
`core/enforcement.py:141,150,195` and invalidated the same way in
`api.py:375`. The collision is not hypothetical — the library's own
docstring, two lines above `Resource.id` (`core/types.py:41-43`), gives
colon-bearing resource IDs as the canonical example (`"doc:456"`,
`"project:abc"`). Concrete collision using only the documented shape:
- Request A: `identity.id="user:123"`, `action="viewer"`,
  `resource=Resource(type="document", id="doc:456")` → key
  `"user:123:viewer:document:doc:456"`
- Request B: `identity.id="user:123"`, `action="viewer:document"`,
  `resource=Resource(type="doc", id="456")` → **identical string.**

If A was ever checked and cached `True`, B — a completely unrelated
identity/action/resource combination that may never have been granted
anything — reads back A's cached `True` from `enforce()` without ever
calling OpenFGA. This is a direct authorization-cache-poisoning primitive,
and it can also occur **by accident**, with no attacker needed, any time
an app follows the library's own documented convention of colon-bearing
hierarchical/composite resource IDs — exactly the shape ARCH-2's new
`from_parent`/`tupleToUserset` support encourages.
→ Encode fields unambiguously — length-prefix each field before joining
(`f"{len(a)}:{a}|{len(b)}:{b}|..."`), or hash each field independently and
join the hashes, or `hashlib.sha256("\x00".join(fields).encode()).
hexdigest()`. Add a regression test asserting two requests differing only
in where a `:` falls produce different keys. **Effort: S.** *(No test
covers this — `tests/core/test_types.py::test_cache_key` only asserts the
format of one key; no test constructs two distinct requests and checks
their keys differ.)*
→ **Shipped 2026-09-02.** `AuthzRequest.cache_key()` now length-prefixes
each field before joining (`f"{len(field)}:{field}"` joined with `|`) —
provably injective, since a length prefix can never be misread as
content. `test_cache_key`'s expected string updated; new regression test
`test_cache_key_is_injective_across_colon_boundaries` locks in the exact
collision case described above. **This changes the cache-key format** —
existing cache entries are effectively invalidated on upgrade (they'll
simply miss once, not collide), which is the point.

---

## 🟠 HIGH

**SEC2-2. The shipped multi-tenant FastAPI helper trusts an
unauthenticated `X-Tenant-ID` header with no binding to the validated
identity — a tenant-boundary bypass by header spoofing.**
`adapters/fastapi.py:252-266`:
```python
def tenant_from_request(request: "Request") -> str:
    tenant = request.headers.get("X-Tenant-ID")
    if not tenant:
        raise HTTPException(status_code=400, detail="Missing tenant")
    return tenant
```
This is not example scaffolding — it's an exported, public function in the
shipped adapter module, and it is what's actually wired into
`examples/12_multitenant_fastapi.py:110-119` (the flagship, "confirmed
against a real OpenFGA server" multi-tenancy + FastAPI composition from
ARCH-4) and `tests/adapters/test_fastapi_extras.py:137-167`'s regression
test. Both only verify "different header → different tenant's `Authz`"
(200 vs. 403) — neither exercises the security-relevant case: **an
authenticated user for Tenant A sending `X-Tenant-ID: tenant-B`.** Nothing
in `MultiTenantAuthz.for_tenant()` or `_resolve_authz()` cross-checks the
header-selected tenant against any claim in the validated JWT
(`KeycloakAuthMiddleware`/`OIDCJWTValidator` extract only `sub`, never a
tenant/org claim — `oidc.py:204-213`). Any authenticated caller who can
set an HTTP header — every caller — can pick any tenant string and get
that tenant's OpenFGA store used for the check, with only their own
JWT-derived identity fixed. Where the same identity string or object ID
naturally recurs across tenants (shared usernames, sequential/demo IDs, a
wildcard/public grant in the target tenant), this is a direct cross-tenant
authorization bypass, mediated by a header the library itself ships as the
default/example tenant-resolution mechanism.
→ Either (a) drop `tenant_from_request` from the public adapter surface
and document that tenant resolution *must* come from a signed/verified
claim (JWT `tenant_id`/`org_id`, or a subdomain resolved server-side)
rather than a raw header, or (b) keep it but rename/document it
unmistakably as "insecure, demo-only — do not use with real
authentication without cross-checking against a token claim," and add
that cross-check as an opt-in helper. **Effort: S–M.**
→ **Shipped 2026-09-02**, via option (b) plus the opt-in helper.
`tenant_from_request`'s docstring now leads with an explicit "insecure by
itself — demo/development use only" warning naming the exact bypass. New
`tenant_from_verified_claim(claim="tenant_id")` reads the tenant from
`request.state.user.attributes` — the verified JWT payload, now carried
through by `OIDCJWTValidator.to_identity()` (see `05`'s ARCH2-7) — never
from a request header. `examples/12_multitenant_fastapi.py` gained an
explicit security-note comment pointing at the safe alternative (its own
"auth" is an intentional fake-header stand-in, so switching the example
itself wasn't meaningful — there's no real token to read a claim from).
New tests confirm the safe resolver ignores a spoofed `X-Tenant-ID`
entirely and correctly rejects a missing claim/unauthenticated request.

**SEC2-3. `MultiTenantAuthz` + auto-provisioning has no validation, cap,
or eviction on `tenant_id` — combined with SEC2-2, an attacker can force
unbounded OpenFGA store creation and unbounded process memory growth.**
`api.py:439-472` (`for_tenant`) — on `TenantNotFoundError`, calls
`self.tenant_manager.provision(tenant_id)` with no allowlist/format check,
then caches the result forever in `self._cache`, which the class's own
docstring now explicitly documents as unbounded/no-eviction "by design...
for a small, bounded tenant count." `core/tenant_manager.py:34-78`
(`provision`) passes any `tenant_id` string straight to
`client.create_store(name=tenant_id)` with zero validation — confirmed as
tested, intended behavior for *any* unknown tenant string
(`tests/api/test_multi_tenant.py:80-96`). Combined with SEC2-2 (an
attacker fully controls the `tenant_id` string reaching this path via
`X-Tenant-ID`), any caller can send an unbounded stream of distinct
garbage tenant IDs and force: (a) one new, permanently-cached
`Authz`/`AuthzEngine`/`OpenFGAClient` per distinct string (each holding an
`httpx.AsyncClient` pool), growing process memory/socket count without
bound; (b) one new, real OpenFGA store created per distinct string,
exhausting OpenFGA-side store quotas/costs.
→ Validate `tenant_id` against an expected format/allowlist before
provisioning; cap `MultiTenantAuthz`'s cache size (LRU with eviction
calling `aclose()`, per the class's own docstring's suggested workaround,
which nothing in the shipped code actually implements today); consider
requiring tenant existence to be pre-registered rather than lazily
auto-provisioned from arbitrary request-derived strings in production.
**Effort: M.**
→ **Shipped 2026-09-02.** `TenantManager` now validates every `tenant_id`
against `DEFAULT_TENANT_ID_PATTERN` (alphanumeric + `_.-`, 1-128 chars,
overridable via `tenant_id_pattern=`) before any lookup/lock/store-creation
happens, raising `InvalidAuthzRequest` on a mismatch.
`MultiTenantAuthz`'s tenant cache is now LRU-bounded
(`max_cached_tenants`, default 1000; evicted tenants' `Authz.aclose()` is
scheduled in the background) instead of unconditionally unbounded — pass
`max_cached_tenants=None` to opt back into the old behavior. New tests
cover the pattern rejecting a path-traversal-shaped tenant_id, a custom
pattern override, LRU eviction under a small cap, and that recently-used
tenants are protected from eviction.

**SEC2-4. Cache keys carry no tenant/store dimension — sharing one cache
backend across more than one `AuthzEngine`/tenant silently leaks
authorization decisions cross-tenant.** `core/types.py:134`'s
`cache_key()` (SEC2-1's same method) composed with
`AuthzEngine.__init__` (`core/enforcement.py:38-79`, no tenant/namespace
concept at all) and `RedisCache` (`cache/redis.py:26-49`, namespaced only
by one global, non-tenant-aware `prefix`, whose own docstring advertises
it as suitable for "multi-instance deployments"). Today's shipped
`MultiTenantAuthz.for_tenant()` happens not to pass `cache=` at all (see
`ARCH2-3` in
[`05_architecture_and_modeling.md`](05_architecture_and_modeling.md), which
files that gap in full), so the built-in path isn't exposed yet — but
nothing prevents, warns against, or even mentions the obvious next step of
wiring one shared `RedisCache` across several tenants' `AuthzEngine`
instances instead of paying for N Redis DBs/prefixes. The moment that's
done (and `ARCH2-3` is fixed without this), `user:alice` having `viewer`
on `document:1` in Tenant A and *not* in Tenant B produces a cache entry
keyed only `"user:alice:viewer:document:1"` — Tenant B's engine, sharing
the same cache, reads back Tenant A's decision.
→ Give `cache_key()` (or a wrapping layer) a mandatory tenant/store-scoping
component — e.g. `AuthzEngine(cache=..., cache_namespace=store_id)`
prefixed onto every key, with `MultiTenantAuthz.for_tenant()` passing the
resolved `store_id` so the `ARCH2-3` fix is safe by construction from day
one. At minimum, document loudly on `RedisCache`/`AuthzEngine` that one
cache instance must never be shared across stores without an out-of-band
per-tenant prefix. **Effort: S (docs) / M (real namespacing).**
**→ Ship this together with `ARCH2-3` — do the namespacing before wiring
`MultiTenantAuthz`'s cache support, not after.**
→ **Shipped 2026-09-02, together with `05`'s ARCH2-3 as planned.**
`AuthzEngine` now accepts `cache_namespace`, prefixed onto every cache key
via `_scoped_cache_key()` (used by both `enforce()` and `invalidate()`);
`MultiTenantAuthz.for_tenant()` passes `cache_namespace=store_id` when
building each tenant's engine, so `ARCH2-3`'s cache wiring is safe by
construction. New engine-level test
`test_cache_namespace_isolates_engines_sharing_one_cache_backend`
(`tests/core/test_enforcement_audit_and_cache.py`) proves two engines
sharing one cache backend but different namespaces never read back each
other's decisions; `test_invalidate_respects_cache_namespace` covers
`invalidate()`.

---

## 🟡 MEDIUM

**SEC2-5. Plain (non-JSON) f-string logging of attacker-reachable
`tenant_id` — log injection/forging.**
```
core/tenant_manager.py:41       logger.info(f"provision_start tenant={tenant_id}")
core/tenant_manager.py:72       logger.info(f"provision_success tenant={tenant_id} store_id={store_id}")
core/tenant_manager.py:75       logger.exception(f"provision_failed tenant={tenant_id} store_id={store_id}")
core/migrations_manager.py:49   logger.info(f"migration_start tenant={tenant_id}")
core/migrations_manager.py:71   logger.info(f"migration_noop tenant={tenant_id} model_id={current_model}")
core/migrations_manager.py:77   logger.info(f"migration_success tenant={tenant_id} model_id={new_model_id}")
```
`core/logging.py:6-10` configures plain `logging.basicConfig` with a
`%(message)s` text formatter — no structured/escaped output. This is a
real regression relative to the rest of the codebase: the hot-path
enforcement logger (`core/enforcement.py:202-216,279-292`) was clearly
hardened to use `json.dumps({...})` (which escapes control characters),
but the tenant-provisioning and model-migration loggers were not brought
in line. Combined with SEC2-3 (`tenant_id` is attacker-reachable via
`X-Tenant-ID` → `provision()`), a crafted `tenant_id` containing
`\n`/ANSI escapes can forge fake log lines or break downstream log
parsers/SIEM ingestion.
→ Route these through the same `json.dumps({...})`-structured pattern
already used in `core/enforcement.py`, or use `logger.info("provision_start",
extra={"tenant": tenant_id})` with a structured formatter. **Effort: S.**

**SEC2-6. `MultiTenantAuthz.for_tenant()` has a check-then-act race —
concurrent first-requests for the same uncached tenant each leak their own
`OpenFGAClient`/connection pool.** Filed in full as `ARCH2-9` in
[`05_architecture_and_modeling.md`](05_architecture_and_modeling.md) —
noted here because it's also a genuine socket/resource-exhaustion concern
under adversarial load (an attacker sending concurrent requests for
never-yet-cached tenant strings, per SEC2-3, amplifies the leak rate).
Fix once, in `05`'s todos.
→ **Shipped 2026-09-02** as part of `05`'s ARCH2-9 (a whole-critical-
section `asyncio.Lock` around `for_tenant()`'s resolve/provision/
construct sequence). Combined with SEC2-3's cache cap and tenant_id
validation, an attacker sending concurrent garbage tenant IDs can no
longer amplify the connection-pool leak this finding describes.

**SEC2-7. No `permissions:` block in `.github/workflows/ci.yml`, and
third-party Actions pinned to mutable tags rather than commit SHAs.**
`ci.yml` (whole file) declares no workflow- or job-level `permissions:`
(contrast with `release.yml:7-8`, which does scope `contents: write`
explicitly). Both workflows reference Actions by floating tag
(`actions/checkout@v4`, `astral-sh/setup-uv@v5`, `actions/setup-python@v5`,
`actions/upload-artifact@v4`, `actions/download-artifact@v4`,
`pypa/gh-action-pypi-publish@release/v1`). `release.yml` — the workflow
holding both `contents: write` and, for `publish-pypi`, `id-token: write`
OIDC trust — is the highest-value target for a tag-repoint supply-chain
attack. `release.yml:37` also runs `pip install python-semantic-release
build` with no version pins in a `contents: write` job (see `REL2-8` in
[`07_reliability_and_operations.md`](07_reliability_and_operations.md)
for the reliability framing of that same line).
→ Add `permissions: contents: read` at the top of `ci.yml`; pin every
third-party Action to a full 40-char commit SHA (comment the version
alongside); pin the `pip install` versions in `release.yml:37`.
**Effort: S.**

**SEC2-8. No dependency-vulnerability scanning, SAST, or secret-scanning
anywhere in the toolchain.** `.pre-commit-config.yaml` configures only
`black`, `ruff --fix`, `isort`, `end-of-file-fixer`, `trailing-whitespace`.
`pyproject.toml`'s `[tool.ruff.lint] select` omits Ruff's `S`
(bandit-equivalent) rule set. Repo-wide search found no `bandit`,
`semgrep`, `pip-audit`, `safety`, `gitleaks`, `trufflehog`,
`detect-secrets`, `.github/dependabot.yml`, or `renovate.json`.
*(Positive finding: dependencies at their exact `uv.lock`-pinned versions
— openfga-sdk 0.10.4, httpx 0.28.1, pyjwt 2.13.0, starlette 1.6.0, etc. —
were checked and none carry a known CVE at these exact versions; PyJWT
2.13.0 and Starlette 1.6.0 are specifically past the fixed versions for
several 2026 CVEs in those libraries.)*
→ Add `pip-audit` (CI step or pre-commit), a secret-scanning pre-commit
hook (gitleaks/detect-secrets), Ruff's `S` ruleset or a dedicated
bandit/semgrep job, and `.github/dependabot.yml` for both
`github-actions` and the Python ecosystem. **Effort: M** (several small,
independent additions).

**SEC2-9. CI's live-integration Docker images are unpinned/mutable, most
notably `openfga/openfga:latest`.** `docker-compose.yml:16`
(`openfga/openfga:latest`), `:45` (`redis:7-alpine`), `:52`
(`postgres:16-alpine`) — all floating tags, actually exercised in CI
(`ci.yml`'s `integration-test` job runs `make test-integration`, which
brings this stack up). `openfga:latest` floats to whatever the
maintainers push next with zero reproducibility or review point in this
repo (`quay.io/keycloak/keycloak:26.0` is already pinned correctly, for
comparison).
→ Pin `openfga` to a specific released tag and `redis`/`postgres` to a
specific patch tag or `@sha256:` digest; bump deliberately via PR.
**Effort: S.**

---

## 🟢 LOW

**SEC2-10. Runtime dependency constraints have no upper bound.**
`pyproject.toml:23-59` — every dependency is a bare `>=` with no ceiling.
`uv.lock` pins this repo's own dev/CI environment but isn't honored by
downstream `pip install`s of the published library, so a consumer's
resolver can pick any future major version — including a breaking change
to validation semantics in `pyjwt`/`httpx` — with nothing acting as a
brake. Debatable for a library in general, but worth a documented decision
for the identity/crypto-adjacent packages specifically.
→ Either bound `pyjwt`/`httpx` explicitly or document the reasoning for
leaving them open; rely on `SEC2-8`'s Dependabot addition to react quickly
either way. **Effort: S.**

**Verified non-issue, noted for completeness:** `docker/keycloak/
realm.json`'s `"sslRequired": "none"`, the demo `alice`/`alice` user, and
`docker-compose.yml`'s `admin`/`admin` are all clearly local-dev-only (the
compose file's own header says so; `.env.example` only points at
`localhost`; `cli/config.py` is a bare `os.getenv` wrapper with no
embedded fallback credentials). No code path treats these as production
defaults.

---

## Areas checked with no new findings

JWT algorithm allow-list / alg confusion (`ALGORITHMS = ["RS256"]`
hardcoded, never taken from the token header — unchanged from SEC-2); JWKS
SSRF (`issuer`/`jwks_url`/`audience` are always static constructor
arguments in every non-test instantiation site; nothing derives them from
a request header or per-tenant runtime value); SQL injection across
`storage/postgres.py`, `audit/postgres.py`, `storage/schema.py`,
`storage/sql/*.sql` (every query is parameterized, no table/schema name
interpolation anywhere); Redis/Postgres tenant-key construction
(collision-free, unlike `cache_key()`); context/contextual-tuples cache
bypass (`AuthzRequest.is_cacheable()` correctly forces any context-bearing
request to skip the cache); error handling / info disclosure at the HTTP
boundary (fixed, generic messages only — never `str(exc)` or stack
traces); audit log PII (`AuditEvent.reason_data` only ever contains
`{cache_hit, relation}`; the ABAC `context` dict is never written to any
log); DoS via `list_objects`/bulk writes (`write_tuples()`'s
100-tuple chunking from REL-8 confirmed still in place; explicit 2s
default `httpx` timeout); secrets/config hygiene (no `verify=False`, no
permissive CORS, no secret-bearing log calls, no committed private keys).

---

## Priority order

1. **SEC2-1** (cache-key collision) — the single most concrete,
   easiest-to-reproduce defect; fix before anything else touches the
   cache layer.
2. **SEC2-2 + SEC2-3** together — ship as one pass: they compose (SEC2-2
   supplies the attacker-controlled `tenant_id`, SEC2-3 is what it can be
   abused to do).
3. **SEC2-4** — cheap to at least document now; do the real per-store
   namespacing before `05`'s `ARCH2-3` wires a cache into
   `MultiTenantAuthz`.
4. **SEC2-5, SEC2-6** — small, independent, low-risk fixes (SEC2-6 shared
   with `05`).
5. **SEC2-7, SEC2-8, SEC2-9, SEC2-10** — CI/supply-chain hardening batch,
   all low-effort and independent of the code fixes above.

## Next step

Nothing in this file is shipped yet — this is a freshly filed backlog.
[`06_security_and_identity_todos.md`](06_security_and_identity_todos.md).
