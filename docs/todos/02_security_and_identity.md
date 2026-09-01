# py-authz — Security & Identity Audit

**Date:** 2026-08-31 · repo as of `revive_authz` (post-1.2.0).
**Scope:** everything on the trust boundary and the failure-mode path —
`adapters/keycloak.py` / `keycloak_fastapi.py` (token validation),
`api.py`/`core/enforcement.py` (engine concurrency + audit-on-hot-path),
`api.py`'s `MultiTenantAuthz` (tenant-isolation failure modes), and
packaging/licensing hygiene.
**Method:** traced every place an exception, a shared mutable attribute, or
an external-service failure could change an authorization outcome or take
down the enforcement path, then checked whether the corresponding test
file exercises the failure path or only the happy path.

This is the first audit filed against this repository.

---

## Identity & token validation

### 🔴 CRITICAL

**SEC-1. JWKS is fetched once per process and never refreshed — Keycloak
key rotation causes a self-inflicted outage.** `KeycloakJWTValidator.
_get_jwks()` (`adapters/keycloak.py:50-53`) fetches the JWKS document
exactly once and caches it in `self._jwks` forever. This is not an
oversight caught after the fact — it's the tested, intended behavior:
`tests/adapters/test_keycloak.py:96-108`'s `test_fetch_jwks_caches_result`
asserts exactly one HTTP call across two `_get_jwks()` invocations, and
`test_validate_raises_when_kid_unknown` (`test_keycloak.py:142-150`) shows
an unrecognized `kid` simply raises `AuthenticationError` immediately —
there is no refetch-on-miss. The moment Keycloak rotates its signing keys
(a routine operational event, scheduled or manual), **every token issued
after the rotation fails validation** with "unknown kid" until the
py-authz process is restarted. A routine IdP maintenance action becomes an
application outage with no recovery short of a redeploy.
→ On an unrecognized `kid`, refetch the JWKS once before failing (with a
short per-process cooldown to avoid a flood of refetches from a client
sending garbage `kid` values). **Effort: S.**

### 🟠 HIGH

**SEC-2. `KeycloakJWTValidator` hardcodes a JWKS path and offers no help
for Keycloak's default-audience footgun.** The validator builds its JWKS
URL as `{issuer}/protocol/openid-connect/certs`
(`adapters/keycloak.py:36`) with no OIDC discovery-document
(`.well-known/openid-configuration`) support, and requires an exact
`audience` match against `aud` with no fallback to the `azp` claim. By
default, Keycloak access tokens carry `aud: "account"` unless an operator
explicitly adds an audience mapper to the client — exactly the workaround
this repository's own maintainer had to hand-add to
`docker/keycloak/realm.json` to get the bundled example working (see
`todos.md`'s note on adding an "oidc-audience-mapper" to the
`py-authz-demo` client). Every adopter following the README's Keycloak
section will hit this identical wall on day one, with no error message
from the library pointing at the fix — `jwt.decode`'s
`InvalidAudienceError` surfaces only as a generic "Invalid token: ..."
(`adapters/keycloak.py:92-93`). There is also no generic `OIDCJWTValidator`
for Auth0/Okta/Cognito, despite the README describing Keycloak as merely
"optional" identity-provider support.
→ Support discovery-document-based JWKS resolution; give the
audience-mismatch case a clearer message pointing at Keycloak's
audience-mapper requirement; extract a generic `OIDCJWTValidator` with
`KeycloakJWTValidator` as a thin, issuer-URL-shape subclass. **Effort: M.**
→ **Shipped 2026-08-31.** New `adapters/oidc.py:OIDCJWTValidator` —
resolves its JWKS endpoint via `{issuer}/.well-known/openid-configuration`
on first use unless an explicit `jwks_url` is given, and gives audience
mismatches (`jwt.InvalidAudienceError`) an actionable message (overridable
per-provider via `_audience_error_message`). `KeycloakJWTValidator` is now
a ~20-line subclass that just passes its deterministic JWKS path
explicitly (so it still skips the discovery round trip — verified by the
unmodified `test_fetch_jwks_caches_result` still asserting exactly one
HTTP call) and overrides `_audience_error_message` with Keycloak-specific
wording naming the audience-mapper requirement directly. **Confirmed
against a real Keycloak realm**: `tests/live/test_keycloak_live.py` adds
a test using the bare `OIDCJWTValidator` (no explicit `jwks_url`) against
the same live realm `KeycloakJWTValidator`'s tests use, proving the
generic discovery path genuinely works against a real, standards-compliant
provider — not just a mocked one.

**SEC-3. An audit-logger failure can take down authorization for the whole
process, and the write sits on the synchronous hot path.**
`AuthzEngine.enforce()` (`core/enforcement.py:184-201`) builds an
`AuditEvent` and calls `await self.audit_logger.log(event)` with no
try/except around it. Any exception from the configured audit backend —
Postgres pool exhaustion, a network blip, the `jsonb` serialization bug in
REL-4 (`03_reliability_and_operations.md`) — propagates straight out of
`enforce()` uncaught, meaning **every single authorization check in the
process fails whenever the audit sink is unhealthy**, turning a logging
concern into a full-blown availability incident. The method's own comment
admits this is unfinished: `# TODO: Make this background task - slow db
can degrade performance` (`core/enforcement.py:185`). No test constructs
an `audit_logger.log()` that raises to check what `enforce()` does with
it — every audit-related test in `tests/core/
test_enforcement_audit_and_cache.py` uses a `RecordingAuditLogger` that
never fails.
→ Isolate audit-logging exceptions (log-and-continue; never let them
change the `allowed` result or propagate to the caller), and move the
write off the hot path (background task/queue) as
`docs/architecture.md:201-202` already recommends but nothing enforces.
Add a test where `audit_logger.log()` raises and assert `enforce()` still
returns the correct decision. **Effort: M.**

**SEC-4. A resolver failure can be silently reinterpreted as "tenant
doesn't exist," triggering unwanted auto-provisioning.**
`MultiTenantAuthz.for_tenant()` (`api.py:305-312`) wraps `tenant_resolver.
resolve(tenant_id)` in a bare `except Exception:` and, if a
`tenant_manager` is configured, treats **any** failure — a transient DB
timeout, a bug in a custom resolver, not just "not found" — as grounds to
auto-provision a brand-new, empty OpenFGA store. `TenantManager.
provision()` does re-check `tenant_store.get()` under lock before creating
(`tenant_manager.py:48-51`), which closes the window *only if* the
resolver and the store share the same underlying data source — a
relationship the API neither enforces nor documents. A resolver backed by
one system (e.g. a fast in-memory/cache layer) paired with a store backed
by another (a database) has no such protection: a transient resolver
failure for an existing tenant could result in a second, empty store being
created and silently overwriting that tenant's mapping, effectively
revoking every permission that tenant had ever been granted.
→ Define a dedicated `TenantNotFoundError` (or similar) that
`TenantResolver` implementations raise specifically for the "doesn't
exist yet" case; catch only that type in `for_tenant()` and let anything
else propagate as a hard failure rather than a silent reprovision.
**Effort: S.**

### 🟡 MEDIUM

**SEC-5. No fail-open/fail-closed policy, and the FastAPI adapter doesn't
translate service failures into HTTP responses.** `require_dependency`/
`require_fastapi` (`adapters/fastapi.py`) call `authz.can(...)`, which can
raise `ServiceUnavailable`/`ServiceTimeout` (from an OpenFGA outage, via
`clients/openfga.py`). Neither is caught in the adapter, so an OpenFGA
outage surfaces to every protected route as an unhandled exception (a
generic 500 with a raw traceback) instead of a clear 503 — and there is no
documented, supported way for an integrator to choose "fail open" (allow
when the dependency is down) vs. "fail closed" (deny), a decision every
production authorization integration needs to make deliberately rather
than by accident of an uncaught exception.
→ Catch `ExternalServiceError` in the adapters and map it to a 503 by
default (fail-closed), with a documented override for callers who need
fail-open behavior for specific routes. **Effort: S–M.**
→ **Shipped 2026-08-31.** New shared `_enforce()` helper in
`adapters/fastapi.py`, used by both `require_dependency` and
`require_fastapi`, catches `ExternalServiceError` and raises a 503
(`detail="Authorization service unavailable"`) by default. Both now
accept a `fail_open: bool = False` keyword — passing `True` lets the
request through instead when the dependency is degraded, documented as
an explicit, deliberate per-route opt-in rather than a global default.
Tested via both the direct-dependency-call and full-`TestClient`-request
paths, for both `fail_open=False` (503) and `fail_open=True` (request
served).

**SEC-6. `Authz.require()` mutates shared engine state to change
behavior — unsafe under concurrent use of one engine.** `api.py:136-144`
temporarily flips `self._engine.raise_on_denied` on the (normally
process-wide, shared) `AuthzEngine` instance, calls `enforce()`, then
restores the original value in a `finally`. Under concurrent asyncio
tasks — the normal shape of a web app serving many requests through one
shared engine — a task calling `Authz.enforce()` (expecting a bare `bool`)
can interleave, across the `await` inside `enforce()`, with a concurrent
`Authz.require()` call on another task, each briefly seeing the other's
`raise_on_denied` value: a `require()` call can silently return `False`
instead of raising, or an `enforce()` call can unexpectedly raise.
→ Thread `raise_on_denied` through as a per-call parameter to
`AuthzEngine.enforce()`/`_handle_result()` rather than a mutable instance
attribute. **Effort: S.**
→ **Shipped 2026-08-31.** `AuthzEngine.enforce(request, raise_on_denied=
None)` — `None` (the default) uses the engine's own configured default,
`True`/`False` overrides it for just that call; `_handle_result()` now
takes the resolved value as a required parameter instead of reading
`self.raise_on_denied`. `Authz.enforce()`/`require()` gained the same
keyword-only parameter, and `require()` now passes `raise_on_denied=True`
per-call instead of mutating `self._engine.raise_on_denied`. New
concurrency regression test: 25 concurrent `enforce()` calls and 25
concurrent `require()` calls sharing one denied engine (with a real
cache, giving `enforce()` genuine `await` points) — `enforce()` always
returned `False`, `require()` always raised, regardless of interleaving.

**SEC-7. `LICENSE` is an incomplete MIT-license placeholder.** The
repository's `LICENSE` file is three lines: the "MIT License" header and
"Copyright (c) 2026 Your Name" — missing the license's actual permission
grant and warranty-disclaimer text entirely, and using a template
placeholder name instead of the real copyright holder, despite the
README's `[MIT](LICENSE)` badge/link and `pyproject.toml`'s
`license = { text = "MIT" }` presenting it as a complete, valid license to
every consumer and to PyPI/GitHub's license detection.
→ Replace with the standard, complete MIT license text and the actual
copyright holder. **Effort: S.**
→ **Shipped 2026-08-31.** Full standard MIT license text, copyright
holder "Salad Guyo" (matching `pyproject.toml`'s `authors`), year 2025
(the repository's actual first commit, not the placeholder's 2026).

### 🟢 LOW

**SEC-8. No rate limiting anywhere in the library.** `todos.md` lists
"Rate limiting" as a planned feature; today nothing throttles calls into
Keycloak's JWKS endpoint or OpenFGA's `check` endpoint from the library
side, and there's no guidance in the docs for host applications on
protecting these paths from abusive callers. Most appropriately a
host-app-layer concern rather than something the library should own
outright, but worth an explicit docs note given it's already a known,
named gap.
→ At minimum, document the expectation that host apps rate-limit
authenticated and unauthenticated endpoints that trigger authz checks;
consider a lightweight, optional token-bucket helper for JWKS-refetch
protection (ties into SEC-1). **Effort: M.**
→ **Shipped 2026-08-31 (documentation only).** New "Known sharp edges"
bullet in `docs/architecture.md` states plainly that the library doesn't
rate-limit its own outbound OpenFGA/JWKS calls (that's the host app's
job) and names `jwks_refresh_cooldown` (SEC-1) as the one narrow,
self-protection exception the library already owns — no new code needed
since that cooldown helper already shipped with SEC-1.

---

## Next step

All findings in this file are shipped — Tier 0 (SEC-1, SEC-3, SEC-4),
Tier 1 (SEC-2, SEC-5), and Tier 2 (SEC-6, SEC-7, SEC-8).
[`02_security_and_identity_todos.md`](02_security_and_identity_todos.md).
