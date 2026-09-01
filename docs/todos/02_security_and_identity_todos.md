# py-authz — Security & Identity Backlog

Execution checklist for
[`02_security_and_identity.md`](02_security_and_identity.md). IDs match
that file.

> **Status (2026-08-31):** All three tiers shipped same day. Tier 0
> (SEC-1, SEC-3, SEC-4). Tier 1 (SEC-2, SEC-5), confirmed against a real
> Keycloak/FastAPI stack. Tier 2 (SEC-6, SEC-7, SEC-8). Nothing left open
> in this file.

---

## Tier 0 — Failure-elsewhere-shouldn't-corrupt-authz (ship together) ✅

- [x] **SEC-1 — Refetch JWKS on unknown `kid` before failing.**
  `KeycloakJWTValidator._get_jwks()` takes a `force_refresh` flag; on an
  unrecognized `kid`, `validate()` now calls it once with
  `force_refresh=True` before giving up. Refetches are rate-limited via a
  new `jwks_refresh_cooldown` constructor param (default 60s), tracked
  independently of the initial cache fill so the *first* forced refresh
  is never blocked by its own cooldown. `tests/adapters/test_keycloak.py`
  adds a `SequencedHTTPClient` test double and covers: still-unknown-kid
  raises after exactly one refetch attempt, a rotated key is picked up via
  the refetch, repeated forced refreshes within the cooldown are
  suppressed, and a forced refresh is allowed again once the cooldown
  elapses.
- [x] **SEC-3 — Isolate audit-logger failures from the authz decision.**
  `AuthzEngine._dispatch_audit_event()` now fires the audit write as a
  background `asyncio` task (`_log_audit_event()`, wrapped in try/except
  that logs-and-continues on any failure) instead of awaiting it inline —
  closing the engine's own `# TODO: Make this background task` comment.
  Added `AuthzEngine.flush_audit_logs()` to await in-flight writes
  (tests; graceful shutdown). `tests/core/test_enforcement_audit_and_cache.py`
  updated to flush before asserting on recorded events, and gains
  `test_enforce_survives_audit_logger_failure` /
  `test_enforce_denied_survives_audit_logger_failure` locking in that a
  failing audit sink never changes or blocks the returned decision.
  `docs/architecture.md`'s request-lifecycle diagram and "Audit logging"
  section updated to describe the new backgrounded, failure-isolated
  behavior.
- [x] **SEC-4 — Add `TenantNotFoundError` and stop swallowing arbitrary
  resolver exceptions.** New `TenantNotFoundError(AuthzError)` in
  `core/exceptions.py`. `StaticTenantResolver.resolve()` raises it instead
  of a bare `ValueError`; `TenantResolver`'s docstring documents the
  contract. `MultiTenantAuthz.for_tenant()`'s `except Exception` narrowed
  to `except TenantNotFoundError` — anything else now propagates as a
  hard failure instead of triggering auto-provisioning.
  `examples/06_multitenant.py`'s `_StoreBackedResolver` updated to match.
  `tests/api/test_multi_tenant.py` adds
  `test_for_tenant_does_not_auto_provision_on_arbitrary_resolver_error`
  (a `RuntimeError` from the resolver propagates, and no store is
  provisioned), and its existing tests were updated from `KeyError` to
  `TenantNotFoundError`. **Note: this is a breaking change** for any
  custom `TenantResolver` that previously relied on raising an arbitrary
  exception to trigger auto-provisioning — it must now raise
  `TenantNotFoundError` specifically; worth a changelog callout.

## Tier 1 — Production-Keycloak hardening ✅

- [x] **SEC-2 — OIDC discovery + audience-mismatch guidance + generic
  validator.** New `adapters/oidc.py:OIDCJWTValidator` resolves the JWKS
  URL from `{issuer}/.well-known/openid-configuration` on first use
  unless an explicit `jwks_url` is given; `_audience_error_message()` is
  overridable per provider. `KeycloakJWTValidator` (`adapters/
  keycloak.py`) is now a thin subclass passing its deterministic JWKS
  path explicitly (skipping discovery — unchanged, fast behavior) and
  overriding the audience-mismatch message with Keycloak-specific
  guidance naming the audience-mapper requirement. New
  `tests/adapters/test_oidc.py` (discovery resolution + caching, explicit
  `jwks_url` skips discovery, generic audience-mismatch message); new
  Keycloak-specific audience-message test and a `jwks_url`
  backward-compatibility test in `tests/adapters/test_keycloak.py`.
  **Confirmed against a real Keycloak realm**: `tests/live/
  test_keycloak_live.py` adds a test using bare `OIDCJWTValidator` (no
  explicit `jwks_url`) against the same live realm, proving discovery
  genuinely resolves and validates against a real provider.
- [x] **SEC-5 — Translate service failures into HTTP responses in the
  FastAPI adapter, with a documented fail-open/fail-closed choice.** New
  shared `_enforce()` helper in `adapters/fastapi.py` catches
  `ExternalServiceError` and raises a 503 by default; both
  `require_dependency` and `require_fastapi` gain a `fail_open: bool =
  False` keyword to opt a route into letting the request through instead
  during an outage. `tests/adapters/test_fastapi_extras.py` adds
  coverage for both the direct-call and full-`TestClient`-request paths,
  for both `fail_open=False` (503) and `fail_open=True` (request served).

## Tier 2 — Independent fixes ✅

- [x] **SEC-6 — Make `raise_on_denied` a per-call parameter, not mutable
  shared state.** `AuthzEngine.enforce(request, raise_on_denied=None)` —
  `None` uses the engine's default, an explicit `True`/`False` overrides
  it for that call only; `_handle_result()` now requires the resolved
  value as a parameter. `Authz.enforce()`/`require()` gained the same
  keyword; `require()` passes `raise_on_denied=True` per-call instead of
  mutating `self._engine.raise_on_denied`. New concurrency test: 25
  concurrent `enforce()` + 25 concurrent `require()` calls sharing one
  denied engine (with a real cache for genuine `await` points) — each
  always got its own correct behavior regardless of interleaving.
- [x] **SEC-7 — Replace the LICENSE placeholder with the complete MIT
  text and the real copyright holder.** Done — "Salad Guyo", 2025 (the
  repository's actual first commit).
- [x] **SEC-8 — Document rate-limiting expectations for host apps.**
  New "Known sharp edges" bullet in `docs/architecture.md`: the library
  doesn't rate-limit its own outbound calls (host app's job), except the
  narrow, already-shipped `jwks_refresh_cooldown` (SEC-1) protecting one
  specific internal code path — no new rate-limiting code was needed.

---

## Next step

All three tiers are shipped. Nothing left open in this file.
