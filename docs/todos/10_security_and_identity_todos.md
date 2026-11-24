# py-authz — Security & Identity Backlog (Round 3)

Execution checklist for
[`10_security_and_identity.md`](10_security_and_identity.md). IDs match
that file.

> **Status (2026-11-24):** Tier 0 shipped as one change (SEC3-1, SEC3-2,
> SEC3-3, plus the live end-to-end test), together with SEC3-4 from
> Tier 1, which touched the same role-assignment function. SEC3-3 is now
> **reproduced** against a real OpenFGA, not just inferred: the pre-fix
> model shape returns a 400 on both write and check for a `service:`
> principal. Tier 1 is now fully shipped too: SEC3-6 and SEC3-7 landed
> in the second batch (2026-11-24). Remaining tiers open.

---

## Tier 0 — Service-account trust boundary (ship together, first) ✅

- [x] **SEC3-3 — Give SAs a real subject type.** Add a `service_account`
  type to `rbac_model.py`, with `subjects=["user","service_account"]` on
  every `system`/`tenant` relation. Add `subject_kind` to the role-grant
  and role-revoke schema (`routes/operators.py:159,185`).
  Shipped:
  - New subject-only `ServiceAccountSubject` type, and
    `subjects=ROLE_SUBJECTS` on every role relation.
  - `RoleAssignment.subject_kind` (`user` | `service_account`). Granting
    to an unknown or revoked SA is a 400; revoking from one still works,
    since that's cleanup.
  - The panel's roles screen gained a subject-type picker and parses
    `service_account:` subjects on revoke.
  - Existing deployments pick up the new RBAC model automatically: the
    control plane re-syncs it at startup.
  - New `test_every_role_relation_accepts_users_and_service_accounts`.
- [x] **SEC3-2 — Key SA identity on the immutable id; close the
  rotate/re-create escalation.** Principal becomes
  `service_account:<sa_id>`. Rotate, revoke and create require an
  effective role ≥ the target SA's role. Revoke deletes the SA's RBAC
  tuples. Regression test: an admin cannot rotate an owner-held SA, and
  a re-created name doesn't inherit grants.
  Shipped:
  - New `control_plane/role_grants.py`:
    - `direct_role_grants()` reads every `system:`/`tenant:` role tuple
      for a principal, paginated.
    - `dominates()` returns true only if the caller holds a role ≥ each
      of those grants on the same object; `system#owner` always
      dominates.
  - Rotate and revoke both require domination. Revoke deletes every
    grant and reports `roles_removed`.
  - Create needs no domination check, because a new SA holds no roles.
  - Regression tests cover:
    - admin vs. an owner-held SA (the exact reproduced escalation);
    - admin vs. an SA holding an unrelated tenant role, since system and
      tenant scopes are independent;
    - the allowed dominated case;
    - system owner;
    - revoke cleanup;
    - id-not-name principal keying.
  - The testkit's `read_tuples` learned OpenFGA's bare-type object
    filter (`"tenant:"`).
- [x] **SEC3-1 — Enforce scopes, deny by default.** Closed scope enum,
  validated on create. Every route dependency declares its scope. An SA
  hitting a route with no declared scope gets 403. Parametrized test
  over every route × an SA without the scope → 403.
  Shipped:
  - **New `control_plane/scopes.py`.** `Scope` is a `StrEnum` of 16
    `resource:read|write` scopes. `ANY_PRINCIPAL` is a non-grantable
    sentinel, used only by `GET /auth/me`.
  - **`scope=` is a required keyword on every auth factory.** There's no
    default to forget, and a typo fails at import time. A new
    `authenticated(scope=...)` factory covers routes that do their own
    RBAC (`/operators`, `/auth/me`).
  - **Create validates scopes.** `ServiceAccountCreateRequest.scopes:
    list[Scope]` returns a 422 for an unknown scope.
  - **Deny by default, enforced as a test.**
    `tests/control_plane/test_route_scopes.py` walks every route in
    `app.API_ROUTERS` (newly a module constant, so the test sees exactly
    what's served) and fails if any route lacks a scope-tagged
    dependency or depends on `get_current_principal` directly.
  - **Behavioural test on a real route.** In
    `test_scopes_are_enforced_on_a_real_production_route`, an owner-role
    SA without `metrics:read` gets 403, and with it gets 200.
  - **Panel scope picker** updated to the enum.
  - **Breaking:** SAs created with pre-enum free-form scopes (e.g.
    `models:sync`) keep them in the database, but those strings no
    longer match anything. Recreate such SAs. In practice SAs never
    worked against a real OpenFGA before SEC3-3, so no working
    deployment depended on them.
- [x] **Live test** (with `13`'s DX3-1): create an SA, grant it a role,
  authenticate with its secret, call a scoped route against a real
  OpenFGA.
  `test_operator_and_service_account_flows_end_to_end` runs against the
  full compose stack and passes, along with the 35 existing live tests.

## Tier 1 — Operator RBAC and cache correctness ✅

- [x] **SEC3-4 — Grants/revokes only strictly below the caller's own
  role.** `tenant#owner` changes require `tenant#owner` or
  `system#owner`. Flip `test_granting_a_tenant_role_accepts_tenant_admin`
  to cover the role being granted.
  Pulled into Tier 0, since it's the same `_require_role_management`
  function. The rule:
  - `system#owner` may manage anything.
  - `tenant#owner` may manage any role on that tenant.
  - `tenant#admin` may manage only `operator`, `auditor` and `viewer`.

  New tests: an admin can't promote anyone to owner, can't grant a peer
  admin role, and can't revoke an owner; a tenant owner can manage
  owners. The existing accepts-tenant-admin test still passes, because it
  grants `auditor`, which is below admin.
- [x] **SEC3-6 — Resolve tenant → store id in `/cache/invalidate`;
  prefix match; escape glob metacharacters.** Replace the two tests that
  encode the bug. Also needed by `12`'s REL3-4.
  Shipped:
  - The route resolves the store id via `tenant_store` (404 on an
    unknown tenant). Tenant and tenant+user modes use the new
    `RedisCache.delete_by_prefix()`; user-across-all-tenants stays a
    fragment match.
  - Every caller-supplied fragment or prefix is glob-escaped, so
    `tenant_id="*"` is now just an unknown tenant.
  - The route tests were rewritten to run the **real** `RedisCache` over
    a new shared `tests/fake_redis.py`, which implements Redis's own
    glob semantics including escapes. Two tenants' keys are written by
    real `AuthzEngine`s namespaced by store id, and the tests assert
    which keys survive, not which strings were passed. Four of the new
    tests fail on the old route.
- [x] **SEC3-7 — Deprovision deletes `tenant:<id>` RBAC tuples** (and
  optionally `model_versions` rows). Test: re-provision the same id → the
  old admin has no access.
  Shipped: the deprovision route calls the new
  `role_grants.delete_object_role_grants()` (paginated read, then revoke
  each, audited with the acting principal) and reports `roles_removed`.
  The test covers user and service-account grants removed while another
  tenant's grants are untouched. `model_versions` rows are deliberately
  kept as history.

## Tier 2 — Token acceptance and the RBAC store's own exposure

- [ ] **SEC3-8 — Require `exp`/`iat`/`sub`/`iss`/`aud`; optional
  `expected_typ`/`allowed_azp`; separate control-plane client and
  audience in docs and env examples; move `record_login` after the RBAC
  check.**
- [ ] **SEC3-5 — OpenFGA auth support plus a shared-unauthenticated
  warning.** Depends on `11`'s ARCH3-11 (a shared connection object to
  carry credentials). Document isolating the RBAC store.

## Tier 3 — Hardening (small, parallelizable)

- [ ] **SEC3-9 — Validate the SA id format; don't track failures for
  unknown ids; bound the limiter dicts.**
- [ ] **SEC3-10 — CSV formula neutralisation plus `charset=utf-8`.**
  Add a unit test once `13`'s DX3-7 gives the panel a test runner.
- [ ] **SEC3-11 — Generic 5xx detail plus request id; no exception text
  on `/health`; `CONTROL_PLANE_EXPOSE_DOCS=false` default.**
- [ ] **SEC3-12 — Sealed session `iat`/`exp`; POST logout with refresh
  revocation and `end_session_endpoint`; security headers in
  `next.config.ts`.**
- [ ] **SEC3-13 — Lockout keyed on (account, network), or backoff
  instead of a hard lockout.**
- [ ] **SEC3-14 — `KeycloakAuthMiddleware` returns a `JSONResponse`, not
  `raise HTTPException`.**
- [ ] **SEC3-15 — npm Dependabot, `pnpm audit`, `uv sync --locked`,
  semantic-release refreshes `uv.lock`.**
