# py-authz — Security & Identity Backlog (Round 2)

Execution checklist for
[`06_security_and_identity.md`](06_security_and_identity.md). IDs match
that file.

> **Status (2026-09-02):** Tiers 0–2 shipped. `SEC2-4` was pulled forward
> and shipped alongside `05`'s `ARCH2-3`; `SEC2-6` (a cross-reference)
> resolved alongside `05`'s ARCH2-9. Only Tier 3 (CI/supply-chain
> hardening) remains open.

---

## Tier 0 — Ship first, ahead of everything else in this audit round ✅

- [x] **SEC2-1 — Make `AuthzRequest.cache_key()` injective.**
  Each field is now length-prefixed (`f"{len(field)}:{field}"`) before
  joining with `|`. New regression test
  `test_cache_key_is_injective_across_colon_boundaries`
  (`tests/core/test_types.py`) locks in the exact collision case
  described in the findings doc. Note: this changes the cache-key format,
  effectively invalidating any pre-upgrade cache entries on deploy (they
  simply miss once, not collide — which is the point).

## Tier 1 — Multi-tenant trust boundary (ship together — they compose) ✅

- [x] **SEC2-2 — Fix the `X-Tenant-ID` trust boundary.** Kept
  `tenant_from_request` but its docstring now leads with an explicit
  "insecure by itself — demo/development use only" warning. New
  `tenant_from_verified_claim(claim="tenant_id")` reads the tenant from
  `request.state.user.attributes` (the verified JWT payload — see `05`'s
  ARCH2-7, which is what makes `attributes` populated) instead of a raw
  header. `examples/12_multitenant_fastapi.py` gained a security-note
  comment (its "auth" is an intentional fake-header stand-in, so there's
  no real claim to switch it to). New tests confirm the safe resolver
  ignores a spoofed header and correctly rejects a missing claim.
- [x] **SEC2-3 — Validate and bound tenant auto-provisioning.**
  `TenantManager` validates every `tenant_id` against
  `DEFAULT_TENANT_ID_PATTERN` (overridable via `tenant_id_pattern=`)
  before any lookup/lock/store-creation, raising `InvalidAuthzRequest` on
  a mismatch. `MultiTenantAuthz`'s tenant cache is now LRU-bounded
  (`max_cached_tenants`, default 1000, evicting in the background) instead
  of unconditionally unbounded. New tests cover pattern rejection, a
  custom pattern, LRU eviction under a small cap, and recently-used-tenant
  protection from eviction.

## Tier 2 — Cache/tenant namespacing (do before `05`'s ARCH2-3 ships)

- [x] **SEC2-4 — Give cache keys a mandatory tenant/store-scoping
  component.** `AuthzEngine` now accepts `cache_namespace`, applied via a
  new `_scoped_cache_key()` helper used by both `enforce()` and
  `invalidate()`. `MultiTenantAuthz.for_tenant()` passes
  `cache_namespace=store_id` for every tenant's engine. New test
  `test_cache_namespace_isolates_engines_sharing_one_cache_backend`
  (`tests/core/test_enforcement_audit_and_cache.py`) proves two engines
  sharing one cache backend but different namespaces don't read back each
  other's decisions. **Shipped together with `05`'s ARCH2-3**, as planned.
- [x] **SEC2-6 — See `05`'s ARCH2-9** (`MultiTenantAuthz.for_tenant()`
  check-then-act race) — fixed there (shipped 2026-09-02); this file's
  finding was a cross-reference only.

## Tier 3 — Independent hardening (small, parallelizable)

- [ ] **SEC2-5 — Structure the tenant-provisioning and migration log
  lines** (`tenant_manager.py`, `migrations_manager.py`) through
  `json.dumps({...})` or `logger.info(..., extra={...})`, matching
  `core/enforcement.py`'s existing pattern, to close the log-injection gap
  on attacker-reachable `tenant_id` values.
- [ ] **SEC2-7 — CI hardening**: add `permissions: contents: read` to
  `ci.yml`; pin every third-party GitHub Action (in both `ci.yml` and
  `release.yml`) to a full commit SHA; pin `python-semantic-release`/
  `build` versions in `release.yml`'s `pip install` line.
- [ ] **SEC2-8 — Add supply-chain scanning**: `pip-audit` (CI step or
  pre-commit hook), a secret-scanning pre-commit hook (gitleaks or
  detect-secrets), Ruff's `S` ruleset or a bandit/semgrep job, and
  `.github/dependabot.yml` for both `github-actions` and the Python
  ecosystem.
- [ ] **SEC2-9 — Pin CI's Docker Compose images**: give `openfga/openfga`
  a specific released tag (not `:latest`) and pin `redis`/`postgres` to
  specific patch tags or digests.
- [ ] **SEC2-10 — Decide and document (or add) upper-bound version
  constraints** for `pyjwt`/`httpx` in `pyproject.toml`, given their
  identity/crypto-adjacent role.

---

## Next step

Ship Tier 0 (SEC2-1) immediately and independently of everything else.
Then Tier 1 (the tenant-trust-boundary pair), Tier 2 (cache namespacing,
coordinated with `05`'s ARCH2-3), and Tier 3 (CI/supply-chain hardening,
fully parallelizable and low-risk) in any order.
