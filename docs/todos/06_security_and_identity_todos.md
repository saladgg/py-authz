# py-authz — Security & Identity Backlog (Round 2)

Execution checklist for
[`06_security_and_identity.md`](06_security_and_identity.md). IDs match
that file.

> **Status (2026-09-05):** Tiers 0–3 shipped — this file is fully closed.
> `SEC2-4` was pulled forward and shipped alongside `05`'s `ARCH2-3`;
> `SEC2-6` (a cross-reference) resolved alongside `05`'s ARCH2-9. Tier 3
> (CI/supply-chain hardening) shipped 2026-09-05.

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

## Tier 3 — Independent hardening (small, parallelizable) ✅

- [x] **SEC2-5 — Structure the tenant-provisioning and migration log
  lines** (`tenant_manager.py`, `migrations_manager.py`) through
  `json.dumps({...})` or `logger.info(..., extra={...})`, matching
  `core/enforcement.py`'s existing pattern, to close the log-injection gap
  on attacker-reachable `tenant_id` values.
  Both files' `provision_*`/`migration_*` log lines now go through
  `json.dumps({"event": ..., "tenant": tenant_id, ...})`, matching
  `core/enforcement.py`'s existing structured-logging convention exactly
  — no more raw f-string interpolation of an attacker-reachable
  `tenant_id` into a log message.
- [x] **SEC2-7 — CI hardening**: add `permissions: contents: read` to
  `ci.yml`; pin every third-party GitHub Action (in both `ci.yml` and
  `release.yml`) to a full commit SHA; pin `python-semantic-release`/
  `build` versions in `release.yml`'s `pip install` line.
  `ci.yml` now declares workflow-level `permissions: contents: read`
  (least-privilege; `release.yml`'s broader `contents: write`/
  `id-token: write` scoping was already correct and is unchanged). Every
  `uses:` in both workflows (`actions/checkout`, `astral-sh/setup-uv`,
  `actions/setup-python`, `actions/upload-artifact`,
  `actions/download-artifact`, `pypa/gh-action-pypi-publish`) is now
  pinned to a full commit SHA resolved live via `gh api` against the
  version each tag currently pointed to, with a trailing `# vX.Y.Z`
  comment. `release.yml`'s `pip install python-semantic-release==10.6.2
  build==1.6.0` was already pinned (`REL2-12`) — left as-is.
- [x] **SEC2-8 — Add supply-chain scanning**: `pip-audit` (CI step or
  pre-commit hook), a secret-scanning pre-commit hook (gitleaks or
  detect-secrets), Ruff's `S` ruleset or a bandit/semgrep job, and
  `.github/dependabot.yml` for both `github-actions` and the Python
  ecosystem.
  `pip-audit` added as a `dev`-group dependency, a new `make audit`
  target, and a new `Audit dependencies` step in `ci.yml`'s `lint-test`
  job (chosen over a pre-commit hook since this repo's CI doesn't run
  `pre-commit` itself, so a step that must actually gate merges belongs
  in CI) — clean run, no known vulnerabilities. `gitleaks` added as a new
  pre-commit hook (`.pre-commit-config.yaml`). Ruff's `S` ruleset added
  to `pyproject.toml`; its only two classes of finding (663× `S101`
  `assert` across `tests/**`, one `S101` type-narrowing assert in
  `core/enforcement.py`) are silenced via a `tests/**` per-file-ignore and
  one inline `# noqa: S101` respectively — both documented inline, no
  ruleset left broken. `.github/dependabot.yml` added, covering both the
  `github-actions` and `pip` ecosystems on a weekly schedule.
- [x] **SEC2-9 — Pin CI's Docker Compose images**: give `openfga/openfga`
  a specific released tag (not `:latest`) and pin `redis`/`postgres` to
  specific patch tags or digests.
  `docker-compose.yml` (the only compose file; `make test-integration` /
  `ci.yml`'s `integration-test` job both target it) now pins
  `openfga/openfga:v1.19.0` (latest stable release as of 2026-09-05),
  `redis:7.4.11-alpine`, and `postgres:16.15-alpine` — all specific patch
  tags, no floating `:latest`/bare-major tags left.
- [x] **SEC2-10 — Decide and document (or add) upper-bound version
  constraints** for `pyjwt`/`httpx` in `pyproject.toml`, given their
  identity/crypto-adjacent role.
  Decided to add upper bounds, documented inline in `pyproject.toml`:
  `httpx>=0.28.1,<1` and `pyjwt[crypto]>=2.13.0,<3` (both occurrences,
  including the `all` extra). Reasoning captured next to each constraint;
  `SEC2-8`'s new Dependabot config still reacts quickly to an in-range
  release either way.

---

## Next step

Nothing left open in this file — Tiers 0 through 3 have all shipped.
Any further security/identity work belongs in a future audit round, not
this backlog.
