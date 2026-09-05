# py-authz — Developer Experience & Test Coverage Backlog (Round 2)

Execution checklist for
[`08_developer_experience_and_testing.md`](08_developer_experience_and_testing.md).
IDs match that file.

> **Status (2026-09-05):** Tiers 0–2 shipped 2026-09-02 (`DX2-1` through
> `DX2-5`), `DX2-10`/`DX2-12` (Tier 4 cross-references) resolved the same
> day as side effects. Tier 4's remaining item (`DX2-9`), all of Tier 5
> (`DX2-13` through `DX2-16`), and all of Tier 6 (`DX2-7`, `DX2-8`,
> `DX2-17` through `DX2-20`, plus the batched Low-severity items) shipped
> 2026-09-05. Tier 3 (`DX2-6`, `DX2-11` — live tests) also shipped
> 2026-09-05, confirmed passing against a real OpenFGA server. **This
> backlog (`08`) is now fully closed.**

---

## Tier 0 — Ship first ✅

- [x] **DX2-1 — Fix `bulk_enforce()`'s exception contract.** Added an
  `error: Exception | None = None` field to `BulkAuthzResult`;
  `bulk_enforce()`'s worker now catches per-request exceptions and
  records them there instead of letting them escape the task group. New
  regression test
  `test_bulk_enforce_captures_per_request_errors_without_losing_others`
  confirms no `ExceptionGroup` and no discarded results.

## Tier 1 — Type-safety and packaging correctness ✅

- [x] **DX2-2 — Re-enable `arg-type`/`union-attr` in mypy.** New
  `core/protocols.py:FGAClientProtocol` — `AuthzEngine.fga_client` is now
  typed against it instead of the concrete `OpenFGAClient` class, so
  `testkit.make_fake_authz()` type-checks correctly (`InMemoryFGAClient.
  store_id` widened to `str | None` to match invariantly). Fixed
  `context.py`'s `ContextVar[str | None]` annotation. Fixed `api.py:236`'s
  `list_objects()` guard to narrow correctly (incidentally also fixing
  `DX2-12`). Two remaining errors narrowly suppressed with documented
  `# type: ignore[arg-type]` (PyJWT's `from_jwk` stub; `sync_model()`'s
  inherent need for a real `OpenFGAClient`). `mypy py_authz` passes clean
  with both codes re-enabled in `pyproject.toml`.
- [x] **DX2-3 — Add a `py.typed` marker.** Empty `py_authz/py.typed`
  added to `[tool.setuptools.package-data]` alongside `storage/sql/*.sql`;
  confirmed present in an actual built wheel.

## Tier 2 — Fail-safe hardening on the enforcement path ✅

- [x] **DX2-4 — Make cache failures non-fatal in `enforce()`.** Both the
  cache `get()` (in `enforce()`) and `set()` (in the new
  `_check_and_cache()` helper from `07`'s REL2-6) now catch, log, and
  fall through/complete without affecting the decision. New tests mirror
  `test_enforce_survives_audit_logger_failure` for both cache directions.
- [x] **DX2-5 — Handle a missing `kid` claim cleanly in
  `OIDCJWTValidator.validate()`.** `unverified_header.get("kid")` +
  explicit `AuthenticationError` on `None`. New test covers a token with
  no `kid` header.

## Tier 3 — Test-suite composition (closes the "mock both sides" gap) ✅

- [x] **DX2-6 — Add `tests/live/test_multi_tenant_live.py`** exercising
  `MultiTenantAuthz` with its real `StaticTenantResolver`/`TenantManager`
  classes against real OpenFGA, mirroring `tests/storage/test_hybrid.py`'s
  real-class pattern. Two tests: `test_for_tenant_provisions_real_tenant_
  and_enforces_correctly` drives a fresh-provision path (`StaticTenantResolver`
  with an empty mapping, so every call falls through to the real
  `TenantManager`) through a real `create_store()` + `ModelSync(client).
  sync(force=True)` + `enforce()`, proving a real `False` → `grant()` →
  real `True` decision; `test_for_tenant_reuses_already_provisioned_tenant_
  without_reprovisioning` uses two independent `MultiTenantAuthz` instances
  sharing one real `TenantManager`/`tenant_store` (so the outer per-instance
  LRU cache can't mask the effect) to prove `TenantManager.provision()`'s
  own double-checked-locking early return actually fires against a real,
  already-persisted mapping — no second store gets created, and both
  engines resolve to the same real store. Both tests use `InMemoryTenant
  Store` (per the finding's own guidance — the point is exercising
  `TenantManager`/`ModelSync`, not re-covering a persistence backend
  already tested live elsewhere) and clean up every store they create via
  `OpenFGAClient.delete_store()` (ARCH2-8). **Effort: M — shipped.**
- [x] **DX2-11 — Folded a live `MigrationManager.migrate_tenant()` run
  into the same file** (`test_multi_tenant_live.py`), rather than a
  separate `test_migrate_live.py` — the setup (a `TenantManager`-provisioned
  tenant on a real store) is identical to `DX2-6`'s own fixtures, so
  splitting it out would only have duplicated them. `test_migrate_tenant_
  runs_real_model_sync_and_reports_unchanged` migrates an already-provisioned
  tenant immediately after provisioning and confirms the real
  `ModelSync(client).sync()` call correctly reports no change
  (`ModelSync.last_sync_changed` — ARCH2-17) — `model_registry` is
  asserted untouched — then double-checks the model id `migrate_tenant()`
  returned actually matches what `client.get_latest_model()` reads back
  from the live server. `test_migrate_tenant_raises_tenant_not_found_for_
  unknown_tenant` covers the "no such tenant" branch too. **Effort:
  S/M — shipped.**

  **Live-server confirmation:** started `docker compose up -d openfga`,
  waited for `curl -sf http://localhost:8082/healthz`, then ran
  `FGA_API_URL=http://localhost:8082 uv run pytest tests/live/test_multi_
  tenant_live.py -q --no-cov` — **4 passed**. Without `FGA_API_URL` set,
  the same file reports **4 skipped** (the same `requires_openfga`
  skip-gate/message every other file in `tests/live/` uses), confirming
  `make test`/plain `pytest` stay fast and fully offline by default.

## Tier 4 — Small, independent correctness fixes ✅

- [x] **DX2-9** — add an optional `leeway: float = 0` constructor
  parameter threaded to `jwt.decode()` in `adapters/oidc.py`. Also
  threaded through `KeycloakJWTValidator.__init__` for parity. New tests
  `test_token_just_outside_default_leeway_rejected_with_leeway_zero`/
  `_accepted_with_generous_leeway` (`tests/adapters/test_oidc.py`) confirm
  the parameter actually reaches `jwt.decode(..., leeway=...)`.
- [x] **DX2-10 — See `05`'s ARCH2-9** (`MultiTenantAuthz.for_tenant()`
  check-then-act race) — fixed there (shipped 2026-09-02); this file's
  finding was a cross-reference only.
- [x] **DX2-12** — fix `list_objects()`'s unbound-`Relation` guard to
  check falsiness consistently. **Shipped 2026-09-02**, incidentally,
  while fixing the same line's mypy error for DX2-2. New tests in
  `tests/api/test_relation_api.py` cover both the `None`- and
  empty-string-`resource_type` unbound-`Relation` `TypeError` paths.

## Tier 5 — CLI polish (batch together) ✅

- [x] **DX2-13** — add a `--version` flag backed by
  `importlib.metadata.version('py-authz')`. Falls back to a clearly
  labeled `"unknown (not installed)"` string rather than crashing in a
  non-installed source checkout. New test
  `test_main_version_flag_prints_version_and_exits_cleanly`.
- [x] **DX2-14** — add `help=` text to every subparser and argument
  missing it; add an `epilog=` with example invocations. Top-level
  parser and all three subparsers (`generate-model`/`sync`/`migrate`) now
  have `description=`/`help=`/`epilog=` with real invocation examples,
  via `argparse.RawDescriptionHelpFormatter`.
- [x] **DX2-15** — add an opt-in `--json` output flag to `sync`/`migrate`.
  `sync --json` prints `{"store_id", "active_model_id"}`; `migrate --json`
  prints `{"succeeded", "failed"}` (or `{"dry_run", "changes"}` for
  `--dry-run`, or `{"tenants_found": 0, ...}` when nothing matched) —
  `result.failed`'s `Exception` values are `str()`-ed for JSON safety.
  New tests in `tests/cli/test_sync_command.py`/`test_migrate_command.py`.
- [x] **DX2-16** — document the flag-over-env-var precedence and the full
  env-var list, in both README and `--help` strings. A shared `_ENV_VARS`
  block appears in the top-level epilog and `sync`/`migrate`'s own
  epilogs; every config flag's `help=` also names its env var
  (`help="... (env: FGA_STORE_ID)"`). README's CLI section states the
  precedence rule and points to `--help` for the per-command list.

## Tier 6 — Docs accuracy sweep (batch together, all small) ✅

- [x] **DX2-7** — fix the OpenFGA port (8080 → 8082) in `README.md`,
  `docs/getting_started.md` (×2), and `examples/README.md` (×2, its
  Prerequisites section's `docker compose`/`curl` lines — the seed-script
  env-var example a few lines below was already correct). Verified
  against `docker-compose.yml`'s `"8082:8080"` mapping first.
- [x] **DX2-8** — fix README's `MigrationManager` usage example
  (keyword-only constructor, `migrate_all(tenant_ids)` returning a
  `MigrationBatchResult` not `apply_all()`); added `migrate` (with
  `--dry-run`/`--yes`/`--json`) to the CLI section, plus a note on the
  CLI-flag/env-var precedence rule.
- [x] **DX2-17** — rewrote `docs/getting_started.md`'s `inherits=`
  explanation to match `modeling/base.py`'s corrected semantics
  (`inherits` is just a `union` alias) and added a worked
  `from_parent=(tupleset_relation, computed_relation)` example for the
  cross-object hierarchy case, pointing at
  `examples/11_hierarchical_permissions.py`.
- [x] **DX2-18** — added `CONTRIBUTING.md` (extracted from README's
  Development section, plus a PR-submission checklist and the
  Conventional-Commits/release-automation note) and `SECURITY.md` (GitHub
  private security advisories as the primary report channel, with a
  response-time SLA). README's Development section now just links to
  both.
- [x] **DX2-19** — deleted the stale top-level `todos.md` (it was
  git-ignored, not tracked — its one still-relevant note, the Keycloak
  `oidc-audience-mapper` config, was already independently captured in
  `docker/keycloak/realm.json`, `adapters/keycloak.py`, and `02`'s
  findings doc; everything else was already-shipped scratch notes or
  unrelated personal drafts).
- [x] **DX2-20** — added `examples/13_fail_open_fastapi.py`: a
  fail-closed and a fail-open route on the same resource side by side,
  with `docker compose stop openfga` instructions to see them diverge on
  a real outage. Registered in `examples/README.md`.
- [x] Stale README badges — version badge bumped to `1.4.0`; the
  "Status: production" badge (linking to a nonexistent PyPI project page)
  now reads "not yet on PyPI" and links to the repo's real Releases page;
  the `@v1.2.0` install-example tag bumped to `@v1.4.0` (both occurrences).
- [x] Fixed `adapters/keycloak_fastapi.py`'s bearer-token split
  (`auth_header.split(" ")[1]` → `.removeprefix("Bearer ")`) — clearer
  than `split(" ", 1)[1]` given the preceding `.startswith("Bearer ")`
  check. New regression test
  `test_middleware_extracts_token_containing_a_space`.
- [x] Renamed `tests/integration/` → `tests/mocked_integration/` (`git
  mv`, one file) — no CI/Makefile/other-test references existed to
  update (confirmed via grep first); the module's own docstring already
  correctly self-identified as mocked, this just fixes the misleading
  directory name against `tests/live/`.
- [x] Added a lock (`asyncio.Lock`, matching `MultiTenantAuthz.
  _resolution_lock`'s existing check-then-act double-checked-locking
  idiom in `api.py`) around `OIDCJWTValidator._get_jwks()`'s cold-start
  and post-rotation forced-refresh fetches. New tests
  `test_concurrent_cold_start_calls_only_fetch_jwks_once`/
  `_concurrent_force_refresh_calls_only_fetch_jwks_once` confirm exactly
  one underlying fetch happens under 10 concurrent callers.

---

## Next step

All tiers (0–6) are shipped. `DX2-6`/`DX2-11` — the last two open items —
shipped 2026-09-05 as `tests/live/test_multi_tenant_live.py`, confirmed
passing against a real OpenFGA server (`docker compose up -d openfga`).
**This backlog (`08`) is now fully closed; no further action is tracked
here.**
