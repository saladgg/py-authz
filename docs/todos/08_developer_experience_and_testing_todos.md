# py-authz — Developer Experience & Test Coverage Backlog (Round 2)

Execution checklist for
[`08_developer_experience_and_testing.md`](08_developer_experience_and_testing.md).
IDs match that file.

> **Status (2026-09-02):** Tiers 0–2 shipped (`DX2-1` through `DX2-5`).
> `DX2-10`/`DX2-12` (Tier 4 cross-references) also resolved as side
> effects. Tiers 3, 5, 6, and the rest of Tier 4 remain open.

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

## Tier 3 — Test-suite composition (closes the "mock both sides" gap)

- [ ] **DX2-6 — Add `tests/live/test_multi_tenant_live.py`** exercising
  `MultiTenantAuthz` with its real `StaticTenantResolver`/`TenantManager`
  classes against real OpenFGA, mirroring `tests/storage/test_hybrid.py`'s
  real-class pattern.
- [ ] **DX2-11 — Fold a live `TenantManager.provision()`/
  `MigrationManager.migrate_tenant()` run into that same live test** (or a
  new `tests/live/test_migrate_live.py`), so the real `ModelSync(client).
  sync(force=True)` call as invoked from inside these managers is
  exercised against a real server at least once.

## Tier 4 — Small, independent correctness fixes

- [ ] **DX2-9** — add an optional `leeway: float = 0` constructor
  parameter threaded to `jwt.decode()` in `adapters/oidc.py`.
- [x] **DX2-10 — See `05`'s ARCH2-9** (`MultiTenantAuthz.for_tenant()`
  check-then-act race) — fixed there (shipped 2026-09-02); this file's
  finding was a cross-reference only.
- [x] **DX2-12** — fix `list_objects()`'s unbound-`Relation` guard to
  check falsiness consistently. **Shipped 2026-09-02**, incidentally,
  while fixing the same line's mypy error for DX2-2. New tests in
  `tests/api/test_relation_api.py` cover both the `None`- and
  empty-string-`resource_type` unbound-`Relation` `TypeError` paths.

## Tier 5 — CLI polish (batch together)

- [ ] **DX2-13** — add a `--version` flag backed by
  `importlib.metadata.version('py-authz')`.
- [ ] **DX2-14** — add `help=` text to every subparser and argument
  missing it; add an `epilog=` with example invocations.
- [ ] **DX2-15** — add an opt-in `--json` output flag to `sync`/`migrate`.
- [ ] **DX2-16** — document the flag-over-env-var precedence and the full
  env-var list, in both README and `--help` strings.

## Tier 6 — Docs accuracy sweep (batch together, all small)

- [ ] **DX2-7** — fix the OpenFGA port (8080 → 8082) in `README.md`,
  `docs/getting_started.md` (×2), and `examples/README.md`.
- [ ] **DX2-8** — fix README's `MigrationManager` usage example
  (keyword-only constructor, `migrate_all()` not `apply_all()`); add
  `migrate` to the CLI section.
- [ ] **DX2-17** — rewrite `docs/getting_started.md`'s `inherits=`
  explanation to match `modeling/base.py`'s corrected semantics and
  mention `from_parent` for the cross-object hierarchy case.
- [ ] **DX2-18** — add `CONTRIBUTING.md` (extracted from README's
  Development section) and a short `SECURITY.md` vulnerability-disclosure
  policy.
- [ ] **DX2-19** — delete or fold the stale top-level `todos.md` into
  `docs/todos/`.
- [ ] **DX2-20** — add a worked FastAPI example demonstrating
  `fail_open=True` on a specific route.
- [ ] Stale README badges (version, PyPI "production" status link) and
  the stale `@v1.2.0` install-example tag — bump to match `v1.3.0`.
- [ ] Fix `keycloak_fastapi.py`'s bearer-token split
  (`split(" ")[1]` → `split(" ", 1)[1]` or `.removeprefix(...)`).
- [ ] Consider renaming/relocating `tests/integration/` (mocked) to
  reduce confusion against `tests/live/` (real).
- [ ] Add a lock around `OIDCJWTValidator._get_jwks()`'s cold-start/
  post-rotation fetch to avoid a thundering herd against the IdP.

---

## Next step

Tiers 0–2 are shipped. What's left: Tier 3 (closing the mock-both-sides
test gap for multi-tenancy with live tests), and Tiers 4–6 (small,
independent fixes and docs accuracy) — all safe to parallelize in any
order.
