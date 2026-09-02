# py-authz — Developer Experience & Test Coverage Audit (Round 2)

**Date:** 2026-09-02 · repo as of `audit2` (post-1.3.0, after all of `01`–`04`
shipped).
**Scope:** the mypy/typing configuration; the public API's error-handling
completeness (`bulk_enforce`, `OIDCJWTValidator`); test-suite composition
(mocked-both-sides risk); the FastAPI adapter, CLI, and examples' fidelity
to current signatures; docs accuracy; packaging polish (`py.typed`,
`--version`).
**Method:** read `docs/todos/04_developer_experience_and_testing*.md` in
full first to confirm DX-1…10 are genuinely shipped (independently
re-verified: `tests/live/` is real, skip-gated, and wired into
`.github/workflows/ci.yml`'s `integration-test` job, not just claimed;
`require_dependency`/`require_fastapi` accept async getters; the CLI has
top-level error handling with exit codes; CI runs on `pull_request`).
Nothing below re-files a `04` finding — every item here is new, verified
by reading the actual code (the CRITICAL finding by direct reproduction),
and cross-checked against the test suite.

This is the second audit filed against this repository's developer
experience and test-coverage surface.

---

## 🔴 CRITICAL

**DX2-1. `AuthzEngine.bulk_enforce()` breaks the library's own exception
contract on partial failure, and silently discards completed results.**
`core/enforcement.py:507-525`:
```python
async def bulk_enforce(self, requests, *, concurrency=10):
    semaphore = anyio.Semaphore(concurrency)
    results: list[BulkAuthzResult] = []

    async def worker(req):
        async with semaphore:
            allowed = await self.enforce(req)
            results.append(BulkAuthzResult(req, allowed))

    async with anyio.create_task_group() as tg:
        for req in requests:
            tg.start_soon(worker, req)
    return results
```
Reproduced directly (not speculation) — a task group with one failing
worker among several succeeding ones:
```
raised <class 'ExceptionGroup'> unhandled errors in a TaskGroup (1 sub-exception)
partial results [0, 1, 3, 4]
```
`ExceptionGroup` is not an `AuthzError` subclass. `docs/architecture.md`'s
exception-hierarchy section tells callers to "catch `AuthzError` at
framework boundaries" (the exact pattern `cli/main.py` just implemented
for DX-6) — that pattern silently fails to catch a `bulk_enforce()`
partial failure. Worse, because the exception propagates out of the
`async with` block before `return results` executes, the 4 already-
computed results for requests that succeeded are thrown away entirely,
not returned alongside the failure. Any caller doing `try: results =
await engine.bulk_enforce(reqs) except AuthzError: ...` (the documented
pattern) gets an unhandled `ExceptionGroup` instead, and loses every
already-decided result in the batch — for a bulk-check use case (e.g.
rendering a list UI with per-row permissions) this turns one bad request
into a total page failure instead of a partial one.
→ Catch per-worker exceptions and either (a) attach them to
`BulkAuthzResult` (add an `error` field) so callers can inspect/skip
failed items while keeping successes, or (b) explicitly unwrap the
`ExceptionGroup` and re-raise the first real exception so `except
AuthzError` keeps working. Add a regression test with one worker raising
`ExternalServiceError`/`InvalidAuthzRequest` mid-batch. **Effort: S.**
*(`tests/core/test_bulk_enforce.py`'s 5 tests are all happy-path — none
construct a request whose underlying `fga_client.check()` raises
mid-batch.)*
→ **Shipped 2026-09-02**, via option (a). `BulkAuthzResult` gained an
`error: Exception | None = None` field; `bulk_enforce()`'s worker now
catches per-request exceptions and appends `BulkAuthzResult(req, False,
error=exc)` instead of letting them propagate into the task group. New
test `test_bulk_enforce_captures_per_request_errors_without_losing_others`
confirms a mid-batch failure no longer raises an `ExceptionGroup` and the
other requests' results are preserved.

---

## 🟠 HIGH

**DX2-2. mypy's own disabled error codes mask 4 real, reproducible type
errors — including one in the library's official testkit.**
`pyproject.toml:130-133`:
```toml
disable_error_code = [
  "var-annotated", "import-untyped",
  "annotation-unchecked", "union-attr", "arg-type"
]
```
`arg-type` and `union-attr` are two of mypy's highest-value checks. With
them force-re-enabled, 4 real errors surface that `make lint`/CI never
see:
```
py_authz/core/context.py:7: error: Argument 1 to "set" of "ContextVar" has incompatible type "str"; expected "None"  [arg-type]
py_authz/adapters/oidc.py:168: error: Argument 2 has incompatible type "RSAPrivateKey | RSAPublicKey"; expected "RSAPublicKey | ..."  [arg-type]
py_authz/api.py:236: error: Item "None" of "type[ResourceModel] | None" has no attribute "type"  [union-attr]
py_authz/testkit.py:179: error: Argument "fga_client" to "AuthzEngine" has incompatible type "InMemoryFGAClient"; expected "OpenFGAClient"  [arg-type]
```
The last one is the most concerning: `testkit.py`'s `make_fake_authz()` —
the library's official, blessed way to unit-test against a fake in-memory
client — constructs `AuthzEngine(fga_client=client)` where `client:
InMemoryFGAClient`, but `AuthzEngine.__init__` types `fga_client:
OpenFGAClient` (a concrete class, not a `Protocol`); `InMemoryFGAClient`
doesn't inherit from `OpenFGAClient`, so this is a genuine nominal-typing
mismatch on the library's flagship testing helper, invisible only because
`arg-type` is globally suppressed. `make lint`/CI report "Success: no
issues found in 60 source files" — false confidence: the config was set
up to make mypy pass, not to make the code correct under mypy.
→ Define an `FGAClientProtocol` (or similar) with `check`/`write_tuples`/
`store_id`/optionally `explain`, type `AuthzEngine.fga_client` against it
(it already duck-types via `hasattr` elsewhere, so a `Protocol` is a
natural fit), fix `context.py`'s `ContextVar[str | None]` annotation, and
re-evaluate whether `arg-type`/`union-attr` need to stay globally disabled
vs. suppressed with narrow `# type: ignore[arg-type]` at the 1-2
genuinely-unavoidable PyJWT-stub sites. **Effort: M.**
→ **Shipped 2026-09-02.** `arg-type`/`union-attr` removed from
`pyproject.toml`'s `disable_error_code`. New `core/protocols.py:
FGAClientProtocol` (structural — `check`/`list_objects`/`write_tuples`/
`store_id`) is what `AuthzEngine.fga_client` is now typed against, fixing
`testkit.InMemoryFGAClient`'s mismatch (its `store_id` annotation widened
to `str | None` to match invariantly). `context.py`'s `ContextVar`
annotated `ContextVar[str | None]`. `api.py:236`'s `list_objects()` guard
rewritten to narrow correctly (which also fixed `DX2-12`'s falsy-
`resource_type` bug as a side effect). Two narrow `# type: ignore[arg-type]`
remain, both documented inline: PyJWT's `from_jwk` return-type stub being
broader than what `jwt.decode` accepts, and `Authz.sync_model()`'s
`ModelSync(...)` call, which inherently needs a real `OpenFGAClient`
(store-management endpoints outside `FGAClientProtocol`'s scope) — calling
it against a testkit-fake-backed `Authz` was already a runtime
`AttributeError` before this change, not something the ignore introduces.
`mypy py_authz` passes clean with both codes re-enabled.

**DX2-3. No `py.typed` marker — PEP 561 compliance is missing despite the
library being fully type-hinted.** `find py_authz -name py.typed` returns
nothing; `pyproject.toml`'s `[tool.setuptools.package-data]` lists only
`storage/sql/*.sql`. Without this marker, any downstream project running
mypy/pyright against `py-authz` silently treats every import as `Any` —
the extensive type hints throughout `py_authz/` provide zero benefit to
consumers. A common, easy-to-miss packaging gap for a library about to be
published to PyPI (REL-9) — the exact `MANIFEST.in`-adjacent class of gap
the first audit already found and fixed once for the `.sql` files.
→ Add an empty `py_authz/py.typed` file and list it in `package-data`
(`py_authz = ["storage/sql/*.sql", "py.typed"]`). **Effort: S.**
→ **Shipped 2026-09-02.** Empty `py_authz/py.typed` added and listed in
`package-data`; confirmed present in an actual built wheel (`python -m
build --wheel`) — the same verification REL-4's `.sql`-file fix used,
since `include-package-data = true` alone doesn't guarantee it.

**DX2-4. A cache backend outage isn't fail-safe — untested, same failure
class already fixed for two other dependencies.** `core/enforcement.py:
149-151` — `if self.cache and cacheable: cached = await self.cache.get
(cache_key)`. `RedisCache.get()`/`.set()` call `self._client.get/set(...)`
with no exception handling anywhere in the class. A Redis connection
error/timeout propagates straight out of `enforce()`/`can()`/`require()`
as a raw `redis.exceptions.*`, not an `AuthzError`. This is exactly the
failure mode the first-pass audit fixed for the audit logger (SEC-3, "an
unhealthy audit sink could take down all authorization decisions") and for
Keycloak key rotation (SEC-1) — but the cache, a third dependency in the
same `enforce()` call path, was never audited and has no equivalent
protection. A Redis blip turns a pure performance optimization into a hard
outage for every authorization check.
→ Decide a policy (cache should be advisory, never load-bearing — catch
cache exceptions, log, fall through to the real OpenFGA check), then add a
regression test mirroring `test_enforce_survives_audit_logger_failure`.
**Effort: S.** *(No test constructs a cache double whose `get`/`set`
raises.)*
→ **Shipped 2026-09-02.** `enforce()`'s cache `get()` and the new
`_check_and_cache()` helper's cache `set()` (see `07`'s REL2-6, shipped
in the same pass) both now catch any exception, log it, and fall through
to/complete the real OpenFGA check — a cache failure can no longer affect
the returned decision. New tests
`test_enforce_survives_cache_get_failure`/`_cache_set_failure` mirror the
audit-logger regression tests exactly.

**DX2-5. `OIDCJWTValidator.validate()` crashes with an uncaught `KeyError`
on a token with no `kid` header — 500 instead of a clean 401.**
`adapters/oidc.py:147-148`:
```python
unverified_header = jwt.get_unverified_header(token)
kid = unverified_header["kid"]
```
inside a `try` whose `except` clauses only catch `jwt.
ExpiredSignatureError`/`InvalidAudienceError`/`InvalidTokenError`. A JWT
with no `kid` claim (valid per spec, or trivially crafted) raises a bare
`KeyError` — reproduced directly by encoding a token with no `kid` header
and running it through `validate()`. `KeycloakAuthMiddleware.dispatch()`
only handles `except AuthenticationError`, so this `KeyError` propagates
out of the middleware as an unhandled 500.
→ Use `unverified_header.get("kid")` and raise `AuthenticationError
("Invalid token: missing kid")` when `None`, alongside the existing
`jwt.InvalidTokenError` handling. **Effort: S.** *(Every test in
`test_keycloak.py`/`test_oidc.py` monkeypatches `jwt.get_unverified_
header` to always return a dict containing `kid`; the missing-claim path
is never exercised.)*
→ **Shipped 2026-09-02**, exactly as specified —
`unverified_header.get("kid")` and an explicit `AuthenticationError` on
`None`. New test `test_validate_raises_clean_error_when_kid_missing`
confirms a token with no `kid` header now fails cleanly instead of
raising a bare `KeyError`.

**DX2-6. `MultiTenantAuthz` is never tested composed with its own real
`TenantResolver`/`TenantManager` classes.** `tests/api/test_multi_tenant.
py` uses only hand-rolled `FakeResolver`/`FakeManager` doubles — never the
real `StaticTenantResolver`/`TenantManager`. `TenantManager.provision()`
has real, non-trivial logic (double-checked locking, `ModelSync`
invocation, cleanup-on-failure) the 3-line `FakeManager.provision()` stub
doesn't represent; no `tests/live/test_multi_tenant_live.py` exists. This
is precisely the mock-both-sides pattern that caused REL-1
(`HybridTenantStore`+`RedisTenantStore`) — two of the library's own
classes composed together, each side only ever exercised against a
bespoke, more forgiving double of the other. ARCH-4's fix ("confirmed
against a real OpenFGA server") was a manually-run example script, not a
regression test — a future contract change to `TenantManager.provision()`
would pass every existing test while breaking the real composed path.
→ Add `tests/live/test_multi_tenant_live.py` exercising
`MultiTenantAuthz(tenant_resolver=StaticTenantResolver(...),
tenant_manager=TenantManager(...))` end-to-end against real OpenFGA,
mirroring the real-class pattern `tests/storage/test_hybrid.py` already
established. **Effort: M.**

**DX2-7. OpenFGA's port is documented wrong in three places, self-
contradicting within one file.** `README.md`, `docs/getting_started.md`
(×2), and `examples/README.md` all say `http://localhost:8080` in one
place — but `docker-compose.yml` maps OpenFGA to host port **8082**
specifically to avoid colliding with Keycloak (8081); `.env.example` and
`examples/README.md` (34 lines below its own wrong line, in the *same
file*) both correctly say 8082. Anyone following the getting-started flow
literally (`curl http://localhost:8080/healthz`) gets connection refused
on the very first sanity check.
→ Change all incorrect call sites to 8082. **Effort: S.**

**DX2-8. README's only `MigrationManager` usage example is completely
broken.** README shows:
```python
from py_authz.core.migrations_manager import MigrationManager

await MigrationManager(store, client_factory).apply_all()
```
but `MigrationManager.__init__` is keyword-only (`*, api_url, tenant_store,
model_registry`), and the method is `migrate_all(self, tenant_ids:
list[str])`, not `apply_all()`. Copy-pasting the README's only documented
usage of this class fails on three separate counts. The README's CLI
section also still documents only `generate-model`/`sync`, omitting the
`migrate` command DX-5 shipped.
→ `mgr = MigrationManager(api_url=..., tenant_store=tenant_store,
model_registry=model_registry); await mgr.migrate_all(tenant_ids)`, or
better, point readers at `py-authz migrate --all-tenants` instead. Add
`migrate` to the CLI section. **Effort: S.**

---

## 🟡 MEDIUM

**DX2-9. No clock-skew (`leeway`) tolerance in JWT validation.**
`jwt.decode(...)` (`adapters/oidc.py:166-172`) passes no `leeway`, so
PyJWT's default of 0 applies to `exp`/`nbf`/`iat`. Not configured, not
documented as a deliberate choice. In any real deployment with drifted
clocks between the IdP and this service, this produces intermittent,
hard-to-diagnose token rejections right at expiry boundaries. → Add an
optional `leeway: float = 0` constructor param threaded to `jwt.decode`.
**Effort: S.**

**DX2-10. `MultiTenantAuthz.for_tenant()` has an unguarded check-then-set
race, orphaning connection pools under concurrency.** Filed in full as
`ARCH2-9` in
[`05_architecture_and_modeling.md`](05_architecture_and_modeling.md) —
noted here because it's also the DX-relevant regression: this is the same
leak shape REL-7 fixed for shutdown, reintroduced via a concurrency path
REL-7's own tests never covered. Fix once, in `05`'s todos; add the
concurrency regression test there.

**DX2-11. `TenantManager`/`MigrationManager` fully mock `ModelSync`; the
real composition is never run live.** `tests/core/test_tenant_manager.py`
and `test_migrations_manager.py` both `monkeypatch.setattr(...,
"ModelSync", FakeModelSync)`. `tests/live/test_model_sync_live.py` tests
`ModelSync` alone against real OpenFGA, but no live test drives
`TenantManager.provision()` or `MigrationManager.migrate_tenant()` — the
real `ModelSync(client).sync(force=True)` call as actually invoked from
inside these two managers is never exercised against a real server.
ARCH-1's bug (wrong field name in OpenFGA's real response) was exactly
this class of defect. → Fold into the live test recommended for `DX2-6`,
or add `tests/live/test_migrate_live.py`. **Effort: S/M.**

**DX2-12. `Authz.list_objects()`'s unbound-`Relation` guard has an
untested falsy-vs-`None` edge case, and its `TypeError` branch is
untested.** `api.py:232-236`:
```python
if relation.resource_cls is None and resource_type is None:
    raise TypeError("Relation is unbound; pass resource_type explicitly.")
type_name = resource_type or relation.resource_cls.type
```
The guard only fires when *both* are `None`. If `relation.resource_cls is
None` but `resource_type` is passed as `""` (falsy-but-not-`None`), the
guard is skipped, then `resource_type or relation.resource_cls.type` falls
through (since `""` is falsy) and raises `AttributeError: 'NoneType'
object has no attribute 'type'` instead of the intended `TypeError`
(confirmed by mypy's own `union-attr` flag on this line — see `DX2-2`). No
test constructs an unbound `Relation` and calls `list_objects()` with it.
→ Change the guard to check falsiness consistently (`if
relation.resource_cls is None and not resource_type`), and add a test for
the unbound-`Relation` `TypeError` path. **Effort: S.**
→ **Shipped 2026-09-02** (incidentally, while fixing the same line's
mypy `union-attr` error for this file's own DX2-2, below — the rewrite
that makes mypy narrow the type correctly also fixes the
falsy-`resource_type` case). New tests
`test_list_objects_raises_type_error_for_unbound_relation_with_no_resource_type`/
`_with_empty_resource_type` (`tests/api/test_relation_api.py`) cover both
the previously-untested `TypeError` branches.

**DX2-13. CLI has no `--version` flag, and no way to discover the
installed version at all.** Verified live: `python -m py_authz.cli.main
--version` → `error: unrecognized arguments: --version`. Combined with
`py_authz/__init__.py` exporting no `__version__`, there's no way — CLI
flag or Python attribute — to check which version is installed short of
`pip show py-authz`. A real operability gap for a tool pitched at CI
pipelines. → `parser.add_argument("--version", action="version",
version=f"py-authz {importlib.metadata.version('py-authz')}")`.
**Effort: S.**

**DX2-14. Inconsistent CLI help text; several primary flags have no help
string at all.** Verified live: top-level `--help` shows no description
for `generate-model`/`sync` (their `add_parser()` calls pass no `help=`)
while `migrate` has one. `sync --help` shows `--store-id`, `--api-url`,
`--model-id` with zero help text, despite these being the command's
primary (env-var-fallback-having) inputs. No subcommand's `--help`
includes a usage example, despite the README having ready-made ones. →
Add `help=` throughout; add an `epilog=` with 1-2 example invocations per
subparser. **Effort: S.**

**DX2-15. No machine-readable output mode; output shapes are inconsistent
across CLI commands.** `sync` prints `f"Active model: {new_model_id}"`;
`migrate` prints `f"{tenant_id}: {model_id}"` per line — two different
free-text shapes; `generate-model` is the only structured (JSON) output,
and only because JSON is its product, not from a `--format` flag. Given
the CLI is pitched for CI pipelines, a pipeline wanting per-tenant
migration results has to line-parse free text with no shared convention.
→ Add an opt-in `--json` flag to `sync`/`migrate`. **Effort: S/M.**

**DX2-16. CLI config precedence (flag over env var) is real but
undocumented outside source.** `sync.py`/`migrate.py` all do `arg or
get_env(NAME, required=True)` (`FGA_STORE_ID`, `FGA_API_URL`,
`FGA_MODEL_ID`, `TENANT_STORE_CONN`) — this precedence and the full
env-var list is undocumented in README's CLI section and not surfaced in
`--help`. An integrator has to read source to discover it. → Document in
README/`--help` (`help="... (env: FGA_STORE_ID)"`). **Effort: S.**

**DX2-17. `docs/getting_started.md` still describes the pre-fix,
incorrect semantics of `inherits=`.** Says: "Use `inherits=[...]` when the
implication comes from another object (e.g. a document inheriting its
folder's viewers)." But `modeling/base.py` documents `inherits` as
"currently an alias of `union`... if you're modeling inherit-from-a-
different-parent-object, that's `from_parent`, not `inherits`." This is
exactly the ARCH-2 gap, except the fix only propagated to
`modeling/base.py`'s docstring and `examples/README.md` — this first-touch
onboarding doc still tells a new user the wrong mechanism for the
folder→document case, which will silently produce a same-object
`computedUserset` instead of the intended cross-object relationship. →
Rewrite to match `modeling/base.py`, mention `from_parent` as the real
mechanism. **Effort: S.**

**DX2-18. No CONTRIBUTING.md, SECURITY.md, or CODE_OF_CONDUCT.md.**
Confirmed via `git ls-files`/`find` at repo root and `.github/` — none
exist. For a security-sensitive authorization library about to be
published (REL-9), the absence of a vulnerability-disclosure policy
(`SECURITY.md`) is the more notable gap. **Effort: S** (extract dev-setup
content already in README's Development section for CONTRIBUTING.md;
write a short SECURITY.md).

**DX2-19. Stray, stale top-level `todos.md` contradicts the current
shipped state.** `/todos.md` (105 lines, tracked in git, not part of the
`docs/todos/` system) is pre-audit developer scratch notes listing
`list_objects`, contextual tuples, the testkit fake, and a generic
`OIDCJWTValidator` as open gaps — all now shipped. It also references a
stale `v1.1.1` install URL and an already-resolved "add license file"
item. A new contributor skimming the repo root would be actively misled
about what's already done. → Delete it, or fold any genuinely-still-
relevant note into `docs/todos/`. **Effort: S.**

**DX2-20. No worked FastAPI example for the `fail_open` per-route
override.** `grep -rln "fail_open" examples/ README.md docs/` matches
only `docs/todos/`. Both FastAPI examples use default (fail-closed)
behavior only. An integrator who needs the escape hatch for an
availability-first route has only the adapter's docstring to go on, no
copy-pasteable example. **Effort: S.**

---

## 🟢 LOW

- **README badges are stale/misleading** — a hardcoded `version-1.0.0`
  badge, two minor versions behind `pyproject.toml`'s `v1.3.0`, and a
  "Status: production" badge linking to a nonexistent PyPI project page,
  directly contradicting the "not yet on PyPI" callout three sections
  below. **Effort: S.**
- **README's working install example pins a stale tag**
  (`git+https://...@v1.2.0`) — not broken (explicitly presented as a
  swappable example), just stale since the 1.3.0 release. **Effort: S.**
- **Bearer-token extraction assumes exactly one space** —
  `adapters/keycloak_fastapi.py`'s `auth_header.split(" ")[1]` — a header
  with irregular whitespace yields an empty token. Fails safe (→ 401 via
  the existing `AuthenticationError` path), just a confusing symptom.
  → `split(" ", 1)[1]` or `.removeprefix("Bearer ").strip()`.
  **Effort: S.**
- **No shell completion** for the CLI (hand-rolled `argparse`, no
  `argcomplete`/equivalent) — an absent nicety, not a defect for a
  CI-oriented tool. **Effort: S/M.**
- **`tests/integration/` vs `tests/live/` naming is confusing** now that
  both exist side by side — `test_openfga_integration.py`'s own docstring
  is honest ("Mocked 'integration' tests...") and not misleading
  internally, but the directory name gives no signal to a new contributor
  that it's the mocked one. → Rename or fold into `tests/api/`.
  **Effort: S.**
- **`OIDCJWTValidator._get_jwks()` has no lock** — concurrent requests
  during cold start or right after a key rotation can trigger duplicate
  JWKS fetches (thundering herd against the IdP), not a correctness bug.
  **Effort: S.**
- **`context.py`'s `ContextVar` is untyped** —
  `contextvars.ContextVar("request_id", default=None)` infers as
  `ContextVar[None]`, which is why mypy flags `set_request_id`'s `.set
  (str)` call under `arg-type` (see `DX2-2`). → `ContextVar[str |
  None]("request_id", default=None)`. **Effort: S.**

---

## Areas checked and found genuinely fine (no new finding)

**Examples** (`examples/*.py`, 12 files + `models.py`/`seed.py`): every
call into `Authz`, `MultiTenantAuthz`, `TenantManager`,
`require_fastapi`/`require_dependency`, `KeycloakJWTValidator`,
`engine.explain`/`bulk_enforce`, and `testkit.make_fake_authz` was
cross-checked line-by-line against current signatures — all match; this
area was thoroughly and correctly fixed by the first-pass audit.
**`docs/architecture.md`**: 5 concrete claims (cache-key format, audit
fire-and-forget behavior, metrics as optional dependency, exception
hierarchy, `RedisCache` constructor) all verified accurate against source.
**FastAPI adapter parameter consistency**: `require_dependency`/
`require_fastapi` have identical signatures; error response shapes
(403/503/401) are consistent, all via standard `HTTPException`.
**Algorithm confusion / JWKS rotation / audience validation**: `ALGORITHMS
= ["RS256"]` is pinned explicitly, never inferred from the token; JWKS
caching + rate-limited refetch-on-unknown-kid is correct and well-tested
(minus the missing-`kid` gap in `DX2-5`). **`HybridTenantStore` +
`RedisTenantStore` composition**: `tests/storage/test_hybrid.py` and
`tests/live/test_redis_storage_live.py` already use the real classes with
only the external `redis-py` boundary mocked — the correct pattern,
confirming REL-1's fix is durable. **CLI top-level error handling
(DX-6)**, **`generate-model`'s default validation (DX-5)**, and
**`migrate`'s mutual-exclusion check** all confirmed still working
correctly. **Exception hierarchy** (`core/exceptions.py`): every declared
exception class is actually raised somewhere in the codebase — no dead
exception classes.

---

## Next step

Nothing in this file is shipped yet — this is a freshly filed backlog.
[`08_developer_experience_and_testing_todos.md`](08_developer_experience_and_testing_todos.md).
