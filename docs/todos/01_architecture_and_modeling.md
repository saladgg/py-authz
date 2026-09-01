# py-authz — Architecture & Modeling Audit

**Date:** 2026-08-31 · repo as of `revive_authz` (post-1.2.0, `list_objects` +
contextual tuples + testkit landed in 27d0254).
**Scope:** the framework-agnostic core — `api.py`, `core/enforcement.py`,
`modeling/`, `core/model_sync.py` / `model_diff.py`, and the extension
points the architecture doc (`docs/architecture.md`) advertises (config,
metrics, retry, testkit fidelity).
**Method:** read every module under `py_authz/core/`, `py_authz/modeling/`,
`py_authz/api.py`, `py_authz/config/`, `py_authz/utils/`, and `testkit.py`
line by line against what the README/architecture.md/examples claim they
do, then traced each claim through its test file to see whether the claim
is actually exercised. Several of the findings below are bugs that no test
currently catches — each cites the specific test gap alongside the defect.

This is the first audit filed against this repository; nothing here is a
re-check of prior work.

---

## Technical / core design

### 🔴 CRITICAL

**ARCH-1. `ModelSync` almost certainly cannot detect "no change" against a
real OpenFGA server — its marquee feature is likely non-functional.**
`py_authz/core/model_sync.py:48` reads
`current_model["authorization_model_id"]` from the value returned by
`OpenFGAClient.get_latest_model()` — but that method
(`py_authz/clients/openfga.py:213-228`) returns the **first item of
OpenFGA's `GET /stores/{id}/authorization-models` list response**, and per
OpenFGA's API, list items are keyed `"id"`, not `"authorization_model_id"`
(only the *write* endpoint's response, `POST .../authorization-models`,
uses that key — which is what `_upload_model` at `model_sync.py:73`
correctly reads). This means the "unchanged, reuse existing model" branch
of `sync()` (`model_sync.py:46-48`) raises `KeyError` the moment a model
already exists in the store — i.e. on every deploy after the first.
Compounding this, `ModelDiffer.is_equal()` (`core/model_diff.py:21-27`)
diffs the **entire raw dicts**, so even with the key fixed, the local
`generate_model()` output (`{"schema_version", "type_definitions"}`) will
never structurally equal OpenFGA's stored model (which additionally
carries `id` and other server-added fields) — the diff-and-skip path
described in `docs/architecture.md:100-110` ("This keeps deploy-time sync
cheap and idempotent") would still never trigger even if the `KeyError`
were fixed. No test exercises this: `tests/core/test_model_sync.py`'s
`MockFGAClient.get_latest_model()` returns `None` unconditionally
(`test_model_sync.py:9-10`), so the "existing model found" branch has
never once run against a realistically-shaped response.
→ Read `current_model["id"]`, and make `ModelDiffer` compare only the
schema-relevant fields (`schema_version`, `type_definitions`) after
stripping server-added metadata from both sides. Add a test using a
`MockFGAClient.get_latest_model()` that returns an OpenFGA-shaped item
(`{"id": ..., "schema_version": ..., "type_definitions": [...]}`), and an
integration test (see `03_reliability_and_operations.md` REL-9) that runs
`sync()` twice against a real OpenFGA and asserts the second call is a
true no-op. **Effort: M.**

> **Confirmed against a real OpenFGA server while fixing this (DX-9):**
> stripping only the top-level `id` wasn't sufficient. OpenFGA's stored/
> echoed model also fills in every optional field *inside* each type
> definition at its protobuf zero value instead of omitting it —
> `computedUserset.object: ""`, each `directly_related_user_types` entry's
> `condition: ""`, and each type's `metadata.module: ""` /
> `metadata.source_info: null` — none of which a locally generated model
> ever has. `ModelDiffer` needs a recursive normalizer that strips these
> specific zero-value fields while preserving genuinely meaningful empty
> values (`"this": {}` marks direct assignment and must never be
> stripped). See `core/model_diff.py`'s `_strip_server_defaults` for the
> shipped fix — confirmed equal against a real store in
> `tests/live/test_model_sync_live.py`.

**ARCH-2. The declarative modeling layer cannot express hierarchical
permissions, despite documentation claiming it can.**
`examples/README.md:136-139` says `inherits=[...]` "is meant for computed
usersets (e.g., inherit folder permissions)" — but
`OpenFGAModelGenerator._build_relation` (`py_authz/modeling/generator.py:
94-143`) only ever emits `computedUserset`, which references a relation on
the **same object**. `union=[...]` and `inherits=[...]` are, today,
literally identical — two separate loops (`generator.py:115-120` and
`121-128`) that append the exact same `{"computedUserset": {"relation":
name}}` shape into the same `parts` list. OpenFGA's actual mechanism for
"a viewer of the parent folder is a viewer of this document" is
`tupleToUserset` (referencing a *different* object through a stored
relation tuple, e.g. `parent`), which `Relation`/`OpenFGAModelGenerator`
has no representation for at all. Any application with nested resources —
orgs → teams → projects, folders → files, tenants → resources, which is
close to the majority shape of real-world authorization models — cannot
express that hierarchy through this library's declarative layer and must
drop to hand-written OpenFGA JSON, defeating the point of the modeling
layer for exactly the cases where it matters most.
→ Add a real `tupleToUserset` construct (e.g. `Relation(..., from_parent=
("parent", "viewer"))` or a dedicated helper) that emits
`{"tupleToUserset": {"tupleset": {"relation": "parent"}, "computedUserset":
{"relation": "viewer"}}}`. While there, fold `union` and `inherits` into a
single parameter (or give `inherits` its real, distinct semantics) since
they are currently indistinguishable dead weight in the public API.
**Effort: L.**
→ **Shipped 2026-08-31** as `Relation(from_parent=(tupleset_relation,
computed_relation))`, matching the design above almost exactly.
`union`/`inherits` were deliberately left as same-shaped aliases (not
merged/renamed) to avoid a breaking change to existing models — the new,
genuinely distinct mechanism lives entirely under the new parameter name.
One refinement over the original proposal: when `from_parent` is set and
`subjects` isn't given explicitly, `subjects` now defaults to `[]` instead
of `["user"]` — a purely parent-inherited relation isn't directly
assignable by default, matching the shape OpenFGA itself expects for a
bare `tupleToUserset` rewrite (no `this`). `DefaultModelValidator` now
accepts `tupleToUserset` as a valid rewrite; `testkit.InMemoryFGAClient`
walks it too, so unit tests get the same hierarchy semantics as
production. **Confirmed against a real OpenFGA server** —
`tests/live/test_hierarchy_live.py` syncs a folder→document model using
`from_parent` and verifies both that OpenFGA accepts it and that a folder
viewer is correctly recognized as a document viewer. The shared example
models (`examples/models.py`) and a new `examples/
11_hierarchical_permissions.py` now actually deliver on
`examples/models.py`'s original docstring claim ("folder — holds
documents, inheritable permissions"), which was unfulfilled before this
fix. `examples/README.md`'s modeling notes rewritten to correctly
distinguish `union`/`inherits` (same-object, aliases) from `from_parent`
(cross-object, the real mechanism).

**ARCH-3. `DefaultModelValidator`'s cycle detection does not detect
cycles.** `validation/default.py:18` calls `detect_cycles(relations=
relations)`, passing the OpenFGA-shaped dict where each value is a
*rewrite-rule* dict (e.g. `{"union": {"child": [...]}}`). But
`detect_cycles` (`validation/default.py:29-48`) assumes `relations.get(
node, [])` returns a **list of child relation names** and iterates it as
such. In practice it iterates the rewrite dict's top-level keys — the
literal strings `"this"`, `"union"`, `"computedUserset"` — as if they were
relation names, which they never are (no relation is named `"union"`), so
the walk always terminates in one hop with nothing detected. Traced by
hand: a genuinely circular model (`editor` unions to `viewer`, `viewer`
unions back to `editor`) passes `validate()` cleanly. This is invisible to
the test suite because `tests/validation/test_default.py:69-79`'s
`test_detect_cycles_*` tests call `detect_cycles` **directly** with
hand-built adjacency-list dicts (`detect_cycles({"a": ["a"]})`) that don't
match the shape `validate()` actually passes it in production — the unit
tests validate an algorithm that is correct in isolation and never wired
correctly to its caller.
→ Either walk the real rewrite tree (recurse into `union.child[]` →
`computedUserset.relation` / future `tupleToUserset.computedUserset.
relation`), or run cycle detection over the pre-generation `Relation.
union`/`inherits` name lists already available in `modeling/generator.py:
_relation_map` before they're compiled to JSON. Add a test that drives
`DefaultModelValidator.validate()` (not `detect_cycles` in isolation) with
two genuinely cyclic `ResourceModel` classes. **Effort: M.**

**ARCH-10. `Authz.grant`/`revoke`/`grant_many`/`revoke_many` crash on the
exact usage the README and examples document.** `api.py:218` (and the
equivalent lines in `revoke`/`grant_many`/`revoke_many`) call
`resource.to_fga_object()` unconditionally — but `to_fga_object()` is only
defined on `Resource` (`core/types.py:54`), not on `ResourceModel`
(`modeling/base.py`), and both the README ("Push the model to OpenFGA...")
and `examples/06_multitenant.py` (`await acme.grant(alice, "owner",
report)` where `report = Document(id="report")`, a `ResourceModel`
instance) call `grant()` with a `ResourceModel` directly — the same shape
`Authz.can()`/`enforce()` already accept via `ResourceModel.to_resource()`.
Every such call raises `AttributeError: 'Document' object has no attribute
'to_fga_object'`. Not caught by any existing test:
`tests/api/test_grant_revoke.py` only ever passes a raw `Resource`
instance, never a `ResourceModel`, and no test actually runs
`examples/06_multitenant.py` end to end. *Found while fixing ARCH-1 —
`tests/live/test_tuples_live.py` (added for DX-9, see
`04_developer_experience_and_testing.md`) calls `grant()` with a
`ResourceModel`, exactly as the docs show, and hit this immediately
against a real OpenFGA store.*
→ Accept both shapes in `grant`/`revoke`/`grant_many`/`revoke_many`,
converting a `ResourceModel` via `.to_resource().to_fga_object()`,
mirroring `Authz.can()`'s existing dual support. **Effort: S.**

### 🟠 HIGH

**ARCH-4. Multi-tenancy and the FastAPI adapter have never been composed,
and the adapter's shape doesn't allow it.** `require_dependency`/
`require_fastapi` (`adapters/fastapi.py:44-151`) both take a single
`authz` object captured at decoration/registration time — there is no way
to supply a per-request tenant-resolved `Authz` (the exact thing
`MultiTenantAuthz.for_tenant(tenant_id)` produces). `tenant_from_request()`
(`adapters/fastapi.py:154-168`) — the one helper that reads a tenant id
off a request — is dead code, called from nowhere in the repository.
Neither example demonstrates the combination: `examples/06_multitenant.py`
is a raw asyncio script with no FastAPI at all, while
`examples/04_fastapi_app.py`/`05_keycloak_fastapi.py` both wire a single
global `Authz` into `app.state.authz` at startup. A real multi-tenant
FastAPI app — the intersection of two features this library calls
first-class — has no supported path today.
→ Give `require_dependency`/`require_fastapi` an `authz_getter: Callable[
[Request], Authz | Awaitable[Authz]]` alternative to the static `authz`
argument, and add an example wiring `tenant_from_request` →
`MultiTenantAuthz.for_tenant` → the guard. **Effort: M.**
→ **Shipped 2026-08-31.** Rather than a separate `authz_getter` parameter,
`authz` itself now accepts either a static `Authz` instance or a sync/
async callable taking the `Request` (new `_resolve_authz()` helper,
`adapters/fastapi.py`) — `callable(authz)` unambiguously distinguishes
the two, since a plain `Authz` instance is never itself callable, so no
new parameter or `Authz` import was needed. `tenant_from_request` now has
a real caller: new `examples/12_multitenant_fastapi.py` wires it into
`MultiTenantAuthz.for_tenant` end to end. **Confirmed against a real
OpenFGA server**: ran the example live, requesting the same route with
`X-Tenant-ID: acme` (200, alice granted `viewer`) vs. `X-Tenant-ID:
globex` (403, no relationship) — genuine per-tenant isolation through
the FastAPI adapter. Incidental fix found while validating this:
`uvicorn`, which every FastAPI example's documented run command
requires, was never declared as a dependency anywhere — added to the
`fastapi`/`all` dependency groups.

### 🟡 MEDIUM

**ARCH-5. `config.Settings` is dead code.** `py_authz/config/settings.py`
defines a one-field pydantic `Settings(openfga_url=...)`. Its only
reference anywhere in the repository besides its own definition is its own
test (`tests/config/test_settings.py`) — it is never imported by
`AuthzEngine`, `Authz`, the CLI, or any adapter. There is no
environment-variable-driven configuration path for the library outside the
CLI's unrelated, ad hoc `cli/config.py:get_env` (used only by
`sync_command`). A user reading the "Project Layout" table in the README,
which lists `config/` as a first-class package, will find nothing that
actually uses it.
→ Either wire `Settings` into real construction paths (an env-driven
`OpenFGAClient`/`AuthzEngine` factory), or delete it and document that
configuration is code-first by design. **Effort: S (remove) / M (wire
up).**
→ **Shipped 2026-08-31 (removed).** `py_authz/config/` and its test
deleted entirely — it was dead, and building out real env-driven
configuration for every component would cut against the library's own
"explicit over implicit" design goal rather than serve it.
`docs/architecture.md`'s design-goals section now states the code-first
configuration stance explicitly (with the CLI's `cli/config.py:get_env`
named as the one deliberate exception, since a CLI is a standalone
process rather than a library import into a host app that already owns
its configuration). README's project-layout table updated to match.

**ARCH-6. Several modules are unused stubs that contradict what the docs
say they do.** `core/metrics.py`'s `Metrics`/`metrics` singleton (counter
only — `incr()`, no histogram) is referenced by nothing except its own
test (`tests/core/test_metrics.py`); `AuthzEngine.enforce()`/
`bulk_enforce()` never call it. `docs/architecture.md:257-258` claims
"`core/metrics.py` holds counter/histogram helpers; wire them to your
metrics backend if you want allow/deny rates and p99 latency" — there is
no histogram, and nothing wires anything anywhere. `core/logging.py:
setup_logging()` is defined but never called from any module, example, or
test. `utils/logging.py` and `utils/retry.py` are both single-line-comment
stub files (`# Logging configuration`, `# Retry utility`) with no code —
the latter explaining why retry logic is duplicated ad hoc inline in
`clients/openfga.py` instead of being a shared, independently testable
utility the module name implies exists.
→ Either implement and wire these (emit metrics from the actual
enforce/bulk_enforce path; back `OpenFGAClient.check`'s retry loop with a
real, reusable helper), or delete the stubs so the package doesn't
advertise capabilities it doesn't have. **Effort: M.**
→ **Shipped 2026-08-31 (wired, not deleted).** `AuthzEngine` now accepts
an optional `metrics=` dependency (same injection pattern as `cache`/
`audit_logger` — nothing recorded unless passed in, no hardwired global)
and `enforce()` records `authz_check_total`/`authz_allowed_total`/
`authz_denied_total`/`authz_cache_hit_total` counters plus an
`authz_check_duration_ms` observation per call (`bulk_enforce` gets this
for free — it already calls `enforce()` per request). `core/metrics.py`'s
`Metrics` gained a real `observe()` for duration samples, making
`docs/architecture.md`'s "counter/histogram helpers" claim actually true.
`core/logging.py:setup_logging()` is now called from `cli/main.py` (new
`-v`/`--verbose` flag) — it was the one place in the library that should
own logging configuration, since `TenantManager`/`MigrationManager`'s
progress logs were otherwise invisible by default. `utils/logging.py`
(a true duplicate, nothing to wire it to) deleted. `utils/retry.py` filled
with a real `retry_async()` helper; `OpenFGAClient.check()`'s inline
retry loop refactored to use it, confirmed behavior-preserving against
its existing test suite (all passed unmodified) — a shared, unit-tested
retry helper instead of hand-rolled backoff logic in one call site.

**ARCH-7. `testkit.InMemoryFGAClient` doesn't honor `Relation(inherits=
[...])`, only `union=[...]`.** `testkit.py:127`'s `_check()` recurses only
over `rel.union`. Since the real generator treats `union` and `inherits`
identically (ARCH-2), a model author using `inherits=` gets correct
behavior against real OpenFGA but **incorrect (falsely denied) behavior in
unit tests** built on `make_fake_authz()` — the fake silently diverges from
the real backend for a feature `tests/modeling/test_generator_extended.py:
8-27` explicitly exercises at the generator level, just never through the
testkit that's supposed to mirror it.
→ Walk both `rel.union` and `rel.inherits` in `_check()` (this collapses
naturally once ARCH-2 unifies the two parameters). **Effort: S.**
→ **Shipped 2026-08-31.** `_check()` now walks `(*rel.union,
*rel.inherits)` together. New test registers an `inherits=`-only model
and confirms the same transitive resolution `union=` already had.

### 🟢 LOW

**ARCH-8. Naming collision: two unrelated things are both called
`require`.** `Authz.require()` (`api.py:118`, an async instance method
that raises on denial) and `modeling.decorators.require()` (a decorator
factory) share a name with different call shapes
(`from py_authz.modeling.decorators import require` vs.
`authz.require(...)`), which is easy to confuse in an import statement or
a code review.
→ Rename the decorator (e.g. `authorize`/`enforce_call`). **Effort: S.**
→ **Shipped 2026-08-31** as `authorize` — a clean rename (not aliased;
it was only ever imported directly in two test files, never re-exported
via `modeling/__init__.py`), with its docstring now explicitly noting why
it isn't called `require`.

**ARCH-9. `AuthzEngine.explain()` doesn't accept `context`/
`contextual_tuples`.** `core/enforcement.py:283-287`'s initial `check()`
call inside `explain()` omits both, unlike `enforce()` — an "explain why
this was denied" call under an ABAC model can silently disagree with the
decision actually being explained, if the real check depended on context.
→ Add `context`/`contextual_tuples` parameters to `explain()`, mirroring
`enforce()`. **Effort: S.**
→ **Shipped 2026-08-31.** `AuthzRequest` already carried `context`/
`contextual_tuples` (no new parameters needed on `explain()` itself) —
the bug was that `explain()` never read them off the request when
calling `fga_client.check()`/`fga_client.explain()`. Both calls now
forward them, with a `TypeError` fallback to the old, kwarg-free
`explain()` call shape for any custom client implementation that
predates this.

---

## Next step

All findings in this file are shipped — Tier 0 (ARCH-1, ARCH-3), Tier 1
(ARCH-2, plus ARCH-10 discovered along the way), and Tier 2 (ARCH-4
through ARCH-9). Full checklist:
[`01_architecture_and_modeling_todos.md`](01_architecture_and_modeling_todos.md).
