# py-authz — Architecture & Modeling Backlog

Execution checklist for
[`01_architecture_and_modeling.md`](01_architecture_and_modeling.md). IDs
match that file.

> **Status (2026-08-31):** All three tiers shipped same day. Tier 0
> (ARCH-1, ARCH-3), plus ARCH-10 — a new, previously-undiscovered bug
> found by the live-service testing done to actually confirm ARCH-1's fix
> (see DX-9 in `04_developer_experience_and_testing_todos.md`), fixed
> same day rather than filed separately. Tier 1 (ARCH-2) — product
> decision was "yes, implement it" — confirmed against a real OpenFGA
> server. Tier 2 (ARCH-4 through ARCH-9) — all six shipped, confirmed
> against a real OpenFGA server where applicable (ARCH-4). Nothing left
> open in this file.

---

## Tier 0 — Silent defects in advertised features (fix first) ✅

- [x] **ARCH-1 — Fix `ModelSync`'s "no-op if unchanged" path.**
  `core/model_sync.py` now reads `current_model["id"]` (not
  `"authorization_model_id"`, which only exists on the *write* endpoint's
  response). `ModelDiffer.normalize`/`is_equal` (`core/model_diff.py`) now
  compare only `schema_version` + `type_definitions`, and recursively
  strip OpenFGA's server-added zero-value noise (`_strip_server_defaults`
  — `computedUserset.object: ""`, `directly_related_user_types[].
  condition: ""`, `metadata.module`/`metadata.source_info`, etc.) while
  preserving genuinely meaningful empty values like `"this": {}`.
  `tests/core/test_model_sync.py` rewritten with a `MockFGAClient` that
  returns an OpenFGA-shaped (`id`-keyed) current model, covering:
  reuse-when-unchanged, re-upload-when-changed, upload-when-nothing-exists,
  and `force=True` always uploading. `tests/core/test_model_diff.py` adds
  tests locking in the zero-value stripping. **Confirmed against a real
  OpenFGA server** in `tests/live/test_model_sync_live.py` (part of DX-9)
  — the first version of this fix (stripping only the top-level `id`)
  passed every mocked unit test but still failed against a real store,
  because the real fix needed the deeper, recursive stripping described
  above. That gap is exactly what DX-9 exists to close.
- [x] **ARCH-3 — Make cycle detection actually walk the rewrite tree.**
  `validation/default.py` gains `_referenced_relations()`, which recurses
  the real OpenFGA rewrite-rule shape (`computedUserset`, `union`/
  `intersection` `child` lists, `difference` `base`/`subtract`) to find
  the relation names a rewrite rule actually depends on;
  `tupleToUserset`'s `computedUserset` is deliberately excluded since it
  names a relation on a different object type. `detect_cycles` now walks
  that extracted dependency graph instead of a rewrite dict's own operator
  keys. `tests/validation/test_default.py`'s `detect_cycles` tests were
  rewritten to use real rewrite-rule dicts instead of hand-built adjacency
  lists (the old shape was the bug — the tests validated an algorithm
  correct in isolation but never wired correctly to its caller); added
  `test_detect_cycles_raises_on_cycle_nested_in_union` (the actual shape
  the generator emits), `test_detect_cycles_ignores_tuple_to_userset_
  cross_type_reference`, and `test_validate_raises_on_circular_relations_
  end_to_end` driving two cyclic relations through
  `DefaultModelValidator.validate()` directly.
- [x] **ARCH-10 — Fix `grant`/`revoke`/`grant_many`/`revoke_many` crashing
  on a `ResourceModel` argument.** New `_to_fga_object()` helper in
  `api.py` accepts either a `Resource` or a `ResourceModel`, converting
  the latter via `.to_resource().to_fga_object()` — mirroring
  `Authz.can()`'s existing dual support. All four methods now use it.
  `tests/api/test_grant_revoke.py` adds four regression tests passing a
  `ResourceModel` directly. Verified end to end by actually running
  `examples/06_multitenant.py` against a live OpenFGA store (it uses
  exactly this calling convention) — it now completes successfully;
  before this fix it would have raised `AttributeError` the moment
  `main()` reached its first `.grant()` call.

## Tier 1 — Design gaps needing a decision ✅

- [x] **ARCH-2 — Decide + implement hierarchical relation support
  (`tupleToUserset`).** Product decision: implement it. Shipped as
  `Relation(from_parent=(tupleset_relation, computed_relation))`
  (`modeling/base.py`), emitting a real `tupleToUserset` rewrite
  (`modeling/generator.py`). `union`/`inherits` deliberately left as
  same-shaped aliases rather than merged/renamed, to avoid a breaking
  change — `from_parent` is the new, genuinely distinct mechanism.
  `subjects` now defaults to `[]` (not `["user"]`) when `from_parent` is
  set with no explicit `subjects`, matching the "not directly assignable
  by default" shape a pure `tupleToUserset` rewrite needs.
  `DefaultModelValidator` accepts `tupleToUserset` as a valid rewrite;
  `testkit.InMemoryFGAClient` walks it too. Tests added across
  `tests/modeling/test_base.py`, `test_generator_extended.py`,
  `tests/validation/test_default.py`, and `tests/test_testkit.py`.
  **Confirmed against a real OpenFGA server** —
  `tests/live/test_hierarchy_live.py` syncs a folder→document model and
  verifies the inheritance actually evaluates correctly server-side.
  `examples/models.py` now actually wires `Document.viewer` to inherit
  from `Folder.viewer` via `parent`, fulfilling the module's own
  docstring claim ("folder — holds documents, inheritable permissions"),
  which was unfulfilled before this fix; new
  `examples/11_hierarchical_permissions.py` demonstrates it end to end
  (verified by actually running it, plus `01`/`02`/`07`/`08` to confirm
  the shared-model change doesn't break the other examples — it doesn't).
  `examples/README.md`'s modeling notes rewritten to correctly
  distinguish `union`/`inherits` from `from_parent`.

## Tier 2 — Independent fixes ✅

- [x] **ARCH-4 — Let the FastAPI adapter accept a per-request-resolved
  `Authz`.** `authz` itself (not a new separate parameter) now accepts a
  sync/async callable taking `Request`, via `_resolve_authz()`
  (`callable(authz)` distinguishes it from a static `Authz` instance,
  which is never itself callable). New `examples/
  12_multitenant_fastapi.py` wires `tenant_from_request` →
  `MultiTenantAuthz.for_tenant` → `require_fastapi`. **Confirmed against
  a real OpenFGA server**: ran the example live — `X-Tenant-ID: acme` →
  200 (alice granted `viewer`), `X-Tenant-ID: globex` → 403 (no
  relationship), missing user → 401, missing tenant header → 400.
  Incidental fix: added `uvicorn` to the `fastapi`/`all` dependency
  groups — every FastAPI example's documented run command needed it, but
  nothing declared it.
- [x] **ARCH-5 — Resolve `config.Settings`.** Deleted (`py_authz/config/`
  and its test) — dead code, and env-driven configuration for every
  component would work against the library's "explicit over implicit"
  design goal rather than serve it. `docs/architecture.md` and the
  README's project-layout table updated to state the code-first stance
  explicitly.
- [x] **ARCH-6 — Wire or remove the metrics/logging/retry stubs.**
  Wired, not deleted: `AuthzEngine(metrics=...)` (optional, injected like
  `cache`/`audit_logger`) records check/allowed/denied/cache-hit counters
  and a duration observation per `enforce()` call (`bulk_enforce` gets
  this for free). `core/metrics.py:Metrics` gained a real `observe()`.
  `cli/main.py` now calls `core/logging.py:setup_logging()` (new
  `-v`/`--verbose` flag) — `TenantManager`/`MigrationManager`'s progress
  logs were otherwise invisible. `utils/logging.py` deleted (a true
  duplicate). `utils/retry.py` filled with a real `retry_async()`
  helper; `OpenFGAClient.check()`'s inline retry loop refactored to use
  it — confirmed behavior-preserving (its existing test suite passed
  unmodified).
- [x] **ARCH-7 — Make `testkit.InMemoryFGAClient` honor `inherits=`.**
  `_check()` now walks `(*rel.union, *rel.inherits)` together. New test
  registers an `inherits=`-only model and confirms the same transitive
  resolution `union=` already had.
- [x] **ARCH-8 — Rename `modeling.decorators.require`.** Renamed to
  `authorize` (clean rename, no alias needed — it was never re-exported
  via `modeling/__init__.py`, only imported directly in two test files,
  both updated).
- [x] **ARCH-9 — Thread `context`/`contextual_tuples` through
  `AuthzEngine.explain()`.** `AuthzRequest` already carried both — the
  bug was `explain()` never reading them off the request. Both the
  `check()` and `explain()` client calls now forward them, with a
  `TypeError` fallback to the old call shape for custom client
  implementations that predate this.

---

## Next step

All three tiers are shipped. Nothing left open in this file.
