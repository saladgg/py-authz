# py-authz — Developer Experience, Testing & Missing Capabilities Backlog (Round 3)

Execution checklist for
[`13_developer_experience_testing_and_capabilities.md`](13_developer_experience_testing_and_capabilities.md).
IDs match that file.

> **Status (2026-11-24):** DX3-1 shipped with `10`'s Tier 0. Everything
> else open.

---

## Tier 0 — Safety nets that would have caught this round's worst bugs

- [x] **DX3-1 — Authenticated live control-plane end-to-end test**
  (operator flow plus SA flow plus cache invalidation). Land it alongside
  `10`'s Tier 0.
  `test_operator_and_service_account_flows_end_to_end` covers: a real
  Keycloak password-grant token → break-glass makes it `system#owner` →
  provision a tenant with a real store and model sync → grant a tenant
  role → a manual grant with a reason that shows up in the audit log
  when filtered by *tenant id* (`09`'s regression) → the SA flow (create,
  403 without a role, role grant by id, 200 with role and scope, 403 on a
  route outside its scopes, revoke removes its grant in the real store).
  The live fixture's truncate now also clears the control-plane tables.
  **Cache invalidation is not covered yet.** It lands with `10`'s SEC3-6,
  whose fix it would assert.
- [ ] **DX3-2 — Cross-tenant 403 test parametrized over every
  tenant-scoped route.**
- [ ] **DX3-7 — Panel CI job (lint, tsc, build, audit) plus a vitest
  suite for `lib/` and the CSV export.**
- [ ] **DX3-8 — `migrate`: no default backend; non-zero exit on an empty
  `--all-tenants`; builder tests.**

## Tier 1 — Test-suite quality

- [ ] **DX3-3 — Real signed-token JWT tests (alg none, HS256 confusion,
  iss, exp, nbf, typ).**
- [ ] **DX3-4 — `fail_under = 95`; cover the lifespan wiring.**
- [ ] **DX3-5 — Injectable clock; event-driven lock and job tests.**
- [ ] **DX3-6 — Example import test; run selected examples in the live
  job.**

## Tier 2 — Docs and metadata accuracy

- [ ] **DX3-9 — Fix the README multi-tenancy snippet and the `model_id`
  comment.**
- [ ] **DX3-10 — semantic-release updates the README version; `:nf`
  version; URLs; classifier; upgrade notes in the CHANGELOG.**
- [ ] **DX3-11 — Lower `requires-python` to 3.12 after a runtime check;
  add the matrix.**
- [ ] **DX3-12 — README cache-key and ruff-rules corrections.**

## Tier 3 — Control-panel UX

- [ ] **DX3-13 — Error boundaries, loading states, 401 → logout, guarded
  JSON parse.**
- [ ] **DX3-14 — Surface API errors; real pagination and totals.**
- [ ] **DX3-15 — Mobile navigation sheet.**
- [ ] **DX3-16 — Label associations, `aria-current`, move `shadcn` to
  devDependencies, `engines`.**

## Tier 4 — New capabilities (each needs a short design note first)

- [ ] **DX3-17 — Conditions, wildcards and usersets in the modeling DSL
  and in grants.** Blocked on `11`'s ARCH3-3 and ARCH3-6.
- [ ] **DX3-18 — Django/DRF, Flask and ASGI adapters on top of
  `SyncAuthz`.** Blocked on `11`'s ARCH3-2.
- [ ] **DX3-19 — Consistency, ListUsers, BatchCheck, Expand,
  ReadChanges.**
- [ ] **DX3-20 — Optional OpenTelemetry tracing extra.**
- [ ] **DX3-21 — DSL output, `py-authz test`/`check`/`diff`.**
- [ ] **DX3-22 — `py-authz audit purge`.**
