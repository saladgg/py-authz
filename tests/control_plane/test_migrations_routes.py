"""Tests for py_authz.control_plane.routes.migrations (CP-7): dry-run
(synchronous) vs. real (async job) migrations, job polling, and listing.

`migration_manager` is injected via `Depends`, so it's faked directly;
`job_runner`/`job_store` use the real `JobRunner` (a plain orchestration
class with no I/O of its own) wrapping an in-memory fake `JobStore`,
matching the "fake only the storage layer" convention used elsewhere
(e.g. `test_tenant_manager.py`'s `FakeOpenFGAClient`).
"""

import asyncio
from datetime import datetime

import pytest
from fastapi import FastAPI
from starlette.testclient import TestClient

from py_authz.control_plane.errors import authz_error_handler
from py_authz.control_plane.jobs import PENDING, SUCCEEDED, Job, JobRunner
from py_authz.control_plane.rbac_model import SYSTEM_OBJECT_ID, System
from py_authz.control_plane.routes import migrations as migrations_routes
from py_authz.core.exceptions import AuthzError
from py_authz.core.migrations_manager import MigrationBatchResult
from py_authz.core.tenant_store import InMemoryTenantStore
from py_authz.core.types import Identity

from .conftest import bearer

_NOW = datetime(2026, 1, 1)


class FakeJobStore:
    def __init__(self):
        self.jobs: dict[str, Job] = {}
        self._counter = 0

    async def create(self, *, kind, params, initiated_by):
        self._counter += 1
        job = Job(
            id=f"job-{self._counter}",
            kind=kind,
            status=PENDING,
            params=params,
            result=None,
            initiated_by=initiated_by,
            started_at=None,
            finished_at=None,
            created_at=_NOW,
        )
        self.jobs[job.id] = job
        return job

    async def mark_running(self, job_id):
        job = self.jobs[job_id]
        self.jobs[job_id] = Job(**{**job.__dict__, "status": "running", "started_at": _NOW})

    async def mark_finished(self, job_id, *, status, result):
        job = self.jobs[job_id]
        self.jobs[job_id] = Job(
            **{**job.__dict__, "status": status, "result": result, "finished_at": _NOW}
        )

    async def get(self, job_id):
        return self.jobs.get(job_id)

    async def list(self, *, kind=None, limit=50, offset=0):
        jobs = [j for j in self.jobs.values() if kind is None or j.kind == kind]
        return jobs[offset : offset + limit]


class FakeMigrationManager:
    def __init__(self):
        self.dry_run_calls: list[list[str]] = []
        self.migrate_calls: list[list[str]] = []
        self.batch_result = MigrationBatchResult(succeeded={"acme": "model-1"}, failed={})
        self.concurrency_seen: list[int] = []
        self.dry_run_failures: dict[str, Exception] = {}

    async def dry_run_batch(self, tenant_ids, *, concurrency=10):
        from py_authz.core.migrations_manager import DryRunBatchResult

        self.dry_run_calls.append(tenant_ids)
        self.concurrency_seen.append(concurrency)
        return DryRunBatchResult(
            would_change={t: True for t in tenant_ids if t not in self.dry_run_failures},
            failed={t: self.dry_run_failures[t] for t in tenant_ids if t in self.dry_run_failures},
        )

    async def migrate_all(self, tenant_ids, *, concurrency=10):
        self.migrate_calls.append(tenant_ids)
        self.concurrency_seen.append(concurrency)
        return self.batch_result


@pytest.fixture
def tenant_store():
    return InMemoryTenantStore()


@pytest.fixture
def job_store():
    return FakeJobStore()


@pytest.fixture
def migration_manager():
    return FakeMigrationManager()


@pytest.fixture
def app(
    rbac_authz,
    oidc_validator,
    operator_store,
    bootstrapper,
    tenant_store,
    job_store,
    migration_manager,
):
    fastapi_app = FastAPI()
    fastapi_app.add_exception_handler(AuthzError, authz_error_handler)
    fastapi_app.include_router(migrations_routes.router, prefix="/api/v1")

    fastapi_app.state.rbac_authz = rbac_authz
    fastapi_app.state.oidc_validator = oidc_validator
    fastapi_app.state.operator_store = operator_store
    fastapi_app.state.bootstrapper = bootstrapper
    fastapi_app.state.tenant_store = tenant_store
    fastapi_app.state.job_store = job_store
    fastapi_app.state.job_runner = JobRunner(job_store)
    fastapi_app.state.migration_manager = migration_manager

    return fastapi_app


@pytest.fixture
def client(app):
    return TestClient(app)


@pytest.mark.asyncio
async def test_start_migration_requires_system_operator(client, rbac_authz):
    resp = client.post("/api/v1/migrations", headers=bearer(), json={"all_tenants": True})
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_start_migration_requires_all_tenants_or_tenant_ids(client, rbac_authz):
    await rbac_authz.grant(Identity(id="user:alice"), "operator", System(id=SYSTEM_OBJECT_ID))

    resp = client.post("/api/v1/migrations", headers=bearer(), json={})

    assert resp.status_code == 400


@pytest.mark.asyncio
async def test_dry_run_runs_synchronously_against_named_tenants(
    client, rbac_authz, migration_manager
):
    await rbac_authz.grant(Identity(id="user:alice"), "operator", System(id=SYSTEM_OBJECT_ID))

    resp = client.post(
        "/api/v1/migrations",
        headers=bearer(),
        json={"dry_run": True, "tenant_ids": ["acme", "other-corp"]},
    )

    assert resp.status_code == 200
    assert resp.json() == {
        "dry_run": True,
        "would_change": {"acme": True, "other-corp": True},
        "failed": {},
    }
    assert migration_manager.dry_run_calls == [["acme", "other-corp"]]
    assert migration_manager.migrate_calls == []


@pytest.mark.asyncio
async def test_migration_concurrency_setting_is_passed_through(
    app, client, rbac_authz, migration_manager
):
    """Regression test for REL3-11: `CONTROL_PLANE_MIGRATION_CONCURRENCY`
    was parsed into settings but never reached `MigrationManager`."""
    from types import SimpleNamespace

    app.state.settings = SimpleNamespace(migration_concurrency=3)
    await rbac_authz.grant(Identity(id="user:alice"), "operator", System(id=SYSTEM_OBJECT_ID))

    resp = client.post(
        "/api/v1/migrations", headers=bearer(), json={"dry_run": True, "tenant_ids": ["acme"]}
    )

    assert resp.status_code == 200
    assert migration_manager.concurrency_seen == [3]


@pytest.mark.asyncio
async def test_dry_run_with_all_tenants_resolves_from_tenant_store(
    client, rbac_authz, tenant_store, migration_manager
):
    await tenant_store.set("acme", "store-for-acme")
    await tenant_store.set("other-corp", "store-for-other")
    await rbac_authz.grant(Identity(id="user:alice"), "operator", System(id=SYSTEM_OBJECT_ID))

    resp = client.post(
        "/api/v1/migrations", headers=bearer(), json={"dry_run": True, "all_tenants": True}
    )

    assert resp.status_code == 200
    assert migration_manager.dry_run_calls == [["acme", "other-corp"]]


@pytest.mark.asyncio
async def test_real_migration_returns_a_pending_job_that_later_succeeds(
    client, rbac_authz, migration_manager, job_store
):
    await rbac_authz.grant(Identity(id="user:alice"), "operator", System(id=SYSTEM_OBJECT_ID))

    resp = client.post("/api/v1/migrations", headers=bearer(), json={"tenant_ids": ["acme"]})

    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == PENDING
    assert body["initiated_by"] == "user:alice"
    job_id = body["id"]

    # The job runs in a background asyncio task started by JobRunner.submit
    # — give the event loop a turn to let it finish before polling.
    for _ in range(50):
        if job_store.jobs[job_id].status != PENDING:
            break
        await asyncio.sleep(0.01)

    resp = client.get(f"/api/v1/migrations/{job_id}", headers=bearer())
    assert resp.status_code == 200
    finished = resp.json()
    assert finished["status"] == SUCCEEDED
    assert finished["result"] == {"succeeded": {"acme": "model-1"}, "failed": {}}


@pytest.mark.asyncio
async def test_real_migration_job_reports_failure(client, rbac_authz, migration_manager, job_store):
    await rbac_authz.grant(Identity(id="user:alice"), "operator", System(id=SYSTEM_OBJECT_ID))
    migration_manager.batch_result = MigrationBatchResult(
        succeeded={}, failed={"acme": RuntimeError("boom")}
    )

    resp = client.post("/api/v1/migrations", headers=bearer(), json={"tenant_ids": ["acme"]})
    job_id = resp.json()["id"]

    for _ in range(200):
        if job_store.jobs[job_id].status not in (PENDING, "running"):
            break
        await asyncio.sleep(0.01)

    resp = client.get(f"/api/v1/migrations/{job_id}", headers=bearer())
    body = resp.json()
    # REL3-3: every tenant failed, so the job failed — it used to say
    # `succeeded` because migrate_all() itself doesn't raise.
    assert body["status"] == "failed"
    assert body["result"]["failed"] == {"acme": "boom"}


@pytest.mark.asyncio
async def test_get_migration_job_requires_system_auditor(client, rbac_authz, job_store):
    resp = client.get("/api/v1/migrations/job-1", headers=bearer())
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_get_unknown_migration_job_is_404(client, rbac_authz):
    await rbac_authz.grant(Identity(id="user:alice"), "auditor", System(id=SYSTEM_OBJECT_ID))

    resp = client.get("/api/v1/migrations/no-such-job", headers=bearer())

    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_list_migration_jobs_requires_system_auditor(client, rbac_authz, job_store):
    await job_store.create(kind="migrate", params={}, initiated_by="user:alice")

    resp = client.get("/api/v1/migrations", headers=bearer())
    assert resp.status_code == 403

    await rbac_authz.grant(Identity(id="user:alice"), "auditor", System(id=SYSTEM_OBJECT_ID))
    resp = client.get("/api/v1/migrations", headers=bearer())
    assert resp.status_code == 200
    assert len(resp.json()["items"]) == 1


@pytest.mark.asyncio
async def test_dry_run_reports_a_failing_tenant_instead_of_500ing(
    client, rbac_authz, migration_manager
):
    """REL3-9: one stale/unreachable tenant used to abort the whole preview
    with an unhandled ExceptionGroup (a raw 500)."""
    from py_authz.core.exceptions import TenantNotFoundError

    migration_manager.dry_run_failures["ghost"] = TenantNotFoundError("Tenant not found: ghost")
    await rbac_authz.grant(Identity(id="user:alice"), "operator", System(id=SYSTEM_OBJECT_ID))

    resp = client.post(
        "/api/v1/migrations",
        headers=bearer(),
        json={"dry_run": True, "tenant_ids": ["acme", "ghost"]},
    )

    assert resp.status_code == 200
    assert resp.json()["would_change"] == {"acme": True}
    assert resp.json()["failed"] == {"ghost": "TenantNotFoundError"}


@pytest.mark.asyncio
async def test_a_migration_where_every_tenant_failed_is_not_reported_succeeded(
    client, rbac_authz, migration_manager, job_store
):
    """REL3-3: an all-failed batch used to end `succeeded`."""
    from py_authz.control_plane.jobs import FAILED, PARTIAL

    await rbac_authz.grant(Identity(id="user:alice"), "operator", System(id=SYSTEM_OBJECT_ID))

    migration_manager.batch_result = MigrationBatchResult(
        succeeded={}, failed={"acme": RuntimeError("boom")}
    )
    job_id = client.post(
        "/api/v1/migrations", headers=bearer(), json={"tenant_ids": ["acme"]}
    ).json()["id"]
    for _ in range(200):
        if job_store.jobs[job_id].status not in ("pending", "running"):
            break
        await asyncio.sleep(0.01)
    assert job_store.jobs[job_id].status == FAILED

    migration_manager.batch_result = MigrationBatchResult(
        succeeded={"acme": "m1"}, failed={"other": RuntimeError("boom")}
    )
    job_id = client.post(
        "/api/v1/migrations", headers=bearer(), json={"tenant_ids": ["acme", "other"]}
    ).json()["id"]
    for _ in range(200):
        if job_store.jobs[job_id].status not in ("pending", "running"):
            break
        await asyncio.sleep(0.01)
    assert job_store.jobs[job_id].status == PARTIAL
