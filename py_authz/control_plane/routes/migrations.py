"""
Async migrations (CP-7): a request that would otherwise block for the
duration of a same-shape `py-authz migrate` CLI invocation instead
returns a job immediately; the actual work runs via `JobRunner` (CP-7)
using the existing `MigrationManager` unchanged.
"""

from fastapi import APIRouter, Depends, HTTPException

from py_authz.control_plane.auth import CurrentPrincipal, require_system_role
from py_authz.control_plane.deps import (
    get_job_runner,
    get_job_store,
    get_migration_concurrency,
    get_migration_manager,
    get_tenant_store,
)
from py_authz.control_plane.jobs import Job, JobRunner, JobStore
from py_authz.control_plane.schemas import MigrationRequest
from py_authz.control_plane.scopes import Scope
from py_authz.core.exceptions import InvalidAuthzRequest
from py_authz.core.migrations_manager import MigrationManager

router = APIRouter(prefix="/migrations", tags=["migrations"])

#: Migrating across tenants is a system-wide action — an individual
#: tenant admin doesn't get to trigger a rollout naming *other* tenants,
#: and "all tenants" has no single tenant to scope a `tenant_role` check
#: to anyway.
_require_operator = require_system_role("operator", scope=Scope.MIGRATIONS_WRITE)
_require_auditor = require_system_role("auditor", scope=Scope.MIGRATIONS_READ)


def _job_dict(job: Job) -> dict:
    return {
        "id": job.id,
        "kind": job.kind,
        "status": job.status,
        "params": job.params,
        "result": job.result,
        "initiated_by": job.initiated_by,
        "started_at": job.started_at.isoformat() if job.started_at else None,
        "finished_at": job.finished_at.isoformat() if job.finished_at else None,
        "created_at": job.created_at.isoformat(),
    }


async def _resolve_tenant_ids(body: MigrationRequest, tenant_store) -> list[str]:
    if body.all_tenants:
        return await tenant_store.list_tenant_ids()
    if body.tenant_ids:
        return body.tenant_ids
    raise InvalidAuthzRequest("Either all_tenants=true or a non-empty tenant_ids list is required")


@router.post("", dependencies=[Depends(_require_operator)])
async def start_migration(
    body: MigrationRequest,
    principal: CurrentPrincipal = Depends(_require_operator),
    migration_manager: MigrationManager = Depends(get_migration_manager),
    tenant_store=Depends(get_tenant_store),
    job_runner: JobRunner = Depends(get_job_runner),
    concurrency: int = Depends(get_migration_concurrency),
) -> dict:
    """
    `dry_run=true` runs synchronously (a dry run is read-only and bounded
    by the same concurrency `MigrationManager.dry_run_all()` already
    uses — no need for the job machinery just to preview). Otherwise
    returns a `pending` job immediately; poll `GET /migrations/{job_id}`.
    """
    tenant_ids = await _resolve_tenant_ids(body, tenant_store)

    if body.dry_run:
        results = await migration_manager.dry_run_all(tenant_ids, concurrency=concurrency)
        return {"dry_run": True, "would_change": results}

    async def work() -> dict:
        batch = await migration_manager.migrate_all(tenant_ids, concurrency=concurrency)
        return {
            "succeeded": batch.succeeded,
            "failed": {tenant_id: str(exc) for tenant_id, exc in batch.failed.items()},
        }

    job = await job_runner.submit(
        kind="migrate",
        params={"tenant_ids": tenant_ids, "all_tenants": body.all_tenants},
        initiated_by=principal.identity.id,
        work=work,
    )
    return _job_dict(job)


@router.get("/{job_id}", dependencies=[Depends(_require_auditor)])
async def get_migration_job(job_id: str, job_store: JobStore = Depends(get_job_store)) -> dict:
    job = await job_store.get(job_id)
    if job is None:
        raise HTTPException(status_code=404, detail=f"No such job: {job_id}")
    return _job_dict(job)


@router.get("", dependencies=[Depends(_require_auditor)])
async def list_migration_jobs(
    limit: int = 50, offset: int = 0, job_store: JobStore = Depends(get_job_store)
) -> dict:
    jobs = await job_store.list(kind="migrate", limit=limit, offset=offset)
    return {"items": [_job_dict(j) for j in jobs]}
