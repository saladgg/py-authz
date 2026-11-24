"""Model view/sync/dry-run, version history, rollback (CP-6)."""

from fastapi import APIRouter, Depends, Query

from py_authz.clients.openfga import OpenFGAClient
from py_authz.control_plane.auth import (
    CurrentPrincipal,
    require_system_role,
    require_tenant_role,
    require_tenant_role_from_query,
)
from py_authz.control_plane.deps import get_model_version_store, get_settings, get_tenant_store
from py_authz.control_plane.model_versions import ModelVersionStore
from py_authz.control_plane.schemas import MAX_PAGE_SIZE, ModelRollbackRequest
from py_authz.control_plane.scopes import Scope
from py_authz.control_plane.settings import ControlPlaneSettings
from py_authz.core.exceptions import InvalidAuthzRequest, TenantNotFoundError
from py_authz.core.model_diff import ModelDiffer
from py_authz.core.model_sync import ModelSync
from py_authz.modeling.generator import generate_model

router = APIRouter(tags=["models"])

_require_viewer = require_system_role("viewer", scope=Scope.MODELS_READ)
_require_sync = require_tenant_role_from_query("admin", scope=Scope.MODELS_WRITE)
_require_tenant_auditor = require_tenant_role("auditor", scope=Scope.MODELS_READ)
_require_tenant_admin = require_tenant_role("admin", scope=Scope.MODELS_WRITE)


def _version_dict(version) -> dict:
    return {
        "id": version.id,
        "tenant_id": version.tenant_id,
        "model_id": version.model_id,
        "change_summary": version.change_summary,
        "created_by": version.created_by,
        "created_at": version.created_at.isoformat(),
    }


@router.get("/models", dependencies=[Depends(_require_viewer)])
async def get_current_model() -> dict:
    """
    The model currently registered in this process's Python source (see
    the control-plane deployment's `CONTROL_PLANE_MODEL_MODULE` — same
    idea as the CLI's `--module` flag) — what the *next* sync of any
    tenant would upload, not what any particular tenant is running right
    now (see `GET /tenants/{id}` for that).
    """
    return generate_model()


@router.post("/models/sync")
async def sync_model(
    tenant_id: str,
    dry_run: bool = False,
    principal: CurrentPrincipal = Depends(_require_sync),
    tenant_store=Depends(get_tenant_store),
    model_version_store: ModelVersionStore = Depends(get_model_version_store),
    settings: ControlPlaneSettings = Depends(get_settings),
) -> dict:
    """
    Diff-and-upload the currently registered model to `tenant_id`'s
    store (`ModelSync.sync()`, reused unchanged) — or, with
    `dry_run=true`, only report whether it *would* change anything
    (mirrors `migrate --dry-run`'s existing preview-then-commit shape).
    A version is recorded (CP-6) only on an actual, non-dry-run change.
    """
    store_id = await tenant_store.get(tenant_id)
    if store_id is None:
        raise TenantNotFoundError(f"Unknown tenant: {tenant_id}")

    client = OpenFGAClient.for_tenant(api_url=settings.fga_api_url, store_id=store_id)
    try:
        new_model = generate_model()

        if dry_run:
            current_model = await client.get_latest_model()
            would_change = not (current_model and ModelDiffer.is_equal(new_model, current_model))
            return {"tenant_id": tenant_id, "dry_run": True, "would_change": would_change}

        # Captured before sync() uploads anything, so the diff summary
        # below compares against what was actually live a moment ago —
        # sync() itself re-fetches this internally to decide whether to
        # upload, but doesn't hand the comparison back to the caller.
        previous_model = await client.get_latest_model()

        syncer = ModelSync(client)
        model_id = await syncer.sync()

        if syncer.last_sync_changed:
            await model_version_store.record(
                tenant_id=tenant_id,
                model_id=model_id,
                schema_json=new_model,
                change_summary=ModelDiffer.summarize_diff(previous_model, new_model),
                created_by=principal.identity.id,
            )

        return {"tenant_id": tenant_id, "model_id": model_id, "changed": syncer.last_sync_changed}
    finally:
        await client.aclose()


@router.get("/tenants/{tenant_id}/models/history", dependencies=[Depends(_require_tenant_auditor)])
async def model_history(
    tenant_id: str,
    limit: int = Query(50, ge=1, le=MAX_PAGE_SIZE),
    offset: int = Query(0, ge=0),
    model_version_store: ModelVersionStore = Depends(get_model_version_store),
) -> dict:
    versions = await model_version_store.history(tenant_id, limit=limit, offset=offset)
    return {"items": [_version_dict(v) for v in versions]}


@router.post("/tenants/{tenant_id}/models/rollback")
async def rollback_model(
    tenant_id: str,
    body: ModelRollbackRequest,
    principal: CurrentPrincipal = Depends(_require_tenant_admin),
    tenant_store=Depends(get_tenant_store),
    model_version_store: ModelVersionStore = Depends(get_model_version_store),
    settings: ControlPlaneSettings = Depends(get_settings),
) -> dict:
    """
    Re-sync `tenant_id` to a prior `model_versions` row's schema — a
    *forward* sync to an old schema (`ModelSync.sync(force=True)` with
    that schema as its `model_factory`), not a magic undo of everything
    that happened since. Recorded as its own new `model_versions` row,
    same as any other sync.
    """
    version = await model_version_store.get(body.version_id)
    if version is None or version.tenant_id != tenant_id:
        raise InvalidAuthzRequest(
            f"No model version {body.version_id} recorded for tenant {tenant_id!r}"
        )

    store_id = await tenant_store.get(tenant_id)
    if store_id is None:
        raise TenantNotFoundError(f"Unknown tenant: {tenant_id}")

    client = OpenFGAClient.for_tenant(api_url=settings.fga_api_url, store_id=store_id)
    try:
        previous_model = await client.get_latest_model()

        syncer = ModelSync(client, model_factory=lambda: version.schema_json)
        model_id = await syncer.sync(force=True)

        diff_summary = ModelDiffer.summarize_diff(previous_model, version.schema_json)
        await model_version_store.record(
            tenant_id=tenant_id,
            model_id=model_id,
            schema_json=version.schema_json,
            change_summary=f"rolled back to version {version.id}: {diff_summary}",
            created_by=principal.identity.id,
        )

        return {"tenant_id": tenant_id, "model_id": model_id, "rolled_back_to_version": version.id}
    finally:
        await client.aclose()
