"""
DX3-2: cross-tenant isolation across EVERY tenant-scoped route.

Each route module's own tests cover "no role vs. role on the same
tenant"; nothing asserted the highest-value property of a multi-tenant
admin API — that holding a role on tenant `acme` grants nothing on tenant
`globex`. This sweeps every route in `app.API_ROUTERS` whose path names a
tenant, plus the routes that take the tenant from a query parameter or
the body, and asserts an `acme` *owner* gets 403 on `globex`.

Route bodies never run here: authorization fails first, so the stores the
handlers would use are permissive stand-ins.
"""

import pytest
from fastapi import FastAPI
from fastapi.routing import APIRoute
from starlette.testclient import TestClient

from py_authz.control_plane.app import API_PREFIX, API_ROUTERS
from py_authz.control_plane.errors import authz_error_handler
from py_authz.control_plane.rbac_model import Tenant
from py_authz.core.exceptions import AuthzError
from py_authz.core.types import Identity

from .conftest import bearer


class _Unused:
    """State a handler would use if authorization ever let it run."""

    def __getattr__(self, name):
        raise AssertionError(f"route body ran despite cross-tenant access ({name})")


@pytest.fixture
def app(rbac_authz, oidc_validator, operator_store, bootstrapper):
    fastapi_app = FastAPI()
    fastapi_app.add_exception_handler(AuthzError, authz_error_handler)
    for router in API_ROUTERS:
        fastapi_app.include_router(router, prefix=API_PREFIX)

    for name in (
        "tenant_store",
        "tenant_manager",
        "model_registry",
        "multi_tenant_authz",
        "model_version_store",
        "audit_query",
        "redis_cache",
        "service_account_store",
        "migration_manager",
        "job_store",
        "job_runner",
        "metrics",
    ):
        setattr(fastapi_app.state, name, _Unused())
    fastapi_app.state.rbac_authz = rbac_authz
    fastapi_app.state.oidc_validator = oidc_validator
    fastapi_app.state.operator_store = operator_store
    fastapi_app.state.bootstrapper = bootstrapper
    return fastapi_app


def _tenant_path_routes():
    for router in API_ROUTERS:
        for route in router.routes:
            assert isinstance(route, APIRoute)
            if "{tenant_id}" in route.path:
                for method in sorted(route.methods):
                    yield method, API_PREFIX + route.path


TENANT_PATH_ROUTES = list(_tenant_path_routes())

#: Routes taking the tenant from somewhere other than the path.
OTHER_TENANT_ROUTES = [
    ("POST", "/api/v1/models/sync?tenant_id=globex", None),
    ("GET", "/api/v1/audit-logs?tenant_id=globex", None),
    (
        "POST",
        "/api/v1/operators/roles",
        {"subject": "bob", "scope": "tenant", "tenant_id": "globex", "role": "viewer"},
    ),
    (
        "DELETE",
        "/api/v1/operators/roles",
        {"subject": "bob", "scope": "tenant", "tenant_id": "globex", "role": "viewer"},
    ),
    ("GET", "/api/v1/operators/roles?scope=tenant&tenant_id=globex", None),
]


def test_the_sweep_actually_covers_routes():
    assert len(TENANT_PATH_ROUTES) >= 8


@pytest.mark.asyncio
@pytest.mark.parametrize(("method", "path"), TENANT_PATH_ROUTES)
async def test_an_owner_of_one_tenant_cannot_use_another_tenants_path_routes(
    app, rbac_authz, method, path
):
    await rbac_authz.grant(Identity(id="user:alice"), "owner", Tenant(id="acme"))

    resp = TestClient(app).request(
        method, path.replace("{tenant_id}", "globex"), headers=bearer(), json={}
    )

    assert resp.status_code == 403, (method, path, resp.text)


@pytest.mark.asyncio
@pytest.mark.parametrize(("method", "path", "body"), OTHER_TENANT_ROUTES)
async def test_an_owner_of_one_tenant_cannot_target_another_tenant_by_query_or_body(
    app, rbac_authz, method, path, body
):
    await rbac_authz.grant(Identity(id="user:alice"), "owner", Tenant(id="acme"))

    resp = TestClient(app).request(method, path, headers=bearer(), json=body)

    assert resp.status_code == 403, (method, path, resp.text)


# ---------------------------------------------------------------------------
# REL3-15: list endpoints reject unbounded or negative paging params
# ---------------------------------------------------------------------------


async def _authorize_everything(rbac_authz):
    from py_authz.control_plane.rbac_model import SYSTEM_OBJECT_ID, System

    await rbac_authz.grant(Identity(id="user:alice"), "owner", System(id=SYSTEM_OBJECT_ID))
    await rbac_authz.grant(Identity(id="user:alice"), "owner", Tenant(id="acme"))


@pytest.mark.parametrize(
    "path",
    [
        "/api/v1/audit-logs",
        "/api/v1/migrations",
        "/api/v1/tenants",
        "/api/v1/tenants/acme/models/history",
    ],
)
@pytest.mark.parametrize("query", ["limit=100000000", "limit=0", "limit=-1", "offset=-5"])
@pytest.mark.asyncio
async def test_list_endpoints_reject_out_of_range_paging(app, rbac_authz, path, query):
    """A fully authorized caller is refused by validation (the handler
    never runs) — a huge limit used to load a whole table into API
    memory, a negative one surfaced as an asyncpg 500."""
    await _authorize_everything(rbac_authz)

    resp = TestClient(app).get(f"{path}?{query}", headers=bearer())

    assert resp.status_code == 422, (path, query, resp.text)


@pytest.mark.asyncio
async def test_tuple_page_size_is_capped_at_openfgas_limit(app, rbac_authz):
    await _authorize_everything(rbac_authz)

    resp = TestClient(app).get("/api/v1/tenants/acme/tuples?page_size=1000", headers=bearer())

    assert resp.status_code == 422
