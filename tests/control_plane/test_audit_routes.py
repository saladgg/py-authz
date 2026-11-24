"""
Tests for py_authz.control_plane.routes.audit (CP-5).

Regression coverage for a bug found via live testing against a real
stack: `audit_logs.tenant_id` is populated from
`AuthzEngine.fga_client.store_id` (the OpenFGA store id), not the
human-readable `tenant_id` every other route in this API uses — so
`GET /audit-logs?tenant_id=<human-readable-id>` must resolve it via
`TenantStore` before querying, or it silently returns zero rows forever
no matter how many matching events exist.

Uses `require_system_or_tenant_role_from_query`'s real auth path (a fake
`OIDCJWTValidator`, matching `test_auth.py`'s pattern) rather than
overriding `get_current_principal` via `app.dependency_overrides` — that
dependency factory calls `get_current_principal(request)` as a plain
function, not through FastAPI's own DI, so an override on it alone
wouldn't take effect here the way it does for `routes/operators.py`
(which uses `Depends(get_current_principal)` directly).
"""

from datetime import datetime

import pytest
from fastapi import FastAPI
from starlette.testclient import TestClient

from py_authz.api import Authz
from py_authz.control_plane.errors import authz_error_handler
from py_authz.control_plane.rbac_model import RBAC_MODELS, SYSTEM_OBJECT_ID, System, Tenant
from py_authz.control_plane.routes import audit as audit_routes
from py_authz.core.enforcement import AuthzEngine
from py_authz.core.exceptions import AuthzError
from py_authz.core.tenant_store import InMemoryTenantStore
from py_authz.core.types import Identity
from py_authz.modeling.registry import ResourceModelRegistry
from py_authz.testkit import InMemoryFGAClient


class FakeOIDCValidator:
    def __init__(self, tokens: dict[str, dict]):
        self.tokens = tokens

    async def validate(self, token: str) -> dict:
        from py_authz.core.exceptions import AuthenticationError

        if token not in self.tokens:
            raise AuthenticationError("invalid token")
        return self.tokens[token]

    def to_identity(self, payload: dict) -> Identity:
        return Identity(id=f"user:{payload['sub']}", attributes=payload)


class FakeOperatorStore:
    async def record_login(self, *, subject, email):
        pass


class FakeBootstrapper:
    async def maybe_bootstrap(self, identity):
        pass


class FakeAuditQuery:
    def __init__(self, rows):
        self.rows = rows
        self.calls = []

    async def query(self, **kwargs):
        self.calls.append(kwargs)
        return [dict(r) for r in self.rows if kwargs.get("tenant_id") in (None, r["tenant_id"])]


ALICE = Identity(id="user:alice")


@pytest.fixture
def rbac_authz():
    reg = ResourceModelRegistry()
    # Strict mode + the full RBAC model (incl. the `service_account`
    # subject type): reject what a real OpenFGA rejects (ARCH3-9).
    for model in RBAC_MODELS:
        reg.register(model)
    client = InMemoryFGAClient(model_registry=reg, strict=True)
    return Authz(AuthzEngine(fga_client=client))


@pytest.fixture
def tenant_store():
    return InMemoryTenantStore()


@pytest.fixture
def audit_query():
    return FakeAuditQuery(
        [
            {
                "id": 1,
                "timestamp": datetime(2026, 1, 1),
                "tenant_id": "store-for-acme",  # the real OpenFGA store id
                "user_id": "user:bob",
                "action": "owner",
                "resource": "document:roadmap",
                "allowed": True,
                "reason": "onboarding",
                "reason_data": None,
                "request_id": None,
            }
        ]
    )


@pytest.fixture
def client(rbac_authz, tenant_store, audit_query):
    fastapi_app = FastAPI()
    fastapi_app.add_exception_handler(AuthzError, authz_error_handler)
    fastapi_app.include_router(audit_routes.router, prefix="/api/v1")

    fastapi_app.state.rbac_authz = rbac_authz
    fastapi_app.state.tenant_store = tenant_store
    fastapi_app.state.audit_query = audit_query
    fastapi_app.state.oidc_validator = FakeOIDCValidator({"good-token": {"sub": "alice"}})
    fastapi_app.state.operator_store = FakeOperatorStore()
    fastapi_app.state.bootstrapper = FakeBootstrapper()

    return TestClient(fastapi_app)


def _bearer():
    return {"Authorization": "Bearer good-token"}


@pytest.mark.asyncio
async def test_filtering_by_human_readable_tenant_id_resolves_to_store_id(
    client, rbac_authz, tenant_store, audit_query
):
    await tenant_store.set("acme-corp", "store-for-acme")
    await rbac_authz.grant(ALICE, "auditor", Tenant(id="acme-corp"))

    resp = client.get("/api/v1/audit-logs", params={"tenant_id": "acme-corp"}, headers=_bearer())

    assert resp.status_code == 200
    items = resp.json()["items"]
    assert len(items) == 1
    # The response echoes back the human-readable tenant_id, not the raw
    # OpenFGA store id that's actually stored in the row.
    assert items[0]["tenant_id"] == "acme-corp"

    # And the underlying query was actually given the resolved store id,
    # not the human-readable one — confirms the fix, not just a response
    # relabeling that happens to look right.
    assert audit_query.calls[-1]["tenant_id"] == "store-for-acme"


@pytest.mark.asyncio
async def test_filtering_by_unknown_tenant_id_is_404(client, rbac_authz):
    # `require_system_or_tenant_role_from_query` checks the RBAC role
    # *first* — a caller must be authorized for this specific tenant
    # object before the route body ever runs (see that dependency's own
    # docstring: a system role doesn't imply a tenant one). Granting a
    # role directly on the not-yet-provisioned tenant id isolates this
    # test to the handler's own "does this tenant actually exist" check.
    await rbac_authz.grant(ALICE, "auditor", Tenant(id="never-provisioned"))

    resp = client.get(
        "/api/v1/audit-logs", params={"tenant_id": "never-provisioned"}, headers=_bearer()
    )

    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_no_tenant_filter_requires_system_role_and_passes_none_through(
    client, rbac_authz, audit_query
):
    await rbac_authz.grant(ALICE, "auditor", System(id=SYSTEM_OBJECT_ID))

    resp = client.get("/api/v1/audit-logs", headers=_bearer())

    assert resp.status_code == 200
    assert audit_query.calls[-1]["tenant_id"] is None


@pytest.mark.asyncio
async def test_no_tenant_filter_denied_without_system_role(client, rbac_authz):
    # Alice holds only a tenant-scoped role — not enough for an unscoped,
    # every-tenant query.
    await rbac_authz.grant(ALICE, "auditor", Tenant(id="acme-corp"))

    resp = client.get("/api/v1/audit-logs", headers=_bearer())

    assert resp.status_code == 403
