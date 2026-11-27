"""
Tests for py_authz.control_plane.routes.audit (CP-5).

Since ARCH3-16, `audit_logs.tenant_id` holds the tenant id and
`store_id` the store id. Rows written before migration 0009 held the
store id in `tenant_id`, so a tenant filter also passes the tenant's
current store id as `legacy_store_id`.

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
        wanted = {kwargs.get("tenant_id"), kwargs.get("legacy_store_id")} - {None}
        rows = [dict(r) for r in self.rows if not wanted or r["tenant_id"] in wanted]
        return rows[: kwargs.get("limit", 50)]


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
async def test_tenant_filter_passes_tenant_id_and_legacy_store_id(
    client, rbac_authz, tenant_store, audit_query
):
    await tenant_store.set("acme-corp", "store-for-acme")
    await rbac_authz.grant(ALICE, "auditor", Tenant(id="acme-corp"))

    resp = client.get("/api/v1/audit-logs", params={"tenant_id": "acme-corp"}, headers=_bearer())

    assert resp.status_code == 200
    items = resp.json()["items"]
    # The legacy row (store id in `tenant_id`) is found and echoed back
    # with the requested tenant id.
    assert len(items) == 1
    assert items[0]["tenant_id"] == "acme-corp"
    assert audit_query.calls[-1]["tenant_id"] == "acme-corp"
    assert audit_query.calls[-1]["legacy_store_id"] == "store-for-acme"


@pytest.mark.asyncio
async def test_unknown_tenant_still_queries_by_tenant_id(client, rbac_authz, audit_query):
    """ARCH3-16: a deprovisioned tenant's history stays queryable (no 404)."""
    await rbac_authz.grant(ALICE, "auditor", Tenant(id="gone"))

    resp = client.get("/api/v1/audit-logs", params={"tenant_id": "gone"}, headers=_bearer())

    assert resp.status_code == 200
    assert audit_query.calls[-1]["tenant_id"] == "gone"
    assert audit_query.calls[-1]["legacy_store_id"] is None


@pytest.mark.asyncio
async def test_full_page_returns_a_cursor_that_round_trips(client, rbac_authz, audit_query):
    """REL3-15: keyset pagination."""
    await rbac_authz.grant(ALICE, "auditor", System(id=SYSTEM_OBJECT_ID))

    first = client.get("/api/v1/audit-logs", params={"limit": 1}, headers=_bearer())

    assert first.status_code == 200
    cursor = first.json()["next_cursor"]
    assert cursor is not None
    resp = client.get(
        "/api/v1/audit-logs", params={"limit": 1, "cursor": cursor}, headers=_bearer()
    )
    assert resp.status_code == 200
    assert audit_query.calls[-1]["before"] == (datetime(2026, 1, 1), 1)

    short = client.get("/api/v1/audit-logs", params={"limit": 5}, headers=_bearer())
    assert short.json()["next_cursor"] is None


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "params",
    [{"cursor": "not-a-cursor!"}, {"cursor": "MjAyNnwx", "offset": 5}],
)
async def test_bad_cursor_or_cursor_with_offset_is_400(client, rbac_authz, params):
    await rbac_authz.grant(ALICE, "auditor", System(id=SYSTEM_OBJECT_ID))

    resp = client.get("/api/v1/audit-logs", params=params, headers=_bearer())

    assert resp.status_code == 400


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
