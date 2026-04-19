import pytest
from fastapi import FastAPI, HTTPException, Request
from fastapi.testclient import TestClient

from py_authz.adapters.fastapi import (
    default_user_getter,
    request_context_middleware,
    require_dependency,
    require_fastapi,
    tenant_from_request,
)
from py_authz.core.types import Identity
from py_authz.modeling import Relation, ResourceModel


class Doc(ResourceModel):
    type = "document"
    view = Relation("viewer")


class AllowAuthz:
    async def can(self, *a, **kw):
        return True


class DenyAuthz:
    async def can(self, *a, **kw):
        return False


def _inject_user_middleware(app):
    @app.middleware("http")
    async def inject_user(request: Request, call_next):
        request.state.user = Identity(id="user:1")
        return await call_next(request)


@pytest.mark.asyncio
async def test_require_dependency_runs_check_and_passes_when_allowed():
    """
    Exercise the dependency callable directly — FastAPI dependency wiring
    is not the thing under test here, the enforcement logic is.
    """
    dep = require_dependency(
        AllowAuthz(),
        Doc.view,
        resource_getter=lambda request: Doc("static"),
        user_getter=lambda request: Identity(id="user:1"),
    )

    class _Req:
        class state:
            user = Identity(id="user:1")

    # Should not raise
    await dep(_Req())


@pytest.mark.asyncio
async def test_require_dependency_raises_403_when_denied():
    dep = require_dependency(
        DenyAuthz(),
        Doc.view,
        resource_getter=lambda request: Doc("static"),
        user_getter=lambda request: Identity(id="user:1"),
    )

    class _Req:
        class state:
            user = Identity(id="user:1")

    try:
        await dep(_Req())
    except HTTPException as exc:
        assert exc.status_code == 403
    else:
        raise AssertionError("expected HTTPException")


def test_require_fastapi_decorator_returns_403_when_denied():
    app = FastAPI()
    _inject_user_middleware(app)

    @app.get("/docs/{doc_id}")
    @require_fastapi(
        DenyAuthz(),
        Doc.view,
        resource_getter=lambda request, doc_id: Doc(doc_id),
    )
    async def handler(request: Request, doc_id: str):
        return {"ok": True}

    client = TestClient(app)
    res = client.get("/docs/42")

    assert res.status_code == 403


def test_require_fastapi_decorator_supports_sync_handlers():
    app = FastAPI()
    _inject_user_middleware(app)

    @app.get("/docs/{doc_id}")
    @require_fastapi(
        AllowAuthz(),
        Doc.view,
        resource_getter=lambda request, doc_id: Doc(doc_id),
    )
    def handler(request: Request, doc_id: str):
        return {"sync": True, "doc_id": doc_id}

    client = TestClient(app)
    res = client.get("/docs/42")

    assert res.status_code == 200
    assert res.json() == {"sync": True, "doc_id": "42"}


def test_default_user_getter_raises_when_missing_user():
    class _Req:
        class state:
            pass

    try:
        default_user_getter(_Req())
    except HTTPException as e:
        assert e.status_code == 401
    else:
        raise AssertionError("should have raised")


def test_default_user_getter_returns_identity():
    identity = Identity(id="user:1")

    class _Req:
        class state:
            user = identity

    assert default_user_getter(_Req()) is identity


def test_tenant_from_request_reads_header():
    class _Req:
        headers = {"X-Tenant-ID": "tenant-42"}

    assert tenant_from_request(_Req()) == "tenant-42"


def test_tenant_from_request_raises_when_missing():
    class _Req:
        headers = {}

    try:
        tenant_from_request(_Req())
    except HTTPException as e:
        assert e.status_code == 400
    else:
        raise AssertionError("should have raised")


def test_request_context_middleware_sets_request_id_header():
    app = FastAPI()
    app.middleware("http")(request_context_middleware)

    @app.get("/ping")
    async def ping():
        return {"ok": True}

    client = TestClient(app)
    res = client.get("/ping")

    assert res.status_code == 200
    assert "X-Request-ID" in res.headers
    assert len(res.headers["X-Request-ID"]) > 0
