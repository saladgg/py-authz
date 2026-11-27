import pytest
from fastapi import FastAPI, HTTPException, Request
from fastapi.testclient import TestClient

from py_authz.adapters.fastapi import (
    default_user_getter,
    request_context_middleware,
    require_dependency,
    require_fastapi,
    tenant_from_request,
    tenant_from_verified_claim,
)
from py_authz.core.exceptions import ServiceUnavailable
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


class UnavailableAuthz:
    async def can(self, *a, **kw):
        raise ServiceUnavailable("OpenFGA is down")


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
async def test_require_dependency_resolves_authz_via_sync_callable():
    """
    Regression test for ARCH-4: `authz` may be a callable resolving a
    per-request `Authz` instead of a static one — the mechanism for
    multi-tenant FastAPI apps (`MultiTenantAuthz.for_tenant(...)`).
    """
    resolved_for: list[str] = []

    def authz_getter(request):
        resolved_for.append(request.tenant_id)
        return AllowAuthz()

    dep = require_dependency(
        authz_getter,
        Doc.view,
        resource_getter=lambda request: Doc("static"),
        user_getter=lambda request: Identity(id="user:1"),
    )

    class _Req:
        tenant_id = "acme"

        class state:
            user = Identity(id="user:1")

    await dep(_Req())

    assert resolved_for == ["acme"]


@pytest.mark.asyncio
async def test_require_dependency_resolves_authz_via_async_callable():
    async def authz_getter(request):
        return AllowAuthz()

    dep = require_dependency(
        authz_getter,
        Doc.view,
        resource_getter=lambda request: Doc("static"),
        user_getter=lambda request: Identity(id="user:1"),
    )

    class _Req:
        class state:
            user = Identity(id="user:1")

    # Should not raise — proves the async resolver actually ran and its
    # result (not the coroutine itself) was used for the check.
    await dep(_Req())


@pytest.mark.asyncio
async def test_require_dependency_authz_callable_can_deny():
    async def authz_getter(request):
        return DenyAuthz()

    dep = require_dependency(
        authz_getter,
        Doc.view,
        resource_getter=lambda request: Doc("static"),
        user_getter=lambda request: Identity(id="user:1"),
    )

    class _Req:
        class state:
            user = Identity(id="user:1")

    with pytest.raises(HTTPException) as exc_info:
        await dep(_Req())
    assert exc_info.value.status_code == 403


def test_require_fastapi_decorator_resolves_authz_per_request():
    """
    Regression test for ARCH-4, exercised end to end: a tenant header
    picks which `Authz` backs the check, via `tenant_from_request` (see
    `examples/12_multitenant_fastapi.py`).
    """
    app = FastAPI()
    _inject_user_middleware(app)

    tenants = {"acme": AllowAuthz(), "globex": DenyAuthz()}

    async def authz_for_request(request: Request):
        tenant_id = tenant_from_request(request)
        return tenants[tenant_id]

    @app.get("/docs/{doc_id}")
    @require_fastapi(
        authz_for_request,
        Doc.view,
        resource_getter=lambda request, doc_id: Doc(doc_id),
    )
    async def handler(request: Request, doc_id: str):
        return {"ok": True}

    client = TestClient(app)

    res_acme = client.get("/docs/1", headers={"X-Tenant-ID": "acme"})
    assert res_acme.status_code == 200

    res_globex = client.get("/docs/1", headers={"X-Tenant-ID": "globex"})
    assert res_globex.status_code == 403


@pytest.mark.asyncio
async def test_require_dependency_supports_async_resource_and_user_getters():
    """
    Regression test for DX-1: the common real case is an async DB lookup
    to load the resource being authorized (and, less commonly, the user).
    """
    loaded_ids: list[str] = []

    async def load_document(request, doc_id: str) -> Doc:
        loaded_ids.append(doc_id)
        return Doc(doc_id)

    async def load_user(request) -> Identity:
        return Identity(id="user:async")

    dep = require_dependency(
        AllowAuthz(),
        Doc.view,
        resource_getter=load_document,
        user_getter=load_user,
    )

    class _Req:
        class state:
            user = Identity(id="user:1")

    # Should not raise, and the async getters must actually have run.
    await dep(_Req(), doc_id="42")
    assert loaded_ids == ["42"]


@pytest.mark.asyncio
async def test_require_dependency_raises_503_when_backend_unavailable():
    """
    Regression test for SEC-5: an `ExternalServiceError` from the authz
    backend must surface as a 503 (fail-closed by default), never as an
    unhandled exception or a 403 "denied" decision.
    """
    dep = require_dependency(
        UnavailableAuthz(),
        Doc.view,
        resource_getter=lambda request: Doc("static"),
        user_getter=lambda request: Identity(id="user:1"),
    )

    class _Req:
        class state:
            user = Identity(id="user:1")

    with pytest.raises(HTTPException) as exc_info:
        await dep(_Req())

    assert exc_info.value.status_code == 503


@pytest.mark.asyncio
async def test_require_dependency_fail_open_lets_request_through_on_unavailable():
    dep = require_dependency(
        UnavailableAuthz(),
        Doc.view,
        resource_getter=lambda request: Doc("static"),
        user_getter=lambda request: Identity(id="user:1"),
        fail_open=True,
    )

    class _Req:
        class state:
            user = Identity(id="user:1")

    # Should not raise at all.
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


def test_require_fastapi_decorator_returns_503_when_backend_unavailable():
    """Regression test for SEC-5, exercised through the full decorator via
    a real FastAPI request."""
    app = FastAPI()
    _inject_user_middleware(app)

    @app.get("/docs/{doc_id}")
    @require_fastapi(
        UnavailableAuthz(),
        Doc.view,
        resource_getter=lambda request, doc_id: Doc(doc_id),
    )
    async def handler(request: Request, doc_id: str):
        return {"ok": True}

    client = TestClient(app)
    res = client.get("/docs/42")

    assert res.status_code == 503


def test_require_fastapi_decorator_fail_open_serves_request_when_unavailable():
    app = FastAPI()
    _inject_user_middleware(app)

    @app.get("/docs/{doc_id}")
    @require_fastapi(
        UnavailableAuthz(),
        Doc.view,
        resource_getter=lambda request, doc_id: Doc(doc_id),
        fail_open=True,
    )
    async def handler(request: Request, doc_id: str):
        return {"ok": True}

    client = TestClient(app)
    res = client.get("/docs/42")

    assert res.status_code == 200
    assert res.json() == {"ok": True}


def test_require_fastapi_decorator_supports_async_resource_getter():
    """
    Regression test for DX-1, exercised through the full decorator (not
    just calling the dependency directly) via a real FastAPI request.
    """
    app = FastAPI()
    _inject_user_middleware(app)

    async def load_document(request, doc_id: str) -> Doc:
        return Doc(doc_id)

    @app.get("/docs/{doc_id}")
    @require_fastapi(
        AllowAuthz(),
        Doc.view,
        resource_getter=load_document,
    )
    async def handler(request: Request, doc_id: str):
        return {"ok": True, "doc_id": doc_id}

    client = TestClient(app)
    res = client.get("/docs/99")

    assert res.status_code == 200
    assert res.json() == {"ok": True, "doc_id": "99"}


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


# ----------------------------------------------------------------------
# Regression coverage for SEC2-2: `tenant_from_verified_claim` resolves
# the tenant from the authenticated identity's verified token claims,
# never from a caller-controlled request header.
# ----------------------------------------------------------------------


def test_tenant_from_verified_claim_reads_identity_attributes():
    class _Req:
        class state:
            user = Identity(id="user:1", attributes={"tenant_id": "acme"})

    resolve = tenant_from_verified_claim()

    assert resolve(_Req()) == "acme"


def test_tenant_from_verified_claim_supports_custom_claim_name():
    class _Req:
        class state:
            user = Identity(id="user:1", attributes={"org_id": "globex"})

    resolve = tenant_from_verified_claim("org_id")

    assert resolve(_Req()) == "globex"


def test_tenant_from_verified_claim_raises_when_claim_missing():
    class _Req:
        class state:
            user = Identity(id="user:1", attributes={})

    resolve = tenant_from_verified_claim()

    with pytest.raises(HTTPException) as exc_info:
        resolve(_Req())
    assert exc_info.value.status_code == 400


def test_tenant_from_verified_claim_raises_when_unauthenticated():
    class _Req:
        class state:
            pass

    resolve = tenant_from_verified_claim()

    with pytest.raises(HTTPException) as exc_info:
        resolve(_Req())
    assert exc_info.value.status_code == 400


def test_tenant_from_verified_claim_ignores_spoofed_header():
    """
    Unlike `tenant_from_request`, this must never look at the request
    header at all — a caller can't influence tenant selection just by
    setting X-Tenant-ID; only a claim inside their verified token counts.
    """

    class _Req:
        headers = {"X-Tenant-ID": "attacker-controlled"}

        class state:
            user = Identity(id="user:1", attributes={"tenant_id": "acme"})

    resolve = tenant_from_verified_claim()

    assert resolve(_Req()) == "acme"


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


class RejectingAuthz:
    """OpenFGA rejected the check itself (e.g. a misconfigured relation)."""

    async def can(self, *a, **kw):
        from py_authz.core.exceptions import UpstreamRequestRejected

        raise UpstreamRequestRejected("relation not found", status_code=400)


@pytest.mark.asyncio
async def test_fail_open_never_applies_when_openfga_rejects_the_check():
    """ARCH3-7: a rejected check is a misconfiguration, not an outage.
    Before, it was an ExternalServiceError and `fail_open=True` let the
    request through — i.e. a typo'd relation silently allowed everyone."""
    dep = require_dependency(
        RejectingAuthz(),
        Doc.view,
        resource_getter=lambda request: Doc("static"),
        user_getter=lambda request: Identity(id="user:1"),
        fail_open=True,
    )

    class _Req:
        class state:
            user = Identity(id="user:1")

    with pytest.raises(HTTPException) as exc_info:
        await dep(_Req())

    assert exc_info.value.status_code == 500


def _bare_request(user=None):
    request = Request({"type": "http", "method": "GET", "path": "/", "headers": []})
    if user is not None:
        request.state.user = user
    return request


@pytest.mark.asyncio
async def test_require_fastapi_decorator_finds_a_positional_request():
    """The wrapper accepts the `Request` positionally too (e.g. a handler
    called directly), skipping non-Request args to find it."""
    seen = {}

    def resource_getter(request, **kwargs):
        seen["kwargs"] = kwargs
        return Doc(kwargs["doc_id"])

    @require_fastapi(AllowAuthz(), Doc.view, resource_getter=resource_getter)
    async def handler(marker, request, doc_id):
        return {"marker": marker, "doc_id": doc_id, "user": request.state.user.id}

    request = _bare_request(Identity(id="user:1"))

    result = await handler("first", request, doc_id="42")

    assert result == {"marker": "first", "doc_id": "42", "user": "user:1"}
    assert seen["kwargs"] == {"doc_id": "42"}


@pytest.mark.asyncio
async def test_require_fastapi_decorator_denies_with_a_positional_request():
    @require_fastapi(DenyAuthz(), Doc.view, resource_getter=lambda request: Doc("1"))
    async def handler(request):
        raise AssertionError("handler must not run when denied")

    with pytest.raises(HTTPException) as exc_info:
        await handler(_bare_request(Identity(id="user:1")))

    assert exc_info.value.status_code == 403


@pytest.mark.asyncio
async def test_require_fastapi_decorator_without_a_request_raises():
    """A handler that doesn't take a `Request` can't be checked — fail
    loudly rather than skip enforcement."""
    called = []

    @require_fastapi(AllowAuthz(), Doc.view, resource_getter=lambda request: Doc("1"))
    async def handler(doc_id):
        called.append(doc_id)

    with pytest.raises(RuntimeError, match="Request object not found"):
        await handler("42")

    assert called == []
