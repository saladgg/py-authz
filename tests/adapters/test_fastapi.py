from fastapi import FastAPI, Request
from fastapi.testclient import TestClient

from py_authz.adapters.fastapi import require_fastapi
from py_authz.core.types import Identity
from py_authz.modeling import Relation, ResourceModel


class Doc(ResourceModel):
    type = "document"
    view = Relation("viewer")


class MockAuthz:
    async def can(self, *args, **kwargs):
        return True


def test_fastapi_decorator():
    app = FastAPI()
    authz = MockAuthz()

    @app.middleware("http")
    async def inject_user(request: Request, call_next):
        request.state.user = Identity(id="user:1")
        return await call_next(request)

    @app.get("/docs/{doc_id}")
    @require_fastapi(
        authz,
        Doc.view,
        resource_getter=lambda request, doc_id: Doc(doc_id),
    )
    async def handler(request: Request, doc_id: str):
        return {"ok": True}

    client = TestClient(app)

    res = client.get("/docs/1")

    assert res.status_code == 200
