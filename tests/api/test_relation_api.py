import pytest

from py_authz.api import Authz
from py_authz.core.enforcement import AuthzEngine
from py_authz.core.types import Identity
from py_authz.modeling import Relation, ResourceModel
from tests.conftest import MockOpenFGAClient


class Doc(ResourceModel):
    type = "document"
    view = Relation("viewer")


@pytest.mark.asyncio
async def test_can_with_relation_and_resource_model():
    engine = AuthzEngine(fga_client=MockOpenFGAClient(allowed=True), cache=None)
    authz = Authz(engine)

    result = await authz.can(Doc.view, Identity(id="user:1"), Doc("42"))

    assert result is True


@pytest.mark.asyncio
async def test_can_with_relation_rejects_non_resource_model():
    engine = AuthzEngine(fga_client=MockOpenFGAClient(), cache=None)
    authz = Authz(engine)

    with pytest.raises(TypeError, match="ResourceModel"):
        await authz.can(Doc.view, Identity(id="user:1"), "not-a-model")


@pytest.mark.asyncio
async def test_sync_model_requires_fga_client():
    engine = AuthzEngine(fga_client=None, cache=None)
    authz = Authz(engine)

    with pytest.raises(RuntimeError, match="FGA client not configured"):
        await authz.sync_model()


@pytest.mark.asyncio
async def test_sync_model_delegates_to_model_sync(monkeypatch):
    engine = AuthzEngine(fga_client=MockOpenFGAClient(), cache=None)
    authz = Authz(engine)

    class FakeSync:
        def __init__(self, client):
            self.client = client

        async def sync(self):
            return "new-model-id"

    import py_authz.api as api_module

    monkeypatch.setattr(api_module, "ModelSync", FakeSync)

    result = await authz.sync_model()

    assert result == "new-model-id"
