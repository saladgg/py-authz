import pytest

from py_authz.core.enforcement import AuthzEngine
from py_authz.core.exceptions import InvalidAuthzRequest
from py_authz.core.types import ContextualTuple, Identity


class ListObjectsClient:
    def __init__(self, objects=None):
        self.store_id = "s"
        self._objects = objects or []
        self.calls: list[dict] = []

    async def list_objects(
        self,
        user,
        relation,
        type,
        *,
        contextual_tuples=None,
        context=None,
    ):
        self.calls.append(
            {
                "user": user,
                "relation": relation,
                "type": type,
                "contextual_tuples": contextual_tuples,
                "context": context,
            }
        )
        return self._objects


@pytest.mark.asyncio
async def test_engine_list_objects_returns_client_response():
    client = ListObjectsClient(objects=["document:1", "document:2"])
    engine = AuthzEngine(fga_client=client)

    result = await engine.list_objects(
        user=Identity(id="user:alice"),
        relation="viewer",
        resource_type="document",
    )

    assert result == ["document:1", "document:2"]
    assert client.calls[0]["user"] == "user:alice"
    assert client.calls[0]["relation"] == "viewer"
    assert client.calls[0]["type"] == "document"


@pytest.mark.asyncio
async def test_engine_list_objects_forwards_contextual_state():
    client = ListObjectsClient()
    engine = AuthzEngine(fga_client=client)

    await engine.list_objects(
        user=Identity(id="user:alice"),
        relation="viewer",
        resource_type="document",
        context={"now": "2026-04-26"},
        contextual_tuples=[ContextualTuple("user:alice", "owner", "document:x")],
    )

    call = client.calls[0]
    assert call["context"] == {"now": "2026-04-26"}
    assert call["contextual_tuples"] == [
        {"user": "user:alice", "relation": "owner", "object": "document:x"}
    ]


@pytest.mark.asyncio
async def test_engine_list_objects_validates_inputs():
    engine = AuthzEngine(fga_client=ListObjectsClient())

    with pytest.raises(InvalidAuthzRequest):
        await engine.list_objects(user=Identity(id=""), relation="viewer", resource_type="d")

    with pytest.raises(InvalidAuthzRequest):
        await engine.list_objects(user=Identity(id="user:1"), relation="", resource_type="d")

    with pytest.raises(InvalidAuthzRequest):
        await engine.list_objects(user=Identity(id="user:1"), relation="viewer", resource_type="")
