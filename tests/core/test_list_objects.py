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


@pytest.mark.asyncio
@pytest.mark.parametrize("with_metrics", [True, False])
async def test_a_result_at_the_cap_is_flagged_as_possibly_truncated(caplog, with_metrics):
    """REL3-17: OpenFGA truncates at its result cap without saying so."""
    from py_authz.core.metrics import Metrics

    client = ListObjectsClient(objects=["document:1", "document:2", "document:3"])
    client.list_objects_max_results = 3
    metrics = Metrics() if with_metrics else None
    engine = AuthzEngine(fga_client=client, metrics=metrics)

    result = await engine.list_objects(Identity(id="user:1"), "viewer", "document")

    assert len(result) == 3
    assert "authz_list_objects_possibly_truncated" in caplog.text
    if metrics:
        assert metrics.counters["authz_list_objects_truncated_total"] == 1


@pytest.mark.asyncio
@pytest.mark.parametrize("cap", [4, None])
async def test_a_result_below_the_cap_or_without_one_is_not_flagged(caplog, cap):
    from py_authz.core.metrics import Metrics

    client = ListObjectsClient(objects=["document:1", "document:2", "document:3"])
    client.list_objects_max_results = cap
    metrics = Metrics()
    engine = AuthzEngine(fga_client=client, metrics=metrics)

    await engine.list_objects(Identity(id="user:1"), "viewer", "document")

    assert "possibly_truncated" not in caplog.text
    assert "authz_list_objects_truncated_total" not in metrics.counters
