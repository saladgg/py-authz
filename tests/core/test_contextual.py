import pytest

from py_authz.cache.memory import InMemoryCache
from py_authz.core.enforcement import AuthzEngine
from py_authz.core.types import AuthzRequest, ContextualTuple, Identity, Resource


class CapturingClient:
    def __init__(self, allowed=True):
        self.store_id = "s"
        self.allowed = allowed
        self.last_kwargs: dict | None = None
        self.call_count = 0

    async def check(self, user, relation, object, *, contextual_tuples=None, context=None):
        self.call_count += 1
        self.last_kwargs = {
            "user": user,
            "relation": relation,
            "object": object,
            "contextual_tuples": contextual_tuples,
            "context": context,
        }
        return self.allowed


@pytest.mark.asyncio
async def test_enforce_forwards_context_and_contextual_tuples():
    client = CapturingClient(allowed=True)
    engine = AuthzEngine(fga_client=client)

    request = AuthzRequest(
        identity=Identity(id="user:alice"),
        action="viewer",
        resource=Resource(type="document", id="1"),
        context={"hour": 14},
        contextual_tuples=(ContextualTuple("user:alice", "owner", "document:1"),),
    )

    assert await engine.enforce(request) is True
    assert client.last_kwargs["context"] == {"hour": 14}
    assert client.last_kwargs["contextual_tuples"] == [
        {"user": "user:alice", "relation": "owner", "object": "document:1"}
    ]


@pytest.mark.asyncio
async def test_requests_with_context_bypass_cache():
    """A request carrying per-request state must always re-check FGA."""
    client = CapturingClient(allowed=True)
    cache = InMemoryCache()
    engine = AuthzEngine(fga_client=client, cache=cache)

    base = {
        "identity": Identity(id="user:alice"),
        "action": "viewer",
        "resource": Resource(type="document", id="1"),
    }

    # First call with context: hits FGA, must NOT populate cache for this key.
    await engine.enforce(AuthzRequest(**base, context={"hour": 9}))
    assert client.call_count == 1

    # Second call with different context but same (user, relation, object):
    # if the engine were caching, it would short-circuit and return the same
    # answer without consulting FGA.
    await engine.enforce(AuthzRequest(**base, context={"hour": 23}))
    assert client.call_count == 2

    # Same for contextual tuples.
    await engine.enforce(
        AuthzRequest(
            **base,
            contextual_tuples=(ContextualTuple("user:alice", "owner", "document:1"),),
        )
    )
    assert client.call_count == 3


@pytest.mark.asyncio
async def test_plain_requests_still_cache():
    client = CapturingClient(allowed=True)
    engine = AuthzEngine(fga_client=client, cache=InMemoryCache())

    request = AuthzRequest(
        identity=Identity(id="user:alice"),
        action="viewer",
        resource=Resource(type="document", id="1"),
    )

    await engine.enforce(request)
    await engine.enforce(request)

    # second call served from cache
    assert client.call_count == 1
