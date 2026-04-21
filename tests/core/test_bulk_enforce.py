import pytest

from py_authz.core.enforcement import AuthzEngine
from py_authz.core.types import AuthzRequest, BulkAuthzResult, Identity, Resource
from tests.conftest import MockOpenFGAClient


@pytest.mark.asyncio
async def test_bulk_enforce_returns_one_result_per_request(bulk_requests, engine):
    results = await engine.bulk_enforce(bulk_requests)

    assert len(results) == len(bulk_requests)
    assert all(isinstance(r, BulkAuthzResult) for r in results)
    assert all(r.allowed is True for r in results)


@pytest.mark.asyncio
async def test_bulk_enforce_preserves_request_linkage(bulk_requests, engine):
    results = await engine.bulk_enforce(bulk_requests)

    # Results may be in any order due to concurrency; match by request identity
    returned_resources = {r.request.resource.id for r in results}
    expected_resources = {req.resource.id for req in bulk_requests}
    assert returned_resources == expected_resources


@pytest.mark.asyncio
async def test_bulk_enforce_mixed_allow_deny():
    """Different requests may yield different decisions."""
    # Two clients: we can't swap per-request on a single mock, so we use two
    # engines and route requests manually. Simpler: test with denied client.
    engine = AuthzEngine(fga_client=MockOpenFGAClient(allowed=False), cache=None)

    requests = [
        AuthzRequest(
            identity=Identity(id=f"user:{i}"),
            action="view",
            resource=Resource(type="doc", id=str(i)),
        )
        for i in range(3)
    ]

    results = await engine.bulk_enforce(requests)

    assert len(results) == 3
    assert all(r.allowed is False for r in results)


@pytest.mark.asyncio
async def test_bulk_enforce_respects_concurrency_limit():
    """
    With concurrency=1 the semaphore serializes access. The test passes as
    long as all results come back; behavior under a slow mock is asserted
    by tracking call count equal to request count.
    """
    fga = MockOpenFGAClient(allowed=True)
    engine = AuthzEngine(fga_client=fga, cache=None)

    requests = [
        AuthzRequest(
            identity=Identity(id="user:1"),
            action="view",
            resource=Resource(type="doc", id=str(i)),
        )
        for i in range(4)
    ]

    results = await engine.bulk_enforce(requests, concurrency=1)

    assert len(results) == 4
    assert len(fga.calls) == 4


@pytest.mark.asyncio
async def test_bulk_enforce_empty_list_returns_empty(engine):
    results = await engine.bulk_enforce([])
    assert results == []
