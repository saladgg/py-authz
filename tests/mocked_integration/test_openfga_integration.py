"""
Mocked "integration" tests for the full Authz → AuthzEngine → OpenFGAClient
stack. These exercise the same wiring a real OpenFGA deployment would, but
use a scripted httpx-compatible client so the suite runs offline.
"""

import httpx
import pytest

from py_authz.api import Authz
from py_authz.clients.openfga import OpenFGAClient
from py_authz.core.enforcement import AuthzEngine
from py_authz.core.types import Identity, Resource


class MockResponse:
    def __init__(self, data=None, status_code=200):
        self._data = data or {}
        self.status_code = status_code

    def raise_for_status(self):
        if self.status_code >= 400:
            raise httpx.HTTPStatusError("HTTP error", request=None, response=self)

    def json(self):
        return self._data


class ScriptedHTTPClient:
    """
    Minimal httpx-compatible client driven by an in-memory tuple store.

    Responds to OpenFGA's `/stores/{id}/check` endpoint with `allowed=True`
    iff the exact (user, relation, object) tuple has been written.
    """

    def __init__(self):
        self.tuples: set[tuple[str, str, str]] = set()
        self.check_calls: list[dict] = []

    def write_tuple(self, user: str, relation: str, obj: str) -> None:
        self.tuples.add((user, relation, obj))

    async def request(self, method, path, json=None, **_kwargs):

        return await self.post(path, json=json)

    async def post(self, path, json=None, **_):
        if path.endswith("/check"):
            self.check_calls.append(json)
            key = json["tuple_key"]
            allowed = (key["user"], key["relation"], key["object"]) in self.tuples
            return MockResponse({"allowed": allowed})

        raise AssertionError(f"Unexpected POST to {path}")


@pytest.fixture
def http():
    return ScriptedHTTPClient()


@pytest.fixture
def authz(http):
    client = OpenFGAClient(
        api_url="http://fake-openfga",
        store_id="store-1",
        model_id="model-1",
        http_client=http,
    )
    engine = AuthzEngine(fga_client=client)
    return Authz(engine)


@pytest.mark.asyncio
async def test_authorized_access(authz, http):
    user = Identity(id="user:123")
    doc = Resource(type="document", id="456")

    http.write_tuple("user:123", "viewer", "document:456")

    allowed = await authz.enforce("viewer", user, doc)

    assert allowed is True
    assert http.check_calls[0]["authorization_model_id"] == "model-1"
    assert http.check_calls[0]["tuple_key"] == {
        "user": "user:123",
        "relation": "viewer",
        "object": "document:456",
    }


@pytest.mark.asyncio
async def test_denied_access(authz, http):
    user = Identity(id="user:999")
    doc = Resource(type="document", id="456")

    allowed = await authz.enforce("viewer", user, doc)

    assert allowed is False
    assert len(http.check_calls) == 1
