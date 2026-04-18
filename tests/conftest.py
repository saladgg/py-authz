import pytest

from py_authz.api import Authz
from py_authz.cache.memory import InMemoryCache
from py_authz.core.enforcement import AuthzEngine
from py_authz.core.types import AuthzRequest, Identity, Resource


class MockOpenFGAClient:
    """
    Mock OpenFGA client for testing.

    Allows controlling responses without real HTTP calls.
    """

    def __init__(self, allowed: bool = True):
        self.allowed = allowed
        self.calls = []

    async def check(self, user: str, relation: str, object: str) -> bool:
        self.calls.append((user, relation, object))
        return self.allowed


@pytest.fixture
def identity():
    return Identity(id="user:123")


@pytest.fixture
def resource():
    return Resource(type="document", id="456")


@pytest.fixture
def authz_request(identity, resource):
    return AuthzRequest(
        identity=identity,
        action="viewer",
        resource=resource,
    )


@pytest.fixture
def mock_fga_client():
    return MockOpenFGAClient(allowed=True)


@pytest.fixture
def cache():
    return InMemoryCache()


@pytest.fixture
def engine(mock_fga_client, cache):
    return AuthzEngine(fga_client=mock_fga_client, cache=cache)


@pytest.fixture
def authz(engine):
    return Authz(engine)
