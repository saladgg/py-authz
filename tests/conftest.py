import pytest

from py_authz.api import Authz
from py_authz.cache.memory import InMemoryCache
from py_authz.core.enforcement import AuthzEngine
from py_authz.core.types import AuthzRequest, Identity, Resource


class MockOpenFGAClient:
    """
    Mock OpenFGA client for testing.

    Records interactions and allows controlling responses without real HTTP calls.

    Attributes:
        allowed: default response for `check`.
        store_id: mimics the real client's store_id (used by audit + logging).
        calls: list of (user, relation, object) tuples recorded on check.
        writes: list of write-tuple payloads recorded on write_tuples.
        deletes: list of delete-tuple payloads recorded on write_tuples.
        explain_data: response returned from `explain` (if `has_explain=True`).
        explain_raises: optional exception for `explain` to raise.
    """

    def __init__(
        self,
        allowed: bool = True,
        *,
        store_id: str = "store-test",
        has_explain: bool = False,
        explain_data=None,
        explain_raises: Exception | None = None,
    ):
        self.allowed = allowed
        self.store_id = store_id
        self.calls: list[tuple[str, str, str]] = []
        self.writes: list[dict] = []
        self.deletes: list[dict] = []
        self.write_tuples_calls: list[tuple[list[dict], list[dict] | None]] = []
        self._has_explain = has_explain
        self._explain_data = explain_data
        self._explain_raises = explain_raises

    async def check(self, user: str, relation: str, object: str) -> bool:
        self.calls.append((user, relation, object))
        return self.allowed

    async def write_tuples(
        self,
        writes: list[dict],
        deletes: list[dict] | None = None,
    ) -> None:
        self.write_tuples_calls.append((list(writes), list(deletes) if deletes else None))
        self.writes.extend(writes)
        if deletes:
            self.deletes.extend(deletes)

    def __getattr__(self, name):
        # Conditionally expose `explain` so `hasattr(client, "explain")`
        # matches the production code path in AuthzEngine.explain.
        if name == "explain" and self._has_explain:

            async def _explain(user: str, relation: str, object: str):
                if self._explain_raises is not None:
                    raise self._explain_raises
                return self._explain_data

            return _explain
        raise AttributeError(name)


class RecordingAuditLogger:
    """Captures audit events for assertions."""

    def __init__(self):
        self.events: list = []

    async def log(self, event):
        self.events.append(event)


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
def denied_fga_client():
    return MockOpenFGAClient(allowed=False)


@pytest.fixture
def cache():
    return InMemoryCache()


@pytest.fixture
def audit_logger():
    return RecordingAuditLogger()


@pytest.fixture
def engine(mock_fga_client, cache):
    return AuthzEngine(fga_client=mock_fga_client, cache=cache)


@pytest.fixture
def denied_engine(denied_fga_client):
    return AuthzEngine(fga_client=denied_fga_client, cache=None)


@pytest.fixture
def authz(engine):
    return Authz(engine)


@pytest.fixture
def denied_authz(denied_engine):
    return Authz(denied_engine)


@pytest.fixture
def bulk_requests(identity):
    """A batch of distinct AuthzRequests for bulk-enforce tests."""
    return [
        AuthzRequest(
            identity=identity,
            action="viewer",
            resource=Resource(type="document", id=str(i)),
        )
        for i in range(5)
    ]


@pytest.fixture
async def model(authz):
    """
    Loads the current model into OpenFGA.
    """
    from py_authz.core.model_sync import ModelSync

    syncer = ModelSync(authz._engine.fga_client)
    await syncer.sync(force=True)

    return authz
