import pytest

from py_authz.cache.memory import InMemoryCache
from py_authz.core.enforcement import AuthzEngine
from py_authz.core.types import AuthzRequest, Identity, Resource
from tests.conftest import MockOpenFGAClient as _BaseMockOpenFGAClient


class MockOpenFGAClient(_BaseMockOpenFGAClient):
    """Mock with a store_id attribute, which the audit logger reads."""

    def __init__(self, allowed: bool = True, store_id: str = "store-test"):
        super().__init__(allowed=allowed)
        self.store_id = store_id


class RecordingAuditLogger:
    def __init__(self):
        self.events: list = []

    async def log(self, event):
        self.events.append(event)


def _request(allowed_user="user:1"):
    return AuthzRequest(
        identity=Identity(id=allowed_user),
        action="view",
        resource=Resource(type="doc", id="1"),
    )


@pytest.mark.asyncio
async def test_cache_hit_short_circuits_fga_call():
    cache = InMemoryCache()
    fga = MockOpenFGAClient(allowed=True)
    engine = AuthzEngine(fga_client=fga, cache=cache)

    req = _request()

    # 1st call populates cache
    assert await engine.enforce(req) is True
    # 2nd call should be cache hit — fga called once in total
    assert await engine.enforce(req) is True
    assert len(fga.calls) == 1


@pytest.mark.asyncio
async def test_audit_logger_called_with_allowed_event():
    audit = RecordingAuditLogger()
    engine = AuthzEngine(
        fga_client=MockOpenFGAClient(allowed=True),
        cache=None,
        audit_logger=audit,
    )

    await engine.enforce(_request())
    await engine.flush_audit_logs()  # audit writes are dispatched in the background

    assert len(audit.events) == 1
    event = audit.events[0]
    assert event.allowed is True
    assert event.user_id == "user:1"
    assert event.action == "view"
    assert event.resource == "doc:1"
    assert "allowed via relation" in event.reason
    assert event.reason_data == {"cache_hit": False, "relation": "view"}


@pytest.mark.asyncio
async def test_audit_logger_called_with_denied_event():
    audit = RecordingAuditLogger()
    engine = AuthzEngine(
        fga_client=MockOpenFGAClient(allowed=False),
        cache=None,
        audit_logger=audit,
    )

    await engine.enforce(_request())
    await engine.flush_audit_logs()

    assert audit.events[0].allowed is False
    assert "no matching relation" in audit.events[0].reason


@pytest.mark.asyncio
async def test_enforce_survives_audit_logger_failure():
    """
    Regression test for SEC-3: an unhealthy audit sink must never affect
    the enforcement decision, and must never propagate out of `enforce()`.
    """

    class FailingAuditLogger:
        def __init__(self):
            self.call_count = 0

        async def log(self, event):
            self.call_count += 1
            raise RuntimeError("audit sink is down")

    audit = FailingAuditLogger()
    engine = AuthzEngine(
        fga_client=MockOpenFGAClient(allowed=True),
        cache=None,
        audit_logger=audit,
    )

    result = await engine.enforce(_request())
    assert result is True

    # The background audit task runs (and fails) once flushed; the
    # decision above must already have been unaffected either way.
    await engine.flush_audit_logs()
    assert audit.call_count == 1


@pytest.mark.asyncio
async def test_enforce_denied_survives_audit_logger_failure():
    """Same as above, but for a denied decision with raise_on_denied."""

    class FailingAuditLogger:
        async def log(self, event):
            raise RuntimeError("audit sink is down")

    engine = AuthzEngine(
        fga_client=MockOpenFGAClient(allowed=False),
        cache=None,
        audit_logger=FailingAuditLogger(),
        raise_on_denied=True,
    )

    from py_authz.core.exceptions import AuthorizationDenied

    with pytest.raises(AuthorizationDenied):
        await engine.enforce(_request())

    await engine.flush_audit_logs()


@pytest.mark.asyncio
async def test_invalid_request_variants_all_raise():
    from py_authz.core.exceptions import InvalidAuthzRequest

    engine = AuthzEngine(fga_client=MockOpenFGAClient(), cache=None)

    cases = [
        AuthzRequest(
            identity=Identity(id=""),
            action="view",
            resource=Resource(type="doc", id="1"),
        ),
        AuthzRequest(
            identity=Identity(id="user:1"),
            action="",
            resource=Resource(type="doc", id="1"),
        ),
        AuthzRequest(
            identity=Identity(id="user:1"),
            action="view",
            resource=Resource(type="", id="1"),
        ),
        AuthzRequest(
            identity=Identity(id="user:1"),
            action="view",
            resource=Resource(type="doc", id=""),
        ),
    ]

    for req in cases:
        with pytest.raises(InvalidAuthzRequest):
            await engine.enforce(req)
