from py_authz.core.types import (
    AuthzExplanation,
    AuthzRequest,
    BulkAuthzResult,
    Identity,
    Resource,
)


def test_cache_key():
    user = Identity(id="user:1")
    resource = Resource(type="doc", id="123")

    req = AuthzRequest(identity=user, action="view", resource=resource)

    assert req.cache_key() == "user:1:view:doc:123"


def test_authz_explanation_defaults():
    exp = AuthzExplanation(allowed=True, reason="direct grant")

    assert exp.allowed is True
    assert exp.reason == "direct grant"
    assert exp.path is None
    assert exp.details is None


def test_authz_explanation_with_path_and_details():
    details = {"raw": "something"}
    exp = AuthzExplanation(
        allowed=False,
        reason="no match",
        path=["step-1", "step-2"],
        details=details,
    )

    assert exp.allowed is False
    assert exp.path == ["step-1", "step-2"]
    assert exp.details is details


def test_bulk_authz_result_holds_request_and_decision():
    req = AuthzRequest(
        identity=Identity(id="user:1"),
        action="view",
        resource=Resource(type="doc", id="42"),
    )
    res = BulkAuthzResult(req, True)

    assert res.request is req
    assert res.allowed is True
