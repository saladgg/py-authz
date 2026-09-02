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

    assert req.cache_key() == "6:user:1|4:view|3:doc|3:123"


def test_cache_key_is_injective_across_colon_boundaries():
    """
    Regression test for SEC2-1: a naive ":".join(...) cache key is NOT
    injective — two unrelated requests, built using the library's own
    documented colon-bearing resource-ID convention ("doc:456"), could
    concatenate to the identical raw string. The length-prefixed encoding
    must keep them distinct.
    """
    req_a = AuthzRequest(
        identity=Identity(id="user:123"),
        action="viewer",
        resource=Resource(type="document", id="doc:456"),
    )
    req_b = AuthzRequest(
        identity=Identity(id="user:123"),
        action="viewer:document",
        resource=Resource(type="doc", id="456"),
    )

    assert req_a.cache_key() != req_b.cache_key()


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
