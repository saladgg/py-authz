from py_authz.core.types import AuthzRequest, Identity, Resource


def test_cache_key():
    user = Identity(id="user:1")
    resource = Resource(type="doc", id="123")

    req = AuthzRequest(identity=user, action="view", resource=resource)

    assert req.cache_key() == "user:1:view:doc:123"
