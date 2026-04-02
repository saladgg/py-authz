import pytest
from django_authz.authorization.policies import ObjectRef, Policy


class AllowAllClient:
    def check(self, user, relation, object_):
        return True


class DenyAllClient:
    def check(self, user, relation, object_):
        return False


class CapturingClient:
    def __init__(self):
        self.calls = []

    def check(self, user, relation, object_):
        self.calls.append({"user": user, "relation": relation, "object_": object_})
        return True


def test_policy_is_allowed_returns_true():
    policy = Policy(client=AllowAllClient())
    assert policy.is_allowed("user:alice", "reader", ObjectRef("doc", "1")) is True


def test_policy_is_allowed_returns_false():
    policy = Policy(client=DenyAllClient())
    assert policy.is_allowed("user:alice", "editor", ObjectRef("doc", "1")) is False


def test_policy_formats_object_string_correctly():
    client = CapturingClient()
    policy = Policy(client=client)
    policy.is_allowed("user:bob", "viewer", ObjectRef("project", "99"))

    assert len(client.calls) == 1
    assert client.calls[0]["object_"] == "project:99"
    assert client.calls[0]["user"] == "user:bob"
    assert client.calls[0]["relation"] == "viewer"


def test_policy_raises_when_no_client_and_openfga_not_configured():
    """Policy() with no explicit client raises ValueError when OPENFGA settings are absent."""
    with pytest.raises(ValueError, match="OPENFGA_API_URL"):
        Policy()


def test_objectref_is_frozen():
    obj = ObjectRef("doc", "42")
    with pytest.raises((AttributeError, TypeError)):
        obj.type = "other"  # type: ignore[misc]


def test_objectref_fields():
    obj = ObjectRef(type="document", id="123")
    assert obj.type == "document"
    assert obj.id == "123"


def test_objectref_equality():
    assert ObjectRef("doc", "1") == ObjectRef("doc", "1")
    assert ObjectRef("doc", "1") != ObjectRef("doc", "2")
