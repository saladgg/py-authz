"""Tests for immutable token/principal dataclasses and RelationTuple."""

import pytest

from django_authz.models.relations import RelationTuple
from django_authz.models.tokens import AccessToken, IDToken, Principal


# ---------------------------------------------------------------------------
# IDToken
# ---------------------------------------------------------------------------


def test_idtoken_stores_all_fields():
    token = IDToken(
        sub="sub-1",
        email="alice@example.com",
        preferred_username="alice",
        realm_access={"roles": ["admin"]},
        resource_access={"backend": {"roles": ["user"]}},
    )
    assert token.sub == "sub-1"
    assert token.email == "alice@example.com"
    assert token.preferred_username == "alice"
    assert token.realm_access == {"roles": ["admin"]}
    assert token.resource_access == {"backend": {"roles": ["user"]}}


def test_idtoken_optional_fields_default_to_none():
    token = IDToken(sub="sub-2")
    assert token.email is None
    assert token.preferred_username is None
    assert token.realm_access is None
    assert token.resource_access is None


def test_idtoken_is_frozen():
    token = IDToken(sub="sub-3")
    with pytest.raises((AttributeError, TypeError)):
        token.sub = "other"  # type: ignore[misc]


# ---------------------------------------------------------------------------
# AccessToken
# ---------------------------------------------------------------------------


def test_accesstoken_stores_all_fields():
    token = AccessToken(
        raw="raw.jwt.string",
        subject="sub-1",
        email="bob@example.com",
        scope="openid profile email",
    )
    assert token.raw == "raw.jwt.string"
    assert token.subject == "sub-1"
    assert token.email == "bob@example.com"
    assert token.scope == "openid profile email"


def test_accesstoken_optional_fields_default_to_none():
    token = AccessToken(raw="raw.jwt.string")
    assert token.subject is None
    assert token.email is None
    assert token.scope is None


def test_accesstoken_is_frozen():
    token = AccessToken(raw="raw.jwt.string")
    with pytest.raises((AttributeError, TypeError)):
        token.raw = "other"  # type: ignore[misc]


# ---------------------------------------------------------------------------
# Principal
# ---------------------------------------------------------------------------


def test_principal_stores_all_fields(jwt_payload):
    principal = Principal(
        subject=jwt_payload["sub"],
        email=jwt_payload["email"],
        username=jwt_payload["preferred_username"],
        claims=jwt_payload,
    )
    assert principal.subject == jwt_payload["sub"]
    assert principal.email == jwt_payload["email"]
    assert principal.username == jwt_payload["preferred_username"]
    assert principal.claims == jwt_payload


def test_principal_optional_fields_default_to_none():
    principal = Principal(subject="sub-x")
    assert principal.email is None
    assert principal.username is None
    assert principal.claims is None


def test_principal_is_frozen():
    principal = Principal(subject="sub-x")
    with pytest.raises((AttributeError, TypeError)):
        principal.subject = "other"  # type: ignore[misc]


# ---------------------------------------------------------------------------
# RelationTuple
# ---------------------------------------------------------------------------


def test_relation_tuple_fga_string():
    t = RelationTuple(object_type="doc", object_id="42", relation="reader", user="user:alice")
    assert t.fga_string() == "doc:42#reader@user:alice"


def test_relation_tuple_fga_string_with_subject_set():
    """A group subject set should format correctly."""
    t = RelationTuple(
        object_type="project", object_id="7", relation="member", user="group:eng#member"
    )
    assert t.fga_string() == "project:7#member@group:eng#member"


def test_relation_tuple_is_frozen():
    t = RelationTuple(object_type="doc", object_id="1", relation="reader", user="user:x")
    with pytest.raises((AttributeError, TypeError)):
        t.relation = "editor"  # type: ignore[misc]


def test_relation_tuple_equality():
    t1 = RelationTuple(object_type="doc", object_id="1", relation="reader", user="user:x")
    t2 = RelationTuple(object_type="doc", object_id="1", relation="reader", user="user:x")
    assert t1 == t2
