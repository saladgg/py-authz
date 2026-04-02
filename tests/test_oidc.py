import pytest
from django.contrib.auth import get_user_model

from django_authz.authentication.oidc import OIDCAuthenticationBackend

User = get_user_model()


# ---------------------------------------------------------------------------
# create_user
# ---------------------------------------------------------------------------


@pytest.mark.django_db
def test_create_user_uses_preferred_username():
    backend = OIDCAuthenticationBackend()
    claims = {"preferred_username": "alice", "email": "alice@example.com", "sub": "sub-1"}
    user = backend.create_user(claims)
    assert user.username == "alice"
    assert user.email == "alice@example.com"


@pytest.mark.django_db
def test_create_user_falls_back_to_email_when_no_preferred_username():
    backend = OIDCAuthenticationBackend()
    claims = {"email": "bob@example.com", "sub": "sub-2"}
    user = backend.create_user(claims)
    assert user.username == "bob@example.com"
    assert user.email == "bob@example.com"


@pytest.mark.django_db
def test_create_user_falls_back_to_sub_when_no_username_or_email():
    backend = OIDCAuthenticationBackend()
    claims = {"sub": "sub-xyz"}
    user = backend.create_user(claims)
    assert user.username == "sub-xyz"
    assert user.email == ""


# ---------------------------------------------------------------------------
# update_user
# ---------------------------------------------------------------------------


@pytest.mark.django_db
def test_update_user_syncs_email_when_changed():
    user = User.objects.create_user(username="charlie", email="old@example.com")
    backend = OIDCAuthenticationBackend()
    updated = backend.update_user(user, {"email": "new@example.com"})
    assert updated.email == "new@example.com"
    user.refresh_from_db()
    assert user.email == "new@example.com"


@pytest.mark.django_db
def test_update_user_does_not_save_when_email_unchanged():
    user = User.objects.create_user(username="diana", email="same@example.com")
    backend = OIDCAuthenticationBackend()
    updated = backend.update_user(user, {"email": "same@example.com"})
    assert updated.email == "same@example.com"


@pytest.mark.django_db
def test_update_user_does_nothing_when_no_email_in_claims():
    user = User.objects.create_user(username="ed", email="ed@example.com")
    backend = OIDCAuthenticationBackend()
    updated = backend.update_user(user, {})
    assert updated.email == "ed@example.com"


# ---------------------------------------------------------------------------
# filter_users_by_claims
# ---------------------------------------------------------------------------


@pytest.mark.django_db
def test_filter_users_by_claims_finds_user_case_insensitively():
    User.objects.create_user(username="fiona", email="Fiona@Example.com")
    backend = OIDCAuthenticationBackend()
    result = backend.filter_users_by_claims({"email": "fiona@example.com"})
    assert result.count() == 1


@pytest.mark.django_db
def test_filter_users_by_claims_returns_empty_queryset_without_email():
    backend = OIDCAuthenticationBackend()
    result = backend.filter_users_by_claims({})
    assert result.count() == 0


@pytest.mark.django_db
def test_filter_users_by_claims_returns_empty_queryset_when_no_match():
    backend = OIDCAuthenticationBackend()
    result = backend.filter_users_by_claims({"email": "nobody@example.com"})
    assert result.count() == 0
