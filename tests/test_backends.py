"""Tests for the shared get_or_create_user provisioning helper."""

import pytest

from django_authz.authentication.backends import get_or_create_user


@pytest.mark.django_db
def test_get_or_create_user_uses_explicit_username(faker):
    username = faker.unique.user_name()
    user = get_or_create_user(subject="sub-1", email="a@example.com", username=username)
    assert user.username == username


@pytest.mark.django_db
def test_get_or_create_user_falls_back_to_email_when_no_username(faker):
    email = faker.unique.email()
    user = get_or_create_user(subject="sub-2", email=email)
    assert user.username == email


@pytest.mark.django_db
def test_get_or_create_user_falls_back_to_subject_when_no_username_or_email():
    user = get_or_create_user(subject="sub-xyz")
    assert user.username == "sub-xyz"


@pytest.mark.django_db
def test_get_or_create_user_stores_email(faker):
    email = faker.unique.email()
    user = get_or_create_user(subject="sub-3", email=email)
    assert user.email == email


@pytest.mark.django_db
def test_get_or_create_user_returns_existing_user_on_second_call(faker):
    username = faker.unique.user_name()
    user1 = get_or_create_user(subject="sub-4", username=username)
    user2 = get_or_create_user(subject="sub-4", username=username)
    assert user1.pk == user2.pk


@pytest.mark.django_db
def test_get_or_create_user_sets_empty_email_when_none():
    user = get_or_create_user(subject="sub-5")
    assert user.email == ""
