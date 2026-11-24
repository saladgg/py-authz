"""Tests for py_authz.control_plane.security (CP-3, CP-17)."""

import pytest

from py_authz.control_plane.security import (
    SECRET_PREFIX,
    generate_secret,
    hash_secret,
    parse_account_id,
    verify_secret,
)


def test_generate_secret_has_expected_prefix_and_embeds_account_id():
    secret = generate_secret("sa_abc123")

    assert secret.startswith(SECRET_PREFIX)
    assert parse_account_id(secret) == "sa_abc123"


def test_generate_secret_is_unique_per_call():
    a = generate_secret("sa_1")
    b = generate_secret("sa_1")

    assert a != b  # same account, different random suffix


def test_parse_account_id_returns_none_for_non_service_account_token():
    assert parse_account_id("not-a-service-account-token") is None
    assert parse_account_id("") is None


@pytest.mark.parametrize(
    "token",
    [
        SECRET_PREFIX,  # no "." separator at all
        f"{SECRET_PREFIX}sa_1.",  # empty secret part
        f"{SECRET_PREFIX}not-an-id.x",  # wrong id shape
        f"{SECRET_PREFIX}sa_{'a' * 500}.x",  # unbounded id (SEC3-9)
        f"{SECRET_PREFIX}sa_1*.x",
    ],
)
def test_parse_account_id_rejects_a_malformed_service_account_token(token):
    """SEC3-9: a token carrying the prefix but not the shape is rejected
    outright, before any store lookup or rate-limiter bookkeeping."""
    from py_authz.control_plane.security import MalformedServiceAccountToken

    with pytest.raises(MalformedServiceAccountToken):
        parse_account_id(token)


def test_hash_and_verify_round_trip():
    secret = generate_secret("sa_1")
    hashed = hash_secret(secret)

    assert verify_secret(secret, hashed) is True


def test_verify_rejects_wrong_secret():
    secret = generate_secret("sa_1")
    hashed = hash_secret(secret)

    assert verify_secret("wrong-secret", hashed) is False


def test_verify_rejects_malformed_hash_instead_of_raising():
    assert verify_secret("anything", "not-a-real-argon2-hash") is False


def test_hash_never_equals_plaintext():
    secret = generate_secret("sa_1")
    assert hash_secret(secret) != secret
