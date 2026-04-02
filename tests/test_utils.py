"""Tests for django_authz.utils: get_bearer_token and merge_dicts."""

import pytest
from django.http import HttpRequest

from django_authz.utils import get_bearer_token, merge_dicts


# ---------------------------------------------------------------------------
# get_bearer_token
# ---------------------------------------------------------------------------


def test_get_bearer_token_returns_token_from_valid_header(rf):
    request = rf.get("/", HTTP_AUTHORIZATION="Bearer mytoken123")
    assert get_bearer_token(request) == "mytoken123"


def test_get_bearer_token_returns_none_when_no_header(rf):
    request = rf.get("/")
    assert get_bearer_token(request) is None


def test_get_bearer_token_returns_none_for_non_bearer_scheme(rf):
    request = rf.get("/", HTTP_AUTHORIZATION="Basic dXNlcjpwYXNz")
    assert get_bearer_token(request) is None


def test_get_bearer_token_returns_none_for_empty_authorization(rf):
    request = rf.get("/", HTTP_AUTHORIZATION="")
    assert get_bearer_token(request) is None


def test_get_bearer_token_is_case_insensitive_on_scheme(rf):
    """'bearer' (lowercase) should also be accepted."""
    request = rf.get("/", HTTP_AUTHORIZATION="bearer lowercasetoken")
    assert get_bearer_token(request) == "lowercasetoken"


def test_get_bearer_token_returns_none_when_token_part_missing(rf):
    """'Bearer ' with nothing after it should return None."""
    request = HttpRequest()
    request.META["HTTP_AUTHORIZATION"] = "Bearer "
    assert get_bearer_token(request) is None


# ---------------------------------------------------------------------------
# merge_dicts
# ---------------------------------------------------------------------------


def test_merge_dicts_combines_non_overlapping_keys():
    result = merge_dicts({"a": 1}, {"b": 2})
    assert result == {"a": 1, "b": 2}


def test_merge_dicts_later_values_win_on_duplicate_keys():
    result = merge_dicts({"a": 1, "b": 2}, {"b": 99})
    assert result["b"] == 99


def test_merge_dicts_accepts_more_than_two_maps():
    result = merge_dicts({"a": 1}, {"b": 2}, {"c": 3})
    assert result == {"a": 1, "b": 2, "c": 3}


def test_merge_dicts_returns_empty_dict_for_no_args():
    assert merge_dicts() == {}


def test_merge_dicts_does_not_mutate_inputs():
    first = {"a": 1}
    second = {"b": 2}
    merge_dicts(first, second)
    assert "b" not in first
