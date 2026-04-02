"""Tests for the synchronous and asynchronous OpenFGA SDK clients."""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from django_authz.authorization.openfga_sdk import AsyncOpenFGASDKClient, OpenFGASDKClient


def _async_ctx(mock_inner):
    """Return an object usable as an async context manager yielding mock_inner."""
    cm = MagicMock()
    cm.__aenter__ = AsyncMock(return_value=mock_inner)
    cm.__aexit__ = AsyncMock(return_value=False)
    return cm


# ---------------------------------------------------------------------------
# AsyncOpenFGASDKClient
# ---------------------------------------------------------------------------


async def test_async_client_check_returns_true():
    mock_inner = AsyncMock()
    mock_inner.check.return_value = MagicMock(allowed=True)

    with patch(
        "django_authz.authorization.openfga_sdk._OpenFgaClient",
        return_value=_async_ctx(mock_inner),
    ):
        client = AsyncOpenFGASDKClient(api_url="http://fga", store_id="store1")
        result = await client.check("user:alice", "reader", "doc:1")

    assert result is True


async def test_async_client_check_returns_false():
    mock_inner = AsyncMock()
    mock_inner.check.return_value = MagicMock(allowed=False)

    with patch(
        "django_authz.authorization.openfga_sdk._OpenFgaClient",
        return_value=_async_ctx(mock_inner),
    ):
        client = AsyncOpenFGASDKClient(api_url="http://fga", store_id="store1")
        result = await client.check("user:alice", "editor", "doc:1")

    assert result is False


async def test_async_client_write_sends_tuple_keys():
    mock_inner = AsyncMock()

    with patch(
        "django_authz.authorization.openfga_sdk._OpenFgaClient",
        return_value=_async_ctx(mock_inner),
    ):
        client = AsyncOpenFGASDKClient(api_url="http://fga", store_id="store1")
        await client.write([{"user": "user:alice", "relation": "reader", "object": "doc:1"}])

    mock_inner.write.assert_called_once()


async def test_async_client_list_relations_returns_list():
    mock_inner = AsyncMock()
    mock_inner.list_relations.return_value = MagicMock(relations=["reader", "editor"])

    with patch(
        "django_authz.authorization.openfga_sdk._OpenFgaClient",
        return_value=_async_ctx(mock_inner),
    ):
        client = AsyncOpenFGASDKClient(api_url="http://fga", store_id="store1")
        result = await client.list_relations("user:alice", "doc:1")

    assert result == ["reader", "editor"]


async def test_async_client_list_relations_returns_empty_list_when_none():
    mock_inner = AsyncMock()
    mock_inner.list_relations.return_value = MagicMock(relations=None)

    with patch(
        "django_authz.authorization.openfga_sdk._OpenFgaClient",
        return_value=_async_ctx(mock_inner),
    ):
        client = AsyncOpenFGASDKClient(api_url="http://fga", store_id="store1")
        result = await client.list_relations("user:alice", "doc:1")

    assert result == []


# ---------------------------------------------------------------------------
# OpenFGASDKClient (sync wrapper)
# ---------------------------------------------------------------------------


def test_sync_client_check_returns_true():
    mock_inner = AsyncMock()
    mock_inner.check.return_value = MagicMock(allowed=True)

    with patch(
        "django_authz.authorization.openfga_sdk._OpenFgaClient",
        return_value=_async_ctx(mock_inner),
    ):
        client = OpenFGASDKClient(api_url="http://fga", store_id="store1")
        result = client.check("user:alice", "reader", "doc:1")

    assert result is True


def test_sync_client_check_returns_false():
    mock_inner = AsyncMock()
    mock_inner.check.return_value = MagicMock(allowed=False)

    with patch(
        "django_authz.authorization.openfga_sdk._OpenFgaClient",
        return_value=_async_ctx(mock_inner),
    ):
        client = OpenFGASDKClient(api_url="http://fga", store_id="store1")
        result = client.check("user:alice", "editor", "doc:1")

    assert result is False


def test_sync_client_write():
    mock_inner = AsyncMock()

    with patch(
        "django_authz.authorization.openfga_sdk._OpenFgaClient",
        return_value=_async_ctx(mock_inner),
    ):
        client = OpenFGASDKClient(api_url="http://fga", store_id="store1")
        client.write([{"user": "user:alice", "relation": "reader", "object": "doc:1"}])

    mock_inner.write.assert_called_once()


def test_sync_client_list_relations():
    mock_inner = AsyncMock()
    mock_inner.list_relations.return_value = MagicMock(relations=["viewer"])

    with patch(
        "django_authz.authorization.openfga_sdk._OpenFgaClient",
        return_value=_async_ctx(mock_inner),
    ):
        client = OpenFGASDKClient(api_url="http://fga", store_id="store1")
        result = client.list_relations("user:alice", "doc:1")

    assert result == ["viewer"]
