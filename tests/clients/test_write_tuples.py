import httpx
import pytest

from py_authz.clients.openfga import OpenFGAClient
from py_authz.core.exceptions import (
    ExternalServiceError,
    ServiceTimeout,
    ServiceUnavailable,
)


class MockResponse:
    def __init__(self, data=None, status_code=200):
        self._data = data or {}
        self.status_code = status_code

    def raise_for_status(self):
        if self.status_code >= 400:
            raise httpx.HTTPStatusError(
                "HTTP error",
                request=None,
                response=self,
            )

    def json(self):
        return self._data


class RecordingWriteClient:
    """Records `request` calls and returns a scripted response."""

    def __init__(self, response_data=None, status_code=200):
        self._response_data = response_data or {}
        self._status_code = status_code
        self.calls: list[tuple[str, str, dict | None]] = []

    async def request(self, method, path, json=None):
        self.calls.append((method, path, json))
        return MockResponse(self._response_data, status_code=self._status_code)

    async def aclose(self):
        pass


def _tuple(user="user:1", relation="viewer", obj="document:1"):
    return {"user": user, "relation": relation, "object": obj}


@pytest.mark.asyncio
async def test_write_tuples_posts_writes_only():
    http = RecordingWriteClient()
    client = OpenFGAClient(
        api_url="http://fake",
        store_id="s1",
        model_id=None,
        http_client=http,
    )

    await client.write_tuples(writes=[_tuple()])

    assert http.calls == [
        (
            "POST",
            "/stores/s1/write",
            {"writes": {"tuple_keys": [_tuple()]}},
        )
    ]


@pytest.mark.asyncio
async def test_write_tuples_posts_deletes_only():
    http = RecordingWriteClient()
    client = OpenFGAClient(
        api_url="http://fake",
        store_id="s1",
        model_id=None,
        http_client=http,
    )

    await client.write_tuples(writes=[], deletes=[_tuple()])

    assert http.calls == [
        (
            "POST",
            "/stores/s1/write",
            {"deletes": {"tuple_keys": [_tuple()]}},
        )
    ]


@pytest.mark.asyncio
async def test_write_tuples_posts_writes_and_deletes():
    http = RecordingWriteClient()
    client = OpenFGAClient(
        api_url="http://fake",
        store_id="s1",
        model_id=None,
        http_client=http,
    )

    w = _tuple(user="user:a", relation="viewer", obj="document:1")
    d = _tuple(user="user:b", relation="editor", obj="document:2")

    await client.write_tuples(writes=[w], deletes=[d])

    method, path, body = http.calls[0]
    assert method == "POST"
    assert path == "/stores/s1/write"
    assert body == {
        "writes": {"tuple_keys": [w]},
        "deletes": {"tuple_keys": [d]},
    }


@pytest.mark.asyncio
async def test_write_tuples_empty_writes_and_no_deletes_sends_empty_payload():
    """
    Calling with writes=[] and deletes=None should still issue a POST
    but with an empty payload (neither writes nor deletes key).
    """
    http = RecordingWriteClient()
    client = OpenFGAClient(
        api_url="http://fake",
        store_id="s1",
        model_id=None,
        http_client=http,
    )

    await client.write_tuples(writes=[])

    assert http.calls == [("POST", "/stores/s1/write", {})]


@pytest.mark.asyncio
async def test_write_tuples_maps_http_error():
    http = RecordingWriteClient(status_code=500)
    client = OpenFGAClient(
        api_url="http://fake",
        store_id="s1",
        model_id=None,
        http_client=http,
    )

    with pytest.raises(ExternalServiceError):
        await client.write_tuples(writes=[_tuple()])


class TimeoutWriteClient:
    async def request(self, *args, **kwargs):
        raise httpx.TimeoutException("boom")

    async def aclose(self):
        pass


class ConnectErrorWriteClient:
    async def request(self, *args, **kwargs):
        raise httpx.ConnectError("boom")

    async def aclose(self):
        pass


@pytest.mark.asyncio
async def test_write_tuples_maps_timeout():
    client = OpenFGAClient(
        api_url="http://fake",
        store_id="s1",
        model_id=None,
        http_client=TimeoutWriteClient(),
    )

    with pytest.raises(ServiceTimeout):
        await client.write_tuples(writes=[_tuple()])


@pytest.mark.asyncio
async def test_write_tuples_maps_connect_error():
    client = OpenFGAClient(
        api_url="http://fake",
        store_id="s1",
        model_id=None,
        http_client=ConnectErrorWriteClient(),
    )

    with pytest.raises(ServiceUnavailable):
        await client.write_tuples(writes=[_tuple()])


def test_tuple_helper_shape():
    client = OpenFGAClient(
        api_url="http://fake",
        store_id="s1",
        model_id=None,
        http_client=RecordingWriteClient(),
    )

    assert client._tuple("user:1", "viewer", "doc:1") == {
        "user": "user:1",
        "relation": "viewer",
        "object": "doc:1",
    }
