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
        max_retries=0,  # disable retry for deterministic test (see REL2-3)
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
        max_retries=0,
    )

    with pytest.raises(ServiceUnavailable):
        await client.write_tuples(writes=[_tuple()])


@pytest.mark.asyncio
async def test_write_tuples_chunks_over_100_combined_operations():
    """
    Regression test for REL-8: OpenFGA caps a single Write request at 100
    combined tuple operations (writes + deletes together). Previously, a
    caller granting permissions in bulk over that limit got an opaque
    `ExternalServiceError` from OpenFGA's 400 response with no chunking.
    """
    http = RecordingWriteClient()
    client = OpenFGAClient(
        api_url="http://fake",
        store_id="s1",
        model_id=None,
        http_client=http,
    )

    writes = [_tuple(user=f"user:{i}") for i in range(70)]
    deletes = [_tuple(user=f"user:d{i}") for i in range(50)]

    await client.write_tuples(writes=writes, deletes=deletes)

    # 120 combined operations, chunk size 100 -> two requests.
    assert len(http.calls) == 2
    total_writes = sum(
        len(json.get("writes", {}).get("tuple_keys", [])) for _, _, json in http.calls
    )
    total_deletes = sum(
        len(json.get("deletes", {}).get("tuple_keys", [])) for _, _, json in http.calls
    )
    assert total_writes == 70
    assert total_deletes == 50
    # Every chunk stays within the combined 100-item cap.
    for _, _, json in http.calls:
        combined = len(json.get("writes", {}).get("tuple_keys", [])) + len(
            json.get("deletes", {}).get("tuple_keys", [])
        )
        assert combined <= 100


@pytest.mark.asyncio
async def test_write_tuples_exactly_100_combined_operations_is_one_request():
    http = RecordingWriteClient()
    client = OpenFGAClient(
        api_url="http://fake",
        store_id="s1",
        model_id=None,
        http_client=http,
    )

    writes = [_tuple(user=f"user:{i}") for i in range(100)]

    await client.write_tuples(writes=writes)

    assert len(http.calls) == 1
    assert len(http.calls[0][2]["writes"]["tuple_keys"]) == 100


@pytest.mark.asyncio
async def test_write_tuples_101_combined_operations_is_two_requests():
    http = RecordingWriteClient()
    client = OpenFGAClient(
        api_url="http://fake",
        store_id="s1",
        model_id=None,
        http_client=http,
    )

    writes = [_tuple(user=f"user:{i}") for i in range(101)]

    await client.write_tuples(writes=writes)

    assert len(http.calls) == 2
    sizes = [len(call[2].get("writes", {}).get("tuple_keys", [])) for call in http.calls]
    assert sum(sizes) == 101
    assert all(size <= 100 for size in sizes)


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
