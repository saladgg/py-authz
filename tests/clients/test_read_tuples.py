import pytest

from py_authz.clients.openfga import OpenFGAClient


class RecordingReadClient:
    def __init__(self, response_data=None):
        self._response_data = response_data or {}
        self.calls: list[tuple[str, str, dict | None]] = []

    async def request(self, method, path, json=None):
        self.calls.append((method, path, json))

        class _Resp:
            def __init__(self, data):
                self._data = data

            def raise_for_status(self):
                pass

            def json(self):
                return self._data

        return _Resp(self._response_data)

    async def aclose(self):
        pass


@pytest.mark.asyncio
async def test_read_tuples_posts_only_given_filters():
    http = RecordingReadClient({"tuples": []})
    client = OpenFGAClient(api_url="http://fake", store_id="s1", model_id=None, http_client=http)

    await client.read_tuples(relation="viewer", object="document:1")

    method, path, payload = http.calls[0]
    assert method == "POST"
    assert path == "/stores/s1/read"
    assert payload == {"tuple_key": {"relation": "viewer", "object": "document:1"}}


@pytest.mark.asyncio
async def test_read_tuples_empty_filter_omits_tuple_key():
    http = RecordingReadClient({"tuples": []})
    client = OpenFGAClient(api_url="http://fake", store_id="s1", model_id=None, http_client=http)

    await client.read_tuples()

    _, _, payload = http.calls[0]
    assert payload == {}


@pytest.mark.asyncio
async def test_read_tuples_returns_normalized_shape():
    http = RecordingReadClient(
        {
            "tuples": [
                {
                    "key": {"user": "user:alice", "relation": "viewer", "object": "document:1"},
                    "timestamp": "2026-01-01T00:00:00Z",
                }
            ],
            "continuation_token": "abc",
        }
    )
    client = OpenFGAClient(api_url="http://fake", store_id="s1", model_id=None, http_client=http)

    result = await client.read_tuples(object="document:1")

    assert result == {
        "tuples": [
            {
                "user": "user:alice",
                "relation": "viewer",
                "object": "document:1",
                "timestamp": "2026-01-01T00:00:00Z",
            }
        ],
        "continuation_token": "abc",
    }


@pytest.mark.asyncio
async def test_read_tuples_empty_continuation_token_normalizes_to_none():
    http = RecordingReadClient({"tuples": [], "continuation_token": ""})
    client = OpenFGAClient(api_url="http://fake", store_id="s1", model_id=None, http_client=http)

    result = await client.read_tuples()

    assert result["continuation_token"] is None


@pytest.mark.asyncio
async def test_read_tuples_forwards_paging_params():
    http = RecordingReadClient({"tuples": []})
    client = OpenFGAClient(api_url="http://fake", store_id="s1", model_id=None, http_client=http)

    page_cursor = "tok"  # an opaque pagination cursor, not a credential
    await client.read_tuples(user="user:1", page_size=10, continuation_token=page_cursor)

    _, _, payload = http.calls[0]
    assert payload == {
        "tuple_key": {"user": "user:1"},
        "page_size": 10,
        "continuation_token": "tok",
    }
