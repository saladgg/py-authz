import pytest

from py_authz.clients.openfga import OpenFGAClient


class RecordingClient:
    def __init__(self, response_data=None):
        self._response_data = response_data or {}
        self.calls: list[tuple[str, str, dict | None]] = []

    async def request(self, method, path, json=None):
        self.calls.append((method, path, json))

        class _R:
            def __init__(self, data):
                self._data = data
                self.status_code = 200

            def raise_for_status(self):
                pass

            def json(self):
                return self._data

        return _R(self._response_data)

    async def aclose(self):
        pass


@pytest.mark.asyncio
async def test_list_objects_posts_correct_payload_and_returns_objects():
    http = RecordingClient({"objects": ["document:1", "document:2"]})
    client = OpenFGAClient(
        api_url="http://fake",
        store_id="store-1",
        model_id="model-1",
        http_client=http,
    )

    objects = await client.list_objects(user="user:alice", relation="viewer", type="document")

    assert objects == ["document:1", "document:2"]
    assert http.calls == [
        (
            "POST",
            "/stores/store-1/list-objects",
            {
                "type": "document",
                "relation": "viewer",
                "user": "user:alice",
                "authorization_model_id": "model-1",
            },
        )
    ]


@pytest.mark.asyncio
async def test_list_objects_forwards_contextual_tuples_and_context():
    http = RecordingClient({"objects": []})
    client = OpenFGAClient(
        api_url="http://fake",
        store_id="store-1",
        model_id="model-1",
        http_client=http,
    )

    await client.list_objects(
        user="user:alice",
        relation="viewer",
        type="document",
        contextual_tuples=[
            {"user": "user:alice", "relation": "owner", "object": "document:secret"}
        ],
        context={"now": "2026-04-26T12:00:00Z"},
    )

    payload = http.calls[0][2]
    assert payload["contextual_tuples"] == {
        "tuple_keys": [{"user": "user:alice", "relation": "owner", "object": "document:secret"}]
    }
    assert payload["context"] == {"now": "2026-04-26T12:00:00Z"}


@pytest.mark.asyncio
async def test_list_objects_returns_empty_list_when_no_objects_key():
    http = RecordingClient({})
    client = OpenFGAClient(
        api_url="http://fake",
        store_id="s",
        model_id="m",
        http_client=http,
    )

    assert await client.list_objects(user="user:1", relation="viewer", type="doc") == []


@pytest.mark.asyncio
async def test_check_forwards_contextual_tuples_and_context():
    class _Capture:
        def __init__(self):
            self.payload = None

        async def post(self, path, json=None):
            self.payload = json

            class _R:
                def __init__(self):
                    self.status_code = 200

                def raise_for_status(self):
                    pass

                def json(self_inner):
                    return {"allowed": True}

            return _R()

    http = _Capture()
    client = OpenFGAClient(
        api_url="http://fake",
        store_id="s",
        model_id="m",
        http_client=http,
    )

    await client.check(
        "user:1",
        "viewer",
        "doc:1",
        contextual_tuples=[{"user": "user:1", "relation": "owner", "object": "doc:1"}],
        context={"ip": "10.0.0.1"},
    )

    assert http.payload["contextual_tuples"] == {
        "tuple_keys": [{"user": "user:1", "relation": "owner", "object": "doc:1"}]
    }
    assert http.payload["context"] == {"ip": "10.0.0.1"}


@pytest.mark.asyncio
async def test_check_omits_contextual_keys_when_not_provided():
    class _Capture:
        def __init__(self):
            self.payload = None

        async def post(self, path, json=None):
            self.payload = json

            class _R:
                status_code = 200

                def raise_for_status(self):
                    pass

                def json(self_inner):
                    return {"allowed": False}

            return _R()

    http = _Capture()
    client = OpenFGAClient(
        api_url="http://fake",
        store_id="s",
        model_id="m",
        http_client=http,
    )

    await client.check("user:1", "viewer", "doc:1")

    assert "contextual_tuples" not in http.payload
    assert "context" not in http.payload
