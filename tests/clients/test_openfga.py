import httpx
import pytest

from py_authz.clients.openfga import OpenFGAClient
from py_authz.core.exceptions import (
    ExternalServiceError,
    ServiceTimeout,
    ServiceUnavailable,
)

# -------------------------------------------------------------------
# Helpers
# -------------------------------------------------------------------


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


# -------------------------------------------------------------------
# Success Case
# -------------------------------------------------------------------


class SuccessClient:
    async def post(self, *args, **kwargs):
        return MockResponse({"allowed": True})


@pytest.mark.asyncio
async def test_check_success():
    client = OpenFGAClient(
        api_url="http://fake",
        store_id="store",
        model_id="model",
        http_client=SuccessClient(),
    )

    result = await client.check("user:1", "viewer", "doc:1")

    assert result is True


# -------------------------------------------------------------------
# Timeout Handling
# -------------------------------------------------------------------


class TimeoutClient:
    async def post(self, *args, **kwargs):
        raise httpx.TimeoutException("Timeout")


@pytest.mark.asyncio
async def test_check_timeout_raises():
    client = OpenFGAClient(
        api_url="http://fake",
        store_id="store",
        model_id="model",
        http_client=TimeoutClient(),
        max_retries=0,  # disable retry for deterministic test
    )

    with pytest.raises(ServiceTimeout):
        await client.check("user:1", "viewer", "doc:1")


# -------------------------------------------------------------------
# Connection Error
# -------------------------------------------------------------------


class ConnectionErrorClient:
    async def post(self, *args, **kwargs):
        raise httpx.ConnectError("Connection failed")


@pytest.mark.asyncio
async def test_check_connection_error():
    client = OpenFGAClient(
        api_url="http://fake",
        store_id="store",
        model_id="model",
        http_client=ConnectionErrorClient(),
        max_retries=0,
    )

    with pytest.raises(ServiceUnavailable):
        await client.check("user:1", "viewer", "doc:1")


# -------------------------------------------------------------------
# HTTP Errors (4xx / 5xx)
# -------------------------------------------------------------------


class ErrorResponseClient:
    async def post(self, *args, **kwargs):
        return MockResponse(status_code=500)


@pytest.mark.asyncio
async def test_check_http_error():
    client = OpenFGAClient(
        api_url="http://fake",
        store_id="store",
        model_id="model",
        http_client=ErrorResponseClient(),
    )

    with pytest.raises(ExternalServiceError):
        await client.check("user:1", "viewer", "doc:1")


# -------------------------------------------------------------------
# Retry Behavior
# -------------------------------------------------------------------


class FlakyClient:
    """
    Fails first time, succeeds second time.
    """

    def __init__(self):
        self.calls = 0

    async def post(self, *args, **kwargs):
        self.calls += 1

        if self.calls == 1:
            raise httpx.TimeoutException("Temporary failure")

        return MockResponse({"allowed": True})


@pytest.mark.asyncio
async def test_check_retries_and_succeeds():
    flaky = FlakyClient()

    client = OpenFGAClient(
        api_url="http://fake",
        store_id="store",
        model_id="model",
        http_client=flaky,
        max_retries=1,
    )

    result = await client.check("user:1", "viewer", "doc:1")

    assert result is True
    assert flaky.calls == 2  # retried once


# -------------------------------------------------------------------
# Store / Model helpers
# -------------------------------------------------------------------


class RecordingClient:
    """HTTP client that records requests and returns scripted responses."""

    def __init__(self, response_data=None, status_code=200):
        self._response_data = response_data or {}
        self._status_code = status_code
        self.calls: list[tuple[str, str, dict | None]] = []
        self.aclose_called = False

    async def request(self, method, path, json=None):
        self.calls.append((method, path, json))
        return MockResponse(self._response_data, status_code=self._status_code)

    async def aclose(self):
        self.aclose_called = True


@pytest.mark.asyncio
async def test_create_store_returns_id_and_posts_name():
    http = RecordingClient({"id": "store-abc"})
    client = OpenFGAClient(
        api_url="http://fake",
        store_id=None,
        model_id=None,
        http_client=http,
    )

    store_id = await client.create_store(name="tenant-1")

    assert store_id == "store-abc"
    assert http.calls == [("POST", "/stores", {"name": "tenant-1"})]


@pytest.mark.asyncio
async def test_get_latest_model_returns_first_model():
    http = RecordingClient(
        {
            "authorization_models": [
                {"authorization_model_id": "newest"},
                {"authorization_model_id": "older"},
            ]
        }
    )
    client = OpenFGAClient(
        api_url="http://fake",
        store_id="s1",
        model_id=None,
        http_client=http,
    )

    model = await client.get_latest_model()

    assert model == {"authorization_model_id": "newest"}
    assert http.calls == [("GET", "/stores/s1/authorization-models", None)]


@pytest.mark.asyncio
async def test_get_latest_model_returns_none_when_empty():
    http = RecordingClient({"authorization_models": []})
    client = OpenFGAClient(
        api_url="http://fake",
        store_id="s1",
        model_id=None,
        http_client=http,
    )

    assert await client.get_latest_model() is None


@pytest.mark.asyncio
async def test_request_maps_http_error_to_external_service_error():
    http = RecordingClient(status_code=500)
    client = OpenFGAClient(
        api_url="http://fake",
        store_id="s1",
        model_id=None,
        http_client=http,
    )

    with pytest.raises(ExternalServiceError):
        await client.get_latest_model()


class TimeoutRequestClient:
    async def request(self, *args, **kwargs):
        raise httpx.TimeoutException("boom")

    async def aclose(self):
        pass


class ConnectErrorRequestClient:
    async def request(self, *args, **kwargs):
        raise httpx.ConnectError("boom")

    async def aclose(self):
        pass


@pytest.mark.asyncio
async def test_request_maps_timeout_to_service_timeout():
    client = OpenFGAClient(
        api_url="http://fake",
        store_id="s1",
        model_id=None,
        http_client=TimeoutRequestClient(),
    )

    with pytest.raises(ServiceTimeout):
        await client.create_store(name="t")


@pytest.mark.asyncio
async def test_request_maps_connect_error_to_service_unavailable():
    client = OpenFGAClient(
        api_url="http://fake",
        store_id="s1",
        model_id=None,
        http_client=ConnectErrorRequestClient(),
    )

    with pytest.raises(ServiceUnavailable):
        await client.create_store(name="t")


@pytest.mark.asyncio
async def test_aclose_closes_underlying_http_client():
    http = RecordingClient({"id": "x"})
    client = OpenFGAClient(
        api_url="http://fake",
        store_id=None,
        model_id=None,
        http_client=http,
    )

    await client.aclose()

    assert http.aclose_called is True
