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
# for_tenant() factory (ARCH2-20)
# -------------------------------------------------------------------


def test_for_tenant_builds_equivalent_client():
    """
    `OpenFGAClient.for_tenant(...)` builds a client indistinguishable
    from the equivalent direct `OpenFGAClient(...)` call — same
    attributes, both directions defaulted the same way — so the three
    tenant-lifecycle call sites (`TenantManager`, `MultiTenantAuthz`,
    `MigrationManager`) that now route through it get an identical
    client to what they built by hand before.
    """
    via_factory = OpenFGAClient.for_tenant(
        api_url="http://fake/",
        store_id="store-1",
        model_id="model-1",
    )
    via_ctor = OpenFGAClient(
        api_url="http://fake/",
        store_id="store-1",
        model_id="model-1",
    )

    assert via_factory.api_url == via_ctor.api_url == "http://fake"
    assert via_factory.store_id == via_ctor.store_id == "store-1"
    assert via_factory.model_id == via_ctor.model_id == "model-1"
    assert via_factory.timeout == via_ctor.timeout
    assert via_factory.max_retries == via_ctor.max_retries


def test_for_tenant_defaults_store_and_model_id_to_none():
    """
    `TenantManager.provision()` calls `for_tenant()` with only `api_url`
    — before a store exists, `store_id`/`model_id` aren't known yet.
    """
    client = OpenFGAClient.for_tenant(api_url="http://fake")

    assert client.store_id is None
    assert client.model_id is None


def test_for_tenant_accepts_injected_http_client():
    http_client = SuccessClient()

    client = OpenFGAClient.for_tenant(
        api_url="http://fake",
        store_id="store-1",
        http_client=http_client,
    )

    assert client._client is http_client


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
        max_retries=0,  # disable retry for deterministic test
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
        max_retries=0,
    )

    with pytest.raises(ServiceUnavailable):
        await client.create_store(name="t")


# ----------------------------------------------------------------------
# Regression coverage for REL2-3: `_request()` (behind `create_store`/
# `get_latest_model`/`list_objects`/`write_tuples`) previously had no
# retry at all, unlike `check()`.
# ----------------------------------------------------------------------


class FlakyRequestClient:
    """Fails once, then succeeds — mirrors `FlakyClient` for `check()`."""

    def __init__(self):
        self.calls = 0

    async def request(self, *args, **kwargs):
        self.calls += 1
        if self.calls == 1:
            raise httpx.TimeoutException("Temporary failure")
        return MockResponse({"id": "store-abc"})


@pytest.mark.asyncio
async def test_request_retries_and_succeeds():
    flaky = FlakyRequestClient()
    client = OpenFGAClient(
        api_url="http://fake",
        store_id=None,
        model_id=None,
        http_client=flaky,
        max_retries=1,
    )

    store_id = await client.create_store(name="t")

    assert store_id == "store-abc"
    assert flaky.calls == 2  # retried once


class UnexpectedErrorRequestClient:
    async def request(self, *args, **kwargs):
        raise ValueError("malformed response")

    async def aclose(self):
        pass


@pytest.mark.asyncio
async def test_request_maps_unexpected_exception_to_external_service_error():
    """The catch-all fallback (matching `check()`'s own) — a non-httpx
    exception must still surface as an `ExternalServiceError`, not raw."""
    client = OpenFGAClient(
        api_url="http://fake",
        store_id="s1",
        model_id=None,
        http_client=UnexpectedErrorRequestClient(),
    )

    with pytest.raises(ExternalServiceError):
        await client.create_store(name="t")


# ----------------------------------------------------------------------
# Regression coverage for ARCH2-8: `delete_store()` is what lets
# `TenantManager.provision()` clean up an orphaned store on partial
# failure. A DELETE response typically has no body (204 No Content) —
# `_request()` must not choke trying to `.json()`-decode an empty one.
# ----------------------------------------------------------------------


class NoContentResponse:
    status_code = 204

    def raise_for_status(self):
        pass

    def json(self):
        raise ValueError("no JSON object could be decoded")


class DeleteRecordingClient:
    def __init__(self):
        self.calls: list[tuple[str, str]] = []

    async def request(self, method, path, json=None):
        self.calls.append((method, path))
        return NoContentResponse()


@pytest.mark.asyncio
async def test_delete_store_sends_delete_and_tolerates_empty_body():
    http = DeleteRecordingClient()
    client = OpenFGAClient(
        api_url="http://fake",
        store_id=None,
        model_id=None,
        http_client=http,
    )

    await client.delete_store("store-abc")  # must not raise

    assert http.calls == [("DELETE", "/stores/store-abc")]


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
