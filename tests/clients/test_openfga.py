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
    async def request(self, method, path, json=None, **_kwargs):
        return await self.post(path, json=json)

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
    async def request(self, method, path, json=None, **_kwargs):
        return await self.post(path, json=json)

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
    async def request(self, method, path, json=None, **_kwargs):
        return await self.post(path, json=json)

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
    async def request(self, method, path, json=None, **_kwargs):
        return await self.post(path, json=json)

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

    async def request(self, method, path, json=None, **_kwargs):

        return await self.post(path, json=json)

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

    async def request(self, method, path, json=None, **_kwargs):
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
    assert http.calls == [("GET", "/stores/s1/authorization-models?page_size=1", None)]


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
    """Fails once with `error`, then succeeds."""

    def __init__(self, error=None, data=None):
        self.calls = 0
        self.error = error or httpx.ReadTimeout("Temporary failure")
        self.data = data or {"id": "store-abc"}

    async def request(self, *args, **kwargs):
        self.calls += 1
        if self.calls == 1:
            raise self.error
        return MockResponse(self.data)


@pytest.mark.asyncio
async def test_request_retries_a_read_call_after_a_read_timeout():
    flaky = FlakyRequestClient(data={"authorization_models": [{"id": "m1"}]})
    client = OpenFGAClient(
        api_url="http://fake", store_id="s", model_id=None, http_client=flaky, max_retries=1
    )

    model = await client.get_latest_model()

    assert model == {"id": "m1"}
    assert flaky.calls == 2  # retried once


@pytest.mark.asyncio
async def test_create_store_is_not_retried_after_a_read_timeout():
    """REL3-6: the server may already have created the store — a retry
    would make a second, orphaned one."""
    flaky = FlakyRequestClient()
    client = OpenFGAClient(
        api_url="http://fake", store_id=None, model_id=None, http_client=flaky, max_retries=2
    )

    with pytest.raises(ServiceTimeout):
        await client.create_store(name="t")
    assert flaky.calls == 1


@pytest.mark.asyncio
async def test_create_store_is_retried_when_the_request_never_reached_the_server():
    flaky = FlakyRequestClient(error=httpx.ConnectError("refused"))
    client = OpenFGAClient(
        api_url="http://fake", store_id=None, model_id=None, http_client=flaky, max_retries=1
    )

    assert await client.create_store(name="t") == "store-abc"
    assert flaky.calls == 2


@pytest.mark.asyncio
async def test_non_idempotent_writes_are_not_retried_after_a_read_timeout():
    flaky = FlakyRequestClient(data={})
    client = OpenFGAClient(
        api_url="http://fake",
        store_id="s",
        model_id=None,
        http_client=flaky,
        max_retries=2,
        idempotent_writes=False,
    )

    with pytest.raises(ServiceTimeout):
        await client.write_tuples([{"user": "user:1", "relation": "viewer", "object": "doc:1"}])
    assert flaky.calls == 1


@pytest.mark.asyncio
async def test_idempotent_writes_are_retried_after_a_read_timeout():
    flaky = FlakyRequestClient(data={})
    client = OpenFGAClient(
        api_url="http://fake", store_id="s", model_id=None, http_client=flaky, max_retries=1
    )

    await client.write_tuples([{"user": "user:1", "relation": "viewer", "object": "doc:1"}])
    assert flaky.calls == 2


class StatusSequenceClient:
    def __init__(self, statuses, data=None):
        self.statuses = list(statuses)
        self.data = data or {}
        self.calls = 0

    async def request(self, *args, **kwargs):
        self.calls += 1
        status = self.statuses.pop(0) if self.statuses else 200
        return MockResponse(self.data, status_code=status)


@pytest.mark.asyncio
async def test_transient_statuses_are_retried_for_idempotent_calls():
    """REL3-17: 429/503 used to fail immediately."""
    http = StatusSequenceClient([429, 503], data={"allowed": True})
    client = OpenFGAClient(
        api_url="http://fake", store_id="s", model_id=None, http_client=http, max_retries=2
    )

    assert await client.check("user:1", "viewer", "doc:1") is True
    assert http.calls == 3


@pytest.mark.asyncio
async def test_a_4xx_is_an_upstream_rejection_not_an_outage():
    """ARCH3-7: OpenFGA saying "your request is invalid" used to be an
    ExternalServiceError (a 503), retried pointlessly and failed open."""
    from py_authz.core.exceptions import InvalidAuthzRequest, UpstreamRequestRejected

    http = StatusSequenceClient([400], data={"code": "validation_error", "message": "bad type"})
    client = OpenFGAClient(
        api_url="http://fake", store_id="s", model_id=None, http_client=http, max_retries=2
    )

    with pytest.raises(UpstreamRequestRejected) as info:
        await client.check("user:1", "viewer", "doc:1")

    assert isinstance(info.value, InvalidAuthzRequest)
    assert not isinstance(info.value, ExternalServiceError)
    assert info.value.status_code == 400
    assert info.value.detail == "bad type"
    assert http.calls == 1  # never retried


@pytest.mark.asyncio
async def test_deleting_an_already_deleted_store_succeeds():
    client = OpenFGAClient(
        api_url="http://fake",
        store_id="s",
        model_id=None,
        http_client=StatusSequenceClient([404]),
    )

    await client.delete_store("gone")  # no exception


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

    async def request(self, method, path, json=None, **_kwargs):
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


# ----------------------------------------------------------------------
# Remaining `_request()` paths: retries exhausted on a transient status,
# non-404 delete failures, `ping()`, model upload, and error-body parsing.
# ----------------------------------------------------------------------


@pytest.mark.asyncio
async def test_transient_status_after_retries_are_exhausted_is_an_external_service_error():
    from py_authz.core.exceptions import UpstreamRequestRejected

    http = StatusSequenceClient([503, 503])
    client = OpenFGAClient(
        api_url="http://fake", store_id="s", model_id=None, http_client=http, max_retries=0
    )

    with pytest.raises(ExternalServiceError) as info:
        await client.read_tuples()

    assert not isinstance(info.value, UpstreamRequestRejected)
    assert http.calls == 1  # max_retries=0: the 503 is classified, not retried


@pytest.mark.asyncio
async def test_delete_store_still_raises_rejections_other_than_404():
    from py_authz.core.exceptions import UpstreamRequestRejected

    client = OpenFGAClient(
        api_url="http://fake",
        store_id="s",
        model_id=None,
        http_client=StatusSequenceClient([400], data={"message": "invalid store id"}),
    )

    with pytest.raises(UpstreamRequestRejected) as info:
        await client.delete_store("bad id")

    assert info.value.status_code == 400
    assert info.value.detail == "invalid store id"


@pytest.mark.asyncio
async def test_ping_hits_healthz_and_raises_when_unhealthy():
    http = RecordingClient({"status": "SERVING"})
    client = OpenFGAClient(api_url="http://fake", store_id=None, model_id=None, http_client=http)

    await client.ping()

    assert http.calls == [("GET", "/healthz", None)]

    down = OpenFGAClient(
        api_url="http://fake",
        store_id=None,
        model_id=None,
        http_client=StatusSequenceClient([500]),
        max_retries=0,
    )
    with pytest.raises(ExternalServiceError):
        await down.ping()


@pytest.mark.asyncio
async def test_write_authorization_model_posts_the_model_to_the_store():
    http = RecordingClient({"authorization_model_id": "m-1"})
    client = OpenFGAClient(api_url="http://fake", store_id="s1", model_id=None, http_client=http)
    model = {"schema_version": "1.1", "type_definitions": [{"type": "user"}]}

    result = await client.write_authorization_model(model)

    assert result == {"authorization_model_id": "m-1"}
    assert http.calls == [("POST", "/stores/s1/authorization-models", model)]


class _NonJsonErrorResponse(MockResponse):
    def json(self):
        raise ValueError("not JSON")


class _SingleResponseClient:
    def __init__(self, response):
        self.response = response

    async def request(self, *args, **kwargs):
        return self.response


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "response",
    [
        _NonJsonErrorResponse(status_code=400),  # e.g. a proxy's HTML error page
        MockResponse(["not", "a", "dict"], status_code=400),
        MockResponse({"code": "validation_error"}, status_code=400),  # no message
    ],
    ids=["non-json-body", "non-dict-body", "no-message"],
)
async def test_rejection_without_a_usable_error_message_has_no_detail(response):
    from py_authz.core.exceptions import UpstreamRequestRejected

    client = OpenFGAClient(
        api_url="http://fake",
        store_id="s",
        model_id=None,
        http_client=_SingleResponseClient(response),
    )

    with pytest.raises(UpstreamRequestRejected) as info:
        await client.check("user:1", "viewer", "doc:1")

    assert info.value.status_code == 400
    assert info.value.detail is None
    assert str(info.value).endswith(": 400")
