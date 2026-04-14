import pytest
import httpx

from py_authz.clients.openfga import OpenFGAClient
from py_authz.core.exceptions import (
    ServiceTimeout,
    ServiceUnavailable,
    ExternalServiceError,
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