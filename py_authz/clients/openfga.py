from typing import Optional
import httpx
import asyncio

from py_authz.core.exceptions import (
    ExternalServiceError,
    ServiceTimeout,
    ServiceUnavailable,
)


class OpenFGAClient:
    """
    Async client for interacting with the OpenFGA API.

    This class abstracts away HTTP communication and provides a clean,
    minimal interface for authorization checks.

    Features:
        - Async HTTP requests (httpx)
        - Timeout handling
        - Basic retry mechanism
        - Error mapping to domain-specific exceptions

    Notes:
        - This client is intentionally minimal (only check for now).
        - Additional APIs (write, list objects, etc.) can be added later.
    """

    def __init__(
        self,
        api_url: str,
        store_id: str,
        model_id: str,
        *,
        timeout: float = 2.0,
        max_retries: int = 2,
        http_client: Optional[httpx.AsyncClient] = None,
    ):
        """
        Initialize the OpenFGA client.

        Args:
            api_url (str):
                Base URL of the OpenFGA API.
                Example: "http://localhost:8080"

            store_id (str):
                OpenFGA store identifier.

            model_id (str):
                Authorization model ID.

            timeout (float):
                Request timeout in seconds.

            max_retries (int):
                Number of retry attempts for transient failures.

            http_client (Optional[httpx.AsyncClient]):
                Optional injected HTTP client (useful for testing).
        """
        self.api_url = api_url.rstrip("/")
        self.store_id = store_id
        self.model_id = model_id
        self.timeout = timeout
        self.max_retries = max_retries

        self._client = http_client or httpx.AsyncClient(
            base_url=self.api_url,
            timeout=self.timeout,
        )

    async def check(self, user: str, relation: str, object: str) -> bool:
        """
        Perform an authorization check via OpenFGA.

        Args:
            user (str):
                User identifier (e.g., "user:123")

            relation (str):
                Relation/action (e.g., "viewer")

            object (str):
                Object identifier (e.g., "document:456")

        Returns:
            bool:
                True if allowed, False otherwise.

        Raises:
            ServiceTimeout:
                If the request times out.

            ServiceUnavailable:
                If the OpenFGA service is unreachable.

            ExternalServiceError:
                For other API-related failures.
        """
        endpoint = f"/stores/{self.store_id}/check"

        payload = {
            "tuple_key": {
                "user": user,
                "relation": relation,
                "object": object,
            },
            "authorization_model_id": self.model_id,
        }

        attempt = 0

        while True:
            try:
                response = await self._client.post(endpoint, json=payload)

                # Raise for non-2xx responses
                response.raise_for_status()

                data = response.json()

                return data.get("allowed", False)

            except httpx.TimeoutException as exc:
                if attempt >= self.max_retries:
                    raise ServiceTimeout(
                        "OpenFGA request timed out",
                        service="openfga",
                        cause=exc,
                    ) from exc

            except httpx.ConnectError as exc:
                if attempt >= self.max_retries:
                    raise ServiceUnavailable(
                        "Unable to connect to OpenFGA",
                        service="openfga",
                        cause=exc,
                    ) from exc

            except httpx.HTTPStatusError as exc:
                # Non-2xx responses (4xx, 5xx)
                raise ExternalServiceError(
                    f"OpenFGA API error: {exc.response.status_code}",
                    service="openfga",
                    cause=exc,
                ) from exc

            except Exception as exc:
                raise ExternalServiceError(
                    "Unexpected error during OpenFGA request",
                    service="openfga",
                    cause=exc,
                ) from exc

            # Retry logic (simple exponential backoff)
            attempt += 1
            await asyncio.sleep(0.1 * (2 ** attempt))