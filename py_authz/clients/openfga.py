import httpx

from py_authz.core.exceptions import (
    ExternalServiceError,
    ServiceTimeout,
    ServiceUnavailable,
)
from py_authz.utils.retry import retry_async

#: OpenFGA's own cap on combined tuple operations (writes + deletes
#: together) in a single Write request.
_MAX_TUPLES_PER_WRITE = 100


def _chunk_tuple_operations(
    writes: list[dict],
    deletes: list[dict],
    chunk_size: int,
):
    """
    Yield `(write_batch, delete_batch)` pairs, each with a combined size
    of at most `chunk_size`.

    When `writes`/`deletes` together already fit in one chunk (the common
    case — including the "both empty" case), yields exactly the original
    two lists once, unchanged, so callers observe the same single-request
    behavior as before this existed.
    """
    if len(writes) + len(deletes) <= chunk_size:
        yield (writes, deletes)
        return

    tagged = [("w", t) for t in writes] + [("d", t) for t in deletes]
    for i in range(0, len(tagged), chunk_size):
        batch = tagged[i : i + chunk_size]
        yield (
            [t for kind, t in batch if kind == "w"],
            [t for kind, t in batch if kind == "d"],
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
        store_id: str | None,
        model_id: str | None,
        *,
        timeout: float = 2.0,
        max_retries: int = 2,
        http_client: httpx.AsyncClient | None = None,
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

    async def check(
        self,
        user: str,
        relation: str,
        object: str,
        *,
        contextual_tuples: list[dict] | None = None,
        context: dict | None = None,
    ) -> bool:
        """
        Perform an authorization check via OpenFGA.

        Args:
            user (str):
                User identifier (e.g., "user:123")

            relation (str):
                Relation/action (e.g., "viewer")

            object (str):
                Object identifier (e.g., "document:456")

            contextual_tuples (Optional[list[dict]]):
                Per-request tuples that participate in evaluation but are
                not persisted. Each dict has keys: user, relation, object.

            context (Optional[dict]):
                Context values for OpenFGA conditions (ABAC). Forwarded
                to the model's condition expressions verbatim.

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

        payload: dict = {
            "tuple_key": {
                "user": user,
                "relation": relation,
                "object": object,
            },
            "authorization_model_id": self.model_id,
        }

        if contextual_tuples:
            payload["contextual_tuples"] = {"tuple_keys": contextual_tuples}

        if context:
            payload["context"] = context

        try:
            response = await retry_async(
                lambda: self._client.post(endpoint, json=payload),
                retryable=(httpx.TimeoutException, httpx.ConnectError),
                max_retries=self.max_retries,
            )

            # Raise for non-2xx responses
            response.raise_for_status()

            data = response.json()

            return data.get("allowed", False)

        except httpx.TimeoutException as exc:
            raise ServiceTimeout(
                "OpenFGA request timed out",
                service="openfga",
                cause=exc,
            ) from exc

        except httpx.ConnectError as exc:
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

    async def _request(self, method: str, path: str, json: dict | None = None) -> dict:
        try:
            response = await self._client.request(method, path, json=json)
            response.raise_for_status()
            return response.json()
        except httpx.TimeoutException as exc:
            raise ServiceTimeout(
                f"OpenFGA {method} {path} timed out",
                service="openfga",
                cause=exc,
            ) from exc
        except httpx.ConnectError as exc:
            raise ServiceUnavailable(
                f"Unable to connect to OpenFGA for {method} {path}",
                service="openfga",
                cause=exc,
            ) from exc
        except httpx.HTTPStatusError as exc:
            raise ExternalServiceError(
                f"OpenFGA API error: {exc.response.status_code}",
                service="openfga",
                cause=exc,
            ) from exc

    async def _get(self, path: str) -> dict:
        return await self._request("GET", path)

    async def _post(self, path: str, json: dict) -> dict:
        return await self._request("POST", path, json=json)

    async def get_latest_model(self) -> dict | None:
        """
        Fetch latest authorization model from OpenFGA.

        Returns:
            dict or None
        """
        res = await self._get(f"/stores/{self.store_id}/authorization-models")

        models = res.get("authorization_models", [])

        if not models:
            return None

        # Latest is first (OpenFGA returns descending)
        return models[0]

    async def create_store(self, name: str) -> str:
        """
        Create a new OpenFGA store.

        Returns:
            str: store_id
        """
        res = await self._post(
            "/stores",
            json={"name": name},
        )

        return res["id"]

    async def aclose(self) -> None:
        await self._client.aclose()

    def _tuple(self, user: str, relation: str, object: str) -> dict:
        return {
            "user": user,
            "relation": relation,
            "object": object,
        }

    async def list_objects(
        self,
        user: str,
        relation: str,
        type: str,
        *,
        contextual_tuples: list[dict] | None = None,
        context: dict | None = None,
    ) -> list[str]:
        """
        Return all objects of a given type the user has the relation on.

        This is the inverse of `check`: instead of asking "can user X do Y on
        object Z?", it asks "which objects of type T can user X do Y on?".

        Args:
            user: User identifier (e.g., "user:123").
            relation: Relation/action (e.g., "viewer").
            type: Resource type to enumerate (e.g., "document").
            contextual_tuples: Optional per-request tuples.
            context: Optional ABAC context for conditions.

        Returns:
            list[str]: Object strings in the form "<type>:<id>".
        """
        payload: dict = {
            "type": type,
            "relation": relation,
            "user": user,
            "authorization_model_id": self.model_id,
        }

        if contextual_tuples:
            payload["contextual_tuples"] = {"tuple_keys": contextual_tuples}

        if context:
            payload["context"] = context

        res = await self._post(
            f"/stores/{self.store_id}/list-objects",
            json=payload,
        )

        return list(res.get("objects", []))

    async def write_tuples(
        self,
        writes: list[dict],
        deletes: list[dict] | None = None,
    ) -> None:
        """
        Write and/or delete tuples in OpenFGA.

        Args:
            writes: list of tuple dicts
            deletes: optional list of tuple dicts

        OpenFGA caps a single Write request at `_MAX_TUPLES_PER_WRITE`
        combined tuple operations (writes + deletes together) — a bulk
        grant/revoke over that (seeding a new tenant, an org-wide role
        change) is chunked into multiple sequential Write requests instead
        of hitting an opaque 400 from OpenFGA. Each chunk is its own
        atomic Write call, but the operation as a whole is NOT atomic
        across chunks — if a later chunk fails, earlier chunks have
        already been applied. Callers needing all-or-nothing semantics
        over more than `_MAX_TUPLES_PER_WRITE` tuples must handle that
        themselves (e.g. retry/compensate); OpenFGA itself offers no
        larger-than-one-request transaction to fall back on either.
        """
        deletes = deletes or []

        for write_batch, delete_batch in _chunk_tuple_operations(
            writes, deletes, _MAX_TUPLES_PER_WRITE
        ):
            payload: dict = {}

            if write_batch:
                payload["writes"] = {"tuple_keys": write_batch}

            if delete_batch:
                payload["deletes"] = {"tuple_keys": delete_batch}

            await self._post(
                f"/stores/{self.store_id}/write",
                json=payload,
            )
