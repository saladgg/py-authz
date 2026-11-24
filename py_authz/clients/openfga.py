import httpx

from py_authz.core.exceptions import (
    ExternalServiceError,
    ServiceTimeout,
    ServiceUnavailable,
    UpstreamRequestRejected,
)
from py_authz.utils.retry import retry_async

#: Failures where the request provably never reached OpenFGA — safe to
#: retry for *any* call, including non-idempotent ones (REL3-6).
_NEVER_SENT = (httpx.ConnectError, httpx.ConnectTimeout, httpx.PoolTimeout)

#: Additionally retried for idempotent calls: a read timeout (the server
#: may or may not have processed the request — harmless to repeat when
#: repeating can't change anything).
_IDEMPOTENT_RETRYABLE = (*_NEVER_SENT, httpx.TimeoutException)

#: Transient HTTP statuses retried for idempotent calls (REL3-17).
_RETRYABLE_STATUSES = frozenset({429, 502, 503, 504})

#: OpenFGA statuses that mean "your request is invalid", not "I'm
#: unavailable" — surfaced as `UpstreamRequestRejected` (ARCH3-7).
_REJECTED_STATUSES = frozenset({400, 404, 409, 422})


class _RetryableStatus(Exception):
    def __init__(self, response: httpx.Response):
        super().__init__(f"retryable status {response.status_code}")
        self.response = response


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
        idempotent_writes: bool = True,
        list_objects_timeout: float = 10.0,
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

            idempotent_writes (bool):
                Send OpenFGA's `on_duplicate: "ignore"` / `on_missing:
                "ignore"` write options (OpenFGA >= 1.8), so granting an
                existing tuple or revoking a missing one succeeds, and a
                write can be safely retried after a read timeout (ARCH3-10,
                REL3-6). Set `False` for an older server that rejects the
                options — writes are then only retried when the request
                provably never reached the server.

            list_objects_timeout (float):
                Timeout for `list_objects()` specifically (REL3-17).
                ListObjects is OpenFGA's most expensive endpoint and its
                own server-side deadline (3s by default) exceeds the
                general `timeout`; it is also never retried on a read
                timeout, since repeating a slow query just multiplies load.
        """
        self.api_url = api_url.rstrip("/")
        self.store_id = store_id
        self.model_id = model_id
        self.timeout = timeout
        self.max_retries = max_retries
        self.idempotent_writes = idempotent_writes
        self.list_objects_timeout = list_objects_timeout

        self._client = http_client or httpx.AsyncClient(
            base_url=self.api_url,
            timeout=self.timeout,
        )

    @classmethod
    def for_tenant(
        cls,
        *,
        api_url: str,
        store_id: str | None = None,
        model_id: str | None = None,
        timeout: float = 2.0,
        max_retries: int = 2,
        http_client: httpx.AsyncClient | None = None,
        idempotent_writes: bool = True,
    ) -> "OpenFGAClient":
        """
        Construct an `OpenFGAClient` scoped to one tenant's store.

        This is exactly `OpenFGAClient(...)` — a single named
        constructor for the shape every tenant-lifecycle call site needs
        (`TenantManager.provision()`, `MultiTenantAuthz.for_tenant()`,
        `MigrationManager`), all of which previously hand-built an
        `OpenFGAClient` independently (see ARCH2-20). `store_id`/
        `model_id` default to `None` since `TenantManager.provision()`
        constructs a client *before* a store exists (it assigns
        `client.store_id` once `create_store()` returns one). Routing
        every such call site through here means a future required
        constructor parameter (e.g. auth credentials) only needs adding
        in one place.

        Args:
            api_url: Base URL of the OpenFGA API.
            store_id: OpenFGA store identifier, if already known.
            model_id: Authorization model ID, if already known.
            timeout: Request timeout in seconds.
            max_retries: Number of retry attempts for transient failures.
            http_client: Optional injected HTTP client (useful for testing).
        """
        return cls(
            api_url=api_url,
            store_id=store_id,
            model_id=model_id,
            timeout=timeout,
            max_retries=max_retries,
            http_client=http_client,
            idempotent_writes=idempotent_writes,
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

        data = await self._request("POST", endpoint, json=payload, idempotent=True)
        return data.get("allowed", False)

    async def _request(
        self,
        method: str,
        path: str,
        json: dict | None = None,
        *,
        idempotent: bool,
        timeout: float | None = None,
        retry_read_timeouts: bool = True,
    ) -> dict:
        """
        Shared HTTP helper behind every OpenFGA call.

        Retry policy depends on whether repeating the request is safe
        (REL3-6). Every call retries failures where the request provably
        never reached the server (connect errors/timeouts, pool
        exhaustion). Only `idempotent` calls also retry read timeouts —
        previously `create_store()` and writes retried a read timeout
        too, which after a server-side commit created a duplicate,
        orphaned store or failed with "tuple already exists" despite
        having succeeded — and transient 429/502/503/504 responses.

        Errors are classified (ARCH3-7): 400/404/409/422 →
        `UpstreamRequestRejected` (a client/config error); timeouts →
        `ServiceTimeout`; connect errors → `ServiceUnavailable`; any
        other non-2xx or unexpected failure → `ExternalServiceError`.
        """
        if idempotent:
            retryable: tuple[type[Exception], ...] = (
                (*_IDEMPOTENT_RETRYABLE, _RetryableStatus)
                if retry_read_timeouts
                else (*_NEVER_SENT, _RetryableStatus)
            )
        else:
            retryable = _NEVER_SENT

        async def attempt() -> httpx.Response:
            kwargs: dict = {"json": json}
            if timeout is not None:
                kwargs["timeout"] = timeout
            response = await self._client.request(method, path, **kwargs)
            if idempotent and response.status_code in _RETRYABLE_STATUSES:
                raise _RetryableStatus(response)
            return response

        try:
            try:
                response = await retry_async(
                    attempt, retryable=retryable, max_retries=self.max_retries
                )
            except _RetryableStatus as exc:
                response = exc.response  # retries exhausted — classify below
            response.raise_for_status()
            try:
                return response.json()
            except ValueError:
                # A successful DELETE typically has no body (204 No
                # Content) — `.json()` raises `json.JSONDecodeError`
                # (a `ValueError`) on it.
                return {}
        except httpx.TimeoutException as exc:
            raise ServiceTimeout(
                f"OpenFGA {method} {path} timed out", service="openfga", cause=exc
            ) from exc
        except httpx.ConnectError as exc:
            raise ServiceUnavailable(
                f"Unable to connect to OpenFGA for {method} {path}", service="openfga", cause=exc
            ) from exc
        except httpx.HTTPStatusError as exc:
            status = exc.response.status_code
            if status in _REJECTED_STATUSES:
                detail = _error_message(exc.response)
                raise UpstreamRequestRejected(
                    f"OpenFGA rejected {method} {path}: {status}"
                    + (f" — {detail}" if detail else ""),
                    status_code=status,
                    detail=detail,
                ) from exc
            raise ExternalServiceError(
                f"OpenFGA API error: {status}", service="openfga", cause=exc
            ) from exc
        except Exception as exc:
            # Catch-all: an unexpected non-httpx failure (e.g. a malformed
            # response body) is still classified as an
            # `ExternalServiceError` instead of propagating raw and
            # bypassing the CLI's exit-code mapping / the FastAPI
            # adapter's fail-open/fail-closed handling.
            raise ExternalServiceError(
                f"Unexpected error during OpenFGA {method} {path}", service="openfga", cause=exc
            ) from exc

    async def _get(self, path: str) -> dict:
        return await self._request("GET", path, idempotent=True)

    async def _post(self, path: str, json: dict) -> dict:
        """Read-only POST (check/list/read). Writes use `_request(...,
        idempotent=...)` directly so their retry policy is explicit."""
        return await self._request("POST", path, json=json, idempotent=True)

    async def get_latest_model(self) -> dict | None:
        """
        Fetch latest authorization model from OpenFGA.

        Returns:
            dict or None
        """
        # `page_size=1` (REL3-17): only the newest model is needed, but this
        # used to fetch a full page on every sync, dry run and health probe.
        res = await self._get(f"/stores/{self.store_id}/authorization-models?page_size=1")

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
        # Not idempotent: a retried create after a read timeout would make
        # a second, orphaned store (REL3-6).
        res = await self._request("POST", "/stores", json={"name": name}, idempotent=False)

        return res["id"]

    async def delete_store(self, store_id: str) -> None:
        """
        Delete an OpenFGA store.

        Added for ARCH2-8: `TenantManager.provision()` previously had no
        way to clean up the real OpenFGA store it had just created if a
        later step (model sync, persisting the mapping) failed —
        orphaning it permanently.
        """
        try:
            await self._request("DELETE", f"/stores/{store_id}", idempotent=True)
        except UpstreamRequestRejected as exc:
            # Already gone (e.g. a retried delete whose first attempt
            # succeeded): the desired end state holds.
            if exc.status_code != 404:
                raise

    async def ping(self) -> None:
        """OpenFGA's own `GET /healthz` — reachability only, no store
        needed. Raises on failure. Intended for readiness probes; build
        the client with `max_retries=0` and a short `timeout` for that, so
        a probe can't take several seconds of retries (REL3-7)."""
        await self._request("GET", "/healthz", idempotent=True)

    async def write_authorization_model(self, model: dict) -> dict:
        """Upload a new authorization model version (`POST
        /authorization-models`). Not retried after a read timeout — a
        repeat would just create a redundant duplicate version."""
        return await self._request(
            "POST",
            f"/stores/{self.store_id}/authorization-models",
            json=model,
            idempotent=False,
        )

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

        res = await self._request(
            "POST",
            f"/stores/{self.store_id}/list-objects",
            json=payload,
            idempotent=True,
            timeout=self.list_objects_timeout,
            retry_read_timeouts=False,
        )

        return list(res.get("objects", []))

    async def read_tuples(
        self,
        *,
        user: str | None = None,
        relation: str | None = None,
        object: str | None = None,
        page_size: int | None = None,
        continuation_token: str | None = None,
    ) -> dict:
        """
        Read relationship tuples matching a (partial) filter, via
        OpenFGA's `POST /stores/{id}/read`.

        This is the inverse of `check()`/`list_objects()`: those answer
        "can/does user X hold relation Y on object Z", this answers "what
        tuples actually exist" — e.g. "who has `viewer` on
        `document:roadmap`" (`relation`+`object`, no `user`) or "what does
        `user:alice` hold, full stop" (`user` only). At least one of
        `user`/`relation`/`object` should normally be given — OpenFGA
        accepts an empty filter too, but that means "every tuple in the
        store" and is rarely what a caller actually wants.

        Args:
            user: Restrict to tuples for this user (e.g. "user:alice").
            relation: Restrict to tuples with this relation.
            object: Restrict to tuples on this object (e.g.
                "document:roadmap"), or just a type ("document:") to
                match every object of that type.
            page_size: Max tuples to return in this page (OpenFGA's own
                default/cap applies if omitted).
            continuation_token: Resume a previous call's next page — pass
                back the `continuation_token` from that call's result.

        Returns:
            dict: `{"tuples": [{"user", "relation", "object",
            "timestamp"}, ...], "continuation_token": str | None}` — an
            empty/`None` `continuation_token` means there are no more
            pages.
        """
        tuple_key = {
            k: v
            for k, v in {"user": user, "relation": relation, "object": object}.items()
            if v is not None
        }

        payload: dict = {}
        if tuple_key:
            payload["tuple_key"] = tuple_key
        if page_size:
            payload["page_size"] = page_size
        if continuation_token:
            payload["continuation_token"] = continuation_token

        res = await self._post(f"/stores/{self.store_id}/read", json=payload)

        tuples = [
            {
                "user": t["key"]["user"],
                "relation": t["key"]["relation"],
                "object": t["key"]["object"],
                "timestamp": t.get("timestamp"),
            }
            for t in res.get("tuples", [])
        ]

        return {
            "tuples": tuples,
            "continuation_token": res.get("continuation_token") or None,
        }

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
                if self.idempotent_writes:
                    payload["writes"]["on_duplicate"] = "ignore"

            if delete_batch:
                payload["deletes"] = {"tuple_keys": delete_batch}
                if self.idempotent_writes:
                    payload["deletes"]["on_missing"] = "ignore"

            await self._request(
                "POST",
                f"/stores/{self.store_id}/write",
                json=payload,
                idempotent=self.idempotent_writes,
            )


def _error_message(response: httpx.Response) -> str | None:
    try:
        body = response.json()
    except ValueError:
        return None
    if isinstance(body, dict):
        message = body.get("message")
        return str(message) if message else None
    return None
