import json
import time
from datetime import datetime

import anyio

from py_authz.audit.types import AuditEvent
from py_authz.cache.base import BaseCache
from py_authz.clients.openfga import OpenFGAClient
from py_authz.core.context import get_request_id
from py_authz.core.exceptions import (
    AuthorizationDenied,
    InvalidAuthzRequest,
)
from py_authz.core.logging import logger
from py_authz.core.types import (
    AuthzExplanation,
    AuthzRequest,
    BulkAuthzResult,
    ContextualTuple,
    Identity,
)


class AuthzEngine:
    """
    Core authorization engine responsible for enforcing access control.

    This class orchestrates:
        - Authorization checks via OpenFGA
        - Caching for performance
        - Validation of incoming requests

    It is the central component of the py-authz library.
    """

    def __init__(
        self,
        fga_client: OpenFGAClient,
        cache: BaseCache | None = None,
        *,
        raise_on_denied: bool = False,
        audit_logger=None,
    ):
        """
        Initialize the authorization engine.

        Args:
            fga_client (OpenFGAClient):
                Client used to communicate with OpenFGA.

            cache (Optional[BaseCache]):
                Optional cache backend.

            raise_on_denied (bool):
                If True, raises AuthorizationDenied instead of returning False.

            audit_logger:
                Save audit logs
        """
        self.fga_client = fga_client
        self.cache = cache
        self.raise_on_denied = raise_on_denied
        self.audit_logger = audit_logger

    def _extract_path(self, explanation_data) -> list[str] | None:
        """
        Extract readable path from OpenFGA explanation.
        """
        if not explanation_data:
            return None

        # depends on OpenFGA response structure
        # keep generic/fallback for now
        try:
            return [str(explanation_data)]
        except Exception:
            return None

    async def invalidate(self, request: AuthzRequest):
        if self.cache:
            await self.cache.delete(request.cache_key())

    async def enforce(self, request: AuthzRequest) -> bool:
        """
        Enforce an authorization decision.

        Args:
            request (AuthzRequest):
                The authorization request.

        Returns:
            bool:
                True if access is allowed, False otherwise.

        Raises:
            InvalidAuthzRequest:
                If the request is malformed.

            AuthorizationDenied:
                If access is denied and raise_on_denied=True.
        """

        self._validate_request(request)

        start = time.time()
        cache_key = request.cache_key()
        cacheable = request.is_cacheable()

        # -------------------------------------------------
        # 1. Check cache (skipped when per-request state is present)
        # -------------------------------------------------
        cache_hit = False

        if self.cache and cacheable:
            cached = await self.cache.get(cache_key)
            if cached is not None:
                cache_hit = True
                duration = (time.time() - start) * 1000

                logger.info(
                    json.dumps(
                        {
                            "event": "authz_check",
                            "request_id": get_request_id(),
                            "tenant": getattr(self.fga_client, "store_id", None),
                            "user": request.identity.id,
                            "relation": request.action,
                            "resource": request.resource.to_fga_object(),
                            "allowed": cached,
                            "cache_hit": True,
                            "latency_ms": round(duration, 2),
                        }
                    )
                )

                return self._handle_result(cached, request)

        # -------------------------------------------------
        # 2. Call OpenFGA
        # -------------------------------------------------
        contextual = (
            [t.to_fga() for t in request.contextual_tuples] if request.contextual_tuples else None
        )
        allowed = await self.fga_client.check(
            user=request.identity.id,
            relation=request.action,
            object=request.resource.to_fga_object(),
            contextual_tuples=contextual,
            context=request.context,
        )

        # -------------------------------------------------
        # 3. Cache result (only when request is cacheable)
        # -------------------------------------------------
        if self.cache and cacheable:
            await self.cache.set(cache_key, allowed)

        duration = (time.time() - start) * 1000

        # -------------------------------------------------
        # 4. Logging (AFTER decision)
        # -------------------------------------------------
        logger.info(
            json.dumps(
                {
                    "event": "authz_check",
                    "request_id": get_request_id(),
                    "tenant": getattr(self.fga_client, "store_id", None),
                    "user": request.identity.id,
                    "relation": request.action,
                    "resource": request.resource.to_fga_object(),
                    "allowed": allowed,
                    "cache_hit": cache_hit,
                    "latency_ms": round(duration, 2),
                }
            )
        )

        # -------------------------------------------------
        # 5. Return / raise
        # -------------------------------------------------

        if self.audit_logger:
            # TODO: Make this background task - slow db can degrade performance
            reason = self._build_reason(request, allowed, cache_hit)
            event = AuditEvent(
                timestamp=datetime.now(),
                tenant_id=self.fga_client.store_id,
                user_id=request.identity.id,
                action=request.action,
                resource=request.resource.to_fga_object(),
                allowed=allowed,
                reason=reason,
                reason_data={
                    "cache_hit": cache_hit,
                    "relation": request.action,
                },
                request_id=get_request_id(),
            )
            await self.audit_logger.log(event)
        return self._handle_result(allowed, request)

    # ------------------------------------------------------------------
    # Internal Helpers
    # ------------------------------------------------------------------

    def _validate_request(self, request: AuthzRequest) -> None:
        """
        Validate the authorization request.

        Args:
            request (AuthzRequest)

        Raises:
            InvalidAuthzRequest: If validation fails.
        """
        if not request.identity or not request.identity.id:
            raise InvalidAuthzRequest("Missing or invalid identity")

        if not request.action:
            raise InvalidAuthzRequest("Action must be provided")

        if not request.resource:
            raise InvalidAuthzRequest("Resource must be provided")

        if not request.resource.type or not request.resource.id:
            raise InvalidAuthzRequest("Invalid resource format")

    def _handle_result(self, allowed: bool, request: AuthzRequest) -> bool:
        """
        Handle the authorization result.

        Args:
            allowed (bool): Result from OpenFGA or cache
            request (AuthzRequest)

        Returns:
            bool

        Raises:
            AuthorizationDenied:
                If access is denied and raise_on_denied=True
        """
        if not allowed and self.raise_on_denied:
            logger.warning(
                json.dumps(
                    {
                        "event": "authz_denied_exception",
                        "request_id": get_request_id(),
                        "user": request.identity.id,
                        "resource": request.resource.to_fga_object(),
                    }
                )
            )
            raise AuthorizationDenied(
                f"Access denied for {request.identity.id} "
                f"to perform '{request.action}' on "
                f"{request.resource.to_fga_object()}"
            )

        return allowed

    def _build_reason(self, request: AuthzRequest, allowed: bool, cache_hit: bool) -> str:
        if cache_hit:
            return "cache_hit"

        if allowed:
            return f"allowed via relation '{request.action}'"

        return f"no matching relation '{request.action}'"

    async def explain(self, request: AuthzRequest) -> AuthzExplanation:
        """
        Explain an authorization decision.

        Returns:
            AuthzExplanation
        """
        self._validate_request(request)

        # Basic check
        allowed = await self.fga_client.check(
            user=request.identity.id,
            relation=request.action,
            object=request.resource.to_fga_object(),
        )

        # Try advanced explanation (if supported)
        explanation_data = None

        if hasattr(self.fga_client, "explain"):
            try:
                explanation_data = await self.fga_client.explain(
                    user=request.identity.id,
                    relation=request.action,
                    object=request.resource.to_fga_object(),
                )
            except Exception:
                # fallback silently
                explanation_data = None

        # Build human-readable reason
        if allowed:
            reason = f"User has '{request.action}' on {request.resource.to_fga_object()}"
        else:
            reason = f"No '{request.action}' relation found"

        path = self._extract_path(explanation_data)

        return AuthzExplanation(
            allowed=allowed,
            reason=reason,
            path=path,
            details=explanation_data,
        )

    async def list_objects(
        self,
        user: Identity,
        relation: str,
        resource_type: str,
        *,
        context: dict | None = None,
        contextual_tuples: list[ContextualTuple] | None = None,
    ) -> list[str]:
        """
        Return all objects of `resource_type` that `user` has `relation` on.

        This is the inverse of `enforce`: instead of checking one object,
        OpenFGA returns the full set the user has access to. Required for
        list/index pages where checking each row would be O(n) round-trips.

        Returns:
            list[str]: object strings in "<type>:<id>" form.
        """
        if not user or not user.id:
            raise InvalidAuthzRequest("Missing or invalid identity")
        if not relation:
            raise InvalidAuthzRequest("Relation must be provided")
        if not resource_type:
            raise InvalidAuthzRequest("resource_type must be provided")

        start = time.time()

        contextual = [t.to_fga() for t in contextual_tuples] if contextual_tuples else None

        objects = await self.fga_client.list_objects(
            user=user.id,
            relation=relation,
            type=resource_type,
            contextual_tuples=contextual,
            context=context,
        )

        duration = (time.time() - start) * 1000

        logger.info(
            json.dumps(
                {
                    "event": "authz_list_objects",
                    "request_id": get_request_id(),
                    "tenant": getattr(self.fga_client, "store_id", None),
                    "user": user.id,
                    "relation": relation,
                    "type": resource_type,
                    "count": len(objects),
                    "latency_ms": round(duration, 2),
                }
            )
        )

        return objects

    async def bulk_enforce(
        self,
        requests: list[AuthzRequest],
        *,
        concurrency: int = 10,
    ) -> list[BulkAuthzResult]:
        semaphore = anyio.Semaphore(concurrency)
        results: list[BulkAuthzResult] = []

        async def worker(req: AuthzRequest):
            async with semaphore:
                allowed = await self.enforce(req)
                results.append(BulkAuthzResult(req, allowed))

        async with anyio.create_task_group() as tg:
            for req in requests:
                tg.start_soon(worker, req)

        return results
