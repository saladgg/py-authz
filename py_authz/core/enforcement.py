import asyncio
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
        metrics=None,
    ):
        """
        Initialize the authorization engine.

        Args:
            fga_client (OpenFGAClient):
                Client used to communicate with OpenFGA.

            cache (Optional[BaseCache]):
                Optional cache backend.

            raise_on_denied (bool):
                Default behavior when `enforce()`'s own `raise_on_denied`
                argument isn't given: if True, raises AuthorizationDenied
                instead of returning False.

            audit_logger:
                Save audit logs

            metrics:
                Optional object implementing `incr(name, amount=1)` /
                `observe(name, value)` (see `core/metrics.py:Metrics`, or
                pass the module-level `metrics` singleton from there).
                When given, `enforce()` records check/cache-hit/allowed/
                denied counters and check-duration observations. `None`
                (the default) records nothing — this is an optional,
                explicitly-injected dependency like `cache`/`audit_logger`,
                not a hardwired global.
        """
        self.fga_client = fga_client
        self.cache = cache
        self.raise_on_denied = raise_on_denied
        self.audit_logger = audit_logger
        self.metrics = metrics
        self._background_audit_tasks: set[asyncio.Task] = set()

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

    async def enforce(
        self,
        request: AuthzRequest,
        *,
        raise_on_denied: bool | None = None,
    ) -> bool:
        """
        Enforce an authorization decision.

        Args:
            request (AuthzRequest):
                The authorization request.

            raise_on_denied (Optional[bool]):
                Per-call override of the engine's own `raise_on_denied`
                default. `None` (the default) uses the engine's default;
                pass `True`/`False` explicitly to override it for just
                this call. This is what lets `Authz.require()` request
                raise-on-denied behavior without mutating the (possibly
                shared, concurrently-used) engine's own state — see
                `Authz.require()`.

        Returns:
            bool:
                True if access is allowed, False otherwise.

        Raises:
            InvalidAuthzRequest:
                If the request is malformed.

            AuthorizationDenied:
                If access is denied and raise_on_denied resolves to True.
        """

        self._validate_request(request)

        effective_raise_on_denied = (
            self.raise_on_denied if raise_on_denied is None else raise_on_denied
        )

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

                self._record_metrics(allowed=cached, cache_hit=True, duration_ms=duration)

                return self._handle_result(
                    cached, request, raise_on_denied=effective_raise_on_denied
                )

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

        self._record_metrics(allowed=allowed, cache_hit=cache_hit, duration_ms=duration)

        # -------------------------------------------------
        # 5. Return / raise
        # -------------------------------------------------

        if self.audit_logger:
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
            self._dispatch_audit_event(event)
        return self._handle_result(allowed, request, raise_on_denied=effective_raise_on_denied)

    def _record_metrics(self, *, allowed: bool, cache_hit: bool, duration_ms: float) -> None:
        """No-op when no `metrics` was injected (the common case)."""
        if not self.metrics:
            return

        self.metrics.incr("authz_check_total")
        self.metrics.incr("authz_allowed_total" if allowed else "authz_denied_total")
        if cache_hit:
            self.metrics.incr("authz_cache_hit_total")
        self.metrics.observe("authz_check_duration_ms", duration_ms)

    # ------------------------------------------------------------------
    # Audit dispatch
    # ------------------------------------------------------------------

    def _dispatch_audit_event(self, event: AuditEvent) -> None:
        """
        Write an audit event off the synchronous enforcement hot path.

        The write is fired-and-forgotten as a background task rather than
        awaited inline: an unhealthy audit sink (a slow or unreachable
        database, say) must add latency to *its own* write, never become
        an availability incident for every authorization check in the
        process. Failures are caught inside `_log_audit_event` and never
        propagate — audit logging is a side effect of a decision, never a
        precondition for one.

        Note: a background task is best-effort. A process that exits
        immediately after its last `enforce()` call may drop the final
        write(s) — call `flush_audit_logs()` before shutdown if your audit
        sink needs every write to land.
        """
        task = asyncio.ensure_future(self._log_audit_event(event))
        self._background_audit_tasks.add(task)
        task.add_done_callback(self._background_audit_tasks.discard)

    async def _log_audit_event(self, event: AuditEvent) -> None:
        try:
            await self.audit_logger.log(event)
        except Exception:
            logger.exception(
                json.dumps(
                    {
                        "event": "audit_log_failed",
                        "request_id": get_request_id(),
                        "user": event.user_id,
                        "resource": event.resource,
                    }
                )
            )

    async def flush_audit_logs(self) -> None:
        """
        Await any in-flight background audit writes.

        Most callers don't need this — it exists for tests that assert on
        audit-logger state right after an `enforce()` call, and for hosts
        that want every audit write for their already-handled requests to
        land before shutting down. Wrap the call in your own timeout
        (e.g. `anyio.move_on_after`) if you need one.
        """
        pending = list(self._background_audit_tasks)
        if pending:
            await asyncio.gather(*pending, return_exceptions=True)

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

    def _handle_result(
        self, allowed: bool, request: AuthzRequest, *, raise_on_denied: bool
    ) -> bool:
        """
        Handle the authorization result.

        Args:
            allowed (bool): Result from OpenFGA or cache
            request (AuthzRequest)
            raise_on_denied (bool): resolved per-call value (see
                `enforce()`) — this method no longer reads
                `self.raise_on_denied` directly, so it can't be affected
                by another concurrent call mutating engine state.

        Returns:
            bool

        Raises:
            AuthorizationDenied:
                If access is denied and raise_on_denied=True
        """
        if not allowed and raise_on_denied:
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

        contextual = (
            [t.to_fga() for t in request.contextual_tuples] if request.contextual_tuples else None
        )

        # Basic check — forwarding `context`/`contextual_tuples` so the
        # explanation matches the decision it explains; the original
        # `enforce()` decision could depend on either, and dropping them
        # here would silently explain a *different* check.
        allowed = await self.fga_client.check(
            user=request.identity.id,
            relation=request.action,
            object=request.resource.to_fga_object(),
            contextual_tuples=contextual,
            context=request.context,
        )

        # Try advanced explanation (if supported)
        explanation_data = None

        if hasattr(self.fga_client, "explain"):
            try:
                explanation_data = await self.fga_client.explain(
                    user=request.identity.id,
                    relation=request.action,
                    object=request.resource.to_fga_object(),
                    contextual_tuples=contextual,
                    context=request.context,
                )
            except TypeError:
                # Backward-compatible with an `explain` implementation
                # that doesn't accept these newer keyword arguments.
                try:
                    explanation_data = await self.fga_client.explain(
                        user=request.identity.id,
                        relation=request.action,
                        object=request.resource.to_fga_object(),
                    )
                except Exception:
                    explanation_data = None
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
