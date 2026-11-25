import asyncio
import json
import logging
import time
from datetime import datetime

import anyio

from py_authz.audit.types import AuditEvent
from py_authz.cache.base import BaseCache
from py_authz.core.context import get_request_id
from py_authz.core.exceptions import (
    AuthorizationDenied,
    InvalidAuthzRequest,
)
from py_authz.core.logging import logger
from py_authz.core.protocols import FGAClientProtocol
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
        fga_client: FGAClientProtocol,
        cache: BaseCache | None = None,
        *,
        raise_on_denied: bool = False,
        audit_logger=None,
        metrics=None,
        cache_namespace: str | None = None,
        max_background_audit_tasks: int = 1000,
    ):
        """
        Initialize the authorization engine.

        Args:
            fga_client (FGAClientProtocol):
                Client used to communicate with OpenFGA — any object
                implementing `check`/`list_objects`/`write_tuples`/
                `store_id` (structurally, per `FGAClientProtocol`; no
                inheritance required). `OpenFGAClient` and
                `testkit.InMemoryFGAClient` both satisfy this.

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

            cache_namespace (Optional[str]):
                Prefix mixed into every cache key this engine computes.
                Required whenever a `cache` backend might ever be shared
                by more than one `AuthzEngine`/OpenFGA store — e.g. one
                Redis instance shared across `MultiTenantAuthz` tenants.
                Without it, two engines pointed at different stores but
                sharing one cache would read back each other's cached
                authorization decisions for any identity/action/resource
                triple that happens to match across tenants. Pass the
                tenant's `store_id` (or equivalent). `None` (the default)
                is fine for a single, standalone engine that owns its
                cache outright.

            max_background_audit_tasks (int):
                Upper bound on concurrently in-flight background audit
                writes (see `_dispatch_audit_event`). Previously
                unbounded: if the audit sink hangs (rather than failing
                fast) under sustained load, every `enforce()` call spawns
                one more never-completing task, growing process memory
                without bound for as long as the outage lasts. Once this
                many writes are in flight, a new one is dropped (logged as
                a warning) rather than queued indefinitely — audit writes
                are already documented as best-effort, not guaranteed
                delivery (see REL2-4).
        """
        self.fga_client = fga_client
        self.cache = cache
        self.raise_on_denied = raise_on_denied
        self.audit_logger = audit_logger
        self.metrics = metrics
        self.cache_namespace = cache_namespace
        self.max_background_audit_tasks = max_background_audit_tasks
        self._background_audit_tasks: set[asyncio.Task] = set()
        #: In-flight upstream `check()` calls, keyed by scoped cache key —
        #: lets concurrent `enforce()` calls that miss the cache on the
        #: *same* key share one OpenFGA round trip instead of each issuing
        #: their own (a "cache stampede" right after a flush/restart, or
        #: the instant a hot key's TTL expires — see REL2-6).
        self._inflight_checks: dict[str, asyncio.Task[bool]] = {}

    def _extract_path(self, explanation_data) -> list[str] | None:
        """
        Extract readable path from OpenFGA explanation.
        """
        if not explanation_data:
            return None

        # `OpenFGAClient.explain()` returns `{"path": [...]}` (ARCH3-8).
        if isinstance(explanation_data, dict) and isinstance(explanation_data.get("path"), list):
            return [str(step) for step in explanation_data["path"]]

        # Any other client-specific shape: keep it readable, as before.
        try:
            return [str(explanation_data)]
        except Exception:
            return None

    def _scoped_cache_key(self, request: AuthzRequest) -> str:
        """Apply `cache_namespace` (see `__init__`) to `request`'s cache key."""
        key = request.cache_key()
        return f"{self.cache_namespace}:{key}" if self.cache_namespace else key

    async def invalidate(self, request: AuthzRequest):
        if self.cache:
            await self.cache.delete(self._scoped_cache_key(request))

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
        cache_key = self._scoped_cache_key(request)
        cacheable = request.is_cacheable()

        # -------------------------------------------------
        # 1. Check cache (skipped when per-request state is present)
        # -------------------------------------------------
        cache_hit = False

        if self.cache and cacheable:
            try:
                cached = await self.cache.get(cache_key)
            except Exception:
                # The cache is advisory, never load-bearing: a Redis blip
                # must degrade to a real OpenFGA check, not turn a pure
                # performance optimization into a hard outage for every
                # authorization check (see DX2-4 — the same failure class
                # SEC-3/SEC-1 already fixed for the audit logger and
                # Keycloak key rotation).
                logger.exception(
                    json.dumps(
                        {
                            "event": "cache_get_failed",
                            "request_id": get_request_id(),
                            "cache_key": cache_key,
                        }
                    )
                )
                cached = None

            if cached is not None:
                cache_hit = True
                duration = (time.time() - start) * 1000

                # Building/serializing this payload has a real cost
                # (attribute lookups, `json.dumps`) on a hot path meant to
                # run on every authorization decision — skip it entirely
                # when INFO logging is disabled and nothing would consume
                # the result (see REL2-16).
                if logger.isEnabledFor(logging.INFO):
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
                self._audit_decision(request, cached, cache_hit=True)

                return self._handle_result(
                    cached, request, raise_on_denied=effective_raise_on_denied
                )

        # -------------------------------------------------
        # 2. Call OpenFGA (coalescing concurrent misses on the same key —
        #    see REL2-6) and cache the result (3.)
        # -------------------------------------------------
        contextual = (
            [t.to_fga() for t in request.contextual_tuples] if request.contextual_tuples else None
        )
        allowed = await self._check_upstream(request, cache_key, cacheable, contextual)

        duration = (time.time() - start) * 1000

        # -------------------------------------------------
        # 4. Logging (AFTER decision)
        # -------------------------------------------------
        # Same guard as the cache-hit branch above (REL2-16) — this line
        # runs on every uncached/live-checked `enforce()` call, so skip
        # building/serializing the payload when INFO logging is disabled.
        if logger.isEnabledFor(logging.INFO):
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

        self._audit_decision(request, allowed, cache_hit=cache_hit)
        return self._handle_result(allowed, request, raise_on_denied=effective_raise_on_denied)

    async def _check_upstream(
        self,
        request: AuthzRequest,
        cache_key: str,
        cacheable: bool,
        contextual: list[dict] | None,
    ) -> bool:
        """
        Call OpenFGA and cache the result — but if another `enforce()`
        call is already doing exactly that for this same `cache_key`,
        await its result instead of issuing a redundant upstream call
        (see REL2-6).

        Only coalesced when caching actually applies (`cacheable` and
        `self.cache` configured); an uncacheable request (ABAC context/
        contextual tuples) or a cacheless engine always calls through
        directly, since there's no shared key to coalesce on.
        """
        if not (self.cache and cacheable):
            return await self.fga_client.check(
                user=request.identity.id,
                relation=request.action,
                object=request.resource.to_fga_object(),
                contextual_tuples=contextual,
                context=request.context,
            )

        # Every await on the shared task is shielded (REL3-1): the task is
        # shared by every coalesced caller, so cancelling one caller (a
        # client disconnect, a request timeout) must cancel only that
        # caller's wait — never the upstream check the others are still
        # waiting on. Without the shield, one disconnect fanned a
        # `CancelledError` (a `BaseException`, so it escaped both
        # `except AuthzError` and the `fail_open` policy) out to every
        # unrelated request sharing the key.
        existing = self._inflight_checks.get(cache_key)
        if existing is not None:
            return await asyncio.shield(existing)

        task = asyncio.ensure_future(self._check_and_cache(request, cache_key, contextual))
        self._inflight_checks[cache_key] = task

        def _forget(done: asyncio.Future) -> None:
            # The task removes its own entry when it finishes, not the
            # owning caller — so an owner cancelled mid-flight doesn't
            # evict an entry that other callers are still coalescing on.
            # Only remove it if it's still the current one: a newer task
            # installed after this one finished must never be evicted.
            if self._inflight_checks.get(cache_key) is done:
                del self._inflight_checks[cache_key]
            # Retrieve the exception so an owner-less failure (every
            # caller cancelled) doesn't log "exception was never
            # retrieved"; the callers that are still waiting get it
            # through their own shielded await.
            if not done.cancelled():
                done.exception()

        task.add_done_callback(_forget)
        return await asyncio.shield(task)

    async def _check_and_cache(
        self, request: AuthzRequest, cache_key: str, contextual: list[dict] | None
    ) -> bool:
        # Only ever called by `_check_upstream()` after it has already
        # confirmed `self.cache` is configured. Type-narrowing invariant,
        # not a security boundary — noqa'd rather than widening the
        # `S101` per-file-ignore to non-test code (see SEC2-8).
        assert self.cache is not None  # noqa: S101

        allowed = await self.fga_client.check(
            user=request.identity.id,
            relation=request.action,
            object=request.resource.to_fga_object(),
            contextual_tuples=contextual,
            context=request.context,
        )

        try:
            await self.cache.set(cache_key, allowed)
        except Exception:
            # Same fail-safe policy as the cache read (DX2-4): a cache
            # write failure must never affect the decision just made.
            logger.exception(
                json.dumps(
                    {
                        "event": "cache_set_failed",
                        "request_id": get_request_id(),
                        "cache_key": cache_key,
                    }
                )
            )

        return allowed

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

    def _audit_decision(self, request: AuthzRequest, allowed: bool, *, cache_hit: bool) -> None:
        """
        Dispatch an audit event for an `enforce()` decision.

        Called from both the cache-hit and live-check branches of
        `enforce()` — a cache hit is a real access decision and must be
        recorded like any other, not silently skipped (see ARCH2-1: this
        used to be inlined only on the live-check path, so every decision
        served from the cache within its TTL produced zero audit records).
        """
        if not self.audit_logger:
            return

        reason = self._build_reason(request, allowed, cache_hit)
        event = AuditEvent(
            timestamp=datetime.now(),
            tenant_id=getattr(self.fga_client, "store_id", None),
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

    def record_write(
        self,
        *,
        identity: Identity,
        relation: str,
        resource_object: str,
        operation: str,
        reason: str | None = None,
        actor: Identity | None = None,
    ) -> None:
        """
        Record metrics and an audit event for a direct tuple write.

        `Authz.grant`/`revoke`/`grant_many`/`revoke_many` call
        `fga_client.write_tuples()` directly — they don't perform a check,
        so they never went through `enforce()`, which was previously the
        only place a check/audit event or metrics counter was ever
        produced (see ARCH2-2). This is the equivalent hook for the write
        path: call it once per granted/revoked tuple.

        Args:
            identity: The subject the tuple was written for.
            relation: The relation granted/revoked.
            resource_object: The OpenFGA object string ("<type>:<id>").
            operation: `"grant"` or `"revoke"`.
            reason: Optional human-readable justification for this
                write, folded into `reason_data` (and used as the audit
                event's top-level `reason` string, in place of the
                generic default). A caller that requires operators to
                explain a manual grant/revoke — e.g. a control-plane API
                (see CP-8) — passes this through from that mandatory
                field, rather than only having `operation`/`relation` to
                go on later.
            actor: Optional identity that *performed* this write, when it
                differs from `identity` (the write's subject) — e.g. an
                operator granting `alice` a relation on `alice`'s behalf.
                Recorded as `reason_data["actor"]`; `event.user_id` stays
                `identity.id` (the subject), matching every other audit
                event's convention of `user_id` naming the tuple's
                subject, not the caller.
        """
        if self.metrics:
            self.metrics.incr(f"authz_{operation}_total")

        if not self.audit_logger:
            return

        reason_data = {"operation": operation, "relation": relation}
        if reason is not None:
            reason_data["reason"] = reason
        if actor is not None:
            reason_data["actor"] = actor.id

        event = AuditEvent(
            timestamp=datetime.now(),
            tenant_id=getattr(self.fga_client, "store_id", None),
            user_id=identity.id,
            action=relation,
            resource=resource_object,
            allowed=True,
            reason=reason or f"{operation} via Authz.{operation}",
            reason_data=reason_data,
            request_id=get_request_id(),
        )
        self._dispatch_audit_event(event)

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

        If `max_background_audit_tasks` in-flight writes are already
        queued (the audit sink is hung, not just slow — e.g. a Postgres
        connection stuck mid-query with no `command_timeout` configured),
        this write is dropped and logged as a warning instead of adding a
        task that would grow the backlog without bound (see REL2-4).
        """
        if len(self._background_audit_tasks) >= self.max_background_audit_tasks:
            logger.warning(
                json.dumps(
                    {
                        "event": "audit_log_dropped_backpressure",
                        "request_id": get_request_id(),
                        "user": event.user_id,
                        "resource": event.resource,
                        "in_flight": len(self._background_audit_tasks),
                    }
                )
            )
            return

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
        """
        Enforce many requests concurrently (bounded by `concurrency`).

        A failure on one request (e.g. a transient `ExternalServiceError`
        from OpenFGA) does not abort the batch or discard the results
        already computed for the other requests — it's captured on that
        request's own `BulkAuthzResult.error` instead, and `allowed` is
        `False` for that entry. See DX2-1: this previously let such an
        exception propagate out of the whole call as an unhandled
        `ExceptionGroup` (not an `AuthzError`, so `except AuthzError` at a
        framework boundary didn't catch it either), discarding every
        already-completed result in the batch.

        Returns:
            list[BulkAuthzResult]: exactly one result per input request,
            regardless of whether any individual request's check failed.
        """
        semaphore = anyio.Semaphore(concurrency)
        results: list[BulkAuthzResult] = []

        async def worker(req: AuthzRequest):
            async with semaphore:
                try:
                    allowed = await self.enforce(req)
                    results.append(BulkAuthzResult(req, allowed))
                except Exception as exc:
                    results.append(BulkAuthzResult(req, False, error=exc))

        async with anyio.create_task_group() as tg:
            for req in requests:
                tg.start_soon(worker, req)

        return results
