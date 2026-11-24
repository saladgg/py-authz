"""
Synchronous access to `Authz`, for WSGI and other non-async code
(Django, Flask, scripts, Celery tasks).

Why not just `asyncio.run(authz.can(...))` per call? `Authz` talks to
OpenFGA through one long-lived `httpx.AsyncClient`, whose pooled
connections are bound to the event loop that first used them. A fresh
loop per call (which is what `asyncio.run`/`anyio.run` do) means the
second call reuses a connection from a loop that no longer exists and
fails with `RuntimeError('Event loop is closed')` — every other call,
since the failure also resets the pool. That's exactly the bug the sync
`@authorize` decorator shipped with (ARCH3-2): checks fail closed, so a
legitimately allowed user was denied on alternating requests.

`SyncAuthz` instead owns **one** event loop, running forever on a daemon
thread, and submits every call to it with
`asyncio.run_coroutine_threadsafe`. Many threads may call it
concurrently (each call blocks only its own thread); the underlying
`Authz` only ever sees one loop.

Don't also use the wrapped `Authz` directly from a *different* event
loop while a `SyncAuthz` wraps it — the same loop-affinity rule applies.
"""

from __future__ import annotations

import asyncio
import threading
from collections.abc import Coroutine
from typing import Any, TypeVar

from py_authz.api import Authz
from py_authz.core.types import ContextualTuple, Identity, Resource
from py_authz.modeling.base import ResourceModel

T = TypeVar("T")


class SyncAuthz:
    """
    Blocking facade over an `Authz`.

    Example:
        authz = SyncAuthz(Authz.from_env(...))
        if authz.can("viewer", user, Document(id="roadmap")):
            ...
        authz.close()  # or use it as a context manager

    Every public coroutine method of `Authz` is available as a blocking
    method of the same name (`can`, `enforce`, `require`, `list_objects`,
    `grant`, `revoke`, `grant_many`, `revoke_many`, `read_tuples`, ...).
    """

    def __init__(self, authz: Authz, *, timeout: float | None = 30.0):
        """
        Args:
            authz: the async `Authz` to wrap.
            timeout: per-call ceiling in seconds (`None` waits forever). A
                call that exceeds it raises `TimeoutError` and is
                cancelled on the background loop.
        """
        self._authz = authz
        self._timeout = timeout
        self._loop = asyncio.new_event_loop()
        self._thread = threading.Thread(
            target=self._loop.run_forever, name="py-authz-sync", daemon=True
        )
        self._thread.start()
        self._closed = False

    # ------------------------------------------------------------------
    # Core
    # ------------------------------------------------------------------

    def run(self, coro: Coroutine[Any, Any, T]) -> T:
        """Run `coro` on the background loop and block for its result."""
        if self._closed:
            coro.close()
            raise RuntimeError("SyncAuthz is closed")
        if threading.current_thread() is self._thread:
            coro.close()
            raise RuntimeError(
                "SyncAuthz called from its own event loop thread — that would deadlock; "
                "await the wrapped Authz directly instead"
            )
        future = asyncio.run_coroutine_threadsafe(coro, self._loop)
        try:
            return future.result(timeout=self._timeout)
        except TimeoutError:
            future.cancel()
            raise

    def close(self) -> None:
        """Close the wrapped `Authz` (its HTTP pool) and stop the loop.
        Idempotent."""
        if self._closed:
            return
        try:
            self.run(self._authz.aclose())
        finally:
            self._closed = True
            self._loop.call_soon_threadsafe(self._loop.stop)
            self._thread.join(timeout=5)
            if not self._loop.is_running():
                self._loop.close()

    def __enter__(self) -> SyncAuthz:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    @property
    def authz(self) -> Authz:
        """The wrapped async `Authz`."""
        return self._authz

    # ------------------------------------------------------------------
    # Typed convenience methods for the common calls
    # ------------------------------------------------------------------

    def can(
        self,
        action,
        user: Identity,
        resource: Resource | ResourceModel,
        *,
        context: dict | None = None,
        contextual_tuples: list[ContextualTuple] | None = None,
    ) -> bool:
        return self.run(
            self._authz.can(
                action, user, resource, context=context, contextual_tuples=contextual_tuples
            )
        )

    def require(
        self,
        action: str,
        user: Identity,
        resource: Resource | ResourceModel,
        *,
        context: dict | None = None,
        contextual_tuples: list[ContextualTuple] | None = None,
    ) -> None:
        self.run(
            self._authz.require(
                action, user, resource, context=context, contextual_tuples=contextual_tuples
            )
        )

    def __getattr__(self, name: str):
        """Any other `Authz` coroutine method, made blocking."""
        attr = getattr(self._authz, name)
        if not asyncio.iscoroutinefunction(attr):
            return attr

        def blocking(*args, **kwargs):
            return self.run(attr(*args, **kwargs))

        blocking.__name__ = name
        blocking.__doc__ = attr.__doc__
        return blocking
