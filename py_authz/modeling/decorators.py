import asyncio
import concurrent.futures
import functools
import inspect
from collections.abc import Callable

import anyio

from py_authz.core.exceptions import AuthorizationDenied
from py_authz.core.types import Identity
from py_authz.modeling.base import Relation, ResourceModel


def authorize(
    authz,
    relation: Relation,
    *,
    user_getter: Callable[..., Identity],
    resource_getter: Callable[..., ResourceModel],
):
    """
    Decorator for enforcing authorization on function calls.
    Supports both async and sync functions safely using anyio.

    Named `authorize` (not `require`) to avoid colliding with
    `Authz.require()` — an async instance method with a very different
    call shape (`await authz.require(action, user, resource)` vs.
    `@authorize(authz, relation, user_getter=..., resource_getter=...)`)
    that's easy to confuse when both are in scope.
    """

    def decorator(func: Callable):

        is_async = inspect.iscoroutinefunction(func)

        # -------------------------------------------------
        # Async version (unchanged)
        # -------------------------------------------------
        @functools.wraps(func)
        async def async_wrapper(*args, **kwargs):
            user = user_getter(*args, **kwargs)
            resource = resource_getter(*args, **kwargs)

            allowed = await authz.can(relation, user, resource)

            if not allowed:
                raise AuthorizationDenied(f"{user.id} cannot perform {relation.name} on {resource}")

            return await func(*args, **kwargs)

        # -------------------------------------------------
        # Sync version (FIXED with anyio)
        # -------------------------------------------------
        @functools.wraps(func)
        def sync_wrapper(*args, **kwargs):
            user = user_getter(*args, **kwargs)
            resource = resource_getter(*args, **kwargs)

            async def _check():
                return await authz.can(relation, user, resource)

            # Safe execution regardless of event loop state
            try:
                # Fast path: this sync function is itself running inside a
                # worker thread anyio spawned (e.g. via
                # `anyio.to_thread.run_sync`) — hop back to the event loop
                # that spawned it.
                allowed = anyio.from_thread.run(_check)
            except RuntimeError:
                # Not in an anyio worker thread. See ARCH2-6: `anyio.run()`
                # (a fresh `asyncio.run()`) is only safe here if *this*
                # thread has no event loop already running — otherwise
                # (e.g. this sync-wrapped function was called from inside
                # async code on the same thread) it raises a second,
                # unhandled RuntimeError ("asyncio.run() cannot be called
                # from a running event loop") instead of the intended
                # fallback. Detect that case and run the check on a
                # dedicated thread with its own event loop instead, so the
                # call still blocks and returns a real result without
                # deadlocking the caller's loop.
                try:
                    asyncio.get_running_loop()
                except RuntimeError:
                    allowed = anyio.run(_check)
                else:
                    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
                        allowed = pool.submit(anyio.run, _check).result()

            if not allowed:
                raise AuthorizationDenied(f"{user.id} cannot perform {relation.name} on {resource}")

            return func(*args, **kwargs)

        return async_wrapper if is_async else sync_wrapper

    return decorator
