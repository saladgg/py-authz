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
                allowed = anyio.from_thread.run(_check)
            except RuntimeError:
                # fallback if not in worker thread
                allowed = anyio.run(_check)

            if not allowed:
                raise AuthorizationDenied(f"{user.id} cannot perform {relation.name} on {resource}")

            return func(*args, **kwargs)

        return async_wrapper if is_async else sync_wrapper

    return decorator
