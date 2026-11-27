import functools
import inspect
import threading
import weakref
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
        # Sync version
        # -------------------------------------------------
        @functools.wraps(func)
        def sync_wrapper(*args, **kwargs):
            user = user_getter(*args, **kwargs)
            resource = resource_getter(*args, **kwargs)

            allowed = _run_check_sync(authz, relation, user, resource)

            if not allowed:
                raise AuthorizationDenied(f"{user.id} cannot perform {relation.name} on {resource}")

            return func(*args, **kwargs)

        return async_wrapper if is_async else sync_wrapper

    return decorator


# One background-loop runner per wrapped `Authz`, shared by every sync
# decorated function using it (ARCH3-2). Weakly keyed so a discarded
# `Authz` doesn't keep its runner thread's bookkeeping alive.
_runners: weakref.WeakKeyDictionary = weakref.WeakKeyDictionary()
_runners_lock = threading.Lock()


def _runner_for(authz):
    from py_authz.sync import SyncAuthz

    # A `SyncAuthz` never reaches here: `_run_check_sync` calls it directly.
    with _runners_lock:
        runner = _runners.get(authz)
        if runner is None:
            runner = SyncAuthz(authz)
            _runners[authz] = runner
        return runner


def _run_check_sync(authz, relation, user, resource) -> bool:
    """
    Run `authz.can(...)` from synchronous code.

    - Inside an anyio worker thread (e.g. a sync FastAPI endpoint, which
      Starlette runs via `anyio.to_thread`): hop back to the caller's own
      event loop, which is the loop `authz`'s HTTP client already lives
      on.
    - Anywhere else (WSGI, scripts, a thread with no loop, or even a
      thread whose loop is busy running this very call): submit to one
      long-lived background loop per `authz` (`SyncAuthz`). This used to
      call `anyio.run()` — a brand-new event loop per call — which broke
      the client's pooled connections on every other call (ARCH3-2).
    """
    from py_authz.sync import SyncAuthz

    if isinstance(authz, SyncAuthz):
        return authz.can(relation, user, resource)

    try:
        return anyio.from_thread.run(authz.can, relation, user, resource)
    except RuntimeError:
        pass  # not in an anyio worker thread

    return _runner_for(authz).can(relation, user, resource)
