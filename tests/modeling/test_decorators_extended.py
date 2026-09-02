import asyncio

import pytest

from py_authz.core.exceptions import AuthorizationDenied
from py_authz.core.types import Identity
from py_authz.modeling import Relation, ResourceModel
from py_authz.modeling.decorators import authorize


class Doc(ResourceModel):
    type = "document"
    view = Relation("viewer")


class AllowAuthz:
    async def can(self, *a, **kw):
        return True


class DenyAuthz:
    async def can(self, *a, **kw):
        return False


def test_async_decorator_allows():
    @authorize(
        AllowAuthz(),
        Doc.view,
        user_getter=lambda u, d: u,
        resource_getter=lambda u, d: d,
    )
    async def handler(user, doc):
        return "ok"

    result = asyncio.run(handler(Identity(id="user:1"), Doc("1")))

    assert result == "ok"


def test_async_decorator_raises_when_denied():
    @authorize(
        DenyAuthz(),
        Doc.view,
        user_getter=lambda u, d: u,
        resource_getter=lambda u, d: d,
    )
    async def handler(user, doc):
        return "ok"

    with pytest.raises(AuthorizationDenied):
        asyncio.run(handler(Identity(id="user:1"), Doc("1")))


def test_sync_decorator_raises_when_denied():
    @authorize(
        DenyAuthz(),
        Doc.view,
        user_getter=lambda u, d: u,
        resource_getter=lambda u, d: d,
    )
    def handler(user, doc):
        return "ok"

    with pytest.raises(AuthorizationDenied):
        handler(Identity(id="user:1"), Doc("1"))


def test_sync_decorator_works_when_called_from_inside_a_running_event_loop():
    """
    Regression test for ARCH2-6: calling a sync-wrapped function from code
    already running inside an event loop on the same thread (e.g. a sync
    helper invoked from an async framework callback, not via
    `anyio.to_thread.run_sync`) used to crash with a second, unhandled
    RuntimeError ("asyncio.run() cannot be called from a running event
    loop") once `anyio.from_thread.run`'s own RuntimeError fallback path
    was reached.
    """

    @authorize(
        AllowAuthz(),
        Doc.view,
        user_getter=lambda u, d: u,
        resource_getter=lambda u, d: d,
    )
    def handler(user, doc):
        return "ok"

    async def outer():
        return handler(Identity(id="user:1"), Doc("1"))

    result = asyncio.run(outer())

    assert result == "ok"
