import asyncio

import pytest

from py_authz.core.exceptions import AuthorizationDenied
from py_authz.core.types import Identity
from py_authz.modeling import Relation, ResourceModel
from py_authz.modeling.decorators import require


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
    @require(
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
    @require(
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
    @require(
        DenyAuthz(),
        Doc.view,
        user_getter=lambda u, d: u,
        resource_getter=lambda u, d: d,
    )
    def handler(user, doc):
        return "ok"

    with pytest.raises(AuthorizationDenied):
        handler(Identity(id="user:1"), Doc("1"))
