"""Tests for the `BaseCache` contract in py_authz.cache.base."""

import pytest

from py_authz.cache.base import BaseCache


class _DelegatingCache(BaseCache):
    """A concrete subclass that defers every method to the base implementation."""

    async def get(self, key):
        return await super().get(key)

    async def set(self, key, value, ttl=60):
        return await super().set(key, value, ttl)

    async def delete(self, key):
        return await super().delete(key)

    async def clear(self):
        return await super().clear()


def test_base_cache_cannot_be_instantiated_directly():
    with pytest.raises(TypeError):
        BaseCache()  # type: ignore[abstract]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("method", "args"),
    [("get", ("k",)), ("set", ("k", True)), ("delete", ("k",)), ("clear", ())],
)
async def test_base_implementations_raise_not_implemented(method, args):
    # A subclass that forgets to provide real behaviour (and falls back to
    # `super()`) must fail loudly rather than silently act as a no-op cache.
    cache = _DelegatingCache()

    with pytest.raises(NotImplementedError):
        await getattr(cache, method)(*args)
