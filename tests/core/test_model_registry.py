import pytest

from py_authz.core.model_registry import InMemoryModelRegistry


@pytest.mark.asyncio
async def test_returns_none_for_unknown_tenant():
    reg = InMemoryModelRegistry()
    assert await reg.get("missing") is None


@pytest.mark.asyncio
async def test_set_and_get_round_trip():
    reg = InMemoryModelRegistry()

    await reg.set("t1", "model-1")

    assert await reg.get("t1") == "model-1"


@pytest.mark.asyncio
async def test_set_overwrites_existing_model():
    reg = InMemoryModelRegistry()

    await reg.set("t1", "model-1")
    await reg.set("t1", "model-2")

    assert await reg.get("t1") == "model-2"
