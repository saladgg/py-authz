import pytest

import py_authz.api as api_module
from py_authz.api import MultiTenantAuthz


class FakeResolver:
    def __init__(self, mapping: dict[str, str], error: Exception | None = None):
        self.mapping = mapping
        self.error = error
        self.calls: list[str] = []

    async def resolve(self, tenant_id: str) -> str:
        self.calls.append(tenant_id)
        if self.error:
            raise self.error
        return self.mapping[tenant_id]


class FakeManager:
    def __init__(self):
        self.provisioned: list[str] = []

    async def provision(self, tenant_id: str) -> str:
        self.provisioned.append(tenant_id)
        return f"store-for-{tenant_id}"


class FakeFGAClient:
    instances: list["FakeFGAClient"] = []

    def __init__(self, *, api_url, store_id, model_id):
        self.api_url = api_url
        self.store_id = store_id
        self.model_id = model_id
        FakeFGAClient.instances.append(self)


@pytest.fixture(autouse=True)
def patch_fga_client(monkeypatch):
    FakeFGAClient.instances = []
    monkeypatch.setattr(api_module, "OpenFGAClient", FakeFGAClient)


@pytest.mark.asyncio
async def test_for_tenant_resolves_and_builds_authz():
    resolver = FakeResolver({"t1": "store-1"})

    mt = MultiTenantAuthz(
        api_url="http://fake",
        model_id="model-1",
        tenant_resolver=resolver,
    )

    authz = await mt.for_tenant("t1")

    assert authz is not None
    assert resolver.calls == ["t1"]
    assert FakeFGAClient.instances[0].store_id == "store-1"


@pytest.mark.asyncio
async def test_for_tenant_caches_authz_instance():
    resolver = FakeResolver({"t1": "store-1"})
    mt = MultiTenantAuthz(api_url="http://fake", model_id=None, tenant_resolver=resolver)

    first = await mt.for_tenant("t1")
    second = await mt.for_tenant("t1")

    assert first is second
    # resolver only called on first access
    assert resolver.calls == ["t1"]


@pytest.mark.asyncio
async def test_for_tenant_auto_provisions_on_resolver_error():
    resolver = FakeResolver({}, error=KeyError("unknown"))
    manager = FakeManager()

    mt = MultiTenantAuthz(
        api_url="http://fake",
        model_id=None,
        tenant_resolver=resolver,
        tenant_manager=manager,
    )

    authz = await mt.for_tenant("t-new")

    assert authz is not None
    assert manager.provisioned == ["t-new"]
    assert FakeFGAClient.instances[0].store_id == "store-for-t-new"


@pytest.mark.asyncio
async def test_for_tenant_reraises_when_no_manager():
    resolver = FakeResolver({}, error=KeyError("unknown"))

    mt = MultiTenantAuthz(
        api_url="http://fake",
        model_id=None,
        tenant_resolver=resolver,
    )

    with pytest.raises(KeyError):
        await mt.for_tenant("t-unknown")
