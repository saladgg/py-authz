import pytest

import py_authz.api as api_module
from py_authz.api import MultiTenantAuthz
from py_authz.core.exceptions import TenantNotFoundError


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
        self.closed = False
        FakeFGAClient.instances.append(self)

    async def aclose(self) -> None:
        self.closed = True


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
async def test_for_tenant_auto_provisions_on_tenant_not_found():
    resolver = FakeResolver({}, error=TenantNotFoundError("unknown"))
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
    resolver = FakeResolver({}, error=TenantNotFoundError("unknown"))

    mt = MultiTenantAuthz(
        api_url="http://fake",
        model_id=None,
        tenant_resolver=resolver,
    )

    with pytest.raises(TenantNotFoundError):
        await mt.for_tenant("t-unknown")


@pytest.mark.asyncio
async def test_for_tenant_does_not_auto_provision_on_arbitrary_resolver_error():
    """
    Regression test for SEC-4: a resolver failure that is NOT
    `TenantNotFoundError` (e.g. a transient DB/network error) must
    propagate as a hard failure, even when a `tenant_manager` is
    configured — it must never be silently reinterpreted as "this tenant
    doesn't exist yet" and trigger auto-provisioning of a new store.
    """
    resolver = FakeResolver({}, error=RuntimeError("db connection reset"))
    manager = FakeManager()

    mt = MultiTenantAuthz(
        api_url="http://fake",
        model_id=None,
        tenant_resolver=resolver,
        tenant_manager=manager,
    )

    with pytest.raises(RuntimeError, match="db connection reset"):
        await mt.for_tenant("t-existing")

    assert manager.provisioned == []
    assert FakeFGAClient.instances == []


@pytest.mark.asyncio
async def test_aclose_closes_every_cached_tenant_client():
    """
    Regression test for REL-7: `MultiTenantAuthz` previously had no way to
    release the `OpenFGAClient`s (and their `httpx.AsyncClient` connection
    pools) it accumulates as it resolves more tenants — a real socket leak
    in any long-running process serving more than a handful of tenants.
    """
    resolver = FakeResolver({"t1": "store-1", "t2": "store-2"})
    mt = MultiTenantAuthz(api_url="http://fake", model_id=None, tenant_resolver=resolver)

    await mt.for_tenant("t1")
    await mt.for_tenant("t2")
    assert len(FakeFGAClient.instances) == 2

    await mt.aclose()

    assert all(client.closed for client in FakeFGAClient.instances)
    assert mt._cache == {}


@pytest.mark.asyncio
async def test_aclose_on_empty_cache_is_a_noop():
    resolver = FakeResolver({})
    mt = MultiTenantAuthz(api_url="http://fake", model_id=None, tenant_resolver=resolver)

    await mt.aclose()  # must not raise

    assert mt._cache == {}


@pytest.mark.asyncio
async def test_authz_aclose_closes_underlying_fga_client():
    resolver = FakeResolver({"t1": "store-1"})
    mt = MultiTenantAuthz(api_url="http://fake", model_id=None, tenant_resolver=resolver)

    authz = await mt.for_tenant("t1")
    await authz.aclose()

    assert FakeFGAClient.instances[0].closed is True


@pytest.mark.asyncio
async def test_authz_aclose_tolerates_a_client_with_no_aclose():
    """
    `Authz.aclose()` must not assume every `fga_client` implements
    `aclose()` — a caller could hand `AuthzEngine` an arbitrary
    duck-typed client that only implements `check()`.
    """
    from py_authz.api import Authz
    from py_authz.core.enforcement import AuthzEngine

    class ClientWithoutAclose:
        async def check(self, *args, **kwargs):
            return True

    authz = Authz(AuthzEngine(fga_client=ClientWithoutAclose()))

    await authz.aclose()  # must not raise
