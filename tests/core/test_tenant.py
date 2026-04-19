from py_authz.core.tenant import TenantContext


def test_tenant_context_holds_id_and_store_id():
    tc = TenantContext(id="t1", store_id="store-1")

    assert tc.id == "t1"
    assert tc.store_id == "store-1"


def test_tenant_context_is_mutable_dataclass():
    tc = TenantContext(id="t1", store_id="store-1")

    tc.store_id = "store-2"

    assert tc.store_id == "store-2"
