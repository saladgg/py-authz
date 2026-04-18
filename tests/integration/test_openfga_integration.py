import httpx
import pytest

from py_authz.api import Authz
from py_authz.clients.openfga import OpenFGAClient
from py_authz.core.enforcement import AuthzEngine
from py_authz.core.types import Identity, Resource

OPENFGA_URL = "http://localhost:8080"


# -------------------------------------------------------------------
# Helpers
# -------------------------------------------------------------------


async def create_store() -> str:
    async with httpx.AsyncClient() as client:
        res = await client.post(f"{OPENFGA_URL}/stores", json={"name": "test-store"})
        res.raise_for_status()
        return res.json()["id"]


async def write_model(store_id: str) -> str:
    # Modern model syntax (schema 1.1 is still the stable version in 2026)
    model = {
        "schema_version": "1.1",
        "type_definitions": [
            {"type": "user"},
            {
                "type": "document",
                "relations": {
                    "viewer": {
                        "this": {}  # ← Fixed: direct "this" instead of rewrite
                    }
                },
                "metadata": {
                    "relations": {"viewer": {"directly_related_user_types": [{"type": "user"}]}}
                },
            },
        ],
    }

    async with httpx.AsyncClient() as client:
        res = await client.post(
            f"{OPENFGA_URL}/stores/{store_id}/authorization-models",
            json=model,
        )

        # 🔥 Excellent for debugging (kept from your original)
        if res.status_code >= 400:
            print("STATUS:", res.status_code)
            print("BODY:", res.text)
            print("MODEL SENT:", model)

        res.raise_for_status()
        return res.json()["authorization_model_id"]


async def write_tuple(store_id: str, user: str, relation: str, obj: str):
    async with httpx.AsyncClient() as client:
        res = await client.post(
            f"{OPENFGA_URL}/stores/{store_id}/write",
            json={
                "writes": {
                    "tuple_keys": [
                        {
                            "user": user,
                            "relation": relation,
                            "object": obj,
                        }
                    ]
                },
                # Makes tests idempotent (recommended since OpenFGA v1.10+)
                "on_duplicate": "ignore",
            },
        )

        if res.status_code >= 400:
            print("WRITE FAILED - STATUS:", res.status_code)
            print("BODY:", res.text)

        res.raise_for_status()


# -------------------------------------------------------------------
# Fixtures
# -------------------------------------------------------------------


@pytest.fixture(scope="module")
async def fga_setup():
    store_id = await create_store()
    model_id = await write_model(store_id)
    return store_id, model_id


@pytest.fixture
async def authz(fga_setup):
    store_id, model_id = fga_setup

    client = OpenFGAClient(
        api_url=OPENFGA_URL,
        store_id=store_id,
        model_id=model_id,  # Passing model_id is good practice
    )

    engine = AuthzEngine(fga_client=client)
    return Authz(engine)


# -------------------------------------------------------------------
# Tests
# -------------------------------------------------------------------


@pytest.mark.asyncio
async def test_authorized_access(authz, fga_setup):
    store_id, _ = fga_setup

    user = Identity(id="user:123")
    doc = Resource(type="document", id="456")

    # Grant access
    await write_tuple(store_id, "user:123", "viewer", "document:456")

    allowed = await authz.enforce("viewer", user, doc)

    assert allowed is True


@pytest.mark.asyncio
async def test_denied_access(authz):
    user = Identity(id="user:999")
    doc = Resource(type="document", id="456")

    allowed = await authz.enforce("viewer", user, doc)

    assert allowed is False
