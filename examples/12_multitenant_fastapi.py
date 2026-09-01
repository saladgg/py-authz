"""
12 — Multi-tenant FastAPI: resolve `Authz` per request via `X-Tenant-ID`.

Combines two previously-separate examples: `06_multitenant.py`'s
`MultiTenantAuthz` (a store per tenant) and the FastAPI adapter from `04`/
`05`. `require_dependency`/`require_fastapi` accept either a static
`Authz` instance, or a sync/async callable that resolves one per request
— this is what lets a single set of routes serve every tenant, each
backed by its own OpenFGA store, instead of one global `Authz` baked in
at startup.

On startup, this app provisions two tenants (`acme`, `globex`) via
`TenantManager` and grants alice `viewer` on `document:report` in `acme`
only — so the same route returns a different decision depending on which
tenant's header is sent.

Run:
    uv run uvicorn examples.12_multitenant_fastapi:app --reload

Try:
    curl -H "X-Tenant-ID: acme" -H "X-User-Id: alice" http://localhost:8000/documents/report
    curl -H "X-Tenant-ID: globex" -H "X-User-Id: alice" \
        http://localhost:8000/documents/report  # → 403

Requires: pip install py-authz[fastapi]
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from contextlib import asynccontextmanager

from fastapi import FastAPI, Request

from examples.models import Document
from py_authz import Authz, Identity
from py_authz.adapters.fastapi import (
    request_context_middleware,
    require_fastapi,
    tenant_from_request,
)
from py_authz.api import MultiTenantAuthz
from py_authz.core.exceptions import TenantNotFoundError
from py_authz.core.tenant_manager import TenantManager
from py_authz.core.tenant_store import InMemoryTenantStore

OPENFGA_URL = os.environ.get("FGA_API_URL", "http://localhost:8082")


class _StoreBackedResolver:
    """Same as 06_multitenant.py's — reads from the shared TenantStore,
    raising `TenantNotFoundError` so `MultiTenantAuthz` falls back to the
    manager for auto-provisioning."""

    def __init__(self, tenant_store: InMemoryTenantStore) -> None:
        self._store = tenant_store

    async def resolve(self, tenant_id: str) -> str:
        store_id = await self._store.get(tenant_id)
        if store_id is None:
            raise TenantNotFoundError(f"Unknown tenant: {tenant_id}")
        return store_id


@asynccontextmanager
async def lifespan(app: FastAPI):
    tenant_store = InMemoryTenantStore()
    manager = TenantManager(api_url=OPENFGA_URL, tenant_store=tenant_store)

    mt = MultiTenantAuthz(
        api_url=OPENFGA_URL,
        model_id=None,  # per-tenant latest model is used
        tenant_resolver=_StoreBackedResolver(tenant_store),
        tenant_manager=manager,  # auto-provision an unknown tenant on first access
    )
    app.state.mt = mt

    # Seed: alice can view document:report in "acme", but has no
    # relationship to it in "globex" — demonstrates per-tenant isolation.
    acme = await mt.for_tenant("acme")
    await acme.grant(Identity(id="user:alice"), "viewer", Document(id="report"))
    await mt.for_tenant("globex")

    yield

    # Release every cached tenant's OpenFGAClient connection pool — see
    # MultiTenantAuthz.aclose()'s docstring (REL-7). Nothing else does
    # this, and it's a real leak in a long-running process otherwise.
    await mt.aclose()


app = FastAPI(lifespan=lifespan)
app.middleware("http")(request_context_middleware)


@app.middleware("http")
async def fake_auth_middleware(request: Request, call_next):
    """Stand-in for real auth — see 04/05 for real Keycloak JWT validation."""
    user_id = request.headers.get("X-User-Id")
    if user_id:
        request.state.user = Identity(id=f"user:{user_id}")
    return await call_next(request)


async def authz_for_request(request: Request) -> Authz:
    """
    The per-request resolver `require_fastapi`/`require_dependency` accept
    in place of a static `Authz` instance: called with the current
    request, awaited if it returns a coroutine (this one is `async def`,
    so it always does).
    """
    mt: MultiTenantAuthz = request.app.state.mt
    tenant_id = tenant_from_request(request)
    return await mt.for_tenant(tenant_id)


@app.get("/documents/{doc_id}")
@require_fastapi(
    authz_for_request,
    Document.viewer,
    resource_getter=lambda request, doc_id: Document(id=doc_id),
)
async def read_document(request: Request, doc_id: str):
    return {"id": doc_id, "tenant": tenant_from_request(request)}
