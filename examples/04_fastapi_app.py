"""
04 — FastAPI integration.

A minimal HTTP app that protects routes with py-authz. For clarity, this
example fakes authentication with an `X-User-Id` header and attaches an
`Identity` to `request.state.user` in a custom middleware. Example 05
replaces that with real Keycloak JWT validation.

Run:
    uv run uvicorn examples.04_fastapi_app:app --reload

Try:
    curl -H "X-User-Id: alice" http://localhost:8000/documents/roadmap
    curl -H "X-User-Id: alice" -X PATCH http://localhost:8000/documents/roadmap
    curl -H "X-User-Id: carol" -X PATCH http://localhost:8000/documents/roadmap
    # → 403

Requires: pip install py-authz[fastapi]
"""

from __future__ import annotations

import os
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, Request

from examples.models import Document
from py_authz import Authz, Identity
from py_authz.adapters.fastapi import request_context_middleware, require_fastapi
from py_authz.cache.memory import InMemoryCache
from py_authz.clients.openfga import OpenFGAClient
from py_authz.core.enforcement import AuthzEngine


@asynccontextmanager
async def lifespan(app: FastAPI):
    client = OpenFGAClient(
        api_url=os.environ["FGA_API_URL"],
        store_id=os.environ["FGA_STORE_ID"],
        model_id=os.environ["FGA_MODEL_ID"],
    )
    engine = AuthzEngine(fga_client=client, cache=InMemoryCache())
    app.state.authz = Authz(engine)
    try:
        yield
    finally:
        await client.aclose()


app = FastAPI(lifespan=lifespan)

# Adds an X-Request-ID header + propagates it to authz logs via context vars.
app.middleware("http")(request_context_middleware)


@app.middleware("http")
async def fake_auth_middleware(request: Request, call_next):
    """
    Stand-in for real auth. Reads `X-User-Id` and attaches an Identity so the
    authz adapter can pick it up via `request.state.user`.
    """
    user_id = request.headers.get("X-User-Id")
    if user_id:
        request.state.user = Identity(id=f"user:{user_id}")
    return await call_next(request)


def _authz(request: Request) -> Authz:
    return request.app.state.authz


@app.get("/documents/{doc_id}")
async def read_document(request: Request, doc_id: str):
    # Inline check — useful when the resource isn't known until runtime,
    # or when you want custom failure handling.
    user = getattr(request.state, "user", None)
    if not user:
        raise HTTPException(401, "Unauthorized")

    allowed = await _authz(request).can(Document.viewer, user, Document(id=doc_id))
    if not allowed:
        raise HTTPException(403, "Forbidden")
    return {"id": doc_id, "content": "..."}


@app.patch("/documents/{doc_id}")
async def update_document(request: Request, doc_id: str):
    # Decorator form — declarative, reusable. The decorator needs the `authz`
    # instance at import time, so we grab it from app.state via a wrapper.
    return await _patch_impl(request, doc_id=doc_id)


async def _patch_impl(request: Request, doc_id: str):
    # Build the decorator lazily so it can read the app-scoped Authz. In a real
    # app you'd usually hold a module-level Authz instead of using app.state.
    decorated = require_fastapi(
        _authz(request),
        Document.editor,
        resource_getter=lambda request, doc_id: Document(id=doc_id),
    )(_do_update)
    return await decorated(request=request, doc_id=doc_id)


async def _do_update(request: Request, doc_id: str):
    return {"id": doc_id, "updated": True}
