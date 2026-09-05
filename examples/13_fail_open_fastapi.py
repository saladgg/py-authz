"""
13 — `fail_open=True`: staying available during an OpenFGA outage.

`require_fastapi`/`require_dependency` both default to `fail_open=False`
(fail-closed): if the authorization backend itself fails — OpenFGA
unreachable, timed out, or (in a multi-tenant app) tenant provisioning
timing out on a contended lock — the request is rejected with a 503,
kept distinct from a genuine 403 "denied" decision. That's the right
default for anything where an incorrect "allow" is worse than downtime.

Some routes have the opposite risk profile: staying available matters
more than strict enforcement during a short outage (e.g. a read-only
"browse" page where an unnecessary 503 is worse than briefly showing
content to someone who might not be entitled to it). Pass
`fail_open=True` on exactly those routes to let the request through
instead of 503-ing when — and only when — the authorization backend
itself is down; a normal "denied" decision (OpenFGA reachable, answer is
just `False`) still 403s exactly as before on every route, `fail_open`
makes no difference there at all.

This example puts one fail-closed (the default) and one fail-open route
side by side on the same resource, so you can see them diverge under an
actual outage.

Run:
    uv run uvicorn examples.13_fail_open_fastapi:app --reload

Try, with OpenFGA up (both behave identically — a real decision):
    curl -H "X-User-Id: alice" http://localhost:8000/documents/roadmap
    curl -H "X-User-Id: alice" http://localhost:8000/documents/roadmap/lenient
    curl -H "X-User-Id: carol" http://localhost:8000/documents/roadmap          # → 403
    curl -H "X-User-Id: carol" http://localhost:8000/documents/roadmap/lenient  # → 403

Now stop OpenFGA to see them diverge:
    docker compose stop openfga
    curl -H "X-User-Id: alice" http://localhost:8000/documents/roadmap          # → 503
    curl -H "X-User-Id: alice" http://localhost:8000/documents/roadmap/lenient  # → 200 (fail-open)
    docker compose start openfga

Requires: pip install py-authz[fastapi]
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, Request

from examples.models import Document
from py_authz import Authz, Identity
from py_authz.adapters.fastapi import require_fastapi
from py_authz.clients.openfga import OpenFGAClient
from py_authz.core.enforcement import AuthzEngine


@asynccontextmanager
async def lifespan(app: FastAPI):
    client = OpenFGAClient(
        api_url=os.environ["FGA_API_URL"],
        store_id=os.environ["FGA_STORE_ID"],
        model_id=os.environ["FGA_MODEL_ID"],
    )
    app.state.authz = Authz(AuthzEngine(fga_client=client))
    try:
        yield
    finally:
        await client.aclose()


app = FastAPI(lifespan=lifespan)


@app.middleware("http")
async def fake_auth_middleware(request: Request, call_next):
    """Stand-in for real auth — see `04_fastapi_app.py`."""
    user_id = request.headers.get("X-User-Id")
    if user_id:
        request.state.user = Identity(id=f"user:{user_id}")
    return await call_next(request)


def _authz(request: Request) -> Authz:
    return request.app.state.authz


@app.get("/documents/{doc_id}")
async def read_document_strict(request: Request, doc_id: str):
    """
    Fail-closed (the default). If OpenFGA itself is unreachable, this
    returns 503 — never silently lets the request through.
    """
    user = getattr(request.state, "user", None)
    if not user:
        raise HTTPException(401, "Unauthorized")

    decorated = require_fastapi(
        _authz(request),
        Document.viewer,
        resource_getter=lambda request, doc_id: Document(id=doc_id),
        # fail_open=False is the default — spelled out here for contrast
        # with the /lenient route below.
        fail_open=False,
    )(_read_impl)
    return await decorated(request=request, doc_id=doc_id)


@app.get("/documents/{doc_id}/lenient")
async def read_document_lenient(request: Request, doc_id: str):
    """
    Fail-open. A genuine "denied" decision (OpenFGA reachable, answer is
    `False`) still 403s exactly like the strict route above — only an
    OpenFGA *outage* is treated differently: the request is let through
    instead of 503-ing. Reserve this for routes where staying available
    during a short outage matters more than strict enforcement, e.g. a
    read-only browse page.
    """
    user = getattr(request.state, "user", None)
    if not user:
        raise HTTPException(401, "Unauthorized")

    decorated = require_fastapi(
        _authz(request),
        Document.viewer,
        resource_getter=lambda request, doc_id: Document(id=doc_id),
        fail_open=True,
    )(_read_impl)
    return await decorated(request=request, doc_id=doc_id)


async def _read_impl(request: Request, doc_id: str):
    return {"id": doc_id, "content": "..."}
