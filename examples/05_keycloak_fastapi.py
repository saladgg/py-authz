"""
05 — Keycloak + FastAPI.

`KeycloakJWTValidator` fetches JWKS from your realm and verifies RS256 Bearer
tokens. `KeycloakAuthMiddleware` runs it on every request and, on success,
attaches an `Identity(id="user:<sub>")` to `request.state.user` — the same
shape the authz adapter expects.

Note: the authorization-model `user:<id>` in OpenFGA must match the JWT
`sub` claim. Seed your tuples accordingly, or map `sub` → your own user IDs
in a custom `to_identity` override.

Run:
    uv run uvicorn examples.05_keycloak_fastapi:app --reload

Try (with a real token from your realm):
    curl -H "Authorization: Bearer $TOKEN" http://localhost:8000/documents/roadmap

Requires:
    pip install py-authz[fastapi] pyjwt[crypto]
Env:
    KEYCLOAK_ISSUER     e.g. https://auth.example.com/realms/myrealm
    KEYCLOAK_AUDIENCE   your Keycloak client_id
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from contextlib import asynccontextmanager

from fastapi import FastAPI, Request

from examples.models import Document
from py_authz import Authz
from py_authz.adapters.fastapi import default_user_getter, require_fastapi
from py_authz.adapters.keycloak import KeycloakJWTValidator
from py_authz.adapters.keycloak_fastapi import KeycloakAuthMiddleware
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


validator = KeycloakJWTValidator(
    issuer=os.environ["KEYCLOAK_ISSUER"],
    audience=os.environ["KEYCLOAK_AUDIENCE"],
)

app = FastAPI(lifespan=lifespan)
app.add_middleware(KeycloakAuthMiddleware, validator=validator)


# Build the require-dependency once at startup.
# (Need the Authz instance, so we wire it via a small factory on first request.)
_guard = None


def view_document_guard(request: Request):
    global _guard
    if _guard is None:
        _guard = require_fastapi(
            request.app.state.authz,
            Document.viewer,
            resource_getter=lambda req, doc_id: Document(id=doc_id),
            user_getter=default_user_getter,
        )
    return _guard


@app.get("/documents/{doc_id}")
async def read_document(request: Request, doc_id: str):
    guard = view_document_guard(request)(_handler)
    return await guard(request=request, doc_id=doc_id)


async def _handler(request: Request, doc_id: str):
    return {"id": doc_id, "viewer": request.state.user.id}
