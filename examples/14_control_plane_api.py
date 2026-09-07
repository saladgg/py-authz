"""
14 — Control-plane API: stand up the management backend from
`py_authz.control_plane` (see `docs/control_plane.md` for the full
walkthrough this file is the runnable half of).

Unlike every other numbered example, this isn't an *end-user*-facing
authorization check — it's the admin surface described in
`docs/todos/09_control_panel.md`: tenant CRUD, model sync, migrations,
service accounts, audit querying, cache stats, all as an HTTP API a
Next.js frontend (not yet built — see that backlog's Tier 3) or a plain
`curl`/`httpx` script can drive.

`create_app()` reads `ControlPlaneSettings.from_env()` — every env var it
needs is documented in `docs/control_plane.md`, alongside a full,
copy-pasteable walkthrough (start the dev stack, create the RBAC store,
break-glass-bootstrap the first operator, get a token, drive the API).
The short version:

    docker compose up -d openfga keycloak redis postgres
    export FGA_API_URL=http://localhost:8082
    export CONTROL_PLANE_FGA_STORE_ID=<a fresh store id — see the doc>
    export CONTROL_PLANE_POSTGRES_DSN=postgres://py_authz:py_authz@localhost:5433/py_authz
    export CONTROL_PLANE_REDIS_URL=redis://localhost:6380/0
    export CONTROL_PLANE_OIDC_ISSUER=http://localhost:8081/realms/py-authz
    export CONTROL_PLANE_OIDC_AUDIENCE=py-authz-demo
    export CONTROL_PLANE_BREAK_GLASS_SUBJECT=<alice's Keycloak `sub` — see the doc>

Run:
    uv run uvicorn examples.14_control_plane_api:app --reload

Try (after getting a bearer token — see the doc for the exact curl):
    curl -H "Authorization: Bearer $TOKEN" http://localhost:8000/api/v1/auth/me
    curl -H "Authorization: Bearer $TOKEN" -X POST http://localhost:8000/api/v1/tenants \
        -H "Content-Type: application/json" -d '{"tenant_id": "acme-corp"}'
    curl -H "Authorization: Bearer $TOKEN" http://localhost:8000/api/v1/tenants

Requires: pip install "py-authz[control-plane]"
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

# Side-effect import: registers `examples.models`' `Document`/`Folder`
# into the global `py_authz.modeling.registry.registry` singleton, so
# `GET /api/v1/models` and `POST /api/v1/models/sync` have something
# beyond the bare `user` type to work with — this is what
# `ControlPlaneSettings.model_module` (`CONTROL_PLANE_MODEL_MODULE` env
# var) is *for*; importing directly here is the equivalent for a process
# that already knows which module that is, same as how a real deployment
# would import its own model module at the top of its own entrypoint.
import examples.models  # noqa: F401
from py_authz.control_plane.app import create_app

app = create_app()
