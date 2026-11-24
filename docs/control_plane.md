# Control-Plane API

A linear walkthrough for standing up `py_authz.control_plane` — the
optional HTTP management API for operating a py-authz deployment
(tenants, authorization models, migrations, audit trail, service
accounts) against a fresh dev stack. See
[`docs/todos/09_control_panel.md`](todos/09_control_panel.md) for the
design this implements and
[`docs/todos/09_control_panel_todos.md`](todos/09_control_panel_todos.md)
for what's shipped (everything — all four tiers, backend and frontend
both).

This doc covers the **backend API** end to end, driven with `curl` so
every request/response is visible. Once it's running, the
**Next.js frontend** (`../control-panel/`) is the more pleasant way to
actually use it day to day — see [§8](#8-the-nextjs-frontend) and
[`../control-panel/README.md`](../control-panel/README.md). The runnable
half of the backend walkthrough below is
[`examples/14_control_plane_api.py`](../examples/14_control_plane_api.py).

---

## 1. Install

Requires **Python 3.13+** and the `control-plane` extra (FastAPI,
Postgres, Redis, PyJWT, argon2-cffi):

```bash
pip install "py-authz[control-plane]"
```

Using [`uv`](https://github.com/astral-sh/uv) for development:

```bash
make venv
make install-dev   # already includes control-plane, via the `test`/`dev` groups
```

---

## 2. Start the dev stack

The control-plane API needs all four of OpenFGA, Postgres, Redis, and an
OIDC provider (Keycloak, bundled for dev). All four are in the repo's
`docker-compose.yml`:

```bash
docker compose up -d openfga keycloak redis postgres
curl http://localhost:8082/healthz          # OpenFGA
curl http://localhost:8081/realms/py-authz  # Keycloak realm (imported from docker/keycloak/realm.json)
```

| Service  | Host address                                              |
| -------- | ---------------------------------------------------------- |
| OpenFGA  | `http://localhost:8082`                                     |
| Keycloak | `http://localhost:8081` (realm `py-authz`, client `py-authz-demo`, user `alice`/`alice`) |
| Redis    | `redis://localhost:6380/0`                                   |
| Postgres | `postgres://py_authz:py_authz@localhost:5433/py_authz`        |

---

## 3. Create the RBAC store

The control-plane API syncs its own dogfooded RBAC model (`system`/`tenant`
types — see [`py_authz/control_plane/rbac_model.py`](../py_authz/control_plane/rbac_model.py))
into a **dedicated** OpenFGA store, separate from any tenant's. Create an
empty store for it once:

```bash
STORE_ID=$(curl -s -X POST http://localhost:8082/stores \
    -H "Content-Type: application/json" \
    -d '{"name": "py-authz-control-plane-rbac"}' | python3 -c "import sys, json; print(json.load(sys.stdin)['id'])")

echo "CONTROL_PLANE_FGA_STORE_ID=$STORE_ID"
```

`create_app()` syncs the RBAC model into this store automatically on
startup (idempotent — re-running the API doesn't re-upload it unless the
model itself changed), the same way `TenantManager.provision()` does for
a tenant's own store.

---

## 4. Configure the environment

The repo root's [`.env.example`](../.env.example) has every var below
(and every other optional one — cache/rate-limit tuning, a pinned model
id, ...) already grouped under "§3. Control-plane API", ready to
`cp .env.example .env` and fill in. The minimum to get running:

```bash
export FGA_API_URL=http://localhost:8082
export CONTROL_PLANE_FGA_STORE_ID=$STORE_ID
export CONTROL_PLANE_POSTGRES_DSN=postgres://py_authz:py_authz@localhost:5433/py_authz
export CONTROL_PLANE_REDIS_URL=redis://localhost:6380/0
export CONTROL_PLANE_OIDC_ISSUER=http://localhost:8081/realms/py-authz
export CONTROL_PLANE_OIDC_AUDIENCE=py-authz-demo
```

`CONTROL_PLANE_POSTGRES_DSN` is applied automatically on startup
(`apply_schema()` — every table this library needs, tenant/model/audit
plus the new operators/service_accounts/model_versions/control_plane_jobs
ones, `CREATE TABLE IF NOT EXISTS`, safe to run repeatedly). See
[`ControlPlaneSettings`](../py_authz/control_plane/settings.py)'s own
docstrings for every var's exact meaning/default (Redis is optional —
cache stats/invalidate routes 503 without it; `CONTROL_PLANE_MODEL_MODULE`
is only needed if you don't already import your model module some other
way, as this example does).

---

## 5. Break-glass: bootstrap the first operator

The dogfooded RBAC store starts with zero grants — nobody can call
anything yet, including granting the first role. Resolve this once by
naming the very first `system#owner` via an env var, consumed only while
the RBAC store has zero grants at all (see
[`bootstrap.py`](../py_authz/control_plane/bootstrap.py)):

```bash
TOKEN=$(curl -s -X POST http://localhost:8081/realms/py-authz/protocol/openid-connect/token \
    -d grant_type=password -d client_id=py-authz-demo -d username=alice -d password=alice \
    | python3 -c "import sys, json; print(json.load(sys.stdin)['access_token'])")

SUB=$(python3 -c "
import base64, json, sys
payload = '$TOKEN'.split('.')[1]
payload += '=' * (-len(payload) % 4)
print(json.loads(base64.urlsafe_b64decode(payload))['sub'])
")

export CONTROL_PLANE_BREAK_GLASS_SUBJECT=$SUB
```

The break-glass grant fires the first time this subject's token
authenticates against a running API — i.e. on the *first* `GET
/api/v1/auth/me` call below, not at startup.

---

## 6. Run the API

```bash
uv run uvicorn examples.14_control_plane_api:app --reload
```

(That example does one thing beyond `python -m py_authz.control_plane`:
it imports `examples/models.py` first, so `Document`/`Folder` are
registered and `GET /api/v1/models` has something to show — see
`ControlPlaneSettings.model_module`'s docstring for the equivalent via an
env var instead of a direct import.)

---

## 7. Drive the API

```bash
# Confirm the break-glass bootstrap landed you `system#owner`:
curl -s -H "Authorization: Bearer $TOKEN" http://localhost:8000/api/v1/auth/me | python3 -m json.tool
# {"id": "user:<sub>", "kind": "operator", "scopes": null, "system_role": "owner"}

# Provision a tenant:
curl -s -X POST http://localhost:8000/api/v1/tenants \
    -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
    -d '{"tenant_id": "acme-corp"}'

# List tenants:
curl -s -H "Authorization: Bearer $TOKEN" http://localhost:8000/api/v1/tenants

# You (system#owner) still can't see acme-corp's own detail/tuples/audit
# routes without an explicit tenant-scoped grant — that's deliberate
# (see require_tenant_role's docstring). Grant yourself tenant#admin on
# it directly against the RBAC store the same way any py-authz consumer
# would, or create a service account instead (below) for automation.

# Create a service account (the secret is shown exactly once):
curl -s -X POST http://localhost:8000/api/v1/service-accounts \
    -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
    -d '{"name": "ci-bot", "scopes": ["models:write", "tenants:read"]}'
# {"id": "sa_...", "name": "ci-bot", ..., "secret": "pasa_sa_....<random>"}

# A service account needs BOTH a scope and an RBAC role for a route to
# succeed. Scopes come from a closed list (py_authz/control_plane/scopes.py;
# an unknown one is a 422) and act as a ceiling; the role is granted like
# an operator's, but by account id with subject_kind=service_account:
curl -s -X POST http://localhost:8000/api/v1/operators/roles \
    -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
    -d '{"subject": "sa_...", "subject_kind": "service_account",
         "scope": "tenant", "tenant_id": "acme-corp", "role": "admin"}'

# Use that secret as a bearer token — same routes, scope-checked first.
# Its principal is service_account:<id> (never its name, which can be
# reused after revoke):
curl -s -H "Authorization: Bearer pasa_sa_....<random>" http://localhost:8000/api/v1/auth/me

# Rotating or revoking an account requires holding every role it holds
# (system#owner always qualifies) — rotation hands you its secret.
# Revoking also deletes its role grants.

# Sync the currently-registered model to a tenant (dry-run first):
curl -s "http://localhost:8000/api/v1/models/sync?tenant_id=acme-corp&dry_run=true" \
    -X POST -H "Authorization: Bearer $TOKEN"
curl -s "http://localhost:8000/api/v1/models/sync?tenant_id=acme-corp" \
    -X POST -H "Authorization: Bearer $TOKEN"

# Audit trail:
curl -s -H "Authorization: Bearer $TOKEN" "http://localhost:8000/api/v1/audit-logs?limit=10"

# Probes (unauthenticated, unversioned):
curl -s http://localhost:8000/livez    # process alive — use for liveness
curl -s http://localhost:8000/readyz   # Postgres + Redis + OpenFGA; 503 if any is down
# /health is an alias of /readyz (it now returns 503, not 200, when degraded).
```

Every route, its required role, and its request/response shape is in
[`docs/todos/09_control_panel.md`](todos/09_control_panel.md) §2.3, and
concretely in [`py_authz/control_plane/routes/`](../py_authz/control_plane/routes/)
— each route module is a thin wrapper, so the fastest way to see exactly
what a route does is to read it directly.

---

## 8. The Next.js frontend

`../control-panel/` is a separate Next.js app (its own `package.json`,
deployed independently of the Python backend) that calls every route
above via a BFF (Backend-for-Frontend) session — the browser holds one
httpOnly, encrypted session cookie and never a raw OIDC token; the
Next.js *server* attaches `Authorization: Bearer <token>` when it calls
this API. See [`../control-panel/README.md`](../control-panel/README.md)
for its architecture.

With the backend already running (steps 1–6 above):

```bash
cd control-panel
pnpm install
cp .env.local.example .env.local
# Edit .env.local: CONTROL_PLANE_API_URL (this API's URL), OIDC_ISSUER/
# OIDC_CLIENT_ID (same realm/client as CONTROL_PLANE_OIDC_ISSUER/AUDIENCE
# above), OIDC_REDIRECT_URI, and a real SESSION_SECRET
# (`openssl rand -base64 32`).
pnpm dev
```

Open `http://localhost:3001`, sign in with the same Keycloak
credentials used above (`alice`/`alice` against the bundled dev realm) —
the break-glass bootstrap fires on this first login exactly like it does
for the `curl`-driven `GET /auth/me` in step 5, landing you as
`system#owner`.

---

## 9. Next steps

- **Rate limiting / secrets hardening.** Already shipped (CP-16, CP-17)
  — the service-account secret-verification path locks out after
  repeated failures per account id, and a revoked/rotated secret's hash
  is actually invalidated, not just flagged.
- **Production deployment.** This doc is a local dev walkthrough. For
  anything beyond that: run behind TLS termination, don't reuse the dev
  Keycloak realm/credentials, and read `ControlPlaneSettings`'s own
  docstrings for every tunable (cache size, migration concurrency, rate
  limit thresholds). The frontend's own `SESSION_SECRET` needs the same
  treatment — a real random value, not the placeholder in
  `.env.local.example`.
- **Scaling to more than one control-plane API instance.** `JobRunner`
  (CP-7, backing the Migrations screen's job progress) and the default
  `InMemoryRateLimiter` (CP-16) are both single-process by design for
  v1 — configure `CONTROL_PLANE_REDIS_URL` for the rate limiter to share
  state across instances; a real job queue for `control_plane_jobs`
  would be new work if that ever becomes the bottleneck.
