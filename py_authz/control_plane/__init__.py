"""
The control-plane API: an optional, thin HTTP shell around `py_authz`'s
existing `Authz`/`MultiTenantAuthz`/`TenantManager`/`ModelSync`/
`MigrationManager` surface, plus the net-new pieces the library never had
(service accounts, operator RBAC, model version history, audit
querying). See `docs/todos/09_control_panel.md` for the design this
implements.

Requires the `py-authz[control-plane]` extra (FastAPI, Postgres, Redis,
PyJWT, argon2-cffi). `create_app()` is the one entry point most
deployments need:

    from py_authz.control_plane.app import create_app
    app = create_app()  # reads ControlPlaneSettings.from_env()

Everything else in this package (`rbac_model`, `security`,
`service_accounts`, `operators`, `model_versions`, `jobs`, `auth`) is
importable independently for a deployment that wants to reuse a piece
without the FastAPI app itself.
"""
