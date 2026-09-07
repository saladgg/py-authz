-- Backs the control-plane API's service-account CRUD
-- (py_authz/control_plane/service_accounts.py). `secret_hash` is an
-- argon2 hash — the plaintext secret is shown exactly once at
-- create/rotate time and never persisted anywhere.
CREATE TABLE IF NOT EXISTS service_accounts (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    description TEXT,
    secret_hash TEXT NOT NULL,
    scopes TEXT[] NOT NULL DEFAULT '{}',
    created_by TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_used_at TIMESTAMPTZ,
    revoked_at TIMESTAMPTZ
);

-- Revoked accounts are soft-deleted (see `revoked_at`) so past audit-log
-- entries attributing actions to this id remain meaningful; the unique
-- name constraint is scoped to non-revoked rows so a revoked account's
-- name can be reused by a new one.
CREATE UNIQUE INDEX IF NOT EXISTS idx_service_accounts_active_name
    ON service_accounts (name)
    WHERE revoked_at IS NULL;
