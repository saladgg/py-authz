-- Backs PostgresTenantStore (py_authz/storage/postgres.py).
CREATE TABLE IF NOT EXISTS tenants (
    tenant_id TEXT PRIMARY KEY,
    store_id TEXT NOT NULL
);
