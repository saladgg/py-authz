-- Backs PostgresModelRegistry (py_authz/storage/postgres.py).
CREATE TABLE IF NOT EXISTS tenant_models (
    tenant_id TEXT PRIMARY KEY,
    model_id TEXT NOT NULL
);
