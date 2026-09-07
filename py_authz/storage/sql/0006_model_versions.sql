-- Backs the control-plane API's model version history/rollback
-- (py_authz/control_plane/model_versions.py, CP-6). Append-only, unlike
-- `tenant_models` (0002) which keeps meaning "current" — this is the
-- history `tenant_models` never had. `tenant_id` is nullable for the
-- global/single-tenant case.
CREATE TABLE IF NOT EXISTS model_versions (
    id BIGSERIAL PRIMARY KEY,
    tenant_id TEXT,
    model_id TEXT NOT NULL,
    schema_json JSONB NOT NULL,
    change_summary TEXT,
    created_by TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- The obvious query shape: "this tenant's model history, newest first"
-- (or, for the nullable-tenant global case, "the global model history").
CREATE INDEX IF NOT EXISTS idx_model_versions_tenant_created
    ON model_versions (tenant_id, created_at DESC);
