-- Backs PostgresAuditQuery (py_authz/audit/postgres.py, CP-5). The
-- existing `idx_audit_logs_tenant_timestamp` (0003) is a composite index
-- on (tenant_id, "timestamp") and doesn't cover a query filtering by
-- time range alone (e.g. the control-plane API's audit log screen with
-- no tenant selected) — this plain index does.
CREATE INDEX IF NOT EXISTS idx_audit_logs_timestamp
    ON audit_logs ("timestamp");
