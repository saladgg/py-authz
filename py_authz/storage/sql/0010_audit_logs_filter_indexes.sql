-- py-authz: no-transaction
-- REL3-15: audit queries filtered by user or resource, without a tenant,
-- used to walk the timestamp index across every row. These match the
-- query's keyset order ("timestamp" DESC, id DESC). Built CONCURRENTLY so
-- an upgrade doesn't block audit writes on a large table.
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_audit_logs_user_timestamp
    ON audit_logs (user_id, "timestamp" DESC, id DESC);
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_audit_logs_resource_timestamp
    ON audit_logs (resource, "timestamp" DESC, id DESC);
