-- Backs PostgresAuditLogger (py_authz/audit/postgres.py).
--
-- No retention/partitioning policy is defined here — this table grows
-- without bound under normal operation. Decide a retention window (and
-- likely partition by month on "timestamp") before relying on this in a
-- high-volume production deployment; that's deliberately out of scope
-- for the bundled schema, which only needs to be correct, not optimal
-- for every retention/compliance policy an adopter might need. See
-- `audit_logs_retention.example.sql` (same directory) for a documented
-- periodic-delete query and a native-partitioning migration sketch — it
-- is NOT applied by `apply_schema()`; adapt and run it through your own
-- migration tooling once retention actually matters for your deployment
-- (see REL2-17).
CREATE TABLE IF NOT EXISTS audit_logs (
    id BIGSERIAL PRIMARY KEY,
    "timestamp" TIMESTAMPTZ NOT NULL,
    tenant_id TEXT,
    user_id TEXT NOT NULL,
    action TEXT NOT NULL,
    resource TEXT NOT NULL,
    allowed BOOLEAN NOT NULL,
    reason TEXT,
    reason_data JSONB,
    request_id TEXT
);

-- The obvious query shape: "this tenant's audit trail, newest first".
CREATE INDEX IF NOT EXISTS idx_audit_logs_tenant_timestamp
    ON audit_logs (tenant_id, "timestamp" DESC);
