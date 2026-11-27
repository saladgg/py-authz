-- ARCH3-16: audit events record both the tenant id and the OpenFGA store
-- id. Before this, `audit_logs.tenant_id` held the store id. Rows written
-- before the upgrade keep that value and have `store_id` NULL;
-- `PostgresAuditQuery` still finds them by tenant (see its `legacy_store_id`
-- filter), and `audit_logs_backfill_0009.example.sql` rewrites them if you
-- want the columns consistent.
--
-- Adding a nullable column without a default only touches the catalog,
-- but it still needs a brief ACCESS EXCLUSIVE lock. The lock_timeout
-- makes the migration fail fast instead of queueing behind a long-running
-- read, which would block every audit INSERT queued behind it.
SET LOCAL lock_timeout = '5s';
ALTER TABLE audit_logs ADD COLUMN IF NOT EXISTS store_id TEXT;
