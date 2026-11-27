-- OPTIONAL one-off backfill after migration 0009 (ARCH3-16).
--
-- NOT applied by `apply_schema()` and not in `SCHEMA_FILES`. Before 0009,
-- `audit_logs.tenant_id` held the OpenFGA store id. This rewrites those
-- rows so `store_id` holds the store id and `tenant_id` the tenant id,
-- using the current `tenants` mapping. Rows for a store that no longer
-- maps to a tenant (deprovisioned, or the RBAC store) get `store_id` set
-- and `tenant_id` cleared.
--
-- You don't need it: `PostgresAuditQuery` (and `GET /audit-logs`) already
-- find a tenant's pre-0009 rows through its current store id. Run it if
-- other tools read `audit_logs` directly.
--
-- Runs in bounded batches so no single statement holds row locks for
-- long. Repeat each statement until it updates 0 rows.

-- 1. Rows whose store maps to a known tenant.
UPDATE audit_logs a
SET store_id = a.tenant_id, tenant_id = t.tenant_id
FROM tenants t
WHERE t.store_id = a.tenant_id
AND a.id IN (
    SELECT a2.id FROM audit_logs a2
    JOIN tenants t2 ON t2.store_id = a2.tenant_id
    WHERE a2.store_id IS NULL
    LIMIT 10000
);

-- 2. Whatever is left (no tenant maps to that store any more). Run only
--    after step 1 reports 0 rows.
UPDATE audit_logs
SET store_id = tenant_id, tenant_id = NULL
WHERE id IN (
    SELECT id FROM audit_logs WHERE store_id IS NULL AND tenant_id IS NOT NULL LIMIT 10000
);
