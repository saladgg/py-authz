-- Backs the control-plane API's async job system
-- (py_authz/control_plane/jobs.py, CP-7) — what a "sync"/"migrate"/
-- "provision"/"deprovision" request that would otherwise block for the
-- duration of a same-shape CLI command runs as instead: insert a
-- `pending` row, run the work in the background, update the row as it
-- progresses.
CREATE TABLE IF NOT EXISTS control_plane_jobs (
    id TEXT PRIMARY KEY,
    kind TEXT NOT NULL,
    status TEXT NOT NULL,
    params_json JSONB,
    result_json JSONB,
    initiated_by TEXT,
    started_at TIMESTAMPTZ,
    finished_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- The obvious query shape: job history, newest first.
CREATE INDEX IF NOT EXISTS idx_control_plane_jobs_created
    ON control_plane_jobs (created_at DESC);
