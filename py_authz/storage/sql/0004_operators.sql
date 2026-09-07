-- Backs the control-plane API's operator record
-- (py_authz/control_plane/operators.py). `subject` is the verified OIDC
-- `sub` claim; an operator's actual role(s) live in the dogfooded RBAC
-- OpenFGA store (see py_authz/control_plane/rbac_model.py), not a column
-- here — this table exists only to remember "this subject has logged in
-- before" (e.g. for a directory/listing screen), not to gate anything.
CREATE TABLE IF NOT EXISTS operators (
    id BIGSERIAL PRIMARY KEY,
    subject TEXT NOT NULL UNIQUE,
    email TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
