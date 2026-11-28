-- #5217: presigned OCI blob pulls bypass the serve-time verifier. Record when
-- a background integrity check was last claimed so repeated redirects do not
-- re-read the same layer on every pull.
SET LOCAL lock_timeout = '5s';

-- Expand-only: one nullable column, no rewrite. A previous release ignores it.
ALTER TABLE oci_blobs
    ADD COLUMN IF NOT EXISTS presign_repair_checked_at TIMESTAMPTZ NULL;
