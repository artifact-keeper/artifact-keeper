-- Generic upload bodies staged on a repository's object-storage backend (#3916).
--
-- A raw PUT into an S3/GCS/Azure repository streams its body into
-- `generic-upload-staging/<uuid>` on that repository's backend, then copies it
-- to its content-addressed key and deletes the staging object. The row is
-- written BEFORE the first byte and deleted with the object, so an upload
-- killed mid-flight (crash, eviction, shutdown) leaves a row the hourly sweep
-- (`sweep_stale_generic_upload_staging`) uses to find and delete the orphan.
-- Tracking in the database rather than listing the prefix keeps the sweep
-- bounded and works on every backend, including Azure, which has no list
-- operation here.
CREATE TABLE IF NOT EXISTS generic_upload_staging (
    storage_key     TEXT PRIMARY KEY,
    storage_backend TEXT NOT NULL,
    storage_path    TEXT NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_generic_upload_staging_created_at
    ON generic_upload_staging (created_at);
