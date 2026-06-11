-- Mark upload sessions created by peer replication.
--
-- The generic resumable upload API is also used by inter-peer replication.
-- Keeping this flag lets retry/recovery cleanup remove only replication-owned
-- leftovers without touching ordinary client resumable uploads.

ALTER TABLE upload_sessions
    ADD COLUMN IF NOT EXISTS is_replication BOOLEAN NOT NULL DEFAULT false;

UPDATE upload_sessions
SET is_replication = true
WHERE is_replication = false
  AND (
      artifact_metadata_format IS NOT NULL
      OR artifact_metadata IS NOT NULL
      OR artifact_metadata_properties IS NOT NULL
      OR package_description IS NOT NULL
      OR package_metadata IS NOT NULL
  );

CREATE INDEX IF NOT EXISTS idx_upload_sessions_replication_path
    ON upload_sessions (repository_id, artifact_path)
    WHERE is_replication = true;
