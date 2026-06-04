-- Preserve source artifact metadata across resumable upload sessions.
--
-- Regular client uploads can omit these nullable columns and retain the
-- existing fallback behavior. Peer replication sets them from the source
-- artifact row so chunked replication does not derive name/version from the
-- path at completion time.

ALTER TABLE upload_sessions
    ADD COLUMN IF NOT EXISTS artifact_name TEXT,
    ADD COLUMN IF NOT EXISTS artifact_version TEXT;
