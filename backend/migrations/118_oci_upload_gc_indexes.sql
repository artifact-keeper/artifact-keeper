-- Indexes backing the OCI upload garbage-collection queries.
--
-- The storage GC sweeps run, on every pass:
--   * a TTL scan of oci_upload_sessions
--     (WHERE updated_at < NOW() - INTERVAL '24 hours' ORDER BY updated_at LIMIT N), and
--   * NOT EXISTS correlated subqueries against oci_upload_sessions.storage_temp_key
--     and oci_upload_parts.storage_key to decide whether an oci_upload_cleanup_keys
--     row is still referenced.
--
-- Migration 026 only indexed oci_upload_sessions(repository_id) and migration 115
-- only indexed oci_upload_parts(upload_session_id, part_index), so the queries
-- above fell back to sequential scans that degrade as these tables grow on a busy
-- registry (up to ~2000 seq scans per GC pass at the 1000-row scan limit). These
-- indexes turn each scan into an index lookup.
CREATE INDEX IF NOT EXISTS idx_oci_upload_sessions_updated_at
    ON oci_upload_sessions(updated_at);

CREATE INDEX IF NOT EXISTS idx_oci_upload_sessions_storage_temp_key
    ON oci_upload_sessions(storage_temp_key);

CREATE INDEX IF NOT EXISTS idx_oci_upload_parts_storage_key
    ON oci_upload_parts(storage_key);
