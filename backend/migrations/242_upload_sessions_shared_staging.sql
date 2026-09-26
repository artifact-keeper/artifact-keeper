-- Chunked upload staging moves from per-replica local disk to the
-- repository's storage backend (#3918), with a durable purge marker so staged
-- chunks of failed, cancelled and abandoned sessions are reclaimed (#3922).
--
-- Before this, `upload_sessions.temp_file_path` was an absolute path on the
-- local disk of whichever replica served `POST /api/v1/uploads`. Behind more
-- than one replica a PATCH or the completion routed elsewhere could not find
-- it, and a failed completion left the assembled file behind with nothing to
-- reclaim it.
--
-- `staged_in_storage`: TRUE for sessions whose chunks are staged as one
-- object per chunk in the repository's storage backend, keyed off the session
-- id. Rows created by an older server version keep the default FALSE: their
-- bytes live in `temp_file_path` on some replica's local disk, which this
-- version cannot continue, so it refuses them with a clear error and only
-- removes the local file when reaping.
--
-- `staging_purged_at`: set once a session's staged chunk objects have been
-- deleted. A terminal session (completed/failed/cancelled) with
-- `staged_in_storage` and no purge timestamp still owns staged bytes; the
-- hourly upload reaper claims and deletes those, on any replica.
ALTER TABLE upload_sessions
    ADD COLUMN IF NOT EXISTS staged_in_storage BOOLEAN NOT NULL DEFAULT FALSE,
    ADD COLUMN IF NOT EXISTS staging_purged_at TIMESTAMPTZ;

CREATE INDEX IF NOT EXISTS idx_upload_sessions_unpurged_staging
    ON upload_sessions (updated_at)
    WHERE staged_in_storage AND staging_purged_at IS NULL;
