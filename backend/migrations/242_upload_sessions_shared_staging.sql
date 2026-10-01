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
--
-- `staging_storage_backend` / `staging_storage_path`: the repository's
-- storage location captured when the session is created, so the staged
-- chunks stay findable after the repository row is gone.
--
-- `upload_staging_orphans`: when a session row that still owns staged chunks
-- is deleted — a repository or user deletion cascades `upload_sessions`
-- (migrations 125, 200), or a replication retry removes a stale session — a
-- trigger records what to delete, and the reaper purges it. Without it those
-- rows were the only record of the objects.

-- Fail fast instead of queueing every upload behind a long transaction while
-- waiting for the ACCESS EXCLUSIVE lock (precedent: 232, 237).
SET LOCAL lock_timeout = '5s';

ALTER TABLE upload_sessions
    ADD COLUMN IF NOT EXISTS staged_in_storage BOOLEAN NOT NULL DEFAULT FALSE,
    ADD COLUMN IF NOT EXISTS staging_purged_at TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS staging_storage_backend TEXT,
    ADD COLUMN IF NOT EXISTS staging_storage_path TEXT;

CREATE INDEX IF NOT EXISTS idx_upload_sessions_unpurged_staging
    ON upload_sessions (updated_at)
    WHERE staged_in_storage AND staging_purged_at IS NULL;

CREATE TABLE IF NOT EXISTS upload_staging_orphans (
    session_id UUID PRIMARY KEY,
    total_chunks INT NOT NULL,
    storage_backend TEXT NOT NULL,
    storage_path TEXT NOT NULL,
    -- Failed purge attempts; the reaper gives up (and logs) at 24.
    attempts INT NOT NULL DEFAULT 0,
    last_error TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE OR REPLACE FUNCTION ak_upload_session_staging_orphan() RETURNS trigger AS $$
BEGIN
    IF OLD.staged_in_storage
       AND OLD.staging_purged_at IS NULL
       AND OLD.staging_storage_backend IS NOT NULL THEN
        INSERT INTO upload_staging_orphans
            (session_id, total_chunks, storage_backend, storage_path)
        VALUES (OLD.id, OLD.total_chunks, OLD.staging_storage_backend,
                COALESCE(OLD.staging_storage_path, ''))
        ON CONFLICT (session_id) DO NOTHING;
    END IF;
    RETURN OLD;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS ak_upload_session_staging_orphan ON upload_sessions;
CREATE TRIGGER ak_upload_session_staging_orphan
    AFTER DELETE ON upload_sessions
    FOR EACH ROW EXECUTE FUNCTION ak_upload_session_staging_orphan();
