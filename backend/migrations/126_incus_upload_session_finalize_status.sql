-- Async finalize tracking for incus uploads.
--
-- Both the monolithic PUT and the chunked-upload `complete` now return 202
-- once the request body is staged to local disk, then push the assembled
-- file to the configured StorageBackend on a background task. For a
-- multi-GiB artifact that backend push (e.g. a GCS resumable upload) can run
-- for minutes -- longer than a typical L7 gateway request timeout -- so doing
-- it inside the request returned 504 even though the bytes had been received.
--
-- The background push means the artifact row does not exist when the client
-- gets its 202, so a failed push would otherwise be silently lost. These
-- columns make the finalize outcome observable: the session row carries a
-- status the client polls via `GET /incus/{repo}/uploads/{id}`, the error
-- string on failure, and the resulting artifact id on success.

ALTER TABLE incus_upload_sessions
    ADD COLUMN IF NOT EXISTS status VARCHAR(20) NOT NULL DEFAULT 'receiving',
    ADD COLUMN IF NOT EXISTS finalize_error TEXT,
    ADD COLUMN IF NOT EXISTS artifact_id UUID;

ALTER TABLE incus_upload_sessions
    DROP CONSTRAINT IF EXISTS incus_upload_sessions_status_check;
ALTER TABLE incus_upload_sessions
    ADD CONSTRAINT incus_upload_sessions_status_check
    CHECK (status IN ('receiving', 'finalizing', 'completed', 'failed'));
