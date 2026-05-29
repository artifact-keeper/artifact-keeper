-- Track immutable storage parts for OCI chunked uploads.
--
-- This lets PATCH append new data without downloading and rewriting the
-- previous temporary object, and lets final PUT concatenate parts by streaming.
ALTER TABLE oci_upload_sessions
    ADD COLUMN IF NOT EXISTS state TEXT NOT NULL DEFAULT 'open';

ALTER TABLE oci_upload_sessions
    ADD COLUMN IF NOT EXISTS state_token UUID;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM pg_constraint
        WHERE conname = 'chk_oci_upload_sessions_state'
          AND conrelid = 'oci_upload_sessions'::regclass
    ) THEN
        ALTER TABLE oci_upload_sessions
            ADD CONSTRAINT chk_oci_upload_sessions_state
            CHECK (state IN ('open', 'committing'));
    END IF;
END $$;

CREATE TABLE IF NOT EXISTS oci_upload_parts (
    id BIGSERIAL PRIMARY KEY,
    upload_session_id UUID NOT NULL REFERENCES oci_upload_sessions(id) ON DELETE CASCADE,
    part_index INTEGER NOT NULL CONSTRAINT chk_oci_upload_parts_part_index CHECK (part_index >= 0),
    storage_key TEXT NOT NULL,
    size_bytes BIGINT NOT NULL CONSTRAINT chk_oci_upload_parts_size_bytes CHECK (size_bytes >= 0),
    digest_sha256 TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(upload_session_id, part_index)
);

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM pg_constraint
        WHERE conname = 'chk_oci_upload_parts_part_index'
          AND conrelid = 'oci_upload_parts'::regclass
    ) THEN
        ALTER TABLE oci_upload_parts
            ADD CONSTRAINT chk_oci_upload_parts_part_index
            CHECK (part_index >= 0);
    END IF;

    IF NOT EXISTS (
        SELECT 1
        FROM pg_constraint
        WHERE conname = 'chk_oci_upload_parts_size_bytes'
          AND conrelid = 'oci_upload_parts'::regclass
    ) THEN
        ALTER TABLE oci_upload_parts
            ADD CONSTRAINT chk_oci_upload_parts_size_bytes
            CHECK (size_bytes >= 0);
    END IF;
END $$;

CREATE INDEX IF NOT EXISTS idx_oci_upload_parts_session
    ON oci_upload_parts(upload_session_id, part_index);
