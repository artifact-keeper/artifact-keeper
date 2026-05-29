-- Durable cleanup journal for OCI upload temporary storage objects.
--
-- Upload temp keys are written to storage before the corresponding session/part
-- row is durable. If the DB write then fails and the compensating storage
-- delete also fails, the key would otherwise have no discoverable owner.
CREATE TABLE IF NOT EXISTS oci_upload_cleanup_keys (
    id BIGSERIAL PRIMARY KEY,
    repository_id UUID NOT NULL REFERENCES repositories(id) ON DELETE CASCADE,
    upload_session_id UUID,
    storage_key TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    storage_write_completed_at TIMESTAMPTZ,
    UNIQUE(storage_key)
);

CREATE INDEX IF NOT EXISTS idx_oci_upload_cleanup_keys_created
    ON oci_upload_cleanup_keys(created_at);

CREATE INDEX IF NOT EXISTS idx_oci_upload_cleanup_keys_storage_write_completed
    ON oci_upload_cleanup_keys(storage_write_completed_at);

CREATE INDEX IF NOT EXISTS idx_oci_upload_cleanup_keys_repo
    ON oci_upload_cleanup_keys(repository_id);
