-- Incus/LXC chunked upload sessions for resumable large image uploads.
-- Each session tracks an in-progress upload with a temp file on disk.
-- Sessions are cleaned up on completion, cancellation, or by the admin
-- cleanup endpoint after 24 hours of inactivity.

CREATE TABLE incus_upload_sessions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    repository_id UUID NOT NULL REFERENCES repositories(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES users(id),
    artifact_path TEXT NOT NULL,
    product TEXT NOT NULL,
    version TEXT NOT NULL,
    filename TEXT NOT NULL,
    bytes_received BIGINT NOT NULL DEFAULT 0,
    storage_temp_path TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_incus_upload_sessions_repo ON incus_upload_sessions(repository_id);
CREATE INDEX idx_incus_upload_sessions_updated ON incus_upload_sessions(updated_at);
