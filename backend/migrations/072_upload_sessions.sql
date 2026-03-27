-- Chunked/resumable upload sessions and chunk tracking.
-- Separate from the peer-transfer tables (029_transfer_sessions) to avoid
-- coupling client uploads with inter-node replication.

CREATE TABLE upload_sessions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id),
    repository_id UUID NOT NULL REFERENCES repositories(id),
    repository_key TEXT NOT NULL,
    artifact_path TEXT NOT NULL,
    content_type TEXT DEFAULT 'application/octet-stream',
    total_size BIGINT NOT NULL,
    chunk_size INT NOT NULL DEFAULT 8388608,
    total_chunks INT NOT NULL,
    completed_chunks INT NOT NULL DEFAULT 0,
    bytes_received BIGINT NOT NULL DEFAULT 0,
    checksum_sha256 VARCHAR(128) NOT NULL,
    temp_file_path TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','in_progress','completed','failed','cancelled')),
    error_message TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL DEFAULT NOW() + INTERVAL '24 hours'
);

CREATE TABLE upload_chunks (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    session_id UUID NOT NULL REFERENCES upload_sessions(id) ON DELETE CASCADE,
    chunk_index INT NOT NULL,
    byte_offset BIGINT NOT NULL,
    byte_length INT NOT NULL,
    checksum_sha256 VARCHAR(128),
    status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','completed','failed')),
    completed_at TIMESTAMPTZ,
    UNIQUE(session_id, chunk_index)
);

CREATE INDEX idx_upload_sessions_user ON upload_sessions(user_id);
CREATE INDEX idx_upload_sessions_status ON upload_sessions(status);
CREATE INDEX idx_upload_sessions_expires ON upload_sessions(expires_at);
CREATE INDEX idx_upload_chunks_session ON upload_chunks(session_id);
