-- OCI Distribution Spec support: upload sessions, tags, and blob tracking

-- Upload session tracking for chunked blob uploads
CREATE TABLE oci_upload_sessions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    repository_id UUID NOT NULL REFERENCES repositories(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES users(id),
    bytes_received BIGINT NOT NULL DEFAULT 0,
    storage_temp_key TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_oci_upload_sessions_repo ON oci_upload_sessions(repository_id);

-- Tag-to-digest mapping for OCI manifests
CREATE TABLE oci_tags (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    repository_id UUID NOT NULL REFERENCES repositories(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    tag TEXT NOT NULL,
    manifest_digest TEXT NOT NULL,
    manifest_content_type TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(repository_id, name, tag)
);

CREATE INDEX idx_oci_tags_repo_name ON oci_tags(repository_id, name);
CREATE INDEX idx_oci_tags_digest ON oci_tags(manifest_digest);

-- Blob tracking per repository
CREATE TABLE oci_blobs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    repository_id UUID NOT NULL REFERENCES repositories(id) ON DELETE CASCADE,
    digest TEXT NOT NULL,
    size_bytes BIGINT NOT NULL,
    storage_key TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(repository_id, digest)
);

CREATE INDEX idx_oci_blobs_repo_digest ON oci_blobs(repository_id, digest);
