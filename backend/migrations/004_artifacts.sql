-- Create artifacts table
CREATE TABLE artifacts (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    repository_id UUID NOT NULL REFERENCES repositories(id) ON DELETE CASCADE,
    path VARCHAR(2048) NOT NULL,
    name VARCHAR(512) NOT NULL,
    version VARCHAR(255),
    size_bytes BIGINT NOT NULL,
    checksum_sha256 CHAR(64) NOT NULL,
    checksum_md5 CHAR(32),
    checksum_sha1 CHAR(40),
    content_type VARCHAR(255) NOT NULL,
    storage_key VARCHAR(2048) NOT NULL,
    is_deleted BOOLEAN NOT NULL DEFAULT false,
    uploaded_by UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    UNIQUE(repository_id, path)
);

-- Create artifact_metadata table
CREATE TABLE artifact_metadata (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    artifact_id UUID UNIQUE NOT NULL REFERENCES artifacts(id) ON DELETE CASCADE,
    format VARCHAR(50) NOT NULL,
    metadata JSONB NOT NULL,
    properties JSONB NOT NULL DEFAULT '{}'
);

-- Create download_statistics table
CREATE TABLE download_statistics (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    artifact_id UUID NOT NULL REFERENCES artifacts(id) ON DELETE CASCADE,
    user_id UUID REFERENCES users(id) ON DELETE SET NULL,
    ip_address INET NOT NULL,
    user_agent VARCHAR(512),
    downloaded_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

-- Create indexes
CREATE INDEX idx_artifacts_repo_path ON artifacts(repository_id, path);
CREATE INDEX idx_artifacts_repo_name_version ON artifacts(repository_id, name, version);
CREATE INDEX idx_artifacts_checksum ON artifacts(checksum_sha256);
CREATE INDEX idx_artifacts_name_gin ON artifacts USING gin(name gin_trgm_ops);
CREATE INDEX idx_artifact_metadata_gin ON artifact_metadata USING gin(metadata);
CREATE INDEX idx_download_stats_artifact ON download_statistics(artifact_id, downloaded_at);
CREATE INDEX idx_download_stats_user ON download_statistics(user_id, downloaded_at);

-- Enable pg_trgm extension for text search
CREATE EXTENSION IF NOT EXISTS pg_trgm;
