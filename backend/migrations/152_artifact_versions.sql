-- #2367: first-class versioning for generic/mlmodel artifacts.
--
-- `artifacts` keeps its UNIQUE(repository_id, path) row as the single
-- HEAD/latest pointer (all download/list/quarantine/proxy machinery is
-- unchanged). For repositories that opt in via `versioning_enabled`,
-- every upload to a Generic/Mlmodel repo APPENDS an immutable revision
-- here instead of overwriting (or 409ing) the prior content.
CREATE TABLE artifact_versions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    repository_id UUID NOT NULL REFERENCES repositories(id) ON DELETE CASCADE,
    path VARCHAR(2048) NOT NULL,
    -- Server-managed auto-increment per (repository_id, path), starting at 1.
    revision INTEGER NOT NULL,
    -- Optional human-readable tag supplied by the client
    -- (X-Artifact-Version header on upload).
    version_label VARCHAR(255),
    name VARCHAR(512) NOT NULL,
    size_bytes BIGINT NOT NULL,
    checksum_sha256 CHAR(64) NOT NULL,
    checksum_sha1 CHAR(40),
    checksum_md5 CHAR(32),
    content_type VARCHAR(255) NOT NULL,
    storage_key VARCHAR(2048) NOT NULL,
    uploaded_by UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    UNIQUE (repository_id, path, revision)
);

-- Latest-first listing / max-revision lookup per coordinate.
CREATE INDEX idx_artifact_versions_repo_path_rev
    ON artifact_versions (repository_id, path, revision DESC);

-- Per-repo opt-in flag. DEFAULT false: existing repositories keep the
-- exact current upload semantics (overwrite checks and the
-- release-immutability backstop stay in force).
ALTER TABLE repositories
    ADD COLUMN versioning_enabled BOOLEAN NOT NULL DEFAULT false;
