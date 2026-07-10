-- Proxy cache artifacts table.
--
-- Tracks every artifact cached by a remote (proxy) repository.
-- Each row corresponds to one cached upstream file with its metadata.
--
-- NOTE: if proxy_cache_artifacts exceeds ~100M rows, add monthly
-- partitioning via pg_partman.

CREATE TABLE IF NOT EXISTS proxy_cache_artifacts (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    repository_id UUID NOT NULL REFERENCES repositories(id) ON DELETE CASCADE,
    path TEXT NOT NULL,
    storage_key TEXT NOT NULL,
    size_bytes BIGINT NOT NULL DEFAULT 0,
    checksum_sha256 VARCHAR(64),
    content_type VARCHAR(255),
    cached_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ,
    etag VARCHAR(255),
    last_modified TIMESTAMPTZ,
    ttl_secs INTEGER
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_proxy_cache_repo_key
    ON proxy_cache_artifacts(repository_id, storage_key);

CREATE INDEX IF NOT EXISTS idx_proxy_cache_repo_id
    ON proxy_cache_artifacts(repository_id);

CREATE INDEX IF NOT EXISTS idx_proxy_cache_expires
    ON proxy_cache_artifacts(expires_at)
    WHERE expires_at IS NOT NULL;
