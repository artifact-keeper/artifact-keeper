-- Enhance download_statistics with source tracking, range support,
-- safe FK semantics, proxy cache artifact linkage, and nullable
-- artifact_id for proxy downloads (no local artifact row exists).

-- Allow artifact_id to be NULL so proxy/remote downloads (which
-- don't create artifacts table rows) can still be recorded.
ALTER TABLE download_statistics ALTER COLUMN artifact_id DROP NOT NULL;
--
-- NOTE: if download_statistics exceeds ~100M rows, add monthly partitioning via
-- pg_partman. PK must change to (id, downloaded_at) for partitioning.

-- New columns for download analytics
ALTER TABLE download_statistics
    ADD COLUMN source VARCHAR(32) NOT NULL DEFAULT 'proxy',
    ADD COLUMN byte_range VARCHAR(64),
    ADD COLUMN session_id UUID,
    ADD COLUMN proxy_cache_artifact_id UUID;

-- Constrain source to known values
ALTER TABLE download_statistics
    ADD CONSTRAINT chk_download_statistics_source
    CHECK (source IN (
        'proxy',
        'redirect-s3',
        'redirect-cloudfront',
        'redirect-azure',
        'redirect-gcs'
    ));

-- Replace ON DELETE CASCADE with SET NULL so deleting a popular artifact
-- doesn't cascade-delete millions of download rows (long table lock).
ALTER TABLE download_statistics
    DROP CONSTRAINT download_statistics_artifact_id_fkey,
    ADD CONSTRAINT download_statistics_artifact_id_fkey
    FOREIGN KEY (artifact_id) REFERENCES artifacts(id)
    ON DELETE SET NULL;

-- Link proxy cache artifacts to download rows
ALTER TABLE download_statistics
    ADD CONSTRAINT fk_download_statistics_proxy_cache_artifact
    FOREIGN KEY (proxy_cache_artifact_id) REFERENCES proxy_cache_artifacts(id)
    ON DELETE SET NULL;

-- Index for proxy cache download queries
CREATE INDEX idx_download_stats_proxy_cache_artifact
    ON download_statistics(proxy_cache_artifact_id, downloaded_at);
