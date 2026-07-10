-- Add repository_id to download_statistics for direct FK to repositories
-- (currently only accessible through artifact_id -> artifacts.repository_id,
-- which fails for proxy-cached downloads that have no artifacts row).
--
-- Also add download_virtual_resolution table to track which virtual repo
-- resolved to which member repo for each download.

-- Direct FK to the repository that served the download.
-- Always populated for new rows; NULL for legacy rows before this migration.
ALTER TABLE download_statistics
    ADD COLUMN repository_id UUID;

ALTER TABLE download_statistics
    ADD CONSTRAINT fk_download_statistics_repository
    FOREIGN KEY (repository_id) REFERENCES repositories(id)
    ON DELETE SET NULL;

CREATE INDEX idx_download_stats_repository
    ON download_statistics(repository_id, downloaded_at);

-- Tracks virtual repository resolution: when a download is served through
-- a virtual repository, this table records which actual member served it.
-- download_statistics.repository_id points to the member;
-- download_virtual_resolution records that the user came via a virtual repo.
CREATE TABLE download_virtual_resolution (
    id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    download_id      UUID NOT NULL REFERENCES download_statistics(id) ON DELETE CASCADE,
    virtual_repo_id  UUID NOT NULL REFERENCES repositories(id),
    UNIQUE (download_id)
);

CREATE INDEX idx_download_virtual_resolution_repo
    ON download_virtual_resolution(virtual_repo_id, download_id);
