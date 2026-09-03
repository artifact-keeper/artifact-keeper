-- Proxy-cached objects in the daily storage snapshot.
--
-- Proxy-cached objects carry no `artifacts` row (#1280), so every snapshot
-- counted only hosted objects: on an instance with pull-through remotes the
-- storage trend under-reported both the object count and the bytes, and
-- total_downloads missed every proxy serve. These sibling columns keep the
-- existing totals hosted-only (unchanged meaning for existing consumers) and
-- record the proxy half alongside, mirroring the split already exposed by
-- /admin/stats and the storage breakdown.
--
-- Historic rows are reconstructed where possible by migration 212; anything it
-- cannot recover stays 0, so trends split cleanly only from the first snapshot
-- taken after this deploy.
--
-- `IF NOT EXISTS` so the migration is idempotent on a database that already
-- carries these columns from an out-of-tree build.
ALTER TABLE storage_metrics
    ADD COLUMN IF NOT EXISTS proxy_artifact_count BIGINT NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS proxy_storage_bytes  BIGINT NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS proxy_download_count BIGINT NOT NULL DEFAULT 0;

COMMENT ON COLUMN storage_metrics.proxy_artifact_count IS
    'Proxy-cached objects at snapshot time; 0 for rows predating migration 210';
COMMENT ON COLUMN storage_metrics.proxy_storage_bytes IS
    'Bytes held by proxy-cached objects; 0 for rows predating migration 210';
COMMENT ON COLUMN storage_metrics.proxy_download_count IS
    'Proxy pull-through serves; 0 for rows predating migration 210';
