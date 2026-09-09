-- Proxy-cached objects in the daily storage snapshot.
--
-- Proxy-cached objects carry no `artifacts` row (#1280), so every snapshot
-- counted only hosted objects: on an instance with pull-through remotes the
-- storage trend under-reported both the object count and the bytes, and
-- total_downloads missed every proxy serve. These sibling columns record the
-- proxy half explicitly, leaving every existing total byte-for-byte unchanged,
-- mirroring the split already exposed by /admin/stats and the storage
-- breakdown. Note the totals are not uniformly hosted-only: total_artifacts
-- and total_downloads read only the hosted tables, so the new counts are
-- disjoint from them, but total_storage_bytes sums the usage ledger and so
-- ALREADY contains proxy_storage_bytes (migration 182 defines the ledger's
-- proxy_bytes as exactly that sum) — it is a breakdown, do not add the two.
--
-- Historic rows are reconstructed where possible by migration 215; anything it
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
    'Proxy-cached objects at snapshot time; disjoint from total_artifacts. Rows predating migration 210 are reconstructed by 215 as a lower bound, or stay 0';
COMMENT ON COLUMN storage_metrics.proxy_storage_bytes IS
    'Bytes held by proxy-cached objects; a breakdown of total_storage_bytes, not a disjoint bucket (do not add the two). Rows predating migration 210 are reconstructed by 215 as a lower bound, or stay 0';
COMMENT ON COLUMN storage_metrics.proxy_download_count IS
    'Proxy pull-through serves; disjoint from total_downloads. Rows predating migration 210 are reconstructed by 215 as a lower bound, or stay 0';
