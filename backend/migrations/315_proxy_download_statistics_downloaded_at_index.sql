-- no-transaction
-- 315_proxy_download_statistics_downloaded_at_index.sql
-- #4963: the proxy half of 313, for the same retention pass and for the same
-- reason a plain B-tree.
--
-- Cost on a million-row table: two scans of `proxy_download_statistics` under
-- SHARE UPDATE EXCLUSIVE, which blocks no reads or writes; the build first waits
-- for transactions already open on the table. An interrupted build is dropped
-- and retried at the next boot (registered in
-- `migration_repair::CONCURRENT_INDEX_MIGRATIONS`). Down path: drop the index by
-- name; nothing in 1.11 uses it.
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_proxy_dl_stats_downloaded_at
    ON proxy_download_statistics (downloaded_at);
