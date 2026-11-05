-- no-transaction
-- 313_download_statistics_downloaded_at_index.sql
-- #4963: the statistics retention pass (`download_stats_retention`) finds
-- expired rows by download time. No index led on it, so the last batch of every
-- pass, which by definition runs out of expired rows, read the whole table.
--
-- A plain B-tree, not a partial index (the cutoff moves) and not BRIN: the pass
-- frees the oldest pages and new rows reuse them, so heap order stops following
-- time. It adds one index entry to every recorded download.
--
-- Cost on a million-row table: two scans of `download_statistics` under SHARE
-- UPDATE EXCLUSIVE, which blocks no reads or writes; the build first waits for
-- transactions already open on the table. An interrupted build is dropped and
-- retried at the next boot (registered in
-- `migration_repair::CONCURRENT_INDEX_MIGRATIONS`). Down path: drop the index by
-- name; nothing in 1.11 uses it.
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_download_stats_downloaded_at
    ON download_statistics (downloaded_at);
