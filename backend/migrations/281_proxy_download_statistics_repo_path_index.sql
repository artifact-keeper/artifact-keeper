-- no-transaction
-- 281_proxy_download_statistics_repo_path_index.sql
-- #3844 / #4539: serves the per-path download counts of a Remote
-- repository's listing (`proxy_catalog::download_counts_by_paths`), the
-- per-repository totals and the repository foreign key's ON DELETE CASCADE,
-- all keyed on `(repository_id, path)` instead of the catalog id so they
-- survive eviction.
--
-- Cost on a million-row table: two scans of `proxy_download_statistics` under
-- SHARE UPDATE EXCLUSIVE, which blocks no reads or writes; the build first
-- waits for transactions already open on the table. An interrupted build is
-- dropped and retried at the next boot (registered in
-- `migration_repair::CONCURRENT_INDEX_MIGRATIONS`).
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_proxy_dl_stats_repo_path
    ON proxy_download_statistics (repository_id, path, downloaded_at);
