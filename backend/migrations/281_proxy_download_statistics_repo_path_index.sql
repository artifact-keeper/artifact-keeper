-- no-transaction
-- 281_proxy_download_statistics_repo_path_index.sql
-- #3844 / #4539: serves the per-path download counts of a Remote
-- repository's listing (`proxy_catalog::download_counts_by_paths`) and the
-- per-repository totals, both now keyed on `(repository_id, path)` instead of
-- the catalog id so they survive eviction. Built online.
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_proxy_dl_stats_repo_path
    ON proxy_download_statistics (repository_id, path, downloaded_at);
