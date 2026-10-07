-- 280_proxy_download_statistics_repo_path_index_reset.sql
-- Drop any leftover idx_proxy_dl_stats_repo_path before 281 builds it, the
-- reset half of the docs/operations/online-migrations.md "Index build" pair.
-- This runs once and is then recorded, so it does NOT cover a retry of an
-- interrupted 281: that case is handled at every boot by
-- `migration_repair::repair_invalid_concurrent_indexes`, where 281 is
-- registered in `CONCURRENT_INDEX_MIGRATIONS`.
DROP INDEX IF EXISTS idx_proxy_dl_stats_repo_path;
