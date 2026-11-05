-- 312_download_statistics_downloaded_at_index_reset.sql
-- Drop any leftover idx_download_stats_downloaded_at before 313 builds it, the
-- reset half of the docs/operations/online-migrations.md "Index build" pair. It
-- runs once; a retry of an interrupted build is handled at every boot by
-- `migration_repair::repair_invalid_concurrent_indexes` (the build is
-- registered in `CONCURRENT_INDEX_MIGRATIONS`).
DROP INDEX IF EXISTS idx_download_stats_downloaded_at;
