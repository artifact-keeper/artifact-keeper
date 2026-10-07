-- 282_proxy_download_statistics_ip_index_reset.sql
-- Drop any leftover idx_proxy_dl_stats_ip before 283 builds it, the reset
-- half of the docs/operations/online-migrations.md "Index build" pair. It
-- runs once; a retry of an interrupted 283 is handled at every boot by
-- `migration_repair::repair_invalid_concurrent_indexes` (283 is registered in
-- `CONCURRENT_INDEX_MIGRATIONS`).
DROP INDEX IF EXISTS idx_proxy_dl_stats_ip;
