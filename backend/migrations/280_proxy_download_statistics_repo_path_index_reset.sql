-- 280_proxy_download_statistics_repo_path_index_reset.sql
-- Clear any index left INVALID by an interrupted concurrent build of 281,
-- which is `-- no-transaction` and re-runs in full if it fails
-- (docs/operations/online-migrations.md "Index build").
DROP INDEX IF EXISTS idx_proxy_dl_stats_repo_path;
