-- no-transaction
-- 283_proxy_download_statistics_ip_index.sql
-- #3844 / #4539: `/api/v1/admin/downloads/by-ip/{ip}` now lists proxy serves
-- too. The hosted half is served by idx_download_stats_ip (migration 151);
-- this is its sibling on the proxy table, so the by-IP lookup does not scan
-- every proxy download row.
--
-- Cost on a million-row table: two scans of `proxy_download_statistics` under
-- SHARE UPDATE EXCLUSIVE, which blocks no reads or writes; the build first
-- waits for transactions already open on the table. An interrupted build is
-- dropped and retried at the next boot (registered in
-- `migration_repair::CONCURRENT_INDEX_MIGRATIONS`).
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_proxy_dl_stats_ip
    ON proxy_download_statistics (ip_address, downloaded_at);
