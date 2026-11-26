-- #6504: evicting a proxy cache entry no longer rewrites its download history.
--
-- 279 made `proxy_download_statistics.proxy_cache_id` reference
-- `proxy_cache_artifacts(id)` with ON DELETE SET NULL, so the history of an
-- evicted entry survives (#4539). The cost was one non-HOT UPDATE per history
-- row inside every eviction DELETE (`proxy_cache_id` is indexed), so the most
-- downloaded packages were the most expensive to evict.
--
-- Every history row carries `(repository_id, path)` since 277/278, and every
-- reader joins `proxy_cache_id` to `proxy_cache_artifacts.id`, so an id whose
-- entry is gone answers the same as NULL. Cache ids are random UUIDs, so a
-- stale id never matches a later entry. The rows are kept, only the rewrite
-- goes. The previous release does not rely on the NULL either.

SET LOCAL lock_timeout = '5s';

ALTER TABLE proxy_download_statistics
    DROP CONSTRAINT IF EXISTS proxy_download_statistics_proxy_cache_id_fkey;
