-- 279_proxy_download_statistics_keep_history.sql
-- #3844 / #4539: evicting a proxy cache entry no longer deletes its download
-- history. The `proxy_cache_id` foreign key was ON DELETE CASCADE (migration
-- 160); it becomes ON DELETE SET NULL, so a row whose cache entry was evicted
-- (lifecycle_service/proxy_cache.rs) or purged survives, keyed on the
-- `(repository_id, path)` that 277/278 gave it. Deleting the repository still
-- deletes the history (277's repository foreign key).
--
-- Cost on a million-row table: no scan, but ACCESS EXCLUSIVE on BOTH
-- `proxy_download_statistics` and `proxy_cache_artifacts` (dropping and
-- re-adding a foreign key locks the referenced table too) for the catalogue
-- update. `proxy_cache_artifacts` is read by every proxy serve, so proxy
-- serves wait for at most lock_timeout (5 s) while this commits. The locks
-- are taken up front in the serve path's order (`record_proxy_download`
-- upserts the catalog, then inserts the statistics row) so the migration
-- cannot deadlock with a serve. DROP NOT NULL does not scan; the replacement
-- foreign key is NOT VALID (every existing row satisfied the one it replaces,
-- and the ON DELETE action applies to every row regardless).
SET LOCAL lock_timeout = '5s';

LOCK TABLE proxy_cache_artifacts, proxy_download_statistics IN ACCESS EXCLUSIVE MODE;

ALTER TABLE proxy_download_statistics
    ALTER COLUMN proxy_cache_id DROP NOT NULL;

ALTER TABLE proxy_download_statistics
    DROP CONSTRAINT IF EXISTS proxy_download_statistics_proxy_cache_id_fkey;

ALTER TABLE proxy_download_statistics
    ADD CONSTRAINT proxy_download_statistics_proxy_cache_id_fkey
    FOREIGN KEY (proxy_cache_id) REFERENCES proxy_cache_artifacts(id) ON DELETE SET NULL NOT VALID;
