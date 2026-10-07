-- 279_proxy_download_statistics_keep_history.sql
-- #3844 / #4539: evicting a proxy cache entry no longer deletes its
-- download history. The `proxy_cache_id` foreign key was ON DELETE CASCADE
-- (migration 160); it becomes ON DELETE SET NULL, so a row whose cache entry
-- was evicted (lifecycle_service/proxy_cache.rs) or purged survives, keyed on
-- the `(repository_id, path)` that 277/278 gave it. Deleting the repository
-- still deletes the history (277's repository foreign key).
--
-- Cost on a million-row table: catalogue-only. DROP NOT NULL does not scan;
-- the replacement foreign key is NOT VALID (every existing row satisfied the
-- one it replaces, and the ON DELETE action applies to every row regardless).
SET LOCAL lock_timeout = '5s';

ALTER TABLE proxy_download_statistics
    ALTER COLUMN proxy_cache_id DROP NOT NULL;

ALTER TABLE proxy_download_statistics
    DROP CONSTRAINT IF EXISTS proxy_download_statistics_proxy_cache_id_fkey;

ALTER TABLE proxy_download_statistics
    ADD CONSTRAINT proxy_download_statistics_proxy_cache_id_fkey
    FOREIGN KEY (proxy_cache_id) REFERENCES proxy_cache_artifacts(id) ON DELETE SET NULL NOT VALID;
