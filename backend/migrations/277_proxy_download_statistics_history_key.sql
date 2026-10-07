-- 277_proxy_download_statistics_history_key.sql
-- #3844 / #4539: proxy download history must outlive the cache entry it
-- was served from.
--
-- `proxy_download_statistics` was keyed only on `proxy_cache_id`, which
-- CASCADEs from `proxy_cache_artifacts` (migration 160), and lifecycle
-- eviction deletes that row (#4440), so every eviction erased the download
-- history of what it evicted. This migration adds the coordinate the serve
-- happened at, `(repository_id, path)`, so history is keyed on something an
-- eviction does not delete. 278 backfills it, 279 relaxes the cascade to
-- SET NULL, 280/281 index it.
--
-- Cost on a million-row table: catalogue-only. Two nullable columns with no
-- default, a NOT VALID foreign key (every existing row is NULL until 278 and
-- so satisfies it), and a trigger; each takes ACCESS EXCLUSIVE /
-- SHARE ROW EXCLUSIVE for a catalogue update only, bounded by lock_timeout.
--
-- The trigger fills the key from the catalog row when an insert does not
-- supply it. The application writes both columns itself
-- (`proxy_catalog::record_proxy_download`), so on the hot path the trigger is
-- one NULL test; it exists for the rolling deploy, where pods still running
-- the previous release insert `proxy_cache_id` only, and those rows must not
-- be left unkeyed once 279 stops them being deleted with their cache entry.
SET LOCAL lock_timeout = '5s';

ALTER TABLE proxy_download_statistics
    ADD COLUMN repository_id UUID,
    ADD COLUMN path TEXT;

-- Deleting a repository still deletes its proxy download history, as the
-- catalog cascade did before.
ALTER TABLE proxy_download_statistics
    ADD CONSTRAINT proxy_download_statistics_repository_id_fkey
    FOREIGN KEY (repository_id) REFERENCES repositories(id) ON DELETE CASCADE NOT VALID;

CREATE OR REPLACE FUNCTION proxy_download_statistics_fill_key() RETURNS trigger AS $$
BEGIN
    IF NEW.repository_id IS NULL AND NEW.proxy_cache_id IS NOT NULL THEN
        SELECT c.repository_id, c.path
          INTO NEW.repository_id, NEW.path
          FROM proxy_cache_artifacts c
         WHERE c.id = NEW.proxy_cache_id;
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER proxy_download_statistics_fill_key
    BEFORE INSERT ON proxy_download_statistics
    FOR EACH ROW EXECUTE FUNCTION proxy_download_statistics_fill_key();
