-- no-transaction
-- 345_artifacts_listing_size_index.sql
-- #5040: the flat artifact listing sorted by size
-- (`GET /api/v1/repositories/{key}/artifacts?sort_by=size`) pages a repository
-- with `WHERE repository_id = $1 AND is_deleted = false ... ORDER BY size_bytes,
-- id` and continues from a `(size_bytes, id)` keyset. Without an index leading
-- on `(repository_id, size_bytes)` every page reads and sorts all of the
-- repository's rows. Partial on `is_deleted = false` like the listing, which
-- never shows tombstoned artifacts. The created-at order is 346.
--
-- Cost: two scans of `artifacts` under SHARE UPDATE EXCLUSIVE, which blocks no
-- reads or writes; the build first waits for transactions already open on the
-- table. An interrupted build is dropped and retried at the next boot
-- (registered in `migration_repair::CONCURRENT_INDEX_MIGRATIONS`). Down path:
-- drop the index by name.
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_artifacts_repo_size_id
    ON artifacts (repository_id, size_bytes, id)
    WHERE is_deleted = false;
