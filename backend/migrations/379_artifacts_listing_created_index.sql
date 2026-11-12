-- no-transaction
-- 379_artifacts_listing_created_index.sql
-- #5040: the flat artifact listing sorted by creation time
-- (`GET /api/v1/repositories/{key}/artifacts?sort_by=created_at`), same shape
-- as 378 on `(repository_id, created_at, id)`.
--
-- Cost: two scans of `artifacts` under SHARE UPDATE EXCLUSIVE, which blocks no
-- reads or writes; the build first waits for transactions already open on the
-- table. An interrupted build is dropped and retried at the next boot
-- (registered in `migration_repair::CONCURRENT_INDEX_MIGRATIONS`). Down path:
-- drop the index by name.
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_artifacts_repo_created_id
    ON artifacts (repository_id, created_at, id)
    WHERE is_deleted = false;
