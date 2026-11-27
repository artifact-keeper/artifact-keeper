-- no-transaction
-- 428_artifacts_index_pending_index.sql
-- #6525: the rows still waiting for their first listing (migration 426's
-- `artifacts.index_pending`). A scan-policy update or delete marks the shards
-- of every pending hosted conda row for rebuild
-- (`index_time::mark_pending_conda_rows_dirty`), and a pending row is cleared
-- the first time a build lists it, so the set is a small, short-lived
-- fraction of the table: the partial index keeps that lookup off a scan of
-- every conda row.
--
-- Cost: two scans of `artifacts` under SHARE UPDATE EXCLUSIVE, which blocks
-- no reads or writes; the build first waits for transactions already open on
-- the table. An interrupted build is dropped and retried at the next boot
-- (registered in `migration_repair::CONCURRENT_INDEX_MIGRATIONS`). Down path:
-- drop the index by name.
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_artifacts_index_pending
    ON artifacts (repository_id)
    WHERE index_pending;
