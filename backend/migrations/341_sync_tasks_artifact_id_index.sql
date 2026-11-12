-- no-transaction
-- 341_sync_tasks_artifact_id_index.sql
-- #5624: `sync_tasks.artifact_id` had no index (every other index leads on
-- `peer_instance_id`), so each deleted `artifacts` row scanned `sync_tasks`
-- for its foreign-key action (the `ON DELETE SET NULL` from 340, the CASCADE
-- before it): most of a repository-delete batch's time, and quadratic as that
-- job queues peer deletes into the same table. The sync worker's sweep of tasks
-- whose artifact is gone (`artifact_id IS NULL`) is served by the same index: a
-- B-tree stores NULLs, and `IS NULL` is an indexable condition.
--
-- Cost: two scans of `sync_tasks` under SHARE UPDATE EXCLUSIVE, which blocks no
-- reads or writes; the build first waits for transactions already open on the
-- table, so a long-running transaction delays it (as for 297). An interrupted
-- build is dropped and retried at the next boot (registered in
-- `migration_repair::CONCURRENT_INDEX_MIGRATIONS`). Down path: drop the index
-- by name.
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_sync_tasks_artifact_id
    ON sync_tasks (artifact_id);
