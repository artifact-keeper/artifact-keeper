-- no-transaction
-- 335_mcp_introspection_jobs_snapshot_index.sql
-- #5386: the capability snapshot retention pass deletes old snapshots, and
-- `mcp_introspection_jobs.snapshot_id` references them `ON DELETE SET NULL`.
-- Without an index leading on `snapshot_id`, every deleted snapshot made the
-- foreign-key action (and the pass's own "is it referenced by a job" check)
-- read the whole job table.
--
-- Partial: most open jobs and every cancelled one carry no snapshot.
--
-- Cost: two scans of `mcp_introspection_jobs` under SHARE UPDATE EXCLUSIVE,
-- which blocks no reads or writes; the build first waits for transactions
-- already open on the table. An interrupted build is dropped and retried at
-- the next boot (registered in `migration_repair::CONCURRENT_INDEX_MIGRATIONS`).
-- Down path: drop the index by name.
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_mcp_introspection_jobs_snapshot
    ON mcp_introspection_jobs (snapshot_id)
    WHERE snapshot_id IS NOT NULL;
