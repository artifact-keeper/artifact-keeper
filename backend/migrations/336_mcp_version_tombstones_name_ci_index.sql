-- no-transaction
-- 336_mcp_version_tombstones_name_ci_index.sql
-- #5434: a hosted MCP publish refuses a server name that differs only in
-- letter case from a name the repository already recorded. The check reads
-- `mcp_version_tombstones` by `(repository_id, lower(name))` inside the
-- publish transaction; the primary key `(repository_id, name, version)`
-- cannot serve a `lower(name)` lookup, so without this index every publish
-- would read every ledger row of its repository.
--
-- Cost: two scans of `mcp_version_tombstones` under SHARE UPDATE EXCLUSIVE,
-- which blocks no reads or writes; the build first waits for transactions
-- already open on the table. An interrupted build is dropped and retried at
-- the next boot (registered in `migration_repair::CONCURRENT_INDEX_MIGRATIONS`).
-- Down path: drop the index by name.
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_mcp_version_tombstones_name_ci
    ON mcp_version_tombstones (repository_id, lower(name));
