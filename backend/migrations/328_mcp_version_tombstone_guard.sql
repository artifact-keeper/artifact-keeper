-- Issue #5253: a recorded MCP `name@version` can never be stored again.
--
-- `mcp_version_tombstones` (323) records every server.json row inserted into
-- an MCP repository and has no foreign key to `artifacts`, so it outlives a
-- soft delete and a trash purge. Until now only the hosted publish route
-- consulted it: a Remote sync re-ingested a purged version (whatever bytes
-- upstream serves now), and a promotion into an MCP repository hard-deletes
-- a trashed row at the target path and inserts the copy. Either let a
-- deleted version come back with different bytes under the same
-- `name@version`.
--
-- This guard makes the ledger binding for every writer: an INSERT of a
-- server.json row whose `(repository_id, name, version)` is already
-- recorded fails with `unique_violation` (the error class of a duplicate
-- path, so callers that map a duplicate key to `409` do so here too). The
-- one sanctioned release, a republish of a version whose package resolution
-- failed and was never served, deletes the ledger row in the same
-- transaction first (`services::mcp_write::release_failed_version`).
--
-- Creating a trigger takes SHARE ROW EXCLUSIVE on `artifacts`: bound the
-- wait (docs/operations/online-migrations.md), as 323 does.
SET LOCAL lock_timeout = '5s';

CREATE OR REPLACE FUNCTION mcp_refuse_tombstoned_version() RETURNS trigger AS $$
BEGIN
    IF EXISTS (SELECT 1 FROM mcp_version_tombstones t
               JOIN repositories r ON r.id = t.repository_id
               WHERE t.repository_id = NEW.repository_id
                 AND t.name = NEW.name
                 AND t.version = NEW.version
                 AND r.format = 'mcp') THEN
        RAISE EXCEPTION USING
            ERRCODE = 'unique_violation',
            MESSAGE = format(
                'duplicate key value: MCP server version %s@%s was stored in this repository before (mcp_version_tombstones)',
                NEW.name, NEW.version);
    END IF;
    RETURN NEW;
END
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS mcp_version_tombstone_guard ON artifacts;
CREATE TRIGGER mcp_version_tombstone_guard
    BEFORE INSERT ON artifacts
    FOR EACH ROW
    WHEN (NEW.path LIKE 'servers/%/server.json')
    EXECUTE FUNCTION mcp_refuse_tombstoned_version();
