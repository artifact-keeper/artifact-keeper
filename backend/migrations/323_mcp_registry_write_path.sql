-- MCP registry write path (#5253, Phase 2/3): version tombstones and the
-- async package-resolution queue.

-- Every `name@version` an MCP repository has ever stored. A row is written by
-- trigger whenever a server.json artifact row is inserted (publish, peer
-- replication, promotion), so the ledger cannot miss a write path, and it is
-- never deleted while the repository exists: a version that was deleted,
-- trashed and purged stays reserved, and a publish of it answers `409
-- mcp_version_exists`.
CREATE TABLE IF NOT EXISTS mcp_version_tombstones (
    repository_id     UUID        NOT NULL REFERENCES repositories(id) ON DELETE CASCADE,
    name              TEXT        NOT NULL,
    version           TEXT        NOT NULL,
    first_artifact_id UUID,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (repository_id, name, version)
);

CREATE OR REPLACE FUNCTION mcp_record_version_tombstone() RETURNS trigger AS $$
BEGIN
    IF EXISTS (SELECT 1 FROM repositories r
               WHERE r.id = NEW.repository_id AND r.format = 'mcp') THEN
        INSERT INTO mcp_version_tombstones (repository_id, name, version, first_artifact_id)
        VALUES (NEW.repository_id, NEW.name, NEW.version, NEW.id)
        ON CONFLICT (repository_id, name, version) DO NOTHING;
    END IF;
    RETURN NULL;
END
$$ LANGUAGE plpgsql;

-- The trigger takes SHARE ROW EXCLUSIVE on `artifacts` and the backfill
-- below reads it: bound the wait (docs/operations/online-migrations.md) so a
-- long transaction fails this migration (retried at the next start) instead
-- of queueing every artifact write behind it.
SET LOCAL lock_timeout = '5s';

DROP TRIGGER IF EXISTS mcp_version_tombstone ON artifacts;
CREATE TRIGGER mcp_version_tombstone
    AFTER INSERT ON artifacts
    FOR EACH ROW
    WHEN (NEW.path LIKE 'servers/%/server.json')
    EXECUTE FUNCTION mcp_record_version_tombstone();

-- Versions stored before this migration, trashed ones included.
INSERT INTO mcp_version_tombstones (repository_id, name, version, first_artifact_id, created_at)
SELECT a.repository_id, a.name, a.version, a.id, a.created_at
FROM artifacts a
JOIN repositories r ON r.id = a.repository_id
WHERE r.format = 'mcp' AND a.path LIKE 'servers/%/server.json'
ON CONFLICT (repository_id, name, version) DO NOTHING;

-- One row per server version whose packages are still being resolved (a
-- Remote backing repository is being filled through its proxy path). The
-- version's own state lives in its metadata (`resolution`); this is the
-- work queue: claimed with `FOR UPDATE SKIP LOCKED` and a random
-- `claim_token`, retried with backoff, removed when the version resolves or
-- fails for good.
CREATE TABLE IF NOT EXISTS mcp_resolve_jobs (
    artifact_id      UUID        PRIMARY KEY REFERENCES artifacts(id) ON DELETE CASCADE,
    repository_id    UUID        NOT NULL REFERENCES repositories(id) ON DELETE CASCADE,
    requested_by     UUID,
    attempts         INTEGER     NOT NULL DEFAULT 0,
    next_attempt_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    claim_token      UUID,
    claimed_by       TEXT,
    claim_expires_at TIMESTAMPTZ,
    last_error       TEXT,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_mcp_resolve_jobs_due ON mcp_resolve_jobs (next_attempt_at);
