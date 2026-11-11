-- #5408: `POST /api/v1/repositories/{key}/mcp/seed` records a job here with
-- the requested `name@version` list as its items, answers 202 and seeds the
-- items in the background: each name is fetched from the upstream registry's
-- version list, recorded in the catalog as a sync page would record it, and
-- the version is pinned (approved and ingested) as `catalog/pins` does.
-- `GET .../mcp/seed/{job_id}` reads the job and its per-item outcome.
--
-- Additive only: older releases never read this table.
CREATE TABLE IF NOT EXISTS mcp_remote_seed_jobs (
    id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    repository_id  UUID NOT NULL REFERENCES repositories(id) ON DELETE CASCADE,
    status         TEXT NOT NULL DEFAULT 'pending'
        CHECK (status IN ('pending', 'running', 'completed', 'failed')),
    -- [{name, version, state, reason, catalogId}], in request order.
    items          JSONB NOT NULL,
    reason         TEXT,
    error          TEXT,
    created_by     UUID,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    started_at     TIMESTAMPTZ,
    finished_at    TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_mcp_remote_seed_jobs_repository
    ON mcp_remote_seed_jobs (repository_id, created_at);
