-- 329_proxy_cache_seed_jobs.sql
-- #5284: `POST /api/v1/repositories/{key}/cache/seed` records a job here, one
-- item row per requested path in input order, and answers 202. A background
-- worker fetches each pending item through the proxy, under a row claim
-- (claim_token / claim_expires_at) so exactly one replica runs a job at a
-- time and a job whose replica died is resumed by another from the items
-- still `pending`. `GET .../cache/seed/{job_id}` reads the job and its items,
-- which are the seed's inventory.
--
-- Additive only: older releases never read these tables.
CREATE TABLE IF NOT EXISTS proxy_cache_seed_jobs (
    id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    repository_id     UUID NOT NULL REFERENCES repositories(id) ON DELETE CASCADE,
    kind              TEXT NOT NULL,
    status            TEXT NOT NULL DEFAULT 'pending'
        CHECK (status IN ('pending', 'running', 'completed', 'failed')),
    concurrency       INTEGER NOT NULL,
    max_total_bytes   BIGINT,
    error_summary     TEXT,
    attempts          INTEGER NOT NULL DEFAULT 0,
    claimed_by        TEXT,
    claim_token       UUID,
    claim_expires_at  TIMESTAMPTZ,
    created_by        UUID,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    started_at        TIMESTAMPTZ,
    finished_at       TIMESTAMPTZ,
    updated_at        TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- The resumer's scan for pending work and lapsed claims.
CREATE INDEX IF NOT EXISTS idx_proxy_cache_seed_jobs_claimable
    ON proxy_cache_seed_jobs (status, claim_expires_at)
    WHERE status IN ('pending', 'running');

CREATE INDEX IF NOT EXISTS idx_proxy_cache_seed_jobs_repository
    ON proxy_cache_seed_jobs (repository_id, created_at);

CREATE TABLE IF NOT EXISTS proxy_cache_seed_items (
    job_id            UUID NOT NULL REFERENCES proxy_cache_seed_jobs(id) ON DELETE CASCADE,
    position          INTEGER NOT NULL,
    path              TEXT NOT NULL,
    state             TEXT NOT NULL DEFAULT 'pending'
        CHECK (state IN ('pending', 'cached', 'already_cached', 'refused', 'failed')),
    reason            TEXT,
    http_status       INTEGER,
    size_bytes        BIGINT,
    checksum_sha256   TEXT,
    updated_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (job_id, position)
);

COMMENT ON TABLE proxy_cache_seed_jobs IS
    'Proxy-cache seed jobs of Remote repositories (#5284).';
COMMENT ON TABLE proxy_cache_seed_items IS
    'One row per requested item of a proxy-cache seed job, in input order: the seed inventory (#5284).';

-- Down path: rollback is SKIP_MIGRATIONS=true on the older release, which
-- never reads the tables. To remove them by hand:
--   DROP TABLE IF EXISTS proxy_cache_seed_items;
--   DROP TABLE IF EXISTS proxy_cache_seed_jobs;
