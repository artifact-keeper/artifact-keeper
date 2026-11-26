-- #4184: warm a conda Remote's proxy cache from an ingested lockfile.
--
-- 1. `environment_packages` gains the download URL and sha256 the lockfile
--    pins. Without them a stored environment names packages but not the
--    files to fetch, nor the checksum that says a cached copy is the pinned
--    one. Both are nullable: environments ingested before this release keep
--    NULL and a warm reports their entries as `no_url` until re-ingested.
-- 2. `conda_warm_jobs` / `conda_warm_items` persist a warm run, one item per
--    distinct package file, so a run is idempotent (one active job per
--    (repository, environment, platform filter)) and resumable (a restarted
--    or second replica claims the items still pending).
--
-- Expand-only: two nullable columns (metadata-only ADD COLUMN, no rewrite)
-- and two new tables whose indexes build on empty tables. The previous
-- release neither reads nor writes any of it, so it keeps running against
-- this schema (docs/operations/online-migrations.md).
SET LOCAL lock_timeout = '5s';

ALTER TABLE environment_packages
    ADD COLUMN IF NOT EXISTS url TEXT,
    ADD COLUMN IF NOT EXISTS sha256 TEXT;

CREATE TABLE IF NOT EXISTS conda_warm_jobs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    -- The repository the warm was asked for (a Remote, or a Virtual whose
    -- Remote members are warmed).
    repository_id UUID NOT NULL REFERENCES repositories(id) ON DELETE CASCADE,
    environment_id UUID NOT NULL REFERENCES environments(id) ON DELETE CASCADE,
    -- Optional platform filter; '' means every platform the lock resolves.
    platform TEXT NOT NULL DEFAULT '',
    -- pending -> running -> completed | cancelled | budget_exceeded |
    -- failed. Every end state is terminal; a new request for the same key
    -- starts a new job (whose items are then mostly skipped as already
    -- cached). `budget_exceeded`: the job fetched CONDA_WARM_MAX_JOB_BYTES.
    -- `failed`: its runner gave up after repeated database errors.
    status TEXT NOT NULL DEFAULT 'pending',
    requested_by UUID,
    total INTEGER NOT NULL DEFAULT 0,
    -- Conda memberships with no recorded URL (ingested before this release,
    -- or a lockfile that records none): reported, never fetched.
    skipped_no_url INTEGER NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    started_at TIMESTAMPTZ,
    finished_at TIMESTAMPTZ,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT conda_warm_jobs_status_check
        CHECK (status IN ('pending', 'running', 'completed', 'cancelled',
                          'budget_exceeded', 'failed'))
);

-- Idempotency: at most one active job per (repository, environment, filter).
CREATE UNIQUE INDEX IF NOT EXISTS uq_conda_warm_jobs_active
    ON conda_warm_jobs (repository_id, environment_id, platform)
    WHERE status IN ('pending', 'running');

-- Resume scan on startup: the few active jobs.
CREATE INDEX IF NOT EXISTS idx_conda_warm_jobs_active
    ON conda_warm_jobs (status)
    WHERE status IN ('pending', 'running');

-- The ON DELETE CASCADE from environments: deleting an environment finds
-- its jobs without a sequential scan.
CREATE INDEX IF NOT EXISTS idx_conda_warm_jobs_environment
    ON conda_warm_jobs (environment_id);

CREATE TABLE IF NOT EXISTS conda_warm_items (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    job_id UUID NOT NULL REFERENCES conda_warm_jobs(id) ON DELETE CASCADE,
    -- The Remote whose cache is filled; NULL when the URL resolves to none.
    remote_repository_id UUID REFERENCES repositories(id) ON DELETE CASCADE,
    url TEXT NOT NULL,
    subdir TEXT NOT NULL DEFAULT '',
    filename TEXT NOT NULL DEFAULT '',
    expected_sha256 TEXT,
    -- pending | in_progress | fetched | cached | held | blocked |
    -- checksum_mismatch | failed | not_remote | not_allowed
    status TEXT NOT NULL DEFAULT 'pending',
    attempts INTEGER NOT NULL DEFAULT 0,
    bytes BIGINT,
    detail TEXT,
    claimed_at TIMESTAMPTZ,
    finished_at TIMESTAMPTZ,
    UNIQUE (job_id, url)
);

-- Claiming work: the pending (and lapsed in-progress) items of one job.
CREATE INDEX IF NOT EXISTS idx_conda_warm_items_job_status
    ON conda_warm_items (job_id, status);

-- The ON DELETE CASCADE from repositories: deleting a Remote finds the items
-- that filled it without a sequential scan.
CREATE INDEX IF NOT EXISTS idx_conda_warm_items_remote
    ON conda_warm_items (remote_repository_id)
    WHERE remote_repository_id IS NOT NULL;
