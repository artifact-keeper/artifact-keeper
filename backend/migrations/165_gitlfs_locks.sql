-- Dedicated storage for Git LFS file locks.
--
-- The Git LFS file-locking API (POST/GET /lfs/{repo}/locks, /locks/verify,
-- /locks/{id}/unlock) previously piggy-backed each lock onto a row in
-- `artifact_metadata`, using the *repository* id as the `artifact_id` grouping
-- key. That column is `UUID UNIQUE NOT NULL REFERENCES artifacts(id)` (see
-- 004_artifacts.sql), so a repositories.id is never a valid artifacts.id and
-- every `create_lock` INSERT failed the FK constraint with a 500. Even had a
-- valid artifact id been used, the UNIQUE constraint would have capped a
-- repository at a single lock. The whole locking subsystem was non-functional.
--
-- Locks are a repository-scoped concept in their own right, not artifact
-- metadata: they key on (repository_id, path) and reference no artifact row.
-- This table gives them correct storage. A repository may hold many locks; a
-- given path may be locked at most once (the LFS "already locked" 409 case).
CREATE TABLE IF NOT EXISTS lfs_locks (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    repository_id UUID NOT NULL REFERENCES repositories(id) ON DELETE CASCADE,
    path          TEXT NOT NULL,
    ref_name      TEXT,
    owner_id      UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    owner_name    TEXT NOT NULL,
    locked_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (repository_id, path)
);

CREATE INDEX IF NOT EXISTS idx_lfs_locks_repository_id
    ON lfs_locks (repository_id);
