-- Projects P1 (#2472): metadata grouping for repositories.
--
-- A project is a named collection of repositories. Membership grants are
-- stored in the existing `permissions` table with target_type = 'project'
-- (no third authz store). `repositories.project_id` is nullable and
-- defaults to NULL: unassigned repositories behave exactly as before.
-- Quotas are stored but NOT enforced in P1 (enforcement lands in P3).

CREATE TABLE IF NOT EXISTS projects (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    key VARCHAR(255) NOT NULL UNIQUE,
    name VARCHAR(255) NOT NULL,
    description TEXT,
    quota_bytes BIGINT,                 -- P1: stored only, NOT enforced (quotas=P3)
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

ALTER TABLE repositories ADD COLUMN IF NOT EXISTS project_id UUID REFERENCES projects(id) ON DELETE SET NULL;

CREATE INDEX IF NOT EXISTS idx_repositories_project_id ON repositories(project_id);

INSERT INTO projects (key, name, description)
VALUES ('_default', 'Default', 'Default project (UI placeholder; no repos auto-assigned)')
ON CONFLICT (key) DO NOTHING;
