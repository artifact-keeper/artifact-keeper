-- Age-based quality gate for proxy (remote) registries.
-- Per-repository config and review queue for young upstream packages.

ALTER TABLE repositories
    ADD COLUMN IF NOT EXISTS age_gate_enabled BOOLEAN NOT NULL DEFAULT false,
    ADD COLUMN IF NOT EXISTS age_gate_min_age_days INT NOT NULL DEFAULT 7
        CHECK (age_gate_min_age_days BETWEEN 1 AND 3650);

CREATE TABLE age_gate_reviews (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    repository_id UUID NOT NULL REFERENCES repositories(id) ON DELETE CASCADE,
    package_name TEXT NOT NULL,
    package_version TEXT NOT NULL,
    upstream_published_at TIMESTAMPTZ,
    status TEXT NOT NULL CHECK (status IN ('pending', 'approved', 'rejected')),
    requested_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    reviewed_by UUID REFERENCES users(id) ON DELETE SET NULL,
    reviewed_at TIMESTAMPTZ,
    review_reason TEXT,
    request_count INT NOT NULL DEFAULT 1,
    last_requested_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (repository_id, package_name, package_version)
);

CREATE INDEX idx_age_gate_reviews_pending
    ON age_gate_reviews (repository_id, status)
    WHERE status = 'pending';

CREATE INDEX idx_age_gate_reviews_repo_status
    ON age_gate_reviews (repository_id, status);
