-- Promotion approval workflow
-- Adds a promotion_approvals table for staging-to-release approval requests
-- and a require_approval flag on repositories.

CREATE TABLE IF NOT EXISTS promotion_approvals (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    artifact_id UUID NOT NULL,
    source_repo_id UUID NOT NULL,
    target_repo_id UUID NOT NULL,
    requested_by UUID NOT NULL,
    requested_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    status VARCHAR(20) NOT NULL DEFAULT 'pending'
        CHECK (status IN ('pending', 'approved', 'rejected')),
    reviewed_by UUID,
    reviewed_at TIMESTAMPTZ,
    review_notes TEXT,
    policy_result JSONB,
    skip_policy_check BOOLEAN DEFAULT FALSE,
    notes TEXT,

    CONSTRAINT fk_approval_artifact
        FOREIGN KEY (artifact_id) REFERENCES artifacts(id),
    CONSTRAINT fk_approval_source
        FOREIGN KEY (source_repo_id) REFERENCES repositories(id),
    CONSTRAINT fk_approval_target
        FOREIGN KEY (target_repo_id) REFERENCES repositories(id)
);

CREATE INDEX IF NOT EXISTS idx_promotion_approvals_status
    ON promotion_approvals(status);

CREATE INDEX IF NOT EXISTS idx_promotion_approvals_source
    ON promotion_approvals(source_repo_id);

CREATE INDEX IF NOT EXISTS idx_promotion_approvals_requested
    ON promotion_approvals(requested_at DESC);

-- Add require_approval flag to repositories so admins can
-- gate staging promotions through the approval workflow.
ALTER TABLE repositories
    ADD COLUMN IF NOT EXISTS require_approval BOOLEAN DEFAULT FALSE;
