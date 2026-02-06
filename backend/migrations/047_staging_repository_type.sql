-- Add Staging repository type for promotion workflow
-- Staging repos hold artifacts pending promotion to release repos

-- Add the new enum value to repository_type
ALTER TYPE repository_type ADD VALUE IF NOT EXISTS 'staging';

-- Add promotion tracking columns to repositories
ALTER TABLE repositories
    ADD COLUMN IF NOT EXISTS promotion_target_id UUID REFERENCES repositories(id),
    ADD COLUMN IF NOT EXISTS promotion_policy_id UUID REFERENCES security_policies(id);

-- Create promotion history table
CREATE TABLE IF NOT EXISTS promotion_history (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    artifact_id UUID NOT NULL REFERENCES artifacts(id) ON DELETE CASCADE,
    source_repo_id UUID NOT NULL REFERENCES repositories(id),
    target_repo_id UUID NOT NULL REFERENCES repositories(id),
    promoted_by UUID REFERENCES users(id),
    policy_result JSONB,
    notes TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Index for querying promotion history
CREATE INDEX IF NOT EXISTS idx_promotion_history_artifact ON promotion_history(artifact_id);
CREATE INDEX IF NOT EXISTS idx_promotion_history_source ON promotion_history(source_repo_id);
CREATE INDEX IF NOT EXISTS idx_promotion_history_target ON promotion_history(target_repo_id);
CREATE INDEX IF NOT EXISTS idx_promotion_history_created ON promotion_history(created_at);

COMMENT ON COLUMN repositories.promotion_target_id IS 'Default release repo for staging promotions';
COMMENT ON COLUMN repositories.promotion_policy_id IS 'Security policy to evaluate before promotion';
COMMENT ON TABLE promotion_history IS 'Audit trail of artifact promotions from staging to release';
