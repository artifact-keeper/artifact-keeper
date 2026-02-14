-- Promotion gates: age-based gates, signature verification, and rejection workflow
-- Extends scan_policies with promotion gate fields and promotion_history with rejection tracking.

-- Add promotion gate columns to scan_policies
ALTER TABLE scan_policies
    ADD COLUMN IF NOT EXISTS min_staging_hours INTEGER,
    ADD COLUMN IF NOT EXISTS max_artifact_age_days INTEGER,
    ADD COLUMN IF NOT EXISTS require_signature BOOLEAN NOT NULL DEFAULT FALSE;

COMMENT ON COLUMN scan_policies.min_staging_hours IS 'Minimum hours an artifact must spend in staging before promotion';
COMMENT ON COLUMN scan_policies.max_artifact_age_days IS 'Maximum age in days for an artifact to be eligible for promotion';
COMMENT ON COLUMN scan_policies.require_signature IS 'Require artifact to have a valid signature before promotion';

-- Add rejection tracking to promotion_history
ALTER TABLE promotion_history
    ADD COLUMN IF NOT EXISTS status VARCHAR(20) NOT NULL DEFAULT 'promoted'
        CHECK (status IN ('promoted', 'rejected', 'pending_approval')),
    ADD COLUMN IF NOT EXISTS rejection_reason TEXT;

CREATE INDEX IF NOT EXISTS idx_promotion_history_status ON promotion_history(status);

COMMENT ON COLUMN promotion_history.status IS 'Status of the promotion: promoted, rejected, or pending_approval';
COMMENT ON COLUMN promotion_history.rejection_reason IS 'Reason for rejection when status is rejected';
