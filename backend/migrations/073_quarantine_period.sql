-- Add quarantine period support for quality gate enforcement.
-- When quarantine is enabled, newly uploaded artifacts are held in a
-- 'quarantined' state until security scans complete or the timeout expires.

-- Extend the quarantine_status CHECK constraint to include new states.
-- The existing column (from migration 022) allows: 'unscanned', 'clean', 'flagged'.
-- We add: 'quarantined' (held pending scan), 'released' (scan passed, available),
-- and 'rejected' (scan failed, blocked).
ALTER TABLE artifacts DROP CONSTRAINT IF EXISTS artifacts_quarantine_status_check;
ALTER TABLE artifacts ADD CONSTRAINT artifacts_quarantine_status_check
    CHECK (quarantine_status IN ('unscanned', 'clean', 'flagged', 'quarantined', 'released', 'rejected'));

-- Timestamp indicating when quarantine expires. NULL means no quarantine.
-- If quarantine_until is in the future and quarantine_status = 'quarantined',
-- the artifact is blocked from download.
ALTER TABLE artifacts ADD COLUMN IF NOT EXISTS quarantine_until TIMESTAMPTZ;

-- Index for efficient lookup of quarantined artifacts nearing expiry.
CREATE INDEX IF NOT EXISTS idx_artifacts_quarantine_until
    ON artifacts(quarantine_until)
    WHERE quarantine_until IS NOT NULL AND quarantine_status = 'quarantined';
