-- Extend the quarantine_status CHECK constraint to support the quarantine period
-- workflow: artifacts can be 'quarantined' on upload (pending scan), then
-- transition to 'released' (scan passed) or 'rejected' (scan failed / admin).
-- The original values ('unscanned', 'clean', 'flagged') remain valid for
-- backward compatibility with proxy-scan workflows.

-- Drop the existing CHECK constraint and recreate with new values
ALTER TABLE artifacts DROP CONSTRAINT IF EXISTS artifacts_quarantine_status_check;
ALTER TABLE artifacts ADD CONSTRAINT artifacts_quarantine_status_check
    CHECK (quarantine_status IN ('unscanned', 'clean', 'flagged', 'quarantined', 'released', 'rejected'));

-- Add quarantine_until column: when the quarantine period expires, the artifact
-- can be auto-released if scanning has not flagged issues.
ALTER TABLE artifacts ADD COLUMN IF NOT EXISTS quarantine_until TIMESTAMPTZ;

-- Index for efficient lookup of quarantined artifacts whose hold period expired
CREATE INDEX IF NOT EXISTS idx_artifacts_quarantine_until
    ON artifacts (quarantine_until)
    WHERE quarantine_status = 'quarantined' AND quarantine_until IS NOT NULL;
