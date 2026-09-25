-- Scan-policy blocks were persisted as quarantine_status = 'quarantined'
-- (until NULL, reason 'Policy ''…''). The download gate then 409'd as
-- quarantine *before* the scan-policy 403, so the security dashboard,
-- artifact listing, and cargo/npm/maven clients all called a policy hold
-- a quarantine. Distinguish the states.
ALTER TABLE artifacts DROP CONSTRAINT IF EXISTS artifacts_quarantine_status_check;
ALTER TABLE artifacts ADD CONSTRAINT artifacts_quarantine_status_check
    CHECK (quarantine_status IN (
        'unscanned', 'clean', 'flagged', 'quarantined',
        'released', 'rejected', 'policy_blocked'
    ));

UPDATE artifacts
SET quarantine_status = 'policy_blocked'
WHERE is_deleted = false
  AND quarantine_status = 'quarantined'
  AND quarantine_until IS NULL
  AND quarantine_reason LIKE '%Policy ''%';

CREATE INDEX IF NOT EXISTS idx_artifacts_policy_blocked
    ON artifacts (created_at DESC)
    WHERE is_deleted = false AND quarantine_status = 'policy_blocked';
