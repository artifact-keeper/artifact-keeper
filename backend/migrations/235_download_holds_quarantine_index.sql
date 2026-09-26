-- Listing index for the admin quarantine queue (`GET /api/v1/admin/holds/quarantine`).
-- Existing idx_artifacts_quarantine covers any non-null status; this one is
-- narrower (currently-blocking rows) and includes until so remaining-time
-- sorts do not scan the whole artifacts table.
CREATE INDEX IF NOT EXISTS idx_artifacts_download_holds_quarantine
    ON artifacts (quarantine_status, quarantine_until, created_at DESC)
    WHERE is_deleted = false
      AND quarantine_status IN ('quarantined', 'rejected');
