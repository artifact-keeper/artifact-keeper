-- no-transaction
-- Listing index for GET /api/v1/admin/holds/quarantine (#4281). Existing
-- idx_artifacts_quarantine covers any non-null status; this one is narrower
-- (currently-blocking rows) and includes until so remaining-time sorts do
-- not scan the whole artifacts table. CONCURRENTLY so the build never blocks
-- uploads; on a million-row artifacts table this is two table scans with no
-- write block.
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_artifacts_download_holds_quarantine
    ON artifacts (quarantine_status, quarantine_until, created_at DESC)
    WHERE is_deleted = false
      AND quarantine_status IN ('quarantined', 'rejected');
