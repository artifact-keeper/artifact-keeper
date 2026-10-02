-- Listing indexes for the admin quarantine queue (`GET /api/v1/admin/holds/quarantine`).
-- Existing idx_artifacts_quarantine covers any non-null status; this one is
-- narrower (currently-blocking rows) and includes until so remaining-time
-- sorts do not scan the whole artifacts table.
CREATE INDEX IF NOT EXISTS idx_artifacts_download_holds_quarantine
    ON artifacts (quarantine_status, quarantine_until, created_at DESC)
    WHERE is_deleted = false
      AND quarantine_status IN ('quarantined', 'rejected');

-- Proxy-cache holds (#3912) live on quarantine_until / quarantine_released_at,
-- not artifacts. The same queue lists them.
CREATE INDEX IF NOT EXISTS idx_proxy_cache_download_holds
    ON proxy_cache_artifacts (quarantine_until, cached_at DESC)
    WHERE quarantine_released_at IS NULL
      AND quarantine_until IS NOT NULL;
