-- Clear any leftover INVALID concurrent index before the `-- no-transaction`
-- build in the next file. `CREATE INDEX CONCURRENTLY IF NOT EXISTS` would skip
-- an INVALID leftover and leave it unused-but-maintained forever.
--
-- Proxy-cache holds (#3912) live on `proxy_cache_artifacts`, which is not a
-- hot table in the PF-008 gate, so that listing index is built here in the
-- same transaction.
DROP INDEX IF EXISTS idx_artifacts_download_holds_quarantine;

CREATE INDEX IF NOT EXISTS idx_proxy_cache_download_holds
    ON proxy_cache_artifacts (quarantine_until, cached_at DESC)
    WHERE quarantine_released_at IS NULL
      AND quarantine_until IS NOT NULL;
