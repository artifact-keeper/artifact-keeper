-- no-transaction
-- Listing index for the proxy-cache half of GET /api/v1/admin/holds/quarantine
-- and the active count in GET /api/v1/admin/holds/summary (#4281). Held proxy
-- rows are a tiny fraction of the cache, so the partial index stays small (16kB
-- for 200 held rows out of 1M cached). Measured on 1M rows: the holds predicate
-- went from a ~90ms parallel seq scan to a ~0.1ms index-only scan.
-- CONCURRENTLY because `proxy_cache_artifacts` is a PF-008 hot table: the build
-- is one table scan per pass and never blocks proxy-cache upserts. Any INVALID
-- leftover from an interrupted build is dropped by 265.
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_proxy_cache_download_holds
    ON proxy_cache_artifacts (quarantine_until, cached_at DESC)
    WHERE quarantine_released_at IS NULL
      AND quarantine_until IS NOT NULL;
