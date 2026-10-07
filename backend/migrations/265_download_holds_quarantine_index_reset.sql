-- Clear any leftover INVALID concurrent indexes before the `-- no-transaction`
-- builds in 266 and 272. `CREATE INDEX CONCURRENTLY IF NOT EXISTS` would skip
-- an INVALID leftover and leave it unused-but-maintained forever.
--
-- Both listing indexes sit on PF-008 hot tables (`artifacts` and
-- `proxy_cache_artifacts`, see src/migration_safety.rs HOT_TABLES), so each is
-- built CONCURRENTLY in a file of its own: 266 for `artifacts`, 272 for
-- `proxy_cache_artifacts`. A plain CREATE INDEX here would hold SHARE on the
-- table for the whole build and stall every upload or proxied fetch.
SET LOCAL lock_timeout = '5s';

DROP INDEX IF EXISTS idx_artifacts_download_holds_quarantine;

DROP INDEX IF EXISTS idx_proxy_cache_download_holds;
