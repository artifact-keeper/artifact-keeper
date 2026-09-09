-- Reconstruct the proxy halves of historic storage snapshots (follows 210).
--
-- 210 added the columns with DEFAULT 0, so every snapshot captured before it
-- landed reports "no remote half": the storage trend renders one populated row
-- and a wall of zeros above it. The proxy tables carry their own timestamps
-- (`proxy_cache_artifacts.cached_at`, `proxy_download_statistics.downloaded_at`),
-- so the cumulative figure as of each snapshot date is recoverable — matching
-- how the hosted `total_artifacts` / `total_downloads` are cumulative too.
--
-- A LOWER BOUND BY CONSTRUCTION, for two independent reasons:
--   * an object cached and later evicted, or a serve pruned by download
--     retention, is no longer on record at all; and
--   * `cached_at` is when the object was LAST written, not first cached — the
--     catalog upsert resets it to `now()` in its ON CONFLICT arm
--     (`proxy_catalog::upsert`), so every TTL revalidation and every refresh
--     of a mutable index moves an object forward, out of the snapshot dates it
--     was in fact already occupying. A long-lived, frequently revalidated
--     object therefore contributes to recent rows only.
-- Both shortfalls only ever under-report, never over-report. Only rows still
-- entirely at 0 are touched, so this cannot overwrite a figure that was
-- captured live, and re-running is safe.
--
-- OPERATOR NOTE: this is a full-table aggregate over both proxy tables and it
-- runs at startup, inside the migration transaction, before the API serves.
-- Cost is one aggregating pass per proxy table (the per-day rollups below,
-- both MATERIALIZED so they are computed once rather than re-run per snapshot
-- row) plus a small scan per snapshot row. On installs with a long retention
-- window and a busy proxy, treat as a seconds-to-minutes migration.
WITH cache_daily AS MATERIALIZED (
    SELECT cached_at::date AS day,
           COUNT(*)::BIGINT AS objects,
           COALESCE(SUM(size_bytes), 0)::BIGINT AS bytes
    FROM proxy_cache_artifacts
    GROUP BY 1
),
serve_daily AS MATERIALIZED (
    SELECT downloaded_at::date AS day, COUNT(*)::BIGINT AS serves
    FROM proxy_download_statistics
    GROUP BY 1
)
UPDATE storage_metrics sm
SET proxy_artifact_count = COALESCE(
        (SELECT SUM(objects) FROM cache_daily WHERE day <= sm.snapshot_date), 0
    )::BIGINT,
    proxy_storage_bytes = COALESCE(
        (SELECT SUM(bytes) FROM cache_daily WHERE day <= sm.snapshot_date), 0
    )::BIGINT,
    proxy_download_count = COALESCE(
        (SELECT SUM(serves) FROM serve_daily WHERE day <= sm.snapshot_date), 0
    )::BIGINT
WHERE sm.proxy_artifact_count = 0
  AND sm.proxy_storage_bytes = 0
  AND sm.proxy_download_count = 0;
