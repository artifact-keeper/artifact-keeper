-- #1030: partial index supporting the DISTINCT ON (artifact_id, scan_type)
-- ORDER BY (artifact_id, scan_type, completed_at DESC NULLS LAST, created_at DESC)
-- queries used by the security dashboard / per-repo score recompute paths
-- (introduced for #962 / #1126 / #1127).
--
-- Without this index PostgreSQL picks the existing
-- `idx_scan_results_artifact_verified ON scan_results (artifact_id, created_at DESC)`
-- (or `idx_scan_results_artifact_created` depending on which migrations are
-- present), satisfies the WHERE filter index-only, and then sorts the matching
-- rows in memory to honour the new ORDER BY. At production scale (5M+ rows
-- in #962's reporter's environment) that sort dominates each dashboard call
-- and regresses what was an index-only COUNT(*) before the fix.
--
-- The partial index trades a few MB of disk for an index-only scan that
-- already produces rows in the exact DISTINCT ON ordering. It is intentionally
-- partial on `status = 'completed'` so it indexes only the rows the latest-
-- scan windowing ever reads; in-flight / failed rows do not bloat the tree.
--
-- A NOT EXISTS check on `legacy_unverified` keeps this migration forward-
-- compatible with the column added by release/1.1.x's migration 075 if/when
-- that column lands on main. The DO block degrades gracefully today (column
-- absent on main) and tightens automatically once the column exists.

DO $$
DECLARE
    has_legacy_unverified boolean;
BEGIN
    SELECT EXISTS (
        SELECT 1
        FROM information_schema.columns
        WHERE table_schema = current_schema()
          AND table_name = 'scan_results'
          AND column_name = 'legacy_unverified'
    ) INTO has_legacy_unverified;

    IF has_legacy_unverified THEN
        EXECUTE $idx$
            CREATE INDEX IF NOT EXISTS idx_scan_results_latest_per_artifact_type
            ON scan_results (
                artifact_id,
                scan_type,
                completed_at DESC NULLS LAST,
                created_at DESC
            )
            WHERE status = 'completed' AND legacy_unverified = false
        $idx$;
    ELSE
        EXECUTE $idx$
            CREATE INDEX IF NOT EXISTS idx_scan_results_latest_per_artifact_type
            ON scan_results (
                artifact_id,
                scan_type,
                completed_at DESC NULLS LAST,
                created_at DESC
            )
            WHERE status = 'completed'
        $idx$;
    END IF;
END
$$;

COMMENT ON INDEX idx_scan_results_latest_per_artifact_type IS
    'Supports DISTINCT ON (artifact_id, scan_type) latest-scan windowing used '
    'by the security dashboard and per-repo score recompute. See #1030.';
