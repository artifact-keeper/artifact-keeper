-- no-transaction
-- #4426: the partial index behind `ScanResultService::find_reusable_scan`
-- (cross-artifact scan dedup), now restricted to rows this instance's own
-- scanner produced. #2464 added `scan_results.origin`; the query already
-- requires `origin = 'local_scan'` (that filter is the correctness
-- guarantee), and the index predicate now matches it so imported rows are
-- never even indexed as dedup candidates. Columns as migration 209 (minus
-- `status`, which the predicate pins to one value).
--
-- CONCURRENTLY so the build never blocks scan writers: on a million-row
-- scan_results table this is two table scans under SHARE UPDATE EXCLUSIVE
-- with no write block, needing room for the new index beside the old one
-- (which migration 275 then drops). It waits for transactions already open
-- when it starts. Re-runnable: migration 273 clears an INVALID leftover.
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_scan_results_dedup_local
    ON scan_results (checksum_sha256, scan_type, pin_identity)
    WHERE status = 'completed' AND origin = 'local_scan';
