-- #3604: carry the component-pin identity on each scan_results row.
--
-- #3442 made the npm CVE verdict a function of the request coordinate
-- (repository format + artifact name + version), which it materializes as a
-- synthetic component "pin" the engine grades. But the cross-artifact reuse
-- key (`ScanResultService::find_reusable_scan`) still matched only on
-- (checksum_sha256, scan_type, status='completed'). That key was sound while a
-- verdict was a pure function of the bytes -- identical bytes, identical
-- answer -- and #3442 silently invalidated it: two byte-identical uploads under
-- DIFFERENT coordinates (e.g. `safe-first@1.0.0` and `lodash@4.17.11`, both npm)
-- collapsed onto ONE cached verdict, and reuse is consulted before the scan, so
-- the pinned scan for the second coordinate never ran. An attacker holding only
-- `write:artifacts` could prime a clean verdict under a throwaway name and have
-- it served for the real, vulnerable coordinate.
--
-- The fix records the pin identity that PRODUCED a verdict on the row, so reuse
-- can require it to equal the current request's pin.
ALTER TABLE scan_results ADD COLUMN IF NOT EXISTS pin_identity TEXT;

-- Reuse now filters `pin_identity IS NOT DISTINCT FROM $current` on top of the
-- existing (checksum, scan_type, status) predicate. `IS NOT DISTINCT FROM` is
-- deliberate: a NULL pin (an unpinned format) matches ONLY another NULL pin, so
-- a pinned npm verdict can never be handed back for an unpinned generic request
-- (the direction the red team proved), and vice versa. Extending the dedup
-- index with pin_identity keeps the lookup covered.
--
-- Existing rows keep pin_identity = NULL. They were graded by a binary that
-- applied no pin, so their verdict IS the unpinned (byte-only) verdict -- which
-- is exactly what a NULL pin means -- and a pinned request will correctly
-- decline to reuse them and scan fresh.
DROP INDEX IF EXISTS idx_scan_results_dedup;
CREATE INDEX IF NOT EXISTS idx_scan_results_dedup
ON scan_results(checksum_sha256, scan_type, status, pin_identity)
WHERE status = 'completed';
