-- Issue #3411: admit `external` as a scan_results.scan_type.
--
-- The external findings ingestion endpoint writes a completed scan_results row
-- on behalf of an out-of-tree scanner. The vendor's identity goes in
-- scan_findings.source (already on the wire as FindingResponse.source) and in
-- scan_results.scanner_version; the scan_type stays GENERIC.
--
-- That genericity is the point. `scan_results_scan_type_check` has already been
-- dropped and fully re-stated four times (022, 032, 034, 060), and two of its
-- eight existing values (`license`, `malware`) have no implementor. One
-- `external` value stops the constraint growing once per integration, so this
-- is intended to be the last migration this constraint needs.
--
-- Written in the online shape (ADD ... NOT VALID, then VALIDATE) rather than the
-- DROP + validating ADD its four predecessors used. scan_results is a hot table
-- and the old shape re-validated every row under ACCESS EXCLUSIVE -- see the
-- 032/034/060 entries in `migration_safety::ALLOWLIST`. Here the DROP and the
-- NOT VALID ADD are both catalog-only, and VALIDATE CONSTRAINT takes only
-- SHARE UPDATE EXCLUSIVE, so concurrent reads and writes are never blocked.
--
-- Widening a CHECK can never fail validation against rows that already satisfy
-- the narrower predicate, so the VALIDATE step is a formality that leaves the
-- constraint in the same state the predecessors produced.
ALTER TABLE scan_results DROP CONSTRAINT IF EXISTS scan_results_scan_type_check;
ALTER TABLE scan_results ADD CONSTRAINT scan_results_scan_type_check
    CHECK (scan_type IN ('dependency', 'image', 'license', 'malware', 'filesystem', 'grype', 'openscap', 'incus', 'external'))
    NOT VALID;
ALTER TABLE scan_results VALIDATE CONSTRAINT scan_results_scan_type_check;
