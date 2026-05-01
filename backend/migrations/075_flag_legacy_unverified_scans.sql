-- Migration: flag legacy unverified scan_results rows (#994 follow-up for #996)
--
-- Versions v1.1.0 through v1.1.8 had a bug (#994) where ImageScanner,
-- TrivyFsScanner, IncusScanner, and OpenScapScanner would short-circuit
-- with Ok(vec![]) when the artifact format did not match the scanner.
-- The orchestrator persisted a scan_results row anyway, with
-- status='completed', findings_count=0, scanner_version=NULL. Receivers
-- treating these rows as "scan completed clean" were misled.
--
-- v1.1.9 (#996) gates row creation on Scanner::is_applicable(), so new
-- silent rows cannot occur. This migration flags the existing buggy rows
-- so consumer queries (policy evaluation, promotion gating, dashboards)
-- can exclude them and treat affected artifacts as unscanned, forcing a
-- rescan rather than waving them through on a deceptive completed row.
--
-- Idempotent: ADD COLUMN IF NOT EXISTS, CREATE INDEX IF NOT EXISTS, and
-- the UPDATE narrows on the buggy fingerprint so re-running is a no-op
-- once rows are flagged (and harmless on rows that already match).

ALTER TABLE scan_results
  ADD COLUMN IF NOT EXISTS legacy_unverified BOOLEAN NOT NULL DEFAULT false;

-- Conservative criteria: completed scans with no scanner_version recorded
-- AND zero findings AND no error message. Real scans always populate
-- scanner_version (verified by the four scanner implementations and the
-- DependencyScanner, which set scanner_version on complete_scan). Real
-- zero-finding scans (truly clean artifacts) populate scanner_version
-- too. Failed scans set error_message, so they are excluded.
UPDATE scan_results
  SET legacy_unverified = true
  WHERE status = 'completed'
    AND scanner_version IS NULL
    AND findings_count = 0
    AND coalesce(error_message, '') = '';

-- Partial index on the new consumer query path that filters out
-- legacy_unverified rows. The "WHERE legacy_unverified = false" clause
-- makes this strictly smaller than idx_scan_results_artifact (full
-- index on artifact_id), which is the existing covering index for the
-- "latest scan for artifact" pattern.
CREATE INDEX IF NOT EXISTS idx_scan_results_artifact_verified
  ON scan_results (artifact_id, created_at DESC)
  WHERE legacy_unverified = false;
