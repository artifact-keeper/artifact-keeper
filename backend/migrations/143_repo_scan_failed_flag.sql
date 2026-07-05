-- #2167: fail-closed scoring when a vulnerability scan errors.
--
-- A repo whose LATEST applicable scan is `status='failed'` (the scanner
-- errored: e.g. trivy DB UNAUTHORIZED, grype "unexpected EOF") previously
-- contributed zero findings and was graded A (clean) — a false security
-- control that let a malicious image pass as clean.
--
-- `recalculate_score` now detects that condition and floors the grade to F
-- while setting this persisted flag so both the dashboard/UI and the
-- release-gate can treat "scan errored" as NOT clean. The flag is cleared
-- automatically once a newer `completed` scan supersedes the failed row.
--
-- Defaults FALSE so every existing row (and any repo with no failed scan) is
-- unchanged until the next `recalculate_score` runs.
ALTER TABLE repo_security_scores
    ADD COLUMN has_failed_scan BOOLEAN NOT NULL DEFAULT FALSE;
