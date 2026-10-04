-- #3013 (first slice): distinguish WHAT KIND of finding a row is.
--
-- Every scanner so far reports known weaknesses in declared dependencies, and
-- scan_findings had no way to say that a finding is something else. A
-- disputed CVE and a known-malicious package both landed as an ordinary row
-- and both drove the same `quarantine_status = 'flagged'`, so no policy could
-- treat hostile content differently from a weakness.
--
--   vulnerability  a known weakness (CVE, GHSA, ...). Every existing row.
--   malicious      the package itself is known to be hostile, e.g. an OSV
--                  `MAL-*` advisory from ossf/malicious-packages.
--   policy         a configuration / compliance rule violation (OpenSCAP).
--
-- Cost on a large scan_findings table:
--   * ADD COLUMN ... NOT NULL DEFAULT <constant> is catalogue-only since
--     PostgreSQL 11: existing rows read the default, nothing is rewritten.
--   * The CHECK is added NOT VALID (catalogue update; new rows are checked
--     immediately) and then validated, which scans the table under
--     SHARE UPDATE EXCLUSIVE and does not block writers
--     (docs/operations/online-migrations.md, rewrite 2).
ALTER TABLE scan_findings
    ADD COLUMN IF NOT EXISTS finding_class TEXT NOT NULL DEFAULT 'vulnerability';

ALTER TABLE scan_findings
    ADD CONSTRAINT scan_findings_finding_class_check
    CHECK (finding_class IN ('vulnerability', 'malicious', 'policy')) NOT VALID;

ALTER TABLE scan_findings VALIDATE CONSTRAINT scan_findings_finding_class_check;
