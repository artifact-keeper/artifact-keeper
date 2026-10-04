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
--   * The CHECK is added NOT VALID: a catalogue update, enforced on every
--     new INSERT/UPDATE from now on, with no scan of existing rows.
--
-- The CHECK is deliberately NOT validated here. sqlx runs this file in one
-- transaction, and both statements above take ACCESS EXCLUSIVE, held until
-- commit; a VALIDATE CONSTRAINT in the same file would full-scan
-- scan_findings while every reader and writer queues behind that lock. It
-- also buys nothing: every pre-existing row holds the constant default
-- 'vulnerability', which satisfies the CHECK by construction.
ALTER TABLE scan_findings
    ADD COLUMN IF NOT EXISTS finding_class TEXT NOT NULL DEFAULT 'vulnerability';

ALTER TABLE scan_findings
    ADD CONSTRAINT scan_findings_finding_class_check
    CHECK (finding_class IN ('vulnerability', 'malicious', 'policy')) NOT VALID;
