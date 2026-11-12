-- #5263: a numeric CVSS threshold on the proxy scan gate, alongside the
-- severity threshold.
--
-- The gate (`ProxySeverityGate`) compared scanner severity categories, so a
-- policy such as "block CVSS >= 8.0" could not be expressed: two `high`
-- findings either side of 8.0 received the same decision, and raising the
-- threshold to `critical` is a different policy. A severity label and a CVSS
-- score are also two assessments that need not agree.
--
-- Three additions, all nullable, all NULL on existing rows.
--
-- 1. `scan_configs.cvss_threshold`: the per-repository number. NULL (every
--    existing repository) keeps the gate exactly as it was. Like
--    `severity_threshold` it is live only when `block_on_policy_violation` is
--    set. When set, a finding that carries a CVSS base score blocks at or
--    above the number whatever its severity label, and a finding with no
--    score is still graded by `severity_threshold`.
--
-- 2. `proxy_scan_results.max_cvss_score` and `.max_unscored_severity`: the
--    CVSS summary of a verdict's findings. A verdict is shared by digest
--    across repositories while the threshold is per repository, so the row
--    cannot store a decision, and `max_severity` alone cannot re-evaluate a
--    numeric threshold on a cached verdict. `max_cvss_score` is the highest
--    base score among all findings that carry one;
--    `max_unscored_severity` the highest severity above info among findings
--    with no score. Both NULL on a vulnerable verdict means no summary (before this
--    migration): a numeric threshold blocks it as ungraded until the digest
--    is scanned again, the way an unrecorded `max_severity` blocks under a
--    severity threshold. A repository with no `cvss_threshold` never reads
--    either column.
--
-- 3. `proxy_scan_findings.cvss_*`: the assessment each finding was graded
--    by (score, CVSS version, vector, source), so an operator can see why a
--    numeric threshold did or did not block.
--
-- DOUBLE PRECISION, not NUMERIC: the values are written rounded to one
-- decimal and compared in the application, and sqlx reads the type without an
-- optional decimal feature.
--
-- Cost: each ADD COLUMN is nullable with no default, so it is a catalogue
-- update with no table rewrite. Re-runnable.
ALTER TABLE scan_configs
    ADD COLUMN IF NOT EXISTS cvss_threshold DOUBLE PRECISION
        CHECK (cvss_threshold >= 0 AND cvss_threshold <= 10);

ALTER TABLE proxy_scan_results
    ADD COLUMN IF NOT EXISTS max_cvss_score DOUBLE PRECISION
        CHECK (max_cvss_score >= 0 AND max_cvss_score <= 10);

ALTER TABLE proxy_scan_results
    ADD COLUMN IF NOT EXISTS max_unscored_severity TEXT;

ALTER TABLE proxy_scan_findings
    ADD COLUMN IF NOT EXISTS cvss_score DOUBLE PRECISION
        CHECK (cvss_score >= 0 AND cvss_score <= 10);

ALTER TABLE proxy_scan_findings
    ADD COLUMN IF NOT EXISTS cvss_version TEXT;

ALTER TABLE proxy_scan_findings
    ADD COLUMN IF NOT EXISTS cvss_vector TEXT;

ALTER TABLE proxy_scan_findings
    ADD COLUMN IF NOT EXISTS cvss_source TEXT;
