-- #1151, #1153 follow-ups to #903 / PR #1150.
--
-- 1151 (PURL length cap):
--   `scan_packages.purl` was unbounded TEXT. A malicious lockfile could pack
--   a multi-MB PURL string and, combined with the 50k row cap, balloon the
--   SBOM JSON. The PURL RFC recommends an upper bound around 2048 chars;
--   that is enforced at the DB column level so a syntactic check that
--   slipped past application code still cannot persist an oversized value.
--
--   Existing rows: every PURL in the wild is well below 2048 chars (real
--   PURLs cluster around 30-120 bytes). The USING cast preserves any
--   pathological rows by truncating to 2048; loss of trailing bytes is
--   acceptable for legacy data because the application path now validates
--   before insert.
--
-- 1153 (partial-scan signal):
--   When Trivy logs a warning on stderr for an unparseable target
--   (truncated package-lock.json, invalid version syntax, unrecognized
--   lockfile version) the scan returns success with an empty Packages
--   block. The SBOM endpoint then reports no packages for that target and
--   downstream attestation signs off on "clean".
--
--   New column `scan_completeness` distinguishes "scanner ran and saw no
--   packages" (= 'complete') from "scanner ran but skipped one or more
--   known-present targets" (= 'partial'). NULL is treated as 'complete'
--   for legacy rows.

-- 1151: bound the PURL column.
ALTER TABLE scan_packages
    ALTER COLUMN purl TYPE VARCHAR(2048) USING LEFT(purl, 2048);

-- 1153: mark scans that hit a partial-target signal.
ALTER TABLE scan_results
    ADD COLUMN IF NOT EXISTS scan_completeness VARCHAR(20)
        NOT NULL DEFAULT 'complete'
        CHECK (scan_completeness IN ('complete', 'partial'));
