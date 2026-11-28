-- #6335: record how many dependency lookups ADVISORY_EXCLUDE_PATTERNS kept out.
--
-- The dependency scanner already logs `advisory_excluded = <n>` for each scan,
-- but a completed scan row carried no such fact. An operator or auditor could
-- therefore not tell from the stored result (or from the scan API) that part
-- of the inventory was deliberately kept out of OSV/GitHub lookups.
--
-- Zero for rows written before this migration and for scanners that do not
-- consult external advisory feeds. The constant default is catalog-only on
-- PostgreSQL 11+ (no table rewrite), so the lock is brief even on a large
-- scan_results table.
SET LOCAL lock_timeout = '5s';

ALTER TABLE scan_results
    ADD COLUMN IF NOT EXISTS advisory_excluded INTEGER NOT NULL DEFAULT 0;
