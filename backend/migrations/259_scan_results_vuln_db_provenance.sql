-- #3014: record WHICH vulnerability database a scan ran against.
--
-- `scanner_version` (migration 022) names the scanner binary, e.g.
-- `trivy-0.71.2`. The same binary returns different answers about identical
-- bytes depending on how old its vulnerability database is, and nothing
-- recorded that second fact, so "when was this artifact last meaningfully
-- scanned" was unanswerable, a reused (dedup) verdict silently inherited an
-- unknown database vintage, and an air-gapped deployment could not tell which
-- verdicts predate its latest offline database import.
--
--   vuln_db_version       the database identity the scanner reported, e.g.
--                         `trivy-db-v2`, `grype-db-v6.0.2`, or `live:osv` for
--                         the dependency scanner, which queries live advisory
--                         APIs rather than a local snapshot.
--   vuln_db_published_at  when that database was built / last updated
--                         (trivy `UpdatedAt`, grype `built`); for a live-API
--                         scanner, the query time.
--
-- Both nullable: not every scan type has a vulnerability database (OpenSCAP is
-- configuration compliance), and rows written before this migration cannot be
-- backfilled. NULL means "unknown", never "fresh".
--
-- Cost: two nullable columns with no default are a catalogue-only change
-- (brief ACCESS EXCLUSIVE, no rewrite, no scan) on any size of scan_results.
ALTER TABLE scan_results
    ADD COLUMN IF NOT EXISTS vuln_db_version VARCHAR(100),
    ADD COLUMN IF NOT EXISTS vuln_db_published_at TIMESTAMPTZ;
