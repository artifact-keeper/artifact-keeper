-- #6300: when the fleet first saw each CVE-scanner version token.
--
-- A proxy scan verdict carries the scanner version it was graded with,
-- including the vulnerability-DB build (`grype-0.120.1+db-2026-11-10`). For
-- PROXY_SCAN_DB_GRACE_HOURS after a new token is first seen here, a verdict
-- the same scanner graded against the previous build keeps deciding pulls
-- while the pulls queue re-grades. The first sighting is kept in the database,
-- not per process, so a restart or a new replica does not reopen the window.
--
-- Additive: a new table, no lock on an existing one. One row per DB build,
-- so it stays a few hundred rows and needs no index beyond its key.
CREATE TABLE IF NOT EXISTS proxy_scan_db_versions (
    scanner_version TEXT PRIMARY KEY,
    first_seen_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

