-- #5971: the CVE scanner version each scan worker runs.
--
-- API pods without grype compare stored proxy verdicts against the versions
-- the live workers report. One row per worker, refreshed on every sweep, so
-- workers whose vulnerability databases updated at different times never
-- overwrite each other, and a version nobody refreshed lately stops counting.
--
-- Additive: a new table, no lock on an existing one. Rows of workers gone a
-- day are deleted on a sweep, so it stays a handful of rows.
CREATE TABLE IF NOT EXISTS scan_worker_scanner_versions (
    worker_id           TEXT PRIMARY KEY,
    cve_scanner_version TEXT NOT NULL,
    reported_at         TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
