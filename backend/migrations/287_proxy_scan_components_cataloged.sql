-- #4594: record how many components the CVE engine cataloged for a proxy verdict.
--
-- A conda package with no Python or recognised binary content (a compiled
-- library, `tzdata`, `ca-certificates`) is unpacked and scanned to completion,
-- but the engine catalogs no component for it. The inline gate now grades such
-- a scan on its findings instead of treating it as inconclusive, and records
-- `components_cataloged = 0` so the proxy-scans view can show that the verdict
-- was graded on file contents only.
--
-- NULL means the engine reported no catalog, OR a verdict recorded before this
-- migration. Written with every verdict by the inline scan and the rescan
-- endpoint, so a later scan replaces it together with the verdict.
ALTER TABLE proxy_scan_results
    ADD COLUMN IF NOT EXISTS components_cataloged INTEGER
        CHECK (components_cataloged >= 0);
