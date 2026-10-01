-- #4096: carry the inline proxy scan's inventory completeness with its verdict.
--
-- `ProxyScanVerdict.scan_completeness` (#1153) already says whether the
-- CVE-authoritative scanner saw a target it could not parse, but only the
-- hosted path persisted it (`scan_results.scan_completeness`). The proxy path
-- dropped it, so `GET /repositories/{key}/security/proxy-sbom` always rendered
-- the regenerated SBOM as authoritative, even over a half-read inventory.
--
-- NULL means complete, OR a verdict recorded before this migration (whose
-- completeness was never captured). It mirrors the in-memory `Option` and the
-- SBOM generator contract, where `None` emits no completeness marker.
-- Values track `scan_results.scan_completeness` (migrations 090 and 223).
ALTER TABLE proxy_scan_results
    ADD COLUMN IF NOT EXISTS scan_completeness TEXT
        CHECK (scan_completeness IN ('complete', 'partial', 'not_cataloged'));
