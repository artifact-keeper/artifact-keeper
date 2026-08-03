-- #2954: inline scan-and-block on download (proxy PyPI + hosted).
--
-- Proxy-cached bytes are deliberately NOT written to `artifacts` (#1278/#1280),
-- and `scan_results.artifact_id` is NOT NULL REFERENCES artifacts(id). There is
-- therefore no row to attach a proxy scan verdict to. This table stores a
-- content-addressed (checksum_sha256) verdict independent of `artifacts`,
-- preserving the #1278/#1280 invariant. Verdicts are shared across
-- repos/tenants that pull identical bytes (same bytes = same CVEs) and survive
-- proxy-cache eviction.
CREATE TABLE proxy_scan_results (
    id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    checksum_sha256  TEXT NOT NULL,          -- content identity (the cache key)
    scan_type        TEXT NOT NULL,          -- 'grype'
    verdict          TEXT NOT NULL,          -- 'clean' | 'vulnerable' | 'error'
    findings_count   INT  NOT NULL DEFAULT 0,
    critical_count   INT  NOT NULL DEFAULT 0,
    high_count       INT  NOT NULL DEFAULT 0,
    medium_count     INT  NOT NULL DEFAULT 0,
    low_count        INT  NOT NULL DEFAULT 0,
    max_severity     TEXT,                   -- highest observed, for policy compare
    scanner_version  TEXT,                   -- e.g. grype-0.8x + db build => CVE-DB freshness
    repository_id    UUID REFERENCES repositories(id) ON DELETE SET NULL, -- provenance only
    scanned_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT uq_proxy_scan UNIQUE (checksum_sha256, scan_type),
    CONSTRAINT ck_proxy_scan_verdict CHECK (verdict IN ('clean', 'vulnerable', 'error'))
);

CREATE INDEX idx_proxy_scan_checksum ON proxy_scan_results (checksum_sha256, scan_type);

-- #2954: per-repo fail-open (default) / fail-closed (opt-in) action for the
-- inline proxy scan. Reuses the `block_unscanned` semantics: fail-open serves
-- the first pull of an unknown digest immediately (loud: warn + audit +
-- X-AK-Scan: pending) while the async scan populates the verdict; fail-closed
-- blocks (403) on a vulnerable verdict and returns 423 rather than ever serving
-- unscanned bytes when the object is over-cap or the inline scan budget is
-- exceeded. Additive column with a fail-open default so operators who have not
-- opted in see today's behavior unchanged.
ALTER TABLE scan_configs
    ADD COLUMN proxy_scan_action TEXT NOT NULL DEFAULT 'fail_open'
        CHECK (proxy_scan_action IN ('fail_open', 'fail_closed'));
