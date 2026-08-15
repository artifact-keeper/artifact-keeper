-- Proxy-cached artifact security visibility (#3394, #3395).
--
-- Three related objects ship in one slot because they are one feature: the
-- read path for proxy scan visibility (index), the component inventory that
-- backs proxy SBOM generation (proxy_scan_packages), and the per-CVE detail
-- that answers "which CVE blocked my build?" (proxy_scan_findings).
--
-- Everything here is keyed on `checksum_sha256`, never on `artifacts.id`.
-- Proxy-cached bytes are deliberately NOT written to `artifacts` (#1278/#1280),
-- so the artifact-keyed scan pipeline structurally cannot hold a row for them.
-- Content keying also means byte-identical artifacts cached in many
-- repositories store one copy, and no tenant's cache eviction can destroy data
-- another tenant is serving.

-- ---------------------------------------------------------------------------
-- 1. Index: repository catalog -> digest join (#3394)
-- ---------------------------------------------------------------------------
-- GET /api/v1/repositories/:key/security/proxy-scans resolves a repository's
-- cached paths and joins each `checksum_sha256` to `proxy_scan_results` to
-- report a verdict. The summary aggregate scans every catalog row for the
-- repository (`WHERE repository_id = $1 AND checksum_sha256 IS NOT NULL`) and
-- needs the checksum for the join key. `idx_proxy_cache_repo` (repository_id
-- only) does not cover checksum, so the planner falls back to a heap fetch per
-- row. This composite index lets the summary aggregate run as an index-only
-- scan.
CREATE INDEX IF NOT EXISTS idx_proxy_cache_repo_checksum
    ON proxy_cache_artifacts (repository_id, checksum_sha256);

-- ---------------------------------------------------------------------------
-- 2. Package inventory: proxy SBOM generation (#3394)
-- ---------------------------------------------------------------------------
-- `ScanOutput.packages` is produced by the CVE-authoritative scanner on every
-- proxied download and, before this migration, discarded --
-- `run_inline_proxy_scanners_target` consumed only `findings` and `cataloged`.
-- Retaining it is what makes SBOM generation possible for proxy-cached content
-- without re-fetching or re-scanning the bytes.
--
-- `repository_id` is deliberately absent: the inventory is a property of the
-- content, not of the tenant that happened to pull it first, and omitting it
-- keeps this table off the cross-tenant eviction path.
CREATE TABLE IF NOT EXISTS proxy_scan_packages (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    checksum_sha256 TEXT NOT NULL,
    scan_type       TEXT NOT NULL,
    name            TEXT NOT NULL,
    version         TEXT,
    purl            TEXT,
    license         TEXT,
    recorded_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- A scanner can report the same (name, version) twice for one artifact -- e.g.
-- a PyPI wheel's own METADATA plus the synthetic pin `prepare_pinned` writes
-- into the workspace root. `version` is nullable, and NULL never equals NULL in
-- a plain UNIQUE constraint, so the uniqueness key COALESCEs it to a sentinel
-- that cannot collide with a real version string.
CREATE UNIQUE INDEX IF NOT EXISTS uq_proxy_scan_packages
    ON proxy_scan_packages (
        checksum_sha256,
        scan_type,
        name,
        COALESCE(version, '')
    );

-- The read path resolves a cache path to a digest, then fetches the whole
-- inventory for that digest and scan type.
CREATE INDEX IF NOT EXISTS idx_proxy_scan_packages_digest
    ON proxy_scan_packages (checksum_sha256, scan_type);

-- ---------------------------------------------------------------------------
-- 3. Per-CVE detail (#3395)
-- ---------------------------------------------------------------------------
-- `proxy_scan_results` stores counts and max severity per digest; it does not
-- store WHICH CVEs were found. So a blocked pull could report "9 findings, 4
-- high" without being able to answer the operator's actual first question:
-- which CVE blocked my build? The findings already exist in memory at
-- `aggregate_proxy_verdict` and were discarded once the counts were computed.
--
-- Same shape as `proxy_scan_packages` on purpose: digest-keyed, scan-type
-- scoped, deduplicated on write (the pin duplication that inflated
-- `findings_count` applies identically here -- see `dedupe_findings`).
CREATE TABLE IF NOT EXISTS proxy_scan_findings (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    checksum_sha256 TEXT NOT NULL,
    scan_type       TEXT NOT NULL,
    cve_id          TEXT NOT NULL,
    severity        TEXT NOT NULL,
    package_name    TEXT,
    package_version TEXT,
    fixed_version   TEXT,
    title           TEXT,
    recorded_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- One CVE can legitimately appear against several components of the same
-- artifact, so the component is part of the key. NULLs are COALESCEd for the
-- same reason as above.
CREATE UNIQUE INDEX IF NOT EXISTS uq_proxy_scan_findings
    ON proxy_scan_findings (
        checksum_sha256,
        scan_type,
        cve_id,
        COALESCE(package_name, ''),
        COALESCE(package_version, '')
    );

-- Read path: resolve a cache path to a digest, then fetch that digest's CVEs.
CREATE INDEX IF NOT EXISTS idx_proxy_scan_findings_digest
    ON proxy_scan_findings (checksum_sha256, scan_type);

-- Reverse lookup: blast radius asks "which proxy-cached digests carry this
-- CVE?" (#3397).
CREATE INDEX IF NOT EXISTS idx_proxy_scan_findings_cve
    ON proxy_scan_findings (cve_id);
