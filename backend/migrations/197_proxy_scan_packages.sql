-- Proxy SBOM: persist the package inventory the inline proxy scan already
-- computes.
--
-- `ScanOutput.packages` is produced by the CVE-authoritative scanner on every
-- proxied download and, before this migration, discarded --
-- `run_inline_proxy_scanners_target` consumed only `findings` and `cataloged`.
-- Retaining it is what makes SBOM generation possible for proxy-cached content
-- without re-fetching or re-scanning the bytes.
--
-- Digest-keyed, exactly like `proxy_scan_results`: proxy content has no
-- `artifacts` row (#1278/#1280), and keying on content means the same bytes
-- cached in many repositories store one inventory. `repository_id` is
-- deliberately absent -- the inventory is a property of the content, not of
-- the tenant that happened to pull it first, and omitting it keeps this table
-- off the cross-tenant eviction path.

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
