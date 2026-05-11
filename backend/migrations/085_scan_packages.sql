-- #903: SBOM must reflect the full dependency tree, not just CVE-bearing
-- components. scan_findings only stores rows for packages with known
-- vulnerabilities; uploading express@4.18.2 (30+ direct deps, no active
-- CVEs in Trivy's DB on a given day) produced an empty SBOM.
--
-- This table is the canonical inventory of every package the scanner saw,
-- regardless of vulnerability status. SBOM generation reads from here first
-- and falls back to scan_findings only for legacy data that pre-dates this
-- migration.
--
-- Separate table (rather than extending scan_findings with severity='info'
-- rows) so that vulnerability aggregation queries do not need to filter,
-- and so columns specific to inventory (purl, license, source_target) can
-- evolve without touching findings.

CREATE TABLE IF NOT EXISTS scan_packages (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_result_id UUID NOT NULL REFERENCES scan_results(id) ON DELETE CASCADE,
    artifact_id UUID NOT NULL REFERENCES artifacts(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    version TEXT,
    purl TEXT,
    license TEXT,
    -- The Trivy `Target` field — e.g. "package-lock.json", "requirements.txt",
    -- "Java", "Pipenv". Useful for SBOM consumers that want to bucket
    -- packages by ecosystem; never user-facing.
    source_target TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- The two read paths: SBOM-for-artifact and admin-debugging-by-scan.
CREATE INDEX IF NOT EXISTS scan_packages_artifact_id_idx
    ON scan_packages (artifact_id);
CREATE INDEX IF NOT EXISTS scan_packages_scan_result_id_idx
    ON scan_packages (scan_result_id);

-- A single scan must not double-insert the same (name, version) tuple,
-- which can otherwise happen when Trivy lists a package both in the
-- standalone Packages section and again inside a Vulnerabilities target
-- (e.g. multi-module Java archives). NULL versions are coalesced so the
-- uniqueness check works on packages whose version Trivy did not resolve.
CREATE UNIQUE INDEX IF NOT EXISTS scan_packages_unique_per_scan
    ON scan_packages (scan_result_id, name, COALESCE(version, ''));
