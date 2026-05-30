-- #1426: Document the deprecation of `cve_history` in favour of
-- `scan_findings` as the source of truth for per-artifact CVE state.
--
-- Context: the table was introduced in migration 045 and intended to be the
-- per-(artifact, cve) rollup for the Security tab. In practice no scanner
-- writes to it (`SbomService::record_cve` has zero callers in the backend),
-- and `scan_findings` (per-scan-run) ended up carrying the live data plus
-- its own acknowledgement state (`is_acknowledged`). #1375 already moved
-- the Security tab read paths to project `scan_findings` into synthetic
-- `CveHistoryEntry` rows; #1426 wires the corresponding acknowledge write
-- path through `POST /sbom/cve/status/by-artifact/{artifact_id}/by-cve/{cve_id}`.
--
-- We keep the table -- not drop it -- so the rare curated / admin write
-- path (`POST /sbom/cve/status/{id}` against a real cve_history row) keeps
-- working, and any rows that customers have populated by hand survive.
-- The COMMENTs below pin the deprecation in the schema itself so the
-- semantics are visible to anyone reading the DB directly via psql `\d`.
--
-- Removal plan: defer until v1.3.0 when we can ship a migration that
-- copies any extant curated rows into `scan_findings`-side comments and
-- drops the table.

COMMENT ON TABLE cve_history IS
    'DEPRECATED (#1426, v1.2.0): never populated by the scanner pipeline. '
    'Use `scan_findings` as the source of truth for per-artifact CVE state. '
    'Retained for the legacy admin/promotion-policy write path '
    '(`SbomService::record_cve`) and `POST /api/v1/sbom/cve/status/{id}`. '
    'New code should write via '
    '`POST /api/v1/sbom/cve/status/by-artifact/{artifact_id}/by-cve/{cve_id}` '
    'which mutates `scan_findings` directly. Removal scheduled for v1.3.0.';

COMMENT ON COLUMN cve_history.status IS
    'DEPRECATED (#1426): the four-state lifecycle (open/fixed/acknowledged/'
    'false_positive) has no direct equivalent on `scan_findings`, whose only '
    'acknowledge column is the boolean `is_acknowledged`. Read paths '
    'collapse `false_positive` and `acknowledged` to "acknowledged" and '
    'cannot represent "fixed" on synth rows.';

COMMENT ON COLUMN cve_history.acknowledged_by IS
    'DEPRECATED (#1426): parallel to `scan_findings.acknowledged_by`; the '
    'Security tab acknowledge button writes the scan_findings copy via '
    '`POST /api/v1/security/findings/{id}/acknowledge` and the '
    '`/cve/status/by-artifact/.../by-cve/...` route.';
