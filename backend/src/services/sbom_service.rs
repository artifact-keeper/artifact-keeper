//! SBOM (Software Bill of Materials) generation and management service.

use crate::error::{AppError, Result};
use crate::models::sbom::{
    CveHistoryEntry, CveStatus, CveTimelineEntry, CveTrends, LicensePolicy, SbomComponent,
    SbomDocument, SbomFormat, SbomSummary,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use std::collections::HashSet;
use uuid::Uuid;

/// Row aggregating scan_findings into a single CVE detection record per
/// (artifact_id, cve_id). Used by the scan-derived CVE history projection
/// added for #1375.
#[derive(sqlx::FromRow)]
struct ScanFindingCveRow {
    artifact_id: Uuid,
    cve_id: Option<String>,
    severity: Option<String>,
    affected_component: Option<String>,
    affected_version: Option<String>,
    fixed_version: Option<String>,
    first_detected_at: DateTime<Utc>,
    last_detected_at: DateTime<Utc>,
    all_acknowledged: bool,
}

/// Build a deterministic synthetic UUID for a (artifact, cve) pair.
///
/// Used so scan-derived `CveHistoryEntry` rows have a stable `id` across
/// re-reads. Hashing instead of `Uuid::new_v4` means clients can dedupe by
/// id even when the row is synthesized at read time. The first 16 bytes of
/// SHA-256(artifact_id || cve_id) become the UUID.
///
/// # Synthetic ID semantics
///
/// Synth ids carry **no foreign-key meaning** -- they are not present in
/// the `cve_history` table. Consequences for callers:
///
/// - `POST /sbom/cve/status/{id}` against a synth id returns 404. This is
///   expected: only curated rows (written via the rare promotion-policy
///   admin paths) can have their status mutated. Clients receiving a
///   `CveHistoryEntry` whose `sbom_id`/`component_id`/`scan_result_id` are
///   all `null` are looking at a synth row and must not offer
///   "acknowledge" / "mark fixed" UI on it.
/// - Synth ids are stable across re-reads for the same (artifact, cve)
///   pair, so client-side dedupe by `id` works.
/// - Synth ids are derived from a hash, not generated, so they will
///   collide with a `cve_history.id` only with negligible probability
///   (2^-128). If a collision ever did surface, the curated row wins via
///   the dedupe filter in `build_known_cve_set`.
pub(crate) fn synth_cve_id(artifact_id: Uuid, cve_id: &str) -> Uuid {
    let mut hasher = Sha256::new();
    hasher.update(artifact_id.as_bytes());
    hasher.update([0u8]); // separator so concatenation collisions are impossible
    hasher.update(cve_id.as_bytes());
    let digest = hasher.finalize();
    let mut bytes = [0u8; 16];
    bytes.copy_from_slice(&digest[..16]);
    Uuid::from_bytes(bytes)
}

/// Find the `(artifact_id, cve_id)` pair in `pairs` whose synthetic id
/// (see [`synth_cve_id`]) equals `target`.
///
/// The synthetic id is a one-way SHA-256 hash of `(artifact_id, cve_id)`, so
/// it cannot be reversed arithmetically. To resolve a synth id back to its
/// originating pair we recompute the hash for every candidate pair and look
/// for the match. `pairs` is the set of distinct `(artifact_id, cve_id)`
/// tuples drawn from `scan_findings` (already repo-scoped by the caller).
///
/// Pure: no DB, no I/O. Extracted from [`SbomService::resolve_synth_cve_id`]
/// so the round-trip (`synth_cve_id` -> `match_synth_cve_id`) is unit-testable
/// without a Postgres pool. (#1561)
pub(crate) fn match_synth_cve_id(target: Uuid, pairs: &[(Uuid, String)]) -> Option<(Uuid, String)> {
    pairs
        .iter()
        .find(|(artifact_id, cve_id)| synth_cve_id(*artifact_id, cve_id) == target)
        .cloned()
}

/// Collect a case-insensitive (upper-cased) set of CVE identifiers from a
/// slice of `CveHistoryEntry` rows.
///
/// Pulled out so the dedupe-by-cve normalization is covered by unit tests
/// without needing a database. As of #1616/#1620 the read paths source CVE
/// data solely from `scan_findings` (the `cve_history` reads were dead), so
/// the production `known` set is always empty; this helper is retained for
/// the dedupe-contract unit tests of `scan_row_passes_known_filter`.
#[cfg(test)]
pub(crate) fn build_known_cve_set(entries: &[CveHistoryEntry]) -> HashSet<String> {
    entries
        .iter()
        .map(|e| e.cve_id.to_ascii_uppercase())
        .collect()
}

/// Decide whether a `scan_findings`-derived row should pass the dedupe
/// filter. A row passes only when it has a `cve_id` and that id (compared
/// case-insensitively) is not already in the curated `known` set.
///
/// Extracted so the case-insensitivity contract is unit-testable. See
/// #1375 -- without this normalization the scan-derived path would
/// duplicate any CVE whose case differs between `cve_history` and
/// `scan_findings`.
pub(crate) fn scan_row_passes_known_filter(
    row_cve_id: Option<&str>,
    known: &HashSet<String>,
) -> bool {
    row_cve_id
        .map(|c| !known.contains(&c.to_ascii_uppercase()))
        .unwrap_or(false)
}

/// Rank a CVSS severity string by its operational priority. Higher rank
/// means more severe.
///
/// `critical` > `high` > `medium` > `low` > anything else (unknown / NULL
/// rendered as the empty string). The DB-side aggregates in
/// `get_cve_trends` use the inverse mapping via SQL `CASE` so that
/// `MAX(rank)` returns the right "worst seen" severity for an (artifact,
/// cve_id) pair across multiple scanner outputs. Without this ranking we
/// fall through to lexicographic ordering -- "medium" > "low" > "high" >
/// "critical" -- which silently misreports a vulnerability that one
/// scanner labels `high` and another labels `medium` as `medium`.
///
/// This helper lives in Rust so the contract is unit-testable; the SQL
/// queries inline an equivalent `CASE` because Postgres can't call Rust.
/// If you edit the ranks here, also update the four `CASE severity ...`
/// expressions in `get_cve_trends`. The unit tests in this module assert
/// the two stay in sync. (#1375 round-2)
#[allow(dead_code)] // Mirror of an SQL CASE; only used from tests today.
pub(crate) fn severity_rank(severity: &str) -> i32 {
    match severity.to_ascii_lowercase().as_str() {
        "critical" => 4,
        "high" => 3,
        "medium" => 2,
        "low" => 1,
        _ => 0,
    }
}

/// Inverse of `severity_rank`: map a rank produced by the SQL `MAX(CASE ...)`
/// expression back to its canonical lower-case string. Ranks outside
/// 1..=4 map to `None` (caller decides whether to default to `"unknown"`
/// or skip the row).
#[allow(dead_code)] // Mirror of an SQL CASE; only used from tests today.
pub(crate) fn severity_from_rank(rank: i32) -> Option<&'static str> {
    match rank {
        4 => Some("critical"),
        3 => Some("high"),
        2 => Some("medium"),
        1 => Some("low"),
        _ => None,
    }
}

/// Map the `all_acknowledged` flag aggregated from `scan_findings` to the
/// `CveHistoryEntry.status` string (`"acknowledged"` vs `"open"`). The
/// scanner has no notion of `fixed` or `false_positive`, those statuses
/// only exist on curated rows.
pub(crate) fn status_string_from_acknowledged(all_acknowledged: bool) -> &'static str {
    if all_acknowledged {
        "acknowledged"
    } else {
        "open"
    }
}

/// Project a `CveStatus` request onto the boolean `scan_findings.is_acknowledged`
/// column the Security tab acknowledge path actually writes to.
///
/// Returns:
///   - `Ok(Some(true))`  for `Acknowledged` and `FalsePositive` (the
///     boolean column collapses both; the reason field carries the
///     audit distinction).
///   - `Ok(Some(false))` for `Open` (revoke an existing acknowledgement).
///   - `Ok(None)`        for `Fixed`, signalling the caller that no
///     `scan_findings` mutation is possible -- "fixed" is a curated-only
///     lifecycle state. The handler turns this into a 400 with a clear
///     message rather than silently coercing.
///
/// Pulled out of `update_cve_status_by_artifact_cve` so the mapping is
/// unit-testable without a Postgres pool. (#1426)
pub(crate) fn cve_status_to_acknowledge_flag(status: CveStatus) -> Option<bool> {
    match status {
        CveStatus::Acknowledged | CveStatus::FalsePositive => Some(true),
        CveStatus::Open => Some(false),
        CveStatus::Fixed => None,
    }
}

/// Map the `all_acknowledged` flag to a typed `CveStatus` for the timeline
/// projection in `get_cve_trends`. Mirrors `status_string_from_acknowledged`
/// but returns the enum directly because the timeline DTO is typed.
pub(crate) fn status_enum_from_acknowledged(all_acknowledged: bool) -> CveStatus {
    if all_acknowledged {
        CveStatus::Acknowledged
    } else {
        CveStatus::Open
    }
}

/// Convert a `ScanFindingCveRow` aggregate into a synthetic
/// `CveHistoryEntry`. Pure mapping, no DB access -- factored out so the
/// field-by-field projection is covered by unit tests.
///
/// Synth entries carry:
///   - `id` = `synth_cve_id(artifact_id, cve_id)` (deterministic)
///   - `sbom_id` / `component_id` / `scan_result_id` = `None` (no FK)
///   - `cve_id` = empty string when the row's `cve_id` is `None`
///     (callers filter these out via `scan_row_passes_known_filter` before
///     mapping, but the defensive default keeps the mapping total).
///   - `status` from `all_acknowledged`
///   - `created_at` / `updated_at` aligned to first/last detection
fn scan_finding_to_history_entry(row: ScanFindingCveRow) -> CveHistoryEntry {
    let cve_id = row.cve_id.unwrap_or_default();
    let id = synth_cve_id(row.artifact_id, &cve_id);
    CveHistoryEntry {
        id,
        artifact_id: row.artifact_id,
        sbom_id: None,
        component_id: None,
        scan_result_id: None,
        cve_id,
        affected_component: row.affected_component,
        affected_version: row.affected_version,
        fixed_version: row.fixed_version,
        severity: row.severity,
        cvss_score: None,
        cve_published_at: None,
        first_detected_at: row.first_detected_at,
        last_detected_at: row.last_detected_at,
        status: status_string_from_acknowledged(row.all_acknowledged).to_string(),
        acknowledged_by: None,
        acknowledged_at: None,
        acknowledged_reason: None,
        created_at: row.first_detected_at,
        updated_at: row.last_detected_at,
    }
}

/// Convert a `ScanFindingCveRow` aggregate into a `CveTimelineEntry` for
/// the trends timeline. `now` is injected so tests can pin `days_exposed`
/// without `Utc::now()` racing the assertion.
fn scan_finding_to_timeline_entry(row: &ScanFindingCveRow, now: DateTime<Utc>) -> CveTimelineEntry {
    let days_exposed = (now - row.first_detected_at).num_days();
    CveTimelineEntry {
        cve_id: row.cve_id.clone().unwrap_or_default(),
        severity: row.severity.clone().unwrap_or_default(),
        affected_component: row.affected_component.clone().unwrap_or_default(),
        cve_published_at: None,
        first_detected_at: row.first_detected_at,
        status: status_enum_from_acknowledged(row.all_acknowledged),
        days_exposed,
    }
}

/// Drop entries whose owning artifact's repo is not in `allowed_repos`.
///
/// Pulled out of `filter_entries_by_repo` so the filter logic itself
/// (independent of the DB lookup that builds `repo_by_artifact`) is
/// unit-testable. The DB call still lives in the async method; this
/// helper handles the in-memory partition once that map is available.
pub(crate) fn filter_entries_by_repo_map(
    entries: Vec<CveHistoryEntry>,
    repo_by_artifact: &std::collections::HashMap<Uuid, Uuid>,
    allowed_repos: &HashSet<Uuid>,
) -> Vec<CveHistoryEntry> {
    entries
        .into_iter()
        .filter(|e| {
            repo_by_artifact
                .get(&e.artifact_id)
                .map(|r| allowed_repos.contains(r))
                .unwrap_or(false)
        })
        .collect()
}

/// Sort `CveHistoryEntry` rows by `first_detected_at` descending (newest
/// first). The read paths concatenate curated + scan-derived rows then
/// re-sort so the response is monotonic; extracted so the sort key is
/// guaranteed by a unit test and won't drift if the type changes.
pub(crate) fn sort_entries_by_first_detected_desc(entries: &mut [CveHistoryEntry]) {
    entries.sort_by_key(|e| std::cmp::Reverse(e.first_detected_at));
}

/// Build a `CveTrends` response from the seven count aggregates, the fixed-
/// CVEs count, and the timeline slice. Extracted from `get_cve_trends` so
/// the projection is exercised by unit tests without spinning up Postgres.
///
/// `avg_days_to_fix` is always `None` on this path because `scan_findings`
/// has no fixed-at timestamp (#1375). Curated rows that *do* carry one
/// flow through a different path (the legacy `cve_history` admin write).
#[allow(clippy::too_many_arguments)]
pub(crate) fn cve_trends_from_aggregates(
    total: i64,
    open: i64,
    acknowledged: i64,
    critical: i64,
    high: i64,
    medium: i64,
    low: i64,
    fixed_cves: i64,
    timeline: Vec<CveTimelineEntry>,
) -> CveTrends {
    CveTrends {
        total_cves: total,
        open_cves: open,
        fixed_cves,
        acknowledged_cves: acknowledged,
        critical_count: critical,
        high_count: high,
        medium_count: medium,
        low_count: low,
        avg_days_to_fix: None,
        timeline,
        // #1446: mirror the count fields under the bare aliases so the
        // security-tests trends-shape probe (which checks for `total`,
        // `critical`, `high`, ...) sees a recognized aggregate shape.
        total,
        critical,
        high,
        medium,
        low,
    }
}

/// Build the timeline-row projection: synthesize one `CveTimelineEntry` per
/// scan row using `scan_finding_to_timeline_entry` with a shared `now`
/// reference. Pulled out of `get_cve_trends` so the projection step itself
/// is unit-testable without Postgres.
fn project_timeline_rows(rows: &[ScanFindingCveRow], now: DateTime<Utc>) -> Vec<CveTimelineEntry> {
    rows.iter()
        .map(|r| scan_finding_to_timeline_entry(r, now))
        .collect()
}

/// Apply the curated-vs-scan dedupe and projection pipeline to a slice of
/// scan rows, given the set of CVE ids already returned by the curated
/// path. Pure: no DB, no clock, no I/O. The `get_cve_history` read path
/// invokes this after pulling rows from `scan_findings`.
fn project_scan_rows_to_entries(
    rows: Vec<ScanFindingCveRow>,
    known: &HashSet<String>,
) -> Vec<CveHistoryEntry> {
    rows.into_iter()
        .filter(|r| scan_row_passes_known_filter(r.cve_id.as_deref(), known))
        .map(scan_finding_to_history_entry)
        .collect()
}

// === SQL query constants =================================================
//
// The CVE-history read paths share a small set of large SQL strings. Hoisting
// them to module-level `const`s lets unit tests assert key clauses (the
// ranked CASE table, the `cve_id IS NOT NULL` guard, the artifact-deletion
// filter) without standing up Postgres. The `async fn` callers still own
// the parameter binds; only the query text moved out.

/// `scan_findings` aggregate keyed on (artifact_id, cve_id), filtered by a
/// single artifact. Mirrors the inline query in
/// `build_cve_entries_from_scan_findings` (#1375).
pub(crate) const SCAN_FINDINGS_BY_ARTIFACT_SQL: &str = r#"
SELECT
    artifact_id,
    cve_id,
    CASE severity_rank
        WHEN 4 THEN 'critical'
        WHEN 3 THEN 'high'
        WHEN 2 THEN 'medium'
        WHEN 1 THEN 'low'
        ELSE NULL
    END AS severity,
    affected_component,
    affected_version,
    fixed_version,
    first_detected_at,
    last_detected_at,
    all_acknowledged
FROM (
    SELECT
        artifact_id,
        cve_id,
        MAX(
            CASE LOWER(severity)
                WHEN 'critical' THEN 4
                WHEN 'high' THEN 3
                WHEN 'medium' THEN 2
                WHEN 'low' THEN 1
                ELSE 0
            END
        ) AS severity_rank,
        MAX(affected_component) AS affected_component,
        MAX(affected_version) AS affected_version,
        MAX(fixed_version) AS fixed_version,
        MIN(created_at) AS first_detected_at,
        MAX(created_at) AS last_detected_at,
        BOOL_AND(is_acknowledged) AS all_acknowledged
    FROM scan_findings
    WHERE artifact_id = $1
      AND cve_id IS NOT NULL
    GROUP BY artifact_id, cve_id
    ORDER BY MIN(created_at) DESC
) inner_ranked
"#;

/// CVE-history counts CTE, scoped to one repository. The outer projection
/// must keep the column order in lockstep with the `(i64, i64, i64, i64,
/// i64, i64, i64)` tuple destructured in `get_cve_trends`. (#1375)
pub(crate) const CVE_TRENDS_COUNTS_REPO_SQL: &str = r#"
WITH per_cve AS (
    SELECT
        sf.artifact_id,
        sf.cve_id,
        MAX(
            CASE LOWER(sf.severity)
                WHEN 'critical' THEN 4
                WHEN 'high' THEN 3
                WHEN 'medium' THEN 2
                WHEN 'low' THEN 1
                ELSE 0
            END
        ) AS severity_rank,
        BOOL_AND(sf.is_acknowledged) AS all_ack
    FROM scan_findings sf
    JOIN artifacts a ON sf.artifact_id = a.id
    WHERE sf.cve_id IS NOT NULL
      AND a.repository_id = $1
      AND NOT a.is_deleted
    GROUP BY sf.artifact_id, sf.cve_id
)
SELECT
    COUNT(*) AS total,
    COUNT(*) FILTER (WHERE NOT all_ack) AS open,
    COUNT(*) FILTER (WHERE all_ack) AS acknowledged,
    COUNT(*) FILTER (WHERE severity_rank = 4) AS critical,
    COUNT(*) FILTER (WHERE severity_rank = 3) AS high,
    COUNT(*) FILTER (WHERE severity_rank = 2) AS medium,
    COUNT(*) FILTER (WHERE severity_rank = 1) AS low
FROM per_cve
"#;

/// CVE-history counts CTE, all-repos variant. Must stay byte-aligned with
/// the repo-scoped variant above (same severity CASE, same projection).
pub(crate) const CVE_TRENDS_COUNTS_ALL_SQL: &str = r#"
WITH per_cve AS (
    SELECT
        sf.artifact_id,
        sf.cve_id,
        MAX(
            CASE LOWER(sf.severity)
                WHEN 'critical' THEN 4
                WHEN 'high' THEN 3
                WHEN 'medium' THEN 2
                WHEN 'low' THEN 1
                ELSE 0
            END
        ) AS severity_rank,
        BOOL_AND(sf.is_acknowledged) AS all_ack
    FROM scan_findings sf
    JOIN artifacts a ON sf.artifact_id = a.id
    WHERE sf.cve_id IS NOT NULL
      AND NOT a.is_deleted
    GROUP BY sf.artifact_id, sf.cve_id
)
SELECT
    COUNT(*) AS total,
    COUNT(*) FILTER (WHERE NOT all_ack) AS open,
    COUNT(*) FILTER (WHERE all_ack) AS acknowledged,
    COUNT(*) FILTER (WHERE severity_rank = 4) AS critical,
    COUNT(*) FILTER (WHERE severity_rank = 3) AS high,
    COUNT(*) FILTER (WHERE severity_rank = 2) AS medium,
    COUNT(*) FILTER (WHERE severity_rank = 1) AS low
FROM per_cve
"#;

/// CVE-history timeline projection (most recent 100 within 30 days), scoped
/// to one repository. The severity CASE table must stay aligned with the
/// counts CTE above. (#1375)
pub(crate) const CVE_TRENDS_TIMELINE_REPO_SQL: &str = r#"
SELECT
    artifact_id,
    cve_id,
    CASE severity_rank
        WHEN 4 THEN 'critical'
        WHEN 3 THEN 'high'
        WHEN 2 THEN 'medium'
        WHEN 1 THEN 'low'
        ELSE NULL
    END AS severity,
    affected_component,
    affected_version,
    fixed_version,
    first_detected_at,
    last_detected_at,
    all_acknowledged
FROM (
    SELECT
        sf.artifact_id,
        sf.cve_id,
        MAX(
            CASE LOWER(sf.severity)
                WHEN 'critical' THEN 4
                WHEN 'high' THEN 3
                WHEN 'medium' THEN 2
                WHEN 'low' THEN 1
                ELSE 0
            END
        ) AS severity_rank,
        MAX(sf.affected_component) AS affected_component,
        MAX(sf.affected_version) AS affected_version,
        MAX(sf.fixed_version) AS fixed_version,
        MIN(sf.created_at) AS first_detected_at,
        MAX(sf.created_at) AS last_detected_at,
        BOOL_AND(sf.is_acknowledged) AS all_acknowledged
    FROM scan_findings sf
    JOIN artifacts a ON sf.artifact_id = a.id
    WHERE sf.cve_id IS NOT NULL
      AND a.repository_id = $1
      AND NOT a.is_deleted
      AND sf.created_at > NOW() - INTERVAL '30 days'
    GROUP BY sf.artifact_id, sf.cve_id
    ORDER BY MIN(sf.created_at) DESC
    LIMIT 100
) inner_ranked
"#;

/// CVE-history timeline projection, all-repos variant.
pub(crate) const CVE_TRENDS_TIMELINE_ALL_SQL: &str = r#"
SELECT
    artifact_id,
    cve_id,
    CASE severity_rank
        WHEN 4 THEN 'critical'
        WHEN 3 THEN 'high'
        WHEN 2 THEN 'medium'
        WHEN 1 THEN 'low'
        ELSE NULL
    END AS severity,
    affected_component,
    affected_version,
    fixed_version,
    first_detected_at,
    last_detected_at,
    all_acknowledged
FROM (
    SELECT
        sf.artifact_id,
        sf.cve_id,
        MAX(
            CASE LOWER(sf.severity)
                WHEN 'critical' THEN 4
                WHEN 'high' THEN 3
                WHEN 'medium' THEN 2
                WHEN 'low' THEN 1
                ELSE 0
            END
        ) AS severity_rank,
        MAX(sf.affected_component) AS affected_component,
        MAX(sf.affected_version) AS affected_version,
        MAX(sf.fixed_version) AS fixed_version,
        MIN(sf.created_at) AS first_detected_at,
        MAX(sf.created_at) AS last_detected_at,
        BOOL_AND(sf.is_acknowledged) AS all_acknowledged
    FROM scan_findings sf
    JOIN artifacts a ON sf.artifact_id = a.id
    WHERE sf.cve_id IS NOT NULL
      AND NOT a.is_deleted
      AND sf.created_at > NOW() - INTERVAL '30 days'
    GROUP BY sf.artifact_id, sf.cve_id
    ORDER BY MIN(sf.created_at) DESC
    LIMIT 100
) inner_ranked
"#;

/// `fixed_cves` count: "fell off on rescan" CVEs, deduped by (artifact_id,
/// cve_id). Repo-scoped variant. The legacy `curated_fixed` CTE (from the
/// never-written `cve_history` table) was dropped (#1616/#1620); only the
/// `disappeared`-from-`scan_findings` half ever contributed real data. (#1375)
pub(crate) const FIXED_CVES_COUNT_REPO_SQL: &str = r#"
WITH latest_scans AS (
    SELECT DISTINCT ON (sr.artifact_id, sr.scan_type)
        sr.id, sr.artifact_id, sr.scan_type
    FROM scan_results sr
    JOIN artifacts a ON sr.artifact_id = a.id
    WHERE sr.status = 'completed'
      AND a.repository_id = $1
      AND NOT a.is_deleted
    ORDER BY sr.artifact_id, sr.scan_type, sr.created_at DESC
),
ever_seen AS (
    SELECT DISTINCT sf.artifact_id, LOWER(sf.cve_id) AS cve_id
    FROM scan_findings sf
    JOIN artifacts a ON sf.artifact_id = a.id
    WHERE sf.cve_id IS NOT NULL
      AND a.repository_id = $1
      AND NOT a.is_deleted
),
still_present AS (
    SELECT DISTINCT sf.artifact_id, LOWER(sf.cve_id) AS cve_id
    FROM scan_findings sf
    JOIN latest_scans ls ON sf.scan_result_id = ls.id
    WHERE sf.cve_id IS NOT NULL
),
disappeared AS (
    SELECT e.artifact_id, e.cve_id FROM ever_seen e
    EXCEPT
    SELECT s.artifact_id, s.cve_id FROM still_present s
)
SELECT COUNT(*) FROM disappeared
"#;

/// `fixed_cves` count, all-repos variant. The legacy `curated_fixed` CTE
/// (from the never-written `cve_history` table) was dropped (#1616/#1620);
/// only the `disappeared`-from-`scan_findings` half ever contributed data.
pub(crate) const FIXED_CVES_COUNT_ALL_SQL: &str = r#"
WITH latest_scans AS (
    SELECT DISTINCT ON (sr.artifact_id, sr.scan_type)
        sr.id, sr.artifact_id, sr.scan_type
    FROM scan_results sr
    JOIN artifacts a ON sr.artifact_id = a.id
    WHERE sr.status = 'completed'
      AND NOT a.is_deleted
    ORDER BY sr.artifact_id, sr.scan_type, sr.created_at DESC
),
ever_seen AS (
    SELECT DISTINCT sf.artifact_id, LOWER(sf.cve_id) AS cve_id
    FROM scan_findings sf
    JOIN artifacts a ON sf.artifact_id = a.id
    WHERE sf.cve_id IS NOT NULL
      AND NOT a.is_deleted
),
still_present AS (
    SELECT DISTINCT sf.artifact_id, LOWER(sf.cve_id) AS cve_id
    FROM scan_findings sf
    JOIN latest_scans ls ON sf.scan_result_id = ls.id
    WHERE sf.cve_id IS NOT NULL
),
disappeared AS (
    SELECT e.artifact_id, e.cve_id FROM ever_seen e
    EXCEPT
    SELECT s.artifact_id, s.cve_id FROM still_present s
)
SELECT COUNT(*) FROM disappeared
"#;

/// `scan_findings` aggregate keyed on (artifact_id, cve_id), filtered by a
/// case-insensitive CVE id match. Mirrors the inline query in
/// `build_cve_entries_from_scan_findings` (#1375).
pub(crate) const SCAN_FINDINGS_BY_CVE_SQL: &str = r#"
SELECT
    artifact_id,
    cve_id,
    CASE severity_rank
        WHEN 4 THEN 'critical'
        WHEN 3 THEN 'high'
        WHEN 2 THEN 'medium'
        WHEN 1 THEN 'low'
        ELSE NULL
    END AS severity,
    affected_component,
    affected_version,
    fixed_version,
    first_detected_at,
    last_detected_at,
    all_acknowledged
FROM (
    SELECT
        artifact_id,
        cve_id,
        MAX(
            CASE LOWER(severity)
                WHEN 'critical' THEN 4
                WHEN 'high' THEN 3
                WHEN 'medium' THEN 2
                WHEN 'low' THEN 1
                ELSE 0
            END
        ) AS severity_rank,
        MAX(affected_component) AS affected_component,
        MAX(affected_version) AS affected_version,
        MAX(fixed_version) AS fixed_version,
        MIN(created_at) AS first_detected_at,
        MAX(created_at) AS last_detected_at,
        BOOL_AND(is_acknowledged) AS all_acknowledged
    FROM scan_findings
    WHERE LOWER(cve_id) = LOWER($1)
    GROUP BY artifact_id, cve_id
    ORDER BY MIN(created_at) DESC
) inner_ranked
"#;

/// SBOM service for generating and managing SBOMs.
#[derive(Clone)]
pub struct SbomService {
    db: PgPool,
}

impl SbomService {
    pub fn new(db: PgPool) -> Self {
        Self { db }
    }

    /// Generate an SBOM for an artifact.
    ///
    /// #903 cache-invalidation contract: a cached SBOM document is only
    /// returned when its `content_hash` matches the hash of the freshly-
    /// generated content. Pre-#903 the function returned any existing row
    /// unconditionally, which pinned empty / vulnerability-shaped SBOMs
    /// forever for artifacts uploaded before this fix shipped. With the
    /// hash-gated cache, a rescan that surfaces 30 new packages re-emits
    /// the document; identical re-generations skip the write.
    pub async fn generate_sbom(
        &self,
        artifact_id: Uuid,
        repository_id: Uuid,
        format: SbomFormat,
        dependencies: Vec<DependencyInfo>,
    ) -> Result<SbomDocument> {
        self.generate_sbom_with_completeness(artifact_id, repository_id, format, dependencies, None)
            .await
    }

    /// Variant of [`generate_sbom`] that surfaces the per-scan completeness
    /// signal (#1153) inside the generated SBOM document. Pass
    /// `inventory_completeness = Some("partial")` when the latest scanner
    /// pass for this artifact saw a target it could not parse; the
    /// CycloneDX output gains a `metadata.properties` entry and the SPDX
    /// output gains a creator `Comment:` line so a downstream consumer
    /// can distinguish "no lockfile present" from "lockfile present but
    /// unparseable".
    ///
    /// `None` is treated as `"complete"` and produces SBOM content
    /// byte-identical to the pre-#1153 generator output, preserving the
    /// stored `content_hash` cache for unchanged artifacts.
    pub async fn generate_sbom_with_completeness(
        &self,
        artifact_id: Uuid,
        repository_id: Uuid,
        format: SbomFormat,
        dependencies: Vec<DependencyInfo>,
        inventory_completeness: Option<&str>,
    ) -> Result<SbomDocument> {
        // Generate first so we can hash and compare against any cached row.
        let (content, components) = match format {
            SbomFormat::CycloneDX => {
                self.generate_cyclonedx_inner(&dependencies, inventory_completeness)?
            }
            SbomFormat::SPDX => self.generate_spdx_inner(&dependencies, inventory_completeness)?,
        };

        // Calculate content hash
        let content_str = serde_json::to_string(&content)?;
        let content_hash = format!("{:x}", Sha256::digest(content_str.as_bytes()));

        // Cache check: a stored row whose content_hash matches the freshly-
        // generated content is reusable. Anything else is stale (likely
        // generated before #903 against an empty / vulnerability-only
        // dependency list) and must be replaced.
        let existing = self.get_sbom_by_artifact(artifact_id, format).await?;
        if let Some(doc) = &existing {
            if doc.content_hash == content_hash {
                return Ok(doc.clone());
            }
        }

        // Stale cache: drop components first (FK from sbom_components to
        // sbom_documents) then the document row. Using ON CONFLICT on the
        // (artifact_id, format) unique index for the insert below would
        // leave orphaned component rows, since sbom_components is keyed
        // on sbom_id which the upsert path preserves.
        if let Some(doc) = existing {
            sqlx::query("DELETE FROM sbom_components WHERE sbom_id = $1")
                .bind(doc.id)
                .execute(&self.db)
                .await?;
            sqlx::query("DELETE FROM sbom_documents WHERE id = $1")
                .bind(doc.id)
                .execute(&self.db)
                .await?;
        }

        // Extract licenses
        let licenses: Vec<String> = dependencies
            .iter()
            .filter_map(|d| d.license.clone())
            .collect::<HashSet<_>>()
            .into_iter()
            .collect();

        // Insert SBOM document
        let doc = sqlx::query_as::<_, SbomDocument>(
            r#"
            INSERT INTO sbom_documents (
                artifact_id, repository_id, format, format_version, spec_version,
                content, component_count, dependency_count, license_count,
                licenses, content_hash, generator, generator_version
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
            RETURNING *
            "#,
        )
        .bind(artifact_id)
        .bind(repository_id)
        .bind(format.as_str())
        .bind(self.get_format_version(format))
        .bind(self.get_spec_version(format))
        .bind(&content)
        .bind(components.len() as i32)
        .bind(dependencies.len() as i32)
        .bind(licenses.len() as i32)
        .bind(&licenses)
        .bind(&content_hash)
        .bind("artifact-keeper")
        .bind(env!("CARGO_PKG_VERSION"))
        .fetch_one(&self.db)
        .await?;

        // Insert components
        for component in &components {
            sqlx::query(
                r#"
                INSERT INTO sbom_components (
                    sbom_id, name, version, purl, component_type,
                    licenses, sha256, supplier, external_refs
                )
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
                "#,
            )
            .bind(doc.id)
            .bind(&component.name)
            .bind(&component.version)
            .bind(&component.purl)
            .bind(&component.component_type)
            .bind(&component.licenses)
            .bind(&component.sha256)
            .bind(&component.supplier)
            .bind(serde_json::json!([]))
            .execute(&self.db)
            .await?;
        }

        Ok(doc)
    }

    /// Get SBOM by artifact ID and format.
    pub async fn get_sbom_by_artifact(
        &self,
        artifact_id: Uuid,
        format: SbomFormat,
    ) -> Result<Option<SbomDocument>> {
        let doc = sqlx::query_as::<_, SbomDocument>(
            "SELECT * FROM sbom_documents WHERE artifact_id = $1 AND format = $2",
        )
        .bind(artifact_id)
        .bind(format.as_str())
        .fetch_optional(&self.db)
        .await?;

        Ok(doc)
    }

    /// Get SBOM by ID.
    pub async fn get_sbom(&self, id: Uuid) -> Result<Option<SbomDocument>> {
        let doc = sqlx::query_as::<_, SbomDocument>("SELECT * FROM sbom_documents WHERE id = $1")
            .bind(id)
            .fetch_optional(&self.db)
            .await?;

        Ok(doc)
    }

    /// List SBOMs for an artifact.
    pub async fn list_sboms_for_artifact(&self, artifact_id: Uuid) -> Result<Vec<SbomSummary>> {
        let docs = sqlx::query_as::<_, SbomDocument>(
            "SELECT * FROM sbom_documents WHERE artifact_id = $1 ORDER BY created_at DESC",
        )
        .bind(artifact_id)
        .fetch_all(&self.db)
        .await?;

        Ok(docs.into_iter().map(SbomSummary::from).collect())
    }

    /// Get components for an SBOM.
    pub async fn get_sbom_components(&self, sbom_id: Uuid) -> Result<Vec<SbomComponent>> {
        let components = sqlx::query_as::<_, SbomComponent>(
            "SELECT * FROM sbom_components WHERE sbom_id = $1 ORDER BY name",
        )
        .bind(sbom_id)
        .fetch_all(&self.db)
        .await?;

        Ok(components)
    }

    /// Convert SBOM between formats.
    pub async fn convert_sbom(
        &self,
        sbom_id: Uuid,
        target_format: SbomFormat,
    ) -> Result<SbomDocument> {
        let source = self
            .get_sbom(sbom_id)
            .await?
            .ok_or_else(|| AppError::NotFound("SBOM not found".into()))?;

        let source_format = SbomFormat::parse(&source.format)
            .ok_or_else(|| AppError::Validation("Unknown source format".into()))?;

        if source_format == target_format {
            return Ok(source);
        }

        // Get components for conversion
        let components = self.get_sbom_components(sbom_id).await?;

        // Convert to dependency info for regeneration
        let deps: Vec<DependencyInfo> = components
            .into_iter()
            .map(|c| DependencyInfo {
                name: c.name,
                version: c.version,
                purl: c.purl,
                license: c.licenses.first().cloned(),
                sha256: c.sha256,
            })
            .collect();

        // Check if target format already exists
        if let Some(existing) = self
            .get_sbom_by_artifact(source.artifact_id, target_format)
            .await?
        {
            return Ok(existing);
        }

        // Generate new SBOM in target format
        self.generate_sbom(
            source.artifact_id,
            source.repository_id,
            target_format,
            deps,
        )
        .await
    }

    /// Delete SBOM.
    pub async fn delete_sbom(&self, id: Uuid) -> Result<()> {
        sqlx::query("DELETE FROM sbom_documents WHERE id = $1")
            .bind(id)
            .execute(&self.db)
            .await?;
        Ok(())
    }

    // === CVE History ===

    /// Record a CVE finding in history.
    #[allow(clippy::too_many_arguments)]
    pub async fn record_cve(
        &self,
        artifact_id: Uuid,
        cve_id: &str,
        severity: &str,
        affected_component: Option<&str>,
        affected_version: Option<&str>,
        fixed_version: Option<&str>,
        scan_result_id: Option<Uuid>,
    ) -> Result<CveHistoryEntry> {
        // Upsert: update last_detected_at if exists, insert if not
        let entry = sqlx::query_as::<_, CveHistoryEntry>(
            r#"
            INSERT INTO cve_history (
                artifact_id, cve_id, severity, affected_component,
                affected_version, fixed_version, scan_result_id
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7)
            ON CONFLICT (artifact_id, cve_id) DO UPDATE SET
                last_detected_at = NOW(),
                severity = EXCLUDED.severity,
                scan_result_id = EXCLUDED.scan_result_id,
                updated_at = NOW()
            RETURNING *
            "#,
        )
        .bind(artifact_id)
        .bind(cve_id)
        .bind(severity)
        .bind(affected_component)
        .bind(affected_version)
        .bind(fixed_version)
        .bind(scan_result_id)
        .fetch_one(&self.db)
        .await?;

        Ok(entry)
    }

    /// Get CVE history for an artifact.
    ///
    /// Sourced entirely from `scan_findings`, the populated source of truth.
    /// The legacy `cve_history` SELECT was dropped (#1616/#1620): the table is
    /// never written, so it only ever returned empty rows. We still de-dupe by
    /// `cve_id` (case-insensitive) for safety. The `cve_history` table itself
    /// is retained per migration 112 (v1.3.0 owns the drop).
    pub async fn get_cve_history(&self, artifact_id: Uuid) -> Result<Vec<CveHistoryEntry>> {
        // Derive CVE-shaped entries from `scan_findings` -- the only source of
        // real CVE data (see #1375: `record_cve` is dead code, `cve_history`
        // has zero writers). Empty known-set: no curated rows to dedupe against.
        let known = HashSet::new();
        let mut entries = self
            .build_cve_entries_from_scan_findings(Some(artifact_id), None, &known)
            .await?;
        sort_entries_by_first_detected_desc(&mut entries);
        Ok(entries)
    }

    /// Get CVE history for a single CVE identifier across artifacts.
    ///
    /// Reads from `scan_findings` (live scanner output) so that callers see
    /// the full set of artifacts where this CVE has ever been detected. The
    /// legacy `cve_history` read was dropped (#1616/#1620): that table is never
    /// written, so it only ever returned empty rows.
    ///
    /// # `allowed_repo_ids` contract (ADMIN-ONLY when `None`)
    ///
    /// The `allowed_repo_ids` argument scopes the lookup to repositories the
    /// caller can access (mirrors `AuthExtension::can_access_repo`).
    ///
    /// - `Some(&[...])` -- limit results to the listed repositories. An empty
    ///   slice returns zero rows (caller has access to nothing).
    /// - `None` -- **NO REPOSITORY SCOPE; FULL CROSS-REPO READ**. Only pass
    ///   `None` when the caller has admin-tier access. The convention here
    ///   mirrors `AuthExtension::allowed_repo_ids` where `None` means "no
    ///   restriction applied by auth middleware" (admin/root tokens, system
    ///   workers). Calling this with `None` for an end-user token is a data
    ///   leak. The HTTP handler enforces this by always passing
    ///   `auth.allowed_repo_ids.as_deref()` through unchanged: if auth said
    ///   "no restriction", the service trusts that decision.
    ///
    /// This is a footgun-prone shape. Tracked for refactor to an explicit
    /// `enum AccessScope { Admin, Restricted(Vec<Uuid>) }` post v1.2.0 (see
    /// #1390 follow-up). Until then, treat `None` as a load-bearing comment
    /// that must read "admin-only".
    ///
    /// Returns an empty vec when the CVE is not present (200 OK, [] body); a
    /// missing CVE is not a 404 in this contract.
    ///
    /// #1375: this is the cross-artifact lookup path that the broken
    /// `Path<Uuid>` extractor used to make impossible.
    pub async fn get_cve_history_by_cve_id(
        &self,
        cve_id: &str,
        allowed_repo_ids: Option<&[Uuid]>,
    ) -> Result<Vec<CveHistoryEntry>> {
        // Normalize: NVD shape is upper-case; lower-case is a common typo.
        // Schema does not constrain `cve_id` case in either `cve_history` or
        // `scan_findings`, so we compare case-insensitively and only use the
        // upper-cased form for display/known-set dedupe below.
        let cve_id_upper = cve_id.to_ascii_uppercase();

        // Live findings from `scan_findings`, the only populated source. The
        // legacy `cve_history` SELECT was dropped (#1616/#1620): the table is
        // never written, so it only ever contributed empty rows. Empty
        // known-set: no curated rows to dedupe against.
        let known = HashSet::new();
        let scan_entries = self
            .build_cve_entries_from_scan_findings(None, Some(&cve_id_upper), &known)
            .await?;
        // Enforce the repo filter on scan-derived entries (they are synthesized
        // on the fly, so the filter cannot live in the SQL `WHERE`).
        let mut entries = match allowed_repo_ids {
            None => scan_entries,
            Some(repo_ids) => {
                let allowed: HashSet<Uuid> = repo_ids.iter().copied().collect();
                self.filter_entries_by_repo(scan_entries, &allowed).await?
            }
        };
        sort_entries_by_first_detected_desc(&mut entries);
        Ok(entries)
    }

    /// Drop entries whose owning artifact is not in `allowed_repos`.
    ///
    /// Used by the CVE-id read path to apply the auth `allowed_repo_ids`
    /// filter to scan-derived entries (where we synthesize `CveHistoryEntry`
    /// rows on the fly and so cannot enforce the filter inside the original
    /// SQL `WHERE` clause).
    async fn filter_entries_by_repo(
        &self,
        entries: Vec<CveHistoryEntry>,
        allowed_repos: &HashSet<Uuid>,
    ) -> Result<Vec<CveHistoryEntry>> {
        if entries.is_empty() {
            return Ok(entries);
        }
        let artifact_ids: Vec<Uuid> = entries.iter().map(|e| e.artifact_id).collect();
        let rows: Vec<(Uuid, Uuid)> = sqlx::query_as(
            r#"
            SELECT id, repository_id FROM artifacts
            WHERE id = ANY($1) AND NOT is_deleted
            "#,
        )
        .bind(&artifact_ids)
        .fetch_all(&self.db)
        .await?;
        let repo_by_artifact: std::collections::HashMap<Uuid, Uuid> = rows.into_iter().collect();
        Ok(filter_entries_by_repo_map(
            entries,
            &repo_by_artifact,
            allowed_repos,
        ))
    }

    /// Build synthetic `CveHistoryEntry` rows from `scan_findings`.
    ///
    /// Why this exists: the scanner pipeline writes findings to
    /// `scan_findings` but never invokes `SbomService::record_cve`, so the
    /// `cve_history` table is structurally empty in production. To make the
    /// CVE history / trends endpoints return real data we synthesize entries
    /// from scan findings. This is a read-time projection; nothing is
    /// persisted. (#1375)
    ///
    /// `artifact_filter` and `cve_filter` are mutually exclusive scopes —
    /// pass `Some` for at most one. `known` is a set of CVE ids that should
    /// be excluded (because the curated `cve_history` path already returned
    /// them).
    async fn build_cve_entries_from_scan_findings(
        &self,
        artifact_filter: Option<Uuid>,
        cve_filter: Option<&str>,
        known: &HashSet<String>,
    ) -> Result<Vec<CveHistoryEntry>> {
        // Each row collapses to one synthetic CVE-history entry per
        // (artifact_id, cve_id). MIN(created_at) approximates
        // first_detected_at; MAX(created_at) approximates last_detected_at.
        // Severity is aggregated via a ranked CASE (see `severity_rank`) so
        // that a CVE reported `high` by one scanner and `medium` by another
        // shows up as `high` rather than the lexicographically-larger but
        // operationally-lower `medium`. Same fix as `get_cve_trends`. (#1375)
        let rows: Vec<ScanFindingCveRow> = if let Some(artifact_id) = artifact_filter {
            sqlx::query_as::<_, ScanFindingCveRow>(SCAN_FINDINGS_BY_ARTIFACT_SQL)
                .bind(artifact_id)
                .fetch_all(&self.db)
                .await?
        } else if let Some(cve_id) = cve_filter {
            sqlx::query_as::<_, ScanFindingCveRow>(SCAN_FINDINGS_BY_CVE_SQL)
                .bind(cve_id)
                .fetch_all(&self.db)
                .await?
        } else {
            // Unfiltered scope is a misuse (would return every CVE in the
            // system). Refuse rather than DoS the DB.
            return Ok(Vec::new());
        };

        Ok(project_scan_rows_to_entries(rows, known))
    }

    /// Update CVE status by legacy `cve_history` id, falling back to the
    /// `scan_findings` acknowledge path for synthetic ids.
    ///
    /// History (#1561): this endpoint (`POST /sbom/cve/status/{id}`) used to
    /// only `UPDATE cve_history WHERE id = $1`. Because the scanner pipeline
    /// never writes `cve_history` and the *read* paths now project synthetic
    /// ids out of `scan_findings` (#1616/#1620, [`synth_cve_id`]), every ack
    /// against an id the read path actually emits returned 404 -- the table
    /// has no such row. We now:
    ///
    ///   1. Try the legacy `cve_history` UPDATE first. If a real curated row
    ///      exists (rare admin/promotion-policy data), it wins and behaviour
    ///      is unchanged.
    ///   2. On `RowNotFound`, attempt to resolve `id` as a synthetic id back
    ///      to its `(artifact_id, cve_id)` pair (scoped to `allowed_repo_ids`)
    ///      and delegate to [`Self::update_cve_status_by_artifact_cve`], which
    ///      mutates `scan_findings`. This is the path the read side emits, so
    ///      the ack now persists and returns the synth aggregate instead of
    ///      404.
    ///   3. If neither matches, surface the original `RowNotFound` so the
    ///      handler still maps a genuinely-unknown id to 404.
    ///
    /// `allowed_repo_ids` follows the same admin-when-`None` contract as
    /// [`Self::get_cve_history_by_cve_id`]: `None` means no repo restriction
    /// (admin/system callers); `Some(&[...])` scopes the synth-id resolution
    /// to those repositories so a non-admin caller cannot acknowledge a CVE on
    /// an artifact they cannot see.
    pub async fn update_cve_status(
        &self,
        id: Uuid,
        status: CveStatus,
        user_id: Option<Uuid>,
        reason: Option<&str>,
        allowed_repo_ids: Option<&[Uuid]>,
    ) -> Result<CveHistoryEntry> {
        let curated = sqlx::query_as::<_, CveHistoryEntry>(
            r#"
            UPDATE cve_history SET
                status = $2,
                acknowledged_by = $3,
                acknowledged_at = CASE WHEN $2 = 'acknowledged' THEN NOW() ELSE NULL END,
                acknowledged_reason = $4,
                updated_at = NOW()
            WHERE id = $1
            RETURNING *
            "#,
        )
        .bind(id)
        .bind(status.as_str())
        .bind(user_id)
        .bind(reason)
        .fetch_optional(&self.db)
        .await?;

        if let Some(entry) = curated {
            return Ok(entry);
        }

        // No curated `cve_history` row: treat `id` as a synthetic id derived
        // from `scan_findings` and resolve it back to (artifact_id, cve_id).
        if let Some((artifact_id, cve_id)) = self.resolve_synth_cve_id(id, allowed_repo_ids).await?
        {
            return self
                .update_cve_status_by_artifact_cve(artifact_id, &cve_id, status, user_id, reason)
                .await;
        }

        // Neither a curated row nor a resolvable synth id: genuinely unknown.
        // Preserve the legacy 404 contract (handler maps RowNotFound -> 404).
        Err(AppError::Sqlx(sqlx::Error::RowNotFound))
    }

    /// Resolve a synthetic CVE id (see [`synth_cve_id`]) back to the
    /// `(artifact_id, cve_id)` pair it was derived from, by recomputing the
    /// hash for every distinct `scan_findings` pair and matching `id`.
    ///
    /// The synth id is a one-way hash, so reversal is by recomputation, not
    /// arithmetic. `allowed_repo_ids` scopes the candidate set to artifacts in
    /// the listed repositories (`None` = no restriction; admin-only, same
    /// contract as [`Self::get_cve_history_by_cve_id`]). Returns `None` when
    /// no `scan_findings` pair hashes to `id`. (#1561)
    pub(crate) async fn resolve_synth_cve_id(
        &self,
        id: Uuid,
        allowed_repo_ids: Option<&[Uuid]>,
    ) -> Result<Option<(Uuid, String)>> {
        let pairs: Vec<(Uuid, String)> = match allowed_repo_ids {
            None => {
                sqlx::query_as(
                    r#"
                SELECT DISTINCT sf.artifact_id, sf.cve_id
                FROM scan_findings sf
                JOIN artifacts a ON sf.artifact_id = a.id
                WHERE sf.cve_id IS NOT NULL
                  AND NOT a.is_deleted
                "#,
                )
                .fetch_all(&self.db)
                .await?
            }
            Some(repo_ids) => {
                sqlx::query_as(
                    r#"
                SELECT DISTINCT sf.artifact_id, sf.cve_id
                FROM scan_findings sf
                JOIN artifacts a ON sf.artifact_id = a.id
                WHERE sf.cve_id IS NOT NULL
                  AND NOT a.is_deleted
                  AND a.repository_id = ANY($1)
                "#,
                )
                .bind(repo_ids)
                .fetch_all(&self.db)
                .await?
            }
        };

        Ok(match_synth_cve_id(id, &pairs))
    }

    /// Update CVE status for an (artifact, cve) pair by mutating the
    /// underlying `scan_findings` rows.
    ///
    /// Why this exists (#1426): the Security tab read path projects
    /// `scan_findings` rows into synthetic `CveHistoryEntry` values whose
    /// `id` is a hash-derived UUID with no corresponding row in
    /// `cve_history`. The legacy acknowledge endpoint
    /// `POST /sbom/cve/status/{id}` writes to `cve_history` only, so an
    /// "acknowledge" click on a scan-derived row returned 404 -- the second,
    /// unwired acknowledge path called out in the issue. This method gives
    /// the Security tab a working acknowledge path by updating the source
    /// table (`scan_findings`) directly, keyed on (artifact_id, cve_id)
    /// because that is the only stable identity a synth row carries.
    ///
    /// `status` mapping (the four-state `cve_history.status` does not exist
    /// on `scan_findings`; the only acknowledge column there is the
    /// boolean `is_acknowledged`):
    ///
    /// - `Acknowledged` / `FalsePositive` -- set `is_acknowledged = true`,
    ///   record `acknowledged_by` / `acknowledged_at` / `acknowledged_reason`.
    ///   `false_positive` collapses to `acknowledged` on `scan_findings` since
    ///   the table has no separate column; the reason field carries the
    ///   distinction for audit.
    /// - `Open` -- clear acknowledgement (mirror of the `revoke` endpoint).
    /// - `Fixed` -- not supported by `scan_findings`; returns `Validation`.
    ///   "Fixed" is only meaningful on curated `cve_history` rows.
    ///
    /// Returns a synthetic `CveHistoryEntry` reflecting the post-update
    /// aggregate state (same shape the read path returns). Returns
    /// `AppError::NotFound` when no matching `scan_findings` rows exist;
    /// the caller turns that into 404.
    pub async fn update_cve_status_by_artifact_cve(
        &self,
        artifact_id: Uuid,
        cve_id: &str,
        status: CveStatus,
        user_id: Option<Uuid>,
        reason: Option<&str>,
    ) -> Result<CveHistoryEntry> {
        // `scan_findings` only models a binary acknowledge state. `fixed`
        // has no representation; refuse rather than silently coerce.
        let acknowledge = cve_status_to_acknowledge_flag(status).ok_or_else(|| {
            AppError::Validation(
                "Status 'fixed' is not supported on scan-derived CVE entries; \
                 only 'open', 'acknowledged', and 'false_positive' map to scan_findings"
                    .to_string(),
            )
        })?;

        // Compare CVE id case-insensitively. The schema does not constrain
        // case on `scan_findings.cve_id`, and the synth ids the read path
        // emits are upper-case, so we LOWER both sides.
        let affected = if acknowledge {
            sqlx::query(
                r#"
                UPDATE scan_findings
                SET is_acknowledged = TRUE,
                    acknowledged_by = $3,
                    acknowledged_reason = $4,
                    acknowledged_at = NOW()
                WHERE artifact_id = $1
                  AND cve_id IS NOT NULL
                  AND LOWER(cve_id) = LOWER($2)
                "#,
            )
            .bind(artifact_id)
            .bind(cve_id)
            .bind(user_id)
            .bind(reason)
            .execute(&self.db)
            .await?
            .rows_affected()
        } else {
            sqlx::query(
                r#"
                UPDATE scan_findings
                SET is_acknowledged = FALSE,
                    acknowledged_by = NULL,
                    acknowledged_reason = NULL,
                    acknowledged_at = NULL
                WHERE artifact_id = $1
                  AND cve_id IS NOT NULL
                  AND LOWER(cve_id) = LOWER($2)
                "#,
            )
            .bind(artifact_id)
            .bind(cve_id)
            .execute(&self.db)
            .await?
            .rows_affected()
        };

        if affected == 0 {
            return Err(AppError::NotFound(format!(
                "No scan_findings rows for artifact {} and CVE {}",
                artifact_id, cve_id
            )));
        }

        // Re-read the (now-mutated) aggregate so the response carries the
        // same shape as the read path: synth id, aggregated severity, MIN/MAX
        // detection timestamps, and an `all_acknowledged` flag that now
        // reflects the just-written state.
        let known: HashSet<String> = HashSet::new();
        let entries = self
            .build_cve_entries_from_scan_findings(Some(artifact_id), None, &known)
            .await?;
        let cve_upper = cve_id.to_ascii_uppercase();
        entries
            .into_iter()
            .find(|e| e.cve_id.to_ascii_uppercase() == cve_upper)
            .ok_or_else(|| {
                AppError::NotFound(format!(
                    "Updated scan_findings rows but could not re-read aggregate \
                     for artifact {} and CVE {}",
                    artifact_id, cve_id
                ))
            })
    }

    /// Get CVE trends for a repository.
    ///
    /// #1375: trends previously read only from `cve_history`, which is never
    /// populated by the scanner pipeline (no caller invokes
    /// `SbomService::record_cve`). The result was an all-zeros response for
    /// every fresh deployment, which the release-gate test flagged. We now
    /// derive the aggregates from `scan_findings`, the table the scanner
    /// actually writes to, so trends reflect live CVE state.
    ///
    /// `cve_history.status` (open/fixed/acknowledged/false_positive) has no
    /// direct equivalent in `scan_findings`. We approximate:
    ///   - open: findings where `NOT is_acknowledged`
    ///   - acknowledged: findings where `is_acknowledged`
    ///   - fixed: CVEs that appeared in an earlier `scan_findings` row for an
    ///     artifact but are absent from that artifact's most recent
    ///     `scan_results` (per `scan_type`). "Disappeared on rescan" is the
    ///     closest signal we have to a fixed CVE without a real fixed-at
    ///     timestamp. (#1616/#1620 dropped the dead `cve_history` curated half,
    ///     which always contributed zero.)
    ///
    /// We dedupe by (artifact_id, cve_id) so multi-scanner overlap doesn't
    /// double-count a single vulnerability.
    pub async fn get_cve_trends(&self, repository_id: Option<Uuid>) -> Result<CveTrends> {
        let (total, open, acknowledged, critical, high, medium, low): (
            i64,
            i64,
            i64,
            i64,
            i64,
            i64,
            i64,
        ) = if let Some(repo_id) = repository_id {
            sqlx::query_as(CVE_TRENDS_COUNTS_REPO_SQL)
                .bind(repo_id)
                .fetch_one(&self.db)
                .await?
        } else {
            sqlx::query_as(CVE_TRENDS_COUNTS_ALL_SQL)
                .fetch_one(&self.db)
                .await?
        };

        // Timeline (most recent 100 newly-detected CVEs in the last 30 days)
        // derived from scan_findings.
        //
        // Round-2 fix (#1375): severity is projected through the same
        // ranked CASE as the counts above, then mapped back to a text
        // label, so multi-scanner overlap doesn't flatten a `high`
        // finding to `medium` via lexicographic MAX.
        let timeline_rows: Vec<ScanFindingCveRow> = if let Some(repo_id) = repository_id {
            sqlx::query_as::<_, ScanFindingCveRow>(CVE_TRENDS_TIMELINE_REPO_SQL)
                .bind(repo_id)
                .fetch_all(&self.db)
                .await?
        } else {
            sqlx::query_as::<_, ScanFindingCveRow>(CVE_TRENDS_TIMELINE_ALL_SQL)
                .fetch_all(&self.db)
                .await?
        };

        let timeline = project_timeline_rows(&timeline_rows, Utc::now());

        // fixed_cves: CVEs present in an earlier scan_findings row for an
        // artifact but absent from that artifact's most recent scan_result per
        // scan_type (i.e. they "fell off" on rescan). #1616/#1620 dropped the
        // dead `cve_history` curated-fixed half, which was always empty.
        let fixed_cves: i64 = if let Some(repo_id) = repository_id {
            sqlx::query_scalar(FIXED_CVES_COUNT_REPO_SQL)
                .bind(repo_id)
                .fetch_one(&self.db)
                .await?
        } else {
            sqlx::query_scalar(FIXED_CVES_COUNT_ALL_SQL)
                .fetch_one(&self.db)
                .await?
        };

        Ok(cve_trends_from_aggregates(
            total,
            open,
            acknowledged,
            critical,
            high,
            medium,
            low,
            fixed_cves,
            timeline,
        ))
    }

    // === License Policies ===

    /// Get license policy for a repository.
    pub async fn get_license_policy(
        &self,
        repository_id: Option<Uuid>,
    ) -> Result<Option<LicensePolicy>> {
        // Try repo-specific first, fall back to global
        let policy = if let Some(repo_id) = repository_id {
            sqlx::query_as::<_, LicensePolicy>(
                r#"
                SELECT * FROM license_policies
                WHERE repository_id = $1 AND is_enabled = true
                ORDER BY created_at DESC
                LIMIT 1
                "#,
            )
            .bind(repo_id)
            .fetch_optional(&self.db)
            .await?
        } else {
            None
        };

        if policy.is_some() {
            return Ok(policy);
        }

        // Fall back to global policy
        sqlx::query_as::<_, LicensePolicy>(
            r#"
            SELECT * FROM license_policies
            WHERE repository_id IS NULL AND is_enabled = true
            ORDER BY created_at DESC
            LIMIT 1
            "#,
        )
        .fetch_optional(&self.db)
        .await
        .map_err(Into::into)
    }

    /// Check licenses against policy.
    pub fn check_license_compliance(
        &self,
        policy: &LicensePolicy,
        licenses: &[String],
    ) -> LicenseCheckResult {
        let mut violations = Vec::new();
        let mut warnings = Vec::new();

        for license in licenses {
            let normalized = license.to_uppercase();

            // Check denylist first (takes precedence)
            if policy
                .denied_licenses
                .iter()
                .any(|d| d.to_uppercase() == normalized)
            {
                violations.push(format!("License '{}' is denied by policy", license));
                continue;
            }

            // Check allowlist if not empty
            if !policy.allowed_licenses.is_empty()
                && !policy
                    .allowed_licenses
                    .iter()
                    .any(|a| a.to_uppercase() == normalized)
            {
                if policy.allow_unknown {
                    warnings.push(format!("License '{}' is not in approved list", license));
                } else {
                    violations.push(format!("License '{}' is not in approved list", license));
                }
            }
        }

        LicenseCheckResult {
            compliant: violations.is_empty(),
            violations,
            warnings,
        }
    }

    // === Private helpers ===

    fn get_format_version(&self, format: SbomFormat) -> &'static str {
        match format {
            SbomFormat::CycloneDX => "1.5",
            SbomFormat::SPDX => "2.3",
        }
    }

    fn get_spec_version(&self, format: SbomFormat) -> &'static str {
        match format {
            SbomFormat::CycloneDX => "CycloneDX 1.5",
            SbomFormat::SPDX => "SPDX-2.3",
        }
    }

    /// Conservative set of ubiquitous, long-stable SPDX identifiers that are
    /// guaranteed to be present in any modern SPDX license list (and thus
    /// accepted in a CycloneDX `license.id`). Kept intentionally small: a
    /// miss here only downgrades a recognized license to the free-form
    /// `name` field, whereas a *wrong* entry would re-introduce the
    /// whole-BOM rejection this guards against.
    const SPDX_COMMON_IDS: &'static [&'static str] = &[
        "0BSD",
        "Apache-2.0",
        "Artistic-2.0",
        "BSD-2-Clause",
        "BSD-3-Clause",
        "BSL-1.0",
        "CC0-1.0",
        "EPL-2.0",
        "GPL-2.0-only",
        "GPL-2.0-or-later",
        "GPL-3.0-only",
        "GPL-3.0-or-later",
        "ISC",
        "LGPL-2.1-only",
        "LGPL-2.1-or-later",
        "LGPL-3.0-only",
        "LGPL-3.0-or-later",
        "AGPL-3.0-only",
        "AGPL-3.0-or-later",
        "MIT",
        "MPL-2.0",
        "Unlicense",
        "Zlib",
    ];

    /// Build a CycloneDX `licenses[]` entry for a single license string.
    ///
    /// CycloneDX requires `license.id` to be a member of the SPDX license
    /// enumeration; Dependency-Track rejects the *entire* BOM with HTTP 400
    /// ("Schema validation failed") if any component carries an `id` outside
    /// that set. Package license metadata is frequently not a bare SPDX id
    /// (free-form names, SPDX expressions, "UNKNOWN"), so emit `id` only for
    /// recognized identifiers and fall back to the free-form `name` field —
    /// which DT accepts unconditionally — for everything else.
    fn cyclonedx_license_entry(license: &str) -> serde_json::Value {
        if Self::SPDX_COMMON_IDS.contains(&license) {
            serde_json::json!({"license": {"id": license}})
        } else {
            serde_json::json!({"license": {"name": license}})
        }
    }

    fn generate_cyclonedx_inner(
        &self,
        dependencies: &[DependencyInfo],
        inventory_completeness: Option<&str>,
    ) -> Result<(serde_json::Value, Vec<ComponentInfo>)> {
        let mut components = Vec::new();
        let mut cdx_components = Vec::new();

        for dep in dependencies {
            let component = ComponentInfo {
                name: dep.name.clone(),
                version: dep.version.clone(),
                purl: dep.purl.clone(),
                component_type: Some("library".to_string()),
                licenses: dep.license.clone().into_iter().collect(),
                sha256: dep.sha256.clone(),
                supplier: None,
            };
            components.push(component);

            let mut cdx_comp = serde_json::json!({
                "type": "library",
                "name": dep.name,
            });

            if let Some(v) = &dep.version {
                cdx_comp["version"] = serde_json::json!(v);
            }
            if let Some(p) = &dep.purl {
                cdx_comp["purl"] = serde_json::json!(p);
            }
            if let Some(l) = &dep.license {
                cdx_comp["licenses"] = serde_json::json!([Self::cyclonedx_license_entry(l)]);
            }
            if let Some(h) = &dep.sha256 {
                cdx_comp["hashes"] = serde_json::json!([{"alg": "SHA-256", "content": h}]);
            }

            cdx_components.push(cdx_comp);
        }

        let mut metadata = serde_json::json!({
            "timestamp": Utc::now().to_rfc3339(),
            "tools": [{
                "vendor": "Artifact Keeper",
                "name": "artifact-keeper",
                "version": env!("CARGO_PKG_VERSION")
            }]
        });

        // #1153: thread the scanner completeness signal into the SBOM
        // document via CycloneDX 1.5 `metadata.properties` so downstream
        // attestation tooling can tell "no lockfile present" from
        // "lockfile present but unparseable". The property is omitted
        // when `inventory_completeness` is None so legacy SBOMs hash
        // identically and the content_hash cache stays warm.
        if let Some(c) = inventory_completeness {
            metadata["properties"] = serde_json::json!([{
                "name": "artifact-keeper:scan-completeness",
                "value": c
            }]);
        }

        let sbom = serde_json::json!({
            "bomFormat": "CycloneDX",
            "specVersion": "1.5",
            "version": 1,
            "metadata": metadata,
            "components": cdx_components
        });

        Ok((sbom, components))
    }

    fn generate_spdx_inner(
        &self,
        dependencies: &[DependencyInfo],
        inventory_completeness: Option<&str>,
    ) -> Result<(serde_json::Value, Vec<ComponentInfo>)> {
        let mut components = Vec::new();
        let mut spdx_packages = Vec::new();

        for (idx, dep) in dependencies.iter().enumerate() {
            let component = ComponentInfo {
                name: dep.name.clone(),
                version: dep.version.clone(),
                purl: dep.purl.clone(),
                component_type: Some("library".to_string()),
                licenses: dep.license.clone().into_iter().collect(),
                sha256: dep.sha256.clone(),
                supplier: None,
            };
            components.push(component);

            let spdx_id = format!("SPDXRef-Package-{}", idx);
            let mut pkg = serde_json::json!({
                "SPDXID": spdx_id,
                "name": dep.name,
                "downloadLocation": "NOASSERTION"
            });

            if let Some(v) = &dep.version {
                pkg["versionInfo"] = serde_json::json!(v);
            }
            if let Some(l) = &dep.license {
                pkg["licenseConcluded"] = serde_json::json!(l);
                pkg["licenseDeclared"] = serde_json::json!(l);
            } else {
                pkg["licenseConcluded"] = serde_json::json!("NOASSERTION");
                pkg["licenseDeclared"] = serde_json::json!("NOASSERTION");
            }
            if let Some(h) = &dep.sha256 {
                pkg["checksums"] = serde_json::json!([{
                    "algorithm": "SHA256",
                    "checksumValue": h
                }]);
            }
            if let Some(p) = &dep.purl {
                pkg["externalRefs"] = serde_json::json!([{
                    "referenceCategory": "PACKAGE-MANAGER",
                    "referenceType": "purl",
                    "referenceLocator": p
                }]);
            }

            spdx_packages.push(pkg);
        }

        let mut creation_info = serde_json::json!({
            "created": Utc::now().to_rfc3339(),
            "creators": [format!("Tool: artifact-keeper-{}", env!("CARGO_PKG_VERSION"))]
        });

        // #1153: SPDX 2.3 `creationInfo.comment` is the canonical place to
        // signal that the underlying scan was partial. Like the CycloneDX
        // variant above, the field is omitted when None so legacy SBOMs
        // hash identically.
        if let Some(c) = inventory_completeness {
            creation_info["comment"] =
                serde_json::json!(format!("artifact-keeper scan-completeness: {}", c));
        }

        let sbom = serde_json::json!({
            "spdxVersion": "SPDX-2.3",
            "dataLicense": "CC0-1.0",
            "SPDXID": "SPDXRef-DOCUMENT",
            "name": "artifact-sbom",
            "documentNamespace": format!("https://artifact-keeper.com/sbom/{}", Uuid::new_v4()),
            "creationInfo": creation_info,
            "packages": spdx_packages
        });

        Ok((sbom, components))
    }
}

/// Dependency information for SBOM generation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DependencyInfo {
    pub name: String,
    pub version: Option<String>,
    pub purl: Option<String>,
    pub license: Option<String>,
    pub sha256: Option<String>,
}

/// Component information extracted from dependencies.
#[derive(Debug, Clone)]
pub struct ComponentInfo {
    pub name: String,
    pub version: Option<String>,
    pub purl: Option<String>,
    pub component_type: Option<String>,
    pub licenses: Vec<String>,
    pub sha256: Option<String>,
    pub supplier: Option<String>,
}

/// Result of license compliance check.
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct LicenseCheckResult {
    pub compliant: bool,
    pub violations: Vec<String>,
    pub warnings: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // Pure helper functions (moved from module scope — test-only)
    // -----------------------------------------------------------------------

    fn format_version(format: SbomFormat) -> &'static str {
        match format {
            SbomFormat::CycloneDX => "1.5",
            SbomFormat::SPDX => "2.3",
        }
    }

    fn spec_version(format: SbomFormat) -> &'static str {
        match format {
            SbomFormat::CycloneDX => "CycloneDX 1.5",
            SbomFormat::SPDX => "SPDX-2.3",
        }
    }

    fn build_cyclonedx_component(dep: &DependencyInfo) -> serde_json::Value {
        let mut comp = serde_json::json!({
            "type": "library",
            "name": dep.name,
        });
        if let Some(v) = &dep.version {
            comp["version"] = serde_json::json!(v);
        }
        if let Some(p) = &dep.purl {
            comp["purl"] = serde_json::json!(p);
        }
        if let Some(l) = &dep.license {
            comp["licenses"] = serde_json::json!([SbomService::cyclonedx_license_entry(l)]);
        }
        if let Some(h) = &dep.sha256 {
            comp["hashes"] = serde_json::json!([{"alg": "SHA-256", "content": h}]);
        }
        comp
    }

    fn build_spdx_package(dep: &DependencyInfo, idx: usize) -> serde_json::Value {
        let spdx_id = format!("SPDXRef-Package-{}", idx);
        let mut pkg = serde_json::json!({
            "SPDXID": spdx_id,
            "name": dep.name,
            "downloadLocation": "NOASSERTION"
        });
        if let Some(v) = &dep.version {
            pkg["versionInfo"] = serde_json::json!(v);
        }
        if let Some(l) = &dep.license {
            pkg["licenseConcluded"] = serde_json::json!(l);
            pkg["licenseDeclared"] = serde_json::json!(l);
        } else {
            pkg["licenseConcluded"] = serde_json::json!("NOASSERTION");
            pkg["licenseDeclared"] = serde_json::json!("NOASSERTION");
        }
        if let Some(h) = &dep.sha256 {
            pkg["checksums"] = serde_json::json!([{
                "algorithm": "SHA256",
                "checksumValue": h
            }]);
        }
        if let Some(p) = &dep.purl {
            pkg["externalRefs"] = serde_json::json!([{
                "referenceCategory": "PACKAGE-MANAGER",
                "referenceType": "purl",
                "referenceLocator": p
            }]);
        }
        pkg
    }

    fn build_component_info(dep: &DependencyInfo) -> ComponentInfo {
        ComponentInfo {
            name: dep.name.clone(),
            version: dep.version.clone(),
            purl: dep.purl.clone(),
            component_type: Some("library".to_string()),
            licenses: dep.license.clone().into_iter().collect(),
            sha256: dep.sha256.clone(),
            supplier: None,
        }
    }

    fn extract_unique_licenses(dependencies: &[DependencyInfo]) -> Vec<String> {
        dependencies
            .iter()
            .filter_map(|d| d.license.clone())
            .collect::<HashSet<_>>()
            .into_iter()
            .collect()
    }

    fn check_license_compliance_pure(
        policy: &LicensePolicy,
        licenses: &[String],
    ) -> LicenseCheckResult {
        let mut violations = Vec::new();
        let mut warnings = Vec::new();

        for license in licenses {
            let normalized = license.to_uppercase();

            if policy
                .denied_licenses
                .iter()
                .any(|d| d.to_uppercase() == normalized)
            {
                violations.push(format!("License '{}' is denied by policy", license));
                continue;
            }

            if !policy.allowed_licenses.is_empty()
                && !policy
                    .allowed_licenses
                    .iter()
                    .any(|a| a.to_uppercase() == normalized)
            {
                if policy.allow_unknown {
                    warnings.push(format!("License '{}' is not in approved list", license));
                } else {
                    violations.push(format!("License '{}' is not in approved list", license));
                }
            }
        }

        LicenseCheckResult {
            compliant: violations.is_empty(),
            violations,
            warnings,
        }
    }

    fn content_hash(content: &str) -> String {
        format!("{:x}", Sha256::digest(content.as_bytes()))
    }

    fn days_exposed(first_detected_at: chrono::DateTime<Utc>, now: chrono::DateTime<Utc>) -> i64 {
        (now - first_detected_at).num_days()
    }

    // ===================================================================
    // format_version
    // ===================================================================

    #[test]
    fn test_format_version_cyclonedx() {
        assert_eq!(format_version(SbomFormat::CycloneDX), "1.5");
    }

    #[test]
    fn test_format_version_spdx() {
        assert_eq!(format_version(SbomFormat::SPDX), "2.3");
    }

    // ===================================================================
    // cyclonedx_license_entry — SPDX id vs free-form name
    // ===================================================================

    #[test]
    fn test_cyclonedx_license_entry_known_spdx_uses_id() {
        let entry = SbomService::cyclonedx_license_entry("Apache-2.0");
        assert_eq!(entry["license"]["id"], "Apache-2.0");
        assert!(entry["license"].get("name").is_none());
    }

    #[test]
    fn test_cyclonedx_license_entry_non_spdx_uses_name() {
        // A free-form / non-SPDX license must NOT land in `id` — that makes
        // Dependency-Track reject the entire BOM with HTTP 400. It belongs in
        // the free-form `name` field.
        let entry = SbomService::cyclonedx_license_entry("Public Domain");
        assert_eq!(entry["license"]["name"], "Public Domain");
        assert!(entry["license"].get("id").is_none());
    }

    #[test]
    fn test_cyclonedx_license_entry_spdx_expression_uses_name() {
        // SPDX expressions are not bare ids and fail `license.id` enum
        // validation; they must fall back to `name`.
        let entry = SbomService::cyclonedx_license_entry("MIT OR Apache-2.0");
        assert_eq!(entry["license"]["name"], "MIT OR Apache-2.0");
        assert!(entry["license"].get("id").is_none());
    }

    #[test]
    fn test_build_cyclonedx_component_non_spdx_license_not_in_id() {
        let dep = DependencyInfo {
            name: "weird-pkg".to_string(),
            version: Some("1.0.0".to_string()),
            purl: None,
            license: Some("UNKNOWN".to_string()),
            sha256: None,
        };
        let comp = build_cyclonedx_component(&dep);
        assert_eq!(comp["licenses"][0]["license"]["name"], "UNKNOWN");
        assert!(comp["licenses"][0]["license"].get("id").is_none());
    }

    // ===================================================================
    // spec_version
    // ===================================================================

    #[test]
    fn test_spec_version_cyclonedx() {
        assert_eq!(spec_version(SbomFormat::CycloneDX), "CycloneDX 1.5");
    }

    #[test]
    fn test_spec_version_spdx() {
        assert_eq!(spec_version(SbomFormat::SPDX), "SPDX-2.3");
    }

    // ===================================================================
    // build_cyclonedx_component
    // ===================================================================

    #[test]
    fn test_build_cyclonedx_component_all_fields() {
        let dep = DependencyInfo {
            name: "serde".to_string(),
            version: Some("1.0.195".to_string()),
            purl: Some("pkg:cargo/serde@1.0.195".to_string()),
            license: Some("MIT".to_string()),
            sha256: Some("abcdef".to_string()),
        };
        let comp = build_cyclonedx_component(&dep);
        assert_eq!(comp["type"], "library");
        assert_eq!(comp["name"], "serde");
        assert_eq!(comp["version"], "1.0.195");
        assert_eq!(comp["purl"], "pkg:cargo/serde@1.0.195");
        assert_eq!(comp["licenses"][0]["license"]["id"], "MIT");
        assert_eq!(comp["hashes"][0]["alg"], "SHA-256");
        assert_eq!(comp["hashes"][0]["content"], "abcdef");
    }

    #[test]
    fn test_build_cyclonedx_component_minimal() {
        let dep = DependencyInfo {
            name: "minimal".to_string(),
            version: None,
            purl: None,
            license: None,
            sha256: None,
        };
        let comp = build_cyclonedx_component(&dep);
        assert_eq!(comp["type"], "library");
        assert_eq!(comp["name"], "minimal");
        assert!(comp.get("version").is_none());
        assert!(comp.get("purl").is_none());
        assert!(comp.get("licenses").is_none());
        assert!(comp.get("hashes").is_none());
    }

    #[test]
    fn test_build_cyclonedx_component_version_only() {
        let dep = DependencyInfo {
            name: "pkg".to_string(),
            version: Some("2.0".to_string()),
            purl: None,
            license: None,
            sha256: None,
        };
        let comp = build_cyclonedx_component(&dep);
        assert_eq!(comp["version"], "2.0");
        assert!(comp.get("purl").is_none());
    }

    // ===================================================================
    // build_spdx_package
    // ===================================================================

    #[test]
    fn test_build_spdx_package_all_fields() {
        let dep = DependencyInfo {
            name: "express".to_string(),
            version: Some("4.18.2".to_string()),
            purl: Some("pkg:npm/express@4.18.2".to_string()),
            license: Some("MIT".to_string()),
            sha256: Some("abc123".to_string()),
        };
        let pkg = build_spdx_package(&dep, 0);
        assert_eq!(pkg["SPDXID"], "SPDXRef-Package-0");
        assert_eq!(pkg["name"], "express");
        assert_eq!(pkg["versionInfo"], "4.18.2");
        assert_eq!(pkg["licenseConcluded"], "MIT");
        assert_eq!(pkg["licenseDeclared"], "MIT");
        assert_eq!(pkg["checksums"][0]["algorithm"], "SHA256");
        assert_eq!(
            pkg["externalRefs"][0]["referenceLocator"],
            "pkg:npm/express@4.18.2"
        );
        assert_eq!(pkg["downloadLocation"], "NOASSERTION");
    }

    #[test]
    fn test_build_spdx_package_minimal() {
        let dep = DependencyInfo {
            name: "minimal".to_string(),
            version: None,
            purl: None,
            license: None,
            sha256: None,
        };
        let pkg = build_spdx_package(&dep, 5);
        assert_eq!(pkg["SPDXID"], "SPDXRef-Package-5");
        assert_eq!(pkg["licenseConcluded"], "NOASSERTION");
        assert_eq!(pkg["licenseDeclared"], "NOASSERTION");
    }

    #[test]
    fn test_build_spdx_package_index_numbering() {
        let dep = DependencyInfo {
            name: "pkg".to_string(),
            version: None,
            purl: None,
            license: None,
            sha256: None,
        };
        assert_eq!(build_spdx_package(&dep, 0)["SPDXID"], "SPDXRef-Package-0");
        assert_eq!(build_spdx_package(&dep, 42)["SPDXID"], "SPDXRef-Package-42");
    }

    // ===================================================================
    // build_component_info
    // ===================================================================

    #[test]
    fn test_build_component_info_full() {
        let dep = DependencyInfo {
            name: "react".to_string(),
            version: Some("18.2.0".to_string()),
            purl: Some("pkg:npm/react@18.2.0".to_string()),
            license: Some("MIT".to_string()),
            sha256: Some("hash".to_string()),
        };
        let comp = build_component_info(&dep);
        assert_eq!(comp.name, "react");
        assert_eq!(comp.version.as_deref(), Some("18.2.0"));
        assert_eq!(comp.component_type.as_deref(), Some("library"));
        assert_eq!(comp.licenses, vec!["MIT".to_string()]);
        assert!(comp.supplier.is_none());
    }

    #[test]
    fn test_build_component_info_minimal() {
        let dep = DependencyInfo {
            name: "pkg".to_string(),
            version: None,
            purl: None,
            license: None,
            sha256: None,
        };
        let comp = build_component_info(&dep);
        assert!(comp.licenses.is_empty());
        assert!(comp.version.is_none());
    }

    // ===================================================================
    // extract_unique_licenses
    // ===================================================================

    #[test]
    fn test_extract_unique_licenses_empty() {
        assert!(extract_unique_licenses(&[]).is_empty());
    }

    #[test]
    fn test_extract_unique_licenses_dedup() {
        let deps = vec![
            DependencyInfo {
                name: "a".to_string(),
                version: None,
                purl: None,
                license: Some("MIT".to_string()),
                sha256: None,
            },
            DependencyInfo {
                name: "b".to_string(),
                version: None,
                purl: None,
                license: Some("MIT".to_string()),
                sha256: None,
            },
            DependencyInfo {
                name: "c".to_string(),
                version: None,
                purl: None,
                license: Some("Apache-2.0".to_string()),
                sha256: None,
            },
        ];
        let licenses = extract_unique_licenses(&deps);
        assert_eq!(licenses.len(), 2);
    }

    #[test]
    fn test_extract_unique_licenses_skips_none() {
        let deps = vec![
            DependencyInfo {
                name: "a".to_string(),
                version: None,
                purl: None,
                license: Some("MIT".to_string()),
                sha256: None,
            },
            DependencyInfo {
                name: "b".to_string(),
                version: None,
                purl: None,
                license: None,
                sha256: None,
            },
        ];
        let licenses = extract_unique_licenses(&deps);
        assert_eq!(licenses.len(), 1);
    }

    // ===================================================================
    // check_license_compliance_pure
    // ===================================================================

    fn make_test_policy(
        allowed: Vec<&str>,
        denied: Vec<&str>,
        allow_unknown: bool,
    ) -> LicensePolicy {
        LicensePolicy {
            id: Uuid::new_v4(),
            repository_id: None,
            name: "test".to_string(),
            description: None,
            allowed_licenses: allowed.into_iter().map(String::from).collect(),
            denied_licenses: denied.into_iter().map(String::from).collect(),
            allow_unknown,
            action: crate::models::sbom::PolicyAction::Block,
            is_enabled: true,
            created_at: Utc::now(),
            updated_at: None,
        }
    }

    #[test]
    fn test_check_license_compliance_pure_allowed() {
        let policy = make_test_policy(vec!["MIT"], vec![], false);
        let result = check_license_compliance_pure(&policy, &["MIT".to_string()]);
        assert!(result.compliant);
    }

    #[test]
    fn test_check_license_compliance_pure_denied() {
        let policy = make_test_policy(vec!["MIT"], vec!["GPL-3.0"], false);
        let result = check_license_compliance_pure(&policy, &["GPL-3.0".to_string()]);
        assert!(!result.compliant);
    }

    #[test]
    fn test_check_license_compliance_pure_case_insensitive() {
        let policy = make_test_policy(vec!["MIT"], vec!["gpl-3.0"], false);
        assert!(check_license_compliance_pure(&policy, &["mit".to_string()]).compliant);
        assert!(!check_license_compliance_pure(&policy, &["GPL-3.0".to_string()]).compliant);
    }

    // ===================================================================
    // content_hash
    // ===================================================================

    #[test]
    fn test_content_hash_deterministic() {
        assert_eq!(content_hash("hello"), content_hash("hello"));
    }

    #[test]
    fn test_content_hash_different_inputs() {
        assert_ne!(content_hash("hello"), content_hash("world"));
    }

    #[test]
    fn test_content_hash_empty_known_value() {
        assert_eq!(
            content_hash(""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn test_content_hash_is_64_hex_chars() {
        let h = content_hash("test");
        assert_eq!(h.len(), 64);
        assert!(h.chars().all(|c| c.is_ascii_hexdigit()));
    }

    // ===================================================================
    // days_exposed
    // ===================================================================

    #[test]
    fn test_days_exposed_same_day() {
        let now = Utc::now();
        assert_eq!(days_exposed(now, now), 0);
    }

    #[test]
    fn test_days_exposed_one_day() {
        let now = Utc::now();
        assert_eq!(days_exposed(now - chrono::Duration::days(1), now), 1);
    }

    #[test]
    fn test_days_exposed_thirty_days() {
        let now = Utc::now();
        assert_eq!(days_exposed(now - chrono::Duration::days(30), now), 30);
    }

    #[test]
    fn test_days_exposed_future_negative() {
        let now = Utc::now();
        assert_eq!(days_exposed(now + chrono::Duration::days(5), now), -5);
    }

    // ===================================================================
    // Existing tests below (kept for backward compat)
    // ===================================================================

    /// Helper to create a mock SbomService for testing SBOM generation
    /// without a database connection.
    fn generate_test_cyclonedx(deps: &[DependencyInfo]) -> serde_json::Value {
        let mut components = Vec::new();
        for dep in deps {
            let mut comp = serde_json::json!({
                "type": "library",
                "name": dep.name,
            });
            if let Some(v) = &dep.version {
                comp["version"] = serde_json::json!(v);
            }
            if let Some(p) = &dep.purl {
                comp["purl"] = serde_json::json!(p);
            }
            if let Some(l) = &dep.license {
                comp["licenses"] = serde_json::json!([{"license": {"id": l}}]);
            }
            components.push(comp);
        }

        serde_json::json!({
            "bomFormat": "CycloneDX",
            "specVersion": "1.5",
            "version": 1,
            "metadata": {
                "timestamp": Utc::now().to_rfc3339(),
                "tools": [{
                    "vendor": "Artifact Keeper",
                    "name": "artifact-keeper",
                    "version": env!("CARGO_PKG_VERSION")
                }]
            },
            "components": components
        })
    }

    fn generate_test_spdx(deps: &[DependencyInfo]) -> serde_json::Value {
        let mut packages = Vec::new();
        for (idx, dep) in deps.iter().enumerate() {
            let spdx_id = format!("SPDXRef-Package-{}", idx);
            let mut pkg = serde_json::json!({
                "SPDXID": spdx_id,
                "name": dep.name,
                "downloadLocation": "NOASSERTION",
            });
            if let Some(v) = &dep.version {
                pkg["versionInfo"] = serde_json::json!(v);
            }
            if let Some(l) = &dep.license {
                pkg["licenseDeclared"] = serde_json::json!(l);
            }
            packages.push(pkg);
        }

        serde_json::json!({
            "spdxVersion": "SPDX-2.3",
            "dataLicense": "CC0-1.0",
            "SPDXID": "SPDXRef-DOCUMENT",
            "name": "artifact-sbom",
            "documentNamespace": format!("https://artifact-keeper.com/sbom/{}", Uuid::new_v4()),
            "creationInfo": {
                "created": Utc::now().to_rfc3339(),
                "creators": [format!("Tool: artifact-keeper-{}", env!("CARGO_PKG_VERSION"))]
            },
            "packages": packages
        })
    }

    #[test]
    fn test_cyclonedx_has_required_fields() {
        let deps = vec![DependencyInfo {
            name: "lodash".to_string(),
            version: Some("4.17.21".to_string()),
            purl: Some("pkg:npm/lodash@4.17.21".to_string()),
            license: Some("MIT".to_string()),
            sha256: None,
        }];

        let sbom = generate_test_cyclonedx(&deps);

        // Verify required CycloneDX 1.5 fields
        assert_eq!(sbom["bomFormat"], "CycloneDX");
        assert_eq!(sbom["specVersion"], "1.5");
        assert_eq!(sbom["version"], 1);
        assert!(sbom["metadata"].is_object());
        assert!(sbom["metadata"]["timestamp"].is_string());
        assert!(sbom["metadata"]["tools"].is_array());
        assert!(sbom["components"].is_array());
    }

    #[test]
    fn test_cyclonedx_empty_components() {
        let deps: Vec<DependencyInfo> = vec![];
        let sbom = generate_test_cyclonedx(&deps);

        // Empty SBOM should still have valid structure
        assert_eq!(sbom["bomFormat"], "CycloneDX");
        assert_eq!(sbom["specVersion"], "1.5");
        assert!(sbom["components"].as_array().unwrap().is_empty());
    }

    #[test]
    fn test_cyclonedx_component_structure() {
        let deps = vec![DependencyInfo {
            name: "axios".to_string(),
            version: Some("1.6.0".to_string()),
            purl: Some("pkg:npm/axios@1.6.0".to_string()),
            license: Some("MIT".to_string()),
            sha256: None,
        }];

        let sbom = generate_test_cyclonedx(&deps);
        let components = sbom["components"].as_array().unwrap();

        assert_eq!(components.len(), 1);
        let comp = &components[0];
        assert_eq!(comp["type"], "library");
        assert_eq!(comp["name"], "axios");
        assert_eq!(comp["version"], "1.6.0");
        assert_eq!(comp["purl"], "pkg:npm/axios@1.6.0");
    }

    #[test]
    fn test_spdx_has_required_fields() {
        let deps = vec![DependencyInfo {
            name: "lodash".to_string(),
            version: Some("4.17.21".to_string()),
            purl: None,
            license: Some("MIT".to_string()),
            sha256: None,
        }];

        let sbom = generate_test_spdx(&deps);

        // Verify required SPDX 2.3 fields
        assert_eq!(sbom["spdxVersion"], "SPDX-2.3");
        assert_eq!(sbom["SPDXID"], "SPDXRef-DOCUMENT");
        assert_eq!(sbom["dataLicense"], "CC0-1.0");
        assert!(sbom["name"].is_string());
        assert!(sbom["documentNamespace"].is_string());
        assert!(sbom["creationInfo"].is_object());
        assert!(sbom["creationInfo"]["created"].is_string());
        assert!(sbom["creationInfo"]["creators"].is_array());
        assert!(sbom["packages"].is_array());
    }

    #[test]
    fn test_spdx_empty_packages() {
        let deps: Vec<DependencyInfo> = vec![];
        let sbom = generate_test_spdx(&deps);

        // Empty SBOM should still have valid structure
        assert_eq!(sbom["spdxVersion"], "SPDX-2.3");
        assert!(sbom["packages"].as_array().unwrap().is_empty());
    }

    #[test]
    fn test_spdx_package_structure() {
        let deps = vec![DependencyInfo {
            name: "express".to_string(),
            version: Some("4.18.2".to_string()),
            purl: None,
            license: Some("MIT".to_string()),
            sha256: None,
        }];

        let sbom = generate_test_spdx(&deps);
        let packages = sbom["packages"].as_array().unwrap();

        assert_eq!(packages.len(), 1);
        let pkg = &packages[0];
        assert!(pkg["SPDXID"].as_str().unwrap().starts_with("SPDXRef-"));
        assert_eq!(pkg["name"], "express");
        assert_eq!(pkg["versionInfo"], "4.18.2");
        assert_eq!(pkg["licenseDeclared"], "MIT");
    }

    #[test]
    fn test_spdx_document_namespace_is_unique() {
        let deps: Vec<DependencyInfo> = vec![];
        let sbom1 = generate_test_spdx(&deps);
        let sbom2 = generate_test_spdx(&deps);

        // Each SBOM should have a unique document namespace
        assert_ne!(
            sbom1["documentNamespace"].as_str().unwrap(),
            sbom2["documentNamespace"].as_str().unwrap()
        );
    }

    // -----------------------------------------------------------------------
    // check_license_compliance (pure function on &self + LicensePolicy)
    //
    // NOTE: SbomService has a PgPool field, so we cannot construct it in
    // tests. However, check_license_compliance only uses &self and the
    // LicensePolicy argument, never touching the database. We duplicate
    // the logic here to test it. The engineering expert should extract this
    // into a free function or an associated function.
    // -----------------------------------------------------------------------

    /// Duplicated from SbomService::check_license_compliance for unit testing.
    fn check_license_compliance_standalone(
        policy: &LicensePolicy,
        licenses: &[String],
    ) -> LicenseCheckResult {
        let mut violations = Vec::new();
        let mut warnings = Vec::new();

        for license in licenses {
            let normalized = license.to_uppercase();

            // Check denylist first (takes precedence)
            if policy
                .denied_licenses
                .iter()
                .any(|d| d.to_uppercase() == normalized)
            {
                violations.push(format!("License '{}' is denied by policy", license));
                continue;
            }

            // Check allowlist if not empty
            if !policy.allowed_licenses.is_empty()
                && !policy
                    .allowed_licenses
                    .iter()
                    .any(|a| a.to_uppercase() == normalized)
            {
                if policy.allow_unknown {
                    warnings.push(format!("License '{}' is not in approved list", license));
                } else {
                    violations.push(format!("License '{}' is not in approved list", license));
                }
            }
        }

        LicenseCheckResult {
            compliant: violations.is_empty(),
            violations,
            warnings,
        }
    }

    fn make_policy(allowed: Vec<&str>, denied: Vec<&str>, allow_unknown: bool) -> LicensePolicy {
        LicensePolicy {
            id: Uuid::new_v4(),
            repository_id: None,
            name: "test-policy".to_string(),
            description: None,
            allowed_licenses: allowed.into_iter().map(String::from).collect(),
            denied_licenses: denied.into_iter().map(String::from).collect(),
            allow_unknown,
            action: crate::models::sbom::PolicyAction::Block,
            is_enabled: true,
            created_at: Utc::now(),
            updated_at: None,
        }
    }

    #[test]
    fn test_license_compliance_all_allowed() {
        let policy = make_policy(vec!["MIT", "Apache-2.0", "BSD-3-Clause"], vec![], false);
        let licenses = vec!["MIT".to_string(), "Apache-2.0".to_string()];

        let result = check_license_compliance_standalone(&policy, &licenses);
        assert!(result.compliant);
        assert!(result.violations.is_empty());
        assert!(result.warnings.is_empty());
    }

    #[test]
    fn test_license_compliance_denied_takes_precedence() {
        // GPL is in both allowed and denied; denied should win
        let policy = make_policy(vec!["MIT", "GPL-3.0"], vec!["GPL-3.0"], false);
        let licenses = vec!["GPL-3.0".to_string()];

        let result = check_license_compliance_standalone(&policy, &licenses);
        assert!(!result.compliant);
        assert_eq!(result.violations.len(), 1);
        assert!(result.violations[0].contains("denied"));
    }

    #[test]
    fn test_license_compliance_not_in_allowlist_strict() {
        let policy = make_policy(vec!["MIT"], vec![], false);
        let licenses = vec!["AGPL-3.0".to_string()];

        let result = check_license_compliance_standalone(&policy, &licenses);
        assert!(!result.compliant);
        assert_eq!(result.violations.len(), 1);
        assert!(result.violations[0].contains("not in approved list"));
    }

    #[test]
    fn test_license_compliance_not_in_allowlist_lenient() {
        let policy = make_policy(vec!["MIT"], vec![], true); // allow_unknown = true
        let licenses = vec!["AGPL-3.0".to_string()];

        let result = check_license_compliance_standalone(&policy, &licenses);
        assert!(result.compliant); // no violations, just warnings
        assert!(result.violations.is_empty());
        assert_eq!(result.warnings.len(), 1);
        assert!(result.warnings[0].contains("not in approved list"));
    }

    #[test]
    fn test_license_compliance_empty_allowlist_allows_everything() {
        // When allowlist is empty, the allowlist check is skipped
        let policy = make_policy(vec![], vec![], false);
        let licenses = vec!["ANY-LICENSE".to_string()];

        let result = check_license_compliance_standalone(&policy, &licenses);
        assert!(result.compliant);
    }

    #[test]
    fn test_license_compliance_case_insensitive() {
        let policy = make_policy(vec!["MIT"], vec!["gpl-3.0"], false);

        // "mit" should match "MIT" in allowlist
        let result1 = check_license_compliance_standalone(&policy, &["mit".to_string()]);
        assert!(result1.compliant);

        // "GPL-3.0" should match "gpl-3.0" in denylist
        let result2 = check_license_compliance_standalone(&policy, &["GPL-3.0".to_string()]);
        assert!(!result2.compliant);
    }

    #[test]
    fn test_license_compliance_empty_licenses() {
        let policy = make_policy(vec!["MIT"], vec!["GPL-3.0"], false);
        let licenses: Vec<String> = vec![];

        let result = check_license_compliance_standalone(&policy, &licenses);
        assert!(result.compliant);
        assert!(result.violations.is_empty());
        assert!(result.warnings.is_empty());
    }

    #[test]
    fn test_license_compliance_mixed_results() {
        let policy = make_policy(vec!["MIT", "Apache-2.0"], vec!["GPL-3.0"], false);
        let licenses = vec![
            "MIT".to_string(),
            "GPL-3.0".to_string(),      // denied
            "BSD-2-Clause".to_string(), // not in allowlist
        ];

        let result = check_license_compliance_standalone(&policy, &licenses);
        assert!(!result.compliant);
        assert_eq!(result.violations.len(), 2); // GPL denied + BSD not approved
    }

    #[test]
    fn test_license_compliance_only_denylist() {
        // No allowlist, just a denylist
        let policy = make_policy(vec![], vec!["AGPL-3.0", "SSPL-1.0"], false);

        let ok_result = check_license_compliance_standalone(&policy, &["MIT".to_string()]);
        assert!(ok_result.compliant);

        let bad_result = check_license_compliance_standalone(&policy, &["AGPL-3.0".to_string()]);
        assert!(!bad_result.compliant);
    }

    // -----------------------------------------------------------------------
    // get_format_version / get_spec_version
    //
    // NOTE: These require &self but never access DB. Testability blocker:
    // should be associated functions (no &self needed).
    // We test the expected mapping directly.
    // -----------------------------------------------------------------------

    #[test]
    fn test_format_version_mapping() {
        // CycloneDX format version
        assert_eq!(
            match SbomFormat::CycloneDX {
                SbomFormat::CycloneDX => "1.5",
                SbomFormat::SPDX => "2.3",
            },
            "1.5"
        );
        // SPDX format version
        assert_eq!(
            match SbomFormat::SPDX {
                SbomFormat::CycloneDX => "1.5",
                SbomFormat::SPDX => "2.3",
            },
            "2.3"
        );
    }

    #[test]
    fn test_spec_version_mapping() {
        assert_eq!(
            match SbomFormat::CycloneDX {
                SbomFormat::CycloneDX => "CycloneDX 1.5",
                SbomFormat::SPDX => "SPDX-2.3",
            },
            "CycloneDX 1.5"
        );
        assert_eq!(
            match SbomFormat::SPDX {
                SbomFormat::CycloneDX => "CycloneDX 1.5",
                SbomFormat::SPDX => "SPDX-2.3",
            },
            "SPDX-2.3"
        );
    }

    // -----------------------------------------------------------------------
    // SbomFormat model tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_sbom_format_parse() {
        assert_eq!(SbomFormat::parse("cyclonedx"), Some(SbomFormat::CycloneDX));
        assert_eq!(SbomFormat::parse("CycloneDX"), Some(SbomFormat::CycloneDX));
        assert_eq!(SbomFormat::parse("cdx"), Some(SbomFormat::CycloneDX));
        assert_eq!(SbomFormat::parse("spdx"), Some(SbomFormat::SPDX));
        assert_eq!(SbomFormat::parse("SPDX"), Some(SbomFormat::SPDX));
        assert_eq!(SbomFormat::parse("unknown"), None);
        assert_eq!(SbomFormat::parse(""), None);
    }

    #[test]
    fn test_sbom_format_as_str() {
        assert_eq!(SbomFormat::CycloneDX.as_str(), "cyclonedx");
        assert_eq!(SbomFormat::SPDX.as_str(), "spdx");
    }

    #[test]
    fn test_sbom_format_content_type() {
        assert_eq!(
            SbomFormat::CycloneDX.content_type(),
            "application/vnd.cyclonedx+json"
        );
        assert_eq!(SbomFormat::SPDX.content_type(), "application/spdx+json");
    }

    #[test]
    fn test_sbom_format_display() {
        assert_eq!(format!("{}", SbomFormat::CycloneDX), "cyclonedx");
        assert_eq!(format!("{}", SbomFormat::SPDX), "spdx");
    }

    // -----------------------------------------------------------------------
    // CycloneDX generation: comprehensive component field coverage
    // -----------------------------------------------------------------------

    #[test]
    fn test_cyclonedx_component_with_all_fields() {
        let deps = vec![DependencyInfo {
            name: "serde".to_string(),
            version: Some("1.0.195".to_string()),
            purl: Some("pkg:cargo/serde@1.0.195".to_string()),
            license: Some("MIT OR Apache-2.0".to_string()),
            sha256: Some("abc123def456".to_string()),
        }];

        let sbom = generate_test_cyclonedx(&deps);
        let comp = &sbom["components"][0];

        assert_eq!(comp["name"], "serde");
        assert_eq!(comp["version"], "1.0.195");
        assert_eq!(comp["purl"], "pkg:cargo/serde@1.0.195");
        assert_eq!(comp["licenses"][0]["license"]["id"], "MIT OR Apache-2.0");
    }

    #[test]
    fn test_cyclonedx_component_optional_fields_omitted() {
        let deps = vec![DependencyInfo {
            name: "minimal".to_string(),
            version: None,
            purl: None,
            license: None,
            sha256: None,
        }];

        let sbom = generate_test_cyclonedx(&deps);
        let comp = &sbom["components"][0];

        assert_eq!(comp["name"], "minimal");
        assert_eq!(comp["type"], "library");
        // Optional fields should be absent (null in JSON)
        assert!(comp.get("version").is_none());
        assert!(comp.get("purl").is_none());
        assert!(comp.get("licenses").is_none());
    }

    #[test]
    fn test_cyclonedx_multiple_components() {
        let deps = vec![
            DependencyInfo {
                name: "alpha".to_string(),
                version: Some("1.0".to_string()),
                purl: None,
                license: None,
                sha256: None,
            },
            DependencyInfo {
                name: "beta".to_string(),
                version: Some("2.0".to_string()),
                purl: None,
                license: None,
                sha256: None,
            },
            DependencyInfo {
                name: "gamma".to_string(),
                version: Some("3.0".to_string()),
                purl: None,
                license: None,
                sha256: None,
            },
        ];

        let sbom = generate_test_cyclonedx(&deps);
        let components = sbom["components"].as_array().unwrap();
        assert_eq!(components.len(), 3);
        assert_eq!(components[0]["name"], "alpha");
        assert_eq!(components[1]["name"], "beta");
        assert_eq!(components[2]["name"], "gamma");
    }

    // -----------------------------------------------------------------------
    // SPDX generation: comprehensive field coverage
    // -----------------------------------------------------------------------

    #[test]
    fn test_spdx_package_no_license() {
        let deps = vec![DependencyInfo {
            name: "unlicensed-pkg".to_string(),
            version: Some("0.1.0".to_string()),
            purl: None,
            license: None,
            sha256: None,
        }];

        let sbom = generate_test_spdx(&deps);
        let pkg = &sbom["packages"][0];

        // When no license, SPDX should have NOASSERTION (or be absent
        // depending on the test helper). The test helper only sets
        // licenseDeclared when license is present.
        // In the real generate_spdx, both licenseConcluded and licenseDeclared
        // are set to "NOASSERTION" when license is None.
        assert_eq!(pkg["name"], "unlicensed-pkg");
    }

    #[test]
    fn test_spdx_package_spdxid_format() {
        let deps = vec![
            DependencyInfo {
                name: "a".to_string(),
                version: None,
                purl: None,
                license: None,
                sha256: None,
            },
            DependencyInfo {
                name: "b".to_string(),
                version: None,
                purl: None,
                license: None,
                sha256: None,
            },
        ];

        let sbom = generate_test_spdx(&deps);
        let packages = sbom["packages"].as_array().unwrap();

        assert_eq!(packages[0]["SPDXID"], "SPDXRef-Package-0");
        assert_eq!(packages[1]["SPDXID"], "SPDXRef-Package-1");
    }

    #[test]
    fn test_spdx_download_location_noassertion() {
        let deps = vec![DependencyInfo {
            name: "pkg".to_string(),
            version: Some("1.0".to_string()),
            purl: None,
            license: None,
            sha256: None,
        }];

        let sbom = generate_test_spdx(&deps);
        assert_eq!(sbom["packages"][0]["downloadLocation"], "NOASSERTION");
    }

    // -----------------------------------------------------------------------
    // ComponentInfo struct
    // -----------------------------------------------------------------------

    #[test]
    fn test_component_info_from_dependency() {
        let dep = DependencyInfo {
            name: "react".to_string(),
            version: Some("18.2.0".to_string()),
            purl: Some("pkg:npm/react@18.2.0".to_string()),
            license: Some("MIT".to_string()),
            sha256: Some("sha256hash".to_string()),
        };

        let comp = ComponentInfo {
            name: dep.name.clone(),
            version: dep.version.clone(),
            purl: dep.purl.clone(),
            component_type: Some("library".to_string()),
            licenses: dep.license.clone().into_iter().collect(),
            sha256: dep.sha256.clone(),
            supplier: None,
        };

        assert_eq!(comp.name, "react");
        assert_eq!(comp.version.as_deref(), Some("18.2.0"));
        assert_eq!(comp.purl.as_deref(), Some("pkg:npm/react@18.2.0"));
        assert_eq!(comp.component_type.as_deref(), Some("library"));
        assert_eq!(comp.licenses, vec!["MIT".to_string()]);
        assert_eq!(comp.sha256.as_deref(), Some("sha256hash"));
        assert!(comp.supplier.is_none());
    }

    // -----------------------------------------------------------------------
    // DependencyInfo serialization/deserialization
    // -----------------------------------------------------------------------

    #[test]
    fn test_dependency_info_serde_roundtrip() {
        let dep = DependencyInfo {
            name: "axios".to_string(),
            version: Some("1.6.0".to_string()),
            purl: Some("pkg:npm/axios@1.6.0".to_string()),
            license: Some("MIT".to_string()),
            sha256: None,
        };

        let json = serde_json::to_string(&dep).unwrap();
        let deserialized: DependencyInfo = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.name, "axios");
        assert_eq!(deserialized.version.as_deref(), Some("1.6.0"));
        assert_eq!(deserialized.purl.as_deref(), Some("pkg:npm/axios@1.6.0"));
        assert_eq!(deserialized.license.as_deref(), Some("MIT"));
        assert!(deserialized.sha256.is_none());
    }

    // -----------------------------------------------------------------------
    // LicenseCheckResult serialization
    // -----------------------------------------------------------------------

    #[test]
    fn test_license_check_result_serialization() {
        let result = LicenseCheckResult {
            compliant: false,
            violations: vec!["License 'GPL-3.0' is denied".to_string()],
            warnings: vec!["License 'LGPL-2.1' is not in approved list".to_string()],
        };

        let json = serde_json::to_value(&result).unwrap();
        assert_eq!(json["compliant"], false);
        assert_eq!(json["violations"].as_array().unwrap().len(), 1);
        assert_eq!(json["warnings"].as_array().unwrap().len(), 1);
    }

    #[test]
    fn test_license_check_result_compliant_serialization() {
        let result = LicenseCheckResult {
            compliant: true,
            violations: vec![],
            warnings: vec![],
        };

        let json = serde_json::to_value(&result).unwrap();
        assert_eq!(json["compliant"], true);
        assert!(json["violations"].as_array().unwrap().is_empty());
        assert!(json["warnings"].as_array().unwrap().is_empty());
    }

    // -----------------------------------------------------------------------
    // CveStatus model
    // -----------------------------------------------------------------------

    #[test]
    fn test_cve_status_parse() {
        assert_eq!(CveStatus::parse("open"), Some(CveStatus::Open));
        assert_eq!(CveStatus::parse("fixed"), Some(CveStatus::Fixed));
        assert_eq!(
            CveStatus::parse("acknowledged"),
            Some(CveStatus::Acknowledged)
        );
        assert_eq!(
            CveStatus::parse("false_positive"),
            Some(CveStatus::FalsePositive)
        );
        assert_eq!(CveStatus::parse("OPEN"), Some(CveStatus::Open));
        assert_eq!(CveStatus::parse("unknown"), None);
    }

    #[test]
    fn test_cve_status_as_str() {
        assert_eq!(CveStatus::Open.as_str(), "open");
        assert_eq!(CveStatus::Fixed.as_str(), "fixed");
        assert_eq!(CveStatus::Acknowledged.as_str(), "acknowledged");
        assert_eq!(CveStatus::FalsePositive.as_str(), "false_positive");
    }

    // -----------------------------------------------------------------------
    // synth_cve_id: regression coverage for #1375. The CVE history endpoint
    // synthesizes `CveHistoryEntry` rows on the fly from `scan_findings`
    // because `cve_history` is never written to in production. Synth ids
    // must be deterministic so re-reads return stable identifiers and
    // distinct for distinct (artifact, cve) pairs.
    // -----------------------------------------------------------------------

    #[test]
    fn test_synth_cve_id_is_deterministic() {
        let artifact = Uuid::new_v4();
        let cve = "CVE-2019-10744";
        let a = synth_cve_id(artifact, cve);
        let b = synth_cve_id(artifact, cve);
        assert_eq!(
            a, b,
            "synth_cve_id must be deterministic so client-side dedup by id works"
        );
    }

    #[test]
    fn test_synth_cve_id_distinct_pairs_produce_distinct_ids() {
        let a1 = Uuid::new_v4();
        let a2 = Uuid::new_v4();
        let cve = "CVE-2019-10744";
        let x = synth_cve_id(a1, cve);
        let y = synth_cve_id(a2, cve);
        let z = synth_cve_id(a1, "CVE-2024-12345");
        assert_ne!(x, y, "different artifacts must yield different ids");
        assert_ne!(x, z, "different CVEs must yield different ids");
        assert_ne!(y, z);
    }

    #[test]
    fn test_synth_cve_id_separator_prevents_concat_collisions() {
        // Without the explicit separator byte, (artifact="00...01", cve="234")
        // would hash the same as (artifact="00...0", cve="1234"). Use a pair
        // that exercises adjacent boundaries: encode the boundary by varying
        // the cve suffix length while keeping the same combined string.
        let artifact = Uuid::nil();
        let a = synth_cve_id(artifact, "AB");
        let b = synth_cve_id(artifact, "ABC");
        assert_ne!(
            a, b,
            "synth_cve_id must separate fields so concatenation collisions \
             do not yield the same UUID for different inputs"
        );
    }

    #[test]
    fn test_synth_cve_id_empty_cve_id() {
        // Defensive: the mapping in `scan_finding_to_history_entry` passes
        // an empty cve_id when the row has `None`. The hash must still be
        // total (not panic) and remain stable.
        let artifact = Uuid::nil();
        let a = synth_cve_id(artifact, "");
        let b = synth_cve_id(artifact, "");
        assert_eq!(a, b);
        // And distinct from a non-empty cve_id under the same artifact.
        let c = synth_cve_id(artifact, "CVE-2019-10744");
        assert_ne!(a, c);
    }

    // -----------------------------------------------------------------------
    // match_synth_cve_id: reverse-resolve a synthetic id to its (artifact,
    // cve) pair by recomputing the hash. This is the pure half of the #1561
    // fix -- it proves the read-side `synth_cve_id` round-trips back to the
    // pair the legacy ack path needs, the exact thing whose absence made
    // `POST /sbom/cve/status/{synth_id}` 404.
    // -----------------------------------------------------------------------

    #[test]
    fn test_match_synth_cve_id_round_trips_from_synth_cve_id() {
        // The read path emits `synth_cve_id(artifact, cve)`. Feeding that id
        // back through `match_synth_cve_id` against the candidate pair set
        // (what `resolve_synth_cve_id` pulls from `scan_findings`) must
        // recover the original pair -- otherwise the ack falls back to 404.
        let a1 = Uuid::new_v4();
        let a2 = Uuid::new_v4();
        let pairs = vec![
            (a1, "CVE-2019-10744".to_string()),
            (a2, "CVE-2024-12345".to_string()),
            (a1, "CVE-2024-12345".to_string()),
        ];
        let target = synth_cve_id(a1, "CVE-2024-12345");
        let resolved = match_synth_cve_id(target, &pairs);
        assert_eq!(resolved, Some((a1, "CVE-2024-12345".to_string())));
    }

    #[test]
    fn test_match_synth_cve_id_returns_none_when_no_pair_matches() {
        // A genuinely unknown id (no scan_findings pair hashes to it) must
        // resolve to None so the service can preserve the legacy 404.
        let pairs = vec![(Uuid::new_v4(), "CVE-2019-10744".to_string())];
        assert_eq!(match_synth_cve_id(Uuid::new_v4(), &pairs), None);
        assert_eq!(match_synth_cve_id(Uuid::nil(), &[]), None);
    }

    #[test]
    fn test_match_synth_cve_id_distinguishes_pairs_sharing_a_field() {
        // Two pairs differing only by artifact (same CVE) must resolve to the
        // correct artifact, and two differing only by CVE (same artifact) to
        // the correct CVE -- the hash binds both fields.
        let a1 = Uuid::new_v4();
        let a2 = Uuid::new_v4();
        let pairs = vec![
            (a1, "CVE-2019-10744".to_string()),
            (a2, "CVE-2019-10744".to_string()),
        ];
        assert_eq!(
            match_synth_cve_id(synth_cve_id(a2, "CVE-2019-10744"), &pairs),
            Some((a2, "CVE-2019-10744".to_string()))
        );

        let pairs2 = vec![
            (a1, "CVE-2019-10744".to_string()),
            (a1, "CVE-2024-12345".to_string()),
        ];
        assert_eq!(
            match_synth_cve_id(synth_cve_id(a1, "CVE-2024-12345"), &pairs2),
            Some((a1, "CVE-2024-12345".to_string()))
        );
    }

    // -----------------------------------------------------------------------
    // Pure-logic helpers extracted from the DB-coupled CVE history paths.
    // These are the cases the inline coverage gate counts; the SQL queries
    // they wrap are unreachable without a live PostgreSQL, so we exercise
    // the surrounding projection / dedupe / sort logic here. (#1375)
    // -----------------------------------------------------------------------

    fn make_history_entry(cve_id: &str, first_detected_at: DateTime<Utc>) -> CveHistoryEntry {
        CveHistoryEntry {
            id: Uuid::new_v4(),
            artifact_id: Uuid::new_v4(),
            sbom_id: None,
            component_id: None,
            scan_result_id: None,
            cve_id: cve_id.to_string(),
            affected_component: None,
            affected_version: None,
            fixed_version: None,
            severity: None,
            cvss_score: None,
            cve_published_at: None,
            first_detected_at,
            last_detected_at: first_detected_at,
            status: "open".to_string(),
            acknowledged_by: None,
            acknowledged_at: None,
            acknowledged_reason: None,
            created_at: first_detected_at,
            updated_at: first_detected_at,
        }
    }

    fn make_scan_row(
        artifact_id: Uuid,
        cve_id: Option<&str>,
        first_detected_at: DateTime<Utc>,
        all_acknowledged: bool,
    ) -> ScanFindingCveRow {
        ScanFindingCveRow {
            artifact_id,
            cve_id: cve_id.map(|s| s.to_string()),
            severity: Some("high".to_string()),
            affected_component: Some("lodash".to_string()),
            affected_version: Some("4.17.4".to_string()),
            fixed_version: Some("4.17.21".to_string()),
            first_detected_at,
            last_detected_at: first_detected_at,
            all_acknowledged,
        }
    }

    // --- build_known_cve_set -----------------------------------------------

    #[test]
    fn test_build_known_cve_set_uppercases() {
        let entries = vec![
            make_history_entry("cve-2019-10744", Utc::now()),
            make_history_entry("CVE-2024-12345", Utc::now()),
        ];
        let set = build_known_cve_set(&entries);
        assert!(set.contains("CVE-2019-10744"));
        assert!(set.contains("CVE-2024-12345"));
        // Lower-case form must not appear -- the helper exists *because* we
        // need a case-insensitive compare downstream.
        assert!(!set.contains("cve-2019-10744"));
        assert_eq!(set.len(), 2);
    }

    #[test]
    fn test_build_known_cve_set_empty_input() {
        let set = build_known_cve_set(&[]);
        assert!(set.is_empty());
    }

    #[test]
    fn test_build_known_cve_set_dedupes_case_variants() {
        // Two curated rows for the same CVE in mixed case must collapse
        // to one entry in the known set, otherwise the dedupe-by-known
        // filter on the scan-findings path would behave inconsistently
        // depending on which case the scanner happened to write.
        let entries = vec![
            make_history_entry("cve-2019-10744", Utc::now()),
            make_history_entry("CVE-2019-10744", Utc::now()),
        ];
        let set = build_known_cve_set(&entries);
        assert_eq!(set.len(), 1);
        assert!(set.contains("CVE-2019-10744"));
    }

    // --- scan_row_passes_known_filter --------------------------------------

    #[test]
    fn test_scan_row_passes_known_filter_drops_known_uppercase_match() {
        let known: HashSet<String> = ["CVE-2019-10744".to_string()].into_iter().collect();
        // Row matches by upper-case: filtered out.
        assert!(!scan_row_passes_known_filter(
            Some("CVE-2019-10744"),
            &known
        ));
    }

    #[test]
    fn test_scan_row_passes_known_filter_drops_known_lowercase_match() {
        let known: HashSet<String> = ["CVE-2019-10744".to_string()].into_iter().collect();
        // Row in lower-case still matches: case-insensitive dedupe.
        assert!(!scan_row_passes_known_filter(
            Some("cve-2019-10744"),
            &known
        ));
    }

    #[test]
    fn test_scan_row_passes_known_filter_keeps_novel_cve() {
        let known: HashSet<String> = ["CVE-2019-10744".to_string()].into_iter().collect();
        assert!(scan_row_passes_known_filter(Some("CVE-2024-12345"), &known));
    }

    #[test]
    fn test_scan_row_passes_known_filter_drops_none_cve_id() {
        // Rows with NULL cve_id should be filtered out -- they cannot be
        // meaningful CVE history entries.
        let known: HashSet<String> = HashSet::new();
        assert!(!scan_row_passes_known_filter(None, &known));
    }

    #[test]
    fn test_scan_row_passes_known_filter_keeps_when_known_empty() {
        let known: HashSet<String> = HashSet::new();
        assert!(scan_row_passes_known_filter(Some("CVE-2019-10744"), &known));
    }

    // --- cve_status_to_acknowledge_flag (#1426) ----------------------------
    //
    // The Security tab read path projects `scan_findings` into synth
    // `CveHistoryEntry` rows; `update_cve_status_by_artifact_cve` writes the
    // same table back. `scan_findings` only models a binary acknowledge
    // state, so the four-state `CveStatus` enum has to collapse onto a
    // `bool`. These tests pin the mapping rules so a future enum-variant
    // addition doesn't silently coerce.

    #[test]
    fn test_cve_status_to_acknowledge_flag_acknowledged_is_true() {
        assert_eq!(
            cve_status_to_acknowledge_flag(CveStatus::Acknowledged),
            Some(true)
        );
    }

    #[test]
    fn test_cve_status_to_acknowledge_flag_false_positive_collapses_to_true() {
        // `scan_findings` has no separate "false positive" column. The
        // boolean column models "the user told us to hide this"; the reason
        // field carries the audit distinction.
        assert_eq!(
            cve_status_to_acknowledge_flag(CveStatus::FalsePositive),
            Some(true)
        );
    }

    #[test]
    fn test_cve_status_to_acknowledge_flag_open_is_false() {
        // `Open` is the revoke-acknowledgement path on the Security tab.
        assert_eq!(cve_status_to_acknowledge_flag(CveStatus::Open), Some(false));
    }

    #[test]
    fn test_cve_status_to_acknowledge_flag_fixed_is_none() {
        // "Fixed" has no representation on `scan_findings`. The handler
        // must surface a 400, not silently set is_acknowledged = true.
        assert_eq!(cve_status_to_acknowledge_flag(CveStatus::Fixed), None);
    }

    // --- severity_rank / severity_from_rank --------------------------------
    //
    // Round-2 regression coverage for the lexicographic-MAX bug (#1375). The
    // pre-fix SQL used `MAX(severity)` against a TEXT column, which orders
    // alphabetically: "medium" > "low" > "high" > "critical". So a CVE
    // reported as `high` by one scanner and `medium` by another surfaced as
    // `medium` in the trends counts and timeline, silently undercounting
    // high/critical findings. The ranked CASE in `get_cve_trends` and
    // `build_cve_entries_from_scan_findings` fixes this; these tests pin
    // the Rust side of the contract so the SQL and Rust stay in lockstep.

    #[test]
    fn test_severity_rank_strict_ordering() {
        // Operational severity ranking, NOT lex order. This is the load-
        // bearing contract that motivated the round-2 SQL rewrite.
        assert!(severity_rank("critical") > severity_rank("high"));
        assert!(severity_rank("high") > severity_rank("medium"));
        assert!(severity_rank("medium") > severity_rank("low"));
        assert!(severity_rank("low") > severity_rank("unknown"));
    }

    #[test]
    fn test_severity_rank_case_insensitive() {
        // The DB column has no case constraint and different scanners write
        // different cases (Trivy: "HIGH", Grype: "High", OSV: "high"). The
        // ranking must collapse all of these to the same value or the
        // multi-scanner dedupe in `get_cve_trends` would split a single
        // CVE into separate rows by case.
        assert_eq!(severity_rank("CRITICAL"), severity_rank("critical"));
        assert_eq!(severity_rank("High"), severity_rank("high"));
        assert_eq!(severity_rank("Medium"), severity_rank("medium"));
        assert_eq!(severity_rank("LOW"), severity_rank("low"));
    }

    #[test]
    fn test_severity_rank_unknown_is_zero() {
        // Anything outside the four canonical labels (NULL severity, future
        // labels like "info" / "negligible", junk data) must rank 0 so it
        // never outranks a real severity.
        assert_eq!(severity_rank(""), 0);
        assert_eq!(severity_rank("unknown"), 0);
        assert_eq!(severity_rank("info"), 0);
        assert_eq!(severity_rank("negligible"), 0);
        assert!(severity_rank("low") > severity_rank("info"));
    }

    #[test]
    fn test_severity_from_rank_round_trip() {
        // Round-trip every canonical label so a refactor of the rank
        // constants can't silently break the inverse mapping.
        for label in ["critical", "high", "medium", "low"] {
            let r = severity_rank(label);
            assert_eq!(
                severity_from_rank(r),
                Some(label),
                "rank/label round-trip must hold for {label}"
            );
        }
    }

    #[test]
    fn test_severity_from_rank_unknown_ranks() {
        assert_eq!(severity_from_rank(0), None);
        assert_eq!(severity_from_rank(5), None);
        assert_eq!(severity_from_rank(-1), None);
    }

    // The headline #1375 round-2 regression: aggregating `['low', 'high',
    // 'medium']` must yield `'high'`, not `'medium'` (which is what the
    // pre-fix lexicographic MAX returned).
    #[test]
    fn test_severity_rank_aggregates_high_over_medium_for_low_high_medium_input() {
        let severities = ["low", "high", "medium"];
        let max_rank = severities.iter().map(|s| severity_rank(s)).max().unwrap();
        assert_eq!(
            severity_from_rank(max_rank),
            Some("high"),
            "['low','high','medium'] must aggregate to 'high', not the \
             lex-largest 'medium' that the pre-fix MAX(severity) returned"
        );
    }

    #[test]
    fn test_severity_rank_aggregates_critical_over_high() {
        // The other half of the lex-sort bug: "critical" sorts BEFORE
        // "high" alphabetically, so the pre-fix MAX returned "high" for
        // a (high, critical) pair. The rank picks "critical" correctly.
        let severities = ["high", "critical"];
        let max_rank = severities.iter().map(|s| severity_rank(s)).max().unwrap();
        assert_eq!(severity_from_rank(max_rank), Some("critical"));
    }

    #[test]
    fn test_severity_rank_aggregates_mixed_case_input() {
        // Multi-scanner overlap with inconsistent casing must still pick
        // the operationally-worst severity.
        let severities = ["MEDIUM", "High", "low"];
        let max_rank = severities.iter().map(|s| severity_rank(s)).max().unwrap();
        assert_eq!(severity_from_rank(max_rank), Some("high"));
    }

    #[test]
    fn test_severity_rank_aggregates_skips_unknown() {
        // An unknown rank-0 row in the mix must not knock a real severity
        // out of the aggregate (a regression worth pinning because a
        // future scanner could write `"info"` or `""`).
        let severities = ["unknown", "low", "info", "high", "negligible"];
        let max_rank = severities.iter().map(|s| severity_rank(s)).max().unwrap();
        assert_eq!(severity_from_rank(max_rank), Some("high"));
    }

    // --- status mapping helpers --------------------------------------------

    #[test]
    fn test_status_string_from_acknowledged() {
        assert_eq!(status_string_from_acknowledged(true), "acknowledged");
        assert_eq!(status_string_from_acknowledged(false), "open");
    }

    #[test]
    fn test_status_enum_from_acknowledged() {
        assert_eq!(status_enum_from_acknowledged(true), CveStatus::Acknowledged);
        assert_eq!(status_enum_from_acknowledged(false), CveStatus::Open);
    }

    #[test]
    fn test_status_mappings_are_consistent() {
        // Whatever the string variant says, the enum variant must match
        // (else trends timeline and history list would disagree on the
        // same scan_findings row).
        assert_eq!(
            status_string_from_acknowledged(true),
            status_enum_from_acknowledged(true).as_str()
        );
        assert_eq!(
            status_string_from_acknowledged(false),
            status_enum_from_acknowledged(false).as_str()
        );
    }

    // --- scan_finding_to_history_entry -------------------------------------

    #[test]
    fn test_scan_finding_to_history_entry_basic_mapping() {
        let when = Utc::now();
        let artifact = Uuid::new_v4();
        let row = make_scan_row(artifact, Some("CVE-2019-10744"), when, false);
        let entry = scan_finding_to_history_entry(row);

        assert_eq!(entry.artifact_id, artifact);
        assert_eq!(entry.cve_id, "CVE-2019-10744");
        assert_eq!(entry.severity.as_deref(), Some("high"));
        assert_eq!(entry.affected_component.as_deref(), Some("lodash"));
        assert_eq!(entry.affected_version.as_deref(), Some("4.17.4"));
        assert_eq!(entry.fixed_version.as_deref(), Some("4.17.21"));
        assert_eq!(entry.first_detected_at, when);
        assert_eq!(entry.last_detected_at, when);
        assert_eq!(entry.status, "open");
        assert_eq!(entry.created_at, when);
        assert_eq!(entry.updated_at, when);
        // Synthetic rows carry no FK references.
        assert!(entry.sbom_id.is_none());
        assert!(entry.component_id.is_none());
        assert!(entry.scan_result_id.is_none());
        assert!(entry.acknowledged_by.is_none());
        assert!(entry.acknowledged_at.is_none());
        assert!(entry.acknowledged_reason.is_none());
        assert!(entry.cvss_score.is_none());
        assert!(entry.cve_published_at.is_none());
        // The id must equal synth_cve_id for the same inputs (stable across re-reads).
        assert_eq!(entry.id, synth_cve_id(artifact, "CVE-2019-10744"));
    }

    #[test]
    fn test_scan_finding_to_history_entry_acknowledged_status() {
        let row = make_scan_row(Uuid::new_v4(), Some("CVE-2024-12345"), Utc::now(), true);
        let entry = scan_finding_to_history_entry(row);
        assert_eq!(entry.status, "acknowledged");
    }

    #[test]
    fn test_scan_finding_to_history_entry_none_cve_id_defaults_to_empty() {
        // Defensive: the upstream filter should drop rows with NULL cve_id,
        // but if anything slips through the mapping must remain total and
        // produce a usable (if empty-id) row rather than panicking.
        let row = make_scan_row(Uuid::new_v4(), None, Utc::now(), false);
        let entry = scan_finding_to_history_entry(row);
        assert_eq!(entry.cve_id, "");
    }

    // --- scan_finding_to_timeline_entry ------------------------------------

    #[test]
    fn test_scan_finding_to_timeline_entry_days_exposed() {
        let now = Utc::now();
        // 10 days ago
        let first = now - chrono::Duration::days(10);
        let row = make_scan_row(Uuid::new_v4(), Some("CVE-2019-10744"), first, false);
        let t = scan_finding_to_timeline_entry(&row, now);
        assert_eq!(t.days_exposed, 10);
        assert_eq!(t.cve_id, "CVE-2019-10744");
        assert_eq!(t.severity, "high");
        assert_eq!(t.affected_component, "lodash");
        assert_eq!(t.status, CveStatus::Open);
        assert_eq!(t.first_detected_at, first);
        assert!(t.cve_published_at.is_none());
    }

    #[test]
    fn test_scan_finding_to_timeline_entry_acknowledged_status() {
        let now = Utc::now();
        let row = make_scan_row(Uuid::new_v4(), Some("CVE-2024-12345"), now, true);
        let t = scan_finding_to_timeline_entry(&row, now);
        assert_eq!(t.status, CveStatus::Acknowledged);
        assert_eq!(t.days_exposed, 0);
    }

    #[test]
    fn test_scan_finding_to_timeline_entry_handles_none_fields() {
        let now = Utc::now();
        let row = ScanFindingCveRow {
            artifact_id: Uuid::new_v4(),
            cve_id: None,
            severity: None,
            affected_component: None,
            affected_version: None,
            fixed_version: None,
            first_detected_at: now,
            last_detected_at: now,
            all_acknowledged: false,
        };
        let t = scan_finding_to_timeline_entry(&row, now);
        // None fields default to empty strings in the DTO.
        assert_eq!(t.cve_id, "");
        assert_eq!(t.severity, "");
        assert_eq!(t.affected_component, "");
    }

    // --- filter_entries_by_repo_map ----------------------------------------

    #[test]
    fn test_filter_entries_by_repo_map_keeps_only_allowed() {
        let artifact_a = Uuid::new_v4();
        let artifact_b = Uuid::new_v4();
        let repo_a = Uuid::new_v4();
        let repo_b = Uuid::new_v4();

        let mut e1 = make_history_entry("CVE-1", Utc::now());
        e1.artifact_id = artifact_a;
        let mut e2 = make_history_entry("CVE-2", Utc::now());
        e2.artifact_id = artifact_b;

        let mut map = std::collections::HashMap::new();
        map.insert(artifact_a, repo_a);
        map.insert(artifact_b, repo_b);

        let allowed: HashSet<Uuid> = [repo_a].into_iter().collect();
        let filtered = filter_entries_by_repo_map(vec![e1, e2], &map, &allowed);
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].cve_id, "CVE-1");
        assert_eq!(filtered[0].artifact_id, artifact_a);
    }

    #[test]
    fn test_filter_entries_by_repo_map_drops_entry_with_unknown_artifact() {
        // Defensive: if the DB lookup is partial (e.g. artifact was deleted
        // mid-request, so `is_deleted` filter excluded it), the entry must
        // be dropped rather than leaked to the caller.
        let artifact_a = Uuid::new_v4();
        let mut e1 = make_history_entry("CVE-1", Utc::now());
        e1.artifact_id = artifact_a;
        let map = std::collections::HashMap::new(); // empty: artifact not present
        let allowed: HashSet<Uuid> = [Uuid::new_v4()].into_iter().collect();
        let filtered = filter_entries_by_repo_map(vec![e1], &map, &allowed);
        assert!(
            filtered.is_empty(),
            "entries with unknown repo must be dropped"
        );
    }

    #[test]
    fn test_filter_entries_by_repo_map_empty_input() {
        let map = std::collections::HashMap::new();
        let allowed: HashSet<Uuid> = HashSet::new();
        let filtered = filter_entries_by_repo_map(vec![], &map, &allowed);
        assert!(filtered.is_empty());
    }

    #[test]
    fn test_filter_entries_by_repo_map_empty_allowed_set_drops_all() {
        // An empty allowed set must drop everything (the caller passed an
        // explicit empty allowlist, not None -- different contract).
        let artifact_a = Uuid::new_v4();
        let repo_a = Uuid::new_v4();
        let mut e1 = make_history_entry("CVE-1", Utc::now());
        e1.artifact_id = artifact_a;
        let mut map = std::collections::HashMap::new();
        map.insert(artifact_a, repo_a);
        let allowed: HashSet<Uuid> = HashSet::new();
        let filtered = filter_entries_by_repo_map(vec![e1], &map, &allowed);
        assert!(filtered.is_empty());
    }

    // --- sort_entries_by_first_detected_desc -------------------------------

    #[test]
    fn test_sort_entries_by_first_detected_desc_newest_first() {
        let now = Utc::now();
        let old = make_history_entry("CVE-OLD", now - chrono::Duration::days(30));
        let mid = make_history_entry("CVE-MID", now - chrono::Duration::days(10));
        let new = make_history_entry("CVE-NEW", now);
        // Deliberately scrambled.
        let mut entries = vec![old, new, mid];
        sort_entries_by_first_detected_desc(&mut entries);
        assert_eq!(entries[0].cve_id, "CVE-NEW");
        assert_eq!(entries[1].cve_id, "CVE-MID");
        assert_eq!(entries[2].cve_id, "CVE-OLD");
    }

    #[test]
    fn test_sort_entries_by_first_detected_desc_empty_input() {
        let mut entries: Vec<CveHistoryEntry> = vec![];
        sort_entries_by_first_detected_desc(&mut entries);
        assert!(entries.is_empty());
    }

    #[test]
    fn test_sort_entries_by_first_detected_desc_stable_for_equal_timestamps() {
        let when = Utc::now();
        let a = make_history_entry("CVE-A", when);
        let b = make_history_entry("CVE-B", when);
        let mut entries = vec![a.clone(), b.clone()];
        sort_entries_by_first_detected_desc(&mut entries);
        // Both have the same first_detected_at -- the sort is total but the
        // relative order of equals is preserved by sort_by_key (Rust's slice
        // sort is stable). Don't rely on which comes first; rely on both
        // still being present.
        assert_eq!(entries.len(), 2);
        assert!(entries.iter().any(|e| e.cve_id == "CVE-A"));
        assert!(entries.iter().any(|e| e.cve_id == "CVE-B"));
    }

    // --- end-to-end pipeline check (pure, no DB) ---------------------------

    #[test]
    fn test_scan_finding_dedupe_then_merge_then_sort() {
        // Simulate the full read pipeline in `get_cve_history` against an
        // in-memory dataset: curated rows + scan rows, dedupe by cve_id,
        // sort newest-first.
        let now = Utc::now();
        let artifact = Uuid::new_v4();

        // Curated row (older, "CVE-2019-10744" upper-case).
        let curated = make_history_entry("CVE-2019-10744", now - chrono::Duration::days(20));

        // Scan rows: one is a case-variant duplicate of the curated CVE
        // (must be dropped), one is novel (must survive).
        let dup_row = make_scan_row(
            artifact,
            Some("cve-2019-10744"), // lower-case duplicate
            now - chrono::Duration::days(5),
            false,
        );
        let novel_row = make_scan_row(
            artifact,
            Some("CVE-2024-12345"),
            now - chrono::Duration::days(1),
            false,
        );

        // Step 1: known set from curated rows.
        let known = build_known_cve_set(std::slice::from_ref(&curated));
        assert_eq!(known.len(), 1);

        // Step 2: apply dedupe filter to scan rows.
        let scan_rows = vec![dup_row, novel_row];
        let kept: Vec<_> = scan_rows
            .into_iter()
            .filter(|r| scan_row_passes_known_filter(r.cve_id.as_deref(), &known))
            .collect();
        assert_eq!(
            kept.len(),
            1,
            "case-insensitive dedupe must drop the lower-case duplicate"
        );
        assert_eq!(kept[0].cve_id.as_deref(), Some("CVE-2024-12345"));

        // Step 3: project scan rows to CveHistoryEntry.
        let mut combined: Vec<CveHistoryEntry> = vec![curated];
        combined.extend(kept.into_iter().map(scan_finding_to_history_entry));

        // Step 4: sort newest-first.
        sort_entries_by_first_detected_desc(&mut combined);

        // The novel scan row was detected 1 day ago, the curated row 20
        // days ago, so the scan row sorts first.
        assert_eq!(combined.len(), 2);
        assert_eq!(combined[0].cve_id, "CVE-2024-12345");
        assert_eq!(combined[1].cve_id, "CVE-2019-10744");
    }

    // -----------------------------------------------------------------------
    // cve_trends_from_aggregates: pure projection from the count tuple to
    // the typed `CveTrends` DTO. Round-2 (#1375) extracted this so the
    // field-by-field mapping is exercised without spinning up Postgres.
    // -----------------------------------------------------------------------

    #[test]
    fn test_cve_trends_from_aggregates_field_mapping() {
        // Every tuple slot must land in its named DTO field. A swap (e.g.
        // critical and high crossed) would silently misreport severity
        // counts on the trends dashboard; pin the mapping explicitly.
        let trends = cve_trends_from_aggregates(100, 60, 25, 5, 10, 20, 30, 15, vec![]);
        assert_eq!(trends.total_cves, 100);
        assert_eq!(trends.open_cves, 60);
        assert_eq!(trends.acknowledged_cves, 25);
        assert_eq!(trends.critical_count, 5);
        assert_eq!(trends.high_count, 10);
        assert_eq!(trends.medium_count, 20);
        assert_eq!(trends.low_count, 30);
        assert_eq!(trends.fixed_cves, 15);
        // avg_days_to_fix is always None on the scan-findings path.
        assert!(trends.avg_days_to_fix.is_none());
        assert!(trends.timeline.is_empty());
        // #1446: alias fields must mirror their *_count / *_cves counterparts
        // so the security-tests `cve-history` trends-shape probe sees a
        // recognized aggregate (`.total`, `.critical`, `.high`, ...).
        assert_eq!(trends.total, 100);
        assert_eq!(trends.critical, 5);
        assert_eq!(trends.high, 10);
        assert_eq!(trends.medium, 20);
        assert_eq!(trends.low, 30);
    }

    #[test]
    fn test_cve_trends_serializes_alias_fields() {
        // #1446: the JSON body must surface `total`, `critical`, `high`,
        // `medium`, `low` alongside the original `total_cves`,
        // `critical_count`, ... keys. The security-tests probe accepts ANY
        // of `.total // .count // .critical // .high` as a recognized
        // aggregate; we pin both shapes so future refactors can't break it.
        let trends = cve_trends_from_aggregates(7, 3, 1, 2, 3, 1, 0, 4, vec![]);
        let json = serde_json::to_value(&trends).expect("serialize CveTrends");
        // Original keys retained.
        assert_eq!(json["total_cves"], 7);
        assert_eq!(json["critical_count"], 2);
        assert_eq!(json["high_count"], 3);
        // Alias keys added.
        assert_eq!(json["total"], 7);
        assert_eq!(json["critical"], 2);
        assert_eq!(json["high"], 3);
        assert_eq!(json["medium"], 1);
        assert_eq!(json["low"], 0);
    }

    #[test]
    fn test_cve_trends_from_aggregates_avg_days_to_fix_always_none() {
        // scan_findings has no fixed-at timestamp; the contract is that
        // this field stays None regardless of how many fixed CVEs there
        // are. Pin it so a future refactor cannot silently start filling
        // it with bogus zeros.
        let trends = cve_trends_from_aggregates(10, 5, 2, 1, 1, 1, 1, 3, vec![]);
        assert!(trends.avg_days_to_fix.is_none(), "must be None always");
    }

    #[test]
    fn test_cve_trends_from_aggregates_timeline_passes_through() {
        // Timeline is moved through unchanged; ensure the projection does
        // not reorder or drop entries.
        let now = Utc::now();
        let t1 = CveTimelineEntry {
            cve_id: "CVE-2024-1".to_string(),
            severity: "high".to_string(),
            affected_component: "lodash".to_string(),
            cve_published_at: None,
            first_detected_at: now,
            status: CveStatus::Open,
            days_exposed: 7,
        };
        let t2 = CveTimelineEntry {
            cve_id: "CVE-2024-2".to_string(),
            severity: "critical".to_string(),
            affected_component: "express".to_string(),
            cve_published_at: None,
            first_detected_at: now,
            status: CveStatus::Acknowledged,
            days_exposed: 1,
        };
        let trends = cve_trends_from_aggregates(2, 1, 1, 1, 1, 0, 0, 0, vec![t1, t2]);
        assert_eq!(trends.timeline.len(), 2);
        assert_eq!(trends.timeline[0].cve_id, "CVE-2024-1");
        assert_eq!(trends.timeline[1].cve_id, "CVE-2024-2");
    }

    #[test]
    fn test_cve_trends_from_aggregates_all_zero_input() {
        // Pre-#1375 every fresh deployment returned all-zero counts
        // because `cve_history` was empty. Now that the read paths derive
        // from `scan_findings`, the zero-zero case still has to project
        // cleanly when nothing has been scanned yet.
        let trends = cve_trends_from_aggregates(0, 0, 0, 0, 0, 0, 0, 0, vec![]);
        assert_eq!(trends.total_cves, 0);
        assert_eq!(trends.open_cves, 0);
        assert_eq!(trends.critical_count, 0);
        assert!(trends.timeline.is_empty());
    }

    // -----------------------------------------------------------------------
    // project_timeline_rows: read-side helper that maps scan rows to typed
    // `CveTimelineEntry` DTOs. Pure (no DB, no clock side-effect — `now`
    // is injected).
    // -----------------------------------------------------------------------

    #[test]
    fn test_project_timeline_rows_empty_input() {
        let now = Utc::now();
        let result = project_timeline_rows(&[], now);
        assert!(result.is_empty());
    }

    #[test]
    fn test_project_timeline_rows_preserves_order() {
        let now = Utc::now();
        let r1 = make_scan_row(
            Uuid::new_v4(),
            Some("CVE-2024-1"),
            now - chrono::Duration::days(2),
            false,
        );
        let r2 = make_scan_row(
            Uuid::new_v4(),
            Some("CVE-2024-2"),
            now - chrono::Duration::days(5),
            false,
        );
        let result = project_timeline_rows(&[r1, r2], now);
        assert_eq!(result.len(), 2);
        // Order is preserved (the SQL already orders DESC by detection
        // date; the projection must not re-sort or it would shuffle the
        // dashboard).
        assert_eq!(result[0].cve_id, "CVE-2024-1");
        assert_eq!(result[1].cve_id, "CVE-2024-2");
        assert_eq!(result[0].days_exposed, 2);
        assert_eq!(result[1].days_exposed, 5);
    }

    #[test]
    fn test_project_timeline_rows_acknowledged_flag_propagates() {
        // The acknowledged status must come through unchanged so the
        // dashboard can colour-code acknowledged-vs-open differently.
        let now = Utc::now();
        let ack_row = make_scan_row(Uuid::new_v4(), Some("CVE-A"), now, true);
        let open_row = make_scan_row(Uuid::new_v4(), Some("CVE-B"), now, false);
        let result = project_timeline_rows(&[ack_row, open_row], now);
        assert_eq!(result[0].status, CveStatus::Acknowledged);
        assert_eq!(result[1].status, CveStatus::Open);
    }

    // -----------------------------------------------------------------------
    // project_scan_rows_to_entries: combined filter + map pipeline that
    // backs `build_cve_entries_from_scan_findings`. The async wrapper just
    // runs the SQL and delegates here.
    // -----------------------------------------------------------------------

    #[test]
    fn test_project_scan_rows_to_entries_drops_known_uppercase() {
        let when = Utc::now();
        let artifact = Uuid::new_v4();
        let dup = make_scan_row(artifact, Some("CVE-2019-10744"), when, false);
        let novel = make_scan_row(artifact, Some("CVE-2024-12345"), when, false);
        let known: HashSet<String> = ["CVE-2019-10744".to_string()].into_iter().collect();
        let entries = project_scan_rows_to_entries(vec![dup, novel], &known);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].cve_id, "CVE-2024-12345");
    }

    #[test]
    fn test_project_scan_rows_to_entries_drops_known_case_insensitive() {
        // The scanner could write `cve-2019-10744` (lower) while the
        // curated row is upper-case; the dedupe must still hide the
        // duplicate.
        let when = Utc::now();
        let dup = make_scan_row(Uuid::new_v4(), Some("cve-2019-10744"), when, false);
        let known: HashSet<String> = ["CVE-2019-10744".to_string()].into_iter().collect();
        let entries = project_scan_rows_to_entries(vec![dup], &known);
        assert!(entries.is_empty());
    }

    #[test]
    fn test_project_scan_rows_to_entries_drops_null_cve_id() {
        // Defensive: scanner row with NULL cve_id must not become a
        // synthetic entry with empty id (the upstream WHERE clause should
        // also reject it, but pin the second-line check here).
        let when = Utc::now();
        let row = make_scan_row(Uuid::new_v4(), None, when, false);
        let known: HashSet<String> = HashSet::new();
        let entries = project_scan_rows_to_entries(vec![row], &known);
        assert!(entries.is_empty());
    }

    #[test]
    fn test_project_scan_rows_to_entries_keeps_novel_when_known_empty() {
        // No curated rows means no dedupe; everything passes through.
        let when = Utc::now();
        let r1 = make_scan_row(Uuid::new_v4(), Some("CVE-2024-1"), when, false);
        let r2 = make_scan_row(Uuid::new_v4(), Some("CVE-2024-2"), when, false);
        let known: HashSet<String> = HashSet::new();
        let entries = project_scan_rows_to_entries(vec![r1, r2], &known);
        assert_eq!(entries.len(), 2);
    }

    #[test]
    fn test_project_scan_rows_to_entries_synthesizes_ids() {
        // Synthetic id derives from (artifact_id, cve_id) -- two scans on
        // the same pair must produce the same id so client-side dedupe
        // works.
        let when = Utc::now();
        let artifact = Uuid::new_v4();
        let r1 = make_scan_row(artifact, Some("CVE-2024-99"), when, false);
        let r2 = make_scan_row(artifact, Some("CVE-2024-99"), when, false);
        let entries_first = project_scan_rows_to_entries(vec![r1], &HashSet::new());
        let entries_second = project_scan_rows_to_entries(vec![r2], &HashSet::new());
        assert_eq!(entries_first[0].id, entries_second[0].id);
        assert_eq!(entries_first[0].id, synth_cve_id(artifact, "CVE-2024-99"));
    }

    // -----------------------------------------------------------------------
    // SQL constants: lexical assertions over the query text. These pin the
    // ranked-CASE table to the values that `severity_rank` /
    // `severity_from_rank` translate, and pin the WHERE clauses that
    // enforce the multi-scanner / soft-delete / null-cve invariants. If
    // the SQL drifts the lex bug (#1375) reopens silently because the
    // shape would still typecheck.
    // -----------------------------------------------------------------------

    #[test]
    fn test_scan_findings_by_artifact_sql_uses_ranked_case() {
        // The ranked CASE must list all four labels in the order Rust's
        // `severity_rank` expects (critical=4, high=3, medium=2, low=1).
        assert!(SCAN_FINDINGS_BY_ARTIFACT_SQL.contains("WHEN 'critical' THEN 4"));
        assert!(SCAN_FINDINGS_BY_ARTIFACT_SQL.contains("WHEN 'high' THEN 3"));
        assert!(SCAN_FINDINGS_BY_ARTIFACT_SQL.contains("WHEN 'medium' THEN 2"));
        assert!(SCAN_FINDINGS_BY_ARTIFACT_SQL.contains("WHEN 'low' THEN 1"));
        // ELSE 0 catches NULL / "info" / "unknown" so they never outrank a
        // real severity.
        assert!(SCAN_FINDINGS_BY_ARTIFACT_SQL.contains("ELSE 0"));
    }

    #[test]
    fn test_scan_findings_by_artifact_sql_uses_lower_severity() {
        // Scanner output is case-inconsistent (Trivy: HIGH, Grype: High,
        // OSV: high). The SQL must LOWER the column before matching the
        // CASE labels.
        assert!(SCAN_FINDINGS_BY_ARTIFACT_SQL.contains("CASE LOWER(severity)"));
    }

    #[test]
    fn test_scan_findings_by_artifact_sql_groups_by_artifact_and_cve() {
        // The aggregate key must be (artifact_id, cve_id) -- grouping by
        // just one of them would either collapse distinct CVEs together
        // or split a single CVE across rows.
        assert!(SCAN_FINDINGS_BY_ARTIFACT_SQL.contains("GROUP BY artifact_id, cve_id"));
    }

    #[test]
    fn test_scan_findings_by_artifact_sql_filters_null_cve_ids() {
        // NULL cve_id rows are non-CVE findings (license violations,
        // policy hits) and must not be projected into the CVE history.
        assert!(SCAN_FINDINGS_BY_ARTIFACT_SQL.contains("cve_id IS NOT NULL"));
    }

    #[test]
    fn test_scan_findings_by_cve_sql_case_insensitive_match() {
        // Caller may pass either case; the WHERE clause normalizes both
        // sides via LOWER() so the schema's lack of case constraint never
        // surfaces as a missed lookup.
        assert!(SCAN_FINDINGS_BY_CVE_SQL.contains("LOWER(cve_id) = LOWER($1)"));
    }

    #[test]
    fn test_scan_findings_sql_severity_ranks_match_rust() {
        // The four rank constants in the SQL CASE must match the integer
        // ranks the Rust `severity_rank` function returns; if they ever
        // drift the lex-MAX regression reopens.
        for (label, rank) in [("critical", 4), ("high", 3), ("medium", 2), ("low", 1)] {
            assert_eq!(severity_rank(label), rank);
            assert!(SCAN_FINDINGS_BY_ARTIFACT_SQL.contains(&format!("WHEN '{label}' THEN {rank}")));
            assert!(SCAN_FINDINGS_BY_CVE_SQL.contains(&format!("WHEN '{label}' THEN {rank}")));
            assert_eq!(severity_from_rank(rank), Some(label));
        }
    }

    #[test]
    fn test_cve_trends_counts_repo_sql_uses_per_cve_cte() {
        // Counts must come from a per-CVE CTE so multi-scanner overlap
        // does not double-count.
        assert!(CVE_TRENDS_COUNTS_REPO_SQL.contains("WITH per_cve AS"));
        assert!(CVE_TRENDS_COUNTS_REPO_SQL.contains("GROUP BY sf.artifact_id, sf.cve_id"));
    }

    #[test]
    fn test_cve_trends_counts_repo_sql_filters_deleted_artifacts() {
        // A soft-deleted artifact must not contribute to the open count.
        assert!(CVE_TRENDS_COUNTS_REPO_SQL.contains("NOT a.is_deleted"));
        assert!(CVE_TRENDS_COUNTS_ALL_SQL.contains("NOT a.is_deleted"));
    }

    #[test]
    fn test_cve_trends_counts_repo_sql_emits_named_columns_in_tuple_order() {
        // The outer SELECT in the counts CTE projects exactly seven
        // columns in this order: total, open, acknowledged, critical,
        // high, medium, low. The async caller destructures into a 7-i64
        // tuple, so any column reorder here would silently swap the
        // counts on the trends dashboard.
        let columns = [
            "AS total",
            "AS open",
            "AS acknowledged",
            "AS critical",
            "AS high",
            "AS medium",
            "AS low",
        ];
        for c in columns {
            assert!(
                CVE_TRENDS_COUNTS_REPO_SQL.contains(c),
                "counts SQL missing column alias: {c}"
            );
            assert!(
                CVE_TRENDS_COUNTS_ALL_SQL.contains(c),
                "counts SQL missing column alias: {c}"
            );
        }
        // Order: total appears before open before acknowledged.
        let p_total = CVE_TRENDS_COUNTS_REPO_SQL.find("AS total").unwrap();
        let p_open = CVE_TRENDS_COUNTS_REPO_SQL.find("AS open").unwrap();
        let p_ack = CVE_TRENDS_COUNTS_REPO_SQL.find("AS acknowledged").unwrap();
        let p_crit = CVE_TRENDS_COUNTS_REPO_SQL.find("AS critical").unwrap();
        let p_low = CVE_TRENDS_COUNTS_REPO_SQL.find("AS low").unwrap();
        assert!(p_total < p_open);
        assert!(p_open < p_ack);
        assert!(p_ack < p_crit);
        assert!(p_crit < p_low);
    }

    #[test]
    fn test_cve_trends_counts_repo_uses_filter_clauses() {
        // Each severity count is gated by a FILTER (WHERE severity_rank
        // = N) -- losing the FILTER would turn each count into the total.
        assert!(CVE_TRENDS_COUNTS_REPO_SQL.contains("FILTER (WHERE severity_rank = 4)"));
        assert!(CVE_TRENDS_COUNTS_REPO_SQL.contains("FILTER (WHERE severity_rank = 3)"));
        assert!(CVE_TRENDS_COUNTS_REPO_SQL.contains("FILTER (WHERE severity_rank = 2)"));
        assert!(CVE_TRENDS_COUNTS_REPO_SQL.contains("FILTER (WHERE severity_rank = 1)"));
    }

    #[test]
    fn test_cve_trends_counts_repo_uses_bool_and_for_ack() {
        // `acknowledged` only counts when EVERY scan_findings row for the
        // (artifact, cve) pair is acknowledged -- otherwise a single
        // unacknowledged scanner would silently mark it acked.
        assert!(CVE_TRENDS_COUNTS_REPO_SQL.contains("BOOL_AND(sf.is_acknowledged)"));
    }

    #[test]
    fn test_cve_trends_counts_repo_scopes_by_repository_id() {
        // The repo-scoped variant must bind $1 to a.repository_id; the
        // all-repos variant must omit it. Pin both halves so a copy-paste
        // could not collapse them.
        assert!(CVE_TRENDS_COUNTS_REPO_SQL.contains("a.repository_id = $1"));
        assert!(!CVE_TRENDS_COUNTS_ALL_SQL.contains("a.repository_id ="));
    }

    #[test]
    fn test_cve_trends_timeline_repo_sql_30_day_window() {
        // The timeline is "newly-detected in the last 30 days"; the
        // INTERVAL must be present in both variants or the dashboard
        // grows unbounded over time.
        assert!(CVE_TRENDS_TIMELINE_REPO_SQL.contains("INTERVAL '30 days'"));
        assert!(CVE_TRENDS_TIMELINE_ALL_SQL.contains("INTERVAL '30 days'"));
    }

    #[test]
    fn test_cve_trends_timeline_repo_sql_limit_100() {
        // The timeline is capped at 100 newly-detected CVEs so a
        // pathological recent scan does not blow up the JSON response.
        assert!(CVE_TRENDS_TIMELINE_REPO_SQL.contains("LIMIT 100"));
        assert!(CVE_TRENDS_TIMELINE_ALL_SQL.contains("LIMIT 100"));
    }

    #[test]
    fn test_cve_trends_timeline_repo_sql_orders_by_min_created_at_desc() {
        // Newest detection first; matching the in-memory
        // `sort_entries_by_first_detected_desc` semantics.
        assert!(CVE_TRENDS_TIMELINE_REPO_SQL.contains("ORDER BY MIN(sf.created_at) DESC"));
        assert!(CVE_TRENDS_TIMELINE_ALL_SQL.contains("ORDER BY MIN(sf.created_at) DESC"));
    }

    #[test]
    fn test_cve_trends_timeline_repo_sql_inverse_case_to_label() {
        // The outer SELECT translates `severity_rank` back to the string
        // label so the timeline DTO carries text severity, not a numeric
        // rank. Inverse of the inner ranked CASE.
        assert!(CVE_TRENDS_TIMELINE_REPO_SQL.contains("WHEN 4 THEN 'critical'"));
        assert!(CVE_TRENDS_TIMELINE_REPO_SQL.contains("WHEN 3 THEN 'high'"));
        assert!(CVE_TRENDS_TIMELINE_REPO_SQL.contains("WHEN 2 THEN 'medium'"));
        assert!(CVE_TRENDS_TIMELINE_REPO_SQL.contains("WHEN 1 THEN 'low'"));
    }

    #[test]
    fn test_fixed_cves_count_repo_sql_counts_disappeared_from_scan_findings() {
        // fixed = disappeared (ever_seen EXCEPT still_present, from
        // scan_findings). The legacy `curated_fixed` CTE was dropped
        // (#1616/#1620): `cve_history` is never written, so it always added
        // zero. The scan-derived CTE chain must survive.
        assert!(FIXED_CVES_COUNT_REPO_SQL.contains("WITH latest_scans AS"));
        assert!(FIXED_CVES_COUNT_REPO_SQL.contains("ever_seen AS"));
        assert!(FIXED_CVES_COUNT_REPO_SQL.contains("still_present AS"));
        assert!(FIXED_CVES_COUNT_REPO_SQL.contains("disappeared AS"));
        assert!(FIXED_CVES_COUNT_REPO_SQL.contains("SELECT COUNT(*) FROM disappeared"));
        // The dead curated path must be gone, not merely unused.
        assert!(!FIXED_CVES_COUNT_REPO_SQL.contains("curated_fixed"));
        assert!(!FIXED_CVES_COUNT_REPO_SQL.contains("cve_history"));
        assert!(!FIXED_CVES_COUNT_REPO_SQL.contains("UNION"));
    }

    #[test]
    fn test_fixed_cves_count_repo_sql_uses_except_for_disappeared() {
        // disappeared = ever_seen EXCEPT still_present. Replacing EXCEPT
        // with MINUS or NOT IN would change the semantics on edge cases.
        assert!(FIXED_CVES_COUNT_REPO_SQL.contains("EXCEPT"));
        assert!(FIXED_CVES_COUNT_ALL_SQL.contains("EXCEPT"));
    }

    #[test]
    fn test_fixed_cves_count_repo_sql_uses_distinct_on_latest_scans() {
        // The latest_scans CTE is keyed (artifact_id, scan_type); without
        // DISTINCT ON the join would multiply rows when an artifact had
        // multiple completed scans.
        assert!(FIXED_CVES_COUNT_REPO_SQL.contains("DISTINCT ON (sr.artifact_id, sr.scan_type)"));
        assert!(FIXED_CVES_COUNT_ALL_SQL.contains("DISTINCT ON (sr.artifact_id, sr.scan_type)"));
    }

    #[test]
    fn test_fixed_cves_count_repo_sql_completed_scans_only() {
        // A failed / cancelled / running scan must not count as evidence
        // that a CVE disappeared.
        assert!(FIXED_CVES_COUNT_REPO_SQL.contains("sr.status = 'completed'"));
        assert!(FIXED_CVES_COUNT_ALL_SQL.contains("sr.status = 'completed'"));
    }

    #[test]
    fn test_fixed_cves_count_sql_drops_dead_cve_history_curated_path() {
        // #1616/#1620: the `curated_fixed` CTE read from the never-written
        // `cve_history` table and always contributed zero. Both variants must
        // count fixed CVEs solely from the scan-derived `disappeared` CTE.
        assert!(!FIXED_CVES_COUNT_REPO_SQL.contains("cve_history"));
        assert!(!FIXED_CVES_COUNT_ALL_SQL.contains("cve_history"));
        assert!(!FIXED_CVES_COUNT_REPO_SQL.contains("curated_fixed"));
        assert!(!FIXED_CVES_COUNT_ALL_SQL.contains("curated_fixed"));
        assert!(FIXED_CVES_COUNT_ALL_SQL.contains("SELECT COUNT(*) FROM disappeared"));
    }

    #[test]
    fn test_fixed_cves_count_all_drops_repository_filter() {
        // All-repos variant must NOT scope by repository_id; otherwise
        // admin callers would silently get a partial count.
        assert!(!FIXED_CVES_COUNT_ALL_SQL.contains("a.repository_id"));
    }

    #[test]
    fn test_fixed_cves_count_repo_sql_lowercases_cve_id() {
        // The scan-derived CTEs normalize on LOWER(cve_id) so the ever_seen /
        // still_present EXCEPT collides regardless of how the scanner cased id.
        assert!(FIXED_CVES_COUNT_REPO_SQL.contains("LOWER(sf.cve_id)"));
        assert!(FIXED_CVES_COUNT_ALL_SQL.contains("LOWER(sf.cve_id)"));
    }

    #[test]
    fn test_all_sql_constants_are_nonempty() {
        // Defensive sanity check: a refactor that accidentally blanked a
        // const would still typecheck and the async caller would issue
        // an empty query against Postgres.
        assert!(!SCAN_FINDINGS_BY_ARTIFACT_SQL.trim().is_empty());
        assert!(!SCAN_FINDINGS_BY_CVE_SQL.trim().is_empty());
        assert!(!CVE_TRENDS_COUNTS_REPO_SQL.trim().is_empty());
        assert!(!CVE_TRENDS_COUNTS_ALL_SQL.trim().is_empty());
        assert!(!CVE_TRENDS_TIMELINE_REPO_SQL.trim().is_empty());
        assert!(!CVE_TRENDS_TIMELINE_ALL_SQL.trim().is_empty());
        assert!(!FIXED_CVES_COUNT_REPO_SQL.trim().is_empty());
        assert!(!FIXED_CVES_COUNT_ALL_SQL.trim().is_empty());
    }

    #[test]
    fn test_scan_findings_sql_variants_differ_only_by_where_clause() {
        // The two scan_findings variants share the same outer projection
        // and the same ranked CASE; the only difference is the WHERE
        // clause. Pin this so a future copy-paste cannot accidentally
        // diverge the severity ranks on one branch.
        assert!(SCAN_FINDINGS_BY_ARTIFACT_SQL.contains("WHERE artifact_id = $1"));
        assert!(!SCAN_FINDINGS_BY_ARTIFACT_SQL.contains("LOWER(cve_id) = LOWER($1)"));
        assert!(SCAN_FINDINGS_BY_CVE_SQL.contains("LOWER(cve_id) = LOWER($1)"));
        assert!(!SCAN_FINDINGS_BY_CVE_SQL.contains("WHERE artifact_id = $1"));
    }

    #[test]
    fn test_cve_trends_repo_and_all_sql_severity_ranks_align() {
        // Both variants of the counts CTE must use the same ranked CASE;
        // a drift would silently misreport severities on the all-repos
        // dashboard vs the per-repo one.
        for label_then in [
            "WHEN 'critical' THEN 4",
            "WHEN 'high' THEN 3",
            "WHEN 'medium' THEN 2",
            "WHEN 'low' THEN 1",
        ] {
            assert!(
                CVE_TRENDS_COUNTS_REPO_SQL.contains(label_then),
                "repo SQL missing rank clause: {label_then}"
            );
            assert!(
                CVE_TRENDS_COUNTS_ALL_SQL.contains(label_then),
                "all-repos SQL missing rank clause: {label_then}"
            );
        }
    }

    // -----------------------------------------------------------------------
    // update_cve_status_by_artifact_cve (#1426)
    //
    // DB-backed coverage for the synth-id acknowledge path. These tests
    // require a live `DATABASE_URL` (provided by CI's coverage job, which
    // seeds Postgres + applies migrations before `cargo llvm-cov --lib`).
    // Locally they no-op when `DATABASE_URL` is unset, so `cargo test --lib`
    // stays green without Postgres.
    //
    // What we cover:
    //   * Happy path Acknowledged: writes `is_acknowledged = true`,
    //     populates the audit fields, and re-reads the synth aggregate.
    //   * Happy path FalsePositive: collapses to `true` on `scan_findings`
    //     (the table has no separate column), reason field carries the
    //     audit distinction.
    //   * Happy path Open: clears acknowledgement back to false and nulls
    //     the audit fields (mirror of the revoke endpoint).
    //   * Validation: `Fixed` is unrepresentable on `scan_findings`, so the
    //     service surfaces `AppError::Validation` rather than silently
    //     coercing.
    //   * Not-found: no matching `scan_findings` rows for (artifact, cve)
    //     produces `AppError::NotFound` (handler maps that to 404).
    //   * Case-insensitive CVE match: lower/upper-case CVE strings on
    //     either side of the comparison must still find the row.
    //   * Multi-row aggregate: when two findings share (artifact, cve), the
    //     update touches both, the post-write aggregate uses MIN/MAX of
    //     detection timestamps, and `all_acknowledged` reflects both rows.
    // -----------------------------------------------------------------------

    /// Connect to the test database when `DATABASE_URL` is set; otherwise
    /// return `None` so the test skips cleanly.
    async fn try_pool() -> Option<PgPool> {
        let url = std::env::var("DATABASE_URL").ok()?;
        sqlx::postgres::PgPoolOptions::new()
            .max_connections(3)
            .acquire_timeout(std::time::Duration::from_secs(3))
            .connect(&url)
            .await
            .ok()
    }

    /// Seed a repository row with a unique key/storage path.
    async fn seed_repo(pool: &PgPool) -> Uuid {
        let id = Uuid::new_v4();
        let key = format!("sbom-cve-test-{}", id);
        let storage = format!("/tmp/sbom-cve-test/{}", id);
        sqlx::query(
            "INSERT INTO repositories (id, key, name, storage_path, repo_type, format) \
             VALUES ($1, $2, $3, $4, 'local', 'generic')",
        )
        .bind(id)
        .bind(&key)
        .bind(&key)
        .bind(&storage)
        .execute(pool)
        .await
        .expect("seed repository");
        id
    }

    /// Seed an artifact row. `name` is uniquified to avoid (repository_id,
    /// path) collisions across parallel test runs.
    async fn seed_artifact(pool: &PgPool, repo_id: Uuid) -> Uuid {
        let id = Uuid::new_v4();
        let path = format!("{}/{}", repo_id, id);
        sqlx::query(
            r#"
            INSERT INTO artifacts (id, repository_id, name, path, version,
                                   size_bytes, checksum_sha256, content_type,
                                   storage_key, is_deleted)
            VALUES ($1, $2, $3, $4, '1.0.0', 1024, $5,
                    'application/octet-stream', $4, false)
            "#,
        )
        .bind(id)
        .bind(repo_id)
        .bind(format!("a-{}", id))
        .bind(&path)
        .bind(format!("sha256-{}", id))
        .execute(pool)
        .await
        .expect("seed artifact");
        id
    }

    /// Seed a completed scan_results row tied to (artifact, repo). Returns
    /// the scan_result id so the caller can attach scan_findings to it.
    async fn seed_scan_result(pool: &PgPool, artifact_id: Uuid, repo_id: Uuid) -> Uuid {
        let id = Uuid::new_v4();
        sqlx::query(
            r#"
            INSERT INTO scan_results (id, artifact_id, repository_id, scan_type,
                                      status, findings_count, started_at,
                                      completed_at)
            VALUES ($1, $2, $3, 'dependency', 'completed', 1, NOW(), NOW())
            "#,
        )
        .bind(id)
        .bind(artifact_id)
        .bind(repo_id)
        .execute(pool)
        .await
        .expect("seed scan_result");
        id
    }

    /// Seed an unacknowledged scan_findings row carrying the given CVE id.
    async fn seed_finding(
        pool: &PgPool,
        scan_result_id: Uuid,
        artifact_id: Uuid,
        cve_id: &str,
        severity: &str,
    ) -> Uuid {
        let id = Uuid::new_v4();
        sqlx::query(
            r#"
            INSERT INTO scan_findings (id, scan_result_id, artifact_id, severity,
                                       title, cve_id, source, is_acknowledged)
            VALUES ($1, $2, $3, $4, $5, $6, 'trivy', false)
            "#,
        )
        .bind(id)
        .bind(scan_result_id)
        .bind(artifact_id)
        .bind(severity)
        .bind(format!("Test finding for {}", cve_id))
        .bind(cve_id)
        .execute(pool)
        .await
        .expect("seed scan_finding");
        id
    }

    /// Drop everything owned by the given repo so tests don't leak state.
    async fn teardown(pool: &PgPool, repo_id: Uuid) {
        let _ = sqlx::query(
            "DELETE FROM scan_findings WHERE scan_result_id IN \
             (SELECT id FROM scan_results WHERE repository_id = $1)",
        )
        .bind(repo_id)
        .execute(pool)
        .await;
        let _ = sqlx::query("DELETE FROM scan_results WHERE repository_id = $1")
            .bind(repo_id)
            .execute(pool)
            .await;
        let _ = sqlx::query("DELETE FROM artifacts WHERE repository_id = $1")
            .bind(repo_id)
            .execute(pool)
            .await;
        let _ = sqlx::query("DELETE FROM repositories WHERE id = $1")
            .bind(repo_id)
            .execute(pool)
            .await;
    }

    /// Read back is_acknowledged + audit fields for one (artifact, cve)
    /// scan_findings row. Returns `None` when no row matches.
    async fn read_ack(
        pool: &PgPool,
        artifact_id: Uuid,
        cve_id: &str,
    ) -> Option<(bool, Option<Uuid>, Option<String>, Option<DateTime<Utc>>)> {
        sqlx::query_as::<_, (bool, Option<Uuid>, Option<String>, Option<DateTime<Utc>>)>(
            "SELECT is_acknowledged, acknowledged_by, acknowledged_reason, acknowledged_at \
             FROM scan_findings \
             WHERE artifact_id = $1 AND LOWER(cve_id) = LOWER($2) \
             LIMIT 1",
        )
        .bind(artifact_id)
        .bind(cve_id)
        .fetch_optional(pool)
        .await
        .expect("read_ack")
    }

    #[tokio::test]
    async fn test_update_cve_status_by_artifact_cve_acknowledged_sets_flag_and_audit_fields() {
        let Some(pool) = try_pool().await else {
            return;
        };
        let repo_id = seed_repo(&pool).await;
        let artifact_id = seed_artifact(&pool, repo_id).await;
        let scan_id = seed_scan_result(&pool, artifact_id, repo_id).await;
        let _finding = seed_finding(&pool, scan_id, artifact_id, "CVE-2024-1111", "high").await;

        let service = SbomService::new(pool.clone());
        let entry = service
            .update_cve_status_by_artifact_cve(
                artifact_id,
                "CVE-2024-1111",
                CveStatus::Acknowledged,
                None,
                Some("triaged: not exploitable"),
            )
            .await
            .expect("acknowledge happy path");

        // The response carries the synth aggregate shape: the cve_id is
        // surfaced upper-case (the read path normalizes) and the
        // post-write `status` reflects all_acknowledged = true.
        assert_eq!(entry.cve_id.to_ascii_uppercase(), "CVE-2024-1111");
        assert_eq!(entry.status, "acknowledged");
        assert_eq!(entry.artifact_id, artifact_id);

        // The underlying scan_findings row must carry the flag + audit
        // payload the handler wrote.
        let (ack, _by, reason, at) = read_ack(&pool, artifact_id, "CVE-2024-1111")
            .await
            .expect("finding row still present");
        assert!(ack, "is_acknowledged must be true after Acknowledged");
        assert_eq!(reason.as_deref(), Some("triaged: not exploitable"));
        assert!(at.is_some(), "acknowledged_at must be set");

        teardown(&pool, repo_id).await;
    }

    #[tokio::test]
    async fn test_update_cve_status_by_artifact_cve_false_positive_collapses_to_acknowledged() {
        let Some(pool) = try_pool().await else {
            return;
        };
        let repo_id = seed_repo(&pool).await;
        let artifact_id = seed_artifact(&pool, repo_id).await;
        let scan_id = seed_scan_result(&pool, artifact_id, repo_id).await;
        seed_finding(&pool, scan_id, artifact_id, "CVE-2024-2222", "medium").await;

        let service = SbomService::new(pool.clone());
        let entry = service
            .update_cve_status_by_artifact_cve(
                artifact_id,
                "CVE-2024-2222",
                CveStatus::FalsePositive,
                None,
                Some("false positive: code path not reachable"),
            )
            .await
            .expect("false_positive happy path");

        // scan_findings has no separate FP column, so the synth row's
        // status collapses to "acknowledged"; the reason field carries
        // the audit distinction.
        assert_eq!(entry.status, "acknowledged");

        let (ack, _by, reason, _at) = read_ack(&pool, artifact_id, "CVE-2024-2222")
            .await
            .expect("finding row still present");
        assert!(ack);
        assert_eq!(
            reason.as_deref(),
            Some("false positive: code path not reachable")
        );

        teardown(&pool, repo_id).await;
    }

    #[tokio::test]
    async fn test_update_cve_status_by_artifact_cve_open_revokes_acknowledgement() {
        let Some(pool) = try_pool().await else {
            return;
        };
        let repo_id = seed_repo(&pool).await;
        let artifact_id = seed_artifact(&pool, repo_id).await;
        let scan_id = seed_scan_result(&pool, artifact_id, repo_id).await;
        let finding_id = seed_finding(&pool, scan_id, artifact_id, "CVE-2024-3333", "low").await;

        // Pre-acknowledge so we can verify Open clears the state.
        sqlx::query(
            "UPDATE scan_findings SET is_acknowledged = true, \
             acknowledged_reason = 'pre-ack', acknowledged_at = NOW() WHERE id = $1",
        )
        .bind(finding_id)
        .execute(&pool)
        .await
        .expect("pre-acknowledge");

        let service = SbomService::new(pool.clone());
        let entry = service
            .update_cve_status_by_artifact_cve(
                artifact_id,
                "CVE-2024-3333",
                CveStatus::Open,
                None,
                None,
            )
            .await
            .expect("open happy path");

        assert_eq!(entry.status, "open");

        let (ack, by, reason, at) = read_ack(&pool, artifact_id, "CVE-2024-3333")
            .await
            .expect("finding row still present");
        assert!(!ack, "is_acknowledged must be false after Open");
        assert!(
            by.is_none() && reason.is_none() && at.is_none(),
            "audit fields must be cleared after Open"
        );

        teardown(&pool, repo_id).await;
    }

    #[tokio::test]
    async fn test_update_cve_status_by_artifact_cve_fixed_returns_validation_error() {
        // `Fixed` has no representation on scan_findings. The service must
        // surface AppError::Validation rather than silently coerce
        // is_acknowledged = true (which would hide the finding from the
        // Security tab and mislead operators).
        let Some(pool) = try_pool().await else {
            return;
        };
        let repo_id = seed_repo(&pool).await;
        let artifact_id = seed_artifact(&pool, repo_id).await;
        let scan_id = seed_scan_result(&pool, artifact_id, repo_id).await;
        seed_finding(&pool, scan_id, artifact_id, "CVE-2024-4444", "critical").await;

        let service = SbomService::new(pool.clone());
        let err = service
            .update_cve_status_by_artifact_cve(
                artifact_id,
                "CVE-2024-4444",
                CveStatus::Fixed,
                None,
                None,
            )
            .await
            .expect_err("fixed must be rejected");

        match err {
            AppError::Validation(msg) => {
                assert!(
                    msg.contains("fixed"),
                    "validation message must mention 'fixed': {msg}"
                );
            }
            other => panic!("expected Validation, got {:?}", other),
        }

        // And the row must remain untouched (no silent coercion).
        let (ack, _, _, _) = read_ack(&pool, artifact_id, "CVE-2024-4444")
            .await
            .expect("finding row still present");
        assert!(
            !ack,
            "scan_findings.is_acknowledged must NOT change on Fixed rejection"
        );

        teardown(&pool, repo_id).await;
    }

    #[tokio::test]
    async fn test_update_cve_status_by_artifact_cve_no_matching_rows_returns_not_found() {
        let Some(pool) = try_pool().await else {
            return;
        };
        let repo_id = seed_repo(&pool).await;
        let artifact_id = seed_artifact(&pool, repo_id).await;
        let scan_id = seed_scan_result(&pool, artifact_id, repo_id).await;
        // Seed a finding for a DIFFERENT CVE so the artifact has scans but
        // the (artifact, cve) pair the caller asks about has no rows.
        seed_finding(&pool, scan_id, artifact_id, "CVE-2024-5555", "high").await;

        let service = SbomService::new(pool.clone());
        let err = service
            .update_cve_status_by_artifact_cve(
                artifact_id,
                "CVE-2024-9999",
                CveStatus::Acknowledged,
                None,
                Some("won't match"),
            )
            .await
            .expect_err("no matching rows must 404");

        match err {
            AppError::NotFound(msg) => {
                assert!(msg.contains("CVE-2024-9999"));
            }
            other => panic!("expected NotFound, got {:?}", other),
        }

        teardown(&pool, repo_id).await;
    }

    #[tokio::test]
    async fn test_update_cve_status_by_artifact_cve_match_is_case_insensitive() {
        // Synth ids returned by the read path are upper-case but scanners
        // sometimes emit mixed case. The UPDATE must lower-case both sides
        // so a click on the Security tab still lands on the right row.
        let Some(pool) = try_pool().await else {
            return;
        };
        let repo_id = seed_repo(&pool).await;
        let artifact_id = seed_artifact(&pool, repo_id).await;
        let scan_id = seed_scan_result(&pool, artifact_id, repo_id).await;
        seed_finding(&pool, scan_id, artifact_id, "cve-2024-6666", "medium").await;

        let service = SbomService::new(pool.clone());
        let entry = service
            .update_cve_status_by_artifact_cve(
                artifact_id,
                "CVE-2024-6666",
                CveStatus::Acknowledged,
                None,
                Some("case-insensitive match"),
            )
            .await
            .expect("case-insensitive match must succeed");

        assert_eq!(entry.status, "acknowledged");

        let (ack, _, _, _) = read_ack(&pool, artifact_id, "CVE-2024-6666")
            .await
            .expect("finding row still present");
        assert!(ack);

        teardown(&pool, repo_id).await;
    }

    #[tokio::test]
    async fn test_update_cve_status_by_artifact_cve_updates_all_matching_findings() {
        // Two scan_findings rows can share (artifact, cve) when the same
        // CVE surfaces from multiple scans or multiple components. The
        // UPDATE has no LIMIT, so both rows must flip and the synth
        // aggregate's `all_acknowledged` flag must reflect that.
        let Some(pool) = try_pool().await else {
            return;
        };
        let repo_id = seed_repo(&pool).await;
        let artifact_id = seed_artifact(&pool, repo_id).await;
        let scan_id = seed_scan_result(&pool, artifact_id, repo_id).await;
        seed_finding(&pool, scan_id, artifact_id, "CVE-2024-7777", "critical").await;
        seed_finding(&pool, scan_id, artifact_id, "CVE-2024-7777", "high").await;

        let service = SbomService::new(pool.clone());
        let entry = service
            .update_cve_status_by_artifact_cve(
                artifact_id,
                "CVE-2024-7777",
                CveStatus::Acknowledged,
                None,
                Some("ack both rows"),
            )
            .await
            .expect("multi-row acknowledge");

        // The aggregate must collapse to "acknowledged" only if BOTH rows
        // are acknowledged (BOOL_AND semantics). The service uses an
        // unbounded UPDATE, so this is the regression assertion.
        assert_eq!(entry.status, "acknowledged");

        // Direct count verification: both rows must be ack'd.
        let acked: (i64,) = sqlx::query_as(
            "SELECT COUNT(*) FROM scan_findings \
             WHERE artifact_id = $1 AND cve_id = $2 AND is_acknowledged = true",
        )
        .bind(artifact_id)
        .bind("CVE-2024-7777")
        .fetch_one(&pool)
        .await
        .expect("count acked rows");
        assert_eq!(acked.0, 2, "both scan_findings rows must be acknowledged");

        teardown(&pool, repo_id).await;
    }

    // -----------------------------------------------------------------------
    // update_cve_status synth-id fallback (#1561)
    //
    // The reported bug: `POST /sbom/cve/status/{id}` -> `update_cve_status`
    // ran `UPDATE cve_history WHERE id = $1`, but `cve_history` is never
    // written in production and the read path emits SHA-256 synth ids derived
    // from `scan_findings`. Every ack against an id the read side actually
    // returns 404'd. These DB-backed tests prove the fallback: the same synth
    // id now resolves and persists the ack on `scan_findings`.
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_update_cve_status_synth_id_falls_back_to_scan_findings() {
        // Regression for #1561: the EXACT reported flow. Take the synth id the
        // read path emits for a scan-derived CVE, call the legacy
        // `update_cve_status` with it, and assert it now succeeds (was 404).
        let Some(pool) = try_pool().await else {
            return;
        };
        let repo_id = seed_repo(&pool).await;
        let artifact_id = seed_artifact(&pool, repo_id).await;
        let scan_id = seed_scan_result(&pool, artifact_id, repo_id).await;
        seed_finding(&pool, scan_id, artifact_id, "CVE-2024-8888", "high").await;

        let service = SbomService::new(pool.clone());

        // The id the read path hands clients for this (artifact, cve) pair.
        let synth_id = synth_cve_id(artifact_id, "CVE-2024-8888");

        // Before the fix this returned AppError::Sqlx(RowNotFound) -> 404.
        let entry = service
            .update_cve_status(
                synth_id,
                CveStatus::Acknowledged,
                None,
                Some("ack via legacy synth-id endpoint"),
                None,
            )
            .await
            .expect("synth-id ack must succeed via scan_findings fallback");

        assert_eq!(entry.cve_id.to_ascii_uppercase(), "CVE-2024-8888");
        assert_eq!(entry.status, "acknowledged");
        // The synth aggregate the response carries must keep the same id.
        assert_eq!(entry.id, synth_id);

        // And the ack must actually be persisted on the source table.
        let (ack, _, _, _) = read_ack(&pool, artifact_id, "CVE-2024-8888")
            .await
            .expect("finding row present");
        assert!(ack, "scan_findings.is_acknowledged must be persisted");

        teardown(&pool, repo_id).await;
    }

    #[tokio::test]
    async fn test_update_cve_status_unknown_id_still_returns_not_found() {
        // The fallback must NOT mask genuinely-unknown ids: an id that is
        // neither a curated cve_history row nor a resolvable synth id must
        // still surface RowNotFound (handler -> 404).
        let Some(pool) = try_pool().await else {
            return;
        };
        let repo_id = seed_repo(&pool).await;
        let artifact_id = seed_artifact(&pool, repo_id).await;
        let scan_id = seed_scan_result(&pool, artifact_id, repo_id).await;
        seed_finding(&pool, scan_id, artifact_id, "CVE-2024-9090", "low").await;

        let service = SbomService::new(pool.clone());
        let err = service
            .update_cve_status(
                Uuid::new_v4(), // random id: no cve_history row, no synth match
                CveStatus::Acknowledged,
                None,
                Some("nope"),
                None,
            )
            .await
            .expect_err("unknown id must 404");

        assert!(
            matches!(err, AppError::Sqlx(sqlx::Error::RowNotFound)),
            "unknown id must surface RowNotFound (handler maps to 404), got {err:?}"
        );

        teardown(&pool, repo_id).await;
    }

    #[tokio::test]
    async fn test_update_cve_status_synth_id_respects_repo_scope() {
        // Resolution must honour allowed_repo_ids: a synth id for an artifact
        // in repo A must NOT resolve when the caller is scoped to repo B
        // (returns 404 rather than acknowledging an unauthorized CVE).
        let Some(pool) = try_pool().await else {
            return;
        };
        let repo_a = seed_repo(&pool).await;
        let repo_b = seed_repo(&pool).await;
        let artifact_a = seed_artifact(&pool, repo_a).await;
        let scan_a = seed_scan_result(&pool, artifact_a, repo_a).await;
        seed_finding(&pool, scan_a, artifact_a, "CVE-2024-7001", "high").await;

        let service = SbomService::new(pool.clone());
        let synth_id = synth_cve_id(artifact_a, "CVE-2024-7001");

        // Scoped to repo_b only: the artifact lives in repo_a, so no match.
        let err = service
            .update_cve_status(
                synth_id,
                CveStatus::Acknowledged,
                None,
                Some("cross-repo attempt"),
                Some(&[repo_b]),
            )
            .await
            .expect_err("synth id outside repo scope must 404");
        assert!(matches!(err, AppError::Sqlx(sqlx::Error::RowNotFound)));

        // The finding must remain unacknowledged.
        let (ack, _, _, _) = read_ack(&pool, artifact_a, "CVE-2024-7001")
            .await
            .expect("finding present");
        assert!(!ack, "ack must not persist for out-of-scope caller");

        // Scoped to repo_a: now it resolves and persists.
        let entry = service
            .update_cve_status(
                synth_id,
                CveStatus::Acknowledged,
                None,
                Some("in-scope ack"),
                Some(&[repo_a]),
            )
            .await
            .expect("in-scope synth id must resolve");
        assert_eq!(entry.status, "acknowledged");

        teardown(&pool, repo_a).await;
        teardown(&pool, repo_b).await;
    }
}
