//! Security scanning and policy management handlers.

use axum::{
    extract::{Extension, Path, Query, State},
    routing::{delete, get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use utoipa::{IntoParams, OpenApi, ToSchema};
use uuid::Uuid;

use crate::api::handlers::artifacts::check_artifact_visibility;
use crate::api::handlers::repositories::{
    require_repo_admin, require_repo_write_access, require_visible,
};
use crate::api::middleware::auth::AuthExtension;
use crate::api::SharedState;
use crate::error::{AppError, Result};
use crate::models::security::ScanResult;
use crate::services::policy_service::PolicyService;
use crate::services::proxy_catalog;
use crate::services::proxy_scan_service::ProxyScanService;
use crate::services::repository_service::RepositoryService;
use crate::services::scan_config_service::{ScanConfigService, UpsertScanConfigRequest};
use crate::services::scan_result_service::ScanResultService;

/// Canonical 404 body for the scan-by-id read routes. Both "this scan id does
/// not exist" (from `ScanResultService::get_scan`) and "the scan exists but the
/// caller may not see its repository" (from `check_artifact_visibility`) must
/// return this SAME message so the response is not a boolean existence oracle
/// for hidden scans. Kept identical to the string `get_scan` emits for a truly
/// absent id. (#2439 residual.)
const SCAN_NOT_FOUND_MSG: &str = "Scan result not found";

/// Normalize a cross-repo-visibility `NotFound` (which carries an
/// artifact-flavored message) to the canonical scan-not-found body, so a
/// no-access scan is indistinguishable from an absent one.
fn unify_scan_not_found(e: AppError) -> AppError {
    match e {
        AppError::NotFound(_) => AppError::NotFound(SCAN_NOT_FOUND_MSG.to_string()),
        other => other,
    }
}

/// Create security routes
pub fn router() -> Router<SharedState> {
    Router::new()
        // Dashboard
        .route("/dashboard", get(get_dashboard))
        // Scores
        .route("/scores", get(get_all_scores))
        // Scan configs
        .route("/configs", get(list_scan_configs))
        // Scan operations
        .route("/scan", post(trigger_scan))
        .route("/scans", get(list_scans))
        .route("/scans/:id", get(get_scan))
        .route("/scans/:id/findings", get(list_findings))
        .route("/artifacts/:artifact_id/scans", get(list_artifact_scans))
        // Finding acknowledgment
        .route("/findings/:id/acknowledge", post(acknowledge_finding))
        .route("/findings/:id/acknowledge", delete(revoke_acknowledgment))
        // Policy CRUD
        .route("/policies", get(list_policies).post(create_policy))
        .route(
            "/policies/:id",
            get(get_policy).put(update_policy).delete(delete_policy),
        )
}

/// Repository-scoped security routes (nested under /repositories/:key)
pub fn repo_security_router() -> Router<SharedState> {
    Router::new()
        .route(
            "/:key/security",
            get(get_repo_security).put(update_repo_security),
        )
        .route("/:key/security/scans", get(list_repo_scans))
        .route("/:key/security/proxy-scans", get(get_repo_proxy_scans))
        .route(
            "/:key/security/proxy-scans/rescan",
            post(rescan_proxy_cached_path),
        )
}

// ---------------------------------------------------------------------------
// Request / Response types
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize, ToSchema)]
pub struct DashboardResponse {
    pub repos_with_scanning: i64,
    pub total_scans: i64,
    pub total_findings: i64,
    pub critical_findings: i64,
    pub high_findings: i64,
    pub policy_violations_blocked: i64,
    pub repos_grade_a: i64,
    pub repos_grade_f: i64,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct ScoreResponse {
    pub id: Uuid,
    pub repository_id: Uuid,
    pub score: i32,
    pub grade: String,
    pub total_findings: i32,
    pub critical_count: i32,
    pub high_count: i32,
    pub medium_count: i32,
    pub low_count: i32,
    pub acknowledged_count: i32,
    pub last_scan_at: Option<chrono::DateTime<chrono::Utc>>,
    pub calculated_at: chrono::DateTime<chrono::Utc>,
    /// True when the latest applicable scan for this repo errored (#2167).
    /// The `grade` is floored to `F` while this holds, so clients and the
    /// release-gate must treat the repo as NOT clean regardless of the numeric
    /// finding counts. Cleared automatically once a `completed` rescan
    /// supersedes the failed scan.
    pub has_failed_scan: bool,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct TriggerScanRequest {
    pub artifact_id: Option<Uuid>,
    pub repository_id: Option<Uuid>,
    /// Skip the hash-based scan dedup short-circuit when running this scan.
    ///
    /// Defaults to `false`. Normal trigger calls dedup against prior
    /// completed scans for the same checksum + scan_type so a freshly
    /// uploaded byte-identical artifact reuses the existing result instead
    /// of re-running the scanner. When `true`, that dedup is skipped: the
    /// scanner runs against the bytes again and writes a fresh
    /// `scan_results` row. Use this to recover from a silently-broken
    /// prior scan (e.g. an extraction bug producing a completed,
    /// zero-finding row that masks the real findings until the dedup TTL
    /// expires; see #1469). Costs an extra scan run, so leave it unset
    /// for routine trigger calls.
    ///
    /// **Admin only.** Setting this to `true` bypasses the dedup short-
    /// circuit and fans out unbounded scanner work per artifact. The
    /// `trigger_scan` handler rejects this field with 403 for non-admin
    /// callers, since a non-admin force-rescan path would be a DoS
    /// amplifier (the pre-existing `force=true` was naturally rate-limited
    /// by dedup; `bypass_dedup` removes that safety).
    #[serde(default)]
    pub bypass_dedup: Option<bool>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct TriggerScanResponse {
    pub message: String,
    pub artifacts_queued: u32,
    /// Scan result IDs created (one per active scanner) when triggering an
    /// artifact-level scan. Empty for repository-level scans (where the
    /// per-artifact rows are created inside the spawned worker) and for
    /// artifact-level triggers when no scanners are configured.
    ///
    /// Clients (and the release-gate test in artifact-keeper-test#58) should
    /// poll `GET /api/v1/security/scans/{id}` against these IDs rather than
    /// guessing the most-recent scan from `GET /artifacts/{id}/scans`.
    #[serde(default)]
    pub scan_result_ids: Vec<Uuid>,
}

#[derive(Debug, Default, Deserialize, IntoParams)]
pub struct ListScansQuery {
    pub repository_id: Option<Uuid>,
    pub artifact_id: Option<Uuid>,
    pub status: Option<String>,
    pub page: Option<i64>,
    pub per_page: Option<i64>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct ScanListResponse {
    pub items: Vec<ScanResponse>,
    pub total: i64,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct ScanResponse {
    pub id: Uuid,
    pub artifact_id: Uuid,
    pub artifact_name: Option<String>,
    pub artifact_version: Option<String>,
    pub repository_id: Uuid,
    pub scan_type: String,
    pub status: String,
    pub findings_count: i32,
    pub critical_count: i32,
    pub high_count: i32,
    pub medium_count: i32,
    pub low_count: i32,
    pub info_count: i32,
    pub scanner_version: Option<String>,
    pub error_message: Option<String>,
    pub started_at: Option<chrono::DateTime<chrono::Utc>>,
    pub completed_at: Option<chrono::DateTime<chrono::Utc>>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    /// True when the row was synthesized by the dedup path (`copy_scan_results`)
    /// because a prior scan with the same `(checksum_sha256, scan_type)` pair
    /// already existed within the dedup TTL. No scanner was actually invoked
    /// for this row; counts and findings were copied from `source_scan_id`.
    pub is_reused: bool,
    /// When `is_reused` is true, the `id` of the source scan whose results
    /// were copied. Useful for distinguishing "fresh scan" from "deduped
    /// satisfaction" in release-gate provenance checks. None for original
    /// (non-reused) scans.
    pub source_scan_id: Option<Uuid>,
    /// #2471: number of `not_applicable` scanner rows folded into this row.
    /// `Some(n)` marks a synthetic *summary* row that collapses `n` redundant
    /// "this scanner does not apply" results (e.g. the image-family scanners
    /// `filesystem`/`incus`/`openscap` all declining on a Docker image) into a
    /// single muted "not applicable to this artifact" indication, so the UI
    /// stops rendering N rows that read as N failures. `None` for every real
    /// (non-collapsed) scan row. Omitted from the wire when `None`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub collapsed_not_applicable_count: Option<i32>,
    /// #2471: the individual `scan_type` values folded into a summary row,
    /// sorted and de-duplicated (e.g. `["filesystem","incus","openscap"]`).
    /// Present only on a synthetic summary row (alongside
    /// `collapsed_not_applicable_count`); `None` / omitted otherwise.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub collapsed_scan_types: Option<Vec<String>>,
}

// ---------------------------------------------------------------------------
// Model-to-response conversions
// ---------------------------------------------------------------------------

impl ScanResponse {
    fn from_scan(
        s: ScanResult,
        artifact_name: Option<String>,
        artifact_version: Option<String>,
    ) -> Self {
        // #1373 / B13: a reused row (cross-artifact dedup) is a thin pointer at
        // a source scan that holds the real findings. Report the SOURCE scan id
        // as this row's `id` so that two byte-identical artifacts surface the
        // SAME logical scan_id to clients. The release-gate `scan-dedup-checksum`
        // suite asserts exactly this: triggering a scan on a byte-identical
        // second artifact must resolve to the same scan_id as the first. The
        // row's own (placeholder) id is internal bookkeeping; clients that need
        // the findings hit `GET /security/scans/{id}` which works against the
        // source id because the findings live there. `source_scan_id` is still
        // exposed verbatim below for provenance.
        let reported_id = match (s.is_reused, s.source_scan_id) {
            (true, Some(source_id)) => source_id,
            _ => s.id,
        };
        Self {
            id: reported_id,
            artifact_id: s.artifact_id,
            artifact_name,
            artifact_version,
            repository_id: s.repository_id,
            scan_type: s.scan_type,
            status: s.status,
            findings_count: s.findings_count,
            critical_count: s.critical_count,
            high_count: s.high_count,
            medium_count: s.medium_count,
            low_count: s.low_count,
            info_count: s.info_count,
            scanner_version: s.scanner_version,
            error_message: s.error_message,
            started_at: s.started_at,
            completed_at: s.completed_at,
            created_at: s.created_at,
            is_reused: s.is_reused,
            source_scan_id: s.source_scan_id,
            collapsed_not_applicable_count: None,
            collapsed_scan_types: None,
        }
    }
}

/// #2471: collapse redundant `not_applicable` scan rows into one summary row
/// per artifact.
///
/// When an artifact is offered to several image-family scanners that decline to
/// run (`filesystem`, `incus`, `openscap`, ... all returning the dedicated
/// `not_applicable` status from #1470), the raw scan list carries one
/// `not_applicable` row per scanner. Operators misread these as N separate
/// failures. This folds every `not_applicable` row belonging to the same
/// artifact into a single synthetic summary row that records how many scanners
/// declined (`collapsed_not_applicable_count`) and which `scan_type`s they were
/// (`collapsed_scan_types`), so the UI can render one muted "not applicable to
/// this artifact" indication instead of N ❌-looking rows.
///
/// Only groups of **two or more** `not_applicable` rows are collapsed — a lone
/// `not_applicable` row is not redundant and passes through untouched. Every
/// non-`not_applicable` row (completed / running / failed / findings) passes
/// through verbatim. Relative ordering is preserved: the summary row takes the
/// position of the artifact's *first* (most-recent, since the query is
/// `created_at DESC`) collapsed row, and inherits that row's `id` so the UI can
/// still drill into a representative scanner result.
fn collapse_not_applicable_rows(items: Vec<ScanResponse>) -> Vec<ScanResponse> {
    const NOT_APPLICABLE: &str = "not_applicable";

    // Count not_applicable rows per artifact so we know which groups qualify.
    let mut na_per_artifact: std::collections::HashMap<Uuid, usize> =
        std::collections::HashMap::new();
    for item in &items {
        if item.status == NOT_APPLICABLE {
            *na_per_artifact.entry(item.artifact_id).or_insert(0) += 1;
        }
    }

    let mut out: Vec<ScanResponse> = Vec::with_capacity(items.len());
    // Track which artifacts have already had their summary row emitted.
    let mut summarized: std::collections::HashSet<Uuid> = std::collections::HashSet::new();

    for item in items {
        let collapses = item.status == NOT_APPLICABLE
            && na_per_artifact.get(&item.artifact_id).copied().unwrap_or(0) >= 2;

        if !collapses {
            out.push(item);
            continue;
        }

        if summarized.contains(&item.artifact_id) {
            // A later row of an already-summarized group: fold its scan_type in.
            if let Some(summary) = out
                .iter_mut()
                .find(|r| r.artifact_id == item.artifact_id && r.collapsed_scan_types.is_some())
            {
                if let Some(types) = summary.collapsed_scan_types.as_mut() {
                    types.push(item.scan_type.clone());
                    types.sort();
                    types.dedup();
                    summary.collapsed_not_applicable_count = Some(types.len() as i32);
                }
            }
            continue;
        }

        // First collapsed row for this artifact: turn it into the summary row.
        summarized.insert(item.artifact_id);
        let mut summary = item;
        summary.collapsed_scan_types = Some(vec![summary.scan_type.clone()]);
        summary.scan_type = NOT_APPLICABLE.to_string();
        summary.collapsed_not_applicable_count = Some(1);
        summary.error_message = Some("Not applicable to this artifact".to_string());
        out.push(summary);
    }

    out
}

impl From<crate::models::security::ScanFinding> for FindingResponse {
    fn from(f: crate::models::security::ScanFinding) -> Self {
        Self {
            id: f.id,
            scan_result_id: f.scan_result_id,
            artifact_id: f.artifact_id,
            severity: f.severity,
            title: f.title,
            description: f.description,
            cve_id: f.cve_id,
            affected_component: f.affected_component,
            affected_version: f.affected_version,
            fixed_version: f.fixed_version,
            source: f.source,
            source_url: f.source_url,
            is_acknowledged: f.is_acknowledged,
            acknowledged_by: f.acknowledged_by,
            acknowledged_reason: f.acknowledged_reason,
            acknowledged_at: f.acknowledged_at,
            created_at: f.created_at,
        }
    }
}

impl From<crate::models::security::ScanPolicy> for PolicyResponse {
    fn from(p: crate::models::security::ScanPolicy) -> Self {
        Self {
            id: p.id,
            name: p.name,
            repository_id: p.repository_id,
            max_severity: p.max_severity,
            block_unscanned: p.block_unscanned,
            block_on_fail: p.block_on_fail,
            is_enabled: p.is_enabled,
            min_staging_hours: p.min_staging_hours,
            max_artifact_age_days: p.max_artifact_age_days,
            require_signature: p.require_signature,
            created_at: p.created_at,
            updated_at: p.updated_at,
        }
    }
}

impl From<crate::models::security::RepoSecurityScore> for ScoreResponse {
    fn from(s: crate::models::security::RepoSecurityScore) -> Self {
        Self {
            id: s.id,
            repository_id: s.repository_id,
            score: s.score,
            grade: s.grade,
            total_findings: s.total_findings,
            critical_count: s.critical_count,
            high_count: s.high_count,
            medium_count: s.medium_count,
            low_count: s.low_count,
            acknowledged_count: s.acknowledged_count,
            last_scan_at: s.last_scan_at,
            calculated_at: s.calculated_at,
            has_failed_scan: s.has_failed_scan,
        }
    }
}

impl From<crate::models::security::ScanConfig> for ScanConfigResponse {
    fn from(c: crate::models::security::ScanConfig) -> Self {
        Self {
            id: c.id,
            repository_id: c.repository_id,
            scan_enabled: c.scan_enabled,
            scan_on_upload: c.scan_on_upload,
            scan_on_proxy: c.scan_on_proxy,
            block_on_policy_violation: c.block_on_policy_violation,
            severity_threshold: c.severity_threshold,
            proxy_scan_action: c.proxy_scan_action,
            created_at: c.created_at,
            updated_at: c.updated_at,
        }
    }
}

/// Batch-lookup artifact name/version and enrich scan results into responses.
async fn enrich_scans(db: &PgPool, scans: Vec<ScanResult>) -> Result<Vec<ScanResponse>> {
    let artifact_ids: Vec<Uuid> = scans.iter().map(|s| s.artifact_id).collect();
    let artifact_info: std::collections::HashMap<Uuid, (String, Option<String>)> =
        if !artifact_ids.is_empty() {
            sqlx::query!(
                r#"SELECT id, name, version FROM artifacts WHERE id = ANY($1)"#,
                &artifact_ids,
            )
            .fetch_all(db)
            .await
            .map_err(|e| AppError::Database(e.to_string()))?
            .into_iter()
            .map(|r| (r.id, (r.name, r.version)))
            .collect()
        } else {
            std::collections::HashMap::new()
        };

    Ok(scans
        .into_iter()
        .map(|s| {
            let (artifact_name, artifact_version) = artifact_info
                .get(&s.artifact_id)
                .map(|(n, v)| (Some(n.clone()), v.clone()))
                .unwrap_or((None, None));
            ScanResponse::from_scan(s, artifact_name, artifact_version)
        })
        .collect())
}

#[derive(Debug, Default, Deserialize, IntoParams)]
pub struct ListFindingsQuery {
    pub page: Option<i64>,
    pub per_page: Option<i64>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct FindingListResponse {
    pub items: Vec<FindingResponse>,
    pub total: i64,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct FindingResponse {
    pub id: Uuid,
    pub scan_result_id: Uuid,
    pub artifact_id: Uuid,
    pub severity: String,
    pub title: String,
    pub description: Option<String>,
    pub cve_id: Option<String>,
    pub affected_component: Option<String>,
    pub affected_version: Option<String>,
    pub fixed_version: Option<String>,
    pub source: Option<String>,
    pub source_url: Option<String>,
    pub is_acknowledged: bool,
    pub acknowledged_by: Option<Uuid>,
    pub acknowledged_reason: Option<String>,
    pub acknowledged_at: Option<chrono::DateTime<chrono::Utc>>,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct AcknowledgeRequest {
    pub reason: String,
}

/// Secure default for `block_unscanned` on policy creation (#1643). When a
/// client omits the field, a new policy blocks unscanned artifacts by default
/// rather than silently failing open. Existing policies are untouched (the
/// migration only changes the column default for future rows; stored values are
/// not rewritten). Kept defaulted-secure rather than hard-required so IaC and
/// automation that omit the field stay backward-compatible.
fn default_block_unscanned() -> bool {
    true
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct CreatePolicyRequest {
    pub name: String,
    pub repository_id: Option<Uuid>,
    pub max_severity: String,
    #[serde(default = "default_block_unscanned")]
    pub block_unscanned: bool,
    pub block_on_fail: bool,
    pub min_staging_hours: Option<i32>,
    pub max_artifact_age_days: Option<i32>,
    #[serde(default)]
    pub require_signature: bool,
}

/// Partial-update payload for `PUT /security/policies/{id}`.
///
/// Every field is `Option<T>` so clients can send any subset of mutable
/// columns; omitted fields leave the existing row value untouched. The
/// previous shape required all of `name`, `max_severity`, `block_unscanned`,
/// `block_on_fail`, `is_enabled` on every call. That was incompatible with
/// the release-gate `scan-policy-crud` test (and external callers) which
/// PATCH a subset like `{max_severity, is_enabled}`; under the strict shape
/// the request was rejected as a 422 and the boolean toggle silently never
/// took effect on a follow-up GET. See #1374.
///
/// For `min_staging_hours` / `max_artifact_age_days` the field is the inner
/// nullable `i32`; "not provided" leaves the column untouched. Explicit
/// `null` to clear those columns is not currently supported; the release
/// gate only mutates the bool/enum fields, so the narrower semantics are
/// sufficient and we avoid an ambiguous JSON contract.
#[derive(Debug, Default, Deserialize, ToSchema)]
pub struct UpdatePolicyRequest {
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub max_severity: Option<String>,
    #[serde(default)]
    pub block_unscanned: Option<bool>,
    #[serde(default)]
    pub block_on_fail: Option<bool>,
    #[serde(default)]
    pub is_enabled: Option<bool>,
    #[serde(default)]
    pub min_staging_hours: Option<i32>,
    #[serde(default)]
    pub max_artifact_age_days: Option<i32>,
    #[serde(default)]
    pub require_signature: Option<bool>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct PolicyResponse {
    pub id: Uuid,
    pub name: String,
    pub repository_id: Option<Uuid>,
    pub max_severity: String,
    pub block_unscanned: bool,
    pub block_on_fail: bool,
    pub is_enabled: bool,
    pub min_staging_hours: Option<i32>,
    pub max_artifact_age_days: Option<i32>,
    pub require_signature: bool,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct RepoSecurityResponse {
    pub config: Option<ScanConfigResponse>,
    pub score: Option<ScoreResponse>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct ScanConfigResponse {
    pub id: Uuid,
    pub repository_id: Uuid,
    pub scan_enabled: bool,
    pub scan_on_upload: bool,
    pub scan_on_proxy: bool,
    /// Opt-in that makes `severity_threshold` enforced on the proxy/OCI
    /// inline scan gate (#3243/#3246). When false (default), the gate blocks
    /// on any finding above `info`. Hosted-artifact blocking remains
    /// configured via scan policies.
    pub block_on_policy_violation: bool,
    /// Severity floor for the inline proxy scan gate; live only when
    /// `block_on_policy_violation` is set (#3243/#3246). Findings at or above
    /// it block the pull.
    pub severity_threshold: String,
    /// #2954: fail-open (default) / fail-closed action for the inline proxy
    /// scan-on-fetch.
    pub proxy_scan_action: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

// ---------------------------------------------------------------------------
// Dashboard
// ---------------------------------------------------------------------------

#[utoipa::path(
    get,
    path = "/dashboard",
    context_path = "/api/v1/security",
    tag = "security",
    responses(
        (status = 200, description = "Security dashboard summary", body = DashboardResponse),
        (status = 403, description = "Admin privileges required", body = crate::api::openapi::ErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
async fn get_dashboard(
    State(state): State<SharedState>,
    Extension(auth): Extension<AuthExtension>,
) -> Result<Json<DashboardResponse>> {
    // Aggregate counts span all repos; restrict to admin. See #1034.
    auth.require_admin()?;

    let svc = ScanResultService::new(state.db.clone());
    let summary = svc.get_dashboard_summary().await?;

    Ok(Json(DashboardResponse {
        repos_with_scanning: summary.repos_with_scanning,
        total_scans: summary.total_scans,
        total_findings: summary.total_findings,
        critical_findings: summary.critical_findings,
        high_findings: summary.high_findings,
        policy_violations_blocked: summary.policy_violations_blocked,
        repos_grade_a: summary.repos_grade_a,
        repos_grade_f: summary.repos_grade_f,
    }))
}

// ---------------------------------------------------------------------------
// Scores
// ---------------------------------------------------------------------------

#[utoipa::path(
    get,
    path = "/scores",
    context_path = "/api/v1/security",
    tag = "security",
    responses(
        (status = 200, description = "All repository security scores", body = Vec<ScoreResponse>),
        (status = 403, description = "Admin privileges required", body = crate::api::openapi::ErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
async fn get_all_scores(
    State(state): State<SharedState>,
    Extension(auth): Extension<AuthExtension>,
) -> Result<Json<Vec<ScoreResponse>>> {
    // Same gate as `get_dashboard` (#1034). The leaderboard returns
    // per-repo IDs + grades + per-severity counts, which is richer
    // metadata than the dashboard aggregates and an even bigger
    // multi-tenant info leak.
    auth.require_admin()?;

    let svc = ScanResultService::new(state.db.clone());
    let scores = svc.get_all_scores().await?;
    let response: Vec<ScoreResponse> = scores.into_iter().map(ScoreResponse::from).collect();
    Ok(Json(response))
}

#[utoipa::path(
    get,
    path = "/configs",
    context_path = "/api/v1/security",
    tag = "security",
    responses(
        (status = 200, description = "List of scan configurations", body = Vec<ScanConfigResponse>),
    ),
    security(("bearer_auth" = []))
)]
async fn list_scan_configs(
    State(state): State<SharedState>,
    Extension(_auth): Extension<AuthExtension>,
) -> Result<Json<Vec<ScanConfigResponse>>> {
    let svc = ScanConfigService::new(state.db.clone());
    let configs = svc.list_configs().await?;
    let response: Vec<ScanConfigResponse> =
        configs.into_iter().map(ScanConfigResponse::from).collect();
    Ok(Json(response))
}

// ---------------------------------------------------------------------------
// Scan operations
// ---------------------------------------------------------------------------

#[utoipa::path(
    post,
    path = "/scan",
    context_path = "/api/v1/security",
    tag = "security",
    request_body = TriggerScanRequest,
    responses(
        (status = 200, description = "Scan triggered successfully", body = TriggerScanResponse),
        (status = 400, description = "Validation error", body = crate::api::openapi::ErrorResponse),
        (status = 403, description = "bypass_dedup requested by non-admin caller", body = crate::api::openapi::ErrorResponse),
        (status = 503, description = "Scanner service not configured", body = crate::api::openapi::ErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
async fn trigger_scan(
    State(state): State<SharedState>,
    Extension(auth): Extension<AuthExtension>,
    Json(body): Json<TriggerScanRequest>,
) -> Result<Json<TriggerScanResponse>> {
    // #2321 G5: triggering scans fans out scanner work per artifact (and, at the
    // repo level, one worker per artifact). Previously only the `bypass_dedup`
    // shape was admin-gated, leaving the default and `bypass_dedup=false` shapes
    // open to any authenticated user as an amplification/DoS lever. Require admin
    // for ALL request shapes, up front, and record the RBAC-deny.
    //
    // Chosen default: global admin. If a future policy decides repo-write should
    // suffice for a single-artifact scan, narrow this deliberately with a test.
    crate::services::audit_service::enforce_admin_audited(
        auth.is_admin,
        state.db.clone(),
        auth.user_id,
        crate::services::audit_service::ResourceType::ScanResult,
        "/api/v1/security/scan",
        "POST",
    )
    .await?;

    // 503 (not 500) because "scanner not configured" is a normal operational
    // state on minimal stacks (no Trivy / OpenSCAP service), not a server
    // bug. 500 alerts on operator dashboards; 503 does not.
    let scanner = state
        .scanner_service
        .as_ref()
        .ok_or_else(|| AppError::ServiceUnavailable("Scanner service not configured".to_string()))?
        .clone();

    // `bypass_dedup = true` skips the hash-based scan dedup short-circuit and
    // fans out a fresh scanner run per artifact (and, at the repo level, one
    // tokio::spawn worker per artifact in the repo). The whole handler is now
    // admin-only (see the gate above), so no separate non-admin check is needed
    // here; the flag still selects the dedup behavior for the admin caller.
    let bypass_dedup = body.bypass_dedup.unwrap_or(false);

    if let Some(artifact_id) = body.artifact_id {
        // Honest not-found up front (#2227): without this, an id with no
        // `artifacts` row -- e.g. the synthetic, SHA-256-derived id a Remote
        // repo lists for a proxy-cached object (#1280/#1278) -- returned a
        // fire-and-forget 200 and then failed only in the worker's logs
        // ("Scan failed for artifact ...: Artifact not found"). Resolve the
        // row first and return a clear 404 so the caller learns that scans
        // are only available for artifacts hosted in this registry.
        let exists: Option<Uuid> =
            sqlx::query_scalar("SELECT id FROM artifacts WHERE id = $1 AND is_deleted = false")
                .bind(artifact_id)
                .fetch_optional(&state.db)
                .await
                .map_err(|e: sqlx::Error| AppError::Database(e.to_string()))?;
        if exists.is_none() {
            return Err(AppError::NotFound(
                crate::api::handlers::sbom::ON_DEMAND_SCAN_NOT_AVAILABLE_MSG.into(),
            ));
        }

        // Pre-allocate one scan_result row per configured scanner so the IDs
        // can be returned in this response. The actual scan work is still
        // fire-and-forget (tokio::spawn) but uses these pre-committed IDs
        // instead of inserting new rows. See artifact-keeper#906.
        //
        // `bypass_dedup` (#1469) must be passed to BOTH prepare and execute:
        // prepare needs it so the same-artifact short-circuit doesn't return
        // the stale completed row's id (which would leave the worker with
        // nothing to do); execute needs it so the cross-artifact reuse path
        // doesn't copy the same stale row into a new `is_reused = true` row
        // for the newly-allocated placeholder.
        let prepared = scanner
            .prepare_artifact_scan(artifact_id, true, bypass_dedup)
            .await?;
        let scan_result_ids = crate::services::scanner_service::extract_scan_result_ids(&prepared);
        let prepared_map = crate::services::scanner_service::prepared_pairs_to_map(prepared);

        let scanner_for_spawn = scanner.clone();
        tokio::spawn(async move {
            if let Err(e) = scanner_for_spawn
                .scan_artifact_with_prepared(artifact_id, prepared_map, true, bypass_dedup)
                .await
            {
                tracing::error!("Scan failed for artifact {}: {}", artifact_id, e);
            }
        });
        return Ok(Json(TriggerScanResponse {
            message: crate::services::scanner_service::build_artifact_scan_message(artifact_id),
            artifacts_queued: 1,
            scan_result_ids,
        }));
    }

    let repository_id = body.repository_id.ok_or_else(|| {
        AppError::Validation("Either artifact_id or repository_id is required".to_string())
    })?;

    // Use the same enumeration the scan worker uses (virtual repos resolve to
    // their member repos recursively) so the reported count always matches
    // what actually gets enqueued (#2228).
    let count: i64 = scanner
        .repository_scan_artifact_ids(repository_id)
        .await?
        .len() as i64;

    tokio::spawn(async move {
        if let Err(e) = scanner
            .scan_repository_with_options(repository_id, true, bypass_dedup)
            .await
        {
            tracing::error!("Repository scan failed for {}: {}", repository_id, e);
        }
    });
    // Repository-level triggers don't pre-allocate per-artifact rows because
    // the count can be large and individual rows are still created inside the
    // worker. Clients that need scan_result_ids must trigger artifact-level
    // scans (one per artifact_id) instead.
    Ok(Json(TriggerScanResponse {
        message: crate::services::scanner_service::build_repository_scan_message(
            repository_id,
            count,
        ),
        artifacts_queued: count as u32,
        scan_result_ids: Vec::new(),
    }))
}

#[utoipa::path(
    get,
    path = "/scans",
    context_path = "/api/v1/security",
    tag = "security",
    params(ListScansQuery),
    responses(
        (status = 200, description = "Paginated list of scans", body = ScanListResponse),
    ),
    security(("bearer_auth" = []))
)]
async fn list_scans(
    State(state): State<SharedState>,
    Extension(auth): Extension<AuthExtension>,
    Query(query): Query<ListScansQuery>,
) -> Result<Json<ScanListResponse>> {
    // Cross-repo authorization (#2439): this global scan list is
    // artifact/repo-scoped data. Gate on whichever filter the caller
    // supplied so a non-member cannot enumerate another repo's scans:
    //   - artifact_id → canonical artifact-visibility gate;
    //   - repository_id → canonical repo-visibility gate;
    //   - neither → an unfiltered listing would expose every repo's scans,
    //     so restrict it to admins (non-admins must scope by repo/artifact).
    // Existence-hiding NotFound (never Forbidden) for the scoped branches.
    let auth = Some(auth);
    match (query.artifact_id, query.repository_id) {
        (Some(artifact_id), _) => {
            check_artifact_visibility(&auth, artifact_id, &state.db).await?;
        }
        (None, Some(repository_id)) => {
            let repo_service = RepositoryService::new(state.db.clone());
            let repo = repo_service.get_by_id(repository_id).await?;
            require_visible(&repo, &auth, &repo_service).await?;
        }
        (None, None) => {
            if !auth.as_ref().is_some_and(|a| a.is_admin) {
                return Err(AppError::Authorization(
                    "Listing all scans requires admin; scope the request with \
                     repository_id or artifact_id"
                        .to_string(),
                ));
            }
        }
    }

    let svc = ScanResultService::new(state.db.clone());
    let page = query.page.unwrap_or(1);
    let per_page = query.per_page.unwrap_or(20).min(100);
    let offset = (page - 1) * per_page;

    let (scans, total) = svc
        .list_scans(
            query.repository_id,
            query.artifact_id,
            query.status.as_deref(),
            offset,
            per_page,
        )
        .await?;

    // #2471: fold redundant per-artifact `not_applicable` rows into a single
    // muted summary row before returning. `total` is left as the raw DB row
    // count (it drives pagination); the collapse only shrinks the rows shown on
    // this page, and the `total >= items.len()` invariant still holds.
    let items = collapse_not_applicable_rows(enrich_scans(&state.db, scans).await?);
    Ok(Json(ScanListResponse { items, total }))
}

#[utoipa::path(
    get,
    path = "/scans/{id}",
    context_path = "/api/v1/security",
    tag = "security",
    params(
        ("id" = Uuid, Path, description = "Scan result ID")
    ),
    responses(
        (status = 200, description = "Scan details", body = ScanResponse),
        (status = 404, description = "Scan not found", body = crate::api::openapi::ErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
async fn get_scan(
    State(state): State<SharedState>,
    Extension(auth): Extension<AuthExtension>,
    Path(id): Path<Uuid>,
) -> Result<Json<ScanResponse>> {
    let svc = ScanResultService::new(state.db.clone());
    let s = svc.get_scan(id).await?;

    // Cross-repo authorization (#2439): resolve the scan's owning artifact,
    // then apply the canonical visibility gate (existence-hiding 404) before
    // returning any scan detail. Normalize the no-access 404 body to the same
    // message an absent id produces so it is not an existence oracle.
    check_artifact_visibility(&Some(auth), s.artifact_id, &state.db)
        .await
        .map_err(unify_scan_not_found)?;

    let mut items = enrich_scans(&state.db, vec![s]).await?;
    Ok(Json(items.remove(0)))
}

// ---------------------------------------------------------------------------
// Findings
// ---------------------------------------------------------------------------

#[utoipa::path(
    get,
    path = "/scans/{id}/findings",
    context_path = "/api/v1/security",
    tag = "security",
    params(
        ("id" = Uuid, Path, description = "Scan result ID"),
        ListFindingsQuery,
    ),
    responses(
        (status = 200, description = "Paginated list of findings for a scan", body = FindingListResponse),
        (status = 404, description = "Scan not found", body = crate::api::openapi::ErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
async fn list_findings(
    State(state): State<SharedState>,
    Extension(auth): Extension<AuthExtension>,
    Path(scan_id): Path<Uuid>,
    Query(query): Query<ListFindingsQuery>,
) -> Result<Json<FindingListResponse>> {
    let svc = ScanResultService::new(state.db.clone());

    // Verify the scan exists. Without this check, an unknown scan_id falls
    // through the `WHERE scan_result_id = $1` query and returns a 200 with
    // an empty envelope, contradicting the 404 documented in the OpenAPI
    // annotation above. Clients can't distinguish "unknown scan" from "real
    // scan with zero findings" without this pre-check.
    let scan = svc.get_scan(scan_id).await?;

    // Cross-repo authorization (#2439): resolve the scan's owning artifact and
    // apply the canonical visibility gate (existence-hiding 404) before
    // returning any CVE finding for it. Normalize the no-access 404 body to the
    // same message an absent id produces so it is not an existence oracle.
    check_artifact_visibility(&Some(auth), scan.artifact_id, &state.db)
        .await
        .map_err(unify_scan_not_found)?;

    let page = query.page.unwrap_or(1);
    let per_page = query.per_page.unwrap_or(50).min(200);
    let offset = (page - 1) * per_page;

    let (findings, total) = svc.list_findings(scan_id, offset, per_page).await?;

    let items: Vec<FindingResponse> = findings.into_iter().map(FindingResponse::from).collect();
    Ok(Json(FindingListResponse { items, total }))
}

#[utoipa::path(
    post,
    path = "/findings/{id}/acknowledge",
    context_path = "/api/v1/security",
    tag = "security",
    params(
        ("id" = Uuid, Path, description = "Finding ID")
    ),
    request_body = AcknowledgeRequest,
    responses(
        (status = 200, description = "Finding acknowledged", body = FindingResponse),
        (status = 403, description = "Admin privileges required", body = crate::api::openapi::ErrorResponse),
        (status = 404, description = "Finding not found", body = crate::api::openapi::ErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
async fn acknowledge_finding(
    State(state): State<SharedState>,
    Extension(auth): Extension<AuthExtension>,
    Path(finding_id): Path<Uuid>,
    Json(body): Json<AcknowledgeRequest>,
) -> Result<Json<FindingResponse>> {
    // Admin-only: non-admins could otherwise hide findings from any
    // repo by passing its UUID, suppressing them from #962's dashboard
    // counts. No per-user repo-membership model exists; admin gate
    // matches the dashboard gate in #1034. See #1032.
    auth.require_admin()?;

    let svc = ScanResultService::new(state.db.clone());
    let user_id = auth.user_id;

    let f = svc
        .acknowledge_finding(finding_id, user_id, &body.reason)
        .await?;

    Ok(Json(FindingResponse::from(f)))
}

#[utoipa::path(
    delete,
    path = "/findings/{id}/acknowledge",
    context_path = "/api/v1/security",
    tag = "security",
    params(
        ("id" = Uuid, Path, description = "Finding ID")
    ),
    responses(
        (status = 200, description = "Acknowledgment revoked", body = FindingResponse),
        (status = 403, description = "Admin privileges required", body = crate::api::openapi::ErrorResponse),
        (status = 404, description = "Finding not found", body = crate::api::openapi::ErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
async fn revoke_acknowledgment(
    State(state): State<SharedState>,
    Extension(auth): Extension<AuthExtension>,
    Path(finding_id): Path<Uuid>,
) -> Result<Json<FindingResponse>> {
    // Symmetric gate with acknowledge_finding (#1032): both write to the
    // same row. Allowing un-privileged un-acknowledge would let an attacker
    // un-hide a finding the admin previously acknowledged for a legitimate
    // reason, churning dashboard counts.
    auth.require_admin()?;

    let svc = ScanResultService::new(state.db.clone());
    let f = svc.revoke_acknowledgment(finding_id).await?;

    Ok(Json(FindingResponse::from(f)))
}

// ---------------------------------------------------------------------------
// Policies
// ---------------------------------------------------------------------------

#[utoipa::path(
    get,
    path = "/policies",
    context_path = "/api/v1/security",
    tag = "security",
    responses(
        (status = 200, description = "List of security policies", body = Vec<PolicyResponse>),
    ),
    security(("bearer_auth" = []))
)]
async fn list_policies(
    State(state): State<SharedState>,
    Extension(_auth): Extension<AuthExtension>,
) -> Result<Json<Vec<PolicyResponse>>> {
    let svc = PolicyService::new(state.db.clone());
    let policies = svc.list_policies().await?;
    let response: Vec<PolicyResponse> = policies.into_iter().map(PolicyResponse::from).collect();
    Ok(Json(response))
}

#[utoipa::path(
    post,
    path = "/policies",
    context_path = "/api/v1/security",
    tag = "security",
    request_body = CreatePolicyRequest,
    responses(
        (status = 200, description = "Policy created", body = PolicyResponse),
        (status = 400, description = "Invalid max_severity (must be one of critical, high, medium, low; case-insensitive)", body = crate::api::openapi::ErrorResponse),
        (status = 404, description = "repository_id does not reference an existing repository", body = crate::api::openapi::ErrorResponse),
        (status = 422, description = "Validation error", body = crate::api::openapi::ErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
async fn create_policy(
    State(state): State<SharedState>,
    Extension(auth): Extension<AuthExtension>,
    Json(body): Json<CreatePolicyRequest>,
) -> Result<Json<PolicyResponse>> {
    auth.require_admin()?;
    let svc = PolicyService::new(state.db.clone());
    let p = svc
        .create_policy(
            &body.name,
            body.repository_id,
            &body.max_severity,
            body.block_unscanned,
            body.block_on_fail,
            body.min_staging_hours,
            body.max_artifact_age_days,
            body.require_signature,
        )
        .await?;

    Ok(Json(PolicyResponse::from(p)))
}

#[utoipa::path(
    get,
    path = "/policies/{id}",
    context_path = "/api/v1/security",
    tag = "security",
    params(
        ("id" = Uuid, Path, description = "Policy ID")
    ),
    responses(
        (status = 200, description = "Policy details", body = PolicyResponse),
        (status = 404, description = "Policy not found", body = crate::api::openapi::ErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
async fn get_policy(
    State(state): State<SharedState>,
    Extension(_auth): Extension<AuthExtension>,
    Path(id): Path<Uuid>,
) -> Result<Json<PolicyResponse>> {
    let svc = PolicyService::new(state.db.clone());
    let p = svc.get_policy(id).await?;

    Ok(Json(PolicyResponse::from(p)))
}

#[utoipa::path(
    put,
    path = "/policies/{id}",
    context_path = "/api/v1/security",
    tag = "security",
    params(
        ("id" = Uuid, Path, description = "Policy ID")
    ),
    request_body = UpdatePolicyRequest,
    responses(
        (status = 200, description = "Policy updated", body = PolicyResponse),
        (status = 404, description = "Policy not found", body = crate::api::openapi::ErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
async fn update_policy(
    State(state): State<SharedState>,
    Extension(auth): Extension<AuthExtension>,
    Path(id): Path<Uuid>,
    Json(body): Json<UpdatePolicyRequest>,
) -> Result<Json<PolicyResponse>> {
    auth.require_admin()?;
    let svc = PolicyService::new(state.db.clone());
    // PUT is partial-update friendly: any field client omits is left at its
    // current DB value via COALESCE in the service layer. See #1374.
    let p = svc
        .update_policy(
            id,
            body.name.as_deref(),
            body.max_severity.as_deref(),
            body.block_unscanned,
            body.block_on_fail,
            body.is_enabled,
            body.min_staging_hours,
            body.max_artifact_age_days,
            body.require_signature,
        )
        .await?;

    Ok(Json(PolicyResponse::from(p)))
}

#[utoipa::path(
    delete,
    path = "/policies/{id}",
    context_path = "/api/v1/security",
    tag = "security",
    params(
        ("id" = Uuid, Path, description = "Policy ID")
    ),
    responses(
        (status = 200, description = "Policy deleted", body = Object),
        (status = 404, description = "Policy not found", body = crate::api::openapi::ErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
async fn delete_policy(
    State(state): State<SharedState>,
    Extension(auth): Extension<AuthExtension>,
    Path(id): Path<Uuid>,
) -> Result<Json<serde_json::Value>> {
    auth.require_admin()?;
    let svc = PolicyService::new(state.db.clone());
    svc.delete_policy(id).await?;
    Ok(Json(serde_json::json!({ "deleted": true })))
}

// ---------------------------------------------------------------------------
// Repo-scoped security
// ---------------------------------------------------------------------------

#[utoipa::path(
    get,
    path = "/{key}/security",
    context_path = "/api/v1/repositories",
    tag = "security",
    params(
        ("key" = String, Path, description = "Repository key")
    ),
    responses(
        (status = 200, description = "Repository security config and score", body = RepoSecurityResponse),
        (status = 404, description = "Repository not found", body = crate::api::openapi::ErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
async fn get_repo_security(
    State(state): State<SharedState>,
    Extension(auth): Extension<Option<AuthExtension>>,
    Path(key): Path<String>,
) -> Result<Json<RepoSecurityResponse>> {
    let auth =
        auth.ok_or_else(|| AppError::Authentication("Authentication required".to_string()))?;
    // Resolve repository by key. The /repositories nest is NOT gated by
    // repo_visibility_middleware, so enforce the canonical visibility gate
    // (is_public + per-repo role-assignment membership) here to avoid leaking a
    // private repo's security config/score to a non-member.
    let repo_service = RepositoryService::new(state.db.clone());
    let repo = repo_service.get_by_key(&key).await?;
    require_visible(&repo, &Some(auth), &repo_service).await?;
    let repo = repo.id;

    let config_svc = ScanConfigService::new(state.db.clone());
    let result_svc = ScanResultService::new(state.db.clone());

    let config = config_svc.get_config(repo).await?;
    let score = result_svc.get_score(repo).await?;

    Ok(Json(RepoSecurityResponse {
        config: config.map(ScanConfigResponse::from),
        score: score.map(ScoreResponse::from),
    }))
}

#[utoipa::path(
    put,
    path = "/{key}/security",
    context_path = "/api/v1/repositories",
    tag = "security",
    params(
        ("key" = String, Path, description = "Repository key")
    ),
    request_body = UpsertScanConfigRequest,
    responses(
        (status = 200, description = "Repository security config updated", body = ScanConfigResponse),
        (status = 404, description = "Repository not found", body = crate::api::openapi::ErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
async fn update_repo_security(
    State(state): State<SharedState>,
    Extension(auth): Extension<Option<AuthExtension>>,
    Path(key): Path<String>,
    Json(body): Json<UpsertScanConfigRequest>,
) -> Result<Json<ScanConfigResponse>> {
    let auth =
        auth.ok_or_else(|| AppError::Authentication("Authentication required".to_string()))?;
    // Tenant write gate: the /repositories nest bypasses repo_visibility_middleware,
    // so enforce is_public + per-repo role-assignment membership here.
    let repo_service = RepositoryService::new(state.db.clone());
    let repo = repo_service.get_by_key(&key).await?;
    require_repo_write_access(&auth, &repo, &repo_service).await?;
    // Scan configuration is a repository supply-chain control (scan_enabled /
    // block_on_policy_violation / severity_threshold): disabling it must be
    // repository administration, not artifact publishing. Same admin tier and
    // fail-closed gate as the configuration subresources fixed in #2745
    // (#2603 sibling, #2750).
    require_repo_admin(&auth, repo.id, &state.permission_service).await?;
    let repo = repo.id;

    let svc = ScanConfigService::new(state.db.clone());
    let c = svc.upsert_config(repo, &body).await?;

    Ok(Json(ScanConfigResponse::from(c)))
}

#[utoipa::path(
    get,
    path = "/artifacts/{artifact_id}/scans",
    context_path = "/api/v1/security",
    tag = "security",
    params(
        ("artifact_id" = Uuid, Path, description = "Artifact ID"),
        ("status" = Option<String>, Query, description = "Filter by scan status"),
        ("page" = Option<i64>, Query, description = "Page number (default: 1)"),
        ("per_page" = Option<i64>, Query, description = "Items per page (default: 20, max: 100)"),
    ),
    responses(
        (status = 200, description = "Paginated list of scans for an artifact", body = ScanListResponse),
    ),
    security(("bearer_auth" = []))
)]
async fn list_artifact_scans(
    State(state): State<SharedState>,
    Extension(auth): Extension<AuthExtension>,
    Path(artifact_id): Path<Uuid>,
    Query(query): Query<ListScansQuery>,
) -> Result<Json<ScanListResponse>> {
    // Cross-repo authorization (#2439): apply the canonical artifact-visibility
    // gate (existence-hiding 404) before listing any scan for this artifact.
    check_artifact_visibility(&Some(auth), artifact_id, &state.db).await?;

    let svc = ScanResultService::new(state.db.clone());
    let page = query.page.unwrap_or(1);
    let per_page = query.per_page.unwrap_or(20).min(100);
    let offset = (page - 1) * per_page;

    let (scans, total) = svc
        .list_scans(
            None,
            Some(artifact_id),
            query.status.as_deref(),
            offset,
            per_page,
        )
        .await?;

    // #2471: fold redundant per-artifact `not_applicable` rows into a single
    // muted summary row before returning. `total` is left as the raw DB row
    // count (it drives pagination); the collapse only shrinks the rows shown on
    // this page, and the `total >= items.len()` invariant still holds.
    let items = collapse_not_applicable_rows(enrich_scans(&state.db, scans).await?);
    Ok(Json(ScanListResponse { items, total }))
}

#[utoipa::path(
    get,
    path = "/{key}/security/scans",
    context_path = "/api/v1/repositories",
    tag = "security",
    params(
        ("key" = String, Path, description = "Repository key"),
        ListScansQuery,
    ),
    responses(
        (status = 200, description = "Paginated list of scans for a repository", body = ScanListResponse),
        (status = 404, description = "Repository not found", body = crate::api::openapi::ErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
async fn list_repo_scans(
    State(state): State<SharedState>,
    Extension(auth): Extension<Option<AuthExtension>>,
    Path(key): Path<String>,
    Query(query): Query<ListScansQuery>,
) -> Result<Json<ScanListResponse>> {
    let auth =
        auth.ok_or_else(|| AppError::Authentication("Authentication required".to_string()))?;
    // Resolve repository by key. The /repositories nest bypasses
    // repo_visibility_middleware, so enforce the canonical visibility gate here
    // to avoid leaking a private repo's scan list to a non-member.
    let repo_service = RepositoryService::new(state.db.clone());
    let repo = repo_service.get_by_key(&key).await?;
    require_visible(&repo, &Some(auth), &repo_service).await?;
    let repo = repo.id;

    let svc = ScanResultService::new(state.db.clone());
    let page = query.page.unwrap_or(1);
    let per_page = query.per_page.unwrap_or(20).min(100);
    let offset = (page - 1) * per_page;

    let (scans, total) = svc
        .list_scans(Some(repo), None, query.status.as_deref(), offset, per_page)
        .await?;

    // #2471: fold redundant per-artifact `not_applicable` rows into a single
    // muted summary row before returning. `total` is left as the raw DB row
    // count (it drives pagination); the collapse only shrinks the rows shown on
    // this page, and the `total >= items.len()` invariant still holds.
    let items = collapse_not_applicable_rows(enrich_scans(&state.db, scans).await?);
    Ok(Json(ScanListResponse { items, total }))
}

// ---------------------------------------------------------------------------
// Proxy scan visibility (#3344 follow-up)
//
// Proxy-cached bytes deliberately have no `artifacts` row, so their scan
// verdicts live in the digest-keyed `proxy_scan_results` table and are invisible
// to every artifact-keyed security read. This endpoint is the only surface that
// reports them, joined back to the calling repository's own cache catalog.
//
// Three properties are load-bearing and must not be relaxed:
//   1. Lookup is by cache PATH, never by digest. A digest parameter would make
//      this a cross-tenant lookup oracle (verdicts are shared by content hash
//      across every repository in the deployment); a path is inherently scoped
//      to the calling repository.
//   2. Authentication is required unconditionally, including on public
//      repositories -- `require_visible` returns early for `is_public`, so the
//      auth check MUST come first.
//   3. `repository_id` (the provenance column on `proxy_scan_results`) is never
//      returned, and `scanned_at` is floored at the caller's own `cached_at`:
//      a raw `scanned_at` predating the caller's first pull proves another
//      tenant fetched byte-identical content earlier, and when.
// ---------------------------------------------------------------------------

/// Verdict state for a proxy-cached path: a scan verdict of `clean`.
const PROXY_STATE_CLEAN: &str = "clean";
/// Verdict state for a proxy-cached path: a scan verdict of `vulnerable`.
const PROXY_STATE_VULNERABLE: &str = "vulnerable";
/// Verdict state for a proxy-cached path with no usable verdict row.
const PROXY_STATE_NOT_SCANNED: &str = "not_scanned";
/// Verdict state for a catalog row whose `checksum_sha256` is still NULL.
///
/// `record_proxy_download` upserts a placeholder before the content commits and
/// only backfills the checksum on a successful cache commit, so an aborted tee,
/// a client disconnect, or an over-cap fail-open stream leaves the row NULL
/// permanently (there is no cleanup job). Such a row joins to nothing and must
/// never be reported as `not_scanned` -- it is reported under its own state and
/// its own `pending_ingest` count so the totals reconcile with the listing.
const PROXY_STATE_PENDING_INGEST: &str = "pending_ingest";

/// `not_scanned` reason: `scan_configs.scan_on_proxy` is false **or absent**.
///
/// No `scan_configs` row is created at repository creation -- the only
/// production insert is the settings upsert -- so "never configured" is the
/// default state and must resolve here, matching `is_proxy_scan_enabled`'s
/// `unwrap_or(false)` and therefore matching what the gate actually does.
const PROXY_REASON_SCANNING_DISABLED: &str = "scanning_disabled";
/// `not_scanned` reason: everything else. Must never be worded as safe.
const PROXY_REASON_UNKNOWN: &str = "unknown";

/// `proxy_scan_action` reported when the repository has no `scan_configs` row,
/// matching the column default in migration 181.
const DEFAULT_PROXY_SCAN_ACTION: &str = "fail_open";

/// Canonical 404 body for a path that does not resolve in this repository's
/// proxy cache catalog. Identical for "no such path" and "that path belongs to
/// another repository" so the endpoint is not a cross-tenant existence oracle.
const PROXY_PATH_NOT_FOUND_MSG: &str = "No proxy-cached artifact at that path";

/// Upper bound on the per-CVE detail returned for one path (#3395). A base
/// image can carry thousands of findings; the endpoint reports counts for the
/// true total and this list for the actionable head of it.
const MAX_PROXY_FINDINGS: i64 = 200;

/// Projection shared by the single-path and paged reads.
///
/// `$1` is the repository id and `$2` the scan type. The scan-type filter is
/// mandatory: `uq_proxy_scan` is `(checksum_sha256, scan_type)`, so an
/// unfiltered join fans a path out into one row per scan type the day a second
/// scanner writes verdicts.
///
/// Cached upstream index responses are excluded through the shared
/// [`proxy_catalog::not_cached_index_sql`] predicate -- the same one the
/// artifact listing uses, so the two views cannot disagree. An HTML index page
/// has no package inventory, so counting it as `not_scanned` is a permanent
/// false positive with no available remedy.
fn proxy_scan_select() -> String {
    format!(
        r#"
    SELECT pca.path, pca.checksum_sha256, pca.size_bytes, pca.cached_at,
           psr.verdict, psr.findings_count, psr.critical_count, psr.high_count,
           psr.medium_count, psr.low_count, psr.max_severity, psr.scanned_at
      FROM proxy_cache_artifacts pca
      LEFT JOIN proxy_scan_results psr
             ON psr.checksum_sha256 = pca.checksum_sha256
            AND psr.scan_type = $2
     WHERE pca.repository_id = $1
       AND {not_index}
"#,
        not_index = proxy_catalog::not_cached_index_sql("pca.path"),
    )
}

#[derive(Debug, Clone, sqlx::FromRow)]
struct ProxyScanRow {
    path: String,
    checksum_sha256: Option<String>,
    size_bytes: i64,
    cached_at: chrono::DateTime<chrono::Utc>,
    verdict: Option<String>,
    findings_count: Option<i32>,
    critical_count: Option<i32>,
    high_count: Option<i32>,
    medium_count: Option<i32>,
    low_count: Option<i32>,
    max_severity: Option<String>,
    scanned_at: Option<chrono::DateTime<chrono::Utc>>,
}

#[derive(Debug, Default, Deserialize, IntoParams)]
pub struct ProxyScansQuery {
    /// Cache path of a single entry, e.g.
    /// `simple/click/click-8.0.0-py3-none-any.whl`. When set, the response
    /// carries just that entry and omits the repository summary.
    pub path: Option<String>,
    pub page: Option<i64>,
    pub per_page: Option<i64>,
}

/// Per-state counts over **distinct digests**, not paths: one repository can
/// cache the same digest at many paths, and the UI label must say so.
#[derive(Debug, Default, PartialEq, Eq, Serialize, ToSchema, sqlx::FromRow)]
pub struct ProxyScanSummary {
    pub clean: i64,
    pub vulnerable: i64,
    pub not_scanned: i64,
    /// Catalog rows whose `checksum_sha256` is still NULL. Counted as PATHS
    /// (they have no digest to dedupe on) and excluded from every other count.
    pub pending_ingest: i64,
    /// Distinct digests cached by this repository. Equals
    /// `clean + vulnerable + not_scanned`.
    pub total_digests: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
pub struct ProxyScanEntry {
    pub path: String,
    /// SHA-256 of the cached bytes; NULL while the row is `pending_ingest`.
    pub digest: Option<String>,
    /// `clean` | `vulnerable` | `not_scanned` | `pending_ingest`.
    pub state: String,
    /// Set only when `state` is `not_scanned`.
    pub not_scanned_reason: Option<String>,
    pub findings_count: Option<i32>,
    pub critical_count: Option<i32>,
    pub high_count: Option<i32>,
    pub medium_count: Option<i32>,
    pub low_count: Option<i32>,
    pub max_severity: Option<String>,
    /// Floored at this repository's own `cached_at` -- see the module note.
    pub scanned_at: Option<chrono::DateTime<chrono::Utc>>,
    pub cached_at: chrono::DateTime<chrono::Utc>,
    pub size_bytes: i64,
    /// The CVEs behind the counts (#3395), most severe first and bounded to
    /// [`MAX_PROXY_FINDINGS`].
    ///
    /// Populated ONLY for a single-path (`?path=`) read, and only for a
    /// `vulnerable` entry. Two reasons it is absent from the paged listing:
    /// one query per row would make the list an N+1, and the listing is a
    /// per-repository overview whose job is to point at the entry to open.
    ///
    /// `None` (omitted) means "not requested at this granularity"; an empty
    /// vector means "requested, and this digest has no recorded detail" --
    /// which is the real state for anything cached before #3395 shipped. The
    /// two must stay distinguishable or a pre-#3395 artifact renders as having
    /// no CVEs, which reads as clean.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub findings: Option<Vec<crate::models::security::ProxyFinding>>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct ProxyScansResponse {
    pub repository_key: String,
    /// Enforcement context. Without it `vulnerable` is ambiguous: with
    /// scanning on it means pulls are blocked; with scanning off it means the
    /// artifact is served anyway and the verdict was recorded elsewhere.
    pub scan_on_proxy: bool,
    /// `fail_open` | `fail_closed`. Lets `not_scanned` be read as "may have
    /// been served unscanned" versus "was withheld".
    pub proxy_scan_action: String,
    /// Omitted for a single-path (`?path=`) read.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub summary: Option<ProxyScanSummary>,
    pub items: Vec<ProxyScanEntry>,
    /// Catalog paths matching the query (paths, not digests).
    pub total: i64,
    pub page: i64,
    pub per_page: i64,
}

/// Derive the reported state from the joined row.
///
/// A NULL checksum wins over any verdict (there cannot be one). `verdict`
/// values other than `clean`/`vulnerable` -- i.e. the unreachable `error`
/// verdict -- fall to `not_scanned` so the summary's per-state counts still sum
/// to `total_digests`.
fn proxy_scan_state(checksum: Option<&str>, verdict: Option<&str>) -> &'static str {
    if checksum.is_none() {
        return PROXY_STATE_PENDING_INGEST;
    }
    match verdict {
        Some(PROXY_STATE_CLEAN) => PROXY_STATE_CLEAN,
        Some(PROXY_STATE_VULNERABLE) => PROXY_STATE_VULNERABLE,
        _ => PROXY_STATE_NOT_SCANNED,
    }
}

/// Reason accompanying `not_scanned`, and only `not_scanned`.
fn proxy_not_scanned_reason(state: &str, scan_on_proxy: bool) -> Option<&'static str> {
    if state != PROXY_STATE_NOT_SCANNED {
        return None;
    }
    Some(if scan_on_proxy {
        PROXY_REASON_UNKNOWN
    } else {
        PROXY_REASON_SCANNING_DISABLED
    })
}

/// Floor a globally-shared `scanned_at` at the calling repository's own
/// `cached_at`, so the response cannot date another tenant's earlier pull of
/// byte-identical content.
fn floor_scanned_at(
    scanned_at: Option<chrono::DateTime<chrono::Utc>>,
    cached_at: chrono::DateTime<chrono::Utc>,
) -> Option<chrono::DateTime<chrono::Utc>> {
    scanned_at.map(|s| s.max(cached_at))
}

/// Clamp paging input to `(page, per_page, offset)`.
fn proxy_scan_paging(page: Option<i64>, per_page: Option<i64>) -> (i64, i64, i64) {
    let page = page.unwrap_or(1).max(1);
    let per_page = per_page.unwrap_or(50).clamp(1, 200);
    (page, per_page, (page - 1) * per_page)
}

impl ProxyScanEntry {
    /// Project one joined row into the wire shape. Pure: every security-
    /// relevant transform (state derivation, `scanned_at` flooring, dropping
    /// `repository_id`) happens here and is unit-tested without a database.
    fn from_row(row: ProxyScanRow, scan_on_proxy: bool) -> Self {
        let state = proxy_scan_state(row.checksum_sha256.as_deref(), row.verdict.as_deref());
        let scored = state == PROXY_STATE_CLEAN || state == PROXY_STATE_VULNERABLE;
        Self {
            path: row.path,
            digest: row.checksum_sha256,
            state: state.to_string(),
            not_scanned_reason: proxy_not_scanned_reason(state, scan_on_proxy).map(str::to_string),
            // Counts belong to the verdict row; suppress them wholesale when
            // there is no verdict so a `not_scanned` entry can never render as
            // "0 findings", which reads as clean.
            findings_count: scored.then_some(row.findings_count).flatten(),
            critical_count: scored.then_some(row.critical_count).flatten(),
            high_count: scored.then_some(row.high_count).flatten(),
            medium_count: scored.then_some(row.medium_count).flatten(),
            low_count: scored.then_some(row.low_count).flatten(),
            max_severity: if scored { row.max_severity } else { None },
            scanned_at: if scored {
                floor_scanned_at(row.scanned_at, row.cached_at)
            } else {
                None
            },
            cached_at: row.cached_at,
            size_bytes: row.size_bytes,
            findings: None,
        }
    }

    /// Attach per-CVE detail to a single-path entry (#3395).
    ///
    /// Suppressed unless the entry is `vulnerable`, mirroring the count
    /// suppression above and for the same reason: attaching an empty CVE list
    /// to a `not_scanned` or `pending_ingest` entry renders as "we looked and
    /// found nothing", which is exactly the false all-clear this whole surface
    /// exists to remove. A `clean` entry is also left alone -- its detail is
    /// the absence of findings, already carried by `findings_count: 0`.
    fn with_findings(mut self, findings: Vec<crate::models::security::ProxyFinding>) -> Self {
        if self.state == PROXY_STATE_VULNERABLE {
            self.findings = Some(findings);
        }
        self
    }
}

/// Per-state counts over distinct digests for one repository.
async fn fetch_proxy_scan_summary(db: &PgPool, repo_id: Uuid) -> Result<ProxyScanSummary> {
    sqlx::query_as::<_, ProxyScanSummary>(&format!(
        r#"
        SELECT
            COUNT(DISTINCT pca.checksum_sha256)
                FILTER (WHERE psr.verdict = 'clean') AS clean,
            COUNT(DISTINCT pca.checksum_sha256)
                FILTER (WHERE psr.verdict = 'vulnerable') AS vulnerable,
            COUNT(DISTINCT pca.checksum_sha256) FILTER (
                WHERE psr.verdict IS NULL
                   OR psr.verdict NOT IN ('clean', 'vulnerable')
            ) AS not_scanned,
            COUNT(*) FILTER (WHERE pca.checksum_sha256 IS NULL) AS pending_ingest,
            COUNT(DISTINCT pca.checksum_sha256) AS total_digests
          FROM proxy_cache_artifacts pca
          LEFT JOIN proxy_scan_results psr
                 ON psr.checksum_sha256 = pca.checksum_sha256
                AND psr.scan_type = $2
         WHERE pca.repository_id = $1
           AND {not_index}
        "#,
        not_index = proxy_catalog::not_cached_index_sql("pca.path"),
    ))
    .bind(repo_id)
    .bind(crate::api::handlers::proxy_helpers::PROXY_SCAN_TYPE)
    .fetch_one(db)
    .await
    .map_err(|e| AppError::Database(e.to_string()))
}

/// One catalog path, scoped to `repo_id`. `None` is a 404 for both "no such
/// path" and "that path is another repository's".
async fn fetch_proxy_scan_path(
    db: &PgPool,
    repo_id: Uuid,
    path: &str,
) -> Result<Option<ProxyScanRow>> {
    sqlx::query_as::<_, ProxyScanRow>(&format!("{} AND pca.path = $3", proxy_scan_select()))
        .bind(repo_id)
        .bind(crate::api::handlers::proxy_helpers::PROXY_SCAN_TYPE)
        .bind(path)
        .fetch_optional(db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))
}

/// One page of catalog paths, newest cache entry first.
async fn fetch_proxy_scan_page(
    db: &PgPool,
    repo_id: Uuid,
    limit: i64,
    offset: i64,
) -> Result<Vec<ProxyScanRow>> {
    sqlx::query_as::<_, ProxyScanRow>(&format!(
        "{} AND pca.checksum_sha256 IS NOT NULL \
         ORDER BY pca.cached_at DESC, pca.path ASC LIMIT $3 OFFSET $4",
        proxy_scan_select()
    ))
    .bind(repo_id)
    .bind(crate::api::handlers::proxy_helpers::PROXY_SCAN_TYPE)
    .bind(limit)
    .bind(offset)
    .fetch_all(db)
    .await
    .map_err(|e| AppError::Database(e.to_string()))
}

/// Paths eligible for the paged list (NULL-checksum placeholders excluded, to
/// match the rows the page actually returns).
async fn count_proxy_scan_paths(db: &PgPool, repo_id: Uuid) -> Result<i64> {
    sqlx::query_scalar::<_, i64>(&format!(
        "SELECT COUNT(*) FROM proxy_cache_artifacts \
         WHERE repository_id = $1 AND checksum_sha256 IS NOT NULL AND {not_index}",
        not_index = proxy_catalog::not_cached_index_sql("path"),
    ))
    .bind(repo_id)
    .fetch_one(db)
    .await
    .map_err(|e| AppError::Database(e.to_string()))
}

#[utoipa::path(
    get,
    path = "/{key}/security/proxy-scans",
    context_path = "/api/v1/repositories",
    tag = "security",
    params(
        ("key" = String, Path, description = "Repository key"),
        ProxyScansQuery,
    ),
    responses(
        (status = 200, description = "Proxy scan verdicts for a repository", body = ProxyScansResponse),
        (status = 401, description = "Authentication required", body = crate::api::openapi::ErrorResponse),
        (status = 404, description = "Repository or path not found", body = crate::api::openapi::ErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
async fn get_repo_proxy_scans(
    State(state): State<SharedState>,
    Extension(auth): Extension<Option<AuthExtension>>,
    Path(key): Path<String>,
    Query(query): Query<ProxyScansQuery>,
) -> Result<Json<ProxyScansResponse>> {
    // Authentication FIRST, unconditionally. `require_visible` returns Ok early
    // for a public repository, so checking it first would make this endpoint
    // anonymously readable on exactly the repositories with the widest
    // audience -- the bug this feature exists to remove.
    let auth =
        auth.ok_or_else(|| AppError::Authentication("Authentication required".to_string()))?;
    // The /repositories nest is NOT gated by repo_visibility_middleware, so
    // enforce the canonical visibility gate here.
    let repo_service = RepositoryService::new(state.db.clone());
    let repo = repo_service.get_by_key(&key).await?;
    require_visible(&repo, &Some(auth), &repo_service).await?;
    let repo_id = repo.id;

    // Enforcement context. An absent config row is the default state, not an
    // error: it means scanning has never been enabled here.
    let config = ScanConfigService::new(state.db.clone())
        .get_config(repo_id)
        .await?;
    let scan_on_proxy = config.as_ref().is_some_and(|c| c.scan_on_proxy);
    let proxy_scan_action = config
        .as_ref()
        .map(|c| c.proxy_scan_action.clone())
        .unwrap_or_else(|| DEFAULT_PROXY_SCAN_ACTION.to_string());

    let (summary, items, total, page, per_page) = match query.path.as_deref() {
        Some(path) => {
            let row = fetch_proxy_scan_path(&state.db, repo_id, path)
                .await?
                .ok_or_else(|| AppError::NotFound(PROXY_PATH_NOT_FOUND_MSG.to_string()))?;
            let digest = row.checksum_sha256.clone();
            let entry = ProxyScanEntry::from_row(row, scan_on_proxy);
            // Per-CVE detail (#3395). Read by DIGEST, but only a digest this
            // repository's own catalog row already resolved to -- the caller
            // never supplies one, preserving the path-keyed property above.
            let entry = match digest {
                Some(d) if entry.state == PROXY_STATE_VULNERABLE => {
                    let findings = ProxyScanService::new(state.db.clone())
                        .fetch_findings(
                            &d,
                            crate::api::handlers::proxy_helpers::PROXY_SCAN_TYPE,
                            MAX_PROXY_FINDINGS,
                        )
                        .await?;
                    entry.with_findings(findings)
                }
                _ => entry,
            };
            (None, vec![entry], 1, 1, 1)
        }
        None => {
            let (page, per_page, offset) = proxy_scan_paging(query.page, query.per_page);
            let summary = fetch_proxy_scan_summary(&state.db, repo_id).await?;
            let total = count_proxy_scan_paths(&state.db, repo_id).await?;
            let items = fetch_proxy_scan_page(&state.db, repo_id, per_page, offset)
                .await?
                .into_iter()
                .map(|r| ProxyScanEntry::from_row(r, scan_on_proxy))
                .collect();
            (Some(summary), items, total, page, per_page)
        }
    };

    Ok(Json(ProxyScansResponse {
        repository_key: key,
        scan_on_proxy,
        proxy_scan_action,
        summary,
        items,
        total,
        page,
        per_page,
    }))
}

// ---------------------------------------------------------------------------
// On-demand rescan of an already-cached path (#3396)
//
// An artifact cached before inventory/CVE recording shipped has no SBOM and no
// per-CVE detail, and before this the only remedy was for someone to pull it
// again through a repository with scan-on-proxy enabled -- which the operator
// cannot force. `proxy_cache_artifacts.storage_key` is NOT NULL, so the bytes
// are already in object storage and a rescan reads them directly: no upstream
// fetch, no dependency on the artifact being requested again.
//
// The write path is `proxy_helpers::proxy_scan_and_record` -- the SAME function
// the inline gate calls. There is deliberately no second recording path, so a
// rescanned verdict and a pulled verdict cannot disagree.
// ---------------------------------------------------------------------------

/// Minimum interval between rescans **per repository**.
///
/// This endpoint converts one authenticated request into a full scanner run
/// over up to [`PROXY_SCAN_MAX_BYTES`](crate::services::scanner_service::PROXY_SCAN_MAX_BYTES)
/// of content, which is the most expensive thing a non-admin can ask this
/// service to do. The throttle is per repository rather than per path because
/// the cost being bounded is scanner work, and a caller cycling through 10 000
/// distinct cached paths would defeat a per-path limit entirely.
const PROXY_RESCAN_COOLDOWN: std::time::Duration = std::time::Duration::from_secs(30);

/// Last rescan per repository, for [`PROXY_RESCAN_COOLDOWN`].
///
/// In-process on purpose: this is a courtesy throttle on an authenticated,
/// write-gated endpoint, not a security control, and a shared-state limiter
/// would put a database round trip in front of every call. A multi-replica
/// deployment therefore allows one rescan per replica per window, which is
/// still bounded.
static PROXY_RESCAN_LAST: once_cell::sync::Lazy<
    std::sync::Mutex<std::collections::HashMap<Uuid, std::time::Instant>>,
> = once_cell::sync::Lazy::new(|| std::sync::Mutex::new(std::collections::HashMap::new()));

/// Whether a rescan is due, and if not, how long is left. Pure so the throttle
/// direction is testable without a clock or a request.
///
/// `None` (never rescanned) is always allowed. A `last` in the future -- which
/// `Instant` makes impossible in practice but a saturating subtraction would
/// silently absorb -- yields the full cooldown rather than allowing.
fn rescan_cooldown_remaining(
    last: Option<std::time::Instant>,
    now: std::time::Instant,
    cooldown: std::time::Duration,
) -> Option<std::time::Duration> {
    let last = last?;
    let elapsed = now.saturating_duration_since(last);
    (elapsed < cooldown).then(|| cooldown - elapsed)
}

/// Whether a cached object is small enough to rescan inline.
///
/// The same cap the download-time gate applies
/// ([`PROXY_SCAN_MAX_BYTES`](crate::services::scanner_service::PROXY_SCAN_MAX_BYTES)),
/// checked against the catalog row BEFORE any bytes are read. Without it this
/// endpoint would be the one place in the product that buffers an unbounded
/// proxy object into memory — and it would do so for an object the gate
/// declines to scan anyway, so the work could never produce a verdict worth
/// having.
///
/// A negative or absurd `size_bytes` (a corrupt catalog row) is refused rather
/// than treated as small.
fn rescan_size_is_scannable(size_bytes: i64) -> bool {
    (0..=crate::services::scanner_service::PROXY_SCAN_MAX_BYTES as i64).contains(&size_bytes)
}

/// Claim the rescan slot for `repo_id`, or report the remaining cooldown.
fn claim_rescan_slot(repo_id: Uuid) -> std::result::Result<(), std::time::Duration> {
    let now = std::time::Instant::now();
    let mut guard = PROXY_RESCAN_LAST
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    if let Some(remaining) =
        rescan_cooldown_remaining(guard.get(&repo_id).copied(), now, PROXY_RESCAN_COOLDOWN)
    {
        return Err(remaining);
    }
    guard.insert(repo_id, now);
    Ok(())
}

/// 429 for a rescan asked for inside the cooldown, with `Retry-After`.
fn rescan_throttled_response(remaining: std::time::Duration) -> axum::response::Response {
    use axum::response::IntoResponse;
    let secs = remaining.as_secs().max(1);
    (
        axum::http::StatusCode::TOO_MANY_REQUESTS,
        [(axum::http::header::RETRY_AFTER, secs.to_string())],
        Json(serde_json::json!({
            "error": "RESCAN_THROTTLED",
            "message": format!(
                "A proxy rescan was already run for this repository; retry in {secs}s"
            ),
        })),
    )
        .into_response()
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct ProxyRescanRequest {
    /// Cache path within this repository, e.g.
    /// `simple/click/click-8.0.0-py3-none-any.whl`. Path-keyed for the same
    /// cross-tenant reason the read endpoint is.
    pub path: String,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct ProxyRescanResponse {
    pub repository_key: String,
    pub path: String,
    pub digest: String,
    /// `clean` | `vulnerable` -- the verdict just recorded.
    pub state: String,
    pub findings_count: i32,
    pub critical_count: i32,
    pub high_count: i32,
    pub medium_count: i32,
    pub low_count: i32,
    pub max_severity: Option<String>,
    /// Components cataloged and persisted, i.e. how much SBOM this rescan
    /// produced. Zero means the scanner reported no inventory for these bytes.
    pub package_count: usize,
    /// Per-CVE detail from this run, bounded to [`MAX_PROXY_FINDINGS`].
    pub findings: Vec<crate::models::security::ProxyFinding>,
}

/// Rescan bytes already in the proxy cache, recording the verdict, package
/// inventory and per-CVE detail exactly as an inline gated pull would (#3396).
#[utoipa::path(
    post,
    path = "/{key}/security/proxy-scans/rescan",
    context_path = "/api/v1/repositories",
    tag = "security",
    params(("key" = String, Path, description = "Repository key")),
    request_body = ProxyRescanRequest,
    responses(
        (status = 200, description = "Rescan completed", body = ProxyRescanResponse),
        (status = 401, description = "Authentication required", body = crate::api::openapi::ErrorResponse),
        (status = 404, description = "Repository or path not found", body = crate::api::openapi::ErrorResponse),
        (status = 422, description = "Cached object is above the inline scan cap", body = crate::api::openapi::ErrorResponse),
        (status = 429, description = "Rescan cooldown in effect"),
        (status = 503, description = "No scanner configured, or the scan was inconclusive"),
    ),
    security(("bearer_auth" = []))
)]
async fn rescan_proxy_cached_path(
    State(state): State<SharedState>,
    Extension(auth): Extension<Option<AuthExtension>>,
    Path(key): Path<String>,
    Json(body): Json<ProxyRescanRequest>,
) -> Result<axum::response::Response> {
    use axum::response::IntoResponse;

    let auth =
        auth.ok_or_else(|| AppError::Authentication("Authentication required".to_string()))?;
    // Write access, not merely visibility: this spends scanner CPU and
    // rewrites a verdict that gates every tenant pulling the same digest.
    let repo_service = RepositoryService::new(state.db.clone());
    let repo = repo_service.get_by_key(&key).await?;
    require_repo_write_access(&auth, &repo, &repo_service).await?;

    let path = body.path.trim().to_string();
    if path.is_empty() {
        return Err(AppError::Validation("path must not be empty".to_string()));
    }

    // Resolve the path in THIS repository's catalog. Same canonical 404 as the
    // read endpoint, so a rescan cannot probe another tenant's cache.
    let entry = proxy_catalog::find_cached_entry(&state.db, repo.id, &path)
        .await?
        .ok_or_else(|| AppError::NotFound(PROXY_PATH_NOT_FOUND_MSG.to_string()))?;

    // Refuse an over-cap object BEFORE claiming the throttle slot or reading a
    // byte: the inline gate refuses these too, so buffering one here would be
    // the one place in the product where an unbounded proxy object is pulled
    // fully into memory.
    if !rescan_size_is_scannable(entry.size_bytes) {
        return Err(AppError::UnprocessableEntity(format!(
            "Cached object is {} bytes, above the {} byte inline scan cap; \
             the download-time gate does not scan it either",
            entry.size_bytes,
            crate::services::scanner_service::PROXY_SCAN_MAX_BYTES
        )));
    }

    if let Err(remaining) = claim_rescan_slot(repo.id) {
        return Ok(rescan_throttled_response(remaining));
    }

    // The storage error text is deliberately not echoed: it names storage keys
    // and backend internals, and the caller can act on none of it.
    let bytes = state.storage.get(&entry.storage_key).await.map_err(|e| {
        tracing::warn!(
            repo_id = %repo.id, path = %path, error = %e,
            "proxy rescan: cached bytes are no longer readable"
        );
        AppError::NotFound(PROXY_PATH_NOT_FOUND_MSG.to_string())
    })?;

    // The digest is recomputed from the bytes we just read rather than trusted
    // from the catalog row: the verdict is keyed on content, and recording a
    // verdict for these bytes under a stale row's digest would attach a scan
    // result to content nobody scanned.
    let digest = crate::api::handlers::proxy_helpers::sha256_hex(&bytes);
    let synthetic = crate::api::handlers::proxy_helpers::proxy_rescan_synthetic_artifact(
        repo.id,
        &path,
        &digest,
        bytes.len() as i64,
        entry.content_type.as_deref(),
    );

    // Identity is deliberately NOT asserted here. The inline gate can name the
    // coordinate a client asked for; a rescan of stored bytes cannot, and
    // inventing one would let a rescan record a `clean` verdict against an
    // identity the engine never graded (#3003). Passing `None` runs the same
    // code without the expected-component assertion.
    let verdict = crate::api::handlers::proxy_helpers::proxy_scan_and_record(
        &state,
        repo.id,
        &digest,
        &synthetic,
        &bytes,
        None,
        &crate::api::handlers::proxy_helpers::ProxyScanMode::File,
    )
    .await
    .ok_or_else(|| {
        AppError::ServiceUnavailable(
            "Rescan was inconclusive: no scanner is configured, or the scan failed or \
             exceeded its budget. The stored verdict is unchanged."
                .to_string(),
        )
    })?;

    let mut findings = verdict.findings.clone();
    findings.truncate(MAX_PROXY_FINDINGS as usize);

    Ok(Json(ProxyRescanResponse {
        repository_key: key,
        path,
        digest,
        state: verdict.verdict_token().to_string(),
        findings_count: verdict.findings_count,
        critical_count: verdict.critical_count,
        high_count: verdict.high_count,
        medium_count: verdict.medium_count,
        low_count: verdict.low_count,
        max_severity: verdict.max_severity_token().map(str::to_string),
        package_count: verdict.packages.len(),
        findings,
    })
    .into_response())
}

#[derive(OpenApi)]
#[openapi(
    paths(
        get_dashboard,
        get_all_scores,
        list_scan_configs,
        trigger_scan,
        list_scans,
        get_scan,
        list_findings,
        acknowledge_finding,
        revoke_acknowledgment,
        list_policies,
        create_policy,
        get_policy,
        update_policy,
        delete_policy,
        get_repo_security,
        update_repo_security,
        list_artifact_scans,
        list_repo_scans,
        get_repo_proxy_scans,
        rescan_proxy_cached_path,
    ),
    components(schemas(
        DashboardResponse,
        ScoreResponse,
        TriggerScanRequest,
        TriggerScanResponse,
        ScanListResponse,
        ScanResponse,
        FindingListResponse,
        FindingResponse,
        AcknowledgeRequest,
        CreatePolicyRequest,
        UpdatePolicyRequest,
        PolicyResponse,
        RepoSecurityResponse,
        ScanConfigResponse,
        ProxyScansResponse,
        ProxyScanSummary,
        ProxyScanEntry,
        ProxyRescanRequest,
        ProxyRescanResponse,
        crate::models::security::ProxyFinding,
    ))
)]
pub struct SecurityApiDoc;

#[cfg(test)]
mod tests {
    use super::*;

    /// Cross-tenant authz guard (xtenant-write-authz-systemic). The repo-scoped
    /// security endpoints live under the /repositories nest (not gated by
    /// repo_visibility_middleware), so each must enforce the tenant gate itself.
    /// Assert the write handler calls `require_repo_write_access` and the read
    /// handlers call `require_visible`. String-grep because the handlers need a
    /// full DB-backed `SharedState` to run.
    /// Source text of one top-level `async fn` in this module, for the
    /// authorization guards that cannot instantiate a DB-backed `SharedState`.
    ///
    /// The slice is bounded at the function's own closing brace (`\n}\n` at
    /// column zero), NOT at the next `\nasync fn ` declaration: the async
    /// helpers inside `mod tests` are indented, so a declaration-bounded slice
    /// runs to EOF for the last handler in the file and matches the assertions
    /// against the tests' own source, passing regardless of the handler.
    fn handler_body(handler: &str) -> &'static str {
        let source = include_str!("security.rs");
        let marker = format!("async fn {}(", handler);
        let start = source
            .find(&marker)
            .unwrap_or_else(|| panic!("handler `{}` not found", handler));
        let rest = &source[start + marker.len()..];
        let end = rest.find("\n}\n").unwrap_or(rest.len());
        &rest[..end]
    }

    #[test]
    fn test_repo_security_handlers_enforce_tenant_gate() {
        let body_of = handler_body;
        // Class-level, not per-site: every repo-scoped WRITE handler in this
        // module must carry the tenant write gate. Listing them here means a
        // handler added later fails this test by omission rather than by
        // someone remembering to extend it.
        for writer in ["update_repo_security", "rescan_proxy_cached_path"] {
            assert!(
                body_of(writer).contains("require_repo_write_access("),
                "{} must call require_repo_write_access (xtenant)",
                writer
            );
        }
        assert!(
            body_of("update_repo_security").contains("require_repo_admin("),
            "update_repo_security must call require_repo_admin (#2750): scan \
             configuration is a supply-chain control on the repository-admin \
             tier; `write` (artifact publishing) must not suffice to disable \
             scanning or the block-on-severity gate"
        );
        for reader in [
            "get_repo_security",
            "list_repo_scans",
            "get_repo_proxy_scans",
        ] {
            assert!(
                body_of(reader).contains("require_visible("),
                "{} must call require_visible (xtenant)",
                reader
            );
        }
    }

    /// The proxy-scan endpoint must demand authentication BEFORE
    /// `require_visible`, which returns `Ok(())` early for a public repository.
    /// Reversing the two lines silently makes verdict counts and per-CVE-adjacent
    /// detail anonymously readable on every public proxy repository -- the
    /// largest audience of a public registry, and the exact regression this
    /// feature exists to prevent. Source-grep because the handler needs a
    /// DB-backed `SharedState` to run; the DB-backed counterpart is
    /// `proxy_scans_requires_auth_even_on_public_repo`.
    #[test]
    fn proxy_scans_authenticates_before_visibility_check() {
        let body = handler_body("get_repo_proxy_scans");
        let auth_at = body
            .find("auth.ok_or_else(")
            .expect("get_repo_proxy_scans must reject an unauthenticated caller");
        let visible_at = body
            .find("require_visible(")
            .expect("get_repo_proxy_scans must call require_visible");
        assert!(
            auth_at < visible_at,
            "get_repo_proxy_scans must reject anonymous callers BEFORE \
             require_visible, which returns early for public repositories"
        );
    }

    /// The join to `proxy_scan_results` must filter on the shared
    /// `PROXY_SCAN_TYPE` constant, not a literal. `uq_proxy_scan` is
    /// `(checksum_sha256, scan_type)`, so an unfiltered join fans one cached
    /// path into one row per scan type -- inflating every count -- the day a
    /// second scanner writes verdicts.
    #[test]
    fn proxy_scan_queries_filter_on_scan_type_constant() {
        assert!(
            proxy_scan_select().contains("psr.scan_type = $2"),
            "the shared projection must filter the join on scan_type"
        );
        let source = include_str!("security.rs");
        // Build the needle at runtime: a literal here would be found in this
        // test's own source and fail unconditionally.
        let hardcoded = format!("scan_type = '{}'", "grype");
        assert!(
            !source.contains(&hardcoded),
            "bind PROXY_SCAN_TYPE rather than hardcoding the scanner name"
        );
        for fetcher in [
            "fetch_proxy_scan_summary",
            "fetch_proxy_scan_path",
            "fetch_proxy_scan_page",
        ] {
            assert!(
                handler_body(fetcher).contains("PROXY_SCAN_TYPE"),
                "{} must bind PROXY_SCAN_TYPE",
                fetcher
            );
        }
    }

    /// `proxy_scan_results.repository_id` is provenance for whichever tenant
    /// happened to scan the bytes first. Verdicts are shared by digest across
    /// the deployment, so returning it would name another tenant to any
    /// authenticated caller. It must not appear in the projection or the wire
    /// types.
    #[test]
    fn proxy_scan_projection_never_selects_repository_id() {
        let select = proxy_scan_select();
        let (projection, _) = select
            .split_once("FROM proxy_cache_artifacts")
            .expect("projection must read from the cache catalog");
        assert!(
            !projection.contains("repository_id"),
            "the proxy-scan projection must not select repository_id: {}",
            projection
        );
        assert!(
            !select.contains("psr.repository_id"),
            "proxy_scan_results.repository_id is another tenant's provenance"
        );
        let entry = ProxyScanEntry::from_row(sample_proxy_row(), true);
        let json = serde_json::to_string(&entry).expect("serialize");
        assert!(
            !json.contains("repository_id"),
            "ProxyScanEntry must not expose repository_id: {}",
            json
        );
    }

    fn sample_proxy_row() -> ProxyScanRow {
        ProxyScanRow {
            path: "simple/click/click-8.0.0-py3-none-any.whl".to_string(),
            checksum_sha256: Some("a".repeat(64)),
            size_bytes: 1234,
            cached_at: chrono::Utc::now(),
            verdict: Some("clean".to_string()),
            findings_count: Some(0),
            critical_count: Some(0),
            high_count: Some(0),
            medium_count: Some(0),
            low_count: Some(0),
            max_severity: None,
            scanned_at: Some(chrono::Utc::now()),
        }
    }

    #[test]
    fn proxy_scan_state_maps_verdicts_and_null_checksums() {
        let digest = "b".repeat(64);
        assert_eq!(
            proxy_scan_state(Some(&digest), Some("clean")),
            PROXY_STATE_CLEAN
        );
        assert_eq!(
            proxy_scan_state(Some(&digest), Some("vulnerable")),
            PROXY_STATE_VULNERABLE
        );
        assert_eq!(
            proxy_scan_state(Some(&digest), None),
            PROXY_STATE_NOT_SCANNED
        );
        // `error` has no production writer; it must never render as clean.
        assert_eq!(
            proxy_scan_state(Some(&digest), Some("error")),
            PROXY_STATE_NOT_SCANNED
        );
        // A NULL checksum wins over any verdict: there cannot be one, and the
        // row must not be counted as `not_scanned`.
        assert_eq!(proxy_scan_state(None, None), PROXY_STATE_PENDING_INGEST);
        assert_eq!(
            proxy_scan_state(None, Some("clean")),
            PROXY_STATE_PENDING_INGEST
        );
    }

    /// An absent `scan_configs` row is the default state (nothing creates one
    /// at repository creation), and `is_proxy_scan_enabled` reads it as
    /// `false`. The handler collapses "absent" and "false" into a single
    /// `scan_on_proxy: false`, and both must report `scanning_disabled`.
    #[test]
    fn proxy_not_scanned_reason_covers_disabled_and_unknown() {
        assert_eq!(
            proxy_not_scanned_reason(PROXY_STATE_NOT_SCANNED, false),
            Some(PROXY_REASON_SCANNING_DISABLED)
        );
        assert_eq!(
            proxy_not_scanned_reason(PROXY_STATE_NOT_SCANNED, true),
            Some(PROXY_REASON_UNKNOWN)
        );
        // Never attached to a state that carries a verdict.
        for state in [
            PROXY_STATE_CLEAN,
            PROXY_STATE_VULNERABLE,
            PROXY_STATE_PENDING_INGEST,
        ] {
            assert_eq!(proxy_not_scanned_reason(state, false), None);
        }
    }

    /// Verdicts are global by digest, so a raw `scanned_at` predating the
    /// caller's own `cached_at` proves some other repository in the deployment
    /// pulled byte-identical content earlier, and dates it. Flooring removes
    /// that tenant-activity oracle.
    #[test]
    fn floor_scanned_at_hides_other_tenants_earlier_pull() {
        let cached = chrono::Utc::now();
        let earlier = cached - chrono::Duration::days(30);
        let later = cached + chrono::Duration::hours(2);
        assert_eq!(floor_scanned_at(Some(earlier), cached), Some(cached));
        assert_eq!(floor_scanned_at(Some(later), cached), Some(later));
        assert_eq!(floor_scanned_at(Some(cached), cached), Some(cached));
        assert_eq!(floor_scanned_at(None, cached), None);
    }

    #[test]
    fn proxy_scan_paging_clamps_input() {
        assert_eq!(proxy_scan_paging(None, None), (1, 50, 0));
        assert_eq!(proxy_scan_paging(Some(3), Some(10)), (3, 10, 20));
        // Out-of-range input must not produce a negative OFFSET or an
        // unbounded LIMIT.
        assert_eq!(proxy_scan_paging(Some(0), Some(0)), (1, 1, 0));
        assert_eq!(proxy_scan_paging(Some(-5), Some(-5)), (1, 1, 0));
        assert_eq!(proxy_scan_paging(Some(2), Some(10_000)), (2, 200, 200));
    }

    /// A `not_scanned` entry must carry NO counts. Serving `findings_count: 0`
    /// for an unscanned artifact is indistinguishable from a clean verdict on
    /// the wire and is the same "implied clean" failure the feature removes.
    #[test]
    fn proxy_scan_entry_suppresses_counts_without_a_verdict() {
        let mut row = sample_proxy_row();
        row.verdict = None;
        row.findings_count = Some(0);
        row.critical_count = Some(0);
        row.max_severity = Some("high".to_string());
        let scanned = chrono::Utc::now() - chrono::Duration::days(1);
        row.scanned_at = Some(scanned);

        let entry = ProxyScanEntry::from_row(row, false);
        assert_eq!(entry.state, PROXY_STATE_NOT_SCANNED);
        assert_eq!(
            entry.not_scanned_reason.as_deref(),
            Some(PROXY_REASON_SCANNING_DISABLED)
        );
        assert_eq!(entry.findings_count, None);
        assert_eq!(entry.critical_count, None);
        assert_eq!(entry.max_severity, None);
        assert_eq!(entry.scanned_at, None);
    }

    #[test]
    fn proxy_scan_entry_projects_a_vulnerable_verdict() {
        let mut row = sample_proxy_row();
        row.verdict = Some("vulnerable".to_string());
        row.findings_count = Some(7);
        row.critical_count = Some(1);
        row.high_count = Some(2);
        row.medium_count = Some(3);
        row.low_count = Some(1);
        row.max_severity = Some("critical".to_string());
        row.scanned_at = Some(row.cached_at - chrono::Duration::days(9));
        let cached_at = row.cached_at;

        let entry = ProxyScanEntry::from_row(row, true);
        assert_eq!(entry.state, PROXY_STATE_VULNERABLE);
        assert_eq!(entry.not_scanned_reason, None);
        assert_eq!(entry.findings_count, Some(7));
        assert_eq!(entry.critical_count, Some(1));
        assert_eq!(entry.high_count, Some(2));
        assert_eq!(entry.medium_count, Some(3));
        assert_eq!(entry.low_count, Some(1));
        assert_eq!(entry.max_severity.as_deref(), Some("critical"));
        // Floored at this repository's own cached_at.
        assert_eq!(entry.scanned_at, Some(cached_at));
        assert_eq!(entry.size_bytes, 1234);
    }

    /// A placeholder catalog row (checksum never backfilled after an aborted
    /// tee or client disconnect) is its own state, never `not_scanned` and
    /// never clean.
    #[test]
    fn proxy_scan_entry_reports_pending_ingest_for_null_checksum() {
        let mut row = sample_proxy_row();
        row.checksum_sha256 = None;
        let entry = ProxyScanEntry::from_row(row, true);
        assert_eq!(entry.state, PROXY_STATE_PENDING_INGEST);
        assert_eq!(entry.digest, None);
        assert_eq!(entry.not_scanned_reason, None);
        assert_eq!(entry.findings_count, None);
        assert_eq!(entry.scanned_at, None);
    }

    /// `stale` was dropped by product decision: it is only reachable for
    /// digests nobody has pulled in the TTL window (pulling through a scanning
    /// repository re-scans and refreshes `scanned_at`), and there is no remedy
    /// affordance to attach to it. Guard against it being reintroduced by
    /// copy-paste from an earlier draft of the design.
    #[test]
    fn proxy_scan_response_has_no_stale_field() {
        let entry = ProxyScanEntry::from_row(sample_proxy_row(), true);
        let json = serde_json::to_value(&entry).expect("serialize");
        assert!(
            json.get("stale").is_none(),
            "`stale` was dropped from this iteration: {}",
            json
        );
    }

    /// The `?path=` read omits the summary; the list read carries it.
    #[test]
    fn proxy_scans_response_omits_summary_for_a_single_path() {
        let response = ProxyScansResponse {
            repository_key: "pypi-proxy".to_string(),
            scan_on_proxy: false,
            proxy_scan_action: DEFAULT_PROXY_SCAN_ACTION.to_string(),
            summary: None,
            items: vec![ProxyScanEntry::from_row(sample_proxy_row(), false)],
            total: 1,
            page: 1,
            per_page: 1,
        };
        let json = serde_json::to_value(&response).expect("serialize");
        assert!(json.get("summary").is_none());
        // Enforcement context is always present: without it `vulnerable` is
        // ambiguous between "pulls are blocked" and "served anyway".
        assert_eq!(json["scan_on_proxy"], serde_json::json!(false));
        assert_eq!(json["proxy_scan_action"], serde_json::json!("fail_open"));
    }

    // -----------------------------------------------------------------------
    // Per-CVE detail attachment (#3395) -- pure
    // -----------------------------------------------------------------------

    fn sample_proxy_finding() -> crate::models::security::ProxyFinding {
        crate::models::security::ProxyFinding {
            cve_id: "CVE-2019-14806".to_string(),
            severity: "high".to_string(),
            package_name: Some("werkzeug".to_string()),
            package_version: Some("0.15.0".to_string()),
            fixed_version: Some("0.15.3".to_string()),
            title: Some("Pallets Werkzeug insecure default".to_string()),
        }
    }

    /// Detail is attached ONLY to a `vulnerable` entry.
    ///
    /// The failure this prevents is specific: attaching an empty CVE list to a
    /// `not_scanned` or `pending_ingest` entry renders in a UI as "we looked
    /// and found nothing", which is the false all-clear this whole surface
    /// exists to remove. A `clean` entry is excluded too — its detail is the
    /// absence of findings, already carried by `findings_count: 0`.
    #[test]
    fn proxy_findings_attach_only_to_a_vulnerable_entry() {
        let detail = vec![sample_proxy_finding()];

        let mut row = sample_proxy_row();
        row.verdict = Some(PROXY_STATE_VULNERABLE.to_string());
        let vulnerable = ProxyScanEntry::from_row(row, true).with_findings(detail.clone());
        assert_eq!(vulnerable.state, PROXY_STATE_VULNERABLE);
        assert_eq!(vulnerable.findings.as_deref(), Some(&detail[..]));

        for (verdict, expected_state) in [
            (Some(PROXY_STATE_CLEAN.to_string()), PROXY_STATE_CLEAN),
            (None, PROXY_STATE_NOT_SCANNED),
        ] {
            let mut row = sample_proxy_row();
            row.verdict = verdict;
            let entry = ProxyScanEntry::from_row(row, true).with_findings(detail.clone());
            assert_eq!(entry.state, expected_state);
            assert!(
                entry.findings.is_none(),
                "{expected_state} must not carry a CVE list"
            );
        }

        // pending_ingest: NULL checksum, so there is nothing to look up.
        let mut row = sample_proxy_row();
        row.checksum_sha256 = None;
        row.verdict = Some(PROXY_STATE_VULNERABLE.to_string());
        let pending = ProxyScanEntry::from_row(row, true).with_findings(detail);
        assert_eq!(pending.state, PROXY_STATE_PENDING_INGEST);
        assert!(pending.findings.is_none());
    }

    /// `None` and `Some([])` must stay distinguishable on the wire.
    ///
    /// `None` (the field omitted) means "not requested at this granularity" —
    /// which is every row of the paged listing. `Some([])` means "requested,
    /// and this digest has no recorded detail", the real state of anything
    /// cached before #3395 shipped. Collapsing the two makes a pre-#3395
    /// artifact render as a vulnerable artifact with no CVEs.
    #[test]
    fn absent_and_empty_proxy_findings_are_different_on_the_wire() {
        let mut row = sample_proxy_row();
        row.verdict = Some(PROXY_STATE_VULNERABLE.to_string());
        let listed = ProxyScanEntry::from_row(row.clone(), true);
        let json = serde_json::to_value(&listed).expect("serialize");
        assert!(
            json.get("findings").is_none(),
            "the paged listing omits the field entirely: {json}"
        );

        let detailed = ProxyScanEntry::from_row(row, true).with_findings(vec![]);
        let json = serde_json::to_value(&detailed).expect("serialize");
        assert_eq!(
            json["findings"],
            serde_json::json!([]),
            "an empty list is present, not omitted: {json}"
        );
    }

    // -----------------------------------------------------------------------
    // Rescan throttle (#3396) -- pure
    // -----------------------------------------------------------------------

    /// The throttle direction, over every shape the clock can produce.
    ///
    /// A never-rescanned repository is always allowed; inside the window the
    /// REMAINING time is reported (it becomes `Retry-After`, so an inverted
    /// subtraction would advertise a wait longer than the cooldown); at and
    /// after the boundary it is allowed again.
    #[test]
    fn rescan_cooldown_allows_first_call_and_reports_remaining_inside_the_window() {
        let cooldown = std::time::Duration::from_secs(30);
        let now = std::time::Instant::now();

        assert!(
            rescan_cooldown_remaining(None, now, cooldown).is_none(),
            "a repository that has never been rescanned is never throttled"
        );

        let just_now = now - std::time::Duration::from_secs(1);
        let remaining =
            rescan_cooldown_remaining(Some(just_now), now, cooldown).expect("inside the window");
        assert_eq!(remaining, std::time::Duration::from_secs(29));
        assert!(
            remaining <= cooldown,
            "remaining can never exceed the cooldown itself"
        );

        // Exactly at the boundary is allowed: `elapsed < cooldown` is strict,
        // so a caller polling `Retry-After` succeeds on its first retry rather
        // than being told to wait again.
        assert!(rescan_cooldown_remaining(Some(now - cooldown), now, cooldown).is_none());
        assert!(rescan_cooldown_remaining(
            Some(now - cooldown - std::time::Duration::from_secs(1)),
            now,
            cooldown
        )
        .is_none());

        // A `last` in the future must not underflow into "allowed forever".
        let future = now + std::time::Duration::from_secs(5);
        assert_eq!(
            rescan_cooldown_remaining(Some(future), now, cooldown),
            Some(cooldown),
            "saturating subtraction yields the full cooldown, never an allow"
        );
    }

    /// The rescan size cap mirrors the download-time gate exactly, and a
    /// corrupt catalog row (negative size) is refused rather than treated as
    /// small — the direction that would otherwise let a bad row through the
    /// one check standing between this endpoint and an unbounded buffer.
    #[test]
    fn rescan_size_cap_matches_the_download_gate_and_rejects_absurd_rows() {
        let cap = crate::services::scanner_service::PROXY_SCAN_MAX_BYTES as i64;
        assert!(rescan_size_is_scannable(0));
        assert!(rescan_size_is_scannable(1024));
        assert!(rescan_size_is_scannable(cap), "the cap itself is inclusive");
        assert!(!rescan_size_is_scannable(cap + 1));
        assert!(!rescan_size_is_scannable(-1));
        assert!(!rescan_size_is_scannable(i64::MAX));
    }

    /// Claiming the slot is one-shot per window and per repository: two
    /// different repositories do not throttle each other.
    #[test]
    fn claim_rescan_slot_is_per_repository_and_one_shot() {
        let a = Uuid::new_v4();
        let b = Uuid::new_v4();
        assert!(claim_rescan_slot(a).is_ok(), "first claim wins");
        let denied = claim_rescan_slot(a).expect_err("second claim inside the window");
        assert!(denied <= PROXY_RESCAN_COOLDOWN);
        assert!(
            claim_rescan_slot(b).is_ok(),
            "a different repository has its own budget"
        );
    }

    /// The throttle response is a 429 carrying `Retry-After`, not a 4xx a
    /// client would retry immediately or treat as permanent.
    #[test]
    fn rescan_throttled_response_is_429_with_retry_after() {
        let resp = rescan_throttled_response(std::time::Duration::from_secs(7));
        assert_eq!(resp.status(), axum::http::StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(
            resp.headers()
                .get(axum::http::header::RETRY_AFTER)
                .and_then(|v| v.to_str().ok()),
            Some("7")
        );
        // Sub-second remainders must not advertise `Retry-After: 0`, which
        // invites an immediate retry that is guaranteed to fail.
        let resp = rescan_throttled_response(std::time::Duration::from_millis(200));
        assert_eq!(
            resp.headers()
                .get(axum::http::header::RETRY_AFTER)
                .and_then(|v| v.to_str().ok()),
            Some("1")
        );
    }

    // -----------------------------------------------------------------------
    // Rescan inconclusive-cause discrimination (#3455) -- RED probe
    // -----------------------------------------------------------------------

    // streaming-invariant: test-only body read, not an artifact path (#1608)
    #[allow(clippy::disallowed_methods)]
    async fn json_body(resp: axum::response::Response) -> serde_json::Value {
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .expect("read body");
        serde_json::from_slice(&bytes).expect("json body")
    }

    /// DB-backed regression proving the actual endpoint discriminates, not
    /// just the pure response builder above. This is the genuine red -> green
    /// case for #3455: pre-fix, `proxy_scan_and_record` returned `None` for
    /// EVERY inconclusive cause and this handler's `.ok_or_else` turned that
    /// into one indistinguishable `AppError::ServiceUnavailable` -- so this
    /// test's `.expect` panics (not a compile error, not a setup failure)
    /// against that code, and passes once the handler discriminates.
    #[tokio::test]
    async fn rescan_with_no_scanner_configured_returns_discriminated_503() {
        use crate::api::handlers::test_db_helpers as tdh;
        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let fx = ProxyScanFixture::new(pool.clone()).await;
        let digest = unique_digest();
        let path = "simple/x/x-1.0.whl";
        seed_cached_path(&pool, fx.repo_id, path, Some(&digest), chrono::Utc::now()).await;
        // `seed_cached_path` only inserts the catalog row; the handler also
        // reads the bytes back from storage at the SAME key it computed
        // (`proxy-cache/{repo_id}/{path}/__content__`), so the object must
        // actually exist there too or the handler 404s before it ever
        // reaches the scanner gate this test is probing.
        fx.state()
            .storage
            .put(
                &format!("proxy-cache/{}/{}/__content__", fx.repo_id, path),
                bytes::Bytes::from_static(b"stub cached bytes"),
            )
            .await
            .expect("seed cached bytes in storage");

        let auth = crate::api::handlers::test_db_helpers::make_auth(fx.user_id, &fx.username);
        let body = ProxyRescanRequest {
            path: path.to_string(),
        };
        let result = rescan_proxy_cached_path(
            State(fx.state()),
            Extension(Some(auth)),
            Path(fx.key.clone()),
            Json(body),
        )
        .await;

        let resp = result.expect(
            "an inconclusive rescan must be a built 503 Response (Ok(_)), not \
             an AppError -- the pre-#3455 handler propagated a single generic \
             AppError::ServiceUnavailable for every cause here",
        );
        assert_eq!(resp.status(), axum::http::StatusCode::SERVICE_UNAVAILABLE);
        let json = json_body(resp).await;
        assert_eq!(
            json["error"],
            serde_json::json!("NO_SCANNER_CONFIGURED"),
            "must name the specific cause, not a generic inconclusive message"
        );

        fx.cleanup(&[digest]).await;
    }

    // -----------------------------------------------------------------------
    // Proxy scan visibility -- DB-backed
    // -----------------------------------------------------------------------

    /// A user with visibility into a fresh proxy repository, plus the read that
    /// every DB-backed case below performs. Factored out so the four tests
    /// carry only their own fixtures and assertions.
    struct ProxyScanFixture {
        pool: PgPool,
        user_id: Uuid,
        username: String,
        repo_id: Uuid,
        key: String,
        dir: std::path::PathBuf,
    }

    impl ProxyScanFixture {
        async fn new(pool: PgPool) -> Self {
            use crate::api::handlers::test_db_helpers as tdh;
            let (user_id, username) = tdh::create_user(&pool).await;
            let (repo_id, key, dir) = tdh::create_repo(&pool, "remote", "pypi").await;
            tdh::grant_repo_access(&pool, repo_id, user_id).await;
            Self {
                pool,
                user_id,
                username,
                repo_id,
                key,
                dir,
            }
        }

        fn state(&self) -> SharedState {
            crate::api::handlers::test_db_helpers::build_state(
                self.pool.clone(),
                self.dir.to_string_lossy().as_ref(),
            )
        }

        async fn read(&self, query: ProxyScansQuery) -> Result<Json<ProxyScansResponse>> {
            let auth =
                crate::api::handlers::test_db_helpers::make_auth(self.user_id, &self.username);
            get_repo_proxy_scans(
                State(self.state()),
                Extension(Some(auth)),
                Path(self.key.clone()),
                Query(query),
            )
            .await
        }

        /// Read and unwrap, for the cases where a failure is a test bug.
        async fn read_ok(&self, query: ProxyScansQuery) -> ProxyScansResponse {
            self.read(query).await.expect("proxy-scan read").0
        }

        /// `proxy_scan_results` rows survive repository deletion (the FK is
        /// `ON DELETE SET NULL`), so digest-keyed fixtures are removed by hand.
        async fn cleanup(self, digests: &[String]) {
            let _ = sqlx::query("DELETE FROM proxy_scan_results WHERE checksum_sha256 = ANY($1)")
                .bind(digests)
                .execute(&self.pool)
                .await;
            let _ = sqlx::query("DELETE FROM scan_configs WHERE repository_id = $1")
                .bind(self.repo_id)
                .execute(&self.pool)
                .await;
            crate::api::handlers::test_db_helpers::cleanup(&self.pool, self.repo_id, self.user_id)
                .await;
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }

    /// Insert one `proxy_cache_artifacts` row for `repo_id`.
    async fn seed_cached_path(
        pool: &PgPool,
        repo_id: Uuid,
        path: &str,
        checksum: Option<&str>,
        cached_at: chrono::DateTime<chrono::Utc>,
    ) {
        sqlx::query(
            "INSERT INTO proxy_cache_artifacts \
             (repository_id, path, storage_key, metadata_key, size_bytes, \
              checksum_sha256, cached_at) \
             VALUES ($1, $2, $3, $4, 1024, $5, $6)",
        )
        .bind(repo_id)
        .bind(path)
        .bind(format!("proxy-cache/{}/{}/__content__", repo_id, path))
        .bind(format!(
            "proxy-cache/{}/{}/__cache_meta__.json",
            repo_id, path
        ))
        .bind(checksum)
        .bind(cached_at)
        .execute(pool)
        .await
        .expect("seed proxy_cache_artifacts");
    }

    /// Insert one digest-keyed verdict. `scan_type` is a parameter so the
    /// scan-type filter can be exercised with a second scanner's row.
    async fn seed_proxy_verdict(
        pool: &PgPool,
        checksum: &str,
        scan_type: &str,
        verdict: &str,
        findings: i32,
        scanned_at: chrono::DateTime<chrono::Utc>,
    ) {
        let vulnerable = verdict == PROXY_STATE_VULNERABLE;
        sqlx::query(
            "INSERT INTO proxy_scan_results \
             (checksum_sha256, scan_type, verdict, findings_count, critical_count, \
              max_severity, scanned_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7)",
        )
        .bind(checksum)
        .bind(scan_type)
        .bind(verdict)
        .bind(findings)
        .bind(i32::from(vulnerable))
        .bind(vulnerable.then_some("critical"))
        .bind(scanned_at)
        .execute(pool)
        .await
        .expect("seed proxy_scan_results");
    }

    /// Shorthand for seeding a grype verdict, the scan type this endpoint reads.
    async fn seed_grype_verdict(
        pool: &PgPool,
        checksum: &str,
        verdict: &str,
        findings: i32,
        scanned_at: chrono::DateTime<chrono::Utc>,
    ) {
        seed_proxy_verdict(
            pool,
            checksum,
            crate::api::handlers::proxy_helpers::PROXY_SCAN_TYPE,
            verdict,
            findings,
            scanned_at,
        )
        .await;
    }

    /// A digest unique to this test run: `proxy_scan_results` is global by
    /// content hash, so fixtures must not collide across parallel tests.
    fn unique_digest() -> String {
        format!("{:0>64}", Uuid::new_v4().simple())
    }

    /// The endpoint must 401 an anonymous caller even on a PUBLIC repository.
    /// `require_visible` returns `Ok(())` immediately for `is_public`, so a
    /// handler that gated on visibility alone would publish verdict counts to
    /// the internet. DB-backed counterpart of
    /// `proxy_scans_authenticates_before_visibility_check`.
    #[tokio::test]
    async fn proxy_scans_requires_auth_even_on_public_repo() {
        use crate::api::handlers::test_db_helpers as tdh;
        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let fx = ProxyScanFixture::new(pool).await;
        sqlx::query("UPDATE repositories SET is_public = true WHERE id = $1")
            .bind(fx.repo_id)
            .execute(&fx.pool)
            .await
            .expect("make repo public");

        let anon = get_repo_proxy_scans(
            State(fx.state()),
            Extension(None),
            Path(fx.key.clone()),
            Query(ProxyScansQuery::default()),
        )
        .await;
        assert!(
            matches!(anon, Err(AppError::Authentication(_))),
            "anonymous read of a PUBLIC repo's proxy scans must 401, got {:?}",
            anon.map(|_| "ok")
        );

        // The same request authenticated succeeds, proving the 401 came from
        // the auth gate and not from a missing repository.
        let ok = fx.read_ok(ProxyScansQuery::default()).await;
        assert_eq!(ok.summary.expect("summary"), ProxyScanSummary::default());

        fx.cleanup(&[]).await;
    }

    /// Route registration and the wire status code, over the real URL rather
    /// than a direct handler call: a typo in the path would make every
    /// unauthenticated probe 404 instead of 401, which is indistinguishable
    /// from "this deployment does not have the feature" and would silently
    /// leave the web on its fallback rendering.
    #[tokio::test]
    async fn proxy_scans_route_is_mounted_and_401s_anonymously() {
        use crate::api::handlers::test_db_helpers as tdh;
        use axum::body::Body;
        use axum::http::{Request, StatusCode};
        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let fx = ProxyScanFixture::new(pool).await;
        let app = tdh::router_anon(repo_security_router(), fx.state());
        let (status, _body) = tdh::send(
            app,
            Request::builder()
                .uri(format!("/{}/security/proxy-scans", fx.key))
                .body(Body::empty())
                .expect("request"),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::UNAUTHORIZED,
            "the route must be mounted and reject anonymous callers"
        );

        let app = tdh::router_with_auth(
            repo_security_router(),
            fx.state(),
            tdh::make_auth(fx.user_id, &fx.username),
        );
        let (status, body) = tdh::send(
            app,
            Request::builder()
                .uri(format!("/{}/security/proxy-scans?per_page=5", fx.key))
                .body(Body::empty())
                .expect("request"),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let json: serde_json::Value = serde_json::from_slice(&body).expect("json body");
        assert_eq!(json["repository_key"], serde_json::json!(fx.key));
        assert_eq!(json["per_page"], serde_json::json!(5));
        assert_eq!(json["summary"]["total_digests"], serde_json::json!(0));
        assert!(
            !String::from_utf8_lossy(&body).contains("repository_id"),
            "the wire response must not carry repository_id"
        );

        fx.cleanup(&[]).await;
    }

    /// Summary counts DISTINCT DIGESTS, not paths: one repository routinely
    /// caches the same bytes at several paths. NULL-checksum placeholders are
    /// excluded from every state and reported as `pending_ingest` so the totals
    /// still reconcile with the artifact listing.
    #[tokio::test]
    async fn proxy_scans_summary_counts_distinct_digests() {
        use crate::api::handlers::test_db_helpers as tdh;
        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let fx = ProxyScanFixture::new(pool).await;
        let now = chrono::Utc::now();
        let (clean, vuln, unscanned) = (unique_digest(), unique_digest(), unique_digest());
        let seed = |path: &'static str, sum: Option<String>| {
            let (pool, repo_id) = (fx.pool.clone(), fx.repo_id);
            async move { seed_cached_path(&pool, repo_id, path, sum.as_deref(), now).await }
        };

        // The same clean digest cached at two paths is ONE clean digest.
        seed("simple/a/a-1.0.whl", Some(clean.clone())).await;
        seed("simple/a/a-1.0-copy.whl", Some(clean.clone())).await;
        seed("simple/b/b-1.0.whl", Some(vuln.clone())).await;
        seed("simple/c/c-1.0.whl", Some(unscanned.clone())).await;
        // Placeholder row: the checksum was never backfilled.
        seed("simple/d/d-1.0.whl", None).await;
        seed_grype_verdict(&fx.pool, &clean, PROXY_STATE_CLEAN, 0, now).await;
        seed_grype_verdict(&fx.pool, &vuln, PROXY_STATE_VULNERABLE, 4, now).await;

        let resp = fx.read_ok(ProxyScansQuery::default()).await;

        let summary = resp.summary.expect("list read carries a summary");
        assert_eq!(
            summary,
            ProxyScanSummary {
                clean: 1,
                vulnerable: 1,
                not_scanned: 1,
                pending_ingest: 1,
                total_digests: 3,
            },
            "summary must count distinct digests and bucket the placeholder"
        );
        assert_eq!(
            summary.clean + summary.vulnerable + summary.not_scanned,
            summary.total_digests,
            "per-state counts must partition the distinct digests"
        );
        // The paged list is over PATHS and excludes the placeholder row.
        assert_eq!(resp.total, 4);
        assert_eq!(resp.items.len(), 4);
        assert!(
            resp.items
                .iter()
                .all(|i| i.state != PROXY_STATE_PENDING_INGEST),
            "NULL-checksum rows must not appear in the paged list"
        );
        // Scanning was never configured for this repository -> the absent
        // `scan_configs` row must read as disabled, not as `unknown`.
        assert!(!resp.scan_on_proxy);
        assert_eq!(resp.proxy_scan_action, DEFAULT_PROXY_SCAN_ACTION);
        let not_scanned = resp
            .items
            .iter()
            .find(|i| i.state == PROXY_STATE_NOT_SCANNED)
            .expect("one not_scanned entry");
        assert_eq!(
            not_scanned.not_scanned_reason.as_deref(),
            Some(PROXY_REASON_SCANNING_DISABLED)
        );

        fx.cleanup(&[clean, vuln]).await;
    }

    /// Two guarantees on the `?path=` read:
    ///   * it resolves only within the calling repository, so a path cached by
    ///     someone else 404s with the same body as a path nobody cached;
    ///   * `scanned_at` is floored at the caller's own `cached_at`, so the
    ///     response cannot date another tenant's earlier pull of identical
    ///     bytes.
    #[tokio::test]
    async fn proxy_scans_path_lookup_is_repo_scoped_and_floors_scanned_at() {
        use crate::api::handlers::test_db_helpers as tdh;
        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let fx = ProxyScanFixture::new(pool.clone()).await;
        let (other_id, _other_key, other_dir) = tdh::create_repo(&pool, "remote", "pypi").await;

        let digest = unique_digest();
        // Truncated to MICROSECONDS at the source. `Utc::now()` carries
        // nanoseconds; `timestamptz` stores microseconds, so a raw `now()`
        // compares unequal to its own round trip whenever the clock hands back
        // a non-zero nanosecond remainder -- which is most of the time on CI
        // and rarely on a developer's machine. That asymmetry is what made this
        // assertion look flaky rather than wrong.
        let cached_at = chrono::SubsecRound::trunc_subsecs(chrono::Utc::now(), 6);
        // Another tenant pulled byte-identical content a month before we did.
        let scanned_at = cached_at - chrono::Duration::days(30);
        seed_cached_path(
            &pool,
            fx.repo_id,
            "simple/x/x-1.0.whl",
            Some(&digest),
            cached_at,
        )
        .await;
        seed_cached_path(
            &pool,
            other_id,
            "simple/secret/s-1.0.whl",
            Some(&digest),
            cached_at,
        )
        .await;
        seed_grype_verdict(&pool, &digest, PROXY_STATE_CLEAN, 0, scanned_at).await;

        let query = |path: &str| ProxyScansQuery {
            path: Some(path.to_string()),
            ..Default::default()
        };

        let mine = fx.read_ok(query("simple/x/x-1.0.whl")).await;
        assert!(mine.summary.is_none(), "path read omits the summary");
        assert_eq!(mine.items.len(), 1);
        assert_eq!(mine.items[0].state, PROXY_STATE_CLEAN);
        assert_eq!(
            mine.items[0].scanned_at,
            Some(cached_at),
            "scanned_at must be floored at this repository's own cached_at"
        );

        // The other repository's path is cached, and shares our digest, but is
        // not ours: the same 404 as a path that was never cached at all.
        let foreign = fx.read(query("simple/secret/s-1.0.whl")).await;
        let absent = fx.read(query("simple/never/n-1.0.whl")).await;
        let msg = |r: Result<Json<ProxyScansResponse>>| match r {
            Err(AppError::NotFound(m)) => m,
            other => panic!("expected NotFound, got {:?}", other.map(|_| "ok")),
        };
        assert_eq!(msg(foreign), msg(absent), "404 bodies must be identical");

        fx.cleanup(&[digest]).await;
        tdh::cleanup_member_repo(&pool, other_id, &other_dir).await;
    }

    /// End to end for #3395: the `?path=` read answers "which CVE blocked my
    /// build?" for a vulnerable proxy-cached path, and stays silent for a
    /// clean one.
    ///
    /// The digest is never accepted from the caller — it comes from THIS
    /// repository's own catalog row — so the detail read inherits the
    /// path-keyed scoping the listing already has. That is asserted here by
    /// reading a path another repository cached at the same digest: it 404s
    /// rather than yielding the detail.
    #[tokio::test]
    async fn proxy_scan_path_read_returns_per_cve_detail_for_a_vulnerable_path() {
        use crate::api::handlers::test_db_helpers as tdh;
        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let fx = ProxyScanFixture::new(pool.clone()).await;
        let (other_id, _other_key, other_dir) = tdh::create_repo(&pool, "remote", "pypi").await;

        let vuln = unique_digest();
        let clean = unique_digest();
        let now = chrono::Utc::now();
        seed_cached_path(&pool, fx.repo_id, "simple/w/w-0.15.0.whl", Some(&vuln), now).await;
        seed_cached_path(&pool, fx.repo_id, "simple/c/c-1.0.whl", Some(&clean), now).await;
        // Another tenant holds the same vulnerable bytes at its own path.
        seed_cached_path(&pool, other_id, "simple/secret/s.whl", Some(&vuln), now).await;
        seed_grype_verdict(&pool, &vuln, PROXY_STATE_VULNERABLE, 2, now).await;
        seed_grype_verdict(&pool, &clean, PROXY_STATE_CLEAN, 0, now).await;

        ProxyScanService::new(pool.clone())
            .record_findings(
                &vuln,
                crate::api::handlers::proxy_helpers::PROXY_SCAN_TYPE,
                &[
                    crate::models::security::ProxyFinding {
                        cve_id: "CVE-2019-14806".to_string(),
                        severity: "high".to_string(),
                        package_name: Some("werkzeug".to_string()),
                        package_version: Some("0.15.0".to_string()),
                        fixed_version: Some("0.15.3".to_string()),
                        title: Some("insecure default".to_string()),
                    },
                    crate::models::security::ProxyFinding {
                        cve_id: "CVE-2020-28724".to_string(),
                        severity: "critical".to_string(),
                        package_name: Some("werkzeug".to_string()),
                        package_version: Some("0.15.0".to_string()),
                        fixed_version: None,
                        title: None,
                    },
                ],
            )
            .await
            .expect("record findings");

        let query = |path: &str| ProxyScansQuery {
            path: Some(path.to_string()),
            ..Default::default()
        };

        let detail = fx.read_ok(query("simple/w/w-0.15.0.whl")).await;
        let entry = &detail.items[0];
        assert_eq!(entry.state, PROXY_STATE_VULNERABLE);
        let findings = entry
            .findings
            .as_ref()
            .expect("vulnerable path carries CVEs");
        assert_eq!(
            findings
                .iter()
                .map(|f| f.cve_id.as_str())
                .collect::<Vec<_>>(),
            vec!["CVE-2020-28724", "CVE-2019-14806"],
            "most severe first, so a truncated render shows what matters"
        );
        assert_eq!(findings[1].fixed_version.as_deref(), Some("0.15.3"));

        // Clean: no list at all, so it can never render as "we looked".
        let clean_read = fx.read_ok(query("simple/c/c-1.0.whl")).await;
        assert_eq!(clean_read.items[0].state, PROXY_STATE_CLEAN);
        assert!(clean_read.items[0].findings.is_none());

        // The paged listing never carries detail (N+1 avoidance, and it is an
        // overview surface).
        let listed = fx.read_ok(ProxyScansQuery::default()).await;
        assert!(
            listed.items.iter().all(|i| i.findings.is_none()),
            "the listing must not fan out one detail query per row"
        );

        // Cross-tenant: same digest, another repository's path, still a 404.
        match fx.read(query("simple/secret/s.whl")).await {
            Err(AppError::NotFound(m)) => assert_eq!(m, PROXY_PATH_NOT_FOUND_MSG),
            other => panic!("expected NotFound, got {:?}", other.map(|_| "ok")),
        }

        let _ = sqlx::query("DELETE FROM proxy_scan_findings WHERE checksum_sha256 = $1")
            .bind(&vuln)
            .execute(&pool)
            .await;
        fx.cleanup(&[vuln, clean]).await;
        tdh::cleanup_member_repo(&pool, other_id, &other_dir).await;
    }

    /// The rescan endpoint resolves its path in the CALLER's catalog only, and
    /// answers the canonical proxy 404 for anything else — so it cannot be
    /// used to probe another tenant's cache, and cannot be used to spend
    /// scanner CPU on a path the caller cannot see. Asserted before the
    /// throttle is claimed, so a probe cannot even consume the caller's own
    /// rescan budget.
    #[tokio::test]
    async fn rescan_rejects_paths_outside_the_callers_catalog() {
        use crate::api::handlers::test_db_helpers as tdh;
        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let fx = ProxyScanFixture::new(pool.clone()).await;
        let (other_id, _other_key, other_dir) = tdh::create_repo(&pool, "remote", "pypi").await;
        let digest = unique_digest();
        let now = chrono::Utc::now();
        seed_cached_path(&pool, other_id, "simple/secret/s.whl", Some(&digest), now).await;

        let rescan = |path: &str| {
            let state = fx.state();
            let auth = tdh::make_auth(fx.user_id, &fx.username);
            let key = fx.key.clone();
            let body = ProxyRescanRequest {
                path: path.to_string(),
            };
            async move {
                rescan_proxy_cached_path(State(state), Extension(Some(auth)), Path(key), Json(body))
                    .await
            }
        };

        let msg = |r: Result<axum::response::Response>| match r {
            Err(AppError::NotFound(m)) => m,
            other => panic!("expected NotFound, got {:?}", other.map(|_| "ok")),
        };
        assert_eq!(
            msg(rescan("simple/secret/s.whl").await),
            PROXY_PATH_NOT_FOUND_MSG,
            "another tenant's cached path is indistinguishable from an absent one"
        );
        assert_eq!(
            msg(rescan("simple/never/n.whl").await),
            PROXY_PATH_NOT_FOUND_MSG
        );

        // An empty path is a client error, not a 404 — a 404 would imply the
        // server looked something up.
        match rescan("   ").await {
            Err(AppError::Validation(_)) => {}
            other => panic!("expected Validation, got {:?}", other.map(|_| "ok")),
        }

        fx.cleanup(&[digest]).await;
        tdh::cleanup_member_repo(&pool, other_id, &other_dir).await;
    }

    /// `uq_proxy_scan` is `(checksum_sha256, scan_type)`, so a second scanner
    /// writing verdicts for the same digest is legal. The join must filter on
    /// `PROXY_SCAN_TYPE`: unfiltered, the entry would either duplicate or pick
    /// up a foreign scanner's verdict.
    #[tokio::test]
    async fn proxy_scans_ignore_other_scan_types() {
        use crate::api::handlers::test_db_helpers as tdh;
        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let fx = ProxyScanFixture::new(pool.clone()).await;
        let digest = unique_digest();
        let now = chrono::Utc::now();
        seed_cached_path(&pool, fx.repo_id, "simple/y/y-1.0.whl", Some(&digest), now).await;
        // A different scan type only. The grype-keyed read must not see it.
        seed_proxy_verdict(&pool, &digest, "trivy", PROXY_STATE_CLEAN, 0, now).await;

        // Turn proxy scanning ON so the reason distinguishes "disabled" from
        // "no row for this scanner".
        ScanConfigService::new(pool.clone())
            .upsert_config(
                fx.repo_id,
                &UpsertScanConfigRequest {
                    scan_on_proxy: Some(true),
                    ..Default::default()
                },
            )
            .await
            .expect("enable scan_on_proxy");

        let resp = fx.read_ok(ProxyScansQuery::default()).await;

        assert!(resp.scan_on_proxy, "enforcement context must be reported");
        assert_eq!(resp.items.len(), 1, "the join must not duplicate the path");
        assert_eq!(resp.items[0].state, PROXY_STATE_NOT_SCANNED);
        assert_eq!(
            resp.items[0].not_scanned_reason.as_deref(),
            Some(PROXY_REASON_UNKNOWN),
            "scanning is enabled, so the reason is unknown -- not disabled"
        );
        let summary = resp.summary.expect("summary");
        assert_eq!(summary.not_scanned, 1);
        assert_eq!(summary.clean, 0);

        fx.cleanup(&[digest]).await;
    }

    /// A pull-through cache stores the upstream INDEX responses beside the
    /// packages, and they were counted as unscanned items. That is a permanent
    /// false positive in a security view: an HTML index page has no package
    /// inventory, so no scan can ever clear it and the operator is shown an
    /// "unknown" status with no available remedy.
    ///
    /// This is the reported fixture exactly -- two packages and their two
    /// index pages. The true unscanned count is ZERO.
    #[tokio::test]
    async fn proxy_scans_exclude_cached_index_responses() {
        use crate::api::handlers::test_db_helpers as tdh;
        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let fx = ProxyScanFixture::new(pool).await;
        let now = chrono::Utc::now();
        let (clean, vuln) = (unique_digest(), unique_digest());
        let seed = |path: &'static str, sum: Option<String>| {
            let (pool, repo_id) = (fx.pool.clone(), fx.repo_id);
            async move { seed_cached_path(&pool, repo_id, path, sum.as_deref(), now).await }
        };

        seed("simple/idna/", Some(unique_digest())).await;
        seed(
            "simple/idna/idna-3.18-py3-none-any.whl",
            Some(clean.clone()),
        )
        .await;
        seed("simple/pyyaml/", Some(unique_digest())).await;
        seed("simple/pyyaml/PyYAML-5.3.1.tar.gz", Some(vuln.clone())).await;
        // The PEP 691 JSON index, which has a basename rather than a trailing
        // slash. Also a placeholder index row: excluded before it can be
        // counted as `pending_ingest`.
        seed("simple/idna/index.v1+json", Some(unique_digest())).await;
        seed("simple/pyyaml/index.v1+json", None).await;
        seed_grype_verdict(&fx.pool, &clean, PROXY_STATE_CLEAN, 0, now).await;
        seed_grype_verdict(&fx.pool, &vuln, PROXY_STATE_VULNERABLE, 3, now).await;

        let resp = fx.read_ok(ProxyScansQuery::default()).await;
        let summary = resp.summary.expect("summary");
        assert_eq!(
            summary,
            ProxyScanSummary {
                clean: 1,
                vulnerable: 1,
                not_scanned: 0,
                pending_ingest: 0,
                total_digests: 2,
            },
            "index responses are not artifacts and must not be counted"
        );
        let listed: Vec<&str> = resp.items.iter().map(|i| i.path.as_str()).collect();
        assert_eq!(
            listed.len(),
            2,
            "only the two packages are listed, got {:?}",
            listed
        );
        assert!(
            listed.contains(&"simple/idna/idna-3.18-py3-none-any.whl")
                && listed.contains(&"simple/pyyaml/PyYAML-5.3.1.tar.gz"),
            "got {:?}",
            listed
        );
        assert_eq!(resp.total, 2, "`total` must match the filtered listing");

        // The single-path read agrees: an index path is not an artifact here.
        let index_lookup = fx
            .read(ProxyScansQuery {
                path: Some("simple/idna/".to_string()),
                ..Default::default()
            })
            .await;
        assert!(
            matches!(index_lookup, Err(AppError::NotFound(_))),
            "a cached index path must not resolve as an artifact"
        );

        fx.cleanup(&[clean, vuln]).await;
    }

    /// The exclusion must be narrow. A package whose name legitimately looks
    /// index-like still has to list and still has to be scanned -- silently
    /// dropping a real artifact from a security view is a worse failure than
    /// the false positive this filter removes.
    #[tokio::test]
    async fn proxy_scans_keep_artifacts_with_index_like_names() {
        use crate::api::handlers::test_db_helpers as tdh;
        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let fx = ProxyScanFixture::new(pool).await;
        let now = chrono::Utc::now();
        let seed = |path: &'static str| {
            let (pool, repo_id) = (fx.pool.clone(), fx.repo_id);
            let digest = unique_digest();
            async move {
                seed_cached_path(&pool, repo_id, path, Some(&digest), now).await;
                digest
            }
        };

        // A package literally named `index`; a file whose basename merely ENDS
        // with the index basename; and a detached signature over an index.
        let digests = vec![
            seed("simple/index/index-1.0.tar.gz").await,
            seed("simple/foo/my-index.v1+json").await,
            seed("simple/foo/index.v1+json.asc").await,
        ];

        let resp = fx.read_ok(ProxyScansQuery::default()).await;
        let summary = resp.summary.expect("summary");
        assert_eq!(
            summary.total_digests, 3,
            "index-like artifact names must not be filtered out"
        );
        assert_eq!(
            summary.not_scanned, 3,
            "they are real artifacts with no verdict, so they stay unscanned"
        );
        assert_eq!(resp.items.len(), 3);

        fx.cleanup(&digests).await;
    }

    /// Paging must not run off the end of the catalog, and `total` counts the
    /// paths the list can return (placeholders excluded), so a client can page
    /// to exactly the last entry.
    #[tokio::test]
    async fn proxy_scans_pages_the_catalog() {
        use crate::api::handlers::test_db_helpers as tdh;
        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let fx = ProxyScanFixture::new(pool.clone()).await;
        let base = chrono::Utc::now();
        let mut digests = Vec::new();
        for i in 0..3i64 {
            let d = unique_digest();
            seed_cached_path(
                &pool,
                fx.repo_id,
                &format!("simple/p/p-{}.whl", i),
                Some(&d),
                base - chrono::Duration::minutes(i),
            )
            .await;
            digests.push(d);
        }
        seed_cached_path(&pool, fx.repo_id, "simple/p/pending.whl", None, base).await;

        let page = |page: i64| ProxyScansQuery {
            path: None,
            page: Some(page),
            per_page: Some(2),
        };

        let first = fx.read_ok(page(1)).await;
        assert_eq!(first.total, 3, "placeholder rows are not listable");
        assert_eq!(first.per_page, 2);
        assert_eq!(first.items.len(), 2);
        // Newest cache entry first.
        assert_eq!(first.items[0].path, "simple/p/p-0.whl");

        let second = fx.read_ok(page(2)).await;
        assert_eq!(second.page, 2);
        assert_eq!(second.items.len(), 1);
        assert_eq!(second.items[0].path, "simple/p/p-2.whl");

        assert!(
            fx.read_ok(page(9)).await.items.is_empty(),
            "past the end is empty"
        );

        fx.cleanup(&digests).await;
    }

    /// DB-backed (#2750, sibling of #2603): a non-admin member holding only
    /// `write` (developer role via `grant_repo_access`, no fine-grained `admin`
    /// grant) is DENIED `update_repo_security`, and the denied request must not
    /// persist a scan config; granting the repository `admin` action lets it
    /// through; a global admin always passes. Scan configuration gates the
    /// vulnerability-scanning / block-on-severity supply chain, so write-level
    /// access (artifact publishing) must not suffice to disable it.
    #[tokio::test]
    async fn update_repo_security_requires_repo_admin_db() {
        use crate::api::handlers::test_db_helpers as tdh;
        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let (user_id, username) = tdh::create_user(&pool).await;
        let (repo_id, key, dir) = tdh::create_repo(&pool, "local", "generic").await;
        // Write-level membership only (developer role): passes the tenant gate.
        tdh::grant_repo_access(&pool, repo_id, user_id).await;
        let state = tdh::build_state(pool.clone(), dir.to_string_lossy().as_ref());
        let auth = tdh::make_auth(user_id, &username);

        // The exploit shape: turn scanning and the block-on-severity gate off.
        let body = || UpsertScanConfigRequest {
            scan_enabled: Some(false),
            block_on_policy_violation: Some(false),
            ..Default::default()
        };

        // 1) Write-only member -> 403, and nothing persisted.
        let denied = update_repo_security(
            State(state.clone()),
            Extension(Some(auth.clone())),
            Path(key.clone()),
            Json(body()),
        )
        .await;
        assert!(
            matches!(denied, Err(AppError::Authorization(_))),
            "write-only member must be denied (403) update_repo_security: {denied:?}"
        );
        let persisted = ScanConfigService::new(pool.clone())
            .get_config(repo_id)
            .await
            .expect("get_config");
        assert!(
            persisted.is_none(),
            "denied update_repo_security must not persist a scan config"
        );

        // 2) Grant repository `admin` -> allowed. Rebuild state so the
        // permission-service cache (which recorded the pre-grant deny above)
        // is empty and the new grant is resolved from the database.
        tdh::grant_repo_admin(&pool, repo_id, user_id).await;
        let state = tdh::build_state(pool.clone(), dir.to_string_lossy().as_ref());
        let allowed = update_repo_security(
            State(state.clone()),
            Extension(Some(auth.clone())),
            Path(key.clone()),
            Json(body()),
        )
        .await;
        assert!(
            allowed.is_ok(),
            "repo-admin member must pass update_repo_security: {allowed:?}"
        );

        // 3) Global admin -> allowed.
        let admin = tdh::admin_auth(Uuid::new_v4(), "root");
        let admin_ok = update_repo_security(
            State(state.clone()),
            Extension(Some(admin)),
            Path(key.clone()),
            Json(UpsertScanConfigRequest {
                scan_enabled: Some(true),
                ..Default::default()
            }),
        )
        .await;
        assert!(
            admin_ok.is_ok(),
            "global admin must pass update_repo_security: {admin_ok:?}"
        );

        tdh::cleanup(&pool, repo_id, user_id).await;
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Admin gate on the GLOBAL security-policy write handlers. The global
    /// /api/v1/security/policies write endpoints must be admin-only, matching
    /// every sibling governance endpoint; otherwise any authenticated user can
    /// disable/delete org-wide scan policies. String-grep because the handlers
    /// need a full DB-backed `SharedState` to run.
    #[test]
    fn test_global_policy_write_handlers_require_admin() {
        for writer in ["create_policy", "update_policy", "delete_policy"] {
            assert!(
                handler_body(writer).contains("require_admin("),
                "{} must call require_admin (global policy write is admin-only)",
                writer
            );
        }
    }

    // -----------------------------------------------------------------------
    // Pure helper functions (testable without DB)
    // -----------------------------------------------------------------------

    /// Compute scan list pagination values.
    /// Returns `(page, per_page, offset)`.
    fn compute_scan_pagination(
        raw_page: Option<i64>,
        raw_per_page: Option<i64>,
    ) -> (i64, i64, i64) {
        let page = raw_page.unwrap_or(1);
        let per_page = raw_per_page.unwrap_or(20).min(100);
        let offset = (page - 1) * per_page;
        (page, per_page, offset)
    }

    /// Compute findings pagination values.
    /// Returns `(page, per_page, offset)`.
    fn compute_findings_pagination(
        raw_page: Option<i64>,
        raw_per_page: Option<i64>,
    ) -> (i64, i64, i64) {
        let page = raw_page.unwrap_or(1);
        let per_page = raw_per_page.unwrap_or(50).min(200);
        let offset = (page - 1) * per_page;
        (page, per_page, offset)
    }

    /// Build the trigger scan response message for a single artifact.
    fn build_artifact_scan_message(artifact_id: Uuid) -> TriggerScanResponse {
        TriggerScanResponse {
            message: format!("Scan queued for artifact {}", artifact_id),
            artifacts_queued: 1,
            scan_result_ids: Vec::new(),
        }
    }

    /// Build the trigger scan response message for a repository scan.
    fn build_repo_scan_message(repository_id: Uuid, count: i64) -> TriggerScanResponse {
        TriggerScanResponse {
            message: format!(
                "Repository scan queued for {} ({} artifacts)",
                repository_id, count
            ),
            artifacts_queued: count as u32,
            scan_result_ids: Vec::new(),
        }
    }

    /// Build a JSON response for successful deletion.
    fn build_deleted_response() -> serde_json::Value {
        serde_json::json!({ "deleted": true })
    }

    /// Convert a ScanResult model into a ScanResponse DTO with artifact info.
    fn scan_result_to_response(
        s: ScanResult,
        artifact_name: Option<String>,
        artifact_version: Option<String>,
    ) -> ScanResponse {
        ScanResponse::from_scan(s, artifact_name, artifact_version)
    }

    // -----------------------------------------------------------------------
    // compute_scan_pagination
    // -----------------------------------------------------------------------

    #[test]
    fn test_compute_scan_pagination_defaults() {
        let (page, per_page, offset) = compute_scan_pagination(None, None);
        assert_eq!(page, 1);
        assert_eq!(per_page, 20);
        assert_eq!(offset, 0);
    }

    #[test]
    fn test_compute_scan_pagination_page_2() {
        let (page, per_page, offset) = compute_scan_pagination(Some(2), Some(50));
        assert_eq!(page, 2);
        assert_eq!(per_page, 50);
        assert_eq!(offset, 50);
    }

    #[test]
    fn test_compute_scan_pagination_page_3() {
        let (page, per_page, offset) = compute_scan_pagination(Some(3), Some(10));
        assert_eq!(page, 3);
        assert_eq!(per_page, 10);
        assert_eq!(offset, 20);
    }

    #[test]
    fn test_compute_scan_pagination_capped_per_page() {
        let (_page, per_page, _offset) = compute_scan_pagination(Some(1), Some(500));
        assert_eq!(per_page, 100);
    }

    #[test]
    fn test_compute_scan_pagination_large_page() {
        let (page, per_page, offset) = compute_scan_pagination(Some(100), Some(20));
        assert_eq!(page, 100);
        assert_eq!(per_page, 20);
        assert_eq!(offset, 1980);
    }

    // -----------------------------------------------------------------------
    // compute_findings_pagination
    // -----------------------------------------------------------------------

    #[test]
    fn test_compute_findings_pagination_defaults() {
        let (page, per_page, offset) = compute_findings_pagination(None, None);
        assert_eq!(page, 1);
        assert_eq!(per_page, 50);
        assert_eq!(offset, 0);
    }

    #[test]
    fn test_compute_findings_pagination_page_2() {
        let (page, per_page, offset) = compute_findings_pagination(Some(2), Some(100));
        assert_eq!(page, 2);
        assert_eq!(per_page, 100);
        assert_eq!(offset, 100);
    }

    #[test]
    fn test_compute_findings_pagination_capped() {
        let (_page, per_page, _offset) = compute_findings_pagination(Some(1), Some(1000));
        assert_eq!(per_page, 200);
    }

    #[test]
    fn test_compute_findings_pagination_page_3_custom() {
        let (page, per_page, offset) = compute_findings_pagination(Some(3), Some(25));
        assert_eq!(page, 3);
        assert_eq!(per_page, 25);
        assert_eq!(offset, 50);
    }

    // -----------------------------------------------------------------------
    // build_artifact_scan_message
    // -----------------------------------------------------------------------

    #[test]
    fn test_build_artifact_scan_message() {
        let id = Uuid::new_v4();
        let resp = build_artifact_scan_message(id);
        assert_eq!(resp.artifacts_queued, 1);
        assert!(resp.message.contains(&id.to_string()));
        assert!(resp.message.contains("Scan queued for artifact"));
    }

    #[test]
    fn test_build_artifact_scan_message_nil_uuid() {
        let resp = build_artifact_scan_message(Uuid::nil());
        assert_eq!(resp.artifacts_queued, 1);
        assert!(resp
            .message
            .contains("00000000-0000-0000-0000-000000000000"));
    }

    // -----------------------------------------------------------------------
    // build_repo_scan_message
    // -----------------------------------------------------------------------

    #[test]
    fn test_build_repo_scan_message() {
        let id = Uuid::new_v4();
        let resp = build_repo_scan_message(id, 42);
        assert_eq!(resp.artifacts_queued, 42);
        assert!(resp.message.contains(&id.to_string()));
        assert!(resp.message.contains("42 artifacts"));
    }

    #[test]
    fn test_build_repo_scan_message_zero_artifacts() {
        let id = Uuid::new_v4();
        let resp = build_repo_scan_message(id, 0);
        assert_eq!(resp.artifacts_queued, 0);
        assert!(resp.message.contains("0 artifacts"));
    }

    #[test]
    fn test_build_repo_scan_message_large_count() {
        let id = Uuid::new_v4();
        let resp = build_repo_scan_message(id, 10000);
        assert_eq!(resp.artifacts_queued, 10000);
        assert!(resp.message.contains("10000 artifacts"));
    }

    // -----------------------------------------------------------------------
    // build_deleted_response
    // -----------------------------------------------------------------------

    #[test]
    fn test_build_deleted_response() {
        let resp = build_deleted_response();
        assert_eq!(resp["deleted"], true);
    }

    #[test]
    fn test_build_deleted_response_only_one_key() {
        let resp = build_deleted_response();
        let obj = resp.as_object().unwrap();
        assert_eq!(obj.len(), 1);
    }

    // -----------------------------------------------------------------------
    // scan_result_to_response / ScanResponse::from_scan
    // -----------------------------------------------------------------------

    fn make_scan_result() -> ScanResult {
        ScanResult {
            id: Uuid::new_v4(),
            artifact_id: Uuid::new_v4(),
            repository_id: Uuid::new_v4(),
            scan_type: "trivy".to_string(),
            status: "completed".to_string(),
            findings_count: 10,
            critical_count: 2,
            high_count: 3,
            medium_count: 4,
            low_count: 1,
            info_count: 0,
            scanner_version: Some("0.50.0".to_string()),
            error_message: None,
            started_at: Some(chrono::Utc::now()),
            completed_at: Some(chrono::Utc::now()),
            created_at: chrono::Utc::now(),
            is_reused: false,
            source_scan_id: None,
        }
    }

    #[test]
    fn test_scan_response_from_scan_with_artifact_info() {
        let scan = make_scan_result();
        let scan_id = scan.id;
        let resp = scan_result_to_response(
            scan,
            Some("my-artifact".to_string()),
            Some("1.0.0".to_string()),
        );
        assert_eq!(resp.id, scan_id);
        assert_eq!(resp.scan_type, "trivy");
        assert_eq!(resp.status, "completed");
        assert_eq!(resp.findings_count, 10);
        assert_eq!(resp.critical_count, 2);
        assert_eq!(resp.high_count, 3);
        assert_eq!(resp.medium_count, 4);
        assert_eq!(resp.low_count, 1);
        assert_eq!(resp.info_count, 0);
        assert_eq!(resp.scanner_version, Some("0.50.0".to_string()));
        assert_eq!(resp.error_message, None);
        assert_eq!(resp.artifact_name, Some("my-artifact".to_string()));
        assert_eq!(resp.artifact_version, Some("1.0.0".to_string()));
    }

    #[test]
    fn test_scan_response_from_scan_no_artifact_info() {
        let scan = ScanResult {
            id: Uuid::new_v4(),
            artifact_id: Uuid::new_v4(),
            repository_id: Uuid::new_v4(),
            scan_type: "vulnerability".to_string(),
            status: "failed".to_string(),
            findings_count: 0,
            critical_count: 0,
            high_count: 0,
            medium_count: 0,
            low_count: 0,
            info_count: 0,
            scanner_version: None,
            error_message: Some("Scanner not available".to_string()),
            started_at: None,
            completed_at: None,
            created_at: chrono::Utc::now(),
            is_reused: false,
            source_scan_id: None,
        };
        let resp = scan_result_to_response(scan, None, None);
        assert_eq!(resp.artifact_name, None);
        assert_eq!(resp.artifact_version, None);
        assert_eq!(
            resp.error_message,
            Some("Scanner not available".to_string())
        );
        assert_eq!(resp.status, "failed");
        assert!(!resp.is_reused);
        assert!(resp.source_scan_id.is_none());
    }

    #[test]
    fn test_scan_response_preserves_all_counts() {
        let scan = ScanResult {
            id: Uuid::new_v4(),
            artifact_id: Uuid::new_v4(),
            repository_id: Uuid::new_v4(),
            scan_type: "license".to_string(),
            status: "completed".to_string(),
            findings_count: 100,
            critical_count: 10,
            high_count: 20,
            medium_count: 30,
            low_count: 25,
            info_count: 15,
            scanner_version: Some("2.0".to_string()),
            error_message: None,
            started_at: Some(chrono::Utc::now()),
            completed_at: Some(chrono::Utc::now()),
            created_at: chrono::Utc::now(),
            is_reused: false,
            source_scan_id: None,
        };
        let resp = scan_result_to_response(scan, Some("lib".to_string()), None);
        assert_eq!(resp.findings_count, 100);
        assert_eq!(resp.critical_count, 10);
        assert_eq!(resp.high_count, 20);
        assert_eq!(resp.medium_count, 30);
        assert_eq!(resp.low_count, 25);
        assert_eq!(resp.info_count, 15);
    }

    #[test]
    fn test_scan_response_propagates_reuse_metadata() {
        let source_id = Uuid::new_v4();
        let scan = ScanResult {
            id: Uuid::new_v4(),
            artifact_id: Uuid::new_v4(),
            repository_id: Uuid::new_v4(),
            scan_type: "trivy".to_string(),
            status: "completed".to_string(),
            findings_count: 7,
            critical_count: 1,
            high_count: 2,
            medium_count: 2,
            low_count: 2,
            info_count: 0,
            scanner_version: None,
            error_message: None,
            started_at: Some(chrono::Utc::now()),
            completed_at: Some(chrono::Utc::now()),
            created_at: chrono::Utc::now(),
            is_reused: true,
            source_scan_id: Some(source_id),
        };
        let resp = scan_result_to_response(scan, Some("artifact".into()), None);
        assert!(resp.is_reused);
        assert_eq!(resp.source_scan_id, Some(source_id));
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["is_reused"], true);
        assert_eq!(json["source_scan_id"], source_id.to_string());
    }

    /// B13 / #1373: a reused row must report the SOURCE scan id as its `id`
    /// so two byte-identical artifacts surface the same logical scan_id. The
    /// release-gate `scan-dedup-checksum` suite reads `.items[0].id` from each
    /// artifact's `/scans` list and asserts they are equal. Before this fix the
    /// reused row reported its own placeholder id, so the ids differed and the
    /// assertion failed.
    #[test]
    fn test_scan_response_reused_row_reports_source_scan_id_as_id() {
        let placeholder_id = Uuid::new_v4();
        let source_id = Uuid::new_v4();
        let scan = ScanResult {
            id: placeholder_id,
            artifact_id: Uuid::new_v4(),
            repository_id: Uuid::new_v4(),
            scan_type: "trivy".to_string(),
            status: "completed".to_string(),
            findings_count: 3,
            critical_count: 1,
            high_count: 1,
            medium_count: 1,
            low_count: 0,
            info_count: 0,
            scanner_version: None,
            error_message: None,
            started_at: Some(chrono::Utc::now()),
            completed_at: Some(chrono::Utc::now()),
            created_at: chrono::Utc::now(),
            is_reused: true,
            source_scan_id: Some(source_id),
        };
        let resp = scan_result_to_response(scan, None, None);
        assert_eq!(
            resp.id, source_id,
            "reused row must report the source scan id as its id (B13)"
        );
        // provenance is still exposed verbatim.
        assert_eq!(resp.source_scan_id, Some(source_id));
        assert!(resp.is_reused);
    }

    /// A reused row with `source_scan_id == None` (should not happen in
    /// practice, but guard against a partial write) falls back to its own id
    /// rather than panicking or emitting a nil UUID.
    #[test]
    fn test_scan_response_reused_without_source_falls_back_to_own_id() {
        let own_id = Uuid::new_v4();
        let mut scan = make_scan_result();
        scan.id = own_id;
        scan.is_reused = true;
        scan.source_scan_id = None;
        let resp = scan_result_to_response(scan, None, None);
        assert_eq!(resp.id, own_id);
    }

    #[test]
    fn test_scan_response_preserves_timestamps() {
        let scan = make_scan_result();
        let created = scan.created_at;
        let started = scan.started_at;
        let completed = scan.completed_at;
        let resp = scan_result_to_response(scan, None, None);
        assert_eq!(resp.created_at, created);
        assert_eq!(resp.started_at, started);
        assert_eq!(resp.completed_at, completed);
    }

    // -----------------------------------------------------------------------
    // collapse_not_applicable_rows (#2471)
    // -----------------------------------------------------------------------

    /// Build a `ScanResponse` for a given artifact/scan_type/status. Keeps the
    /// collapse tests terse and independent of a DB.
    fn make_scan_response(artifact_id: Uuid, scan_type: &str, status: &str) -> ScanResponse {
        let mut resp = scan_result_to_response(make_scan_result(), None, None);
        resp.artifact_id = artifact_id;
        resp.scan_type = scan_type.to_string();
        resp.status = status.to_string();
        resp
    }

    /// N `not_applicable` rows for one artifact collapse into a single summary
    /// row that records the count and the sorted, de-duplicated scan_types,
    /// while a genuine finding row for the same artifact passes through.
    #[test]
    fn test_collapse_folds_multiple_not_applicable_into_one_summary() {
        let art = Uuid::new_v4();
        let items = vec![
            make_scan_response(art, "image", "completed"),
            make_scan_response(art, "openscap", "not_applicable"),
            make_scan_response(art, "incus", "not_applicable"),
            make_scan_response(art, "filesystem", "not_applicable"),
        ];

        let out = collapse_not_applicable_rows(items);

        // 1 real finding row + 1 summary row.
        assert_eq!(out.len(), 2);
        let real = out
            .iter()
            .find(|r| r.status == "completed")
            .expect("finding row survives");
        assert_eq!(real.scan_type, "image");
        assert!(real.collapsed_not_applicable_count.is_none());

        let summary = out
            .iter()
            .find(|r| r.collapsed_not_applicable_count.is_some())
            .expect("summary row emitted");
        assert_eq!(summary.status, "not_applicable");
        assert_eq!(summary.scan_type, "not_applicable");
        assert_eq!(summary.collapsed_not_applicable_count, Some(3));
        assert_eq!(
            summary.collapsed_scan_types.as_deref(),
            Some(
                [
                    "filesystem".to_string(),
                    "incus".to_string(),
                    "openscap".to_string()
                ]
                .as_slice()
            )
        );
    }

    /// A lone `not_applicable` row is not redundant and must pass through
    /// unchanged (no synthetic summary, no annotation).
    #[test]
    fn test_collapse_leaves_single_not_applicable_untouched() {
        let art = Uuid::new_v4();
        let items = vec![
            make_scan_response(art, "image", "completed"),
            make_scan_response(art, "filesystem", "not_applicable"),
        ];

        let out = collapse_not_applicable_rows(items);

        assert_eq!(out.len(), 2);
        let na = out
            .iter()
            .find(|r| r.status == "not_applicable")
            .expect("na row survives");
        assert_eq!(na.scan_type, "filesystem");
        assert!(na.collapsed_not_applicable_count.is_none());
        assert!(na.collapsed_scan_types.is_none());
    }

    /// Collapse is scoped per-artifact: two artifacts each with their own
    /// group of `not_applicable` rows collapse independently.
    #[test]
    fn test_collapse_groups_per_artifact() {
        let a1 = Uuid::new_v4();
        let a2 = Uuid::new_v4();
        let items = vec![
            make_scan_response(a1, "incus", "not_applicable"),
            make_scan_response(a1, "openscap", "not_applicable"),
            make_scan_response(a2, "filesystem", "not_applicable"),
            make_scan_response(a2, "openscap", "not_applicable"),
        ];

        let out = collapse_not_applicable_rows(items);

        assert_eq!(out.len(), 2);
        for summary in &out {
            assert_eq!(summary.collapsed_not_applicable_count, Some(2));
        }
        assert_ne!(out[0].artifact_id, out[1].artifact_id);
    }

    /// Rows with no `not_applicable` status are returned verbatim, in order.
    #[test]
    fn test_collapse_noop_without_not_applicable() {
        let art = Uuid::new_v4();
        let items = vec![
            make_scan_response(art, "image", "completed"),
            make_scan_response(art, "dependency", "failed"),
        ];

        let out = collapse_not_applicable_rows(items);

        assert_eq!(out.len(), 2);
        assert_eq!(out[0].scan_type, "image");
        assert_eq!(out[1].scan_type, "dependency");
        assert!(out
            .iter()
            .all(|r| r.collapsed_not_applicable_count.is_none()));
    }

    /// The summary row keeps the position and `id` of the artifact's first
    /// (most-recent) collapsed row so the UI can still drill into a
    /// representative result and ordering is stable.
    #[test]
    fn test_collapse_summary_inherits_first_row_id_and_position() {
        let art = Uuid::new_v4();
        let first_na = make_scan_response(art, "incus", "not_applicable");
        let first_id = first_na.id;
        let items = vec![
            first_na,
            make_scan_response(art, "openscap", "not_applicable"),
            make_scan_response(art, "image", "completed"),
        ];

        let out = collapse_not_applicable_rows(items);

        assert_eq!(out.len(), 2);
        // Summary takes the first slot (where the first not_applicable row was).
        assert_eq!(out[0].id, first_id);
        assert_eq!(out[0].collapsed_not_applicable_count, Some(2));
        assert_eq!(out[1].status, "completed");
    }

    // -----------------------------------------------------------------------
    // DashboardResponse construction
    // -----------------------------------------------------------------------

    #[test]
    fn test_dashboard_response_construction() {
        let resp = DashboardResponse {
            repos_with_scanning: 10,
            total_scans: 100,
            total_findings: 50,
            critical_findings: 5,
            high_findings: 15,
            policy_violations_blocked: 3,
            repos_grade_a: 6,
            repos_grade_f: 1,
        };
        assert_eq!(resp.repos_with_scanning, 10);
        assert_eq!(resp.total_scans, 100);
        assert_eq!(resp.total_findings, 50);
        assert_eq!(resp.critical_findings, 5);
        assert_eq!(resp.high_findings, 15);
        assert_eq!(resp.policy_violations_blocked, 3);
        assert_eq!(resp.repos_grade_a, 6);
        assert_eq!(resp.repos_grade_f, 1);
    }

    #[test]
    fn test_dashboard_response_zeros() {
        let resp = DashboardResponse {
            repos_with_scanning: 0,
            total_scans: 0,
            total_findings: 0,
            critical_findings: 0,
            high_findings: 0,
            policy_violations_blocked: 0,
            repos_grade_a: 0,
            repos_grade_f: 0,
        };
        assert_eq!(resp.repos_with_scanning, 0);
        assert_eq!(resp.total_findings, 0);
    }

    // -----------------------------------------------------------------------
    // Request/response serde
    // -----------------------------------------------------------------------

    #[test]
    fn test_trigger_scan_request_serde_artifact_only() {
        let id = Uuid::new_v4();
        let json = serde_json::json!({ "artifact_id": id });
        let req: TriggerScanRequest = serde_json::from_value(json).unwrap();
        assert_eq!(req.artifact_id, Some(id));
        assert_eq!(req.repository_id, None);
    }

    #[test]
    fn test_trigger_scan_request_serde_repo_only() {
        let id = Uuid::new_v4();
        let json = serde_json::json!({ "repository_id": id });
        let req: TriggerScanRequest = serde_json::from_value(json).unwrap();
        assert_eq!(req.artifact_id, None);
        assert_eq!(req.repository_id, Some(id));
    }

    #[test]
    fn test_trigger_scan_request_serde_both() {
        let aid = Uuid::new_v4();
        let rid = Uuid::new_v4();
        let json = serde_json::json!({ "artifact_id": aid, "repository_id": rid });
        let req: TriggerScanRequest = serde_json::from_value(json).unwrap();
        assert_eq!(req.artifact_id, Some(aid));
        assert_eq!(req.repository_id, Some(rid));
    }

    #[test]
    fn test_trigger_scan_request_serde_empty() {
        let json = serde_json::json!({});
        let req: TriggerScanRequest = serde_json::from_value(json).unwrap();
        assert_eq!(req.artifact_id, None);
        assert_eq!(req.repository_id, None);
        assert_eq!(
            req.bypass_dedup, None,
            "bypass_dedup must default to None when the field is omitted, so existing \
             clients that pre-date #1469 keep their cache-friendly trigger semantics"
        );
    }

    #[test]
    fn test_trigger_scan_request_serde_bypass_dedup_true() {
        // #1469: the explicit "rescan now, ignore cached results" path.
        // Pinned because the handler maps None -> false, so a regression
        // that drops the field from the struct or renames it would silently
        // collapse `{"bypass_dedup": true}` back to the cached path.
        let aid = Uuid::new_v4();
        let json = serde_json::json!({ "artifact_id": aid, "bypass_dedup": true });
        let req: TriggerScanRequest = serde_json::from_value(json).unwrap();
        assert_eq!(req.artifact_id, Some(aid));
        assert_eq!(req.bypass_dedup, Some(true));
    }

    #[test]
    fn test_trigger_scan_request_serde_bypass_dedup_false() {
        let aid = Uuid::new_v4();
        let json = serde_json::json!({ "artifact_id": aid, "bypass_dedup": false });
        let req: TriggerScanRequest = serde_json::from_value(json).unwrap();
        assert_eq!(req.bypass_dedup, Some(false));
    }

    // -----------------------------------------------------------------------
    // Structural guard for issue #918: trigger_scan must return 503
    // (ServiceUnavailable), not 500 (Internal), when scanner_service is None.
    // -----------------------------------------------------------------------
    //
    // The error.rs unit tests added with this fix only verify that the
    // ServiceUnavailable variant maps to a 503 status code. They do NOT
    // verify that the trigger_scan handler actually emits that variant.
    // A regression that reverted the handler call site to AppError::Internal
    // (the original bug) would still pass every other test in this crate.
    //
    // Constructing a SharedState with scanner_service: None would require a
    // live Postgres pool (no #[sqlx::test] pattern is used in this file),
    // so we use a source-grep test as the lightweight regression contract.
    //
    // The forbidden substrings are constructed at runtime via format!() so
    // this test's own body does not contain them and trip the check on itself.
    #[test]
    fn test_trigger_scan_handler_uses_service_unavailable_for_missing_scanner() {
        let src = include_str!("security.rs");

        // Slice out just the trigger_scan function body so we are asserting on
        // the bug-fix call site, not on (e.g.) a doc comment elsewhere in the
        // file that happens to mention "Internal".
        let fn_marker = "async fn trigger_scan(";
        let fn_start = src
            .find(fn_marker)
            .expect("trigger_scan function must exist");
        // The next handler in this file is `list_scans`. Bound the slice on
        // that to avoid scanning the rest of the module.
        let next_fn_marker = "async fn list_scans(";
        let fn_end_rel = src[fn_start..]
            .find(next_fn_marker)
            .expect("list_scans must follow trigger_scan in this file");
        let body = &src[fn_start..fn_start + fn_end_rel];

        // Build the forbidden pattern at runtime so this assertion's own
        // text does not satisfy the search.
        let internal_variant = format!("AppError::{}(", "Internal");
        let bad_call = format!(
            "{}\"Scanner service not configured\"",
            internal_variant.as_str()
        );
        assert!(
            !body.contains(&bad_call),
            "regression of issue #918: trigger_scan must NOT return \
             AppError::Internal for the scanner-not-configured case; that \
             maps to HTTP 500 and triggers operator alerts. Use \
             AppError::ServiceUnavailable so it maps to HTTP 503 instead.",
        );

        // Anchor: the handler must affirmatively use the ServiceUnavailable
        // variant. Spelled in two pieces so this assertion's own text does
        // not satisfy the search trivially.
        let good_variant = format!("AppError::{}(", "ServiceUnavailable");
        let good_call = format!(
            "{}\"Scanner service not configured\"",
            good_variant.as_str()
        );
        assert!(
            body.contains(&good_call),
            "trigger_scan must return AppError::ServiceUnavailable(\"Scanner \
             service not configured\") when state.scanner_service is None, \
             so the response is HTTP 503 (not 500).",
        );
    }

    // -----------------------------------------------------------------------
    // Regression: bypass_dedup must be admin-gated in trigger_scan.
    //
    // PR #1514 review feedback: `bypass_dedup` skips the hash-based scan
    // dedup short-circuit and fans out unbounded tokio::spawn workers across
    // an entire repository's artifacts. The pre-existing `force = true` path
    // was naturally rate-limited because dedup collapsed repeated calls
    // against the same checksum into a single cached result; `bypass_dedup`
    // removes that safety, so a non-admin caller setting it to true would be
    // a DoS amplifier.
    //
    // This test invokes the `trigger_scan` handler directly (not via the
    // router) so it covers the actual 403 branch under `cargo llvm-cov`.
    // It runs against a real Postgres pool when `DATABASE_URL` is set and
    // no-ops cleanly otherwise, matching the `tdh::Fixture` pattern used
    // by sibling handler tests.
    //
    // #2321 G5 update: the handler is now admin-only for EVERY request shape
    // (not just bypass_dedup=true), so a non-admin can no longer trigger scans
    // at all — closing the amplification lever on the default/false shapes too.
    //
    // Coverage strategy: four call shapes prove the gate's behaviour without
    // spinning up a real scan run:
    //
    //   1. non-admin + bypass_dedup=true    -> 403 Authorization (the gate)
    //   2. non-admin + bypass_dedup omitted -> 403 Authorization (all shapes)
    //   3. non-admin + bypass_dedup=false   -> 403 Authorization
    //   4. admin     + no ids               -> 400 Validation
    //      (admins pass the gate and land on the next check; not over-blocked)
    // -----------------------------------------------------------------------
    #[tokio::test]
    async fn test_trigger_scan_handler_requires_admin_all_shapes() {
        use crate::api::handlers::test_db_helpers as tdh;
        use std::sync::Arc;

        let Some(fx) = tdh::Fixture::setup("local", "generic").await else {
            return; // no DATABASE_URL: skip cleanly
        };

        // Build a ScannerService so the handler gets past the 503 short-
        // circuit. The 403 admin-gate check fires before any scanner method
        // is invoked, so a vanilla constructor without trivy/openscap URLs
        // is sufficient for this test.
        let advisory_client = Arc::new(crate::services::scanner_service::AdvisoryClient::new(None));
        let scan_result_service =
            Arc::new(crate::services::scan_result_service::ScanResultService::new(fx.pool.clone()));
        let scan_config_service =
            Arc::new(crate::services::scan_config_service::ScanConfigService::new(fx.pool.clone()));
        let scanner_auth = Arc::new(crate::services::auth_service::AuthService::new(
            fx.pool.clone(),
            Arc::new(crate::config::Config::test_config()),
        ));
        let scanner = Arc::new(crate::services::scanner_service::ScannerService::new(
            fx.pool.clone(),
            advisory_client,
            scan_result_service,
            scan_config_service,
            None, // trivy_url
            None, // trivy_adapter_url
            fx.state.storage.clone(),
            fx.state.storage_registry.clone(),
            fx.storage_dir.to_string_lossy().into_owned(),
            "/tmp/scan".to_string(),
            None, // openscap_url
            "standard".to_string(),
            scanner_auth,
            None, // scan_identity: anonymous pulls in test
            300,  // scan_token_ttl_seconds
        ));

        // The fixture's SharedState is `Arc<AppState>` with `scanner_service:
        // None`. Rebuild the inner AppState with the scanner wired in. We
        // can't mutate the existing Arc once it's shared, so we construct a
        // fresh AppState that points at the same pool / storage.
        let mut state_inner = crate::api::AppState::new(
            fx.state.config.clone(),
            fx.pool.clone(),
            fx.state.storage.clone(),
            fx.state.storage_registry.clone(),
        );
        state_inner.set_scanner_service(scanner);
        let state: SharedState = Arc::new(state_inner);

        let make_auth = |is_admin: bool| AuthExtension {
            user_id: fx.user_id,
            username: fx.username.clone(),
            email: format!("{}@test.local", fx.username),
            is_admin,
            is_api_token: false,
            is_service_account: false,
            scopes: None,
            allowed_repo_ids: crate::models::access_scope::AccessScope::Admin,
            iat_ms: None,
        };

        // #2321 G5: trigger_scan is now admin-only for ALL request shapes, not
        // just `bypass_dedup=true`. Non-admins are rejected 403 regardless of
        // the flag; admins pass the gate and reach the post-auth validation.

        // ---- Case 1: non-admin + bypass_dedup=true -> 403 Authorization
        let result = trigger_scan(
            State(state.clone()),
            Extension(make_auth(false)),
            Json(TriggerScanRequest {
                artifact_id: None,
                repository_id: None,
                bypass_dedup: Some(true),
            }),
        )
        .await;
        assert!(
            matches!(result, Err(AppError::Authorization(_))),
            "non-admin + bypass_dedup=true must be 403, got: {:?}",
            result.as_ref().err()
        );

        // ---- Case 2: non-admin + bypass_dedup omitted -> 403 Authorization
        let result = trigger_scan(
            State(state.clone()),
            Extension(make_auth(false)),
            Json(TriggerScanRequest {
                artifact_id: None,
                repository_id: None,
                bypass_dedup: None,
            }),
        )
        .await;
        assert!(
            matches!(result, Err(AppError::Authorization(_))),
            "non-admin + bypass_dedup omitted must be 403 (all shapes admin-only), got: {:?}",
            result.as_ref().err()
        );

        // ---- Case 3: non-admin + bypass_dedup=false -> 403 Authorization
        let result = trigger_scan(
            State(state.clone()),
            Extension(make_auth(false)),
            Json(TriggerScanRequest {
                artifact_id: None,
                repository_id: None,
                bypass_dedup: Some(false),
            }),
        )
        .await;
        assert!(
            matches!(result, Err(AppError::Authorization(_))),
            "non-admin + bypass_dedup=false must be 403, got: {:?}",
            result.as_ref().err()
        );

        // ---- Case 4 (legit): admin + no ids -> 400 Validation. Proves the
        // admin PASSES the gate and lands on the next check (post-auth), i.e.
        // the gate does not over-block the admin path.
        let result = trigger_scan(
            State(state.clone()),
            Extension(make_auth(true)),
            Json(TriggerScanRequest {
                artifact_id: None,
                repository_id: None,
                bypass_dedup: Some(true),
            }),
        )
        .await;
        match result {
            Err(AppError::Validation(msg)) => {
                assert!(
                    msg.contains("artifact_id") || msg.contains("repository_id"),
                    "admin must reach the post-gate validation check, got: {}",
                    msg
                );
            }
            other => panic!(
                "expected AppError::Validation for admin with no ids (proves the \
                 gate lets admins through), got: {:?}",
                other.as_ref().err()
            ),
        }

        fx.teardown().await;
    }

    #[test]
    fn test_create_policy_request_serde() {
        let json = serde_json::json!({
            "name": "strict-policy",
            "max_severity": "high",
            "block_unscanned": true,
            "block_on_fail": true,
        });
        let req: CreatePolicyRequest = serde_json::from_value(json).unwrap();
        assert_eq!(req.name, "strict-policy");
        assert_eq!(req.max_severity, "high");
        assert!(req.block_unscanned);
        assert!(req.block_on_fail);
        assert!(!req.require_signature);
        assert_eq!(req.repository_id, None);
        assert_eq!(req.min_staging_hours, None);
        assert_eq!(req.max_artifact_age_days, None);
    }

    #[test]
    fn test_create_policy_request_block_unscanned_defaults_true_when_omitted() {
        // #1643: omitting block_unscanned must default to true (secure default),
        // not deserialize-fail or fall open to false. Backward-compatible for
        // IaC/automation that does not send the field.
        let json = serde_json::json!({
            "name": "no-toggle",
            "max_severity": "high",
            "block_on_fail": false,
        });
        let req: CreatePolicyRequest = serde_json::from_value(json).unwrap();
        assert!(
            req.block_unscanned,
            "omitted block_unscanned must default to true (#1643)"
        );
    }

    #[test]
    fn test_create_policy_request_explicit_false_is_respected() {
        // An operator who explicitly opts out must still be able to.
        let json = serde_json::json!({
            "name": "opt-out",
            "max_severity": "high",
            "block_unscanned": false,
            "block_on_fail": false,
        });
        let req: CreatePolicyRequest = serde_json::from_value(json).unwrap();
        assert!(!req.block_unscanned);
    }

    #[test]
    fn test_create_policy_request_with_all_fields() {
        let repo_id = Uuid::new_v4();
        let json = serde_json::json!({
            "name": "full-policy",
            "repository_id": repo_id,
            "max_severity": "critical",
            "block_unscanned": false,
            "block_on_fail": false,
            "min_staging_hours": 24,
            "max_artifact_age_days": 90,
            "require_signature": true,
        });
        let req: CreatePolicyRequest = serde_json::from_value(json).unwrap();
        assert_eq!(req.name, "full-policy");
        assert_eq!(req.repository_id, Some(repo_id));
        assert!(req.require_signature);
        assert_eq!(req.min_staging_hours, Some(24));
        assert_eq!(req.max_artifact_age_days, Some(90));
    }

    #[test]
    fn test_update_policy_request_serde() {
        let json = serde_json::json!({
            "name": "updated-policy",
            "max_severity": "medium",
            "block_unscanned": false,
            "block_on_fail": true,
            "is_enabled": false,
        });
        let req: UpdatePolicyRequest = serde_json::from_value(json).unwrap();
        assert_eq!(req.name.as_deref(), Some("updated-policy"));
        assert_eq!(req.is_enabled, Some(false));
        // require_signature was not in the payload; we expect None (== "leave alone"),
        // never a synthesised `false` that would silently flip the persisted column.
        assert_eq!(req.require_signature, None);
    }

    #[test]
    fn test_update_policy_request_all_fields() {
        let json = serde_json::json!({
            "name": "full-update",
            "max_severity": "low",
            "block_unscanned": true,
            "block_on_fail": true,
            "is_enabled": true,
            "min_staging_hours": 48,
            "max_artifact_age_days": 365,
            "require_signature": true,
        });
        let req: UpdatePolicyRequest = serde_json::from_value(json).unwrap();
        assert_eq!(req.name.as_deref(), Some("full-update"));
        assert_eq!(req.max_severity.as_deref(), Some("low"));
        assert_eq!(req.block_unscanned, Some(true));
        assert_eq!(req.block_on_fail, Some(true));
        assert_eq!(req.is_enabled, Some(true));
        assert_eq!(req.min_staging_hours, Some(48));
        assert_eq!(req.max_artifact_age_days, Some(365));
        assert_eq!(req.require_signature, Some(true));
    }

    // -----------------------------------------------------------------------
    // #1374 regression: PUT must accept a partial body and surface every
    // field that was sent. Previously the strict-shape DTO rejected
    // `{max_severity, is_enabled}` as a 422 and the release-gate
    // `scan-policy-crud` flow saw `is_enabled` come back unchanged on a
    // follow-up GET (the observable "empty string" in the bash assertion).
    // -----------------------------------------------------------------------

    #[test]
    fn test_update_policy_request_partial_max_severity_and_is_enabled() {
        // The exact shape the release-gate test sends. Without the partial-
        // update fix this would fail to deserialise (missing `name`, etc.)
        // and bubble up as a 422 from the handler.
        let json = serde_json::json!({
            "max_severity": "critical",
            "is_enabled": false,
        });
        let req: UpdatePolicyRequest = serde_json::from_value(json).unwrap();

        // Both fields are observed -- the bug used to drop `is_enabled`.
        assert_eq!(req.max_severity.as_deref(), Some("critical"));
        assert_eq!(req.is_enabled, Some(false));

        // Untouched fields stay None so the service-layer COALESCE keeps the
        // existing DB value; they must NOT default to `false` / empty string.
        assert!(req.name.is_none());
        assert!(req.block_unscanned.is_none());
        assert!(req.block_on_fail.is_none());
        assert!(req.min_staging_hours.is_none());
        assert!(req.max_artifact_age_days.is_none());
        assert!(req.require_signature.is_none());
    }

    #[test]
    fn test_update_policy_request_empty_body_is_a_noop() {
        // An empty body must parse cleanly so a no-op PUT does not 422.
        // The COALESCE in `PolicyService::update_policy` then leaves the row
        // unchanged; this is the regression boundary for #1374.
        let json = serde_json::json!({});
        let req: UpdatePolicyRequest = serde_json::from_value(json).unwrap();
        assert!(req.name.is_none());
        assert!(req.max_severity.is_none());
        assert!(req.is_enabled.is_none());
        assert!(req.block_unscanned.is_none());
        assert!(req.block_on_fail.is_none());
        assert!(req.require_signature.is_none());
    }

    #[test]
    fn test_update_policy_request_is_enabled_only() {
        // The release-gate also exercises a single-field toggle of
        // `is_enabled`. Make sure that path round-trips a `false` value
        // (the bug was that bash saw an empty string here).
        let json = serde_json::json!({ "is_enabled": false });
        let req: UpdatePolicyRequest = serde_json::from_value(json).unwrap();
        assert_eq!(req.is_enabled, Some(false));
        // A bare `is_enabled: false` PATCH must not synthesise other fields.
        assert!(req.name.is_none());
        assert!(req.max_severity.is_none());
    }

    #[test]
    fn test_update_policy_response_has_concrete_bool_for_is_enabled() {
        // Closes the loop with the response contract: PolicyResponse must
        // always emit `is_enabled` as a JSON boolean, never absent or null,
        // so jq queries in the release gate cannot observe an empty string.
        let p = PolicyResponse {
            id: Uuid::nil(),
            name: "p".to_string(),
            repository_id: None,
            max_severity: "critical".to_string(),
            block_unscanned: true,
            block_on_fail: true,
            is_enabled: false,
            min_staging_hours: None,
            max_artifact_age_days: None,
            require_signature: false,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        };
        let json = serde_json::to_value(&p).unwrap();
        assert!(
            json["is_enabled"].is_boolean(),
            "is_enabled must be a JSON bool, got {}",
            json["is_enabled"]
        );
        assert_eq!(json["is_enabled"], false);
        assert_eq!(json["max_severity"], "critical");
    }

    #[test]
    fn test_acknowledge_request_serde() {
        let json = serde_json::json!({ "reason": "False positive" });
        let req: AcknowledgeRequest = serde_json::from_value(json).unwrap();
        assert_eq!(req.reason, "False positive");
    }

    #[test]
    fn test_acknowledge_request_long_reason() {
        let reason = "This CVE does not apply to our usage because we never pass user input to the affected function. Verified by security team on 2024-03-15.";
        let json = serde_json::json!({ "reason": reason });
        let req: AcknowledgeRequest = serde_json::from_value(json).unwrap();
        assert_eq!(req.reason, reason);
    }

    // -----------------------------------------------------------------------
    // ListScansQuery / ListFindingsQuery
    // -----------------------------------------------------------------------

    #[test]
    fn test_list_scans_query_all_none() {
        let json = serde_json::json!({});
        let query: ListScansQuery = serde_json::from_value(json).unwrap();
        assert_eq!(query.page, None);
        assert_eq!(query.per_page, None);
        assert_eq!(query.status, None);
        assert_eq!(query.repository_id, None);
        assert_eq!(query.artifact_id, None);
    }

    #[test]
    fn test_list_scans_query_with_values() {
        let id = Uuid::new_v4();
        let json = serde_json::json!({
            "repository_id": id,
            "status": "completed",
            "page": 2,
            "per_page": 50,
        });
        let query: ListScansQuery = serde_json::from_value(json).unwrap();
        assert_eq!(query.repository_id, Some(id));
        assert_eq!(query.status, Some("completed".to_string()));
        assert_eq!(query.page, Some(2));
        assert_eq!(query.per_page, Some(50));
    }

    #[test]
    fn test_list_findings_query_defaults() {
        let json = serde_json::json!({});
        let query: ListFindingsQuery = serde_json::from_value(json).unwrap();
        assert_eq!(query.page, None);
        assert_eq!(query.per_page, None);
    }

    #[test]
    fn test_list_findings_query_with_values() {
        let json = serde_json::json!({ "page": 5, "per_page": 100 });
        let query: ListFindingsQuery = serde_json::from_value(json).unwrap();
        assert_eq!(query.page, Some(5));
        assert_eq!(query.per_page, Some(100));
    }

    // -----------------------------------------------------------------------
    // ScoreResponse construction
    // -----------------------------------------------------------------------

    #[test]
    fn test_score_response_construction() {
        let now = chrono::Utc::now();
        let resp = ScoreResponse {
            id: Uuid::new_v4(),
            repository_id: Uuid::new_v4(),
            score: 85,
            grade: "A".to_string(),
            total_findings: 5,
            critical_count: 0,
            high_count: 1,
            medium_count: 2,
            low_count: 2,
            acknowledged_count: 1,
            last_scan_at: Some(now),
            calculated_at: now,
            has_failed_scan: false,
        };
        assert_eq!(resp.score, 85);
        assert_eq!(resp.grade, "A");
        assert_eq!(resp.total_findings, 5);
        assert_eq!(resp.acknowledged_count, 1);
    }

    #[test]
    fn test_score_response_no_last_scan() {
        let resp = ScoreResponse {
            id: Uuid::new_v4(),
            repository_id: Uuid::new_v4(),
            score: 0,
            grade: "F".to_string(),
            total_findings: 0,
            critical_count: 0,
            high_count: 0,
            medium_count: 0,
            low_count: 0,
            acknowledged_count: 0,
            last_scan_at: None,
            calculated_at: chrono::Utc::now(),
            has_failed_scan: false,
        };
        assert_eq!(resp.score, 0);
        assert_eq!(resp.grade, "F");
        assert!(resp.last_scan_at.is_none());
    }

    // -----------------------------------------------------------------------
    // RepoSecurityResponse
    // -----------------------------------------------------------------------

    #[test]
    fn test_repo_security_response_with_no_config_or_score() {
        let resp = RepoSecurityResponse {
            config: None,
            score: None,
        };
        assert!(resp.config.is_none());
        assert!(resp.score.is_none());
    }

    #[test]
    fn test_repo_security_response_with_config_and_score() {
        let now = chrono::Utc::now();
        let resp = RepoSecurityResponse {
            config: Some(ScanConfigResponse {
                id: Uuid::new_v4(),
                repository_id: Uuid::new_v4(),
                scan_enabled: true,
                scan_on_upload: true,
                scan_on_proxy: false,
                block_on_policy_violation: true,
                severity_threshold: "high".to_string(),
                proxy_scan_action: "fail_open".to_string(),
                created_at: now,
                updated_at: now,
            }),
            score: Some(ScoreResponse {
                id: Uuid::new_v4(),
                repository_id: Uuid::new_v4(),
                score: 92,
                grade: "A".to_string(),
                total_findings: 2,
                critical_count: 0,
                high_count: 0,
                medium_count: 1,
                low_count: 1,
                acknowledged_count: 0,
                last_scan_at: Some(now),
                calculated_at: now,
                has_failed_scan: false,
            }),
        };
        assert!(resp.config.is_some());
        assert!(resp.score.is_some());
        assert!(resp.config.unwrap().scan_enabled);
        assert_eq!(resp.score.unwrap().score, 92);
    }

    // -----------------------------------------------------------------------
    // PolicyViolation-like constructions
    // -----------------------------------------------------------------------

    #[test]
    fn test_scan_config_response_construction() {
        let now = chrono::Utc::now();
        let resp = ScanConfigResponse {
            id: Uuid::new_v4(),
            repository_id: Uuid::new_v4(),
            scan_enabled: false,
            scan_on_upload: false,
            scan_on_proxy: true,
            block_on_policy_violation: false,
            severity_threshold: "medium".to_string(),
            proxy_scan_action: "fail_closed".to_string(),
            created_at: now,
            updated_at: now,
        };
        assert!(!resp.scan_enabled);
        assert!(resp.scan_on_proxy);
        assert_eq!(resp.severity_threshold, "medium");
    }

    // -----------------------------------------------------------------------
    // Serialization round-trip
    // -----------------------------------------------------------------------

    #[test]
    fn test_dashboard_response_serialization() {
        let resp = DashboardResponse {
            repos_with_scanning: 5,
            total_scans: 10,
            total_findings: 20,
            critical_findings: 1,
            high_findings: 3,
            policy_violations_blocked: 0,
            repos_grade_a: 4,
            repos_grade_f: 0,
        };
        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains("\"repos_with_scanning\":5"));
        assert!(json.contains("\"total_scans\":10"));
        assert!(json.contains("\"total_findings\":20"));
    }

    #[test]
    fn test_trigger_scan_response_serialization() {
        let resp = TriggerScanResponse {
            message: "Scan queued".to_string(),
            artifacts_queued: 42,
            scan_result_ids: Vec::new(),
        };
        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains("\"artifacts_queued\":42"));
        assert!(json.contains("Scan queued"));
        // Empty list serializes to [] (not omitted) so callers can rely on the
        // field always being present.
        assert!(json.contains("\"scan_result_ids\":[]"));
    }

    #[test]
    fn test_trigger_scan_response_with_scan_result_ids() {
        let id1 = Uuid::new_v4();
        let id2 = Uuid::new_v4();
        let resp = TriggerScanResponse {
            message: "Scan queued for artifact".to_string(),
            artifacts_queued: 1,
            scan_result_ids: vec![id1, id2],
        };
        let json = serde_json::to_value(&resp).unwrap();
        let ids = json["scan_result_ids"].as_array().unwrap();
        assert_eq!(ids.len(), 2);
        assert_eq!(ids[0], id1.to_string());
        assert_eq!(ids[1], id2.to_string());
    }

    #[test]
    fn test_score_response_serialization() {
        let now = chrono::Utc::now();
        let resp = ScoreResponse {
            id: Uuid::new_v4(),
            repository_id: Uuid::new_v4(),
            score: 75,
            grade: "B".to_string(),
            total_findings: 10,
            critical_count: 0,
            high_count: 2,
            medium_count: 5,
            low_count: 3,
            acknowledged_count: 1,
            last_scan_at: Some(now),
            calculated_at: now,
            has_failed_scan: false,
        };
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["score"], 75);
        assert_eq!(json["grade"], "B");
        assert_eq!(json["total_findings"], 10);
    }

    #[test]
    fn test_policy_response_serialization() {
        let now = chrono::Utc::now();
        let resp = PolicyResponse {
            id: Uuid::new_v4(),
            name: "test-policy".to_string(),
            repository_id: None,
            max_severity: "high".to_string(),
            block_unscanned: true,
            block_on_fail: false,
            is_enabled: true,
            min_staging_hours: Some(12),
            max_artifact_age_days: None,
            require_signature: false,
            created_at: now,
            updated_at: now,
        };
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["name"], "test-policy");
        assert_eq!(json["max_severity"], "high");
        assert_eq!(json["block_unscanned"], true);
        assert_eq!(json["is_enabled"], true);
        assert_eq!(json["min_staging_hours"], 12);
        assert!(json["max_artifact_age_days"].is_null());
    }

    #[test]
    fn test_finding_response_serialization() {
        let now = chrono::Utc::now();
        let resp = FindingResponse {
            id: Uuid::new_v4(),
            scan_result_id: Uuid::new_v4(),
            artifact_id: Uuid::new_v4(),
            severity: "critical".to_string(),
            title: "CVE-2024-12345".to_string(),
            description: Some("Remote code execution".to_string()),
            cve_id: Some("CVE-2024-12345".to_string()),
            affected_component: Some("log4j".to_string()),
            affected_version: Some("2.14.0".to_string()),
            fixed_version: Some("2.17.1".to_string()),
            source: Some("trivy".to_string()),
            source_url: Some("https://nvd.nist.gov/vuln/detail/CVE-2024-12345".to_string()),
            is_acknowledged: false,
            acknowledged_by: None,
            acknowledged_reason: None,
            acknowledged_at: None,
            created_at: now,
        };
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["severity"], "critical");
        assert_eq!(json["title"], "CVE-2024-12345");
        assert_eq!(json["cve_id"], "CVE-2024-12345");
        assert_eq!(json["affected_component"], "log4j");
        assert_eq!(json["is_acknowledged"], false);
    }

    #[test]
    fn test_finding_response_acknowledged() {
        let now = chrono::Utc::now();
        let user_id = Uuid::new_v4();
        let resp = FindingResponse {
            id: Uuid::new_v4(),
            scan_result_id: Uuid::new_v4(),
            artifact_id: Uuid::new_v4(),
            severity: "medium".to_string(),
            title: "Outdated dependency".to_string(),
            description: None,
            cve_id: None,
            affected_component: None,
            affected_version: None,
            fixed_version: None,
            source: None,
            source_url: None,
            is_acknowledged: true,
            acknowledged_by: Some(user_id),
            acknowledged_reason: Some("False positive".to_string()),
            acknowledged_at: Some(now),
            created_at: now,
        };
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["is_acknowledged"], true);
        assert_eq!(json["acknowledged_by"], user_id.to_string());
        assert_eq!(json["acknowledged_reason"], "False positive");
    }

    #[test]
    fn test_scan_list_response_serialization() {
        let resp = ScanListResponse {
            items: vec![],
            total: 0,
        };
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["total"], 0);
        assert!(json["items"].as_array().unwrap().is_empty());
    }

    #[test]
    fn test_finding_list_response_serialization() {
        let resp = FindingListResponse {
            items: vec![],
            total: 42,
        };
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["total"], 42);
    }

    // -----------------------------------------------------------------------
    // Cross-repo scan/finding-read authorization (#2439).
    //
    // The global (non repo-nested) scan read routes -- `list_scans`,
    // `get_scan`, `list_findings`, `list_artifact_scans` -- query
    // artifact/repo-scoped data with NO per-repo authorization before this
    // fix, leaking CVE/supply-chain data to any authenticated non-member.
    // Each now runs the canonical `check_artifact_visibility` / `require_visible`
    // gate. These DB-backed tests call the handlers directly (matching the
    // `trigger_scan` sibling) and no-op when `DATABASE_URL` is unset.
    // -----------------------------------------------------------------------

    /// Insert an `artifacts` row owned by `repo_id` and return its id.
    #[cfg(test)]
    async fn seed_artifact_row(pool: &sqlx::PgPool, repo_id: Uuid) -> Uuid {
        let id = Uuid::new_v4();
        let path = format!("{}/{}", repo_id, id);
        sqlx::query(
            "INSERT INTO artifacts (id, repository_id, name, path, version, size_bytes, \
             checksum_sha256, content_type, storage_key, is_deleted) \
             VALUES ($1, $2, $3, $4, '1.0.0', 1024, $5, 'application/octet-stream', $4, false)",
        )
        .bind(id)
        .bind(repo_id)
        .bind(format!("scan-art-{}", id))
        .bind(&path)
        .bind(format!("sha256-scan-{}", id))
        .execute(pool)
        .await
        .expect("seed artifact row");
        id
    }

    /// Insert a completed `scan_results` row + one `scan_findings` row for
    /// `(repo_id, artifact_id)`. Returns `(scan_id, finding_id)`.
    #[cfg(test)]
    async fn seed_scan_with_finding(
        pool: &sqlx::PgPool,
        repo_id: Uuid,
        artifact_id: Uuid,
    ) -> (Uuid, Uuid) {
        let scan_id = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO scan_results (id, artifact_id, repository_id, scan_type, status, \
             findings_count, started_at, completed_at) \
             VALUES ($1, $2, $3, 'dependency', 'completed', 1, NOW(), NOW())",
        )
        .bind(scan_id)
        .bind(artifact_id)
        .bind(repo_id)
        .execute(pool)
        .await
        .expect("seed scan_result");
        let finding_id: Uuid = sqlx::query_scalar(
            "INSERT INTO scan_findings (scan_result_id, artifact_id, severity, title, cve_id, \
             source, is_acknowledged) \
             VALUES ($1, $2, 'critical', 'seed finding', 'CVE-2024-9999', 'trivy', false) \
             RETURNING id",
        )
        .bind(scan_id)
        .bind(artifact_id)
        .fetch_one(pool)
        .await
        .expect("seed scan_finding");
        (scan_id, finding_id)
    }

    #[cfg(test)]
    async fn teardown_scans(pool: &sqlx::PgPool, repo_id: Uuid) {
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
    }

    #[cfg(test)]
    async fn set_public(pool: &sqlx::PgPool, repo_id: Uuid, public: bool) {
        sqlx::query("UPDATE repositories SET is_public = $1 WHERE id = $2")
            .bind(public)
            .bind(repo_id)
            .execute(pool)
            .await
            .expect("set is_public");
    }

    /// A denial (404) message must not leak any scan/finding metadata field.
    #[cfg(test)]
    fn assert_no_scan_leak(err: &AppError) {
        let msg = format!("{:?}", err);
        for needle in ["repository_id", "cve", "CVE-", "severity", "critical"] {
            assert!(
                !msg.contains(needle),
                "denial message must not leak `{needle}`: {msg}"
            );
        }
    }

    // --- get_scan ---------------------------------------------------------

    #[tokio::test]
    async fn test_get_scan_member_ok_db() {
        use crate::api::handlers::test_db_helpers as tdh;
        let Some(fx) = tdh::Fixture::setup("local", "generic").await else {
            return;
        };
        let art = seed_artifact_row(&fx.pool, fx.repo_id).await;
        let (scan_id, _f) = seed_scan_with_finding(&fx.pool, fx.repo_id, art).await;
        // fixture user is auto-granted repo access (a member).
        let res = get_scan(
            State(fx.state.clone()),
            Extension(tdh::make_auth(fx.user_id, &fx.username)),
            Path(scan_id),
        )
        .await;
        teardown_scans(&fx.pool, fx.repo_id).await;
        fx.teardown().await;
        assert!(res.is_ok(), "member must see the scan, got {:?}", res.err());
    }

    #[tokio::test]
    async fn test_get_scan_non_member_404_no_leak_db() {
        use crate::api::handlers::test_db_helpers as tdh;
        let Some(fx) = tdh::Fixture::setup("local", "generic").await else {
            return;
        };
        let art = seed_artifact_row(&fx.pool, fx.repo_id).await;
        let (scan_id, _f) = seed_scan_with_finding(&fx.pool, fx.repo_id, art).await;
        let (outsider, outname) = tdh::create_user(&fx.pool).await;
        let res = get_scan(
            State(fx.state.clone()),
            Extension(tdh::make_auth(outsider, &outname)),
            Path(scan_id),
        )
        .await;
        teardown_scans(&fx.pool, fx.repo_id).await;
        tdh::cleanup_user(&fx.pool, outsider).await;
        fx.teardown().await;
        match res {
            Err(ref e @ AppError::NotFound(_)) => assert_no_scan_leak(e),
            other => panic!("non-member must get 404, got {:?}", other.err()),
        }
    }

    #[tokio::test]
    async fn test_get_scan_admin_ok_db() {
        use crate::api::handlers::test_db_helpers as tdh;
        let Some(fx) = tdh::Fixture::setup("local", "generic").await else {
            return;
        };
        let art = seed_artifact_row(&fx.pool, fx.repo_id).await;
        let (scan_id, _f) = seed_scan_with_finding(&fx.pool, fx.repo_id, art).await;
        let (admin_id, admin_name) = tdh::create_user(&fx.pool).await;
        let res = get_scan(
            State(fx.state.clone()),
            Extension(tdh::admin_auth(admin_id, &admin_name)),
            Path(scan_id),
        )
        .await;
        teardown_scans(&fx.pool, fx.repo_id).await;
        tdh::cleanup_user(&fx.pool, admin_id).await;
        fx.teardown().await;
        assert!(res.is_ok(), "admin bypass must see the scan");
    }

    #[tokio::test]
    async fn test_get_scan_public_repo_non_member_ok_db() {
        use crate::api::handlers::test_db_helpers as tdh;
        let Some(fx) = tdh::Fixture::setup("local", "generic").await else {
            return;
        };
        set_public(&fx.pool, fx.repo_id, true).await;
        let art = seed_artifact_row(&fx.pool, fx.repo_id).await;
        let (scan_id, _f) = seed_scan_with_finding(&fx.pool, fx.repo_id, art).await;
        let (outsider, outname) = tdh::create_user(&fx.pool).await;
        let res = get_scan(
            State(fx.state.clone()),
            Extension(tdh::make_auth(outsider, &outname)),
            Path(scan_id),
        )
        .await;
        teardown_scans(&fx.pool, fx.repo_id).await;
        tdh::cleanup_user(&fx.pool, outsider).await;
        fx.teardown().await;
        assert!(
            res.is_ok(),
            "public-repo scan is visible to any authed user"
        );
    }

    // --- list_findings ----------------------------------------------------

    #[tokio::test]
    async fn test_list_findings_non_member_404_no_leak_db() {
        use crate::api::handlers::test_db_helpers as tdh;
        let Some(fx) = tdh::Fixture::setup("local", "generic").await else {
            return;
        };
        let art = seed_artifact_row(&fx.pool, fx.repo_id).await;
        let (scan_id, _f) = seed_scan_with_finding(&fx.pool, fx.repo_id, art).await;
        let (outsider, outname) = tdh::create_user(&fx.pool).await;
        let res = list_findings(
            State(fx.state.clone()),
            Extension(tdh::make_auth(outsider, &outname)),
            Path(scan_id),
            Query(ListFindingsQuery::default()),
        )
        .await;
        teardown_scans(&fx.pool, fx.repo_id).await;
        tdh::cleanup_user(&fx.pool, outsider).await;
        fx.teardown().await;
        match res {
            Err(ref e @ AppError::NotFound(_)) => assert_no_scan_leak(e),
            other => panic!("non-member must get 404, got {:?}", other.err()),
        }
    }

    #[tokio::test]
    async fn test_list_findings_member_ok_db() {
        use crate::api::handlers::test_db_helpers as tdh;
        let Some(fx) = tdh::Fixture::setup("local", "generic").await else {
            return;
        };
        let art = seed_artifact_row(&fx.pool, fx.repo_id).await;
        let (scan_id, _f) = seed_scan_with_finding(&fx.pool, fx.repo_id, art).await;
        let res = list_findings(
            State(fx.state.clone()),
            Extension(tdh::make_auth(fx.user_id, &fx.username)),
            Path(scan_id),
            Query(ListFindingsQuery::default()),
        )
        .await;
        teardown_scans(&fx.pool, fx.repo_id).await;
        fx.teardown().await;
        let body = res.expect("member sees findings");
        assert_eq!(body.0.total, 1);
    }

    // --- list_artifact_scans ---------------------------------------------

    #[tokio::test]
    async fn test_list_artifact_scans_non_member_404_db() {
        use crate::api::handlers::test_db_helpers as tdh;
        let Some(fx) = tdh::Fixture::setup("local", "generic").await else {
            return;
        };
        let art = seed_artifact_row(&fx.pool, fx.repo_id).await;
        let (_s, _f) = seed_scan_with_finding(&fx.pool, fx.repo_id, art).await;
        let (outsider, outname) = tdh::create_user(&fx.pool).await;
        let res = list_artifact_scans(
            State(fx.state.clone()),
            Extension(tdh::make_auth(outsider, &outname)),
            Path(art),
            Query(ListScansQuery::default()),
        )
        .await;
        teardown_scans(&fx.pool, fx.repo_id).await;
        tdh::cleanup_user(&fx.pool, outsider).await;
        fx.teardown().await;
        assert!(
            matches!(res, Err(AppError::NotFound(_))),
            "non-member must get 404 on artifact scans, got {:?}",
            res.err()
        );
    }

    #[tokio::test]
    async fn test_list_artifact_scans_member_ok_db() {
        use crate::api::handlers::test_db_helpers as tdh;
        let Some(fx) = tdh::Fixture::setup("local", "generic").await else {
            return;
        };
        let art = seed_artifact_row(&fx.pool, fx.repo_id).await;
        let (_s, _f) = seed_scan_with_finding(&fx.pool, fx.repo_id, art).await;
        let res = list_artifact_scans(
            State(fx.state.clone()),
            Extension(tdh::make_auth(fx.user_id, &fx.username)),
            Path(art),
            Query(ListScansQuery::default()),
        )
        .await;
        teardown_scans(&fx.pool, fx.repo_id).await;
        fx.teardown().await;
        let body = res.expect("member sees artifact scans");
        assert_eq!(body.0.total, 1);
    }

    // --- list_scans (filtered + unfiltered) -------------------------------

    #[tokio::test]
    async fn test_list_scans_artifact_filter_non_member_404_db() {
        use crate::api::handlers::test_db_helpers as tdh;
        let Some(fx) = tdh::Fixture::setup("local", "generic").await else {
            return;
        };
        let art = seed_artifact_row(&fx.pool, fx.repo_id).await;
        let (_s, _f) = seed_scan_with_finding(&fx.pool, fx.repo_id, art).await;
        let (outsider, outname) = tdh::create_user(&fx.pool).await;
        let res = list_scans(
            State(fx.state.clone()),
            Extension(tdh::make_auth(outsider, &outname)),
            Query(ListScansQuery {
                artifact_id: Some(art),
                ..Default::default()
            }),
        )
        .await;
        teardown_scans(&fx.pool, fx.repo_id).await;
        tdh::cleanup_user(&fx.pool, outsider).await;
        fx.teardown().await;
        assert!(
            matches!(res, Err(AppError::NotFound(_))),
            "non-member filtering by hidden artifact must 404, got {:?}",
            res.err()
        );
    }

    #[tokio::test]
    async fn test_list_scans_repo_filter_member_ok_db() {
        use crate::api::handlers::test_db_helpers as tdh;
        let Some(fx) = tdh::Fixture::setup("local", "generic").await else {
            return;
        };
        let art = seed_artifact_row(&fx.pool, fx.repo_id).await;
        let (_s, _f) = seed_scan_with_finding(&fx.pool, fx.repo_id, art).await;
        let res = list_scans(
            State(fx.state.clone()),
            Extension(tdh::make_auth(fx.user_id, &fx.username)),
            Query(ListScansQuery {
                repository_id: Some(fx.repo_id),
                ..Default::default()
            }),
        )
        .await;
        teardown_scans(&fx.pool, fx.repo_id).await;
        fx.teardown().await;
        assert!(res.is_ok(), "member filtering by own repo must 200");
    }

    #[tokio::test]
    async fn test_list_scans_unfiltered_non_admin_denied_db() {
        use crate::api::handlers::test_db_helpers as tdh;
        let Some(fx) = tdh::Fixture::setup("local", "generic").await else {
            return;
        };
        let res = list_scans(
            State(fx.state.clone()),
            Extension(tdh::make_auth(fx.user_id, &fx.username)),
            Query(ListScansQuery::default()),
        )
        .await;
        fx.teardown().await;
        assert!(
            matches!(res, Err(AppError::Authorization(_))),
            "unfiltered global scan list must be admin-only, got {:?}",
            res.err()
        );
    }

    #[tokio::test]
    async fn test_list_scans_unfiltered_admin_ok_db() {
        use crate::api::handlers::test_db_helpers as tdh;
        let Some(fx) = tdh::Fixture::setup("local", "generic").await else {
            return;
        };
        let (admin_id, admin_name) = tdh::create_user(&fx.pool).await;
        let res = list_scans(
            State(fx.state.clone()),
            Extension(tdh::admin_auth(admin_id, &admin_name)),
            Query(ListScansQuery::default()),
        )
        .await;
        tdh::cleanup_user(&fx.pool, admin_id).await;
        fx.teardown().await;
        assert!(res.is_ok(), "admin may list all scans unfiltered");
    }

    // --- 404-body uniformity: hidden-exists vs truly-absent (#2439 residual) --
    //
    // A hidden-but-existing scan (no-access) and a nonexistent scan id must
    // return the SAME 404 body, else the status/message is a boolean existence
    // oracle. Extract the NotFound message in both cases and assert equality.

    #[cfg(test)]
    fn not_found_msg<T>(res: &Result<T>) -> String {
        match res {
            Err(AppError::NotFound(m)) => m.clone(),
            Err(other) => panic!("expected NotFound, got {:?}", other),
            Ok(_) => panic!("expected NotFound, got Ok"),
        }
    }

    #[tokio::test]
    async fn test_get_scan_404_body_uniform_hidden_vs_absent_db() {
        use crate::api::handlers::test_db_helpers as tdh;
        let Some(fx) = tdh::Fixture::setup("local", "generic").await else {
            return;
        };
        let art = seed_artifact_row(&fx.pool, fx.repo_id).await;
        let (scan_id, _f) = seed_scan_with_finding(&fx.pool, fx.repo_id, art).await;
        let (outsider, outname) = tdh::create_user(&fx.pool).await;

        // hidden-but-existing scan, seen by a non-member.
        let hidden = get_scan(
            State(fx.state.clone()),
            Extension(tdh::make_auth(outsider, &outname)),
            Path(scan_id),
        )
        .await;
        // truly-absent scan id.
        let absent = get_scan(
            State(fx.state.clone()),
            Extension(tdh::make_auth(outsider, &outname)),
            Path(Uuid::new_v4()),
        )
        .await;

        teardown_scans(&fx.pool, fx.repo_id).await;
        tdh::cleanup_user(&fx.pool, outsider).await;
        fx.teardown().await;

        let hm = not_found_msg(&hidden);
        let am = not_found_msg(&absent);
        assert_eq!(
            hm, am,
            "hidden and absent get_scan 404 bodies must be identical (no oracle)"
        );
        assert_eq!(hm, SCAN_NOT_FOUND_MSG, "canonical scan-not-found message");
    }

    #[tokio::test]
    async fn test_list_findings_404_body_uniform_hidden_vs_absent_db() {
        use crate::api::handlers::test_db_helpers as tdh;
        let Some(fx) = tdh::Fixture::setup("local", "generic").await else {
            return;
        };
        let art = seed_artifact_row(&fx.pool, fx.repo_id).await;
        let (scan_id, _f) = seed_scan_with_finding(&fx.pool, fx.repo_id, art).await;
        let (outsider, outname) = tdh::create_user(&fx.pool).await;

        let hidden = list_findings(
            State(fx.state.clone()),
            Extension(tdh::make_auth(outsider, &outname)),
            Path(scan_id),
            Query(ListFindingsQuery::default()),
        )
        .await;
        let absent = list_findings(
            State(fx.state.clone()),
            Extension(tdh::make_auth(outsider, &outname)),
            Path(Uuid::new_v4()),
            Query(ListFindingsQuery::default()),
        )
        .await;

        teardown_scans(&fx.pool, fx.repo_id).await;
        tdh::cleanup_user(&fx.pool, outsider).await;
        fx.teardown().await;

        let hm = not_found_msg(&hidden);
        let am = not_found_msg(&absent);
        assert_eq!(
            hm, am,
            "hidden and absent list_findings 404 bodies must be identical (no oracle)"
        );
        assert_eq!(hm, SCAN_NOT_FOUND_MSG, "canonical scan-not-found message");
    }
}
