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

use crate::api::middleware::auth::AuthExtension;
use crate::api::SharedState;
use crate::error::{AppError, Result};
use crate::models::security::ScanResult;
use crate::services::policy_service::PolicyService;
use crate::services::scan_config_service::{ScanConfigService, UpsertScanConfigRequest};
use crate::services::scan_result_service::ScanResultService;

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
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct TriggerScanRequest {
    pub artifact_id: Option<Uuid>,
    pub repository_id: Option<Uuid>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct TriggerScanResponse {
    pub message: String,
    pub artifacts_queued: u32,
}

#[derive(Debug, Deserialize, IntoParams)]
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
        Self {
            id: s.id,
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
        }
    }
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

#[derive(Debug, Deserialize, IntoParams)]
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

#[derive(Debug, Deserialize, ToSchema)]
pub struct CreatePolicyRequest {
    pub name: String,
    pub repository_id: Option<Uuid>,
    pub max_severity: String,
    pub block_unscanned: bool,
    pub block_on_fail: bool,
    pub min_staging_hours: Option<i32>,
    pub max_artifact_age_days: Option<i32>,
    #[serde(default)]
    pub require_signature: bool,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct UpdatePolicyRequest {
    pub name: String,
    pub max_severity: String,
    pub block_unscanned: bool,
    pub block_on_fail: bool,
    pub is_enabled: bool,
    pub min_staging_hours: Option<i32>,
    pub max_artifact_age_days: Option<i32>,
    #[serde(default)]
    pub require_signature: bool,
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
    pub block_on_policy_violation: bool,
    pub severity_threshold: String,
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
    ),
    security(("bearer_auth" = []))
)]
async fn get_dashboard(
    State(state): State<SharedState>,
    Extension(_auth): Extension<AuthExtension>,
) -> Result<Json<DashboardResponse>> {
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
    ),
    security(("bearer_auth" = []))
)]
async fn get_all_scores(
    State(state): State<SharedState>,
    Extension(_auth): Extension<AuthExtension>,
) -> Result<Json<Vec<ScoreResponse>>> {
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
        (status = 500, description = "Scanner service not configured", body = crate::api::openapi::ErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
async fn trigger_scan(
    State(state): State<SharedState>,
    Extension(_auth): Extension<AuthExtension>,
    Json(body): Json<TriggerScanRequest>,
) -> Result<Json<TriggerScanResponse>> {
    let scanner = state
        .scanner_service
        .as_ref()
        .ok_or_else(|| AppError::Internal("Scanner service not configured".to_string()))?
        .clone();

    if let Some(artifact_id) = body.artifact_id {
        tokio::spawn(async move {
            if let Err(e) = scanner.scan_artifact_with_options(artifact_id, true).await {
                tracing::error!("Scan failed for artifact {}: {}", artifact_id, e);
            }
        });
        return Ok(Json(TriggerScanResponse {
            message: format!("Scan queued for artifact {}", artifact_id),
            artifacts_queued: 1,
        }));
    }

    let repository_id = body.repository_id.ok_or_else(|| {
        AppError::Validation("Either artifact_id or repository_id is required".to_string())
    })?;

    let count: i64 = sqlx::query_scalar!(
        "SELECT COUNT(*) as \"count!\" FROM artifacts WHERE repository_id = $1 AND is_deleted = false",
        repository_id
    )
    .fetch_one(&state.db)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;

    tokio::spawn(async move {
        if let Err(e) = scanner
            .scan_repository_with_options(repository_id, true)
            .await
        {
            tracing::error!("Repository scan failed for {}: {}", repository_id, e);
        }
    });
    Ok(Json(TriggerScanResponse {
        message: format!(
            "Repository scan queued for {} ({} artifacts)",
            repository_id, count
        ),
        artifacts_queued: count as u32,
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
    Extension(_auth): Extension<AuthExtension>,
    Query(query): Query<ListScansQuery>,
) -> Result<Json<ScanListResponse>> {
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

    let items = enrich_scans(&state.db, scans).await?;
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
    Extension(_auth): Extension<AuthExtension>,
    Path(id): Path<Uuid>,
) -> Result<Json<ScanResponse>> {
    let svc = ScanResultService::new(state.db.clone());
    let s = svc.get_scan(id).await?;

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
    Extension(_auth): Extension<AuthExtension>,
    Path(scan_id): Path<Uuid>,
    Query(query): Query<ListFindingsQuery>,
) -> Result<Json<FindingListResponse>> {
    let svc = ScanResultService::new(state.db.clone());
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
        (status = 404, description = "Finding not found", body = crate::api::openapi::ErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
async fn revoke_acknowledgment(
    State(state): State<SharedState>,
    Extension(_auth): Extension<AuthExtension>,
    Path(finding_id): Path<Uuid>,
) -> Result<Json<FindingResponse>> {
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
        (status = 422, description = "Validation error", body = crate::api::openapi::ErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
async fn create_policy(
    State(state): State<SharedState>,
    Extension(_auth): Extension<AuthExtension>,
    Json(body): Json<CreatePolicyRequest>,
) -> Result<Json<PolicyResponse>> {
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
    Extension(_auth): Extension<AuthExtension>,
    Path(id): Path<Uuid>,
    Json(body): Json<UpdatePolicyRequest>,
) -> Result<Json<PolicyResponse>> {
    let svc = PolicyService::new(state.db.clone());
    let p = svc
        .update_policy(
            id,
            &body.name,
            &body.max_severity,
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
    Extension(_auth): Extension<AuthExtension>,
    Path(id): Path<Uuid>,
) -> Result<Json<serde_json::Value>> {
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
    let _auth =
        auth.ok_or_else(|| AppError::Authentication("Authentication required".to_string()))?;
    // Resolve repository by key
    let repo = sqlx::query_scalar!("SELECT id FROM repositories WHERE key = $1", key,)
        .fetch_optional(&state.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?
        .ok_or_else(|| AppError::NotFound("Repository not found".to_string()))?;

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
    let _auth =
        auth.ok_or_else(|| AppError::Authentication("Authentication required".to_string()))?;
    let repo = sqlx::query_scalar!("SELECT id FROM repositories WHERE key = $1", key,)
        .fetch_optional(&state.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?
        .ok_or_else(|| AppError::NotFound("Repository not found".to_string()))?;

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
    Extension(_auth): Extension<AuthExtension>,
    Path(artifact_id): Path<Uuid>,
    Query(query): Query<ListScansQuery>,
) -> Result<Json<ScanListResponse>> {
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

    let items = enrich_scans(&state.db, scans).await?;
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
    let _auth =
        auth.ok_or_else(|| AppError::Authentication("Authentication required".to_string()))?;
    let repo = sqlx::query_scalar!("SELECT id FROM repositories WHERE key = $1", key,)
        .fetch_optional(&state.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?
        .ok_or_else(|| AppError::NotFound("Repository not found".to_string()))?;

    let svc = ScanResultService::new(state.db.clone());
    let page = query.page.unwrap_or(1);
    let per_page = query.per_page.unwrap_or(20).min(100);
    let offset = (page - 1) * per_page;

    let (scans, total) = svc
        .list_scans(Some(repo), None, query.status.as_deref(), offset, per_page)
        .await?;

    let items = enrich_scans(&state.db, scans).await?;
    Ok(Json(ScanListResponse { items, total }))
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
    ))
)]
pub struct SecurityApiDoc;

// ---------------------------------------------------------------------------
// Pure helper functions (testable without DB)
// ---------------------------------------------------------------------------

/// Compute scan list pagination values.
/// Returns `(page, per_page, offset)`.
pub(crate) fn compute_scan_pagination(
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
pub(crate) fn compute_findings_pagination(
    raw_page: Option<i64>,
    raw_per_page: Option<i64>,
) -> (i64, i64, i64) {
    let page = raw_page.unwrap_or(1);
    let per_page = raw_per_page.unwrap_or(50).min(200);
    let offset = (page - 1) * per_page;
    (page, per_page, offset)
}

/// Build the trigger scan response message for a single artifact.
pub(crate) fn build_artifact_scan_message(artifact_id: Uuid) -> TriggerScanResponse {
    TriggerScanResponse {
        message: format!("Scan queued for artifact {}", artifact_id),
        artifacts_queued: 1,
    }
}

/// Build the trigger scan response message for a repository scan.
pub(crate) fn build_repo_scan_message(repository_id: Uuid, count: i64) -> TriggerScanResponse {
    TriggerScanResponse {
        message: format!(
            "Repository scan queued for {} ({} artifacts)",
            repository_id, count
        ),
        artifacts_queued: count as u32,
    }
}

/// Build a JSON response for successful deletion.
pub(crate) fn build_deleted_response() -> serde_json::Value {
    serde_json::json!({ "deleted": true })
}

/// Convert a ScanResult model into a ScanResponse DTO with artifact info.
pub(crate) fn scan_result_to_response(
    s: ScanResult,
    artifact_name: Option<String>,
    artifact_version: Option<String>,
) -> ScanResponse {
    ScanResponse::from_scan(s, artifact_name, artifact_version)
}

#[cfg(test)]
mod tests {
    use super::*;

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
        };
        let resp = scan_result_to_response(scan, None, None);
        assert_eq!(resp.artifact_name, None);
        assert_eq!(resp.artifact_version, None);
        assert_eq!(
            resp.error_message,
            Some("Scanner not available".to_string())
        );
        assert_eq!(resp.status, "failed");
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
        assert_eq!(req.name, "updated-policy");
        assert!(!req.is_enabled);
        assert!(!req.require_signature);
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
        assert_eq!(req.name, "full-update");
        assert_eq!(req.max_severity, "low");
        assert!(req.block_unscanned);
        assert!(req.block_on_fail);
        assert!(req.is_enabled);
        assert_eq!(req.min_staging_hours, Some(48));
        assert_eq!(req.max_artifact_age_days, Some(365));
        assert!(req.require_signature);
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
        };
        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains("\"artifacts_queued\":42"));
        assert!(json.contains("Scan queued"));
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
}
