//! Security scanning and policy management handlers.

use axum::{
    extract::{Extension, Path, Query, State},
    routing::{delete, get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::api::middleware::auth::AuthExtension;
use crate::api::SharedState;
use crate::error::{AppError, Result};
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
            "/security",
            get(get_repo_security).put(update_repo_security),
        )
        .route("/security/scans", get(list_repo_scans))
}

// ---------------------------------------------------------------------------
// Request / Response types
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize)]
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

#[derive(Debug, Serialize)]
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

#[derive(Debug, Deserialize)]
pub struct TriggerScanRequest {
    pub artifact_id: Option<Uuid>,
    pub repository_id: Option<Uuid>,
}

#[derive(Debug, Serialize)]
pub struct TriggerScanResponse {
    pub message: String,
    pub artifacts_queued: u32,
}

#[derive(Debug, Deserialize)]
pub struct ListScansQuery {
    pub repository_id: Option<Uuid>,
    pub artifact_id: Option<Uuid>,
    pub status: Option<String>,
    pub page: Option<i64>,
    pub per_page: Option<i64>,
}

#[derive(Debug, Serialize)]
pub struct ScanListResponse {
    pub items: Vec<ScanResponse>,
    pub total: i64,
}

#[derive(Debug, Serialize)]
pub struct ScanResponse {
    pub id: Uuid,
    pub artifact_id: Uuid,
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

#[derive(Debug, Deserialize)]
pub struct ListFindingsQuery {
    pub page: Option<i64>,
    pub per_page: Option<i64>,
}

#[derive(Debug, Serialize)]
pub struct FindingListResponse {
    pub items: Vec<FindingResponse>,
    pub total: i64,
}

#[derive(Debug, Serialize)]
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

#[derive(Debug, Deserialize)]
pub struct AcknowledgeRequest {
    pub reason: String,
}

#[derive(Debug, Deserialize)]
pub struct CreatePolicyRequest {
    pub name: String,
    pub repository_id: Option<Uuid>,
    pub max_severity: String,
    pub block_unscanned: bool,
    pub block_on_fail: bool,
}

#[derive(Debug, Deserialize)]
pub struct UpdatePolicyRequest {
    pub name: String,
    pub max_severity: String,
    pub block_unscanned: bool,
    pub block_on_fail: bool,
    pub is_enabled: bool,
}

#[derive(Debug, Serialize)]
pub struct PolicyResponse {
    pub id: Uuid,
    pub name: String,
    pub repository_id: Option<Uuid>,
    pub max_severity: String,
    pub block_unscanned: bool,
    pub block_on_fail: bool,
    pub is_enabled: bool,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Serialize)]
pub struct RepoSecurityResponse {
    pub config: Option<ScanConfigResponse>,
    pub score: Option<ScoreResponse>,
}

#[derive(Debug, Serialize)]
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

async fn get_all_scores(
    State(state): State<SharedState>,
    Extension(_auth): Extension<AuthExtension>,
) -> Result<Json<Vec<ScoreResponse>>> {
    let svc = ScanResultService::new(state.db.clone());
    let scores = svc.get_all_scores().await?;

    let response: Vec<ScoreResponse> = scores
        .into_iter()
        .map(|s| ScoreResponse {
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
        })
        .collect();

    Ok(Json(response))
}

// ---------------------------------------------------------------------------
// Scan operations
// ---------------------------------------------------------------------------

async fn trigger_scan(
    State(_state): State<SharedState>,
    Extension(_auth): Extension<AuthExtension>,
    Json(body): Json<TriggerScanRequest>,
) -> Result<Json<TriggerScanResponse>> {
    if body.artifact_id.is_none() && body.repository_id.is_none() {
        return Err(AppError::Validation(
            "Either artifact_id or repository_id is required".to_string(),
        ));
    }

    // For now, return a queued response. The actual scanning runs async.
    // In a full implementation, we'd spawn the scanner task here.
    let msg = if let Some(artifact_id) = body.artifact_id {
        format!("Scan queued for artifact {}", artifact_id)
    } else if let Some(repo_id) = body.repository_id {
        format!("Repository scan queued for {}", repo_id)
    } else {
        unreachable!()
    };

    Ok(Json(TriggerScanResponse {
        message: msg,
        artifacts_queued: 1,
    }))
}

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

    let items: Vec<ScanResponse> = scans
        .into_iter()
        .map(|s| ScanResponse {
            id: s.id,
            artifact_id: s.artifact_id,
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
        })
        .collect();

    Ok(Json(ScanListResponse { items, total }))
}

async fn get_scan(
    State(state): State<SharedState>,
    Extension(_auth): Extension<AuthExtension>,
    Path(id): Path<Uuid>,
) -> Result<Json<ScanResponse>> {
    let svc = ScanResultService::new(state.db.clone());
    let s = svc.get_scan(id).await?;

    Ok(Json(ScanResponse {
        id: s.id,
        artifact_id: s.artifact_id,
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
    }))
}

// ---------------------------------------------------------------------------
// Findings
// ---------------------------------------------------------------------------

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

    let items: Vec<FindingResponse> = findings
        .into_iter()
        .map(|f| FindingResponse {
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
        })
        .collect();

    Ok(Json(FindingListResponse { items, total }))
}

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

    Ok(Json(FindingResponse {
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
    }))
}

async fn revoke_acknowledgment(
    State(state): State<SharedState>,
    Extension(_auth): Extension<AuthExtension>,
    Path(finding_id): Path<Uuid>,
) -> Result<Json<FindingResponse>> {
    let svc = ScanResultService::new(state.db.clone());
    let f = svc.revoke_acknowledgment(finding_id).await?;

    Ok(Json(FindingResponse {
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
    }))
}

// ---------------------------------------------------------------------------
// Policies
// ---------------------------------------------------------------------------

async fn list_policies(
    State(state): State<SharedState>,
    Extension(_auth): Extension<AuthExtension>,
) -> Result<Json<Vec<PolicyResponse>>> {
    let svc = PolicyService::new(state.db.clone());
    let policies = svc.list_policies().await?;

    let response: Vec<PolicyResponse> = policies
        .into_iter()
        .map(|p| PolicyResponse {
            id: p.id,
            name: p.name,
            repository_id: p.repository_id,
            max_severity: p.max_severity,
            block_unscanned: p.block_unscanned,
            block_on_fail: p.block_on_fail,
            is_enabled: p.is_enabled,
            created_at: p.created_at,
            updated_at: p.updated_at,
        })
        .collect();

    Ok(Json(response))
}

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
        )
        .await?;

    Ok(Json(PolicyResponse {
        id: p.id,
        name: p.name,
        repository_id: p.repository_id,
        max_severity: p.max_severity,
        block_unscanned: p.block_unscanned,
        block_on_fail: p.block_on_fail,
        is_enabled: p.is_enabled,
        created_at: p.created_at,
        updated_at: p.updated_at,
    }))
}

async fn get_policy(
    State(state): State<SharedState>,
    Extension(_auth): Extension<AuthExtension>,
    Path(id): Path<Uuid>,
) -> Result<Json<PolicyResponse>> {
    let svc = PolicyService::new(state.db.clone());
    let p = svc.get_policy(id).await?;

    Ok(Json(PolicyResponse {
        id: p.id,
        name: p.name,
        repository_id: p.repository_id,
        max_severity: p.max_severity,
        block_unscanned: p.block_unscanned,
        block_on_fail: p.block_on_fail,
        is_enabled: p.is_enabled,
        created_at: p.created_at,
        updated_at: p.updated_at,
    }))
}

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
        )
        .await?;

    Ok(Json(PolicyResponse {
        id: p.id,
        name: p.name,
        repository_id: p.repository_id,
        max_severity: p.max_severity,
        block_unscanned: p.block_unscanned,
        block_on_fail: p.block_on_fail,
        is_enabled: p.is_enabled,
        created_at: p.created_at,
        updated_at: p.updated_at,
    }))
}

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

async fn get_repo_security(
    State(state): State<SharedState>,
    Extension(_auth): Extension<AuthExtension>,
    Path(key): Path<String>,
) -> Result<Json<RepoSecurityResponse>> {
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
        config: config.map(|c| ScanConfigResponse {
            id: c.id,
            repository_id: c.repository_id,
            scan_enabled: c.scan_enabled,
            scan_on_upload: c.scan_on_upload,
            scan_on_proxy: c.scan_on_proxy,
            block_on_policy_violation: c.block_on_policy_violation,
            severity_threshold: c.severity_threshold,
            created_at: c.created_at,
            updated_at: c.updated_at,
        }),
        score: score.map(|s| ScoreResponse {
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
        }),
    }))
}

async fn update_repo_security(
    State(state): State<SharedState>,
    Extension(_auth): Extension<AuthExtension>,
    Path(key): Path<String>,
    Json(body): Json<UpsertScanConfigRequest>,
) -> Result<Json<ScanConfigResponse>> {
    let repo = sqlx::query_scalar!("SELECT id FROM repositories WHERE key = $1", key,)
        .fetch_optional(&state.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?
        .ok_or_else(|| AppError::NotFound("Repository not found".to_string()))?;

    let svc = ScanConfigService::new(state.db.clone());
    let c = svc.upsert_config(repo, &body).await?;

    Ok(Json(ScanConfigResponse {
        id: c.id,
        repository_id: c.repository_id,
        scan_enabled: c.scan_enabled,
        scan_on_upload: c.scan_on_upload,
        scan_on_proxy: c.scan_on_proxy,
        block_on_policy_violation: c.block_on_policy_violation,
        severity_threshold: c.severity_threshold,
        created_at: c.created_at,
        updated_at: c.updated_at,
    }))
}

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

    Ok(Json(ScanListResponse {
        items: scans
            .into_iter()
            .map(|s| ScanResponse {
                id: s.id,
                artifact_id: s.artifact_id,
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
            })
            .collect(),
        total,
    }))
}

async fn list_repo_scans(
    State(state): State<SharedState>,
    Extension(_auth): Extension<AuthExtension>,
    Path(key): Path<String>,
    Query(query): Query<ListScansQuery>,
) -> Result<Json<ScanListResponse>> {
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

    let items: Vec<ScanResponse> = scans
        .into_iter()
        .map(|s| ScanResponse {
            id: s.id,
            artifact_id: s.artifact_id,
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
        })
        .collect();

    Ok(Json(ScanListResponse { items, total }))
}
