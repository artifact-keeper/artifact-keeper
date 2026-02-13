//! Quality gates and health score handlers.

use axum::{
    extract::{Extension, Path, Query, State},
    routing::{delete, get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, OpenApi, ToSchema};
use uuid::Uuid;

use crate::api::middleware::auth::AuthExtension;
use crate::api::SharedState;
use crate::error::{AppError, Result};
use crate::services::quality_check_service::QualityCheckService;

/// Create quality gate routes
pub fn router() -> Router<SharedState> {
    Router::new()
        // Health scores
        .route("/health/artifacts/:artifact_id", get(get_artifact_health))
        .route("/health/repositories/:key", get(get_repo_health))
        .route("/health/dashboard", get(get_health_dashboard))
        // Quality checks
        .route("/checks/trigger", post(trigger_checks))
        .route("/checks", get(list_checks))
        .route("/checks/:id", get(get_check))
        .route("/checks/:id/issues", get(list_check_issues))
        // Issue suppression
        .route("/issues/:id/suppress", post(suppress_issue))
        .route("/issues/:id/suppress", delete(unsuppress_issue))
        // Quality gate CRUD
        .route("/gates", get(list_gates).post(create_gate))
        .route(
            "/gates/:id",
            get(get_gate).put(update_gate).delete(delete_gate),
        )
        // Gate evaluation
        .route("/gates/evaluate/:artifact_id", post(evaluate_gate))
}

#[derive(Debug, Serialize, ToSchema)]
pub struct ArtifactHealthResponse {
    pub artifact_id: Uuid,
    pub health_score: i32,
    pub health_grade: String,
    pub security_score: Option<i32>,
    pub license_score: Option<i32>,
    pub quality_score: Option<i32>,
    pub metadata_score: Option<i32>,
    pub total_issues: i32,
    pub critical_issues: i32,
    pub checks_passed: i32,
    pub checks_total: i32,
    pub last_checked_at: Option<chrono::DateTime<chrono::Utc>>,
    pub checks: Vec<CheckSummary>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct CheckSummary {
    pub check_type: String,
    pub score: Option<i32>,
    pub passed: Option<bool>,
    pub status: String,
    pub issues_count: i32,
    pub completed_at: Option<chrono::DateTime<chrono::Utc>>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct RepoHealthResponse {
    pub repository_id: Uuid,
    pub repository_key: String,
    pub health_score: i32,
    pub health_grade: String,
    pub avg_security_score: Option<i32>,
    pub avg_license_score: Option<i32>,
    pub avg_quality_score: Option<i32>,
    pub avg_metadata_score: Option<i32>,
    pub artifacts_evaluated: i32,
    pub artifacts_passing: i32,
    pub artifacts_failing: i32,
    pub last_evaluated_at: Option<chrono::DateTime<chrono::Utc>>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct HealthDashboardResponse {
    pub total_repositories: i64,
    pub total_artifacts_evaluated: i64,
    pub avg_health_score: i32,
    pub repos_grade_a: i64,
    pub repos_grade_b: i64,
    pub repos_grade_c: i64,
    pub repos_grade_d: i64,
    pub repos_grade_f: i64,
    pub repositories: Vec<RepoHealthResponse>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct CheckResponse {
    pub id: Uuid,
    pub artifact_id: Uuid,
    pub repository_id: Uuid,
    pub check_type: String,
    pub status: String,
    pub score: Option<i32>,
    pub passed: Option<bool>,
    #[schema(value_type = Option<Object>)]
    pub details: Option<serde_json::Value>,
    pub issues_count: i32,
    pub critical_count: i32,
    pub high_count: i32,
    pub medium_count: i32,
    pub low_count: i32,
    pub info_count: i32,
    pub checker_version: Option<String>,
    pub error_message: Option<String>,
    pub started_at: Option<chrono::DateTime<chrono::Utc>>,
    pub completed_at: Option<chrono::DateTime<chrono::Utc>>,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct IssueResponse {
    pub id: Uuid,
    pub check_result_id: Uuid,
    pub artifact_id: Uuid,
    pub severity: String,
    pub category: String,
    pub title: String,
    pub description: Option<String>,
    pub location: Option<String>,
    pub is_suppressed: bool,
    pub suppressed_by: Option<Uuid>,
    pub suppressed_reason: Option<String>,
    pub suppressed_at: Option<chrono::DateTime<chrono::Utc>>,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct TriggerChecksRequest {
    pub artifact_id: Option<Uuid>,
    pub repository_id: Option<Uuid>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct TriggerChecksResponse {
    pub message: String,
    pub artifacts_queued: u32,
}

#[derive(Debug, Deserialize, IntoParams)]
pub struct ListChecksQuery {
    pub artifact_id: Option<Uuid>,
    pub repository_id: Option<Uuid>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct SuppressIssueRequest {
    pub reason: String,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct CreateGateRequest {
    pub repository_id: Option<Uuid>,
    pub name: String,
    pub description: Option<String>,
    pub min_health_score: Option<i32>,
    pub min_security_score: Option<i32>,
    pub min_quality_score: Option<i32>,
    pub min_metadata_score: Option<i32>,
    pub max_critical_issues: Option<i32>,
    pub max_high_issues: Option<i32>,
    pub max_medium_issues: Option<i32>,
    #[serde(default)]
    pub required_checks: Vec<String>,
    #[serde(default = "default_true")]
    pub enforce_on_promotion: bool,
    #[serde(default)]
    pub enforce_on_download: bool,
    #[serde(default = "default_warn")]
    pub action: String,
}

fn default_true() -> bool {
    true
}
fn default_warn() -> String {
    "warn".to_string()
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct UpdateGateRequest {
    pub name: Option<String>,
    pub description: Option<String>,
    pub min_health_score: Option<i32>,
    pub min_security_score: Option<i32>,
    pub min_quality_score: Option<i32>,
    pub min_metadata_score: Option<i32>,
    pub max_critical_issues: Option<i32>,
    pub max_high_issues: Option<i32>,
    pub max_medium_issues: Option<i32>,
    pub required_checks: Option<Vec<String>>,
    pub enforce_on_promotion: Option<bool>,
    pub enforce_on_download: Option<bool>,
    pub action: Option<String>,
    pub is_enabled: Option<bool>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct GateResponse {
    pub id: Uuid,
    pub repository_id: Option<Uuid>,
    pub name: String,
    pub description: Option<String>,
    pub min_health_score: Option<i32>,
    pub min_security_score: Option<i32>,
    pub min_quality_score: Option<i32>,
    pub min_metadata_score: Option<i32>,
    pub max_critical_issues: Option<i32>,
    pub max_high_issues: Option<i32>,
    pub max_medium_issues: Option<i32>,
    pub required_checks: Vec<String>,
    pub enforce_on_promotion: bool,
    pub enforce_on_download: bool,
    pub action: String,
    pub is_enabled: bool,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct GateEvaluationResponse {
    pub passed: bool,
    pub action: String,
    pub gate_name: String,
    pub health_score: i32,
    pub health_grade: String,
    pub violations: Vec<GateViolationResponse>,
    #[schema(value_type = Object)]
    pub component_scores: serde_json::Value,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct GateViolationResponse {
    pub rule: String,
    pub expected: String,
    pub actual: String,
    pub message: String,
}

#[derive(Debug, Deserialize, IntoParams)]
pub struct EvaluateGateQuery {
    pub repository_id: Option<Uuid>,
}

impl From<crate::models::quality::QualityCheckResult> for CheckResponse {
    fn from(c: crate::models::quality::QualityCheckResult) -> Self {
        Self {
            id: c.id,
            artifact_id: c.artifact_id,
            repository_id: c.repository_id,
            check_type: c.check_type,
            status: c.status,
            score: c.score,
            passed: c.passed,
            details: c.details,
            issues_count: c.issues_count,
            critical_count: c.critical_count,
            high_count: c.high_count,
            medium_count: c.medium_count,
            low_count: c.low_count,
            info_count: c.info_count,
            checker_version: c.checker_version,
            error_message: c.error_message,
            started_at: c.started_at,
            completed_at: c.completed_at,
            created_at: c.created_at,
        }
    }
}

impl From<crate::models::quality::QualityCheckIssue> for IssueResponse {
    fn from(i: crate::models::quality::QualityCheckIssue) -> Self {
        Self {
            id: i.id,
            check_result_id: i.check_result_id,
            artifact_id: i.artifact_id,
            severity: i.severity,
            category: i.category,
            title: i.title,
            description: i.description,
            location: i.location,
            is_suppressed: i.is_suppressed,
            suppressed_by: i.suppressed_by,
            suppressed_reason: i.suppressed_reason,
            suppressed_at: i.suppressed_at,
            created_at: i.created_at,
        }
    }
}

impl From<crate::models::quality::QualityGate> for GateResponse {
    fn from(g: crate::models::quality::QualityGate) -> Self {
        Self {
            id: g.id,
            repository_id: g.repository_id,
            name: g.name,
            description: g.description,
            min_health_score: g.min_health_score,
            min_security_score: g.min_security_score,
            min_quality_score: g.min_quality_score,
            min_metadata_score: g.min_metadata_score,
            max_critical_issues: g.max_critical_issues,
            max_high_issues: g.max_high_issues,
            max_medium_issues: g.max_medium_issues,
            required_checks: g.required_checks,
            enforce_on_promotion: g.enforce_on_promotion,
            enforce_on_download: g.enforce_on_download,
            action: g.action,
            is_enabled: g.is_enabled,
            created_at: g.created_at,
            updated_at: g.updated_at,
        }
    }
}

impl From<crate::models::quality::QualityGateViolation> for GateViolationResponse {
    fn from(v: crate::models::quality::QualityGateViolation) -> Self {
        Self {
            rule: v.rule,
            expected: v.expected,
            actual: v.actual,
            message: v.message,
        }
    }
}

#[utoipa::path(
    get,
    path = "/health/artifacts/{artifact_id}",
    context_path = "/api/v1/quality",
    tag = "quality",
    params(
        ("artifact_id" = Uuid, Path, description = "Artifact ID"),
    ),
    responses(
        (status = 200, description = "Artifact health score", body = ArtifactHealthResponse),
        (status = 404, description = "Artifact not found", body = crate::api::openapi::ErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
async fn get_artifact_health(
    State(state): State<SharedState>,
    Extension(_auth): Extension<AuthExtension>,
    Path(artifact_id): Path<Uuid>,
) -> Result<Json<ArtifactHealthResponse>> {
    let qc_service = QualityCheckService::new(state.db.clone());

    let health = qc_service
        .get_artifact_health(artifact_id)
        .await?
        .ok_or_else(|| AppError::NotFound("No health score found for artifact".to_string()))?;
    let checks = qc_service.list_checks(artifact_id).await?;

    let check_summaries: Vec<CheckSummary> = checks
        .into_iter()
        .map(|c| CheckSummary {
            check_type: c.check_type,
            score: c.score,
            passed: c.passed,
            status: c.status,
            issues_count: c.issues_count,
            completed_at: c.completed_at,
        })
        .collect();

    Ok(Json(ArtifactHealthResponse {
        artifact_id: health.artifact_id,
        health_score: health.health_score,
        health_grade: health.health_grade,
        security_score: health.security_score,
        license_score: health.license_score,
        quality_score: health.quality_score,
        metadata_score: health.metadata_score,
        total_issues: health.total_issues,
        critical_issues: health.critical_issues,
        checks_passed: health.checks_passed,
        checks_total: health.checks_total,
        last_checked_at: health.last_checked_at,
        checks: check_summaries,
    }))
}

#[utoipa::path(
    get,
    path = "/health/repositories/{key}",
    context_path = "/api/v1/quality",
    tag = "quality",
    params(
        ("key" = String, Path, description = "Repository key"),
    ),
    responses(
        (status = 200, description = "Repository health score", body = RepoHealthResponse),
        (status = 404, description = "Repository not found", body = crate::api::openapi::ErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
async fn get_repo_health(
    State(state): State<SharedState>,
    Extension(_auth): Extension<AuthExtension>,
    Path(key): Path<String>,
) -> Result<Json<RepoHealthResponse>> {
    let repo_id: Uuid = sqlx::query_scalar("SELECT id FROM repositories WHERE key = $1")
        .bind(&key)
        .fetch_optional(&state.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?
        .ok_or_else(|| AppError::NotFound("Repository not found".to_string()))?;

    let qc_service = QualityCheckService::new(state.db.clone());
    let health = qc_service
        .get_repo_health(repo_id)
        .await?
        .ok_or_else(|| AppError::NotFound("No health score found for repository".to_string()))?;

    Ok(Json(RepoHealthResponse {
        repository_id: health.repository_id,
        repository_key: key,
        health_score: health.health_score,
        health_grade: health.health_grade,
        avg_security_score: health.avg_security_score,
        avg_license_score: health.avg_license_score,
        avg_quality_score: health.avg_quality_score,
        avg_metadata_score: health.avg_metadata_score,
        artifacts_evaluated: health.artifacts_evaluated,
        artifacts_passing: health.artifacts_passing,
        artifacts_failing: health.artifacts_failing,
        last_evaluated_at: health.last_evaluated_at,
    }))
}

#[utoipa::path(
    get,
    path = "/health/dashboard",
    context_path = "/api/v1/quality",
    tag = "quality",
    responses(
        (status = 200, description = "Health dashboard summary", body = HealthDashboardResponse),
    ),
    security(("bearer_auth" = []))
)]
async fn get_health_dashboard(
    State(state): State<SharedState>,
    Extension(_auth): Extension<AuthExtension>,
) -> Result<Json<HealthDashboardResponse>> {
    let qc_service = QualityCheckService::new(state.db.clone());
    let all_repo_scores = qc_service.list_repo_health_scores().await?;

    // Look up repository keys for all repos
    let repo_ids: Vec<Uuid> = all_repo_scores.iter().map(|r| r.repository_id).collect();
    let repo_keys: std::collections::HashMap<Uuid, String> = if !repo_ids.is_empty() {
        sqlx::query_as::<_, (Uuid, String)>(
            r#"SELECT id, key FROM repositories WHERE id = ANY($1)"#,
        )
        .bind(&repo_ids)
        .fetch_all(&state.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?
        .into_iter()
        .collect()
    } else {
        std::collections::HashMap::new()
    };

    let total_repositories = all_repo_scores.len() as i64;
    let total_artifacts_evaluated: i64 = all_repo_scores
        .iter()
        .map(|r| r.artifacts_evaluated as i64)
        .sum();
    let avg_health_score = if total_repositories > 0 {
        (all_repo_scores
            .iter()
            .map(|r| r.health_score as i64)
            .sum::<i64>()
            / total_repositories) as i32
    } else {
        0
    };

    let (
        mut repos_grade_a,
        mut repos_grade_b,
        mut repos_grade_c,
        mut repos_grade_d,
        mut repos_grade_f,
    ) = (0i64, 0i64, 0i64, 0i64, 0i64);
    for r in &all_repo_scores {
        match r.health_grade.as_str() {
            "A" => repos_grade_a += 1,
            "B" => repos_grade_b += 1,
            "C" => repos_grade_c += 1,
            "D" => repos_grade_d += 1,
            _ => repos_grade_f += 1,
        }
    }

    let repositories: Vec<RepoHealthResponse> = all_repo_scores
        .into_iter()
        .map(|r| {
            let key = repo_keys.get(&r.repository_id).cloned().unwrap_or_default();
            RepoHealthResponse {
                repository_id: r.repository_id,
                repository_key: key,
                health_score: r.health_score,
                health_grade: r.health_grade,
                avg_security_score: r.avg_security_score,
                avg_license_score: r.avg_license_score,
                avg_quality_score: r.avg_quality_score,
                avg_metadata_score: r.avg_metadata_score,
                artifacts_evaluated: r.artifacts_evaluated,
                artifacts_passing: r.artifacts_passing,
                artifacts_failing: r.artifacts_failing,
                last_evaluated_at: r.last_evaluated_at,
            }
        })
        .collect();

    Ok(Json(HealthDashboardResponse {
        total_repositories,
        total_artifacts_evaluated,
        avg_health_score,
        repos_grade_a,
        repos_grade_b,
        repos_grade_c,
        repos_grade_d,
        repos_grade_f,
        repositories,
    }))
}

#[utoipa::path(
    post,
    path = "/checks/trigger",
    context_path = "/api/v1/quality",
    tag = "quality",
    request_body = TriggerChecksRequest,
    responses(
        (status = 200, description = "Quality checks triggered", body = TriggerChecksResponse),
        (status = 400, description = "Validation error", body = crate::api::openapi::ErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
async fn trigger_checks(
    State(state): State<SharedState>,
    Extension(_auth): Extension<AuthExtension>,
    Json(body): Json<TriggerChecksRequest>,
) -> Result<Json<TriggerChecksResponse>> {
    if let Some(artifact_id) = body.artifact_id {
        let db = state.db.clone();
        tokio::spawn(async move {
            let svc = QualityCheckService::new(db);
            if let Err(e) = svc.check_artifact(artifact_id).await {
                tracing::error!("Quality checks failed for artifact {}: {}", artifact_id, e);
            }
        });
        return Ok(Json(TriggerChecksResponse {
            message: format!("Quality checks queued for artifact {}", artifact_id),
            artifacts_queued: 1,
        }));
    }

    let repository_id = body.repository_id.ok_or_else(|| {
        AppError::Validation("Either artifact_id or repository_id is required".to_string())
    })?;

    let count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*)::int8 FROM artifacts WHERE repository_id = $1 AND is_deleted = false",
    )
    .bind(repository_id)
    .fetch_one(&state.db)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;

    let db = state.db.clone();
    tokio::spawn(async move {
        let svc = QualityCheckService::new(db);
        if let Err(e) = svc.check_repository(repository_id).await {
            tracing::error!(
                "Quality checks failed for repository {}: {}",
                repository_id,
                e
            );
        }
    });

    Ok(Json(TriggerChecksResponse {
        message: format!(
            "Quality checks queued for repository {} ({} artifacts)",
            repository_id, count
        ),
        artifacts_queued: count as u32,
    }))
}

#[utoipa::path(
    get,
    path = "/checks",
    context_path = "/api/v1/quality",
    tag = "quality",
    params(ListChecksQuery),
    responses(
        (status = 200, description = "List of quality check results", body = Vec<CheckResponse>),
    ),
    security(("bearer_auth" = []))
)]
async fn list_checks(
    State(state): State<SharedState>,
    Extension(_auth): Extension<AuthExtension>,
    Query(query): Query<ListChecksQuery>,
) -> Result<Json<Vec<CheckResponse>>> {
    let artifact_id = query.artifact_id.ok_or_else(|| {
        AppError::Validation("artifact_id query parameter is required".to_string())
    })?;
    let qc_service = QualityCheckService::new(state.db.clone());
    let checks = qc_service.list_checks(artifact_id).await?;
    let response: Vec<CheckResponse> = checks.into_iter().map(CheckResponse::from).collect();
    Ok(Json(response))
}

#[utoipa::path(
    get,
    path = "/checks/{id}",
    context_path = "/api/v1/quality",
    tag = "quality",
    params(
        ("id" = Uuid, Path, description = "Check result ID"),
    ),
    responses(
        (status = 200, description = "Check result details", body = CheckResponse),
        (status = 404, description = "Check result not found", body = crate::api::openapi::ErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
async fn get_check(
    State(state): State<SharedState>,
    Extension(_auth): Extension<AuthExtension>,
    Path(id): Path<Uuid>,
) -> Result<Json<CheckResponse>> {
    let qc_service = QualityCheckService::new(state.db.clone());
    let check = qc_service.get_check(id).await?;
    Ok(Json(CheckResponse::from(check)))
}

#[utoipa::path(
    get,
    path = "/checks/{id}/issues",
    context_path = "/api/v1/quality",
    tag = "quality",
    params(
        ("id" = Uuid, Path, description = "Check result ID"),
    ),
    responses(
        (status = 200, description = "List of issues for a check result", body = Vec<IssueResponse>),
        (status = 404, description = "Check result not found", body = crate::api::openapi::ErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
async fn list_check_issues(
    State(state): State<SharedState>,
    Extension(_auth): Extension<AuthExtension>,
    Path(check_id): Path<Uuid>,
) -> Result<Json<Vec<IssueResponse>>> {
    let qc_service = QualityCheckService::new(state.db.clone());
    let issues = qc_service.list_check_issues(check_id).await?;
    let response: Vec<IssueResponse> = issues.into_iter().map(IssueResponse::from).collect();
    Ok(Json(response))
}

#[utoipa::path(
    post,
    path = "/issues/{id}/suppress",
    context_path = "/api/v1/quality",
    tag = "quality",
    params(
        ("id" = Uuid, Path, description = "Issue ID"),
    ),
    request_body = SuppressIssueRequest,
    responses(
        (status = 200, description = "Issue suppressed", body = IssueResponse),
        (status = 404, description = "Issue not found", body = crate::api::openapi::ErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
async fn suppress_issue(
    State(state): State<SharedState>,
    Extension(auth): Extension<AuthExtension>,
    Path(issue_id): Path<Uuid>,
    Json(body): Json<SuppressIssueRequest>,
) -> Result<Json<serde_json::Value>> {
    let qc_service = QualityCheckService::new(state.db.clone());
    let user_id = auth.user_id;
    qc_service
        .suppress_issue(issue_id, user_id, &body.reason)
        .await?;
    Ok(Json(serde_json::json!({ "ok": true })))
}

#[utoipa::path(
    delete,
    path = "/issues/{id}/suppress",
    context_path = "/api/v1/quality",
    tag = "quality",
    params(
        ("id" = Uuid, Path, description = "Issue ID"),
    ),
    responses(
        (status = 200, description = "Issue unsuppressed", body = IssueResponse),
        (status = 404, description = "Issue not found", body = crate::api::openapi::ErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
async fn unsuppress_issue(
    State(state): State<SharedState>,
    Extension(_auth): Extension<AuthExtension>,
    Path(issue_id): Path<Uuid>,
) -> Result<Json<serde_json::Value>> {
    let qc_service = QualityCheckService::new(state.db.clone());
    qc_service.unsuppress_issue(issue_id).await?;
    Ok(Json(serde_json::json!({ "ok": true })))
}

#[utoipa::path(
    get,
    path = "/gates",
    context_path = "/api/v1/quality",
    tag = "quality",
    responses(
        (status = 200, description = "List of quality gates", body = Vec<GateResponse>),
    ),
    security(("bearer_auth" = []))
)]
async fn list_gates(
    State(state): State<SharedState>,
    Extension(_auth): Extension<AuthExtension>,
) -> Result<Json<Vec<GateResponse>>> {
    let qc_service = QualityCheckService::new(state.db.clone());
    let gates = qc_service.list_gates(None).await?;
    let response: Vec<GateResponse> = gates.into_iter().map(GateResponse::from).collect();
    Ok(Json(response))
}

#[utoipa::path(
    post,
    path = "/gates",
    context_path = "/api/v1/quality",
    tag = "quality",
    request_body = CreateGateRequest,
    responses(
        (status = 200, description = "Quality gate created", body = GateResponse),
        (status = 422, description = "Validation error", body = crate::api::openapi::ErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
async fn create_gate(
    State(state): State<SharedState>,
    Extension(_auth): Extension<AuthExtension>,
    Json(body): Json<CreateGateRequest>,
) -> Result<Json<GateResponse>> {
    let qc_service = QualityCheckService::new(state.db.clone());
    let input = crate::services::quality_check_service::CreateQualityGateInput {
        repository_id: body.repository_id,
        name: body.name,
        description: body.description,
        min_health_score: body.min_health_score,
        min_security_score: body.min_security_score,
        min_quality_score: body.min_quality_score,
        min_metadata_score: body.min_metadata_score,
        max_critical_issues: body.max_critical_issues,
        max_high_issues: body.max_high_issues,
        max_medium_issues: body.max_medium_issues,
        required_checks: body.required_checks,
        enforce_on_promotion: body.enforce_on_promotion,
        enforce_on_download: body.enforce_on_download,
        action: body.action,
    };
    let gate = qc_service.create_gate(input).await?;
    Ok(Json(GateResponse::from(gate)))
}

#[utoipa::path(
    get,
    path = "/gates/{id}",
    context_path = "/api/v1/quality",
    tag = "quality",
    params(
        ("id" = Uuid, Path, description = "Quality gate ID"),
    ),
    responses(
        (status = 200, description = "Quality gate details", body = GateResponse),
        (status = 404, description = "Quality gate not found", body = crate::api::openapi::ErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
async fn get_gate(
    State(state): State<SharedState>,
    Extension(_auth): Extension<AuthExtension>,
    Path(id): Path<Uuid>,
) -> Result<Json<GateResponse>> {
    let qc_service = QualityCheckService::new(state.db.clone());
    let gate = qc_service.get_gate(id).await?;
    Ok(Json(GateResponse::from(gate)))
}

#[utoipa::path(
    put,
    path = "/gates/{id}",
    context_path = "/api/v1/quality",
    tag = "quality",
    params(
        ("id" = Uuid, Path, description = "Quality gate ID"),
    ),
    request_body = UpdateGateRequest,
    responses(
        (status = 200, description = "Quality gate updated", body = GateResponse),
        (status = 404, description = "Quality gate not found", body = crate::api::openapi::ErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
async fn update_gate(
    State(state): State<SharedState>,
    Extension(_auth): Extension<AuthExtension>,
    Path(id): Path<Uuid>,
    Json(body): Json<UpdateGateRequest>,
) -> Result<Json<GateResponse>> {
    let qc_service = QualityCheckService::new(state.db.clone());
    let input = crate::services::quality_check_service::UpdateQualityGateInput {
        name: body.name,
        description: body.description,
        min_health_score: body.min_health_score,
        min_security_score: body.min_security_score,
        min_quality_score: body.min_quality_score,
        min_metadata_score: body.min_metadata_score,
        max_critical_issues: body.max_critical_issues,
        max_high_issues: body.max_high_issues,
        max_medium_issues: body.max_medium_issues,
        required_checks: body.required_checks,
        enforce_on_promotion: body.enforce_on_promotion,
        enforce_on_download: body.enforce_on_download,
        action: body.action,
        is_enabled: body.is_enabled,
    };
    let gate = qc_service.update_gate(id, input).await?;
    Ok(Json(GateResponse::from(gate)))
}

#[utoipa::path(
    delete,
    path = "/gates/{id}",
    context_path = "/api/v1/quality",
    tag = "quality",
    params(
        ("id" = Uuid, Path, description = "Quality gate ID"),
    ),
    responses(
        (status = 200, description = "Quality gate deleted", body = Object),
        (status = 404, description = "Quality gate not found", body = crate::api::openapi::ErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
async fn delete_gate(
    State(state): State<SharedState>,
    Extension(_auth): Extension<AuthExtension>,
    Path(id): Path<Uuid>,
) -> Result<Json<serde_json::Value>> {
    let qc_service = QualityCheckService::new(state.db.clone());
    qc_service.delete_gate(id).await?;
    Ok(Json(serde_json::json!({ "deleted": true })))
}

#[utoipa::path(
    post,
    path = "/gates/evaluate/{artifact_id}",
    context_path = "/api/v1/quality",
    tag = "quality",
    params(
        ("artifact_id" = Uuid, Path, description = "Artifact ID to evaluate"),
        EvaluateGateQuery,
    ),
    responses(
        (status = 200, description = "Gate evaluation result", body = GateEvaluationResponse),
        (status = 404, description = "Artifact or gate not found", body = crate::api::openapi::ErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
async fn evaluate_gate(
    State(state): State<SharedState>,
    Extension(_auth): Extension<AuthExtension>,
    Path(artifact_id): Path<Uuid>,
    Query(query): Query<EvaluateGateQuery>,
) -> Result<Json<GateEvaluationResponse>> {
    let qc_service = QualityCheckService::new(state.db.clone());

    // Look up the artifact's repository_id if not explicitly provided
    let repository_id = match query.repository_id {
        Some(id) => id,
        None => sqlx::query_scalar::<_, Uuid>("SELECT repository_id FROM artifacts WHERE id = $1")
            .bind(artifact_id)
            .fetch_optional(&state.db)
            .await
            .map_err(|e| AppError::Database(e.to_string()))?
            .ok_or_else(|| AppError::NotFound("Artifact not found".to_string()))?,
    };

    let evaluation = qc_service
        .evaluate_quality_gate(artifact_id, repository_id)
        .await?;

    let violations: Vec<GateViolationResponse> = evaluation
        .violations
        .into_iter()
        .map(GateViolationResponse::from)
        .collect();

    Ok(Json(GateEvaluationResponse {
        passed: evaluation.passed,
        action: evaluation.action,
        gate_name: evaluation.gate_name,
        health_score: evaluation.health_score,
        health_grade: evaluation.health_grade,
        violations,
        component_scores: serde_json::to_value(&evaluation.component_scores).unwrap_or_default(),
    }))
}

#[derive(OpenApi)]
#[openapi(
    paths(
        get_artifact_health,
        get_repo_health,
        get_health_dashboard,
        trigger_checks,
        list_checks,
        get_check,
        list_check_issues,
        suppress_issue,
        unsuppress_issue,
        list_gates,
        create_gate,
        get_gate,
        update_gate,
        delete_gate,
        evaluate_gate,
    ),
    components(schemas(
        ArtifactHealthResponse,
        CheckSummary,
        RepoHealthResponse,
        HealthDashboardResponse,
        CheckResponse,
        IssueResponse,
        TriggerChecksRequest,
        TriggerChecksResponse,
        SuppressIssueRequest,
        CreateGateRequest,
        UpdateGateRequest,
        GateResponse,
        GateEvaluationResponse,
        GateViolationResponse,
    ))
)]
pub struct QualityGatesApiDoc;
