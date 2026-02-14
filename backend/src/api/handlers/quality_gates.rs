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

// ---------------------------------------------------------------------------
// Pure (non-async, no-DB) helper functions for unit testing
// ---------------------------------------------------------------------------

/// Map a numeric health score to a letter grade.
pub(crate) fn health_grade_from_score(score: i32) -> &'static str {
    match score {
        90..=i32::MAX => "A",
        80..=89 => "B",
        70..=79 => "C",
        60..=69 => "D",
        _ => "F",
    }
}

/// Count how many grades fall into each bucket (A, B, C, D, F).
pub(crate) fn count_grade_distribution(grades: &[&str]) -> (i64, i64, i64, i64, i64) {
    let mut a = 0i64;
    let mut b = 0i64;
    let mut c = 0i64;
    let mut d = 0i64;
    let mut f = 0i64;
    for &g in grades {
        match g {
            "A" => a += 1,
            "B" => b += 1,
            "C" => c += 1,
            "D" => d += 1,
            _ => f += 1,
        }
    }
    (a, b, c, d, f)
}

/// Compute the average health score from a slice. Returns 0 for empty input.
pub(crate) fn compute_avg_health_score(scores: &[i32]) -> i32 {
    if scores.is_empty() {
        return 0;
    }
    let sum: i64 = scores.iter().map(|&s| s as i64).sum();
    (sum / scores.len() as i64) as i32
}

/// Check a minimum-threshold rule. Returns a violation if `actual < min`.
pub(crate) fn check_min_threshold(
    rule_name: &str,
    actual: i32,
    min: Option<i32>,
) -> Option<GateViolationResponse> {
    let min = min?;
    if actual < min {
        Some(GateViolationResponse {
            rule: rule_name.to_string(),
            expected: format!(">= {}", min),
            actual: actual.to_string(),
            message: format!("{} is {} (minimum {})", rule_name, actual, min),
        })
    } else {
        None
    }
}

/// Check a maximum-threshold rule. Returns a violation if `actual > max`.
pub(crate) fn check_max_threshold(
    rule_name: &str,
    actual: i32,
    max: Option<i32>,
) -> Option<GateViolationResponse> {
    let max = max?;
    if actual > max {
        Some(GateViolationResponse {
            rule: rule_name.to_string(),
            expected: format!("<= {}", max),
            actual: actual.to_string(),
            message: format!("{} is {} (maximum {})", rule_name, actual, max),
        })
    } else {
        None
    }
}

/// Evaluate all gate threshold rules and return a list of violations.
#[allow(clippy::too_many_arguments)]
pub(crate) fn evaluate_gate_thresholds(
    health_score: i32,
    security_score: Option<i32>,
    quality_score: Option<i32>,
    metadata_score: Option<i32>,
    critical_issues: i32,
    high_issues: i32,
    medium_issues: i32,
    min_health: Option<i32>,
    min_security: Option<i32>,
    min_quality: Option<i32>,
    min_metadata: Option<i32>,
    max_critical: Option<i32>,
    max_high: Option<i32>,
    max_medium: Option<i32>,
) -> Vec<GateViolationResponse> {
    let mut violations = Vec::new();
    if let Some(v) = check_min_threshold("min_health_score", health_score, min_health) {
        violations.push(v);
    }
    if let Some(v) = check_min_threshold(
        "min_security_score",
        security_score.unwrap_or(0),
        min_security,
    ) {
        violations.push(v);
    }
    if let Some(v) =
        check_min_threshold("min_quality_score", quality_score.unwrap_or(0), min_quality)
    {
        violations.push(v);
    }
    if let Some(v) = check_min_threshold(
        "min_metadata_score",
        metadata_score.unwrap_or(0),
        min_metadata,
    ) {
        violations.push(v);
    }
    if let Some(v) = check_max_threshold("max_critical_issues", critical_issues, max_critical) {
        violations.push(v);
    }
    if let Some(v) = check_max_threshold("max_high_issues", high_issues, max_high) {
        violations.push(v);
    }
    if let Some(v) = check_max_threshold("max_medium_issues", medium_issues, max_medium) {
        violations.push(v);
    }
    violations
}

/// Compute total pages for pagination.
pub(crate) fn compute_total_pages(total: i64, per_page: u32) -> u32 {
    ((total as f64) / (per_page as f64)).ceil() as u32
}

/// Normalize pagination parameters with defaults and clamping.
pub(crate) fn normalize_pagination(page: Option<u32>, per_page: Option<u32>) -> (u32, u32) {
    let page = page.unwrap_or(1).max(1);
    let per_page = per_page.unwrap_or(20).min(100);
    (page, per_page)
}

/// Validate that a status string is one of the recognized values.
pub(crate) fn validate_status(status: &str) -> std::result::Result<(), String> {
    if !["pending", "approved", "rejected"].contains(&status) {
        return Err(format!(
            "Invalid status '{}'. Must be one of: pending, approved, rejected",
            status
        ));
    }
    Ok(())
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

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // default_true / default_warn
    // -----------------------------------------------------------------------

    #[test]
    fn test_default_true() {
        assert!(default_true());
    }

    #[test]
    fn test_default_warn() {
        assert_eq!(default_warn(), "warn");
    }

    // -----------------------------------------------------------------------
    // CreateGateRequest serde with defaults
    // -----------------------------------------------------------------------

    #[test]
    fn test_create_gate_request_minimal() {
        let json = serde_json::json!({
            "name": "basic-gate",
        });
        let req: CreateGateRequest = serde_json::from_value(json).unwrap();
        assert_eq!(req.name, "basic-gate");
        assert_eq!(req.repository_id, None);
        assert_eq!(req.description, None);
        assert_eq!(req.min_health_score, None);
        assert_eq!(req.min_security_score, None);
        assert_eq!(req.min_quality_score, None);
        assert_eq!(req.min_metadata_score, None);
        assert_eq!(req.max_critical_issues, None);
        assert_eq!(req.max_high_issues, None);
        assert_eq!(req.max_medium_issues, None);
        assert!(req.required_checks.is_empty());
        assert!(req.enforce_on_promotion); // default_true
        assert!(!req.enforce_on_download); // default false
        assert_eq!(req.action, "warn"); // default_warn
    }

    #[test]
    fn test_create_gate_request_full() {
        let repo_id = Uuid::new_v4();
        let json = serde_json::json!({
            "name": "strict-gate",
            "repository_id": repo_id,
            "description": "Strict quality gate",
            "min_health_score": 80,
            "min_security_score": 90,
            "min_quality_score": 70,
            "min_metadata_score": 60,
            "max_critical_issues": 0,
            "max_high_issues": 5,
            "max_medium_issues": 20,
            "required_checks": ["security", "license", "metadata"],
            "enforce_on_promotion": false,
            "enforce_on_download": true,
            "action": "block",
        });
        let req: CreateGateRequest = serde_json::from_value(json).unwrap();
        assert_eq!(req.name, "strict-gate");
        assert_eq!(req.repository_id, Some(repo_id));
        assert_eq!(req.description, Some("Strict quality gate".to_string()));
        assert_eq!(req.min_health_score, Some(80));
        assert_eq!(req.min_security_score, Some(90));
        assert_eq!(req.min_quality_score, Some(70));
        assert_eq!(req.min_metadata_score, Some(60));
        assert_eq!(req.max_critical_issues, Some(0));
        assert_eq!(req.max_high_issues, Some(5));
        assert_eq!(req.max_medium_issues, Some(20));
        assert_eq!(req.required_checks, vec!["security", "license", "metadata"]);
        assert!(!req.enforce_on_promotion);
        assert!(req.enforce_on_download);
        assert_eq!(req.action, "block");
    }

    // -----------------------------------------------------------------------
    // UpdateGateRequest serde
    // -----------------------------------------------------------------------

    #[test]
    fn test_update_gate_request_all_none() {
        let json = serde_json::json!({});
        let req: UpdateGateRequest = serde_json::from_value(json).unwrap();
        assert_eq!(req.name, None);
        assert_eq!(req.description, None);
        assert_eq!(req.min_health_score, None);
        assert_eq!(req.is_enabled, None);
        assert_eq!(req.action, None);
    }

    #[test]
    fn test_update_gate_request_partial() {
        let json = serde_json::json!({
            "name": "renamed-gate",
            "is_enabled": false,
            "action": "block",
        });
        let req: UpdateGateRequest = serde_json::from_value(json).unwrap();
        assert_eq!(req.name, Some("renamed-gate".to_string()));
        assert_eq!(req.is_enabled, Some(false));
        assert_eq!(req.action, Some("block".to_string()));
    }

    // -----------------------------------------------------------------------
    // TriggerChecksRequest serde
    // -----------------------------------------------------------------------

    #[test]
    fn test_trigger_checks_request_artifact() {
        let id = Uuid::new_v4();
        let json = serde_json::json!({ "artifact_id": id });
        let req: TriggerChecksRequest = serde_json::from_value(json).unwrap();
        assert_eq!(req.artifact_id, Some(id));
        assert_eq!(req.repository_id, None);
    }

    #[test]
    fn test_trigger_checks_request_repo() {
        let id = Uuid::new_v4();
        let json = serde_json::json!({ "repository_id": id });
        let req: TriggerChecksRequest = serde_json::from_value(json).unwrap();
        assert_eq!(req.artifact_id, None);
        assert_eq!(req.repository_id, Some(id));
    }

    // -----------------------------------------------------------------------
    // SuppressIssueRequest serde
    // -----------------------------------------------------------------------

    #[test]
    fn test_suppress_issue_request() {
        let json = serde_json::json!({ "reason": "Accepted risk" });
        let req: SuppressIssueRequest = serde_json::from_value(json).unwrap();
        assert_eq!(req.reason, "Accepted risk");
    }

    // -----------------------------------------------------------------------
    // Response struct construction
    // -----------------------------------------------------------------------

    #[test]
    fn test_artifact_health_response_construction() {
        let now = chrono::Utc::now();
        let resp = ArtifactHealthResponse {
            artifact_id: Uuid::new_v4(),
            health_score: 85,
            health_grade: "A".to_string(),
            security_score: Some(90),
            license_score: Some(100),
            quality_score: Some(75),
            metadata_score: Some(80),
            total_issues: 5,
            critical_issues: 0,
            checks_passed: 4,
            checks_total: 5,
            last_checked_at: Some(now),
            checks: vec![],
        };
        assert_eq!(resp.health_score, 85);
        assert_eq!(resp.health_grade, "A");
        assert_eq!(resp.security_score, Some(90));
        assert_eq!(resp.critical_issues, 0);
    }

    #[test]
    fn test_check_summary_construction() {
        let cs = CheckSummary {
            check_type: "security".to_string(),
            score: Some(95),
            passed: Some(true),
            status: "completed".to_string(),
            issues_count: 2,
            completed_at: Some(chrono::Utc::now()),
        };
        assert_eq!(cs.check_type, "security");
        assert_eq!(cs.score, Some(95));
        assert_eq!(cs.passed, Some(true));
        assert_eq!(cs.issues_count, 2);
    }

    #[test]
    fn test_gate_violation_response_construction() {
        let v = GateViolationResponse {
            rule: "min_health_score".to_string(),
            expected: ">= 80".to_string(),
            actual: "65".to_string(),
            message: "Health score 65 is below minimum 80".to_string(),
        };
        assert_eq!(v.rule, "min_health_score");
        assert_eq!(v.expected, ">= 80");
        assert_eq!(v.actual, "65");
    }

    // -----------------------------------------------------------------------
    // Grade counting logic (from get_health_dashboard)
    // -----------------------------------------------------------------------

    #[test]
    fn test_grade_counting() {
        let grades = vec!["A", "A", "B", "C", "F", "A"];
        let (mut a, mut b, mut c, mut d, mut f) = (0i64, 0i64, 0i64, 0i64, 0i64);
        for g in &grades {
            match *g {
                "A" => a += 1,
                "B" => b += 1,
                "C" => c += 1,
                "D" => d += 1,
                _ => f += 1,
            }
        }
        assert_eq!(a, 3);
        assert_eq!(b, 1);
        assert_eq!(c, 1);
        assert_eq!(d, 0);
        assert_eq!(f, 1);
    }

    // -----------------------------------------------------------------------
    // HealthDashboardResponse avg_health_score calculation
    // -----------------------------------------------------------------------

    #[test]
    fn test_avg_health_score_calculation() {
        let scores: Vec<i64> = vec![80, 90, 70, 100];
        let total_repositories = scores.len() as i64;
        let avg = if total_repositories > 0 {
            (scores.iter().sum::<i64>() / total_repositories) as i32
        } else {
            0
        };
        assert_eq!(avg, 85);
    }

    #[test]
    fn test_avg_health_score_empty() {
        let scores: Vec<i64> = vec![];
        let total_repositories = scores.len() as i64;
        let avg = if total_repositories > 0 {
            (scores.iter().sum::<i64>() / total_repositories) as i32
        } else {
            0
        };
        assert_eq!(avg, 0);
    }

    // -----------------------------------------------------------------------
    // Serialization
    // -----------------------------------------------------------------------

    #[test]
    fn test_trigger_checks_response_serialization() {
        let resp = TriggerChecksResponse {
            message: "Queued for 5 artifacts".to_string(),
            artifacts_queued: 5,
        };
        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains("\"artifacts_queued\":5"));
    }

    #[test]
    fn test_health_dashboard_response_serialization() {
        let resp = HealthDashboardResponse {
            total_repositories: 3,
            total_artifacts_evaluated: 100,
            avg_health_score: 75,
            repos_grade_a: 1,
            repos_grade_b: 1,
            repos_grade_c: 0,
            repos_grade_d: 0,
            repos_grade_f: 1,
            repositories: vec![],
        };
        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains("\"total_repositories\":3"));
        assert!(json.contains("\"avg_health_score\":75"));
    }

    // -----------------------------------------------------------------------
    // health_grade_from_score
    // -----------------------------------------------------------------------

    #[test]
    fn test_health_grade_a() {
        assert_eq!(health_grade_from_score(100), "A");
        assert_eq!(health_grade_from_score(95), "A");
        assert_eq!(health_grade_from_score(90), "A");
    }

    #[test]
    fn test_health_grade_b() {
        assert_eq!(health_grade_from_score(89), "B");
        assert_eq!(health_grade_from_score(85), "B");
        assert_eq!(health_grade_from_score(80), "B");
    }

    #[test]
    fn test_health_grade_c() {
        assert_eq!(health_grade_from_score(79), "C");
        assert_eq!(health_grade_from_score(70), "C");
    }

    #[test]
    fn test_health_grade_d() {
        assert_eq!(health_grade_from_score(69), "D");
        assert_eq!(health_grade_from_score(60), "D");
    }

    #[test]
    fn test_health_grade_f() {
        assert_eq!(health_grade_from_score(59), "F");
        assert_eq!(health_grade_from_score(0), "F");
        assert_eq!(health_grade_from_score(-1), "F");
    }

    // -----------------------------------------------------------------------
    // count_grade_distribution
    // -----------------------------------------------------------------------

    #[test]
    fn test_count_grade_distribution_mixed() {
        let grades = vec!["A", "A", "B", "C", "F", "A"];
        let (a, b, c, d, f) = count_grade_distribution(&grades);
        assert_eq!(a, 3);
        assert_eq!(b, 1);
        assert_eq!(c, 1);
        assert_eq!(d, 0);
        assert_eq!(f, 1);
    }

    #[test]
    fn test_count_grade_distribution_empty() {
        let (a, b, c, d, f) = count_grade_distribution(&[]);
        assert_eq!((a, b, c, d, f), (0, 0, 0, 0, 0));
    }

    #[test]
    fn test_count_grade_distribution_all_same() {
        let grades = vec!["B", "B", "B"];
        let (a, b, _, _, _) = count_grade_distribution(&grades);
        assert_eq!(a, 0);
        assert_eq!(b, 3);
    }

    #[test]
    fn test_count_grade_distribution_unknown_mapped_to_f() {
        let grades = vec!["X", "Z", ""];
        let (_, _, _, _, f) = count_grade_distribution(&grades);
        assert_eq!(f, 3);
    }

    // -----------------------------------------------------------------------
    // compute_avg_health_score
    // -----------------------------------------------------------------------

    #[test]
    fn test_compute_avg_health_score_basic() {
        assert_eq!(compute_avg_health_score(&[80, 90, 70, 100]), 85);
    }

    #[test]
    fn test_compute_avg_health_score_empty() {
        assert_eq!(compute_avg_health_score(&[]), 0);
    }

    #[test]
    fn test_compute_avg_health_score_single() {
        assert_eq!(compute_avg_health_score(&[75]), 75);
    }

    #[test]
    fn test_compute_avg_health_score_zeros() {
        assert_eq!(compute_avg_health_score(&[0, 0, 0]), 0);
    }

    #[test]
    fn test_compute_avg_health_score_rounding() {
        assert_eq!(compute_avg_health_score(&[33, 33, 34]), 33);
    }

    // -----------------------------------------------------------------------
    // check_min_threshold
    // -----------------------------------------------------------------------

    #[test]
    fn test_check_min_threshold_passes() {
        assert!(check_min_threshold("min_health_score", 80, Some(80)).is_none());
        assert!(check_min_threshold("min_health_score", 90, Some(80)).is_none());
    }

    #[test]
    fn test_check_min_threshold_fails() {
        let v = check_min_threshold("min_health_score", 65, Some(80)).unwrap();
        assert_eq!(v.rule, "min_health_score");
        assert_eq!(v.expected, ">= 80");
        assert_eq!(v.actual, "65");
        assert!(v.message.contains("65"));
    }

    #[test]
    fn test_check_min_threshold_none_threshold() {
        assert!(check_min_threshold("any_rule", 0, None).is_none());
    }

    #[test]
    fn test_check_min_threshold_boundary() {
        assert!(check_min_threshold("score", 79, Some(80)).is_some());
        assert!(check_min_threshold("score", 80, Some(80)).is_none());
        assert!(check_min_threshold("score", 81, Some(80)).is_none());
    }

    // -----------------------------------------------------------------------
    // check_max_threshold
    // -----------------------------------------------------------------------

    #[test]
    fn test_check_max_threshold_passes() {
        assert!(check_max_threshold("max_critical_issues", 0, Some(0)).is_none());
        assert!(check_max_threshold("max_critical_issues", 3, Some(5)).is_none());
    }

    #[test]
    fn test_check_max_threshold_fails() {
        let v = check_max_threshold("max_critical_issues", 3, Some(0)).unwrap();
        assert_eq!(v.rule, "max_critical_issues");
        assert_eq!(v.expected, "<= 0");
        assert_eq!(v.actual, "3");
    }

    #[test]
    fn test_check_max_threshold_none_threshold() {
        assert!(check_max_threshold("any_rule", 999, None).is_none());
    }

    #[test]
    fn test_check_max_threshold_boundary() {
        assert!(check_max_threshold("issues", 5, Some(5)).is_none());
        assert!(check_max_threshold("issues", 6, Some(5)).is_some());
    }

    // -----------------------------------------------------------------------
    // evaluate_gate_thresholds
    // -----------------------------------------------------------------------

    #[test]
    fn test_evaluate_gate_thresholds_all_pass() {
        let violations = evaluate_gate_thresholds(
            90,
            Some(95),
            Some(85),
            Some(80),
            0,
            2,
            5,
            Some(80),
            Some(90),
            Some(70),
            Some(60),
            Some(0),
            Some(5),
            Some(10),
        );
        assert!(violations.is_empty());
    }

    #[test]
    fn test_evaluate_gate_thresholds_health_fails() {
        let violations = evaluate_gate_thresholds(
            65,
            None,
            None,
            None,
            0,
            0,
            0,
            Some(80),
            None,
            None,
            None,
            None,
            None,
            None,
        );
        assert_eq!(violations.len(), 1);
        assert_eq!(violations[0].rule, "min_health_score");
    }

    #[test]
    fn test_evaluate_gate_thresholds_multiple_failures() {
        let violations = evaluate_gate_thresholds(
            50,
            Some(40),
            Some(30),
            Some(20),
            5,
            10,
            20,
            Some(80),
            Some(90),
            Some(70),
            Some(60),
            Some(0),
            Some(5),
            Some(10),
        );
        assert_eq!(violations.len(), 7);
    }

    #[test]
    fn test_evaluate_gate_thresholds_no_thresholds() {
        let violations = evaluate_gate_thresholds(
            10,
            Some(10),
            Some(10),
            Some(10),
            100,
            100,
            100,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
        );
        assert!(violations.is_empty());
    }

    #[test]
    fn test_evaluate_gate_thresholds_issue_counts_only() {
        let violations = evaluate_gate_thresholds(
            100,
            None,
            None,
            None,
            5,
            10,
            20,
            None,
            None,
            None,
            None,
            Some(0),
            Some(5),
            Some(10),
        );
        assert_eq!(violations.len(), 3);
    }

    // -----------------------------------------------------------------------
    // compute_total_pages
    // -----------------------------------------------------------------------

    #[test]
    fn test_compute_total_pages_exact() {
        assert_eq!(compute_total_pages(100, 20), 5);
    }

    #[test]
    fn test_compute_total_pages_remainder() {
        assert_eq!(compute_total_pages(101, 20), 6);
    }

    #[test]
    fn test_compute_total_pages_zero() {
        assert_eq!(compute_total_pages(0, 20), 0);
    }

    #[test]
    fn test_compute_total_pages_one_item() {
        assert_eq!(compute_total_pages(1, 20), 1);
    }

    // -----------------------------------------------------------------------
    // normalize_pagination
    // -----------------------------------------------------------------------

    #[test]
    fn test_normalize_pagination_defaults() {
        let (page, per_page) = normalize_pagination(None, None);
        assert_eq!(page, 1);
        assert_eq!(per_page, 20);
    }

    #[test]
    fn test_normalize_pagination_custom() {
        let (page, per_page) = normalize_pagination(Some(3), Some(50));
        assert_eq!(page, 3);
        assert_eq!(per_page, 50);
    }

    #[test]
    fn test_normalize_pagination_page_zero_clamps() {
        let (page, _) = normalize_pagination(Some(0), None);
        assert_eq!(page, 1);
    }

    #[test]
    fn test_normalize_pagination_per_page_exceeds_max() {
        let (_, per_page) = normalize_pagination(None, Some(200));
        assert_eq!(per_page, 100);
    }

    // -----------------------------------------------------------------------
    // validate_status
    // -----------------------------------------------------------------------

    #[test]
    fn test_validate_status_valid() {
        assert!(validate_status("pending").is_ok());
        assert!(validate_status("approved").is_ok());
        assert!(validate_status("rejected").is_ok());
    }

    #[test]
    fn test_validate_status_invalid() {
        assert!(validate_status("unknown").is_err());
        assert!(validate_status("").is_err());
        assert!(validate_status("PENDING").is_err());
    }

    #[test]
    fn test_validate_status_error_message() {
        let err = validate_status("bad").unwrap_err();
        assert!(err.contains("bad"));
        assert!(err.contains("pending"));
    }
}
