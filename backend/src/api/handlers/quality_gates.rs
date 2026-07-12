//! Quality gates and health score handlers.

use axum::{
    extract::{Extension, Path, Query, State},
    routing::{delete, get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, OpenApi, ToSchema};
use uuid::Uuid;

use crate::api::handlers::artifacts::check_artifact_visibility;
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

// ---------------------------------------------------------------------------
// Admin quality-checks list-all (#2419)
// ---------------------------------------------------------------------------

/// Default page size for the admin quality-checks list when unspecified.
const CHECKS_DEFAULT_PER_PAGE: u32 = 50;
/// Hard cap on page size so a single query cannot pull an unbounded slice.
const CHECKS_MAX_PER_PAGE: u32 = 200;

/// Normalize/clamp admin quality-check-list pagination into an
/// `(offset, limit, page, per_page)` tuple.
///
/// Pure (no I/O), mirroring [`crate::api::handlers::admin::audit_page_bounds`],
/// so the coverage gate exercises the pagination arithmetic even where Postgres
/// is unavailable. `page` is 1-based and floored at 1; `per_page` defaults to
/// [`CHECKS_DEFAULT_PER_PAGE`] and is clamped to `1..=CHECKS_MAX_PER_PAGE`.
pub(crate) fn checks_page_bounds(page: Option<u32>, per_page: Option<u32>) -> (i64, i64, u32, u32) {
    let page = page.unwrap_or(1).max(1);
    let per_page = per_page
        .unwrap_or(CHECKS_DEFAULT_PER_PAGE)
        .clamp(1, CHECKS_MAX_PER_PAGE);
    let offset = i64::from(page - 1) * i64::from(per_page);
    (offset, i64::from(per_page), page, per_page)
}

/// Filters for `GET /api/v1/admin/quality-checks` (#2419).
#[derive(Debug, Deserialize, IntoParams)]
pub struct AdminListChecksQuery {
    /// Filter by repository id.
    pub repository_id: Option<Uuid>,
    /// Filter by artifact id.
    pub artifact_id: Option<Uuid>,
    /// Filter by check status (e.g. `completed`, `running`, `failed`).
    pub status: Option<String>,
    /// 1-based page index (default 1).
    pub page: Option<u32>,
    /// Page size (default 50, max 200).
    pub per_page: Option<u32>,
}

/// Paginated admin quality-check list response (#2419).
#[derive(Debug, Serialize, ToSchema)]
pub struct QualityCheckListResponse {
    pub items: Vec<CheckResponse>,
    pub total: i64,
    pub page: u32,
    pub per_page: u32,
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
    Extension(auth): Extension<AuthExtension>,
    Path(artifact_id): Path<Uuid>,
) -> Result<Json<ArtifactHealthResponse>> {
    let qc_service = QualityCheckService::new(state.db.clone());

    let health = qc_service
        .get_artifact_health(artifact_id)
        .await?
        .ok_or_else(|| AppError::NotFound("No health score found for artifact".to_string()))?;
    // Cross-repo authorization: the caller must be allowed to see this
    // artifact's repository (token scope + admin bypass + private-repo
    // membership), else existence-hiding NotFound (#2437).
    check_artifact_visibility(&Some(auth), artifact_id, &state.db).await?;
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
    Extension(auth): Extension<AuthExtension>,
    Json(body): Json<TriggerChecksRequest>,
) -> Result<Json<TriggerChecksResponse>> {
    auth.require_admin()?;
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
    // Explicit params instead of `params(ListChecksQuery)`: the handler
    // 400s without `artifact_id`, so the spec must declare it required
    // (the struct field is `Option` only so the handler can return a clean
    // validation error instead of an axum 422). `repository_id` is accepted
    // but ignored, so it is intentionally not published.
    params(
        ("artifact_id" = Uuid, Query, description = "Artifact ID to list quality check results for"),
    ),
    responses(
        (status = 200, description = "List of quality check results", body = Vec<CheckResponse>),
        (status = 400, description = "Missing or invalid artifact_id", body = crate::api::openapi::ErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
async fn list_checks(
    State(state): State<SharedState>,
    Extension(auth): Extension<AuthExtension>,
    Query(query): Query<ListChecksQuery>,
) -> Result<Json<Vec<CheckResponse>>> {
    let artifact_id = query.artifact_id.ok_or_else(|| {
        AppError::Validation("artifact_id query parameter is required".to_string())
    })?;
    // Resolve existence first so a nonexistent artifact 404s uniformly with a
    // no-access one (mirrors get_artifact), then enforce cross-repo
    // authorization before returning any check metadata (#2437).
    let _repo_id: Uuid = sqlx::query_scalar(
        "SELECT repository_id FROM artifacts WHERE id = $1 AND is_deleted = false",
    )
    .bind(artifact_id)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?
    .ok_or_else(|| AppError::NotFound("Artifact not found".to_string()))?;
    check_artifact_visibility(&Some(auth), artifact_id, &state.db).await?;
    let qc_service = QualityCheckService::new(state.db.clone());
    let checks = qc_service.list_checks(artifact_id).await?;
    let response: Vec<CheckResponse> = checks.into_iter().map(CheckResponse::from).collect();
    Ok(Json(response))
}

/// Admin list-all quality check results (#2419).
///
/// Returns quality check results across all repositories/artifacts, newest
/// first, filterable by `repository_id`, `artifact_id` and `status`, with
/// `page`/`per_page` pagination and a total count. This powers the web admin
/// quality-checks page, which needs a repository-scoped (or unscoped) view; the
/// artifact-scoped `GET /quality/checks` (which 400s without `artifact_id`)
/// remains the #2334 contract and is unchanged. Admin-only via the `/admin`
/// `admin_middleware` and a defense-in-depth check here.
#[utoipa::path(
    get,
    path = "/quality-checks",
    context_path = "/api/v1/admin",
    tag = "quality",
    params(AdminListChecksQuery),
    responses(
        (status = 200, description = "Paginated quality check results", body = QualityCheckListResponse),
        (status = 403, description = "Admin privileges required"),
    ),
    security(("bearer_auth" = []))
)]
async fn admin_list_checks(
    State(state): State<SharedState>,
    Extension(auth): Extension<AuthExtension>,
    Query(query): Query<AdminListChecksQuery>,
) -> Result<Json<QualityCheckListResponse>> {
    // Defense-in-depth: the `/admin` nest already enforces `admin_middleware`,
    // but never rely on a single gate for a security-sensitive cross-repo read.
    auth.require_admin()?;

    let (offset, limit, page, per_page) = checks_page_bounds(query.page, query.per_page);

    let qc_service = QualityCheckService::new(state.db.clone());
    let (checks, total) = qc_service
        .list_checks_filtered(
            query.repository_id,
            query.artifact_id,
            query.status.as_deref(),
            offset,
            limit,
        )
        .await?;

    Ok(Json(QualityCheckListResponse {
        items: checks.into_iter().map(CheckResponse::from).collect(),
        total,
        page,
        per_page,
    }))
}

/// Admin quality-checks routes (mounted under `/admin`, gated by
/// `admin_middleware`). See [`admin_list_checks`] (#2419).
pub fn admin_router() -> Router<SharedState> {
    Router::new().route("/", get(admin_list_checks))
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
    Extension(auth): Extension<AuthExtension>,
    Path(id): Path<Uuid>,
) -> Result<Json<CheckResponse>> {
    let qc_service = QualityCheckService::new(state.db.clone());
    let check = qc_service.get_check(id).await?;
    // Enforce cross-repo authorization on the check's artifact before
    // returning any check metadata (#2437).
    check_artifact_visibility(&Some(auth), check.artifact_id, &state.db).await?;
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
    Extension(auth): Extension<AuthExtension>,
    Path(check_id): Path<Uuid>,
) -> Result<Json<Vec<IssueResponse>>> {
    let qc_service = QualityCheckService::new(state.db.clone());
    // Resolve the check (404s if missing) so we can authorize its artifact
    // before returning any issue metadata (#2437).
    let check = qc_service.get_check(check_id).await?;
    check_artifact_visibility(&Some(auth), check.artifact_id, &state.db).await?;
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
    auth.require_admin()?;
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
    Extension(auth): Extension<AuthExtension>,
    Path(issue_id): Path<Uuid>,
) -> Result<Json<serde_json::Value>> {
    auth.require_admin()?;
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
    Extension(auth): Extension<AuthExtension>,
    Json(body): Json<CreateGateRequest>,
) -> Result<Json<GateResponse>> {
    auth.require_admin()?;
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
    state
        .event_bus
        .emit("quality_gate.created", gate.id, Some(auth.username.clone()));
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
    Extension(auth): Extension<AuthExtension>,
    Path(id): Path<Uuid>,
    Json(body): Json<UpdateGateRequest>,
) -> Result<Json<GateResponse>> {
    auth.require_admin()?;
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
    state
        .event_bus
        .emit("quality_gate.updated", gate.id, Some(auth.username.clone()));
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
    Extension(auth): Extension<AuthExtension>,
    Path(id): Path<Uuid>,
) -> Result<Json<serde_json::Value>> {
    auth.require_admin()?;
    let qc_service = QualityCheckService::new(state.db.clone());
    qc_service.delete_gate(id).await?;
    state
        .event_bus
        .emit("quality_gate.deleted", id, Some(auth.username.clone()));
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
    Extension(auth): Extension<AuthExtension>,
    Path(artifact_id): Path<Uuid>,
    Query(query): Query<EvaluateGateQuery>,
) -> Result<Json<GateEvaluationResponse>> {
    auth.require_admin()?;
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
        admin_list_checks,
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
        QualityCheckListResponse,
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
    // Pure (non-async, no-DB) helper functions for unit testing
    // -----------------------------------------------------------------------

    /// Map a numeric health score to a letter grade.
    fn health_grade_from_score(score: i32) -> &'static str {
        match score {
            90..=i32::MAX => "A",
            80..=89 => "B",
            70..=79 => "C",
            60..=69 => "D",
            _ => "F",
        }
    }

    /// Count how many grades fall into each bucket (A, B, C, D, F).
    fn count_grade_distribution(grades: &[&str]) -> (i64, i64, i64, i64, i64) {
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
    fn compute_avg_health_score(scores: &[i32]) -> i32 {
        if scores.is_empty() {
            return 0;
        }
        let sum: i64 = scores.iter().map(|&s| s as i64).sum();
        (sum / scores.len() as i64) as i32
    }

    /// Check a minimum-threshold rule. Returns a violation if `actual < min`.
    fn check_min_threshold(
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
    fn check_max_threshold(
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
    fn evaluate_gate_thresholds(
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
    fn compute_total_pages(total: i64, per_page: u32) -> u32 {
        ((total as f64) / (per_page as f64)).ceil() as u32
    }

    /// Normalize pagination parameters with defaults and clamping.
    fn normalize_pagination(page: Option<u32>, per_page: Option<u32>) -> (u32, u32) {
        let page = page.unwrap_or(1).max(1);
        let per_page = per_page.unwrap_or(20).min(100);
        (page, per_page)
    }

    /// Validate that a status string is one of the recognized values.
    fn validate_status(status: &str) -> std::result::Result<(), String> {
        if !["pending", "approved", "rejected"].contains(&status) {
            return Err(format!(
                "Invalid status '{}'. Must be one of: pending, approved, rejected",
                status
            ));
        }
        Ok(())
    }

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

    // -----------------------------------------------------------------------
    // Authorization regression tests (#1805): mutating /quality/* routes must
    // reject non-admin callers with 403. Before the fix these returned 200 for
    // any authenticated user (broken function-level authorization).
    // -----------------------------------------------------------------------
    use crate::api::handlers::test_db_helpers as tdh;

    /// Build the quality router wired to a fresh non-admin caller, plus a
    /// throwaway repo to clean up. Returns `None` when no DB is configured so
    /// the test no-ops. Shared setup keeps each authz case to a single call.
    async fn nonadmin_quality_app() -> Option<(axum::Router, sqlx::PgPool, Uuid, Uuid)> {
        let pool = tdh::try_pool().await?;
        let (user_id, username) = tdh::create_user(&pool).await;
        let (repo_id, _key, storage_dir) = tdh::create_repo(&pool, "local", "rpm").await;
        let state = tdh::build_state(pool.clone(), storage_dir.to_string_lossy().as_ref());
        let auth = tdh::make_auth(user_id, &username); // is_admin: false
                                                       // The real `auth_middleware` inserts BOTH the concrete `AuthExtension`
                                                       // and `Option<AuthExtension>`; these quality handlers extract the
                                                       // concrete shape, so inject both here (mirroring middleware/auth.rs)
                                                       // to avoid a spurious 500 ("Missing request extension").
        let app = router()
            .with_state(state)
            .layer(axum::Extension(auth.clone()))
            .layer(axum::Extension(Some(auth)));
        Some((app, pool, repo_id, user_id))
    }

    #[tokio::test]
    async fn test_trigger_checks_denies_nonadmin() {
        let Some((app, pool, repo_id, user_id)) = nonadmin_quality_app().await else {
            return;
        };
        let body = serde_json::json!({ "repository_id": repo_id }).to_string();
        let req = tdh::post(
            "/checks/trigger".to_string(),
            "application/json",
            body.into(),
        );
        let (status, _) = tdh::send(app, req).await;
        assert_eq!(status, axum::http::StatusCode::FORBIDDEN);
        tdh::cleanup(&pool, repo_id, user_id).await;
    }

    #[tokio::test]
    async fn test_create_gate_denies_nonadmin() {
        let Some((app, pool, repo_id, user_id)) = nonadmin_quality_app().await else {
            return;
        };
        let body = serde_json::json!({
            "repository_id": repo_id,
            "name": "authz-regression-gate",
            "action": "block",
        })
        .to_string();
        let req = tdh::post("/gates".to_string(), "application/json", body.into());
        let (status, _) = tdh::send(app, req).await;
        assert_eq!(status, axum::http::StatusCode::FORBIDDEN);
        tdh::cleanup(&pool, repo_id, user_id).await;
    }

    // -----------------------------------------------------------------------
    // checks_page_bounds (#2419) — pure pagination arithmetic, no DB required
    // so the coverage gate exercises it even without Postgres.
    // -----------------------------------------------------------------------

    #[test]
    fn test_checks_page_bounds_defaults() {
        // No page/per_page -> page 1, default page size, offset 0.
        let (offset, limit, page, per_page) = checks_page_bounds(None, None);
        assert_eq!(offset, 0);
        assert_eq!(limit, CHECKS_DEFAULT_PER_PAGE as i64);
        assert_eq!(page, 1);
        assert_eq!(per_page, CHECKS_DEFAULT_PER_PAGE);
    }

    #[test]
    fn test_checks_page_bounds_computes_offset() {
        // Page 3 at 25/page -> offset 50.
        let (offset, limit, page, per_page) = checks_page_bounds(Some(3), Some(25));
        assert_eq!(offset, 50);
        assert_eq!(limit, 25);
        assert_eq!(page, 3);
        assert_eq!(per_page, 25);
    }

    #[test]
    fn test_checks_page_bounds_floors_page_at_one() {
        // Page 0 must not underflow (page-1) or produce a negative offset.
        let (offset, _limit, page, _pp) = checks_page_bounds(Some(0), Some(10));
        assert_eq!(offset, 0);
        assert_eq!(page, 1);
    }

    #[test]
    fn test_checks_page_bounds_clamps_per_page_to_max() {
        // An over-large per_page is clamped to the hard cap.
        let (_offset, limit, _page, per_page) = checks_page_bounds(Some(1), Some(10_000));
        assert_eq!(limit, CHECKS_MAX_PER_PAGE as i64);
        assert_eq!(per_page, CHECKS_MAX_PER_PAGE);
    }

    #[test]
    fn test_checks_page_bounds_clamps_zero_per_page_to_one() {
        // per_page = 0 would return an empty page forever; clamp up to 1.
        let (_offset, limit, _page, per_page) = checks_page_bounds(Some(1), Some(0));
        assert_eq!(limit, 1);
        assert_eq!(per_page, 1);
    }

    // -----------------------------------------------------------------------
    // admin quality-checks list-all (#2419) — DB-backed. Mirrors admin.rs
    // `test_list_audit_logs_admin_reads_and_non_admin_forbidden_db`.
    // -----------------------------------------------------------------------

    /// Insert an `artifacts` row in `repo_id`, returning its id. Path is
    /// namespaced by a fresh uuid so repeated calls do not collide on the
    /// `(repository_id, path)` uniqueness constraint.
    async fn seed_artifact(pool: &sqlx::PgPool, repo_id: Uuid) -> Uuid {
        let path = format!("qcr-test/{}", Uuid::new_v4());
        sqlx::query_scalar::<_, Uuid>(
            "INSERT INTO artifacts (repository_id, path, name, version, size_bytes, \
                 checksum_sha256, content_type, storage_key, uploaded_by) \
             VALUES ($1, $2, 'qcr-test', '1.0', 1, 'deadbeef', 'application/octet-stream', $3, NULL) \
             RETURNING id",
        )
        .bind(repo_id)
        .bind(&path)
        .bind(&path)
        .fetch_one(pool)
        .await
        .expect("seed artifact")
    }

    /// Insert a `quality_check_results` row with an explicit age so ordering is
    /// deterministic (`secs_ago` larger = older). Returns the new row id.
    async fn seed_check(
        pool: &sqlx::PgPool,
        repo_id: Uuid,
        artifact_id: Uuid,
        status: &str,
        secs_ago: f64,
    ) -> Uuid {
        sqlx::query_scalar::<_, Uuid>(
            "INSERT INTO quality_check_results \
                 (artifact_id, repository_id, check_type, status, created_at) \
             VALUES ($1, $2, 'metadata', $3, NOW() - make_interval(secs => $4)) \
             RETURNING id",
        )
        .bind(artifact_id)
        .bind(repo_id)
        .bind(status)
        .bind(secs_ago)
        .fetch_one(pool)
        .await
        .expect("seed quality_check_result")
    }

    /// Build the admin quality-checks router wired to the given caller.
    fn admin_checks_app(state: SharedState, auth: AuthExtension) -> axum::Router {
        admin_router()
            .with_state(state)
            .layer(axum::Extension(auth))
    }

    async fn json_body(
        app: axum::Router,
        uri: &str,
    ) -> (axum::http::StatusCode, serde_json::Value) {
        let (status, body) = tdh::send(app, tdh::get(uri.to_string())).await;
        let v = if body.is_empty() {
            serde_json::Value::Null
        } else {
            serde_json::from_slice(&body).unwrap_or(serde_json::Value::Null)
        };
        (status, v)
    }

    #[tokio::test]
    async fn test_admin_list_checks_filters_pagination_and_authz_db() {
        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let (user_id, username) = tdh::create_user(&pool).await;
        let (repo_a, _ka, dir_a) = tdh::create_repo(&pool, "local", "rpm").await;
        let (repo_b, _kb, _db) = tdh::create_repo(&pool, "local", "rpm").await;
        let art_a = seed_artifact(&pool, repo_a).await;
        let art_b = seed_artifact(&pool, repo_b).await;

        // repo_a: two checks (completed@30s, failed@20s); repo_b: one (completed@10s, newest).
        // Capture ids so assertions target *our* rows regardless of what other
        // (parallel) DB-backed tests leave in the shared `quality_check_results`.
        let c_a_completed = seed_check(&pool, repo_a, art_a, "completed", 30.0).await;
        let c_a_failed = seed_check(&pool, repo_a, art_a, "failed", 20.0).await;
        let c_b = seed_check(&pool, repo_b, art_b, "completed", 10.0).await;

        let state = tdh::build_state(pool.clone(), dir_a.to_string_lossy().as_ref());
        let mut admin_auth = tdh::make_auth(user_id, &username);
        admin_auth.is_admin = true;

        // Admin list-all (unfiltered) is cross-repo: a single response surfaces
        // rows from BOTH repos, and all three of our seeded rows are present.
        // (Absolute `total` is not asserted here because the table is shared
        // with other tests; the exact-count assertions below use the isolated
        // repository_id/artifact_id/status filters.)
        let (status, v) = json_body(
            admin_checks_app(state.clone(), admin_auth.clone()),
            "/?per_page=200",
        )
        .await;
        assert_eq!(status, axum::http::StatusCode::OK, "admin list-all 200");
        assert_eq!(v["page"], 1);
        assert_eq!(v["per_page"], 200);
        let ids: std::collections::HashSet<String> = v["items"]
            .as_array()
            .unwrap()
            .iter()
            .map(|i| i["id"].as_str().unwrap().to_string())
            .collect();
        assert!(ids.contains(&c_a_completed.to_string()));
        assert!(ids.contains(&c_a_failed.to_string()));
        assert!(ids.contains(&c_b.to_string()), "list-all is cross-repo");
        assert!(v["total"].as_i64().unwrap() >= 3);

        // Filter by repository_id -> only repo_a's two rows, newest-first
        // (failed@20s before completed@30s).
        let (_s, v) = json_body(
            admin_checks_app(state.clone(), admin_auth.clone()),
            &format!("/?repository_id={}", repo_a),
        )
        .await;
        assert_eq!(v["total"], 2);
        assert_eq!(v["items"].as_array().unwrap().len(), 2);
        for item in v["items"].as_array().unwrap() {
            assert_eq!(item["repository_id"], repo_a.to_string());
        }
        assert_eq!(v["items"][0]["id"], c_a_failed.to_string(), "newest-first");
        assert_eq!(v["items"][1]["id"], c_a_completed.to_string());

        // Filter by repository_id + status -> repo_a's single failed row.
        let (_s, v) = json_body(
            admin_checks_app(state.clone(), admin_auth.clone()),
            &format!("/?repository_id={}&status=failed", repo_a),
        )
        .await;
        assert_eq!(v["total"], 1);
        assert_eq!(v["items"][0]["id"], c_a_failed.to_string());
        assert_eq!(v["items"][0]["status"], "failed");

        // Filter by artifact_id -> only repo_b's single row.
        let (_s, v) = json_body(
            admin_checks_app(state.clone(), admin_auth.clone()),
            &format!("/?artifact_id={}", art_b),
        )
        .await;
        assert_eq!(v["total"], 1);
        assert_eq!(v["items"][0]["artifact_id"], art_b.to_string());

        // Pagination (scoped to repo_a so the slice is isolated from other
        // tests): per_page=1 returns one item per page but the full total=2.
        let (_s, p1) = json_body(
            admin_checks_app(state.clone(), admin_auth.clone()),
            &format!("/?repository_id={}&per_page=1&page=1", repo_a),
        )
        .await;
        assert_eq!(p1["total"], 2);
        assert_eq!(p1["items"].as_array().unwrap().len(), 1);
        assert_eq!(p1["items"][0]["id"], c_a_failed.to_string());
        let (_s, p2) = json_body(
            admin_checks_app(state.clone(), admin_auth.clone()),
            &format!("/?repository_id={}&per_page=1&page=2", repo_a),
        )
        .await;
        assert_eq!(p2["items"].as_array().unwrap().len(), 1);
        assert_eq!(p2["items"][0]["id"], c_a_completed.to_string());
        assert_ne!(p1["items"][0]["id"], p2["items"][0]["id"]);

        // Non-admin caller -> 403 (handler defense-in-depth).
        let non_admin = tdh::make_auth(user_id, &username);
        let (status, _v) = json_body(admin_checks_app(state, non_admin), "/").await;
        assert_eq!(status, axum::http::StatusCode::FORBIDDEN);

        // Teardown (artifacts cascade-delete quality_check_results).
        let _ = sqlx::query("DELETE FROM artifacts WHERE repository_id = $1")
            .bind(repo_b)
            .execute(&pool)
            .await;
        let _ = sqlx::query("DELETE FROM repositories WHERE id = $1")
            .bind(repo_b)
            .execute(&pool)
            .await;
        tdh::cleanup(&pool, repo_a, user_id).await;
    }

    // -----------------------------------------------------------------------
    // Regression guard (#2334): the artifact-scoped /quality/checks contract is
    // unchanged — no artifact_id still 400s; with artifact_id returns a bare
    // Vec<CheckResponse> (not the admin envelope).
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_list_checks_requires_artifact_id_and_returns_bare_vec_db() {
        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let (user_id, username) = tdh::create_user(&pool).await;
        let (repo_id, _key, dir) = tdh::create_repo(&pool, "local", "rpm").await;
        let artifact_id = seed_artifact(&pool, repo_id).await;
        seed_check(&pool, repo_id, artifact_id, "completed", 5.0).await;
        // The caller must now be authorized for the artifact's (private) repo
        // (#2437); grant membership so the #2334 shape assertions still hold.
        tdh::grant_repo_access(&pool, repo_id, user_id).await;

        let state = tdh::build_state(pool.clone(), dir.to_string_lossy().as_ref());
        let auth = tdh::make_auth(user_id, &username);

        // No artifact_id -> 400 (unchanged #2334 contract).
        let app = router()
            .with_state(state.clone())
            .layer(axum::Extension(auth.clone()));
        let (status, _v) = json_body(app, "/checks").await;
        assert_eq!(status, axum::http::StatusCode::BAD_REQUEST);

        // With artifact_id -> 200 and a bare JSON array, not the {items,...} envelope.
        let app = router().with_state(state).layer(axum::Extension(auth));
        let (status, v) = json_body(app, &format!("/checks?artifact_id={}", artifact_id)).await;
        assert_eq!(status, axum::http::StatusCode::OK);
        assert!(
            v.is_array(),
            "list_checks returns a bare Vec<CheckResponse>"
        );
        assert_eq!(v.as_array().unwrap().len(), 1);

        tdh::cleanup(&pool, repo_id, user_id).await;
    }

    // -----------------------------------------------------------------------
    // Cross-repo QC metadata authorization (#2437): the artifact-scoped read
    // routes (`/checks`, `/checks/:id`, `/checks/:id/issues`,
    // `/health/artifacts/:id`) must run the canonical
    // `check_artifact_visibility` gate, so a caller with no access to the
    // artifact's private repo gets an existence-hiding 404 that leaks no QC
    // metadata, while members/admins/public-repo callers are unaffected.
    // -----------------------------------------------------------------------

    /// Wire the public quality router to a concrete caller (the real
    /// `auth_middleware` inserts `Extension<AuthExtension>`, which these
    /// handlers read).
    fn quality_app(state: SharedState, auth: AuthExtension) -> axum::Router {
        router().with_state(state).layer(axum::Extension(auth))
    }

    /// Fetch a URI returning the status plus the RAW response body string, so
    /// leak assertions can inspect the exact bytes sent to the client.
    async fn raw_get(app: axum::Router, uri: &str) -> (axum::http::StatusCode, String) {
        let (status, body) = tdh::send(app, tdh::get(uri.to_string())).await;
        (status, String::from_utf8_lossy(&body).to_string())
    }

    /// A no-access 404 body must not leak any quality-check metadata field.
    fn assert_no_qc_leak(body: &str) {
        for needle in ["repository_id", "check_type", "score"] {
            assert!(
                !body.contains(needle),
                "404 body must not leak `{needle}`: {body}"
            );
        }
    }

    /// Seed a private repo + artifact + one completed check.
    /// Returns (repo_id, artifact_id, check_id, storage_dir).
    async fn seed_repo_artifact_check(
        pool: &sqlx::PgPool,
    ) -> (Uuid, Uuid, Uuid, std::path::PathBuf) {
        let (repo_id, _k, dir) = tdh::create_repo(pool, "local", "rpm").await;
        let art = seed_artifact(pool, repo_id).await;
        let check = seed_check(pool, repo_id, art, "completed", 5.0).await;
        (repo_id, art, check, dir)
    }

    // (1) accessible/member user + existing artifact -> 200 with rows.
    #[tokio::test]
    async fn test_list_checks_member_user_ok_db() {
        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let (user_id, username) = tdh::create_user(&pool).await;
        let (repo_id, art, _c, dir) = seed_repo_artifact_check(&pool).await;
        tdh::grant_repo_access(&pool, repo_id, user_id).await;
        let state = tdh::build_state(pool.clone(), dir.to_string_lossy().as_ref());
        let auth = tdh::make_auth(user_id, &username);
        let (status, v) = json_body(
            quality_app(state, auth),
            &format!("/checks?artifact_id={}", art),
        )
        .await;
        assert_eq!(status, axum::http::StatusCode::OK);
        assert_eq!(v.as_array().unwrap().len(), 1);
        tdh::cleanup(&pool, repo_id, user_id).await;
    }

    // (2) authenticated no-access user -> 404 with no leaked metadata.
    #[tokio::test]
    async fn test_list_checks_no_access_404_no_leak_db() {
        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let (outsider_id, outsider) = tdh::create_user(&pool).await;
        let (repo_id, art, _c, dir) = seed_repo_artifact_check(&pool).await;
        let state = tdh::build_state(pool.clone(), dir.to_string_lossy().as_ref());
        let auth = tdh::make_auth(outsider_id, &outsider);
        let (status, body) = raw_get(
            quality_app(state, auth),
            &format!("/checks?artifact_id={}", art),
        )
        .await;
        assert_eq!(status, axum::http::StatusCode::NOT_FOUND);
        assert_no_qc_leak(&body);
        tdh::cleanup(&pool, repo_id, outsider_id).await;
    }

    // (3) missing artifact_id still 400 — the #2334 guard stays FIRST, ahead
    // of any existence/authz work.
    #[tokio::test]
    async fn test_list_checks_missing_artifact_id_still_400_db() {
        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let (user_id, username) = tdh::create_user(&pool).await;
        let (repo_id, _art, _c, dir) = seed_repo_artifact_check(&pool).await;
        let state = tdh::build_state(pool.clone(), dir.to_string_lossy().as_ref());
        let auth = tdh::make_auth(user_id, &username);
        let (status, _v) = json_body(quality_app(state, auth), "/checks").await;
        assert_eq!(status, axum::http::StatusCode::BAD_REQUEST);
        tdh::cleanup(&pool, repo_id, user_id).await;
    }

    // (4) admin -> 200 (visibility bypass), even with no explicit membership.
    #[tokio::test]
    async fn test_list_checks_admin_bypass_ok_db() {
        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let (user_id, username) = tdh::create_user(&pool).await;
        let (repo_id, art, _c, dir) = seed_repo_artifact_check(&pool).await;
        let state = tdh::build_state(pool.clone(), dir.to_string_lossy().as_ref());
        let admin = tdh::admin_auth(user_id, &username);
        let (status, v) = json_body(
            quality_app(state, admin),
            &format!("/checks?artifact_id={}", art),
        )
        .await;
        assert_eq!(status, axum::http::StatusCode::OK);
        assert_eq!(v.as_array().unwrap().len(), 1);
        tdh::cleanup(&pool, repo_id, user_id).await;
    }

    // (5) nonexistent artifact_id -> 404 (uniform with no-access), no leak.
    #[tokio::test]
    async fn test_list_checks_nonexistent_artifact_404_db() {
        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let (user_id, username) = tdh::create_user(&pool).await;
        let (repo_id, _k, dir) = tdh::create_repo(&pool, "local", "rpm").await;
        let state = tdh::build_state(pool.clone(), dir.to_string_lossy().as_ref());
        let admin = tdh::admin_auth(user_id, &username);
        let (status, body) = raw_get(
            quality_app(state, admin),
            &format!("/checks?artifact_id={}", Uuid::new_v4()),
        )
        .await;
        assert_eq!(status, axum::http::StatusCode::NOT_FOUND);
        assert_no_qc_leak(&body);
        tdh::cleanup(&pool, repo_id, user_id).await;
    }

    // (6) public-repo artifact + any authed non-member -> 200.
    #[tokio::test]
    async fn test_list_checks_public_repo_ok_db() {
        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let (user_id, username) = tdh::create_user(&pool).await;
        let (repo_id, art, _c, dir) = seed_repo_artifact_check(&pool).await;
        let _ = sqlx::query("UPDATE repositories SET is_public = true WHERE id = $1")
            .bind(repo_id)
            .execute(&pool)
            .await;
        let state = tdh::build_state(pool.clone(), dir.to_string_lossy().as_ref());
        let auth = tdh::make_auth(user_id, &username);
        let (status, v) = json_body(
            quality_app(state, auth),
            &format!("/checks?artifact_id={}", art),
        )
        .await;
        assert_eq!(status, axum::http::StatusCode::OK);
        assert_eq!(v.as_array().unwrap().len(), 1);
        tdh::cleanup(&pool, repo_id, user_id).await;
    }

    // get_check: no-access user -> 404, no leak.
    #[tokio::test]
    async fn test_get_check_no_access_404_no_leak_db() {
        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let (outsider_id, outsider) = tdh::create_user(&pool).await;
        let (repo_id, _art, check, dir) = seed_repo_artifact_check(&pool).await;
        let state = tdh::build_state(pool.clone(), dir.to_string_lossy().as_ref());
        let auth = tdh::make_auth(outsider_id, &outsider);
        let (status, body) = raw_get(quality_app(state, auth), &format!("/checks/{}", check)).await;
        assert_eq!(status, axum::http::StatusCode::NOT_FOUND);
        assert_no_qc_leak(&body);
        tdh::cleanup(&pool, repo_id, outsider_id).await;
    }

    // list_check_issues: no-access user -> 404, no leak.
    #[tokio::test]
    async fn test_list_check_issues_no_access_404_no_leak_db() {
        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let (outsider_id, outsider) = tdh::create_user(&pool).await;
        let (repo_id, _art, check, dir) = seed_repo_artifact_check(&pool).await;
        let state = tdh::build_state(pool.clone(), dir.to_string_lossy().as_ref());
        let auth = tdh::make_auth(outsider_id, &outsider);
        let (status, body) = raw_get(
            quality_app(state, auth),
            &format!("/checks/{}/issues", check),
        )
        .await;
        assert_eq!(status, axum::http::StatusCode::NOT_FOUND);
        assert_no_qc_leak(&body);
        tdh::cleanup(&pool, repo_id, outsider_id).await;
    }

    // get_artifact_health: no-access user -> 404, no leak.
    #[tokio::test]
    async fn test_get_artifact_health_no_access_404_no_leak_db() {
        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let (outsider_id, outsider) = tdh::create_user(&pool).await;
        let (repo_id, art, _c, dir) = seed_repo_artifact_check(&pool).await;
        // Give the artifact a health score so the existence handling passes and
        // control reaches the authorization gate.
        let _ = sqlx::query(
            "INSERT INTO artifact_health_scores (artifact_id, health_score) VALUES ($1, 90)",
        )
        .bind(art)
        .execute(&pool)
        .await;
        let state = tdh::build_state(pool.clone(), dir.to_string_lossy().as_ref());
        let auth = tdh::make_auth(outsider_id, &outsider);
        let (status, body) = raw_get(
            quality_app(state, auth),
            &format!("/health/artifacts/{}", art),
        )
        .await;
        assert_eq!(status, axum::http::StatusCode::NOT_FOUND);
        assert_no_qc_leak(&body);
        tdh::cleanup(&pool, repo_id, outsider_id).await;
    }
}
