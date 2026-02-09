//! Dependency-Track proxy handlers.
//!
//! Proxies requests to the Dependency-Track API server,
//! providing a unified API surface for the frontend.

use axum::{
    extract::{Path, Query, State},
    routing::get,
    Extension, Json, Router,
};
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, OpenApi, ToSchema};

use crate::api::middleware::auth::AuthExtension;
use crate::api::SharedState;
use crate::error::{AppError, Result};
use crate::services::dependency_track_service::{
    DtAnalysisResponse, DtComponentFull, DtFinding, DtPolicyFull, DtPolicyViolation,
    DtPortfolioMetrics, DtProject, DtProjectMetrics,
};

/// Create Dependency-Track proxy routes.
pub fn router() -> Router<SharedState> {
    Router::new()
        // Health / status
        .route("/status", get(dt_status))
        // Projects
        .route("/projects", get(list_projects))
        .route("/projects/:project_uuid", get(get_project))
        // Findings (vulnerabilities)
        .route(
            "/projects/:project_uuid/findings",
            get(get_project_findings),
        )
        // Components
        .route(
            "/projects/:project_uuid/components",
            get(get_project_components),
        )
        // Metrics
        .route("/projects/:project_uuid/metrics", get(get_project_metrics))
        .route(
            "/projects/:project_uuid/metrics/history",
            get(get_project_metrics_history),
        )
        .route("/metrics/portfolio", get(get_portfolio_metrics))
        // Policy violations
        .route(
            "/projects/:project_uuid/violations",
            get(get_project_violations),
        )
        // Analysis (triage)
        .route("/analysis", axum::routing::put(update_analysis))
        // Policies
        .route("/policies", get(list_policies))
}

// === Request/Response types ===

#[derive(Debug, Serialize, ToSchema)]
struct DtStatusResponse {
    enabled: bool,
    healthy: bool,
    url: Option<String>,
}

#[derive(Debug, Deserialize, IntoParams)]
struct MetricsHistoryQuery {
    #[serde(default = "default_days")]
    days: u32,
}

fn default_days() -> u32 {
    30
}

#[derive(Debug, Deserialize, ToSchema)]
struct UpdateAnalysisBody {
    project_uuid: String,
    component_uuid: String,
    vulnerability_uuid: String,
    state: String,
    justification: Option<String>,
    details: Option<String>,
    #[serde(default)]
    suppressed: bool,
}

// === Helpers ===

fn get_dt_service(
    state: &SharedState,
) -> Result<&crate::services::dependency_track_service::DependencyTrackService> {
    state
        .dependency_track
        .as_ref()
        .map(|dt| dt.as_ref())
        .ok_or_else(|| {
            AppError::Internal("Dependency-Track integration is not enabled".to_string())
        })
}

// === Handlers ===

/// Get Dependency-Track integration status
#[utoipa::path(
    get,
    path = "/status",
    context_path = "/api/v1/dependency-track",
    tag = "security",
    responses(
        (status = 200, description = "Dependency-Track status", body = DtStatusResponse),
    ),
    security(("bearer_auth" = []))
)]
async fn dt_status(State(state): State<SharedState>) -> Result<Json<DtStatusResponse>> {
    match &state.dependency_track {
        Some(dt) => {
            let healthy = dt.health_check().await.unwrap_or(false);
            Ok(Json(DtStatusResponse {
                enabled: true,
                healthy,
                url: Some(dt.base_url().to_string()),
            }))
        }
        None => Ok(Json(DtStatusResponse {
            enabled: false,
            healthy: false,
            url: None,
        })),
    }
}

/// List all Dependency-Track projects
#[utoipa::path(
    get,
    path = "/projects",
    context_path = "/api/v1/dependency-track",
    tag = "security",
    responses(
        (status = 200, description = "List of projects", body = Vec<DtProject>),
    ),
    security(("bearer_auth" = []))
)]
async fn list_projects(
    State(state): State<SharedState>,
    Extension(_auth): Extension<AuthExtension>,
) -> Result<Json<Vec<DtProject>>> {
    let dt = get_dt_service(&state)?;
    let projects = dt.list_projects().await?;
    Ok(Json(projects))
}

/// Get project findings by project UUID
#[utoipa::path(
    get,
    path = "/projects/{project_uuid}",
    context_path = "/api/v1/dependency-track",
    tag = "security",
    params(
        ("project_uuid" = String, Path, description = "Project UUID"),
    ),
    responses(
        (status = 200, description = "Project findings", body = Vec<DtFinding>),
    ),
    security(("bearer_auth" = []))
)]
async fn get_project(
    State(state): State<SharedState>,
    Extension(_auth): Extension<AuthExtension>,
    Path(project_uuid): Path<String>,
) -> Result<Json<Vec<DtFinding>>> {
    let dt = get_dt_service(&state)?;
    let findings = dt.get_findings(&project_uuid).await?;
    Ok(Json(findings))
}

/// Get vulnerability findings for a project
#[utoipa::path(
    get,
    path = "/projects/{project_uuid}/findings",
    context_path = "/api/v1/dependency-track",
    tag = "security",
    params(
        ("project_uuid" = String, Path, description = "Project UUID"),
    ),
    responses(
        (status = 200, description = "Project vulnerability findings", body = Vec<DtFinding>),
    ),
    security(("bearer_auth" = []))
)]
async fn get_project_findings(
    State(state): State<SharedState>,
    Extension(_auth): Extension<AuthExtension>,
    Path(project_uuid): Path<String>,
) -> Result<Json<Vec<DtFinding>>> {
    let dt = get_dt_service(&state)?;
    let findings = dt.get_findings(&project_uuid).await?;
    Ok(Json(findings))
}

/// Get components for a project
#[utoipa::path(
    get,
    path = "/projects/{project_uuid}/components",
    context_path = "/api/v1/dependency-track",
    tag = "security",
    params(
        ("project_uuid" = String, Path, description = "Project UUID"),
    ),
    responses(
        (status = 200, description = "Project components", body = Vec<DtComponentFull>),
    ),
    security(("bearer_auth" = []))
)]
async fn get_project_components(
    State(state): State<SharedState>,
    Extension(_auth): Extension<AuthExtension>,
    Path(project_uuid): Path<String>,
) -> Result<Json<Vec<DtComponentFull>>> {
    let dt = get_dt_service(&state)?;
    let components = dt.get_components(&project_uuid).await?;
    Ok(Json(components))
}

/// Get metrics for a project
#[utoipa::path(
    get,
    path = "/projects/{project_uuid}/metrics",
    context_path = "/api/v1/dependency-track",
    tag = "security",
    params(
        ("project_uuid" = String, Path, description = "Project UUID"),
    ),
    responses(
        (status = 200, description = "Project metrics", body = DtProjectMetrics),
    ),
    security(("bearer_auth" = []))
)]
async fn get_project_metrics(
    State(state): State<SharedState>,
    Extension(_auth): Extension<AuthExtension>,
    Path(project_uuid): Path<String>,
) -> Result<Json<DtProjectMetrics>> {
    let dt = get_dt_service(&state)?;
    let metrics = dt.get_project_metrics(&project_uuid).await?;
    Ok(Json(metrics))
}

/// Get metrics history for a project
#[utoipa::path(
    get,
    path = "/projects/{project_uuid}/metrics/history",
    context_path = "/api/v1/dependency-track",
    tag = "security",
    params(
        ("project_uuid" = String, Path, description = "Project UUID"),
        MetricsHistoryQuery,
    ),
    responses(
        (status = 200, description = "Project metrics history", body = Vec<DtProjectMetrics>),
    ),
    security(("bearer_auth" = []))
)]
async fn get_project_metrics_history(
    State(state): State<SharedState>,
    Extension(_auth): Extension<AuthExtension>,
    Path(project_uuid): Path<String>,
    Query(query): Query<MetricsHistoryQuery>,
) -> Result<Json<Vec<DtProjectMetrics>>> {
    let dt = get_dt_service(&state)?;
    let history = dt
        .get_project_metrics_history(&project_uuid, query.days)
        .await?;
    Ok(Json(history))
}

/// Get portfolio-level metrics
#[utoipa::path(
    get,
    path = "/metrics/portfolio",
    context_path = "/api/v1/dependency-track",
    tag = "security",
    responses(
        (status = 200, description = "Portfolio metrics", body = DtPortfolioMetrics),
    ),
    security(("bearer_auth" = []))
)]
async fn get_portfolio_metrics(
    State(state): State<SharedState>,
    Extension(_auth): Extension<AuthExtension>,
) -> Result<Json<DtPortfolioMetrics>> {
    let dt = get_dt_service(&state)?;
    let metrics = dt.get_portfolio_metrics().await?;
    Ok(Json(metrics))
}

/// Get policy violations for a project
#[utoipa::path(
    get,
    path = "/projects/{project_uuid}/violations",
    context_path = "/api/v1/dependency-track",
    tag = "security",
    params(
        ("project_uuid" = String, Path, description = "Project UUID"),
    ),
    responses(
        (status = 200, description = "Project policy violations", body = Vec<DtPolicyViolation>),
    ),
    security(("bearer_auth" = []))
)]
async fn get_project_violations(
    State(state): State<SharedState>,
    Extension(_auth): Extension<AuthExtension>,
    Path(project_uuid): Path<String>,
) -> Result<Json<Vec<DtPolicyViolation>>> {
    let dt = get_dt_service(&state)?;
    let violations = dt.get_policy_violations(&project_uuid).await?;
    Ok(Json(violations))
}

/// Update analysis (triage) for a finding
#[utoipa::path(
    put,
    path = "/analysis",
    context_path = "/api/v1/dependency-track",
    tag = "security",
    request_body = UpdateAnalysisBody,
    responses(
        (status = 200, description = "Updated analysis", body = DtAnalysisResponse),
    ),
    security(("bearer_auth" = []))
)]
async fn update_analysis(
    State(state): State<SharedState>,
    Extension(_auth): Extension<AuthExtension>,
    Json(body): Json<UpdateAnalysisBody>,
) -> Result<Json<DtAnalysisResponse>> {
    let dt = get_dt_service(&state)?;
    let result = dt
        .update_analysis(
            &body.project_uuid,
            &body.component_uuid,
            &body.vulnerability_uuid,
            &body.state,
            body.justification.as_deref(),
            body.details.as_deref(),
            body.suppressed,
        )
        .await?;
    Ok(Json(result))
}

/// List all policies
#[utoipa::path(
    get,
    path = "/policies",
    context_path = "/api/v1/dependency-track",
    tag = "security",
    responses(
        (status = 200, description = "List of policies", body = Vec<DtPolicyFull>),
    ),
    security(("bearer_auth" = []))
)]
async fn list_policies(
    State(state): State<SharedState>,
    Extension(_auth): Extension<AuthExtension>,
) -> Result<Json<Vec<DtPolicyFull>>> {
    let dt = get_dt_service(&state)?;
    let policies = dt.get_policies().await?;
    Ok(Json(policies))
}

#[derive(OpenApi)]
#[openapi(
    paths(
        dt_status,
        list_projects,
        get_project,
        get_project_findings,
        get_project_components,
        get_project_metrics,
        get_project_metrics_history,
        get_portfolio_metrics,
        get_project_violations,
        update_analysis,
        list_policies,
    ),
    components(schemas(
        DtStatusResponse,
        UpdateAnalysisBody,
        DtProject,
        DtFinding,
        DtComponentFull,
        DtProjectMetrics,
        DtPortfolioMetrics,
        DtPolicyViolation,
        DtAnalysisResponse,
        DtPolicyFull,
    ))
)]
pub struct DependencyTrackApiDoc;
