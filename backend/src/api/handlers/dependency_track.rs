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
    DtAnalysisResponse, DtComponentFull, DtFinding, DtHealthStatus, DtPolicyFull,
    DtPolicyViolation, DtPortfolioMetrics, DtProject, DtProjectMetrics,
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

/// Dependency-Track integration status surfaced to the frontend.
///
/// `healthy` is the boolean the existing UI already binds to. The new
/// `error_status` and `error_message` fields let the UI distinguish a
/// genuine "DT replied OK with no findings" state from "DT is down or
/// misconfigured" (issue #963). When `healthy = true` both error fields
/// are None; when `healthy = false`:
///   - `error_status = Some(401)`: auth failure (check API key)
///   - `error_status = Some(5xx)`: upstream is broken
///   - `error_status = None`:     transport failure (DT pod unreachable)
///   - `error_message`:           operator-facing failure description
#[derive(Debug, Serialize, ToSchema)]
struct DtStatusResponse {
    enabled: bool,
    healthy: bool,
    url: Option<String>,
    /// Upstream HTTP status if the health probe got a response, else None.
    /// Only populated when `healthy = false`.
    #[serde(skip_serializing_if = "Option::is_none")]
    error_status: Option<u16>,
    /// Human-readable explanation when `healthy = false`. Safe to surface
    /// in the UI; does not leak credentials.
    #[serde(skip_serializing_if = "Option::is_none")]
    error_message: Option<String>,
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
async fn dt_status(
    State(state): State<SharedState>,
    Extension(auth): Extension<AuthExtension>,
) -> Result<Json<DtStatusResponse>> {
    auth.require_admin()?;

    match &state.dependency_track {
        Some(dt) => {
            let (healthy, error_status, error_message) = match dt.health_status().await {
                DtHealthStatus::Healthy => (true, None, None),
                DtHealthStatus::Unhealthy { status, reason } => (false, status, Some(reason)),
            };
            Ok(Json(DtStatusResponse {
                enabled: true,
                healthy,
                url: Some(dt.base_url().to_string()),
                error_status,
                error_message,
            }))
        }
        None => Ok(Json(DtStatusResponse {
            enabled: false,
            healthy: false,
            url: None,
            error_status: None,
            error_message: None,
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
    Extension(auth): Extension<AuthExtension>,
) -> Result<Json<Vec<DtProject>>> {
    auth.require_admin()?;

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
    Extension(auth): Extension<AuthExtension>,
    Path(project_uuid): Path<String>,
) -> Result<Json<Vec<DtFinding>>> {
    auth.require_admin()?;

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
    Extension(auth): Extension<AuthExtension>,
    Path(project_uuid): Path<String>,
) -> Result<Json<Vec<DtFinding>>> {
    auth.require_admin()?;

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
    Extension(auth): Extension<AuthExtension>,
    Path(project_uuid): Path<String>,
) -> Result<Json<Vec<DtComponentFull>>> {
    auth.require_admin()?;

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
    Extension(auth): Extension<AuthExtension>,
    Path(project_uuid): Path<String>,
) -> Result<Json<DtProjectMetrics>> {
    auth.require_admin()?;

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
    Extension(auth): Extension<AuthExtension>,
    Path(project_uuid): Path<String>,
    Query(query): Query<MetricsHistoryQuery>,
) -> Result<Json<Vec<DtProjectMetrics>>> {
    auth.require_admin()?;

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
    Extension(auth): Extension<AuthExtension>,
) -> Result<Json<DtPortfolioMetrics>> {
    auth.require_admin()?;

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
    Extension(auth): Extension<AuthExtension>,
    Path(project_uuid): Path<String>,
) -> Result<Json<Vec<DtPolicyViolation>>> {
    auth.require_admin()?;

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
    Extension(auth): Extension<AuthExtension>,
    Json(body): Json<UpdateAnalysisBody>,
) -> Result<Json<DtAnalysisResponse>> {
    auth.require_admin()?;

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
    operation_id = "list_dependency_track_policies",
    responses(
        (status = 200, description = "List of policies", body = Vec<DtPolicyFull>),
    ),
    security(("bearer_auth" = []))
)]
async fn list_policies(
    State(state): State<SharedState>,
    Extension(auth): Extension<AuthExtension>,
) -> Result<Json<Vec<DtPolicyFull>>> {
    auth.require_admin()?;

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

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json;

    // -----------------------------------------------------------------------
    // default_days function
    // -----------------------------------------------------------------------

    #[test]
    fn test_default_days_returns_30() {
        assert_eq!(default_days(), 30);
    }

    // -----------------------------------------------------------------------
    // MetricsHistoryQuery deserialization
    // -----------------------------------------------------------------------

    #[test]
    fn test_metrics_history_query_default_days() {
        let json = r#"{}"#;
        let query: MetricsHistoryQuery = serde_json::from_str(json).unwrap();
        assert_eq!(query.days, 30);
    }

    #[test]
    fn test_metrics_history_query_custom_days() {
        let json = r#"{"days": 90}"#;
        let query: MetricsHistoryQuery = serde_json::from_str(json).unwrap();
        assert_eq!(query.days, 90);
    }

    #[test]
    fn test_metrics_history_query_one_day() {
        let json = r#"{"days": 1}"#;
        let query: MetricsHistoryQuery = serde_json::from_str(json).unwrap();
        assert_eq!(query.days, 1);
    }

    #[test]
    fn test_metrics_history_query_zero_days() {
        let json = r#"{"days": 0}"#;
        let query: MetricsHistoryQuery = serde_json::from_str(json).unwrap();
        assert_eq!(query.days, 0);
    }

    #[test]
    fn test_metrics_history_query_large_days() {
        let json = r#"{"days": 365}"#;
        let query: MetricsHistoryQuery = serde_json::from_str(json).unwrap();
        assert_eq!(query.days, 365);
    }

    // -----------------------------------------------------------------------
    // DtStatusResponse serialization
    // -----------------------------------------------------------------------

    #[test]
    fn test_dt_status_response_enabled() {
        let resp = DtStatusResponse {
            enabled: true,
            healthy: true,
            url: Some("http://dt.example.com".to_string()),
            error_status: None,
            error_message: None,
        };
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["enabled"], true);
        assert_eq!(json["healthy"], true);
        assert_eq!(json["url"], "http://dt.example.com");
        // Error fields elided when healthy.
        assert!(json.get("error_status").is_none());
        assert!(json.get("error_message").is_none());
    }

    #[test]
    fn test_dt_status_response_disabled() {
        let resp = DtStatusResponse {
            enabled: false,
            healthy: false,
            url: None,
            error_status: None,
            error_message: None,
        };
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["enabled"], false);
        assert_eq!(json["healthy"], false);
        assert!(json["url"].is_null());
    }

    #[test]
    fn test_dt_status_response_enabled_but_unhealthy() {
        let resp = DtStatusResponse {
            enabled: true,
            healthy: false,
            url: Some("http://dt.example.com:8081".to_string()),
            error_status: None,
            error_message: None,
        };
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["enabled"], true);
        assert_eq!(json["healthy"], false);
        assert_eq!(json["url"], "http://dt.example.com:8081");
    }

    /// Issue #963 regression: when DT replies with non-2xx (e.g. 401 from a
    /// wrong API key), the status endpoint must surface both the upstream
    /// HTTP status and a human-readable reason so the UI can render an
    /// explicit "scanner unavailable" banner instead of failing open to
    /// "0 dependencies".
    #[test]
    fn test_dt_status_response_unhealthy_with_upstream_401() {
        let resp = DtStatusResponse {
            enabled: true,
            healthy: false,
            url: Some("http://dt.example.com".to_string()),
            error_status: Some(401),
            error_message: Some(
                "Upstream returned HTTP 401 Unauthorized (check DEPENDENCY_TRACK_API_KEY)"
                    .to_string(),
            ),
        };
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["healthy"], false);
        assert_eq!(json["error_status"], 401);
        assert!(json["error_message"].as_str().unwrap().contains("401"));
    }

    /// When DT is unreachable (pod down, DNS failure) there is no upstream
    /// HTTP status. The status endpoint surfaces `error_status = null` and a
    /// "unreachable" reason so the UI renders a different state than
    /// "auth failed".
    #[test]
    fn test_dt_status_response_unhealthy_transport_failure() {
        let resp = DtStatusResponse {
            enabled: true,
            healthy: false,
            url: Some("http://dt.example.com".to_string()),
            error_status: None,
            error_message: Some("Dependency-Track unreachable: connection refused".to_string()),
        };
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["healthy"], false);
        // error_status field elided (skip_serializing_if = None) to signal
        // "no HTTP status was returned" cleanly to the frontend.
        assert!(json.get("error_status").is_none());
        assert!(json["error_message"]
            .as_str()
            .unwrap()
            .contains("unreachable"));
    }

    // -----------------------------------------------------------------------
    // UpdateAnalysisBody deserialization
    // -----------------------------------------------------------------------

    #[test]
    fn test_update_analysis_body_minimal() {
        let json = serde_json::json!({
            "project_uuid": "proj-123",
            "component_uuid": "comp-456",
            "vulnerability_uuid": "vuln-789",
            "state": "NOT_AFFECTED"
        });
        let body: UpdateAnalysisBody = serde_json::from_value(json).unwrap();
        assert_eq!(body.project_uuid, "proj-123");
        assert_eq!(body.component_uuid, "comp-456");
        assert_eq!(body.vulnerability_uuid, "vuln-789");
        assert_eq!(body.state, "NOT_AFFECTED");
        assert!(body.justification.is_none());
        assert!(body.details.is_none());
        assert!(!body.suppressed);
    }

    #[test]
    fn test_update_analysis_body_full() {
        let json = serde_json::json!({
            "project_uuid": "proj-123",
            "component_uuid": "comp-456",
            "vulnerability_uuid": "vuln-789",
            "state": "FALSE_POSITIVE",
            "justification": "PROTECTED_BY_MITIGATING_CONTROL",
            "details": "WAF prevents exploitation",
            "suppressed": true
        });
        let body: UpdateAnalysisBody = serde_json::from_value(json).unwrap();
        assert_eq!(body.state, "FALSE_POSITIVE");
        assert_eq!(
            body.justification.as_deref(),
            Some("PROTECTED_BY_MITIGATING_CONTROL")
        );
        assert_eq!(body.details.as_deref(), Some("WAF prevents exploitation"));
        assert!(body.suppressed);
    }

    #[test]
    fn test_update_analysis_body_missing_required_fails() {
        let json = serde_json::json!({
            "project_uuid": "proj-123",
            "state": "NOT_AFFECTED"
        });
        let result: std::result::Result<UpdateAnalysisBody, _> = serde_json::from_value(json);
        assert!(result.is_err());
    }

    #[test]
    fn test_update_analysis_body_suppressed_defaults_false() {
        let json = serde_json::json!({
            "project_uuid": "a",
            "component_uuid": "b",
            "vulnerability_uuid": "c",
            "state": "IN_TRIAGE"
        });
        let body: UpdateAnalysisBody = serde_json::from_value(json).unwrap();
        assert!(!body.suppressed);
    }

    #[test]
    fn test_update_analysis_body_as_deref_for_optional_fields() {
        let json = serde_json::json!({
            "project_uuid": "a",
            "component_uuid": "b",
            "vulnerability_uuid": "c",
            "state": "EXPLOITABLE",
            "justification": "test-justification",
            "details": "test-details"
        });
        let body: UpdateAnalysisBody = serde_json::from_value(json).unwrap();
        // Mimics the handler's usage: body.justification.as_deref()
        assert_eq!(body.justification.as_deref(), Some("test-justification"));
        assert_eq!(body.details.as_deref(), Some("test-details"));
    }

    // -----------------------------------------------------------------------
    // DtStatusResponse field variations
    // -----------------------------------------------------------------------

    #[test]
    fn test_dt_status_response_url_with_path() {
        let resp = DtStatusResponse {
            enabled: true,
            healthy: true,
            url: Some("http://dt.internal:8080/api".to_string()),
            error_status: None,
            error_message: None,
        };
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["url"], "http://dt.internal:8080/api");
    }

    #[test]
    fn test_dt_status_all_fields_present_in_json() {
        let resp = DtStatusResponse {
            enabled: true,
            healthy: false,
            url: Some("http://localhost".to_string()),
            error_status: Some(503),
            error_message: Some("upstream down".to_string()),
        };
        let json = serde_json::to_value(&resp).unwrap();
        let obj = json.as_object().unwrap();
        assert!(obj.contains_key("enabled"));
        assert!(obj.contains_key("healthy"));
        assert!(obj.contains_key("url"));
        // error_status / error_message are present here because they are
        // Some(...). When None they are elided by skip_serializing_if.
        assert!(obj.contains_key("error_status"));
        assert!(obj.contains_key("error_message"));
        assert_eq!(obj.len(), 5);
    }
}
