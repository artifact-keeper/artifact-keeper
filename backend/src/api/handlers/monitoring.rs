//! Health monitoring API handlers.

use axum::{
    extract::{Extension, Query, State},
    routing::{get, post},
    Json, Router,
};
use chrono::{DateTime, Utc};
use serde::Deserialize;
use utoipa::{IntoParams, OpenApi, ToSchema};

use crate::api::middleware::auth::AuthExtension;
use crate::api::SharedState;
use crate::error::{AppError, Result};
use crate::services::health_monitor_service::{
    AlertState, HealthMonitorService, MonitorConfig, ServiceHealthEntry,
};

#[derive(OpenApi)]
#[openapi(
    paths(
        get_health_log,
        get_alert_states,
        suppress_alert,
        run_health_check,
    ),
    components(schemas(
        SuppressRequest,
        ServiceHealthEntry,
        AlertState,
    )),
)]
pub struct MonitoringApiDoc;

pub fn router() -> Router<SharedState> {
    Router::new()
        .route("/health-log", get(get_health_log))
        .route("/alerts", get(get_alert_states))
        .route("/alerts/suppress", post(suppress_alert))
        .route("/check", post(run_health_check))
}

#[derive(Debug, Deserialize, IntoParams)]
pub struct HealthLogQuery {
    pub service: Option<String>,
    pub limit: Option<i64>,
}

/// GET /api/v1/admin/monitoring/health-log
#[utoipa::path(
    get,
    path = "/health-log",
    context_path = "/api/v1/admin/monitoring",
    tag = "monitoring",
    params(HealthLogQuery),
    responses(
        (status = 200, description = "Health log entries", body = Vec<ServiceHealthEntry>),
    ),
    security(("bearer_auth" = [])),
)]
pub async fn get_health_log(
    State(state): State<SharedState>,
    Query(query): Query<HealthLogQuery>,
) -> Result<Json<Vec<ServiceHealthEntry>>> {
    let monitor = HealthMonitorService::new(state.db.clone(), MonitorConfig::default());
    let limit = query.limit.unwrap_or(100).min(500);
    let entries = monitor
        .get_health_log(query.service.as_deref(), limit)
        .await?;
    Ok(Json(entries))
}

/// GET /api/v1/admin/monitoring/alerts
#[utoipa::path(
    get,
    path = "/alerts",
    context_path = "/api/v1/admin/monitoring",
    tag = "monitoring",
    responses(
        (status = 200, description = "Current alert states", body = Vec<AlertState>),
    ),
    security(("bearer_auth" = [])),
)]
pub async fn get_alert_states(State(state): State<SharedState>) -> Result<Json<Vec<AlertState>>> {
    let monitor = HealthMonitorService::new(state.db.clone(), MonitorConfig::default());
    let states = monitor.get_alert_states().await?;
    Ok(Json(states))
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct SuppressRequest {
    pub service_name: String,
    pub until: DateTime<Utc>,
}

/// POST /api/v1/admin/monitoring/alerts/suppress
#[utoipa::path(
    post,
    path = "/alerts/suppress",
    context_path = "/api/v1/admin/monitoring",
    tag = "monitoring",
    request_body = SuppressRequest,
    responses(
        (status = 200, description = "Alert suppressed"),
    ),
    security(("bearer_auth" = [])),
)]
pub async fn suppress_alert(
    State(state): State<SharedState>,
    Extension(auth): Extension<AuthExtension>,
    Json(payload): Json<SuppressRequest>,
) -> Result<()> {
    if !auth.is_admin {
        return Err(AppError::Unauthorized(
            "Admin privileges required".to_string(),
        ));
    }
    let monitor = HealthMonitorService::new(state.db.clone(), MonitorConfig::default());
    monitor
        .suppress_alerts(&payload.service_name, payload.until)
        .await?;
    Ok(())
}

/// POST /api/v1/admin/monitoring/check - manually trigger health checks
#[utoipa::path(
    post,
    path = "/check",
    context_path = "/api/v1/admin/monitoring",
    tag = "monitoring",
    responses(
        (status = 200, description = "Health check results", body = Vec<ServiceHealthEntry>),
    ),
    security(("bearer_auth" = [])),
)]
pub async fn run_health_check(
    State(state): State<SharedState>,
    Extension(auth): Extension<AuthExtension>,
) -> Result<Json<Vec<ServiceHealthEntry>>> {
    if !auth.is_admin {
        return Err(AppError::Unauthorized(
            "Admin privileges required".to_string(),
        ));
    }
    let monitor = HealthMonitorService::new(state.db.clone(), MonitorConfig::default());
    let results = monitor.check_all_services(&state.config).await?;
    Ok(Json(results))
}
