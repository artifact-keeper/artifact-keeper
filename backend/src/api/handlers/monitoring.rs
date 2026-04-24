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
    paths(get_health_log, get_alert_states, suppress_alert, run_health_check,),
    components(schemas(SuppressRequest, ServiceHealthEntry, AlertState,))
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

#[cfg(test)]
mod tests {
    use super::*;

    // ── HealthLogQuery deserialization tests ─────────────────────────

    #[test]
    fn test_health_log_query_empty() {
        let json = r#"{}"#;
        let q: HealthLogQuery = serde_json::from_str(json).unwrap();
        assert!(q.service.is_none());
        assert!(q.limit.is_none());
    }

    #[test]
    fn test_health_log_query_with_service() {
        let json = r#"{"service": "postgres"}"#;
        let q: HealthLogQuery = serde_json::from_str(json).unwrap();
        assert_eq!(q.service, Some("postgres".to_string()));
    }

    #[test]
    fn test_health_log_query_with_limit() {
        let json = r#"{"limit": 50}"#;
        let q: HealthLogQuery = serde_json::from_str(json).unwrap();
        assert_eq!(q.limit, Some(50));
    }

    #[test]
    fn test_health_log_query_both_params() {
        let json = r#"{"service": "opensearch", "limit": 25}"#;
        let q: HealthLogQuery = serde_json::from_str(json).unwrap();
        assert_eq!(q.service, Some("opensearch".to_string()));
        assert_eq!(q.limit, Some(25));
    }

    // ── Limit clamping logic tests ──────────────────────────────────

    #[test]
    fn test_limit_default_is_100() {
        let query = HealthLogQuery {
            service: None,
            limit: None,
        };
        let limit = query.limit.unwrap_or(100).min(500);
        assert_eq!(limit, 100);
    }

    #[test]
    fn test_limit_clamped_to_500() {
        let query = HealthLogQuery {
            service: None,
            limit: Some(1000),
        };
        let limit = query.limit.unwrap_or(100).min(500);
        assert_eq!(limit, 500);
    }

    #[test]
    fn test_limit_below_max_preserved() {
        let query = HealthLogQuery {
            service: None,
            limit: Some(250),
        };
        let limit = query.limit.unwrap_or(100).min(500);
        assert_eq!(limit, 250);
    }

    #[test]
    fn test_limit_exactly_500() {
        let query = HealthLogQuery {
            service: None,
            limit: Some(500),
        };
        let limit = query.limit.unwrap_or(100).min(500);
        assert_eq!(limit, 500);
    }

    // ── SuppressRequest deserialization tests ────────────────────────

    #[test]
    fn test_suppress_request_deserialization() {
        let json = r#"{"service_name": "postgres", "until": "2024-12-31T23:59:59Z"}"#;
        let req: SuppressRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.service_name, "postgres");
        let expected: DateTime<Utc> = "2024-12-31T23:59:59Z".parse().unwrap();
        assert_eq!(req.until, expected);
    }

    #[test]
    fn test_suppress_request_missing_service_fails() {
        let json = r#"{"until": "2024-12-31T23:59:59Z"}"#;
        let result: std::result::Result<SuppressRequest, _> = serde_json::from_str(json);
        assert!(result.is_err());
    }

    #[test]
    fn test_suppress_request_missing_until_fails() {
        let json = r#"{"service_name": "postgres"}"#;
        let result: std::result::Result<SuppressRequest, _> = serde_json::from_str(json);
        assert!(result.is_err());
    }

    #[test]
    fn test_suppress_request_invalid_date_fails() {
        let json = r#"{"service_name": "postgres", "until": "not-a-date"}"#;
        let result: std::result::Result<SuppressRequest, _> = serde_json::from_str(json);
        assert!(result.is_err());
    }

    // ── MonitorConfig default tests ─────────────────────────────────

    #[test]
    fn test_monitor_config_default() {
        let config = MonitorConfig::default();
        assert_eq!(config.alert_threshold, 3);
        assert_eq!(config.alert_cooldown_minutes, 15);
        assert_eq!(config.check_timeout_secs, 5);
    }

    // ── ServiceHealthEntry serialization tests ──────────────────────

    #[test]
    fn test_service_health_entry_serialization() {
        let entry = ServiceHealthEntry {
            service_name: "postgres".to_string(),
            status: "healthy".to_string(),
            previous_status: Some("unhealthy".to_string()),
            message: Some("Connection restored".to_string()),
            response_time_ms: Some(15),
            checked_at: chrono::Utc::now(),
        };
        let json = serde_json::to_value(&entry).unwrap();
        assert_eq!(json["service_name"], "postgres");
        assert_eq!(json["status"], "healthy");
        assert_eq!(json["previous_status"], "unhealthy");
        assert_eq!(json["response_time_ms"], 15);
    }

    #[test]
    fn test_service_health_entry_minimal() {
        let entry = ServiceHealthEntry {
            service_name: "opensearch".to_string(),
            status: "unknown".to_string(),
            previous_status: None,
            message: None,
            response_time_ms: None,
            checked_at: chrono::Utc::now(),
        };
        let json = serde_json::to_value(&entry).unwrap();
        assert_eq!(json["service_name"], "opensearch");
        assert!(json["previous_status"].is_null());
        assert!(json["message"].is_null());
        assert!(json["response_time_ms"].is_null());
    }

    // ── AlertState serialization tests ──────────────────────────────

    #[test]
    fn test_alert_state_serialization() {
        let state = AlertState {
            service_name: "trivy".to_string(),
            current_status: "degraded".to_string(),
            consecutive_failures: 5,
            last_alert_sent_at: Some(chrono::Utc::now()),
            suppressed_until: None,
            updated_at: chrono::Utc::now(),
        };
        let json = serde_json::to_value(&state).unwrap();
        assert_eq!(json["service_name"], "trivy");
        assert_eq!(json["consecutive_failures"], 5);
        assert!(json["suppressed_until"].is_null());
    }
}
