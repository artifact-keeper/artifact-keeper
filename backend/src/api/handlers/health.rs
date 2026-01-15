//! Health check endpoints.

use axum::{
    extract::State,
    http::StatusCode,
    response::IntoResponse,
    Json,
};
use serde::Serialize;

use crate::api::SharedState;

#[derive(Serialize)]
pub struct HealthResponse {
    pub status: String,
    pub version: String,
    pub checks: HealthChecks,
}

#[derive(Serialize)]
pub struct HealthChecks {
    pub database: CheckStatus,
    pub storage: CheckStatus,
}

#[derive(Serialize)]
pub struct CheckStatus {
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

/// Health check endpoint - basic liveness check
pub async fn health_check(State(state): State<SharedState>) -> impl IntoResponse {
    // Check database connectivity
    let db_check = match sqlx::query("SELECT 1").fetch_one(&state.db).await {
        Ok(_) => CheckStatus {
            status: "healthy".to_string(),
            message: None,
        },
        Err(e) => CheckStatus {
            status: "unhealthy".to_string(),
            message: Some(format!("Database connection failed: {}", e)),
        },
    };

    let overall_status = if db_check.status == "healthy" {
        "healthy"
    } else {
        "unhealthy"
    };

    let response = HealthResponse {
        status: overall_status.to_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
        checks: HealthChecks {
            database: db_check,
            storage: CheckStatus {
                status: "healthy".to_string(),
                message: None,
            },
        },
    };

    let status_code = if overall_status == "healthy" {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };

    (status_code, Json(response))
}

/// Readiness check endpoint - is the service ready to accept traffic?
pub async fn readiness_check(State(state): State<SharedState>) -> impl IntoResponse {
    // Check database connectivity
    match sqlx::query("SELECT 1").fetch_one(&state.db).await {
        Ok(_) => StatusCode::OK,
        Err(_) => StatusCode::SERVICE_UNAVAILABLE,
    }
}

/// Prometheus metrics endpoint
pub async fn metrics() -> impl IntoResponse {
    // TODO: Implement proper Prometheus metrics collection
    let metrics = r#"# HELP artifact_keeper_http_requests_total Total HTTP requests
# TYPE artifact_keeper_http_requests_total counter
artifact_keeper_http_requests_total{method="GET",path="/health"} 1
"#;

    (
        StatusCode::OK,
        [("content-type", "text/plain; charset=utf-8")],
        metrics,
    )
}
