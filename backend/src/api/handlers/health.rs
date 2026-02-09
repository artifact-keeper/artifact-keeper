//! Health check endpoints.

use axum::{extract::State, http::StatusCode, response::IntoResponse, Json};
use reqwest::Client;
use serde::Serialize;
use std::time::Duration;
use utoipa::{OpenApi, ToSchema};

use crate::api::SharedState;

#[derive(Serialize, ToSchema)]
pub struct HealthResponse {
    pub status: String,
    pub version: String,
    pub demo_mode: bool,
    pub checks: HealthChecks,
}

#[derive(Serialize, ToSchema)]
pub struct HealthChecks {
    pub database: CheckStatus,
    pub storage: CheckStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub security_scanner: Option<CheckStatus>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub meilisearch: Option<CheckStatus>,
}

#[derive(Serialize, ToSchema)]
pub struct CheckStatus {
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

/// Probe an external service health endpoint and return a CheckStatus.
async fn check_service_health(
    base_url: &str,
    health_path: &str,
    service_name: &str,
) -> CheckStatus {
    let client = Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .unwrap_or_default();
    let url = format!("{}{}", base_url.trim_end_matches('/'), health_path);
    match client.get(&url).send().await {
        Ok(resp) if resp.status().is_success() => CheckStatus {
            status: "healthy".to_string(),
            message: None,
        },
        Ok(resp) => CheckStatus {
            status: "unhealthy".to_string(),
            message: Some(format!(
                "{} returned status {}",
                service_name,
                resp.status()
            )),
        },
        Err(e) => CheckStatus {
            status: "unavailable".to_string(),
            message: Some(format!("{} unreachable: {}", service_name, e)),
        },
    }
}

/// Health check endpoint - basic liveness check
#[utoipa::path(
    get,
    path = "/health",
    context_path = "",
    tag = "health",
    responses(
        (status = 200, description = "Service is healthy", body = HealthResponse),
        (status = 503, description = "Service is unhealthy", body = HealthResponse),
    )
)]
pub async fn health_check(State(state): State<SharedState>) -> impl IntoResponse {
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

    let scanner_check = match &state.config.trivy_url {
        Some(url) => Some(check_service_health(url, "/healthz", "Trivy").await),
        None => None,
    };

    let meili_check = match &state.config.meilisearch_url {
        Some(url) => Some(check_service_health(url, "/health", "Meilisearch").await),
        None => None,
    };

    let overall_status = if db_check.status == "healthy" {
        "healthy"
    } else {
        "unhealthy"
    };

    let response = HealthResponse {
        status: overall_status.to_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
        demo_mode: state.config.demo_mode,
        checks: HealthChecks {
            database: db_check,
            storage: CheckStatus {
                status: "healthy".to_string(),
                message: None,
            },
            security_scanner: scanner_check,
            meilisearch: meili_check,
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
#[utoipa::path(
    get,
    path = "/ready",
    context_path = "",
    tag = "health",
    responses(
        (status = 200, description = "Service is ready to accept traffic"),
        (status = 503, description = "Service is not ready"),
    )
)]
pub async fn readiness_check(State(state): State<SharedState>) -> impl IntoResponse {
    // Check database connectivity
    match sqlx::query("SELECT 1").fetch_one(&state.db).await {
        Ok(_) => StatusCode::OK,
        Err(_) => StatusCode::SERVICE_UNAVAILABLE,
    }
}

/// Prometheus metrics endpoint.
/// Renders all registered metrics from the metrics-exporter-prometheus recorder.
#[utoipa::path(
    get,
    path = "/metrics",
    context_path = "/api/v1/admin",
    tag = "health",
    responses(
        (status = 200, description = "Prometheus metrics in text format", content_type = "text/plain"),
    )
)]
pub async fn metrics(State(state): State<SharedState>) -> impl IntoResponse {
    let output = if let Some(ref handle) = state.metrics_handle {
        handle.render()
    } else {
        "# No metrics recorder installed\n".to_string()
    };

    (
        StatusCode::OK,
        [("content-type", "text/plain; charset=utf-8")],
        output,
    )
}

#[derive(OpenApi)]
#[openapi(
    paths(health_check, readiness_check, metrics),
    components(schemas(HealthResponse, HealthChecks, CheckStatus))
)]
pub struct HealthApiDoc;

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json;

    /// Test HealthResponse serialization
    #[test]
    fn test_health_response_serialization() {
        let response = HealthResponse {
            status: "healthy".to_string(),
            version: "1.0.0".to_string(),
            demo_mode: false,
            checks: HealthChecks {
                database: CheckStatus {
                    status: "healthy".to_string(),
                    message: None,
                },
                storage: CheckStatus {
                    status: "healthy".to_string(),
                    message: Some("Connected".to_string()),
                },
                security_scanner: None,
                meilisearch: None,
            },
        };

        let json = serde_json::to_string(&response).unwrap();
        assert!(json.contains("\"status\":\"healthy\""));
        assert!(json.contains("\"version\":\"1.0.0\""));
        assert!(json.contains("\"database\""));
        assert!(json.contains("\"storage\""));
        // security_scanner is None, should be skipped
        assert!(!json.contains("\"security_scanner\""));
    }

    /// Test HealthResponse with security scanner
    #[test]
    fn test_health_response_with_scanner() {
        let response = HealthResponse {
            status: "healthy".to_string(),
            version: "1.0.0".to_string(),
            demo_mode: false,
            checks: HealthChecks {
                database: CheckStatus {
                    status: "healthy".to_string(),
                    message: None,
                },
                storage: CheckStatus {
                    status: "healthy".to_string(),
                    message: None,
                },
                security_scanner: Some(CheckStatus {
                    status: "healthy".to_string(),
                    message: None,
                }),
                meilisearch: None,
            },
        };

        let json = serde_json::to_string(&response).unwrap();
        assert!(json.contains("\"security_scanner\""));
    }

    /// Test CheckStatus without message skips serialization
    #[test]
    fn test_check_status_skip_none_message() {
        let status = CheckStatus {
            status: "healthy".to_string(),
            message: None,
        };

        let json = serde_json::to_string(&status).unwrap();
        assert!(!json.contains("message"));
    }

    /// Test CheckStatus with message includes it
    #[test]
    fn test_check_status_with_message() {
        let status = CheckStatus {
            status: "unhealthy".to_string(),
            message: Some("Connection refused".to_string()),
        };

        let json = serde_json::to_string(&status).unwrap();
        assert!(json.contains("\"message\":\"Connection refused\""));
    }

    /// Test unhealthy response structure
    #[test]
    fn test_unhealthy_response_serialization() {
        let response = HealthResponse {
            status: "unhealthy".to_string(),
            version: "1.0.0".to_string(),
            demo_mode: false,
            checks: HealthChecks {
                database: CheckStatus {
                    status: "unhealthy".to_string(),
                    message: Some("Database connection failed: timeout".to_string()),
                },
                storage: CheckStatus {
                    status: "healthy".to_string(),
                    message: None,
                },
                security_scanner: None,
                meilisearch: None,
            },
        };

        let json = serde_json::to_string(&response).unwrap();
        assert!(json.contains("\"status\":\"unhealthy\""));
        assert!(json.contains("Database connection failed"));
    }
}
