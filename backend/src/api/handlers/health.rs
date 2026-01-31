//! Health check endpoints.

use axum::{extract::State, http::StatusCode, response::IntoResponse, Json};
use reqwest::Client;
use serde::Serialize;
use std::time::Duration;

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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub security_scanner: Option<CheckStatus>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub meilisearch: Option<CheckStatus>,
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

    // Check security scanner (Trivy) if configured
    let scanner_check = if let Some(trivy_url) = &state.config.trivy_url {
        let client = Client::builder()
            .timeout(Duration::from_secs(5))
            .build()
            .unwrap_or_default();
        let health_url = format!("{}/healthz", trivy_url.trim_end_matches('/'));
        match client.get(&health_url).send().await {
            Ok(resp) if resp.status().is_success() => Some(CheckStatus {
                status: "healthy".to_string(),
                message: None,
            }),
            Ok(resp) => Some(CheckStatus {
                status: "unhealthy".to_string(),
                message: Some(format!("Trivy returned status {}", resp.status())),
            }),
            Err(e) => Some(CheckStatus {
                status: "unavailable".to_string(),
                message: Some(format!("Trivy unreachable: {}", e)),
            }),
        }
    } else {
        None
    };

    // Check Meilisearch if configured
    let meili_check = if let Some(meili_url) = &state.config.meilisearch_url {
        let client = Client::builder()
            .timeout(Duration::from_secs(5))
            .build()
            .unwrap_or_default();
        let health_url = format!("{}/health", meili_url.trim_end_matches('/'));
        match client.get(&health_url).send().await {
            Ok(resp) if resp.status().is_success() => Some(CheckStatus {
                status: "healthy".to_string(),
                message: None,
            }),
            Ok(resp) => Some(CheckStatus {
                status: "unhealthy".to_string(),
                message: Some(format!("Meilisearch returned status {}", resp.status())),
            }),
            Err(e) => Some(CheckStatus {
                status: "unavailable".to_string(),
                message: Some(format!("Meilisearch unreachable: {}", e)),
            }),
        }
    } else {
        None
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

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        body::Body,
        http::{Request, StatusCode},
        routing::get,
        Router,
    };
    use serde_json;
    use tower::ServiceExt;

    /// Test the metrics endpoint returns valid Prometheus format
    #[tokio::test]
    async fn test_metrics_endpoint() {
        let app = Router::new().route("/metrics", get(metrics));

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/metrics")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let content_type = response.headers().get("content-type").unwrap();
        assert!(content_type.to_str().unwrap().contains("text/plain"));

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let body_str = String::from_utf8(body.to_vec()).unwrap();

        // Verify Prometheus format
        assert!(body_str.contains("# HELP artifact_keeper_http_requests_total"));
        assert!(body_str.contains("# TYPE artifact_keeper_http_requests_total counter"));
    }

    /// Test HealthResponse serialization
    #[test]
    fn test_health_response_serialization() {
        let response = HealthResponse {
            status: "healthy".to_string(),
            version: "1.0.0".to_string(),
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
