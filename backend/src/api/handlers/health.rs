//! Health check endpoints.
//!
//! Provides Kubernetes-style probes:
//! - `/livez`   — lightweight liveness (process alive, no external deps)
//! - `/readyz`  — readiness gate (DB + migrations + setup complete)
//! - `/health`  — rich status page for dashboards (all services + pool stats)
//! - `/healthz` — alias for `/health`

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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub db_pool: Option<DbPoolStats>,
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

/// Lightweight liveness response.
#[derive(Serialize, ToSchema)]
pub struct LivezResponse {
    pub status: String,
}

/// Readiness response with per-check detail.
#[derive(Serialize, ToSchema)]
pub struct ReadyzResponse {
    pub status: String,
    pub checks: ReadyzChecks,
}

#[derive(Serialize, ToSchema)]
pub struct ReadyzChecks {
    pub database: CheckStatus,
    pub migrations: CheckStatus,
    pub setup_complete: CheckStatus,
}

/// Database connection pool statistics.
#[derive(Serialize, ToSchema)]
pub struct DbPoolStats {
    pub max_connections: u32,
    pub idle_connections: u32,
    pub active_connections: u32,
    pub size: u32,
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

/// Health check endpoint — rich status page for dashboards.
///
/// Checks database, storage (real write/read probe), optional services (Trivy,
/// Meilisearch), and exposes DB connection pool statistics.
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

    let storage_check = check_storage_health(&state.config).await;

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

    let pool_stats = DbPoolStats {
        max_connections: state.db.options().get_max_connections(),
        idle_connections: state.db.num_idle() as u32,
        active_connections: state.db.size().saturating_sub(state.db.num_idle() as u32),
        size: state.db.size(),
    };

    let response = HealthResponse {
        status: overall_status.to_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
        demo_mode: state.config.demo_mode,
        checks: HealthChecks {
            database: db_check,
            storage: storage_check,
            security_scanner: scanner_check,
            meilisearch: meili_check,
        },
        db_pool: Some(pool_stats),
    };

    let status_code = if overall_status == "healthy" {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };

    (status_code, Json(response))
}

/// Readiness probe — is the service ready to accept traffic?
///
/// Checks database connectivity, that migrations have run successfully,
/// and that initial setup (admin password) is complete.
#[utoipa::path(
    get,
    path = "/readyz",
    context_path = "",
    tag = "health",
    responses(
        (status = 200, description = "Service is ready", body = ReadyzResponse),
        (status = 503, description = "Service is not ready", body = ReadyzResponse),
    )
)]
pub async fn readiness_check(State(state): State<SharedState>) -> impl IntoResponse {
    let db_check = match sqlx::query("SELECT 1").fetch_one(&state.db).await {
        Ok(_) => CheckStatus {
            status: "healthy".to_string(),
            message: None,
        },
        Err(e) => CheckStatus {
            status: "unhealthy".to_string(),
            message: Some(format!("Database unreachable: {}", e)),
        },
    };

    let migrations_check = match sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS(SELECT 1 FROM _sqlx_migrations WHERE success = true)",
    )
    .fetch_one(&state.db)
    .await
    {
        Ok(true) => CheckStatus {
            status: "healthy".to_string(),
            message: None,
        },
        Ok(false) => CheckStatus {
            status: "unhealthy".to_string(),
            message: Some("No successful migrations found".to_string()),
        },
        Err(e) => CheckStatus {
            status: "unhealthy".to_string(),
            message: Some(format!("Migration check failed: {}", e)),
        },
    };

    let setup_required = state
        .setup_required
        .load(std::sync::atomic::Ordering::Relaxed);
    let setup_check = if !setup_required {
        CheckStatus {
            status: "healthy".to_string(),
            message: None,
        }
    } else {
        CheckStatus {
            status: "unhealthy".to_string(),
            message: Some("Admin password change required".to_string()),
        }
    };

    let all_healthy = db_check.status == "healthy"
        && migrations_check.status == "healthy"
        && setup_check.status == "healthy";

    let response = ReadyzResponse {
        status: if all_healthy {
            "ready".to_string()
        } else {
            "not_ready".to_string()
        },
        checks: ReadyzChecks {
            database: db_check,
            migrations: migrations_check,
            setup_complete: setup_check,
        },
    };

    let status_code = if all_healthy {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };

    (status_code, Json(response))
}

/// Liveness probe — confirms the process is alive and can serve HTTP.
///
/// Takes no State parameter. If Axum can route the request and execute this
/// function, the process is alive. External service failures cannot trigger
/// pod restarts.
#[utoipa::path(
    get,
    path = "/livez",
    context_path = "",
    tag = "health",
    responses(
        (status = 200, description = "Process is alive", body = LivezResponse),
    )
)]
pub async fn liveness_check() -> impl IntoResponse {
    Json(LivezResponse {
        status: "ok".to_string(),
    })
}

/// Verify storage backend is writable.
async fn check_storage_health(config: &crate::config::Config) -> CheckStatus {
    match config.storage_backend.as_str() {
        "filesystem" => {
            // Use a fixed probe filename to avoid path injection concerns.
            // storage_path is from server config, not user input, but we
            // canonicalize and verify the probe stays under the base dir.
            let storage_base = std::path::Path::new(&config.storage_path)
                .canonicalize()
                .unwrap_or_else(|_| std::path::PathBuf::from(&config.storage_path));
            let probe_path = storage_base.join(".health-probe");
            if !probe_path.starts_with(&storage_base) {
                return CheckStatus {
                    status: "unhealthy".to_string(),
                    message: Some("Storage path validation failed".to_string()),
                };
            }
            match tokio::fs::write(&probe_path, b"ok").await {
                Ok(()) => match tokio::fs::read(&probe_path).await {
                    Ok(data) if data == b"ok" => {
                        let _ = tokio::fs::remove_file(&probe_path).await;
                        CheckStatus {
                            status: "healthy".to_string(),
                            message: None,
                        }
                    }
                    Ok(_) => CheckStatus {
                        status: "unhealthy".to_string(),
                        message: Some("Storage read-back mismatch".to_string()),
                    },
                    Err(e) => CheckStatus {
                        status: "unhealthy".to_string(),
                        message: Some(format!("Storage read failed: {}", e)),
                    },
                },
                Err(e) => CheckStatus {
                    status: "unhealthy".to_string(),
                    message: Some(format!("Storage write failed: {}", e)),
                },
            }
        }
        "s3" => {
            if config.s3_bucket.is_some() {
                CheckStatus {
                    status: "healthy".to_string(),
                    message: Some("S3 config present (no probe)".to_string()),
                }
            } else {
                CheckStatus {
                    status: "unhealthy".to_string(),
                    message: Some("S3 bucket not configured".to_string()),
                }
            }
        }
        _ => CheckStatus {
            status: "unknown".to_string(),
            message: Some(format!("Unknown backend: {}", config.storage_backend)),
        },
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
    paths(health_check, readiness_check, liveness_check, metrics),
    components(schemas(
        HealthResponse,
        HealthChecks,
        CheckStatus,
        DbPoolStats,
        LivezResponse,
        ReadyzResponse,
        ReadyzChecks
    ))
)]
pub struct HealthApiDoc;

#[cfg(test)]
mod tests {
    use super::*;

    fn healthy_check() -> CheckStatus {
        CheckStatus {
            status: "healthy".to_string(),
            message: None,
        }
    }

    fn sample_pool_stats() -> DbPoolStats {
        DbPoolStats {
            max_connections: 20,
            idle_connections: 15,
            active_connections: 5,
            size: 20,
        }
    }

    #[test]
    fn test_health_response_serialization() {
        let response = HealthResponse {
            status: "healthy".to_string(),
            version: "1.0.0".to_string(),
            demo_mode: false,
            checks: HealthChecks {
                database: healthy_check(),
                storage: CheckStatus {
                    status: "healthy".to_string(),
                    message: Some("Connected".to_string()),
                },
                security_scanner: None,
                meilisearch: None,
            },
            db_pool: Some(sample_pool_stats()),
        };

        let json = serde_json::to_string(&response).unwrap();
        assert!(json.contains("\"status\":\"healthy\""));
        assert!(json.contains("\"version\":\"1.0.0\""));
        assert!(json.contains("\"database\""));
        assert!(json.contains("\"storage\""));
        assert!(json.contains("\"db_pool\""));
        assert!(json.contains("\"max_connections\":20"));
        // security_scanner is None, should be skipped
        assert!(!json.contains("\"security_scanner\""));
    }

    #[test]
    fn test_health_response_without_pool_stats() {
        let response = HealthResponse {
            status: "healthy".to_string(),
            version: "1.0.0".to_string(),
            demo_mode: false,
            checks: HealthChecks {
                database: healthy_check(),
                storage: healthy_check(),
                security_scanner: None,
                meilisearch: None,
            },
            db_pool: None,
        };

        let json = serde_json::to_string(&response).unwrap();
        assert!(!json.contains("\"db_pool\""));
    }

    #[test]
    fn test_health_response_with_scanner() {
        let response = HealthResponse {
            status: "healthy".to_string(),
            version: "1.0.0".to_string(),
            demo_mode: false,
            checks: HealthChecks {
                database: healthy_check(),
                storage: healthy_check(),
                security_scanner: Some(healthy_check()),
                meilisearch: None,
            },
            db_pool: None,
        };

        let json = serde_json::to_string(&response).unwrap();
        assert!(json.contains("\"security_scanner\""));
    }

    #[test]
    fn test_check_status_skip_none_message() {
        let status = healthy_check();
        let json = serde_json::to_string(&status).unwrap();
        assert!(!json.contains("message"));
    }

    #[test]
    fn test_check_status_with_message() {
        let status = CheckStatus {
            status: "unhealthy".to_string(),
            message: Some("Connection refused".to_string()),
        };
        let json = serde_json::to_string(&status).unwrap();
        assert!(json.contains("\"message\":\"Connection refused\""));
    }

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
                storage: healthy_check(),
                security_scanner: None,
                meilisearch: None,
            },
            db_pool: None,
        };

        let json = serde_json::to_string(&response).unwrap();
        assert!(json.contains("\"status\":\"unhealthy\""));
        assert!(json.contains("Database connection failed"));
    }

    #[test]
    fn test_livez_response_serialization() {
        let response = LivezResponse {
            status: "ok".to_string(),
        };
        let json = serde_json::to_string(&response).unwrap();
        assert_eq!(json, r#"{"status":"ok"}"#);
    }

    #[test]
    fn test_readyz_response_serialization() {
        let response = ReadyzResponse {
            status: "ready".to_string(),
            checks: ReadyzChecks {
                database: healthy_check(),
                migrations: healthy_check(),
                setup_complete: healthy_check(),
            },
        };
        let json = serde_json::to_string(&response).unwrap();
        assert!(json.contains("\"status\":\"ready\""));
        assert!(json.contains("\"migrations\""));
        assert!(json.contains("\"setup_complete\""));
    }

    #[test]
    fn test_readyz_not_ready() {
        let response = ReadyzResponse {
            status: "not_ready".to_string(),
            checks: ReadyzChecks {
                database: healthy_check(),
                migrations: healthy_check(),
                setup_complete: CheckStatus {
                    status: "unhealthy".to_string(),
                    message: Some("Admin password change required".to_string()),
                },
            },
        };
        let json = serde_json::to_string(&response).unwrap();
        assert!(json.contains("\"not_ready\""));
        assert!(json.contains("Admin password change required"));
    }

    #[test]
    fn test_db_pool_stats_serialization() {
        let stats = sample_pool_stats();
        let json = serde_json::to_string(&stats).unwrap();
        assert!(json.contains("\"max_connections\":20"));
        assert!(json.contains("\"idle_connections\":15"));
        assert!(json.contains("\"active_connections\":5"));
        assert!(json.contains("\"size\":20"));
    }
}
