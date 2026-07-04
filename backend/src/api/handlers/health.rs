//! Health check endpoints.
//!
//! Provides Kubernetes-style probes:
//! - `/livez`   - lightweight liveness (process alive, no external deps)
//! - `/readyz`  - readiness gate (DB + migrations reachable). Initial-setup
//!   state (admin password change required) is reported as an informational
//!   field but does NOT cause a 503. A 503 here would make Kubernetes restart
//!   the pod and prevent operators from completing setup via `kubectl exec`.
//! - `/health`  - rich status page for dashboards (all services + pool stats)
//! - `/healthz` - alias for `/health`

use axum::{extract::State, http::StatusCode, response::IntoResponse, Json};
use once_cell::sync::Lazy;
use serde::Serialize;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;
use utoipa::{OpenApi, ToSchema};

use crate::api::SharedState;
use crate::storage::StorageBackend;

/// Canonical status string for a healthy db / migrations / storage check.
/// Held as a module-private constant so the readiness gate (`is_ready`) and
/// the call sites that build `CheckStatus` agree on one spelling. If a future
/// cleanup ever renames this vocabulary, both ends move together rather than
/// drifting silently and making the gate return false for everything.
const STATUS_HEALTHY: &str = "healthy";

/// Canonical status string for an unhealthy db / migrations / storage check.
const STATUS_UNHEALTHY: &str = "unhealthy";

/// Status string for a setup_complete check that has finished (admin
/// password was changed). Distinct from STATUS_HEALTHY because setup is
/// informational, not a readiness gate (see #889) - the vocabulary
/// difference signals that to readers and to anything diffing the JSON.
const SETUP_COMPLETE: &str = "complete";

/// Status string for a setup_complete check that has NOT yet finished.
const SETUP_INCOMPLETE: &str = "incomplete";

#[derive(Serialize, ToSchema)]
pub struct HealthResponse {
    pub status: String,
    pub version: String,
    pub demo_mode: bool,
    pub checks: HealthChecks,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub db_pool: Option<DbPoolStats>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub commit: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dirty: Option<bool>,
}

#[derive(Serialize, ToSchema)]
pub struct HealthChecks {
    pub database: CheckStatus,
    pub storage: CheckStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub security_scanner: Option<CheckStatus>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub opensearch: Option<CheckStatus>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ldap: Option<CheckStatus>,
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
    let client = crate::services::http_client::base_client_builder()
        .timeout(Duration::from_secs(5))
        .build()
        .unwrap_or_default();
    let url = format!("{}{}", base_url.trim_end_matches('/'), health_path);
    match client.get(&url).send().await {
        Ok(resp) if resp.status().is_success() => CheckStatus {
            status: STATUS_HEALTHY.to_string(),
            message: None,
        },
        Ok(resp) => CheckStatus {
            status: STATUS_UNHEALTHY.to_string(),
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

/// Health check endpoint -- rich status page for dashboards.
///
/// Checks database, storage (real write/read probe), optional services (Trivy,
/// OpenSearch), and exposes DB connection pool statistics.
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
            status: STATUS_HEALTHY.to_string(),
            message: None,
        },
        Err(e) => CheckStatus {
            status: STATUS_UNHEALTHY.to_string(),
            message: Some(format!("Database connection failed: {}", e)),
        },
    };

    let storage_check = check_storage_health(&state.config, &state.storage).await;

    let scanner_check = match &state.config.trivy_url {
        Some(url) => Some(check_service_health(url, "/healthz", "Trivy").await),
        None => None,
    };

    let opensearch_check = match &state.search_service {
        Some(ref svc) => match svc.cluster_health().await {
            Ok(status) => match status.as_str() {
                "green" | "yellow" => Some(CheckStatus {
                    status: STATUS_HEALTHY.to_string(),
                    message: None,
                }),
                other => Some(CheckStatus {
                    status: STATUS_UNHEALTHY.to_string(),
                    message: Some(format!("OpenSearch cluster status: {}", other)),
                }),
            },
            Err(e) => Some(CheckStatus {
                status: "unavailable".to_string(),
                message: Some(format!("OpenSearch unreachable: {}", e)),
            }),
        },
        None => None,
    };

    let ldap_check = if state.config.ldap_url.is_some() {
        match crate::services::ldap_service::LdapService::new(
            state.db.clone(),
            std::sync::Arc::new(state.config.clone()),
        ) {
            Ok(svc) => match svc.check_health().await {
                Ok(()) => Some(CheckStatus {
                    status: STATUS_HEALTHY.to_string(),
                    message: None,
                }),
                Err(e) => {
                    tracing::warn!(error = %e, "LDAP health check failed");
                    Some(CheckStatus {
                        status: STATUS_UNHEALTHY.to_string(),
                        message: Some("LDAP server unreachable".to_string()),
                    })
                }
            },
            Err(e) => {
                tracing::warn!(error = %e, "LDAP configuration error");
                Some(CheckStatus {
                    status: STATUS_UNHEALTHY.to_string(),
                    message: Some("LDAP configuration error".to_string()),
                })
            }
        }
    } else {
        None
    };

    let storage_healthy = storage_check.status == STATUS_HEALTHY;
    let opensearch_healthy = opensearch_check
        .as_ref()
        .map_or(true, |c| c.status == STATUS_HEALTHY);

    let overall_status =
        if db_check.status == STATUS_HEALTHY && storage_healthy && opensearch_healthy {
            STATUS_HEALTHY
        } else {
            STATUS_UNHEALTHY
        };

    let pool_stats = DbPoolStats {
        max_connections: state.db.options().get_max_connections(),
        idle_connections: state.db.num_idle() as u32,
        active_connections: state.db.size().saturating_sub(state.db.num_idle() as u32),
        size: state.db.size(),
    };

    let git_sha = env!("GIT_SHA");
    let is_prerelease = env!("CARGO_PKG_VERSION").contains('-');
    let (commit, dirty) = if git_sha != "unknown" {
        (Some(git_sha.to_string()), Some(is_prerelease))
    } else {
        (None, None)
    };

    let response = HealthResponse {
        status: overall_status.to_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
        demo_mode: state.config.demo_mode,
        checks: HealthChecks {
            database: db_check,
            storage: storage_check,
            security_scanner: scanner_check,
            opensearch: opensearch_check,
            ldap: ldap_check,
        },
        db_pool: Some(pool_stats),
        commit,
        dirty,
    };

    let status_code = if overall_status == STATUS_HEALTHY {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };

    (status_code, Json(response))
}

/// Readiness probe - is the service ready to accept traffic?
///
/// Returns 200 once the database is reachable and migrations have applied
/// successfully. Initial-setup state (whether the default admin password has
/// been changed) is reported as an informational field on the response but
/// does NOT influence the status code: a 503 here would make Kubernetes
/// restart the pod, terminating any `kubectl exec` session an operator is
/// using to complete setup. See issue #889.
///
/// API mutations are separately gated by the setup middleware
/// (`api::middleware::setup`) until setup is complete, so a 200 from this
/// endpoint does not imply that write traffic will be accepted.
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
            status: STATUS_HEALTHY.to_string(),
            message: None,
        },
        Err(e) => CheckStatus {
            status: STATUS_UNHEALTHY.to_string(),
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
            status: STATUS_HEALTHY.to_string(),
            message: None,
        },
        Ok(false) => CheckStatus {
            status: STATUS_UNHEALTHY.to_string(),
            message: Some("No successful migrations found".to_string()),
        },
        Err(e) => CheckStatus {
            status: STATUS_UNHEALTHY.to_string(),
            message: Some(format!("Migration check failed: {}", e)),
        },
    };

    let setup_required = state
        .setup_required
        .load(std::sync::atomic::Ordering::Relaxed);
    let (status_code, response) = build_readyz_response(db_check, migrations_check, setup_required);

    if setup_required {
        tracing::debug!("/readyz: setup incomplete (informational, not blocking readiness)");
    }

    (status_code, Json(response))
}

/// Pure response-builder for the readiness probe.
///
/// Splits "what the response says" from "how we discovered it" so the
/// readiness logic is unit-testable without spinning up a `SharedState` or
/// a database pool. The handler is now a thin DB-binding wrapper around
/// this function. Any future regression in the readiness gate (#889) can
/// be caught by exercising this function directly with the three input
/// values, since it is the same logic the handler runs.
///
/// Setup state is informational only. It surfaces "admin password not yet
/// changed" so dashboards and operators can see the condition, but it is
/// intentionally excluded from the readiness gate (see #889 - restarting
/// the pod here makes setup impossible via `kubectl exec`).
fn build_readyz_response(
    db_check: CheckStatus,
    migrations_check: CheckStatus,
    setup_required: bool,
) -> (StatusCode, ReadyzResponse) {
    let setup_check = if setup_required {
        CheckStatus {
            status: SETUP_INCOMPLETE.to_string(),
            message: Some("Admin password change required".to_string()),
        }
    } else {
        CheckStatus {
            status: SETUP_COMPLETE.to_string(),
            message: None,
        }
    };

    let ready = is_ready(&db_check, &migrations_check);

    let response = ReadyzResponse {
        status: if ready {
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

    let status_code = if ready {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };

    (status_code, response)
}

/// Compute whether the service should be reported as ready.
///
/// Only the database and migrations checks gate readiness. Setup state is
/// informational and intentionally excluded - see the docstring on
/// [`readiness_check`] and issue #889.
///
/// Uses the [`STATUS_HEALTHY`] constant rather than a string literal so that
/// the gate cannot silently start returning `false` if the vocabulary used
/// by upstream check builders is ever changed without updating this site.
fn is_ready(db_check: &CheckStatus, migrations_check: &CheckStatus) -> bool {
    db_check.status == STATUS_HEALTHY && migrations_check.status == STATUS_HEALTHY
}

/// Liveness probe - confirms the process is alive and can serve HTTP.
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

/// How long a storage-health result is reused before the disk/network probe
/// is performed again. `/health` and `/healthz` are polled frequently (k8s
/// probes plus dashboards); re-running the probe on every request causes
/// needless disk churn for the filesystem backend and needless network
/// round-trips for object stores. A short TTL keeps a genuinely-broken
/// backend detected within a few seconds while collapsing bursts of polling
/// into a single probe.
const STORAGE_HEALTH_TTL: Duration = Duration::from_secs(5);

/// Process-wide cache of the most recent storage-health probe result.
///
/// Stored as `(probed_at, status)`. Guarded by a `tokio::sync::Mutex` so the
/// short critical section never blocks the async runtime. The first poll after
/// a TTL expiry refreshes it; concurrent pollers that arrive while a fresh
/// entry exists return the cached value without touching the disk.
static STORAGE_HEALTH_CACHE: Lazy<Mutex<Option<(Instant, CheckStatus)>>> =
    Lazy::new(|| Mutex::new(None));

impl Clone for CheckStatus {
    fn clone(&self) -> Self {
        CheckStatus {
            status: self.status.clone(),
            message: self.message.clone(),
        }
    }
}

/// Verify storage backend connectivity, behind a short-TTL cache.
///
/// The actual probe lives in [`probe_storage_health`]; this wrapper collapses
/// frequent `/health` polling into one probe per [`STORAGE_HEALTH_TTL`] window
/// so the endpoint does not hammer the disk (filesystem) or the remote API
/// (object stores) on every request. A genuinely-broken backend is still
/// surfaced within the TTL once the cached entry expires.
async fn check_storage_health(
    config: &crate::config::Config,
    storage: &Arc<dyn StorageBackend>,
) -> CheckStatus {
    {
        let cache = STORAGE_HEALTH_CACHE.lock().await;
        if let Some((probed_at, ref status)) = *cache {
            if probed_at.elapsed() < STORAGE_HEALTH_TTL {
                return status.clone();
            }
        }
    }

    let status = probe_storage_health(config, storage).await;

    {
        let mut cache = STORAGE_HEALTH_CACHE.lock().await;
        *cache = Some((Instant::now(), status.clone()));
    }

    status
}

/// Perform the actual storage backend connectivity probe (uncached).
///
/// Filesystem: write a probe file to a UNIQUE per-call path and best-effort
/// remove it. A successful write proves every writability failure mode a
/// liveness probe cares about (read-only / full / unmounted volume, missing
/// permissions); those all surface as a write error. The path is unique per
/// call (`.health-probe-{uuid}`) so concurrent probes never share a file -
/// previously a fixed `.health-probe` path let one request's cleanup delete
/// the file another request was reading (spurious ENOENT) or let interleaved
/// writes corrupt the read-back (spurious mismatch), each yielding a bogus
/// 503 under concurrency.
///
/// S3, GCS, Azure: perform a real API call via the storage backend's
/// `health_check()` method, with a 5-second timeout.
async fn probe_storage_health(
    config: &crate::config::Config,
    storage: &Arc<dyn StorageBackend>,
) -> CheckStatus {
    match config.storage_backend.as_str() {
        "filesystem" => {
            // storage_path is from server config, not user input, but we
            // canonicalize and verify the probe stays under the base dir.
            let storage_base = match std::path::Path::new(&config.storage_path).canonicalize() {
                Ok(p) => p,
                Err(e) => {
                    return CheckStatus {
                        status: STATUS_UNHEALTHY.to_string(),
                        message: Some(format!("Storage path not accessible: {}", e)),
                    };
                }
            };
            // Unique per-call probe filename so concurrent /health requests
            // never share a file (which previously caused spurious 503s).
            let probe_path = storage_base.join(format!(".health-probe-{}", uuid::Uuid::new_v4()));
            if !probe_path.starts_with(&storage_base) {
                return CheckStatus {
                    status: STATUS_UNHEALTHY.to_string(),
                    message: Some("Storage probe path escaped base directory".to_string()),
                };
            }
            // A write-only probe proves the writability failure modes that
            // matter (RO/full/unmounted/perms). Read-back is intentionally
            // dropped: it added nothing a liveness probe needs and was the
            // source of the cross-request data dependency.
            match tokio::fs::write(&probe_path, b"ok").await {
                Ok(()) => {
                    let _ = tokio::fs::remove_file(&probe_path).await;
                    CheckStatus {
                        status: STATUS_HEALTHY.to_string(),
                        message: None,
                    }
                }
                Err(e) => CheckStatus {
                    status: STATUS_UNHEALTHY.to_string(),
                    message: Some(format!("Storage write failed: {}", e)),
                },
            }
        }
        "s3" | "gcs" | "azure" => {
            // Perform a real connectivity probe with a 5-second timeout so a
            // slow or hung backend does not block the health endpoint.
            let probe = storage.health_check();
            match tokio::time::timeout(Duration::from_secs(5), probe).await {
                Ok(Ok(())) => CheckStatus {
                    status: STATUS_HEALTHY.to_string(),
                    message: None,
                },
                Ok(Err(e)) => CheckStatus {
                    status: STATUS_UNHEALTHY.to_string(),
                    message: Some(format!(
                        "{} storage probe failed: {}",
                        config.storage_backend, e
                    )),
                },
                Err(_) => CheckStatus {
                    status: STATUS_UNHEALTHY.to_string(),
                    message: Some(format!(
                        "{} storage probe timed out (5s)",
                        config.storage_backend
                    )),
                },
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

// ---------------------------------------------------------------------------
// Jemalloc heap profiling (only available with `--features profiling`)
// ---------------------------------------------------------------------------

/// Dump a jemalloc heap profile.
///
/// Requires the binary to be started with `_RJEM_MALLOC_CONF=prof:true` (or
/// the equivalent `MALLOC_CONF`). Returns a pprof-compatible heap profile
/// that can be analyzed with `jeprof` / `pprof`.
///
/// Query parameters:
/// - `activate` - if `"true"`, activate profiling at runtime (prof.active).
/// - `deactivate` - if `"true"`, deactivate profiling (prof.active = false).
/// - `dump` (default) - dump current profile to a temp file and return it.
#[cfg(feature = "profiling")]
pub async fn heap_profile(
    axum::extract::Query(params): axum::extract::Query<std::collections::HashMap<String, String>>,
) -> impl IntoResponse {
    use tikv_jemalloc_ctl::raw;

    // Activate profiling at runtime.
    if params.get("activate").map(|v| v == "true").unwrap_or(false) {
        let name = b"prof.active\0";
        let activated: bool = true;
        if let Err(e) = unsafe { raw::write(name, activated) } {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                [(axum::http::header::CONTENT_TYPE, "text/plain")],
                format!("Failed to activate profiling: {e}"),
            )
                .into_response();
        }
        return (StatusCode::OK, "profiling activated\n").into_response();
    }

    // Deactivate profiling.
    if params
        .get("deactivate")
        .map(|v| v == "true")
        .unwrap_or(false)
    {
        let name = b"prof.active\0";
        let deactivated: bool = false;
        if let Err(e) = unsafe { raw::write(name, deactivated) } {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                [(axum::http::header::CONTENT_TYPE, "text/plain")],
                format!("Failed to deactivate profiling: {e}"),
            )
                .into_response();
        }
        return (StatusCode::OK, "profiling deactivated\n").into_response();
    }

    // Dump heap profile.
    let path = format!("/tmp/ak_heap_{}.prof", std::process::id());
    let c_path = match std::ffi::CString::new(path.clone()) {
        Ok(p) => p,
        Err(e) => {
            return (StatusCode::INTERNAL_SERVER_ERROR, format!("bad path: {e}")).into_response()
        }
    };

    let name = b"prof.dump\0";
    if let Err(e) = unsafe { raw::write(name, c_path.as_ptr() as *const std::ffi::c_char) } {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            [(axum::http::header::CONTENT_TYPE, "text/plain")],
            format!("Failed to dump profile: {e}\n\nHint: start with _RJEM_MALLOC_CONF=prof:true"),
        )
            .into_response();
    }

    match tokio::fs::read(&path).await {
        Ok(data) => {
            let _ = tokio::fs::remove_file(&path).await;
            (
                StatusCode::OK,
                [
                    (axum::http::header::CONTENT_TYPE, "application/octet-stream"),
                    (
                        axum::http::header::CONTENT_DISPOSITION,
                        "attachment; filename=\"heap.prof\"",
                    ),
                ],
                data,
            )
                .into_response()
        }
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Failed to read profile: {e}"),
        )
            .into_response(),
    }
}

/// Memory statistics from jemalloc (available with `--features profiling`).
///
/// Returns a JSON object with allocated, active, resident, mapped, and
/// retained bytes.
#[cfg(feature = "profiling")]
pub async fn memory_stats() -> impl IntoResponse {
    use tikv_jemalloc_ctl::{epoch, stats};

    // Advance the jemalloc epoch to get fresh stats.
    let _ = epoch::advance();

    let allocated = stats::allocated::read().unwrap_or(0);
    let active = stats::active::read().unwrap_or(0);
    let resident = stats::resident::read().unwrap_or(0);
    let mapped = stats::mapped::read().unwrap_or(0);
    let retained = stats::retained::read().unwrap_or(0);

    axum::Json(serde_json::json!({
        "allocator": "jemalloc",
        "allocated_bytes": allocated,
        "active_bytes": active,
        "resident_bytes": resident,
        "mapped_bytes": mapped,
        "retained_bytes": retained,
    }))
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

    // The test helpers below intentionally use TWO distinct status-string
    // vocabularies, matching what the production code emits:
    //
    //   * `healthy` / `unhealthy` for db / migrations / storage checks
    //     (anything that gates readiness or overall health)
    //   * `complete` / `incomplete` for setup_complete (informational only,
    //     intentionally NOT a readiness driver - see #889)
    //
    // The two vocabularies coexist on purpose. If you write a new test that
    // mixes them up (e.g. uses `unhealthy_check` for the setup_complete
    // field), the test passes for the wrong reason. The readyz tests below
    // drive `build_readyz_response` with `setup_required: bool` directly
    // rather than constructing a setup CheckStatus by hand, which avoids
    // the issue inside this module; the comment is here to warn anyone
    // adding new tests that bypass `build_readyz_response`.

    fn healthy_check() -> CheckStatus {
        CheckStatus {
            status: STATUS_HEALTHY.to_string(),
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
            status: STATUS_HEALTHY.to_string(),
            version: "1.0.0".to_string(),
            demo_mode: false,
            checks: HealthChecks {
                database: healthy_check(),
                storage: CheckStatus {
                    status: STATUS_HEALTHY.to_string(),
                    message: Some("Connected".to_string()),
                },
                security_scanner: None,
                opensearch: None,
                ldap: None,
            },
            db_pool: Some(sample_pool_stats()),
            commit: None,
            dirty: None,
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
        // commit/dirty are None, should be skipped
        assert!(!json.contains("\"commit\""));
        assert!(!json.contains("\"dirty\""));
    }

    #[test]
    fn test_health_response_without_pool_stats() {
        let response = HealthResponse {
            status: STATUS_HEALTHY.to_string(),
            version: "1.0.0".to_string(),
            demo_mode: false,
            checks: HealthChecks {
                database: healthy_check(),
                storage: healthy_check(),
                security_scanner: None,
                opensearch: None,
                ldap: None,
            },
            db_pool: None,
            commit: None,
            dirty: None,
        };

        let json = serde_json::to_string(&response).unwrap();
        assert!(!json.contains("\"db_pool\""));
    }

    #[test]
    fn test_health_response_with_scanner() {
        let response = HealthResponse {
            status: STATUS_HEALTHY.to_string(),
            version: "1.0.0".to_string(),
            demo_mode: false,
            checks: HealthChecks {
                database: healthy_check(),
                storage: healthy_check(),
                security_scanner: Some(healthy_check()),
                opensearch: None,
                ldap: None,
            },
            db_pool: None,
            commit: None,
            dirty: None,
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
            status: STATUS_UNHEALTHY.to_string(),
            message: Some("Connection refused".to_string()),
        };
        let json = serde_json::to_string(&status).unwrap();
        assert!(json.contains("\"message\":\"Connection refused\""));
    }

    #[test]
    fn test_unhealthy_response_serialization() {
        let response = HealthResponse {
            status: STATUS_UNHEALTHY.to_string(),
            version: "1.0.0".to_string(),
            demo_mode: false,
            checks: HealthChecks {
                database: CheckStatus {
                    status: STATUS_UNHEALTHY.to_string(),
                    message: Some("Database connection failed: timeout".to_string()),
                },
                storage: healthy_check(),
                security_scanner: None,
                opensearch: None,
                ldap: None,
            },
            db_pool: None,
            commit: None,
            dirty: None,
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

    fn unhealthy_check(message: &str) -> CheckStatus {
        CheckStatus {
            status: STATUS_UNHEALTHY.to_string(),
            message: Some(message.to_string()),
        }
    }

    fn setup_complete_check() -> CheckStatus {
        CheckStatus {
            status: SETUP_COMPLETE.to_string(),
            message: None,
        }
    }

    #[test]
    fn test_readyz_response_serialization() {
        let response = ReadyzResponse {
            status: "ready".to_string(),
            checks: ReadyzChecks {
                database: healthy_check(),
                migrations: healthy_check(),
                setup_complete: setup_complete_check(),
            },
        };
        let json = serde_json::to_string(&response).unwrap();
        assert!(json.contains("\"status\":\"ready\""));
        assert!(json.contains("\"migrations\""));
        assert!(json.contains("\"setup_complete\""));
        assert!(json.contains("\"complete\""));
    }

    #[test]
    fn test_readyz_not_ready() {
        // Migrations failing should drive the response to not_ready / 503.
        let response = ReadyzResponse {
            status: "not_ready".to_string(),
            checks: ReadyzChecks {
                database: healthy_check(),
                migrations: unhealthy_check("No successful migrations found"),
                setup_complete: setup_complete_check(),
            },
        };
        let json = serde_json::to_string(&response).unwrap();
        assert!(json.contains("\"not_ready\""));
        assert!(json.contains("No successful migrations found"));
    }

    /// Regression for #889: when only `setup_required` is true, the readiness
    /// decision must remain "ready" so Kubernetes does not restart the pod
    /// and kick the operator out of `kubectl exec` while they change the
    /// default admin password.
    ///
    /// Drives `build_readyz_response` directly - the same pure function the
    /// handler runs after performing its DB queries - so a future regression
    /// that re-adds setup_complete to the all-healthy gate will fail this
    /// test, not just a copy of the response shape.
    #[test]
    fn test_build_readyz_response_ready_when_only_setup_incomplete() {
        let (status_code, response) = build_readyz_response(
            healthy_check(),
            healthy_check(),
            true, // setup_required
        );

        // The actual handler decision: 200 OK, status="ready".
        assert_eq!(
            status_code,
            StatusCode::OK,
            "setup_required must NOT drive 503 (#889)"
        );
        assert_eq!(response.status, "ready");

        // The informational setup field still surfaces the condition.
        assert_eq!(response.checks.setup_complete.status, SETUP_INCOMPLETE);
        assert_eq!(
            response.checks.setup_complete.message.as_deref(),
            Some("Admin password change required"),
        );
    }

    /// Symmetric: when setup is complete and everything is healthy, the
    /// handler returns 200 with status="ready" and `setup_complete=complete`.
    #[test]
    fn test_build_readyz_response_ready_when_all_complete() {
        let (status_code, response) = build_readyz_response(
            healthy_check(),
            healthy_check(),
            false, // setup_required
        );

        assert_eq!(status_code, StatusCode::OK);
        assert_eq!(response.status, "ready");
        assert_eq!(response.checks.setup_complete.status, SETUP_COMPLETE);
        assert!(response.checks.setup_complete.message.is_none());
    }

    /// An unhealthy database must always drive a not-ready response,
    /// regardless of whether setup is complete or incomplete. Exercises
    /// the same `build_readyz_response` the handler runs.
    #[test]
    fn test_build_readyz_response_not_ready_when_db_unhealthy_regardless_of_setup() {
        for setup_required in [false, true] {
            let (status_code, response) = build_readyz_response(
                unhealthy_check("Database unreachable: timeout"),
                healthy_check(),
                setup_required,
            );
            assert_eq!(
                status_code,
                StatusCode::SERVICE_UNAVAILABLE,
                "unhealthy db must drive 503 (setup_required={})",
                setup_required,
            );
            assert_eq!(response.status, "not_ready");
            assert_eq!(response.checks.database.status, STATUS_UNHEALTHY);
        }
    }

    /// Migrations failures also drive 503, regardless of setup state.
    #[test]
    fn test_build_readyz_response_not_ready_when_migrations_unhealthy() {
        for setup_required in [false, true] {
            let (status_code, response) = build_readyz_response(
                healthy_check(),
                unhealthy_check("No successful migrations found"),
                setup_required,
            );
            assert_eq!(status_code, StatusCode::SERVICE_UNAVAILABLE);
            assert_eq!(response.status, "not_ready");
            assert_eq!(response.checks.migrations.status, STATUS_UNHEALTHY);
        }
    }

    #[test]
    fn test_is_ready_truth_table() {
        let healthy = healthy_check();
        let bad = unhealthy_check("nope");

        assert!(is_ready(&healthy, &healthy));
        assert!(!is_ready(&bad, &healthy));
        assert!(!is_ready(&healthy, &bad));
        assert!(!is_ready(&bad, &bad));
    }

    use async_trait::async_trait;
    use bytes::Bytes;

    /// Mock storage backend that reports healthy.
    struct HealthyMockBackend;

    #[async_trait]
    impl crate::storage::StorageBackend for HealthyMockBackend {
        async fn put(&self, _key: &str, _content: Bytes) -> crate::error::Result<()> {
            Ok(())
        }
        async fn get(&self, _key: &str) -> crate::error::Result<Bytes> {
            Ok(Bytes::new())
        }
        async fn exists(&self, _key: &str) -> crate::error::Result<bool> {
            Ok(false)
        }
        async fn delete(&self, _key: &str) -> crate::error::Result<()> {
            Ok(())
        }
        async fn health_check(&self) -> crate::error::Result<()> {
            Ok(())
        }
        async fn put_stream(
            &self,
            key: &str,
            stream: futures::stream::BoxStream<'static, crate::error::Result<bytes::Bytes>>,
        ) -> crate::error::Result<crate::storage::PutStreamResult> {
            crate::storage::buffered_put_stream_fallback(self, key, stream).await
        }
    }

    /// Mock storage backend that reports unhealthy.
    struct UnhealthyMockBackend;

    #[async_trait]
    impl crate::storage::StorageBackend for UnhealthyMockBackend {
        async fn put(&self, _key: &str, _content: Bytes) -> crate::error::Result<()> {
            Ok(())
        }
        async fn get(&self, _key: &str) -> crate::error::Result<Bytes> {
            Ok(Bytes::new())
        }
        async fn exists(&self, _key: &str) -> crate::error::Result<bool> {
            Ok(false)
        }
        async fn delete(&self, _key: &str) -> crate::error::Result<()> {
            Ok(())
        }
        async fn health_check(&self) -> crate::error::Result<()> {
            Err(crate::error::AppError::Storage(
                "connection refused".to_string(),
            ))
        }
        async fn put_stream(
            &self,
            key: &str,
            stream: futures::stream::BoxStream<'static, crate::error::Result<bytes::Bytes>>,
        ) -> crate::error::Result<crate::storage::PutStreamResult> {
            crate::storage::buffered_put_stream_fallback(self, key, stream).await
        }
    }

    fn test_config(backend: &str) -> crate::config::Config {
        crate::config::Config {
            storage_backend: backend.to_string(),
            gcs_bucket: Some("my-bucket".to_string()),
            ..crate::config::Config::test_config()
        }
    }

    #[tokio::test]
    async fn test_check_storage_health_gcs_healthy() {
        let config = test_config("gcs");
        let storage: Arc<dyn crate::storage::StorageBackend> = Arc::new(HealthyMockBackend);
        let status = probe_storage_health(&config, &storage).await;
        assert_eq!(status.status, "healthy");
    }

    #[tokio::test]
    async fn test_check_storage_health_gcs_unhealthy() {
        let config = test_config("gcs");
        let storage: Arc<dyn crate::storage::StorageBackend> = Arc::new(UnhealthyMockBackend);
        let status = probe_storage_health(&config, &storage).await;
        assert_eq!(status.status, "unhealthy");
        assert!(status.message.unwrap().contains("connection refused"));
    }

    #[tokio::test]
    async fn test_check_storage_health_s3_healthy() {
        let config = test_config("s3");
        let storage: Arc<dyn crate::storage::StorageBackend> = Arc::new(HealthyMockBackend);
        let status = probe_storage_health(&config, &storage).await;
        assert_eq!(status.status, "healthy");
    }

    #[tokio::test]
    async fn test_check_storage_health_s3_unhealthy() {
        let config = test_config("s3");
        let storage: Arc<dyn crate::storage::StorageBackend> = Arc::new(UnhealthyMockBackend);
        let status = probe_storage_health(&config, &storage).await;
        assert_eq!(status.status, "unhealthy");
        assert!(status.message.unwrap().contains("connection refused"));
    }

    #[tokio::test]
    async fn test_check_storage_health_azure_healthy() {
        let config = test_config("azure");
        let storage: Arc<dyn crate::storage::StorageBackend> = Arc::new(HealthyMockBackend);
        let status = probe_storage_health(&config, &storage).await;
        assert_eq!(status.status, "healthy");
    }

    #[tokio::test]
    async fn test_check_storage_health_unknown_backend() {
        let config = test_config("ftp");
        let storage: Arc<dyn crate::storage::StorageBackend> = Arc::new(HealthyMockBackend);
        let status = probe_storage_health(&config, &storage).await;
        assert_eq!(status.status, "unknown");
        assert!(status.message.unwrap().contains("Unknown backend: ftp"));
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

    #[test]
    fn test_health_response_with_commit_and_dirty() {
        let response = HealthResponse {
            status: STATUS_HEALTHY.to_string(),
            version: "1.1.0-rc.5".to_string(),
            demo_mode: false,
            checks: HealthChecks {
                database: healthy_check(),
                storage: healthy_check(),
                security_scanner: None,
                opensearch: None,
                ldap: None,
            },
            db_pool: None,
            commit: Some("abc1234def5678".to_string()),
            dirty: Some(true),
        };

        let json = serde_json::to_string(&response).unwrap();
        assert!(json.contains("\"commit\":\"abc1234def5678\""));
        assert!(json.contains("\"dirty\":true"));
    }

    #[test]
    fn test_health_response_commit_omitted_when_none() {
        let response = HealthResponse {
            status: STATUS_HEALTHY.to_string(),
            version: "1.1.0".to_string(),
            demo_mode: false,
            checks: HealthChecks {
                database: healthy_check(),
                storage: healthy_check(),
                security_scanner: None,
                opensearch: None,
                ldap: None,
            },
            db_pool: None,
            commit: None,
            dirty: None,
        };

        let json = serde_json::to_string(&response).unwrap();
        assert!(!json.contains("\"commit\""));
        assert!(!json.contains("\"dirty\""));
    }

    // -----------------------------------------------------------------------
    // Filesystem storage-probe tests (issue #2019).
    //
    // These exercise `probe_storage_health` (the uncached inner probe) so they
    // are deterministic regardless of execution order; the process-wide TTL
    // cache is covered separately in `test_check_storage_health_ttl_cache`.
    // -----------------------------------------------------------------------

    fn fs_config(dir: &std::path::Path) -> crate::config::Config {
        crate::config::Config {
            storage_backend: "filesystem".to_string(),
            storage_path: dir.to_string_lossy().into_owned(),
            ..crate::config::Config::test_config()
        }
    }

    /// A healthy filesystem backend reports healthy, and the probe leaves no
    /// `.health-probe*` files behind (best-effort cleanup ran).
    #[tokio::test]
    async fn test_probe_storage_health_filesystem_healthy_no_leftover_files() {
        let dir = tempfile::tempdir().unwrap();
        let config = fs_config(dir.path());
        let storage: Arc<dyn crate::storage::StorageBackend> = Arc::new(HealthyMockBackend);

        let status = probe_storage_health(&config, &storage).await;
        assert_eq!(status.status, STATUS_HEALTHY);
        assert!(status.message.is_none());

        let leftovers: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_name().to_string_lossy().starts_with(".health-probe"))
            .collect();
        assert!(
            leftovers.is_empty(),
            "probe left files behind: {:?}",
            leftovers.iter().map(|e| e.file_name()).collect::<Vec<_>>()
        );
    }

    /// An unwritable filesystem backend reports unhealthy. The probe directory
    /// is made read-only so the write fails (the failure mode k8s cares about:
    /// RO mount / missing permissions).
    #[cfg(unix)]
    #[tokio::test]
    async fn test_probe_storage_health_filesystem_unwritable() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let config = fs_config(dir.path());
        let storage: Arc<dyn crate::storage::StorageBackend> = Arc::new(HealthyMockBackend);

        // Drop write permission on the storage dir so the probe write fails.
        let mut perms = std::fs::metadata(dir.path()).unwrap().permissions();
        perms.set_mode(0o500);
        std::fs::set_permissions(dir.path(), perms).unwrap();

        let status = probe_storage_health(&config, &storage).await;

        // Restore permissions so the tempdir can be cleaned up.
        let mut restore = std::fs::metadata(dir.path()).unwrap().permissions();
        restore.set_mode(0o700);
        std::fs::set_permissions(dir.path(), restore).unwrap();

        assert_eq!(status.status, STATUS_UNHEALTHY);
        assert!(
            status
                .message
                .as_deref()
                .unwrap_or_default()
                .contains("Storage write failed"),
            "unexpected message: {:?}",
            status.message
        );
    }

    /// Regression guard for #2019: 40 concurrent filesystem probes against the
    /// same storage dir must ALL report healthy. On the old fixed-path code
    /// (`.health-probe` shared across calls with write -> read-back -> delete)
    /// this races - one call's `remove_file` deletes the file another call is
    /// reading (spurious ENOENT) or interleaved writes corrupt the read-back -
    /// producing spurious "unhealthy" results. The unique-per-call path removes
    /// the shared file, so every probe is independent.
    #[tokio::test]
    async fn test_probe_storage_health_filesystem_concurrent_all_healthy() {
        let dir = tempfile::tempdir().unwrap();
        let config = Arc::new(fs_config(dir.path()));

        let mut handles = Vec::new();
        for _ in 0..40 {
            let config = Arc::clone(&config);
            handles.push(tokio::spawn(async move {
                let storage: Arc<dyn crate::storage::StorageBackend> = Arc::new(HealthyMockBackend);
                probe_storage_health(&config, &storage).await
            }));
        }

        let mut unhealthy = Vec::new();
        for h in handles {
            let status = h.await.unwrap();
            if status.status != STATUS_HEALTHY {
                unhealthy.push(status.message);
            }
        }
        assert!(
            unhealthy.is_empty(),
            "{} of 40 concurrent probes were not healthy: {:?}",
            unhealthy.len(),
            unhealthy
        );

        // No probe files should remain after the burst.
        let leftovers: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_name().to_string_lossy().starts_with(".health-probe"))
            .collect();
        assert!(
            leftovers.is_empty(),
            "{} probe files left behind after concurrent burst",
            leftovers.len()
        );
    }

    /// The process-wide TTL cache returns a previously-cached result without
    /// re-probing, then refreshes after the entry expires. We seed the cache
    /// with a known value via `check_storage_health`, then mutate the cache's
    /// timestamp to simulate expiry and confirm a fresh probe runs.
    ///
    /// This test is `#[serial]`-free by construction: it owns the cache for the
    /// duration by clearing it first; other tests use `probe_storage_health`
    /// (uncached) so they cannot race this one through the shared cache.
    #[tokio::test]
    async fn test_check_storage_health_ttl_cache() {
        let dir = tempfile::tempdir().unwrap();
        let config = fs_config(dir.path());
        let storage: Arc<dyn crate::storage::StorageBackend> = Arc::new(HealthyMockBackend);

        // Start from a clean cache so we control its contents.
        *STORAGE_HEALTH_CACHE.lock().await = None;

        // First call populates the cache.
        let first = check_storage_health(&config, &storage).await;
        assert_eq!(first.status, STATUS_HEALTHY);
        {
            let cache = STORAGE_HEALTH_CACHE.lock().await;
            assert!(
                cache.is_some(),
                "first call should have populated the cache"
            );
        }

        // Overwrite the cache with a fresh-but-unhealthy sentinel; the next
        // call must return it WITHOUT re-probing (the probe would say healthy).
        {
            let mut cache = STORAGE_HEALTH_CACHE.lock().await;
            *cache = Some((
                Instant::now(),
                CheckStatus {
                    status: STATUS_UNHEALTHY.to_string(),
                    message: Some("cached sentinel".to_string()),
                },
            ));
        }
        let cached = check_storage_health(&config, &storage).await;
        assert_eq!(
            cached.status, STATUS_UNHEALTHY,
            "fresh cache entry must be served without re-probing"
        );
        assert_eq!(cached.message.as_deref(), Some("cached sentinel"));

        // Expire the cached entry by backdating its timestamp; the next call
        // must re-probe and return the real (healthy) status.
        {
            let mut cache = STORAGE_HEALTH_CACHE.lock().await;
            let stale_at = Instant::now()
                .checked_sub(STORAGE_HEALTH_TTL + Duration::from_secs(1))
                .expect("test clock");
            if let Some((ref mut at, _)) = *cache {
                *at = stale_at;
            }
        }
        let refreshed = check_storage_health(&config, &storage).await;
        assert_eq!(
            refreshed.status, STATUS_HEALTHY,
            "expired cache entry must trigger a fresh probe"
        );

        // Leave the cache clean for any other consumer.
        *STORAGE_HEALTH_CACHE.lock().await = None;
    }
}
