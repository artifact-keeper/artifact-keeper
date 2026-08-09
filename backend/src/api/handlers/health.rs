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
//!
//! All four are registered at the router root (`api::routes`), outside the
//! `/api/v1` nest, so they are unauthenticated and no `rate_limit_*` layer
//! applies. That is deliberate: orchestrators, load balancers and dashboards
//! poll these constantly, and throttling or authenticating them turns a
//! dependency hiccup into a self-inflicted outage (a 429'd or 401'd liveness
//! probe reads as "dead" to Kubernetes). The cost of an anonymous request is
//! bounded at the work instead — every dependency sub-check on `/health` runs
//! behind a short-TTL, single-flight cache, so an arbitrary request rate
//! collapses to one probe per dependency per window (#3127).

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

/// Apply the detailed-health disclosure gate to the operator-only fields.
///
/// The public `/health` (and `/healthz`) endpoint is unauthenticated
/// (`routes.rs` registers it with no auth layer and the guest-access guard
/// allowlists it), so anything it serializes is readable by any anonymous
/// caller. The exact git commit SHA (`commit`), the prerelease/`dirty` flag,
/// and the live connection-pool internals (`db_pool`) let an attacker
/// fingerprint the precise build and observe pool pressure, so they are only
/// emitted when `detailed` is true (operator opt-in via
/// `EXPOSE_DETAILED_HEALTH`). When `detailed` is false, all three are `None`
/// and skipped by `skip_serializing_if`, leaving a minimal liveness response.
/// See #2226. Pure so the gate is unit-testable without a DB or a live pool.
fn gate_detailed_health_fields(
    detailed: bool,
    pool_stats: DbPoolStats,
    commit: Option<String>,
    dirty: Option<bool>,
) -> (Option<DbPoolStats>, Option<String>, Option<bool>) {
    if detailed {
        (Some(pool_stats), commit, dirty)
    } else {
        (None, None, None)
    }
}

/// Build the HTTP client used to probe operator-configured internal
/// services (Trivy, OpenSCAP).
///
/// Uses the **trusted-internal** client class
/// ([`internal_service_client_builder`]), not the fail-closed upstream
/// class: the probe targets come exclusively from server configuration
/// (`TRIVY_URL` / `OPENSCAP_URL`), never from request input, and in the
/// normal in-cluster / Compose topology they resolve to private-network
/// addresses that the upstream class rejects at DNS time — making
/// `/health` misreport a reachable sidecar as `unavailable` (issue
/// #2478). This matches the trust class already used by the periodic
/// `HealthMonitorService` and the scan clients for the same endpoints.
/// Cloud-metadata, loopback and link-local targets stay hard-blocked.
///
/// [`internal_service_client_builder`]: crate::services::http_client::internal_service_client_builder
fn build_service_probe_client() -> reqwest::Client {
    crate::services::http_client::internal_service_client_builder()
        .timeout(Duration::from_secs(5))
        .build()
        .unwrap_or_default()
}

/// The one probe client, built on first use and reused for the process
/// lifetime.
///
/// Building a `reqwest::Client` is not free: every build runs
/// `apply_custom_ca_cert`, which does a **blocking** `std::fs::read` of
/// `CUSTOM_CA_CERT_PATH` on the async runtime when that variable is set
/// (`services/http_client.rs`), re-parses the PEM bundle, and hands back a
/// client with an empty connection pool — so each probe also pays a fresh TCP
/// (and TLS) handshake. Doing that per `/health` request on an
/// unauthenticated endpoint turns anonymous polling into runtime-blocking
/// filesystem work; one shared client makes it a one-off and lets the probe
/// keep its connection alive between windows (#3127).
static SERVICE_PROBE_CLIENT: Lazy<reqwest::Client> = Lazy::new(build_service_probe_client);

/// Return the shared probe client. `reqwest::Client` is an `Arc` internally,
/// so the clone shares one connection pool rather than creating a new one.
fn service_probe_client() -> reqwest::Client {
    SERVICE_PROBE_CLIENT.clone()
}

/// Probe an external service health endpoint and return a CheckStatus.
async fn check_service_health(
    base_url: &str,
    health_path: &str,
    service_name: &str,
) -> CheckStatus {
    let client = service_probe_client();
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
/// OpenSearch, LDAP), and exposes DB connection pool statistics.
///
/// Every dependency sub-check is served through [`cached_check`], so repeated
/// polling of this unauthenticated endpoint cannot drive one probe per request
/// (#3127). The database check is left uncached deliberately: it is a single
/// `SELECT 1` against an already-established pool connection, which is the
/// cheapest thing on the page and the one signal that most needs to be live.
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

    // Every dependency sub-check below runs behind a short-TTL, single-flight
    // cache (#3127). `/health` is unauthenticated and, by design, not
    // rate-limited, so the ceiling on what an anonymous caller can make this
    // endpoint do has to live in the work itself: one probe per dependency
    // per TTL window, regardless of request rate.
    let scanner_check = match &state.config.trivy_url {
        Some(url) => Some(check_scanner_health(url).await),
        None => None,
    };

    let opensearch_check = match &state.search_service {
        Some(svc) => Some(check_opensearch_health(svc).await),
        None => None,
    };

    let ldap_check = if state.config.ldap_url.is_some() {
        Some(check_ldap_health(&state.db, &state.config).await)
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

    // Info-disclosure hardening (#2226): only surface commit SHA + db-pool
    // internals on the unauthenticated /health when an operator opts in.
    let (db_pool, commit, dirty) = gate_detailed_health_fields(
        state.config.expose_detailed_health,
        pool_stats,
        commit,
        dirty,
    );

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
        db_pool,
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
static STORAGE_HEALTH_CACHE: Lazy<HealthCache> = Lazy::new(|| Mutex::new(None));

/// One cached sub-check result: `(probed_at, status)`.
///
/// Guarded by a `tokio::sync::Mutex` rather than a `std::sync::Mutex` because
/// the guard is held across the probe `.await` (see [`cached_check`]).
type HealthCache = Mutex<Option<(Instant, CheckStatus)>>;

/// TTL for the Trivy / OpenSearch / LDAP sub-checks. Same value and same
/// reasoning as [`STORAGE_HEALTH_TTL`]: short enough that a genuinely-broken
/// dependency is surfaced within seconds, long enough that any realistic
/// polling rate collapses to one probe per dependency per window.
const DEPENDENCY_HEALTH_TTL: Duration = Duration::from_secs(5);

/// Cached result of the security-scanner (Trivy) probe.
static SCANNER_HEALTH_CACHE: Lazy<HealthCache> = Lazy::new(|| Mutex::new(None));

/// Cached result of the OpenSearch cluster-health probe.
static OPENSEARCH_HEALTH_CACHE: Lazy<HealthCache> = Lazy::new(|| Mutex::new(None));

/// Cached result of the LDAP directory-bind probe.
static LDAP_HEALTH_CACHE: Lazy<HealthCache> = Lazy::new(|| Mutex::new(None));

/// Serve a dependency probe through a short-TTL, single-flight cache.
///
/// `/health` and `/healthz` are registered at the router root, outside the
/// `/api/v1` nest, so no `rate_limit_*` layer applies to them — and that is
/// deliberate (orchestrators and dashboards must never be throttled off their
/// own liveness signal). The cost of an anonymous request is therefore capped
/// here, at the work itself, rather than gated at the door: however many
/// requests arrive, each dependency is touched at most once per `ttl`.
///
/// The lock is intentionally held **across** `probe().await`, which makes
/// this single-flight as well as time-bounded. Releasing it first — the
/// obvious shape — leaves the interesting hole wide open: a cold cache plus a
/// simultaneous burst of N requests would let all N through to the real
/// dependency, which is exactly the request-storm shape this is meant to
/// absorb. Under the guard, the first caller probes and the rest wait briefly
/// and then read the entry it just wrote.
///
/// Taking `cache` as a parameter (rather than reaching for a static) keeps
/// the TTL and single-flight behaviour unit-testable against a caller-owned
/// cache, independent of process-wide state.
async fn cached_check<F, Fut>(cache: &HealthCache, ttl: Duration, probe: F) -> CheckStatus
where
    F: FnOnce() -> Fut,
    Fut: std::future::Future<Output = CheckStatus>,
{
    let mut guard = cache.lock().await;
    if let Some((probed_at, ref status)) = *guard {
        if probed_at.elapsed() < ttl {
            return status.clone();
        }
    }

    let status = probe().await;
    *guard = Some((Instant::now(), status.clone()));
    status
}

/// Every process-wide health cache, so test helpers can treat them as a set.
#[cfg(test)]
fn all_health_caches() -> [&'static HealthCache; 4] {
    [
        &STORAGE_HEALTH_CACHE,
        &SCANNER_HEALTH_CACHE,
        &OPENSEARCH_HEALTH_CACHE,
        &LDAP_HEALTH_CACHE,
    ]
}

/// Clear every process-wide health cache.
///
/// These are `Lazy` statics shared by the whole test binary, so a test that
/// exercises caching must be able to start from a known-empty state or it
/// becomes order-dependent.
#[cfg(test)]
async fn reset_health_caches() {
    for cache in all_health_caches() {
        *cache.lock().await = None;
    }
}

/// Backdate every cached entry past its TTL so the next call re-probes.
/// Lets expiry behaviour be exercised deterministically, without sleeping.
#[cfg(test)]
async fn expire_health_caches() {
    let ttl = std::cmp::max(STORAGE_HEALTH_TTL, DEPENDENCY_HEALTH_TTL);
    let stale_at = Instant::now()
        .checked_sub(ttl + Duration::from_secs(1))
        .expect("test clock");
    for cache in all_health_caches() {
        if let Some((ref mut at, _)) = *cache.lock().await {
            *at = stale_at;
        }
    }
}

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
    cached_check(&STORAGE_HEALTH_CACHE, STORAGE_HEALTH_TTL, || {
        probe_storage_health(config, storage)
    })
    .await
}

/// Probe the configured security scanner (Trivy), behind a short-TTL cache.
///
/// The uncached probe builds an HTTP request against the operator-configured
/// `TRIVY_URL`; running it per `/health` request let anonymous polling drive
/// scanner traffic one-for-one (#3127).
async fn check_scanner_health(url: &str) -> CheckStatus {
    cached_check(&SCANNER_HEALTH_CACHE, DEPENDENCY_HEALTH_TTL, || {
        check_service_health(url, "/healthz", "Trivy")
    })
    .await
}

/// Probe the OpenSearch cluster, behind a short-TTL cache.
async fn check_opensearch_health(
    svc: &crate::services::opensearch_service::OpenSearchService,
) -> CheckStatus {
    cached_check(&OPENSEARCH_HEALTH_CACHE, DEPENDENCY_HEALTH_TTL, || {
        probe_opensearch_health(svc)
    })
    .await
}

/// Perform the actual OpenSearch cluster-health query (uncached).
///
/// `yellow` counts as healthy: a single-node cluster reports yellow whenever
/// a replica cannot be allocated, which is the normal steady state for most
/// deployments and is not a service failure.
async fn probe_opensearch_health(
    svc: &crate::services::opensearch_service::OpenSearchService,
) -> CheckStatus {
    match svc.cluster_health().await {
        Ok(status) => match status.as_str() {
            "green" | "yellow" => CheckStatus {
                status: STATUS_HEALTHY.to_string(),
                message: None,
            },
            other => CheckStatus {
                status: STATUS_UNHEALTHY.to_string(),
                message: Some(format!("OpenSearch cluster status: {}", other)),
            },
        },
        Err(e) => CheckStatus {
            status: "unavailable".to_string(),
            message: Some(format!("OpenSearch unreachable: {}", e)),
        },
    }
}

/// Probe the configured LDAP directory, behind a short-TTL cache.
///
/// This is the sharpest leg of the `/health` fan-out (#3127): the uncached
/// probe constructs a fresh `LdapService` (which itself builds an HTTP client)
/// and performs a real service-account bind. Once per request, on an
/// unauthenticated endpoint, that lets an anonymous request storm be amplified
/// into a directory connection storm — capable of exhausting server-side
/// connection limits or interacting badly with the directory's own lockout and
/// throttling counters. Caching turns it into one bind per TTL window no
/// matter the request rate.
async fn check_ldap_health(db: &sqlx::PgPool, config: &crate::config::Config) -> CheckStatus {
    cached_check(&LDAP_HEALTH_CACHE, DEPENDENCY_HEALTH_TTL, || {
        probe_ldap_health(db, config)
    })
    .await
}

/// Perform the actual LDAP service-account bind (uncached).
async fn probe_ldap_health(db: &sqlx::PgPool, config: &crate::config::Config) -> CheckStatus {
    match crate::services::ldap_service::LdapService::new(
        db.clone(),
        std::sync::Arc::new(config.clone()),
    ) {
        Ok(svc) => match svc.check_health().await {
            Ok(()) => CheckStatus {
                status: STATUS_HEALTHY.to_string(),
                message: None,
            },
            Err(e) => {
                tracing::warn!(error = %e, "LDAP health check failed");
                CheckStatus {
                    status: STATUS_UNHEALTHY.to_string(),
                    message: Some("LDAP server unreachable".to_string()),
                }
            }
        },
        Err(e) => {
            tracing::warn!(error = %e, "LDAP configuration error");
            CheckStatus {
                status: STATUS_UNHEALTHY.to_string(),
                message: Some("LDAP configuration error".to_string()),
            }
        }
    }
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

    /// #2478: the internal-service health probe (`TRIVY_URL` /
    /// `OPENSCAP_URL`) must be in the **trusted-internal** client class,
    /// not the fail-closed upstream class. Discriminating check: the
    /// per-hop redirect policy is wired per trust class, and a redirect to
    /// a private RFC1918 target is rejected by the upstream class but
    /// permitted by the trusted-internal class. Serve a `302` to a private
    /// address from a loopback listener (the entry hop uses an IP literal,
    /// which never consults the DNS resolver — mirroring
    /// `http_client.rs::test_webhook_client_refuses_redirect_to_metadata`)
    /// and assert the probe client does NOT fail with the redirect-policy
    /// rejection. With `base_client_builder` (the pre-#2478 code) this
    /// test fails with the "SSRF policy" redirect error.
    #[tokio::test]
    async fn test_service_probe_client_permits_private_redirect_target() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            if let Ok((mut sock, _)) = listener.accept().await {
                let mut buf = [0u8; 1024];
                let _ = sock.read(&mut buf).await;
                let _ = sock
                    .write_all(
                        b"HTTP/1.1 302 Found\r\n\
                          Location: http://10.255.255.9:9/healthz\r\n\
                          Content-Length: 0\r\n\
                          Connection: close\r\n\r\n",
                    )
                    .await;
            }
        });

        let client = service_probe_client();
        let url = format!("http://127.0.0.1:{}/healthz", addr.port());
        let result = client.get(&url).send().await;
        let _ = server.await;

        // Following the redirect means attempting to connect to
        // 10.255.255.9:9, which is expected to fail at the connect layer
        // (nothing routable there). The assertion is only that the
        // redirect POLICY did not reject the private target — that is
        // what distinguishes the trusted-internal class from the
        // fail-closed upstream class.
        if let Err(err) = result {
            assert!(
                !err.is_redirect() && !err.to_string().contains("SSRF"),
                "probe client must not reject a private redirect target \
                 (it must use the trusted-internal class), got: {err}"
            );
        }
    }

    /// #2478 companion: moving the probe to the trusted-internal class
    /// must NOT drop the SSRF guard entirely — a probe target resolving
    /// to loopback (e.g. `TRIVY_URL=http://localhost:...`) is still
    /// refused at DNS time, before any TCP connection. Mirrors the
    /// discriminating listener assertion in `http_client.rs`: an
    /// unguarded client WOULD connect to this listener, so asserting the
    /// listener never accepts a connection proves the resolver blocked
    /// the request.
    #[tokio::test]
    async fn test_service_probe_client_still_refuses_loopback_host() {
        use tokio::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind test listener");
        let port = listener.local_addr().expect("local addr").port();

        let client = service_probe_client();
        let url = format!("http://localhost:{port}/healthz");
        let err = client
            .get(&url)
            .send()
            .await
            .expect_err("probe client must refuse a host resolving to loopback");
        assert!(
            err.is_connect()
                || err.is_request()
                || err.to_string().to_lowercase().contains("ssrf")
                || err.to_string().to_lowercase().contains("block"),
            "expected resolver rejection, got: {err}"
        );

        let accept_result =
            tokio::time::timeout(Duration::from_millis(200), listener.accept()).await;
        assert!(
            accept_result.is_err(),
            "probe client must never connect to a loopback listener: {accept_result:?}"
        );
    }

    /// End-to-end regression guard: `check_service_health` against a live
    /// local endpoint returns `healthy` — the legitimate probe path still
    /// works after the trust-class change.
    #[tokio::test]
    async fn test_check_service_health_reports_healthy_on_200() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = tokio::spawn(async move {
            if let Ok((mut sock, _)) = listener.accept().await {
                let mut buf = [0u8; 1024];
                let _ = sock.read(&mut buf).await;
                let _ = sock
                    .write_all(
                        b"HTTP/1.1 200 OK\r\n\
                          Content-Length: 0\r\n\
                          Connection: close\r\n\r\n",
                    )
                    .await;
            }
        });

        let status =
            check_service_health(&format!("http://127.0.0.1:{port}"), "/healthz", "Trivy").await;
        let _ = server.await;

        assert_eq!(status.status, STATUS_HEALTHY);
        assert!(status.message.is_none());
    }

    #[test]
    fn test_gate_detailed_health_fields_hidden_by_default() {
        // #2226: with detail disabled, commit/dirty/db_pool are all dropped so
        // the anonymous /health body cannot fingerprint the build or pool.
        let (db_pool, commit, dirty) = gate_detailed_health_fields(
            false,
            sample_pool_stats(),
            Some("da0aadeab497b1482181876931ab25933a6506d9".to_string()),
            Some(false),
        );
        assert!(db_pool.is_none());
        assert!(commit.is_none());
        assert!(dirty.is_none());
    }

    #[test]
    fn test_gate_detailed_health_fields_shown_when_enabled() {
        // With the operator opt-in, the detail is preserved verbatim.
        let (db_pool, commit, dirty) = gate_detailed_health_fields(
            true,
            sample_pool_stats(),
            Some("da0aadeab497b1482181876931ab25933a6506d9".to_string()),
            Some(true),
        );
        let pool = db_pool.expect("db_pool should be present when detailed");
        assert_eq!(pool.max_connections, 20);
        assert_eq!(
            commit.as_deref(),
            Some("da0aadeab497b1482181876931ab25933a6506d9")
        );
        assert_eq!(dirty, Some(true));
    }

    #[test]
    fn test_gate_detailed_health_fields_hidden_serializes_minimal() {
        // End-to-end on the response: gated-off fields are omitted from JSON
        // while status/version/checks/demo_mode remain for probes/dashboards.
        let (db_pool, commit, dirty) = gate_detailed_health_fields(
            false,
            sample_pool_stats(),
            Some("abc123".to_string()),
            Some(false),
        );
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
            db_pool,
            commit,
            dirty,
        };
        let json = serde_json::to_string(&response).unwrap();
        assert!(json.contains("\"status\":\"healthy\""));
        assert!(json.contains("\"version\":\"1.0.0\""));
        assert!(json.contains("\"database\""));
        assert!(!json.contains("\"db_pool\""));
        assert!(!json.contains("\"commit\""));
        assert!(!json.contains("\"dirty\""));
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

    // -----------------------------------------------------------------------
    // #3127: the unauthenticated, un-rate-limited `/health` must not fan out
    // one live dependency probe per request.
    //
    // The oracle here is deliberately "how many times did the dependency get
    // touched", not "did we call a cache wrapper": each sub-check is pointed
    // at a counting stub server (an HTTP listener for Trivy and OpenSearch, a
    // raw TCP listener for the LDAP directory) and the real `health_check`
    // handler is driven N times. A test that only asserted on the cache
    // internals would still pass if the handler stopped consulting them.
    // -----------------------------------------------------------------------

    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering as AtomicOrdering};

    /// Serializes every test that touches the process-wide health caches.
    ///
    /// Those caches are `Lazy` statics shared by the entire test binary, so
    /// two tests seeding them concurrently would observe each other's
    /// entries and become order-dependent. Every cache-touching test takes
    /// this lock and starts from a cleared cache, which makes them
    /// deterministic in any order and under `--test-threads` > 1.
    static HEALTH_CACHE_TEST_LOCK: Lazy<Mutex<()>> = Lazy::new(|| Mutex::new(()));

    /// Index of the end of the first complete HTTP request head in `buf`.
    fn request_head_end(buf: &[u8]) -> Option<usize> {
        buf.windows(4).position(|w| w == b"\r\n\r\n").map(|p| p + 4)
    }

    /// A keep-alive-capable HTTP stub on loopback that counts accepted TCP
    /// connections and complete HTTP requests.
    struct CountingHttpStub {
        port: u16,
        conns: Arc<AtomicUsize>,
        reqs: Arc<AtomicUsize>,
        fail: Arc<AtomicBool>,
    }

    impl CountingHttpStub {
        fn conns(&self) -> usize {
            self.conns.load(AtomicOrdering::SeqCst)
        }
        fn reqs(&self) -> usize {
            self.reqs.load(AtomicOrdering::SeqCst)
        }
        /// Flip the stub to answering `500` so the dependency it stands in
        /// for looks genuinely broken.
        fn break_it(&self) {
            self.fail.store(true, AtomicOrdering::SeqCst);
        }
    }

    /// Spawn a [`CountingHttpStub`] that answers `200` with `body` until
    /// [`CountingHttpStub::break_it`] is called, then `500`.
    ///
    /// The connection is kept alive between requests, which is what makes
    /// the accepted-connection counter a usable oracle for "was one client
    /// (and therefore one connection pool) reused, or was a fresh
    /// `reqwest::Client` built per call".
    async fn spawn_counting_http_stub(body: &'static str) -> CountingHttpStub {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind stub");
        let port = listener.local_addr().expect("stub addr").port();
        let conns = Arc::new(AtomicUsize::new(0));
        let reqs = Arc::new(AtomicUsize::new(0));
        let fail = Arc::new(AtomicBool::new(false));

        let (conns_t, reqs_t, fail_t) = (conns.clone(), reqs.clone(), fail.clone());
        tokio::spawn(async move {
            while let Ok((mut sock, _)) = listener.accept().await {
                conns_t.fetch_add(1, AtomicOrdering::SeqCst);
                let (reqs_c, fail_c) = (reqs_t.clone(), fail_t.clone());
                tokio::spawn(async move {
                    let mut acc: Vec<u8> = Vec::new();
                    let mut buf = [0u8; 4096];
                    loop {
                        match sock.read(&mut buf).await {
                            Ok(0) | Err(_) => break,
                            Ok(n) => acc.extend_from_slice(&buf[..n]),
                        }
                        while let Some(end) = request_head_end(&acc) {
                            acc.drain(..end);
                            reqs_c.fetch_add(1, AtomicOrdering::SeqCst);
                            let (code, reason) = if fail_c.load(AtomicOrdering::SeqCst) {
                                (500, "Internal Server Error")
                            } else {
                                (200, "OK")
                            };
                            let resp = format!(
                                "HTTP/1.1 {code} {reason}\r\n\
                                 Content-Type: application/json\r\n\
                                 Content-Length: {}\r\n\r\n{}",
                                body.len(),
                                body
                            );
                            if sock.write_all(resp.as_bytes()).await.is_err() {
                                return;
                            }
                        }
                    }
                });
            }
        });

        CountingHttpStub {
            port,
            conns,
            reqs,
            fail,
        }
    }

    /// A raw TCP stub standing in for the LDAP directory. Counts accepted
    /// connections — i.e. directory binds attempted — then drops the socket
    /// so the bind fails fast instead of hanging until the 5s timeout.
    struct CountingTcpStub {
        port: u16,
        conns: Arc<AtomicUsize>,
    }

    impl CountingTcpStub {
        fn conns(&self) -> usize {
            self.conns.load(AtomicOrdering::SeqCst)
        }
    }

    async fn spawn_counting_tcp_stub() -> CountingTcpStub {
        use tokio::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind stub");
        let port = listener.local_addr().expect("stub addr").port();
        let conns = Arc::new(AtomicUsize::new(0));

        let conns_t = conns.clone();
        tokio::spawn(async move {
            while let Ok((sock, _)) = listener.accept().await {
                conns_t.fetch_add(1, AtomicOrdering::SeqCst);
                drop(sock);
            }
        });

        CountingTcpStub { port, conns }
    }

    /// `LdapConfig` reads the service-account credentials from the process
    /// environment, and `check_health` only performs a real directory bind
    /// when both are present — which is precisely the leg #3127 calls the
    /// sharpest. Set them for the duration of a test and restore them after.
    /// Always constructed while [`HEALTH_CACHE_TEST_LOCK`] is held.
    struct LdapBindEnvGuard {
        prev_dn: Option<String>,
        prev_pw: Option<String>,
    }

    impl LdapBindEnvGuard {
        fn set() -> Self {
            let prev_dn = std::env::var("LDAP_BIND_DN").ok();
            let prev_pw = std::env::var("LDAP_BIND_PASSWORD").ok();
            std::env::set_var("LDAP_BIND_DN", "cn=probe,dc=example,dc=com");
            std::env::set_var("LDAP_BIND_PASSWORD", "probe-secret");
            Self { prev_dn, prev_pw }
        }
    }

    impl Drop for LdapBindEnvGuard {
        fn drop(&mut self) {
            match &self.prev_dn {
                Some(v) => std::env::set_var("LDAP_BIND_DN", v),
                None => std::env::remove_var("LDAP_BIND_DN"),
            }
            match &self.prev_pw {
                Some(v) => std::env::set_var("LDAP_BIND_PASSWORD", v),
                None => std::env::remove_var("LDAP_BIND_PASSWORD"),
            }
        }
    }

    /// Build a real `SharedState` whose Trivy, OpenSearch and LDAP legs all
    /// point at the given loopback stub ports.
    fn fanout_state(
        pool: sqlx::PgPool,
        dir: &std::path::Path,
        trivy_port: u16,
        opensearch_port: u16,
        ldap_port: u16,
    ) -> crate::api::SharedState {
        let config = crate::config::Config {
            storage_backend: "filesystem".to_string(),
            storage_path: dir.to_string_lossy().into_owned(),
            trivy_url: Some(format!("http://127.0.0.1:{trivy_port}")),
            ldap_url: Some(format!("ldap://127.0.0.1:{ldap_port}")),
            ldap_base_dn: Some("dc=example,dc=com".to_string()),
            ..crate::config::Config::test_config()
        };
        let storage: Arc<dyn crate::storage::StorageBackend> = Arc::new(
            crate::storage::filesystem::FilesystemStorage::new(config.storage_path.clone()),
        );
        let registry = Arc::new(crate::storage::StorageRegistry::new(
            std::collections::HashMap::new(),
            "filesystem".to_string(),
        ));
        let mut state = crate::api::AppState::new(config, pool, storage, registry);
        state.search_service = Some(Arc::new(
            crate::services::opensearch_service::OpenSearchService::new(
                &format!("http://127.0.0.1:{opensearch_port}"),
                None,
                None,
                false,
            )
            .expect("build opensearch stub client"),
        ));
        Arc::new(state)
    }

    /// Drive `health_check` once and return the HTTP status it produced.
    async fn call_health(state: &crate::api::SharedState) -> StatusCode {
        use axum::response::IntoResponse as _;
        health_check(axum::extract::State(state.clone()))
            .await
            .into_response()
            .status()
    }

    /// Drive `health_check` once and return `(status, parsed body)`.
    ///
    /// streaming-invariant: test scaffolding exempt — the health response is
    /// a small bounded JSON document, not an artifact path (#1608). The limit
    /// is explicit so a runaway body still fails rather than OOMs.
    #[allow(clippy::disallowed_methods)]
    async fn call_health_json(state: &crate::api::SharedState) -> (StatusCode, serde_json::Value) {
        use axum::response::IntoResponse as _;
        let resp = health_check(axum::extract::State(state.clone()))
            .await
            .into_response();
        let status = resp.status();
        let bytes = axum::body::to_bytes(resp.into_body(), 64 * 1024)
            .await
            .expect("read health body");
        (status, serde_json::from_slice(&bytes).expect("health json"))
    }

    /// #3127 core guard: repeated `/health` polling must touch each
    /// dependency ONCE per TTL window, not once per request.
    ///
    /// Ten sequential calls against the stubs. Pre-fix (an uncached probe per
    /// sub-check) this records 10 Trivy requests, 10 OpenSearch requests and
    /// 10 LDAP binds; with the TTL cache in place each counter is 1.
    #[tokio::test]
    async fn test_health_check_collapses_dependency_fanout_across_requests() {
        let Some(pool) = crate::api::handlers::test_db_helpers::try_pool().await else {
            return;
        };
        let _lock = HEALTH_CACHE_TEST_LOCK.lock().await;
        reset_health_caches().await;
        let _env = LdapBindEnvGuard::set();

        let trivy = spawn_counting_http_stub("{}").await;
        let opensearch = spawn_counting_http_stub("{\"status\":\"green\"}").await;
        let ldap = spawn_counting_tcp_stub().await;

        let dir = tempfile::tempdir().unwrap();
        let state = fanout_state(pool, dir.path(), trivy.port, opensearch.port, ldap.port);

        const POLLS: usize = 10;
        for _ in 0..POLLS {
            let _ = call_health(&state).await;
        }

        println!(
            "[#3127] {POLLS} sequential /health requests -> \
             trivy_probes={} opensearch_probes={} ldap_binds={}",
            trivy.reqs(),
            opensearch.reqs(),
            ldap.conns()
        );

        assert_eq!(
            trivy.reqs(),
            1,
            "{POLLS} /health requests must produce exactly 1 Trivy probe, got {}",
            trivy.reqs()
        );
        assert_eq!(
            opensearch.reqs(),
            1,
            "{POLLS} /health requests must produce exactly 1 OpenSearch \
             cluster-health query, got {}",
            opensearch.reqs()
        );
        assert_eq!(
            ldap.conns(),
            1,
            "{POLLS} /health requests must produce exactly 1 LDAP bind, got {}",
            ldap.conns()
        );

        reset_health_caches().await;
    }

    /// A concurrent burst — the shape an actual request storm takes — must
    /// also collapse to one probe per dependency. A cache that releases its
    /// lock before probing would let every request in a cold-cache burst
    /// through, so this pins the single-flight property specifically.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn test_health_check_collapses_dependency_fanout_under_concurrent_burst() {
        let Some(pool) = crate::api::handlers::test_db_helpers::try_pool().await else {
            return;
        };
        let _lock = HEALTH_CACHE_TEST_LOCK.lock().await;
        reset_health_caches().await;
        let _env = LdapBindEnvGuard::set();

        let trivy = spawn_counting_http_stub("{}").await;
        let opensearch = spawn_counting_http_stub("{\"status\":\"green\"}").await;
        let ldap = spawn_counting_tcp_stub().await;

        let dir = tempfile::tempdir().unwrap();
        let state = fanout_state(pool, dir.path(), trivy.port, opensearch.port, ldap.port);

        const BURST: usize = 25;
        let mut tasks = Vec::with_capacity(BURST);
        for _ in 0..BURST {
            let state = state.clone();
            tasks.push(tokio::spawn(async move { call_health(&state).await }));
        }
        for t in tasks {
            let _ = t.await.expect("health task");
        }

        println!(
            "[#3127] {BURST} CONCURRENT /health requests -> \
             trivy_probes={} opensearch_probes={} ldap_binds={}",
            trivy.reqs(),
            opensearch.reqs(),
            ldap.conns()
        );

        assert_eq!(
            trivy.reqs(),
            1,
            "a concurrent burst must still produce 1 Trivy probe, got {}",
            trivy.reqs()
        );
        assert_eq!(
            opensearch.reqs(),
            1,
            "a concurrent burst must still produce 1 OpenSearch query, got {}",
            opensearch.reqs()
        );
        assert_eq!(
            ldap.conns(),
            1,
            "a concurrent burst must still produce 1 LDAP bind, got {}",
            ldap.conns()
        );

        reset_health_caches().await;
    }

    /// The probe client must be built once and reused, not rebuilt per call
    /// (each rebuild re-reads `CUSTOM_CA_CERT_PATH` with a blocking
    /// `std::fs::read` on the async runtime and throws away the connection
    /// pool).
    ///
    /// Oracle: connection reuse. `check_service_health` is the *uncached*
    /// inner probe, so five sequential calls always make five HTTP requests;
    /// what changes is how many TCP connections they need. A fresh
    /// `reqwest::Client` per call means a fresh pool per call, so five
    /// connections. One shared client keeps the connection alive and needs
    /// exactly one.
    #[tokio::test]
    async fn test_service_probe_client_is_reused_across_probes() {
        let stub = spawn_counting_http_stub("{}").await;
        let base = format!("http://127.0.0.1:{}", stub.port);

        const PROBES: usize = 5;
        for _ in 0..PROBES {
            let status = check_service_health(&base, "/healthz", "Trivy").await;
            assert_eq!(status.status, STATUS_HEALTHY);
        }

        println!(
            "[#3127] {PROBES} uncached Trivy probes -> \
             http_requests={} tcp_connections={}",
            stub.reqs(),
            stub.conns()
        );

        assert_eq!(stub.reqs(), PROBES, "each probe must issue one request");
        assert_eq!(
            stub.conns(),
            1,
            "the probe client must be built once and reused: {PROBES} probes \
             opened {} TCP connections, meaning a new client (and a new \
             connection pool, and a re-read of the CA bundle) per call",
            stub.conns()
        );
    }

    /// Positive control (i): caching must not make `/health` claim health it
    /// does not have. With the OpenSearch dependency answering 500, `/health`
    /// reports 503 and names the broken legs in the body.
    #[tokio::test]
    async fn test_health_check_reports_unhealthy_when_dependency_is_down() {
        let Some(pool) = crate::api::handlers::test_db_helpers::try_pool().await else {
            return;
        };
        let _lock = HEALTH_CACHE_TEST_LOCK.lock().await;
        reset_health_caches().await;
        let _env = LdapBindEnvGuard::set();

        let trivy = spawn_counting_http_stub("{}").await;
        let opensearch = spawn_counting_http_stub("{\"status\":\"green\"}").await;
        let ldap = spawn_counting_tcp_stub().await;
        trivy.break_it();
        opensearch.break_it();

        let dir = tempfile::tempdir().unwrap();
        let state = fanout_state(pool, dir.path(), trivy.port, opensearch.port, ldap.port);

        let (status, body) = call_health_json(&state).await;
        println!("[#3127] dependency down -> status={status} body={body}");

        assert_eq!(
            status,
            StatusCode::SERVICE_UNAVAILABLE,
            "a genuinely broken dependency must still produce a 503"
        );
        assert_eq!(body["status"], STATUS_UNHEALTHY);
        assert_ne!(
            body["checks"]["opensearch"]["status"], STATUS_HEALTHY,
            "a 500 from OpenSearch must not be reported as healthy"
        );
        assert_ne!(
            body["checks"]["security_scanner"]["status"], STATUS_HEALTHY,
            "a 500 from Trivy must not be reported as healthy"
        );
        assert_eq!(
            body["checks"]["ldap"]["status"], STATUS_UNHEALTHY,
            "a directory that resets the connection must be reported unhealthy"
        );

        reset_health_caches().await;
    }

    /// Positive control (ii): the cache must not pin a stale `healthy`
    /// forever. A dependency that goes bad is served from cache inside the
    /// TTL window and surfaced as soon as the window expires.
    #[tokio::test]
    async fn test_health_check_surfaces_dependency_failure_after_ttl_expiry() {
        let Some(pool) = crate::api::handlers::test_db_helpers::try_pool().await else {
            return;
        };
        let _lock = HEALTH_CACHE_TEST_LOCK.lock().await;
        reset_health_caches().await;
        let _env = LdapBindEnvGuard::set();

        let trivy = spawn_counting_http_stub("{}").await;
        let opensearch = spawn_counting_http_stub("{\"status\":\"green\"}").await;
        let ldap = spawn_counting_tcp_stub().await;

        let dir = tempfile::tempdir().unwrap();
        let state = fanout_state(pool, dir.path(), trivy.port, opensearch.port, ldap.port);

        let (status, body) = call_health_json(&state).await;
        assert_eq!(status, StatusCode::OK, "healthy deps must produce a 200");
        assert_eq!(body["checks"]["opensearch"]["status"], STATUS_HEALTHY);

        // Dependency breaks. Inside the TTL window the cached result stands.
        opensearch.break_it();
        let (cached_status, cached_body) = call_health_json(&state).await;
        println!(
            "[#3127] dependency broke, within TTL -> status={cached_status} \
             opensearch={} (opensearch_probes={})",
            cached_body["checks"]["opensearch"]["status"],
            opensearch.reqs()
        );
        assert_eq!(
            cached_status,
            StatusCode::OK,
            "inside the TTL window the cached result is served"
        );
        assert_eq!(opensearch.reqs(), 1, "no re-probe inside the TTL window");

        // Expire every cached entry; the next poll must re-probe and report
        // the real, now-broken state.
        expire_health_caches().await;
        let (expired_status, expired_body) = call_health_json(&state).await;
        println!(
            "[#3127] after TTL expiry -> status={expired_status} \
             opensearch={} (opensearch_probes={})",
            expired_body["checks"]["opensearch"]["status"],
            opensearch.reqs()
        );

        assert_eq!(
            expired_status,
            StatusCode::SERVICE_UNAVAILABLE,
            "an expired cache entry must re-probe and surface the failure"
        );
        assert_ne!(
            expired_body["checks"]["opensearch"]["status"], STATUS_HEALTHY,
            "the broken dependency must be reported once the TTL lapses"
        );
        assert_eq!(
            opensearch.reqs(),
            2,
            "exactly one re-probe after expiry, got {} total",
            opensearch.reqs()
        );

        reset_health_caches().await;
    }

    /// `cached_check` itself, driven against a caller-owned cache so the
    /// TTL and single-flight properties are pinned without touching any
    /// process-wide static: fresh entries are served without probing,
    /// expired ones re-probe, and a concurrent burst on a cold cache
    /// produces exactly one probe.
    #[tokio::test]
    async fn test_cached_check_ttl_and_single_flight() {
        let cache: HealthCache = Mutex::new(None);
        let probes = Arc::new(AtomicUsize::new(0));
        let ttl = Duration::from_secs(60);

        let probe = || {
            let probes = probes.clone();
            async move {
                probes.fetch_add(1, AtomicOrdering::SeqCst);
                // Yield so a burst genuinely interleaves rather than
                // completing inside one poll.
                tokio::task::yield_now().await;
                CheckStatus {
                    status: STATUS_HEALTHY.to_string(),
                    message: None,
                }
            }
        };

        // Cold cache -> one probe. Warm cache -> none.
        assert_eq!(
            cached_check(&cache, ttl, probe).await.status,
            STATUS_HEALTHY
        );
        assert_eq!(probes.load(AtomicOrdering::SeqCst), 1);
        for _ in 0..10 {
            let _ = cached_check(&cache, ttl, probe).await;
        }
        assert_eq!(
            probes.load(AtomicOrdering::SeqCst),
            1,
            "a fresh entry must be served without re-probing"
        );

        // A fresh entry is served verbatim, proving it came from the cache
        // and not from a re-run of the (healthy) probe.
        {
            let mut guard = cache.lock().await;
            *guard = Some((
                Instant::now(),
                CheckStatus {
                    status: STATUS_UNHEALTHY.to_string(),
                    message: Some("cached sentinel".to_string()),
                },
            ));
        }
        let served = cached_check(&cache, ttl, probe).await;
        assert_eq!(served.message.as_deref(), Some("cached sentinel"));
        assert_eq!(probes.load(AtomicOrdering::SeqCst), 1);

        // Backdate past the TTL -> exactly one refresh.
        {
            let mut guard = cache.lock().await;
            if let Some((ref mut at, _)) = *guard {
                *at = Instant::now()
                    .checked_sub(ttl + Duration::from_secs(1))
                    .expect("test clock");
            }
        }
        assert_eq!(
            cached_check(&cache, ttl, probe).await.status,
            STATUS_HEALTHY
        );
        assert_eq!(
            probes.load(AtomicOrdering::SeqCst),
            2,
            "an expired entry must trigger exactly one re-probe"
        );

        // Single flight: a burst against a cold cache probes once.
        let cache = Arc::new(Mutex::new(None));
        let probes = Arc::new(AtomicUsize::new(0));
        let mut tasks = Vec::new();
        for _ in 0..25 {
            let (cache, probes) = (cache.clone(), probes.clone());
            tasks.push(tokio::spawn(async move {
                cached_check(&cache, ttl, || {
                    let probes = probes.clone();
                    async move {
                        probes.fetch_add(1, AtomicOrdering::SeqCst);
                        tokio::task::yield_now().await;
                        CheckStatus {
                            status: STATUS_HEALTHY.to_string(),
                            message: None,
                        }
                    }
                })
                .await
            }));
        }
        for t in tasks {
            assert_eq!(t.await.expect("burst task").status, STATUS_HEALTHY);
        }
        assert_eq!(
            probes.load(AtomicOrdering::SeqCst),
            1,
            "a cold-cache burst must produce exactly one probe, got {}",
            probes.load(AtomicOrdering::SeqCst)
        );
    }

    /// `/livez` must stay genuinely dependency-free: it is the probe
    /// Kubernetes uses to decide whether to restart the pod, so it must never
    /// touch Trivy, OpenSearch, the directory, storage or the database. The
    /// handler takes no `State` at all, and this pins the observable
    /// consequence.
    #[tokio::test]
    async fn test_liveness_check_touches_no_dependencies() {
        use axum::response::IntoResponse as _;

        let trivy = spawn_counting_http_stub("{}").await;
        let opensearch = spawn_counting_http_stub("{\"status\":\"green\"}").await;
        let ldap = spawn_counting_tcp_stub().await;

        for _ in 0..5 {
            let resp = liveness_check().await.into_response();
            assert_eq!(resp.status(), StatusCode::OK);
        }

        println!(
            "[#3127] 5 /livez requests -> trivy_probes={} opensearch_probes={} \
             ldap_binds={}",
            trivy.reqs(),
            opensearch.reqs(),
            ldap.conns()
        );

        assert_eq!(trivy.reqs(), 0, "/livez must not probe the scanner");
        assert_eq!(opensearch.reqs(), 0, "/livez must not probe OpenSearch");
        assert_eq!(ldap.conns(), 0, "/livez must not bind to the directory");
    }
}
