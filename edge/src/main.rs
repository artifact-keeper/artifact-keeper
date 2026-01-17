//! Artifact Keeper Edge Node - Distributed caching node.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Instant;

use axum::extract::{Path, State};
use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::Router;
use tokio::sync::RwLock;
use tower_http::trace::TraceLayer;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

mod cache;
mod sync;

/// Edge node application state with offline mode tracking.
pub struct EdgeState {
    pub primary_url: String,
    pub api_key: String,
    pub cache: Arc<cache::ArtifactCache>,
    /// Tracks whether the edge node is currently offline (cannot reach primary).
    pub is_offline: AtomicBool,
    /// Timestamp of last successful contact with the primary server.
    pub last_primary_contact: RwLock<Option<Instant>>,
}

impl Clone for EdgeState {
    fn clone(&self) -> Self {
        Self {
            primary_url: self.primary_url.clone(),
            api_key: self.api_key.clone(),
            cache: self.cache.clone(),
            is_offline: AtomicBool::new(self.is_offline.load(Ordering::SeqCst)),
            last_primary_contact: RwLock::new(None), // Clone starts fresh
        }
    }
}

/// Application error type for the edge node.
#[derive(Debug)]
pub enum AppError {
    /// The requested artifact was not found.
    NotFound(String),
    /// The primary server is unreachable and artifact is not in cache.
    ServiceUnavailable(String),
    /// Internal server error.
    Internal(String),
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        match self {
            AppError::NotFound(msg) => {
                (StatusCode::NOT_FOUND, msg).into_response()
            }
            AppError::ServiceUnavailable(msg) => {
                let body = serde_json::json!({
                    "error": "service_unavailable",
                    "message": msg,
                    "retry_after": 30
                });
                (
                    StatusCode::SERVICE_UNAVAILABLE,
                    [(header::RETRY_AFTER, "30")],
                    axum::Json(body),
                )
                    .into_response()
            }
            AppError::Internal(msg) => {
                (StatusCode::INTERNAL_SERVER_ERROR, msg).into_response()
            }
        }
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Load environment variables
    dotenvy::dotenv().ok();

    // Initialize tracing
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "artifact_keeper_edge=debug".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    let primary_url =
        std::env::var("PRIMARY_URL").expect("PRIMARY_URL must be set");
    let api_key = std::env::var("EDGE_API_KEY").expect("EDGE_API_KEY must be set");
    let bind_address =
        std::env::var("BIND_ADDRESS").unwrap_or_else(|_| "0.0.0.0:8080".to_string());
    let cache_size: usize = std::env::var("CACHE_SIZE_MB")
        .unwrap_or_else(|_| "1024".to_string())
        .parse()
        .unwrap_or(1024);

    tracing::info!("Starting Artifact Keeper Edge Node");
    tracing::info!("Primary registry: {}", primary_url);

    // Create cache
    let cache = Arc::new(cache::ArtifactCache::new(cache_size));

    // Create state with offline mode tracking
    let state = Arc::new(EdgeState {
        primary_url,
        api_key,
        cache,
        is_offline: AtomicBool::new(false),
        last_primary_contact: RwLock::new(None),
    });

    // Start heartbeat task
    let heartbeat_state = state.clone();
    tokio::spawn(async move {
        sync::heartbeat_loop(heartbeat_state).await;
    });

    // Start connectivity check task (to transition back to online mode)
    let connectivity_state = state.clone();
    tokio::spawn(async move {
        connectivity_check_loop(connectivity_state).await;
    });

    // Build router with artifact proxy and health routes
    let app = Router::new()
        .route("/health", get(health_check))
        .route(
            "/api/v1/repositories/:repo_key/artifacts/*path",
            get(serve_artifact),
        )
        .layer(TraceLayer::new_for_http())
        .with_state(state);

    // Start server
    let addr: SocketAddr = bind_address.parse()?;
    tracing::info!("Listening on {}", addr);

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}

/// Check if an error indicates a connectivity problem.
fn is_connectivity_error(err: &anyhow::Error) -> bool {
    // Check for reqwest errors that indicate network issues
    if let Some(reqwest_err) = err.downcast_ref::<reqwest::Error>() {
        return reqwest_err.is_connect()
            || reqwest_err.is_timeout()
            || reqwest_err.is_request();
    }
    // Check error message for common connectivity indicators
    let msg = err.to_string().to_lowercase();
    msg.contains("connection refused")
        || msg.contains("network unreachable")
        || msg.contains("host unreachable")
        || msg.contains("timed out")
        || msg.contains("dns")
}

/// Mark the edge node as back online after successful primary contact.
async fn mark_online(state: &EdgeState) {
    if state.is_offline.swap(false, Ordering::SeqCst) {
        tracing::info!("Edge node transitioning from offline to online mode");
    }
    let mut last_contact = state.last_primary_contact.write().await;
    *last_contact = Some(Instant::now());
}

/// Mark the edge node as offline due to connectivity issues.
fn mark_offline(state: &EdgeState) {
    if !state.is_offline.swap(true, Ordering::SeqCst) {
        tracing::warn!("Edge node transitioning to offline mode - primary unreachable");
    }
}

/// Serve an artifact from cache or fetch from primary.
///
/// This handler implements offline mode:
/// 1. First checks the local cache
/// 2. If online, tries to fetch from primary (caching on success)
/// 3. If primary is unreachable, transitions to offline mode
/// 4. In offline mode, returns 503 if artifact not in cache
async fn serve_artifact(
    State(state): State<Arc<EdgeState>>,
    Path((repo_key, artifact_path)): Path<(String, String)>,
) -> Result<Response, AppError> {
    let cache_key = format!("{}:{}", repo_key, artifact_path);
    tracing::debug!(
        repo_key = %repo_key,
        artifact_path = %artifact_path,
        cache_key = %cache_key,
        "Serving artifact request"
    );

    // First, try to serve from cache
    if let Some(cached_content) = state.cache.get(&cache_key) {
        tracing::debug!(cache_key = %cache_key, "Cache hit - serving from local cache");
        return Ok((
            StatusCode::OK,
            [(header::CONTENT_TYPE, "application/octet-stream")],
            cached_content,
        )
            .into_response());
    }

    // Not in cache - check if we're online
    if state.is_offline.load(Ordering::SeqCst) {
        tracing::debug!(
            cache_key = %cache_key,
            "Cache miss in offline mode - returning 503"
        );
        return Err(AppError::ServiceUnavailable(
            "Primary server unreachable, artifact not in cache".to_string(),
        ));
    }

    // Try to fetch from primary
    tracing::debug!(cache_key = %cache_key, "Cache miss - fetching from primary");
    let client = reqwest::Client::new();

    match sync::fetch_from_primary(&client, &state, &repo_key, &artifact_path).await {
        Ok(artifact_bytes) => {
            // Success! Mark as online and cache the artifact
            mark_online(&state).await;

            // Store in cache
            state.cache.put(cache_key.clone(), artifact_bytes.clone());
            tracing::debug!(
                cache_key = %cache_key,
                size = artifact_bytes.len(),
                "Fetched and cached artifact from primary"
            );

            Ok((
                StatusCode::OK,
                [(header::CONTENT_TYPE, "application/octet-stream")],
                artifact_bytes,
            )
                .into_response())
        }
        Err(e) if is_connectivity_error(&e) => {
            // Connectivity error - transition to offline mode
            mark_offline(&state);
            tracing::warn!(
                cache_key = %cache_key,
                error = %e,
                "Failed to fetch artifact due to connectivity error - now offline"
            );
            Err(AppError::ServiceUnavailable(
                "Primary server unreachable, artifact not in cache".to_string(),
            ))
        }
        Err(e) => {
            // Non-connectivity error (e.g., 404 from primary)
            tracing::warn!(
                cache_key = %cache_key,
                error = %e,
                "Failed to fetch artifact from primary"
            );

            // Check if it's a 404
            if let Some(reqwest_err) = e.downcast_ref::<reqwest::Error>() {
                if reqwest_err.status() == Some(reqwest::StatusCode::NOT_FOUND) {
                    return Err(AppError::NotFound(format!(
                        "Artifact not found: {}/{}",
                        repo_key, artifact_path
                    )));
                }
            }

            Err(AppError::Internal(format!("Failed to fetch artifact: {}", e)))
        }
    }
}

/// Health check endpoint that reports offline status.
async fn health_check(State(state): State<Arc<EdgeState>>) -> impl IntoResponse {
    let is_offline = state.is_offline.load(Ordering::SeqCst);
    let cache_size = state.cache.size();
    let cache_entries = state.cache.len();

    let last_contact = state.last_primary_contact.read().await;
    let seconds_since_contact = last_contact
        .map(|t| t.elapsed().as_secs())
        .unwrap_or(u64::MAX);

    let status = if is_offline {
        "offline"
    } else {
        "online"
    };

    let body = serde_json::json!({
        "status": status,
        "is_offline": is_offline,
        "cache_size_bytes": cache_size,
        "cache_entries": cache_entries,
        "seconds_since_primary_contact": if seconds_since_contact == u64::MAX {
            None
        } else {
            Some(seconds_since_contact)
        },
    });

    // Return 200 even when offline - the edge is still serving from cache
    // Use a header or body field to indicate degraded mode
    let status_code = StatusCode::OK;

    (status_code, axum::Json(body))
}

/// Periodically check connectivity to the primary server.
///
/// This loop runs every 30 seconds and attempts to contact the primary
/// if the edge node is currently in offline mode. On success, it
/// transitions back to online mode.
async fn connectivity_check_loop(state: Arc<EdgeState>) {
    use std::time::Duration;

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .unwrap();

    let check_interval = Duration::from_secs(30);

    loop {
        tokio::time::sleep(check_interval).await;

        // Only check if we're currently offline
        if !state.is_offline.load(Ordering::SeqCst) {
            continue;
        }

        tracing::debug!("Checking connectivity to primary server");

        // Try a simple health check to the primary
        let health_url = format!("{}/health", state.primary_url);

        match client.get(&health_url).send().await {
            Ok(response) if response.status().is_success() => {
                tracing::info!("Primary server is reachable - transitioning to online mode");
                mark_online(&state).await;
            }
            Ok(response) => {
                tracing::debug!(
                    status = %response.status(),
                    "Primary health check returned non-success status"
                );
            }
            Err(e) => {
                tracing::debug!(
                    error = %e,
                    "Primary health check failed - remaining offline"
                );
            }
        }
    }
}
