//! Artifact Keeper Edge Node - Distributed caching node with swarm-based transfer.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicI32, AtomicI64, AtomicU32, Ordering};
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
use uuid::Uuid;

mod cache;
mod peers;
mod replication;
mod scheduler;
mod sync;
mod transfer;

/// Default chunk size for chunked transfers (1 MB).
const DEFAULT_CHUNK_SIZE: i32 = 1_048_576;

/// Minimum artifact size to use chunked transfer (anything smaller is fetched whole).
const CHUNKED_TRANSFER_THRESHOLD: u64 = 4 * 1024 * 1024; // 4 MB

/// Edge node application state with offline mode tracking.
pub struct EdgeState {
    pub primary_url: String,
    pub api_key: String,
    pub cache: Arc<cache::ArtifactCache>,
    /// The edge node's ID from the primary registry (set after registration/heartbeat).
    pub edge_node_id: RwLock<Option<Uuid>>,
    /// Configurable chunk size for chunked transfers.
    pub transfer_chunk_size: i32,
    /// Whether chunked transfer is enabled.
    pub chunked_transfer_enabled: bool,
    /// Tracks whether the edge node is currently offline (cannot reach primary).
    pub is_offline: AtomicBool,
    /// Timestamp of last successful contact with the primary server.
    pub last_primary_contact: RwLock<Option<Instant>>,
    /// Number of currently active sync transfers.
    pub active_transfers: Arc<AtomicI32>,
    /// Total bytes transferred by the sync scheduler.
    pub bytes_transferred: Arc<AtomicI64>,
    /// Consecutive sync task fetch failures (used for backoff).
    pub consecutive_failures: Arc<AtomicU32>,
}

impl EdgeState {
    /// Get the edge node ID, returning a zeroed UUID if not yet registered.
    pub fn node_id(&self) -> Uuid {
        // Use try_read to avoid blocking; fall back to nil UUID
        self.edge_node_id
            .try_read()
            .ok()
            .and_then(|guard| *guard)
            .unwrap_or(Uuid::nil())
    }

    /// Get the configured chunk size.
    pub fn chunk_size(&self) -> i32 {
        self.transfer_chunk_size
    }
}

impl Clone for EdgeState {
    fn clone(&self) -> Self {
        Self {
            primary_url: self.primary_url.clone(),
            api_key: self.api_key.clone(),
            cache: self.cache.clone(),
            edge_node_id: RwLock::new(None),
            transfer_chunk_size: self.transfer_chunk_size,
            chunked_transfer_enabled: self.chunked_transfer_enabled,
            is_offline: AtomicBool::new(self.is_offline.load(Ordering::SeqCst)),
            last_primary_contact: RwLock::new(None),
            active_transfers: self.active_transfers.clone(),
            bytes_transferred: self.bytes_transferred.clone(),
            consecutive_failures: self.consecutive_failures.clone(),
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
            AppError::NotFound(msg) => (StatusCode::NOT_FOUND, msg).into_response(),
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
            AppError::Internal(msg) => (StatusCode::INTERNAL_SERVER_ERROR, msg).into_response(),
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

    let primary_url = std::env::var("PRIMARY_URL").expect("PRIMARY_URL must be set");
    let api_key = std::env::var("EDGE_API_KEY").expect("EDGE_API_KEY must be set");
    let bind_address = std::env::var("BIND_ADDRESS").unwrap_or_else(|_| "0.0.0.0:8080".to_string());
    let cache_size: usize = std::env::var("CACHE_SIZE_MB")
        .unwrap_or_else(|_| "1024".to_string())
        .parse()
        .unwrap_or(1024);
    let chunk_size: i32 = std::env::var("CHUNK_SIZE_BYTES")
        .unwrap_or_else(|_| DEFAULT_CHUNK_SIZE.to_string())
        .parse()
        .unwrap_or(DEFAULT_CHUNK_SIZE);
    let chunked_enabled: bool = std::env::var("CHUNKED_TRANSFER_ENABLED")
        .unwrap_or_else(|_| "true".to_string())
        .parse()
        .unwrap_or(true);
    let edge_node_id: Option<Uuid> = std::env::var("EDGE_NODE_ID")
        .ok()
        .and_then(|s| s.parse().ok());

    tracing::info!("Starting Artifact Keeper Edge Node");
    tracing::info!("Primary registry: {}", primary_url);
    tracing::info!(
        "Chunked transfer: {}",
        if chunked_enabled {
            "enabled"
        } else {
            "disabled"
        }
    );
    tracing::info!("Chunk size: {} bytes", chunk_size);

    // Create cache
    let cache = Arc::new(cache::ArtifactCache::new(cache_size));

    // Create state with offline mode tracking
    let state = Arc::new(EdgeState {
        primary_url,
        api_key,
        cache,
        edge_node_id: RwLock::new(edge_node_id),
        transfer_chunk_size: chunk_size,
        chunked_transfer_enabled: chunked_enabled,
        is_offline: AtomicBool::new(false),
        last_primary_contact: RwLock::new(None),
        active_transfers: Arc::new(AtomicI32::new(0)),
        bytes_transferred: Arc::new(AtomicI64::new(0)),
        consecutive_failures: Arc::new(AtomicU32::new(0)),
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

    // Start peer discovery loop
    let peer_state = state.clone();
    tokio::spawn(async move {
        peers::peer_discovery_loop(peer_state).await;
    });

    // Start sync scheduler loop
    let scheduler_state = state.clone();
    tokio::spawn(async move {
        scheduler::sync_scheduler_loop(scheduler_state).await;
    });

    // Build router with artifact proxy and health routes
    let app = Router::new()
        .route("/health", get(health_check))
        .route(
            "/api/v1/repositories/:repo_key/artifacts/*path",
            get(serve_artifact),
        )
        .route("/api/v1/artifacts/:artifact_id", get(serve_artifact_by_id))
        .route(
            "/peer/v1/artifacts/:artifact_id/download",
            get(serve_artifact_to_peer),
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
    if let Some(reqwest_err) = err.downcast_ref::<reqwest::Error>() {
        return reqwest_err.is_connect() || reqwest_err.is_timeout() || reqwest_err.is_request();
    }
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
/// This handler implements the swarm-based transfer protocol:
/// 1. First checks the local cache
/// 2. If online, tries to fetch from primary (using chunked transfer for large artifacts)
/// 3. Falls back to simple whole-file fetch for small artifacts
/// 4. If primary is unreachable, transitions to offline mode
/// 5. In offline mode, returns 503 if artifact not in cache
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

            Err(AppError::Internal(format!(
                "Failed to fetch artifact: {}",
                e
            )))
        }
    }
}

/// Serve an artifact to a peer from local cache.
///
/// This is the peer-to-peer endpoint used for edge-to-edge replication.
/// Returns 200 with raw bytes if the artifact is cached, or 404 otherwise.
/// No authentication is required (peers are on the same internal network).
async fn serve_artifact_to_peer(
    State(state): State<Arc<EdgeState>>,
    Path(artifact_id): Path<Uuid>,
) -> Result<Response, AppError> {
    let cache_key = format!("artifact:{}", artifact_id);

    if let Some(cached_content) = state.cache.get(&cache_key) {
        tracing::debug!(artifact_id = %artifact_id, "Serving artifact to peer from cache");
        return Ok((
            StatusCode::OK,
            [(header::CONTENT_TYPE, "application/octet-stream")],
            cached_content,
        )
            .into_response());
    }

    Err(AppError::NotFound(format!(
        "Artifact {} not in local cache",
        artifact_id
    )))
}

/// Serve an artifact by ID using peer-first replication strategy.
///
/// Tries peers first for faster delivery, then falls back to primary.
/// Accepts an optional `size` query parameter to enable chunked transfer
/// for large artifacts when falling back to primary.
async fn serve_artifact_by_id(
    State(state): State<Arc<EdgeState>>,
    Path(artifact_id): Path<Uuid>,
    axum::extract::Query(params): axum::extract::Query<ArtifactByIdParams>,
) -> Result<Response, AppError> {
    let cache_key = format!("artifact:{}", artifact_id);
    let artifact_size = params.size.unwrap_or(0);

    tracing::debug!(
        artifact_id = %artifact_id,
        size = artifact_size,
        "Serving artifact by ID with peer-first strategy"
    );

    // Check offline mode early
    if state.is_offline.load(Ordering::SeqCst) {
        if let Some(cached) = state.cache.get(&cache_key) {
            return Ok((
                StatusCode::OK,
                [(header::CONTENT_TYPE, "application/octet-stream")],
                cached,
            )
                .into_response());
        }
        return Err(AppError::ServiceUnavailable(
            "Primary server unreachable, artifact not in cache".to_string(),
        ));
    }

    let client = reqwest::Client::new();

    match replication::fetch_with_peer_fallback(
        &client,
        &state,
        artifact_id,
        artifact_size,
        &cache_key,
    )
    .await
    {
        Ok(data) => {
            mark_online(&state).await;
            Ok((
                StatusCode::OK,
                [(header::CONTENT_TYPE, "application/octet-stream")],
                data,
            )
                .into_response())
        }
        Err(e) if is_connectivity_error(&e) => {
            mark_offline(&state);
            Err(AppError::ServiceUnavailable(
                "Primary server unreachable, artifact not in cache".to_string(),
            ))
        }
        Err(e) => {
            if let Some(reqwest_err) = e.downcast_ref::<reqwest::Error>() {
                if reqwest_err.status() == Some(reqwest::StatusCode::NOT_FOUND) {
                    return Err(AppError::NotFound(format!(
                        "Artifact not found: {}",
                        artifact_id
                    )));
                }
            }
            Err(AppError::Internal(format!(
                "Failed to fetch artifact: {}",
                e
            )))
        }
    }
}

/// Query parameters for the artifact-by-ID endpoint.
#[derive(Debug, serde::Deserialize)]
struct ArtifactByIdParams {
    /// Optional artifact size hint to enable chunked transfer for large files.
    size: Option<i64>,
}

/// Health check endpoint that reports offline status.
async fn health_check(State(state): State<Arc<EdgeState>>) -> impl IntoResponse {
    let is_offline = state.is_offline.load(Ordering::SeqCst);
    let cache_size = state.cache.size();
    let cache_entries = state.cache.len();
    let node_id = state.edge_node_id.read().await.map(|id| id.to_string());

    let last_contact = state.last_primary_contact.read().await;
    let seconds_since_contact = last_contact
        .map(|t| t.elapsed().as_secs())
        .unwrap_or(u64::MAX);

    let status = if is_offline { "offline" } else { "online" };

    let active_transfers = state.active_transfers.load(Ordering::Relaxed);
    let bytes_transferred_total = state.bytes_transferred.load(Ordering::Relaxed);

    let body = serde_json::json!({
        "status": status,
        "is_offline": is_offline,
        "node_id": node_id,
        "cache_size_bytes": cache_size,
        "cache_entries": cache_entries,
        "chunked_transfer_enabled": state.chunked_transfer_enabled,
        "active_transfers": active_transfers,
        "bytes_transferred_total": bytes_transferred_total,
        "seconds_since_primary_contact": if seconds_since_contact == u64::MAX {
            None
        } else {
            Some(seconds_since_contact)
        },
    });

    let status_code = StatusCode::OK;

    (status_code, axum::Json(body))
}

/// Periodically check connectivity to the primary server.
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
