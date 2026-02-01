//! Mesh peer discovery and management API handlers.

use axum::{
    extract::{Path, Query, State},
    routing::{get, post, put},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::api::SharedState;
use crate::error::Result;
use crate::services::peer_service::{PeerService, PeerStatus, ProbeResult};
use crate::services::transfer_service::TransferService;

/// Create peer routes (nested under /api/v1/edge-nodes/:id/peers)
pub fn peer_router() -> Router<SharedState> {
    Router::new()
        .route("/", get(list_peers))
        .route("/discover", get(discover_peers))
        .route("/probe", post(probe_peer))
        .route("/:target_id/unreachable", post(mark_unreachable))
}

/// Create chunk availability routes (nested under /api/v1/edge-nodes/:id/chunks)
pub fn chunk_router() -> Router<SharedState> {
    Router::new()
        .route(
            "/:artifact_id",
            get(get_chunk_availability).put(update_chunk_availability),
        )
        .route("/:artifact_id/peers", get(get_peers_with_chunks))
        .route("/:artifact_id/scored-peers", get(get_scored_peers))
}

/// Create network profile routes (nested under /api/v1/edge-nodes/:id)
pub fn network_profile_router() -> Router<SharedState> {
    Router::new().route("/network-profile", put(update_network_profile))
}

// --- Request/Response types ---

#[derive(Debug, Deserialize)]
pub struct ListPeersQuery {
    pub status: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct PeerResponse {
    pub id: Uuid,
    pub target_node_id: Uuid,
    pub status: String,
    pub latency_ms: Option<i32>,
    pub bandwidth_estimate_bps: Option<i64>,
    pub shared_artifacts_count: i32,
    pub shared_chunks_count: i32,
    pub bytes_transferred_total: i64,
    pub transfer_success_count: i32,
    pub transfer_failure_count: i32,
    pub last_probed_at: Option<chrono::DateTime<chrono::Utc>>,
    pub last_transfer_at: Option<chrono::DateTime<chrono::Utc>>,
}

#[derive(Debug, Deserialize)]
pub struct ProbeBody {
    pub target_node_id: Uuid,
    pub latency_ms: i32,
    pub bandwidth_estimate_bps: Option<i64>,
}

#[derive(Debug, Serialize)]
pub struct DiscoverablePeerResponse {
    pub node_id: Uuid,
    pub name: String,
    pub endpoint_url: String,
    pub region: Option<String>,
    pub status: String,
}

#[derive(Debug, Serialize)]
pub struct ChunkAvailabilityResponse {
    pub edge_node_id: Uuid,
    pub artifact_id: Uuid,
    pub chunk_bitmap: Vec<u8>,
    pub total_chunks: i32,
    pub available_chunks: i32,
}

#[derive(Debug, Deserialize)]
pub struct UpdateChunkAvailabilityBody {
    pub chunk_bitmap: Vec<u8>,
    pub total_chunks: i32,
}

#[derive(Debug, Serialize)]
pub struct ScoredPeerResponse {
    pub node_id: Uuid,
    pub endpoint_url: String,
    pub latency_ms: Option<i32>,
    pub bandwidth_estimate_bps: Option<i64>,
    pub available_chunks: i32,
    pub score: f64,
}

#[derive(Debug, Deserialize)]
pub struct NetworkProfileBody {
    pub max_bandwidth_bps: Option<i64>,
    pub sync_window_start: Option<String>,
    pub sync_window_end: Option<String>,
    pub sync_window_timezone: Option<String>,
    pub concurrent_transfers_limit: Option<i32>,
}

fn parse_peer_status(s: &str) -> Option<PeerStatus> {
    match s.to_lowercase().as_str() {
        "active" => Some(PeerStatus::Active),
        "probing" => Some(PeerStatus::Probing),
        "unreachable" => Some(PeerStatus::Unreachable),
        "disabled" => Some(PeerStatus::Disabled),
        _ => None,
    }
}

// --- Handlers ---

/// GET /api/v1/edge-nodes/:id/peers
async fn list_peers(
    State(state): State<SharedState>,
    Path(node_id): Path<Uuid>,
    Query(query): Query<ListPeersQuery>,
) -> Result<Json<Vec<PeerResponse>>> {
    let service = PeerService::new(state.db.clone());
    let status_filter = query.status.as_ref().and_then(|s| parse_peer_status(s));
    let peers = service.list_peers(node_id, status_filter).await?;

    let items: Vec<PeerResponse> = peers
        .into_iter()
        .map(|p| PeerResponse {
            id: p.id,
            target_node_id: p.target_node_id,
            status: p.status.to_string(),
            latency_ms: p.latency_ms,
            bandwidth_estimate_bps: p.bandwidth_estimate_bps,
            shared_artifacts_count: p.shared_artifacts_count,
            shared_chunks_count: p.shared_chunks_count,
            bytes_transferred_total: p.bytes_transferred_total,
            transfer_success_count: p.transfer_success_count,
            transfer_failure_count: p.transfer_failure_count,
            last_probed_at: p.last_probed_at,
            last_transfer_at: p.last_transfer_at,
        })
        .collect();

    Ok(Json(items))
}

/// GET /api/v1/edge-nodes/:id/peers/discover
async fn discover_peers(
    State(state): State<SharedState>,
    Path(node_id): Path<Uuid>,
) -> Result<Json<Vec<DiscoverablePeerResponse>>> {
    let service = PeerService::new(state.db.clone());
    let peers = service.discover_peers(node_id).await?;

    let items: Vec<DiscoverablePeerResponse> = peers
        .into_iter()
        .map(|p| DiscoverablePeerResponse {
            node_id: p.node_id,
            name: p.name,
            endpoint_url: p.endpoint_url,
            region: p.region,
            status: p.status,
        })
        .collect();

    Ok(Json(items))
}

/// POST /api/v1/edge-nodes/:id/peers/probe
async fn probe_peer(
    State(state): State<SharedState>,
    Path(node_id): Path<Uuid>,
    Json(body): Json<ProbeBody>,
) -> Result<Json<PeerResponse>> {
    let service = PeerService::new(state.db.clone());
    let peer = service
        .upsert_probe_result(
            node_id,
            ProbeResult {
                target_node_id: body.target_node_id,
                latency_ms: body.latency_ms,
                bandwidth_estimate_bps: body.bandwidth_estimate_bps,
            },
        )
        .await?;

    Ok(Json(PeerResponse {
        id: peer.id,
        target_node_id: peer.target_node_id,
        status: peer.status.to_string(),
        latency_ms: peer.latency_ms,
        bandwidth_estimate_bps: peer.bandwidth_estimate_bps,
        shared_artifacts_count: peer.shared_artifacts_count,
        shared_chunks_count: peer.shared_chunks_count,
        bytes_transferred_total: peer.bytes_transferred_total,
        transfer_success_count: peer.transfer_success_count,
        transfer_failure_count: peer.transfer_failure_count,
        last_probed_at: peer.last_probed_at,
        last_transfer_at: peer.last_transfer_at,
    }))
}

/// POST /api/v1/edge-nodes/:id/peers/:target_id/unreachable
async fn mark_unreachable(
    State(state): State<SharedState>,
    Path((node_id, target_id)): Path<(Uuid, Uuid)>,
) -> Result<()> {
    let service = PeerService::new(state.db.clone());
    service.mark_unreachable(node_id, target_id).await
}

/// GET /api/v1/edge-nodes/:id/chunks/:artifact_id
async fn get_chunk_availability(
    State(state): State<SharedState>,
    Path((node_id, artifact_id)): Path<(Uuid, Uuid)>,
) -> Result<Json<ChunkAvailabilityResponse>> {
    let row = sqlx::query!(
        r#"
        SELECT edge_node_id, artifact_id, chunk_bitmap, total_chunks, available_chunks
        FROM chunk_availability
        WHERE edge_node_id = $1 AND artifact_id = $2
        "#,
        node_id,
        artifact_id,
    )
    .fetch_optional(&state.db)
    .await
    .map_err(|e| crate::error::AppError::Database(e.to_string()))?
    .ok_or_else(|| crate::error::AppError::NotFound("No chunk availability data".to_string()))?;

    Ok(Json(ChunkAvailabilityResponse {
        edge_node_id: row.edge_node_id,
        artifact_id: row.artifact_id,
        chunk_bitmap: row.chunk_bitmap,
        total_chunks: row.total_chunks,
        available_chunks: row.available_chunks,
    }))
}

/// PUT /api/v1/edge-nodes/:id/chunks/:artifact_id
async fn update_chunk_availability(
    State(state): State<SharedState>,
    Path((node_id, artifact_id)): Path<(Uuid, Uuid)>,
    Json(body): Json<UpdateChunkAvailabilityBody>,
) -> Result<()> {
    let service = TransferService::new(state.db.clone());
    service
        .update_chunk_availability(node_id, artifact_id, &body.chunk_bitmap, body.total_chunks)
        .await
}

/// GET /api/v1/edge-nodes/:id/chunks/:artifact_id/peers
async fn get_peers_with_chunks(
    State(state): State<SharedState>,
    Path((node_id, artifact_id)): Path<(Uuid, Uuid)>,
) -> Result<Json<Vec<ChunkAvailabilityResponse>>> {
    let service = TransferService::new(state.db.clone());
    let peers = service.get_peers_with_chunks(artifact_id, node_id).await?;

    let items: Vec<ChunkAvailabilityResponse> = peers
        .into_iter()
        .map(|p| ChunkAvailabilityResponse {
            edge_node_id: p.edge_node_id,
            artifact_id,
            chunk_bitmap: p.chunk_bitmap,
            total_chunks: p.total_chunks,
            available_chunks: p.available_chunks,
        })
        .collect();

    Ok(Json(items))
}

/// GET /api/v1/edge-nodes/:id/chunks/:artifact_id/scored-peers
async fn get_scored_peers(
    State(state): State<SharedState>,
    Path((node_id, artifact_id)): Path<(Uuid, Uuid)>,
) -> Result<Json<Vec<ScoredPeerResponse>>> {
    let service = PeerService::new(state.db.clone());
    let peers = service
        .get_scored_peers_for_artifact(node_id, artifact_id)
        .await?;

    let items: Vec<ScoredPeerResponse> = peers
        .into_iter()
        .map(|p| ScoredPeerResponse {
            node_id: p.node_id,
            endpoint_url: p.endpoint_url,
            latency_ms: p.latency_ms,
            bandwidth_estimate_bps: p.bandwidth_estimate_bps,
            available_chunks: p.available_chunks,
            score: p.score,
        })
        .collect();

    Ok(Json(items))
}

/// PUT /api/v1/edge-nodes/:id/network-profile
async fn update_network_profile(
    State(state): State<SharedState>,
    Path(node_id): Path<Uuid>,
    Json(body): Json<NetworkProfileBody>,
) -> Result<()> {
    // Parse time strings if provided
    let window_start = body
        .sync_window_start
        .as_ref()
        .map(|s| s.parse::<chrono::NaiveTime>())
        .transpose()
        .map_err(|e| {
            crate::error::AppError::Validation(format!("Invalid sync_window_start: {}", e))
        })?;

    let window_end = body
        .sync_window_end
        .as_ref()
        .map(|s| s.parse::<chrono::NaiveTime>())
        .transpose()
        .map_err(|e| {
            crate::error::AppError::Validation(format!("Invalid sync_window_end: {}", e))
        })?;

    sqlx::query!(
        r#"
        UPDATE edge_nodes SET
            max_bandwidth_bps = COALESCE($2, max_bandwidth_bps),
            sync_window_start = COALESCE($3, sync_window_start),
            sync_window_end = COALESCE($4, sync_window_end),
            sync_window_timezone = COALESCE($5, sync_window_timezone),
            concurrent_transfers_limit = COALESCE($6, concurrent_transfers_limit),
            updated_at = NOW()
        WHERE id = $1
        "#,
        node_id,
        body.max_bandwidth_bps,
        window_start,
        window_end,
        body.sync_window_timezone,
        body.concurrent_transfers_limit,
    )
    .execute(&state.db)
    .await
    .map_err(|e| crate::error::AppError::Database(e.to_string()))?;

    Ok(())
}
