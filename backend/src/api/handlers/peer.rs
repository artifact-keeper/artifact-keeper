//! Mesh peer discovery and management API handlers.

use axum::{
    extract::{Path, Query, State},
    routing::{get, post, put},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, OpenApi, ToSchema};
use uuid::Uuid;

use crate::api::SharedState;
use crate::error::Result;
use crate::services::peer_service::{PeerService, PeerStatus, ProbeResult};
use crate::services::transfer_service::TransferService;

/// Create peer routes (nested under /api/v1/peers/:id/connections)
pub fn peer_router() -> Router<SharedState> {
    Router::new()
        .route("/", get(list_peers))
        .route("/discover", get(discover_peers))
        .route("/probe", post(probe_peer))
        .route("/:target_id/unreachable", post(mark_unreachable))
}

/// Create chunk availability routes (nested under /api/v1/peers/:id/chunks)
pub fn chunk_router() -> Router<SharedState> {
    Router::new()
        .route(
            "/:artifact_id",
            get(get_chunk_availability).put(update_chunk_availability),
        )
        .route("/:artifact_id/peers", get(get_peers_with_chunks))
        .route("/:artifact_id/scored-peers", get(get_scored_peers))
}

/// Create network profile routes (nested under /api/v1/peers/:id)
pub fn network_profile_router() -> Router<SharedState> {
    Router::new().route("/network-profile", put(update_network_profile))
}

// --- Request/Response types ---

#[derive(Debug, Deserialize, IntoParams)]
pub struct ListPeersQuery {
    /// Filter peers by status (active, probing, unreachable, disabled)
    pub status: Option<String>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct PeerResponse {
    pub id: Uuid,
    pub target_peer_id: Uuid,
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

#[derive(Debug, Deserialize, ToSchema)]
pub struct ProbeBody {
    pub target_peer_id: Uuid,
    pub latency_ms: i32,
    pub bandwidth_estimate_bps: Option<i64>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct DiscoverablePeerResponse {
    pub peer_id: Uuid,
    pub name: String,
    pub endpoint_url: String,
    pub region: Option<String>,
    pub status: String,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct ChunkAvailabilityResponse {
    pub peer_instance_id: Uuid,
    pub artifact_id: Uuid,
    pub chunk_bitmap: Vec<u8>,
    pub total_chunks: i32,
    pub available_chunks: i32,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct UpdateChunkAvailabilityBody {
    pub chunk_bitmap: Vec<u8>,
    pub total_chunks: i32,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct ScoredPeerResponse {
    pub peer_id: Uuid,
    pub endpoint_url: String,
    pub latency_ms: Option<i32>,
    pub bandwidth_estimate_bps: Option<i64>,
    pub available_chunks: i32,
    pub score: f64,
}

#[derive(Debug, Deserialize, ToSchema)]
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

/// GET /api/v1/peers/:id/connections
#[utoipa::path(
    get,
    path = "/{id}/connections",
    context_path = "/api/v1/peers",
    tag = "peers",
    operation_id = "list_peer_connections",
    params(
        ("id" = Uuid, Path, description = "Peer instance ID"),
        ListPeersQuery,
    ),
    responses(
        (status = 200, description = "List of peer connections", body = Vec<PeerResponse>),
        (status = 404, description = "Peer not found", body = crate::api::openapi::ErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
async fn list_peers(
    State(state): State<SharedState>,
    Path(peer_id): Path<Uuid>,
    Query(query): Query<ListPeersQuery>,
) -> Result<Json<Vec<PeerResponse>>> {
    let service = PeerService::new(state.db.clone());
    let status_filter = query.status.as_ref().and_then(|s| parse_peer_status(s));
    let peers = service.list_peers(peer_id, status_filter).await?;

    let items: Vec<PeerResponse> = peers
        .into_iter()
        .map(|p| PeerResponse {
            id: p.id,
            target_peer_id: p.target_peer_id,
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

/// GET /api/v1/peers/:id/connections/discover
#[utoipa::path(
    get,
    path = "/{id}/connections/discover",
    context_path = "/api/v1/peers",
    tag = "peers",
    params(
        ("id" = Uuid, Path, description = "Peer instance ID"),
    ),
    responses(
        (status = 200, description = "Discoverable peers", body = Vec<DiscoverablePeerResponse>),
    ),
    security(("bearer_auth" = []))
)]
async fn discover_peers(
    State(state): State<SharedState>,
    Path(peer_id): Path<Uuid>,
) -> Result<Json<Vec<DiscoverablePeerResponse>>> {
    let service = PeerService::new(state.db.clone());
    let peers = service.discover_peers(peer_id).await?;

    let items: Vec<DiscoverablePeerResponse> = peers
        .into_iter()
        .map(|p| DiscoverablePeerResponse {
            peer_id: p.node_id,
            name: p.name,
            endpoint_url: p.endpoint_url,
            region: p.region,
            status: p.status,
        })
        .collect();

    Ok(Json(items))
}

/// POST /api/v1/peers/:id/connections/probe
#[utoipa::path(
    post,
    path = "/{id}/connections/probe",
    context_path = "/api/v1/peers",
    tag = "peers",
    params(
        ("id" = Uuid, Path, description = "Peer instance ID"),
    ),
    request_body = ProbeBody,
    responses(
        (status = 200, description = "Probe result recorded", body = PeerResponse),
        (status = 400, description = "target_peer_id equals the source peer id"),
        (status = 404, description = "Source or target peer instance not found"),
    ),
    security(("bearer_auth" = []))
)]
async fn probe_peer(
    State(state): State<SharedState>,
    Path(peer_id): Path<Uuid>,
    Json(body): Json<ProbeBody>,
) -> Result<Json<PeerResponse>> {
    // A peer cannot probe a connection to itself. The `peer_connections`
    // table enforces this with a CHECK (`source_peer_id != target_peer_id`),
    // which previously surfaced as an opaque 500 DATABASE_ERROR. Reject it up
    // front as a 400 client error. (Non-existent source/target peers are
    // mapped to 404 in the service layer's FK handling.)
    if body.target_peer_id == peer_id {
        return Err(crate::error::AppError::Validation(
            "target_peer_id must differ from the source peer id".to_string(),
        ));
    }

    let service = PeerService::new(state.db.clone());
    let peer = service
        .upsert_probe_result(
            peer_id,
            ProbeResult {
                target_peer_id: body.target_peer_id,
                latency_ms: body.latency_ms,
                bandwidth_estimate_bps: body.bandwidth_estimate_bps,
            },
        )
        .await?;

    Ok(Json(PeerResponse {
        id: peer.id,
        target_peer_id: peer.target_peer_id,
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

/// POST /api/v1/peers/:id/connections/:target_id/unreachable
#[utoipa::path(
    post,
    path = "/{id}/connections/{target_id}/unreachable",
    context_path = "/api/v1/peers",
    tag = "peers",
    params(
        ("id" = Uuid, Path, description = "Peer instance ID"),
        ("target_id" = Uuid, Path, description = "Target peer ID to mark unreachable"),
    ),
    responses(
        (status = 200, description = "Peer marked as unreachable"),
    ),
    security(("bearer_auth" = []))
)]
async fn mark_unreachable(
    State(state): State<SharedState>,
    Path((peer_id, target_id)): Path<(Uuid, Uuid)>,
) -> Result<()> {
    let service = PeerService::new(state.db.clone());
    service.mark_unreachable(peer_id, target_id).await
}

/// GET /api/v1/peers/:id/chunks/:artifact_id
#[utoipa::path(
    get,
    path = "/{id}/chunks/{artifact_id}",
    context_path = "/api/v1/peers",
    tag = "peers",
    params(
        ("id" = Uuid, Path, description = "Peer instance ID"),
        ("artifact_id" = Uuid, Path, description = "Artifact ID"),
    ),
    responses(
        (status = 200, description = "Chunk availability for this peer and artifact", body = ChunkAvailabilityResponse),
        (status = 404, description = "No chunk availability data", body = crate::api::openapi::ErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
async fn get_chunk_availability(
    State(state): State<SharedState>,
    Path((peer_id, artifact_id)): Path<(Uuid, Uuid)>,
) -> Result<Json<ChunkAvailabilityResponse>> {
    let row = sqlx::query!(
        r#"
        SELECT peer_instance_id, artifact_id, chunk_bitmap, total_chunks, available_chunks
        FROM chunk_availability
        WHERE peer_instance_id = $1 AND artifact_id = $2
        "#,
        peer_id,
        artifact_id,
    )
    .fetch_optional(&state.db)
    .await
    .map_err(|e| crate::error::AppError::Database(e.to_string()))?
    .ok_or_else(|| crate::error::AppError::NotFound("No chunk availability data".to_string()))?;

    Ok(Json(ChunkAvailabilityResponse {
        peer_instance_id: row.peer_instance_id,
        artifact_id: row.artifact_id,
        chunk_bitmap: row.chunk_bitmap,
        total_chunks: row.total_chunks,
        available_chunks: row.available_chunks,
    }))
}

/// PUT /api/v1/peers/:id/chunks/:artifact_id
#[utoipa::path(
    put,
    path = "/{id}/chunks/{artifact_id}",
    context_path = "/api/v1/peers",
    tag = "peers",
    params(
        ("id" = Uuid, Path, description = "Peer instance ID"),
        ("artifact_id" = Uuid, Path, description = "Artifact ID"),
    ),
    request_body = UpdateChunkAvailabilityBody,
    responses(
        (status = 200, description = "Chunk availability updated"),
    ),
    security(("bearer_auth" = []))
)]
async fn update_chunk_availability(
    State(state): State<SharedState>,
    Path((peer_id, artifact_id)): Path<(Uuid, Uuid)>,
    Json(body): Json<UpdateChunkAvailabilityBody>,
) -> Result<()> {
    let service = TransferService::new(state.db.clone());
    service
        .update_chunk_availability(peer_id, artifact_id, &body.chunk_bitmap, body.total_chunks)
        .await
}

/// GET /api/v1/peers/:id/chunks/:artifact_id/peers
#[utoipa::path(
    get,
    path = "/{id}/chunks/{artifact_id}/peers",
    context_path = "/api/v1/peers",
    tag = "peers",
    params(
        ("id" = Uuid, Path, description = "Peer instance ID"),
        ("artifact_id" = Uuid, Path, description = "Artifact ID"),
    ),
    responses(
        (status = 200, description = "Peers that have chunks for this artifact", body = Vec<ChunkAvailabilityResponse>),
    ),
    security(("bearer_auth" = []))
)]
async fn get_peers_with_chunks(
    State(state): State<SharedState>,
    Path((peer_id, artifact_id)): Path<(Uuid, Uuid)>,
) -> Result<Json<Vec<ChunkAvailabilityResponse>>> {
    let service = TransferService::new(state.db.clone());
    let peers = service.get_peers_with_chunks(artifact_id, peer_id).await?;

    let items: Vec<ChunkAvailabilityResponse> = peers
        .into_iter()
        .map(|p| ChunkAvailabilityResponse {
            peer_instance_id: p.peer_instance_id,
            artifact_id,
            chunk_bitmap: p.chunk_bitmap,
            total_chunks: p.total_chunks,
            available_chunks: p.available_chunks,
        })
        .collect();

    Ok(Json(items))
}

/// GET /api/v1/peers/:id/chunks/:artifact_id/scored-peers
#[utoipa::path(
    get,
    path = "/{id}/chunks/{artifact_id}/scored-peers",
    context_path = "/api/v1/peers",
    tag = "peers",
    params(
        ("id" = Uuid, Path, description = "Peer instance ID"),
        ("artifact_id" = Uuid, Path, description = "Artifact ID"),
    ),
    responses(
        (status = 200, description = "Scored peers for artifact download", body = Vec<ScoredPeerResponse>),
    ),
    security(("bearer_auth" = []))
)]
async fn get_scored_peers(
    State(state): State<SharedState>,
    Path((peer_id, artifact_id)): Path<(Uuid, Uuid)>,
) -> Result<Json<Vec<ScoredPeerResponse>>> {
    let service = PeerService::new(state.db.clone());
    let peers = service
        .get_scored_peers_for_artifact(peer_id, artifact_id)
        .await?;

    let items: Vec<ScoredPeerResponse> = peers
        .into_iter()
        .map(|p| ScoredPeerResponse {
            peer_id: p.node_id,
            endpoint_url: p.endpoint_url,
            latency_ms: p.latency_ms,
            bandwidth_estimate_bps: p.bandwidth_estimate_bps,
            available_chunks: p.available_chunks,
            score: p.score,
        })
        .collect();

    Ok(Json(items))
}

/// PUT /api/v1/peers/:id/network-profile
#[utoipa::path(
    put,
    path = "/{id}/network-profile",
    context_path = "/api/v1/peers",
    tag = "peers",
    params(
        ("id" = Uuid, Path, description = "Peer instance ID"),
    ),
    request_body = NetworkProfileBody,
    responses(
        (status = 200, description = "Network profile updated"),
    ),
    security(("bearer_auth" = []))
)]
async fn update_network_profile(
    State(state): State<SharedState>,
    Path(peer_id): Path<Uuid>,
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
        UPDATE peer_instances SET
            max_bandwidth_bps = COALESCE($2, max_bandwidth_bps),
            sync_window_start = COALESCE($3, sync_window_start),
            sync_window_end = COALESCE($4, sync_window_end),
            sync_window_timezone = COALESCE($5, sync_window_timezone),
            concurrent_transfers_limit = COALESCE($6, concurrent_transfers_limit),
            updated_at = NOW()
        WHERE id = $1
        "#,
        peer_id,
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

#[derive(OpenApi)]
#[openapi(
    paths(
        list_peers,
        discover_peers,
        probe_peer,
        mark_unreachable,
        get_chunk_availability,
        update_chunk_availability,
        get_peers_with_chunks,
        get_scored_peers,
        update_network_profile,
    ),
    components(schemas(
        PeerResponse,
        ProbeBody,
        DiscoverablePeerResponse,
        ChunkAvailabilityResponse,
        UpdateChunkAvailabilityBody,
        ScoredPeerResponse,
        NetworkProfileBody,
    ))
)]
pub struct PeerApiDoc;

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Timelike;
    use serde_json::json;

    // -----------------------------------------------------------------------
    // parse_peer_status tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_parse_peer_status_active() {
        assert!(matches!(
            parse_peer_status("active"),
            Some(PeerStatus::Active)
        ));
    }

    #[test]
    fn test_parse_peer_status_probing() {
        assert!(matches!(
            parse_peer_status("probing"),
            Some(PeerStatus::Probing)
        ));
    }

    #[test]
    fn test_parse_peer_status_unreachable() {
        assert!(matches!(
            parse_peer_status("unreachable"),
            Some(PeerStatus::Unreachable)
        ));
    }

    #[test]
    fn test_parse_peer_status_disabled() {
        assert!(matches!(
            parse_peer_status("disabled"),
            Some(PeerStatus::Disabled)
        ));
    }

    #[test]
    fn test_parse_peer_status_case_insensitive() {
        assert!(matches!(
            parse_peer_status("ACTIVE"),
            Some(PeerStatus::Active)
        ));
        assert!(matches!(
            parse_peer_status("Probing"),
            Some(PeerStatus::Probing)
        ));
        assert!(matches!(
            parse_peer_status("UNREACHABLE"),
            Some(PeerStatus::Unreachable)
        ));
        assert!(matches!(
            parse_peer_status("Disabled"),
            Some(PeerStatus::Disabled)
        ));
    }

    #[test]
    fn test_parse_peer_status_unknown() {
        assert!(parse_peer_status("online").is_none());
        assert!(parse_peer_status("unknown").is_none());
        assert!(parse_peer_status("").is_none());
        assert!(parse_peer_status("  active  ").is_none()); // no trim
    }

    // -----------------------------------------------------------------------
    // PeerStatus Display
    // -----------------------------------------------------------------------

    #[test]
    fn test_peer_status_display() {
        assert_eq!(PeerStatus::Active.to_string(), "active");
        assert_eq!(PeerStatus::Probing.to_string(), "probing");
        assert_eq!(PeerStatus::Unreachable.to_string(), "unreachable");
        assert_eq!(PeerStatus::Disabled.to_string(), "disabled");
    }

    // -----------------------------------------------------------------------
    // ListPeersQuery deserialization
    // -----------------------------------------------------------------------

    #[test]
    fn test_list_peers_query_deserialize_with_status() {
        let json = json!({"status": "active"});
        let query: ListPeersQuery = serde_json::from_value(json).unwrap();
        assert_eq!(query.status.as_deref(), Some("active"));
    }

    #[test]
    fn test_list_peers_query_deserialize_empty() {
        let json = json!({});
        let query: ListPeersQuery = serde_json::from_value(json).unwrap();
        assert!(query.status.is_none());
    }

    // -----------------------------------------------------------------------
    // ProbeBody deserialization
    // -----------------------------------------------------------------------

    #[test]
    fn test_probe_body_deserialize_full() {
        let target_id = Uuid::new_v4();
        let json = json!({
            "target_peer_id": target_id,
            "latency_ms": 45,
            "bandwidth_estimate_bps": 1000000
        });
        let body: ProbeBody = serde_json::from_value(json).unwrap();
        assert_eq!(body.target_peer_id, target_id);
        assert_eq!(body.latency_ms, 45);
        assert_eq!(body.bandwidth_estimate_bps, Some(1000000));
    }

    #[test]
    fn test_probe_body_deserialize_minimal() {
        let target_id = Uuid::new_v4();
        let json = json!({
            "target_peer_id": target_id,
            "latency_ms": 100
        });
        let body: ProbeBody = serde_json::from_value(json).unwrap();
        assert_eq!(body.latency_ms, 100);
        assert!(body.bandwidth_estimate_bps.is_none());
    }

    // -----------------------------------------------------------------------
    // PeerResponse serialization
    // -----------------------------------------------------------------------

    #[test]
    fn test_peer_response_serialize() {
        let id = Uuid::new_v4();
        let target_id = Uuid::new_v4();
        let resp = PeerResponse {
            id,
            target_peer_id: target_id,
            status: "active".to_string(),
            latency_ms: Some(25),
            bandwidth_estimate_bps: Some(500_000),
            shared_artifacts_count: 100,
            shared_chunks_count: 200,
            bytes_transferred_total: 1_000_000_000,
            transfer_success_count: 95,
            transfer_failure_count: 5,
            last_probed_at: None,
            last_transfer_at: None,
        };
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["status"], "active");
        assert_eq!(json["latency_ms"], 25);
        assert_eq!(json["bandwidth_estimate_bps"], 500_000);
        assert_eq!(json["shared_artifacts_count"], 100);
        assert_eq!(json["shared_chunks_count"], 200);
        assert_eq!(json["bytes_transferred_total"], 1_000_000_000_i64);
        assert_eq!(json["transfer_success_count"], 95);
        assert_eq!(json["transfer_failure_count"], 5);
    }

    #[test]
    fn test_peer_response_serialize_null_optionals() {
        let resp = PeerResponse {
            id: Uuid::nil(),
            target_peer_id: Uuid::nil(),
            status: "unreachable".to_string(),
            latency_ms: None,
            bandwidth_estimate_bps: None,
            shared_artifacts_count: 0,
            shared_chunks_count: 0,
            bytes_transferred_total: 0,
            transfer_success_count: 0,
            transfer_failure_count: 0,
            last_probed_at: None,
            last_transfer_at: None,
        };
        let json = serde_json::to_value(&resp).unwrap();
        assert!(json["latency_ms"].is_null());
        assert!(json["bandwidth_estimate_bps"].is_null());
        assert!(json["last_probed_at"].is_null());
    }

    // -----------------------------------------------------------------------
    // DiscoverablePeerResponse serialization
    // -----------------------------------------------------------------------

    #[test]
    fn test_discoverable_peer_response_serialize() {
        let resp = DiscoverablePeerResponse {
            peer_id: Uuid::nil(),
            name: "edge-node-us-east".to_string(),
            endpoint_url: "https://edge-us.example.com".to_string(),
            region: Some("us-east-1".to_string()),
            status: "online".to_string(),
        };
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["name"], "edge-node-us-east");
        assert_eq!(json["endpoint_url"], "https://edge-us.example.com");
        assert_eq!(json["region"], "us-east-1");
        assert_eq!(json["status"], "online");
    }

    #[test]
    fn test_discoverable_peer_response_no_region() {
        let resp = DiscoverablePeerResponse {
            peer_id: Uuid::nil(),
            name: "peer".to_string(),
            endpoint_url: "https://peer.example.com".to_string(),
            region: None,
            status: "online".to_string(),
        };
        let json = serde_json::to_value(&resp).unwrap();
        assert!(json["region"].is_null());
    }

    // -----------------------------------------------------------------------
    // ChunkAvailabilityResponse serialization
    // -----------------------------------------------------------------------

    #[test]
    fn test_chunk_availability_response_serialize() {
        let peer_id = Uuid::new_v4();
        let artifact_id = Uuid::new_v4();
        let resp = ChunkAvailabilityResponse {
            peer_instance_id: peer_id,
            artifact_id,
            chunk_bitmap: vec![0xFF, 0x0F, 0x00],
            total_chunks: 24,
            available_chunks: 12,
        };
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["total_chunks"], 24);
        assert_eq!(json["available_chunks"], 12);
        // chunk_bitmap serialized as array
        let bitmap = json["chunk_bitmap"].as_array().unwrap();
        assert_eq!(bitmap.len(), 3);
        assert_eq!(bitmap[0], 255);
        assert_eq!(bitmap[1], 15);
        assert_eq!(bitmap[2], 0);
    }

    // -----------------------------------------------------------------------
    // UpdateChunkAvailabilityBody deserialization
    // -----------------------------------------------------------------------

    #[test]
    fn test_update_chunk_availability_body_deserialize() {
        let json = json!({
            "chunk_bitmap": [255, 15, 0],
            "total_chunks": 24
        });
        let body: UpdateChunkAvailabilityBody = serde_json::from_value(json).unwrap();
        assert_eq!(body.chunk_bitmap, vec![0xFF, 0x0F, 0x00]);
        assert_eq!(body.total_chunks, 24);
    }

    // -----------------------------------------------------------------------
    // ScoredPeerResponse serialization
    // -----------------------------------------------------------------------

    #[test]
    fn test_scored_peer_response_serialize() {
        let resp = ScoredPeerResponse {
            peer_id: Uuid::nil(),
            endpoint_url: "https://peer.example.com".to_string(),
            latency_ms: Some(10),
            bandwidth_estimate_bps: Some(10_000_000),
            available_chunks: 50,
            score: 0.95,
        };
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["latency_ms"], 10);
        assert_eq!(json["bandwidth_estimate_bps"], 10_000_000);
        assert_eq!(json["available_chunks"], 50);
        assert_eq!(json["score"], 0.95);
    }

    #[test]
    fn test_scored_peer_response_no_metrics() {
        let resp = ScoredPeerResponse {
            peer_id: Uuid::nil(),
            endpoint_url: "https://peer.example.com".to_string(),
            latency_ms: None,
            bandwidth_estimate_bps: None,
            available_chunks: 0,
            score: 0.0,
        };
        let json = serde_json::to_value(&resp).unwrap();
        assert!(json["latency_ms"].is_null());
        assert!(json["bandwidth_estimate_bps"].is_null());
        assert_eq!(json["score"], 0.0);
    }

    // -----------------------------------------------------------------------
    // NetworkProfileBody deserialization
    // -----------------------------------------------------------------------

    #[test]
    fn test_network_profile_body_deserialize_full() {
        let json = json!({
            "max_bandwidth_bps": 100000000,
            "sync_window_start": "02:00:00",
            "sync_window_end": "06:00:00",
            "sync_window_timezone": "America/New_York",
            "concurrent_transfers_limit": 4
        });
        let body: NetworkProfileBody = serde_json::from_value(json).unwrap();
        assert_eq!(body.max_bandwidth_bps, Some(100000000));
        assert_eq!(body.sync_window_start.as_deref(), Some("02:00:00"));
        assert_eq!(body.sync_window_end.as_deref(), Some("06:00:00"));
        assert_eq!(
            body.sync_window_timezone.as_deref(),
            Some("America/New_York")
        );
        assert_eq!(body.concurrent_transfers_limit, Some(4));
    }

    #[test]
    fn test_network_profile_body_deserialize_empty() {
        let json = json!({});
        let body: NetworkProfileBody = serde_json::from_value(json).unwrap();
        assert!(body.max_bandwidth_bps.is_none());
        assert!(body.sync_window_start.is_none());
        assert!(body.sync_window_end.is_none());
        assert!(body.sync_window_timezone.is_none());
        assert!(body.concurrent_transfers_limit.is_none());
    }

    // -----------------------------------------------------------------------
    // NaiveTime parsing (used in update_network_profile)
    // -----------------------------------------------------------------------

    #[test]
    fn test_naive_time_parsing_valid() {
        let time_str = "02:00:00";
        let parsed = time_str.parse::<chrono::NaiveTime>();
        assert!(parsed.is_ok());
        let time = parsed.unwrap();
        assert_eq!(time.hour(), 2);
        assert_eq!(time.minute(), 0);
    }

    #[test]
    fn test_naive_time_parsing_invalid() {
        let time_str = "not-a-time";
        let parsed = time_str.parse::<chrono::NaiveTime>();
        assert!(parsed.is_err());
    }

    #[test]
    fn test_naive_time_parsing_midnight() {
        let time_str = "00:00:00";
        let parsed = time_str.parse::<chrono::NaiveTime>();
        assert!(parsed.is_ok());
    }

    #[test]
    fn test_naive_time_parsing_end_of_day() {
        let time_str = "23:59:59";
        let parsed = time_str.parse::<chrono::NaiveTime>();
        assert!(parsed.is_ok());
        let time = parsed.unwrap();
        assert_eq!(time.hour(), 23);
        assert_eq!(time.minute(), 59);
    }

    // -----------------------------------------------------------------------
    // Time parsing via Option::map + transpose (handler pattern)
    // -----------------------------------------------------------------------

    #[test]
    fn test_optional_time_parsing_some_valid() {
        let time_str = Some("14:30:00".to_string());
        let result = time_str
            .as_ref()
            .map(|s| s.parse::<chrono::NaiveTime>())
            .transpose();
        assert!(result.is_ok());
        assert!(result.unwrap().is_some());
    }

    #[test]
    fn test_optional_time_parsing_none() {
        let time_str: Option<String> = None;
        let result = time_str
            .as_ref()
            .map(|s| s.parse::<chrono::NaiveTime>())
            .transpose();
        assert!(result.is_ok());
        assert!(result.unwrap().is_none());
    }

    #[test]
    fn test_optional_time_parsing_some_invalid() {
        let time_str = Some("invalid".to_string());
        let result = time_str
            .as_ref()
            .map(|s| s.parse::<chrono::NaiveTime>())
            .transpose();
        assert!(result.is_err());
    }

    // -----------------------------------------------------------------------
    // Peer status filter logic
    // -----------------------------------------------------------------------

    #[test]
    fn test_status_filter_from_query() {
        let query = ListPeersQuery {
            status: Some("active".to_string()),
        };
        let filter = query.status.as_ref().and_then(|s| parse_peer_status(s));
        assert!(matches!(filter, Some(PeerStatus::Active)));
    }

    #[test]
    fn test_status_filter_from_query_none() {
        let query = ListPeersQuery { status: None };
        let filter = query.status.as_ref().and_then(|s| parse_peer_status(s));
        assert!(filter.is_none());
    }

    #[test]
    fn test_status_filter_invalid() {
        let query = ListPeersQuery {
            status: Some("invalid".to_string()),
        };
        let filter = query.status.as_ref().and_then(|s| parse_peer_status(s));
        assert!(filter.is_none());
    }

    // -----------------------------------------------------------------------
    // DB-backed probe tests (POST /peers/{id}/connections/probe).
    //
    // Before this fix, a self-referential probe (`target_peer_id == path id`)
    // tripped the `peer_connections_no_self_link` CHECK constraint and surfaced
    // as an opaque 500 DATABASE_ERROR; a probe at a non-existent target tripped
    // the FK and also 500'd. Both are client errors and are now mapped to 4xx:
    //   * self-referential probe -> 400
    //   * non-existent target    -> 404
    //   * valid probe            -> 200
    //
    // Runtime-skips when no `DATABASE_URL` is set (NOT `#[ignore]`).
    // -----------------------------------------------------------------------
    mod probe_db {
        use crate::api::handlers::test_db_helpers as tdh;
        use axum::http::StatusCode;
        use axum::Router;
        use sqlx::PgPool;
        use uuid::Uuid;

        async fn make_peer(pool: &PgPool, tag: &str) -> Uuid {
            tdh::register_test_peer(pool, "probe", tag).await
        }

        fn probe_app(state: crate::api::SharedState) -> Router {
            // Mirror the production mount point: peer_router() lives under
            // /:id/connections.
            let router = Router::new().nest("/:id/connections", super::super::peer_router());
            tdh::router_with_auth(router, state, tdh::make_auth(Uuid::new_v4(), "fed.admin"))
        }

        /// Drive the probe handler: POST `{target_peer_id, latency_ms}` to
        /// `/{src}/connections/probe` on a fresh router and return the status.
        async fn probe(
            state: crate::api::SharedState,
            src: Uuid,
            target: Uuid,
            latency: i64,
        ) -> StatusCode {
            let body = axum::body::Bytes::from(
                format!(
                    r#"{{"target_peer_id":"{}","latency_ms":{}}}"#,
                    target, latency
                )
                .into_bytes(),
            );
            let (status, _) = tdh::send(
                probe_app(state),
                tdh::post(
                    format!("/{}/connections/probe", src),
                    "application/json",
                    body,
                ),
            )
            .await;
            status
        }

        #[tokio::test]
        async fn test_probe_self_reference_is_400_not_500() {
            let Some(pool) = tdh::try_pool().await else {
                return;
            };
            let state = tdh::build_state(pool.clone(), "/tmp/ph-peer-probe");
            let peer_id = make_peer(&pool, "self").await;

            let status = probe(state, peer_id, peer_id, 5).await;

            assert_eq!(
                status,
                StatusCode::BAD_REQUEST,
                "self-referential probe must be a 400, not a 500 DATABASE_ERROR"
            );

            let _ = sqlx::query("DELETE FROM peer_instances WHERE id = $1")
                .bind(peer_id)
                .execute(&pool)
                .await;
        }

        #[tokio::test]
        async fn test_probe_nonexistent_target_is_404_not_500() {
            let Some(pool) = tdh::try_pool().await else {
                return;
            };
            let state = tdh::build_state(pool.clone(), "/tmp/ph-peer-probe");
            let peer_id = make_peer(&pool, "src").await;
            let missing = Uuid::new_v4();

            let status = probe(state, peer_id, missing, 5).await;

            assert_eq!(
                status,
                StatusCode::NOT_FOUND,
                "probe at a non-existent target must be a 404, not a 500"
            );

            let _ = sqlx::query("DELETE FROM peer_instances WHERE id = $1")
                .bind(peer_id)
                .execute(&pool)
                .await;
        }

        #[tokio::test]
        async fn test_probe_valid_target_succeeds() {
            let Some(pool) = tdh::try_pool().await else {
                return;
            };
            let state = tdh::build_state(pool.clone(), "/tmp/ph-peer-probe");
            let src = make_peer(&pool, "src").await;
            let dst = make_peer(&pool, "dst").await;

            let status = probe(state, src, dst, 12).await;

            assert_eq!(
                status,
                StatusCode::OK,
                "a probe between two distinct, existing peers must still succeed"
            );

            let _ = sqlx::query("DELETE FROM peer_instances WHERE id = ANY($1)")
                .bind(vec![src, dst])
                .execute(&pool)
                .await;
        }
    }
}
