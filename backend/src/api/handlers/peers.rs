//! Peer instance management handlers.

use axum::{
    extract::{Extension, Path, Query, State},
    routing::{delete, get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::api::middleware::auth::AuthExtension;
use crate::api::SharedState;
use crate::error::Result;
use crate::services::peer_instance_service::{
    InstanceStatus, PeerInstanceService, RegisterPeerInstanceRequest as ServiceRegisterReq,
    ReplicationMode,
};
use crate::services::peer_service::{PeerAnnouncement, PeerService};

/// Create peer instance routes
pub fn router() -> Router<SharedState> {
    Router::new()
        .route("/", get(list_peers).post(register_peer))
        .route("/announce", post(announce_peer))
        .route("/identity", get(get_identity))
        .route("/:id", get(get_peer).delete(unregister_peer))
        .route("/:id/heartbeat", post(heartbeat))
        .route("/:id/sync", post(trigger_sync))
        .route("/:id/sync/tasks", get(get_sync_tasks))
        .route(
            "/:id/repositories",
            get(get_assigned_repos).post(assign_repo),
        )
        .route("/:id/repositories/:repo_id", delete(unassign_repo))
}

#[derive(Debug, Deserialize)]
pub struct ListPeersQuery {
    pub status: Option<String>,
    pub region: Option<String>,
    pub page: Option<u32>,
    pub per_page: Option<u32>,
}

#[derive(Debug, Deserialize)]
pub struct RegisterPeerRequest {
    pub name: String,
    pub endpoint_url: String,
    pub region: Option<String>,
    pub cache_size_bytes: Option<i64>,
    pub sync_filter: Option<serde_json::Value>,
    pub api_key: String,
}

#[derive(Debug, Serialize)]
pub struct PeerInstanceResponse {
    pub id: Uuid,
    pub name: String,
    pub endpoint_url: String,
    pub status: String,
    pub region: Option<String>,
    pub cache_size_bytes: i64,
    pub cache_used_bytes: i64,
    pub cache_usage_percent: f64,
    pub last_heartbeat_at: Option<chrono::DateTime<chrono::Utc>>,
    pub last_sync_at: Option<chrono::DateTime<chrono::Utc>>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub api_key: String,
    pub is_local: bool,
}

#[derive(Debug, Serialize)]
pub struct PeerInstanceListResponse {
    pub items: Vec<PeerInstanceResponse>,
    pub total: i64,
}

#[derive(Debug, Deserialize)]
pub struct HeartbeatRequest {
    pub cache_used_bytes: i64,
    pub status: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct AssignRepoRequest {
    pub repository_id: Uuid,
    pub sync_enabled: Option<bool>,
    pub replication_mode: Option<String>,
    pub replication_schedule: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct SyncTaskResponse {
    pub id: Uuid,
    pub artifact_id: Uuid,
    pub storage_key: String,
    pub artifact_size: i64,
    pub priority: i32,
}

#[derive(Debug, Deserialize)]
pub struct AnnouncePeerRequest {
    pub peer_id: Uuid,
    pub name: String,
    pub endpoint_url: String,
    pub api_key: String,
}

#[derive(Debug, Serialize)]
pub struct IdentityResponse {
    pub peer_id: Uuid,
    pub name: String,
    pub endpoint_url: String,
    pub api_key: String,
}

fn parse_status(s: &str) -> Option<InstanceStatus> {
    match s.to_lowercase().as_str() {
        "online" => Some(InstanceStatus::Online),
        "offline" => Some(InstanceStatus::Offline),
        "syncing" => Some(InstanceStatus::Syncing),
        "degraded" => Some(InstanceStatus::Degraded),
        _ => None,
    }
}

/// List peer instances
pub async fn list_peers(
    State(state): State<SharedState>,
    Query(query): Query<ListPeersQuery>,
) -> Result<Json<PeerInstanceListResponse>> {
    let page = query.page.unwrap_or(1).max(1);
    let per_page = query.per_page.unwrap_or(20).min(100);
    let offset = ((page - 1) * per_page) as i64;

    let status_filter = query.status.as_ref().and_then(|s| parse_status(s));

    let service = PeerInstanceService::new(state.db.clone());
    let (instances, total) = service
        .list(
            status_filter,
            query.region.as_deref(),
            offset,
            per_page as i64,
        )
        .await?;

    let items: Vec<PeerInstanceResponse> = instances
        .into_iter()
        .map(|n| {
            let usage_percent = if n.cache_size_bytes > 0 {
                (n.cache_used_bytes as f64 / n.cache_size_bytes as f64) * 100.0
            } else {
                0.0
            };
            PeerInstanceResponse {
                id: n.id,
                name: n.name,
                endpoint_url: n.endpoint_url,
                status: n.status.to_string(),
                region: n.region,
                cache_size_bytes: n.cache_size_bytes,
                cache_used_bytes: n.cache_used_bytes,
                cache_usage_percent: usage_percent,
                last_heartbeat_at: n.last_heartbeat_at,
                last_sync_at: n.last_sync_at,
                created_at: n.created_at,
                api_key: n.api_key,
                is_local: n.is_local,
            }
        })
        .collect();

    Ok(Json(PeerInstanceListResponse { items, total }))
}

/// Register new peer instance
pub async fn register_peer(
    State(state): State<SharedState>,
    Extension(_auth): Extension<AuthExtension>,
    Json(payload): Json<RegisterPeerRequest>,
) -> Result<Json<PeerInstanceResponse>> {
    let service = PeerInstanceService::new(state.db.clone());

    let instance = service
        .register(ServiceRegisterReq {
            name: payload.name,
            endpoint_url: payload.endpoint_url,
            region: payload.region,
            cache_size_bytes: payload.cache_size_bytes.unwrap_or(10 * 1024 * 1024 * 1024), // 10GB default
            sync_filter: payload.sync_filter,
            api_key: payload.api_key,
        })
        .await?;

    let usage_percent = if instance.cache_size_bytes > 0 {
        (instance.cache_used_bytes as f64 / instance.cache_size_bytes as f64) * 100.0
    } else {
        0.0
    };

    Ok(Json(PeerInstanceResponse {
        id: instance.id,
        name: instance.name,
        endpoint_url: instance.endpoint_url,
        status: instance.status.to_string(),
        region: instance.region,
        cache_size_bytes: instance.cache_size_bytes,
        cache_used_bytes: instance.cache_used_bytes,
        cache_usage_percent: usage_percent,
        last_heartbeat_at: instance.last_heartbeat_at,
        last_sync_at: instance.last_sync_at,
        created_at: instance.created_at,
        api_key: instance.api_key,
        is_local: instance.is_local,
    }))
}

/// Get peer instance details
pub async fn get_peer(
    State(state): State<SharedState>,
    Path(id): Path<Uuid>,
) -> Result<Json<PeerInstanceResponse>> {
    let service = PeerInstanceService::new(state.db.clone());
    let instance = service.get_by_id(id).await?;

    let usage_percent = if instance.cache_size_bytes > 0 {
        (instance.cache_used_bytes as f64 / instance.cache_size_bytes as f64) * 100.0
    } else {
        0.0
    };

    Ok(Json(PeerInstanceResponse {
        id: instance.id,
        name: instance.name,
        endpoint_url: instance.endpoint_url,
        status: instance.status.to_string(),
        region: instance.region,
        cache_size_bytes: instance.cache_size_bytes,
        cache_used_bytes: instance.cache_used_bytes,
        cache_usage_percent: usage_percent,
        last_heartbeat_at: instance.last_heartbeat_at,
        last_sync_at: instance.last_sync_at,
        created_at: instance.created_at,
        api_key: instance.api_key,
        is_local: instance.is_local,
    }))
}

/// Unregister peer instance
pub async fn unregister_peer(
    State(state): State<SharedState>,
    Extension(_auth): Extension<AuthExtension>,
    Path(id): Path<Uuid>,
) -> Result<()> {
    let service = PeerInstanceService::new(state.db.clone());
    service.unregister(id).await?;
    Ok(())
}

/// Heartbeat from peer instance
pub async fn heartbeat(
    State(state): State<SharedState>,
    Path(id): Path<Uuid>,
    Json(payload): Json<HeartbeatRequest>,
) -> Result<()> {
    let status = payload.status.as_ref().and_then(|s| parse_status(s));
    let service = PeerInstanceService::new(state.db.clone());
    service
        .heartbeat(id, payload.cache_used_bytes, status)
        .await?;
    Ok(())
}

/// Trigger sync for peer instance
pub async fn trigger_sync(
    State(state): State<SharedState>,
    Extension(_auth): Extension<AuthExtension>,
    Path(id): Path<Uuid>,
) -> Result<()> {
    let service = PeerInstanceService::new(state.db.clone());
    service.update_sync_status(id, false).await?;
    Ok(())
}

/// Get pending sync tasks for peer instance
pub async fn get_sync_tasks(
    State(state): State<SharedState>,
    Path(id): Path<Uuid>,
    Query(query): Query<ListPeersQuery>,
) -> Result<Json<Vec<SyncTaskResponse>>> {
    let limit = query.per_page.unwrap_or(50) as i64;
    let service = PeerInstanceService::new(state.db.clone());
    let tasks = service.get_pending_sync_tasks(id, limit).await?;

    let items: Vec<SyncTaskResponse> = tasks
        .into_iter()
        .map(|t| SyncTaskResponse {
            id: t.id,
            artifact_id: t.artifact_id,
            storage_key: t.storage_key,
            artifact_size: t.artifact_size,
            priority: t.priority,
        })
        .collect();

    Ok(Json(items))
}

/// Get assigned repositories for peer instance
pub async fn get_assigned_repos(
    State(state): State<SharedState>,
    Path(id): Path<Uuid>,
) -> Result<Json<Vec<Uuid>>> {
    let service = PeerInstanceService::new(state.db.clone());
    let repos = service.get_assigned_repositories(id).await?;
    Ok(Json(repos))
}

/// Assign repository to peer instance
pub async fn assign_repo(
    State(state): State<SharedState>,
    Extension(_auth): Extension<AuthExtension>,
    Path(id): Path<Uuid>,
    Json(payload): Json<AssignRepoRequest>,
) -> Result<()> {
    let replication_mode =
        payload
            .replication_mode
            .as_ref()
            .and_then(|s| match s.to_lowercase().as_str() {
                "push" => Some(ReplicationMode::Push),
                "pull" => Some(ReplicationMode::Pull),
                "mirror" => Some(ReplicationMode::Mirror),
                "none" => Some(ReplicationMode::None),
                _ => None,
            });

    let service = PeerInstanceService::new(state.db.clone());
    service
        .assign_repository(
            id,
            payload.repository_id,
            payload.sync_enabled.unwrap_or(true),
            replication_mode,
            payload.replication_schedule,
        )
        .await?;
    Ok(())
}

/// Unassign repository from peer instance
pub async fn unassign_repo(
    State(state): State<SharedState>,
    Extension(_auth): Extension<AuthExtension>,
    Path((id, repo_id)): Path<(Uuid, Uuid)>,
) -> Result<()> {
    let service = PeerInstanceService::new(state.db.clone());
    service.unassign_repository(id, repo_id).await?;
    Ok(())
}

/// POST /api/v1/peers/announce
async fn announce_peer(
    State(state): State<SharedState>,
    Json(body): Json<AnnouncePeerRequest>,
) -> Result<Json<serde_json::Value>> {
    let peer_svc = PeerService::new(state.db.clone());
    let instance_svc = PeerInstanceService::new(state.db.clone());
    let local = instance_svc.get_local_instance().await?;

    peer_svc
        .handle_peer_announcement(
            local.id,
            PeerAnnouncement {
                peer_id: body.peer_id,
                name: body.name,
                endpoint_url: body.endpoint_url,
                api_key: body.api_key,
            },
        )
        .await?;

    Ok(Json(serde_json::json!({"status": "accepted"})))
}

/// GET /api/v1/peers/identity
async fn get_identity(State(state): State<SharedState>) -> Result<Json<IdentityResponse>> {
    let svc = PeerInstanceService::new(state.db.clone());
    let local = svc.get_local_instance().await?;

    Ok(Json(IdentityResponse {
        peer_id: local.id,
        name: local.name,
        endpoint_url: local.endpoint_url,
        api_key: local.api_key,
    }))
}
