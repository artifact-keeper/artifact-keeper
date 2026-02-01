//! Edge node management handlers.

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
use crate::services::edge_service::{
    EdgeService, EdgeStatus, RegisterEdgeNodeRequest as ServiceRegisterReq, ReplicationPriority,
};

/// Create edge node routes
pub fn router() -> Router<SharedState> {
    Router::new()
        .route("/", get(list_edge_nodes).post(register_edge_node))
        .route("/:id", get(get_edge_node).delete(unregister_edge_node))
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
pub struct ListEdgeNodesQuery {
    pub status: Option<String>,
    pub region: Option<String>,
    pub page: Option<u32>,
    pub per_page: Option<u32>,
}

#[derive(Debug, Deserialize)]
pub struct RegisterEdgeNodeRequest {
    pub name: String,
    pub endpoint_url: String,
    pub region: Option<String>,
    pub cache_size_bytes: Option<i64>,
    pub sync_filter: Option<serde_json::Value>,
}

#[derive(Debug, Serialize)]
pub struct EdgeNodeResponse {
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
}

#[derive(Debug, Serialize)]
pub struct EdgeNodeListResponse {
    pub items: Vec<EdgeNodeResponse>,
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
    pub priority_override: Option<String>,
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

fn parse_status(s: &str) -> Option<EdgeStatus> {
    match s.to_lowercase().as_str() {
        "online" => Some(EdgeStatus::Online),
        "offline" => Some(EdgeStatus::Offline),
        "syncing" => Some(EdgeStatus::Syncing),
        "degraded" => Some(EdgeStatus::Degraded),
        _ => None,
    }
}

/// List edge nodes
pub async fn list_edge_nodes(
    State(state): State<SharedState>,
    Query(query): Query<ListEdgeNodesQuery>,
) -> Result<Json<EdgeNodeListResponse>> {
    let page = query.page.unwrap_or(1).max(1);
    let per_page = query.per_page.unwrap_or(20).min(100);
    let offset = ((page - 1) * per_page) as i64;

    let status_filter = query.status.as_ref().and_then(|s| parse_status(s));

    let service = EdgeService::new(state.db.clone());
    let (nodes, total) = service
        .list(
            status_filter,
            query.region.as_deref(),
            offset,
            per_page as i64,
        )
        .await?;

    let items: Vec<EdgeNodeResponse> = nodes
        .into_iter()
        .map(|n| {
            let usage_percent = if n.cache_size_bytes > 0 {
                (n.cache_used_bytes as f64 / n.cache_size_bytes as f64) * 100.0
            } else {
                0.0
            };
            EdgeNodeResponse {
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
            }
        })
        .collect();

    Ok(Json(EdgeNodeListResponse { items, total }))
}

/// Register new edge node
pub async fn register_edge_node(
    State(state): State<SharedState>,
    Extension(_auth): Extension<AuthExtension>,
    Json(payload): Json<RegisterEdgeNodeRequest>,
) -> Result<Json<EdgeNodeResponse>> {
    let service = EdgeService::new(state.db.clone());

    let node = service
        .register(ServiceRegisterReq {
            name: payload.name,
            endpoint_url: payload.endpoint_url,
            region: payload.region,
            cache_size_bytes: payload.cache_size_bytes.unwrap_or(10 * 1024 * 1024 * 1024), // 10GB default
            sync_filter: payload.sync_filter,
        })
        .await?;

    let usage_percent = if node.cache_size_bytes > 0 {
        (node.cache_used_bytes as f64 / node.cache_size_bytes as f64) * 100.0
    } else {
        0.0
    };

    Ok(Json(EdgeNodeResponse {
        id: node.id,
        name: node.name,
        endpoint_url: node.endpoint_url,
        status: node.status.to_string(),
        region: node.region,
        cache_size_bytes: node.cache_size_bytes,
        cache_used_bytes: node.cache_used_bytes,
        cache_usage_percent: usage_percent,
        last_heartbeat_at: node.last_heartbeat_at,
        last_sync_at: node.last_sync_at,
        created_at: node.created_at,
    }))
}

/// Get edge node details
pub async fn get_edge_node(
    State(state): State<SharedState>,
    Path(id): Path<Uuid>,
) -> Result<Json<EdgeNodeResponse>> {
    let service = EdgeService::new(state.db.clone());
    let node = service.get_by_id(id).await?;

    let usage_percent = if node.cache_size_bytes > 0 {
        (node.cache_used_bytes as f64 / node.cache_size_bytes as f64) * 100.0
    } else {
        0.0
    };

    Ok(Json(EdgeNodeResponse {
        id: node.id,
        name: node.name,
        endpoint_url: node.endpoint_url,
        status: node.status.to_string(),
        region: node.region,
        cache_size_bytes: node.cache_size_bytes,
        cache_used_bytes: node.cache_used_bytes,
        cache_usage_percent: usage_percent,
        last_heartbeat_at: node.last_heartbeat_at,
        last_sync_at: node.last_sync_at,
        created_at: node.created_at,
    }))
}

/// Unregister edge node
pub async fn unregister_edge_node(
    State(state): State<SharedState>,
    Extension(_auth): Extension<AuthExtension>,
    Path(id): Path<Uuid>,
) -> Result<()> {
    let service = EdgeService::new(state.db.clone());
    service.unregister(id).await?;
    Ok(())
}

/// Heartbeat from edge node
pub async fn heartbeat(
    State(state): State<SharedState>,
    Path(id): Path<Uuid>,
    Json(payload): Json<HeartbeatRequest>,
) -> Result<()> {
    let status = payload.status.as_ref().and_then(|s| parse_status(s));
    let service = EdgeService::new(state.db.clone());
    service
        .heartbeat(id, payload.cache_used_bytes, status)
        .await?;
    Ok(())
}

/// Trigger sync for edge node
pub async fn trigger_sync(
    State(state): State<SharedState>,
    Extension(_auth): Extension<AuthExtension>,
    Path(id): Path<Uuid>,
) -> Result<()> {
    let service = EdgeService::new(state.db.clone());
    service.update_sync_status(id, false).await?;
    Ok(())
}

/// Get pending sync tasks for edge node
pub async fn get_sync_tasks(
    State(state): State<SharedState>,
    Path(id): Path<Uuid>,
    Query(query): Query<ListEdgeNodesQuery>,
) -> Result<Json<Vec<SyncTaskResponse>>> {
    let limit = query.per_page.unwrap_or(50) as i64;
    let service = EdgeService::new(state.db.clone());
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

/// Get assigned repositories for edge node
pub async fn get_assigned_repos(
    State(state): State<SharedState>,
    Path(id): Path<Uuid>,
) -> Result<Json<Vec<Uuid>>> {
    let service = EdgeService::new(state.db.clone());
    let repos = service.get_assigned_repositories(id).await?;
    Ok(Json(repos))
}

/// Assign repository to edge node
pub async fn assign_repo(
    State(state): State<SharedState>,
    Extension(_auth): Extension<AuthExtension>,
    Path(id): Path<Uuid>,
    Json(payload): Json<AssignRepoRequest>,
) -> Result<()> {
    let priority_override =
        payload
            .priority_override
            .as_ref()
            .and_then(|s| match s.to_lowercase().as_str() {
                "immediate" => Some(ReplicationPriority::Immediate),
                "scheduled" => Some(ReplicationPriority::Scheduled),
                "on_demand" => Some(ReplicationPriority::OnDemand),
                "local_only" => Some(ReplicationPriority::LocalOnly),
                _ => None,
            });

    let service = EdgeService::new(state.db.clone());
    service
        .assign_repository(
            id,
            payload.repository_id,
            payload.sync_enabled.unwrap_or(true),
            priority_override,
            payload.replication_schedule,
        )
        .await?;
    Ok(())
}

/// Unassign repository from edge node
pub async fn unassign_repo(
    State(state): State<SharedState>,
    Extension(_auth): Extension<AuthExtension>,
    Path((id, repo_id)): Path<(Uuid, Uuid)>,
) -> Result<()> {
    let service = EdgeService::new(state.db.clone());
    service.unassign_repository(id, repo_id).await?;
    Ok(())
}
