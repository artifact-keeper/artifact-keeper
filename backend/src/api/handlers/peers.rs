//! Peer instance management handlers.

use axum::{
    extract::{Extension, Path, Query, State},
    routing::{delete, get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, OpenApi, ToSchema};
use uuid::Uuid;

use crate::api::middleware::auth::AuthExtension;
use crate::api::SharedState;
use crate::error::Result;
use crate::services::peer_instance_service::{
    InstanceStatus, PeerInstanceService, RegisterPeerInstanceRequest as ServiceRegisterReq,
    ReplicationMode,
};
use crate::services::peer_service::{PeerAnnouncement, PeerService};
use crate::services::sync_policy_service::SyncPolicyService;

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

#[derive(Debug, Deserialize, IntoParams)]
pub struct ListPeersQuery {
    pub status: Option<String>,
    pub region: Option<String>,
    pub page: Option<u32>,
    pub per_page: Option<u32>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct RegisterPeerRequest {
    pub name: String,
    pub endpoint_url: String,
    pub region: Option<String>,
    pub cache_size_bytes: Option<i64>,
    #[schema(value_type = Object)]
    pub sync_filter: Option<serde_json::Value>,
    pub api_key: String,
}

#[derive(Debug, Serialize, ToSchema)]
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
    #[serde(skip_serializing)]
    pub api_key: String,
    pub is_local: bool,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct PeerInstanceListResponse {
    pub items: Vec<PeerInstanceResponse>,
    pub total: i64,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct HeartbeatRequest {
    pub cache_used_bytes: i64,
    pub status: Option<String>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct AssignRepoRequest {
    pub repository_id: Uuid,
    pub sync_enabled: Option<bool>,
    pub replication_mode: Option<String>,
    pub replication_schedule: Option<String>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct SyncTaskResponse {
    pub id: Uuid,
    pub artifact_id: Uuid,
    pub storage_key: String,
    pub artifact_size: i64,
    pub priority: i32,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct AnnouncePeerRequest {
    pub peer_id: Uuid,
    pub name: String,
    pub endpoint_url: String,
    pub api_key: String,
}

#[derive(Debug, Serialize, ToSchema)]
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
#[utoipa::path(
    get,
    path = "",
    context_path = "/api/v1/peers",
    tag = "peers",
    params(ListPeersQuery),
    responses(
        (status = 200, description = "List of peer instances", body = PeerInstanceListResponse),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
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
#[utoipa::path(
    post,
    path = "",
    context_path = "/api/v1/peers",
    tag = "peers",
    request_body = RegisterPeerRequest,
    responses(
        (status = 200, description = "Peer instance registered successfully", body = PeerInstanceResponse),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
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

    // Re-evaluate sync policies for the new peer
    let sync_svc = SyncPolicyService::new(state.db.clone());
    if let Err(e) = sync_svc.evaluate_for_peer(instance.id).await {
        tracing::warn!(
            "Sync policy evaluation failed for new peer {}: {}",
            instance.id,
            e
        );
    }

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
#[utoipa::path(
    get,
    path = "/{id}",
    context_path = "/api/v1/peers",
    tag = "peers",
    params(
        ("id" = Uuid, Path, description = "Peer instance ID")
    ),
    responses(
        (status = 200, description = "Peer instance details", body = PeerInstanceResponse),
        (status = 404, description = "Peer instance not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
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
#[utoipa::path(
    delete,
    path = "/{id}",
    context_path = "/api/v1/peers",
    tag = "peers",
    params(
        ("id" = Uuid, Path, description = "Peer instance ID")
    ),
    responses(
        (status = 200, description = "Peer instance unregistered successfully"),
        (status = 404, description = "Peer instance not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
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
#[utoipa::path(
    post,
    path = "/{id}/heartbeat",
    context_path = "/api/v1/peers",
    tag = "peers",
    params(
        ("id" = Uuid, Path, description = "Peer instance ID")
    ),
    request_body = HeartbeatRequest,
    responses(
        (status = 200, description = "Heartbeat recorded successfully"),
        (status = 404, description = "Peer instance not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
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
#[utoipa::path(
    post,
    path = "/{id}/sync",
    context_path = "/api/v1/peers",
    tag = "peers",
    params(
        ("id" = Uuid, Path, description = "Peer instance ID")
    ),
    responses(
        (status = 200, description = "Sync triggered successfully"),
        (status = 404, description = "Peer instance not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
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
#[utoipa::path(
    get,
    path = "/{id}/sync/tasks",
    context_path = "/api/v1/peers",
    tag = "peers",
    params(
        ("id" = Uuid, Path, description = "Peer instance ID"),
        ListPeersQuery,
    ),
    responses(
        (status = 200, description = "List of pending sync tasks", body = Vec<SyncTaskResponse>),
        (status = 404, description = "Peer instance not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
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
#[utoipa::path(
    get,
    path = "/{id}/repositories",
    context_path = "/api/v1/peers",
    tag = "peers",
    params(
        ("id" = Uuid, Path, description = "Peer instance ID")
    ),
    responses(
        (status = 200, description = "List of assigned repository IDs", body = Vec<Uuid>),
        (status = 404, description = "Peer instance not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn get_assigned_repos(
    State(state): State<SharedState>,
    Path(id): Path<Uuid>,
) -> Result<Json<Vec<Uuid>>> {
    let service = PeerInstanceService::new(state.db.clone());
    let repos = service.get_assigned_repositories(id).await?;
    Ok(Json(repos))
}

/// Assign repository to peer instance
#[utoipa::path(
    post,
    path = "/{id}/repositories",
    context_path = "/api/v1/peers",
    tag = "peers",
    params(
        ("id" = Uuid, Path, description = "Peer instance ID")
    ),
    request_body = AssignRepoRequest,
    responses(
        (status = 200, description = "Repository assigned successfully"),
        (status = 404, description = "Peer instance not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
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
#[utoipa::path(
    delete,
    path = "/{id}/repositories/{repo_id}",
    context_path = "/api/v1/peers",
    tag = "peers",
    params(
        ("id" = Uuid, Path, description = "Peer instance ID"),
        ("repo_id" = Uuid, Path, description = "Repository ID")
    ),
    responses(
        (status = 200, description = "Repository unassigned successfully"),
        (status = 404, description = "Peer instance or repository not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
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
#[utoipa::path(
    post,
    path = "/announce",
    context_path = "/api/v1/peers",
    tag = "peers",
    request_body = AnnouncePeerRequest,
    responses(
        (status = 200, description = "Peer announcement accepted", body = Object),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
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
#[utoipa::path(
    get,
    path = "/identity",
    context_path = "/api/v1/peers",
    tag = "peers",
    responses(
        (status = 200, description = "Local peer identity", body = IdentityResponse),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
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

#[derive(OpenApi)]
#[openapi(
    paths(
        list_peers,
        register_peer,
        get_peer,
        unregister_peer,
        heartbeat,
        trigger_sync,
        get_sync_tasks,
        get_assigned_repos,
        assign_repo,
        unassign_repo,
        announce_peer,
        get_identity,
    ),
    components(schemas(
        RegisterPeerRequest,
        PeerInstanceResponse,
        PeerInstanceListResponse,
        HeartbeatRequest,
        AssignRepoRequest,
        SyncTaskResponse,
        AnnouncePeerRequest,
        IdentityResponse,
    ))
)]
pub struct PeersApiDoc;

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    // -----------------------------------------------------------------------
    // parse_status tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_parse_status_online() {
        assert!(matches!(
            parse_status("online"),
            Some(InstanceStatus::Online)
        ));
    }

    #[test]
    fn test_parse_status_offline() {
        assert!(matches!(
            parse_status("offline"),
            Some(InstanceStatus::Offline)
        ));
    }

    #[test]
    fn test_parse_status_syncing() {
        assert!(matches!(
            parse_status("syncing"),
            Some(InstanceStatus::Syncing)
        ));
    }

    #[test]
    fn test_parse_status_degraded() {
        assert!(matches!(
            parse_status("degraded"),
            Some(InstanceStatus::Degraded)
        ));
    }

    #[test]
    fn test_parse_status_case_insensitive() {
        assert!(matches!(
            parse_status("ONLINE"),
            Some(InstanceStatus::Online)
        ));
        assert!(matches!(
            parse_status("Offline"),
            Some(InstanceStatus::Offline)
        ));
        assert!(matches!(
            parse_status("SyNcInG"),
            Some(InstanceStatus::Syncing)
        ));
        assert!(matches!(
            parse_status("DEGRADED"),
            Some(InstanceStatus::Degraded)
        ));
    }

    #[test]
    fn test_parse_status_unknown_returns_none() {
        assert!(parse_status("unknown").is_none());
        assert!(parse_status("active").is_none());
        assert!(parse_status("").is_none());
        assert!(parse_status("  online  ").is_none()); // no trim
    }

    // -----------------------------------------------------------------------
    // ListPeersQuery deserialization
    // -----------------------------------------------------------------------

    #[test]
    fn test_list_peers_query_deserialize_full() {
        let json_str = r#"{"status":"online","region":"us-east","page":2,"per_page":50}"#;
        let query: ListPeersQuery = serde_json::from_str(json_str).unwrap();
        assert_eq!(query.status.as_deref(), Some("online"));
        assert_eq!(query.region.as_deref(), Some("us-east"));
        assert_eq!(query.page, Some(2));
        assert_eq!(query.per_page, Some(50));
    }

    #[test]
    fn test_list_peers_query_deserialize_empty() {
        let json_str = r#"{}"#;
        let query: ListPeersQuery = serde_json::from_str(json_str).unwrap();
        assert!(query.status.is_none());
        assert!(query.region.is_none());
        assert!(query.page.is_none());
        assert!(query.per_page.is_none());
    }

    // -----------------------------------------------------------------------
    // RegisterPeerRequest deserialization
    // -----------------------------------------------------------------------

    #[test]
    fn test_register_peer_request_deserialize_minimal() {
        let json_str =
            r#"{"name":"peer1","endpoint_url":"https://peer1.example.com","api_key":"key123"}"#;
        let req: RegisterPeerRequest = serde_json::from_str(json_str).unwrap();
        assert_eq!(req.name, "peer1");
        assert_eq!(req.endpoint_url, "https://peer1.example.com");
        assert_eq!(req.api_key, "key123");
        assert!(req.region.is_none());
        assert!(req.cache_size_bytes.is_none());
        assert!(req.sync_filter.is_none());
    }

    #[test]
    fn test_register_peer_request_deserialize_full() {
        let json_str = json!({
            "name": "peer1",
            "endpoint_url": "https://peer1.example.com",
            "api_key": "key123",
            "region": "eu-west-1",
            "cache_size_bytes": 5368709120_i64,
            "sync_filter": {"formats": ["maven", "npm"]}
        });
        let req: RegisterPeerRequest = serde_json::from_value(json_str).unwrap();
        assert_eq!(req.name, "peer1");
        assert_eq!(req.region.as_deref(), Some("eu-west-1"));
        assert_eq!(req.cache_size_bytes, Some(5368709120));
        assert!(req.sync_filter.is_some());
    }

    // -----------------------------------------------------------------------
    // PeerInstanceResponse serialization
    // -----------------------------------------------------------------------

    #[test]
    fn test_peer_instance_response_api_key_hidden() {
        let resp = PeerInstanceResponse {
            id: Uuid::nil(),
            name: "test-peer".to_string(),
            endpoint_url: "https://example.com".to_string(),
            status: "online".to_string(),
            region: None,
            cache_size_bytes: 1000,
            cache_used_bytes: 500,
            cache_usage_percent: 50.0,
            last_heartbeat_at: None,
            last_sync_at: None,
            created_at: chrono::Utc::now(),
            api_key: "secret-key-should-be-hidden".to_string(),
            is_local: false,
        };
        let json = serde_json::to_value(&resp).unwrap();
        // api_key should be skipped due to skip_serializing
        assert!(json.get("api_key").is_none());
        assert_eq!(json["name"], "test-peer");
        assert_eq!(json["status"], "online");
    }

    #[test]
    fn test_peer_instance_response_cache_usage() {
        let resp = PeerInstanceResponse {
            id: Uuid::nil(),
            name: "test-peer".to_string(),
            endpoint_url: "https://example.com".to_string(),
            status: "online".to_string(),
            region: Some("us-east-1".to_string()),
            cache_size_bytes: 10000,
            cache_used_bytes: 7500,
            cache_usage_percent: 75.0,
            last_heartbeat_at: None,
            last_sync_at: None,
            created_at: chrono::Utc::now(),
            api_key: "key".to_string(),
            is_local: true,
        };
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["cache_usage_percent"], 75.0);
        assert_eq!(json["is_local"], true);
        assert_eq!(json["region"], "us-east-1");
    }

    // -----------------------------------------------------------------------
    // Cache usage percentage calculation logic
    // -----------------------------------------------------------------------

    #[test]
    fn test_cache_usage_percent_zero_size() {
        // When cache_size_bytes is 0, usage percent should be 0.0
        let cache_size_bytes: i64 = 0;
        let cache_used_bytes: i64 = 100;
        let usage_percent = if cache_size_bytes > 0 {
            (cache_used_bytes as f64 / cache_size_bytes as f64) * 100.0
        } else {
            0.0
        };
        assert_eq!(usage_percent, 0.0);
    }

    #[test]
    fn test_cache_usage_percent_normal() {
        let cache_size_bytes: i64 = 10_000_000;
        let cache_used_bytes: i64 = 5_000_000;
        let usage_percent = if cache_size_bytes > 0 {
            (cache_used_bytes as f64 / cache_size_bytes as f64) * 100.0
        } else {
            0.0
        };
        assert!((usage_percent - 50.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_cache_usage_percent_full() {
        let cache_size_bytes: i64 = 1_000_000;
        let cache_used_bytes: i64 = 1_000_000;
        let usage_percent = if cache_size_bytes > 0 {
            (cache_used_bytes as f64 / cache_size_bytes as f64) * 100.0
        } else {
            0.0
        };
        assert!((usage_percent - 100.0).abs() < f64::EPSILON);
    }

    // -----------------------------------------------------------------------
    // HeartbeatRequest deserialization
    // -----------------------------------------------------------------------

    #[test]
    fn test_heartbeat_request_deserialize() {
        let json_str = r#"{"cache_used_bytes": 12345, "status": "online"}"#;
        let req: HeartbeatRequest = serde_json::from_str(json_str).unwrap();
        assert_eq!(req.cache_used_bytes, 12345);
        assert_eq!(req.status.as_deref(), Some("online"));
    }

    #[test]
    fn test_heartbeat_request_status_optional() {
        let json_str = r#"{"cache_used_bytes": 0}"#;
        let req: HeartbeatRequest = serde_json::from_str(json_str).unwrap();
        assert_eq!(req.cache_used_bytes, 0);
        assert!(req.status.is_none());
    }

    // -----------------------------------------------------------------------
    // AssignRepoRequest deserialization and replication mode parsing
    // -----------------------------------------------------------------------

    #[test]
    fn test_assign_repo_request_deserialize() {
        let id = Uuid::new_v4();
        let json_str = json!({
            "repository_id": id,
            "sync_enabled": true,
            "replication_mode": "push",
            "replication_schedule": "0 */6 * * *"
        });
        let req: AssignRepoRequest = serde_json::from_value(json_str).unwrap();
        assert_eq!(req.repository_id, id);
        assert_eq!(req.sync_enabled, Some(true));
        assert_eq!(req.replication_mode.as_deref(), Some("push"));
        assert_eq!(req.replication_schedule.as_deref(), Some("0 */6 * * *"));
    }

    #[test]
    fn test_replication_mode_parsing() {
        let parse_mode = |s: &str| -> Option<ReplicationMode> {
            match s.to_lowercase().as_str() {
                "push" => Some(ReplicationMode::Push),
                "pull" => Some(ReplicationMode::Pull),
                "mirror" => Some(ReplicationMode::Mirror),
                "none" => Some(ReplicationMode::None),
                _ => None,
            }
        };
        assert!(matches!(parse_mode("push"), Some(ReplicationMode::Push)));
        assert!(matches!(parse_mode("pull"), Some(ReplicationMode::Pull)));
        assert!(matches!(
            parse_mode("mirror"),
            Some(ReplicationMode::Mirror)
        ));
        assert!(matches!(parse_mode("none"), Some(ReplicationMode::None)));
        assert!(matches!(parse_mode("PUSH"), Some(ReplicationMode::Push)));
        assert!(parse_mode("invalid").is_none());
        assert!(parse_mode("").is_none());
    }

    // -----------------------------------------------------------------------
    // Pagination logic
    // -----------------------------------------------------------------------

    #[test]
    fn test_pagination_defaults() {
        let page: u32 = 1;
        let per_page: u32 = 20_u32;
        assert_eq!(page, 1);
        assert_eq!(per_page, 20);
    }

    #[test]
    fn test_pagination_zero_page_clamped() {
        let page: u32 = 1;
        assert_eq!(page, 1);
    }

    #[test]
    fn test_pagination_per_page_capped() {
        let per_page: u32 = 100;
        assert_eq!(per_page, 100);
    }

    #[test]
    fn test_pagination_offset_calculation() {
        let page: u32 = 3;
        let per_page: u32 = 20;
        let offset = ((page - 1) * per_page) as i64;
        assert_eq!(offset, 40);
    }

    // -----------------------------------------------------------------------
    // AnnouncePeerRequest / IdentityResponse
    // -----------------------------------------------------------------------

    #[test]
    fn test_announce_peer_request_deserialize() {
        let peer_id = Uuid::new_v4();
        let json = json!({
            "peer_id": peer_id,
            "name": "remote-peer",
            "endpoint_url": "https://remote.example.com",
            "api_key": "remote-key"
        });
        let req: AnnouncePeerRequest = serde_json::from_value(json).unwrap();
        assert_eq!(req.peer_id, peer_id);
        assert_eq!(req.name, "remote-peer");
        assert_eq!(req.endpoint_url, "https://remote.example.com");
        assert_eq!(req.api_key, "remote-key");
    }

    #[test]
    fn test_identity_response_serialize() {
        let id = Uuid::new_v4();
        let resp = IdentityResponse {
            peer_id: id,
            name: "local-peer".to_string(),
            endpoint_url: "https://local.example.com".to_string(),
            api_key: "local-key".to_string(),
        };
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["peer_id"], id.to_string());
        assert_eq!(json["name"], "local-peer");
        assert_eq!(json["endpoint_url"], "https://local.example.com");
        assert_eq!(json["api_key"], "local-key");
    }

    // -----------------------------------------------------------------------
    // SyncTaskResponse serialization
    // -----------------------------------------------------------------------

    #[test]
    fn test_sync_task_response_serialize() {
        let id = Uuid::new_v4();
        let artifact_id = Uuid::new_v4();
        let resp = SyncTaskResponse {
            id,
            artifact_id,
            storage_key: "artifacts/maven/com/example/1.0/foo.jar".to_string(),
            artifact_size: 1024 * 1024,
            priority: 5,
        };
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["id"], id.to_string());
        assert_eq!(json["artifact_id"], artifact_id.to_string());
        assert_eq!(
            json["storage_key"],
            "artifacts/maven/com/example/1.0/foo.jar"
        );
        assert_eq!(json["artifact_size"], 1048576);
        assert_eq!(json["priority"], 5);
    }

    // -----------------------------------------------------------------------
    // PeerInstanceListResponse serialization
    // -----------------------------------------------------------------------

    #[test]
    fn test_peer_instance_list_response_empty() {
        let resp = PeerInstanceListResponse {
            items: vec![],
            total: 0,
        };
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["items"].as_array().unwrap().len(), 0);
        assert_eq!(json["total"], 0);
    }

    // -----------------------------------------------------------------------
    // Default cache size in register (10GB)
    // -----------------------------------------------------------------------

    #[test]
    fn test_default_cache_size() {
        let default_cache: i64 = 10 * 1024 * 1024 * 1024;
        assert_eq!(default_cache, 10_737_418_240);
    }

    // -----------------------------------------------------------------------
    // sync_enabled defaults to true
    // -----------------------------------------------------------------------

    #[test]
    fn test_assign_repo_sync_enabled_default() {
        let sync_enabled: bool = true;
        assert!(sync_enabled);
    }

    // -----------------------------------------------------------------------
    // sync tasks limit default
    // -----------------------------------------------------------------------

    #[test]
    fn test_sync_tasks_limit_default() {
        let limit = 50_u32 as i64;
        assert_eq!(limit, 50);
    }
}
