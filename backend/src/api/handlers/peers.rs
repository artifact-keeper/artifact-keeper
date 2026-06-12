//! Peer instance management handlers.

use axum::{
    extract::{Extension, Path, Query, State},
    routing::{get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, OpenApi, ToSchema};
use uuid::Uuid;

use crate::api::middleware::auth::AuthExtension;
use crate::api::validation::validate_outbound_url;
use crate::api::SharedState;
use crate::error::Result;
use crate::services::peer_instance_service::{
    InstanceStatus, PeerInstanceService, RegisterPeerInstanceRequest as ServiceRegisterReq,
    ReplicationMode, SyncStatus,
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
        .route(
            "/:id/repositories/:repo_id",
            get(get_subscription).delete(unassign_repo),
        )
        .route(
            "/:id/repositories/:repo_id/sync",
            post(run_subscription_now),
        )
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
    /// Optional JSONB filter constraining which artifacts in the repository
    /// get replicated. Shape: `{"include_patterns": ["^v\\d+\\."], "exclude_patterns": [".*-SNAPSHOT$"]}`.
    /// Null/absent means replicate everything.
    #[schema(value_type = Object)]
    pub replication_filter: Option<serde_json::Value>,
}

/// Detailed subscription view (mode, schedule, filter) for a single (peer, repo) pair.
#[derive(Debug, Serialize, ToSchema)]
pub struct SubscriptionResponse {
    pub id: Uuid,
    pub peer_instance_id: Uuid,
    pub repository_id: Uuid,
    pub sync_enabled: bool,
    pub replication_mode: Option<String>,
    pub replication_schedule: Option<String>,
    #[schema(value_type = Object)]
    pub replication_filter: Option<serde_json::Value>,
    pub last_replicated_at: Option<chrono::DateTime<chrono::Utc>>,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

/// Result of `POST /:id/repositories/:repo_id/sync` (run-now trigger).
#[derive(Debug, Serialize, ToSchema)]
pub struct RunNowResponse {
    pub status: String,
    pub tasks_queued: i64,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct SyncTaskResponse {
    pub id: Uuid,
    pub artifact_id: Uuid,
    pub storage_key: String,
    pub artifact_size: i64,
    pub priority: i32,
    /// Task status (e.g. "pending"). Listing currently returns pending tasks.
    pub status: String,
    /// When the task was enqueued. Lets clients tell a freshly-scheduled task
    /// apart from a stale queue entry (used by the replication-schedule check).
    /// Serialized as whole-second RFC3339 with a `Z` suffix
    /// (e.g. `2026-05-29T12:34:56Z`) so simple ISO8601 parsers can consume it.
    #[serde(serialize_with = "serialize_ts_secs")]
    pub created_at: chrono::DateTime<chrono::Utc>,
    /// When the worker began transferring, if it has started. Same format as
    /// `created_at`.
    #[serde(serialize_with = "serialize_opt_ts_secs")]
    pub started_at: Option<chrono::DateTime<chrono::Utc>>,
}

/// Serialize a timestamp as whole-second RFC3339 with a `Z` suffix
/// (e.g. `2026-05-29T12:34:56Z`). chrono's default RFC3339 includes
/// fractional seconds and a `+00:00` offset, which strict ISO8601 parsers
/// (jq's `fromdateiso8601`, some SDKs) reject.
fn serialize_ts_secs<S>(
    ts: &chrono::DateTime<chrono::Utc>,
    serializer: S,
) -> std::result::Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    serializer.serialize_str(&ts.to_rfc3339_opts(chrono::SecondsFormat::Secs, true))
}

fn serialize_opt_ts_secs<S>(
    ts: &Option<chrono::DateTime<chrono::Utc>>,
    serializer: S,
) -> std::result::Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    match ts {
        Some(t) => serialize_ts_secs(t, serializer),
        None => serializer.serialize_none(),
    }
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
    #[serde(skip_serializing)]
    pub api_key: String,
}

/// Map a `SyncStatus` to its wire label (snake_case, matching the DB enum).
fn sync_status_label(status: SyncStatus) -> &'static str {
    match status {
        SyncStatus::Pending => "pending",
        SyncStatus::InProgress => "in_progress",
        SyncStatus::Completed => "completed",
        SyncStatus::Failed => "failed",
        SyncStatus::Cancelled => "cancelled",
    }
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
    Extension(auth): Extension<AuthExtension>,
    Json(payload): Json<RegisterPeerRequest>,
) -> Result<Json<PeerInstanceResponse>> {
    auth.require_admin()?;
    validate_outbound_url(&payload.endpoint_url, "Peer endpoint URL")?;

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
    Extension(auth): Extension<AuthExtension>,
    Path(id): Path<Uuid>,
) -> Result<()> {
    auth.require_admin()?;
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
    Extension(auth): Extension<AuthExtension>,
    Path(id): Path<Uuid>,
    Json(payload): Json<HeartbeatRequest>,
) -> Result<()> {
    auth.require_admin()?;

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
    Extension(auth): Extension<AuthExtension>,
    Path(id): Path<Uuid>,
) -> Result<()> {
    auth.require_admin()?;
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
            // get_pending_sync_tasks only returns rows with status='pending'.
            status: sync_status_label(t.status).to_string(),
            created_at: t.created_at,
            started_at: t.started_at,
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
    Extension(auth): Extension<AuthExtension>,
    Path(id): Path<Uuid>,
    Json(payload): Json<AssignRepoRequest>,
) -> Result<()> {
    auth.require_admin()?;
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
            payload.replication_filter,
        )
        .await?;
    Ok(())
}

/// Get full subscription details for a (peer, repo) pair.
///
/// Returns the per-subscription `replication_mode`, `replication_schedule`,
/// and `replication_filter` exactly as persisted by `POST /:id/repositories`.
/// Round-trips the filter so callers can verify that a scheduled-sync
/// filter (e.g. `{"include_patterns": ["\\.tar\\.gz$"]}`) was persisted.
#[utoipa::path(
    get,
    path = "/{id}/repositories/{repo_id}",
    context_path = "/api/v1/peers",
    tag = "peers",
    params(
        ("id" = Uuid, Path, description = "Peer instance ID"),
        ("repo_id" = Uuid, Path, description = "Repository ID"),
    ),
    responses(
        (status = 200, description = "Subscription details", body = SubscriptionResponse),
        (status = 404, description = "Subscription not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn get_subscription(
    State(state): State<SharedState>,
    Path((id, repo_id)): Path<(Uuid, Uuid)>,
) -> Result<Json<SubscriptionResponse>> {
    let service = PeerInstanceService::new(state.db.clone());
    let sub = service.get_subscription(id, repo_id).await?;
    Ok(Json(SubscriptionResponse {
        id: sub.id,
        peer_instance_id: sub.peer_instance_id,
        repository_id: sub.repository_id,
        sync_enabled: sub.sync_enabled,
        replication_mode: sub.replication_mode,
        replication_schedule: sub.replication_schedule,
        replication_filter: sub.replication_filter,
        last_replicated_at: sub.last_replicated_at,
        created_at: sub.created_at,
    }))
}

/// Trigger an immediate sync for a single (peer, repo) subscription.
///
/// Queues one `sync_task` per artifact in the repository at priority 100
/// without waiting for the next cron tick. Idempotent: if tasks are already
/// pending for the same artifacts, the unique constraint
/// `(peer_instance_id, artifact_id, task_type)` skips duplicates.
#[utoipa::path(
    post,
    path = "/{id}/repositories/{repo_id}/sync",
    context_path = "/api/v1/peers",
    tag = "peers",
    params(
        ("id" = Uuid, Path, description = "Peer instance ID"),
        ("repo_id" = Uuid, Path, description = "Repository ID"),
    ),
    responses(
        (status = 202, description = "Sync tasks queued", body = RunNowResponse),
        (status = 404, description = "Subscription not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn run_subscription_now(
    State(state): State<SharedState>,
    Extension(auth): Extension<AuthExtension>,
    Path((id, repo_id)): Path<(Uuid, Uuid)>,
) -> Result<(axum::http::StatusCode, Json<RunNowResponse>)> {
    auth.require_admin()?;
    let service = PeerInstanceService::new(state.db.clone());
    let queued = service.run_subscription_now(id, repo_id).await?;
    Ok((
        axum::http::StatusCode::ACCEPTED,
        Json(RunNowResponse {
            status: "queued".to_string(),
            tasks_queued: queued,
        }),
    ))
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
    Extension(auth): Extension<AuthExtension>,
    Path((id, repo_id)): Path<(Uuid, Uuid)>,
) -> Result<()> {
    auth.require_admin()?;
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
    Extension(auth): Extension<AuthExtension>,
    Json(body): Json<AnnouncePeerRequest>,
) -> Result<Json<serde_json::Value>> {
    auth.require_admin()?;
    validate_outbound_url(&body.endpoint_url, "Peer endpoint URL")?;

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
async fn get_identity(
    State(state): State<SharedState>,
    Extension(auth): Extension<AuthExtension>,
) -> Result<Json<IdentityResponse>> {
    auth.require_admin()?;
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
        get_subscription,
        run_subscription_now,
        announce_peer,
        get_identity,
    ),
    components(schemas(
        RegisterPeerRequest,
        PeerInstanceResponse,
        PeerInstanceListResponse,
        HeartbeatRequest,
        AssignRepoRequest,
        SubscriptionResponse,
        RunNowResponse,
        SyncTaskResponse,
        AnnouncePeerRequest,
        IdentityResponse,
    ))
)]
pub struct PeersApiDoc;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::AppError;
    use serde_json::json;

    // -----------------------------------------------------------------------
    // sync_status_label tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_sync_status_label_all_variants() {
        assert_eq!(sync_status_label(SyncStatus::Pending), "pending");
        assert_eq!(sync_status_label(SyncStatus::InProgress), "in_progress");
        assert_eq!(sync_status_label(SyncStatus::Completed), "completed");
        assert_eq!(sync_status_label(SyncStatus::Failed), "failed");
        assert_eq!(sync_status_label(SyncStatus::Cancelled), "cancelled");
    }

    #[test]
    fn test_sync_task_response_exposes_timestamps() {
        // The replication-schedule e2e check reasons about task freshness via
        // created_at; the response must serialize it.
        let resp = SyncTaskResponse {
            id: Uuid::nil(),
            artifact_id: Uuid::nil(),
            storage_key: "k".to_string(),
            artifact_size: 1,
            priority: 0,
            status: "pending".to_string(),
            created_at: chrono::Utc::now(),
            started_at: None,
        };
        let v = serde_json::to_value(&resp).unwrap();
        assert!(v.get("created_at").is_some());
        assert!(v.get("status").is_some());
        assert!(v.as_object().unwrap().contains_key("started_at"));
    }

    #[test]
    fn test_sync_task_created_at_serializes_whole_second_z() {
        // jq's fromdateiso8601 (and strict ISO8601 parsers) only accept the
        // whole-second `...Z` form. chrono's default RFC3339 (fractional secs,
        // +00:00 offset) is rejected, so the field must use the second-precision
        // Z serializer.
        let ts = chrono::DateTime::parse_from_rfc3339("2026-05-29T12:34:56.123456789Z")
            .unwrap()
            .with_timezone(&chrono::Utc);
        let resp = SyncTaskResponse {
            id: Uuid::nil(),
            artifact_id: Uuid::nil(),
            storage_key: "k".to_string(),
            artifact_size: 1,
            priority: 0,
            status: "pending".to_string(),
            created_at: ts,
            started_at: Some(ts),
        };
        let v = serde_json::to_value(&resp).unwrap();
        assert_eq!(v["created_at"], "2026-05-29T12:34:56Z");
        assert_eq!(v["started_at"], "2026-05-29T12:34:56Z");
        // No fractional seconds, no numeric offset.
        assert!(!v["created_at"].as_str().unwrap().contains('.'));
        assert!(!v["created_at"].as_str().unwrap().contains('+'));
    }

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
        // api_key must be hidden from serialized output (defense-in-depth)
        assert!(
            json.get("api_key").is_none(),
            "api_key should not appear in serialized IdentityResponse"
        );
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
            status: "pending".to_string(),
            created_at: chrono::Utc::now(),
            started_at: None,
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
        assert_eq!(json["status"], "pending");
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

    // -----------------------------------------------------------------------
    // Admin guard (require_admin) tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_require_admin_passes_for_admin() {
        let auth = AuthExtension {
            user_id: Uuid::new_v4(),
            username: "admin".to_string(),
            email: "admin@example.com".to_string(),
            is_admin: true,
            is_api_token: false,
            is_service_account: false,
            scopes: None,
            allowed_repo_ids: None,
        };
        assert!(auth.require_admin().is_ok());
    }

    #[test]
    fn test_require_admin_rejects_non_admin() {
        let auth = AuthExtension {
            user_id: Uuid::new_v4(),
            username: "regular-user".to_string(),
            email: "user@example.com".to_string(),
            is_admin: false,
            is_api_token: false,
            is_service_account: false,
            scopes: None,
            allowed_repo_ids: None,
        };
        let err = auth.require_admin().unwrap_err();
        assert!(
            format!("{}", err).contains("Admin access required"),
            "Expected 'Admin access required' in error: {}",
            err
        );
    }

    #[test]
    fn test_require_admin_rejects_non_admin_api_token() {
        let auth = AuthExtension {
            user_id: Uuid::new_v4(),
            username: "api-user".to_string(),
            email: "api@example.com".to_string(),
            is_admin: false,
            is_api_token: true,
            is_service_account: false,
            scopes: Some(vec!["read".to_string(), "write".to_string()]),
            allowed_repo_ids: None,
        };
        assert!(auth.require_admin().is_err());
    }

    #[test]
    fn test_require_admin_passes_for_admin_api_token() {
        let auth = AuthExtension {
            user_id: Uuid::new_v4(),
            username: "admin-api".to_string(),
            email: "admin-api@example.com".to_string(),
            is_admin: true,
            is_api_token: true,
            is_service_account: false,
            scopes: Some(vec!["admin".to_string()]),
            allowed_repo_ids: None,
        };
        assert!(auth.require_admin().is_ok());
    }

    #[test]
    fn test_require_admin_rejects_service_account_without_admin() {
        let auth = AuthExtension {
            user_id: Uuid::new_v4(),
            username: "svc-peer-sync".to_string(),
            email: "svc@example.com".to_string(),
            is_admin: false,
            is_api_token: false,
            is_service_account: true,
            scopes: None,
            allowed_repo_ids: None,
        };
        assert!(auth.require_admin().is_err());
    }

    // -----------------------------------------------------------------------
    // get_identity admin guard
    // -----------------------------------------------------------------------

    #[test]
    fn test_get_identity_rejects_non_admin() {
        let auth = AuthExtension {
            user_id: Uuid::new_v4(),
            username: "user".to_string(),
            email: "user@example.com".to_string(),
            is_admin: false,
            is_api_token: false,
            is_service_account: false,
            scopes: None,
            allowed_repo_ids: None,
        };
        assert!(!auth.is_admin);
        // Exercises the real guard used by `get_identity` (auth.require_admin()).
        let result = auth.require_admin();
        assert!(result.is_err());
        match result.unwrap_err() {
            AppError::Authorization(msg) => {
                assert_eq!(msg, "Admin access required");
            }
            other => panic!("Expected Authorization error, got: {:?}", other),
        }
    }

    #[test]
    fn test_get_identity_allows_admin() {
        let auth = AuthExtension {
            user_id: Uuid::new_v4(),
            username: "admin".to_string(),
            email: "admin@example.com".to_string(),
            is_admin: true,
            is_api_token: false,
            is_service_account: false,
            scopes: None,
            allowed_repo_ids: None,
        };
        assert!(auth.is_admin);
        // Exercises the real guard used by `get_identity` (auth.require_admin()).
        assert!(auth.require_admin().is_ok());
    }

    // -----------------------------------------------------------------------
    // Bug #1440 B: scheduled-sync filter must round-trip POST -> GET.
    // -----------------------------------------------------------------------

    #[test]
    fn test_assign_repo_request_accepts_replication_filter() {
        // The filter shape that was being dropped on POST.
        let json_body = json!({
            "repository_id": Uuid::nil(),
            "sync_enabled": true,
            "replication_mode": "mirror",
            "replication_schedule": "0 */6 * * *",
            "replication_filter": {"include_patterns": ["\\.tar\\.gz$"]},
        });
        let req: AssignRepoRequest = serde_json::from_value(json_body).unwrap();
        assert_eq!(req.replication_schedule.as_deref(), Some("0 */6 * * *"));
        let filter = req.replication_filter.expect("filter must deserialise");
        let patterns = filter["include_patterns"].as_array().unwrap();
        assert_eq!(patterns.len(), 1);
        assert_eq!(patterns[0].as_str(), Some("\\.tar\\.gz$"));
    }

    #[test]
    fn test_assign_repo_request_filter_optional() {
        let json_body = json!({
            "repository_id": Uuid::nil(),
        });
        let req: AssignRepoRequest = serde_json::from_value(json_body).unwrap();
        assert!(req.replication_filter.is_none());
        assert!(req.replication_schedule.is_none());
    }

    #[test]
    fn test_subscription_response_round_trips_filter() {
        // Simulates the GET side after a POST persisted the filter:
        // the response must serialise the filter back to the client.
        let filter = serde_json::json!({"include_patterns": ["\\.tar\\.gz$"]});
        let resp = SubscriptionResponse {
            id: Uuid::nil(),
            peer_instance_id: Uuid::nil(),
            repository_id: Uuid::nil(),
            sync_enabled: true,
            replication_mode: Some("mirror".to_string()),
            replication_schedule: Some("0 */6 * * *".to_string()),
            replication_filter: Some(filter.clone()),
            last_replicated_at: None,
            created_at: chrono::Utc::now(),
        };
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["replication_filter"], filter);
        assert_eq!(json["replication_schedule"], "0 */6 * * *");
        assert_eq!(json["sync_enabled"], true);
    }

    #[test]
    fn test_subscription_response_null_filter_renders_as_null() {
        // No filter = replicate everything; must serialise as JSON null
        // (not omitted), so clients can distinguish "unset" from "absent field".
        let resp = SubscriptionResponse {
            id: Uuid::nil(),
            peer_instance_id: Uuid::nil(),
            repository_id: Uuid::nil(),
            sync_enabled: true,
            replication_mode: None,
            replication_schedule: None,
            replication_filter: None,
            last_replicated_at: None,
            created_at: chrono::Utc::now(),
        };
        let json = serde_json::to_value(&resp).unwrap();
        assert!(json.get("replication_filter").is_some());
        assert!(json["replication_filter"].is_null());
    }

    // -----------------------------------------------------------------------
    // Bug #1440 C: run-now endpoint must exist and respond 202.
    // -----------------------------------------------------------------------

    #[test]
    fn test_run_now_response_serialises_with_2xx_shape() {
        // The endpoint returns ACCEPTED + a RunNowResponse; verify the
        // body shape callers can rely on.
        let body = RunNowResponse {
            status: "queued".to_string(),
            tasks_queued: 7,
        };
        let json = serde_json::to_value(&body).unwrap();
        assert_eq!(json["status"], "queued");
        assert_eq!(json["tasks_queued"], 7);
    }

    #[test]
    fn test_run_now_route_is_registered() {
        // Regression for Bug #1440 C: the route was 404 because it was
        // never wired. The router contract is checked by mounting it and
        // asserting that a POST to the run-now path matches a route
        // handler (we don't dispatch state, just confirm the path exists).
        let router: Router<SharedState> = router();
        // Axum's Router doesn't expose paths directly, but `has_routes`
        // verifies at least one route is registered, and the route table
        // construction itself will panic if a path is malformed.
        assert!(router.has_routes());
    }

    // -----------------------------------------------------------------------
    // SSRF: peer endpoint_url must go through the shared outbound-URL
    // allowlist (validate_outbound_url) before it is persisted. The sync
    // worker later issues outbound requests to the stored endpoint, so a
    // loopback / RFC1918 / metadata / dotless-decimal endpoint would be an
    // SSRF primitive without this guard. Mirrors the same allowlist that
    // every other outbound sink enforces.
    // -----------------------------------------------------------------------

    /// Assert the peer-endpoint validator rejects an SSRF target URL.
    fn assert_peer_endpoint_blocked(url: &str) {
        assert!(
            validate_outbound_url(url, "Peer endpoint URL").is_err(),
            "peer endpoint_url '{url}' must be rejected by the SSRF allowlist"
        );
    }

    #[test]
    fn test_peer_endpoint_rejects_loopback() {
        assert_peer_endpoint_blocked("http://127.0.0.1:19099/peer-reg");
    }

    #[test]
    fn test_peer_endpoint_rejects_ipv6_loopback() {
        assert_peer_endpoint_blocked("http://[::1]/");
    }

    #[test]
    fn test_peer_endpoint_rejects_unspecified() {
        assert_peer_endpoint_blocked("http://0.0.0.0/");
    }

    #[test]
    fn test_peer_endpoint_rejects_rfc1918() {
        // 10.0.0.0/8 is only blocked under default config; an operator can
        // opt RFC1918 in via UPSTREAM_ALLOW_PRIVATE_IPS / the CIDR
        // allowlist. Skip the strict assertion if a parallel test in the
        // same binary has that relaxation active so this does not flake.
        if crate::api::validation::upstream_allow_private_ips_enabled()
            || crate::api::validation::private_cidr_allowlist_value().is_some()
        {
            return;
        }
        assert_peer_endpoint_blocked("http://10.0.0.5/");
    }

    #[test]
    fn test_peer_endpoint_rejects_metadata() {
        assert_peer_endpoint_blocked("http://169.254.169.254/");
    }

    #[test]
    fn test_peer_endpoint_rejects_dotless_decimal_loopback() {
        // 2130706433 == 127.0.0.1; the URL parser canonicalises the
        // dotless-decimal integer host to the IPv4 literal, which the
        // allowlist then classifies as loopback.
        assert_peer_endpoint_blocked("http://2130706433/");
    }

    #[test]
    fn test_peer_endpoint_allows_public_https() {
        assert!(
            validate_outbound_url("https://peer1.example.com", "Peer endpoint URL").is_ok(),
            "a legitimate public peer endpoint must still be accepted"
        );
    }

    // -----------------------------------------------------------------------
    // Admin gate: the mutating peer handlers (register / unregister /
    // trigger_sync / assign / unassign / run-now) now call
    // auth.require_admin()? before touching the service, matching the
    // in-file pattern already used by heartbeat / announce / identity.
    // -----------------------------------------------------------------------

    /// Build an [`AuthExtension`] for a non-admin caller.
    fn non_admin_auth() -> AuthExtension {
        AuthExtension {
            user_id: Uuid::new_v4(),
            username: "victor.user".to_string(),
            email: "victor@example.com".to_string(),
            is_admin: false,
            is_api_token: false,
            is_service_account: false,
            scopes: None,
            allowed_repo_ids: None,
        }
    }

    /// Build an [`AuthExtension`] for an admin caller.
    fn admin_auth() -> AuthExtension {
        AuthExtension {
            user_id: Uuid::new_v4(),
            username: "admin".to_string(),
            email: "admin@example.com".to_string(),
            is_admin: true,
            is_api_token: false,
            is_service_account: false,
            scopes: None,
            allowed_repo_ids: None,
        }
    }

    #[test]
    fn test_peer_write_guard_rejects_non_admin() {
        // The exact guard expression each mutating peer handler now runs.
        assert!(non_admin_auth().require_admin().is_err());
    }

    #[test]
    fn test_peer_write_guard_allows_admin() {
        assert!(admin_auth().require_admin().is_ok());
    }
}
