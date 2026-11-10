//! Management API of Remote MCP registries (#5253), mounted under
//! `/api/v1/repositories/{key}/mcp/...`: the upstream catalog the web UI
//! browses (unapproved entries live here and never on `/v0.1`), the
//! approval queue's decisions, `name@version` pins, bulk decisions (by
//! full-name glob, with a dry run, or by id), and the manual sync trigger. Documented with exact shapes in
//! `docs/mcp-registry.md` ("Remote repositories").

use axum::extract::{Extension, Path, Query, State};
use axum::http::StatusCode;
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

use crate::api::handlers::proxy_helpers::{self, RepoInfo};
use crate::api::handlers::repositories::{
    hide_write_denial_from_non_readers, require_repo_admin, require_repo_write_access,
    require_visible,
};
use crate::api::middleware::auth::AuthExtension;
use crate::api::SharedState;
use crate::error::{AppError, Result};
use crate::services::mcp_catalog::{
    self as catalog, BulkAction, BulkDecideResult, BulkResult, CatalogItem, CatalogPage,
    CatalogQuery, CatalogView, Decision, DecisionResult,
};
use crate::services::mcp_remote::{self, SyncError, SyncState};
use crate::services::repository_service::RepositoryService;

pub fn repo_router() -> Router<SharedState> {
    Router::new()
        .route("/:key/mcp/catalog", get(list_catalog))
        .route("/:key/mcp/catalog/servers/:ns", get(get_server_encoded))
        .route("/:key/mcp/catalog/servers/:ns/:name", get(get_server_split))
        .route("/:key/mcp/catalog/bulk-approve", post(bulk_approve))
        .route("/:key/mcp/catalog/bulk-block", post(bulk_block))
        .route("/:key/mcp/catalog/bulk-decide", post(bulk_decide))
        .route("/:key/mcp/catalog/pins", post(create_pin))
        .route(
            "/:key/mcp/catalog/:id/request-approval",
            post(request_approval),
        )
        .route("/:key/mcp/catalog/:id/:decision", post(decide))
        .route("/:key/mcp/sync", get(sync_status).post(trigger_sync))
        .route("/:key/mcp/seed", post(start_seed))
        .route("/:key/mcp/seed/:job_id", get(get_seed))
}

/// `GET /api/v1/mcp/pending-summary`: the instance-wide approval-queue
/// count of Remote MCP registries, mounted behind `auth_middleware`.
pub fn summary_router() -> Router<SharedState> {
    Router::new().route("/pending-summary", get(pending_summary))
}

fn require_auth(auth: Option<AuthExtension>) -> Result<AuthExtension> {
    auth.ok_or_else(|| AppError::Unauthorized("Authentication required".to_string()))
}

/// The Remote MCP repository `key`, readable by `auth` (404 otherwise, the
/// unknown-key answer).
/// The OpenAPI document of the Remote MCP management routes (#5253).
#[derive(utoipa::OpenApi)]
#[openapi(
    paths(
        list_catalog,
        get_server_encoded,
        decide,
        bulk_approve,
        bulk_block,
        bulk_decide,
        create_pin,
        request_approval,
        sync_status,
        trigger_sync,
        start_seed,
        get_seed,
        pending_summary,
    ),
    components(schemas(
        CatalogPage,
        CatalogItem,
        crate::services::mcp_catalog::CatalogPin,
        crate::services::mcp_catalog::CatalogVersion,
        crate::services::mcp_catalog::CatalogSummary,
        crate::services::mcp_catalog::CatalogLint,
        Decision,
        DecisionResult,
        BulkResult,
        BulkAction,
        BulkDecideResult,
        DecisionRequest,
        BulkApproveRequest,
        BulkBlockRequest,
        BulkDecideRequest,
        PinRequest,
        ApprovalRequestBody,
        SyncAcceptedResponse,
        crate::services::mcp_seed::SeedRequest,
        crate::services::mcp_seed::SeedServer,
        crate::services::mcp_seed::SeedAccepted,
        crate::services::mcp_seed::SeedJob,
        crate::services::mcp_seed::SeedItem,
        PendingSummary,
        PendingRepository,
    ))
)]
pub struct McpRemoteApiDoc;

async fn readable_repo(state: &SharedState, auth: &AuthExtension, key: &str) -> Result<RepoInfo> {
    auth.require_scope("read:repositories")?;
    let service = RepositoryService::new(state.db.clone());
    let model = service.get_by_key(key).await?;
    require_visible(&model, &Some(auth.clone()), &service).await?;
    remote_info(state, key).await
}

/// The Remote MCP repository `key`, administered by `auth`.
async fn administered_repo(
    state: &SharedState,
    auth: &AuthExtension,
    key: &str,
) -> Result<RepoInfo> {
    auth.require_scope("write:repositories")?;
    let service = RepositoryService::new(state.db.clone());
    let model = service.get_by_key(key).await?;
    require_repo_write_access(auth, &model, &service).await?;
    // #5458: an admin refusal to a caller who cannot read the repository is
    // the unknown-key 404 too (`require_repo_write_access` already hides its
    // own refusals the same way).
    let admin = require_repo_admin(auth, model.id, &state.permission_service).await;
    hide_write_denial_from_non_readers(admin, auth, &model, &service).await?;
    remote_info(state, key).await
}

/// What of the catalog `auth` may see (see [`CatalogView`]): a repository
/// administrator everything; a caller who holds the repository (the MCP
/// surface's reason gate) the decision detail; anyone else who can see the
/// repository only the upstream entries and their decisions.
async fn catalog_view(state: &SharedState, auth: &AuthExtension, repo: &RepoInfo) -> CatalogView {
    if require_repo_admin(auth, repo.id, &state.permission_service)
        .await
        .is_ok()
    {
        return CatalogView::Curator;
    }
    match crate::api::handlers::quarantine::caller_passes_reason_gate(&state.db, auth, repo.id)
        .await
    {
        Ok(true) => CatalogView::Holder,
        _ => CatalogView::Reader,
    }
}

async fn remote_info(state: &SharedState, key: &str) -> Result<RepoInfo> {
    let repo = proxy_helpers::resolve_repo_by_key(&state.db, key, &["mcp"], "an MCP registry")
        .await
        .map_err(|_| AppError::NotFound("Repository not found".to_string()))?;
    catalog::require_remote_mcp(&repo)?;
    Ok(repo)
}

#[utoipa::path(
    get,
    operation_id = "mcp_remote_list_catalog",
    path = "/{key}/mcp/catalog",
    context_path = "/api/v1/repositories",
    tag = "mcp",
    params(("key" = String, Path, description = "Remote MCP repository key"), CatalogQuery),
    responses(
        (status = 200, body = CatalogPage),
        (status = 400, description = "Invalid query"),
        (status = 401, description = "Authentication required"),
        (status = 404, description = "Not a Remote MCP repository the caller can read"),
    )
)]
pub async fn list_catalog(
    State(state): State<SharedState>,
    Extension(auth): Extension<Option<AuthExtension>>,
    Path(key): Path<String>,
    Query(q): Query<CatalogQuery>,
) -> Result<Json<CatalogPage>> {
    let auth = require_auth(auth)?;
    let repo = readable_repo(&state, &auth, &key).await?;
    let filter = catalog::parse_query(&q)?;
    let view = catalog_view(&state, &auth, &repo).await;
    Ok(Json(
        catalog::list(&state.db, &repo, &filter)
            .await?
            .for_view(view),
    ))
}

async fn get_server(
    state: &SharedState,
    auth: Option<AuthExtension>,
    key: &str,
    name: &str,
) -> Result<Json<CatalogItem>> {
    let auth = require_auth(auth)?;
    let repo = readable_repo(state, &auth, key).await?;
    let view = catalog_view(state, &auth, &repo).await;
    Ok(Json(
        catalog::item_by_name(&state.db, &repo, name)
            .await?
            .for_view(view),
    ))
}

#[utoipa::path(
    get,
    operation_id = "mcp_remote_get_server_encoded",
    path = "/{key}/mcp/catalog/servers/{serverName}",
    context_path = "/api/v1/repositories",
    tag = "mcp",
    params(
        ("key" = String, Path, description = "Remote MCP repository key"),
        ("serverName" = String, Path, description = "Server name, URL-encoded or with a literal slash"),
    ),
    responses((status = 200, body = CatalogItem), (status = 404, description = "Unknown name"))
)]
pub async fn get_server_encoded(
    State(state): State<SharedState>,
    Extension(auth): Extension<Option<AuthExtension>>,
    Path((key, ns)): Path<(String, String)>,
) -> Result<Json<CatalogItem>> {
    get_server(&state, auth, &key, &ns).await
}

pub async fn get_server_split(
    State(state): State<SharedState>,
    Extension(auth): Extension<Option<AuthExtension>>,
    Path((key, ns, name)): Path<(String, String, String)>,
) -> Result<Json<CatalogItem>> {
    get_server(&state, auth, &key, &format!("{ns}/{name}")).await
}

/// Body of a decision.
#[derive(Debug, Default, Deserialize, ToSchema)]
pub struct DecisionRequest {
    #[serde(default)]
    pub reason: Option<String>,
}

#[utoipa::path(
    post,
    operation_id = "mcp_remote_decide",
    path = "/{key}/mcp/catalog/{id}/{decision}",
    context_path = "/api/v1/repositories",
    tag = "mcp",
    params(
        ("key" = String, Path, description = "Remote MCP repository key"),
        ("id" = Uuid, Path, description = "Catalog row id (a name or a name@version pin)"),
        ("decision" = Decision, Path, description = "approve | block | reopen"),
    ),
    request_body = DecisionRequest,
    responses(
        (status = 200, body = DecisionResult),
        (status = 403, description = "Repository admin required"),
        (status = 404, description = "Unknown row"),
        (status = 409, description = "Approved, but the ingested version's storage key is held by another repository"),
        (status = 500, description = "Approved, but the ingested version could not be stored"),
        (status = 507, description = "Approved, but storing the ingested version exceeds a quota"),
    )
)]
pub async fn decide(
    State(state): State<SharedState>,
    Extension(auth): Extension<Option<AuthExtension>>,
    Path((key, id, decision)): Path<(String, Uuid, Decision)>,
    body: Option<Json<DecisionRequest>>,
) -> Result<Json<DecisionResult>> {
    let auth = require_auth(auth)?;
    let repo = administered_repo(&state, &auth, &key).await?;
    let reason = body.and_then(|b| b.0.reason);
    Ok(Json(
        catalog::decide(&state, &repo, id, decision, auth.user_id, reason.as_deref()).await?,
    ))
}

/// Body of a full-name-glob bulk approval.
#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct BulkApproveRequest {
    /// Glob over the full server name (`*` matches any run of characters,
    /// `/` included): `io.github.acme/*` (one namespace), `com.acme.*/*`
    /// (its sub-namespaces), `io.github.acme/weather` (one server). A bare
    /// namespace (`com.acme`) is refused with `422`; write `com.acme/*`.
    pub pattern: String,
    /// Also approve flagged (`review`) names that match (default `false`).
    #[serde(default)]
    pub include_review: bool,
    #[serde(default)]
    pub reason: Option<String>,
    /// Change nothing; answer what would be approved (default `false`).
    #[serde(default)]
    pub dry_run: bool,
}

/// Body of a full-name-glob bulk block.
#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct BulkBlockRequest {
    /// Glob over the full server name, as for a bulk approval.
    pub pattern: String,
    #[serde(default)]
    pub reason: Option<String>,
    /// Change nothing; answer what would be blocked (default `false`).
    #[serde(default)]
    pub dry_run: bool,
}

/// Body of a bulk decision by id.
#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct BulkDecideRequest {
    /// Catalog row ids (names or `name@version` pins), 1 to 500.
    pub ids: Vec<Uuid>,
    pub action: BulkAction,
    #[serde(default)]
    pub reason: Option<String>,
}

#[utoipa::path(
    post,
    operation_id = "mcp_remote_bulk_approve",
    path = "/{key}/mcp/catalog/bulk-approve",
    context_path = "/api/v1/repositories",
    tag = "mcp",
    params(("key" = String, Path, description = "Remote MCP repository key")),
    request_body = BulkApproveRequest,
    responses(
        (status = 200, body = BulkResult),
        (status = 400, description = "Invalid pattern"),
        (status = 403, description = "Repository admin required, or a namespace-spanning pattern under the posture lock"),
        (status = 422, description = "A bare namespace (write `com.acme/*`)"),
    )
)]
pub async fn bulk_approve(
    State(state): State<SharedState>,
    Extension(auth): Extension<Option<AuthExtension>>,
    Path(key): Path<String>,
    Json(req): Json<BulkApproveRequest>,
) -> Result<Json<BulkResult>> {
    let auth = require_auth(auth)?;
    let repo = administered_repo(&state, &auth, &key).await?;
    let pattern = catalog::validate_bulk_pattern(&req.pattern)?;
    // Under an instance posture lock, only an instance administrator may
    // bulk-approve across namespaces nobody named (`*`, `com.*`, ...).
    if !auth.is_admin && crate::services::mcp_settings::spans_namespaces(&pattern) {
        let rows = crate::services::mcp_settings::load_rows(&state.db, repo.id).await?;
        if crate::services::mcp_settings::locks_of(&rows).posture {
            return Err(AppError::Authorization(format!(
                "{} is locked by an instance administrator for this repository: a bulk \
                 approval may not span namespaces (`{pattern}`); name the namespace",
                crate::services::mcp_settings::REMOTE_POSTURE_KEY,
            )));
        }
    }
    Ok(Json(
        catalog::decide_pattern(
            &state,
            &repo,
            BulkAction::Approve,
            &pattern,
            req.include_review,
            req.dry_run,
            auth.user_id,
            req.reason.as_deref(),
        )
        .await?,
    ))
}

#[utoipa::path(
    post,
    operation_id = "mcp_remote_bulk_block",
    path = "/{key}/mcp/catalog/bulk-block",
    context_path = "/api/v1/repositories",
    tag = "mcp",
    params(("key" = String, Path, description = "Remote MCP repository key")),
    request_body = BulkBlockRequest,
    responses(
        (status = 200, body = BulkResult),
        (status = 400, description = "Invalid pattern"),
        (status = 403, description = "Repository admin required"),
        (status = 422, description = "A bare namespace (write `com.acme/*`)"),
    )
)]
pub async fn bulk_block(
    State(state): State<SharedState>,
    Extension(auth): Extension<Option<AuthExtension>>,
    Path(key): Path<String>,
    Json(req): Json<BulkBlockRequest>,
) -> Result<Json<BulkResult>> {
    let auth = require_auth(auth)?;
    let repo = administered_repo(&state, &auth, &key).await?;
    // A block only tightens: the posture lock does not restrict it.
    Ok(Json(
        catalog::decide_pattern(
            &state,
            &repo,
            BulkAction::Block,
            &req.pattern,
            false,
            req.dry_run,
            auth.user_id,
            req.reason.as_deref(),
        )
        .await?,
    ))
}

#[utoipa::path(
    post,
    operation_id = "mcp_remote_bulk_decide",
    path = "/{key}/mcp/catalog/bulk-decide",
    context_path = "/api/v1/repositories",
    tag = "mcp",
    params(("key" = String, Path, description = "Remote MCP repository key")),
    request_body = BulkDecideRequest,
    responses(
        (status = 200, body = BulkDecideResult),
        (status = 400, description = "No ids, or more than 500"),
        (status = 403, description = "Repository admin required"),
    )
)]
pub async fn bulk_decide(
    State(state): State<SharedState>,
    Extension(auth): Extension<Option<AuthExtension>>,
    Path(key): Path<String>,
    Json(req): Json<BulkDecideRequest>,
) -> Result<Json<BulkDecideResult>> {
    let auth = require_auth(auth)?;
    let repo = administered_repo(&state, &auth, &key).await?;
    Ok(Json(
        catalog::decide_ids(
            &state,
            &repo,
            req.action,
            &req.ids,
            auth.user_id,
            req.reason.as_deref(),
        )
        .await?,
    ))
}

/// Body of a `name@version` pin.
#[derive(Debug, Deserialize, ToSchema)]
pub struct PinRequest {
    pub name: String,
    pub version: String,
    #[serde(default)]
    pub reason: Option<String>,
}

#[utoipa::path(
    post,
    operation_id = "mcp_remote_create_pin",
    path = "/{key}/mcp/catalog/pins",
    context_path = "/api/v1/repositories",
    tag = "mcp",
    params(("key" = String, Path, description = "Remote MCP repository key")),
    request_body = PinRequest,
    responses(
        (status = 200, body = DecisionResult),
        (status = 404, description = "Name not in the catalog"),
        (status = 409, description = "Pinned, but the ingested version's storage key is held by another repository"),
        (status = 500, description = "Pinned, but the ingested version could not be stored"),
        (status = 507, description = "Pinned, but storing the ingested version exceeds a quota"),
    )
)]
pub async fn create_pin(
    State(state): State<SharedState>,
    Extension(auth): Extension<Option<AuthExtension>>,
    Path(key): Path<String>,
    Json(req): Json<PinRequest>,
) -> Result<Json<DecisionResult>> {
    let auth = require_auth(auth)?;
    let repo = administered_repo(&state, &auth, &key).await?;
    Ok(Json(
        catalog::pin(
            &state,
            &repo,
            &req.name,
            &req.version,
            auth.user_id,
            req.reason.as_deref(),
        )
        .await?,
    ))
}

/// One repository's share of [`PendingSummary`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
pub struct PendingRepository {
    pub key: String,
    /// Names awaiting a first decision (`pending`).
    pub pending: i64,
    /// Flagged names (`review`: a lookalike, or reopened).
    pub review: i64,
    /// `name@version` rows awaiting a decision (a content drift).
    pub drifted: i64,
}

/// The approval queue across the Remote MCP repositories the caller can
/// read (every one for an instance administrator).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
pub struct PendingSummary {
    pub pending: i64,
    pub review: i64,
    pub drifted: i64,
    /// `pending + review + drifted`.
    pub total: i64,
    /// The repositories with something in the queue, by key.
    pub repositories: Vec<PendingRepository>,
}

#[utoipa::path(
    get,
    operation_id = "mcp_pending_summary",
    path = "/pending-summary",
    context_path = "/api/v1/mcp",
    tag = "mcp",
    responses(
        (status = 200, body = PendingSummary),
        (status = 401, description = "Authentication required"),
    )
)]
pub async fn pending_summary(
    State(state): State<SharedState>,
    Extension(auth): Extension<Option<AuthExtension>>,
) -> Result<Json<PendingSummary>> {
    let auth = require_auth(auth)?;
    auth.require_scope("read:repositories")?;
    let remotes: Vec<(Uuid, String)> = sqlx::query_as(
        "SELECT id, key FROM repositories WHERE format = 'mcp' AND repo_type = 'remote' \
           AND key NOT LIKE '~deleting~%' ORDER BY key",
    )
    .fetch_all(&state.db)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;
    // The catalog's own read check per repository (`readable_repo`), so the
    // count never covers a queue the caller could not browse.
    let service = RepositoryService::new(state.db.clone());
    let mut visible: Vec<(Uuid, String)> = Vec::new();
    for (id, key) in remotes {
        let Ok(model) = service.get_by_key(&key).await else {
            continue;
        };
        if require_visible(&model, &Some(auth.clone()), &service)
            .await
            .is_ok()
        {
            visible.push((id, key));
        }
    }
    let ids: Vec<Uuid> = visible.iter().map(|v| v.0).collect();
    let counts: Vec<(Uuid, i64, i64, i64)> = sqlx::query_as(
        "SELECT staging_repo_id, \
                count(*) FILTER (WHERE version = '*' AND status = 'pending'), \
                count(*) FILTER (WHERE version = '*' AND status = 'review'), \
                count(*) FILTER (WHERE version <> '*' AND status IN ('pending', 'review')) \
         FROM curation_packages WHERE format = 'mcp' AND staging_repo_id = ANY($1) \
         GROUP BY staging_repo_id",
    )
    .bind(&ids)
    .fetch_all(&state.db)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;
    let mut out = PendingSummary {
        pending: 0,
        review: 0,
        drifted: 0,
        total: 0,
        repositories: Vec::new(),
    };
    for (id, key) in visible {
        let Some(&(_, pending, review, drifted)) = counts.iter().find(|c| c.0 == id) else {
            continue;
        };
        if pending + review + drifted == 0 {
            continue;
        }
        out.pending += pending;
        out.review += review;
        out.drifted += drifted;
        out.repositories.push(PendingRepository {
            key,
            pending,
            review,
            drifted,
        });
    }
    out.total = out.pending + out.review + out.drifted;
    Ok(Json(out))
}

/// Body of a request for approval.
#[derive(Debug, Default, Deserialize, ToSchema)]
pub struct ApprovalRequestBody {
    /// Why the server is needed (at most 500 characters kept).
    #[serde(default)]
    pub note: Option<String>,
}

#[utoipa::path(
    post,
    operation_id = "mcp_remote_request_approval",
    path = "/{key}/mcp/catalog/{id}/request-approval",
    context_path = "/api/v1/repositories",
    tag = "mcp",
    params(
        ("key" = String, Path, description = "Remote MCP repository key"),
        ("id" = Uuid, Path, description = "Name row id"),
    ),
    request_body = ApprovalRequestBody,
    responses((status = 200, body = CatalogItem))
)]
pub async fn request_approval(
    State(state): State<SharedState>,
    Extension(auth): Extension<Option<AuthExtension>>,
    Path((key, id)): Path<(String, Uuid)>,
    body: Option<Json<ApprovalRequestBody>>,
) -> Result<Json<CatalogItem>> {
    let auth = require_auth(auth)?;
    let repo = readable_repo(&state, &auth, &key).await?;
    let note = body.and_then(|b| b.0.note);
    let view = catalog_view(&state, &auth, &repo).await;
    Ok(Json(
        catalog::request_approval(&state.db, &repo, id, auth.user_id, note.as_deref())
            .await?
            .for_view(view),
    ))
}

/// `GET .../mcp/sync`: the stored sync state and whether a pass runs now.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SyncStatusResponse {
    #[serde(flatten)]
    pub state: SyncState,
    /// A pass of this repository (manual or scheduled, on any replica) holds
    /// its sync lock right now (#5404). Once it is `false` again,
    /// `lastFinishedAt`, `lastError` and `lastSummary` describe the pass that
    /// ended last.
    pub running: bool,
}

#[utoipa::path(
    get,
    operation_id = "mcp_remote_sync_status",
    path = "/{key}/mcp/sync",
    context_path = "/api/v1/repositories",
    tag = "mcp",
    params(("key" = String, Path, description = "Remote MCP repository key")),
    responses((status = 200, body = Object, description = "The stored sync state and `running`"))
)]
pub async fn sync_status(
    State(state): State<SharedState>,
    Extension(auth): Extension<Option<AuthExtension>>,
    Path(key): Path<String>,
) -> Result<Json<SyncStatusResponse>> {
    let auth = require_auth(auth)?;
    let repo = readable_repo(&state, &auth, &key).await?;
    let stored = mcp_remote::load_state(&state.db, repo.id)
        .await
        .map_err(AppError::Database)?;
    let running = mcp_remote::sync_running(&state.db, repo.id)
        .await
        .map_err(AppError::Database)?;
    Ok(Json(SyncStatusResponse {
        state: stored,
        running,
    }))
}

/// `202` answer of a manual sync: the pass runs in the background (#5404).
#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct SyncAcceptedResponse {
    pub repository: String,
    /// Always `running`: the pass holds the repository's sync lock.
    pub status: String,
    /// Where to poll the pass (`GET .../mcp/sync`).
    pub status_url: String,
}

/// The Remote `key` for an upstream-driving trigger (sync, seed): its
/// administrator, or an API token with `trigger:sync` and write access.
async fn triggering_repo(state: &SharedState, auth: &AuthExtension, key: &str) -> Result<RepoInfo> {
    if auth.is_api_token && auth.has_scope("trigger:sync") {
        let service = RepositoryService::new(state.db.clone());
        let model = service.get_by_key(key).await?;
        require_repo_write_access(auth, &model, &service).await?;
        remote_info(state, key).await
    } else {
        administered_repo(state, auth, key).await
    }
}

#[utoipa::path(
    post,
    operation_id = "mcp_remote_start_seed",
    path = "/{key}/mcp/seed",
    context_path = "/api/v1/repositories",
    tag = "mcp",
    params(("key" = String, Path, description = "Remote MCP repository key")),
    request_body = crate::services::mcp_seed::SeedRequest,
    responses(
        (status = 202, body = crate::services::mcp_seed::SeedAccepted, description = "Seed job accepted; poll `statusUrl`"),
        (status = 400, description = "Empty or invalid list, or more than 500 entries"),
        (status = 404, description = "Not a Remote MCP repository the caller administers"),
        (status = 409, description = "Scheduled upstream jobs are paused, or the Remote is cache-only"),
        (status = 502, description = "Outbound fetches are not available on this instance"),
    )
)]
/// Seed named server versions without a full catalog sync (#5408).
pub async fn start_seed(
    State(state): State<SharedState>,
    Extension(auth): Extension<Option<AuthExtension>>,
    Path(key): Path<String>,
    Json(req): Json<crate::services::mcp_seed::SeedRequest>,
) -> Result<(
    axum::http::StatusCode,
    Json<crate::services::mcp_seed::SeedAccepted>,
)> {
    let auth = require_auth(auth)?;
    let repo = triggering_repo(&state, &auth, &key).await?;
    let accepted =
        crate::services::mcp_seed::start(&state, repo, &req.servers, req.reason, auth.user_id)
            .await?;
    Ok((axum::http::StatusCode::ACCEPTED, Json(accepted)))
}

#[utoipa::path(
    get,
    operation_id = "mcp_remote_get_seed",
    path = "/{key}/mcp/seed/{job_id}",
    context_path = "/api/v1/repositories",
    tag = "mcp",
    params(
        ("key" = String, Path, description = "Remote MCP repository key"),
        ("job_id" = Uuid, Path, description = "Seed job id"),
    ),
    responses(
        (status = 200, body = crate::services::mcp_seed::SeedJob),
        (status = 404, description = "Repository or job not found"),
    )
)]
/// A seed job and its per-item outcome (#5408).
pub async fn get_seed(
    State(state): State<SharedState>,
    Extension(auth): Extension<Option<AuthExtension>>,
    Path((key, job_id)): Path<(String, Uuid)>,
) -> Result<Json<crate::services::mcp_seed::SeedJob>> {
    let auth = require_auth(auth)?;
    let repo = readable_repo(&state, &auth, &key).await?;
    Ok(Json(
        crate::services::mcp_seed::load(&state.db, &repo, job_id).await?,
    ))
}

/// Map a sync refusal onto the API's errors.
pub fn sync_error(e: SyncError) -> AppError {
    match e {
        SyncError::Busy | SyncError::Paused => AppError::Conflict(e.to_string()),
        SyncError::NotRemote => AppError::Validation(e.to_string()),
        SyncError::NoProxy | SyncError::Upstream(_) => AppError::BadGateway(e.to_string()),
        SyncError::Database(_) => AppError::Database(e.to_string()),
    }
}

#[utoipa::path(
    post,
    operation_id = "mcp_remote_trigger_sync",
    path = "/{key}/mcp/sync",
    context_path = "/api/v1/repositories",
    tag = "mcp",
    params(("key" = String, Path, description = "Remote MCP repository key")),
    responses(
        (status = 202, body = SyncAcceptedResponse, description = "A pass started in the background; poll `GET .../mcp/sync`"),
        (status = 409, description = "A sync of this repository is running, or scheduled upstream jobs are paused"),
        (status = 502, description = "Outbound fetches are not available on this instance"),
    )
)]
pub async fn trigger_sync(
    State(state): State<SharedState>,
    Extension(auth): Extension<Option<AuthExtension>>,
    Path(key): Path<String>,
) -> Result<(StatusCode, Json<SyncAcceptedResponse>)> {
    let auth = require_auth(auth)?;
    let repo = triggering_repo(&state, &auth, &key).await?;
    let key = repo.key.clone();
    mcp_remote::start_sync(&state, repo)
        .await
        .map_err(sync_error)?;
    Ok((
        StatusCode::ACCEPTED,
        Json(SyncAcceptedResponse {
            status_url: format!("/api/v1/repositories/{key}/mcp/sync"),
            repository: key,
            status: "running".to_string(),
        }),
    ))
}

#[cfg(ak_test_shard = "handlers-1")]
#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::handlers::test_db_helpers as tdh;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use std::sync::Arc;
    use wiremock::matchers::{method, path, query_param, query_param_is_missing};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    #[test]
    fn sync_errors_map_to_statuses() {
        use axum::response::IntoResponse;
        for (e, status) in [
            (SyncError::Busy, 409),
            (SyncError::Paused, 409),
            (SyncError::NotRemote, 400),
            (SyncError::NoProxy, 502),
            (SyncError::Upstream("x".into()), 502),
            (SyncError::Database("x".into()), 500),
        ] {
            assert_eq!(sync_error(e).into_response().status().as_u16(), status);
        }
    }

    fn server(name: &str, version: &str, extra: serde_json::Value) -> serde_json::Value {
        let mut s = serde_json::json!({
            "name": name, "description": "Tools", "version": version,
        });
        if let (Some(o), serde_json::Value::Object(e)) = (s.as_object_mut(), extra) {
            o.extend(e);
        }
        if s.get("packages").is_none() {
            s["remotes"] =
                serde_json::json!([{"type": "streamable-http", "url": "https://mcp.test/mcp"}]);
        }
        s
    }

    fn entry(s: serde_json::Value, updated: &str) -> serde_json::Value {
        serde_json::json!({"server": s, "_meta": {crate::formats::mcp::OFFICIAL_META_KEY: {
            "status": "active", "publishedAt": updated, "updatedAt": updated, "isLatest": true}}})
    }

    fn page(entries: Vec<serde_json::Value>) -> serde_json::Value {
        serde_json::json!({"servers": entries, "metadata": {"count": 0}})
    }

    struct Env {
        fx: tdh::Fixture,
        upstream: MockServer,
        _guard: tdh::SsrfTestAllowlistGuard,
        state: SharedState,
        admin: AuthExtension,
        extra: Vec<(Uuid, std::path::PathBuf)>,
    }

    impl Env {
        async fn new() -> Option<Self> {
            Self::setup(None).await.map(|(env, _)| env)
        }

        /// An [`Env`] whose repositories store on the in-memory shared
        /// cloud backend `s3`, the deployment shape of #5660.
        async fn new_cloud() -> Option<(Self, Arc<tdh::MemStorage>)> {
            let (env, mem) = Self::setup(Some("s3")).await?;
            Some((env, mem.expect("cloud backend")))
        }

        async fn setup(cloud: Option<&str>) -> Option<(Self, Option<Arc<tdh::MemStorage>>)> {
            let fx = tdh::Fixture::setup("remote", "mcp").await?;
            let (upstream, guard) = tdh::non_loopback_mock_server().await;
            sqlx::query("UPDATE repositories SET upstream_url = $2 WHERE id = $1")
                .bind(fx.repo_id)
                .bind(upstream.uri())
                .execute(&fx.pool)
                .await
                .unwrap();
            let dir = fx.storage_dir.to_string_lossy().to_string();
            let proxy = tdh::build_proxy_service_with_fs(fx.pool.clone(), &dir);
            let (state, mem) = match cloud {
                None => (
                    tdh::build_state_with_proxy_and_age_gate(fx.pool.clone(), &dir, proxy),
                    None,
                ),
                Some(backend) => {
                    sqlx::query(
                        "UPDATE repositories SET storage_backend = $2, storage_path = key \
                         WHERE id = $1",
                    )
                    .bind(fx.repo_id)
                    .bind(backend)
                    .execute(&fx.pool)
                    .await
                    .unwrap();
                    let (state, mem) =
                        tdh::build_state_with_cloud_and_proxy(fx.pool.clone(), backend, proxy);
                    (state, Some(mem))
                }
            };
            let mut admin = tdh::make_auth(fx.user_id, &fx.username);
            admin.is_admin = true;
            // Another test may be toggling the shared `upstream_jobs_paused`
            // setting right now; this process reads only the env default.
            crate::services::upstream_pause::ignore_stored_setting_for_tests();
            Some((
                Self {
                    fx,
                    upstream,
                    _guard: guard,
                    state,
                    admin,
                    extra: Vec::new(),
                },
                mem,
            ))
        }

        fn app(&self, auth: Option<AuthExtension>) -> Router {
            Router::new()
                .nest("/mcp", crate::api::handlers::mcp::router())
                .nest("/r", repo_router())
                .with_state(self.state.clone())
                .layer(Extension::<Option<AuthExtension>>(auth))
        }

        async fn call(
            &self,
            auth: Option<AuthExtension>,
            verb: &str,
            uri: &str,
            body: Option<serde_json::Value>,
        ) -> (StatusCode, serde_json::Value) {
            let mut b = Request::builder().method(verb).uri(uri);
            if body.is_some() {
                b = b.header("content-type", "application/json");
            }
            let req = b
                .body(
                    body.map(|v| Body::from(v.to_string()))
                        .unwrap_or_else(Body::empty),
                )
                .unwrap();
            let (s, bytes, _) = tdh::send_with_headers(self.app(auth), req).await;
            (
                s,
                serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null),
            )
        }

        async fn admin(
            &self,
            verb: &str,
            tail: &str,
            body: Option<serde_json::Value>,
        ) -> (StatusCode, serde_json::Value) {
            let uri = format!("/r/{}/mcp{tail}", self.fx.repo_key);
            self.call(Some(self.admin.clone()), verb, &uri, body).await
        }

        /// Start a manual sync (`202`), wait for the pass to end and return
        /// its summary.
        async fn sync(&self) -> serde_json::Value {
            let before = self.settled().await;
            let (s, b) = self.admin("POST", "/sync", None).await;
            assert_eq!(s, StatusCode::ACCEPTED, "{b}");
            self.finished_after(&before).await["lastSummary"].clone()
        }

        /// The sync state once the pass started after `before` was read has
        /// ended: its lock is released, it recorded a start other than
        /// `before`'s and a finish no earlier than that start. Polling on the
        /// stored state, not on time, so a slow pass is waited for and a
        /// pass that ended without a record times out with the state shown.
        async fn finished_after(&self, before: &serde_json::Value) -> serde_json::Value {
            let ts = |v: &serde_json::Value| {
                v.as_str()
                    .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
            };
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(60);
            loop {
                let (s, st) = self.admin("GET", "/sync", None).await;
                assert_eq!(s, StatusCode::OK, "{st}");
                let started = ts(&st["lastStartedAt"]);
                let finished = ts(&st["lastFinishedAt"]);
                if st["running"] == false
                    && started.is_some()
                    && st["lastStartedAt"] != before["lastStartedAt"]
                    && finished >= started
                {
                    return st;
                }
                assert!(
                    std::time::Instant::now() < deadline,
                    "the pass did not end: {st}"
                );
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            }
        }

        /// The sync state once no pass of the repository runs.
        async fn settled(&self) -> serde_json::Value {
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(60);
            loop {
                let (s, st) = self.admin("GET", "/sync", None).await;
                assert_eq!(s, StatusCode::OK, "{st}");
                if st["running"] == false {
                    return st;
                }
                assert!(
                    std::time::Instant::now() < deadline,
                    "sync still running: {st}"
                );
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            }
        }

        async fn item(&self, name: &str) -> serde_json::Value {
            let (s, b) = self
                .admin("GET", &format!("/catalog/servers/{name}"), None)
                .await;
            assert_eq!(s, StatusCode::OK, "{b}");
            b
        }

        async fn listed(&self) -> Vec<String> {
            let uri = format!("/mcp/{}/v0.1/servers", self.fx.repo_key);
            let (s, b) = self.call(None, "GET", &uri, None).await;
            assert_eq!(s, StatusCode::OK, "{b}");
            b["servers"]
                .as_array()
                .unwrap()
                .iter()
                .map(|e| {
                    format!(
                        "{}@{}",
                        e["server"]["name"].as_str().unwrap(),
                        e["server"]["version"].as_str().unwrap()
                    )
                })
                .collect()
        }

        async fn config(&self, key: &str, value: &str) {
            sqlx::query(
                "INSERT INTO repository_config (repository_id, key, value) VALUES ($1, $2, $3) \
                 ON CONFLICT (repository_id, key) DO UPDATE SET value = $3",
            )
            .bind(self.fx.repo_id)
            .bind(key)
            .bind(value)
            .execute(&self.fx.pool)
            .await
            .unwrap();
        }

        async fn serve(&self, extra: wiremock::MockBuilder, entries: Vec<serde_json::Value>) {
            extra
                .respond_with(ResponseTemplate::new(200).set_body_json(page(entries)))
                .mount(&self.upstream)
                .await;
        }

        async fn serve_versions(&self, name: &str, entries: Vec<serde_json::Value>) {
            let p = format!("/v0.1/servers/{}/versions", urlencoding::encode(name));
            self.serve(Mock::given(method("GET")).and(path(p)), entries)
                .await;
        }

        async fn teardown(self) {
            let pool = self.fx.pool.clone();
            for sql in [
                "DELETE FROM curation_packages WHERE staging_repo_id = $1",
                "DELETE FROM packages WHERE repository_id = $1",
                "DELETE FROM age_gate_version_observations WHERE repository_id = $1",
                "DELETE FROM age_gate_reviews WHERE repository_id = $1",
            ] {
                let _ = sqlx::query(sql).bind(self.fx.repo_id).execute(&pool).await;
            }
            for (id, dir) in &self.extra {
                tdh::cleanup_member_repo(&pool, *id, dir).await;
            }
            self.fx.teardown().await;
        }
    }

    const T1: &str = "2026-10-01T00:00:00Z";
    const T2: &str = "2026-10-02T00:00:00Z";

    #[tokio::test]
    async fn catalog_queue_and_decisions() {
        let Some(env) = Env::new().await else { return };
        let all = vec![
            entry(
                server("io.github.acme/a", "1.0.0", serde_json::json!({})),
                T1,
            ),
            entry(
                server(
                    "io.github.acme/a",
                    "2.0.0",
                    serde_json::json!({"title": "A"}),
                ),
                T1,
            ),
            entry(
                server("io.github.acme/b", "1.0.0", serde_json::json!({})),
                T1,
            ),
            entry(server("com.other/c", "1.0.0", serde_json::json!({})), T1),
        ];
        env.serve(
            Mock::given(method("GET")).and(path("/v0.1/servers")),
            all.clone(),
        )
        .await;
        env.serve_versions("io.github.acme/a", all[..2].to_vec())
            .await;
        env.serve_versions("io.github.acme/b", all[2..3].to_vec())
            .await;
        env.serve(
            Mock::given(method("GET")).and(path(format!(
                "/v0.1/servers/{}/versions/1.0.0",
                urlencoding::encode("com.other/c")
            ))),
            Vec::new(),
        )
        .await;
        let summary = env.sync().await;
        assert_eq!(
            (summary["namesNew"].as_u64(), summary["ingested"].as_u64()),
            (Some(3), Some(0))
        );

        // Browse: counts, filters, both spellings of a name, paging.
        let (s, page) = env
            .admin("GET", "/catalog?search=acme&status=pending", None)
            .await;
        assert_eq!(s, StatusCode::OK, "{page}");
        assert_eq!(page["items"].as_array().unwrap().len(), 2);
        assert_eq!(page["counts"]["pending"], 3);
        let a = env.item("io.github.acme%2Fa").await;
        assert_eq!(a["latestVersion"], "2.0.0");
        assert_eq!(a["title"], "A");
        assert_eq!(a["versions"], serde_json::json!(["2.0.0", "1.0.0"]));
        assert_eq!(env.item("io.github.acme/a").await["id"], a["id"]);
        let (s, _) = env.admin("GET", "/catalog?status=open", None).await;
        assert_eq!(s, StatusCode::BAD_REQUEST);
        let (s, _) = env.admin("GET", "/catalog/servers/nope%2Fnope", None).await;
        assert_eq!(s, StatusCode::NOT_FOUND);

        // A reader asks for approval; the request is counted.
        let reader = tdh::make_auth(env.fx.user_id, &env.fx.username);
        let a_id = a["id"].as_str().unwrap().to_string();
        let (s, b) = env
            .call(
                Some(reader.clone()),
                "POST",
                &format!("/r/{}/mcp/catalog/{a_id}/request-approval", env.fx.repo_key),
                Some(serde_json::json!({"note": "we need it"})),
            )
            .await;
        assert_eq!(s, StatusCode::OK, "{b}");
        assert_eq!(b["approvalRequests"]["count"], 1);
        let (_, req) = env.admin("GET", "/catalog?requested=true", None).await;
        assert_eq!(req["items"].as_array().unwrap().len(), 1);
        // Readers may not decide; anonymous callers may not browse.
        let (s, _) = env
            .call(
                Some(reader),
                "POST",
                &format!("/r/{}/mcp/catalog/{a_id}/approve", env.fx.repo_key),
                None,
            )
            .await;
        assert_eq!(s, StatusCode::FORBIDDEN);
        let (s, _) = env
            .call(
                None,
                "GET",
                &format!("/r/{}/mcp/catalog", env.fx.repo_key),
                None,
            )
            .await;
        assert_eq!(s, StatusCode::UNAUTHORIZED);

        // Approve a name: both versions are ingested and served at once.
        let (s, b) = env
            .admin(
                "POST",
                &format!("/catalog/{a_id}/approve"),
                Some(serde_json::json!({"reason": "vetted"})),
            )
            .await;
        assert_eq!(s, StatusCode::OK, "{b}");
        assert_eq!(b["item"]["status"], "approved");
        assert_eq!(b["item"]["ingested"].as_array().unwrap().len(), 2);
        assert_eq!(
            env.listed().await,
            ["io.github.acme/a@1.0.0", "io.github.acme/a@2.0.0"]
        );

        // Pin one version of an unapproved name; the upstream cannot answer it.
        let (s, b) = env
            .admin(
                "POST",
                "/catalog/pins",
                Some(serde_json::json!({"name": "com.other/c", "version": "1.0.0"})),
            )
            .await;
        assert_eq!(s, StatusCode::OK, "{b}");
        assert!(b["ingestError"].is_string(), "{b}");
        assert_eq!(b["item"]["pins"][0]["status"], "approved");
        let (s, _) = env
            .admin(
                "POST",
                "/catalog/pins",
                Some(serde_json::json!({"name": "x/unknown", "version": "1.0.0"})),
            )
            .await;
        assert_eq!(s, StatusCode::NOT_FOUND);
        let (s, _) = env
            .admin(
                "POST",
                "/catalog/pins",
                Some(serde_json::json!({"name": "com.other/c", "version": "latest"})),
            )
            .await;
        assert_eq!(s, StatusCode::BAD_REQUEST);

        // Block hides; the generic curation route re-approves (audited, ingested).
        let (s, _) = env
            .admin("POST", &format!("/catalog/{a_id}/block"), None)
            .await;
        assert_eq!(s, StatusCode::OK);
        assert!(env.listed().await.is_empty());
        sqlx::query("UPDATE curation_packages SET status = 'approved' WHERE id = $1")
            .bind(Uuid::parse_str(&a_id).unwrap())
            .execute(&env.fx.pool)
            .await
            .unwrap();
        crate::services::mcp_catalog::after_generic_status(
            &env.state,
            &[Uuid::parse_str(&a_id).unwrap()],
            "approved",
            env.admin.user_id,
            false,
        )
        .await;
        assert_eq!(env.listed().await.len(), 2);

        // Bulk approval by namespace; the sync backfills what it approved.
        let (s, b) = env
            .admin(
                "POST",
                "/catalog/bulk-approve",
                Some(serde_json::json!({"pattern": "io.github.*"})),
            )
            .await;
        assert_eq!(s, StatusCode::OK, "{b}");
        assert_eq!(b["approved"], 1);
        assert_eq!(b["names"], serde_json::json!(["io.github.acme/b"]));
        let (s, _) = env
            .admin(
                "POST",
                "/catalog/bulk-approve",
                Some(serde_json::json!({"pattern": "bad pattern"})),
            )
            .await;
        assert_eq!(s, StatusCode::BAD_REQUEST);
        env.sync().await;
        assert!(env
            .listed()
            .await
            .contains(&"io.github.acme/b@1.0.0".to_string()));
        let (s, st) = env.admin("GET", "/sync", None).await;
        assert_eq!(s, StatusCode::OK);
        assert!(st["lastSucceededAt"].is_string(), "{st}");
        assert_eq!(st["updatedSince"].as_str().map(|_| ()), Some(()));
        // Reopen puts the name back in the queue.
        let (s, b) = env
            .admin("POST", &format!("/catalog/{a_id}/reopen"), None)
            .await;
        assert_eq!(
            (s, b["item"]["status"].as_str()),
            (StatusCode::OK, Some("review"))
        );
        let (_, q) = env.admin("GET", "/catalog?queue=true", None).await;
        assert!(q["items"]
            .as_array()
            .unwrap()
            .iter()
            .any(|i| i["id"] == a_id.as_str()));
        env.teardown().await;
    }

    /// Review findings 6, 8, 18 and 19 on the management API: what a reader,
    /// a holder and a curator see of the catalog; namespace-spanning bulk
    /// approval under a posture lock; a bulk approval never overwrites a
    /// decision written since its selection.
    #[tokio::test]
    async fn catalog_views_locks_and_bulk_races() {
        let Some(env) = Env::new().await else { return };
        let all = vec![
            entry(
                server("io.github.acme/a", "1.0.0", serde_json::json!({})),
                T1,
            ),
            entry(server("com.other/c", "1.0.0", serde_json::json!({})), T1),
        ];
        env.serve(Mock::given(method("GET")).and(path("/v0.1/servers")), all)
            .await;
        env.sync().await;
        tdh::publish_repo(&env.fx.pool, env.fx.repo_id).await;
        let a = env.item("io.github.acme%2Fa").await;
        let a_id = a["id"].as_str().unwrap().to_string();
        // The holder (a repository member) asks, with a note.
        let holder = tdh::make_auth(env.fx.user_id, &env.fx.username);
        let (s, b) = env
            .call(
                Some(holder.clone()),
                "POST",
                &format!("/r/{}/mcp/catalog/{a_id}/request-approval", env.fx.repo_key),
                Some(serde_json::json!({"note": "secret project name"})),
            )
            .await;
        assert_eq!(s, StatusCode::OK, "{b}");
        assert_eq!(b["approvalRequests"], serde_json::json!({"count": 1}));
        let (reader_id, reader_name) = tdh::create_user(&env.fx.pool).await;
        let reader = tdh::make_auth(reader_id, &reader_name);
        let get = |auth: AuthExtension| {
            let uri = format!(
                "/r/{}/mcp/catalog/servers/io.github.acme%2Fa",
                env.fx.repo_key
            );
            let env = &env;
            async move { env.call(Some(auth), "GET", &uri, None).await }
        };
        let (s, r) = get(reader.clone()).await;
        assert_eq!(s, StatusCode::OK, "{r}");
        assert_eq!(r["approvalRequests"], serde_json::json!({"count": 1}));
        assert!(r.get("denied").is_none(), "{r}");
        assert!(r["evaluatedBy"].is_null() && r["evaluationReason"].is_null());
        assert_eq!(r["flags"], serde_json::json!({}));
        let (_, h) = get(holder.clone()).await;
        assert_eq!(h["approvalRequests"], serde_json::json!({"count": 1}));
        assert_eq!(h["denied"], false);
        let c = env.item("io.github.acme%2Fa").await;
        assert_eq!(c["approvalRequests"]["lastNote"], "secret project name");
        let (s, page) = env
            .call(
                Some(reader.clone()),
                "GET",
                &format!("/r/{}/mcp/catalog", env.fx.repo_key),
                None,
            )
            .await;
        assert_eq!(s, StatusCode::OK);
        assert!(page.to_string().find("secret project name").is_none());

        // Posture lock: a repository owner may not bulk-approve `*`.
        env.config(
            crate::services::mcp_settings::REMOTE_POSTURE_LOCKED_KEY,
            "true",
        )
        .await;
        let (owner_id, owner_name) = tdh::create_user(&env.fx.pool).await;
        tdh::grant_repo_role(&env.fx.pool, env.fx.repo_id, owner_id, "repository-owner").await;
        let owner = tdh::make_auth(owner_id, &owner_name);
        let bulk = |auth: AuthExtension, pattern: &str| {
            let uri = format!("/r/{}/mcp/catalog/bulk-approve", env.fx.repo_key);
            let body = serde_json::json!({"pattern": pattern});
            let env = &env;
            async move { env.call(Some(auth), "POST", &uri, Some(body)).await }
        };
        let (s, b) = bulk(owner.clone(), "*").await;
        assert_eq!(s, StatusCode::FORBIDDEN, "{b}");
        // Full-name globs only: a bare namespace is refused with the hint.
        let (s, b) = bulk(owner.clone(), "io.github.acme").await;
        assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY, "{b}");
        assert!(b.to_string().contains("io.github.acme/*"), "{b}");
        // A dry run answers the matches and changes nothing.
        let (s, b) = env
            .call(
                Some(owner.clone()),
                "POST",
                &format!("/r/{}/mcp/catalog/bulk-approve", env.fx.repo_key),
                Some(serde_json::json!({"pattern": "io.github.acme/*", "dryRun": true})),
            )
            .await;
        assert_eq!(s, StatusCode::OK, "{b}");
        assert_eq!(
            (&b["approved"], &b["dryRun"], &b["names"]),
            (
                &serde_json::json!(1),
                &serde_json::json!(true),
                &serde_json::json!(["io.github.acme/a"])
            )
        );
        assert_eq!(env.item("io.github.acme%2Fa").await["status"], "pending");
        let (s, b) = bulk(owner.clone(), "io.github.acme/*").await;
        assert_eq!(s, StatusCode::OK, "{b}");
        assert_eq!(
            (b["approved"].as_u64(), b["dryRun"].as_bool()),
            (Some(1), Some(false))
        );
        // Blocking only tightens: a namespace-spanning block passes the lock.
        let block = |auth: AuthExtension, body: serde_json::Value| {
            let uri = format!("/r/{}/mcp/catalog/bulk-block", env.fx.repo_key);
            let env = &env;
            async move { env.call(Some(auth), "POST", &uri, Some(body)).await }
        };
        let (s, b) = block(
            owner.clone(),
            serde_json::json!({"pattern": "*", "dryRun": true}),
        )
        .await;
        assert_eq!(s, StatusCode::OK, "{b}");
        assert_eq!(b["blocked"], 2, "{b}");
        assert_eq!(env.item("io.github.acme%2Fa").await["status"], "approved");
        let (s, _) = block(owner.clone(), serde_json::json!({"pattern": "com.other"})).await;
        assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY);
        let (s, b) = block(
            owner.clone(),
            serde_json::json!({"pattern": "io.github.*", "reason": "audit"}),
        )
        .await;
        assert_eq!((s, b["blocked"].as_u64()), (StatusCode::OK, Some(1)), "{b}");
        let a_now = env.item("io.github.acme%2Fa").await;
        assert_eq!(
            (a_now["status"].as_str(), a_now["evaluationReason"].as_str()),
            (Some("blocked"), Some("audit"))
        );
        // By id, as a repository administrator under the lock: approve two
        // rows, one unknown id reported, and an unchanged one left alone.
        let c = env.item("com.other%2Fc").await;
        let decide = |auth: AuthExtension, body: serde_json::Value| {
            let uri = format!("/r/{}/mcp/catalog/bulk-decide", env.fx.repo_key);
            let env = &env;
            async move { env.call(Some(auth), "POST", &uri, Some(body)).await }
        };
        let unknown = Uuid::new_v4();
        let (s, b) = decide(
            owner.clone(),
            serde_json::json!({"ids": [a_id, c["id"], unknown], "action": "approve"}),
        )
        .await;
        assert_eq!(s, StatusCode::OK, "{b}");
        assert_eq!(b["action"], "approve");
        assert_eq!(b["decided"].as_array().unwrap().len(), 2, "{b}");
        assert_eq!(b["notFound"], serde_json::json!([unknown]));
        let (s, b) = decide(
            owner.clone(),
            serde_json::json!({"ids": [a_id], "action": "approve"}),
        )
        .await;
        assert_eq!(
            (s, &b["unchanged"]),
            (StatusCode::OK, &serde_json::json!([a_id]))
        );
        let (s, b) = decide(
            owner.clone(),
            serde_json::json!({"ids": [c["id"]], "action": "block", "reason": "no"}),
        )
        .await;
        assert_eq!(s, StatusCode::OK, "{b}");
        assert_eq!(env.item("com.other%2Fc").await["status"], "blocked");
        let (s, _) = decide(
            owner.clone(),
            serde_json::json!({"ids": [], "action": "block"}),
        )
        .await;
        assert_eq!(s, StatusCode::BAD_REQUEST);
        let (s, _) = decide(
            owner.clone(),
            serde_json::json!({"ids": [a_id], "action": "reopen"}),
        )
        .await;
        assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY);
        let (s, _) = decide(
            holder.clone(),
            serde_json::json!({"ids": [a_id], "action": "block"}),
        )
        .await;
        assert_eq!(s, StatusCode::FORBIDDEN);
        // Back to pending for the race check below.
        sqlx::query(
            "UPDATE curation_packages SET status = 'pending' WHERE staging_repo_id = $1 \
             AND version = '*'",
        )
        .bind(env.fx.repo_id)
        .execute(&env.fx.pool)
        .await
        .unwrap();
        let (s, b) = bulk(env.admin.clone(), "*").await;
        assert_eq!(s, StatusCode::OK, "{b}");

        // A row blocked after selection is not approved by the bulk write.
        let c_id: Uuid = sqlx::query_scalar(
            "SELECT id FROM curation_packages WHERE staging_repo_id = $1 \
             AND package_name = 'com.other/c' AND version = '*'",
        )
        .bind(env.fx.repo_id)
        .fetch_one(&env.fx.pool)
        .await
        .unwrap();
        sqlx::query("UPDATE curation_packages SET status = 'blocked' WHERE id = $1")
            .bind(c_id)
            .execute(&env.fx.pool)
            .await
            .unwrap();
        let approved = catalog::approve_rows_for_tests(
            &env.fx.pool,
            &[c_id],
            &["pending", "review"],
            env.admin.user_id,
        )
        .await;
        assert!(approved.is_empty());
        let status: String =
            sqlx::query_scalar("SELECT status FROM curation_packages WHERE id = $1")
                .bind(c_id)
                .fetch_one(&env.fx.pool)
                .await
                .unwrap();
        assert_eq!(status, "blocked");

        for u in [reader_id, owner_id] {
            let _ = sqlx::query("DELETE FROM role_assignments WHERE user_id = $1")
                .bind(u)
                .execute(&env.fx.pool)
                .await;
            tdh::cleanup_user(&env.fx.pool, u).await;
        }
        let _ = sqlx::query("DELETE FROM repository_config WHERE repository_id = $1")
            .bind(env.fx.repo_id)
            .execute(&env.fx.pool)
            .await;
        env.teardown().await;
    }

    /// The instance-wide queue count: pending and flagged names plus
    /// `name@version` rows awaiting a decision, only over repositories the
    /// caller can read.
    #[tokio::test]
    async fn pending_summary_counts_visible_queues() {
        let Some(env) = Env::new().await else { return };
        let all = vec![
            entry(
                server("io.github.acme/a", "1.0.0", serde_json::json!({})),
                T1,
            ),
            entry(
                server("io.github.acme/b", "1.0.0", serde_json::json!({})),
                T1,
            ),
            entry(server("com.other/c", "1.0.0", serde_json::json!({})), T1),
        ];
        env.serve(Mock::given(method("GET")).and(path("/v0.1/servers")), all)
            .await;
        env.sync().await;
        let b = env.item("io.github.acme%2Fb").await;
        sqlx::query("UPDATE curation_packages SET status = 'review' WHERE id = $1")
            .bind(Uuid::parse_str(b["id"].as_str().unwrap()).unwrap())
            .execute(&env.fx.pool)
            .await
            .unwrap();
        // A drifted version of c.
        crate::services::mcp_remote::upsert_row(
            &env.fx.pool,
            env.fx.repo_id,
            "com.other/c",
            "1.0.0",
            "review",
            true,
            "content drift",
            &serde_json::json!({"kind": "mcp_version"}),
            None,
        )
        .await
        .unwrap();
        let summary = |auth: AuthExtension| {
            let state = env.state.clone();
            async move {
                pending_summary(State(state), Extension(Some(auth)))
                    .await
                    .unwrap()
                    .0
            }
        };
        let mine = |s: &PendingSummary| {
            s.repositories
                .iter()
                .find(|r| r.key == env.fx.repo_key)
                .cloned()
        };
        let all = summary(env.admin.clone()).await;
        assert_eq!(
            mine(&all),
            Some(PendingRepository {
                key: env.fx.repo_key.clone(),
                pending: 2,
                review: 1,
                drifted: 1,
            })
        );
        assert_eq!(all.total, all.pending + all.review + all.drifted);
        assert!(all.total >= 4);
        // A user with no access to the private repository sees nothing of it.
        let (u, name) = tdh::create_user(&env.fx.pool).await;
        let outsider = tdh::make_auth(u, &name);
        assert_eq!(mine(&summary(outsider.clone()).await), None);
        tdh::publish_repo(&env.fx.pool, env.fx.repo_id).await;
        assert_eq!(mine(&summary(outsider).await).map(|r| r.pending), Some(2));
        let err = pending_summary(State(env.state.clone()), Extension(None))
            .await
            .unwrap_err();
        assert!(matches!(err, AppError::Unauthorized(_)));
        tdh::cleanup_user(&env.fx.pool, u).await;
        env.teardown().await;
    }

    /// Review finding 17: a squat sorting before its target on the same
    /// page is still caught, and both names go to review.
    #[tokio::test]
    async fn lookalikes_are_flagged_whatever_the_order() {
        let Some(env) = Env::new().await else { return };
        let all = vec![
            entry(
                server("io.github.acm3/tool", "1.0.0", serde_json::json!({})),
                T1,
            ),
            entry(
                server("io.github.acme/tool", "1.0.0", serde_json::json!({})),
                T1,
            ),
        ];
        env.serve(Mock::given(method("GET")).and(path("/v0.1/servers")), all)
            .await;
        let summary = env.sync().await;
        assert_eq!(summary["flagged"], 2, "{summary}");
        let squat = env.item("io.github.acm3%2Ftool").await;
        let target = env.item("io.github.acme%2Ftool").await;
        assert_eq!(squat["status"], "review", "{squat}");
        assert_eq!(
            squat["flags"]["typosquat"]["similarTo"],
            "io.github.acme/tool"
        );
        assert_eq!(target["status"], "review", "{target}");
        assert_eq!(
            target["flags"]["typosquat"]["similarTo"],
            "io.github.acm3/tool"
        );
        env.teardown().await;
    }

    #[tokio::test]
    async fn drift_status_mirror_reresolve_and_scheduler() {
        let Some(mut env) = Env::new().await else {
            return;
        };
        env.config("mcp_remote_posture", "allow_with_gates").await;
        let npm = serde_json::json!({"packages": [{"registryType": "npm", "identifier": "@acme/echo",
            "version": "1.0.0", "transport": {"type": "stdio"}}]});
        env.serve(
            Mock::given(method("GET"))
                .and(path("/v0.1/servers"))
                .and(query_param_is_missing("updated_since")),
            vec![
                entry(server("com.acme/w", "1.0.0", serde_json::json!({})), T1),
                entry(server("com.acme/pkg", "1.0.0", npm.clone()), T1),
            ],
        )
        .await;
        let s1 = env.sync().await;
        assert_eq!(
            (s1["ingested"].as_u64(), s1["unresolved"].as_u64()),
            (Some(2), Some(1))
        );
        // allow_with_gates serves pending names; the unpinned package hides its version.
        assert_eq!(env.listed().await, ["com.acme/w@1.0.0"]);

        // Upstream edits 1.0.0 and deprecates it; the next pass reads the change.
        let mut edited = entry(
            server(
                "com.acme/w",
                "1.0.0",
                serde_json::json!({"title": "Edited"}),
            ),
            T2,
        );
        edited["_meta"][crate::formats::mcp::OFFICIAL_META_KEY]["status"] = "deprecated".into();
        for since in [T1, T2] {
            env.serve(
                Mock::given(method("GET"))
                    .and(path("/v0.1/servers"))
                    .and(query_param("updated_since", since)),
                vec![edited.clone()],
            )
            .await;
        }
        // The npm package is now pulled through a mapped backing repository.
        let (npm_id, npm_key, npm_dir) = tdh::create_repo(&env.fx.pool, "local", "npm").await;
        env.extra.push((npm_id, npm_dir.clone()));
        let mut npm_info = tdh::make_repo_info(npm_id, &npm_key, &npm_dir, "local", None);
        npm_info.format = "npm".into();
        tdh::seed_artifact_with_checksum(
            &env.fx.state,
            &env.fx.pool,
            &npm_info,
            "npm/echo-1.0.0.tgz",
            "@acme/echo/-/echo-1.0.0.tgz",
            "@acme/echo",
            "1.0.0",
            "application/octet-stream",
            axum::body::Bytes::from_static(b"tgz"),
            env.fx.user_id,
            &"e".repeat(64),
        )
        .await;
        env.config(
            "mcp_package_repos",
            &serde_json::json!({"npm": npm_key}).to_string(),
        )
        .await;
        let s2 = env.sync().await;
        assert_eq!(
            (s2["drifted"].as_u64(), s2["reResolved"].as_u64()),
            (Some(1), Some(1)),
            "{s2}"
        );
        assert_eq!(
            env.listed().await,
            ["com.acme/pkg@1.0.0"],
            "drift holds even under allow_with_gates"
        );
        let w = env.item("com.acme/w").await;
        assert_eq!(w["pins"][0]["status"], "review");
        assert_eq!(
            w["ingested"][0]["upstreamStatus"], "deprecated",
            "status mirrored"
        );
        // The same drift is recorded once.
        let again = crate::services::mcp_remote::sync_repo(
            &env.state,
            &proxy_helpers::resolve_repo_by_key(&env.fx.pool, &env.fx.repo_key, &["mcp"], "x")
                .await
                .ok()
                .unwrap(),
        )
        .await
        .unwrap();
        assert_eq!(again.drifted, 0, "{again:?}");

        // The scheduler finds the repository once it is due.
        sqlx::query("UPDATE mcp_remote_sync_state SET last_started_at = now() - interval '2 hours' WHERE repository_id = $1")
            .bind(env.fx.repo_id)
            .execute(&env.fx.pool)
            .await
            .unwrap();
        let due = crate::services::mcp_remote::due_repositories(&env.fx.pool, 3600)
            .await
            .unwrap();
        assert!(due.contains(&env.fx.repo_key));
        // Only this test's repository: the shared test database holds other
        // tests' Remotes, which are due too, and syncing them here would hold
        // their sync locks under those tests (409 on their own sync).
        crate::services::mcp_remote::sync_each(
            &env.state,
            std::slice::from_ref(&env.fx.repo_key),
            &tokio_util::sync::CancellationToken::new(),
        )
        .await;
        let due = crate::services::mcp_remote::due_repositories(&env.fx.pool, 3600)
            .await
            .unwrap();
        assert!(!due.contains(&env.fx.repo_key));
        env.teardown().await;
    }

    #[tokio::test]
    async fn upstream_failure_and_non_remote_repositories() {
        let Some(env) = Env::new().await else { return };
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(500))
            .mount(&env.upstream)
            .await;
        // The pass starts (202); its failure on the first page is recorded.
        let before = env.settled().await;
        let (s, b) = env.admin("POST", "/sync", None).await;
        assert_eq!(s, StatusCode::ACCEPTED, "{b}");
        let st = env.finished_after(&before).await;
        assert!(st["lastError"].is_string(), "{st}");
        // A held lock answers 409.
        let lease = crate::services::cluster_lock::ClusterLock::try_acquire(
            &crate::services::cluster_lock::PgAdvisoryLock::new(env.fx.pool.clone()),
            crate::services::mcp_remote::SYNC_LOCK_CLASS,
            crate::services::cluster_lock::lease_object_id(&format!(
                "mcp-remote-sync/{}",
                env.fx.repo_id
            )),
        )
        .await
        .unwrap()
        .unwrap();
        let (s, _) = env.admin("POST", "/sync", None).await;
        assert_eq!(s, StatusCode::CONFLICT);
        lease.release().await;
        // A Local MCP repository has no catalog.
        let (id, key, dir) = tdh::create_repo(&env.fx.pool, "local", "mcp").await;
        let (s, _) = env
            .call(
                Some(env.admin.clone()),
                "GET",
                &format!("/r/{key}/mcp/catalog"),
                None,
            )
            .await;
        assert_eq!(s, StatusCode::NOT_FOUND);
        tdh::cleanup_member_repo(&env.fx.pool, id, &dir).await;
        env.teardown().await;
    }
    /// #5404: a manual sync answers `202` at once and its pass, slower than
    /// the request, still completes. A second trigger while it runs answers
    /// `409` and starts no parallel pass.
    #[tokio::test]
    async fn manual_sync_runs_in_the_background() {
        let Some(env) = Env::new().await else { return };
        let doc = server("io.github.acme/slow", "1.0.0", serde_json::json!({}));
        Mock::given(method("GET"))
            .and(path("/v0.1/servers"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(page(vec![entry(doc, T1)]))
                    .set_delay(std::time::Duration::from_secs(3)),
            )
            .mount(&env.upstream)
            .await;

        let before = env.settled().await;
        let started = std::time::Instant::now();
        let (s, b) = env.admin("POST", "/sync", None).await;
        assert_eq!(s, StatusCode::ACCEPTED, "{b}");
        assert!(
            started.elapsed() < std::time::Duration::from_secs(2),
            "the trigger waited for the pass: {:?}",
            started.elapsed()
        );
        assert_eq!(b["status"], "running", "{b}");
        assert_eq!(
            b["statusUrl"],
            format!("/api/v1/repositories/{}/mcp/sync", env.fx.repo_key)
        );

        // The request is over; the pass runs on.
        let (s, st) = env.admin("GET", "/sync", None).await;
        assert_eq!(s, StatusCode::OK, "{st}");
        assert_eq!(st["running"], true, "{st}");
        let (s, b) = env.admin("POST", "/sync", None).await;
        assert_eq!(s, StatusCode::CONFLICT, "{b}");

        let st = env.finished_after(&before).await;
        assert!(
            started.elapsed() >= std::time::Duration::from_secs(3),
            "settled before the slow page was served"
        );
        assert_eq!(st["lastSummary"]["pages"], 1, "{st}");
        assert_eq!(st["lastSummary"]["complete"], true, "{st}");
        assert!(st["lastFinishedAt"].is_string(), "{st}");
        assert!(st["lastError"].is_null(), "{st}");
        assert_eq!(st["lastSummary"]["namesNew"], 1, "{st}");
        assert_eq!(
            env.item("io.github.acme/slow").await["status"],
            "pending",
            "the pass recorded the name"
        );
        let listings = env
            .upstream
            .received_requests()
            .await
            .unwrap_or_default()
            .into_iter()
            .filter(|r| r.url.path() == "/v0.1/servers")
            .count();
        assert_eq!(listings, 1, "the refused trigger started no second pass");
        env.teardown().await;
    }

    /// #5404: while scheduled upstream jobs are paused (#5288) a manual
    /// trigger answers `409` and contacts no upstream, as the scheduled pass
    /// skips its tick.
    #[tokio::test]
    async fn manual_sync_honours_the_upstream_jobs_pause() {
        let Some(env) = Env::new().await else { return };
        env.serve(Mock::given(method("GET")), vec![]).await;
        // The env default is process-wide; nextest runs each test in its own
        // process, so no other test sees it.
        crate::services::upstream_pause::set_env_default(true);
        let (s, b) = env.admin("POST", "/sync", None).await;
        crate::services::upstream_pause::set_env_default(false);
        assert_eq!(s, StatusCode::CONFLICT, "{b}");
        assert!(
            b["message"].as_str().unwrap_or_default().contains("paused"),
            "{b}"
        );
        let st = env.settled().await;
        assert!(st["lastStartedAt"].is_null(), "{st}");
        assert!(
            env.upstream
                .received_requests()
                .await
                .unwrap_or_default()
                .is_empty(),
            "no upstream request while paused"
        );
        env.teardown().await;
    }

    impl Env {
        /// Create a Remote MCP repository of this test's upstream through
        /// `POST /api/v1/repositories` with the extra create-body fields.
        async fn create_remote(&mut self, extra: serde_json::Value) -> Result<(Uuid, String)> {
            let key = format!("mcp-born-{}", Uuid::new_v4().simple());
            let mut body = serde_json::json!({
                "key": key, "name": key, "format": "mcp", "repo_type": "remote",
                "upstream_url": self.upstream.uri(),
            });
            if let (Some(b), serde_json::Value::Object(e)) = (body.as_object_mut(), extra) {
                b.extend(e);
            }
            let created = crate::api::handlers::repositories::create_repository(
                State(self.state.clone()),
                Extension(Some(self.admin.clone())),
                serde_json::to_vec(&body).unwrap().into(),
            )
            .await;
            let n: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM repositories WHERE key = $1")
                .bind(&key)
                .fetch_one(&self.fx.pool)
                .await
                .unwrap();
            let repo = match created {
                Ok(r) => r.0,
                Err(e) => {
                    assert_eq!(n, 0, "a refused create left a repository behind");
                    return Err(e);
                }
            };
            let dir = std::path::PathBuf::from(&self.state.config.storage_path).join(&key);
            self.extra.push((repo.id, dir));
            Ok((repo.id, key))
        }

        /// Age the repositories past the first-sync grace.
        async fn age(&self, ids: &[Uuid]) {
            sqlx::query(
                "UPDATE repositories SET created_at = now() - interval '10 minutes' \
                 WHERE id = ANY($1)",
            )
            .bind(ids)
            .execute(&self.fx.pool)
            .await
            .unwrap();
        }

        async fn upstream_requests(&self) -> usize {
            self.upstream
                .received_requests()
                .await
                .unwrap_or_default()
                .len()
        }
    }

    /// #5402: a Remote created `cache_only`, or with `mcp_remote_sync_paused`,
    /// makes no upstream request on its scheduled sync, and a new Remote is
    /// not due before its create had time to store its settings.
    #[tokio::test]
    async fn remote_born_offline_never_contacts_its_upstream() {
        let Some(mut env) = Env::new().await else {
            return;
        };
        env.serve(Mock::given(method("GET")), vec![]).await;
        let (cache_only, cache_only_key) = env
            .create_remote(serde_json::json!({
                "upstream_mode": "cache_only",
                "egress_proxy": {"mode": "direct"},
            }))
            .await
            .expect("create cache_only");
        let (paused, paused_key) = env
            .create_remote(serde_json::json!({"mcp_remote_sync_paused": true}))
            .await
            .expect("create sync-paused");
        let (online, online_key) = env
            .create_remote(serde_json::json!({}))
            .await
            .expect("create online");

        assert_eq!(
            crate::services::upstream_mode::stored_upstream_mode(&env.fx.pool, cache_only)
                .await
                .unwrap(),
            crate::services::upstream_mode::UpstreamMode::CacheOnly
        );
        assert_eq!(
            crate::services::egress_proxy::load_egress_proxy(&env.fx.pool, cache_only)
                .await
                .unwrap()
                .mode
                .as_str(),
            "direct"
        );
        let mine = |due: Vec<String>| -> Vec<String> {
            due.into_iter()
                .filter(|k| [&cache_only_key, &paused_key, &online_key].contains(&k))
                .collect()
        };
        // Just created: not due yet, whatever its settings.
        let due = mcp_remote_due(&env).await;
        assert!(mine(due).is_empty(), "a new Remote is due at once");

        env.age(&[cache_only, paused, online]).await;
        let due = mine(mcp_remote_due(&env).await);
        assert!(due.contains(&cache_only_key), "{due:?}");
        assert!(due.contains(&online_key), "{due:?}");
        assert!(
            !due.contains(&paused_key),
            "a sync-paused Remote is due: {due:?}"
        );

        // The scheduler's pass over the due cache-only Remote: the upstream
        // gate refuses its first page before any request.
        crate::services::mcp_remote::sync_each(
            &env.state,
            std::slice::from_ref(&cache_only_key),
            &tokio_util::sync::CancellationToken::new(),
        )
        .await;
        assert_eq!(
            env.upstream_requests().await,
            0,
            "a cache-only Remote contacted upstream"
        );
        let st = crate::services::mcp_remote::load_state(&env.fx.pool, cache_only)
            .await
            .unwrap();
        assert!(
            st.last_error
                .as_deref()
                .unwrap_or_default()
                .contains("upstream"),
            "{st:?}"
        );

        // Positive control: the online Remote's pass does reach the upstream.
        crate::services::mcp_remote::sync_each(
            &env.state,
            std::slice::from_ref(&online_key),
            &tokio_util::sync::CancellationToken::new(),
        )
        .await;
        assert!(
            env.upstream_requests().await > 0,
            "the online Remote did not sync"
        );
        env.teardown().await;
    }

    async fn mcp_remote_due(env: &Env) -> Vec<String> {
        crate::services::mcp_remote::due_repositories(&env.fx.pool, 3600)
            .await
            .unwrap()
    }

    /// #5402: while scheduled upstream jobs are paused (#5288), a scheduler
    /// tick contacts no upstream, so a Remote created then waits; and the
    /// create-time Remote settings are refused on other repository types.
    #[tokio::test]
    async fn paused_instance_and_create_time_refusals() {
        let Some(mut env) = Env::new().await else {
            return;
        };
        env.serve(Mock::given(method("GET")), vec![]).await;
        let (id, _) = env
            .create_remote(serde_json::json!({}))
            .await
            .expect("create");
        env.age(&[id]).await;
        // Process-wide; nextest runs each test in its own process.
        crate::services::upstream_pause::set_env_default(true);
        let mut gate = crate::services::upstream_pause::UpstreamPauseGate::new(
            crate::services::upstream_pause::MCP_REMOTE_SYNC_JOB,
        );
        let ran = crate::services::mcp_remote::scheduler_tick(&env.state, 3600, &mut gate).await;
        crate::services::upstream_pause::set_env_default(false);
        assert!(!ran, "a paused tick ran");
        assert_eq!(env.upstream_requests().await, 0);

        for extra in [
            serde_json::json!({"repo_type": "local", "upstream_url": null, "upstream_mode": "cache_only"}),
            serde_json::json!({"repo_type": "local", "upstream_url": null, "egress_proxy": {"mode": "direct"}}),
            serde_json::json!({"egress_proxy": {"mode": "explicit"}}),
            serde_json::json!({"egress_proxy": {"mode": "sideways"}}),
            serde_json::json!({"repo_type": "local", "upstream_url": null, "mcp_remote_sync_paused": true}),
        ] {
            let err = env.create_remote(extra.clone()).await.expect_err("refused");
            assert!(matches!(err, AppError::Validation(_)), "{extra}: {err:?}");
        }
        env.teardown().await;
    }

    /// The seed job `job_id` once it ended.
    async fn settled_seed(env: &Env, status_url: &str) -> serde_json::Value {
        let uri = status_url.replace("/api/v1/repositories", "/r");
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(60);
        loop {
            let (s, job) = env.call(Some(env.admin.clone()), "GET", &uri, None).await;
            assert_eq!(s, StatusCode::OK, "{job}");
            if job["status"] == "completed" || job["status"] == "failed" {
                return job;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "seed still running: {job}"
            );
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
    }

    /// #5408: a seed pins a named version the catalog has never seen, from
    /// the upstream's version list alone (no listing page), refuses a
    /// version upstream does not list and a denied name, and a second seed
    /// of the same version answers `already_pinned` with no upstream contact.
    #[tokio::test]
    async fn seed_pins_named_versions_without_a_catalog_sync() {
        let Some(env) = Env::new().await else { return };
        env.config("mcp_server_deny", r#"["io.evil/*"]"#).await;
        let name = "io.github.daedalus/mcp-sqlite3";
        let v110 = entry(server(name, "1.1.0", serde_json::json!({})), T2);
        env.serve_versions(
            name,
            vec![
                entry(server(name, "1.0.0", serde_json::json!({})), T1),
                v110.clone(),
            ],
        )
        .await;
        // The pin's ingest reads the version document itself.
        Mock::given(method("GET"))
            .and(path(format!(
                "/v0.1/servers/{}/versions/1.1.0",
                urlencoding::encode(name)
            )))
            .respond_with(ResponseTemplate::new(200).set_body_json(v110))
            .mount(&env.upstream)
            .await;
        let body = serde_json::json!({"servers": [
            {"name": name, "version": "1.1.0"},
            {"name": name, "version": "9.9.9"},
            {"name": "io.evil/x", "version": "1.0.0"},
            {"name": name, "version": "1.1.0"},
        ], "reason": "air-gap seed"});
        let (s, b) = env.admin("POST", "/seed", Some(body.clone())).await;
        assert_eq!(s, StatusCode::ACCEPTED, "{b}");
        assert_eq!(b["total"], 3, "duplicates dropped: {b}");
        let job = settled_seed(&env, b["statusUrl"].as_str().unwrap()).await;
        assert_eq!(job["status"], "completed", "{job}");
        let states: Vec<&str> = job["items"]
            .as_array()
            .unwrap()
            .iter()
            .map(|i| i["state"].as_str().unwrap())
            .collect();
        assert_eq!(states, ["pinned", "refused", "refused"], "{job}");
        assert!(job["items"][1]["reason"]
            .as_str()
            .unwrap()
            .contains("9.9.9"));
        assert!(job["items"][2]["reason"].as_str().unwrap().contains("deny"));
        assert!(env.listed().await.contains(&format!("{name}@1.1.0")));
        let item = env.item(name).await;
        assert_eq!(item["id"], job["items"][0]["catalogId"], "{item}");
        let requests = || async {
            env.upstream
                .received_requests()
                .await
                .unwrap_or_default()
                .into_iter()
                .map(|r| r.url.path().to_string())
                .collect::<Vec<_>>()
        };
        let seen = requests().await;
        assert!(
            !seen.iter().any(|p| p == "/v0.1/servers"),
            "a seed paged the catalog: {seen:?}"
        );
        assert!(
            !seen.iter().any(|p| p.contains("io.evil")),
            "a denied name was fetched: {seen:?}"
        );

        let (s, b) = env
            .admin(
                "POST",
                "/seed",
                Some(serde_json::json!({"servers": [{"name": name, "version": "1.1.0"}]})),
            )
            .await;
        assert_eq!(s, StatusCode::ACCEPTED, "{b}");
        let job = settled_seed(&env, b["statusUrl"].as_str().unwrap()).await;
        assert_eq!(job["items"][0]["state"], "already_pinned", "{job}");
        assert_eq!(
            requests().await.len(),
            seen.len(),
            "a re-seed contacted upstream"
        );
        env.teardown().await;
    }

    /// #5408: a seed contacts the upstream, so it is refused (`409`, no job,
    /// no request) on a cache-only Remote and while scheduled upstream jobs
    /// are paused; a bad list is `400`.
    #[tokio::test]
    async fn seed_refusals() {
        let Some(env) = Env::new().await else { return };
        env.serve(Mock::given(method("GET")), vec![]).await;
        let one = serde_json::json!({"servers": [{"name": "io.github.a/x", "version": "1.0.0"}]});
        for bad in [
            serde_json::json!({"servers": []}),
            serde_json::json!({"servers": [{"name": "io.github.a/x", "version": "latest"}]}),
        ] {
            let (s, b) = env.admin("POST", "/seed", Some(bad)).await;
            assert_eq!(s, StatusCode::BAD_REQUEST, "{b}");
        }
        crate::services::upstream_pause::set_env_default(true);
        let (paused, _) = env.admin("POST", "/seed", Some(one.clone())).await;
        crate::services::upstream_pause::set_env_default(false);
        assert_eq!(paused, StatusCode::CONFLICT);
        crate::services::upstream_mode::save_upstream_mode(
            &env.fx.pool,
            env.fx.repo_id,
            crate::services::upstream_mode::UpstreamMode::CacheOnly,
        )
        .await
        .unwrap();
        let (s, b) = env.admin("POST", "/seed", Some(one)).await;
        assert_eq!(s, StatusCode::CONFLICT, "{b}");
        assert!(
            b["message"]
                .as_str()
                .unwrap_or_default()
                .contains("cache-only"),
            "{b}"
        );
        let jobs: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM mcp_remote_seed_jobs WHERE repository_id = $1",
        )
        .bind(env.fx.repo_id)
        .fetch_one(&env.fx.pool)
        .await
        .unwrap();
        assert_eq!(jobs, 0);
        assert!(env
            .upstream
            .received_requests()
            .await
            .unwrap_or_default()
            .is_empty());
        env.teardown().await;
    }

    /// #5422: `POST /api/v1/curation/repos/{key}/sync` on a Remote MCP
    /// registry starts the same background pass as `POST .../mcp/sync`: `202`
    /// at once with `succeeded: true` meaning "started" and the status URL; a
    /// second trigger while it runs is `409`; the pass completes.
    #[tokio::test]
    async fn curation_sync_trigger_runs_the_pass_in_the_background() {
        let Some(env) = Env::new().await else { return };
        sqlx::query("UPDATE repositories SET visibility = 'public' WHERE id = $1")
            .bind(env.fx.repo_id)
            .execute(&env.fx.pool)
            .await
            .unwrap();
        Mock::given(method("GET"))
            .and(path("/v0.1/servers"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(page(vec![entry(
                        server("io.github.acme/cur", "1.0.0", serde_json::json!({})),
                        T1,
                    )]))
                    .set_delay(std::time::Duration::from_secs(3)),
            )
            .mount(&env.upstream)
            .await;
        let app = Router::new()
            .nest("/c", crate::api::handlers::curation::router())
            .with_state(env.state.clone())
            .layer(Extension(env.admin.clone()));
        let post = || async {
            let req = Request::builder()
                .method("POST")
                .uri(format!("/c/repos/{}/sync", env.fx.repo_key))
                .body(Body::empty())
                .unwrap();
            let (s, bytes, _) = tdh::send_with_headers(app.clone(), req).await;
            (
                s,
                serde_json::from_slice::<serde_json::Value>(&bytes).unwrap_or_default(),
            )
        };
        let before = env.settled().await;
        let started = std::time::Instant::now();
        let (s, b) = post().await;
        assert_eq!(s, StatusCode::ACCEPTED, "{b}");
        assert!(
            started.elapsed() < std::time::Duration::from_secs(2),
            "the trigger waited for the pass: {:?}",
            started.elapsed()
        );
        assert_eq!(
            (b["triggered"].as_bool(), b["succeeded"].as_bool()),
            (Some(true), Some(true)),
            "{b}"
        );
        assert_eq!(
            b["status_url"],
            format!("/api/v1/repositories/{}/mcp/sync", env.fx.repo_key)
        );
        let (s, b) = post().await;
        assert_eq!(s, StatusCode::CONFLICT, "{b}");
        let st = env.finished_after(&before).await;
        assert_eq!(st["lastSummary"]["pages"], 1, "{st}");
        assert_eq!(st["lastSummary"]["namesNew"], 1, "{st}");
        env.teardown().await;
    }

    /// #5458: every Remote management write (sync, pin, approve, block,
    /// reopen, the bulk decisions, a seed) by an administrator of ANOTHER
    /// repository answers an existing private Remote key exactly (status,
    /// headers, body) as it answers an unknown key, and changes nothing. A
    /// member who can read keeps the 403.
    #[tokio::test]
    async fn write_denials_to_non_readers_match_an_unknown_key() {
        let Some(mut env) = Env::new().await else {
            return;
        };
        // An administrator of a different repository, not of the instance.
        let (foreign, foreign_name) = tdh::create_user(&env.fx.pool).await;
        let (own_id, _, own_dir) = tdh::create_repo(&env.fx.pool, "remote", "mcp").await;
        env.extra.push((own_id, own_dir));
        tdh::grant_repo_role(&env.fx.pool, own_id, foreign, "repository-owner").await;
        let foreign_auth = tdh::make_auth(foreign, &foreign_name);
        // The same principal through a CI token carrying `trigger:sync`.
        let mut foreign_ci = foreign_auth.clone();
        foreign_ci.is_api_token = true;
        foreign_ci.scopes = Some(vec!["trigger:sync".into(), "write:repositories".into()]);
        let (reader, reader_name) = tdh::create_user(&env.fx.pool).await;
        tdh::grant_repo_role(&env.fx.pool, env.fx.repo_id, reader, "reader").await;
        let reader_auth = tdh::make_auth(reader, &reader_name);
        let unknown = format!("ak5458-unknown-{}", Uuid::new_v4());
        let row = Uuid::new_v4();
        let writes: Vec<(String, Option<serde_json::Value>)> = vec![
            ("/sync".into(), None),
            (
                "/catalog/pins".into(),
                Some(serde_json::json!({"name": "com.acme/a", "version": "1.0.0"})),
            ),
            (format!("/catalog/{row}/approve"), None),
            (format!("/catalog/{row}/block"), None),
            (format!("/catalog/{row}/reopen"), None),
            (
                "/catalog/bulk-approve".into(),
                Some(serde_json::json!({"pattern": "com.acme/*"})),
            ),
            (
                "/catalog/bulk-block".into(),
                Some(serde_json::json!({"pattern": "com.acme/*"})),
            ),
            (
                "/catalog/bulk-decide".into(),
                Some(serde_json::json!({"ids": [row], "action": "approve"})),
            ),
            (
                "/seed".into(),
                Some(serde_json::json!({"servers": [{"name": "com.acme/a", "version": "1.0.0"}]})),
            ),
        ];
        let send =
            |auth: &AuthExtension, key: &str, tail: &str, body: Option<&serde_json::Value>| {
                let mut b = Request::builder()
                    .method("POST")
                    .uri(format!("/r/{key}/mcp{tail}"));
                if body.is_some() {
                    b = b.header("content-type", "application/json");
                }
                let req = b
                    .body(
                        body.map(|v| Body::from(v.to_string()))
                            .unwrap_or_else(Body::empty),
                    )
                    .unwrap();
                tdh::send_with_headers(env.app(Some(auth.clone())), req)
            };
        for (tail, body) in &writes {
            let mut callers = vec![&foreign_auth];
            if tail == "/sync" || tail == "/seed" {
                callers.push(&foreign_ci);
            }
            for auth in callers {
                let existing = send(auth, &env.fx.repo_key, tail, body.as_ref()).await;
                let missing = send(auth, &unknown, tail, body.as_ref()).await;
                assert_eq!(existing.0, StatusCode::NOT_FOUND, "{tail}");
                assert_eq!(existing, missing, "{tail}: existing private vs unknown");
            }
            // A member who can read already knows the repository exists.
            let (s, _, _) = send(&reader_auth, &env.fx.repo_key, tail, body.as_ref()).await;
            assert_eq!(s, StatusCode::FORBIDDEN, "{tail}: reader");
        }
        // Nothing changed: no catalog row, no sync or seed started, no
        // upstream request.
        let rows: i64 =
            sqlx::query_scalar("SELECT count(*) FROM curation_packages WHERE staging_repo_id = $1")
                .bind(env.fx.repo_id)
                .fetch_one(&env.fx.pool)
                .await
                .unwrap();
        assert_eq!(rows, 0);
        let st = env.settled().await;
        assert!(st["lastStartedAt"].is_null(), "{st}");
        assert_eq!(env.upstream.received_requests().await.unwrap().len(), 0);
        tdh::cleanup_user(&env.fx.pool, foreign).await;
        tdh::cleanup_user(&env.fx.pool, reader).await;
        env.teardown().await;
    }

    // -----------------------------------------------------------------------
    // #5660: repo-scoped storage keys, and an approval that cannot store
    // -----------------------------------------------------------------------

    impl Env {
        /// `/r/{key}/mcp{tail}` as the instance administrator.
        async fn admin_at(
            &self,
            key: &str,
            verb: &str,
            tail: &str,
            body: Option<serde_json::Value>,
        ) -> (StatusCode, serde_json::Value) {
            let uri = format!("/r/{key}/mcp{tail}");
            self.call(Some(self.admin.clone()), verb, &uri, body).await
        }

        /// Run one sync of the Remote `key` to its end.
        async fn sync_at(&self, key: &str) {
            let (s, b) = self.admin_at(key, "POST", "/sync", None).await;
            assert_eq!(s, StatusCode::ACCEPTED, "{b}");
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(60);
            loop {
                let (_, st) = self.admin_at(key, "GET", "/sync", None).await;
                if st["running"] == false && st["lastFinishedAt"].is_string() {
                    assert!(st["lastError"].is_null(), "{st}");
                    return;
                }
                assert!(std::time::Instant::now() < deadline, "sync of {key}: {st}");
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            }
        }

        /// Approve the catalog name `name` of the Remote `key`.
        async fn approve_at(&self, key: &str, name: &str) -> (StatusCode, serde_json::Value) {
            let (s, item) = self
                .admin_at(key, "GET", &format!("/catalog/servers/{name}"), None)
                .await;
            assert_eq!(s, StatusCode::OK, "{item}");
            let id = item["id"].as_str().expect("catalog id").to_string();
            self.admin_at(key, "POST", &format!("/catalog/{id}/approve"), None)
                .await
        }

        /// The names served by the MCP registry surface of `key`.
        async fn listed_at(&self, key: &str) -> Vec<String> {
            let uri = format!("/mcp/{key}/v0.1/servers");
            let (s, b) = self.call(None, "GET", &uri, None).await;
            assert_eq!(s, StatusCode::OK, "{b}");
            b["servers"]
                .as_array()
                .unwrap()
                .iter()
                .map(|e| e["server"]["name"].as_str().unwrap().to_string())
                .collect()
        }

        /// A second Remote MCP repository of this test's upstream, on the
        /// same storage backend as the first.
        async fn second_remote(&mut self) -> (Uuid, String) {
            let (id, key, dir) = tdh::create_repo(&self.fx.pool, "remote", "mcp").await;
            sqlx::query(
                "UPDATE repositories SET upstream_url = $2, storage_backend = r.storage_backend, \
                 storage_path = repositories.key \
                 FROM repositories r WHERE repositories.id = $1 AND r.id = $3",
            )
            .bind(id)
            .bind(self.upstream.uri())
            .bind(self.fx.repo_id)
            .execute(&self.fx.pool)
            .await
            .unwrap();
            tdh::grant_repo_access(&self.fx.pool, id, self.fx.user_id).await;
            self.extra.push((id, dir));
            (id, key)
        }

        async fn server_row_key(&self, repo_id: Uuid) -> Option<String> {
            sqlx::query_scalar(
                "SELECT storage_key FROM artifacts WHERE repository_id = $1 \
                 AND path LIKE 'servers/%/server.json' AND is_deleted = false",
            )
            .bind(repo_id)
            .fetch_optional(&self.fx.pool)
            .await
            .unwrap()
        }
    }

    const SHARED: &str = "io.github.acme/shared";

    /// Serve one version of [`SHARED`] from the upstream, and return the
    /// entry as listed.
    async fn serve_shared(env: &Env) -> serde_json::Value {
        let shared = entry(server(SHARED, "1.0.0", serde_json::json!({})), T1);
        env.serve(
            Mock::given(method("GET")).and(path("/v0.1/servers")),
            vec![shared.clone()],
        )
        .await;
        env.serve_versions(SHARED, vec![shared.clone()]).await;
        shared
    }

    /// Two Remote MCP registries of one upstream on a shared cloud namespace
    /// both approve, store and serve the same server version. On main the
    /// second approval answered 200 while its store failed the
    /// cross-repository write guard (409, logged only), and the version was
    /// never served from it.
    #[tokio::test]
    async fn same_version_approves_into_two_cloud_remotes_5660() {
        let Some((mut env, mem)) = Env::new_cloud().await else {
            return;
        };
        serve_shared(&env).await;
        let first = (env.fx.repo_id, env.fx.repo_key.clone());
        let second = env.second_remote().await;

        for (repo_id, key) in [&first, &second] {
            env.sync_at(key).await;
            let (s, b) = env.approve_at(key, SHARED).await;
            assert_eq!(s, StatusCode::OK, "approve in {key}: {b}");
            assert!(b["ingestError"].is_null(), "approve in {key}: {b}");
            assert_eq!(env.listed_at(key).await, [SHARED], "served from {key}");
            let row_key = env.server_row_key(*repo_id).await.expect("ingested row");
            assert!(
                row_key.starts_with(&format!("mcp/{repo_id}/{SHARED}/1.0.0/")),
                "{row_key} must be repo-scoped"
            );
            assert!(
                mem.objects.lock().unwrap().contains_key(&row_key),
                "{row_key} must be written"
            );
        }
        let objects: Vec<String> = mem.objects.lock().unwrap().keys().cloned().collect();
        assert!(
            !objects
                .iter()
                .any(|k| k.starts_with(&format!("mcp/{SHARED}/"))),
            "the legacy flat key must not be written on a cloud backend: {objects:?}"
        );
        env.teardown().await;
    }

    /// An approval whose ingest cannot store the version answers the storage
    /// error (409 with the guard's message), never 200; nothing is served.
    /// The conflict is forced by a row of another repository already holding
    /// the exact key the approving repository writes.
    #[tokio::test]
    async fn approval_answers_the_storage_conflict_5660() {
        let Some((mut env, _mem)) = Env::new_cloud().await else {
            return;
        };
        let shared = serve_shared(&env).await;
        env.sync_at(&env.fx.repo_key.clone()).await;
        let admitted = crate::services::mcp_remote::admit_upstream(
            &crate::services::mcp_remote::parse_entry(&shared).expect("entry"),
        )
        .expect("admitted");
        let key = crate::formats::mcp::storage_key(
            crate::formats::mcp::KeyScope {
                scheme: crate::storage::StorageKeyScheme::RepoScoped,
                storage_backend: "s3",
                repository_id: env.fx.repo_id,
            },
            SHARED,
            "1.0.0",
            &admitted.sha256,
        );
        let (other, _) = env.second_remote().await;
        sqlx::query(
            "INSERT INTO artifacts (repository_id, path, name, version, size_bytes, \
             checksum_sha256, content_type, storage_key) \
             VALUES ($1, 'squatter/server.json', 'squatter', '1', 1, $2, 'application/json', $3)",
        )
        .bind(other)
        .bind(&admitted.sha256)
        .bind(&key)
        .execute(&env.fx.pool)
        .await
        .unwrap();

        let (s, b) = env.approve_at(&env.fx.repo_key.clone(), SHARED).await;
        assert_eq!(s, StatusCode::CONFLICT, "{b}");
        assert!(
            b["message"]
                .as_str()
                .unwrap_or_default()
                .contains("already owned by another repository"),
            "{b}"
        );
        assert!(env.listed_at(&env.fx.repo_key.clone()).await.is_empty());
        assert_eq!(env.server_row_key(env.fx.repo_id).await, None);
        // The decision stands and the next sync retries the ingest.
        assert_eq!(env.item(SHARED).await["status"], "approved");
        env.teardown().await;
    }
}
