//! Management API of Remote MCP registries (#5253), mounted under
//! `/api/v1/repositories/{key}/mcp/...`: the upstream catalog the web UI
//! browses (unapproved entries live here and never on `/v0.1`), the
//! approval queue's decisions, `name@version` pins, namespace-glob bulk
//! approval, and the manual sync trigger. Documented with exact shapes in
//! `docs/mcp-registry.md` ("Remote repositories").

use axum::extract::{Extension, Path, Query, State};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

use crate::api::handlers::proxy_helpers::{self, RepoInfo};
use crate::api::handlers::repositories::{
    require_repo_admin, require_repo_write_access, require_visible,
};
use crate::api::middleware::auth::AuthExtension;
use crate::api::SharedState;
use crate::error::{AppError, Result};
use crate::services::mcp_catalog::{
    self as catalog, BulkResult, CatalogItem, CatalogPage, CatalogQuery, Decision, DecisionResult,
};
use crate::services::mcp_remote::{self, SyncError, SyncState, SyncSummary};
use crate::services::repository_service::RepositoryService;

pub fn repo_router() -> Router<SharedState> {
    Router::new()
        .route("/:key/mcp/catalog", get(list_catalog))
        .route("/:key/mcp/catalog/servers/:ns", get(get_server_encoded))
        .route("/:key/mcp/catalog/servers/:ns/:name", get(get_server_split))
        .route("/:key/mcp/catalog/bulk-approve", post(bulk_approve))
        .route("/:key/mcp/catalog/pins", post(create_pin))
        .route(
            "/:key/mcp/catalog/:id/request-approval",
            post(request_approval),
        )
        .route("/:key/mcp/catalog/:id/:decision", post(decide))
        .route("/:key/mcp/sync", get(sync_status).post(trigger_sync))
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
        create_pin,
        request_approval,
        sync_status,
        trigger_sync,
    ),
    components(schemas(
        CatalogPage,
        CatalogItem,
        crate::services::mcp_catalog::CatalogPin,
        crate::services::mcp_catalog::CatalogVersion,
        Decision,
        DecisionResult,
        BulkResult,
        DecisionRequest,
        BulkApproveRequest,
        PinRequest,
        ApprovalRequestBody,
        SyncResponse,
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
    require_repo_admin(auth, model.id, &state.permission_service).await?;
    remote_info(state, key).await
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
    Ok(Json(catalog::list(&state.db, &repo, &filter).await?))
}

async fn get_server(
    state: &SharedState,
    auth: Option<AuthExtension>,
    key: &str,
    name: &str,
) -> Result<Json<CatalogItem>> {
    let auth = require_auth(auth)?;
    let repo = readable_repo(state, &auth, key).await?;
    Ok(Json(catalog::item_by_name(&state.db, &repo, name).await?))
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

/// Body of a namespace-glob bulk approval.
#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct BulkApproveRequest {
    /// Glob on the full name or the namespace: `io.github.acme/*`,
    /// `com.acme`, `com.acme.*`.
    pub pattern: String,
    /// Also approve flagged (`review`) names that match (default `false`).
    #[serde(default)]
    pub include_review: bool,
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
    responses((status = 200, body = BulkResult), (status = 400, description = "Invalid pattern"))
)]
pub async fn bulk_approve(
    State(state): State<SharedState>,
    Extension(auth): Extension<Option<AuthExtension>>,
    Path(key): Path<String>,
    Json(req): Json<BulkApproveRequest>,
) -> Result<Json<BulkResult>> {
    let auth = require_auth(auth)?;
    let repo = administered_repo(&state, &auth, &key).await?;
    Ok(Json(
        catalog::approve_pattern(
            &state,
            &repo,
            &req.pattern,
            req.include_review,
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
    responses((status = 200, body = DecisionResult), (status = 404, description = "Name not in the catalog"))
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
    Ok(Json(
        catalog::request_approval(&state.db, &repo, id, auth.user_id, note.as_deref()).await?,
    ))
}

#[utoipa::path(
    get,
    operation_id = "mcp_remote_sync_status",
    path = "/{key}/mcp/sync",
    context_path = "/api/v1/repositories",
    tag = "mcp",
    params(("key" = String, Path, description = "Remote MCP repository key")),
    responses((status = 200, body = Object, description = "The stored sync state"))
)]
pub async fn sync_status(
    State(state): State<SharedState>,
    Extension(auth): Extension<Option<AuthExtension>>,
    Path(key): Path<String>,
) -> Result<Json<SyncState>> {
    let auth = require_auth(auth)?;
    let repo = readable_repo(&state, &auth, &key).await?;
    mcp_remote::load_state(&state.db, repo.id)
        .await
        .map(Json)
        .map_err(AppError::Database)
}

/// Answer of a manual sync.
#[derive(Debug, Serialize, ToSchema)]
pub struct SyncResponse {
    pub repository: String,
    #[schema(value_type = Object)]
    pub summary: SyncSummary,
}

/// Map a sync refusal onto the API's errors.
pub fn sync_error(e: SyncError) -> AppError {
    match e {
        SyncError::Busy => AppError::Conflict(e.to_string()),
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
        (status = 200, body = SyncResponse),
        (status = 409, description = "A sync of this repository is running"),
        (status = 502, description = "The upstream registry could not be read"),
    )
)]
pub async fn trigger_sync(
    State(state): State<SharedState>,
    Extension(auth): Extension<Option<AuthExtension>>,
    Path(key): Path<String>,
) -> Result<Json<SyncResponse>> {
    let auth = require_auth(auth)?;
    let repo = if auth.is_api_token && auth.has_scope("trigger:sync") {
        let service = RepositoryService::new(state.db.clone());
        let model = service.get_by_key(&key).await?;
        require_repo_write_access(&auth, &model, &service).await?;
        remote_info(&state, &key).await?
    } else {
        administered_repo(&state, &auth, &key).await?
    };
    let summary = mcp_remote::sync_repo(&state, &repo)
        .await
        .map_err(sync_error)?;
    Ok(Json(SyncResponse {
        repository: repo.key,
        summary,
    }))
}

#[cfg(ak_test_shard = "handlers-1")]
#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::handlers::test_db_helpers as tdh;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use wiremock::matchers::{method, path, query_param, query_param_is_missing};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    #[test]
    fn sync_errors_map_to_statuses() {
        use axum::response::IntoResponse;
        for (e, status) in [
            (SyncError::Busy, 409),
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
            let fx = tdh::Fixture::setup("remote", "mcp").await?;
            let (upstream, guard) = tdh::non_loopback_mock_server().await;
            sqlx::query("UPDATE repositories SET upstream_url = $2 WHERE id = $1")
                .bind(fx.repo_id)
                .bind(upstream.uri())
                .execute(&fx.pool)
                .await
                .unwrap();
            let dir = fx.storage_dir.to_string_lossy().to_string();
            let state = tdh::build_state_with_proxy_and_age_gate(
                fx.pool.clone(),
                &dir,
                tdh::build_proxy_service_with_fs(fx.pool.clone(), &dir),
            );
            let mut admin = tdh::make_auth(fx.user_id, &fx.username);
            admin.is_admin = true;
            Some(Self {
                fx,
                upstream,
                _guard: guard,
                state,
                admin,
                extra: Vec::new(),
            })
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

        async fn sync(&self) -> serde_json::Value {
            let (s, b) = self.admin("POST", "/sync", None).await;
            assert_eq!(s, StatusCode::OK, "{b}");
            b["summary"].clone()
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
        crate::services::mcp_remote::run_due(
            &env.state,
            3600,
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
        let (s, b) = env.admin("POST", "/sync", None).await;
        assert_eq!(s, StatusCode::BAD_GATEWAY, "{b}");
        let (_, st) = env.admin("GET", "/sync", None).await;
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
}
