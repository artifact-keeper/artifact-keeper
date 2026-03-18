//! Repository management handlers.

use axum::{
    body::Bytes,
    extract::{Extension, Multipart, Path, Query, State},
    http::header,
    response::IntoResponse,
    routing::get,
    Json, Router,
};
use serde::{Deserialize, Serialize};
use std::time::Duration;
use utoipa::{IntoParams, OpenApi, ToSchema};
use uuid::Uuid;

use crate::api::download_response::{DownloadResponse, X_ARTIFACT_STORAGE};
use crate::api::dto::Pagination;
use crate::api::handlers::proxy_helpers;
use crate::api::middleware::auth::AuthExtension;
use crate::api::SharedState;
use crate::error::{AppError, Result};
use crate::models::repository::{RepositoryFormat, RepositoryType};
use crate::services::artifact_service::ArtifactService;
use crate::services::repository_service::{
    CreateRepositoryRequest as ServiceCreateRepoReq, RepositoryService,
    UpdateRepositoryRequest as ServiceUpdateRepoReq,
};

/// Require that the request is authenticated, returning an error if not.
fn require_auth(auth: Option<AuthExtension>) -> Result<AuthExtension> {
    auth.ok_or_else(|| AppError::Authentication("Authentication required".to_string()))
}

/// Check that the authenticated user can access a specific repository.
/// If `allowed_repo_ids` is set on the token, the repo must be in that set.
fn require_repo_access(auth: &AuthExtension, repo_id: Uuid) -> Result<()> {
    if auth.can_access_repo(repo_id) {
        Ok(())
    } else {
        Err(AppError::Authorization(
            "Token does not have access to this repository".to_string(),
        ))
    }
}

/// Ensure a repository is visible to the current user.
/// Public repos are visible to everyone. Private repos require authentication.
fn require_visible(
    repo: &crate::models::repository::Repository,
    auth: &Option<AuthExtension>,
) -> Result<()> {
    if repo.is_public {
        return Ok(());
    }
    match auth {
        Some(a) => {
            if a.can_access_repo(repo.id) {
                Ok(())
            } else {
                Err(AppError::NotFound(format!(
                    "Repository '{}' not found",
                    repo.key
                )))
            }
        }
        None => Err(AppError::NotFound(format!(
            "Repository '{}' not found",
            repo.key
        ))),
    }
}

/// Upsert the `index_upstream_url` key in `repository_config` for a given repository.
async fn upsert_index_upstream_url(
    db: &sqlx::PgPool,
    repo_id: Uuid,
    index_url: &str,
) -> Result<()> {
    sqlx::query(
        "INSERT INTO repository_config (repository_id, key, value) \
         VALUES ($1, 'index_upstream_url', $2) \
         ON CONFLICT (repository_id, key) DO UPDATE SET value = $2, updated_at = NOW()",
    )
    .bind(repo_id)
    .bind(index_url)
    .execute(db)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;
    Ok(())
}

/// Create repository routes
pub fn router() -> Router<SharedState> {
    use axum::extract::DefaultBodyLimit;
    use axum::routing::{delete, post, put};

    Router::new()
        .route("/", get(list_repositories).post(create_repository))
        .route(
            "/:key",
            get(get_repository)
                .patch(update_repository)
                .delete(delete_repository),
        )
        // Cache TTL configuration for proxy/remote repositories
        .route("/:key/cache-ttl", put(set_cache_ttl).get(get_cache_ttl))
        // Upstream auth management for remote repositories
        .route("/:key/upstream-auth", put(set_upstream_auth))
        .route("/:key/test-upstream", post(test_upstream))
        // Virtual repository member management
        .route(
            "/:key/members",
            get(list_virtual_members)
                .post(add_virtual_member)
                .put(update_virtual_members),
        )
        .route("/:key/members/:member_key", delete(remove_virtual_member))
        // Artifact routes nested under repository
        .route(
            "/:key/artifacts",
            get(list_artifacts).post(upload_artifact_multipart),
        )
        .route(
            "/:key/artifacts/*path",
            get(get_artifact_metadata)
                .put(upload_artifact)
                .post(upload_artifact_multipart_with_path)
                .delete(delete_artifact),
        )
        // Download uses a separate route prefix to avoid wildcard conflict
        .route("/:key/download/*path", get(download_artifact))
        // Security routes nested under repository
        .merge(super::security::repo_security_router())
        // Label routes nested under repository
        .merge(super::repository_labels::repo_labels_router())
        // Allow up to 512MB uploads (matches format-specific handlers)
        .layer(DefaultBodyLimit::max(512 * 1024 * 1024))
}

#[derive(Debug, Deserialize, IntoParams, ToSchema)]
pub struct ListRepositoriesQuery {
    pub page: Option<u32>,
    pub per_page: Option<u32>,
    pub format: Option<String>,
    #[serde(rename = "type", alias = "repo_type")]
    pub repo_type: Option<String>,
    pub q: Option<String>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct CreateRepositoryRequest {
    pub key: String,
    pub name: String,
    pub description: Option<String>,
    pub format: String,
    pub repo_type: String,
    pub is_public: Option<bool>,
    pub upstream_url: Option<String>,
    pub quota_bytes: Option<i64>,
    /// Override the default storage backend for this repository.
    /// When omitted, the server's configured default is used.
    /// Non-admin users may only use the default backend.
    pub storage_backend: Option<String>,
    /// Custom format key for WASM plugin format handlers (e.g. "rpm-custom").
    pub format_key: Option<String>,
    /// Separate index host for Cargo registries that split index and download
    /// across two hosts (e.g. crates.io uses `https://index.crates.io` for
    /// the sparse index but `https://crates.io` for tarball downloads).
    /// Stored in `repository_config` under the key `index_upstream_url`.
    pub index_upstream_url: Option<String>,
    /// Member repositories to add when creating a virtual repository.
    /// Each entry specifies a repository key and optional priority.
    pub member_repos: Option<Vec<CreateVirtualMemberInput>>,
    /// Upstream auth type: "basic" or "bearer". Only valid for remote repos.
    pub upstream_auth_type: Option<String>,
    /// Username for basic auth.
    pub upstream_username: Option<String>,
    /// Password (basic) or token (bearer). Write-only, never returned in responses.
    pub upstream_password: Option<String>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct CreateVirtualMemberInput {
    pub repo_key: String,
    #[serde(default = "default_priority")]
    pub priority: i32,
}

fn default_priority() -> i32 {
    0
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct UpdateRepositoryRequest {
    pub key: Option<String>,
    pub name: Option<String>,
    pub description: Option<String>,
    pub is_public: Option<bool>,
    pub quota_bytes: Option<i64>,
    /// Update the Cargo index upstream URL (stored in `repository_config`).
    /// When provided, upserts the `index_upstream_url` key for this repository.
    pub index_upstream_url: Option<String>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct RepositoryResponse {
    pub id: Uuid,
    pub key: String,
    pub name: String,
    pub description: Option<String>,
    pub format: String,
    pub repo_type: String,
    pub is_public: bool,
    pub storage_used_bytes: i64,
    pub quota_bytes: Option<i64>,
    pub upstream_auth_type: Option<String>,
    pub upstream_auth_configured: bool,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct RepositoryListResponse {
    pub items: Vec<RepositoryResponse>,
    pub pagination: Pagination,
}

/// Convert a Repository model to a RepositoryResponse with optional storage usage.
fn repo_to_response(
    repo: crate::models::repository::Repository,
    storage_used_bytes: i64,
) -> RepositoryResponse {
    RepositoryResponse {
        id: repo.id,
        key: repo.key,
        name: repo.name,
        description: repo.description,
        format: format!("{:?}", repo.format).to_lowercase(),
        repo_type: format!("{:?}", repo.repo_type).to_lowercase(),
        is_public: repo.is_public,
        storage_used_bytes,
        quota_bytes: repo.quota_bytes,
        upstream_auth_type: None,
        upstream_auth_configured: false,
        created_at: repo.created_at,
        updated_at: repo.updated_at,
    }
}

/// Validate that a repository key is safe and well-formed.
fn validate_repository_key(key: &str) -> Result<()> {
    if key.is_empty() || key.len() > 128 {
        return Err(AppError::Validation(
            "Repository key must be between 1 and 128 characters".to_string(),
        ));
    }
    if !key
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.')
    {
        return Err(AppError::Validation(
            "Repository key must contain only alphanumeric characters, hyphens, underscores, and dots".to_string(),
        ));
    }
    if key.starts_with('.') || key.starts_with('-') {
        return Err(AppError::Validation(
            "Repository key must not start with a dot or hyphen".to_string(),
        ));
    }
    if key.contains("..") {
        return Err(AppError::Validation(
            "Repository key must not contain consecutive dots".to_string(),
        ));
    }
    Ok(())
}

/// Validate that a cache TTL value (in seconds) is within the acceptable range.
/// Minimum is 1 second, maximum is 30 days (2,592,000 seconds).
fn validate_cache_ttl(secs: i64) -> bool {
    (1..=2_592_000).contains(&secs)
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct SetCacheTtlRequest {
    pub cache_ttl_seconds: i64,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct CacheTtlResponse {
    pub repository_key: String,
    pub cache_ttl_seconds: i64,
}

/// Set the proxy cache TTL for a repository
#[utoipa::path(
    put,
    path = "/{key}/cache-ttl",
    context_path = "/api/v1/repositories",
    tag = "repositories",
    params(
        ("key" = String, Path, description = "Repository key"),
    ),
    request_body = SetCacheTtlRequest,
    security(("bearer_auth" = [])),
    responses(
        (status = 200, description = "Cache TTL updated", body = CacheTtlResponse),
        (status = 400, description = "Invalid TTL value"),
        (status = 401, description = "Authentication required"),
        (status = 404, description = "Repository not found"),
    )
)]
pub async fn set_cache_ttl(
    State(state): State<SharedState>,
    Extension(auth): Extension<Option<AuthExtension>>,
    Path(key): Path<String>,
    Json(payload): Json<SetCacheTtlRequest>,
) -> Result<Json<CacheTtlResponse>> {
    let auth = require_auth(auth)?;
    auth.require_scope("write")?;

    if !validate_cache_ttl(payload.cache_ttl_seconds) {
        return Err(AppError::Validation(
            "cache_ttl_seconds must be between 1 and 2592000 (30 days)".to_string(),
        ));
    }

    let service = RepositoryService::new(state.db.clone());
    let repo = service.get_by_key(&key).await?;
    require_repo_access(&auth, repo.id)?;

    // Upsert into repository_config table
    sqlx::query(
        r#"
        INSERT INTO repository_config (repository_id, key, value)
        VALUES ($1, 'cache_ttl_secs', $2)
        ON CONFLICT (repository_id, key)
        DO UPDATE SET value = $2, updated_at = NOW()
        "#,
    )
    .bind(repo.id)
    .bind(payload.cache_ttl_seconds.to_string())
    .execute(&state.db)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;

    Ok(Json(CacheTtlResponse {
        repository_key: key,
        cache_ttl_seconds: payload.cache_ttl_seconds,
    }))
}

/// Get the proxy cache TTL for a repository
#[utoipa::path(
    get,
    path = "/{key}/cache-ttl",
    context_path = "/api/v1/repositories",
    tag = "repositories",
    params(
        ("key" = String, Path, description = "Repository key"),
    ),
    responses(
        (status = 200, description = "Current cache TTL", body = CacheTtlResponse),
        (status = 404, description = "Repository not found"),
    )
)]
pub async fn get_cache_ttl(
    State(state): State<SharedState>,
    Path(key): Path<String>,
) -> Result<Json<CacheTtlResponse>> {
    let service = RepositoryService::new(state.db.clone());
    let repo = service.get_by_key(&key).await?;

    // Read from repository_config table
    let result: Option<(String,)> = sqlx::query_as(
        r#"
        SELECT value FROM repository_config
        WHERE repository_id = $1 AND key = 'cache_ttl_secs'
        "#,
    )
    .bind(repo.id)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;

    let ttl = result
        .and_then(|(v,)| v.parse::<i64>().ok())
        .unwrap_or(3600); // default 1 hour

    Ok(Json(CacheTtlResponse {
        repository_key: key,
        cache_ttl_seconds: ttl,
    }))
}

fn parse_format(s: &str) -> Result<RepositoryFormat> {
    match s.to_lowercase().as_str() {
        "maven" => Ok(RepositoryFormat::Maven),
        "gradle" => Ok(RepositoryFormat::Gradle),
        "npm" => Ok(RepositoryFormat::Npm),
        "pypi" => Ok(RepositoryFormat::Pypi),
        "nuget" => Ok(RepositoryFormat::Nuget),
        "go" => Ok(RepositoryFormat::Go),
        "rubygems" => Ok(RepositoryFormat::Rubygems),
        "docker" => Ok(RepositoryFormat::Docker),
        "helm" => Ok(RepositoryFormat::Helm),
        "rpm" => Ok(RepositoryFormat::Rpm),
        "debian" => Ok(RepositoryFormat::Debian),
        "conan" => Ok(RepositoryFormat::Conan),
        "cargo" => Ok(RepositoryFormat::Cargo),
        "generic" => Ok(RepositoryFormat::Generic),
        "podman" => Ok(RepositoryFormat::Podman),
        "buildx" => Ok(RepositoryFormat::Buildx),
        "oras" => Ok(RepositoryFormat::Oras),
        "wasm_oci" => Ok(RepositoryFormat::WasmOci),
        "helm_oci" => Ok(RepositoryFormat::HelmOci),
        "poetry" => Ok(RepositoryFormat::Poetry),
        "conda" => Ok(RepositoryFormat::Conda),
        "yarn" => Ok(RepositoryFormat::Yarn),
        "bower" => Ok(RepositoryFormat::Bower),
        "pnpm" => Ok(RepositoryFormat::Pnpm),
        "chocolatey" => Ok(RepositoryFormat::Chocolatey),
        "powershell" => Ok(RepositoryFormat::Powershell),
        "terraform" => Ok(RepositoryFormat::Terraform),
        "opentofu" => Ok(RepositoryFormat::Opentofu),
        "alpine" => Ok(RepositoryFormat::Alpine),
        "conda_native" => Ok(RepositoryFormat::CondaNative),
        "composer" => Ok(RepositoryFormat::Composer),
        "hex" => Ok(RepositoryFormat::Hex),
        "cocoapods" => Ok(RepositoryFormat::Cocoapods),
        "swift" => Ok(RepositoryFormat::Swift),
        "pub" => Ok(RepositoryFormat::Pub),
        "sbt" => Ok(RepositoryFormat::Sbt),
        "chef" => Ok(RepositoryFormat::Chef),
        "puppet" => Ok(RepositoryFormat::Puppet),
        "ansible" => Ok(RepositoryFormat::Ansible),
        "gitlfs" => Ok(RepositoryFormat::Gitlfs),
        "vscode" => Ok(RepositoryFormat::Vscode),
        "jetbrains" => Ok(RepositoryFormat::Jetbrains),
        "huggingface" => Ok(RepositoryFormat::Huggingface),
        "mlmodel" => Ok(RepositoryFormat::Mlmodel),
        "cran" => Ok(RepositoryFormat::Cran),
        "vagrant" => Ok(RepositoryFormat::Vagrant),
        "opkg" => Ok(RepositoryFormat::Opkg),
        "p2" => Ok(RepositoryFormat::P2),
        "bazel" => Ok(RepositoryFormat::Bazel),
        "protobuf" => Ok(RepositoryFormat::Protobuf),
        "incus" => Ok(RepositoryFormat::Incus),
        "lxc" => Ok(RepositoryFormat::Lxc),
        _ => Err(AppError::Validation(format!("Invalid format: {}", s))),
    }
}

fn parse_repo_type(s: &str) -> Result<RepositoryType> {
    match s.to_lowercase().as_str() {
        "local" => Ok(RepositoryType::Local),
        "remote" => Ok(RepositoryType::Remote),
        "virtual" => Ok(RepositoryType::Virtual),
        "staging" => Ok(RepositoryType::Staging),
        _ => Err(AppError::Validation(format!("Invalid repo type: {}", s))),
    }
}

/// List repositories
#[utoipa::path(
    get,
    path = "",
    context_path = "/api/v1/repositories",
    tag = "repositories",
    params(ListRepositoriesQuery),
    responses(
        (status = 200, description = "List of repositories", body = RepositoryListResponse),
    )
)]
pub async fn list_repositories(
    State(state): State<SharedState>,
    Extension(auth): Extension<Option<AuthExtension>>,
    Query(query): Query<ListRepositoriesQuery>,
) -> Result<Json<RepositoryListResponse>> {
    let page = query.page.unwrap_or(1).max(1);
    let per_page = query.per_page.unwrap_or(20).min(100);
    let offset = ((page - 1) * per_page) as i64;

    let format_filter = query.format.as_ref().map(|f| parse_format(f)).transpose()?;
    let type_filter = query
        .repo_type
        .as_ref()
        .map(|t| parse_repo_type(t))
        .transpose()?;

    let public_only = auth.is_none();
    let service = RepositoryService::new(state.db.clone());
    let (repos, total) = service
        .list(
            offset,
            per_page as i64,
            format_filter,
            type_filter,
            public_only,
            query.q.as_deref(),
        )
        .await?;

    let total_pages = ((total as f64) / (per_page as f64)).ceil() as u32;

    // Batch fetch storage usage for all repos in one query
    let repo_ids: Vec<Uuid> = repos.iter().map(|r| r.id).collect();
    let storage_map: std::collections::HashMap<Uuid, i64> = if !repo_ids.is_empty() {
        sqlx::query_as::<_, (Uuid, i64)>(
            r#"
            SELECT repository_id, COALESCE(SUM(size_bytes), 0)::BIGINT
            FROM artifacts
            WHERE repository_id = ANY($1) AND is_deleted = false
            GROUP BY repository_id
            "#,
        )
        .bind(&repo_ids)
        .fetch_all(&state.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?
        .into_iter()
        .collect()
    } else {
        std::collections::HashMap::new()
    };

    let items: Vec<RepositoryResponse> = repos
        .into_iter()
        .map(|r| {
            let storage = storage_map.get(&r.id).copied().unwrap_or(0);
            repo_to_response(r, storage)
        })
        .collect();

    Ok(Json(RepositoryListResponse {
        items,
        pagination: Pagination {
            page,
            per_page,
            total,
            total_pages,
        },
    }))
}

/// Create a new repository
#[utoipa::path(
    post,
    path = "",
    context_path = "/api/v1/repositories",
    tag = "repositories",
    request_body = CreateRepositoryRequest,
    security(("bearer_auth" = [])),
    responses(
        (status = 200, description = "Repository created", body = RepositoryResponse),
        (status = 401, description = "Authentication required"),
        (status = 409, description = "Repository key already exists"),
    )
)]
pub async fn create_repository(
    State(state): State<SharedState>,
    Extension(auth): Extension<Option<AuthExtension>>,
    Json(payload): Json<CreateRepositoryRequest>,
) -> Result<Json<RepositoryResponse>> {
    let auth = require_auth(auth)?;
    auth.require_scope("write")?;
    validate_repository_key(&payload.key)?;
    let format = parse_format(&payload.format)?;
    let repo_type = parse_repo_type(&payload.repo_type)?;

    // Resolve storage backend: use the requested one or fall back to the default.
    let storage_backend = match &payload.storage_backend {
        None => state.config.storage_backend.clone(),
        Some(requested) if requested == &state.config.storage_backend => {
            state.config.storage_backend.clone()
        }
        Some(requested) => {
            // Non-admin users cannot choose a non-default backend
            if !auth.is_admin {
                return Err(AppError::Authorization(
                    "Only admins can select a non-default storage backend".to_string(),
                ));
            }
            // Validate the requested backend is available
            if !state.storage_registry.is_available(requested) {
                return Err(AppError::Validation(format!(
                    "Storage backend '{}' is not available",
                    requested
                )));
            }
            requested.clone()
        }
    };

    // Compute storage path: filesystem uses a subdirectory, cloud backends use the key directly
    let storage_path = if storage_backend == "filesystem" {
        format!("{}/{}", state.config.storage_path, payload.key)
    } else {
        payload.key.clone()
    };

    let service = state.create_repository_service();
    let repo = service
        .create(ServiceCreateRepoReq {
            key: payload.key,
            name: payload.name,
            description: payload.description,
            format,
            repo_type: repo_type.clone(),
            storage_backend,
            storage_path,
            upstream_url: payload.upstream_url,
            is_public: payload.is_public.unwrap_or(false),
            quota_bytes: payload.quota_bytes,
            format_key: payload.format_key,
        })
        .await?;

    if let Some(ref index_url) = payload.index_upstream_url {
        upsert_index_upstream_url(&state.db, repo.id, index_url).await?;
    }

    // Add virtual repository members if provided
    if repo_type == RepositoryType::Virtual {
        if let Some(ref member_inputs) = payload.member_repos {
            for (idx, input) in member_inputs.iter().enumerate() {
                let member_repo = service.get_by_key(&input.repo_key).await?;
                let priority = resolve_member_priority(input.priority, idx);
                service
                    .add_virtual_member(repo.id, member_repo.id, priority)
                    .await?;
            }
        }
    }

    // Store upstream auth credentials if provided
    if let Some(ref auth_type) = payload.upstream_auth_type {
        let credentials_json = match auth_type.as_str() {
            "basic" => {
                let username = payload.upstream_username.as_deref().ok_or_else(|| {
                    AppError::Validation("upstream_username is required for basic auth".to_string())
                })?;
                let password = payload.upstream_password.as_deref().ok_or_else(|| {
                    AppError::Validation("upstream_password is required for basic auth".to_string())
                })?;
                serde_json::json!({"username": username, "password": password}).to_string()
            }
            "bearer" => {
                let token = payload.upstream_password.as_deref().ok_or_else(|| {
                    AppError::Validation(
                        "upstream_password is required for bearer auth (used as token)".to_string(),
                    )
                })?;
                serde_json::json!({"token": token}).to_string()
            }
            other => {
                return Err(AppError::Validation(format!(
                    "Invalid upstream_auth_type: {other}. Must be 'basic' or 'bearer'"
                )));
            }
        };
        crate::services::upstream_auth::save_upstream_auth(
            &state.db,
            repo.id,
            auth_type,
            &credentials_json,
        )
        .await?;
    }

    state
        .event_bus
        .emit("repository.created", repo.id, Some(auth.username.clone()));

    let mut response = repo_to_response(repo, 0);
    if let Some(ref at) = payload.upstream_auth_type {
        response.upstream_auth_type = Some(at.clone());
        response.upstream_auth_configured = true;
    }
    Ok(Json(response))
}

/// Get repository details
#[utoipa::path(
    get,
    path = "/{key}",
    context_path = "/api/v1/repositories",
    tag = "repositories",
    params(
        ("key" = String, Path, description = "Repository key"),
    ),
    responses(
        (status = 200, description = "Repository details", body = RepositoryResponse),
        (status = 404, description = "Repository not found"),
    )
)]
pub async fn get_repository(
    State(state): State<SharedState>,
    Extension(auth): Extension<Option<AuthExtension>>,
    Path(key): Path<String>,
) -> Result<Json<RepositoryResponse>> {
    let service = RepositoryService::new(state.db.clone());
    let repo = service.get_by_key(&key).await?;
    require_visible(&repo, &auth)?;
    let storage_used = service.get_storage_usage(repo.id).await?;
    let auth_type =
        crate::services::upstream_auth::get_upstream_auth_type(&state.db, repo.id).await?;

    let mut response = repo_to_response(repo, storage_used);
    response.upstream_auth_configured = auth_type.is_some();
    response.upstream_auth_type = auth_type;
    Ok(Json(response))
}

/// Update repository
#[utoipa::path(
    patch,
    path = "/{key}",
    context_path = "/api/v1/repositories",
    tag = "repositories",
    params(
        ("key" = String, Path, description = "Repository key"),
    ),
    request_body = UpdateRepositoryRequest,
    security(("bearer_auth" = [])),
    responses(
        (status = 200, description = "Repository updated", body = RepositoryResponse),
        (status = 401, description = "Authentication required"),
        (status = 404, description = "Repository not found"),
        (status = 409, description = "Repository key already exists"),
    )
)]
pub async fn update_repository(
    State(state): State<SharedState>,
    Extension(auth): Extension<Option<AuthExtension>>,
    Path(key): Path<String>,
    Json(payload): Json<UpdateRepositoryRequest>,
) -> Result<Json<RepositoryResponse>> {
    let auth = require_auth(auth)?;
    auth.require_scope("write")?;

    // Validate new key if provided
    if let Some(ref new_key) = payload.key {
        validate_repository_key(new_key)?;
    }

    // Validate quota_bytes is within a reasonable range (max 100 TiB)
    if let Some(quota) = payload.quota_bytes {
        if !(0..=100 * 1024 * 1024 * 1024 * 1024).contains(&quota) {
            return Err(AppError::Validation(
                "quota_bytes must be between 0 and 100 TiB".to_string(),
            ));
        }
    }

    let service = state.create_repository_service();

    // Get existing repo by key and check repo access
    let existing = service.get_by_key(&key).await?;
    require_repo_access(&auth, existing.id)?;

    let repo = service
        .update(
            existing.id,
            ServiceUpdateRepoReq {
                key: payload.key,
                name: payload.name,
                description: payload.description,
                is_public: payload.is_public,
                quota_bytes: payload.quota_bytes.map(Some),
                upstream_url: None,
            },
        )
        .await?;

    if let Some(ref index_url) = payload.index_upstream_url {
        upsert_index_upstream_url(&state.db, repo.id, index_url).await?;
    }

    let storage_used = service.get_storage_usage(repo.id).await?;

    state
        .event_bus
        .emit("repository.updated", repo.id, Some(auth.username.clone()));

    Ok(Json(repo_to_response(repo, storage_used)))
}

/// Delete repository
#[utoipa::path(
    delete,
    path = "/{key}",
    context_path = "/api/v1/repositories",
    tag = "repositories",
    params(
        ("key" = String, Path, description = "Repository key"),
    ),
    security(("bearer_auth" = [])),
    responses(
        (status = 200, description = "Repository deleted"),
        (status = 401, description = "Authentication required"),
        (status = 404, description = "Repository not found"),
    )
)]
pub async fn delete_repository(
    State(state): State<SharedState>,
    Extension(auth): Extension<Option<AuthExtension>>,
    Path(key): Path<String>,
) -> Result<()> {
    let auth = require_auth(auth)?;
    auth.require_scope("delete")?;
    let service = state.create_repository_service();
    let repo = service.get_by_key(&key).await?;
    require_repo_access(&auth, repo.id)?;
    service.delete(repo.id).await?;
    state
        .event_bus
        .emit("repository.deleted", repo.id, Some(auth.username.clone()));
    Ok(())
}

// Artifact handlers (nested under repository)

#[derive(Debug, Deserialize, IntoParams, ToSchema)]
pub struct ListArtifactsQuery {
    pub page: Option<u32>,
    pub per_page: Option<u32>,
    pub q: Option<String>,
    pub path_prefix: Option<String>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct ArtifactResponse {
    pub id: Uuid,
    pub repository_key: String,
    pub path: String,
    pub name: String,
    pub version: Option<String>,
    pub size_bytes: i64,
    pub checksum_sha256: String,
    pub content_type: String,
    pub download_count: i64,
    pub created_at: chrono::DateTime<chrono::Utc>,
    #[schema(value_type = Option<Object>)]
    pub metadata: Option<serde_json::Value>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct ArtifactListResponse {
    pub items: Vec<ArtifactResponse>,
    pub pagination: Pagination,
}

/// List artifacts in repository
#[utoipa::path(
    get,
    path = "/{key}/artifacts",
    context_path = "/api/v1/repositories",
    tag = "repositories",
    params(
        ("key" = String, Path, description = "Repository key"),
        ListArtifactsQuery,
    ),
    responses(
        (status = 200, description = "List of artifacts", body = ArtifactListResponse),
        (status = 404, description = "Repository not found"),
    )
)]
pub async fn list_artifacts(
    State(state): State<SharedState>,
    Extension(auth): Extension<Option<AuthExtension>>,
    Path(key): Path<String>,
    Query(query): Query<ListArtifactsQuery>,
) -> Result<Json<ArtifactListResponse>> {
    let page = query.page.unwrap_or(1).max(1);
    let per_page = query.per_page.unwrap_or(20).min(100);
    let offset = ((page - 1) * per_page) as i64;

    let repo_service = RepositoryService::new(state.db.clone());
    let repo = repo_service.get_by_key(&key).await?;
    require_visible(&repo, &auth)?;

    let storage = state.storage_for_repo(&repo.storage_location())?;
    let artifact_service = ArtifactService::new(state.db.clone(), storage);

    let (artifacts, total) = artifact_service
        .list(
            repo.id,
            query.path_prefix.as_deref(),
            query.q.as_deref(),
            offset,
            per_page as i64,
        )
        .await?;

    let total_pages = ((total as f64) / (per_page as f64)).ceil() as u32;

    let mut items = Vec::new();
    for artifact in artifacts {
        let downloads = artifact_service.get_download_stats(artifact.id).await?;
        items.push(ArtifactResponse {
            id: artifact.id,
            repository_key: key.clone(),
            path: artifact.path,
            name: artifact.name,
            version: artifact.version,
            size_bytes: artifact.size_bytes,
            checksum_sha256: artifact.checksum_sha256,
            content_type: artifact.content_type,
            download_count: downloads,
            created_at: artifact.created_at,
            metadata: None,
        });
    }

    Ok(Json(ArtifactListResponse {
        items,
        pagination: Pagination {
            page,
            per_page,
            total,
            total_pages,
        },
    }))
}

/// Get artifact metadata
#[utoipa::path(
    get,
    path = "/{key}/artifacts/{path}",
    context_path = "/api/v1/repositories",
    tag = "repositories",
    operation_id = "get_repository_artifact_metadata",
    params(
        ("key" = String, Path, description = "Repository key"),
        ("path" = String, Path, description = "Artifact path"),
    ),
    responses(
        (status = 200, description = "Artifact metadata", body = ArtifactResponse),
        (status = 404, description = "Artifact not found"),
    )
)]
pub async fn get_artifact_metadata(
    State(state): State<SharedState>,
    Extension(auth): Extension<Option<AuthExtension>>,
    Path((key, path)): Path<(String, String)>,
) -> Result<Json<ArtifactResponse>> {
    let repo_service = RepositoryService::new(state.db.clone());
    let repo = repo_service.get_by_key(&key).await?;
    require_visible(&repo, &auth)?;

    let storage = state.storage_for_repo(&repo.storage_location())?;
    let artifact_service = ArtifactService::new(state.db.clone(), storage);

    let artifact = sqlx::query_as!(
        crate::models::artifact::Artifact,
        r#"
        SELECT
            id, repository_id, path, name, version, size_bytes,
            checksum_sha256, checksum_md5, checksum_sha1,
            content_type, storage_key, is_deleted, uploaded_by,
            created_at, updated_at
        FROM artifacts
        WHERE repository_id = $1 AND path = $2 AND is_deleted = false
        "#,
        repo.id,
        path
    )
    .fetch_optional(&state.db)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?
    .ok_or_else(|| AppError::NotFound("Artifact not found".to_string()))?;

    let downloads = artifact_service.get_download_stats(artifact.id).await?;
    let metadata = artifact_service.get_metadata(artifact.id).await?;

    Ok(Json(ArtifactResponse {
        id: artifact.id,
        repository_key: key,
        path: artifact.path,
        name: artifact.name,
        version: artifact.version,
        size_bytes: artifact.size_bytes,
        checksum_sha256: artifact.checksum_sha256,
        content_type: artifact.content_type,
        download_count: downloads,
        created_at: artifact.created_at,
        metadata: metadata.map(|m| m.metadata),
    }))
}

/// Upload artifact
#[utoipa::path(
    put,
    path = "/{key}/artifacts/{path}",
    context_path = "/api/v1/repositories",
    tag = "repositories",
    params(
        ("key" = String, Path, description = "Repository key"),
        ("path" = String, Path, description = "Artifact path"),
    ),
    request_body(content = Vec<u8>, content_type = "application/octet-stream"),
    security(("bearer_auth" = [])),
    responses(
        (status = 200, description = "Artifact uploaded", body = ArtifactResponse),
        (status = 401, description = "Authentication required"),
        (status = 404, description = "Repository not found"),
    )
)]
pub async fn upload_artifact(
    State(state): State<SharedState>,
    Extension(auth): Extension<Option<AuthExtension>>,
    Path((key, path)): Path<(String, String)>,
    body: Bytes,
) -> Result<Json<ArtifactResponse>> {
    let auth = require_auth(auth)?;
    auth.require_scope("write")?;
    let repo_service = RepositoryService::new(state.db.clone());
    let repo = repo_service.get_by_key(&key).await?;
    require_repo_access(&auth, repo.id)?;

    let storage = state.storage_for_repo(&repo.storage_location())?;
    let artifact_service = state.create_artifact_service(storage);

    // Extract name from path
    let name = path.split('/').next_back().unwrap_or(&path).to_string();

    // Check if this repo has a WASM plugin format handler
    let format_key = repo_service.get_format_key(repo.id).await?;
    let mut wasm_metadata = None;

    if let (Some(ref fk), Some(ref registry)) = (&format_key, &state.plugin_registry) {
        if registry.has_format(fk).await {
            // Run WASM plugin validate + parse_metadata
            match registry.execute_validate(fk, &path, &body).await {
                Ok(Ok(())) => {}
                Ok(Err(validation_err)) => {
                    return Err(crate::error::AppError::Validation(
                        validation_err.to_string(),
                    ));
                }
                Err(e) => {
                    tracing::error!("WASM plugin validate error for {}: {}", fk, e);
                    return Err(crate::error::AppError::Internal(format!(
                        "Plugin error: {}",
                        e
                    )));
                }
            }

            match registry.execute_parse_metadata(fk, &path, &body).await {
                Ok(meta) => {
                    wasm_metadata = Some(meta);
                }
                Err(e) => {
                    tracing::warn!("WASM plugin parse_metadata error for {}: {}", fk, e);
                }
            }
        }
    }

    // Use WASM-extracted metadata if available
    let version = wasm_metadata.as_ref().and_then(|m| m.version.clone());
    let content_type = wasm_metadata
        .as_ref()
        .map(|m| m.content_type.clone())
        .unwrap_or_else(|| {
            mime_guess::from_path(&name)
                .first_or_octet_stream()
                .to_string()
        });

    let artifact = artifact_service
        .upload(
            repo.id,
            &path,
            &name,
            version.as_deref(),
            &content_type,
            body,
            Some(auth.user_id),
        )
        .await?;

    let downloads = artifact_service.get_download_stats(artifact.id).await?;
    let metadata_json = wasm_metadata.map(|m| m.to_json());

    Ok(Json(ArtifactResponse {
        id: artifact.id,
        repository_key: key,
        path: artifact.path,
        name: artifact.name,
        version: artifact.version,
        size_bytes: artifact.size_bytes,
        checksum_sha256: artifact.checksum_sha256,
        content_type: artifact.content_type,
        download_count: downloads,
        created_at: artifact.created_at,
        metadata: metadata_json,
    }))
}

/// Upload artifact via multipart/form-data POST (with path in URL).
///
/// Accepts a multipart form with a `file` field. The URL path is used as the
/// artifact path, falling back to the uploaded filename.
async fn upload_artifact_multipart_with_path(
    State(state): State<SharedState>,
    Extension(auth): Extension<Option<AuthExtension>>,
    Path((key, path)): Path<(String, String)>,
    multipart: Multipart,
) -> Result<Json<ArtifactResponse>> {
    let (body, filename) = extract_multipart_file(multipart).await?;
    // Prefer the URL path; fall back to the filename from the form field
    let artifact_path = if path.is_empty() || path == "/" {
        filename
    } else {
        path
    };
    upload_artifact(
        State(state),
        Extension(auth),
        Path((key, artifact_path)),
        body,
    )
    .await
}

/// Upload artifact via multipart/form-data POST (no path in URL).
///
/// The artifact path comes from the `file` field's filename.
async fn upload_artifact_multipart(
    State(state): State<SharedState>,
    Extension(auth): Extension<Option<AuthExtension>>,
    Path(key): Path<String>,
    multipart: Multipart,
) -> Result<Json<ArtifactResponse>> {
    let (body, filename) = extract_multipart_file(multipart).await?;
    upload_artifact(State(state), Extension(auth), Path((key, filename)), body).await
}

/// Extract the first file field from a multipart form.
async fn extract_multipart_file(mut multipart: Multipart) -> Result<(Bytes, String)> {
    while let Some(field) = multipart
        .next_field()
        .await
        .map_err(|e| AppError::Validation(format!("Invalid multipart data: {e}")))?
    {
        // Accept any field that has a filename (i.e. a file upload)
        let filename = field.file_name().map(|s| s.to_string());
        if let Some(filename) = filename {
            let data: Bytes = field
                .bytes()
                .await
                .map_err(|e| AppError::Validation(format!("Failed to read file: {e}")))?;
            return Ok((data, filename));
        }
    }
    Err(AppError::Validation(
        "No file field found in multipart form".to_string(),
    ))
}

/// Download artifact
#[utoipa::path(
    get,
    path = "/{key}/download/{path}",
    context_path = "/api/v1/repositories",
    tag = "repositories",
    params(
        ("key" = String, Path, description = "Repository key"),
        ("path" = String, Path, description = "Artifact path"),
    ),
    responses(
        (status = 200, description = "Artifact binary content", content_type = "application/octet-stream"),
        (status = 302, description = "Redirect to S3 presigned URL"),
        (status = 404, description = "Artifact not found"),
    )
)]
pub async fn download_artifact(
    State(state): State<SharedState>,
    Extension(auth): Extension<Option<AuthExtension>>,
    Path((key, path)): Path<(String, String)>,
    request: axum::http::Request<axum::body::Body>,
) -> Result<impl IntoResponse> {
    let repo_service = RepositoryService::new(state.db.clone());
    let repo = repo_service.get_by_key(&key).await?;
    require_visible(&repo, &auth)?;

    // Get client IP for analytics
    let ip_addr = request
        .headers()
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.split(',').next())
        .unwrap_or("127.0.0.1")
        .parse()
        .unwrap_or(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST));

    let user_agent = request
        .headers()
        .get(header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .map(String::from);

    // Check if the storage backend supports redirect downloads (S3 with presigned URLs)
    let storage = state.storage_for_repo(&repo.storage_location())?;
    if storage.supports_redirect() {
        // Get artifact metadata first using query_as for runtime checking
        #[derive(sqlx::FromRow)]
        struct ArtifactRow {
            id: Uuid,
            storage_key: String,
        }
        if let Some(artifact) = sqlx::query_as::<_, ArtifactRow>(
            r#"
            SELECT id, storage_key
            FROM artifacts
            WHERE repository_id = $1 AND path = $2 AND is_deleted = false
            "#,
        )
        .bind(repo.id)
        .bind(&path)
        .fetch_optional(&state.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?
        {
            // Try to get presigned URL from the shared storage backend
            if let Some(presigned) = storage
                .get_presigned_url(&artifact.storage_key, Duration::from_secs(3600))
                .await?
            {
                // Record download analytics
                let _ = sqlx::query(
                    r#"
                    INSERT INTO download_events (artifact_id, user_id, ip_address, user_agent, downloaded_at)
                    VALUES ($1, $2, $3, $4, NOW())
                    "#,
                )
                .bind(artifact.id)
                .bind(auth.as_ref().map(|a| a.user_id))
                .bind(ip_addr.to_string())
                .bind(user_agent.as_deref())
                .execute(&state.db)
                .await;

                tracing::info!(
                    repo = %key,
                    path = %path,
                    source = ?presigned.source,
                    "Serving artifact via redirect"
                );
                return Ok(DownloadResponse::redirect(presigned).into_response());
            }
        }
    }

    // Fall back to proxied download (filesystem or S3 without redirect)
    let artifact_service = ArtifactService::new(state.db.clone(), storage);

    let download_result = artifact_service
        .download(
            repo.id,
            &path,
            auth.map(|a| a.user_id),
            Some(ip_addr.to_string()),
            user_agent.as_deref(),
        )
        .await;

    match download_result {
        Ok((artifact, content)) => Ok((
            [
                (header::CONTENT_TYPE, artifact.content_type),
                (
                    header::CONTENT_DISPOSITION,
                    format!("attachment; filename=\"{}\"", artifact.name),
                ),
                (header::CONTENT_LENGTH, artifact.size_bytes.to_string()),
                (
                    header::HeaderName::from_static("x-checksum-sha256"),
                    artifact.checksum_sha256,
                ),
                (
                    header::HeaderName::from_static(X_ARTIFACT_STORAGE),
                    "proxy".to_string(),
                ),
            ],
            content,
        )
            .into_response()),
        Err(AppError::NotFound(_)) if repo.repo_type == RepositoryType::Remote => {
            // Try proxy for remote repositories
            if let (Some(ref upstream_url), Some(ref proxy)) =
                (&repo.upstream_url, &state.proxy_service)
            {
                let (content, content_type) =
                    proxy_helpers::proxy_fetch(proxy, repo.id, &key, upstream_url, &path)
                        .await
                        .map_err(|_| {
                            AppError::NotFound("Artifact not found upstream".to_string())
                        })?;

                let ct = content_type.unwrap_or_else(|| "application/octet-stream".to_string());
                let filename = path.rsplit('/').next().unwrap_or(&path);

                Ok((
                    [
                        (header::CONTENT_TYPE, ct),
                        (
                            header::CONTENT_DISPOSITION,
                            format!("attachment; filename=\"{}\"", filename),
                        ),
                        (header::CONTENT_LENGTH, content.len().to_string()),
                        (
                            header::HeaderName::from_static(X_ARTIFACT_STORAGE),
                            "upstream".to_string(),
                        ),
                    ],
                    content,
                )
                    .into_response())
            } else {
                Err(AppError::NotFound("Artifact not found".to_string()))
            }
        }
        Err(AppError::NotFound(_)) if repo.repo_type == RepositoryType::Virtual => {
            // Virtual repo: try each member in priority order
            let db = state.db.clone();
            let path_clone = path.clone();
            let (content, content_type) = proxy_helpers::resolve_virtual_download(
                &state.db,
                state.proxy_service.as_deref(),
                repo.id,
                &path,
                |member_id, location| {
                    let db = db.clone();
                    let state = state.clone();
                    let p = path_clone.clone();
                    async move {
                        proxy_helpers::local_fetch_by_path(&db, &state, member_id, &location, &p)
                            .await
                    }
                },
            )
            .await
            .map_err(|_| {
                AppError::NotFound("Artifact not found in any member repository".to_string())
            })?;

            let ct = content_type.unwrap_or_else(|| "application/octet-stream".to_string());
            let filename = path.rsplit('/').next().unwrap_or(&path);

            Ok((
                [
                    (header::CONTENT_TYPE, ct),
                    (
                        header::CONTENT_DISPOSITION,
                        format!("attachment; filename=\"{}\"", filename),
                    ),
                    (header::CONTENT_LENGTH, content.len().to_string()),
                    (
                        header::HeaderName::from_static(X_ARTIFACT_STORAGE),
                        "virtual".to_string(),
                    ),
                ],
                content,
            )
                .into_response())
        }
        Err(e) => Err(e),
    }
}

/// Delete artifact
#[utoipa::path(
    delete,
    path = "/{key}/artifacts/{path}",
    context_path = "/api/v1/repositories",
    tag = "repositories",
    params(
        ("key" = String, Path, description = "Repository key"),
        ("path" = String, Path, description = "Artifact path"),
    ),
    security(("bearer_auth" = [])),
    responses(
        (status = 200, description = "Artifact deleted"),
        (status = 401, description = "Authentication required"),
        (status = 404, description = "Artifact not found"),
    )
)]
pub async fn delete_artifact(
    State(state): State<SharedState>,
    Extension(auth): Extension<Option<AuthExtension>>,
    Path((key, path)): Path<(String, String)>,
) -> Result<()> {
    let auth = require_auth(auth)?;
    auth.require_scope("delete")?;
    let repo_service = RepositoryService::new(state.db.clone());
    let repo = repo_service.get_by_key(&key).await?;
    require_repo_access(&auth, repo.id)?;

    let storage = state.storage_for_repo(&repo.storage_location())?;
    let artifact_service = state.create_artifact_service(storage);

    // Find the artifact
    let artifact = sqlx::query_scalar!(
        "SELECT id FROM artifacts WHERE repository_id = $1 AND path = $2 AND is_deleted = false",
        repo.id,
        path
    )
    .fetch_optional(&state.db)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?
    .ok_or_else(|| AppError::NotFound("Artifact not found".to_string()))?;

    artifact_service.delete(artifact).await?;

    Ok(())
}

// Virtual repository member management handlers

#[derive(Debug, Deserialize, ToSchema)]
pub struct AddVirtualMemberRequest {
    pub member_key: String,
    pub priority: Option<i32>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct UpdateVirtualMembersRequest {
    pub members: Vec<VirtualMemberPriority>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct VirtualMemberPriority {
    pub member_key: String,
    pub priority: i32,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct VirtualMemberResponse {
    pub id: Uuid,
    pub member_repo_id: Uuid,
    pub member_repo_key: String,
    pub member_repo_name: String,
    pub member_repo_type: String,
    pub priority: i32,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct VirtualMembersListResponse {
    pub members: Vec<VirtualMemberResponse>,
}

// Row type for virtual member queries
#[derive(sqlx::FromRow)]
struct VirtualMemberRow {
    id: Uuid,
    member_repo_id: Uuid,
    priority: i32,
    created_at: chrono::DateTime<chrono::Utc>,
    member_key: String,
    member_name: String,
    repo_type: RepositoryType,
}

/// List virtual repository members
#[utoipa::path(
    get,
    path = "/{key}/members",
    context_path = "/api/v1/repositories",
    tag = "repositories",
    params(
        ("key" = String, Path, description = "Repository key"),
    ),
    responses(
        (status = 200, description = "List of virtual repository members", body = VirtualMembersListResponse),
        (status = 400, description = "Repository is not virtual"),
        (status = 404, description = "Repository not found"),
    )
)]
pub async fn list_virtual_members(
    State(state): State<SharedState>,
    Path(key): Path<String>,
) -> Result<Json<VirtualMembersListResponse>> {
    let service = RepositoryService::new(state.db.clone());
    let repo = service.get_by_key(&key).await?;

    if repo.repo_type != RepositoryType::Virtual {
        return Err(AppError::Validation(
            "Only virtual repositories have members".to_string(),
        ));
    }

    // Query members with their repository info
    let members: Vec<VirtualMemberRow> = sqlx::query_as(
        r#"
        SELECT
            vrm.id,
            vrm.member_repo_id,
            vrm.priority,
            vrm.created_at,
            r.key as member_key,
            r.name as member_name,
            r.repo_type
        FROM virtual_repo_members vrm
        INNER JOIN repositories r ON r.id = vrm.member_repo_id
        WHERE vrm.virtual_repo_id = $1
        ORDER BY vrm.priority
        "#,
    )
    .bind(repo.id)
    .fetch_all(&state.db)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;

    let members = members.into_iter().map(map_member_row).collect();

    Ok(Json(VirtualMembersListResponse { members }))
}

/// Add a member to a virtual repository
#[utoipa::path(
    post,
    path = "/{key}/members",
    context_path = "/api/v1/repositories",
    tag = "repositories",
    params(
        ("key" = String, Path, description = "Repository key"),
    ),
    request_body = AddVirtualMemberRequest,
    security(("bearer_auth" = [])),
    responses(
        (status = 200, description = "Member added", body = VirtualMemberResponse),
        (status = 401, description = "Authentication required"),
        (status = 404, description = "Repository or member not found"),
    )
)]
pub async fn add_virtual_member(
    State(state): State<SharedState>,
    Extension(auth): Extension<Option<AuthExtension>>,
    Path(key): Path<String>,
    Json(payload): Json<AddVirtualMemberRequest>,
) -> Result<Json<VirtualMemberResponse>> {
    let auth = require_auth(auth)?;
    auth.require_scope("write")?;
    let service = RepositoryService::new(state.db.clone());

    let virtual_repo = service.get_by_key(&key).await?;
    require_repo_access(&auth, virtual_repo.id)?;
    let member_repo = service.get_by_key(&payload.member_key).await?;

    // Get current max priority if not specified
    let priority = match payload.priority {
        Some(p) => p,
        None => {
            let max: Option<i32> = sqlx::query_scalar(
                "SELECT MAX(priority) FROM virtual_repo_members WHERE virtual_repo_id = $1",
            )
            .bind(virtual_repo.id)
            .fetch_one(&state.db)
            .await
            .map_err(|e| AppError::Database(e.to_string()))?;

            max.unwrap_or(0) + 1
        }
    };

    service
        .add_virtual_member(virtual_repo.id, member_repo.id, priority)
        .await?;

    // Fetch the created member record
    let member: VirtualMemberRow = sqlx::query_as(
        r#"
        SELECT
            vrm.id,
            vrm.member_repo_id,
            vrm.priority,
            vrm.created_at,
            r.key as member_key,
            r.name as member_name,
            r.repo_type
        FROM virtual_repo_members vrm
        INNER JOIN repositories r ON r.id = vrm.member_repo_id
        WHERE vrm.virtual_repo_id = $1 AND vrm.member_repo_id = $2
        "#,
    )
    .bind(virtual_repo.id)
    .bind(member_repo.id)
    .fetch_one(&state.db)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;

    Ok(Json(VirtualMemberResponse {
        id: member.id,
        member_repo_id: member.member_repo_id,
        member_repo_key: member.member_key,
        member_repo_name: member.member_name,
        member_repo_type: format!("{:?}", member.repo_type).to_lowercase(),
        priority: member.priority,
        created_at: member.created_at,
    }))
}

/// Remove a member from a virtual repository
#[utoipa::path(
    delete,
    path = "/{key}/members/{member_key}",
    context_path = "/api/v1/repositories",
    tag = "repositories",
    params(
        ("key" = String, Path, description = "Repository key"),
        ("member_key" = String, Path, description = "Member repository key"),
    ),
    security(("bearer_auth" = [])),
    responses(
        (status = 200, description = "Member removed"),
        (status = 400, description = "Repository is not virtual"),
        (status = 401, description = "Authentication required"),
        (status = 404, description = "Repository or member not found"),
    )
)]
pub async fn remove_virtual_member(
    State(state): State<SharedState>,
    Extension(auth): Extension<Option<AuthExtension>>,
    Path((key, member_key)): Path<(String, String)>,
) -> Result<()> {
    let auth = require_auth(auth)?;
    auth.require_scope("write")?;
    let service = RepositoryService::new(state.db.clone());

    let virtual_repo = service.get_by_key(&key).await?;
    require_repo_access(&auth, virtual_repo.id)?;
    let member_repo = service.get_by_key(&member_key).await?;

    if virtual_repo.repo_type != RepositoryType::Virtual {
        return Err(AppError::Validation(
            "Only virtual repositories have members".to_string(),
        ));
    }

    sqlx::query(
        "DELETE FROM virtual_repo_members WHERE virtual_repo_id = $1 AND member_repo_id = $2",
    )
    .bind(virtual_repo.id)
    .bind(member_repo.id)
    .execute(&state.db)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;

    Ok(())
}

/// Update priorities for all members (bulk reorder)
#[utoipa::path(
    put,
    path = "/{key}/members",
    context_path = "/api/v1/repositories",
    tag = "repositories",
    params(
        ("key" = String, Path, description = "Repository key"),
    ),
    request_body = UpdateVirtualMembersRequest,
    security(("bearer_auth" = [])),
    responses(
        (status = 200, description = "Members updated", body = VirtualMembersListResponse),
        (status = 400, description = "Repository is not virtual"),
        (status = 401, description = "Authentication required"),
        (status = 404, description = "Repository not found"),
    )
)]
pub async fn update_virtual_members(
    State(state): State<SharedState>,
    Extension(auth): Extension<Option<AuthExtension>>,
    Path(key): Path<String>,
    Json(payload): Json<UpdateVirtualMembersRequest>,
) -> Result<Json<VirtualMembersListResponse>> {
    let auth = require_auth(auth)?;
    auth.require_scope("write")?;
    let service = RepositoryService::new(state.db.clone());

    let virtual_repo = service.get_by_key(&key).await?;
    require_repo_access(&auth, virtual_repo.id)?;

    if virtual_repo.repo_type != RepositoryType::Virtual {
        return Err(AppError::Validation(
            "Only virtual repositories have members".to_string(),
        ));
    }

    // Update priorities for each member
    for member in &payload.members {
        let member_repo = service.get_by_key(&member.member_key).await?;

        sqlx::query(
            "UPDATE virtual_repo_members SET priority = $1 WHERE virtual_repo_id = $2 AND member_repo_id = $3",
        )
        .bind(member.priority)
        .bind(virtual_repo.id)
        .bind(member_repo.id)
        .execute(&state.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;
    }

    // Return updated list
    list_virtual_members(State(state), Path(key)).await
}

// ---------------------------------------------------------------------------
// Upstream auth management
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize, ToSchema)]
pub struct UpstreamAuthRequest {
    /// Auth type: "basic", "bearer", or "none" to remove.
    pub auth_type: String,
    /// Username for basic auth.
    pub username: Option<String>,
    /// Password (basic) or token (bearer). Write-only, never returned.
    pub password: Option<String>,
}

/// Set or remove upstream auth for a remote repository
#[utoipa::path(
    put,
    path = "/{key}/upstream-auth",
    context_path = "/api/v1/repositories",
    tag = "repositories",
    params(
        ("key" = String, Path, description = "Repository key"),
    ),
    request_body = UpstreamAuthRequest,
    security(("bearer_auth" = [])),
    responses(
        (status = 200, description = "Upstream auth updated"),
        (status = 400, description = "Invalid auth type or missing fields"),
        (status = 401, description = "Authentication required"),
        (status = 404, description = "Repository not found"),
    )
)]
pub async fn set_upstream_auth(
    State(state): State<SharedState>,
    Extension(auth): Extension<Option<AuthExtension>>,
    Path(key): Path<String>,
    Json(payload): Json<UpstreamAuthRequest>,
) -> Result<Json<serde_json::Value>> {
    let auth = require_auth(auth)?;
    auth.require_scope("write")?;

    let service = RepositoryService::new(state.db.clone());
    let repo = service.get_by_key(&key).await?;
    require_repo_access(&auth, repo.id)?;

    if repo.repo_type != RepositoryType::Remote {
        return Err(AppError::Validation(
            "Upstream auth is only valid for remote repositories".to_string(),
        ));
    }

    if payload.auth_type == "none" {
        crate::services::upstream_auth::remove_upstream_auth(&state.db, repo.id).await?;
        return Ok(Json(
            serde_json::json!({"message": "Upstream auth removed"}),
        ));
    }

    let credentials_json = build_upstream_credentials(
        &payload.auth_type,
        payload.username.as_deref(),
        payload.password.as_deref(),
    )?;

    crate::services::upstream_auth::save_upstream_auth(
        &state.db,
        repo.id,
        &payload.auth_type,
        &credentials_json,
    )
    .await?;

    Ok(Json(
        serde_json::json!({"message": "Upstream auth configured"}),
    ))
}

/// Test connectivity to the upstream URL of a remote repository
#[utoipa::path(
    post,
    path = "/{key}/test-upstream",
    context_path = "/api/v1/repositories",
    tag = "repositories",
    params(
        ("key" = String, Path, description = "Repository key"),
    ),
    security(("bearer_auth" = [])),
    responses(
        (status = 200, description = "Upstream reachable"),
        (status = 400, description = "Repository is not remote or has no upstream URL"),
        (status = 401, description = "Authentication required"),
        (status = 404, description = "Repository not found"),
        (status = 502, description = "Upstream unreachable"),
    )
)]
pub async fn test_upstream(
    State(state): State<SharedState>,
    Extension(auth): Extension<Option<AuthExtension>>,
    Path(key): Path<String>,
) -> Result<Json<serde_json::Value>> {
    let auth = require_auth(auth)?;
    auth.require_scope("read")?;

    let service = RepositoryService::new(state.db.clone());
    let repo = service.get_by_key(&key).await?;
    require_repo_access(&auth, repo.id)?;

    if repo.repo_type != RepositoryType::Remote {
        return Err(AppError::Validation(
            "Only remote repositories have an upstream URL".to_string(),
        ));
    }

    let upstream_url = repo.upstream_url.as_deref().ok_or_else(|| {
        AppError::Validation("Repository has no upstream URL configured".to_string())
    })?;

    let client = crate::services::http_client::base_client_builder()
        .timeout(Duration::from_secs(15))
        .build()
        .map_err(|e| AppError::Internal(format!("Failed to build HTTP client: {e}")))?;

    let mut request = client.head(upstream_url);

    // Apply upstream auth if configured
    if let Some(upstream_auth) =
        crate::services::upstream_auth::load_upstream_auth(&state.db, repo.id).await?
    {
        request = crate::services::upstream_auth::apply_upstream_auth(request, &upstream_auth);
    }

    let response = request
        .send()
        .await
        .map_err(|e| AppError::BadGateway(format!("Failed to reach upstream: {e}")))?;

    let status = response.status().as_u16();
    // 2xx or 404 (root URL may not serve content) are acceptable
    if response.status().is_success() || status == 404 {
        Ok(Json(serde_json::json!({
            "status": "ok",
            "upstream_status": status,
            "upstream_url": upstream_url,
        })))
    } else {
        Err(AppError::BadGateway(format!(
            "Upstream returned HTTP {status}"
        )))
    }
}

#[derive(OpenApi)]
#[openapi(
    paths(
        list_repositories,
        create_repository,
        get_repository,
        update_repository,
        delete_repository,
        set_cache_ttl,
        get_cache_ttl,
        list_artifacts,
        get_artifact_metadata,
        upload_artifact,
        download_artifact,
        delete_artifact,
        list_virtual_members,
        add_virtual_member,
        remove_virtual_member,
        update_virtual_members,
        set_upstream_auth,
        test_upstream,
    ),
    components(schemas(
        ListRepositoriesQuery,
        CreateRepositoryRequest,
        UpdateRepositoryRequest,
        RepositoryResponse,
        RepositoryListResponse,
        SetCacheTtlRequest,
        CacheTtlResponse,
        ListArtifactsQuery,
        ArtifactResponse,
        ArtifactListResponse,
        AddVirtualMemberRequest,
        UpdateVirtualMembersRequest,
        VirtualMemberPriority,
        VirtualMemberResponse,
        VirtualMembersListResponse,
        CreateVirtualMemberInput,
        UpstreamAuthRequest,
    ))
)]
pub struct RepositoriesApiDoc;

/// Resolve the effective priority for a virtual member.
/// Uses the explicit priority if > 0, otherwise assigns a 1-based index.
fn resolve_member_priority(explicit: i32, index: usize) -> i32 {
    if explicit > 0 {
        explicit
    } else {
        (index as i32) + 1
    }
}

/// Build a JSON credential string from an upstream auth request.
/// Validates that the required fields are present for the given auth type.
fn build_upstream_credentials(
    auth_type: &str,
    username: Option<&str>,
    password: Option<&str>,
) -> crate::error::Result<String> {
    match auth_type {
        "basic" => {
            let username = username.ok_or_else(|| {
                AppError::Validation("username is required for basic auth".to_string())
            })?;
            let password = password.ok_or_else(|| {
                AppError::Validation("password is required for basic auth".to_string())
            })?;
            Ok(serde_json::json!({"username": username, "password": password}).to_string())
        }
        "bearer" => {
            let token = password.ok_or_else(|| {
                AppError::Validation(
                    "password is required for bearer auth (used as token)".to_string(),
                )
            })?;
            Ok(serde_json::json!({"token": token}).to_string())
        }
        other => Err(AppError::Validation(format!(
            "Invalid auth_type: {other}. Must be 'basic', 'bearer', or 'none'"
        ))),
    }
}

/// Convert a VirtualMemberRow into a VirtualMemberResponse.
fn map_member_row(row: VirtualMemberRow) -> VirtualMemberResponse {
    VirtualMemberResponse {
        id: row.id,
        member_repo_id: row.member_repo_id,
        member_repo_key: row.member_key,
        member_repo_name: row.member_name,
        member_repo_type: format_repo_type(&row.repo_type),
        priority: row.priority,
        created_at: row.created_at,
    }
}

/// Format a RepositoryType as a lowercase string for API responses.
fn format_repo_type(repo_type: &RepositoryType) -> String {
    format!("{:?}", repo_type).to_lowercase()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::AppError;

    // -----------------------------------------------------------------------
    // Extracted pure functions for testability
    // -----------------------------------------------------------------------

    /// Compute pagination offset from page number and per_page size.
    fn compute_pagination(page: Option<u32>, per_page: Option<u32>) -> (u32, u32, i64) {
        let page = page.unwrap_or(1).max(1);
        let per_page = per_page.unwrap_or(20).min(100);
        let offset = ((page - 1) * per_page) as i64;
        (page, per_page, offset)
    }

    /// Compute total number of pages given total items and per_page size.
    fn compute_total_pages(total: i64, per_page: u32) -> u32 {
        ((total as f64) / (per_page as f64)).ceil() as u32
    }

    /// Extract the filename from a slash-delimited path.
    fn extract_name_from_path(path: &str) -> String {
        path.split('/').next_back().unwrap_or(path).to_string()
    }

    /// Build a storage path from a base dir and repository key.
    fn build_storage_path(storage_base: &str, repo_key: &str) -> String {
        format!("{}/{}", storage_base, repo_key)
    }

    /// Build a Content-Disposition attachment header value.
    fn content_disposition_attachment(filename: &str) -> String {
        format!("attachment; filename=\"{}\"", filename)
    }

    /// Extract the download filename from an artifact path.
    fn extract_download_filename(path: &str) -> &str {
        path.rsplit('/').next().unwrap_or(path)
    }

    /// Parse a client IP address from an X-Forwarded-For header value.
    fn parse_client_ip(xff_value: Option<&str>) -> std::net::IpAddr {
        xff_value
            .and_then(|s| s.split(',').next())
            .unwrap_or("127.0.0.1")
            .trim()
            .parse()
            .unwrap_or(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST))
    }

    // -----------------------------------------------------------------------
    // validate_repository_key
    // -----------------------------------------------------------------------

    #[test]
    fn test_validate_repository_key_valid_simple() {
        assert!(validate_repository_key("my-repo").is_ok());
    }

    #[test]
    fn test_validate_repository_key_valid_with_dots() {
        assert!(validate_repository_key("my.repo.name").is_ok());
    }

    #[test]
    fn test_validate_repository_key_valid_with_underscores() {
        assert!(validate_repository_key("my_repo_name").is_ok());
    }

    #[test]
    fn test_validate_repository_key_valid_alphanumeric() {
        assert!(validate_repository_key("myRepo123").is_ok());
    }

    #[test]
    fn test_validate_repository_key_empty() {
        let result = validate_repository_key("");
        assert!(result.is_err());
        match result.unwrap_err() {
            AppError::Validation(msg) => assert!(msg.contains("between 1 and 128")),
            other => panic!("Expected Validation error, got: {:?}", other),
        }
    }

    #[test]
    fn test_validate_repository_key_too_long() {
        let long_key = "a".repeat(129);
        let result = validate_repository_key(&long_key);
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_repository_key_max_length() {
        let key = "a".repeat(128);
        assert!(validate_repository_key(&key).is_ok());
    }

    #[test]
    fn test_validate_repository_key_starts_with_dot() {
        let result = validate_repository_key(".hidden");
        assert!(result.is_err());
        match result.unwrap_err() {
            AppError::Validation(msg) => assert!(msg.contains("must not start with")),
            other => panic!("Expected Validation error, got: {:?}", other),
        }
    }

    #[test]
    fn test_validate_repository_key_starts_with_hyphen() {
        let result = validate_repository_key("-bad");
        assert!(result.is_err());
        match result.unwrap_err() {
            AppError::Validation(msg) => assert!(msg.contains("must not start with")),
            other => panic!("Expected Validation error, got: {:?}", other),
        }
    }

    #[test]
    fn test_validate_repository_key_consecutive_dots() {
        let result = validate_repository_key("bad..key");
        assert!(result.is_err());
        match result.unwrap_err() {
            AppError::Validation(msg) => assert!(msg.contains("consecutive dots")),
            other => panic!("Expected Validation error, got: {:?}", other),
        }
    }

    #[test]
    fn test_validate_repository_key_special_chars() {
        let result = validate_repository_key("bad/key");
        assert!(result.is_err());
        match result.unwrap_err() {
            AppError::Validation(msg) => assert!(msg.contains("alphanumeric")),
            other => panic!("Expected Validation error, got: {:?}", other),
        }
    }

    #[test]
    fn test_validate_repository_key_spaces() {
        let result = validate_repository_key("bad key");
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_repository_key_at_sign() {
        let result = validate_repository_key("bad@key");
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_repository_key_single_char() {
        assert!(validate_repository_key("a").is_ok());
    }

    #[test]
    fn test_validate_repository_key_underscore_start() {
        assert!(validate_repository_key("_repo").is_ok());
    }

    // -----------------------------------------------------------------------
    // parse_format
    // -----------------------------------------------------------------------

    #[test]
    fn test_parse_format_maven() {
        assert_eq!(parse_format("maven").unwrap(), RepositoryFormat::Maven);
    }

    #[test]
    fn test_parse_format_npm() {
        assert_eq!(parse_format("npm").unwrap(), RepositoryFormat::Npm);
    }

    #[test]
    fn test_parse_format_pypi() {
        assert_eq!(parse_format("pypi").unwrap(), RepositoryFormat::Pypi);
    }

    #[test]
    fn test_parse_format_docker() {
        assert_eq!(parse_format("docker").unwrap(), RepositoryFormat::Docker);
    }

    #[test]
    fn test_parse_format_cargo() {
        assert_eq!(parse_format("cargo").unwrap(), RepositoryFormat::Cargo);
    }

    #[test]
    fn test_parse_format_conan() {
        assert_eq!(parse_format("conan").unwrap(), RepositoryFormat::Conan);
    }

    #[test]
    fn test_parse_format_debian() {
        assert_eq!(parse_format("debian").unwrap(), RepositoryFormat::Debian);
    }

    #[test]
    fn test_parse_format_generic() {
        assert_eq!(parse_format("generic").unwrap(), RepositoryFormat::Generic);
    }

    #[test]
    fn test_parse_format_helm() {
        assert_eq!(parse_format("helm").unwrap(), RepositoryFormat::Helm);
    }

    #[test]
    fn test_parse_format_nuget() {
        assert_eq!(parse_format("nuget").unwrap(), RepositoryFormat::Nuget);
    }

    #[test]
    fn test_parse_format_go() {
        assert_eq!(parse_format("go").unwrap(), RepositoryFormat::Go);
    }

    #[test]
    fn test_parse_format_rubygems() {
        assert_eq!(
            parse_format("rubygems").unwrap(),
            RepositoryFormat::Rubygems
        );
    }

    #[test]
    fn test_parse_format_rpm() {
        assert_eq!(parse_format("rpm").unwrap(), RepositoryFormat::Rpm);
    }

    #[test]
    fn test_parse_format_protobuf() {
        assert_eq!(
            parse_format("protobuf").unwrap(),
            RepositoryFormat::Protobuf
        );
    }

    #[test]
    fn test_parse_format_case_insensitive() {
        assert_eq!(parse_format("Maven").unwrap(), RepositoryFormat::Maven);
        assert_eq!(parse_format("NPM").unwrap(), RepositoryFormat::Npm);
        assert_eq!(parse_format("DOCKER").unwrap(), RepositoryFormat::Docker);
    }

    #[test]
    fn test_parse_format_invalid() {
        let result = parse_format("invalid_format");
        assert!(result.is_err());
        match result.unwrap_err() {
            AppError::Validation(msg) => assert!(msg.contains("Invalid format")),
            other => panic!("Expected Validation error, got: {:?}", other),
        }
    }

    #[test]
    fn test_parse_format_all_formats() {
        // Ensure all 45+ formats parse correctly
        let formats = vec![
            "maven",
            "gradle",
            "npm",
            "pypi",
            "nuget",
            "go",
            "rubygems",
            "docker",
            "helm",
            "rpm",
            "debian",
            "conan",
            "cargo",
            "generic",
            "podman",
            "buildx",
            "oras",
            "wasm_oci",
            "helm_oci",
            "poetry",
            "conda",
            "yarn",
            "bower",
            "pnpm",
            "chocolatey",
            "powershell",
            "terraform",
            "opentofu",
            "alpine",
            "conda_native",
            "composer",
            "hex",
            "cocoapods",
            "swift",
            "pub",
            "sbt",
            "chef",
            "puppet",
            "ansible",
            "gitlfs",
            "vscode",
            "jetbrains",
            "huggingface",
            "mlmodel",
            "cran",
            "vagrant",
            "opkg",
            "p2",
            "bazel",
            "protobuf",
        ];
        for f in formats {
            assert!(parse_format(f).is_ok(), "parse_format failed for: {}", f);
        }
    }

    // -----------------------------------------------------------------------
    // parse_repo_type
    // -----------------------------------------------------------------------

    #[test]
    fn test_parse_repo_type_local() {
        assert_eq!(parse_repo_type("local").unwrap(), RepositoryType::Local);
    }

    #[test]
    fn test_parse_repo_type_remote() {
        assert_eq!(parse_repo_type("remote").unwrap(), RepositoryType::Remote);
    }

    #[test]
    fn test_parse_repo_type_virtual() {
        assert_eq!(parse_repo_type("virtual").unwrap(), RepositoryType::Virtual);
    }

    #[test]
    fn test_parse_repo_type_staging() {
        assert_eq!(parse_repo_type("staging").unwrap(), RepositoryType::Staging);
    }

    #[test]
    fn test_parse_repo_type_case_insensitive() {
        assert_eq!(parse_repo_type("Local").unwrap(), RepositoryType::Local);
        assert_eq!(parse_repo_type("REMOTE").unwrap(), RepositoryType::Remote);
        assert_eq!(parse_repo_type("Virtual").unwrap(), RepositoryType::Virtual);
    }

    #[test]
    fn test_parse_repo_type_invalid() {
        let result = parse_repo_type("nonexistent");
        assert!(result.is_err());
        match result.unwrap_err() {
            AppError::Validation(msg) => assert!(msg.contains("Invalid repo type")),
            other => panic!("Expected Validation error, got: {:?}", other),
        }
    }

    // -----------------------------------------------------------------------
    // require_auth
    // -----------------------------------------------------------------------

    #[test]
    fn test_require_auth_some() {
        let auth = AuthExtension {
            user_id: Uuid::new_v4(),
            username: "test".to_string(),
            email: "test@example.com".to_string(),
            is_admin: false,
            is_api_token: false,
            is_service_account: false,
            scopes: None,
            allowed_repo_ids: None,
        };
        assert!(require_auth(Some(auth)).is_ok());
    }

    #[test]
    fn test_require_auth_none() {
        let result = require_auth(None);
        assert!(result.is_err());
        match result.unwrap_err() {
            AppError::Authentication(msg) => assert!(msg.contains("Authentication required")),
            other => panic!("Expected Authentication error, got: {:?}", other),
        }
    }

    // -----------------------------------------------------------------------
    // DTO serialization / deserialization
    // -----------------------------------------------------------------------

    #[test]
    fn test_create_repository_request_deserialization() {
        let json = r#"{
            "key": "my-repo",
            "name": "My Repo",
            "description": "A test repo",
            "format": "maven",
            "repo_type": "local",
            "is_public": true,
            "upstream_url": null,
            "quota_bytes": 1073741824
        }"#;
        let req: CreateRepositoryRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.key, "my-repo");
        assert_eq!(req.name, "My Repo");
        assert_eq!(req.description, Some("A test repo".to_string()));
        assert_eq!(req.format, "maven");
        assert_eq!(req.repo_type, "local");
        assert_eq!(req.is_public, Some(true));
        assert!(req.upstream_url.is_none());
        assert_eq!(req.quota_bytes, Some(1073741824));
    }

    #[test]
    fn test_create_repository_request_minimal() {
        let json = r#"{
            "key": "k",
            "name": "n",
            "format": "npm",
            "repo_type": "local"
        }"#;
        let req: CreateRepositoryRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.key, "k");
        assert!(req.description.is_none());
        assert!(req.is_public.is_none());
        assert!(req.upstream_url.is_none());
        assert!(req.quota_bytes.is_none());
    }

    #[test]
    fn test_update_repository_request_all_none() {
        let json = r#"{}"#;
        let req: UpdateRepositoryRequest = serde_json::from_str(json).unwrap();
        assert!(req.key.is_none());
        assert!(req.name.is_none());
        assert!(req.description.is_none());
        assert!(req.is_public.is_none());
        assert!(req.quota_bytes.is_none());
    }

    #[test]
    fn test_repository_response_serialization() {
        let resp = RepositoryResponse {
            id: Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000").unwrap(),
            key: "my-repo".to_string(),
            name: "My Repo".to_string(),
            description: Some("desc".to_string()),
            format: "maven".to_string(),
            repo_type: "local".to_string(),
            is_public: true,
            storage_used_bytes: 1024,
            quota_bytes: Some(1048576),
            upstream_auth_type: None,
            upstream_auth_configured: false,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        };
        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains("\"key\":\"my-repo\""));
        assert!(json.contains("\"storage_used_bytes\":1024"));
        assert!(json.contains("\"quota_bytes\":1048576"));
    }

    #[test]
    fn test_list_repositories_query_deserialization() {
        let json = r#"{
            "page": 2,
            "per_page": 50,
            "format": "npm",
            "type": "local",
            "q": "test"
        }"#;
        let query: ListRepositoriesQuery = serde_json::from_str(json).unwrap();
        assert_eq!(query.page, Some(2));
        assert_eq!(query.per_page, Some(50));
        assert_eq!(query.format, Some("npm".to_string()));
        assert_eq!(query.repo_type, Some("local".to_string()));
        assert_eq!(query.q, Some("test".to_string()));
    }

    #[test]
    fn test_list_repositories_query_repo_type_alias() {
        // Frontend may send "repo_type" instead of "type" — both must work
        let json = r#"{
            "repo_type": "staging"
        }"#;
        let query: ListRepositoriesQuery = serde_json::from_str(json).unwrap();
        assert_eq!(query.repo_type, Some("staging".to_string()));
    }

    #[test]
    fn test_list_artifacts_query_defaults() {
        let json = r#"{}"#;
        let query: ListArtifactsQuery = serde_json::from_str(json).unwrap();
        assert!(query.page.is_none());
        assert!(query.per_page.is_none());
        assert!(query.q.is_none());
        assert!(query.path_prefix.is_none());
    }

    #[test]
    fn test_artifact_response_serialization() {
        let resp = ArtifactResponse {
            id: Uuid::new_v4(),
            repository_key: "my-repo".to_string(),
            path: "org/example/1.0/example-1.0.jar".to_string(),
            name: "example".to_string(),
            version: Some("1.0".to_string()),
            size_bytes: 1024,
            checksum_sha256: "abc123".to_string(),
            content_type: "application/java-archive".to_string(),
            download_count: 42,
            created_at: chrono::Utc::now(),
            metadata: None,
        };
        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains("\"download_count\":42"));
        assert!(json.contains("\"size_bytes\":1024"));
    }

    #[test]
    fn test_add_virtual_member_request_deserialization() {
        let json = r#"{"member_key": "upstream-repo", "priority": 10}"#;
        let req: AddVirtualMemberRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.member_key, "upstream-repo");
        assert_eq!(req.priority, Some(10));
    }

    #[test]
    fn test_add_virtual_member_request_no_priority() {
        let json = r#"{"member_key": "upstream-repo"}"#;
        let req: AddVirtualMemberRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.member_key, "upstream-repo");
        assert!(req.priority.is_none());
    }

    #[test]
    fn test_update_virtual_members_request_deserialization() {
        let json = r#"{
            "members": [
                {"member_key": "repo-a", "priority": 1},
                {"member_key": "repo-b", "priority": 2}
            ]
        }"#;
        let req: UpdateVirtualMembersRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.members.len(), 2);
        assert_eq!(req.members[0].member_key, "repo-a");
        assert_eq!(req.members[0].priority, 1);
        assert_eq!(req.members[1].member_key, "repo-b");
        assert_eq!(req.members[1].priority, 2);
    }

    #[test]
    fn test_virtual_member_response_serialization() {
        let resp = VirtualMemberResponse {
            id: Uuid::new_v4(),
            member_repo_id: Uuid::new_v4(),
            member_repo_key: "upstream".to_string(),
            member_repo_name: "Upstream Repo".to_string(),
            member_repo_type: "remote".to_string(),
            priority: 1,
            created_at: chrono::Utc::now(),
        };
        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains("\"member_repo_key\":\"upstream\""));
        assert!(json.contains("\"priority\":1"));
    }

    // -----------------------------------------------------------------------
    // compute_pagination
    // -----------------------------------------------------------------------

    #[test]
    fn test_compute_pagination_defaults() {
        let (page, per_page, offset) = compute_pagination(None, None);
        assert_eq!(page, 1);
        assert_eq!(per_page, 20);
        assert_eq!(offset, 0);
    }

    #[test]
    fn test_compute_pagination_custom_values() {
        let (page, per_page, offset) = compute_pagination(Some(3), Some(50));
        assert_eq!(page, 3);
        assert_eq!(per_page, 50);
        assert_eq!(offset, 100);
    }

    #[test]
    fn test_compute_pagination_page_zero_becomes_one() {
        let (page, _, offset) = compute_pagination(Some(0), Some(10));
        assert_eq!(page, 1);
        assert_eq!(offset, 0);
    }

    #[test]
    fn test_compute_pagination_per_page_capped_at_100() {
        let (_, per_page, _) = compute_pagination(Some(1), Some(200));
        assert_eq!(per_page, 100);
    }

    #[test]
    fn test_compute_pagination_large_page() {
        let (page, per_page, offset) = compute_pagination(Some(100), Some(25));
        assert_eq!(page, 100);
        assert_eq!(per_page, 25);
        assert_eq!(offset, 2475);
    }

    // -----------------------------------------------------------------------
    // compute_total_pages
    // -----------------------------------------------------------------------

    #[test]
    fn test_compute_total_pages_exact() {
        assert_eq!(compute_total_pages(100, 20), 5);
    }

    #[test]
    fn test_compute_total_pages_remainder() {
        assert_eq!(compute_total_pages(101, 20), 6);
    }

    #[test]
    fn test_compute_total_pages_zero_total() {
        assert_eq!(compute_total_pages(0, 20), 0);
    }

    #[test]
    fn test_compute_total_pages_single_item() {
        assert_eq!(compute_total_pages(1, 20), 1);
    }

    #[test]
    fn test_compute_total_pages_one_per_page() {
        assert_eq!(compute_total_pages(5, 1), 5);
    }

    // -----------------------------------------------------------------------
    // extract_name_from_path
    // -----------------------------------------------------------------------

    #[test]
    fn test_extract_name_from_path_nested() {
        assert_eq!(
            extract_name_from_path("org/example/1.0/example-1.0.jar"),
            "example-1.0.jar"
        );
    }

    #[test]
    fn test_extract_name_from_path_simple() {
        assert_eq!(extract_name_from_path("myfile.txt"), "myfile.txt");
    }

    #[test]
    fn test_extract_name_from_path_trailing_slash() {
        // rsplit next_back gives empty string after trailing slash
        assert_eq!(extract_name_from_path("some/path/"), "");
    }

    #[test]
    fn test_extract_name_from_path_deep() {
        assert_eq!(extract_name_from_path("a/b/c/d/e/file.bin"), "file.bin");
    }

    // -----------------------------------------------------------------------
    // build_storage_path
    // -----------------------------------------------------------------------

    #[test]
    fn test_build_storage_path_basic() {
        assert_eq!(
            build_storage_path("/var/data", "my-repo"),
            "/var/data/my-repo"
        );
    }

    #[test]
    fn test_build_storage_path_relative() {
        assert_eq!(
            build_storage_path("./storage", "repo-1"),
            "./storage/repo-1"
        );
    }

    // -----------------------------------------------------------------------
    // content_disposition_attachment
    // -----------------------------------------------------------------------

    #[test]
    fn test_content_disposition_attachment_simple() {
        assert_eq!(
            content_disposition_attachment("file.jar"),
            "attachment; filename=\"file.jar\""
        );
    }

    #[test]
    fn test_content_disposition_attachment_spaces() {
        assert_eq!(
            content_disposition_attachment("my file.zip"),
            "attachment; filename=\"my file.zip\""
        );
    }

    // -----------------------------------------------------------------------
    // extract_download_filename
    // -----------------------------------------------------------------------

    #[test]
    fn test_extract_download_filename_path() {
        assert_eq!(
            extract_download_filename("org/example/1.0/example.jar"),
            "example.jar"
        );
    }

    #[test]
    fn test_extract_download_filename_no_slash() {
        assert_eq!(
            extract_download_filename("single-file.txt"),
            "single-file.txt"
        );
    }

    // -----------------------------------------------------------------------
    // parse_client_ip
    // -----------------------------------------------------------------------

    #[test]
    fn test_parse_client_ip_single() {
        let ip = parse_client_ip(Some("10.0.0.1"));
        assert_eq!(ip.to_string(), "10.0.0.1");
    }

    #[test]
    fn test_parse_client_ip_chain() {
        let ip = parse_client_ip(Some("10.0.0.1, 192.168.1.1, 172.16.0.1"));
        assert_eq!(ip.to_string(), "10.0.0.1");
    }

    #[test]
    fn test_parse_client_ip_none() {
        let ip = parse_client_ip(None);
        assert_eq!(ip.to_string(), "127.0.0.1");
    }

    #[test]
    fn test_parse_client_ip_invalid() {
        let ip = parse_client_ip(Some("not-an-ip"));
        assert_eq!(ip.to_string(), "127.0.0.1");
    }

    #[test]
    fn test_parse_client_ip_ipv6() {
        let ip = parse_client_ip(Some("::1"));
        assert_eq!(ip.to_string(), "::1");
    }

    #[test]
    fn test_parse_client_ip_empty() {
        let ip = parse_client_ip(Some(""));
        assert_eq!(ip.to_string(), "127.0.0.1");
    }

    // -----------------------------------------------------------------------
    // repo_to_response
    // -----------------------------------------------------------------------

    #[test]
    fn test_repo_to_response_basic() {
        use crate::models::repository::{ReplicationPriority, Repository};

        let now = chrono::Utc::now();
        let repo = Repository {
            id: Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000").unwrap(),
            key: "maven-central".to_string(),
            name: "Maven Central".to_string(),
            description: Some("Central Maven repo".to_string()),
            format: RepositoryFormat::Maven,
            repo_type: RepositoryType::Local,
            storage_backend: "filesystem".to_string(),
            storage_path: "/data/maven".to_string(),
            upstream_url: None,
            is_public: true,
            quota_bytes: Some(1073741824),
            replication_priority: ReplicationPriority::Immediate,
            promotion_target_id: None,
            promotion_policy_id: None,
            curation_enabled: false,
            curation_source_repo_id: None,
            curation_target_repo_id: None,
            curation_default_action: "allow".to_string(),
            curation_sync_interval_secs: 3600,
            curation_auto_fetch: false,
            created_at: now,
            updated_at: now,
        };

        let response = repo_to_response(repo, 5000);
        assert_eq!(response.key, "maven-central");
        assert_eq!(response.name, "Maven Central");
        assert_eq!(response.format, "maven");
        assert_eq!(response.repo_type, "local");
        assert!(response.is_public);
        assert_eq!(response.storage_used_bytes, 5000);
        assert_eq!(response.quota_bytes, Some(1073741824));
    }

    #[test]
    fn test_repo_to_response_zero_storage() {
        use crate::models::repository::{ReplicationPriority, Repository};

        let now = chrono::Utc::now();
        let repo = Repository {
            id: Uuid::new_v4(),
            key: "npm-hosted".to_string(),
            name: "NPM Local".to_string(),
            description: None,
            format: RepositoryFormat::Npm,
            repo_type: RepositoryType::Remote,
            storage_backend: "s3".to_string(),
            storage_path: "/data/npm".to_string(),
            upstream_url: Some("https://registry.npmjs.org".to_string()),
            is_public: false,
            quota_bytes: None,
            replication_priority: ReplicationPriority::OnDemand,
            promotion_target_id: None,
            promotion_policy_id: None,
            curation_enabled: false,
            curation_source_repo_id: None,
            curation_target_repo_id: None,
            curation_default_action: "allow".to_string(),
            curation_sync_interval_secs: 3600,
            curation_auto_fetch: false,
            created_at: now,
            updated_at: now,
        };

        let response = repo_to_response(repo, 0);
        assert_eq!(response.format, "npm");
        assert_eq!(response.repo_type, "remote");
        assert!(!response.is_public);
        assert_eq!(response.storage_used_bytes, 0);
        assert!(response.quota_bytes.is_none());
        assert!(response.description.is_none());
    }

    #[test]
    fn test_repo_to_response_virtual() {
        use crate::models::repository::{ReplicationPriority, Repository};

        let now = chrono::Utc::now();
        let repo = Repository {
            id: Uuid::new_v4(),
            key: "docker-all".to_string(),
            name: "Docker Virtual".to_string(),
            description: Some("Aggregated Docker".to_string()),
            format: RepositoryFormat::Docker,
            storage_backend: "filesystem".to_string(),
            repo_type: RepositoryType::Virtual,
            storage_path: "/data/docker".to_string(),
            upstream_url: None,
            is_public: true,
            quota_bytes: None,
            replication_priority: ReplicationPriority::LocalOnly,
            promotion_target_id: None,
            promotion_policy_id: None,
            curation_enabled: false,
            curation_source_repo_id: None,
            curation_target_repo_id: None,
            curation_default_action: "allow".to_string(),
            curation_sync_interval_secs: 3600,
            curation_auto_fetch: false,
            created_at: now,
            updated_at: now,
        };

        let response = repo_to_response(repo, 1024 * 1024);
        assert_eq!(response.format, "docker");
        assert_eq!(response.repo_type, "virtual");
        assert_eq!(response.storage_used_bytes, 1024 * 1024);
    }

    #[test]
    fn test_repo_to_response_staging_with_promotion() {
        use crate::models::repository::{ReplicationPriority, Repository};

        let now = chrono::Utc::now();
        let target_id = Uuid::new_v4();
        let policy_id = Uuid::new_v4();
        let repo = Repository {
            id: Uuid::new_v4(),
            key: "cargo-staging".to_string(),
            name: "Cargo Staging".to_string(),
            description: None,
            format: RepositoryFormat::Cargo,
            storage_backend: "filesystem".to_string(),
            repo_type: RepositoryType::Staging,
            storage_path: "/data/cargo-staging".to_string(),
            upstream_url: None,
            is_public: false,
            quota_bytes: Some(5_000_000_000),
            replication_priority: ReplicationPriority::Scheduled,
            promotion_target_id: Some(target_id),
            promotion_policy_id: Some(policy_id),
            curation_enabled: false,
            curation_source_repo_id: None,
            curation_target_repo_id: None,
            curation_default_action: "allow".to_string(),
            curation_sync_interval_secs: 3600,
            curation_auto_fetch: false,
            created_at: now,
            updated_at: now,
        };

        let response = repo_to_response(repo, 42);
        assert_eq!(response.format, "cargo");
        assert_eq!(response.repo_type, "staging");
        assert_eq!(response.storage_used_bytes, 42);
        assert_eq!(response.quota_bytes, Some(5_000_000_000));
    }

    // -----------------------------------------------------------------------
    // require_auth
    // -----------------------------------------------------------------------

    fn make_auth_ext(repo_ids: Option<Vec<Uuid>>) -> AuthExtension {
        AuthExtension {
            user_id: Uuid::new_v4(),
            username: "tester".to_string(),
            email: "test@example.com".to_string(),
            is_admin: false,
            is_api_token: false,
            is_service_account: false,
            scopes: None,
            allowed_repo_ids: repo_ids,
        }
    }

    #[test]
    fn test_require_auth_with_some() {
        let ext = make_auth_ext(None);
        let result = require_auth(Some(ext));
        assert!(result.is_ok());
        assert_eq!(result.unwrap().username, "tester");
    }

    #[test]
    fn test_require_auth_with_none() {
        let result = require_auth(None);
        assert!(result.is_err());
        match result.unwrap_err() {
            AppError::Authentication(msg) => assert!(msg.contains("Authentication required")),
            other => panic!("Expected Authentication error, got: {:?}", other),
        }
    }

    // -----------------------------------------------------------------------
    // require_repo_access
    // -----------------------------------------------------------------------

    #[test]
    fn test_require_repo_access_unrestricted() {
        let ext = make_auth_ext(None);
        let repo_id = Uuid::new_v4();
        assert!(require_repo_access(&ext, repo_id).is_ok());
    }

    #[test]
    fn test_require_repo_access_allowed() {
        let repo_id = Uuid::new_v4();
        let ext = make_auth_ext(Some(vec![repo_id]));
        assert!(require_repo_access(&ext, repo_id).is_ok());
    }

    #[test]
    fn test_require_repo_access_denied() {
        let allowed = Uuid::new_v4();
        let denied = Uuid::new_v4();
        let ext = make_auth_ext(Some(vec![allowed]));
        let result = require_repo_access(&ext, denied);
        assert!(result.is_err());
        match result.unwrap_err() {
            AppError::Authorization(msg) => {
                assert!(msg.contains("does not have access"))
            }
            other => panic!("Expected Authorization error, got: {:?}", other),
        }
    }

    // -----------------------------------------------------------------------
    // require_visible
    // -----------------------------------------------------------------------

    fn make_repo(is_public: bool) -> crate::models::repository::Repository {
        use crate::models::repository::{ReplicationPriority, Repository};

        let now = chrono::Utc::now();
        Repository {
            id: Uuid::new_v4(),
            key: "test-repo".to_string(),
            name: "Test Repo".to_string(),
            description: None,
            format: RepositoryFormat::Pypi,
            storage_backend: "filesystem".to_string(),
            repo_type: RepositoryType::Local,
            storage_path: "/data/test-repo".to_string(),
            upstream_url: None,
            is_public,
            quota_bytes: None,
            replication_priority: ReplicationPriority::Scheduled,
            promotion_target_id: None,
            promotion_policy_id: None,
            curation_enabled: false,
            curation_source_repo_id: None,
            curation_target_repo_id: None,
            curation_default_action: "allow".to_string(),
            curation_sync_interval_secs: 3600,
            curation_auto_fetch: false,
            created_at: now,
            updated_at: now,
        }
    }

    #[test]
    fn test_require_visible_public_no_auth() {
        let repo = make_repo(true);
        assert!(require_visible(&repo, &None).is_ok());
    }

    #[test]
    fn test_require_visible_public_with_auth() {
        let repo = make_repo(true);
        let auth = Some(make_auth_ext(None));
        assert!(require_visible(&repo, &auth).is_ok());
    }

    #[test]
    fn test_require_visible_private_no_auth() {
        let repo = make_repo(false);
        let result = require_visible(&repo, &None);
        assert!(result.is_err());
        match result.unwrap_err() {
            AppError::NotFound(msg) => assert!(msg.contains("test-repo")),
            other => panic!("Expected NotFound error, got: {:?}", other),
        }
    }

    #[test]
    fn test_require_visible_private_with_unrestricted_auth() {
        let repo = make_repo(false);
        let auth = Some(make_auth_ext(None));
        assert!(require_visible(&repo, &auth).is_ok());
    }

    #[test]
    fn test_require_visible_private_with_allowed_repo() {
        let repo = make_repo(false);
        let auth = Some(make_auth_ext(Some(vec![repo.id])));
        assert!(require_visible(&repo, &auth).is_ok());
    }

    #[test]
    fn test_require_visible_private_with_different_repo_restriction() {
        let repo = make_repo(false);
        let other_repo_id = Uuid::new_v4();
        let auth = Some(make_auth_ext(Some(vec![other_repo_id])));
        let result = require_visible(&repo, &auth);
        assert!(result.is_err());
        match result.unwrap_err() {
            AppError::NotFound(msg) => assert!(msg.contains("test-repo")),
            other => panic!("Expected NotFound error, got: {:?}", other),
        }
    }

    // -----------------------------------------------------------------------
    // validate_cache_ttl
    // -----------------------------------------------------------------------

    #[test]
    fn test_validate_cache_ttl_valid_5_minutes() {
        assert!(validate_cache_ttl(300));
    }

    #[test]
    fn test_validate_cache_ttl_valid_1_day() {
        assert!(validate_cache_ttl(86400));
    }

    #[test]
    fn test_validate_cache_ttl_valid_1_week() {
        assert!(validate_cache_ttl(604800));
    }

    #[test]
    fn test_validate_cache_ttl_valid_minimum() {
        assert!(validate_cache_ttl(1));
    }

    #[test]
    fn test_validate_cache_ttl_valid_maximum() {
        assert!(validate_cache_ttl(2_592_000));
    }

    #[test]
    fn test_validate_cache_ttl_invalid_zero() {
        assert!(!validate_cache_ttl(0));
    }

    #[test]
    fn test_validate_cache_ttl_invalid_negative() {
        assert!(!validate_cache_ttl(-1));
    }

    #[test]
    fn test_validate_cache_ttl_invalid_too_large() {
        assert!(!validate_cache_ttl(2_592_001));
    }

    #[test]
    fn test_validate_cache_ttl_invalid_very_negative() {
        assert!(!validate_cache_ttl(-86400));
    }

    // -----------------------------------------------------------------------
    // Cache TTL DTO serialization / deserialization
    // -----------------------------------------------------------------------

    #[test]
    fn test_set_cache_ttl_request_deserialization() {
        let json = r#"{"cache_ttl_seconds": 3600}"#;
        let req: SetCacheTtlRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.cache_ttl_seconds, 3600);
    }

    #[test]
    fn test_cache_ttl_response_serialization() {
        let resp = CacheTtlResponse {
            repository_key: "my-remote-repo".to_string(),
            cache_ttl_seconds: 7200,
        };
        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains("\"repository_key\":\"my-remote-repo\""));
        assert!(json.contains("\"cache_ttl_seconds\":7200"));
    }

    // -----------------------------------------------------------------------
    // Virtual repository member list response
    // -----------------------------------------------------------------------

    #[test]
    fn test_virtual_members_list_response_uses_members_field() {
        let resp = VirtualMembersListResponse {
            members: vec![VirtualMemberResponse {
                id: Uuid::new_v4(),
                member_repo_id: Uuid::new_v4(),
                member_repo_key: "local-maven".to_string(),
                member_repo_name: "Local Maven".to_string(),
                member_repo_type: "local".to_string(),
                priority: 1,
                created_at: chrono::Utc::now(),
            }],
        };
        let json = serde_json::to_string(&resp).unwrap();
        assert!(
            json.contains("\"members\""),
            "response must serialize under 'members', not 'items'"
        );
        assert!(
            !json.contains("\"items\""),
            "response must not contain 'items' key"
        );
        assert!(json.contains("\"member_repo_key\":\"local-maven\""));
    }

    #[test]
    fn test_virtual_members_list_response_empty() {
        let resp = VirtualMembersListResponse { members: vec![] };
        let json = serde_json::to_string(&resp).unwrap();
        assert_eq!(json, r#"{"members":[]}"#);
    }

    #[test]
    fn test_virtual_members_list_response_preserves_priority_order() {
        let resp = VirtualMembersListResponse {
            members: vec![
                VirtualMemberResponse {
                    id: Uuid::new_v4(),
                    member_repo_id: Uuid::new_v4(),
                    member_repo_key: "first".to_string(),
                    member_repo_name: "First".to_string(),
                    member_repo_type: "local".to_string(),
                    priority: 1,
                    created_at: chrono::Utc::now(),
                },
                VirtualMemberResponse {
                    id: Uuid::new_v4(),
                    member_repo_id: Uuid::new_v4(),
                    member_repo_key: "second".to_string(),
                    member_repo_name: "Second".to_string(),
                    member_repo_type: "remote".to_string(),
                    priority: 2,
                    created_at: chrono::Utc::now(),
                },
            ],
        };
        let json = serde_json::to_string(&resp).unwrap();
        let first_pos = json.find("\"first\"").unwrap();
        let second_pos = json.find("\"second\"").unwrap();
        assert!(first_pos < second_pos);
    }

    // -----------------------------------------------------------------------
    // CreateVirtualMemberInput
    // -----------------------------------------------------------------------

    #[test]
    fn test_create_virtual_member_input_deserialization() {
        let json = r#"{"repo_key": "maven-central", "priority": 5}"#;
        let input: CreateVirtualMemberInput = serde_json::from_str(json).unwrap();
        assert_eq!(input.repo_key, "maven-central");
        assert_eq!(input.priority, 5);
    }

    #[test]
    fn test_create_virtual_member_input_default_priority() {
        let json = r#"{"repo_key": "maven-central"}"#;
        let input: CreateVirtualMemberInput = serde_json::from_str(json).unwrap();
        assert_eq!(input.repo_key, "maven-central");
        assert_eq!(input.priority, 0);
    }

    // -----------------------------------------------------------------------
    // CreateRepositoryRequest with member_repos
    // -----------------------------------------------------------------------

    #[test]
    fn test_create_repository_request_with_member_repos() {
        let json = r#"{
            "key": "maven-virtual",
            "name": "Maven Virtual",
            "format": "maven",
            "repo_type": "virtual",
            "member_repos": [
                {"repo_key": "maven-local", "priority": 1},
                {"repo_key": "maven-central", "priority": 2}
            ]
        }"#;
        let req: CreateRepositoryRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.key, "maven-virtual");
        assert_eq!(req.repo_type, "virtual");
        let members = req.member_repos.unwrap();
        assert_eq!(members.len(), 2);
        assert_eq!(members[0].repo_key, "maven-local");
        assert_eq!(members[0].priority, 1);
        assert_eq!(members[1].repo_key, "maven-central");
        assert_eq!(members[1].priority, 2);
    }

    #[test]
    fn test_create_repository_request_without_member_repos() {
        let json = r#"{
            "key": "npm-local",
            "name": "NPM Local",
            "format": "npm",
            "repo_type": "local"
        }"#;
        let req: CreateRepositoryRequest = serde_json::from_str(json).unwrap();
        assert!(req.member_repos.is_none());
    }

    #[test]
    fn test_create_repository_request_empty_member_repos() {
        let json = r#"{
            "key": "maven-virtual",
            "name": "Maven Virtual",
            "format": "maven",
            "repo_type": "virtual",
            "member_repos": []
        }"#;
        let req: CreateRepositoryRequest = serde_json::from_str(json).unwrap();
        let members = req.member_repos.unwrap();
        assert!(members.is_empty());
    }

    #[test]
    fn test_create_repository_request_member_repos_default_priority() {
        let json = r#"{
            "key": "maven-virtual",
            "name": "Maven Virtual",
            "format": "maven",
            "repo_type": "virtual",
            "member_repos": [
                {"repo_key": "maven-local"}
            ]
        }"#;
        let req: CreateRepositoryRequest = serde_json::from_str(json).unwrap();
        let members = req.member_repos.unwrap();
        assert_eq!(members[0].priority, 0);
    }

    // -----------------------------------------------------------------------
    // resolve_member_priority
    // -----------------------------------------------------------------------

    #[test]
    fn test_resolve_member_priority_explicit() {
        assert_eq!(resolve_member_priority(5, 0), 5);
        assert_eq!(resolve_member_priority(10, 3), 10);
    }

    #[test]
    fn test_resolve_member_priority_zero_uses_index() {
        assert_eq!(resolve_member_priority(0, 0), 1);
        assert_eq!(resolve_member_priority(0, 1), 2);
        assert_eq!(resolve_member_priority(0, 4), 5);
    }

    #[test]
    fn test_resolve_member_priority_negative_uses_index() {
        assert_eq!(resolve_member_priority(-1, 0), 1);
        assert_eq!(resolve_member_priority(-5, 2), 3);
    }

    // -----------------------------------------------------------------------
    // format_repo_type
    // -----------------------------------------------------------------------

    #[test]
    fn test_format_repo_type_local() {
        assert_eq!(format_repo_type(&RepositoryType::Local), "local");
    }

    #[test]
    fn test_format_repo_type_remote() {
        assert_eq!(format_repo_type(&RepositoryType::Remote), "remote");
    }

    #[test]
    fn test_format_repo_type_virtual() {
        assert_eq!(format_repo_type(&RepositoryType::Virtual), "virtual");
    }

    #[test]
    fn test_format_repo_type_staging() {
        assert_eq!(format_repo_type(&RepositoryType::Staging), "staging");
    }

    // -----------------------------------------------------------------------
    // map_member_row
    // -----------------------------------------------------------------------

    #[test]
    fn test_map_member_row_local() {
        let id = Uuid::new_v4();
        let member_id = Uuid::new_v4();
        let now = chrono::Utc::now();
        let row = VirtualMemberRow {
            id,
            member_repo_id: member_id,
            priority: 3,
            created_at: now,
            member_key: "maven-local".to_string(),
            member_name: "Maven Local".to_string(),
            repo_type: RepositoryType::Local,
        };
        let resp = map_member_row(row);
        assert_eq!(resp.id, id);
        assert_eq!(resp.member_repo_id, member_id);
        assert_eq!(resp.member_repo_key, "maven-local");
        assert_eq!(resp.member_repo_name, "Maven Local");
        assert_eq!(resp.member_repo_type, "local");
        assert_eq!(resp.priority, 3);
        assert_eq!(resp.created_at, now);
    }

    #[test]
    fn test_map_member_row_remote() {
        let row = VirtualMemberRow {
            id: Uuid::new_v4(),
            member_repo_id: Uuid::new_v4(),
            priority: 1,
            created_at: chrono::Utc::now(),
            member_key: "maven-central".to_string(),
            member_name: "Maven Central".to_string(),
            repo_type: RepositoryType::Remote,
        };
        let resp = map_member_row(row);
        assert_eq!(resp.member_repo_type, "remote");
        assert_eq!(resp.member_repo_key, "maven-central");
    }

    #[test]
    fn test_map_member_row_preserves_priority() {
        let row = VirtualMemberRow {
            id: Uuid::new_v4(),
            member_repo_id: Uuid::new_v4(),
            priority: 42,
            created_at: chrono::Utc::now(),
            member_key: "r".to_string(),
            member_name: "R".to_string(),
            repo_type: RepositoryType::Local,
        };
        assert_eq!(map_member_row(row).priority, 42);
    }

    // -----------------------------------------------------------------------
    // UpstreamAuthRequest deserialization
    // -----------------------------------------------------------------------

    #[test]
    fn test_upstream_auth_request_basic() {
        let json = r#"{"auth_type":"basic","username":"bot","password":"s3cret"}"#;
        let req: UpstreamAuthRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.auth_type, "basic");
        assert_eq!(req.username, Some("bot".to_string()));
        assert_eq!(req.password, Some("s3cret".to_string()));
    }

    #[test]
    fn test_upstream_auth_request_bearer() {
        let json = r#"{"auth_type":"bearer","password":"ghp_token123"}"#;
        let req: UpstreamAuthRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.auth_type, "bearer");
        assert!(req.username.is_none());
        assert_eq!(req.password, Some("ghp_token123".to_string()));
    }

    #[test]
    fn test_upstream_auth_request_none() {
        let json = r#"{"auth_type":"none"}"#;
        let req: UpstreamAuthRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.auth_type, "none");
        assert!(req.username.is_none());
        assert!(req.password.is_none());
    }

    // -----------------------------------------------------------------------
    // build_upstream_credentials
    // -----------------------------------------------------------------------

    #[test]
    fn test_build_upstream_credentials_basic() {
        let json = build_upstream_credentials("basic", Some("admin"), Some("pass")).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["username"], "admin");
        assert_eq!(parsed["password"], "pass");
    }

    #[test]
    fn test_build_upstream_credentials_bearer() {
        let json = build_upstream_credentials("bearer", None, Some("tok_abc")).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["token"], "tok_abc");
    }

    #[test]
    fn test_build_upstream_credentials_basic_missing_username() {
        let result = build_upstream_credentials("basic", None, Some("pass"));
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("username is required"));
    }

    #[test]
    fn test_build_upstream_credentials_basic_missing_password() {
        let result = build_upstream_credentials("basic", Some("user"), None);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("password is required"));
    }

    #[test]
    fn test_build_upstream_credentials_bearer_missing_token() {
        let result = build_upstream_credentials("bearer", None, None);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("password is required"));
    }

    #[test]
    fn test_build_upstream_credentials_invalid_type() {
        let result = build_upstream_credentials("oauth2", Some("u"), Some("p"));
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Invalid auth_type"));
    }
}
