//! Repository management handlers.

use axum::{
    body::Bytes,
    extract::{Extension, Multipart, Path, Query, State},
    http::{header, HeaderMap},
    response::IntoResponse,
    routing::get,
    Json, Router,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::time::Duration;
use utoipa::{IntoParams, OpenApi, ToSchema};
use uuid::Uuid;

use crate::api::download_response::{DownloadResponse, X_ARTIFACT_STORAGE};
use crate::api::dto::Pagination;
use crate::api::handlers::proxy_helpers;
use crate::api::middleware::auth::AuthExtension;
use crate::api::SharedState;
use crate::error::{AppError, Result};
use crate::formats::maven::MavenHandler;
use crate::models::repository::{RepositoryFormat, RepositoryType};
use crate::services::artifact_service::ArtifactService;
use crate::services::repository_service::{
    CreateRepositoryRequest as ServiceCreateRepoReq, RepoVisibility, RepositoryService,
    UpdateRepositoryRequest as ServiceUpdateRepoReq,
};
use crate::services::routing_rules::{self, RoutingRule};

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

/// Generic upsert helper for repository_config key-value pairs.
///
/// Inserts a new row or updates an existing one for the given repository and
/// config key. Used by multiple update paths (index_upstream_url, quarantine
/// settings, etc.).
async fn upsert_repo_config(
    db: &sqlx::PgPool,
    repo_id: Uuid,
    key: &str,
    value: &str,
) -> Result<()> {
    sqlx::query(
        "INSERT INTO repository_config (repository_id, key, value) \
         VALUES ($1, $2, $3) \
         ON CONFLICT (repository_id, key) DO UPDATE SET value = $3, updated_at = NOW()",
    )
    .bind(repo_id)
    .bind(key)
    .bind(value)
    .execute(db)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;
    Ok(())
}

/// Upsert the `index_upstream_url` key in `repository_config` for a given repository.
async fn upsert_index_upstream_url(
    db: &sqlx::PgPool,
    repo_id: Uuid,
    index_url: &str,
) -> Result<()> {
    upsert_repo_config(db, repo_id, "index_upstream_url", index_url).await
}

/// Create repository routes
pub fn router() -> Router<SharedState> {
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
        // Routing rules for path rewriting on remote repositories
        .route(
            "/:key/routing-rules",
            get(get_routing_rules)
                .post(set_routing_rules)
                .delete(delete_routing_rules),
        )
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
        // Token management routes nested under repository
        .merge(super::repo_tokens::repo_tokens_router())
        // Notification subscription routes nested under repository
        .merge(super::notifications::repo_notifications_router())
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
    /// Alias for `is_public`. When set to true, anonymous users can download
    /// artifacts from this repository without authentication. Useful for remote
    /// (pull-through cache) repositories that proxy public upstream registries.
    /// If both `is_public` and `allow_anonymous_access` are provided,
    /// `allow_anonymous_access` takes precedence.
    pub allow_anonymous_access: Option<bool>,
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

impl CreateRepositoryRequest {
    /// Resolve the effective `is_public` value. `allow_anonymous_access` takes
    /// precedence over `is_public` when both are provided.
    pub fn effective_is_public(&self) -> bool {
        self.allow_anonymous_access
            .or(self.is_public)
            .unwrap_or(false)
    }
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
    /// Alias for `is_public`. When set to true, anonymous users can download
    /// artifacts without authentication. Useful for remote (pull-through cache)
    /// repositories that proxy public upstream registries. Write operations
    /// (upload, delete) still require authentication regardless of this setting.
    /// If both `is_public` and `allow_anonymous_access` are provided,
    /// `allow_anonymous_access` takes precedence.
    pub allow_anonymous_access: Option<bool>,
    pub quota_bytes: Option<i64>,
    /// Update the Cargo index upstream URL (stored in `repository_config`).
    /// When provided, upserts the `index_upstream_url` key for this repository.
    pub index_upstream_url: Option<String>,
    /// Enable or disable quarantine period for this repository.
    /// When enabled, newly uploaded artifacts are held until scanned.
    /// Stored in `repository_config` under `quarantine_enabled`.
    pub quarantine_enabled: Option<bool>,
    /// Quarantine hold duration in minutes for this repository.
    /// Stored in `repository_config` under `quarantine_duration_minutes`.
    pub quarantine_duration_minutes: Option<i64>,
    /// Link this staging repository to a release (local) repository.
    /// Promotions from this staging repo will default to the linked release repo,
    /// and promotions to any other repo will be rejected.
    /// Pass an empty string to remove the link.
    /// Stored in `repository_config` under `release_repository_id`.
    pub release_repository_key: Option<String>,
}

impl UpdateRepositoryRequest {
    /// Resolve the effective `is_public` value. `allow_anonymous_access` takes
    /// precedence over `is_public` when both are provided.
    pub fn effective_is_public(&self) -> Option<bool> {
        self.allow_anonymous_access.or(self.is_public)
    }
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
    /// Whether anonymous (unauthenticated) downloads are allowed. This is
    /// always equal to `is_public` and provided as a convenience alias so
    /// the semantics are clear for remote (pull-through cache) repositories.
    pub allow_anonymous_access: bool,
    pub storage_used_bytes: i64,
    pub quota_bytes: Option<i64>,
    pub upstream_url: Option<String>,
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
        allow_anonymous_access: repo.is_public,
        is_public: repo.is_public,
        storage_used_bytes,
        quota_bytes: repo.quota_bytes,
        upstream_url: repo.upstream_url,
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

    let visibility = match &auth {
        None => RepoVisibility::PublicOnly,
        Some(a) if a.is_admin => RepoVisibility::All,
        Some(a) => RepoVisibility::User(a.user_id),
    };
    let service = RepositoryService::new(state.db.clone());
    let (repos, total) = service
        .list(
            offset,
            per_page as i64,
            format_filter,
            type_filter,
            visibility,
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

    let is_public = payload.effective_is_public();

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
            is_public,
            quota_bytes: payload.quota_bytes,
            format_key: payload.format_key,
        })
        .await?;

    if let Some(ref index_url) = payload.index_upstream_url {
        upsert_index_upstream_url(&state.db, repo.id, index_url).await?;
    }

    // Add virtual repository members if provided
    if repo_type == RepositoryType::Virtual {
        match &payload.member_repos {
            Some(member_inputs) if !member_inputs.is_empty() => {
                tracing::info!(
                    repo_key = %repo.key,
                    member_count = member_inputs.len(),
                    "Adding virtual repository members during creation"
                );
                for (idx, input) in member_inputs.iter().enumerate() {
                    let member_repo = service.get_by_key(&input.repo_key).await?;
                    let priority = resolve_member_priority(input.priority, idx);
                    tracing::debug!(
                        virtual_repo = %repo.key,
                        member_key = %input.repo_key,
                        priority = priority,
                        "Adding virtual member"
                    );
                    service
                        .add_virtual_member(repo.id, member_repo.id, priority)
                        .await?;
                }
            }
            Some(_empty) => {
                tracing::debug!(
                    repo_key = %repo.key,
                    "Virtual repo created with empty member_repos array"
                );
            }
            None => {
                tracing::debug!(
                    repo_key = %repo.key,
                    "Virtual repo created without member_repos field"
                );
            }
        }
    }

    // Store upstream auth credentials if provided
    if let Some(ref auth_type) = payload.upstream_auth_type {
        let credentials_json = build_upstream_credentials(
            auth_type,
            payload.upstream_username.as_deref(),
            payload.upstream_password.as_deref(),
        )?;
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

    let effective_is_public = payload.effective_is_public();

    let repo = service
        .update(
            existing.id,
            ServiceUpdateRepoReq {
                key: payload.key,
                name: payload.name,
                description: payload.description,
                is_public: effective_is_public,
                quota_bytes: payload.quota_bytes.map(Some),
                upstream_url: None,
            },
        )
        .await?;

    // Invalidate the in-memory repo cache so that visibility changes take
    // effect immediately instead of waiting for the TTL to expire. Remove
    // both the old key and the new key (in case the key was renamed).
    if let Ok(mut cache) = state.repo_cache.write() {
        cache.remove(&key);
        cache.remove(&repo.key);
    }

    if let Some(ref index_url) = payload.index_upstream_url {
        upsert_index_upstream_url(&state.db, repo.id, index_url).await?;
    }

    if let Some(enabled) = payload.quarantine_enabled {
        upsert_repo_config(
            &state.db,
            repo.id,
            "quarantine_enabled",
            if enabled { "true" } else { "false" },
        )
        .await?;
    }

    if let Some(duration) = payload.quarantine_duration_minutes {
        if duration < 0 {
            return Err(AppError::Validation(
                "quarantine_duration_minutes must be non-negative".to_string(),
            ));
        }
        upsert_repo_config(
            &state.db,
            repo.id,
            "quarantine_duration_minutes",
            &duration.to_string(),
        )
        .await?;
    }

    // Handle release repository linking for staging repos
    if let Some(ref release_key) = payload.release_repository_key {
        if release_key.is_empty() {
            // Remove the link
            sqlx::query(
                "DELETE FROM repository_config WHERE repository_id = $1 AND key = 'release_repository_id'",
            )
            .bind(repo.id)
            .execute(&state.db)
            .await
            .map_err(|e| AppError::Database(e.to_string()))?;
        } else {
            if repo.repo_type != RepositoryType::Staging {
                return Err(AppError::Validation(
                    "Release target linking is only available for staging repositories".to_string(),
                ));
            }

            let release_repo = service.get_by_key(release_key).await.map_err(|_| {
                AppError::Validation(format!("Release repository '{}' not found", release_key))
            })?;

            super::promotion::validate_release_target_link(&repo, &release_repo)?;

            upsert_repo_config(
                &state.db,
                repo.id,
                "release_repository_id",
                &release_repo.id.to_string(),
            )
            .await?;
        }
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

    // Remove the deleted repo from the in-memory cache.
    if let Ok(mut cache) = state.repo_cache.write() {
        cache.remove(&key);
    }

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
    /// When set to `maven_component`, Maven/Gradle artifacts are grouped by
    /// groupId, artifactId, and version.  Individual files (jar, pom, checksums)
    /// appear in the `artifact_files` array of each component.
    pub group_by: Option<String>,
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
    /// Maven component grouping.  Only present when `group_by=maven_component`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub components: Option<Vec<MavenComponentResponse>>,
}

/// A Maven component grouped by GAV (groupId, artifactId, version).
///
/// Each component collects the individual files (jar, pom, checksums, etc.)
/// that share the same Maven coordinates.
#[derive(Debug, Serialize, ToSchema, Clone)]
pub struct MavenComponentResponse {
    /// Representative artifact ID (the first file in the group).
    pub id: Uuid,
    /// Maven groupId with dots (e.g. `org.junit.jupiter`).
    pub group_id: String,
    /// Maven artifactId (e.g. `junit-jupiter-api`).
    pub artifact_id: String,
    /// Maven version string (e.g. `5.11.0`).
    pub version: String,
    /// Repository key this component belongs to.
    pub repository_key: String,
    /// Repository format (always `maven` or `gradle`).
    pub format: String,
    /// Total size in bytes across all files in this component.
    pub size_bytes: i64,
    /// Total download count across all files in this component.
    pub download_count: i64,
    /// Earliest creation timestamp among the component files.
    pub created_at: chrono::DateTime<chrono::Utc>,
    /// Individual filenames belonging to this component.
    pub artifact_files: Vec<String>,
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

    let is_maven_format = matches!(
        repo.format,
        RepositoryFormat::Maven | RepositoryFormat::Gradle
    );
    let want_component_grouping =
        query.group_by.as_deref() == Some("maven_component") && is_maven_format;

    if want_component_grouping {
        return list_artifacts_grouped_by_maven_component(
            &artifact_service,
            &state,
            &repo,
            &key,
            query.path_prefix.as_deref(),
            query.q.as_deref(),
            page,
            per_page,
        )
        .await;
    }

    let (artifacts, total) = if repo.repo_type == RepositoryType::Virtual {
        // For virtual repositories, aggregate artifacts from all member repos.
        // Members are returned in priority order; local/hosted members are
        // included alongside remote members so that locally published artifacts
        // appear in the listing.
        let members = proxy_helpers::fetch_virtual_members(&state.db, repo.id)
            .await
            .map_err(|_| {
                AppError::Internal("Failed to resolve virtual repository members".to_string())
            })?;

        let member_ids: Vec<uuid::Uuid> = members.iter().map(|m| m.id).collect();

        artifact_service
            .list_for_repos(
                &member_ids,
                query.path_prefix.as_deref(),
                query.q.as_deref(),
                offset,
                per_page as i64,
            )
            .await?
    } else {
        artifact_service
            .list(
                repo.id,
                query.path_prefix.as_deref(),
                query.q.as_deref(),
                offset,
                per_page as i64,
            )
            .await?
    };

    let total_pages = ((total as f64) / (per_page as f64)).ceil() as u32;

    let artifact_ids: Vec<Uuid> = artifacts.iter().map(|a| a.id).collect();
    let download_counts = artifact_service
        .get_download_stats_batch(&artifact_ids)
        .await?;

    let mut items = Vec::new();
    for artifact in artifacts {
        items.push(ArtifactResponse {
            id: artifact.id,
            repository_key: key.clone(),
            path: artifact.path,
            name: artifact.name,
            version: artifact.version,
            size_bytes: artifact.size_bytes,
            checksum_sha256: artifact.checksum_sha256,
            content_type: artifact.content_type,
            download_count: *download_counts.get(&artifact.id).unwrap_or(&0),
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
        components: None,
    }))
}

/// Build a grouped-by-component response for Maven/Gradle repositories.
///
/// Fetches all matching artifacts (up to 10 000), groups them by Maven GAV
/// coordinates (groupId, artifactId, version), then paginates the resulting
/// component list.  Files that cannot be parsed as Maven coordinates (e.g.
/// top-level metadata) are silently skipped.
#[allow(clippy::too_many_arguments)]
async fn list_artifacts_grouped_by_maven_component(
    artifact_service: &ArtifactService,
    state: &SharedState,
    repo: &crate::models::repository::Repository,
    repo_key: &str,
    path_prefix: Option<&str>,
    search_query: Option<&str>,
    page: u32,
    per_page: u32,
) -> Result<Json<ArtifactListResponse>> {
    // Fetch a large batch so we can group in-memory.  10 000 individual files
    // is generous; most Maven repos have far fewer cached artifacts.
    const MAX_FETCH: i64 = 10_000;

    let (artifacts, _total_files) = if repo.repo_type == RepositoryType::Virtual {
        let members = proxy_helpers::fetch_virtual_members(&state.db, repo.id)
            .await
            .map_err(|_| {
                AppError::Internal("Failed to resolve virtual repository members".to_string())
            })?;
        let member_ids: Vec<uuid::Uuid> = members.iter().map(|m| m.id).collect();
        artifact_service
            .list_for_repos(&member_ids, path_prefix, search_query, 0, MAX_FETCH)
            .await?
    } else {
        artifact_service
            .list(repo.id, path_prefix, search_query, 0, MAX_FETCH)
            .await?
    };

    let artifact_ids: Vec<Uuid> = artifacts.iter().map(|a| a.id).collect();
    let download_counts = artifact_service
        .get_download_stats_batch(&artifact_ids)
        .await?;

    let components = group_maven_artifacts(
        &artifacts,
        &download_counts,
        repo_key,
        &format!("{:?}", repo.format).to_lowercase(),
    );

    let total_components = components.len() as i64;
    let total_pages = ((total_components as f64) / (per_page as f64)).ceil() as u32;
    let offset = ((page - 1) * per_page) as usize;
    let page_components: Vec<MavenComponentResponse> = components
        .into_iter()
        .skip(offset)
        .take(per_page as usize)
        .collect();

    Ok(Json(ArtifactListResponse {
        items: Vec::new(),
        pagination: Pagination {
            page,
            per_page,
            total: total_components,
            total_pages,
        },
        components: Some(page_components),
    }))
}

/// GAV key used to group Maven artifacts.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
struct GavKey {
    group_id: String,
    artifact_id: String,
    version: String,
}

/// Group a flat list of Maven artifacts by GAV coordinates.
///
/// Returns a sorted `Vec` of `MavenComponentResponse` items. Artifacts whose
/// paths cannot be parsed as Maven coordinates are skipped.
fn group_maven_artifacts(
    artifacts: &[crate::models::artifact::Artifact],
    download_counts: &std::collections::HashMap<Uuid, i64>,
    repo_key: &str,
    format: &str,
) -> Vec<MavenComponentResponse> {
    let mut groups: BTreeMap<GavKey, MavenComponentResponse> = BTreeMap::new();

    for artifact in artifacts {
        let coords = match MavenHandler::parse_coordinates(&artifact.path) {
            Ok(c) => c,
            Err(_) => continue,
        };

        let key = GavKey {
            group_id: coords.group_id.clone(),
            artifact_id: coords.artifact_id.clone(),
            version: coords.version.clone(),
        };

        let filename = artifact
            .path
            .rsplit('/')
            .next()
            .unwrap_or(&artifact.name)
            .to_string();

        let downloads = *download_counts.get(&artifact.id).unwrap_or(&0);

        groups
            .entry(key)
            .and_modify(|comp| {
                comp.size_bytes += artifact.size_bytes;
                comp.download_count += downloads;
                if artifact.created_at < comp.created_at {
                    comp.created_at = artifact.created_at;
                }
                comp.artifact_files.push(filename.clone());
            })
            .or_insert_with(|| MavenComponentResponse {
                id: artifact.id,
                group_id: coords.group_id,
                artifact_id: coords.artifact_id,
                version: coords.version,
                repository_key: repo_key.to_string(),
                format: format.to_string(),
                size_bytes: artifact.size_bytes,
                download_count: downloads,
                created_at: artifact.created_at,
                artifact_files: vec![filename],
            });
    }

    groups.into_values().collect()
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
            quarantine_status, quarantine_until,
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
    headers: HeaderMap,
    body: Bytes,
) -> Result<Json<ArtifactResponse>> {
    let auth = require_auth(auth)?;
    auth.require_scope("write")?;
    let repo_service = RepositoryService::new(state.db.clone());
    let repo = repo_service.get_by_key(&key).await?;
    require_repo_access(&auth, repo.id)?;

    // Verify declared checksums against actual content before storing anything.
    let declared_sha256 = headers
        .get("x-checksum-sha256")
        .and_then(|v| v.to_str().ok());
    let declared_sha1 = headers.get("x-checksum-sha1").and_then(|v| v.to_str().ok());
    let declared_md5 = headers.get("x-checksum-md5").and_then(|v| v.to_str().ok());
    ArtifactService::verify_checksums(&body, declared_sha256, declared_sha1, declared_md5)?;

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

    // Use WASM-extracted metadata if available, otherwise try to derive
    // name and version from the path segments (e.g. "pkg/v1/file.txt").
    let (name, version) = if let Some(ref meta) = wasm_metadata {
        (name, meta.version.clone())
    } else {
        let segments: Vec<&str> = path.split('/').collect();
        if segments.len() >= 3 {
            // Path follows {package_name}/{version}/{filename...} convention
            (segments[0].to_string(), Some(segments[1].to_string()))
        } else {
            (name, None)
        }
    };

    let content_type = wasm_metadata
        .as_ref()
        .map(|m| m.content_type.clone())
        .unwrap_or_else(|| {
            mime_guess::from_path(&path)
                .first_or_octet_stream()
                .to_string()
        });

    // Clean up any soft-deleted artifact at the same path so the
    // UNIQUE(repository_id, path) constraint doesn't block re-upload.
    super::cleanup_soft_deleted_artifact(&state.db, repo.id, &path).await;

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
    headers: HeaderMap,
    multipart: Multipart,
) -> Result<Json<ArtifactResponse>> {
    let (body, filename) = extract_multipart_file(multipart).await?;
    let artifact_path = if path.is_empty() || path == "/" {
        filename
    } else {
        path
    };
    upload_artifact(
        State(state),
        Extension(auth),
        Path((key, artifact_path)),
        headers,
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
    headers: HeaderMap,
    multipart: Multipart,
) -> Result<Json<ArtifactResponse>> {
    let (body, filename) = extract_multipart_file(multipart).await?;
    upload_artifact(
        State(state),
        Extension(auth),
        Path((key, filename)),
        headers,
        body,
    )
    .await
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

    // Check quarantine status before serving the artifact.
    // If the artifact is quarantined or rejected, return 409 Conflict.
    {
        #[derive(sqlx::FromRow)]
        struct QuarantineRow {
            quarantine_status: Option<String>,
            quarantine_until: Option<chrono::DateTime<chrono::Utc>>,
        }

        if let Some(qrow) = sqlx::query_as::<_, QuarantineRow>(
            "SELECT quarantine_status, quarantine_until \
             FROM artifacts \
             WHERE repository_id = $1 AND path = $2 AND is_deleted = false",
        )
        .bind(repo.id)
        .bind(&path)
        .fetch_optional(&state.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?
        {
            crate::services::quarantine_service::check_download_allowed(
                qrow.quarantine_status.as_deref(),
                qrow.quarantine_until,
                chrono::Utc::now(),
            )?;
        }
    }

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

    // Check if the storage backend supports redirect downloads (S3 with presigned URLs).
    // This path is gated on PRESIGNED_DOWNLOADS_ENABLED (or the per-backend
    // redirect setting, which controls supports_redirect()).
    let storage = state.storage_for_repo(&repo.storage_location())?;
    let presigned_enabled = state.config.presigned_downloads_enabled && storage.supports_redirect();
    if presigned_enabled {
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
            let expiry = Duration::from_secs(state.config.presigned_download_expiry_secs);
            // Try to get presigned URL from the shared storage backend
            if let Some(presigned) = storage
                .get_presigned_url(&artifact.storage_key, expiry)
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
                // Apply routing rules to rewrite the path before upstream fetch
                let rules = load_routing_rules(&state.db, repo.id).await;
                let fetch_path = routing_rules::apply_routing_rules(&path, &rules)
                    .unwrap_or_else(|| path.clone());

                let (content, content_type) =
                    proxy_helpers::proxy_fetch(proxy, repo.id, &key, upstream_url, &fetch_path)
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

/// Load a remote repository by key, verifying auth and repo type.
/// Returns an error if the repo is not a remote repository.
async fn load_remote_repo(
    state: &SharedState,
    auth: &AuthExtension,
    key: &str,
) -> Result<crate::models::repository::Repository> {
    let service = RepositoryService::new(state.db.clone());
    let repo = service.get_by_key(key).await?;
    require_repo_access(auth, repo.id)?;
    if repo.repo_type != RepositoryType::Remote {
        return Err(AppError::Validation(
            "This operation is only valid for remote repositories".to_string(),
        ));
    }
    Ok(repo)
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
    let repo = load_remote_repo(&state, &auth, &key).await?;

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
    let repo = load_remote_repo(&state, &auth, &key).await?;

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

// ---------------------------------------------------------------------------
// Routing rules CRUD
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize, ToSchema)]
pub struct SetRoutingRulesRequest {
    /// Ordered list of routing rules. Each rule specifies a regex pattern and
    /// a rewrite template. Rules are evaluated in order during proxy requests.
    pub rules: Vec<RoutingRule>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct RoutingRulesResponse {
    pub repository_key: String,
    pub rules: Vec<RoutingRule>,
}

/// Get routing rules for a repository
#[utoipa::path(
    get,
    path = "/{key}/routing-rules",
    context_path = "/api/v1/repositories",
    tag = "repositories",
    params(
        ("key" = String, Path, description = "Repository key"),
    ),
    responses(
        (status = 200, description = "Current routing rules", body = RoutingRulesResponse),
        (status = 404, description = "Repository not found"),
    )
)]
pub async fn get_routing_rules(
    State(state): State<SharedState>,
    Path(key): Path<String>,
) -> Result<Json<RoutingRulesResponse>> {
    let service = RepositoryService::new(state.db.clone());
    let repo = service.get_by_key(&key).await?;

    let result: Option<(String,)> = sqlx::query_as(
        r#"
        SELECT value FROM repository_config
        WHERE repository_id = $1 AND key = 'routing_rules'
        "#,
    )
    .bind(repo.id)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;

    let rules: Vec<RoutingRule> = result
        .and_then(|(v,)| serde_json::from_str(&v).ok())
        .unwrap_or_default();

    Ok(Json(RoutingRulesResponse {
        repository_key: key,
        rules,
    }))
}

/// Set routing rules for a repository
///
/// Routing rules rewrite the request path before it is forwarded to the
/// upstream server. This is useful for proxying resources like GitHub Releases
/// where the client-facing path structure differs from the upstream URL
/// layout. Rules are evaluated in order and the first match wins.
#[utoipa::path(
    post,
    path = "/{key}/routing-rules",
    context_path = "/api/v1/repositories",
    tag = "repositories",
    params(
        ("key" = String, Path, description = "Repository key"),
    ),
    request_body = SetRoutingRulesRequest,
    security(("bearer_auth" = [])),
    responses(
        (status = 200, description = "Routing rules saved", body = RoutingRulesResponse),
        (status = 400, description = "Invalid rule (bad regex or capture reference)"),
        (status = 401, description = "Authentication required"),
        (status = 404, description = "Repository not found"),
    )
)]
pub async fn set_routing_rules(
    State(state): State<SharedState>,
    Extension(auth): Extension<Option<AuthExtension>>,
    Path(key): Path<String>,
    Json(payload): Json<SetRoutingRulesRequest>,
) -> Result<Json<RoutingRulesResponse>> {
    let auth = require_auth(auth)?;
    auth.require_scope("write")?;

    // Validate every rule before persisting
    for (i, rule) in payload.rules.iter().enumerate() {
        if let Err(msg) = routing_rules::validate_routing_rule(rule) {
            return Err(AppError::Validation(format!(
                "routing rule [{}]: {}",
                i, msg
            )));
        }
    }

    let service = RepositoryService::new(state.db.clone());
    let repo = service.get_by_key(&key).await?;
    require_repo_access(&auth, repo.id)?;

    let value = serde_json::to_string(&payload.rules)
        .map_err(|e| AppError::Internal(format!("Failed to serialize routing rules: {}", e)))?;

    sqlx::query(
        r#"
        INSERT INTO repository_config (repository_id, key, value)
        VALUES ($1, 'routing_rules', $2)
        ON CONFLICT (repository_id, key)
        DO UPDATE SET value = $2, updated_at = NOW()
        "#,
    )
    .bind(repo.id)
    .bind(&value)
    .execute(&state.db)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;

    Ok(Json(RoutingRulesResponse {
        repository_key: key,
        rules: payload.rules,
    }))
}

/// Delete all routing rules for a repository
#[utoipa::path(
    delete,
    path = "/{key}/routing-rules",
    context_path = "/api/v1/repositories",
    tag = "repositories",
    params(
        ("key" = String, Path, description = "Repository key"),
    ),
    security(("bearer_auth" = [])),
    responses(
        (status = 200, description = "Routing rules deleted"),
        (status = 401, description = "Authentication required"),
        (status = 404, description = "Repository not found"),
    )
)]
pub async fn delete_routing_rules(
    State(state): State<SharedState>,
    Extension(auth): Extension<Option<AuthExtension>>,
    Path(key): Path<String>,
) -> Result<Json<serde_json::Value>> {
    let auth = require_auth(auth)?;
    auth.require_scope("write")?;

    let service = RepositoryService::new(state.db.clone());
    let repo = service.get_by_key(&key).await?;
    require_repo_access(&auth, repo.id)?;

    sqlx::query(
        r#"
        DELETE FROM repository_config
        WHERE repository_id = $1 AND key = 'routing_rules'
        "#,
    )
    .bind(repo.id)
    .execute(&state.db)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;

    Ok(Json(
        serde_json::json!({"message": "Routing rules deleted"}),
    ))
}

/// Load routing rules from repository_config for a given repository ID.
/// Returns an empty Vec if no rules are configured.
async fn load_routing_rules(db: &sqlx::PgPool, repo_id: Uuid) -> Vec<RoutingRule> {
    let result: Option<(String,)> = sqlx::query_as(
        "SELECT value FROM repository_config WHERE repository_id = $1 AND key = 'routing_rules'",
    )
    .bind(repo_id)
    .fetch_optional(db)
    .await
    .unwrap_or(None);

    result
        .and_then(|(v,)| serde_json::from_str(&v).ok())
        .unwrap_or_default()
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
        get_routing_rules,
        set_routing_rules,
        delete_routing_rules,
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
        MavenComponentResponse,
        AddVirtualMemberRequest,
        UpdateVirtualMembersRequest,
        VirtualMemberPriority,
        VirtualMemberResponse,
        VirtualMembersListResponse,
        CreateVirtualMemberInput,
        UpstreamAuthRequest,
        SetRoutingRulesRequest,
        RoutingRulesResponse,
        RoutingRule,
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
/// Validates that the required fields are present for the given auth type,
/// then delegates to `build_credentials_json` for serialization.
fn build_upstream_credentials(
    auth_type: &str,
    username: Option<&str>,
    password: Option<&str>,
) -> crate::error::Result<String> {
    use crate::services::upstream_auth::{build_credentials_json, UpstreamAuthType};

    let auth = match auth_type {
        "basic" => {
            let username = username.ok_or_else(|| {
                AppError::Validation("username is required for basic auth".to_string())
            })?;
            let password = password.ok_or_else(|| {
                AppError::Validation("password is required for basic auth".to_string())
            })?;
            UpstreamAuthType::Basic {
                username: username.to_string(),
                password: password.to_string(),
            }
        }
        "bearer" => {
            let token = password.ok_or_else(|| {
                AppError::Validation(
                    "password is required for bearer auth (used as token)".to_string(),
                )
            })?;
            UpstreamAuthType::Bearer {
                token: token.to_string(),
            }
        }
        other => {
            return Err(AppError::Validation(format!(
                "Invalid auth_type: {other}. Must be 'basic', 'bearer', or 'none'"
            )));
        }
    };

    Ok(build_credentials_json(&auth))
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

    /// Extract (package_name, version) from a generic artifact path.
    /// Paths with 3+ segments follow {name}/{version}/{filename...} convention.
    fn extract_name_version_from_path(path: &str) -> (String, Option<String>) {
        let segments: Vec<&str> = path.split('/').collect();
        if segments.len() >= 3 {
            (segments[0].to_string(), Some(segments[1].to_string()))
        } else {
            let name = segments.last().unwrap_or(&path).to_string();
            (name, None)
        }
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
        assert!(req.release_repository_key.is_none());
    }

    #[test]
    fn test_update_repository_request_with_release_key() {
        let json = r#"{"release_repository_key": "release-maven"}"#;
        let req: UpdateRepositoryRequest = serde_json::from_str(json).unwrap();
        assert_eq!(
            req.release_repository_key,
            Some("release-maven".to_string())
        );
    }

    #[test]
    fn test_update_repository_request_clear_release_key() {
        let json = r#"{"release_repository_key": ""}"#;
        let req: UpdateRepositoryRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.release_repository_key, Some(String::new()));
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
            allow_anonymous_access: true,
            storage_used_bytes: 1024,
            quota_bytes: Some(1048576),
            upstream_url: None,
            upstream_auth_type: None,
            upstream_auth_configured: false,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        };
        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains("\"key\":\"my-repo\""));
        assert!(json.contains("\"storage_used_bytes\":1024"));
        assert!(json.contains("\"quota_bytes\":1048576"));
        assert!(json.contains("\"allow_anonymous_access\":true"));
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
        assert!(query.group_by.is_none());
    }

    #[test]
    fn test_list_artifacts_query_group_by() {
        let json = r#"{"group_by": "maven_component"}"#;
        let query: ListArtifactsQuery = serde_json::from_str(json).unwrap();
        assert_eq!(query.group_by.as_deref(), Some("maven_component"));
    }

    // -----------------------------------------------------------------------
    // group_maven_artifacts
    // -----------------------------------------------------------------------

    /// Helper to build an Artifact fixture for grouping tests.
    fn maven_artifact(path: &str, name: &str, size: i64) -> crate::models::artifact::Artifact {
        crate::models::artifact::Artifact {
            id: Uuid::new_v4(),
            repository_id: Uuid::new_v4(),
            path: path.to_string(),
            name: name.to_string(),
            version: None,
            size_bytes: size,
            checksum_sha256: "sha256".to_string(),
            checksum_md5: None,
            checksum_sha1: None,
            content_type: "application/octet-stream".to_string(),
            storage_key: path.to_string(),
            is_deleted: false,
            uploaded_by: None,
            quarantine_status: None,
            quarantine_until: None,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        }
    }

    #[test]
    fn test_group_maven_artifacts_single_component() {
        let artifacts = vec![
            maven_artifact(
                "org/junit/jupiter/junit-jupiter-api/5.11.0/junit-jupiter-api-5.11.0.jar",
                "junit-jupiter-api-5.11.0.jar",
                50_000,
            ),
            maven_artifact(
                "org/junit/jupiter/junit-jupiter-api/5.11.0/junit-jupiter-api-5.11.0.pom",
                "junit-jupiter-api-5.11.0.pom",
                2_000,
            ),
            maven_artifact(
                "org/junit/jupiter/junit-jupiter-api/5.11.0/junit-jupiter-api-5.11.0.jar.sha1",
                "junit-jupiter-api-5.11.0.jar.sha1",
                40,
            ),
        ];

        let downloads = std::collections::HashMap::new();
        let result = group_maven_artifacts(&artifacts, &downloads, "maven-central", "maven");

        assert_eq!(result.len(), 1);
        let comp = &result[0];
        assert_eq!(comp.group_id, "org.junit.jupiter");
        assert_eq!(comp.artifact_id, "junit-jupiter-api");
        assert_eq!(comp.version, "5.11.0");
        assert_eq!(comp.repository_key, "maven-central");
        assert_eq!(comp.format, "maven");
        assert_eq!(comp.size_bytes, 52_040);
        assert_eq!(comp.artifact_files.len(), 3);
        assert!(comp
            .artifact_files
            .contains(&"junit-jupiter-api-5.11.0.jar".to_string()));
        assert!(comp
            .artifact_files
            .contains(&"junit-jupiter-api-5.11.0.pom".to_string()));
        assert!(comp
            .artifact_files
            .contains(&"junit-jupiter-api-5.11.0.jar.sha1".to_string()));
    }

    #[test]
    fn test_group_maven_artifacts_multiple_components() {
        let artifacts = vec![
            maven_artifact(
                "org/junit/jupiter/junit-jupiter-api/5.11.0/junit-jupiter-api-5.11.0.jar",
                "junit-jupiter-api-5.11.0.jar",
                50_000,
            ),
            maven_artifact(
                "org/junit/jupiter/junit-jupiter-api/5.11.0/junit-jupiter-api-5.11.0.pom",
                "junit-jupiter-api-5.11.0.pom",
                2_000,
            ),
            maven_artifact(
                "com/google/guava/guava/33.0.0/guava-33.0.0.jar",
                "guava-33.0.0.jar",
                100_000,
            ),
            maven_artifact(
                "com/google/guava/guava/33.0.0/guava-33.0.0.pom",
                "guava-33.0.0.pom",
                3_000,
            ),
        ];

        let downloads = std::collections::HashMap::new();
        let result = group_maven_artifacts(&artifacts, &downloads, "maven-central", "maven");

        assert_eq!(result.len(), 2);
        // BTreeMap ordering: "com.google.guava" < "org.junit.jupiter"
        assert_eq!(result[0].group_id, "com.google.guava");
        assert_eq!(result[0].artifact_id, "guava");
        assert_eq!(result[0].version, "33.0.0");
        assert_eq!(result[0].artifact_files.len(), 2);

        assert_eq!(result[1].group_id, "org.junit.jupiter");
        assert_eq!(result[1].artifact_id, "junit-jupiter-api");
        assert_eq!(result[1].version, "5.11.0");
        assert_eq!(result[1].artifact_files.len(), 2);
    }

    #[test]
    fn test_group_maven_artifacts_different_versions() {
        let artifacts = vec![
            maven_artifact(
                "org/example/lib/1.0.0/lib-1.0.0.jar",
                "lib-1.0.0.jar",
                10_000,
            ),
            maven_artifact(
                "org/example/lib/2.0.0/lib-2.0.0.jar",
                "lib-2.0.0.jar",
                20_000,
            ),
        ];

        let downloads = std::collections::HashMap::new();
        let result = group_maven_artifacts(&artifacts, &downloads, "repo", "maven");

        assert_eq!(result.len(), 2);
        assert_eq!(result[0].version, "1.0.0");
        assert_eq!(result[1].version, "2.0.0");
    }

    #[test]
    fn test_group_maven_artifacts_skips_unparseable_paths() {
        let artifacts = vec![
            maven_artifact("some-random-file.txt", "some-random-file.txt", 100),
            maven_artifact(
                "org/example/lib/1.0.0/lib-1.0.0.jar",
                "lib-1.0.0.jar",
                10_000,
            ),
        ];

        let downloads = std::collections::HashMap::new();
        let result = group_maven_artifacts(&artifacts, &downloads, "repo", "maven");

        assert_eq!(result.len(), 1);
        assert_eq!(result[0].artifact_id, "lib");
    }

    #[test]
    fn test_group_maven_artifacts_download_counts_aggregated() {
        let a1 = maven_artifact(
            "org/example/lib/1.0.0/lib-1.0.0.jar",
            "lib-1.0.0.jar",
            10_000,
        );
        let a2 = maven_artifact("org/example/lib/1.0.0/lib-1.0.0.pom", "lib-1.0.0.pom", 500);

        let mut downloads = std::collections::HashMap::new();
        downloads.insert(a1.id, 100);
        downloads.insert(a2.id, 25);

        let result = group_maven_artifacts(&[a1, a2], &downloads, "repo", "maven");

        assert_eq!(result.len(), 1);
        assert_eq!(result[0].download_count, 125);
        assert_eq!(result[0].size_bytes, 10_500);
    }

    #[test]
    fn test_group_maven_artifacts_empty_input() {
        let downloads = std::collections::HashMap::new();
        let result = group_maven_artifacts(&[], &downloads, "repo", "maven");
        assert!(result.is_empty());
    }

    #[test]
    fn test_maven_component_response_serialization() {
        let comp = MavenComponentResponse {
            id: Uuid::new_v4(),
            group_id: "org.junit.jupiter".to_string(),
            artifact_id: "junit-jupiter-api".to_string(),
            version: "5.11.0".to_string(),
            repository_key: "maven-central".to_string(),
            format: "maven".to_string(),
            size_bytes: 52_040,
            download_count: 42,
            created_at: chrono::Utc::now(),
            artifact_files: vec![
                "junit-jupiter-api-5.11.0.jar".to_string(),
                "junit-jupiter-api-5.11.0.pom".to_string(),
            ],
        };
        let json = serde_json::to_string(&comp).unwrap();
        assert!(json.contains("\"group_id\":\"org.junit.jupiter\""));
        assert!(json.contains("\"artifact_id\":\"junit-jupiter-api\""));
        assert!(json.contains("\"version\":\"5.11.0\""));
        assert!(json.contains("\"artifact_files\":["));
        assert!(json.contains("junit-jupiter-api-5.11.0.jar"));
    }

    #[test]
    fn test_artifact_list_response_without_components() {
        let resp = ArtifactListResponse {
            items: vec![],
            pagination: Pagination {
                page: 1,
                per_page: 20,
                total: 0,
                total_pages: 0,
            },
            components: None,
        };
        let json = serde_json::to_string(&resp).unwrap();
        // components field should be omitted when None
        assert!(!json.contains("\"components\""));
    }

    #[test]
    fn test_artifact_list_response_with_components() {
        let comp = MavenComponentResponse {
            id: Uuid::new_v4(),
            group_id: "org.example".to_string(),
            artifact_id: "mylib".to_string(),
            version: "1.0.0".to_string(),
            repository_key: "repo".to_string(),
            format: "maven".to_string(),
            size_bytes: 1024,
            download_count: 0,
            created_at: chrono::Utc::now(),
            artifact_files: vec!["mylib-1.0.0.jar".to_string()],
        };
        let resp = ArtifactListResponse {
            items: vec![],
            pagination: Pagination {
                page: 1,
                per_page: 20,
                total: 1,
                total_pages: 1,
            },
            components: Some(vec![comp]),
        };
        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains("\"components\":["));
        assert!(json.contains("\"group_id\":\"org.example\""));
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
        assert!(response.upstream_url.is_none());
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
        assert_eq!(
            response.upstream_url,
            Some("https://registry.npmjs.org".to_string())
        );
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

    /// Assert that `build_upstream_credentials` returns an error whose message
    /// contains `expected_substr`.
    fn assert_credentials_err(
        auth_type: &str,
        username: Option<&str>,
        password: Option<&str>,
        expected_substr: &str,
    ) {
        let result = build_upstream_credentials(auth_type, username, password);
        let err = result.expect_err("expected credential validation error");
        assert!(
            err.to_string().contains(expected_substr),
            "error {:?} should contain {:?}",
            err.to_string(),
            expected_substr,
        );
    }

    #[test]
    fn test_build_upstream_credentials_basic_missing_username() {
        assert_credentials_err("basic", None, Some("pass"), "username is required");
    }

    #[test]
    fn test_build_upstream_credentials_basic_missing_password() {
        assert_credentials_err("basic", Some("user"), None, "password is required");
    }

    #[test]
    fn test_build_upstream_credentials_bearer_missing_token() {
        assert_credentials_err("bearer", None, None, "password is required");
    }

    #[test]
    fn test_build_upstream_credentials_invalid_type() {
        assert_credentials_err("oauth2", Some("u"), Some("p"), "Invalid auth_type");
    }

    // -----------------------------------------------------------------------
    // extract_name_version_from_path (generic artifact path parsing)
    // -----------------------------------------------------------------------

    #[test]
    fn test_extract_name_version_three_segments() {
        let (name, version) = extract_name_version_from_path("shared-pkg/v1/file.txt");
        assert_eq!(name, "shared-pkg");
        assert_eq!(version.as_deref(), Some("v1"));
    }

    #[test]
    fn test_extract_name_version_four_segments() {
        let (name, version) = extract_name_version_from_path("my-lib/2.0.0/dist/archive.tar.gz");
        assert_eq!(name, "my-lib");
        assert_eq!(version.as_deref(), Some("2.0.0"));
    }

    #[test]
    fn test_extract_name_version_two_segments() {
        let (name, version) = extract_name_version_from_path("shared-pkg/file.txt");
        assert_eq!(name, "file.txt");
        assert!(version.is_none());
    }

    #[test]
    fn test_extract_name_version_single_segment() {
        let (name, version) = extract_name_version_from_path("file.txt");
        assert_eq!(name, "file.txt");
        assert!(version.is_none());
    }

    // -----------------------------------------------------------------------
    // Visibility derivation from AuthExtension
    // -----------------------------------------------------------------------

    fn make_auth(is_admin: bool) -> AuthExtension {
        AuthExtension {
            user_id: Uuid::new_v4(),
            username: "testuser".to_string(),
            email: "test@example.com".to_string(),
            is_admin,
            is_api_token: false,
            is_service_account: false,
            scopes: None,
            allowed_repo_ids: None,
        }
    }

    #[test]
    fn test_visibility_no_auth_is_public_only() {
        let auth: Option<AuthExtension> = None;
        let visibility = match &auth {
            None => RepoVisibility::PublicOnly,
            Some(a) if a.is_admin => RepoVisibility::All,
            Some(a) => RepoVisibility::User(a.user_id),
        };
        assert_eq!(visibility, RepoVisibility::PublicOnly);
    }

    #[test]
    fn test_visibility_admin_is_all() {
        let auth = Some(make_auth(true));
        let visibility = match &auth {
            None => RepoVisibility::PublicOnly,
            Some(a) if a.is_admin => RepoVisibility::All,
            Some(a) => RepoVisibility::User(a.user_id),
        };
        assert_eq!(visibility, RepoVisibility::All);
    }

    #[test]
    fn test_visibility_non_admin_user_filters_by_user_id() {
        let user_auth = make_auth(false);
        let expected_user_id = user_auth.user_id;
        let auth = Some(user_auth);
        let visibility = match &auth {
            None => RepoVisibility::PublicOnly,
            Some(a) if a.is_admin => RepoVisibility::All,
            Some(a) => RepoVisibility::User(a.user_id),
        };
        assert_eq!(visibility, RepoVisibility::User(expected_user_id));
    }

    // -----------------------------------------------------------------------
    // allow_anonymous_access alias (CreateRepositoryRequest)
    // -----------------------------------------------------------------------

    #[test]
    fn test_create_request_effective_is_public_defaults_false() {
        let req: CreateRepositoryRequest = serde_json::from_value(serde_json::json!({
            "key": "test",
            "name": "Test",
            "format": "pypi",
            "repo_type": "remote"
        }))
        .unwrap();
        assert!(!req.effective_is_public());
    }

    #[test]
    fn test_create_request_effective_is_public_from_is_public() {
        let req: CreateRepositoryRequest = serde_json::from_value(serde_json::json!({
            "key": "test",
            "name": "Test",
            "format": "pypi",
            "repo_type": "remote",
            "is_public": true
        }))
        .unwrap();
        assert!(req.effective_is_public());
    }

    #[test]
    fn test_create_request_effective_is_public_from_allow_anonymous_access() {
        let req: CreateRepositoryRequest = serde_json::from_value(serde_json::json!({
            "key": "test",
            "name": "Test",
            "format": "pypi",
            "repo_type": "remote",
            "allow_anonymous_access": true
        }))
        .unwrap();
        assert!(req.effective_is_public());
    }

    #[test]
    fn test_create_request_allow_anonymous_access_overrides_is_public() {
        let req: CreateRepositoryRequest = serde_json::from_value(serde_json::json!({
            "key": "test",
            "name": "Test",
            "format": "pypi",
            "repo_type": "remote",
            "is_public": false,
            "allow_anonymous_access": true
        }))
        .unwrap();
        assert!(req.effective_is_public());
    }

    #[test]
    fn test_create_request_allow_anonymous_false_overrides_is_public_true() {
        let req: CreateRepositoryRequest = serde_json::from_value(serde_json::json!({
            "key": "test",
            "name": "Test",
            "format": "pypi",
            "repo_type": "remote",
            "is_public": true,
            "allow_anonymous_access": false
        }))
        .unwrap();
        assert!(!req.effective_is_public());
    }

    // -----------------------------------------------------------------------
    // allow_anonymous_access alias (UpdateRepositoryRequest)
    // -----------------------------------------------------------------------

    #[test]
    fn test_update_request_effective_is_public_none_when_absent() {
        let req: UpdateRepositoryRequest = serde_json::from_value(serde_json::json!({})).unwrap();
        assert!(req.effective_is_public().is_none());
    }

    #[test]
    fn test_update_request_effective_is_public_from_is_public() {
        let req: UpdateRepositoryRequest =
            serde_json::from_value(serde_json::json!({"is_public": true})).unwrap();
        assert_eq!(req.effective_is_public(), Some(true));
    }

    #[test]
    fn test_update_request_effective_is_public_from_allow_anonymous_access() {
        let req: UpdateRepositoryRequest =
            serde_json::from_value(serde_json::json!({"allow_anonymous_access": true})).unwrap();
        assert_eq!(req.effective_is_public(), Some(true));
    }

    #[test]
    fn test_update_request_allow_anonymous_access_overrides_is_public() {
        let req: UpdateRepositoryRequest = serde_json::from_value(serde_json::json!({
            "is_public": false,
            "allow_anonymous_access": true
        }))
        .unwrap();
        assert_eq!(req.effective_is_public(), Some(true));
    }

    // -----------------------------------------------------------------------
    // RepositoryResponse includes allow_anonymous_access
    // -----------------------------------------------------------------------

    #[test]
    fn test_repo_response_includes_allow_anonymous_access_true() {
        let repo = make_repo(true);
        let resp = repo_to_response(repo, 0);
        assert!(resp.allow_anonymous_access);
        assert_eq!(resp.is_public, resp.allow_anonymous_access);
    }

    #[test]
    fn test_repo_response_includes_allow_anonymous_access_false() {
        let repo = make_repo(false);
        let resp = repo_to_response(repo, 0);
        assert!(!resp.allow_anonymous_access);
        assert_eq!(resp.is_public, resp.allow_anonymous_access);
    }

    #[test]
    fn test_repo_response_allow_anonymous_access_serialized() {
        let repo = make_repo(true);
        let resp = repo_to_response(repo, 0);
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["allow_anonymous_access"], true);
        assert_eq!(json["is_public"], true);
    }
}
