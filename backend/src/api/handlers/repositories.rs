//! Repository management handlers.

use axum::{
    body::Bytes,
    extract::{Extension, Multipart, Path, Query, State},
    http::{header, HeaderMap},
    response::IntoResponse,
    routing::get,
    Router,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::time::Duration;
use utoipa::{IntoParams, OpenApi, ToSchema};
use uuid::Uuid;

use crate::api::download_response::{DownloadResponse, X_ARTIFACT_STORAGE};
use crate::api::dto::Pagination;
// Use the crate-local `Json` extractor so any deserialization failure on a
// request body surfaces as HTTP 400 + `{code: "VALIDATION_ERROR"}` instead of
// Axum's default 422 + plain-text body. See #1368 and the module docs in
// `crate::api::extractors`. The wrapper also implements `IntoResponse` so it
// is a drop-in replacement on response types too.
use crate::api::extractors::Json;
use crate::api::handlers::proxy_helpers;
use crate::api::middleware::auth::AuthExtension;
use crate::api::SharedState;
use crate::error::{AppError, Result};
use crate::formats::maven::MavenHandler;
use crate::models::repository::{RepositoryFormat, RepositoryType};
use crate::services::artifact_service::ArtifactService;
use crate::services::permission_service::{SYSTEM_SENTINEL_ID, SYSTEM_TARGET_TYPE};
use crate::services::proxy_service::DEFAULT_CACHE_TTL_SECS;
use crate::services::repository_service::{
    CreateRepositoryRequest as ServiceCreateRepoReq, RepoVisibility, RepositoryService,
    UpdateRepositoryRequest as ServiceUpdateRepoReq,
};
use crate::services::routing_rules::{self, RoutingRule};
use crate::services::upload_service;

/// Require that the request is authenticated, returning an error if not.
fn require_auth(auth: Option<AuthExtension>) -> Result<AuthExtension> {
    auth.ok_or_else(|| AppError::Authentication("Authentication required".to_string()))
}

/// Coerce the requested `is_public` value against the server-wide guest-access
/// policy (issue #850).
///
/// When guest access is disabled, public repositories are meaningless: anonymous
/// users will never reach them. We therefore silently coerce `true` to `false`
/// on create/update so the persisted state matches the runtime policy. Returns
/// the value to persist, plus a flag indicating whether coercion happened so
/// the caller can emit a structured `tracing::warn!` log.
fn coerce_is_public_for_create(requested: bool, guest_access_enabled: bool) -> (bool, bool) {
    if requested && !guest_access_enabled {
        (false, true)
    } else {
        (requested, false)
    }
}

/// Update-side counterpart of [`coerce_is_public_for_create`]. The update
/// payload uses `Option<bool>` because callers can leave the flag unchanged;
/// only an explicit `Some(true)` is coerced.
fn coerce_is_public_for_update(
    requested: Option<bool>,
    guest_access_enabled: bool,
) -> (Option<bool>, bool) {
    if matches!(requested, Some(true)) && !guest_access_enabled {
        (Some(false), true)
    } else {
        (requested, false)
    }
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

/// Issue #913: authorize a virtual-member mutation.
///
/// All three mutating handlers (`add_virtual_member`, `remove_virtual_member`,
/// per-iteration step of `update_virtual_members`) must check access on BOTH
/// the virtual parent and the member repo. A caller with write scope on the
/// virtual parent must not be able to add/remove/reorder members they have no
/// rights to. Tokens with `allowed_repo_ids = None` (admins, JWT sessions,
/// unrestricted API tokens) bypass these checks naturally.
///
/// On denial of the member-repo check, emit a structured `tracing::warn!` so
/// the event is recoverable from logs (the parent-repo denial is left to the
/// existing `require_repo_access` callers that warn elsewhere in this module).
fn authorize_virtual_member_mutation(
    auth: &AuthExtension,
    virtual_repo: &crate::models::repository::Repository,
    member_repo: &crate::models::repository::Repository,
    action: &str,
) -> Result<()> {
    if let Err(e) = require_repo_access(auth, virtual_repo.id) {
        tracing::warn!(
            actor_user_id = %auth.user_id,
            actor_username = %auth.username,
            virtual_repo_id = %virtual_repo.id,
            virtual_repo_key = %virtual_repo.key,
            member_repo_id = %member_repo.id,
            member_repo_key = %member_repo.key,
            action = action,
            "denied virtual-member mutation: caller lacks access to virtual parent repo"
        );
        return Err(e);
    }
    if let Err(e) = require_repo_access(auth, member_repo.id) {
        tracing::warn!(
            actor_user_id = %auth.user_id,
            actor_username = %auth.username,
            virtual_repo_id = %virtual_repo.id,
            virtual_repo_key = %virtual_repo.key,
            member_repo_id = %member_repo.id,
            member_repo_key = %member_repo.key,
            action = action,
            "denied virtual-member mutation: caller lacks access to member repo"
        );
        return Err(e);
    }
    Ok(())
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

/// Sub-router holding ONLY the artifact download route. Split out from
/// the main `router()` so the caller can apply a stricter per-IP rate
/// limit to it without touching the rest of the repository CRUD.
/// See [`router_with_presign_layer`] and #1053.
pub fn download_router() -> Router<SharedState> {
    Router::new().route("/:key/download/*path", get(download_artifact))
}

/// Create repository routes (excluding the download route, which has
/// stricter per-IP rate limiting; see [`download_router`] and #1053).
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
        // Note: `/:key/download/*path` lives in `download_router()` so it
        // can carry a stricter per-IP presign-mint rate limit (#1053).
        // Security routes nested under repository
        .merge(super::security::repo_security_router())
        // Label routes nested under repository
        .merge(super::repository_labels::repo_labels_router())
        // Token management routes nested under repository
        .merge(super::repo_tokens::repo_tokens_router())
        // Email subscription routes nested under repository (#920 replacement
        // for the deleted /notifications email channel)
        .merge(super::email_subscriptions::router())
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

/// Reject `POST /api/v1/repositories` requests that create a virtual repo
/// with no members.
///
/// Such repos are unusable: every fetch returns
/// `404 Resource not found: Virtual repository has no members`. Pre-fix
/// (#1279) the create handler tolerated both broken shapes silently:
///
///   * `member_repos` field omitted entirely. Operators who naturally
///     typed `members: [...]` (the more intuitive name) had their input
///     dropped by serde because the struct field is `member_repos`, not
///     `members`, and `CreateRepositoryRequest` does not enable
///     `deny_unknown_fields`. Result: `member_repos == None`.
///   * `member_repos: []` (empty array). Result:
///     `member_repos == Some(vec![])`.
///
/// Both shapes produced a successfully-created repo whose every fetch
/// returned 404. The error surfaces minutes later when someone actually
/// tries to use the repo, which is the worst possible discoverability.
///
/// This validator returns a `400 Bad Request` at create time, naming
/// the expected field shape and pointing operators at the dedicated
/// `PUT /repositories/{key}/members` endpoint for post-create updates.
/// Non-virtual repo_types pass through unchanged.
fn validate_virtual_repo_member_count(
    repo_key: &str,
    repo_type: &RepositoryType,
    member_repos: Option<&[CreateVirtualMemberInput]>,
) -> Result<()> {
    if *repo_type != RepositoryType::Virtual {
        return Ok(());
    }
    let count = member_repos.map_or(0, <[_]>::len);
    if count == 0 {
        return Err(AppError::Validation(format!(
            "Virtual repository '{}' requires at least one member. Provide \
             `member_repos: [{{\"repo_key\": \"<key>\", \"priority\": <int>}}, ...]` \
             in the request body. Use `PUT /api/v1/repositories/{}/members` \
             after creation to update the member list. (#1279)",
            repo_key, repo_key
        )));
    }
    Ok(())
}

/// Reject `cache_ttl` writes against repositories whose proxy code path will
/// never read the value back. Only Remote (proxy) repositories consume the
/// `cache_ttl_secs` row written by `set_cache_ttl`; writing it for Local,
/// Virtual or Staging repos produces dead state with no consumer.
fn is_cache_ttl_configurable(repo_type: &RepositoryType) -> Result<()> {
    if repo_type != &RepositoryType::Remote {
        return Err(AppError::Validation(
            "cache_ttl is only configurable on remote (proxy) repositories".to_string(),
        ));
    }
    Ok(())
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

    let service = RepositoryService::new(state.db.clone());
    let repo = service.get_by_key(&key).await?;
    require_repo_access(&auth, repo.id)?;

    // Reject writes on non-remote repos before any further validation: the
    // value would never be read back by the proxy code path (see #917).
    // The explicit `repo.repo_type != RepositoryType::Remote` comparison
    // inside `is_cache_ttl_configurable` is what the structural regression
    // test below greps for.
    is_cache_ttl_configurable(&repo.repo_type)?;

    if !validate_cache_ttl(payload.cache_ttl_seconds) {
        return Err(AppError::Validation(
            "cache_ttl_seconds must be between 1 and 2592000 (30 days)".to_string(),
        ));
    }

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
// Note: GET stays permissive for any repo_type even though writes are
// restricted to Remote repositories (see `set_cache_ttl`). Existing UI
// probes call this endpoint for every repo type and expect a 200 with the
// default TTL; tightening the read path would break them.
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

    let ttl = resolve_cache_ttl(result.map(|(v,)| v));

    Ok(Json(CacheTtlResponse {
        repository_key: key,
        cache_ttl_seconds: ttl,
    }))
}

/// Resolve the effective cache TTL from a stored `repository_config` value.
///
/// Falls back to [`DEFAULT_CACHE_TTL_SECS`] when no value is stored or when the
/// stored value cannot be parsed as `i64`. This matches the default applied by
/// `proxy_service` so `GET /cache-ttl` always reports the value the proxy will
/// actually use.
fn resolve_cache_ttl(stored: Option<String>) -> i64 {
    stored
        .and_then(|v| v.parse::<i64>().ok())
        .unwrap_or(DEFAULT_CACHE_TTL_SECS)
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
        (status = 403, description = "Insufficient permissions"),
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

    // Fine-grained permission check: non-admins need "admin" on the system sentinel.
    if !auth.is_admin {
        let has_perm = state
            .permission_service
            .check_permission(
                auth.user_id,
                SYSTEM_TARGET_TYPE,
                SYSTEM_SENTINEL_ID,
                "admin",
                false,
            )
            .await?;
        if !has_perm {
            return Err(AppError::Authorization(
                "Insufficient permissions to create repositories".to_string(),
            ));
        }
    }

    validate_repository_key(&payload.key)?;
    let format = parse_format(&payload.format)?;
    let repo_type = parse_repo_type(&payload.repo_type)?;

    // Validate up-front that virtual repos arrive with at least one member.
    // See `validate_virtual_repo_member_count` for the rationale (#1279).
    validate_virtual_repo_member_count(&payload.key, &repo_type, payload.member_repos.as_deref())?;

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

    // Issue #850: silently coerce `is_public` to false when guest access is
    // disabled server-wide so the persisted state matches the runtime policy.
    let (is_public, coerced) = coerce_is_public_for_create(
        payload.effective_is_public(),
        state.config.guest_access_enabled,
    );
    if coerced {
        tracing::warn!(
            repo_key = %payload.key,
            "Coercing repository to private: AK_GUEST_ACCESS_ENABLED=false disables public repos"
        );
    }

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

    // Add virtual repository members. The up-front validation above
    // guarantees `member_repos` is `Some(non-empty)` whenever
    // `repo_type == Virtual`, so the empty / None arms are unreachable.
    if repo_type == RepositoryType::Virtual {
        let member_inputs = payload
            .member_repos
            .as_deref()
            .expect("member_repos non-empty validated above");
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
                .add_virtual_member(repo.id, member_repo.id, Some(priority))
                .await?;
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

    state.event_bus.emit_repository_event(
        "repository.created",
        repo.id,
        Some(auth.username.clone()),
    );

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
        (status = 403, description = "Insufficient permissions"),
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

    // Fine-grained permission check: non-admins need "admin" on the target repository.
    if !auth.is_admin {
        let has_perm = state
            .permission_service
            .check_permission(auth.user_id, "repository", existing.id, "admin", false)
            .await?;
        if !has_perm {
            return Err(AppError::Authorization(
                "Insufficient permissions to update this repository".to_string(),
            ));
        }
    }

    // Issue #850: ignore any attempt to flip a repository back to public when
    // guest access is disabled. The web UI hides the toggle, but API clients
    // and stale forms may still send `true`.
    let (effective_is_public, coerced) = coerce_is_public_for_update(
        payload.effective_is_public(),
        state.config.guest_access_enabled,
    );
    if coerced {
        tracing::warn!(
            repo_key = %key,
            "Ignoring is_public=true on update: AK_GUEST_ACCESS_ENABLED=false disables public repos"
        );
    }

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
    {
        let mut cache = state.repo_cache.write().await;
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

    state.event_bus.emit_repository_event(
        "repository.updated",
        repo.id,
        Some(auth.username.clone()),
    );

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
        (status = 403, description = "Insufficient permissions"),
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

    // Fine-grained permission check: non-admins need "admin" on the target repository.
    if !auth.is_admin {
        let has_perm = state
            .permission_service
            .check_permission(auth.user_id, "repository", repo.id, "admin", false)
            .await?;
        if !has_perm {
            return Err(AppError::Authorization(
                "Insufficient permissions to delete this repository".to_string(),
            ));
        }
    }

    service.delete(repo.id).await?;

    // Remove the deleted repo from the in-memory cache.
    {
        let mut cache = state.repo_cache.write().await;
        cache.remove(&key);
    }

    state.event_bus.emit_repository_event(
        "repository.deleted",
        repo.id,
        Some(auth.username.clone()),
    );
    Ok(())
}

// Artifact handlers (nested under repository)

#[derive(Debug, Deserialize, IntoParams, ToSchema)]
pub struct ListArtifactsQuery {
    pub page: Option<u32>,
    pub per_page: Option<u32>,
    pub q: Option<String>,
    pub path_prefix: Option<String>,
    /// Server-side artifact grouping.
    ///
    /// Supported values:
    /// - `maven_component`: Maven/Gradle artifacts are grouped by
    ///   groupId, artifactId, and version.  Individual files (jar, pom,
    ///   checksums) appear in the `artifact_files` array of each component.
    /// - `docker_tag`: Docker/OCI artifacts are grouped by (image, tag),
    ///   with `total_size_bytes` summed across the manifest config and
    ///   referenced layer blobs.  The grouped rows are returned in the
    ///   `docker_tags` array.
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
    /// Docker tag grouping.  Only present when `group_by=docker_tag`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub docker_tags: Option<Vec<DockerTagResponse>>,
}

/// A Docker/OCI tag grouped by (image, tag).
///
/// `total_size_bytes` is the server-side aggregation of the manifest body
/// plus every referenced layer blob.  This is what the UI should display
/// as the on-disk image size; the previous client-side aggregation that
/// only summed the manifest body itself reported a few kilobytes for
/// images that are hundreds of megabytes on disk (artifact-keeper#1193).
///
/// For multi-arch image indexes the size is the sum across all per-arch
/// child manifests recorded in `oci_manifest_refs`, so an `amd64+arm64`
/// index reports the combined storage cost.
#[derive(Debug, Serialize, ToSchema, Clone)]
pub struct DockerTagResponse {
    /// Representative manifest artifact ID.
    pub id: Uuid,
    /// Repository key this tag belongs to.
    pub repository_key: String,
    /// Image name (no registry host, no tag).  Maps to the OCI v2 `<name>`
    /// path segment, which may include slashes (e.g. `library/postgres`).
    pub image: String,
    /// Tag string (e.g. `16-alpine`).  Never a `sha256:...` digest;
    /// digest-only references are filtered out of the grouping.
    pub tag: String,
    /// Manifest content digest (e.g. `sha256:abcdef...`).
    pub manifest_digest: String,
    /// Total size in bytes of the manifest plus all referenced layer blobs.
    /// For image indexes, this sums across child manifests.
    pub total_size_bytes: i64,
    /// Number of layer blobs referenced by the manifest.  For image indexes
    /// this is the sum of layer counts across child manifests.  `0` when
    /// the manifest could not be parsed.
    pub layer_count: i32,
    /// Whether this manifest is a multi-arch image index.
    pub is_index: bool,
    /// Last push (or update) timestamp from the underlying `oci_tags` row.
    pub last_pushed_at: chrono::DateTime<chrono::Utc>,
    /// Latest scan status (`pending`, `running`, `completed`, `failed`) from
    /// `scan_results`, if the manifest has ever been scanned.  `None` when
    /// the artifact has never been scanned.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scan_status: Option<String>,
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

    let is_docker_format = matches!(
        repo.format,
        RepositoryFormat::Docker
            | RepositoryFormat::Podman
            | RepositoryFormat::Oras
            | RepositoryFormat::WasmOci
            | RepositoryFormat::HelmOci
    );
    let want_docker_grouping = query.group_by.as_deref() == Some("docker_tag") && is_docker_format;

    if want_docker_grouping {
        return list_artifacts_grouped_by_docker_tag(
            &state,
            &repo,
            &key,
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

    // For Maven/Gradle, also load the metadata.files arrays so we can
    // surface POM, sources, javadoc, and other secondary files that the
    // upload handler groups under one artifact row (#1092). Without this
    // expansion the listing only sees the primary JAR/WAR and any
    // secondary files appear "hidden" until a downstream remote proxy
    // pulls them, at which point the proxy records them as their own
    // artifact rows.
    //
    // Note: `pagination.total` is the number of primary artifact rows,
    // not the post-expansion item count. The items array therefore
    // exceeds `per_page` for any page that contains a GAV with grouped
    // secondary files. Clients that need exact page sizes should call
    // the grouped-by-component endpoint instead (`group_by=maven_component`).
    let maven_files_by_artifact: std::collections::HashMap<Uuid, Vec<serde_json::Value>> =
        if is_maven_format {
            load_maven_secondary_files(&state.db, &artifact_ids).await
        } else {
            std::collections::HashMap::new()
        };

    let mut items = Vec::new();
    for artifact in artifacts {
        let artifact_id = artifact.id;
        let download_count = *download_counts.get(&artifact_id).unwrap_or(&0);
        items.push(build_artifact_response(&artifact, &key, download_count));

        if let Some(secondary) = maven_files_by_artifact.get(&artifact_id) {
            items.extend(expand_maven_secondary_files(&artifact, &key, secondary));
        }
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
        docker_tags: None,
    }))
}

/// Build the `ArtifactResponse` representing a single primary artifact row.
///
/// Extracted from the inline listing loop so it can be unit-tested
/// without a database. Pure transformation of `Artifact` fields plus
/// the precomputed download count.
fn build_artifact_response(
    artifact: &crate::models::artifact::Artifact,
    repo_key: &str,
    download_count: i64,
) -> ArtifactResponse {
    ArtifactResponse {
        id: artifact.id,
        repository_key: repo_key.to_string(),
        path: artifact.path.clone(),
        name: artifact.name.clone(),
        version: artifact.version.clone(),
        size_bytes: artifact.size_bytes,
        checksum_sha256: artifact.checksum_sha256.clone(),
        content_type: artifact.content_type.clone(),
        download_count,
        created_at: artifact.created_at,
        metadata: None,
    }
}

/// Build `ArtifactResponse` rows for each Maven secondary file recorded
/// under a single primary artifact (#1092).
///
/// Skips any entry without a `path` field and any entry whose path
/// matches the primary's own path (defensive against an older upload
/// path that may have double-recorded the primary). Returns the
/// resulting rows in the order they appear in the metadata.files array.
fn expand_maven_secondary_files(
    artifact: &crate::models::artifact::Artifact,
    repo_key: &str,
    secondary: &[serde_json::Value],
) -> Vec<ArtifactResponse> {
    let mut out = Vec::new();
    for f in secondary {
        let Some(fpath) = f.get("path").and_then(|v| v.as_str()) else {
            continue;
        };
        if fpath == artifact.path {
            // Skip the primary's own entry if it ever made it into the
            // files array.
            continue;
        }
        let size = f.get("sizeBytes").and_then(|v| v.as_i64()).unwrap_or(0);
        let sha = f
            .get("sha256")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let ext = f.get("extension").and_then(|v| v.as_str()).unwrap_or("");
        out.push(ArtifactResponse {
            id: artifact.id,
            repository_key: repo_key.to_string(),
            path: fpath.to_string(),
            name: artifact.name.clone(),
            version: artifact.version.clone(),
            size_bytes: size,
            checksum_sha256: sha,
            content_type: content_type_for_maven_extension(ext).to_string(),
            download_count: 0,
            created_at: artifact.created_at,
            metadata: None,
        });
    }
    out
}

/// Return a best-guess HTTP content type for a Maven file extension.
/// Mirrors `api::handlers::maven::content_type_for_path` for the
/// extensions secondary-file rows actually carry. Unknown extensions
/// fall through to `application/octet-stream`.
fn content_type_for_maven_extension(ext: &str) -> &'static str {
    match ext {
        "pom" | "xml" => "text/xml",
        "jar" | "war" | "ear" | "aar" | "bundle" => "application/java-archive",
        "zip" | "tar.gz" => "application/zip",
        "asc" | "sig" => "application/pgp-signature",
        "md5" | "sha1" | "sha256" | "sha512" => "text/plain",
        _ => "application/octet-stream",
    }
}

/// Load the `metadata.files` JSON array for a batch of Maven artifact ids,
/// returning a map keyed by `artifact_id`. Used to expand grouped
/// secondary-file entries into addressable rows in the listing API
/// (#1092). Artifacts without a metadata row or without a `files` array
/// are omitted from the returned map.
async fn load_maven_secondary_files(
    db: &sqlx::PgPool,
    artifact_ids: &[Uuid],
) -> std::collections::HashMap<Uuid, Vec<serde_json::Value>> {
    use sqlx::Row;
    if artifact_ids.is_empty() {
        return std::collections::HashMap::new();
    }
    let rows = match sqlx::query(
        "SELECT artifact_id, metadata FROM artifact_metadata \
         WHERE artifact_id = ANY($1) AND format = 'maven'",
    )
    .bind(artifact_ids)
    .fetch_all(db)
    .await
    {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!("Maven secondary-file metadata lookup failed: {}", e);
            return std::collections::HashMap::new();
        }
    };

    let mut out: std::collections::HashMap<Uuid, Vec<serde_json::Value>> =
        std::collections::HashMap::new();
    for r in rows {
        let id: Uuid = match r.try_get("artifact_id") {
            Ok(v) => v,
            Err(_) => continue,
        };
        let meta: Option<serde_json::Value> = r.try_get("metadata").ok();
        if let Some(files) = extract_secondary_files_from_metadata(meta.as_ref()) {
            out.insert(id, files);
        }
    }
    out
}

/// Pure helper that pulls the `files` array out of an `artifact_metadata.metadata`
/// JSON blob. Returns `None` when the row has no metadata, no `files` array,
/// or an empty `files` array, so the caller can omit the artifact from its
/// "has secondary files" lookup table. Extracted so the JSON-shape parsing
/// is testable without hitting Postgres.
fn extract_secondary_files_from_metadata(
    metadata: Option<&serde_json::Value>,
) -> Option<Vec<serde_json::Value>> {
    let files = metadata
        .and_then(|m| m.get("files"))
        .and_then(|f| f.as_array())
        .cloned()
        .unwrap_or_default();
    if files.is_empty() {
        None
    } else {
        Some(files)
    }
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
        docker_tags: None,
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

// ---------------------------------------------------------------------------
// Docker tag grouping (artifact-keeper#1193)
//
// Mirrors the Maven `group_by=maven_component` pattern: the frontend can
// request a paginated list of Docker tags where each row carries the
// server-side aggregated image size (manifest + every referenced layer
// blob).  Without this, the web UI had to fetch every artifact row and
// guess at sizes from the manifest body alone, which under-reports the
// real on-disk image cost by ~3 orders of magnitude.
//
// The aggregation walks `oci_tags` (human-readable tags only; digest
// references are filtered) and looks up the precomputed `size_bytes` on
// the corresponding `artifacts` row. The OCI v2 PUT-manifest handler
// already computes `config_size + layers_size` when persisting the
// artifact row, so the grouping is a join, not a re-parse of every
// manifest body. For multi-arch image indexes, the child manifest
// digests recorded in `oci_manifest_refs` are also summed in.
// ---------------------------------------------------------------------------

/// Database row used to assemble a `DockerTagResponse`.
///
/// `total_size_bytes` is the precomputed size on the `artifacts` row for
/// the manifest. For image-index manifests, the child sizes are added by
/// `expand_docker_index_sizes` after this query runs.
#[derive(Debug, Clone)]
struct DockerTagRow {
    artifact_id: Uuid,
    image: String,
    tag: String,
    manifest_digest: String,
    manifest_content_type: String,
    manifest_size_bytes: i64,
    last_pushed_at: chrono::DateTime<chrono::Utc>,
    scan_status: Option<String>,
}

/// Build a grouped-by-tag response for Docker/OCI repositories.
///
/// Fetches up to `MAX_FETCH` distinct (image, tag) rows from `oci_tags`,
/// joined to the corresponding `artifacts` row to get the precomputed
/// manifest+layers size. The grouped list is then paginated in memory.
///
/// Digest references (tags containing `:` such as `sha256:abc...`) are
/// excluded, matching the OCI v2 `tags/list` filter.  An optional `q`
/// substring is matched case-insensitively against the tag string so the
/// web UI's tag-search input keeps working in grouped mode.
async fn list_artifacts_grouped_by_docker_tag(
    state: &SharedState,
    repo: &crate::models::repository::Repository,
    repo_key: &str,
    search_query: Option<&str>,
    page: u32,
    per_page: u32,
) -> Result<Json<ArtifactListResponse>> {
    const MAX_FETCH: i64 = 10_000;

    let rows = fetch_docker_tag_rows(&state.db, repo.id, search_query, MAX_FETCH).await?;

    // For multi-arch image indexes, fold in each child manifest's size so
    // the surfaced number matches what `docker pull` actually downloads
    // for the platforms the index references.
    let index_digests: Vec<String> = rows
        .iter()
        .filter(|r| is_docker_index_content_type(&r.manifest_content_type))
        .map(|r| r.manifest_digest.clone())
        .collect();

    let child_sizes = if index_digests.is_empty() {
        std::collections::HashMap::new()
    } else {
        fetch_index_child_sizes(&state.db, repo.id, &index_digests).await?
    };

    let mut docker_tags: Vec<DockerTagResponse> = rows
        .into_iter()
        .map(|row| build_docker_tag_response(row, repo_key, &child_sizes))
        .collect();

    // Stable lexical sort by (image, tag) for paging determinism.
    docker_tags.sort_by(|a, b| (&a.image, &a.tag).cmp(&(&b.image, &b.tag)));

    let total = docker_tags.len() as i64;
    let total_pages = ((total as f64) / (per_page as f64)).ceil() as u32;
    let offset = ((page - 1) * per_page) as usize;
    let page_tags: Vec<DockerTagResponse> = docker_tags
        .into_iter()
        .skip(offset)
        .take(per_page as usize)
        .collect();

    Ok(Json(ArtifactListResponse {
        items: Vec::new(),
        pagination: Pagination {
            page,
            per_page,
            total,
            total_pages,
        },
        components: None,
        docker_tags: Some(page_tags),
    }))
}

/// Fetch raw rows from `oci_tags` joined to `artifacts` and (optionally) the
/// latest `scan_results` row. Returns at most `limit` rows.
///
/// The join keys are deterministic strings produced by the OCI v2 push
/// handler: every `oci_tags` row has a matching `artifacts` row at
/// `path = v2/{image}/manifests/{tag}` (see `handle_put_manifest`).  We
/// use `repository_id + path` so the join survives image renames.
async fn fetch_docker_tag_rows(
    db: &sqlx::PgPool,
    repository_id: Uuid,
    search_query: Option<&str>,
    limit: i64,
) -> Result<Vec<DockerTagRow>> {
    use sqlx::Row;

    // POSITION(':' IN tag) = 0 excludes digest references (sha256:...),
    // matching the spec'd /v2/<name>/tags/list filter.
    //
    // The artifacts join is by composed path because OCI artifact rows do
    // not carry a back-reference to the oci_tags row; the push handler
    // composes `v2/{image}/manifests/{tag}` deterministically.
    //
    // LEFT JOIN scan_results on the latest row per artifact is filtered
    // by NOT EXISTS so we don't carry historical scans; this matches the
    // partial-index pattern from migration 101.
    let sql = if search_query.is_some() {
        r#"SELECT
                a.id            AS artifact_id,
                t.name          AS image,
                t.tag           AS tag,
                t.manifest_digest AS manifest_digest,
                t.manifest_content_type AS manifest_content_type,
                a.size_bytes    AS manifest_size_bytes,
                t.updated_at    AS last_pushed_at,
                s.status        AS scan_status
            FROM oci_tags t
            JOIN artifacts a
              ON a.repository_id = t.repository_id
             AND a.path = 'v2/' || t.name || '/manifests/' || t.tag
             AND a.is_deleted = false
            LEFT JOIN LATERAL (
                SELECT status
                FROM scan_results
                WHERE artifact_id = a.id
                ORDER BY created_at DESC
                LIMIT 1
            ) s ON true
            WHERE t.repository_id = $1
              AND POSITION(':' IN t.tag) = 0
              AND LOWER(t.tag) LIKE '%' || LOWER($2) || '%'
            ORDER BY t.name, t.tag
            LIMIT $3"#
    } else {
        r#"SELECT
                a.id            AS artifact_id,
                t.name          AS image,
                t.tag           AS tag,
                t.manifest_digest AS manifest_digest,
                t.manifest_content_type AS manifest_content_type,
                a.size_bytes    AS manifest_size_bytes,
                t.updated_at    AS last_pushed_at,
                s.status        AS scan_status
            FROM oci_tags t
            JOIN artifacts a
              ON a.repository_id = t.repository_id
             AND a.path = 'v2/' || t.name || '/manifests/' || t.tag
             AND a.is_deleted = false
            LEFT JOIN LATERAL (
                SELECT status
                FROM scan_results
                WHERE artifact_id = a.id
                ORDER BY created_at DESC
                LIMIT 1
            ) s ON true
            WHERE t.repository_id = $1
              AND POSITION(':' IN t.tag) = 0
            ORDER BY t.name, t.tag
            LIMIT $2"#
    };

    let rows = if let Some(q) = search_query {
        sqlx::query(sql)
            .bind(repository_id)
            .bind(q)
            .bind(limit)
            .fetch_all(db)
            .await
            .map_err(|e| AppError::Database(e.to_string()))?
    } else {
        sqlx::query(sql)
            .bind(repository_id)
            .bind(limit)
            .fetch_all(db)
            .await
            .map_err(|e| AppError::Database(e.to_string()))?
    };

    let mut out = Vec::with_capacity(rows.len());
    for r in rows {
        out.push(DockerTagRow {
            artifact_id: r
                .try_get("artifact_id")
                .map_err(|e| AppError::Database(e.to_string()))?,
            image: r
                .try_get("image")
                .map_err(|e| AppError::Database(e.to_string()))?,
            tag: r
                .try_get("tag")
                .map_err(|e| AppError::Database(e.to_string()))?,
            manifest_digest: r
                .try_get("manifest_digest")
                .map_err(|e| AppError::Database(e.to_string()))?,
            manifest_content_type: r
                .try_get::<Option<String>, _>("manifest_content_type")
                .map_err(|e| AppError::Database(e.to_string()))?
                .unwrap_or_default(),
            manifest_size_bytes: r
                .try_get("manifest_size_bytes")
                .map_err(|e| AppError::Database(e.to_string()))?,
            last_pushed_at: r
                .try_get("last_pushed_at")
                .map_err(|e| AppError::Database(e.to_string()))?,
            scan_status: r.try_get("scan_status").ok().flatten(),
        });
    }
    Ok(out)
}

/// Sum the precomputed `artifacts.size_bytes` for each child manifest
/// referenced by an image index. Returns a map keyed by the parent
/// (index) digest with the total child size in bytes.
///
/// Children are stored as their own digest-keyed artifact rows
/// (`v2/{image}/manifests/sha256:...`); we join `oci_manifest_refs` to
/// pick up every (parent, child) edge in one round trip. Children
/// without a matching artifact row contribute zero, which mirrors the
/// `download_blob` fallback behavior for missing children.
async fn fetch_index_child_sizes(
    db: &sqlx::PgPool,
    repository_id: Uuid,
    index_digests: &[String],
) -> Result<std::collections::HashMap<String, i64>> {
    use sqlx::Row;

    let rows = sqlx::query(
        r#"SELECT
                r.parent_digest AS parent_digest,
                COALESCE(SUM(a.size_bytes), 0)::BIGINT AS child_total
            FROM oci_manifest_refs r
            LEFT JOIN artifacts a
              ON a.repository_id = r.repository_id
             AND a.checksum_sha256 = REPLACE(r.child_digest, 'sha256:', '')
             AND a.is_deleted = false
            WHERE r.repository_id = $1
              AND r.parent_digest = ANY($2)
            GROUP BY r.parent_digest"#,
    )
    .bind(repository_id)
    .bind(index_digests)
    .fetch_all(db)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;

    let mut out = std::collections::HashMap::with_capacity(rows.len());
    for r in rows {
        let parent: String = r
            .try_get("parent_digest")
            .map_err(|e| AppError::Database(e.to_string()))?;
        let total: i64 = r
            .try_get("child_total")
            .map_err(|e| AppError::Database(e.to_string()))?;
        out.insert(parent, total);
    }
    Ok(out)
}

/// Convert a fetched `DockerTagRow` into the response shape.
///
/// Folds in the per-index child total (if any) so multi-arch tags
/// report the full on-disk cost across architectures rather than just
/// the index document size.
fn build_docker_tag_response(
    row: DockerTagRow,
    repo_key: &str,
    index_child_sizes: &std::collections::HashMap<String, i64>,
) -> DockerTagResponse {
    let is_index = is_docker_index_content_type(&row.manifest_content_type);
    let child_size = if is_index {
        index_child_sizes
            .get(&row.manifest_digest)
            .copied()
            .unwrap_or(0)
    } else {
        0
    };
    let total_size_bytes = row.manifest_size_bytes.saturating_add(child_size);

    DockerTagResponse {
        id: row.artifact_id,
        repository_key: repo_key.to_string(),
        image: row.image,
        tag: row.tag,
        manifest_digest: row.manifest_digest,
        total_size_bytes,
        // Layer count is not persisted; the push handler stores the sum
        // but not the count. Leaving it as a derived field would require
        // re-fetching every manifest body. Future enhancement: persist
        // layer_count alongside size_bytes on the artifact row.
        layer_count: 0,
        is_index,
        last_pushed_at: row.last_pushed_at,
        scan_status: row.scan_status,
    }
}

/// True for OCI image-index and Docker manifest-list content types.
///
/// Mirrors `oci_v2::is_index_content_type` but lives here to keep the
/// repositories handler self-contained (its cousin in `oci_v2.rs` is
/// `pub(crate)` and could be re-exported, but duplicating two lines is
/// cheaper than the cross-module visibility churn). Charset hints
/// (`; charset=utf-8`) are stripped before comparison.
fn is_docker_index_content_type(content_type: &str) -> bool {
    let bare = content_type
        .split(';')
        .next()
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase();
    matches!(
        bare.as_str(),
        "application/vnd.oci.image.index.v1+json"
            | "application/vnd.docker.distribution.manifest.list.v2+json"
    )
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

    // Validate the composed artifact path against traversal, null bytes,
    // backslashes, percent-encoded traversal, absolute paths, etc. This
    // protects all upload entry points (URL-path variant, multipart with
    // path in URL, and multipart with `path` form field added in #1237).
    // Filesystem storage's `key_to_path` would strip `..` segments, but S3
    // and other object backends would happily accept `../etc/passwd`.
    upload_service::validate_artifact_path(&path)
        .map_err(|e| AppError::Validation(e.to_string()))?;

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
/// The artifact path is built from the optional `path` form field combined
/// with the uploaded file's filename:
///   - missing/empty `path` -> path is just the filename
///   - `path` ending in `/` -> path becomes `<path><filename>` (directory prefix)
///   - otherwise the `path` value is used verbatim as the full artifact path
///
/// This is what makes the web UI's "Custom path (optional)" field actually
/// land artifacts at the requested path (#1237). Previously the form field
/// was silently dropped and only the filename was used.
async fn upload_artifact_multipart(
    State(state): State<SharedState>,
    Extension(auth): Extension<Option<AuthExtension>>,
    Path(key): Path<String>,
    headers: HeaderMap,
    multipart: Multipart,
) -> Result<Json<ArtifactResponse>> {
    let (body, filename, custom_path) = extract_multipart_file_and_path(multipart).await?;
    let artifact_path = compose_artifact_path(custom_path.as_deref(), &filename);
    upload_artifact(
        State(state),
        Extension(auth),
        Path((key, artifact_path)),
        headers,
        body,
    )
    .await
}

/// Combine an optional client-provided `path` field with the uploaded file's
/// filename into a single artifact path.
///
/// Rules (see #1237):
///   - `None` or empty `custom_path` -> `filename`
///   - `custom_path` ending in `/`   -> `<custom_path><filename>` (directory)
///   - otherwise                     -> `custom_path` verbatim (full path)
///
/// Leading slashes on `custom_path` are stripped so callers can pass either
/// `unifi/docs/` or `/unifi/docs/`. Empty segments produced by `//` are
/// rejected by `validate_artifact_path` later in the upload pipeline.
fn compose_artifact_path(custom_path: Option<&str>, filename: &str) -> String {
    let raw = custom_path.unwrap_or("").trim();
    let trimmed = raw.trim_start_matches('/');
    if trimmed.is_empty() {
        return filename.to_string();
    }
    if trimmed.ends_with('/') {
        // Treat as a directory prefix: append the uploaded filename.
        format!("{trimmed}{filename}")
    } else {
        trimmed.to_string()
    }
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

/// Extract both a file field and an optional `path` text field from a
/// multipart form.
///
/// Iterates the full form: a file field (one with a `filename`) yields the
/// body and original filename; a `path` field (any non-file field named
/// `path`) yields the requested artifact path. Either may appear in any
/// order. Returns an error if no file is found.
async fn extract_multipart_file_and_path(
    mut multipart: Multipart,
) -> Result<(Bytes, String, Option<String>)> {
    let mut file: Option<(Bytes, String)> = None;
    let mut custom_path: Option<String> = None;

    while let Some(field) = multipart
        .next_field()
        .await
        .map_err(|e| AppError::Validation(format!("Invalid multipart data: {e}")))?
    {
        let filename = field.file_name().map(|s| s.to_string());
        let name = field.name().map(|s| s.to_string());
        if let Some(filename) = filename {
            // File upload field
            if file.is_none() {
                let data: Bytes = field
                    .bytes()
                    .await
                    .map_err(|e| AppError::Validation(format!("Failed to read file: {e}")))?;
                file = Some((data, filename));
            }
        } else if name.as_deref() == Some("path") {
            // Custom path text field
            let value = field
                .text()
                .await
                .map_err(|e| AppError::Validation(format!("Failed to read path field: {e}")))?;
            custom_path = Some(value);
        }
    }

    match file {
        Some((body, filename)) => Ok((body, filename, custom_path)),
        None => Err(AppError::Validation(
            "No file field found in multipart form".to_string(),
        )),
    }
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
            if let (Some(ref upstream_url), Some(ref proxy)) =
                (&repo.upstream_url, &state.proxy_service)
            {
                let rules = load_routing_rules(&state.db, repo.id).await;
                let fetch_path = routing_rules::apply_routing_rules(&path, &rules)
                    .unwrap_or_else(|| path.clone());

                Ok(proxy_helpers::proxy_fetch_streaming(
                    proxy,
                    repo.id,
                    &key,
                    upstream_url,
                    &fetch_path,
                    "application/octet-stream",
                )
                .await
                .unwrap_or_else(|e| e)
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
    security(("bearer_auth" = [])),
    responses(
        (status = 200, description = "List of virtual repository members (filtered to caller-visible members)", body = VirtualMembersListResponse),
        (status = 400, description = "Repository is not virtual"),
        (status = 401, description = "Authentication required"),
        (status = 404, description = "Repository not found"),
    )
)]
pub async fn list_virtual_members(
    State(state): State<SharedState>,
    Extension(auth): Extension<Option<AuthExtension>>,
    Path(key): Path<String>,
) -> Result<Json<VirtualMembersListResponse>> {
    // Issue #913 (read side): require auth and filter the response to members
    // the caller can actually see. Without this, a token restricted to a single
    // repo (or any authenticated user, prior to this fix) could enumerate the
    // full member set including key, name, and repo_type for repos they have
    // no rights to. Mirrors the write-side authz that add/remove/update apply.
    let auth = require_auth(auth)?;
    let service = RepositoryService::new(state.db.clone());
    let repo = service.get_by_key(&key).await?;

    if repo.repo_type != RepositoryType::Virtual {
        return Err(AppError::Validation(
            "Only virtual repositories have members".to_string(),
        ));
    }

    // Caller must be able to see the virtual parent itself.
    require_repo_access(&auth, repo.id)?;

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

    // Filter to members the caller has access to. Tokens with
    // allowed_repo_ids = None (admins, JWT sessions, unrestricted API tokens)
    // see everything by virtue of `can_access_repo` returning true.
    let members = members
        .into_iter()
        .filter(|row| auth.can_access_repo(row.member_repo_id))
        .map(map_member_row)
        .collect();

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
        (status = 409, description = "Member already exists in virtual repository"),
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
    let member_repo = service.get_by_key(&payload.member_key).await?;
    authorize_virtual_member_mutation(&auth, &virtual_repo, &member_repo, "add")?;

    // Resolve priority inside the service's advisory-locked transaction
    // (ak-jhdq). Computing MAX(priority)+1 here, outside the tx, would let
    // two concurrent POSTs observe the same value and INSERT duplicates.
    service
        .add_virtual_member(virtual_repo.id, member_repo.id, payload.priority)
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
    // Validate repo type BEFORE any access check so a caller without rights
    // on a non-virtual repo gets 400 (validation), not 403 (authz). The 403
    // path would otherwise act as an enumeration oracle: it tells an
    // unauthorized caller the key exists.
    if virtual_repo.repo_type != RepositoryType::Virtual {
        return Err(AppError::Validation(
            "Only virtual repositories have members".to_string(),
        ));
    }
    let member_repo = service.get_by_key(&member_key).await?;
    authorize_virtual_member_mutation(&auth, &virtual_repo, &member_repo, "remove")?;

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

/// Compare the input set of (member_key, member_id) pairs against the
/// `RETURNING` set produced by the bulk UNNEST UPDATE, and surface any
/// missing ids as a 404 listing the affected member keys.
///
/// `returned` is the slice of `member_repo_id`s that the UPDATE actually
/// matched. If its length equals the requested count, every requested
/// (virtual_repo_id, member_repo_id) row was present and updated, and we
/// return Ok(()). Otherwise some member row was deleted between the
/// resolve pass and the UPDATE (TOCTOU). The error message lists the
/// requested keys whose ids did not appear in `returned`, in the order
/// they were submitted, so the caller can retry with a fresh resolve.
///
/// Pure: does not touch the database or any handler state. Lives at
/// module scope so unit tests can exercise the TOCTOU branch without
/// running the full handler.
pub(crate) fn detect_bulk_update_misses<'a, I>(
    virtual_repo_key: &str,
    requested: I,
    returned: &[Uuid],
) -> Result<()>
where
    I: IntoIterator<Item = (&'a str, Uuid)>,
{
    let requested: Vec<(&str, Uuid)> = requested.into_iter().collect();
    if requested.len() == returned.len() {
        return Ok(());
    }
    let returned_set: std::collections::HashSet<Uuid> = returned.iter().copied().collect();
    let missing: Vec<&str> = requested
        .iter()
        .filter(|(_, id)| !returned_set.contains(id))
        .map(|(key, _)| *key)
        .collect();
    Err(AppError::NotFound(format!(
        "members no longer exist on virtual repository {}: {}",
        virtual_repo_key,
        missing.join(", ")
    )))
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
    // Validate repo type BEFORE any access check so a caller without rights
    // on a non-virtual repo gets 400 (validation), not 403 (authz). Avoids
    // the same enumeration oracle remove_virtual_member guards against.
    if virtual_repo.repo_type != RepositoryType::Virtual {
        return Err(AppError::Validation(
            "Only virtual repositories have members".to_string(),
        ));
    }

    // Resolve every member_repo lookup up front. Reads do not need
    // transactional protection and resolving first means a bad key fails
    // fast with 404 before the UPDATE runs.
    //
    // Per-member defensive checks also run during the resolve pass:
    //   - authz: the caller must have rights on each member repo, not just
    //     the virtual parent (issue #913).
    //   - self-membership / cycle detection (issue #915): the current
    //     contract is "update existing rows only" so neither can be
    //     introduced today, but the checks remain so a future contract
    //     extension to upsert missing rows cannot slip a cycle in.
    let mut resolved_member_ids: Vec<Uuid> = Vec::with_capacity(payload.members.len());
    let mut priorities: Vec<i32> = Vec::with_capacity(payload.members.len());
    for member in &payload.members {
        let member_repo = service.get_by_key(&member.member_key).await?;
        authorize_virtual_member_mutation(&auth, &virtual_repo, &member_repo, "update")?;

        if member_repo.id == virtual_repo.id {
            return Err(AppError::Validation(
                "A virtual repository cannot be a member of itself".to_string(),
            ));
        }

        if member_repo.repo_type == RepositoryType::Virtual
            && service
                .would_create_cycle(virtual_repo.id, member_repo.id)
                .await?
        {
            return Err(AppError::Validation(format!(
                "Updating member {} would leave virtual repository {} in a cycle",
                member_repo.key, virtual_repo.key
            )));
        }

        resolved_member_ids.push(member_repo.id);
        priorities.push(member.priority);
    }

    // Single-statement bulk update via UNNEST(uuid[], int4[]). This is atomic
    // by construction in Postgres: the entire statement either succeeds and
    // updates every matching row, or fails and updates none. Removes the
    // need for an explicit transaction, the per-row lock-ordering sort, and
    // the rows_affected loop guard. Concurrent PUTs serialise at the row-
    // lock layer of this single statement and produce a deterministic final
    // state (one wins, the other overwrites it; never a row-level mix).
    //
    // RETURNING gives us the set of member_repo_ids that actually matched
    // the (virtual_repo_id, member_repo_id) predicate. If that set is
    // smaller than the input set, some member row was deleted between the
    // resolve pass and the UPDATE (TOCTOU), and we surface a 404 listing
    // the missing keys so the caller can retry with a fresh resolution.
    let updated: Vec<Uuid> = sqlx::query_scalar(
        r#"
        UPDATE virtual_repo_members
           SET priority = c.priority
          FROM (
            SELECT * FROM UNNEST($2::uuid[], $3::int4[])
                     AS t(member_repo_id, priority)
          ) AS c
         WHERE virtual_repo_members.virtual_repo_id = $1
           AND virtual_repo_members.member_repo_id = c.member_repo_id
        RETURNING virtual_repo_members.member_repo_id
        "#,
    )
    .bind(virtual_repo.id)
    .bind(&resolved_member_ids)
    .bind(&priorities)
    .fetch_all(&state.db)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;

    detect_bulk_update_misses(
        &virtual_repo.key,
        payload
            .members
            .iter()
            .map(|m| m.member_key.as_str())
            .zip(resolved_member_ids.iter().copied()),
        &updated,
    )?;

    // Return updated list. Pass the same auth context so the listing is
    // filtered to caller-visible members consistently.
    list_virtual_members(State(state), Extension(Some(auth)), Path(key)).await
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
        DockerTagResponse,
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
    // expand_maven_secondary_files & build_artifact_response (#1092)
    // -----------------------------------------------------------------------

    fn make_artifact_for_test(path: &str) -> crate::models::artifact::Artifact {
        crate::models::artifact::Artifact {
            id: Uuid::new_v4(),
            repository_id: Uuid::new_v4(),
            path: path.to_string(),
            name: "demo".to_string(),
            version: Some("1.0.0".to_string()),
            size_bytes: 500,
            checksum_sha256: "primary-sha".to_string(),
            checksum_md5: None,
            checksum_sha1: None,
            content_type: "application/java-archive".to_string(),
            storage_key: format!("maven/{}", path),
            is_deleted: false,
            uploaded_by: None,
            quarantine_status: None,
            quarantine_until: None,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        }
    }

    #[test]
    fn test_build_artifact_response_copies_primary_fields() {
        let a = make_artifact_for_test("com/example/demo/1.0.0/demo-1.0.0.jar");
        let resp = build_artifact_response(&a, "maven-hosted", 42);
        assert_eq!(resp.id, a.id);
        assert_eq!(resp.repository_key, "maven-hosted");
        assert_eq!(resp.path, a.path);
        assert_eq!(resp.size_bytes, 500);
        assert_eq!(resp.checksum_sha256, "primary-sha");
        assert_eq!(resp.download_count, 42);
    }

    #[test]
    fn test_expand_maven_secondary_files_emits_each_file() {
        let primary = make_artifact_for_test("com/example/demo/1.0.0/demo-1.0.0.jar");
        let secondary = vec![
            serde_json::json!({
                "path": "com/example/demo/1.0.0/demo-1.0.0.pom",
                "extension": "pom",
                "storageKey": "maven/com/example/demo/1.0.0/demo-1.0.0.pom",
                "sizeBytes": 200,
                "sha256": "pom-sha",
            }),
            serde_json::json!({
                "path": "com/example/demo/1.0.0/demo-1.0.0-sources.jar",
                "extension": "jar",
                "classifier": "sources",
                "storageKey": "maven/com/example/demo/1.0.0/demo-1.0.0-sources.jar",
                "sizeBytes": 800,
                "sha256": "src-sha",
            }),
        ];
        let rows = expand_maven_secondary_files(&primary, "maven-hosted", &secondary);
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].path, "com/example/demo/1.0.0/demo-1.0.0.pom");
        assert_eq!(rows[0].content_type, "text/xml");
        assert_eq!(rows[0].size_bytes, 200);
        assert_eq!(
            rows[1].path,
            "com/example/demo/1.0.0/demo-1.0.0-sources.jar"
        );
        assert_eq!(rows[1].content_type, "application/java-archive");
    }

    #[test]
    fn test_expand_maven_secondary_files_skips_primary_path() {
        // If the primary's own path leaked into the files array, it must
        // not produce a duplicate row.
        let primary = make_artifact_for_test("com/example/demo/1.0.0/demo-1.0.0.jar");
        let secondary = vec![serde_json::json!({
            "path": primary.path,
            "extension": "jar",
            "sizeBytes": 500,
            "sha256": "primary-sha",
        })];
        let rows = expand_maven_secondary_files(&primary, "maven-hosted", &secondary);
        assert!(rows.is_empty());
    }

    #[test]
    fn test_expand_maven_secondary_files_skips_pathless_entries() {
        // A malformed metadata entry without `path` is dropped silently
        // rather than producing a row with an empty path field.
        let primary = make_artifact_for_test("p/demo.jar");
        let secondary = vec![
            serde_json::json!({"extension": "pom", "sizeBytes": 100}),
            serde_json::json!({"path": "p/demo.pom", "extension": "pom"}),
        ];
        let rows = expand_maven_secondary_files(&primary, "k", &secondary);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].path, "p/demo.pom");
    }

    #[test]
    fn test_expand_maven_secondary_files_handles_missing_size_and_sha() {
        let primary = make_artifact_for_test("p/demo.jar");
        let secondary = vec![serde_json::json!({"path": "p/demo.pom", "extension": "pom"})];
        let rows = expand_maven_secondary_files(&primary, "k", &secondary);
        assert_eq!(rows[0].size_bytes, 0);
        assert_eq!(rows[0].checksum_sha256, "");
    }

    // -----------------------------------------------------------------------
    // extract_secondary_files_from_metadata (Maven secondary-file lookup, #1092)
    //
    // Pure helper that parses the `metadata` JSON column for the
    // `files` array used by the per-artifact secondary-files map.
    // Covers each branch of the parsing chain.
    // -----------------------------------------------------------------------

    #[test]
    fn test_extract_secondary_files_returns_files_array_when_present() {
        let meta = serde_json::json!({
            "files": [
                {"path": "p/demo.pom", "extension": "pom"},
                {"path": "p/demo-sources.jar", "extension": "jar"},
            ],
        });
        let out = extract_secondary_files_from_metadata(Some(&meta));
        let files = out.expect("non-empty files");
        assert_eq!(files.len(), 2);
        assert_eq!(files[0]["path"].as_str(), Some("p/demo.pom"));
    }

    #[test]
    fn test_extract_secondary_files_returns_none_when_metadata_missing() {
        // Artifact has no metadata row at all (Option::None).
        assert!(extract_secondary_files_from_metadata(None).is_none());
    }

    #[test]
    fn test_extract_secondary_files_returns_none_when_files_key_absent() {
        // Metadata blob exists but has no `files` key (older POMs that
        // never accumulated a secondary-files list).
        let meta = serde_json::json!({"groupId": "com.example"});
        assert!(extract_secondary_files_from_metadata(Some(&meta)).is_none());
    }

    #[test]
    fn test_extract_secondary_files_returns_none_when_files_is_empty_array() {
        // Explicit empty list -- still nothing to expand.
        let meta = serde_json::json!({"files": []});
        assert!(extract_secondary_files_from_metadata(Some(&meta)).is_none());
    }

    #[test]
    fn test_extract_secondary_files_returns_none_when_files_is_not_an_array() {
        // Defensive against schema drift -- a non-array `files` value
        // is treated as "no secondary files" rather than panicking.
        let meta = serde_json::json!({"files": "not-an-array"});
        assert!(extract_secondary_files_from_metadata(Some(&meta)).is_none());
    }

    // -----------------------------------------------------------------------
    // content_type_for_maven_extension (Maven secondary-file listing, #1092)
    // -----------------------------------------------------------------------

    #[test]
    fn test_content_type_for_maven_extension_pom() {
        assert_eq!(content_type_for_maven_extension("pom"), "text/xml");
    }

    #[test]
    fn test_content_type_for_maven_extension_jar() {
        assert_eq!(
            content_type_for_maven_extension("jar"),
            "application/java-archive"
        );
        assert_eq!(
            content_type_for_maven_extension("war"),
            "application/java-archive"
        );
        assert_eq!(
            content_type_for_maven_extension("aar"),
            "application/java-archive"
        );
    }

    #[test]
    fn test_content_type_for_maven_extension_unknown_falls_back() {
        assert_eq!(
            content_type_for_maven_extension("xyz"),
            "application/octet-stream"
        );
        assert_eq!(
            content_type_for_maven_extension(""),
            "application/octet-stream"
        );
    }

    #[test]
    fn test_content_type_for_maven_extension_checksum_files() {
        assert_eq!(content_type_for_maven_extension("md5"), "text/plain");
        assert_eq!(content_type_for_maven_extension("sha1"), "text/plain");
        assert_eq!(content_type_for_maven_extension("sha256"), "text/plain");
        assert_eq!(content_type_for_maven_extension("sha512"), "text/plain");
    }

    #[test]
    fn test_content_type_for_maven_extension_signatures() {
        assert_eq!(
            content_type_for_maven_extension("asc"),
            "application/pgp-signature"
        );
        assert_eq!(
            content_type_for_maven_extension("sig"),
            "application/pgp-signature"
        );
    }

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

    #[test]
    fn test_list_artifacts_query_group_by_docker_tag() {
        let json = r#"{"group_by": "docker_tag"}"#;
        let query: ListArtifactsQuery = serde_json::from_str(json).unwrap();
        assert_eq!(query.group_by.as_deref(), Some("docker_tag"));
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
            docker_tags: None,
        };
        let json = serde_json::to_string(&resp).unwrap();
        // components and docker_tags fields should be omitted when None
        assert!(!json.contains("\"components\""));
        assert!(!json.contains("\"docker_tags\""));
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
            docker_tags: None,
        };
        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains("\"components\":["));
        assert!(json.contains("\"group_id\":\"org.example\""));
    }

    #[test]
    fn test_artifact_list_response_with_docker_tags() {
        let tag = DockerTagResponse {
            id: Uuid::new_v4(),
            repository_key: "docker-hub".to_string(),
            image: "library/postgres".to_string(),
            tag: "16-alpine".to_string(),
            manifest_digest: "sha256:abcdef".to_string(),
            total_size_bytes: 250_000_000,
            layer_count: 8,
            is_index: false,
            last_pushed_at: chrono::Utc::now(),
            scan_status: Some("completed".to_string()),
        };
        let resp = ArtifactListResponse {
            items: vec![],
            pagination: Pagination {
                page: 1,
                per_page: 20,
                total: 1,
                total_pages: 1,
            },
            components: None,
            docker_tags: Some(vec![tag]),
        };
        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains("\"docker_tags\":["));
        assert!(json.contains("\"image\":\"library/postgres\""));
        assert!(json.contains("\"tag\":\"16-alpine\""));
        assert!(json.contains("\"total_size_bytes\":250000000"));
        assert!(json.contains("\"layer_count\":8"));
        assert!(json.contains("\"is_index\":false"));
        assert!(json.contains("\"scan_status\":\"completed\""));
        assert!(!json.contains("\"components\""));
    }

    // -----------------------------------------------------------------------
    // is_docker_index_content_type
    // -----------------------------------------------------------------------

    #[test]
    fn test_is_docker_index_content_type_recognizes_oci_index() {
        assert!(is_docker_index_content_type(
            "application/vnd.oci.image.index.v1+json"
        ));
    }

    #[test]
    fn test_is_docker_index_content_type_recognizes_docker_manifest_list() {
        assert!(is_docker_index_content_type(
            "application/vnd.docker.distribution.manifest.list.v2+json"
        ));
    }

    #[test]
    fn test_is_docker_index_content_type_strips_charset() {
        assert!(is_docker_index_content_type(
            "application/vnd.oci.image.index.v1+json; charset=utf-8"
        ));
    }

    #[test]
    fn test_is_docker_index_content_type_rejects_single_manifest() {
        assert!(!is_docker_index_content_type(
            "application/vnd.oci.image.manifest.v1+json"
        ));
        assert!(!is_docker_index_content_type(
            "application/vnd.docker.distribution.manifest.v2+json"
        ));
    }

    #[test]
    fn test_is_docker_index_content_type_rejects_empty() {
        assert!(!is_docker_index_content_type(""));
    }

    // -----------------------------------------------------------------------
    // build_docker_tag_response
    // -----------------------------------------------------------------------

    fn docker_tag_row(content_type: &str, manifest_size: i64) -> DockerTagRow {
        DockerTagRow {
            artifact_id: Uuid::new_v4(),
            image: "library/postgres".to_string(),
            tag: "16-alpine".to_string(),
            manifest_digest: "sha256:parentdigest".to_string(),
            manifest_content_type: content_type.to_string(),
            manifest_size_bytes: manifest_size,
            last_pushed_at: chrono::Utc::now(),
            scan_status: None,
        }
    }

    #[test]
    fn test_build_docker_tag_response_single_arch_uses_manifest_size() {
        // For a regular (single-arch) manifest, size_bytes on the artifact
        // row is already config_size + sum(layers.size). No child
        // expansion should happen.
        let row = docker_tag_row("application/vnd.oci.image.manifest.v1+json", 12_345_678);
        let children = std::collections::HashMap::new();

        let resp = build_docker_tag_response(row, "docker-hub", &children);

        assert_eq!(resp.total_size_bytes, 12_345_678);
        assert!(!resp.is_index);
        assert_eq!(resp.image, "library/postgres");
        assert_eq!(resp.tag, "16-alpine");
        assert_eq!(resp.repository_key, "docker-hub");
    }

    #[test]
    fn test_build_docker_tag_response_index_sums_child_sizes() {
        // For an image index, the manifest itself is tiny (the index
        // document), but the children carry the real layer cost. The
        // total should fold in the precomputed child total.
        let row = docker_tag_row(
            "application/vnd.docker.distribution.manifest.list.v2+json",
            2_500, // tiny index document
        );
        let mut children = std::collections::HashMap::new();
        children.insert("sha256:parentdigest".to_string(), 500_000_000); // 500 MB across arches

        let resp = build_docker_tag_response(row, "docker-hub", &children);

        assert_eq!(resp.total_size_bytes, 2_500 + 500_000_000);
        assert!(resp.is_index);
    }

    #[test]
    fn test_build_docker_tag_response_index_without_children_falls_back_to_manifest_only() {
        // Defensive: if the oci_manifest_refs backfill has not yet caught
        // up for an older index, the children map is empty. The response
        // should still surface the manifest body size rather than 0 so
        // the UI does not show a meaningless number.
        let row = docker_tag_row("application/vnd.oci.image.index.v1+json", 1_234);
        let children = std::collections::HashMap::new();

        let resp = build_docker_tag_response(row, "docker-hub", &children);

        assert_eq!(resp.total_size_bytes, 1_234);
        assert!(resp.is_index);
    }

    #[test]
    fn test_build_docker_tag_response_preserves_scan_status() {
        let mut row = docker_tag_row("application/vnd.oci.image.manifest.v1+json", 100);
        row.scan_status = Some("completed".to_string());
        let children = std::collections::HashMap::new();

        let resp = build_docker_tag_response(row, "docker-hub", &children);

        assert_eq!(resp.scan_status.as_deref(), Some("completed"));
    }

    #[test]
    fn test_build_docker_tag_response_saturating_add_handles_overflow() {
        // Pathological case: both sizes near i64::MAX should saturate
        // instead of wrapping to a negative number that the UI would
        // render as a nonsense size.
        let row = docker_tag_row("application/vnd.oci.image.index.v1+json", i64::MAX - 100);
        let mut children = std::collections::HashMap::new();
        children.insert("sha256:parentdigest".to_string(), 1_000);

        let resp = build_docker_tag_response(row, "docker-hub", &children);

        assert_eq!(resp.total_size_bytes, i64::MAX);
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

    // -------------------------------------------------------------------
    // detect_bulk_update_misses (issue #912 TOCTOU detection)
    //
    // The bulk UPDATE ... FROM UNNEST(...) RETURNING produces the set of
    // member_repo_ids that actually matched. If a member row was deleted
    // between the resolve pass and the UPDATE, the RETURNING set is
    // smaller than the input. The handler converts that gap into a 404
    // listing the requested keys that are no longer present. The
    // detection logic is a pure function over (requested, returned)
    // pairs so the entire branch is unit-testable without a database.
    // -------------------------------------------------------------------

    #[test]
    fn test_detect_bulk_update_misses_all_present_returns_ok() {
        // Happy path: every requested id is in the RETURNING set, so the
        // branch returns Ok(()) and the handler proceeds to list members.
        let id_a = Uuid::new_v4();
        let id_b = Uuid::new_v4();
        let requested = [("repo-a", id_a), ("repo-b", id_b)];
        let returned = vec![id_b, id_a];
        let result = detect_bulk_update_misses("v-repo", requested.iter().copied(), &returned);
        assert!(result.is_ok(), "all-present must return Ok, got {result:?}");
    }

    #[test]
    fn test_detect_bulk_update_misses_empty_inputs_returns_ok() {
        // Edge case: empty payload and empty RETURNING. The handler
        // does not currently call the helper with an empty input but
        // the contract should still be Ok(()) so a future caller that
        // passes-through an empty request does not 404 spuriously.
        let result = detect_bulk_update_misses("v-repo", std::iter::empty::<(&str, Uuid)>(), &[]);
        assert!(result.is_ok(), "empty input must return Ok, got {result:?}");
    }

    #[test]
    fn test_detect_bulk_update_misses_single_missing_returns_404() {
        // The most common TOCTOU shape: one member was deleted between
        // resolve and UPDATE. Helper must surface that one key in a 404.
        let id_a = Uuid::new_v4();
        let id_b = Uuid::new_v4();
        let requested = [("repo-a", id_a), ("repo-b", id_b)];
        // Only id_a came back. id_b was deleted.
        let returned = vec![id_a];
        let err = detect_bulk_update_misses("v-repo", requested.iter().copied(), &returned)
            .expect_err("single missing must be Err");
        match err {
            AppError::NotFound(msg) => {
                assert!(
                    msg.contains("repo-b"),
                    "missing key must appear in error message, got: {msg}"
                );
                assert!(
                    !msg.contains("repo-a"),
                    "present key must not appear in error message, got: {msg}"
                );
                assert!(
                    msg.contains("v-repo"),
                    "virtual repo key must appear in error message, got: {msg}"
                );
            }
            other => panic!("expected NotFound, got {other:?}"),
        }
    }

    #[test]
    fn test_detect_bulk_update_misses_all_missing_returns_404_with_every_key() {
        // Worst case: the entire member set was deleted while the
        // PUT was in flight. Every requested key must appear in the 404.
        let id_a = Uuid::new_v4();
        let id_b = Uuid::new_v4();
        let id_c = Uuid::new_v4();
        let requested = [("a", id_a), ("b", id_b), ("c", id_c)];
        let returned: Vec<Uuid> = vec![];
        let err = detect_bulk_update_misses("v-repo", requested.iter().copied(), &returned)
            .expect_err("all-missing must be Err");
        match err {
            AppError::NotFound(msg) => {
                for key in ["a", "b", "c"] {
                    assert!(
                        msg.contains(key),
                        "missing key '{key}' must appear in error, got: {msg}"
                    );
                }
            }
            other => panic!("expected NotFound, got {other:?}"),
        }
    }

    #[test]
    fn test_detect_bulk_update_misses_preserves_submission_order() {
        // The 404 message lists missing keys in the order the caller
        // submitted them, NOT in RETURNING order or set-iteration order.
        // This is load-bearing: callers diff the missing list against
        // their own submission order to figure out which retry to make.
        let id1 = Uuid::new_v4();
        let id2 = Uuid::new_v4();
        let id3 = Uuid::new_v4();
        let id4 = Uuid::new_v4();
        // Submit in order [first, second, third, fourth]; second and
        // fourth get deleted between resolve and UPDATE.
        let requested = [
            ("first", id1),
            ("second", id2),
            ("third", id3),
            ("fourth", id4),
        ];
        let returned = vec![id1, id3];
        let err = detect_bulk_update_misses("v-repo", requested.iter().copied(), &returned)
            .expect_err("partial-missing must be Err");
        match err {
            AppError::NotFound(msg) => {
                let second_pos = msg.find("second").expect("'second' must appear");
                let fourth_pos = msg.find("fourth").expect("'fourth' must appear");
                assert!(
                    second_pos < fourth_pos,
                    "missing keys must be listed in submission order; got: {msg}"
                );
            }
            other => panic!("expected NotFound, got {other:?}"),
        }
    }

    // Note: the original `test_update_virtual_members_resolution_preserves_order`
    // unit test was removed during code review. It exercised
    // `Vec::iter().map().collect()` and `serde_json::from_str`, neither of
    // which touches the single-statement `UPDATE ... FROM UNNEST(...)`
    // bulk update or the RETURNING-set comparison that fixes the #912 bug.
    // A real DB-backed regression test (including a concurrent-PUT race)
    // lives in `backend/tests/virtual_members_atomicity_test.rs`.

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

    /// Structural guard for the defensive cycle / self-membership check
    /// inside `update_virtual_members` (issue #915 second-pass review).
    ///
    /// The handler today only updates priorities of existing rows, so it
    /// cannot insert a new edge and therefore cannot introduce a cycle.
    /// The defensive check is preserved against a future contract change
    /// (e.g. upsert semantics). Because no integration harness here can
    /// observe the no-op behaviour, this test asserts on the *source
    /// text* of the handler so the protection cannot be silently dropped
    /// in a refactor without the test failing.
    ///
    /// Required substrings are constructed via `format!` so this test's
    /// own source text does not accidentally satisfy the search.
    #[test]
    fn test_update_virtual_members_defensive_check_present() {
        let source = include_str!("repositories.rs");

        // Locate the `update_virtual_members` handler body.
        let handler_marker = format!("pub async fn {}{}(", "update_virtual", "_members");
        let handler_start = source
            .find(&handler_marker)
            .expect("update_virtual_members handler must exist");
        // Slice from the handler signature forward; bound at the next
        // top-level `pub` item or end of file.
        let after_sig = &source[handler_start..];
        let handler_end = after_sig[1..]
            .find("\npub ")
            .map(|i| i + 1)
            .unwrap_or(after_sig.len());
        let handler_body = &after_sig[..handler_end];

        // The handler's body must still call the cycle helper.
        let cycle_call = format!("{}_{}_{}", "would", "create", "cycle");
        assert!(
            handler_body.contains(&cycle_call),
            "update_virtual_members must keep its defensive cycle check"
        );

        // ...and must still reject self-membership before updating.
        // The exact comparison is `member_repo.id == virtual_repo.id`.
        let self_check = format!("{}.id == {}.id", "member_repo", "virtual_repo");
        assert!(
            handler_body.contains(&self_check),
            "update_virtual_members must keep its self-membership equality check"
        );

        // ...and the validation message string must remain.
        let cannot_be_member_msg = format!(
            "{} {} {} {} {}",
            "A virtual repository", "cannot be", "a member", "of", "itself"
        );
        assert!(
            handler_body.contains(&cannot_be_member_msg),
            "self-membership rejection message must remain unchanged"
        );
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
    // Issue #913: virtual member endpoints must check access on BOTH the
    // virtual parent and each member repo before mutating membership. These
    // tests now drive the production `authorize_virtual_member_mutation`
    // helper directly (no test-only re-implementation), so a refactor that
    // changes the auth model is forced through the same code path.
    // -----------------------------------------------------------------------

    /// Build a minimal `Repository` value with a caller-chosen id, suitable
    /// for passing to `authorize_virtual_member_mutation`.
    fn make_repo_with_id(id: Uuid, key: &str) -> crate::models::repository::Repository {
        use crate::models::repository::{ReplicationPriority, Repository};
        let now = chrono::Utc::now();
        Repository {
            id,
            key: key.to_string(),
            name: key.to_string(),
            description: None,
            format: RepositoryFormat::Pypi,
            storage_backend: "filesystem".to_string(),
            repo_type: RepositoryType::Local,
            storage_path: format!("/data/{}", key),
            upstream_url: None,
            is_public: false,
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
    fn test_virtual_member_authz_access_to_parent_only_is_denied() {
        // Caller has access to V but not M -> 403.
        let virtual_id = Uuid::new_v4();
        let member_id = Uuid::new_v4();
        let v = make_repo_with_id(virtual_id, "v");
        let m = make_repo_with_id(member_id, "m");
        let ext = make_auth_ext(Some(vec![virtual_id]));
        let result = authorize_virtual_member_mutation(&ext, &v, &m, "add");
        assert!(
            result.is_err(),
            "caller with access to parent only must be denied"
        );
        match result.unwrap_err() {
            AppError::Authorization(msg) => {
                assert!(msg.contains("does not have access"))
            }
            other => panic!("Expected Authorization error, got: {:?}", other),
        }
    }

    #[test]
    fn test_virtual_member_authz_access_to_member_only_is_denied() {
        // Caller has access to M but not V -> 403.
        let virtual_id = Uuid::new_v4();
        let member_id = Uuid::new_v4();
        let v = make_repo_with_id(virtual_id, "v");
        let m = make_repo_with_id(member_id, "m");
        let ext = make_auth_ext(Some(vec![member_id]));
        let result = authorize_virtual_member_mutation(&ext, &v, &m, "remove");
        assert!(
            result.is_err(),
            "caller with access to member only must be denied"
        );
    }

    #[test]
    fn test_virtual_member_authz_access_to_both_is_allowed() {
        // Caller has access to both V and M -> ok.
        let virtual_id = Uuid::new_v4();
        let member_id = Uuid::new_v4();
        let v = make_repo_with_id(virtual_id, "v");
        let m = make_repo_with_id(member_id, "m");
        let ext = make_auth_ext(Some(vec![virtual_id, member_id]));
        assert!(authorize_virtual_member_mutation(&ext, &v, &m, "update").is_ok());
    }

    #[test]
    fn test_virtual_member_authz_unrestricted_token_bypass() {
        // Tokens with allowed_repo_ids = None (admins, JWT sessions,
        // unrestricted API tokens) bypass the per-member check.
        let virtual_id = Uuid::new_v4();
        let member_id = Uuid::new_v4();
        let v = make_repo_with_id(virtual_id, "v");
        let m = make_repo_with_id(member_id, "m");
        let ext = make_auth_ext(None);
        assert!(authorize_virtual_member_mutation(&ext, &v, &m, "add").is_ok());
    }

    #[test]
    fn test_virtual_member_authz_no_access_to_either_is_denied() {
        // Caller has access to neither V nor M -> 403 (failing on parent first).
        let virtual_id = Uuid::new_v4();
        let member_id = Uuid::new_v4();
        let other = Uuid::new_v4();
        let v = make_repo_with_id(virtual_id, "v");
        let m = make_repo_with_id(member_id, "m");
        let ext = make_auth_ext(Some(vec![other]));
        assert!(authorize_virtual_member_mutation(&ext, &v, &m, "add").is_err());
    }

    /// Issue #913 binding test:
    ///
    /// The unit tests above call the production helper directly, but they
    /// can't catch a handler that simply forgets to call it. Read the
    /// handler source and assert each mutating handler invokes
    /// `authorize_virtual_member_mutation`. The handlers require a full
    /// `SharedState` (postgres pool, storage) which the rest of this mod
    /// deliberately avoids, so a string-grep is the cheapest pin.
    #[test]
    fn test_virtual_member_handlers_call_authz_helper() {
        let source = include_str!("repositories.rs");

        for handler in [
            "add_virtual_member",
            "remove_virtual_member",
            "update_virtual_members",
        ] {
            let marker = format!("pub async fn {}(", handler);
            let start = source
                .find(&marker)
                .unwrap_or_else(|| panic!("handler `{}` not found in repositories.rs", handler));
            let rest = &source[start + marker.len()..];
            let end = rest
                .find("\npub async fn ")
                .or_else(|| rest.find("\npub fn "))
                .unwrap_or(rest.len());
            let body = &rest[..end];

            assert!(
                body.contains("authorize_virtual_member_mutation("),
                "handler `{}` does not call `authorize_virtual_member_mutation` \
                 (issue #913). If you intentionally restructured the authz model, \
                 update this test to match.",
                handler
            );
        }
    }

    /// Issue #913 (validation order):
    ///
    /// `remove_virtual_member` must validate `repo_type == Virtual` BEFORE
    /// any `require_repo_access` / `authorize_virtual_member_mutation` call,
    /// otherwise a caller without rights to a non-virtual repo gets 403
    /// instead of 400 — a small enumeration oracle. Same goes for
    /// `update_virtual_members`. The handlers need DB state to invoke
    /// directly, so we string-grep the source for ordering.
    #[test]
    fn test_remove_and_update_validate_repo_type_before_authz() {
        let source = include_str!("repositories.rs");

        for handler in ["remove_virtual_member", "update_virtual_members"] {
            let marker = format!("pub async fn {}(", handler);
            let start = source
                .find(&marker)
                .unwrap_or_else(|| panic!("handler `{}` not found", handler));
            let rest = &source[start + marker.len()..];
            let end = rest
                .find("\npub async fn ")
                .or_else(|| rest.find("\npub fn "))
                .unwrap_or(rest.len());
            let body = &rest[..end];

            let validation_pos = body
                .find("repo_type != RepositoryType::Virtual")
                .unwrap_or_else(|| panic!("handler `{}` is missing repo_type validation", handler));
            let access_pos = body
                .find("require_repo_access(&auth")
                .or_else(|| body.find("authorize_virtual_member_mutation("))
                .unwrap_or_else(|| panic!("handler `{}` is missing access check", handler));

            assert!(
                validation_pos < access_pos,
                "handler `{}` runs access check before repo_type validation \
                 (creates 403-vs-400 enumeration oracle, issue #913)",
                handler
            );
        }
    }

    /// Issue #913 (read side): `list_virtual_members` must take an
    /// `Extension<Option<AuthExtension>>` and filter the response to
    /// caller-visible members. Without this, anyone with network access can
    /// enumerate the full member set including key, name, repo_type. String-
    /// grep because the handler needs a real DB to run.
    #[test]
    fn test_list_virtual_members_requires_auth_and_filters() {
        let source = include_str!("repositories.rs");

        let marker = "pub async fn list_virtual_members(";
        let start = source
            .find(marker)
            .expect("list_virtual_members handler not found");
        let rest = &source[start + marker.len()..];
        let end = rest
            .find("\npub async fn ")
            .or_else(|| rest.find("\npub fn "))
            .or_else(|| rest.find("\nfn "))
            .unwrap_or(rest.len());
        // The signature is part of `rest` before the body proper; capture
        // both signature and body together.
        let sig_and_body = &rest[..end];

        assert!(
            sig_and_body.contains("Extension(auth): Extension<Option<AuthExtension>>"),
            "list_virtual_members must take Extension<Option<AuthExtension>> \
             so the response can be filtered (issue #913)"
        );
        assert!(
            sig_and_body.contains("require_auth(auth)"),
            "list_virtual_members must call require_auth (issue #913)"
        );
        assert!(
            sig_and_body.contains("auth.can_access_repo(row.member_repo_id)"),
            "list_virtual_members must filter the response by \
             can_access_repo(member_repo_id) (issue #913)"
        );
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
    // resolve_cache_ttl (issue #911: GET /cache-ttl default must match proxy)
    // -----------------------------------------------------------------------

    #[test]
    fn test_resolve_cache_ttl_falls_back_to_proxy_default_when_unset() {
        // When no row exists in repository_config, the GET endpoint must
        // report the same default the proxy actually applies (24h, not 1h).
        assert_eq!(resolve_cache_ttl(None), DEFAULT_CACHE_TTL_SECS);
        assert_eq!(resolve_cache_ttl(None), 86400);
    }

    #[test]
    fn test_resolve_cache_ttl_falls_back_when_value_unparseable() {
        assert_eq!(
            resolve_cache_ttl(Some("not-a-number".to_string())),
            DEFAULT_CACHE_TTL_SECS,
        );
    }

    #[test]
    fn test_resolve_cache_ttl_returns_stored_value() {
        assert_eq!(resolve_cache_ttl(Some("7200".to_string())), 7200);
    }

    #[test]
    fn test_resolve_cache_ttl_returns_stored_zero() {
        // resolve_cache_ttl is only responsible for parsing; range validation
        // happens on the SET path via validate_cache_ttl.
        assert_eq!(resolve_cache_ttl(Some("0".to_string())), 0);
    }

    /// Structural guard for issue #911. The unit tests above only cover the
    /// `resolve_cache_ttl` helper. They will still pass if a future change
    /// reverts the `get_cache_ttl` handler call site to a hardcoded literal
    /// like the old 1-hour default, which is exactly the regression we are
    /// trying to prevent. Asserting on the source text of this file at
    /// compile time is ugly but pins the call site without requiring a
    /// Postgres fixture.
    ///
    /// In-process handler tests in this crate would require a live PgPool
    /// (no `#[sqlx::test]` pattern is used in this file), so we use a
    /// source-grep test as the lightweight regression contract instead.
    ///
    /// The forbidden substrings are constructed at runtime so this test's
    /// own body does not contain them and trip the check on itself.
    #[test]
    fn test_get_cache_ttl_handler_uses_resolve_helper_not_hardcoded_literal() {
        let src = include_str!("repositories.rs");

        // Build forbidden patterns at runtime so they do not appear as
        // literal substrings in this source file.
        let unwrap_prefix = ["unwrap", "_or"].concat(); // "unwrap_or"
        let bad_old_default = format!("{}({})", unwrap_prefix, 3600);
        let bad_inline_default = format!("{}({})", unwrap_prefix, 86400);

        assert!(
            !src.contains(&bad_old_default),
            "regression of issue #911: the old 1-hour fallback literal must \
             not reappear in this file; the get_cache_ttl handler must \
             delegate to resolve_cache_ttl(...) so the default stays aligned \
             with proxy_service::DEFAULT_CACHE_TTL_SECS",
        );
        assert!(
            !src.contains(&bad_inline_default),
            "do not hardcode the cache TTL default literal; call \
             resolve_cache_ttl(...) which references DEFAULT_CACHE_TTL_SECS",
        );

        // Anchor: the handler body must actually call the helper.
        // Spelled in three pieces so this assertion's own text does not
        // satisfy the search.
        let helper_call = format!("{}{}{}", "resolve_cache_ttl(result.map(", "|(v,)| v", "))",);
        assert!(
            src.contains(&helper_call),
            "get_cache_ttl handler must call the resolve_cache_ttl helper to \
             derive the effective TTL; do not inline the fallback in the \
             handler",
        );
    }

    // -----------------------------------------------------------------------
    // Cache TTL DTO serialization / deserialization
    // -----------------------------------------------------------------------

    #[test]
    fn test_set_cache_ttl_request_deserialization() {
        let json = r#"{"cache_ttl_seconds": 86400}"#;
        let req: SetCacheTtlRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.cache_ttl_seconds, 86400);
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

    // -----------------------------------------------------------------------
    // Permission check logic (Phase 3: admin-level endpoint checks)
    // -----------------------------------------------------------------------

    /// Simulates the permission gate used in create_repository and other
    /// system-level operations. Admins bypass the check entirely; non-admins
    /// must hold the "admin" action on the target.
    fn check_permission_gate(
        is_admin: bool,
        granted_actions: &[&str],
        required_action: &str,
    ) -> bool {
        if is_admin {
            return true;
        }
        granted_actions.contains(&required_action)
    }

    #[test]
    fn test_permission_gate_admin_always_passes() {
        assert!(check_permission_gate(true, &[], "admin"));
    }

    #[test]
    fn test_permission_gate_admin_passes_without_explicit_grant() {
        // Admin users bypass regardless of whether they have a rule
        assert!(check_permission_gate(true, &["read"], "admin"));
    }

    #[test]
    fn test_permission_gate_non_admin_with_admin_grant_passes() {
        assert!(check_permission_gate(false, &["admin"], "admin"));
    }

    #[test]
    fn test_permission_gate_non_admin_with_multiple_grants_passes() {
        assert!(check_permission_gate(
            false,
            &["read", "write", "admin"],
            "admin"
        ));
    }

    #[test]
    fn test_permission_gate_non_admin_without_admin_grant_denied() {
        assert!(!check_permission_gate(false, &["read", "write"], "admin"));
    }

    #[test]
    fn test_permission_gate_non_admin_empty_grants_denied() {
        assert!(!check_permission_gate(false, &[], "admin"));
    }

    #[test]
    fn test_system_sentinel_is_nil_uuid() {
        // create_repository uses SYSTEM_SENTINEL_ID as the system sentinel target_id
        assert_eq!(
            SYSTEM_SENTINEL_ID.to_string(),
            "00000000-0000-0000-0000-000000000000"
        );
        assert_eq!(SYSTEM_TARGET_TYPE, "system");
    }

    #[test]
    fn test_create_repo_permission_check_admin_bypasses() {
        let auth = make_auth(true);
        // Admin user should always pass the gate
        assert!(check_permission_gate(auth.is_admin, &[], "admin"));
    }

    #[test]
    fn test_create_repo_permission_check_non_admin_with_grant() {
        let auth = make_auth(false);
        // Non-admin with system-level admin grant should pass
        assert!(check_permission_gate(auth.is_admin, &["admin"], "admin"));
    }

    #[test]
    fn test_create_repo_permission_check_non_admin_without_grant() {
        let auth = make_auth(false);
        // Non-admin without grant should be denied
        assert!(!check_permission_gate(auth.is_admin, &[], "admin"));
    }

    #[test]
    fn test_update_repo_permission_check_requires_repo_admin() {
        let auth = make_auth(false);
        // Non-admin needs "admin" on the specific repository
        assert!(check_permission_gate(auth.is_admin, &["admin"], "admin"));
        assert!(!check_permission_gate(
            auth.is_admin,
            &["read", "write"],
            "admin"
        ));
    }

    #[test]
    fn test_delete_repo_permission_check_admin_bypasses() {
        let auth = make_auth(true);
        assert!(check_permission_gate(auth.is_admin, &[], "admin"));
    }

    #[test]
    fn test_delete_repo_permission_check_non_admin_without_grant() {
        let auth = make_auth(false);
        assert!(!check_permission_gate(auth.is_admin, &[], "admin"));
    }

    // -----------------------------------------------------------------------
    // Guest-access coercion (issue #850)
    // -----------------------------------------------------------------------

    #[test]
    fn coerce_create_passthrough_when_guests_enabled() {
        // When guests are enabled (the default), the requested value is
        // returned unchanged regardless of whether it is true or false.
        assert_eq!(coerce_is_public_for_create(true, true), (true, false));
        assert_eq!(coerce_is_public_for_create(false, true), (false, false));
    }

    #[test]
    fn coerce_create_forces_private_when_guests_disabled() {
        assert_eq!(coerce_is_public_for_create(true, false), (false, true));
    }

    #[test]
    fn coerce_create_already_private_is_noop_when_guests_disabled() {
        // No coercion needed when the request is already private; the flag
        // returned in `.1` must be `false` so the caller does not log a
        // misleading warning.
        assert_eq!(coerce_is_public_for_create(false, false), (false, false));
    }

    #[test]
    fn coerce_update_passthrough_when_guests_enabled() {
        assert_eq!(
            coerce_is_public_for_update(Some(true), true),
            (Some(true), false)
        );
        assert_eq!(
            coerce_is_public_for_update(Some(false), true),
            (Some(false), false)
        );
        assert_eq!(coerce_is_public_for_update(None, true), (None, false));
    }

    #[test]
    fn coerce_update_forces_private_when_guests_disabled_and_some_true() {
        assert_eq!(
            coerce_is_public_for_update(Some(true), false),
            (Some(false), true)
        );
    }

    #[test]
    fn coerce_update_some_false_is_noop_when_guests_disabled() {
        assert_eq!(
            coerce_is_public_for_update(Some(false), false),
            (Some(false), false)
        );
    }

    #[test]
    fn coerce_update_none_is_noop_when_guests_disabled() {
        // An update payload that does not touch the visibility field must
        // remain `None` so the service layer leaves the existing value
        // untouched. We never silently flip an existing public repo to
        // private on unrelated updates.
        assert_eq!(coerce_is_public_for_update(None, false), (None, false));
    }

    // -----------------------------------------------------------------------
    // is_cache_ttl_configurable (#917)
    // -----------------------------------------------------------------------

    #[test]
    fn cache_ttl_configurable_for_remote() {
        assert!(is_cache_ttl_configurable(&RepositoryType::Remote).is_ok());
    }

    #[test]
    fn cache_ttl_rejected_for_local() {
        let err = is_cache_ttl_configurable(&RepositoryType::Local).unwrap_err();
        match err {
            AppError::Validation(msg) => assert!(msg.contains("remote (proxy)")),
            other => panic!("Expected Validation error, got: {:?}", other),
        }
    }

    #[test]
    fn cache_ttl_rejected_for_virtual() {
        let err = is_cache_ttl_configurable(&RepositoryType::Virtual).unwrap_err();
        assert!(matches!(err, AppError::Validation(_)));
    }

    #[test]
    fn cache_ttl_rejected_for_staging() {
        let err = is_cache_ttl_configurable(&RepositoryType::Staging).unwrap_err();
        assert!(matches!(err, AppError::Validation(_)));
    }

    /// Structural test guarding against accidental regressions: the
    /// `set_cache_ttl` handler MUST call `is_cache_ttl_configurable` so a
    /// `cache_ttl_secs` row is never written for Local, Virtual or Staging
    /// repositories (issue #917). The expected substrings are built at
    /// runtime from format! so this test body itself does not satisfy the
    /// search.
    #[test]
    fn set_cache_ttl_contains_remote_only_guard() {
        let source = include_str!("repositories.rs");

        // 1. The helper itself must compare against Remote.
        let helper_check = format!("repo_type {} &RepositoryType::Remote", "!=");
        assert!(
            source.contains(&helper_check),
            "is_cache_ttl_configurable must compare against RepositoryType::Remote; missing `{}` (see #917)",
            helper_check,
        );

        // 2. The handler must invoke the helper on the loaded repo.
        let handler_call = format!("is_cache_ttl_configurable({}repo.repo_type)", "&");
        assert!(
            source.contains(&handler_call),
            "set_cache_ttl must call `{}` to reject non-Remote repos (see #917)",
            handler_call,
        );
    }

    /// Ordering regression test (#917 / PR #946 review): inside the
    /// `set_cache_ttl` handler body, the type-check (`is_cache_ttl_configurable`)
    /// MUST run before the range check (`validate_cache_ttl`). If the order is
    /// swapped, a Local repo with a bad TTL value would surface "must be
    /// between 1 and 2592000" instead of the intended "remote (proxy)" type
    /// error, masking the rejection contract this PR adds. Both call markers
    /// are built via format! at runtime so this test body itself does not
    /// satisfy the search.
    #[test]
    fn set_cache_ttl_type_check_runs_before_range_check() {
        let source = include_str!("repositories.rs");

        // Isolate the set_cache_ttl function body so we don't accidentally
        // pick up the validate_cache_ttl definition (which sits earlier in
        // the file) or unrelated handlers.
        let signature = format!("pub async fn {}(", "set_cache_ttl");
        let start = source
            .find(&signature)
            .unwrap_or_else(|| panic!("could not locate `{}` in repositories.rs", signature));

        // The next handler immediately after set_cache_ttl is get_cache_ttl;
        // bound the search there so we only inspect set_cache_ttl's body.
        let next_signature = format!("pub async fn {}(", "get_cache_ttl");
        let end = source[start..]
            .find(&next_signature)
            .map(|offset| start + offset)
            .unwrap_or(source.len());
        let body = &source[start..end];

        let type_check_call = format!("{}(&repo.repo_type)", "is_cache_ttl_configurable");
        let range_check_call = format!("{}(payload.cache_ttl_seconds)", "validate_cache_ttl");

        let type_idx = body.find(&type_check_call).unwrap_or_else(|| {
            panic!(
                "set_cache_ttl must call `{}`; not found in handler body (see #917)",
                type_check_call,
            )
        });
        let range_idx = body.find(&range_check_call).unwrap_or_else(|| {
            panic!(
                "set_cache_ttl must call `{}`; not found in handler body (see #917)",
                range_check_call,
            )
        });

        assert!(
            type_idx < range_idx,
            "type check `{}` must run BEFORE range check `{}` in set_cache_ttl, otherwise a Local repo with a bad TTL surfaces the range error and masks the type-rejection contract (#917). type_idx={}, range_idx={}",
            type_check_call,
            range_check_call,
            type_idx,
            range_idx,
        );
    }

    // -----------------------------------------------------------------------
    // Virtual repo member validation (#1279)
    // -----------------------------------------------------------------------

    fn member(repo_key: &str, priority: i32) -> CreateVirtualMemberInput {
        CreateVirtualMemberInput {
            repo_key: repo_key.to_string(),
            priority,
        }
    }

    /// Non-virtual repos pass through the validator unchanged, regardless of
    /// whether `member_repos` is set. Defensive: callers should not pass
    /// `member_repos` for non-virtual types, but the validator must be a
    /// no-op for them either way.
    #[test]
    fn test_validate_virtual_repo_member_count_noop_for_non_virtual() {
        for rt in [
            RepositoryType::Local,
            RepositoryType::Remote,
            RepositoryType::Staging,
        ] {
            assert!(
                validate_virtual_repo_member_count("my-repo", &rt, None).is_ok(),
                "{:?} with no members must be Ok",
                &rt
            );
            assert!(
                validate_virtual_repo_member_count("my-repo", &rt, Some(&[])).is_ok(),
                "{:?} with empty members must be Ok",
                &rt
            );
        }
    }

    /// A virtual repo with no `member_repos` field at all (the shape that
    /// happens when an operator types `members: [...]` because the struct
    /// uses `member_repos` and doesn't `deny_unknown_fields`) must 400 with
    /// an actionable message.
    #[test]
    fn test_validate_virtual_repo_member_count_rejects_none() {
        let err = validate_virtual_repo_member_count("pypi", &RepositoryType::Virtual, None)
            .expect_err("None members must reject");
        match err {
            AppError::Validation(msg) => {
                assert!(
                    msg.contains("requires at least one member"),
                    "message should explain the requirement; got: {}",
                    msg
                );
                assert!(
                    msg.contains("member_repos"),
                    "message should name the expected field `member_repos`; got: {}",
                    msg
                );
                assert!(
                    msg.contains("pypi"),
                    "message should echo the offending repo key; got: {}",
                    msg
                );
            }
            other => panic!("expected AppError::Validation, got {:?}", other),
        }
    }

    /// A virtual repo created with `member_repos: []` is also unusable. The
    /// validator must reject this with the same Validation error class as
    /// the None case so the handler returns 400 (not 500) in both shapes.
    #[test]
    fn test_validate_virtual_repo_member_count_rejects_empty() {
        let err = validate_virtual_repo_member_count("pypi", &RepositoryType::Virtual, Some(&[]))
            .expect_err("empty members must reject");
        assert!(matches!(err, AppError::Validation(_)));
    }

    /// A virtual repo with one or more members passes validation. Pin both
    /// the single-member and multi-member cases.
    #[test]
    fn test_validate_virtual_repo_member_count_accepts_non_empty() {
        let one = [member("pypi-local", 1)];
        assert!(
            validate_virtual_repo_member_count("pypi", &RepositoryType::Virtual, Some(&one))
                .is_ok()
        );
        let two = [member("pypi-local", 1), member("pypi-remote", 2)];
        assert!(
            validate_virtual_repo_member_count("pypi", &RepositoryType::Virtual, Some(&two))
                .is_ok()
        );
    }

    /// Pin the silent-drop deserialization behaviour the validator
    /// compensates for. If a future PR adds `#[serde(deny_unknown_fields)]`
    /// to `CreateRepositoryRequest` (the proper hardening), this test will
    /// fail and signal that the validator can be tightened or rewritten.
    /// Until then this test documents the trap.
    #[test]
    fn test_create_request_silently_drops_unknown_members_field() {
        let body = serde_json::json!({
            "key": "pypi",
            "name": "PyPI Virtual",
            "format": "pypi",
            "repo_type": "virtual",
            "members": ["pypi-local", "pypi-remote"]
        });
        let parsed: CreateRepositoryRequest =
            serde_json::from_value(body).expect("deserialize should succeed");
        assert!(
            parsed.member_repos.is_none(),
            "`members:` (wrong field name) must currently land as None in `member_repos`. \
             If this fails, deny_unknown_fields was likely added and the validator can \
             be simplified."
        );
    }

    // ---------------------------------------------------------------------
    // download_artifact: remote-repo streaming-fallback path (#1300 / PR #1294).
    //
    // The generic `/:key/download/*path` handler used to buffer the full
    // upstream body into memory before responding, which OOM-killed pods
    // serving multi-GB artifacts. PR #1294 migrated the remote-NotFound
    // fallback arm to `proxy_helpers::proxy_fetch_streaming`. These tests
    // pin that contract end-to-end:
    //
    //   1. wiremock stands in for the real upstream
    //   2. an empty `artifacts` table forces `artifact_service.download`
    //      to return NotFound, which routes execution into the new
    //      `proxy_fetch_streaming(..)` block (lines 2159-2169)
    //   3. assertions confirm the bytes round-trip and the streaming
    //      Content-Type / Content-Length headers come from upstream
    //
    // Without these tests the new lines have no coverage in CI: every
    // other download path the handler can take terminates before the
    // remote-fallback arm. See PR #1294 review and the 70% new-code
    // coverage gate in `.github/workflows/ci.yml` (`coverage` job).
    // ---------------------------------------------------------------------

    use crate::api::handlers::test_db_helpers as tdh;

    /// Update the `upstream_url` and `is_public` columns on a repository row.
    /// Lets the test point a Remote repo at a wiremock server (which only
    /// has a stable URL after `MockServer::start().await`) and skip auth
    /// without needing a separate admin-user fixture.
    async fn point_repo_at_upstream(pool: &sqlx::PgPool, repo_id: Uuid, upstream: &str) {
        sqlx::query(
            "UPDATE repositories \
             SET upstream_url = $2, is_public = true \
             WHERE id = $1",
        )
        .bind(repo_id)
        .bind(upstream)
        .execute(pool)
        .await
        .expect("update repo upstream_url");
    }

    #[tokio::test]
    async fn test_download_artifact_remote_streams_upstream_body() {
        let Some(fx) = tdh::Fixture::setup("remote", "generic").await else {
            return;
        };

        // Stand up the upstream and pin a single path.
        let server = wiremock::MockServer::start().await;
        let upstream_body: &[u8] = b"the-streamed-bytes-from-upstream";
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path("/foo/bar.tgz"))
            .respond_with(
                wiremock::ResponseTemplate::new(200)
                    .set_body_bytes(upstream_body)
                    .insert_header("content-type", "application/x-tar"),
            )
            .mount(&server)
            .await;

        point_repo_at_upstream(&fx.pool, fx.repo_id, &server.uri()).await;

        // Build state with a real proxy_service so the streaming-fallback
        // arm in `download_artifact` has somewhere to dispatch to.
        let proxy =
            tdh::build_proxy_service_with_fs(fx.pool.clone(), fx.storage_dir.to_str().unwrap());
        let state =
            tdh::build_state_with_proxy(fx.pool.clone(), fx.storage_dir.to_str().unwrap(), proxy);

        // Anonymous request: `is_public = true` makes require_visible pass
        // without needing to thread an admin AuthExtension through.
        let router = tdh::router_anon(download_router(), state);
        let req = tdh::get(format!("/{}/download/foo/bar.tgz", fx.repo_key));
        let (status, body) = tdh::send(router, req).await;

        assert_eq!(
            status,
            axum::http::StatusCode::OK,
            "remote-NotFound branch must stream a 200 (not OOM on a buffered \
             alloc, not 404 from the local-fetch arm)"
        );
        assert_eq!(
            &body[..],
            upstream_body,
            "streamed body bytes must round-trip from wiremock through \
             proxy_fetch_streaming and back to the caller"
        );

        fx.teardown().await;
    }

    #[tokio::test]
    async fn test_download_artifact_remote_propagates_upstream_content_type() {
        // The handler passes "application/octet-stream" as the
        // `default_content_type` to `proxy_fetch_streaming`, but the
        // upstream-supplied `content-type` must win when present. This
        // pins the precedence rule alongside the body round-trip above.
        let Some(fx) = tdh::Fixture::setup("remote", "generic").await else {
            return;
        };

        let server = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path("/some/file.bin"))
            .respond_with(
                wiremock::ResponseTemplate::new(200)
                    .set_body_bytes(b"ctype-pinned".as_ref())
                    .insert_header("content-type", "application/java-archive"),
            )
            .mount(&server)
            .await;

        point_repo_at_upstream(&fx.pool, fx.repo_id, &server.uri()).await;

        let proxy =
            tdh::build_proxy_service_with_fs(fx.pool.clone(), fx.storage_dir.to_str().unwrap());
        let state =
            tdh::build_state_with_proxy(fx.pool.clone(), fx.storage_dir.to_str().unwrap(), proxy);
        let router = tdh::router_anon(download_router(), state);
        let req = tdh::get(format!("/{}/download/some/file.bin", fx.repo_key));
        // Reach into the router directly so we can also inspect headers
        // before draining the body into bytes.
        use tower::ServiceExt;
        let resp = router.oneshot(req).await.expect("oneshot");

        assert_eq!(resp.status(), axum::http::StatusCode::OK);
        let ct = resp
            .headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string();
        assert_eq!(
            ct, "application/java-archive",
            "upstream content-type must override the handler's \
             `application/octet-stream` default fallback"
        );

        let body_bytes = axum::body::to_bytes(resp.into_body(), 1024)
            .await
            .expect("body");
        assert_eq!(&body_bytes[..], b"ctype-pinned");

        fx.teardown().await;
    }

    #[tokio::test]
    async fn test_download_artifact_remote_returns_default_content_type_when_upstream_omits_it() {
        // When upstream doesn't set Content-Type, the handler's
        // `application/octet-stream` default must be applied. This covers
        // the `default_content_type` argument plumbed through #1294.
        let Some(fx) = tdh::Fixture::setup("remote", "generic").await else {
            return;
        };

        let server = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path("/no/ctype.bin"))
            .respond_with(
                // No content-type header. wiremock will still emit a
                // default `Content-Type: application/octet-stream` for
                // raw byte bodies in some versions, but in this codebase
                // we rely on the upstream metadata `content_type` field
                // being None to exercise the default fallback.
                wiremock::ResponseTemplate::new(200).set_body_bytes(b"no-upstream-ctype".as_ref()),
            )
            .mount(&server)
            .await;

        point_repo_at_upstream(&fx.pool, fx.repo_id, &server.uri()).await;

        let proxy =
            tdh::build_proxy_service_with_fs(fx.pool.clone(), fx.storage_dir.to_str().unwrap());
        let state =
            tdh::build_state_with_proxy(fx.pool.clone(), fx.storage_dir.to_str().unwrap(), proxy);
        let router = tdh::router_anon(download_router(), state);
        let req = tdh::get(format!("/{}/download/no/ctype.bin", fx.repo_key));
        let (status, body) = tdh::send(router, req).await;

        assert_eq!(status, axum::http::StatusCode::OK);
        assert_eq!(
            &body[..],
            b"no-upstream-ctype",
            "body bytes must still flow through even when upstream omits \
             a Content-Type header"
        );

        fx.teardown().await;
    }

    #[tokio::test]
    async fn test_download_artifact_remote_upstream_404_returns_error_response() {
        // When upstream responds 404, `proxy_fetch_streaming` returns
        // `Err(response)` which the handler unwraps via
        // `.unwrap_or_else(|e| e).into_response()`. This pins that the
        // error path produces a non-200 response (i.e. the unwrap_or_else
        // arm in lines 2167-2168 is exercised, not just the happy path).
        let Some(fx) = tdh::Fixture::setup("remote", "generic").await else {
            return;
        };

        let server = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path("/gone/never.bin"))
            .respond_with(wiremock::ResponseTemplate::new(404))
            .mount(&server)
            .await;

        point_repo_at_upstream(&fx.pool, fx.repo_id, &server.uri()).await;

        let proxy =
            tdh::build_proxy_service_with_fs(fx.pool.clone(), fx.storage_dir.to_str().unwrap());
        let state =
            tdh::build_state_with_proxy(fx.pool.clone(), fx.storage_dir.to_str().unwrap(), proxy);
        let router = tdh::router_anon(download_router(), state);
        let req = tdh::get(format!("/{}/download/gone/never.bin", fx.repo_key));
        let (status, _body) = tdh::send(router, req).await;

        assert_ne!(
            status,
            axum::http::StatusCode::OK,
            "an upstream 404 must NOT surface as a successful streamed body; \
             the err-into-response shortcut on line 2168 must propagate the \
             failure status"
        );

        fx.teardown().await;
    }

    #[tokio::test]
    async fn test_download_artifact_remote_without_proxy_service_returns_not_found() {
        // Belt-and-braces: with `proxy_service = None` the
        // remote-NotFound arm falls through to `Err(NotFound)`, exercising
        // the `else` branch right after the `proxy_fetch_streaming` call.
        // Guards against a refactor that accidentally calls the streaming
        // helper with an unwrap on a missing proxy service.
        let Some(fx) = tdh::Fixture::setup("remote", "generic").await else {
            return;
        };

        // Mark public; do NOT install a proxy_service on the state.
        point_repo_at_upstream(&fx.pool, fx.repo_id, "https://unused.example.test").await;
        let state = tdh::build_state(fx.pool.clone(), fx.storage_dir.to_str().unwrap());

        let router = tdh::router_anon(download_router(), state);
        let req = tdh::get(format!("/{}/download/whatever.bin", fx.repo_key));
        let (status, _body) = tdh::send(router, req).await;

        assert_eq!(
            status,
            axum::http::StatusCode::NOT_FOUND,
            "no proxy_service on the AppState must short-circuit to 404, \
             not call into a streaming helper that does not exist"
        );

        fx.teardown().await;
    }

    // ---------------------------------------------------------------------
    // Source-level pin: the remote-NotFound arm in `download_artifact` must
    // call `proxy_helpers::proxy_fetch_streaming(` (#1294). Mirrors the
    // five pins added in #1183 for the maven / goproxy / gitlfs / alpine /
    // debian handlers. A silent revert to the buffered `proxy_fetch` helper
    // would re-introduce the OOM regression closed by #895 and #1294.
    // ---------------------------------------------------------------------

    #[test]
    fn test_repositories_download_artifact_uses_streaming_helper_1294() {
        let src = include_str!("repositories.rs");
        assert!(
            src.contains("proxy_helpers::proxy_fetch_streaming("),
            "`repositories::download_artifact` MUST call \
             `proxy_helpers::proxy_fetch_streaming(` for the remote \
             upstream-fallback download (#1294). A revert to the buffered \
             `proxy_fetch` helper would re-introduce the OOM regression \
             closed by #895/#1294."
        );
    }

    // ---------------------------------------------------------------------
    // compose_artifact_path (#1237)
    //
    // The web UI's "Custom path (optional)" field is sent as a `path` form
    // field alongside the file in a multipart POST to
    // `/api/v1/repositories/<repo>/artifacts`. Before #1237 this field was
    // silently dropped and only the file's filename ever reached the
    // storage layer. These tests pin the composition rules:
    //   - empty / missing custom_path -> use the filename only
    //   - trailing slash -> directory prefix (append filename)
    //   - no trailing slash -> full path verbatim
    //   - arbitrary depth allowed (1 or N segments)
    // The downstream `validate_artifact_path` in the upload pipeline
    // continues to reject `..`, `//`, null bytes, etc.
    // ---------------------------------------------------------------------

    #[test]
    fn test_compose_artifact_path_no_custom_path_uses_filename() {
        // Empty and absent both fall back to the filename
        assert_eq!(compose_artifact_path(None, "foo.tar.gz"), "foo.tar.gz");
        assert_eq!(compose_artifact_path(Some(""), "foo.tar.gz"), "foo.tar.gz");
        assert_eq!(
            compose_artifact_path(Some("   "), "foo.tar.gz"),
            "foo.tar.gz",
            "whitespace-only path should fall back to filename"
        );
    }

    #[test]
    fn test_compose_artifact_path_one_segment_verbatim() {
        // Bug repro case from #1237: custom_path `unifi/guide.pdf` should
        // become the full artifact path, NOT `unifi-udmp-security-guide.pdf`.
        assert_eq!(
            compose_artifact_path(Some("unifi/guide.pdf"), "unifi-udmp-security-guide.pdf"),
            "unifi/guide.pdf"
        );
        // Single-segment custom path
        assert_eq!(
            compose_artifact_path(Some("renamed.bin"), "original.bin"),
            "renamed.bin"
        );
    }

    #[test]
    fn test_compose_artifact_path_trailing_slash_appends_filename() {
        // Issue #1237 explicit example: `unifi/docs/` + filename ->
        // `unifi/docs/unifi-udmp-security-guide.pdf`
        assert_eq!(
            compose_artifact_path(Some("unifi/docs/"), "unifi-udmp-security-guide.pdf"),
            "unifi/docs/unifi-udmp-security-guide.pdf"
        );
        // Single-segment directory
        assert_eq!(
            compose_artifact_path(Some("releases/"), "v1.tar.gz"),
            "releases/v1.tar.gz"
        );
    }

    #[test]
    fn test_compose_artifact_path_arbitrary_depth() {
        // 3-segment path
        assert_eq!(
            compose_artifact_path(Some("a/b/c/file.bin"), "ignored.bin"),
            "a/b/c/file.bin"
        );
        // 5-segment path (deep)
        assert_eq!(
            compose_artifact_path(Some("a/b/c/d/e/file.bin"), "ignored.bin"),
            "a/b/c/d/e/file.bin"
        );
        // 4-segment directory prefix
        assert_eq!(
            compose_artifact_path(Some("a/b/c/d/"), "file.bin"),
            "a/b/c/d/file.bin"
        );
    }

    #[test]
    fn test_compose_artifact_path_strips_leading_slash() {
        // Leading slash on the form field should not produce an absolute
        // path (validate_artifact_path rejects those). Strip it so a UI
        // that sends `/unifi/docs/` still works.
        assert_eq!(
            compose_artifact_path(Some("/unifi/docs/"), "x.pdf"),
            "unifi/docs/x.pdf"
        );
        assert_eq!(
            compose_artifact_path(Some("/unifi/guide.pdf"), "x.pdf"),
            "unifi/guide.pdf"
        );
    }

    #[test]
    fn test_compose_artifact_path_with_special_chars() {
        // Spaces, dots, dashes, underscores, plus signs - all valid in paths
        // (the downstream validator only rejects traversal patterns).
        assert_eq!(
            compose_artifact_path(Some("my dir/file.tar.gz"), "x.bin"),
            "my dir/file.tar.gz"
        );
        assert_eq!(
            compose_artifact_path(
                Some("releases/v1.2.3-rc.1/"),
                "artifact_v1.2.3+linux.x86_64.bin"
            ),
            "releases/v1.2.3-rc.1/artifact_v1.2.3+linux.x86_64.bin"
        );
    }

    // ---------------------------------------------------------------------
    // Security: composed paths must be rejected by validate_artifact_path
    //
    // Regression for the gap found in #1322's security review:
    // `compose_artifact_path` happily produces `../etc/passwd` from a
    // malicious `path` form field, and the original PR did NOT call
    // `validate_artifact_path` on the composed value before handing it to
    // the storage layer. Filesystem storage's `key_to_path` strips `..`
    // segments, but S3/GCS backends do not, so a `path=../../etc/passwd`
    // form field could escape the repository's storage key prefix.
    //
    // The fix is to call `validate_artifact_path` inside `upload_artifact`
    // so every entry point (URL-path PUT, multipart-with-path POST, and
    // the new multipart `path` form field added in #1237) is covered. The
    // first test pins the composition+validation contract without needing
    // a database; the second drives the actual handler end-to-end and
    // asserts the HTTP response is 400.
    // ---------------------------------------------------------------------

    #[test]
    fn test_compose_artifact_path_traversal_is_rejected_by_validator() {
        // The composed path is exactly the attacker-controlled value
        // (no trailing slash means the path is used verbatim).
        let composed = compose_artifact_path(Some("../etc/passwd"), "ignored.bin");
        assert_eq!(composed, "../etc/passwd");

        // And validate_artifact_path must reject it. If this ever starts
        // returning Ok(_) the security guarantee is gone.
        let err = upload_service::validate_artifact_path(&composed)
            .expect_err("../etc/passwd must be rejected as traversal");
        let msg = err.to_string();
        assert!(
            msg.contains("traversal"),
            "expected traversal rejection, got: {msg}"
        );

        // Belt-and-braces: a few other shapes the composer can produce
        // from hostile form fields, all of which must fail validation.
        for hostile in [
            "../../etc/passwd",
            "a/../b",
            "file\0.txt",
            "a/%2e%2e/b",
            "a\\b",
        ] {
            assert!(
                upload_service::validate_artifact_path(hostile).is_err(),
                "validate_artifact_path must reject {hostile:?}",
            );
        }
    }

    #[tokio::test]
    async fn test_upload_artifact_rejects_traversal_path_with_400() {
        // End-to-end pin: drive `upload_artifact` with a path produced by
        // `compose_artifact_path("../etc/passwd", _)` and assert the
        // handler returns 400 Bad Request without touching storage. Skips
        // gracefully when no DATABASE_URL is configured.
        let Some(fx) = tdh::Fixture::setup("local", "generic").await else {
            return;
        };

        let composed = compose_artifact_path(Some("../etc/passwd"), "ignored.bin");
        assert_eq!(composed, "../etc/passwd");

        // `make_auth` builds a JWT-style AuthExtension (is_api_token =
        // false), so `require_scope("write")` automatically passes - no
        // need to populate `scopes`.
        let auth = tdh::make_auth(fx.user_id, &fx.username);

        let result = upload_artifact(
            State(fx.state.clone()),
            Extension(Some(auth)),
            Path((fx.repo_key.clone(), composed)),
            HeaderMap::new(),
            Bytes::from_static(b"payload-should-never-be-stored"),
        )
        .await;

        let err = result.expect_err("traversal path must be rejected");
        // AppError::Validation maps to 400 Bad Request via IntoResponse
        // (see error.rs status_and_code). Pinning the variant here is
        // equivalent and avoids reaching into a private method.
        assert!(
            matches!(err, AppError::Validation(_)),
            "traversal path must surface as Validation (400), got {err:?}",
        );

        fx.teardown().await;
    }

    // -----------------------------------------------------------------------
    // Virtual-repo /members + /cache-ttl sub-router registration (#1366)
    // -----------------------------------------------------------------------
    //
    // Issue #1366 surfaced as 22 release-gate failures all reporting HTTP 404
    // on `/api/v1/repositories/{key}/members` (and the sibling /cache-ttl
    // route) for v1.2.0-rc.2. Investigation against the same commit
    // (f81136eb) showed the routes are reachable end-to-end on a freshly
    // built backend, so the source itself is not regressed -- the production
    // failure was rooted elsewhere (likely a stale image / deploy artifact).
    //
    // These tests defend the router shape itself so a future refactor that
    // accidentally drops one of the routes (the hypothesis the issue raised)
    // would fail at `cargo test --workspace --lib` rather than slipping
    // through to release-gate. The pattern matches the existing source-level
    // regression for `/lxc` in `routes.rs::tests` (#1272): a runtime test
    // would need a full DB + auth fixture which we already have elsewhere,
    // but those tests cannot catch a route that was simply not registered
    // (a missing route never reaches the handler under test). Source-level
    // pins catch exactly that class of bug.
    //
    // Each assertion is built from `format!`d substrings so the test source
    // itself does not satisfy the search if `include_str!` is replaced
    // with a less specific lookup in a future refactor.
    mod virtual_member_router_registration {
        const SRC: &str = include_str!("repositories.rs");

        fn router_fn_body() -> &'static str {
            // Slice the `pub fn router()` body so route assertions do not
            // accidentally match a route literal that appears inside a
            // doc-comment or another function. The body starts at the
            // signature and ends at the next top-level `pub` item.
            let marker = "pub fn router() -> Router<SharedState> {";
            let start = SRC
                .find(marker)
                .expect("repositories::router() definition must exist");
            let after = &SRC[start..];
            let end = after[1..]
                .find("\npub ")
                .map(|i| i + 1)
                .unwrap_or(after.len());
            &after[..end]
        }

        #[test]
        fn router_registers_members_get_post_put() {
            // The combined route must include all three methods on a single
            // `/:key/members` literal. Splitting them across multiple
            // `.route()` calls is also valid axum, but the current shape is
            // a single call -- if you change that, update this test in the
            // same PR so the intent stays explicit.
            let body = router_fn_body();
            let path = format!("\"/:key/{}\"", "members");
            assert!(
                body.contains(&path),
                "router() must register the {} sub-route (regression of #1366)",
                path
            );
            for method_handler in [
                ("list_virtual_members", "get"),
                ("add_virtual_member", "post"),
                ("update_virtual_members", "put"),
            ] {
                let needle = format!("{}({})", method_handler.1, method_handler.0);
                assert!(
                    body.contains(&needle),
                    "router() must bind {} via `{}` (regression of #1366)",
                    method_handler.0,
                    needle
                );
            }
        }

        #[test]
        fn router_registers_members_delete_by_member_key() {
            let body = router_fn_body();
            let path = format!("\"/:key/{}/:member_key\"", "members");
            assert!(
                body.contains(&path),
                "router() must register the per-member delete route at {} (regression of #1366)",
                path
            );
            let delete_handler = format!("delete({})", "remove_virtual_member");
            assert!(
                body.contains(&delete_handler),
                "router() must bind remove_virtual_member via `{}` (regression of #1366)",
                delete_handler
            );
        }

        #[test]
        fn router_registers_cache_ttl_put_and_get() {
            // The release-gate failure for #1366 also flagged
            // `PUT /repositories/{key}/cache-ttl` returning 404. cache-ttl is
            // a sibling sub-resource of /members, so a regression that drops
            // the virtual-member routes is likely to drop this one too. Pin
            // both routes together so a single source-level read of
            // `router()` covers the whole sub-router shape.
            let body = router_fn_body();
            let path = format!("\"/:key/{}\"", "cache-ttl");
            assert!(
                body.contains(&path),
                "router() must register the {} sub-route (regression of #1366)",
                path
            );
            let put_handler = format!("put({})", "set_cache_ttl");
            let get_handler = format!("get({})", "get_cache_ttl");
            assert!(
                body.contains(&put_handler),
                "router() must bind set_cache_ttl via `{}` (regression of #1366)",
                put_handler
            );
            assert!(
                body.contains(&get_handler),
                "router() must bind get_cache_ttl via `{}` (regression of #1366)",
                get_handler
            );
        }

        #[test]
        fn router_fn_marker_resolves_so_the_above_tests_are_not_vacuous() {
            // Belt-and-suspenders: if a future refactor renames `router()`
            // or changes its signature, `router_fn_body()` would panic and
            // the three tests above would fail noisily rather than passing
            // a `false.contains(...)` against an empty slice.
            let body = router_fn_body();
            assert!(
                body.starts_with("pub fn router() -> Router<SharedState> {"),
                "router_fn_body() did not anchor on the expected signature; \
                 the route assertions above may be vacuously true. Refactor \
                 hint: update the `marker` literal in router_fn_body() to \
                 match the new signature."
            );
            // Sanity check that the body is non-trivial. A bare stub
            // implementation (e.g. `Router::new()` only) would silently
            // make every contains() assertion above fail with a
            // not-found-substring message, which is the right outcome, but
            // we also assert here so the failure mode is obvious.
            assert!(
                body.len() > 200,
                "router() body is suspiciously short ({} bytes); the route \
                 assertions above may be testing an empty router",
                body.len()
            );
        }
    }
}
