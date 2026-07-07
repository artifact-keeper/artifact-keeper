//! Repository management handlers.

use axum::{
    body::{Body, Bytes},
    extract::{Extension, Multipart, Path, Query, State},
    http::{header, HeaderMap, StatusCode},
    response::{IntoResponse, Response},
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
use crate::api::handlers::is_replication_request;
use crate::api::handlers::proxy_helpers;
use crate::api::middleware::auth::AuthExtension;
use crate::api::SharedState;
use crate::error::{AppError, Result};
use crate::formats::maven::MavenHandler;
use crate::models::access_scope::AccessScope;
use crate::models::repository::{RepositoryFormat, RepositoryType};
use crate::services::artifact_service::ArtifactService;
use crate::services::cache_classifier;
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

/// Authorize a write/delete operation against a repository.
///
/// Enforces both the token-scope check (`require_repo_access`) and, for private
/// repositories, per-repo authorization: admins bypass; every other caller must
/// hold a role assignment scoped to the repo (direct or global). Public repos
/// keep their existing behavior (token-scope only).
///
/// Exposed as `pub(crate)` so the repository sub-resource handlers that live in
/// sibling modules (labels, security, email subscriptions) and the chunked
/// upload-session create path can route through the SAME tenant write gate
/// rather than re-deriving (or forgetting) it. The `/api/v1/repositories` nest
/// runs under `optional_auth_middleware` only, NOT `repo_visibility_middleware`,
/// so each sub-handler must enforce this itself.
pub(crate) async fn require_repo_write_access(
    auth: &AuthExtension,
    repo: &crate::models::repository::Repository,
    repo_service: &RepositoryService,
) -> Result<()> {
    require_repo_access(auth, repo.id)?;
    if repo.is_public || auth.is_admin {
        return Ok(());
    }
    if repo_service
        .user_can_access_repo(repo.id, auth.user_id)
        .await?
    {
        Ok(())
    } else {
        Err(AppError::Authorization(
            "You do not have access to this repository".to_string(),
        ))
    }
}

/// Ensure a repository is visible to the current user.
///
/// Public repos are visible to everyone. Private repos require authentication
/// AND per-repo authorization: the caller must be an admin or hold a role
/// assignment scoped to the repository (direct or global). The token-scope
/// check (`can_access_repo`) is also enforced for repository-scoped API tokens.
///
/// Denials on private repos return `NotFound` (not `Forbidden`) to avoid
/// leaking the existence of repositories the caller may not see.
///
/// Exposed as `pub(crate)` so leaky-read sub-resource handlers in sibling
/// modules (labels list, security read) can reuse the canonical visibility gate.
pub(crate) async fn require_visible(
    repo: &crate::models::repository::Repository,
    auth: &Option<AuthExtension>,
    repo_service: &RepositoryService,
) -> Result<()> {
    if repo.is_public {
        return Ok(());
    }
    let not_found = || AppError::NotFound(format!("Repository '{}' not found", repo.key));
    match auth {
        Some(a) => {
            // Repository-scoped API tokens must still allow this repo.
            if !a.can_access_repo(repo.id) {
                return Err(not_found());
            }
            // Per-repo authorization: admins bypass; everyone else needs a
            // role assignment scoped to this repo (or a global assignment).
            if a.is_admin
                || repo_service
                    .user_can_access_repo(repo.id, a.user_id)
                    .await?
            {
                Ok(())
            } else {
                Err(not_found())
            }
        }
        None => Err(not_found()),
    }
}

/// Pure decision for the fine-grained privilege gate on virtual-member
/// mutations: admins always pass; every other caller must hold the
/// `repository:admin` action on the virtual parent. Mirrors the gate used by
/// `update_repository` / `delete_repository`. Factored out so both branches are
/// unit-testable without a database.
fn member_mutation_admin_allowed(is_admin: bool, has_repo_admin: bool) -> bool {
    is_admin || has_repo_admin
}

/// Issue #913: authorize a virtual-member mutation.
///
/// All three mutating handlers (`add_virtual_member`, `remove_virtual_member`,
/// per-iteration step of `update_virtual_members`) must enforce two things
/// before mutating membership:
///
///   1. Token-scope (`require_repo_access`) on BOTH the virtual parent and the
///      member repo. A repository-scoped API token must not reach repos it was
///      not granted. Tokens with `allowed_repo_ids = None` (admins, JWT
///      sessions, unrestricted API tokens) pass this naturally.
///   2. Fine-grained privilege on the virtual parent: managing a virtual
///      repository's member resolution graph is an administrative change to
///      that repository, so non-admins must hold `repository:admin` on the
///      virtual parent — the same check `update_repository` /
///      `delete_repository` enforce. Without this, any authenticated user could
///      reorder/add/remove members (the token-scope check no-ops for JWT
///      sessions, whose `allowed_repo_ids` is always `None`).
///
/// Admins short-circuit the privilege check with no database lookup.
///
/// On denial, emit a structured `tracing::warn!` so the event is recoverable
/// from logs.
async fn authorize_virtual_member_mutation(
    auth: &AuthExtension,
    virtual_repo: &crate::models::repository::Repository,
    member_repo: &crate::models::repository::Repository,
    action: &str,
    permission_service: &crate::services::permission_service::PermissionService,
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

    // Fine-grained privilege gate on the virtual parent. Admins short-circuit
    // with no DB lookup; non-admins need `repository:admin` on the virtual repo.
    let has_repo_admin = if auth.is_admin {
        true
    } else {
        permission_service
            .check_permission(auth.user_id, "repository", virtual_repo.id, "admin", false)
            .await?
    };
    if !member_mutation_admin_allowed(auth.is_admin, has_repo_admin) {
        tracing::warn!(
            actor_user_id = %auth.user_id,
            actor_username = %auth.username,
            virtual_repo_id = %virtual_repo.id,
            virtual_repo_key = %virtual_repo.key,
            member_repo_id = %member_repo.id,
            member_repo_key = %member_repo.key,
            action = action,
            "denied virtual-member mutation: caller lacks repository:admin on virtual parent"
        );
        return Err(AppError::Authorization(
            "Insufficient permissions to manage members of this repository".to_string(),
        ));
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
        // Cache invalidation for a specific path on a Remote (proxy) repository
        // (#1539). POST keeps the action explicit; the underlying
        // `ProxyService::invalidate_cache` is idempotent so a second call for
        // an already-evicted path still returns 200.
        .route("/:key/cache/invalidate", post(invalidate_cache))
        // PEP 708 tracks declarations for PyPI dependency-confusion control (#1600)
        .route("/:key/pypi-tracks", get(list_pypi_tracks))
        .route(
            "/:key/pypi-tracks/:project",
            put(put_pypi_track).delete(delete_pypi_track),
        )
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
    /// When true, direct user uploads to this repository are rejected:
    /// artifacts must arrive via the promotion path. Admin-only to set.
    /// Defaults to false (no behavior change for existing repositories).
    pub promotion_only: Option<bool>,
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
    /// Override the PyPI simple-index prefix for upstreams that do not follow
    /// the standard PEP 503 `/simple/` layout (issue #1546).
    ///
    /// - Omit or `"simple"` — standard PEP 503 (pypi.org, devpi, Nexus). Default.
    /// - `""` (empty) — flat CDN (e.g. `https://download.pytorch.org/whl/cpu`):
    ///   package files are served directly under the upstream root with no prefix.
    /// - Any other non-empty string — custom index prefix.
    ///
    /// Stored in `repository_config` under `pypi_upstream_index_path`.
    /// Only meaningful for PyPI / Poetry / Conda Remote repositories.
    pub pypi_upstream_index_path: Option<String>,
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
    /// When provided, enables/disables the `promotion_only` policy for this
    /// repository (admin-only). When omitted, the flag is left unchanged.
    pub promotion_only: Option<bool>,
    /// Update the Cargo index upstream URL (stored in `repository_config`).
    /// When provided, upserts the `index_upstream_url` key for this repository.
    pub index_upstream_url: Option<String>,
    /// Update the PyPI simple-index prefix (stored in `repository_config` under
    /// `pypi_upstream_index_path`). Pass `""` for flat CDN layout, `"simple"` to
    /// restore the PEP 503 default, or any other non-empty string for a custom prefix.
    /// Only meaningful for PyPI / Poetry / Conda Remote repositories.
    pub pypi_upstream_index_path: Option<String>,
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
    /// When true, direct user uploads are rejected; artifacts must be promoted.
    pub promotion_only: bool,
    pub storage_used_bytes: i64,
    pub quota_bytes: Option<i64>,
    pub upstream_url: Option<String>,
    pub upstream_auth_type: Option<String>,
    pub upstream_auth_configured: bool,
    /// Whether the Package Age / quarantine policy is enabled for this
    /// repository, read back from `repository_config` (#1770 B). `None` when
    /// the repository has no explicit setting (the global default applies).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub quarantine_enabled: Option<bool>,
    /// Configured quarantine hold duration in minutes, read back from
    /// `repository_config` (#1770 B). `None` when unset.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub quarantine_duration_minutes: Option<i64>,
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
        promotion_only: repo.promotion_only,
        storage_used_bytes,
        quota_bytes: repo.quota_bytes,
        upstream_url: repo.upstream_url,
        upstream_auth_type: None,
        upstream_auth_configured: false,
        // Populated by the handlers that have a DB handle (see
        // `with_quarantine_settings`); `repo_to_response` itself is sync and
        // db-less, mirroring `upstream_auth_*` above (#1770 B).
        quarantine_enabled: None,
        quarantine_duration_minutes: None,
        created_at: repo.created_at,
        updated_at: repo.updated_at,
    }
}

/// Populate `RepositoryResponse.quarantine_*` from `repository_config` (#1770
/// B). Split out so the detail and update handlers, which both have a DB
/// handle, can echo the configured Package Age Policy back to clients. The
/// listing path stays db-light and omits these per-repo lookups.
async fn with_quarantine_settings(
    db: &sqlx::PgPool,
    repo_id: Uuid,
    mut response: RepositoryResponse,
) -> RepositoryResponse {
    let (enabled, duration) = crate::services::quarantine_service::repo_settings(db, repo_id).await;
    response.quarantine_enabled = enabled;
    response.quarantine_duration_minutes = duration;
    response
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

/// Clamp a caller-supplied `per_page` into the valid `[1, 100]` range.
///
/// `per_page = 0` (or any value below 1) must NOT pass through: it would reach
/// the `total_pages = ceil(total / per_page)` division as a divide-by-zero and
/// saturate `total_pages` to `u32::MAX` for any non-empty listing (#1783 LOW).
/// `clamp(1, 100)` also caps the page size, matching `list_artifacts`.
pub(crate) fn clamp_per_page(per_page: Option<u32>) -> u32 {
    per_page.unwrap_or(20).clamp(1, 100)
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
    // #1444 follow-up: distinguish "field omitted entirely" (None) from
    // "explicit empty list" (Some(vec![])).
    //
    // * None  -> caller is following the deferred-population pattern: create
    //            the virtual, then add members via `POST /repositories/{key}/members`.
    //            This is the shape every E2E test helper uses. Rejecting it
    //            at create time (the original PR #1279 / #1281 behaviour)
    //            breaks the create-then-add flow and surfaces as the
    //            "members router returns 404" symptom in #1444 because
    //            the follow-up POSTs target a nonexistent repo. We
    //            therefore accept None and leave the empty-virtual state
    //            visible at fetch time (NOT_FOUND on download) -- it
    //            self-resolves on the first add_member.
    //
    // * Some(vec![]) -> caller explicitly said "no members". This is the
    //            silent-drop trap from #1279 (mis-typed field name
    //            deserialised to None pre-fix; the explicit empty form is
    //            also a clear operator mistake). Keep rejecting it so the
    //            mistake surfaces at create-time with an actionable
    //            message, as #1281 intended.
    if let Some([]) = member_repos {
        return Err(AppError::Validation(format!(
            "Virtual repository '{}' was created with an explicit empty \
             `member_repos: []`. Provide one or more members \
             (`member_repos: [{{\"repo_key\": \"<key>\", \"priority\": <int>}}, ...]`) \
             at create time, or omit the field entirely and add members \
             via `POST /api/v1/repositories/{}/members` afterwards. (#1279, #1444)",
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
    require_repo_write_access(&auth, &repo, &service).await?;

    // Fine-grained permission check: non-admins need "admin" on the target
    // repository. Cache TTL is a pull-through proxy supply-chain control on the
    // same administrative tier as delete/update, so the tenant write gate above
    // is not sufficient on its own.
    if !auth.is_admin {
        let has_perm = state
            .permission_service
            .check_permission(auth.user_id, "repository", repo.id, "admin", false)
            .await?;
        if !has_perm {
            return Err(AppError::Authorization(
                "Insufficient permissions to change the cache TTL of this repository".to_string(),
            ));
        }
    }

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

#[derive(Debug, Deserialize, IntoParams, ToSchema)]
pub struct InvalidateCacheQuery {
    /// Artifact path to evict from the proxy cache. Same shape as the path
    /// segment of `GET /api/v1/repositories/{key}/artifacts/{path}`.
    /// Path-traversal segments such as `..` are rejected by
    /// `ProxyService::cache_storage_key` (covered by
    /// `test_invalidate_cache_by_key_rejects_invalid_path`).
    pub path: String,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct InvalidateCacheResponse {
    pub repository_key: String,
    pub path: String,
    pub invalidated: bool,
}

/// Invalidate a single cached artifact entry on a Remote (proxy) repository
/// (#1539).
///
/// Mirrors the auth + repo-access pattern of `set_cache_ttl`. Idempotent:
/// invalidating a path that was never cached (or was already evicted) still
/// returns 200, matching the underlying `ProxyService::invalidate_cache`
/// contract (which ignores delete-of-missing on the storage backend).
#[utoipa::path(
    post,
    path = "/{key}/cache/invalidate",
    context_path = "/api/v1/repositories",
    tag = "repositories",
    params(
        ("key" = String, Path, description = "Repository key"),
        InvalidateCacheQuery,
    ),
    security(("bearer_auth" = [])),
    responses(
        (status = 200, description = "Cache entry invalidated (or was already absent)", body = InvalidateCacheResponse),
        (status = 400, description = "Validation error (e.g. non-remote repo or invalid path)"),
        (status = 401, description = "Authentication required"),
        (status = 404, description = "Repository not found"),
        (status = 503, description = "Proxy service not configured on this deployment"),
    )
)]
pub async fn invalidate_cache(
    State(state): State<SharedState>,
    Extension(auth): Extension<Option<AuthExtension>>,
    Path(key): Path<String>,
    Query(query): Query<InvalidateCacheQuery>,
) -> Result<Json<InvalidateCacheResponse>> {
    let auth = require_auth(auth)?;
    auth.require_scope("write")?;

    let service = RepositoryService::new(state.db.clone());
    let repo = service.get_by_key(&key).await?;
    require_repo_write_access(&auth, &repo, &service).await?;

    // Cache invalidation is meaningless on Local / Virtual / Staging repos --
    // only Remote (proxy) repos own a cache. Reject up front before touching
    // storage so the failure mode is a clear 400, not a silent no-op.
    if repo.repo_type != RepositoryType::Remote {
        return Err(AppError::Validation(
            "cache invalidation is only supported on remote (proxy) repositories".to_string(),
        ));
    }

    // No proxy service => storage backend not configured on this deployment.
    // Surface as 503 so operators can distinguish "feature off" from
    // "server bug" (mirrors the `AppError::ServiceUnavailable` doc comment
    // in `error.rs`). Avoids `unwrap()` on the optional field.
    let proxy = state
        .proxy_service
        .as_ref()
        .ok_or_else(|| AppError::ServiceUnavailable("proxy service not configured".to_string()))?;

    proxy.invalidate_cache(&repo, &query.path).await?;

    Ok(Json(InvalidateCacheResponse {
        repository_key: key,
        path: query.path,
        invalidated: true,
    }))
}

// ---------------------------------------------------------------------------
// PEP 708 `tracks` declarations (#1600)
// ---------------------------------------------------------------------------

/// Body for declaring that a locally-owned PyPI project tracks an upstream one.
#[derive(Debug, Deserialize, ToSchema)]
pub struct PypiTrackRequest {
    /// Upstream Simple index project URL this local project tracks, e.g.
    /// `https://pypi.org/simple/acme-sdk/`. Recorded and emitted as the PEP 708
    /// `tracks` value.
    pub tracks_url: String,
}

/// A single PEP 708 `tracks` declaration.
#[derive(Debug, Serialize, ToSchema)]
pub struct PypiTrackResponse {
    pub repository_key: String,
    /// PEP 503 normalized project name.
    pub normalized_name: String,
    pub tracks_url: String,
}

/// All `tracks` declarations on a repository.
#[derive(Debug, Serialize, ToSchema)]
pub struct PypiTracksListResponse {
    pub items: Vec<PypiTrackResponse>,
}

#[allow(clippy::result_large_err)]
fn require_pypi_tracks_repo(repo: &crate::models::repository::Repository) -> Result<()> {
    // tracks is declared on the hosted repo that OWNS the project (PEP 708:
    // tracks is a property of the project's own repository). It is meaningless
    // on a proxy or virtual repo, which hold no authoritative local project.
    if repo.repo_type != RepositoryType::Local && repo.repo_type != RepositoryType::Staging {
        return Err(AppError::Validation(
            "tracks declarations can only be set on a local (hosted) or staging repository"
                .to_string(),
        ));
    }
    Ok(())
}

/// List the PEP 708 `tracks` declarations on a repository.
#[utoipa::path(
    get,
    path = "/{key}/pypi-tracks",
    context_path = "/api/v1/repositories",
    tag = "repositories",
    params(("key" = String, Path, description = "Repository key")),
    responses(
        (status = 200, description = "tracks declarations", body = PypiTracksListResponse),
        (status = 404, description = "Repository not found"),
    )
)]
pub async fn list_pypi_tracks(
    State(state): State<SharedState>,
    Path(key): Path<String>,
) -> Result<Json<PypiTracksListResponse>> {
    let service = RepositoryService::new(state.db.clone());
    let repo = service.get_by_key(&key).await?;

    let rows: Vec<(String, String)> = sqlx::query_as(
        "SELECT normalized_name, tracks_url FROM pypi_project_tracks \
         WHERE repository_id = $1 ORDER BY normalized_name",
    )
    .bind(repo.id)
    .fetch_all(&state.db)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;

    Ok(Json(PypiTracksListResponse {
        items: rows
            .into_iter()
            .map(|(normalized_name, tracks_url)| PypiTrackResponse {
                repository_key: key.clone(),
                normalized_name,
                tracks_url,
            })
            .collect(),
    }))
}

/// Declare (upsert) that a locally-owned PyPI project tracks an upstream one,
/// allowing a virtual repository to merge versions across members for that name
/// instead of isolating it (PEP 708, #1600).
#[utoipa::path(
    put,
    path = "/{key}/pypi-tracks/{project}",
    context_path = "/api/v1/repositories",
    tag = "repositories",
    params(
        ("key" = String, Path, description = "Repository key"),
        ("project" = String, Path, description = "Project name (PEP 503 normalized server-side)"),
    ),
    request_body = PypiTrackRequest,
    security(("bearer_auth" = [])),
    responses(
        (status = 200, description = "tracks declaration stored", body = PypiTrackResponse),
        (status = 400, description = "Invalid request or repository type"),
        (status = 401, description = "Authentication required"),
        (status = 404, description = "Repository not found"),
    )
)]
pub async fn put_pypi_track(
    State(state): State<SharedState>,
    Extension(auth): Extension<Option<AuthExtension>>,
    Path((key, project)): Path<(String, String)>,
    Json(payload): Json<PypiTrackRequest>,
) -> Result<Json<PypiTrackResponse>> {
    let auth = require_auth(auth)?;
    auth.require_scope("write")?;
    let service = RepositoryService::new(state.db.clone());
    let repo = service.get_by_key(&key).await?;
    require_repo_write_access(&auth, &repo, &service).await?;
    require_pypi_tracks_repo(&repo)?;

    let tracks_url = payload.tracks_url.trim().to_string();
    if !(tracks_url.starts_with("http://") || tracks_url.starts_with("https://")) {
        return Err(AppError::Validation(
            "tracks_url must be an absolute http(s) URL".to_string(),
        ));
    }
    let normalized = crate::api::handlers::pypi::normalize_pep503(&project);
    if normalized.is_empty() {
        return Err(AppError::Validation("invalid project name".to_string()));
    }

    sqlx::query(
        "INSERT INTO pypi_project_tracks (repository_id, normalized_name, tracks_url, created_by) \
         VALUES ($1, $2, $3, $4) \
         ON CONFLICT (repository_id, normalized_name) \
         DO UPDATE SET tracks_url = EXCLUDED.tracks_url, created_by = EXCLUDED.created_by",
    )
    .bind(repo.id)
    .bind(&normalized)
    .bind(&tracks_url)
    .bind(auth.user_id)
    .execute(&state.db)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;

    Ok(Json(PypiTrackResponse {
        repository_key: key,
        normalized_name: normalized,
        tracks_url,
    }))
}

/// Remove a PEP 708 `tracks` declaration, restoring local-precedence isolation
/// for that project name (#1600).
#[utoipa::path(
    delete,
    path = "/{key}/pypi-tracks/{project}",
    context_path = "/api/v1/repositories",
    tag = "repositories",
    params(
        ("key" = String, Path, description = "Repository key"),
        ("project" = String, Path, description = "Project name (PEP 503 normalized server-side)"),
    ),
    security(("bearer_auth" = [])),
    responses(
        (status = 204, description = "tracks declaration removed (idempotent)"),
        (status = 401, description = "Authentication required"),
        (status = 404, description = "Repository not found"),
    )
)]
pub async fn delete_pypi_track(
    State(state): State<SharedState>,
    Extension(auth): Extension<Option<AuthExtension>>,
    Path((key, project)): Path<(String, String)>,
) -> Result<axum::http::StatusCode> {
    let auth = require_auth(auth)?;
    auth.require_scope("write")?;
    let service = RepositoryService::new(state.db.clone());
    let repo = service.get_by_key(&key).await?;
    require_repo_write_access(&auth, &repo, &service).await?;

    let normalized = crate::api::handlers::pypi::normalize_pep503(&project);
    sqlx::query(
        "DELETE FROM pypi_project_tracks WHERE repository_id = $1 AND normalized_name = $2",
    )
    .bind(repo.id)
    .bind(&normalized)
    .execute(&state.db)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;

    Ok(axum::http::StatusCode::NO_CONTENT)
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
    let per_page = clamp_per_page(query.per_page);
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
        // Repo-scoped token: the listing must reflect ONLY the token's
        // allowed repositories, not every repo the owning user can reach.
        // Checked before the general `User` arm. Admin tokens are handled
        // above and bypass scope restrictions.
        Some(a) if matches!(a.allowed_repo_ids, AccessScope::Restricted(_)) => RepoVisibility::Ids(
            a.allowed_repo_ids
                .as_allowed_repo_ids()
                .unwrap_or_default()
                .to_vec(),
        ),
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
    body: Bytes,
) -> Result<Json<RepositoryResponse>> {
    // #1438 (1b): authenticate BEFORE deserializing the body. The previous
    // `Json<CreateRepositoryRequest>` extractor ran first and rejected
    // unauth requests carrying a payload the schema didn't recognize with
    // 400 VALIDATION_ERROR. Anonymous callers must see 401, not 400.
    let auth = require_auth(auth)?;
    auth.require_scope("write")?;

    let payload: CreateRepositoryRequest =
        serde_json::from_slice(&body).map_err(|e| AppError::Validation(e.to_string()))?;

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
    // Resolve the format string via the service. The service owns both the
    // built-in enum mapping and the `format_handlers` fallback for WASM
    // plugin formats, so the handler keeps no business logic of its own here.
    // For plugin formats, `plugin_format_key` carries the canonical handler
    // name and `format` is reported as `Generic`.
    let service = state.create_repository_service();
    let (format, plugin_format_key) = service.resolve_format(&payload.format).await?;
    let repo_type = parse_repo_type(&payload.repo_type)?;

    // Validate up-front that virtual repos do not arrive with an explicit
    // empty `member_repos: []`. Omitted-field (deferred-population) is
    // accepted so the create-then-add pattern works.
    // See `validate_virtual_repo_member_count` for the rationale (#1279, #1444).
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
            promotion_only: payload.promotion_only.unwrap_or(false),
            // Plugin format key takes precedence over any explicit format_key
            // in the payload: when a WASM plugin format was resolved above,
            // `plugin_format_key` carries the canonical handler name.
            format_key: plugin_format_key.or(payload.format_key),
            // Owner auto-grant: record the creator and grant them per-repo
            // access so they retain access under per-repo authorization.
            created_by: Some(auth.user_id),
        })
        .await?;

    if let Some(ref index_url) = payload.index_upstream_url {
        upsert_index_upstream_url(&state.db, repo.id, index_url).await?;
    }

    if let Some(ref index_path) = payload.pypi_upstream_index_path {
        upsert_repo_config(&state.db, repo.id, "pypi_upstream_index_path", index_path).await?;
    }

    // Add virtual repository members. Post-#1444, the validator accepts
    // `member_repos == None` (deferred-population pattern: caller will
    // POST /members later) and only rejects `Some(empty_vec)`. Treat the
    // None arm as a clean no-op here; the Some(non-empty) arm is the
    // create-with-members path and runs the original loop.
    if repo_type == RepositoryType::Virtual {
        if let Some(member_inputs) = payload.member_repos.as_deref() {
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
        } else {
            tracing::info!(
                repo_key = %repo.key,
                "Virtual repo created with no members; deferring to POST /members (#1444)"
            );
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
    require_visible(&repo, &auth, &service).await?;
    let storage_used = service.get_storage_usage(repo.id).await?;
    let auth_type =
        crate::services::upstream_auth::get_upstream_auth_type(&state.db, repo.id).await?;

    let repo_id = repo.id;
    let mut response = repo_to_response(repo, storage_used);
    response.upstream_auth_configured = auth_type.is_some();
    response.upstream_auth_type = auth_type;
    let response = with_quarantine_settings(&state.db, repo_id, response).await;
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
                promotion_only: payload.promotion_only,
            },
        )
        .await?;

    if let Some(ref index_url) = payload.index_upstream_url {
        upsert_index_upstream_url(&state.db, repo.id, index_url).await?;
    }

    if let Some(ref index_path) = payload.pypi_upstream_index_path {
        upsert_repo_config(&state.db, repo.id, "pypi_upstream_index_path", index_path).await?;
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

    // Any quarantine change must flush the resolve_config cache so it takes
    // effect immediately rather than after the short TTL.
    if payload.quarantine_enabled.is_some() || payload.quarantine_duration_minutes.is_some() {
        crate::services::quarantine_service::invalidate_config_cache(repo.id);
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

    // Invalidate the in-memory repo cache so that visibility changes take
    // effect immediately instead of waiting for the TTL to expire. Remove
    // both the old key and the new key (in case the key was renamed). This
    // must run AFTER every repository/config write above: evicting before
    // the repository_config upserts let a concurrent request repopulate the
    // entry with the old index_upstream_url mid-update. Cross-replica
    // eviction is handled by the migration-142 repository_changed trigger.
    {
        let mut cache = state.repo_cache.write().await;
        cache.remove(&key);
        cache.remove(&repo.key);
    }

    let storage_used = service.get_storage_usage(repo.id).await?;

    state.event_bus.emit_repository_event(
        "repository.updated",
        repo.id,
        Some(auth.username.clone()),
    );

    let repo_id = repo.id;
    let response = repo_to_response(repo, storage_used);
    let response = with_quarantine_settings(&state.db, repo_id, response).await;
    Ok(Json(response))
}

/// Batch size for [`collect_repo_oci_upload_temp_keys`]: the union of a
/// repository's cleanup-key/session/part storage keys is drained in bounded
/// chunks of this size instead of one unbounded query, so a repository with a
/// very large cleanup-key backlog cannot force a single pathological SELECT
/// (#1533 F2).
const OCI_UPLOAD_TEMP_KEY_BATCH: i64 = 1000;

/// Collect the storage keys of a repository's in-flight / abandoned OCI upload
/// temp objects: the `oci_upload_cleanup_keys` journal plus (belt-and-braces)
/// the session `storage_temp_key`s and per-part `storage_key`s, in case a
/// storage write predated its journal row.
///
/// This MUST run BEFORE the repository row is deleted. `oci_upload_cleanup_keys`
/// and `oci_upload_sessions` both `ON DELETE CASCADE` with `repositories` (and
/// `oci_upload_parts` cascades from the session), so once the repo row is gone
/// these rows are too and the storage keys are no longer discoverable. The
/// caller purges the returned keys from storage only AFTER a successful delete
/// (see [`purge_oci_upload_temp_objects`]), so a delete that fails leaves the
/// temp objects in place to be retried (#1533 GC-LOW-2).
///
/// The (deduplicated) union is drained with keyset pagination in bounded
/// batches of [`OCI_UPLOAD_TEMP_KEY_BATCH`] so a repository with a very large
/// backlog never issues one unbounded query (#1533 F2). A DB error is logged
/// and ends collection.
async fn collect_repo_oci_upload_temp_keys(state: &SharedState, repo_id: Uuid) -> Vec<String> {
    let mut keys: Vec<String> = Vec::new();
    // Keyset cursor over storage_key (unique within the union set); "" precedes
    // every real key ("oci-uploads/…"), so the first page starts at the top.
    let mut after = String::new();
    loop {
        let batch: Vec<String> = sqlx::query_scalar(
            "SELECT storage_key FROM ( \
                 SELECT storage_key FROM oci_upload_cleanup_keys WHERE repository_id = $1 \
                 UNION SELECT storage_temp_key FROM oci_upload_sessions WHERE repository_id = $1 \
                 UNION SELECT p.storage_key FROM oci_upload_parts p \
                   JOIN oci_upload_sessions s ON s.id = p.upload_session_id \
                  WHERE s.repository_id = $1 \
             ) AS temp_keys \
             WHERE storage_key > $2 \
             ORDER BY storage_key \
             LIMIT $3",
        )
        .bind(repo_id)
        .bind(&after)
        .bind(OCI_UPLOAD_TEMP_KEY_BATCH)
        .fetch_all(&state.db)
        .await
        .unwrap_or_else(|e| {
            tracing::warn!(
                repo_id = %repo_id,
                error = %e,
                "Failed to list OCI upload temp keys to purge for repository delete"
            );
            Vec::new()
        });
        let full_page = batch.len() as i64 == OCI_UPLOAD_TEMP_KEY_BATCH;
        if let Some(last) = batch.last() {
            after = last.clone();
        }
        keys.extend(batch);
        // A short (or empty) page means the backlog is drained.
        if !full_page {
            break;
        }
    }
    keys
}

/// Best-effort purge of a repository's in-flight / abandoned OCI upload temp
/// objects from storage, given the keys previously gathered by
/// [`collect_repo_oci_upload_temp_keys`].
///
/// Called AFTER a successful `service.delete(repo.id)`: purging only once the
/// delete has committed means a delete that fails does not prematurely destroy
/// an in-flight upload's temp objects while the repository survives (#1533
/// GC-LOW-2). Failures (storage resolution and per-object deletes) are logged
/// but never propagated — the repository is already gone.
async fn purge_oci_upload_temp_objects(
    state: &SharedState,
    repo_id: Uuid,
    location: &crate::storage::StorageLocation,
    keys: Vec<String>,
) {
    if keys.is_empty() {
        return;
    }
    let storage = match state.storage_for_repo(location) {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!(
                repo_id = %repo_id,
                error = %e,
                "Could not resolve storage to purge OCI upload temp objects after repository delete"
            );
            return;
        }
    };
    for key in keys {
        match storage.delete(&key).await {
            Ok(()) | Err(AppError::NotFound(_)) => {}
            Err(e) => tracing::warn!(
                repo_id = %repo_id,
                storage_key = %key,
                error = %e,
                "Failed to purge OCI upload temp object after repository delete"
            ),
        }
    }
}

/// Best-effort deletion of a repository's committed artifact objects from the
/// storage backend, called BEFORE the repository row (and its cascading
/// `artifacts` rows) are deleted. Without this, deleting a repository left
/// every stored object orphaned on the backend, most visibly on S3 where the
/// bytes simply stayed in the bucket with nothing referencing them (#1551).
///
/// Only objects owned *exclusively* by this repository are removed: a
/// `storage_key` still referenced by another repository's artifact row
/// (content-addressed dedup can share a key across repos on a shared backend)
/// is left in place, so deleting one repository never destroys another's data.
///
/// OCI objects (`oci-manifests/<digest>` and `oci-blobs/<digest>`) are
/// intentionally OUT of scope here and are excluded from the purge SELECT.
/// They are content-addressed and shared cross-repo through their own
/// reference tables (`oci_tags`, `oci_blobs`, `oci_manifest_refs`), and a
/// manifest object can be referenced by another repository WITHOUT a matching
/// `artifacts` row — so the `artifacts`-only `NOT EXISTS` guard above cannot
/// prove an OCI key is unreferenced. On cloud backends (S3/GCS/Azure) every
/// repository shares one flat global keyspace (no per-repo path isolation),
/// so deleting an OCI key here would destroy a manifest/blob another repo is
/// still serving (regression from #1598; filesystem hid it via per-repo path
/// isolation). OCI reclamation is owned by blob GC, which applies the
/// authoritative `ORPHAN_PREDICATE_SQL` test; once this repository's
/// `oci_tags`/`oci_manifest_refs`/`oci_blobs` rows CASCADE away, any object
/// they alone referenced becomes orphaned and is reclaimed on the next GC pass.
///
/// Never blocks the delete: storage-resolution and per-object failures are
/// logged and swallowed.
async fn purge_repo_artifact_objects(
    state: &SharedState,
    repo_id: Uuid,
    location: &crate::storage::StorageLocation,
) {
    let storage = match state.storage_for_repo(location) {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!(
                repo_id = %repo_id,
                error = %e,
                "Could not resolve storage to purge artifact objects before repository delete"
            );
            return;
        }
    };

    let keys: Vec<String> = sqlx::query_scalar(
        "SELECT DISTINCT a.storage_key FROM artifacts a \
         WHERE a.repository_id = $1 \
           AND a.storage_key NOT LIKE 'oci-manifests/%' \
           AND a.storage_key NOT LIKE 'oci-blobs/%' \
           AND NOT EXISTS ( \
               SELECT 1 FROM artifacts b \
               WHERE b.storage_key = a.storage_key AND b.repository_id <> $1 \
           )",
    )
    .bind(repo_id)
    .fetch_all(&state.db)
    .await
    .unwrap_or_else(|e| {
        tracing::warn!(
            repo_id = %repo_id,
            error = %e,
            "Failed to list artifact storage keys to purge before repository delete"
        );
        Vec::new()
    });

    let total = keys.len();
    let mut failed = 0usize;
    for key in keys {
        match storage.delete(&key).await {
            Ok(()) | Err(AppError::NotFound(_)) => {}
            Err(e) => {
                failed += 1;
                tracing::warn!(
                    repo_id = %repo_id,
                    storage_key = %key,
                    error = %e,
                    "Failed to purge artifact object before repository delete"
                );
            }
        }
    }
    if total > 0 {
        tracing::info!(
            repo_id = %repo_id,
            purged = total - failed,
            failed,
            "Purged artifact storage objects for deleted repository"
        );
    }
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

    // Gather this repo's in-flight / abandoned OCI upload temp storage keys
    // BEFORE the repository row is deleted — the journal/session/part rows
    // CASCADE away with it, so the keys must be captured up front. The actual
    // storage purge is deferred until AFTER a successful delete (below) so a
    // failed delete does not prematurely destroy temp objects the surviving
    // repository may still retry (#1533 GC-LOW-2). Best-effort throughout.
    let oci_upload_temp_keys = collect_repo_oci_upload_temp_keys(&state, repo.id).await;

    // Purge this repo's committed artifact objects from storage BEFORE the
    // repository row is deleted (the artifacts rows CASCADE away with it). The
    // DB delete alone left every stored object orphaned on S3/filesystem
    // (#1551). Best-effort: never blocks the delete.
    purge_repo_artifact_objects(&state, repo.id, &repo.storage_location()).await;

    // Purge this repo's proxy-cache subtree from the global default storage
    // backend. Proxy-cached blobs are keyed by the repo KEY and are not tracked
    // in `artifacts` (#1278), so the purge above never reaches them; left
    // behind, a new repository created with the same key would serve the deleted
    // repo's stale upstream content (#2047). Best-effort: never blocks the
    // delete. Hosted repos have no proxy cache, so this is a no-op for them.
    if let Some(proxy) = state.proxy_service.as_ref() {
        match proxy.purge_repo_cache(&repo.key).await {
            Ok(purged) if purged > 0 => tracing::info!(
                repo_id = %repo.id,
                repo_key = %repo.key,
                purged,
                "Purged proxy-cache storage objects for deleted repository"
            ),
            Ok(_) => {}
            Err(e) => tracing::warn!(
                repo_id = %repo.id,
                repo_key = %repo.key,
                error = %e,
                "Failed to list proxy-cache objects to purge before repository delete"
            ),
        }
    }

    service.delete(repo.id).await?;

    // The repository row is now gone (and its OCI upload journal/session/part
    // rows CASCADED away). Only now purge the temp objects gathered above from
    // storage: had the delete failed, this is skipped and the objects survive
    // to be retried (#1533 GC-LOW-2). Best-effort: never blocks.
    purge_oci_upload_temp_objects(
        &state,
        repo.id,
        &repo.storage_location(),
        oci_upload_temp_keys,
    )
    .await;

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
    /// Whether this artifact can have an SBOM generated or a security scan
    /// run against it. `false` for proxy-cached (Remote) objects: those are
    /// listed with a synthetic, SHA-256-derived id (see
    /// [`cached_artifact_id`]) and have no row in the `artifacts` table
    /// (#1280/#1278), so SBOM/scan lookups by `artifacts.id` cannot resolve
    /// them and `sbom_documents`/`scan_results` cannot reference them.
    /// `true` for hosted artifacts, which carry a real DB id. The web UI
    /// uses this to hide/disable the "Generate SBOM" / "Scan" actions where
    /// they cannot work; clients that predate the field should treat an
    /// absent value as `true` so hosted artifacts are never hidden. (#2227)
    pub analyzable: bool,
    /// When the proxy cache entry for this artifact was last written.
    /// Only populated for Remote (proxy) repositories whose proxy service is
    /// configured AND that have a cache-metadata blob for this path. None
    /// for Local / Virtual / Staging repos and for Remote repos whose cache
    /// hasn't been populated yet (e.g. an artifact that exists as a DB row
    /// from a direct upload but has never been fetched through the proxy).
    /// (#1541)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cache_cached_at: Option<chrono::DateTime<chrono::Utc>>,
    /// When the proxy cache entry for this artifact will expire and be
    /// re-validated against upstream. Same gating as `cache_cached_at`. (#1541)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cache_expires_at: Option<chrono::DateTime<chrono::Utc>>,
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
    /// Rolled-up scan status across all scanners configured for this
    /// artifact. `None` when the artifact has never been scanned.
    ///
    /// Values surface the aggregate state, not a single scanner's row
    /// (see #1497). One of:
    ///
    /// * `pending` / `running` -- at least one scanner is still in flight
    /// * `completed` -- every per-scan-type latest row is `completed`
    /// * `failed` -- every per-scan-type latest row is `failed`
    /// * `partial` -- mixed: at least one `completed` AND at least one
    ///   `failed`. A green generic scanner (e.g. grype) no longer hides
    ///   a failed format-native scanner (e.g. incus) behind a
    ///   `completed` label.
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
    // Clamp per_page to [1, 100]: a `per_page=0` query previously slipped past
    // the `.min(100)` upper bound and reached the `total_pages` divisions
    // below as a divide-by-zero, saturating `total_pages` to u32::MAX for any
    // non-empty repo (#1571). The lower bound makes both the DB and the
    // proxy-cache listing branches well-defined.
    let per_page = query.per_page.unwrap_or(20).clamp(1, 100);
    let offset = ((page - 1) * per_page) as i64;

    let repo_service = RepositoryService::new(state.db.clone());
    let repo = repo_service.get_by_key(&key).await?;
    require_visible(&repo, &auth, &repo_service).await?;

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

    // Remote (proxy) repositories no longer record cached items in the
    // `artifacts` table (#1278 / #1280): doing so reintroduced a doubled-prefix
    // storage path bug on filesystem backends. The cached bodies and metadata
    // sidecars still live in the storage backend under `proxy-cache/<key>/`, so
    // the listing is reconstructed from there. Without this, packages pulled
    // through a remote repo fill up storage but never appear in the UI, so they
    // can't be browsed or scanned (#1548, web #424).
    if repo.repo_type == RepositoryType::Remote {
        return list_remote_cached_artifacts(
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

    // Legacy Maven/Gradle uploads used to group POM, sources, javadoc, and
    // other companion files under one artifact row in metadata.files (#1092).
    // New uploads store each Maven asset as its own `artifacts` row, but keep
    // this expansion so older repositories remain browsable after upgrade.
    //
    // Note for legacy rows: `pagination.total` is the number of artifact rows,
    // not the post-expansion item count. The items array can therefore exceed
    // `per_page` for a page that contains an old GAV-grouped row. Fresh Maven
    // uploads already have one row per physical asset and do not rely on this
    // compatibility expansion.
    let maven_files_by_artifact: std::collections::HashMap<Uuid, Vec<serde_json::Value>> =
        if is_maven_format {
            load_maven_secondary_files(&state.db, &artifact_ids).await
        } else {
            std::collections::HashMap::new()
        };
    let listed_maven_paths: std::collections::HashSet<String> = if is_maven_format {
        artifacts.iter().map(|a| a.path.clone()).collect()
    } else {
        std::collections::HashSet::new()
    };

    // For npm-family repos the artifact is stored under the
    // version-segmented layout `<name>/<version>/<name>-<version>.tgz`
    // (see `api::handlers::npm::store_npm_version`), but npm clients and
    // every external consumer reference tarballs by the download-URL
    // shape `<name>/-/<name>-<version>.tgz`. Surface the URL shape in the
    // listing's `path` so callers that resolve an artifact by the path
    // npm published (the management UI, SDKs, the release-gate real-flow
    // smoke test) match against the same string they downloaded from.
    // Lookup-by-path already accepts both shapes via
    // `normalize_lookup_path` (#1443); this keeps the listing consistent.
    let rewrite_npm_tarball_paths = is_npm_family_format(&repo.format);

    let mut items = Vec::new();
    for artifact in artifacts {
        let artifact_id = artifact.id;
        let download_count = *download_counts.get(&artifact_id).unwrap_or(&0);
        let mut item = build_artifact_response(&artifact, &key, download_count);
        if rewrite_npm_tarball_paths {
            apply_npm_tarball_url_path(&mut item);
        }
        items.push(item);

        if let Some(secondary) = maven_files_by_artifact.get(&artifact_id) {
            items.extend(expand_maven_secondary_files(
                &artifact,
                &key,
                secondary,
                &listed_maven_paths,
            ));
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

/// List the artifacts a remote (proxy) repository has cached.
///
/// Proxy-cached items are not in the `artifacts` table (#1280), so they are
/// reconstructed from the storage backend by [`ProxyService::list_cached_artifacts`].
/// Each entry is mapped to an [`ArtifactResponse`]; entries carry no DB id,
/// version, or download count, so those fields take their natural defaults
/// (a deterministic synthetic id derived from `repo_key + path`, `None`
/// version, zero downloads). Filtering and pagination happen in-process over
/// the recovered set, since there is no DB query to push them into. See #1548
/// and web #424.
async fn list_remote_cached_artifacts(
    state: &SharedState,
    repo: &crate::models::repository::Repository,
    key: &str,
    path_prefix: Option<&str>,
    q: Option<&str>,
    page: u32,
    per_page: u32,
) -> Result<Json<ArtifactListResponse>> {
    // Two-phase listing (#1571): first recover just the cached path strings
    // (no sidecar reads), filter + slice them to the requested page, and only
    // then load sidecars for that page. Both listing filters are path-based,
    // so paging on the paths is exact and avoids the previous O(N) sidecar
    // read on every request. The trade-off is that `total` counts paths whose
    // sidecar may since have gone missing (a half-written / legacy cache
    // write); such a path is still dropped from the returned page, matching
    // the old per-entry skip, but is no longer pre-excluded from the count —
    // an acceptable approximation in exchange for O(page) reads.
    let proxy = state.proxy_service.as_deref();
    let paths = match proxy {
        Some(proxy) => proxy.list_cached_paths(&repo.key).await,
        // No proxy service configured (e.g. proxying disabled): nothing cached.
        None => Vec::new(),
    };

    let (page_paths, total) = filter_and_paginate_paths(paths, path_prefix, q, page, per_page);
    let total_pages = cached_total_pages(total, per_page);

    let entries = match proxy {
        Some(proxy) => proxy.load_cached_entries(&repo.key, &page_paths).await,
        None => Vec::new(),
    };

    let items = entries
        .iter()
        .map(|entry| build_cached_artifact_response(entry, key))
        .collect();

    Ok(Json(ArtifactListResponse {
        items,
        pagination: Pagination {
            page,
            per_page,
            total: total as i64,
            total_pages,
        },
        components: None,
        docker_tags: None,
    }))
}

/// Apply the listing's `path_prefix` and `q` filters to the recovered proxy
/// cache **paths**, then return the slice for the requested page along with
/// the total match count.
///
/// `path_prefix` matches against the start of the logical path; `q` is a
/// case-insensitive substring match against the path. Both filters are
/// purely path-based, so this runs on the path strings alone and the caller
/// loads sidecars only for the returned page (#1571), instead of loading
/// every sidecar before slicing. `per_page` is treated as at least 1 so a
/// `per_page == 0` query cannot wedge pagination. Pure / unit-testable
/// without a storage backend.
fn filter_and_paginate_paths(
    paths: Vec<String>,
    path_prefix: Option<&str>,
    q: Option<&str>,
    page: u32,
    per_page: u32,
) -> (Vec<String>, usize) {
    let q_lower = q
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_lowercase);

    let mut matched: Vec<String> = paths
        .into_iter()
        .filter(|p| match path_prefix {
            Some(prefix) if !prefix.is_empty() => p.starts_with(prefix),
            _ => true,
        })
        .filter(|p| match &q_lower {
            Some(needle) => p.to_lowercase().contains(needle),
            None => true,
        })
        .collect();

    // Stable ordering for deterministic pagination across requests.
    matched.sort();

    let total = matched.len();
    let per_page = (per_page.max(1)) as usize;
    let offset = (page.saturating_sub(1) as usize).saturating_mul(per_page);
    let page_items = matched.into_iter().skip(offset).take(per_page).collect();
    (page_items, total)
}

/// Number of pages for a cached listing of `total` items at `per_page`.
///
/// Guards `per_page == 0` (a value a query can supply — the handler only caps
/// the upper bound) so the count cannot saturate to `u32::MAX` the way the
/// previous `((total as f64) / (per_page as f64)).ceil() as u32` did for any
/// non-empty repo (#1571). Pure / unit-testable.
fn cached_total_pages(total: usize, per_page: u32) -> u32 {
    let per_page = (per_page.max(1)) as usize;
    total.div_ceil(per_page) as u32
}

/// Deterministic artifact id for a proxy-cached object.
///
/// The `uuid` crate is built with only the `v4` feature, so a UUIDv5 is not
/// available. Instead the id is the first 16 bytes of a SHA-256 over the
/// cache storage key `proxy-cache/<repo_key>/<path>`. This is stable across
/// listing calls for a given object and effectively never collides with the
/// random v4 ids the database assigns to hosted artifacts.
fn cached_artifact_id(repo_key: &str, path: &str) -> Uuid {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(format!("proxy-cache/{}/{}", repo_key, path).as_bytes());
    let digest = hasher.finalize();
    let mut bytes = [0u8; 16];
    bytes.copy_from_slice(&digest[..16]);
    Uuid::from_bytes(bytes)
}

/// Map a recovered proxy cache entry to the listing's [`ArtifactResponse`].
///
/// The id is deterministic over `<repo_key>/<path>` (see
/// [`cached_artifact_id`]) so the same cached object always reports the same
/// id across listing calls (useful for client-side keying) without colliding
/// with the random v4 ids hosted artifacts get from the database.
fn build_cached_artifact_response(
    entry: &crate::services::proxy_service::CachedArtifactEntry,
    repo_key: &str,
) -> ArtifactResponse {
    let id = cached_artifact_id(repo_key, &entry.path);
    ArtifactResponse {
        id,
        repository_key: repo_key.to_string(),
        path: entry.path.clone(),
        name: entry.name.clone(),
        version: None,
        size_bytes: entry.size_bytes,
        checksum_sha256: entry.checksum_sha256.clone(),
        content_type: entry.content_type.clone(),
        download_count: 0,
        created_at: entry.cached_at,
        metadata: None,
        // Proxy-cached objects have no `artifacts` row (#1280/#1278) and a
        // synthetic id, so SBOM/scan cannot resolve them: not analyzable.
        analyzable: false,
        // This is a proxy-cache entry, so surface the cache timestamp.
        // CachedArtifactEntry carries no expiry, so cache_expires_at is None.
        cache_cached_at: Some(entry.cached_at),
        cache_expires_at: None,
    }
}

/// Build the `ArtifactResponse` representing a single primary artifact row.
///
/// Extracted from the inline listing loop so it can be unit-tested
/// without a database. Pure transformation of `Artifact` fields plus
/// the precomputed download count.
/// Return the ordered list of paths to try when looking up an artifact
/// by path under a repo of the given format.
///
/// The literal request path is always tried first so non-npm formats
/// and already-stored paths keep working unchanged. For npm-family
/// repos a second candidate is appended whenever the request path
/// matches the canonical npm tarball URL shape
/// (`<name>/-/<name>-<version>.tgz`); that second candidate is the
/// version-segmented stored shape produced by `store_npm_version`. See
/// #1443.
///
/// Returned without duplicates: if the literal path is already the
/// stored shape (or `normalize_lookup_path` returns the same string),
/// only one DB query runs.
fn lookup_path_candidates(path: &str, format: &RepositoryFormat) -> Vec<String> {
    let mut out = vec![path.to_string()];
    if is_npm_family_format(format) {
        if let Some(normalized) = crate::formats::npm::normalize_lookup_path(path) {
            if normalized != path {
                out.push(normalized);
            }
        }
    }
    out
}

/// Map a stored artifact path to the path the proxy cache is keyed under,
/// for the purpose of looking up cache-freshness metadata (#1541 follow-up).
///
/// npm-family tarballs are stored under the version-segmented layout
/// (`<name>/<version>/<file>.tgz`) by `npm::store_npm_version`, but the proxy
/// cached them under the upstream download-URL shape (`<name>/-/<file>.tgz`)
/// because `npm::serve_tarball` fetches via `build_tarball_upstream_path`.
/// Looking up cache metadata by the stored path therefore always missed.
/// Translating the stored tarball path back to the URL shape makes the cache
/// key match what the proxy wrote.
///
/// Returns the literal `path` unchanged for non-npm formats and for npm rows
/// that are not stored tarballs (metadata paths, raw uploads, paths already
/// in URL form) — `tarball_url_path_from_stored` returns `None` for those.
fn cache_metadata_lookup_path(path: &str, format: &RepositoryFormat) -> String {
    if is_npm_family_format(format) {
        if let Some(url_path) = crate::formats::npm::tarball_url_path_from_stored(path) {
            return url_path;
        }
    }
    path.to_string()
}

/// npm-family formats share the publish/download path conventions of
/// the npm registry (`yarn`, `pnpm`, and `bower` all wrap the same
/// upstream wire format). Keep this in sync with the `format` mapping
/// in `parse_format` and with the publish handler in
/// `api::handlers::npm`.
fn is_npm_family_format(format: &RepositoryFormat) -> bool {
    matches!(
        format,
        RepositoryFormat::Npm
            | RepositoryFormat::Yarn
            | RepositoryFormat::Bower
            | RepositoryFormat::Pnpm
    )
}

/// Try each candidate path in order, returning the first match. Skips
/// soft-deleted rows. Used by `get_artifact_metadata` so the npm
/// lookup-by-URL fallback only costs an extra DB roundtrip on a true
/// cache miss.
async fn lookup_artifact_by_paths(
    db: &sqlx::PgPool,
    repository_id: Uuid,
    candidates: &[String],
) -> Result<Option<crate::models::artifact::Artifact>> {
    for candidate in candidates {
        let found = sqlx::query_as!(
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
            repository_id,
            candidate
        )
        .fetch_optional(db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;
        if found.is_some() {
            return Ok(found);
        }
    }
    Ok(None)
}

/// Resolve a request path to the artifact's stored path for the generic
/// download/delete handlers.
///
/// npm publish stores tarballs under the version-segmented layout
/// (`<name>/<version>/<file>.tgz`, see `npm::store_npm_version`), while the Web
/// UI's Download/Delete buttons emit the canonical npm download-URL shape
/// (`<name>/-/<file>.tgz`). An exact-match `WHERE path = $2` lookup against the
/// URL shape therefore never finds the version-segmented row. This mirrors the
/// resolution `get_artifact_metadata` already performs: try the literal path
/// first, then the normalised stored shape for npm-family repos.
///
/// The extra DB roundtrip is taken only when a normalised candidate actually
/// exists (npm-family repo + the `/-/` URL shape): for non-npm formats and
/// already-stored npm paths `lookup_path_candidates` returns a single element,
/// so the guard short-circuits and behaviour is byte-identical to today. On a
/// true local miss the original `path` is returned unchanged, so Remote/Virtual
/// proxy fallback still fires against the original URL shape.
async fn resolve_stored_path(
    state: &SharedState,
    repo: &crate::models::repository::Repository,
    path: String,
) -> Result<String> {
    let candidates = lookup_path_candidates(&path, &repo.format);
    if candidates.len() > 1 {
        Ok(lookup_artifact_by_paths(&state.db, repo.id, &candidates)
            .await?
            .map(|a| a.path)
            .unwrap_or(path))
    } else {
        Ok(path)
    }
}

/// Rewrite an npm-family artifact listing row's `path` from the
/// version-segmented storage layout (`<name>/<version>/<file>.tgz`) to
/// the canonical npm download-URL shape (`<name>/-/<file>.tgz`).
///
/// No-op for any row whose path is not a stored npm tarball (metadata
/// rows, raw uploads, paths already in URL form), so the listing keeps
/// reporting those verbatim. See the real-flow-smoke follow-up to #1443:
/// callers resolve a tarball by the URL path they downloaded from, which
/// must match what the listing reports.
fn apply_npm_tarball_url_path(item: &mut ArtifactResponse) {
    if let Some(url_path) = crate::formats::npm::tarball_url_path_from_stored(&item.path) {
        item.path = url_path;
    }
}

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
        // Hosted artifact backed by a real `artifacts` row: SBOM/scan resolve.
        analyzable: true,
        // Cache metadata is surfaced only by the per-artifact metadata
        // endpoint to avoid fanning out a storage GET per artifact in
        // listings (#1541). Helpers used by listings leave these as None;
        // get_artifact_metadata populates them after the fact.
        cache_cached_at: None,
        cache_expires_at: None,
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
    listed_paths: &std::collections::HashSet<String>,
) -> Vec<ArtifactResponse> {
    let mut out = Vec::new();
    for f in secondary {
        let Some(fpath) = f.get("path").and_then(|v| v.as_str()) else {
            continue;
        };
        if fpath == artifact.path || listed_paths.contains(fpath) {
            // Skip the primary's own entry, and skip legacy metadata entries
            // once the same path exists as a real artifact row.
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
            // Secondary Maven files are recorded under a real primary
            // artifact row (its id), so they are analyzable like the primary.
            analyzable: true,
            cache_cached_at: None,
            cache_expires_at: None,
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

    // Remote (proxy) repositories do NOT record cached items in the `artifacts`
    // table (#1278 / #1280), so `artifact_service.list` returns nothing for them
    // and component grouping came back empty (#1999, regression in 1.2.1).
    // Proxy-cached Maven artifacts ARE indexed into the package catalog
    // (`packages` / `package_versions`, written by
    // `ProxyService::index_cached_package`), so reconstruct the component list
    // from there instead. Hosted/local/virtual grouping is unchanged below.
    if repo.repo_type == RepositoryType::Remote {
        let components = maven_components_from_catalog(
            &state.db,
            repo.id,
            repo_key,
            &format!("{:?}", repo.format).to_lowercase(),
            search_query,
        )
        .await?;
        return Ok(paginate_maven_components(components, page, per_page));
    }

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

    Ok(paginate_maven_components(components, page, per_page))
}

/// Paginate a fully-built list of Maven components into an
/// [`ArtifactListResponse`]. Shared by the hosted/local (artifacts-table) and
/// the remote/proxy (package-catalog) grouping paths so pagination math lives
/// in exactly one place.
fn paginate_maven_components(
    components: Vec<MavenComponentResponse>,
    page: u32,
    per_page: u32,
) -> Json<ArtifactListResponse> {
    let total_components = components.len() as i64;
    let total_pages = ((total_components as f64) / (per_page as f64)).ceil() as u32;
    let offset = ((page - 1) * per_page) as usize;
    let page_components: Vec<MavenComponentResponse> = components
        .into_iter()
        .skip(offset)
        .take(per_page as usize)
        .collect();

    Json(ArtifactListResponse {
        items: Vec::new(),
        pagination: Pagination {
            page,
            per_page,
            total: total_components,
            total_pages,
        },
        components: Some(page_components),
        docker_tags: None,
    })
}

/// Build the Maven component list for a remote/proxy repository from the
/// package catalog (#1999).
///
/// Proxy-cached Maven artifacts are indexed into `packages` /
/// `package_versions` with `packages.name = "groupId:artifactId"` (see
/// [`crate::services::proxy_service::maven_proxy_package_name`]). Each catalog
/// row maps to one [`MavenComponentResponse`]; rows whose name does not split
/// into `groupId:artifactId` are skipped defensively. Results are ordered by
/// name for a stable, paginatable list.
async fn maven_components_from_catalog(
    db: &sqlx::PgPool,
    repository_id: Uuid,
    repo_key: &str,
    format: &str,
    search_query: Option<&str>,
) -> Result<Vec<MavenComponentResponse>> {
    use sqlx::Row;

    let search_pattern = search_query.map(|q| format!("%{}%", q));

    let rows = sqlx::query(
        r#"
        SELECT p.id, p.name, p.version, p.size_bytes, p.download_count, p.created_at
        FROM packages p
        WHERE p.repository_id = $1
          AND ($2::text IS NULL OR p.name ILIKE $2)
        ORDER BY p.name ASC, p.version ASC
        "#,
    )
    .bind(repository_id)
    .bind(&search_pattern)
    .fetch_all(db)
    .await
    .map_err(|e| AppError::Internal(format!("Failed to list proxy package catalog: {e}")))?;

    let mut components = Vec::with_capacity(rows.len());
    for row in rows {
        let name: String = row.get("name");
        let Some((group_id, artifact_id)) = split_maven_catalog_name(&name) else {
            // Defensive: a catalog row not written by the proxy indexer (no
            // `groupId:artifactId` shape) cannot be rendered as a component.
            continue;
        };
        components.push(MavenComponentResponse {
            id: row.get("id"),
            group_id,
            artifact_id,
            version: row.get("version"),
            repository_key: repo_key.to_string(),
            format: format.to_string(),
            size_bytes: row.get("size_bytes"),
            download_count: row.get("download_count"),
            created_at: row.get("created_at"),
            artifact_files: Vec::new(),
        });
    }

    Ok(components)
}

/// Split a proxy package-catalog name (`groupId:artifactId`) back into its
/// `(groupId, artifactId)` parts (#1999). Returns `None` when the name has no
/// `:` separator or either side is empty, so a malformed/foreign catalog row is
/// skipped rather than rendered as a broken component. Maven artifactIds never
/// contain `:`, and groupIds use `.` separators, so the FIRST `:` is the split.
fn split_maven_catalog_name(name: &str) -> Option<(String, String)> {
    let (group_id, artifact_id) = name.split_once(':')?;
    if group_id.is_empty() || artifact_id.is_empty() {
        return None;
    }
    Some((group_id.to_string(), artifact_id.to_string()))
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

/// Collapse the set of per-scan-type latest statuses for an artifact into
/// a single rollup label (#1497).
///
/// The scan pipeline writes one `scan_results` row per (artifact,
/// scan_type) pair (grype, dependency-track, openscap, incus, ...).
/// Surfacing only the most-recent row's status silently masks a failed
/// format-native scanner whenever a generic scanner finishes after it,
/// which is a security-scanning gap (the operator sees `completed` and
/// concludes the artifact was fully scanned).
///
/// Precedence, applied in order:
///
/// 1. Empty input -> `None` (artifact has never been scanned).
/// 2. Any `running` -> `running` (in-flight beats anything terminal).
/// 3. Any `pending` -> `pending` (queued beats terminal).
/// 4. All `completed` -> `completed` (every configured scanner is green).
/// 5. All `failed` -> `failed` (every configured scanner errored out).
/// 6. Mixed terminal (at least one `completed` AND at least one `failed`)
///    -> `partial`. This is the case #1497 was filed for: a green grype
///    plus a failed incus scan now surfaces as `partial`, not
///    `completed`.
///
/// Unknown status strings are pessimistically treated as a failure for
/// the all-completed check (they will not collapse to `completed`).
pub(crate) fn rollup_scan_status(statuses: &[String]) -> Option<String> {
    if statuses.is_empty() {
        return None;
    }

    let mut has_running = false;
    let mut has_pending = false;
    let mut has_completed = false;
    let mut has_failed = false;
    let mut has_unknown = false;

    for s in statuses {
        match s.as_str() {
            "running" => has_running = true,
            "pending" => has_pending = true,
            "completed" => has_completed = true,
            "failed" => has_failed = true,
            _ => has_unknown = true,
        }
    }

    if has_running {
        return Some("running".to_string());
    }
    if has_pending {
        return Some("pending".to_string());
    }
    if has_completed && !has_failed && !has_unknown {
        return Some("completed".to_string());
    }
    if has_failed && !has_completed && !has_unknown {
        return Some("failed".to_string());
    }
    Some("partial".to_string())
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
    // Scan-status rollup (#1497): an artifact can have multiple scan_results
    // rows, one per scan_type (grype, dependency-track, openscap, incus,
    // ...). Previously this query returned only the most-recent row's
    // status via `ORDER BY created_at DESC LIMIT 1`, which silently masked
    // a failed format-native scanner whenever a generic scanner (e.g.
    // grype) finished after it. We now project per-scan-type latest rows
    // and aggregate their statuses with `array_agg(DISTINCT ...)`; the
    // Rust-side `rollup_scan_status` helper collapses the set into a
    // single label (`completed`, `partial`, `failed`, `running`,
    // `pending`) honoring the precedence in its doc comment.
    let sql = if search_query.is_some() {
        r#"SELECT
                a.id            AS artifact_id,
                t.name          AS image,
                t.tag           AS tag,
                t.manifest_digest AS manifest_digest,
                t.manifest_content_type AS manifest_content_type,
                a.size_bytes    AS manifest_size_bytes,
                t.updated_at    AS last_pushed_at,
                s.statuses      AS scan_statuses
            FROM oci_tags t
            JOIN artifacts a
              ON a.repository_id = t.repository_id
             AND a.path = 'v2/' || t.name || '/manifests/' || t.tag
             AND a.is_deleted = false
            LEFT JOIN LATERAL (
                SELECT array_agg(DISTINCT latest.status) AS statuses
                FROM (
                    SELECT DISTINCT ON (sr.scan_type)
                        sr.status
                    FROM scan_results sr
                    WHERE sr.artifact_id = a.id
                    ORDER BY sr.scan_type, sr.created_at DESC
                ) latest
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
                s.statuses      AS scan_statuses
            FROM oci_tags t
            JOIN artifacts a
              ON a.repository_id = t.repository_id
             AND a.path = 'v2/' || t.name || '/manifests/' || t.tag
             AND a.is_deleted = false
            LEFT JOIN LATERAL (
                SELECT array_agg(DISTINCT latest.status) AS statuses
                FROM (
                    SELECT DISTINCT ON (sr.scan_type)
                        sr.status
                    FROM scan_results sr
                    WHERE sr.artifact_id = a.id
                    ORDER BY sr.scan_type, sr.created_at DESC
                ) latest
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
            scan_status: rollup_scan_status(
                r.try_get::<Option<Vec<String>>, _>("scan_statuses")
                    .ok()
                    .flatten()
                    .as_deref()
                    .unwrap_or(&[]),
            ),
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
) -> Result<Response> {
    let repo_service = RepositoryService::new(state.db.clone());
    let repo = repo_service.get_by_key(&key).await?;
    require_visible(&repo, &auth, &repo_service).await?;

    let storage = state.storage_for_repo(&repo.storage_location())?;
    let artifact_service = ArtifactService::new(state.db.clone(), storage);

    // #1443: npm publish stores tarballs under
    // `<name>/<version>/<name>-<version>.tgz` (see
    // `api::handlers::npm::store_npm_version`), but external callers
    // (release-gate smoke test, JFrog/Artifactory-style consumers,
    // webhook payloads) carry the canonical npm download-URL shape
    // `<name>/-/<name>-<version>.tgz`. Without translating the request
    // path, an exact-match lookup against `artifacts.path` never finds
    // the row. Try the literal path first (so non-npm formats and
    // already-stored npm paths still work), then fall back to the
    // normalised stored shape for npm-family repos when the caller
    // handed us the URL shape.
    let candidates = lookup_path_candidates(&path, &repo.format);
    let direct = lookup_artifact_by_paths(&state.db, repo.id, &candidates).await?;

    if let Some(artifact) = direct {
        let downloads = artifact_service.get_download_stats(artifact.id).await?;
        let metadata = artifact_service.get_metadata(artifact.id).await?;

        // #1541: surface proxy cache freshness on Remote repos so the UI
        // can render "expires in 4 hours" / "expired" without a separate
        // round-trip. Single storage GET, gated on `repo.repo_type ==
        // Remote` AND `state.proxy_service.is_some()`. Tolerant of failure:
        // a missing or unreadable metadata blob is a normal state for an
        // artifact that has never been fetched through the proxy (e.g.
        // direct-uploaded into a Remote repo, edge case but observed),
        // so any error or `Ok(None)` collapses to None on both fields
        // rather than failing the whole metadata response.
        //
        // #1541 follow-up (npm path mismatch): npm-family tarballs are stored
        // under the version-segmented layout (`<name>/<version>/<file>.tgz`)
        // but the proxy cached them under the upstream download-URL shape
        // (`<name>/-/<file>.tgz`, see `npm::serve_tarball` ->
        // `build_tarball_upstream_path`). Keying the cache lookup on the
        // stored `artifact.path` therefore always missed, leaving the
        // freshness fields `None` even when a valid cache entry existed.
        // `cache_metadata_lookup_path` maps the stored path back to the URL
        // shape for npm-family tarballs so the cache key matches what the
        // proxy wrote.
        let cache_lookup_path = cache_metadata_lookup_path(&artifact.path, &repo.format);
        let cache_meta = if repo.repo_type == RepositoryType::Remote {
            if let Some(proxy) = state.proxy_service.as_ref() {
                proxy
                    .get_cache_metadata(&key, &cache_lookup_path)
                    .await
                    .ok()
                    .flatten()
            } else {
                None
            }
        } else {
            None
        };

        return Ok(Json(ArtifactResponse {
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
            // This handler resolves a real `artifacts` row by id, so it is
            // always a hosted artifact (analyzable), even inside a Remote repo.
            analyzable: true,
            cache_cached_at: cache_meta.as_ref().map(|m| m.cached_at),
            cache_expires_at: cache_meta.as_ref().map(|m| m.expires_at),
        })
        .into_response());
    }

    // B9 / #1221 / #1217: a virtual repository owns no `artifacts` rows of
    // its own -- its content lives in its member repositories. The generic
    // GET /:key/artifacts/*path route is the format-agnostic artifact-fetch
    // surface clients use to pull bytes through a virtual repo (the
    // virtual-shadowing-guard E2E fetches L's trusted artifact this way).
    // A virtual repo therefore has no direct row to describe, and returning
    // 404 here would make the local member's artifact unreachable through
    // the virtual. Resolve members in priority order and serve the winning
    // member's BYTES, applying the same local-over-remote shadowing guard
    // as `download_artifact`: if a non-Remote member owns the exact path,
    // suppress the proxy so a Remote member cannot shadow the trusted
    // local artifact.
    if repo.repo_type == RepositoryType::Virtual {
        let owns_locally = proxy_helpers::virtual_non_remote_owns_path(&state.db, repo.id, &path)
            .await
            .map_err(|_| AppError::Internal("virtual shadowing-guard query failed".to_string()))?;
        let proxy_for_virtual = if owns_locally {
            None
        } else {
            state.proxy_service.as_deref()
        };
        let db = state.db.clone();
        let path_clone = path.clone();
        let state_clone = state.clone();
        let result = proxy_helpers::resolve_virtual_download(
            &state.db,
            proxy_for_virtual,
            repo.id,
            &path,
            move |member_id, location| {
                let db = db.clone();
                let state = state_clone.clone();
                let p = path_clone.clone();
                async move {
                    proxy_helpers::local_fetch_by_path(&db, &state, member_id, &location, &p).await
                }
            },
        )
        .await
        .map_err(|_| {
            AppError::NotFound("Artifact not found in any member repository".to_string())
        })?;

        let ct = result
            .content_type
            .unwrap_or_else(|| "application/octet-stream".to_string());
        let filename = path.rsplit('/').next().unwrap_or(&path);

        // Stream the member's artifact body straight through instead of
        // buffering it; Content-Length comes from the resolved member's
        // size_bytes when known.
        let mut builder = Response::builder()
            .status(StatusCode::OK)
            .header(header::CONTENT_TYPE, ct)
            .header(
                header::CONTENT_DISPOSITION,
                format!("attachment; filename=\"{}\"", filename),
            )
            .header(
                header::HeaderName::from_static(X_ARTIFACT_STORAGE),
                "virtual",
            );
        if let Some(size) = result.content_length {
            builder = builder.header(header::CONTENT_LENGTH, size.to_string());
        }
        return Ok(builder.body(Body::from_stream(result.body)).unwrap());
    }

    Err(AppError::NotFound("Artifact not found".to_string()))
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
) -> Result<(StatusCode, Json<ArtifactResponse>)> {
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
    require_repo_write_access(&auth, &repo, &repo_service).await?;

    // Reject direct uploads to promotion-only repositories. Such repos accept
    // artifacts only via the promotion path (staging -> promotion -> approval);
    // the promotion service writes through its own path and is unaffected. This
    // applies to all callers including admins.
    if crate::api::handlers::proxy_helpers::promotion_only_blocks_direct_upload(
        repo.promotion_only,
        auth.is_admin,
    ) {
        return Err(AppError::Authorization(
            "Direct uploads are disabled for this repository; publish via promotion".to_string(),
        ));
    }

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

    // Content-Type resolution priority:
    //   1. WASM plugin metadata (format-aware)
    //   2. the request's declared Content-Type header (honour the client)
    //   3. mime_guess from the path extension
    let declared_content_type = headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok());
    let content_type = wasm_metadata
        .as_ref()
        .map(|m| m.content_type.clone())
        .unwrap_or_else(|| resolve_upload_content_type(declared_content_type, &path));

    // No pre-cleanup here: this generic upload endpoint (and the multipart
    // variants that delegate to it) persists through
    // `artifact_service::upload_with_sync_options`, whose release-immutability
    // backstop must SEE any soft-deleted tombstone at this coordinate — purging
    // it first would hide a release-immutability swap (DELETE + re-upload of
    // DIFFERENT bytes to a released coordinate, the exploited path). The
    // service's `ON CONFLICT (repository_id, path) DO UPDATE ... is_deleted =
    // false` resurrects the tombstone for the allowed cases (identical-bytes
    // republish / mutable index files), so the UNIQUE(repository_id, path)
    // constraint is still satisfied without the manual purge.

    let artifact = artifact_service
        .upload_with_sync_options(
            repo.id,
            &path,
            &name,
            version.as_deref(),
            &content_type,
            body,
            Some(auth.user_id),
            !is_replication_request(&headers),
        )
        .await?;

    let downloads = artifact_service.get_download_stats(artifact.id).await?;
    let metadata_json = wasm_metadata.map(|m| m.to_json());

    Ok((
        StatusCode::CREATED,
        Json(ArtifactResponse {
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
            // Freshly-uploaded hosted artifact with a real DB id: analyzable.
            analyzable: true,
            // Just-uploaded artifacts have no proxy cache state yet -- the
            // cache is populated lazily on the first proxy fetch.
            cache_cached_at: None,
            cache_expires_at: None,
        }),
    ))
}

/// Resolve the Content-Type for a generic artifact upload.
///
/// Honours a client-declared `Content-Type` header when it is a valid,
/// non-empty MIME type that is not a multipart wrapper (multipart only
/// describes the request envelope, not the stored object). Otherwise falls
/// back to guessing from the artifact path's file extension.
fn resolve_upload_content_type(declared: Option<&str>, path: &str) -> String {
    if let Some(raw) = declared {
        let trimmed = raw.trim();
        // Strip any `; charset=...` parameters for the multipart check, but
        // preserve the full declared value when we accept it.
        let base = trimmed.split(';').next().unwrap_or(trimmed).trim();
        if !base.is_empty()
            && base.contains('/')
            && !base.eq_ignore_ascii_case("multipart/form-data")
            && !base.to_ascii_lowercase().starts_with("multipart/")
        {
            return trimmed.to_string();
        }
    }
    mime_guess::from_path(path)
        .first_or_octet_stream()
        .to_string()
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
) -> Result<(StatusCode, Json<ArtifactResponse>)> {
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
) -> Result<(StatusCode, Json<ArtifactResponse>)> {
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
            #[allow(clippy::disallowed_methods)]
            // STREAMING-EXEMPT: upload handler buffers one bounded multipart field (capped by DefaultBodyLimit); tracked for incremental-hash put_stream conversion in a later #1608 phase
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
                #[allow(clippy::disallowed_methods)]
                // STREAMING-EXEMPT: upload handler buffers one bounded multipart field (capped by DefaultBodyLimit); tracked for incremental-hash put_stream conversion in a later #1608 phase
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

/// Derive the `Content-Disposition` filename for a downloaded artifact.
///
/// The browser-facing filename must be the basename of the requested artifact
/// path (e.g. `testpkg-1.0.0.tar.gz`), not the artifact's package `name`
/// (`testpkg`). This mirrors the virtual-repo download path, which already uses
/// `path.rsplit('/').next()`.
fn download_filename(path: &str) -> &str {
    path.rsplit('/')
        .next()
        .filter(|s| !s.is_empty())
        .unwrap_or(path)
}

/// Outcome of parsing an HTTP `Range` request header against a known total
/// size. We only support a single `bytes=start-end` range (the common case for
/// resumable downloads and media seeking); anything more exotic falls back to a
/// full-body 200 response.
#[derive(Debug, PartialEq, Eq)]
enum RangeOutcome {
    /// No `Range` header, or a header we choose not to honour: serve full 200.
    Full,
    /// A satisfiable single range, as inclusive `(start, end)` byte offsets.
    Satisfiable { start: u64, end: u64 },
    /// A syntactically valid `bytes=` range that lies outside `[0, total)`:
    /// the caller must answer 416 Range Not Satisfiable.
    Unsatisfiable,
}

/// Parse a single-range HTTP `Range` header value against `total` bytes.
///
/// Supports the three RFC 7233 single-range forms:
/// - `bytes=START-END`   (inclusive)
/// - `bytes=START-`      (START to end of resource)
/// - `bytes=-SUFFIX`     (final SUFFIX bytes)
///
/// Multi-range (`bytes=0-1,2-3`) and unparseable headers degrade to
/// [`RangeOutcome::Full`] rather than erroring, which is a valid server choice
/// per the spec. A `total` of 0 is always served as `Full`.
fn parse_byte_range(header_value: Option<&str>, total: u64) -> RangeOutcome {
    let value = match header_value {
        Some(v) => v.trim(),
        None => return RangeOutcome::Full,
    };
    if total == 0 {
        return RangeOutcome::Full;
    }
    let spec = match value.strip_prefix("bytes=") {
        Some(s) => s.trim(),
        None => return RangeOutcome::Full,
    };
    // Reject multi-range; we only honour a single range.
    if spec.contains(',') {
        return RangeOutcome::Full;
    }
    let (start_str, end_str) = match spec.split_once('-') {
        Some(parts) => parts,
        None => return RangeOutcome::Full,
    };
    let start_str = start_str.trim();
    let end_str = end_str.trim();

    let last = total - 1;
    match (start_str.is_empty(), end_str.is_empty()) {
        // `bytes=-SUFFIX`: final SUFFIX bytes.
        (true, false) => {
            let suffix: u64 = match end_str.parse() {
                Ok(n) => n,
                Err(_) => return RangeOutcome::Full,
            };
            if suffix == 0 {
                return RangeOutcome::Unsatisfiable;
            }
            let len = suffix.min(total);
            RangeOutcome::Satisfiable {
                start: total - len,
                end: last,
            }
        }
        // `bytes=START-`: START to end.
        (false, true) => {
            let start: u64 = match start_str.parse() {
                Ok(n) => n,
                Err(_) => return RangeOutcome::Full,
            };
            if start > last {
                return RangeOutcome::Unsatisfiable;
            }
            RangeOutcome::Satisfiable { start, end: last }
        }
        // `bytes=START-END`: explicit inclusive range.
        (false, false) => {
            let start: u64 = match start_str.parse() {
                Ok(n) => n,
                Err(_) => return RangeOutcome::Full,
            };
            let end: u64 = match end_str.parse() {
                Ok(n) => n,
                Err(_) => return RangeOutcome::Full,
            };
            if start > end || start > last {
                return RangeOutcome::Unsatisfiable;
            }
            RangeOutcome::Satisfiable {
                start,
                end: end.min(last),
            }
        }
        // `bytes=-` is malformed.
        (true, true) => RangeOutcome::Full,
    }
}

/// Adapt a byte stream so it yields only the inclusive `[start, end]` window,
/// skipping leading bytes and truncating trailing ones at chunk boundaries.
/// Used to satisfy a 206 Partial Content response without buffering the whole
/// artifact in memory.
fn slice_byte_stream(
    body: futures::stream::BoxStream<'static, Result<Bytes>>,
    start: u64,
    end: u64,
) -> futures::stream::BoxStream<'static, Result<Bytes>> {
    use futures::StreamExt;

    // Number of bytes to emit (inclusive range).
    let mut remaining = end - start + 1;
    // Number of leading bytes still to discard before the window begins.
    let mut to_skip = start;

    let stream = body.filter_map(move |chunk| {
        let out = match chunk {
            Ok(mut bytes) => {
                if to_skip > 0 {
                    let skip = (to_skip as usize).min(bytes.len());
                    let _ = bytes.split_to(skip);
                    to_skip -= skip as u64;
                }
                if remaining == 0 || bytes.is_empty() {
                    None
                } else {
                    let take = (remaining as usize).min(bytes.len());
                    let slice = bytes.split_to(take);
                    remaining -= take as u64;
                    Some(Ok(slice))
                }
            }
            Err(e) => Some(Err(e)),
        };
        async move { out }
    });
    stream.boxed()
}

/// Build a range-aware streaming download response, shared by the generic
/// artifact download and the format handlers (e.g. incus image download) so
/// every streaming download path honours HTTP `Range` identically (#1847).
///
/// `base_headers` are applied to the `200` and `206` responses; `416` carries
/// only `Accept-Ranges` and `Content-Range` (no body). The helper always
/// advertises `Accept-Ranges: bytes`, so clients know they may resume.
pub(crate) fn ranged_stream_response(
    range_header: Option<&str>,
    total: u64,
    body: futures::stream::BoxStream<'static, Result<Bytes>>,
    base_headers: Vec<(header::HeaderName, String)>,
) -> Result<Response> {
    let build_base = || {
        let mut b = Response::builder().header(header::ACCEPT_RANGES, "bytes");
        for (name, value) in &base_headers {
            b = b.header(name.clone(), value.clone());
        }
        b
    };
    let mk_err =
        |e: axum::http::Error| AppError::Internal(format!("failed to build response: {e}"));
    let response = match parse_byte_range(range_header, total) {
        RangeOutcome::Satisfiable { start, end } => {
            let len = end - start + 1;
            build_base()
                .status(StatusCode::PARTIAL_CONTENT)
                .header(header::CONTENT_LENGTH, len.to_string())
                .header(
                    header::CONTENT_RANGE,
                    format!("bytes {}-{}/{}", start, end, total),
                )
                .body(Body::from_stream(slice_byte_stream(body, start, end)))
                .map_err(mk_err)?
        }
        RangeOutcome::Unsatisfiable => Response::builder()
            .status(StatusCode::RANGE_NOT_SATISFIABLE)
            .header(header::ACCEPT_RANGES, "bytes")
            .header(header::CONTENT_RANGE, format!("bytes */{}", total))
            .body(Body::empty())
            .map_err(mk_err)?,
        RangeOutcome::Full => build_base()
            .status(StatusCode::OK)
            .header(header::CONTENT_LENGTH, total.to_string())
            .body(Body::from_stream(body))
            .map_err(mk_err)?,
    };
    Ok(response)
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
    // A HEAD request must return identical headers to GET but no body, and it
    // must close the connection. Without this flag the handler builds a
    // `Body::from_stream(..)` whose Content-Length advertises the full size
    // while no bytes are written, so HTTP/1.1 keep-alive clients block waiting
    // for a body that never arrives (the connection hangs).
    let is_head = request.method() == axum::http::Method::HEAD;

    let repo_service = RepositoryService::new(state.db.clone());
    let repo = repo_service.get_by_key(&key).await?;
    require_visible(&repo, &auth, &repo_service).await?;

    // Resolve the npm canonical `/-/` URL shape the Web UI emits to the
    // version-segmented path the tarball is actually stored under (#2269),
    // mirroring `get_artifact_metadata`. No-op for non-npm formats and for
    // paths that are already stored literally; on a local miss `path` is left
    // unchanged so the Remote/Virtual proxy fallback below still fires against
    // the original URL shape.
    let path = resolve_stored_path(&state, &repo, path).await?;

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
        .download_stream(
            repo.id,
            &path,
            auth.map(|a| a.user_id),
            Some(ip_addr.to_string()),
            user_agent.as_deref(),
        )
        .await;

    match download_result {
        Ok((artifact, body)) => {
            // Stream the body from storage instead of buffering it in memory
            // (#1608, Core Invariant ①). `size_bytes` gives an accurate
            // Content-Length.
            //
            // The `Content-Disposition` filename is the basename of the
            // requested path (e.g. `testpkg-1.0.0.tar.gz`), not the artifact's
            // package name — matching the virtual-repo download path.
            let total = artifact.size_bytes.max(0) as u64;
            let range_header = request
                .headers()
                .get(header::RANGE)
                .and_then(|v| v.to_str().ok());
            let checksum = artifact.checksum_sha256.trim().to_string();
            // `artifacts.checksum_sha256` is a CHAR(64) column, so Postgres
            // blank-pads shorter values on read; trim before emitting so the
            // header carries the bare checksum.

            // Shared range-aware streaming (#1847): one primitive serves the
            // 200 / 206 / 416 cases for both this generic path and the format
            // handlers (e.g. incus image download).
            let base_headers = vec![
                (header::CONTENT_TYPE, artifact.content_type),
                (
                    header::CONTENT_DISPOSITION,
                    format!("attachment; filename=\"{}\"", download_filename(&path)),
                ),
                (
                    header::HeaderName::from_static("x-checksum-sha256"),
                    checksum,
                ),
                (
                    header::HeaderName::from_static(X_ARTIFACT_STORAGE),
                    "proxy".to_string(),
                ),
            ];
            let response = ranged_stream_response(range_header, total, body, base_headers)?;
            Ok(response)
        }
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
            // Virtual repo: try each member in priority order.
            //
            // Shadowing guard (B9): the generic-format download keys on the
            // exact stored path. If a non-Remote member of this virtual repo
            // owns the path, suppress the proxy service so Remote members are
            // Skip'd and cannot shadow the local artifact. Without this a
            // Remote member earlier in priority order that returns a 200 for
            // the same path (catch-all upstream, or a different object at
            // that path) would win the first-`Ok` race and serve the wrong
            // or empty bytes, while a guarded format handler would 404-refuse.
            let owns_locally =
                proxy_helpers::virtual_non_remote_owns_path(&state.db, repo.id, &path)
                    .await
                    .map_err(|_| {
                        AppError::Internal("virtual shadowing-guard query failed".to_string())
                    })?;
            let proxy_for_virtual = if owns_locally {
                None
            } else {
                state.proxy_service.as_deref()
            };
            let db = state.db.clone();
            let path_clone = path.clone();
            let result = proxy_helpers::resolve_virtual_download(
                &state.db,
                proxy_for_virtual,
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

            let ct = result
                .content_type
                .unwrap_or_else(|| "application/octet-stream".to_string());
            let filename = path.rsplit('/').next().unwrap_or(&path);

            let mut builder = Response::builder()
                .status(StatusCode::OK)
                .header(header::CONTENT_TYPE, ct)
                .header(
                    header::CONTENT_DISPOSITION,
                    format!("attachment; filename=\"{}\"", filename),
                )
                .header(
                    header::HeaderName::from_static(X_ARTIFACT_STORAGE),
                    "virtual",
                );
            if let Some(size) = result.content_length {
                builder = builder.header(header::CONTENT_LENGTH, size.to_string());
            }
            let body = if is_head {
                Body::empty()
            } else {
                Body::from_stream(result.body)
            };
            Ok(builder.body(body).unwrap())
        }
        Err(e) => Err(e),
    }
}

/// Decide whether a delete of `(format, path)` must be refused to preserve
/// release immutability.
///
/// A delete is blocked when the coordinates classify as
/// [`cache_classifier::Mutability::Immutable`] (the same structural rule the
/// upload and proxy-cache paths use) and the caller is neither an admin nor a
/// *trusted* replication request. Admins keep an explicit retraction escape
/// hatch; replication must be able to mirror upstream deletes; mutable paths
/// (e.g. Maven SNAPSHOT directories, indexes) are always deletable.
///
/// `replication_trusted` must already fold in the caller's machine identity:
/// the raw replication request marker is a client-supplied header and so is
/// only honored here when it accompanies a trusted principal (admin or service
/// account). See [`replication_exemption_trusted`] and the call site in
/// [`delete_artifact`].
fn delete_blocked_by_immutability(
    format: &RepositoryFormat,
    path: &str,
    is_admin: bool,
    replication_trusted: bool,
) -> bool {
    !is_admin && !replication_trusted && cache_classifier::classify(format, path).is_immutable()
}

/// Whether the replication escape hatch on the immutability delete guard may be
/// honored for this request.
///
/// The replication marker itself is a client-supplied request header, so it is
/// forgeable by any authenticated caller. We therefore only treat it as a
/// genuine replication write when it accompanies a trusted machine identity —
/// an admin or a service account — which an ordinary human-user token cannot
/// assert. Genuine peer replication runs under such a token, so legitimate
/// mirroring of upstream immutable-artifact deletes is preserved.
fn replication_exemption_trusted(
    is_replication: bool,
    is_admin: bool,
    is_service_account: bool,
) -> bool {
    is_replication && (is_admin || is_service_account)
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
        (status = 409, description = "Artifact is immutable (released) and cannot be deleted"),
    )
)]
pub async fn delete_artifact(
    State(state): State<SharedState>,
    Extension(auth): Extension<Option<AuthExtension>>,
    Path((key, path)): Path<(String, String)>,
    headers: HeaderMap,
) -> Result<()> {
    let auth = require_auth(auth)?;
    auth.require_scope("delete")?;
    let repo_service = RepositoryService::new(state.db.clone());
    let repo = repo_service.get_by_key(&key).await?;
    require_repo_write_access(&auth, &repo, &repo_service).await?;

    // Resolve the npm canonical `/-/` URL shape the Web UI emits to the
    // version-segmented path the tarball is actually stored under (#2269),
    // mirroring `get_artifact_metadata`. Done before the promotion-only /
    // immutability gates below so every gate, the delete query, and the
    // cache-invalidation all operate on one consistent, real artifact path.
    // No-op for non-npm formats and already-literal paths.
    let path = resolve_stored_path(&state, &repo, path).await?;

    // Promotion-only release repositories: a direct DELETE is the symmetric
    // mutation to the (already-gated) direct upload and would let a principal
    // with plain repo-write permanently destroy a released artifact, bypassing
    // the promotion/approval controls. Reject it for non-approvers. Admins are
    // the release-approvers (approve_promotion requires is_admin) and keep the
    // retraction escape hatch; trusted service accounts (e.g. peer replication)
    // are exempt too, mirroring the immutability guard's exemptions below. The
    // promotion service writes via its own RAW SQL path and is unaffected.
    if crate::api::handlers::proxy_helpers::promotion_only_blocks_direct_delete(
        repo.promotion_only,
        auth.is_admin || auth.is_service_account,
    ) {
        return Err(AppError::Authorization(
            "Direct deletes are disabled for this release repository; retract via an approver/promotion workflow".to_string(),
        ));
    }

    // Release immutability: a versioned (immutable) artifact must never be
    // mutated after publication. Deleting one would re-open its coordinates for
    // a different-bytes re-upload (the upload path already rejects an existing
    // immutable version at `artifact_service`), so refuse the delete here using
    // the SAME structural classification the proxy-cache and upload paths use.
    // Admins retain an explicit escape hatch for genuine retractions; mutable
    // paths (e.g. Maven SNAPSHOT directories) are unaffected.
    //
    // The replication exemption must reflect a real machine identity, not just
    // the client-supplied replication header (which any caller can forge).
    // Genuine peer replication runs under a service-account or admin peer token,
    // so only honor the exemption when the header accompanies such a principal.
    // The raw `is_replication` marker is still used below purely for sync-loop
    // suppression, where its semantics are unchanged.
    let is_replication = is_replication_request(&headers);
    let replication_trusted =
        replication_exemption_trusted(is_replication, auth.is_admin, auth.is_service_account);
    if delete_blocked_by_immutability(&repo.format, &path, auth.is_admin, replication_trusted) {
        return Err(AppError::Conflict(
            "Cannot delete an immutable/released artifact".to_string(),
        ));
    }

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

    artifact_service
        .delete_with_sync_options(artifact, !is_replication)
        .await?;

    // Deleting a Maven artifact changes the version set for its GAV, so drop
    // any cached maven-metadata.xml for it; otherwise a GET within the 60s TTL
    // would keep listing the just-removed version.
    if repo.format == RepositoryFormat::Maven {
        if let Ok(coords) = MavenHandler::parse_coordinates(&path) {
            crate::api::handlers::maven::invalidate_maven_metadata_cache(
                repo.id,
                &coords.group_id,
                &coords.artifact_id,
            )
            .await;
        }
    }

    // Deleting an npm artifact changes the packument, so drop the computed
    // packument cache for its package — including in every virtual repo that
    // serves this one; otherwise a warm virtual-repo GET keeps listing the
    // just-removed version for the whole fresh window (#2162).
    if repo.format == RepositoryFormat::Npm {
        if let Some(package) = crate::api::handlers::npm::npm_package_name_from_artifact_path(&path)
        {
            crate::api::handlers::npm::invalidate_packument_caches(
                &state, repo.id, &repo.key, package,
            )
            .await;
        }
    }

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
    authorize_virtual_member_mutation(
        &auth,
        &virtual_repo,
        &member_repo,
        "add",
        &state.permission_service,
    )
    .await?;

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
    authorize_virtual_member_mutation(
        &auth,
        &virtual_repo,
        &member_repo,
        "remove",
        &state.permission_service,
    )
    .await?;

    // Delegate to the service, which scopes the DELETE to the single
    // (virtual_repo_id, member_repo_id) row and returns `AppError::NotFound`
    // (HTTP 404) when no row matched. Routing through the service keeps a
    // single source of truth for the delete predicate so this handler cannot
    // drift back to a virtual-repo-id-only DELETE that would empty every
    // member (B1), and gives the repeat-delete-of-an-already-removed-member
    // path its 404 instead of a misleading 200 (B3).
    service
        .remove_virtual_member(virtual_repo.id, member_repo.id)
        .await?;

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
        authorize_virtual_member_mutation(
            &auth,
            &virtual_repo,
            &member_repo,
            "update",
            &state.permission_service,
        )
        .await?;

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
    // updates every matching row, or fails and updates none.
    //
    // The service runs the UPDATE inside a transaction that first takes the
    // process-wide member-graph advisory lock (B2). Without that lock, two
    // concurrent PUTs over an overlapping member set acquire row locks in
    // planner-scan order and can deadlock on the shared row, which Postgres
    // only breaks after `deadlock_timeout`; under a race loop that surfaces
    // as multi-second stalls that exhaust the client timeout. The lock
    // serialises every member-graph mutation so the UPDATEs never contend.
    //
    // RETURNING gives us the set of member_repo_ids that actually matched
    // the (virtual_repo_id, member_repo_id) predicate. If that set is
    // smaller than the input set, some member row was deleted between the
    // resolve pass and the UPDATE (TOCTOU), and we surface a 404 listing
    // the missing keys so the caller can retry with a fresh resolution.
    let updated = service
        .update_virtual_member_priorities(virtual_repo.id, &resolved_member_ids, &priorities)
        .await?;

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
    let repo_service = RepositoryService::new(state.db.clone());
    require_repo_write_access(&auth, &repo, &repo_service).await?;

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
    let repo_service = RepositoryService::new(state.db.clone());
    require_visible(&repo, &Some(auth.clone()), &repo_service).await?;

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
    require_repo_write_access(&auth, &repo, &service).await?;

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
    require_repo_write_access(&auth, &repo, &service).await?;

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
        list_pypi_tracks,
        put_pypi_track,
        delete_pypi_track,
        get_cache_ttl,
        invalidate_cache,
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
        InvalidateCacheQuery,
        InvalidateCacheResponse,
        PypiTrackRequest,
        PypiTrackResponse,
        PypiTracksListResponse,
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

#[allow(clippy::disallowed_methods)]
// streaming-invariant: test module exempt — buffering response bodies in test assertions is not an artifact path (#1608)
#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::AppError;

    // -----------------------------------------------------------------------
    // Content-Disposition filename derivation (#1785) — the download filename
    // must be the basename of the requested path, not the package name.
    // -----------------------------------------------------------------------

    #[test]
    fn download_filename_uses_path_basename() {
        assert_eq!(
            download_filename("testpkg/1.0.0/testpkg-1.0.0.tar.gz"),
            "testpkg-1.0.0.tar.gz"
        );
    }

    #[test]
    fn download_filename_handles_flat_path() {
        assert_eq!(download_filename("plainfile.bin"), "plainfile.bin");
    }

    #[test]
    fn download_filename_handles_trailing_slash() {
        // A trailing slash would otherwise yield an empty basename; fall back
        // to the full path rather than emitting an empty filename.
        assert_eq!(download_filename("a/b/"), "a/b/");
    }

    // -----------------------------------------------------------------------
    // Proxy package-catalog component grouping (#1999)
    // -----------------------------------------------------------------------

    #[test]
    fn split_maven_catalog_name_splits_group_and_artifact() {
        assert_eq!(
            split_maven_catalog_name("org.apache.commons:commons-lang3"),
            Some((
                "org.apache.commons".to_string(),
                "commons-lang3".to_string()
            ))
        );
    }

    #[test]
    fn split_maven_catalog_name_rejects_missing_separator() {
        assert!(split_maven_catalog_name("commons-lang3").is_none());
    }

    #[test]
    fn split_maven_catalog_name_rejects_empty_sides() {
        assert!(split_maven_catalog_name(":commons-lang3").is_none());
        assert!(split_maven_catalog_name("org.apache:").is_none());
        assert!(split_maven_catalog_name(":").is_none());
    }

    #[test]
    fn split_maven_catalog_name_uses_first_colon() {
        // groupId uses dot separators and artifactId has no colon, so any
        // extra colon (defensive) is folded into the artifactId.
        assert_eq!(
            split_maven_catalog_name("g:a:b"),
            Some(("g".to_string(), "a:b".to_string()))
        );
    }

    fn maven_component(group: &str, artifact: &str) -> MavenComponentResponse {
        MavenComponentResponse {
            id: Uuid::new_v4(),
            group_id: group.to_string(),
            artifact_id: artifact.to_string(),
            version: "1.0.0".to_string(),
            repository_key: "maven-proxy".to_string(),
            format: "maven".to_string(),
            size_bytes: 10,
            download_count: 0,
            created_at: chrono::Utc::now(),
            artifact_files: Vec::new(),
        }
    }

    #[test]
    fn paginate_maven_components_reports_total_and_page() {
        let comps = vec![
            maven_component("g", "a"),
            maven_component("g", "b"),
            maven_component("g", "c"),
        ];
        let resp = paginate_maven_components(comps, 1, 2).0;
        assert_eq!(resp.pagination.total, 3);
        assert_eq!(resp.pagination.total_pages, 2);
        assert_eq!(resp.components.as_ref().unwrap().len(), 2);
        assert!(resp.items.is_empty());
        assert!(resp.docker_tags.is_none());
    }

    #[test]
    fn paginate_maven_components_second_page_has_remainder() {
        let comps = vec![
            maven_component("g", "a"),
            maven_component("g", "b"),
            maven_component("g", "c"),
        ];
        let resp = paginate_maven_components(comps, 2, 2).0;
        assert_eq!(resp.components.as_ref().unwrap().len(), 1);
        assert_eq!(resp.components.as_ref().unwrap()[0].artifact_id, "c");
    }

    #[test]
    fn paginate_maven_components_empty_catalog() {
        let resp = paginate_maven_components(Vec::new(), 1, 20).0;
        assert_eq!(resp.pagination.total, 0);
        assert_eq!(resp.pagination.total_pages, 0);
        assert!(resp.components.as_ref().unwrap().is_empty());
    }

    // -----------------------------------------------------------------------
    // HTTP Range parsing (#1785) — `Range: bytes=...` must produce 206 with the
    // correct window, 416 for out-of-bounds, and degrade to a full 200 for
    // multi-range / unparseable headers.
    // -----------------------------------------------------------------------

    #[test]
    fn range_none_is_full() {
        assert_eq!(parse_byte_range(None, 100), RangeOutcome::Full);
    }

    #[test]
    fn range_explicit_inclusive() {
        assert_eq!(
            parse_byte_range(Some("bytes=0-1023"), 102_624),
            RangeOutcome::Satisfiable {
                start: 0,
                end: 1023
            }
        );
    }

    #[test]
    fn range_open_ended_start() {
        assert_eq!(
            parse_byte_range(Some("bytes=500-"), 1000),
            RangeOutcome::Satisfiable {
                start: 500,
                end: 999
            }
        );
    }

    #[test]
    fn range_suffix() {
        assert_eq!(
            parse_byte_range(Some("bytes=-200"), 1000),
            RangeOutcome::Satisfiable {
                start: 800,
                end: 999
            }
        );
    }

    #[test]
    fn range_suffix_larger_than_total_clamps() {
        assert_eq!(
            parse_byte_range(Some("bytes=-5000"), 1000),
            RangeOutcome::Satisfiable { start: 0, end: 999 }
        );
    }

    #[test]
    fn range_end_clamped_to_last_byte() {
        assert_eq!(
            parse_byte_range(Some("bytes=0-9999"), 1000),
            RangeOutcome::Satisfiable { start: 0, end: 999 }
        );
    }

    #[test]
    fn range_start_past_end_is_unsatisfiable() {
        assert_eq!(
            parse_byte_range(Some("bytes=2000-"), 1000),
            RangeOutcome::Unsatisfiable
        );
        assert_eq!(
            parse_byte_range(Some("bytes=2000-3000"), 1000),
            RangeOutcome::Unsatisfiable
        );
    }

    #[test]
    fn range_inverted_is_unsatisfiable() {
        assert_eq!(
            parse_byte_range(Some("bytes=500-100"), 1000),
            RangeOutcome::Unsatisfiable
        );
    }

    #[test]
    fn range_multi_range_degrades_to_full() {
        assert_eq!(
            parse_byte_range(Some("bytes=0-10,20-30"), 1000),
            RangeOutcome::Full
        );
    }

    #[test]
    fn range_unparseable_degrades_to_full() {
        assert_eq!(
            parse_byte_range(Some("seconds=0-10"), 1000),
            RangeOutcome::Full
        );
        assert_eq!(
            parse_byte_range(Some("bytes=abc-def"), 1000),
            RangeOutcome::Full
        );
        assert_eq!(parse_byte_range(Some("bytes=-"), 1000), RangeOutcome::Full);
    }

    #[test]
    fn range_on_empty_resource_is_full() {
        assert_eq!(parse_byte_range(Some("bytes=0-10"), 0), RangeOutcome::Full);
    }

    #[tokio::test]
    async fn slice_byte_stream_yields_only_window() {
        use futures::StreamExt;
        // Three chunks spanning bytes 0..9: "ab" "cdef" "ghij".
        let chunks: Vec<Result<Bytes>> = vec![
            Ok(Bytes::from_static(b"ab")),
            Ok(Bytes::from_static(b"cdef")),
            Ok(Bytes::from_static(b"ghij")),
        ];
        let body = futures::stream::iter(chunks).boxed();
        // Request bytes 3..=6 inclusive => "defg".
        let sliced = slice_byte_stream(body, 3, 6);
        let collected: Vec<u8> = sliced
            .filter_map(|r| async move { r.ok() })
            .collect::<Vec<_>>()
            .await
            .concat();
        assert_eq!(collected, b"defg");
    }

    // -----------------------------------------------------------------------
    // Remote proxy-cache listing (#1548, web #424)
    // -----------------------------------------------------------------------

    // -----------------------------------------------------------------------
    // Peer replication request detection (#1565) — incoming peer writes must be
    // detected so the local delete/sync path does not re-replicate back to the
    // origin peer (delete-loop prevention).
    // -----------------------------------------------------------------------

    fn headers_with_replication(value: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(
            "x-artifact-keeper-replication",
            axum::http::HeaderValue::from_str(value).unwrap(),
        );
        headers
    }

    #[test]
    fn test_is_replication_request_missing_header_is_false() {
        assert!(!is_replication_request(&HeaderMap::new()));
    }

    #[test]
    fn test_is_replication_request_accepts_truthy_values() {
        for value in ["true", "TRUE", "True", "1", "yes", "YES"] {
            assert!(
                is_replication_request(&headers_with_replication(value)),
                "expected {value:?} to be treated as a replication request"
            );
        }
    }

    #[test]
    fn test_is_replication_request_rejects_falsey_values() {
        for value in ["false", "0", "no", "", "maybe", "truthy"] {
            assert!(
                !is_replication_request(&headers_with_replication(value)),
                "expected {value:?} to NOT be treated as a replication request"
            );
        }
    }

    fn make_cached_entry(path: &str) -> crate::services::proxy_service::CachedArtifactEntry {
        crate::services::proxy_service::CachedArtifactEntry {
            path: path.to_string(),
            name: path.rsplit('/').next().unwrap_or(path).to_string(),
            size_bytes: 1234,
            checksum_sha256: "deadbeef".to_string(),
            content_type: "application/octet-stream".to_string(),
            cached_at: chrono::Utc::now(),
        }
    }

    fn paths(items: &[&str]) -> Vec<String> {
        items.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn test_filter_and_paginate_paths_returns_all_sorted() {
        let input = paths(&["lodash/-/lodash-4.17.21.tgz", "is-odd/-/is-odd-3.0.1.tgz"]);
        let (page, total) = filter_and_paginate_paths(input, None, None, 1, 20);
        assert_eq!(total, 2);
        assert_eq!(page.len(), 2);
        // Sorted by path.
        assert_eq!(page[0], "is-odd/-/is-odd-3.0.1.tgz");
        assert_eq!(page[1], "lodash/-/lodash-4.17.21.tgz");
    }

    #[test]
    fn test_filter_and_paginate_paths_applies_path_prefix() {
        let input = paths(&["lodash/-/lodash-4.17.21.tgz", "is-odd/-/is-odd-3.0.1.tgz"]);
        let (page, total) = filter_and_paginate_paths(input, Some("lodash/"), None, 1, 20);
        assert_eq!(total, 1);
        assert_eq!(page.len(), 1);
        assert_eq!(page[0], "lodash/-/lodash-4.17.21.tgz");
    }

    #[test]
    fn test_filter_and_paginate_paths_applies_case_insensitive_query() {
        let input = paths(&["lodash/-/lodash-4.17.21.tgz", "is-odd/-/is-odd-3.0.1.tgz"]);
        let (page, total) = filter_and_paginate_paths(input, None, Some("IS-ODD"), 1, 20);
        assert_eq!(total, 1);
        assert_eq!(page[0], "is-odd/-/is-odd-3.0.1.tgz");
    }

    #[test]
    fn test_filter_and_paginate_paths_paginates() {
        let input = paths(&["a", "b", "c"]);
        let (page2, total) = filter_and_paginate_paths(input, None, None, 2, 2);
        assert_eq!(total, 3);
        // page size 2, page 2 -> just "c"
        assert_eq!(page2.len(), 1);
        assert_eq!(page2[0], "c");
    }

    #[test]
    fn test_filter_and_paginate_paths_per_page_zero_does_not_wedge() {
        // Regression for #1571: a `per_page=0` query must not panic or produce
        // a degenerate empty page; per_page is treated as at least 1.
        let input = paths(&["a", "b", "c"]);
        let (page1, total) = filter_and_paginate_paths(input, None, None, 1, 0);
        assert_eq!(total, 3);
        assert_eq!(page1, vec!["a".to_string()]);
    }

    #[test]
    fn test_cached_total_pages_guards_per_page_zero() {
        // Regression for #1571: the previous `(total as f64 / per_page as f64)
        // .ceil() as u32` returned u32::MAX (saturated infinity) when per_page
        // was 0 for a non-empty repo. The guarded version returns a sane count.
        assert_eq!(cached_total_pages(5, 0), 5);
        assert_eq!(cached_total_pages(0, 0), 0);
        // Normal ceil-division behaviour is preserved.
        assert_eq!(cached_total_pages(10, 3), 4);
        assert_eq!(cached_total_pages(9, 3), 3);
        assert_eq!(cached_total_pages(0, 20), 0);
    }

    #[test]
    fn test_build_cached_artifact_response_maps_fields_and_is_deterministic() {
        let entry = make_cached_entry("express/-/express-4.18.2.tgz");
        let resp = build_cached_artifact_response(&entry, "npm-remote");
        assert_eq!(resp.repository_key, "npm-remote");
        assert_eq!(resp.path, "express/-/express-4.18.2.tgz");
        assert_eq!(resp.name, "express-4.18.2.tgz");
        assert_eq!(resp.size_bytes, 1234);
        assert_eq!(resp.checksum_sha256, "deadbeef");
        assert_eq!(resp.download_count, 0);
        assert!(resp.version.is_none());
        // Proxy-cached objects have no `artifacts` row and a synthetic id,
        // so they cannot be SBOM'd or scanned: the listing marks them
        // non-analyzable so the UI hides those actions (#2227).
        assert!(!resp.analyzable);
        // A cached-listing entry is a live proxy-cache object, so its
        // freshness timestamp is exactly when it was cached; the sidecar
        // projection carries no expiry. (Asserting these guards the
        // #1542/#1567 field-collision regression that broke the build.)
        assert_eq!(resp.cache_cached_at, Some(entry.cached_at));
        assert!(resp.cache_expires_at.is_none());
        // Same repo_key + path always yields the same id.
        let resp2 = build_cached_artifact_response(&entry, "npm-remote");
        assert_eq!(resp.id, resp2.id);
        // Different path yields a different id.
        let other = make_cached_entry("express/-/express-4.18.3.tgz");
        assert_ne!(
            resp.id,
            build_cached_artifact_response(&other, "npm-remote").id
        );
    }

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
        // Hosted artifacts have a real DB id, so SBOM/scan resolve: analyzable.
        assert!(resp.analyzable);
    }

    // -----------------------------------------------------------------------
    // apply_npm_tarball_url_path: the listing rewrite that lets npm clients
    // (and the release-gate real-flow smoke test) resolve a tarball by the
    // `<name>/-/<file>.tgz` URL path they downloaded from, even though it is
    // stored under `<name>/<version>/<file>.tgz`. Follow-up to #1443.
    // -----------------------------------------------------------------------

    #[test]
    fn test_apply_npm_tarball_url_path_rewrites_stored_tarball() {
        let a = make_artifact_for_test("rfs-pkg/1.0.5/rfs-pkg-1.0.5.tgz");
        let mut resp = build_artifact_response(&a, "rfs-npm", 0);
        apply_npm_tarball_url_path(&mut resp);
        assert_eq!(resp.path, "rfs-pkg/-/rfs-pkg-1.0.5.tgz");
    }

    #[test]
    fn test_apply_npm_tarball_url_path_rewrites_scoped_stored_tarball() {
        let a = make_artifact_for_test("@angular/core/17.0.0/core-17.0.0.tgz");
        let mut resp = build_artifact_response(&a, "npm-hosted", 0);
        apply_npm_tarball_url_path(&mut resp);
        assert_eq!(resp.path, "@angular/core/-/core-17.0.0.tgz");
    }

    #[test]
    fn test_apply_npm_tarball_url_path_noop_for_metadata_row() {
        // Non-tarball rows (a bare package metadata path) are left verbatim.
        let a = make_artifact_for_test("rfs-pkg/package.json");
        let mut resp = build_artifact_response(&a, "rfs-npm", 0);
        apply_npm_tarball_url_path(&mut resp);
        assert_eq!(resp.path, "rfs-pkg/package.json");
    }

    #[test]
    fn test_apply_npm_tarball_url_path_idempotent_on_url_shape() {
        // A path already in the `/-/` URL shape must not be rewritten again.
        let a = make_artifact_for_test("rfs-pkg/-/rfs-pkg-1.0.5.tgz");
        let mut resp = build_artifact_response(&a, "rfs-npm", 0);
        apply_npm_tarball_url_path(&mut resp);
        assert_eq!(resp.path, "rfs-pkg/-/rfs-pkg-1.0.5.tgz");
    }

    #[test]
    fn test_is_npm_family_format_covers_npm_aliases() {
        assert!(is_npm_family_format(&RepositoryFormat::Npm));
        assert!(is_npm_family_format(&RepositoryFormat::Yarn));
        assert!(is_npm_family_format(&RepositoryFormat::Bower));
        assert!(is_npm_family_format(&RepositoryFormat::Pnpm));
        assert!(!is_npm_family_format(&RepositoryFormat::Maven));
        assert!(!is_npm_family_format(&RepositoryFormat::Cargo));
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
        let rows = expand_maven_secondary_files(
            &primary,
            "maven-hosted",
            &secondary,
            &std::collections::HashSet::new(),
        );
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
        let rows = expand_maven_secondary_files(
            &primary,
            "maven-hosted",
            &secondary,
            &std::collections::HashSet::new(),
        );
        assert!(rows.is_empty());
    }

    #[test]
    fn test_expand_maven_secondary_files_skips_real_artifact_rows() {
        let primary = make_artifact_for_test("com/example/demo/1.0.0/demo-1.0.0.jar");
        let real_path = "com/example/demo/1.0.0/demo-1.0.0.pom".to_string();
        let secondary = vec![serde_json::json!({
            "path": real_path,
            "extension": "pom",
            "sizeBytes": 200,
            "sha256": "pom-sha",
        })];
        let listed_paths = std::collections::HashSet::from([real_path]);
        let rows =
            expand_maven_secondary_files(&primary, "maven-hosted", &secondary, &listed_paths);
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
        let rows = expand_maven_secondary_files(
            &primary,
            "k",
            &secondary,
            &std::collections::HashSet::new(),
        );
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].path, "p/demo.pom");
    }

    #[test]
    fn test_expand_maven_secondary_files_handles_missing_size_and_sha() {
        let primary = make_artifact_for_test("p/demo.jar");
        let secondary = vec![serde_json::json!({"path": "p/demo.pom", "extension": "pom"})];
        let rows = expand_maven_secondary_files(
            &primary,
            "k",
            &secondary,
            &std::collections::HashSet::new(),
        );
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
            allowed_repo_ids: AccessScope::Admin,
            iat_ms: None,
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
            promotion_only: false,
            storage_used_bytes: 1024,
            quota_bytes: Some(1048576),
            upstream_url: None,
            upstream_auth_type: None,
            upstream_auth_configured: false,
            quarantine_enabled: None,
            quarantine_duration_minutes: None,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        };
        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains("\"key\":\"my-repo\""));
        assert!(json.contains("\"storage_used_bytes\":1024"));
        assert!(json.contains("\"quota_bytes\":1048576"));
        assert!(json.contains("\"allow_anonymous_access\":true"));
        assert!(json.contains("\"promotion_only\":false"));
    }

    #[test]
    fn test_create_repository_request_promotion_only_deserialization() {
        let json = r#"{
            "key": "maven-releases",
            "name": "Maven Releases",
            "format": "maven",
            "repo_type": "local",
            "promotion_only": true
        }"#;
        let req: CreateRepositoryRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.promotion_only, Some(true));
    }

    #[test]
    fn test_create_repository_request_promotion_only_defaults_none() {
        let json = r#"{
            "key": "k",
            "name": "n",
            "format": "npm",
            "repo_type": "local"
        }"#;
        let req: CreateRepositoryRequest = serde_json::from_str(json).unwrap();
        assert!(req.promotion_only.is_none());
    }

    #[test]
    fn test_update_repository_request_promotion_only_deserialization() {
        let json = r#"{"promotion_only": true}"#;
        let req: UpdateRepositoryRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.promotion_only, Some(true));
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

    // -----------------------------------------------------------------------
    // rollup_scan_status (#1497)
    // -----------------------------------------------------------------------

    fn s(v: &str) -> String {
        v.to_string()
    }

    #[test]
    fn test_rollup_scan_status_empty_returns_none() {
        // Never scanned -> no rollup.
        assert_eq!(rollup_scan_status(&[]), None);
    }

    #[test]
    fn test_rollup_scan_status_all_completed_returns_completed() {
        // Every configured scanner finished cleanly -> green rollup.
        let statuses = vec![s("completed"), s("completed")];
        assert_eq!(rollup_scan_status(&statuses).as_deref(), Some("completed"));
    }

    #[test]
    fn test_rollup_scan_status_all_failed_returns_failed() {
        // Every configured scanner errored out -> hard failure.
        let statuses = vec![s("failed"), s("failed")];
        assert_eq!(rollup_scan_status(&statuses).as_deref(), Some("failed"));
    }

    #[test]
    fn test_rollup_scan_status_mixed_completed_and_failed_returns_partial() {
        // The #1497 regression case: incus (format-native) failed, grype
        // completed. Pre-fix this surfaced as `completed` and the operator
        // had no visible signal that the rootfs scan was skipped. Post-fix
        // it must surface as `partial` so the UI/CLI/release-gate can flag
        // the silent gap.
        let statuses = vec![s("completed"), s("failed")];
        assert_eq!(rollup_scan_status(&statuses).as_deref(), Some("partial"));
    }

    #[test]
    fn test_rollup_scan_status_mixed_with_running_returns_running() {
        // An in-flight scan beats anything terminal so the UI does not
        // prematurely call a still-running set `partial`.
        let statuses = vec![s("completed"), s("failed"), s("running")];
        assert_eq!(rollup_scan_status(&statuses).as_deref(), Some("running"));
    }

    #[test]
    fn test_rollup_scan_status_pending_beats_terminal_only() {
        // pending beats completed/failed but loses to running (running ==
        // already started, pending == not yet started).
        let statuses = vec![s("completed"), s("pending")];
        assert_eq!(rollup_scan_status(&statuses).as_deref(), Some("pending"));

        let statuses = vec![s("pending"), s("running")];
        assert_eq!(rollup_scan_status(&statuses).as_deref(), Some("running"));
    }

    #[test]
    fn test_rollup_scan_status_single_completed_stays_completed() {
        // Only one scanner configured and it passed -> still `completed`.
        // Guards against an overly-strict rollup that demanded N>=2.
        let statuses = vec![s("completed")];
        assert_eq!(rollup_scan_status(&statuses).as_deref(), Some("completed"));
    }

    #[test]
    fn test_rollup_scan_status_single_failed_stays_failed() {
        let statuses = vec![s("failed")];
        assert_eq!(rollup_scan_status(&statuses).as_deref(), Some("failed"));
    }

    #[test]
    fn test_rollup_scan_status_unknown_status_collapses_to_partial() {
        // Pessimistic: an unrecognized status should NOT be allowed to
        // collapse the set to `completed`. Belt-and-braces against a
        // future scanner that writes a status value the rollup does not
        // yet know about.
        let statuses = vec![s("completed"), s("weird-state")];
        assert_eq!(rollup_scan_status(&statuses).as_deref(), Some("partial"));
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
            analyzable: true,
            cache_cached_at: None,
            cache_expires_at: None,
        };
        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains("\"download_count\":42"));
        assert!(json.contains("\"size_bytes\":1024"));
        // `analyzable` is always serialized (no serde skip) so clients can
        // gate the SBOM/Scan actions on it (#2227).
        assert!(json.contains("\"analyzable\":true"));
        // Cache fields are omitted when None so the wire shape stays the
        // same for non-Remote repos and for Remote repos without cache
        // metadata (#1541).
        assert!(!json.contains("cache_cached_at"));
        assert!(!json.contains("cache_expires_at"));
    }

    #[test]
    fn test_artifact_response_serialization_with_cache_metadata() {
        // (#1541) When populated -- which only happens for Remote repos
        // whose proxy is configured AND have a cache-metadata blob for
        // the path -- both timestamps appear as ISO-8601 strings so the
        // web client can render relative time without parsing custom
        // formats.
        let cached = chrono::DateTime::parse_from_rfc3339("2026-06-01T10:00:00Z")
            .unwrap()
            .with_timezone(&chrono::Utc);
        let expires = chrono::DateTime::parse_from_rfc3339("2026-06-02T10:00:00Z")
            .unwrap()
            .with_timezone(&chrono::Utc);

        let resp = ArtifactResponse {
            id: Uuid::new_v4(),
            repository_key: "pypi-remote".to_string(),
            path: "requests/requests-2.31.0-py3-none-any.whl".to_string(),
            name: "requests-2.31.0-py3-none-any.whl".to_string(),
            version: Some("2.31.0".to_string()),
            size_bytes: 62500,
            checksum_sha256: "deadbeef".to_string(),
            content_type: "application/octet-stream".to_string(),
            download_count: 0,
            created_at: cached,
            metadata: None,
            analyzable: false,
            cache_cached_at: Some(cached),
            cache_expires_at: Some(expires),
        };
        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains("\"cache_cached_at\":\"2026-06-01T10:00:00Z\""));
        assert!(json.contains("\"cache_expires_at\":\"2026-06-02T10:00:00Z\""));
    }

    #[test]
    fn get_artifact_metadata_populates_cache_fields_only_for_remote() {
        // (#1541) Structural assertion: the per-artifact metadata handler
        // must (a) gate the cache-metadata read on `repo.repo_type ==
        // RepositoryType::Remote`, (b) further guard on
        // `state.proxy_service.as_ref()` so a non-proxy deployment doesn't
        // panic, and (c) call the new public ProxyService method
        // `get_cache_metadata`. Pinning the source string here keeps the
        // cost-control invariant from quietly drifting if someone later
        // refactors the handler -- e.g. moving the storage GET ahead of
        // the type guard would silently fan out a per-list-item cost we
        // explicitly chose to avoid.
        //
        // The pattern is intentionally tolerant of `cargo fmt` reformatting
        // the chain across multiple lines, the way the proxy-service guard
        // in `invalidate_cache` has to be (#1539). We assert on the pieces,
        // not on a single multi-line string match.
        let source = include_str!("repositories.rs");

        // Find the body of the get_artifact_metadata handler (between its
        // `pub async fn get_artifact_metadata(` opener and the next
        // top-level `pub async fn` / `pub fn` / unindented `}` -- in
        // practice the upload_artifact attribute that follows).
        let start = source
            .find("pub async fn get_artifact_metadata(")
            .expect("get_artifact_metadata handler not found");
        let after = &source[start..];
        let end_rel = after
            .find("\n/// Upload artifact")
            .expect("expected upload_artifact doc-comment to terminate the handler");
        let body = &after[..end_rel];

        assert!(
            body.contains("RepositoryType::Remote"),
            "handler must gate cache lookup on RepositoryType::Remote"
        );
        assert!(
            body.contains("state.proxy_service.as_ref()"),
            "handler must guard on state.proxy_service.as_ref() before calling the proxy"
        );
        assert!(
            body.contains(".get_cache_metadata("),
            "handler must call ProxyService::get_cache_metadata"
        );
        assert!(
            body.contains("cache_cached_at:") && body.contains("cache_expires_at:"),
            "handler must populate both cache_cached_at and cache_expires_at"
        );
    }

    #[test]
    fn cache_metadata_lookup_path_maps_npm_stored_to_url_shape() {
        // (#1541 follow-up) The proxy caches npm tarballs under the upstream
        // download-URL shape, but the artifact row stores the version-
        // segmented shape. The cache lookup must translate so it hits.

        // Unscoped: stored `<name>/<version>/<file>.tgz` -> URL `<name>/-/<file>.tgz`.
        assert_eq!(
            cache_metadata_lookup_path("lodash/4.17.21/lodash-4.17.21.tgz", &RepositoryFormat::Npm),
            "lodash/-/lodash-4.17.21.tgz",
        );

        // Scoped: stored `@scope/name/<version>/<file>.tgz` -> URL `@scope/name/-/<file>.tgz`.
        assert_eq!(
            cache_metadata_lookup_path(
                "@types/node/20.1.0/node-20.1.0.tgz",
                &RepositoryFormat::Npm
            ),
            "@types/node/-/node-20.1.0.tgz",
        );

        // The whole npm family shares the convention.
        assert_eq!(
            cache_metadata_lookup_path(
                "left-pad/1.3.0/left-pad-1.3.0.tgz",
                &RepositoryFormat::Yarn
            ),
            "left-pad/-/left-pad-1.3.0.tgz",
        );
        assert_eq!(
            cache_metadata_lookup_path(
                "left-pad/1.3.0/left-pad-1.3.0.tgz",
                &RepositoryFormat::Pnpm
            ),
            "left-pad/-/left-pad-1.3.0.tgz",
        );
    }

    #[test]
    fn cache_metadata_lookup_path_is_identity_for_non_npm_and_non_tarball() {
        // Non-npm formats are never rewritten, even if the path happens to
        // look tarball-shaped.
        assert_eq!(
            cache_metadata_lookup_path("foo/1.0.0/foo-1.0.0.tgz", &RepositoryFormat::Maven),
            "foo/1.0.0/foo-1.0.0.tgz",
        );

        // npm rows that aren't stored tarballs (metadata, already-URL-shape,
        // raw uploads) fall through unchanged so we don't fabricate a key.
        assert_eq!(
            cache_metadata_lookup_path("lodash/package.json", &RepositoryFormat::Npm),
            "lodash/package.json",
        );
        assert_eq!(
            cache_metadata_lookup_path("lodash/-/lodash-4.17.21.tgz", &RepositoryFormat::Npm),
            "lodash/-/lodash-4.17.21.tgz",
        );
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
            promotion_only: false,
            replication_priority: ReplicationPriority::Immediate,
            curation_enabled: false,
            curation_source_repo_id: None,
            curation_target_repo_id: None,
            curation_default_action: "allow".to_string(),
            curation_sync_interval_secs: 3600,
            curation_auto_fetch: false,
            age_gate_enabled: false,
            age_gate_min_age_days: 7,
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
        // #1770 B: db-less `repo_to_response` leaves quarantine fields unset;
        // the handlers populate them from `repository_config`. Unset fields
        // are omitted from the JSON (serde skip).
        assert!(response.quarantine_enabled.is_none());
        assert!(response.quarantine_duration_minutes.is_none());
        let json = serde_json::to_string(&response).unwrap();
        assert!(!json.contains("quarantine_enabled"));
        assert!(!json.contains("quarantine_duration_minutes"));
    }

    #[test]
    fn test_repository_response_serializes_quarantine_when_set() {
        // #1770 B: when the handler populates the quarantine settings from
        // `repository_config`, they appear in the serialized detail response.
        let resp = RepositoryResponse {
            id: Uuid::new_v4(),
            key: "npm-age".to_string(),
            name: "npm-age".to_string(),
            description: None,
            format: "npm".to_string(),
            repo_type: "remote".to_string(),
            is_public: true,
            allow_anonymous_access: true,
            promotion_only: false,
            storage_used_bytes: 0,
            quota_bytes: None,
            upstream_url: Some("https://registry.npmjs.org".to_string()),
            upstream_auth_type: None,
            upstream_auth_configured: false,
            quarantine_enabled: Some(true),
            quarantine_duration_minutes: Some(525600),
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        };
        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains("\"quarantine_enabled\":true"));
        assert!(json.contains("\"quarantine_duration_minutes\":525600"));
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
            promotion_only: false,
            replication_priority: ReplicationPriority::OnDemand,
            curation_enabled: false,
            curation_source_repo_id: None,
            curation_target_repo_id: None,
            curation_default_action: "allow".to_string(),
            curation_sync_interval_secs: 3600,
            curation_auto_fetch: false,
            age_gate_enabled: false,
            age_gate_min_age_days: 7,
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
            promotion_only: false,
            replication_priority: ReplicationPriority::LocalOnly,
            curation_enabled: false,
            curation_source_repo_id: None,
            curation_target_repo_id: None,
            curation_default_action: "allow".to_string(),
            curation_sync_interval_secs: 3600,
            curation_auto_fetch: false,
            age_gate_enabled: false,
            age_gate_min_age_days: 7,
            created_at: now,
            updated_at: now,
        };

        let response = repo_to_response(repo, 1024 * 1024);
        assert_eq!(response.format, "docker");
        assert_eq!(response.repo_type, "virtual");
        assert_eq!(response.storage_used_bytes, 1024 * 1024);
    }

    #[test]
    fn test_repo_to_response_staging() {
        use crate::models::repository::{ReplicationPriority, Repository};

        let now = chrono::Utc::now();
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
            promotion_only: false,
            replication_priority: ReplicationPriority::Scheduled,
            curation_enabled: false,
            curation_source_repo_id: None,
            curation_target_repo_id: None,
            curation_default_action: "allow".to_string(),
            curation_sync_interval_secs: 3600,
            curation_auto_fetch: false,
            age_gate_enabled: false,
            age_gate_min_age_days: 7,
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
            allowed_repo_ids: AccessScope::from(repo_ids),
            iat_ms: None,
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
            promotion_only: false,
            replication_priority: ReplicationPriority::Scheduled,
            curation_enabled: false,
            curation_source_repo_id: None,
            curation_target_repo_id: None,
            curation_default_action: "allow".to_string(),
            curation_sync_interval_secs: 3600,
            curation_auto_fetch: false,
            age_gate_enabled: false,
            age_gate_min_age_days: 7,
            created_at: now,
            updated_at: now,
        }
    }

    /// A `PermissionService` backed by a lazily-connecting pool. The token-scope
    /// denial tests below reject before the privilege lookup runs, and the admin
    /// path short-circuits before any query, so this service is never asked to
    /// touch the database.
    fn lazy_perm_service() -> crate::services::permission_service::PermissionService {
        crate::services::permission_service::PermissionService::new(
            crate::api::handlers::test_db_helpers::lazy_pool(),
        )
    }

    /// Admin `AuthExtension` (unrestricted token-scope, is_admin = true).
    fn make_admin_ext() -> AuthExtension {
        AuthExtension {
            is_admin: true,
            ..make_auth_ext(None)
        }
    }

    #[tokio::test]
    async fn test_virtual_member_authz_access_to_parent_only_is_denied() {
        // Caller has token-scope to V but not M -> denied at the member-repo
        // token-scope check, before any privilege lookup.
        let virtual_id = Uuid::new_v4();
        let member_id = Uuid::new_v4();
        let v = make_repo_with_id(virtual_id, "v");
        let m = make_repo_with_id(member_id, "m");
        let ext = make_auth_ext(Some(vec![virtual_id]));
        let result =
            authorize_virtual_member_mutation(&ext, &v, &m, "add", &lazy_perm_service()).await;
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

    #[tokio::test]
    async fn test_virtual_member_authz_access_to_member_only_is_denied() {
        // Caller has token-scope to M but not V -> denied at the parent-repo
        // token-scope check, before any privilege lookup.
        let virtual_id = Uuid::new_v4();
        let member_id = Uuid::new_v4();
        let v = make_repo_with_id(virtual_id, "v");
        let m = make_repo_with_id(member_id, "m");
        let ext = make_auth_ext(Some(vec![member_id]));
        let result =
            authorize_virtual_member_mutation(&ext, &v, &m, "remove", &lazy_perm_service()).await;
        assert!(
            result.is_err(),
            "caller with access to member only must be denied"
        );
    }

    #[tokio::test]
    async fn test_virtual_member_authz_admin_short_circuits_with_no_db() {
        // Admins pass both token-scope (unrestricted) and the privilege gate
        // (is_admin short-circuit) without any database lookup.
        let virtual_id = Uuid::new_v4();
        let member_id = Uuid::new_v4();
        let v = make_repo_with_id(virtual_id, "v");
        let m = make_repo_with_id(member_id, "m");
        let ext = make_admin_ext();
        let result =
            authorize_virtual_member_mutation(&ext, &v, &m, "update", &lazy_perm_service()).await;
        assert!(
            result.is_ok(),
            "admin must be allowed via is_admin short-circuit with no DB: {:?}",
            result
        );
    }

    #[tokio::test]
    async fn test_virtual_member_authz_no_access_to_either_is_denied() {
        // Caller has token-scope to neither V nor M -> denied on parent first,
        // before any privilege lookup.
        let virtual_id = Uuid::new_v4();
        let member_id = Uuid::new_v4();
        let other = Uuid::new_v4();
        let v = make_repo_with_id(virtual_id, "v");
        let m = make_repo_with_id(member_id, "m");
        let ext = make_auth_ext(Some(vec![other]));
        let result =
            authorize_virtual_member_mutation(&ext, &v, &m, "add", &lazy_perm_service()).await;
        assert!(result.is_err());
    }

    #[test]
    fn test_member_mutation_admin_allowed_admin_passes() {
        // Admins are allowed regardless of an explicit repository:admin grant.
        assert!(member_mutation_admin_allowed(true, false));
        assert!(member_mutation_admin_allowed(true, true));
    }

    #[test]
    fn test_member_mutation_admin_allowed_nonadmin_needs_repo_admin() {
        // Non-admins are allowed only when they hold repository:admin.
        assert!(member_mutation_admin_allowed(false, true));
        assert!(!member_mutation_admin_allowed(false, false));
    }

    // -----------------------------------------------------------------------
    // xtenant-write-authz-systemic: behavioral coverage for the two shared
    // tenant gates (`require_repo_write_access` / `require_visible`) that every
    // repository sub-resource handler now routes through. The no-DB
    // short-circuits (token scope, public, admin, anonymous) run everywhere;
    // the per-repo role-assignment branch is exercised by the `*_db` tests,
    // which seed a real Postgres and skip cleanly when DATABASE_URL is unset
    // (the same `try_pool()` convention the virtual-member tests use).
    // -----------------------------------------------------------------------
    fn no_db_repo_service() -> RepositoryService {
        RepositoryService::new(crate::api::handlers::test_db_helpers::lazy_pool())
    }

    #[tokio::test]
    async fn test_require_repo_write_access_admin_short_circuits_no_db() {
        let repo = make_repo_with_id(Uuid::new_v4(), "globex-private");
        let res = require_repo_write_access(&make_admin_ext(), &repo, &no_db_repo_service()).await;
        assert!(
            res.is_ok(),
            "admin must pass the write gate via is_admin, no DB: {res:?}"
        );
    }

    #[tokio::test]
    async fn test_require_repo_write_access_public_allowed_no_db() {
        let repo = make_repo(true); // is_public = true
        let res =
            require_repo_write_access(&make_auth_ext(None), &repo, &no_db_repo_service()).await;
        assert!(
            res.is_ok(),
            "a public repo is writable past the gate, no DB: {res:?}"
        );
    }

    #[tokio::test]
    async fn test_require_repo_write_access_out_of_token_scope_denied_no_db() {
        // A repo-scoped token whose scope excludes this repo is denied before any
        // DB lookup (the `require_repo_access` token-scope gate).
        let repo = make_repo_with_id(Uuid::new_v4(), "globex-private");
        let auth = make_auth_ext(Some(vec![Uuid::new_v4()]));
        let res = require_repo_write_access(&auth, &repo, &no_db_repo_service()).await;
        assert!(
            matches!(res, Err(AppError::Authorization(_))),
            "a repo-scoped token must be denied write outside its scope: {res:?}"
        );
    }

    #[tokio::test]
    async fn test_require_visible_public_is_visible_to_anonymous_no_db() {
        let repo = make_repo(true);
        let res = require_visible(&repo, &None, &no_db_repo_service()).await;
        assert!(
            res.is_ok(),
            "public repos are visible to anonymous callers: {res:?}"
        );
    }

    #[tokio::test]
    async fn test_require_visible_private_hidden_from_anonymous_no_db() {
        let repo = make_repo_with_id(Uuid::new_v4(), "globex-private");
        let res = require_visible(&repo, &None, &no_db_repo_service()).await;
        assert!(
            matches!(res, Err(AppError::NotFound(_))),
            "private repos must be hidden (NotFound) from anonymous callers: {res:?}"
        );
    }

    #[tokio::test]
    async fn test_require_visible_out_of_token_scope_not_found_no_db() {
        let repo = make_repo_with_id(Uuid::new_v4(), "globex-private");
        let auth = make_auth_ext(Some(vec![Uuid::new_v4()]));
        let res = require_visible(&repo, &Some(auth), &no_db_repo_service()).await;
        assert!(
            matches!(res, Err(AppError::NotFound(_))),
            "a repo-scoped token must not see a repo outside its scope: {res:?}"
        );
    }

    #[tokio::test]
    async fn test_require_visible_admin_sees_private_no_db() {
        let repo = make_repo_with_id(Uuid::new_v4(), "globex-private");
        let res = require_visible(&repo, &Some(make_admin_ext()), &no_db_repo_service()).await;
        assert!(
            res.is_ok(),
            "admins see any repo via the is_admin short-circuit: {res:?}"
        );
    }

    /// DB-backed: a non-admin, unrestricted-scope session (the password/JWT shape
    /// the systemic fix targets) is DENIED write to a private repo it holds no
    /// role on, and granting a role lets it through. Skips with no DATABASE_URL.
    #[tokio::test]
    async fn test_require_repo_write_access_nonmember_denied_then_granted_db() {
        use crate::api::handlers::test_db_helpers as tdh;
        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let (user_id, username) = tdh::create_user(&pool).await;
        let (repo_id, key, _dir) = tdh::create_repo(&pool, "local", "pypi").await;
        let repo = make_repo_with_id(repo_id, &key); // is_public = false
        let ext = tdh::make_auth(user_id, &username);
        let svc = RepositoryService::new(pool.clone());

        let denied = require_repo_write_access(&ext, &repo, &svc).await;
        assert!(
            matches!(denied, Err(AppError::Authorization(_))),
            "non-member must be denied write on a private repo: {denied:?}"
        );

        tdh::grant_repo_access(&pool, repo_id, user_id).await;
        let allowed = require_repo_write_access(&ext, &repo, &svc).await;
        assert!(
            allowed.is_ok(),
            "a granted member must pass the write gate: {allowed:?}"
        );

        tdh::cleanup(&pool, repo_id, user_id).await;
    }

    // -----------------------------------------------------------------------
    // Release-immutability swap via DELETE + re-upload (the exploited endpoint).
    //
    // These drive the SAME `upload_artifact` / `delete_artifact` handlers the
    // generic repo-scoped `/repositories/{key}/artifacts/*path` route maps to —
    // the endpoint the red-team reproduction hits and which earlier fixes never
    // wired to the guard. DB-backed; skip cleanly when DATABASE_URL is unset.
    // -----------------------------------------------------------------------

    /// Upload a versioned artifact, DELETE it, then PUT DIFFERENT bytes to the
    /// same coordinate -> the re-upload MUST be rejected (409 Conflict). Covers
    /// a default-format (Generic) repo, proving the oracle protects coordinates
    /// the proxy-cache classifier alone treats as mutable.
    #[tokio::test]
    async fn delete_then_reupload_different_bytes_blocked_db() {
        use crate::api::handlers::test_db_helpers as tdh;
        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let (user_id, username) = tdh::create_user(&pool).await;
        let (repo_id, key, dir) = tdh::create_repo(&pool, "local", "generic").await;
        tdh::grant_repo_access(&pool, repo_id, user_id).await;
        let state = tdh::build_state(pool.clone(), dir.to_string_lossy().as_ref());
        let auth = Some(tdh::make_auth(user_id, &username));
        // {package}/{version}/{filename} -> a versioned release coordinate.
        let path = "app/1.0.0/app-1.0.0.bin".to_string();

        // 1) Initial publish.
        let up = upload_artifact(
            State(state.clone()),
            Extension(auth.clone()),
            Path((key.clone(), path.clone())),
            HeaderMap::new(),
            Bytes::from_static(b"ORIGINAL-RELEASE-BYTES"),
        )
        .await;
        assert!(up.is_ok(), "initial publish must succeed: {up:?}");

        // 2) DELETE (soft-delete -> tombstone). Generic classifies mutable, so
        // the delete guard permits this even for a non-admin.
        let del = delete_artifact(
            State(state.clone()),
            Extension(auth.clone()),
            Path((key.clone(), path.clone())),
            HeaderMap::new(),
        )
        .await;
        assert!(del.is_ok(), "delete of the release must succeed: {del:?}");

        // 3) Re-upload DIFFERENT bytes to the same coordinate -> the swap. MUST
        // be blocked by the release-immutability backstop.
        let swap = upload_artifact(
            State(state.clone()),
            Extension(auth.clone()),
            Path((key.clone(), path.clone())),
            HeaderMap::new(),
            Bytes::from_static(b"SWAPPED-MALICIOUS-BYTES"),
        )
        .await;
        assert!(
            matches!(swap, Err(AppError::Conflict(_))),
            "DELETE + re-upload of DIFFERENT bytes to a released coordinate must 409, got: {swap:?}"
        );

        // The stored content must remain the ORIGINAL (no swap occurred).
        let remaining = sqlx::query_scalar::<_, String>(
            "SELECT checksum_sha256 FROM artifacts \
             WHERE repository_id = $1 AND path = $2",
        )
        .bind(repo_id)
        .bind(&path)
        .fetch_optional(&pool)
        .await
        .unwrap();
        let original_sha = ArtifactService::calculate_sha256(b"ORIGINAL-RELEASE-BYTES");
        assert_eq!(
            remaining.as_deref(),
            Some(original_sha.as_str()),
            "the released content must be unchanged after a blocked swap"
        );

        tdh::cleanup(&pool, repo_id, user_id).await;
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// #2237: a direct DELETE on a `promotion_only` release repository is
    /// rejected for a non-admin (non-approver) with 403 FORBIDDEN, while an
    /// admin (release-approver) retains the retraction escape hatch, and a
    /// normal (non-promotion_only) repo is unaffected for the same non-admin.
    #[tokio::test]
    async fn delete_artifact_gated_on_promotion_only_repo_db() {
        use crate::api::handlers::test_db_helpers as tdh;
        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let (user_id, username) = tdh::create_user(&pool).await;
        let (repo_id, key, dir) = tdh::create_repo(&pool, "local", "generic").await;
        tdh::grant_repo_access(&pool, repo_id, user_id).await;
        let state = tdh::build_state(pool.clone(), dir.to_string_lossy().as_ref());
        let auth = Some(tdh::make_auth(user_id, &username));
        let mut admin_ext = tdh::make_auth(user_id, &username);
        admin_ext.is_admin = true;
        let admin = Some(admin_ext);

        let set_promotion_only = |value: bool| {
            let pool = pool.clone();
            async move {
                sqlx::query("UPDATE repositories SET promotion_only = $1 WHERE id = $2")
                    .bind(value)
                    .bind(repo_id)
                    .execute(&pool)
                    .await
                    .expect("set promotion_only");
            }
        };

        // Publish a release artifact (generic classifies this coordinate mutable,
        // so the immutability guard is a no-op — the promotion gate is the only
        // control under test).
        let path = "app/1.0.0/app-1.0.0.bin".to_string();
        upload_artifact(
            State(state.clone()),
            Extension(auth.clone()),
            Path((key.clone(), path.clone())),
            HeaderMap::new(),
            Bytes::from_static(b"RELEASE-BYTES"),
        )
        .await
        .expect("initial publish must succeed");

        // (1) promotion_only=true, non-admin -> 403 FORBIDDEN, artifact intact.
        set_promotion_only(true).await;
        let blocked = delete_artifact(
            State(state.clone()),
            Extension(auth.clone()),
            Path((key.clone(), path.clone())),
            HeaderMap::new(),
        )
        .await;
        assert!(
            matches!(blocked, Err(AppError::Authorization(_))),
            "non-admin DELETE on a promotion_only repo must be rejected 403, got: {blocked:?}"
        );
        let surviving: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM artifacts WHERE repository_id = $1 AND path = $2 AND is_deleted = false",
        )
        .bind(repo_id)
        .bind(&path)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(
            surviving, 1,
            "a blocked delete must leave the release intact"
        );

        // (2) promotion_only=true, admin -> retraction escape hatch: proceeds.
        let admin_del = delete_artifact(
            State(state.clone()),
            Extension(admin.clone()),
            Path((key.clone(), path.clone())),
            HeaderMap::new(),
        )
        .await;
        assert!(
            admin_del.is_ok(),
            "an admin (release-approver) must retain the retraction path, got: {admin_del:?}"
        );

        // (3) promotion_only=false, non-admin -> unaffected: proceeds.
        set_promotion_only(false).await;
        let path2 = "app/2.0.0/app-2.0.0.bin".to_string();
        upload_artifact(
            State(state.clone()),
            Extension(auth.clone()),
            Path((key.clone(), path2.clone())),
            HeaderMap::new(),
            Bytes::from_static(b"NORMAL-REPO-BYTES"),
        )
        .await
        .expect("publish to normal repo must succeed");
        let normal_del = delete_artifact(
            State(state.clone()),
            Extension(auth.clone()),
            Path((key.clone(), path2.clone())),
            HeaderMap::new(),
        )
        .await;
        assert!(
            normal_del.is_ok(),
            "delete on a normal (non-promotion_only) repo must be unaffected, got: {normal_del:?}"
        );

        tdh::cleanup(&pool, repo_id, user_id).await;
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Legit flow: re-uploading the IDENTICAL bytes after a DELETE is allowed
    /// (idempotent retract + republish), and re-uploading DIFFERENT bytes to a
    /// genuinely MUTABLE index path (a Maven `maven-metadata.xml`) is allowed.
    #[tokio::test]
    async fn delete_then_reupload_legit_flows_allowed_db() {
        use crate::api::handlers::test_db_helpers as tdh;
        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let (user_id, username) = tdh::create_user(&pool).await;
        let (repo_id, key, dir) = tdh::create_repo(&pool, "local", "maven").await;
        tdh::grant_repo_access(&pool, repo_id, user_id).await;
        let state = tdh::build_state(pool.clone(), dir.to_string_lossy().as_ref());
        // Admin auth so the delete guard permits deleting an immutable Maven jar.
        let mut admin = tdh::make_auth(user_id, &username);
        admin.is_admin = true;
        let auth = Some(admin);

        // (a) Identical-bytes retract + republish of an immutable coordinate.
        let path = "com/x/app/1.0.0/app-1.0.0.jar".to_string();
        let body = Bytes::from_static(b"SAME-RELEASE-CONTENT");
        upload_artifact(
            State(state.clone()),
            Extension(auth.clone()),
            Path((key.clone(), path.clone())),
            HeaderMap::new(),
            body.clone(),
        )
        .await
        .expect("publish jar");
        delete_artifact(
            State(state.clone()),
            Extension(auth.clone()),
            Path((key.clone(), path.clone())),
            HeaderMap::new(),
        )
        .await
        .expect("admin delete jar");
        let republish = upload_artifact(
            State(state.clone()),
            Extension(auth.clone()),
            Path((key.clone(), path.clone())),
            HeaderMap::new(),
            body.clone(),
        )
        .await;
        assert!(
            republish.is_ok(),
            "identical-bytes republish after delete must be allowed: {republish:?}"
        );

        // (b) Different-bytes re-upload to a MUTABLE index path is allowed.
        let meta = "com/x/app/maven-metadata.xml".to_string();
        upload_artifact(
            State(state.clone()),
            Extension(auth.clone()),
            Path((key.clone(), meta.clone())),
            HeaderMap::new(),
            Bytes::from_static(b"<metadata>v1</metadata>"),
        )
        .await
        .expect("publish metadata");
        delete_artifact(
            State(state.clone()),
            Extension(auth.clone()),
            Path((key.clone(), meta.clone())),
            HeaderMap::new(),
        )
        .await
        .expect("delete metadata");
        let rewrite = upload_artifact(
            State(state.clone()),
            Extension(auth.clone()),
            Path((key.clone(), meta.clone())),
            HeaderMap::new(),
            Bytes::from_static(b"<metadata>v2-updated</metadata>"),
        )
        .await;
        assert!(
            rewrite.is_ok(),
            "rewriting a mutable maven-metadata.xml after delete must be allowed: {rewrite:?}"
        );

        tdh::cleanup(&pool, repo_id, user_id).await;
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// DB-backed sibling for the read/visibility gate: a non-member gets NotFound
    /// on a private repo; a granted member sees it. Skips with no DATABASE_URL.
    #[tokio::test]
    async fn test_require_visible_nonmember_not_found_then_granted_db() {
        use crate::api::handlers::test_db_helpers as tdh;
        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let (user_id, username) = tdh::create_user(&pool).await;
        let (repo_id, key, _dir) = tdh::create_repo(&pool, "local", "pypi").await;
        let repo = make_repo_with_id(repo_id, &key);
        let ext = tdh::make_auth(user_id, &username);
        let svc = RepositoryService::new(pool.clone());

        let hidden = require_visible(&repo, &Some(ext.clone()), &svc).await;
        assert!(
            matches!(hidden, Err(AppError::NotFound(_))),
            "non-member must get NotFound on a private repo: {hidden:?}"
        );

        tdh::grant_repo_access(&pool, repo_id, user_id).await;
        let seen = require_visible(&repo, &Some(ext), &svc).await;
        assert!(seen.is_ok(), "a granted member must see the repo: {seen:?}");

        tdh::cleanup(&pool, repo_id, user_id).await;
    }

    /// DB-backed: a non-admin without `repository:admin` on the virtual parent
    /// is rejected (Insufficient permissions), and granting the rule lets them
    /// through — mirroring the gate `update_repository` enforces. Skips when no
    /// `DATABASE_URL` is configured.
    #[tokio::test]
    async fn test_virtual_member_authz_nonadmin_requires_repo_admin_grant_db() {
        use crate::api::handlers::test_db_helpers as tdh;
        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let (user_id, username) = tdh::create_user(&pool).await;
        let virtual_id = Uuid::new_v4();
        let member_id = Uuid::new_v4();
        let v = make_repo_with_id(virtual_id, "v");
        let m = make_repo_with_id(member_id, "m");
        // Non-admin, unrestricted token-scope (allowed_repo_ids = None) — exactly
        // the password/JWT session shape that the old code let through.
        let ext = tdh::make_auth(user_id, &username);

        // Deny: no repository:admin grant on the virtual parent.
        let denied = authorize_virtual_member_mutation(
            &ext,
            &v,
            &m,
            "update",
            &crate::services::permission_service::PermissionService::new(pool.clone()),
        )
        .await;
        match denied {
            Err(AppError::Authorization(msg)) => {
                assert!(
                    msg.contains("Insufficient permissions"),
                    "unexpected message: {msg}"
                );
            }
            other => panic!("expected Authorization denial, got: {:?}", other),
        }

        // Allow: grant the user repository:admin on the virtual parent. A fresh
        // service avoids the per-process cache from the deny lookup above.
        sqlx::query(
            "INSERT INTO permissions (principal_type, principal_id, target_type, target_id, actions) \
             VALUES ('user', $1, 'repository', $2, ARRAY['admin'])",
        )
        .bind(user_id)
        .bind(virtual_id)
        .execute(&pool)
        .await
        .expect("grant repository:admin");

        let allowed = authorize_virtual_member_mutation(
            &ext,
            &v,
            &m,
            "update",
            &crate::services::permission_service::PermissionService::new(pool.clone()),
        )
        .await;
        assert!(
            allowed.is_ok(),
            "non-admin WITH repository:admin must be allowed: {:?}",
            allowed
        );

        // Cleanup.
        let _ = sqlx::query("DELETE FROM permissions WHERE principal_id = $1")
            .bind(user_id)
            .execute(&pool)
            .await;
        let _ = sqlx::query("DELETE FROM users WHERE id = $1")
            .bind(user_id)
            .execute(&pool)
            .await;
    }

    /// DB-backed: a non-admin member that holds write access (developer role)
    /// on a Remote repo but NO `repository:admin` grant is DENIED on
    /// `set_cache_ttl` (the pull-through proxy cache-TTL is an administrative
    /// supply-chain control, same tier as delete/update). Granting
    /// `repository:admin` lets the same user through, and a global admin is
    /// always allowed. Skips when no `DATABASE_URL` is configured.
    #[tokio::test]
    async fn set_cache_ttl_requires_repo_admin_grant_db() {
        use crate::api::handlers::test_db_helpers as tdh;
        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let (user_id, username) = tdh::create_user(&pool).await;
        // Remote repo: the only repo_type set_cache_ttl accepts writes on.
        let (repo_id, key, dir) = tdh::create_repo(&pool, "remote", "pypi").await;
        // Grant developer (write) access so the user passes require_repo_write_access.
        tdh::grant_repo_access(&pool, repo_id, user_id).await;
        let state = tdh::build_state(pool.clone(), dir.to_string_lossy().as_ref());
        let ext = tdh::make_auth(user_id, &username);
        let req = || SetCacheTtlRequest {
            cache_ttl_seconds: 1,
        };

        // Deny: write access alone is not enough without repository:admin.
        let denied = set_cache_ttl(
            State(state.clone()),
            Extension(Some(ext.clone())),
            Path(key.clone()),
            Json(req()),
        )
        .await;
        match denied {
            Err(AppError::Authorization(msg)) => {
                assert!(
                    msg.contains("Insufficient permissions"),
                    "unexpected message: {msg}"
                );
            }
            other => {
                panic!("expected Authorization denial without repository:admin, got: {other:?}")
            }
        }

        // Allow: grant the user repository:admin on this repo. A fresh state
        // avoids the per-process permission cache from the deny lookup above.
        sqlx::query(
            "INSERT INTO permissions (principal_type, principal_id, target_type, target_id, actions) \
             VALUES ('user', $1, 'repository', $2, ARRAY['admin'])",
        )
        .bind(user_id)
        .bind(repo_id)
        .execute(&pool)
        .await
        .expect("grant repository:admin");
        let state2 = tdh::build_state(pool.clone(), dir.to_string_lossy().as_ref());
        let allowed = set_cache_ttl(
            State(state2),
            Extension(Some(ext.clone())),
            Path(key.clone()),
            Json(req()),
        )
        .await;
        assert!(
            allowed.is_ok(),
            "non-admin WITH repository:admin must be allowed: {allowed:?}"
        );

        // Allow: a global admin is always allowed (is_admin short-circuit).
        let admin_ext = AuthExtension {
            is_admin: true,
            ..tdh::make_auth(user_id, &username)
        };
        let state3 = tdh::build_state(pool.clone(), dir.to_string_lossy().as_ref());
        let admin_ok = set_cache_ttl(
            State(state3),
            Extension(Some(admin_ext)),
            Path(key.clone()),
            Json(req()),
        )
        .await;
        assert!(
            admin_ok.is_ok(),
            "global admin must be allowed: {admin_ok:?}"
        );

        // Cleanup.
        let _ = sqlx::query("DELETE FROM permissions WHERE principal_id = $1")
            .bind(user_id)
            .execute(&pool)
            .await;
        let _ = sqlx::query("DELETE FROM repository_config WHERE repository_id = $1")
            .bind(repo_id)
            .execute(&pool)
            .await;
        tdh::cleanup(&pool, repo_id, user_id).await;
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

    /// Cross-tenant write authz (xtenant-write-authz-systemic):
    ///
    /// The `/api/v1/repositories` REST nest runs under `optional_auth_middleware`
    /// only, NOT `repo_visibility_middleware`, so each sub-resource mutation
    /// handler must enforce the tenant write gate itself. Assert every such
    /// handler references `require_repo_write_access` (the canonical
    /// `is_public + role_assignments` gate) so a future handler cannot silently
    /// fall open to a non-member, non-admin caller on a private repo. String-grep
    /// because the handlers need a full `SharedState` to run.
    #[test]
    fn test_repo_mutation_handlers_call_write_gate() {
        let source = include_str!("repositories.rs");

        for handler in [
            "set_cache_ttl",
            "invalidate_cache",
            "put_pypi_track",
            "delete_pypi_track",
            "set_routing_rules",
            "delete_routing_rules",
            "set_upstream_auth",
            "upload_artifact",
            "delete_artifact",
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
                body.contains("require_repo_write_access("),
                "handler `{}` does not call `require_repo_write_access` \
                 (xtenant-write-authz-systemic). The /repositories nest is not \
                 covered by repo_visibility_middleware, so each mutation handler \
                 must enforce the tenant write gate itself. If you intentionally \
                 restructured the authz model, update this test to match.",
                handler
            );
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
            promotion_only: false,
            replication_priority: ReplicationPriority::Scheduled,
            curation_enabled: false,
            curation_source_repo_id: None,
            curation_target_repo_id: None,
            curation_default_action: "allow".to_string(),
            curation_sync_interval_secs: 3600,
            curation_auto_fetch: false,
            age_gate_enabled: false,
            age_gate_min_age_days: 7,
            created_at: now,
            updated_at: now,
        }
    }

    // NOTE: `require_visible` is now async and consults the per-repo grant
    // model (role_assignments) for private repositories, so the cases that
    // exercise the DB grant lookup (private + authenticated non-admin) are
    // covered by integration/live verification rather than these pure tests.
    // The cases below short-circuit BEFORE any DB access (public repos, the
    // anonymous-on-private denial, and the token-scope mismatch denial) and so
    // remain DB-free; we drive them with an unused pool handle.

    #[tokio::test]
    async fn test_require_visible_public_no_auth() {
        let repo = make_repo(true);
        let svc = RepositoryService::new(crate::api::handlers::test_db_helpers::lazy_pool());
        assert!(require_visible(&repo, &None, &svc).await.is_ok());
    }

    #[tokio::test]
    async fn test_require_visible_public_with_auth() {
        let repo = make_repo(true);
        let auth = Some(make_auth_ext(None));
        let svc = RepositoryService::new(crate::api::handlers::test_db_helpers::lazy_pool());
        assert!(require_visible(&repo, &auth, &svc).await.is_ok());
    }

    #[tokio::test]
    async fn test_require_visible_private_no_auth() {
        let repo = make_repo(false);
        let svc = RepositoryService::new(crate::api::handlers::test_db_helpers::lazy_pool());
        let result = require_visible(&repo, &None, &svc).await;
        assert!(result.is_err());
        match result.unwrap_err() {
            AppError::NotFound(msg) => assert!(msg.contains("test-repo")),
            other => panic!("Expected NotFound error, got: {:?}", other),
        }
    }

    #[tokio::test]
    async fn test_require_visible_private_with_different_repo_restriction() {
        // Token-scope mismatch is rejected before the grant lookup, so this
        // remains DB-free.
        let repo = make_repo(false);
        let other_repo_id = Uuid::new_v4();
        let auth = Some(make_auth_ext(Some(vec![other_repo_id])));
        let svc = RepositoryService::new(crate::api::handlers::test_db_helpers::lazy_pool());
        let result = require_visible(&repo, &auth, &svc).await;
        assert!(result.is_err());
        match result.unwrap_err() {
            AppError::NotFound(msg) => assert!(msg.contains("test-repo")),
            other => panic!("Expected NotFound error, got: {:?}", other),
        }
    }

    /// Admin variant of [`make_auth_ext`]: an authenticated admin with no
    /// repository-scope restriction. Admins bypass per-repo authorization.
    fn make_admin_auth_ext() -> AuthExtension {
        let mut ext = make_auth_ext(None);
        ext.is_admin = true;
        ext
    }

    #[tokio::test]
    async fn test_require_visible_private_admin_bypasses_grant() {
        // Admins bypass the per-repo grant lookup, so this short-circuits
        // before any DB access and remains DB-free.
        let repo = make_repo(false);
        let auth = Some(make_admin_auth_ext());
        let svc = RepositoryService::new(crate::api::handlers::test_db_helpers::lazy_pool());
        assert!(
            require_visible(&repo, &auth, &svc).await.is_ok(),
            "admin must see a private repo without an explicit grant"
        );
    }

    // -----------------------------------------------------------------------
    // require_repo_write_access (authz-private-repo-membership)
    //
    // Write/delete authorization on a repository. The public-repo and admin
    // arms short-circuit before the grant lookup, so they are DB-free. The
    // private + non-admin grant lookup is covered by
    // `repository_service::tests::test_user_can_access_repo_private_grant_enforced`.
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_require_repo_write_access_public_ok() {
        let repo = make_repo(true);
        let auth = make_auth_ext(None);
        let svc = RepositoryService::new(crate::api::handlers::test_db_helpers::lazy_pool());
        assert!(
            require_repo_write_access(&auth, &repo, &svc).await.is_ok(),
            "any authenticated caller may write to a public repo"
        );
    }

    #[tokio::test]
    async fn test_require_repo_write_access_admin_ok() {
        let repo = make_repo(false);
        let auth = make_admin_auth_ext();
        let svc = RepositoryService::new(crate::api::handlers::test_db_helpers::lazy_pool());
        assert!(
            require_repo_write_access(&auth, &repo, &svc).await.is_ok(),
            "admin may write to a private repo without an explicit grant"
        );
    }

    #[tokio::test]
    async fn test_require_repo_write_access_token_scope_denied() {
        // The token-scope check runs first and rejects a repository-scoped
        // token that does not list this repo, before the grant lookup, so this
        // remains DB-free.
        let repo = make_repo(false);
        let other_repo_id = Uuid::new_v4();
        let auth = make_auth_ext(Some(vec![other_repo_id]));
        let svc = RepositoryService::new(crate::api::handlers::test_db_helpers::lazy_pool());
        let result = require_repo_write_access(&auth, &repo, &svc).await;
        assert!(result.is_err());
        match result.unwrap_err() {
            AppError::Authorization(msg) => assert!(msg.contains("does not have access")),
            other => panic!("Expected Authorization error, got: {:?}", other),
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
    // clamp_per_page (#1783 LOW: per_page=0 overflowed total_pages to u32::MAX)
    // -----------------------------------------------------------------------

    #[test]
    fn test_clamp_per_page_zero_becomes_one() {
        // The core regression: 0 must never reach the total_pages division.
        assert_eq!(clamp_per_page(Some(0)), 1);
    }

    #[test]
    fn test_clamp_per_page_none_uses_default() {
        assert_eq!(clamp_per_page(None), 20);
    }

    #[test]
    fn test_clamp_per_page_within_range_unchanged() {
        assert_eq!(clamp_per_page(Some(1)), 1);
        assert_eq!(clamp_per_page(Some(50)), 50);
        assert_eq!(clamp_per_page(Some(100)), 100);
    }

    #[test]
    fn test_clamp_per_page_above_max_capped() {
        assert_eq!(clamp_per_page(Some(101)), 100);
        assert_eq!(clamp_per_page(Some(u32::MAX)), 100);
    }

    #[test]
    fn test_clamp_per_page_zero_total_pages_is_finite() {
        // Mirror the handler computation: total_pages = ceil(total / per_page).
        // With the clamp in place this can never be u32::MAX for per_page=0.
        let per_page = clamp_per_page(Some(0));
        let total: i64 = 128;
        let total_pages = ((total as f64) / (per_page as f64)).ceil() as u32;
        assert_eq!(total_pages, 128);
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
    // POST /repositories/:key/cache/invalidate (#1539)
    // -----------------------------------------------------------------------

    #[test]
    fn test_invalidate_cache_query_deserialization() {
        // serde_urlencoded backs `Query<T>` in axum, but exercising the
        // serde::Deserialize impl through serde_json is sufficient to pin
        // the field name and required-ness. axum-side wiring is exercised
        // by the structural test below.
        let json = r#"{"path": "foo/bar-1.2.3.tgz"}"#;
        let q: InvalidateCacheQuery = serde_json::from_str(json).unwrap();
        assert_eq!(q.path, "foo/bar-1.2.3.tgz");
    }

    #[test]
    fn test_invalidate_cache_query_rejects_missing_path() {
        // `path` is required: an empty object must fail to deserialize so
        // the handler never sees a default-empty path that would silently
        // evict the wrong cache key.
        let json = r#"{}"#;
        let result: std::result::Result<InvalidateCacheQuery, _> = serde_json::from_str(json);
        assert!(
            result.is_err(),
            "missing `path` must fail deserialization, got Ok({:?})",
            result.ok()
        );
    }

    #[test]
    fn test_invalidate_cache_response_serialization() {
        let resp = InvalidateCacheResponse {
            repository_key: "pypi-remote".to_string(),
            path: "simple/requests/".to_string(),
            invalidated: true,
        };
        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains("\"repository_key\":\"pypi-remote\""));
        assert!(json.contains("\"path\":\"simple/requests/\""));
        assert!(json.contains("\"invalidated\":true"));
    }

    /// Structural regression test (#1539): the `invalidate_cache` handler
    /// must guard on (a) `repo.repo_type != RepositoryType::Remote` (returns
    /// 400) and (b) `state.proxy_service.as_ref()` (returns 503 when None),
    /// and BOTH guards must run before the actual `proxy.invalidate_cache(`
    /// call. Otherwise a Local/Virtual repo or a deployment without a
    /// configured storage backend would either silently no-op (worse:
    /// produce a misleading 200) or panic on `unwrap` of an
    /// `Option<Arc<ProxyService>>`. Pins the contract this PR adds.
    #[test]
    fn invalidate_cache_handler_guards_repo_type_and_proxy_service() {
        let source = include_str!("repositories.rs");

        let signature = format!("pub async fn {}(", "invalidate_cache");
        let start = source
            .find(&signature)
            .unwrap_or_else(|| panic!("could not locate `{}` in repositories.rs", signature));

        // Bound the search at the closing `}` of the handler. The next
        // top-level `pub` item gives a safe upper bound: the handler's body
        // ends well before that.
        let end = source[start + signature.len()..]
            .find("\npub ")
            .map(|offset| start + signature.len() + offset)
            .unwrap_or(source.len());
        let body = &source[start..end];

        // Marker strings are built via format! so this test body itself does
        // not satisfy the search.
        let type_check = format!("{} != RepositoryType::Remote", "repo.repo_type");
        // The 503 guard chain (`state.proxy_service.as_ref().ok_or_else(...)`)
        // gets reformatted across multiple lines by rustfmt, so we anchor on
        // the unique `ServiceUnavailable` error construction inside the
        // `ok_or_else` closure -- that marker only exists when the guard is
        // present.
        let proxy_guard = format!(
            "{}::ServiceUnavailable(\"proxy service not configured\"",
            "AppError",
        );
        let evict_call = format!("{}.invalidate_cache(", "proxy");

        let type_idx = body.find(&type_check).unwrap_or_else(|| {
            panic!(
                "invalidate_cache must check `{}` to reject non-Remote repos (#1539)",
                type_check,
            )
        });
        let proxy_idx = body.find(&proxy_guard).unwrap_or_else(|| {
            panic!(
                "invalidate_cache must guard `{}` to surface a 503 instead of unwrap-panic when no storage backend is configured (#1539)",
                proxy_guard,
            )
        });
        let evict_idx = body.find(&evict_call).unwrap_or_else(|| {
            panic!(
                "invalidate_cache must call `{}` on the resolved proxy service (#1539)",
                evict_call,
            )
        });

        assert!(
            type_idx < evict_idx,
            "type-check `{}` must run BEFORE `{}` (#1539). type_idx={}, evict_idx={}",
            type_check,
            evict_call,
            type_idx,
            evict_idx,
        );
        assert!(
            proxy_idx < evict_idx,
            "proxy-service guard `{}` must run BEFORE `{}` (#1539). proxy_idx={}, evict_idx={}",
            proxy_guard,
            evict_call,
            proxy_idx,
            evict_idx,
        );
    }

    /// Runtime regression (#1539): on a Remote repo with the proxy service
    /// configured, `POST /:key/cache/invalidate?path=...` returns 200 with
    /// `invalidated: true`. Idempotent: invalidating a path that was never
    /// cached must still succeed (mirrors `ProxyService::invalidate_cache`,
    /// which ignores delete-of-missing on the storage backend).
    #[tokio::test]
    async fn invalidate_cache_handler_returns_200_for_remote_repo() {
        use crate::api::handlers::test_db_helpers as tdh;
        use axum::body::Body;
        use axum::http::{Request, StatusCode};

        let Some(fx) = tdh::Fixture::setup("remote", "generic").await else {
            return;
        };

        let proxy =
            tdh::build_proxy_service_with_fs(fx.pool.clone(), fx.storage_dir.to_str().unwrap());
        let state =
            tdh::build_state_with_proxy(fx.pool.clone(), fx.storage_dir.to_str().unwrap(), proxy);
        let auth = tdh::make_auth(fx.user_id, &fx.username);
        let router = tdh::router_with_auth(super::router(), state, auth);

        let req = Request::builder()
            .method("POST")
            .uri(format!(
                "/{}/cache/invalidate?path=foo%2Fbar-1.2.3.tgz",
                fx.repo_key
            ))
            .body(Body::empty())
            .expect("build POST request");
        let (status, body) = tdh::send(router, req).await;

        fx.teardown().await;

        assert_eq!(
            status,
            StatusCode::OK,
            "Remote repo + proxy configured must return 200 (idempotent on \
             never-cached paths); got status {} with body: {}",
            status,
            String::from_utf8_lossy(&body),
        );
        let body_str = String::from_utf8_lossy(&body);
        assert!(
            body_str.contains("\"invalidated\":true"),
            "response body must contain `invalidated: true` (#1539); got: {}",
            body_str,
        );
        assert!(
            body_str.contains("\"path\":\"foo/bar-1.2.3.tgz\""),
            "response body must echo the URL-decoded `path` (#1539); got: {}",
            body_str,
        );
    }

    /// Runtime regression (#1539): on a Local (or Virtual / Staging) repo,
    /// the handler MUST return 400 *before* touching the proxy service --
    /// cache invalidation is meaningless on non-Remote repos. The proxy
    /// service is wired up here on purpose so the test fails if the type
    /// guard is removed (otherwise the call would no-op-success on a Local
    /// repo and silently mask the contract).
    #[tokio::test]
    async fn invalidate_cache_handler_returns_400_for_non_remote_repo() {
        use crate::api::handlers::test_db_helpers as tdh;
        use axum::body::Body;
        use axum::http::{Request, StatusCode};

        let Some(fx) = tdh::Fixture::setup("local", "generic").await else {
            return;
        };

        let proxy =
            tdh::build_proxy_service_with_fs(fx.pool.clone(), fx.storage_dir.to_str().unwrap());
        let state =
            tdh::build_state_with_proxy(fx.pool.clone(), fx.storage_dir.to_str().unwrap(), proxy);
        let auth = tdh::make_auth(fx.user_id, &fx.username);
        let router = tdh::router_with_auth(super::router(), state, auth);

        let req = Request::builder()
            .method("POST")
            .uri(format!("/{}/cache/invalidate?path=anything", fx.repo_key))
            .body(Body::empty())
            .expect("build POST request");
        let (status, body) = tdh::send(router, req).await;

        fx.teardown().await;

        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "Local repo MUST surface as 400 BadRequest, not silent 200 \
             (#1539); got status {} with body: {}",
            status,
            String::from_utf8_lossy(&body),
        );
    }

    /// Runtime regression (#1539): on a Remote repo *without* a proxy
    /// service in `SharedState`, the handler MUST return 503 (not 500,
    /// not panic on unwrap). Pins `AppError::ServiceUnavailable` as the
    /// surfaced status so operators can distinguish "feature off" from
    /// "server bug" -- see the doc comment on the guard.
    #[tokio::test]
    async fn invalidate_cache_handler_returns_503_when_proxy_service_missing() {
        use crate::api::handlers::test_db_helpers as tdh;
        use axum::body::Body;
        use axum::http::{Request, StatusCode};

        let Some(fx) = tdh::Fixture::setup("remote", "generic").await else {
            return;
        };

        // Plain `build_state` does NOT install a proxy_service, so the
        // handler hits the `state.proxy_service.as_ref().ok_or_else(...)`
        // arm.
        let state = tdh::build_state(fx.pool.clone(), fx.storage_dir.to_str().unwrap());
        let auth = tdh::make_auth(fx.user_id, &fx.username);
        let router = tdh::router_with_auth(super::router(), state, auth);

        let req = Request::builder()
            .method("POST")
            .uri(format!("/{}/cache/invalidate?path=anything", fx.repo_key))
            .body(Body::empty())
            .expect("build POST request");
        let (status, body) = tdh::send(router, req).await;

        fx.teardown().await;

        assert_eq!(
            status,
            StatusCode::SERVICE_UNAVAILABLE,
            "missing proxy_service MUST surface as 503 ServiceUnavailable, \
             not 500 / not unwrap-panic (#1539); got status {} with body: {}",
            status,
            String::from_utf8_lossy(&body),
        );
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
            allowed_repo_ids: AccessScope::Admin,
            iat_ms: None,
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

    /// A virtual repo with no `member_repos` field at all (the deferred-
    /// population pattern used by every E2E test helper: create, then
    /// `POST /members`) must be accepted. Pre-#1444 this 400'd, which
    /// broke the create-then-add flow and surfaced as the "members router
    /// 404" symptom because the follow-up POSTs targeted a nonexistent
    /// repo. Empty-virtual state is now surfaced at fetch time instead of
    /// create time, and self-heals on the first add_member.
    #[test]
    fn test_validate_virtual_repo_member_count_accepts_none_for_deferred_add() {
        assert!(
            validate_virtual_repo_member_count("pypi", &RepositoryType::Virtual, None).is_ok(),
            "omitted member_repos must be accepted so the create-then-add \
             flow works (regression of #1444)"
        );
    }

    /// A virtual repo created with explicit `member_repos: []` is still a
    /// clear operator mistake (caller has actively typed "zero members")
    /// and must 400 with an actionable message. This preserves the #1279
    /// discoverability win for the case where the operator's intent is
    /// unambiguous, while the omitted-field case (above) flows through
    /// to the deferred-add pattern.
    #[test]
    fn test_validate_virtual_repo_member_count_rejects_explicit_empty() {
        let err = validate_virtual_repo_member_count("pypi", &RepositoryType::Virtual, Some(&[]))
            .expect_err("explicit empty members must reject");
        match err {
            AppError::Validation(msg) => {
                assert!(
                    msg.contains("explicit empty"),
                    "message should call out the explicit-empty shape; got: {}",
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

    // ---------------------------------------------------------------------
    // download_artifact: local-serve streaming happy path (#1608, epic #1607).
    //
    // The generic `/:key/download/*path` handler used to buffer the WHOLE
    // local artifact body into memory (`ArtifactService::download` ->
    // `storage.get()` -> `Bytes`) before responding, an OOM/pod-eviction
    // risk for large artifacts -- the same class #1393 fixed for the
    // per-format handlers. #1608 converts this path to
    // `ArtifactService::download_stream` + `Body::from_stream`. These tests
    // pin the new contract end-to-end:
    //
    //   1. seed a local artifact and download it -> 200 with the exact
    //      bytes, Content-Type, Content-Length (from `size_bytes`),
    //      x-checksum-sha256, and x-artifact-storage: proxy headers
    //   2. a missing path on a Local repo still maps to 404 (the
    //      NotFound contract the Remote/Virtual fallback arms key on)
    // ---------------------------------------------------------------------

    #[tokio::test]
    async fn test_download_artifact_local_streams_body_with_headers() {
        let Some(fx) = tdh::Fixture::setup("local", "generic").await else {
            return;
        };

        let body_bytes: &[u8] = b"the-streamed-local-artifact-body-bytes";
        let repo = fx.repo_info("local", None);
        let storage_key = format!("ph-test/{}.bin", Uuid::new_v4());
        tdh::seed_artifact(
            &fx.state,
            &fx.pool,
            &repo,
            &storage_key,
            "foo/bar.bin",
            "bar",
            "1.0.0",
            "application/x-test",
            Bytes::from_static(body_bytes),
            fx.user_id,
        )
        .await;

        let router = fx.router_with_auth(download_router());
        let req = tdh::get(format!("/{}/download/foo/bar.bin", fx.repo_key));

        // Send manually so we can inspect headers before draining the body.
        use tower::ServiceExt;
        let resp = router
            .oneshot(req)
            .await
            .expect("download_artifact local-serve must respond");
        let status = resp.status();
        let headers = resp.headers().clone();
        let collected = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .expect("collect streamed body");

        fx.teardown().await;

        assert_eq!(
            status,
            axum::http::StatusCode::OK,
            "local-serve happy path must stream a 200"
        );
        assert_eq!(
            &collected[..],
            body_bytes,
            "streamed body bytes must round-trip identically to the stored object"
        );
        assert_eq!(
            headers
                .get(header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok()),
            Some("application/x-test"),
            "Content-Type must come from the artifact row"
        );
        assert_eq!(
            headers
                .get(header::CONTENT_LENGTH)
                .and_then(|v| v.to_str().ok()),
            Some(body_bytes.len().to_string().as_str()),
            "Content-Length must be the artifact's size_bytes (#1608 streamed path)"
        );
        assert_eq!(
            headers
                .get("x-checksum-sha256")
                .and_then(|v| v.to_str().ok()),
            Some("test-seed"),
            "x-checksum-sha256 header must be preserved"
        );
        assert_eq!(
            headers
                .get(X_ARTIFACT_STORAGE)
                .and_then(|v| v.to_str().ok()),
            Some("proxy"),
            "x-artifact-storage must remain `proxy` for the local-serve path"
        );
        // #1785: the Content-Disposition filename must be the basename of the
        // requested path (`bar.bin`), NOT the artifact's package name (`bar`).
        assert_eq!(
            headers
                .get(header::CONTENT_DISPOSITION)
                .and_then(|v| v.to_str().ok()),
            Some("attachment; filename=\"bar.bin\""),
            "Content-Disposition filename must be the path basename, not the package name"
        );
        // #1785: byte-range support must be advertised on every download.
        assert_eq!(
            headers
                .get(header::ACCEPT_RANGES)
                .and_then(|v| v.to_str().ok()),
            Some("bytes"),
            "Accept-Ranges: bytes must be advertised on the local-serve path"
        );
    }

    /// #1785: a `Range: bytes=START-END` request against the local-serve path
    /// must return 206 Partial Content with the correct window, Content-Range,
    /// and Content-Length — not a 200 with the full body.
    #[tokio::test]
    async fn test_download_artifact_local_honours_range_request() {
        let Some(fx) = tdh::Fixture::setup("local", "generic").await else {
            return;
        };

        let body_bytes: &[u8] = b"0123456789abcdef";
        let repo = fx.repo_info("local", None);
        let storage_key = format!("ph-test/{}.bin", Uuid::new_v4());
        tdh::seed_artifact(
            &fx.state,
            &fx.pool,
            &repo,
            &storage_key,
            "foo/ranged.bin",
            "ranged",
            "1.0.0",
            "application/x-test",
            Bytes::from_static(body_bytes),
            fx.user_id,
        )
        .await;

        let router = fx.router_with_auth(download_router());
        let mut req = tdh::get(format!("/{}/download/foo/ranged.bin", fx.repo_key));
        req.headers_mut().insert(
            header::RANGE,
            axum::http::HeaderValue::from_static("bytes=4-7"),
        );

        use tower::ServiceExt;
        let resp = router
            .oneshot(req)
            .await
            .expect("ranged download must respond");
        let status = resp.status();
        let headers = resp.headers().clone();
        let collected = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .expect("collect partial body");

        fx.teardown().await;

        assert_eq!(
            status,
            axum::http::StatusCode::PARTIAL_CONTENT,
            "a satisfiable Range request must return 206"
        );
        assert_eq!(
            &collected[..],
            b"4567",
            "the body must contain only the requested byte window"
        );
        assert_eq!(
            headers
                .get(header::CONTENT_RANGE)
                .and_then(|v| v.to_str().ok()),
            Some("bytes 4-7/16"),
            "Content-Range must report the served window and total size"
        );
        assert_eq!(
            headers
                .get(header::CONTENT_LENGTH)
                .and_then(|v| v.to_str().ok()),
            Some("4"),
            "Content-Length must be the size of the partial window"
        );
    }

    // Regression (#1782): a HEAD request on the generic download endpoint must
    // return the GET headers (status, Content-Type, Content-Length) but an
    // EMPTY body. Previously the handler always attached `Body::from_stream`,
    // so HTTP/1.1 keep-alive clients blocked waiting for `Content-Length`
    // bytes that were never written and the connection hung.
    #[tokio::test]
    async fn test_download_artifact_head_returns_headers_no_body() {
        let Some(fx) = tdh::Fixture::setup("local", "generic").await else {
            return;
        };

        let body_bytes: &[u8] = b"head-request-must-not-return-this-body";
        let repo = fx.repo_info("local", None);
        let storage_key = format!("ph-test/{}.bin", Uuid::new_v4());
        tdh::seed_artifact(
            &fx.state,
            &fx.pool,
            &repo,
            &storage_key,
            "head/probe.bin",
            "probe",
            "1.0.0",
            "application/x-test",
            Bytes::from_static(body_bytes),
            fx.user_id,
        )
        .await;

        let router = fx.router_with_auth(download_router());
        let req = axum::http::Request::builder()
            .method("HEAD")
            .uri(format!("/{}/download/head/probe.bin", fx.repo_key))
            .body(Body::empty())
            .expect("build HEAD request");

        use tower::ServiceExt;
        let resp = router
            .oneshot(req)
            .await
            .expect("HEAD download must respond");
        let status = resp.status();
        let headers = resp.headers().clone();
        let collected = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .expect("collect HEAD body");

        fx.teardown().await;

        assert_eq!(
            status,
            axum::http::StatusCode::OK,
            "HEAD on an existing artifact must return 200"
        );
        // Content-Length still advertises the full size (HEAD semantics) ...
        assert_eq!(
            headers
                .get(header::CONTENT_LENGTH)
                .and_then(|v| v.to_str().ok()),
            Some(body_bytes.len().to_string().as_str()),
            "HEAD must still report the artifact size in Content-Length"
        );
        // ... but NO body bytes are written, so the connection can close.
        assert!(
            collected.is_empty(),
            "HEAD must return an empty body, got {} bytes",
            collected.len()
        );
        assert_eq!(
            headers
                .get(header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok()),
            Some("application/x-test"),
            "HEAD must carry the same Content-Type as GET"
        );
    }

    #[tokio::test]
    async fn test_download_artifact_local_missing_path_returns_404() {
        let Some(fx) = tdh::Fixture::setup("local", "generic").await else {
            return;
        };

        // No proxy_service wired and no upstream: a Local repo with a missing
        // path must surface the NotFound contract as a 404, not a 500.
        let router = fx.router_with_auth(download_router());
        let req = tdh::get(format!("/{}/download/does/not/exist.bin", fx.repo_key));
        let (status, _body) = tdh::send(router, req).await;

        fx.teardown().await;

        assert_eq!(
            status,
            axum::http::StatusCode::NOT_FOUND,
            "missing local artifact must map to 404 (NotFound contract preserved by #1608)"
        );
    }

    // Source-level pin (#1608, epic #1607): the local-serve happy path in
    // `download_artifact` MUST stream via `ArtifactService::download_stream`
    // and `Body::from_stream`, never the buffered `.download(` -> `Bytes`
    // path. A silent revert would re-introduce the OOM regression this fix
    // closes (same class as #1393 for the per-format handlers).
    #[test]
    fn test_repositories_download_artifact_local_streams_1608() {
        let src = include_str!("repositories.rs");
        assert!(
            src.contains(".download_stream("),
            "`repositories::download_artifact` MUST call \
             `ArtifactService::download_stream(` for the local-serve download \
             (#1608). A revert to the buffered `.download(` helper would \
             re-introduce the large-body OOM regression."
        );
    }

    #[tokio::test]
    async fn delete_repository_purges_oci_upload_temp_objects() {
        let Some(fx) = tdh::Fixture::setup("local", "docker").await else {
            return;
        };
        let state = tdh::build_state(fx.pool.clone(), fx.storage_dir.to_str().unwrap());
        let location = crate::storage::StorageLocation {
            backend: "filesystem".to_string(),
            path: fx.storage_dir.to_string_lossy().into_owned(),
        };
        let storage = state.storage_for_repo(&location).expect("resolve storage");

        // An in-flight upload temp object, tracked only by the cleanup-key journal.
        let temp_key = format!("oci-uploads/{}", Uuid::new_v4());
        storage
            .put(
                &temp_key,
                bytes::Bytes::from_static(b"in-flight upload bytes"),
            )
            .await
            .expect("write temp object");
        sqlx::query(
            "INSERT INTO oci_upload_cleanup_keys (repository_id, storage_key, storage_write_completed_at) \
             VALUES ($1, $2, NOW())",
        )
        .bind(fx.repo_id)
        .bind(&temp_key)
        .execute(&fx.pool)
        .await
        .expect("register cleanup key");
        // A session storage_temp_key object (second UNION branch).
        let session_id = Uuid::new_v4();
        let session_temp_key = format!("oci-uploads/{}", Uuid::new_v4());
        storage
            .put(
                &session_temp_key,
                bytes::Bytes::from_static(b"session temp"),
            )
            .await
            .expect("write session temp object");
        sqlx::query(
            "INSERT INTO oci_upload_sessions (id, repository_id, user_id, storage_temp_key) \
             VALUES ($1, $2, $3, $4)",
        )
        .bind(session_id)
        .bind(fx.repo_id)
        .bind(fx.user_id)
        .bind(&session_temp_key)
        .execute(&fx.pool)
        .await
        .expect("insert upload session");

        // A part storage_key object (third UNION branch).
        let part_key = format!("{}.part.00000000.{}", session_temp_key, Uuid::new_v4());
        storage
            .put(&part_key, bytes::Bytes::from_static(b"part bytes"))
            .await
            .expect("write part object");
        sqlx::query(
            "INSERT INTO oci_upload_parts (upload_session_id, part_index, storage_key, size_bytes, digest_sha256) \
             VALUES ($1, 0, $2, $3, NULL)",
        )
        .bind(session_id)
        .bind(&part_key)
        .bind(10_i64)
        .execute(&fx.pool)
        .await
        .expect("insert upload part");

        // A COMMITTED blob — content-addressed, owned by oci_blobs, NOT an upload
        // temp object. The purge must never touch it.
        let blob_digest = format!("sha256:{}", "a".repeat(64));
        let blob_key = format!("oci-blobs/{blob_digest}");
        storage
            .put(
                &blob_key,
                bytes::Bytes::from_static(b"committed blob bytes"),
            )
            .await
            .expect("write committed blob");
        sqlx::query(
            "INSERT INTO oci_blobs (repository_id, digest, size_bytes, storage_key) \
             VALUES ($1, $2, $3, $4)",
        )
        .bind(fx.repo_id)
        .bind(&blob_digest)
        .bind(20_i64)
        .bind(&blob_key)
        .execute(&fx.pool)
        .await
        .expect("insert oci_blobs row");

        for k in [&temp_key, &session_temp_key, &part_key, &blob_key] {
            assert!(
                storage.exists(k).await.expect("exists"),
                "precondition: {k} exists"
            );
        }

        // The repo-delete flow collects the journaled temp/session/part keys
        // (while the owner rows still exist) and then purges them from storage;
        // it must remove those objects but leave the committed blob untouched.
        let keys = collect_repo_oci_upload_temp_keys(&state, fx.repo_id).await;
        purge_oci_upload_temp_objects(&state, fx.repo_id, &location, keys).await;

        for k in [&temp_key, &session_temp_key, &part_key] {
            assert!(
                !storage.exists(k).await.expect("exists after purge"),
                "purge must remove OCI upload temp object {k}"
            );
        }
        assert!(
            storage
                .exists(&blob_key)
                .await
                .expect("blob exists after purge"),
            "purge must NOT delete the committed content-addressed blob {blob_key}"
        );

        fx.teardown().await;
    }

    /// Seed one in-flight OCI upload temp object into `storage` and register its
    /// `oci_upload_cleanup_keys` journal row for `repo_id`; returns the key.
    /// Shared by the ordering tests below so the seeding boilerplate lives in
    /// one place.
    async fn seed_oci_upload_temp_object(
        pool: &sqlx::PgPool,
        storage: &std::sync::Arc<dyn crate::storage::StorageBackend>,
        repo_id: Uuid,
    ) -> String {
        let key = format!("oci-uploads/{}", Uuid::new_v4());
        storage
            .put(&key, bytes::Bytes::from_static(b"in-flight upload bytes"))
            .await
            .expect("write temp object");
        sqlx::query(
            "INSERT INTO oci_upload_cleanup_keys (repository_id, storage_key, storage_write_completed_at) \
             VALUES ($1, $2, NOW())",
        )
        .bind(repo_id)
        .bind(&key)
        .execute(pool)
        .await
        .expect("register cleanup key");
        key
    }

    /// GC-LOW-2 (ordering, success path): a SUCCESSFUL `delete_repository`
    /// purges the repo's in-flight OCI upload temp objects from storage — even
    /// though the journal rows CASCADE away with the repo row, because the keys
    /// are collected *before* the delete and purged *after* it commits.
    #[tokio::test]
    async fn delete_repository_success_purges_oci_upload_temp_objects() {
        let Some(fx) = tdh::Fixture::setup("local", "docker").await else {
            return;
        };
        let location = crate::storage::StorageLocation {
            backend: "filesystem".to_string(),
            path: fx.storage_dir.to_string_lossy().into_owned(),
        };
        let storage = fx
            .state
            .storage_for_repo(&location)
            .expect("resolve storage");
        let temp_key = seed_oci_upload_temp_object(&fx.pool, &storage, fx.repo_id).await;
        assert!(
            storage.exists(&temp_key).await.expect("exists"),
            "precondition: temp object present"
        );

        // Admin auth so the delete-authorization gates pass without a per-repo
        // admin grant.
        let mut auth = tdh::make_auth(fx.user_id, &fx.username);
        auth.is_admin = true;

        delete_repository(
            State(fx.state.clone()),
            Extension(Some(auth)),
            Path(fx.repo_key.clone()),
        )
        .await
        .expect("repository delete must succeed");

        assert!(
            !storage
                .exists(&temp_key)
                .await
                .expect("exists after delete"),
            "a successful repository delete must purge the OCI upload temp object"
        );

        fx.teardown().await;
    }

    /// GC-LOW-2 (ordering, failure path): a `delete_repository` whose underlying
    /// `service.delete` FAILS must NOT purge the repo's in-flight OCI upload temp
    /// objects — they survive to be retried. The row delete is forced to fail by
    /// a `BEFORE DELETE` trigger scoped (via its `WHEN` clause) to this one repo,
    /// so `DELETE FROM repositories` raises and the handler returns before the
    /// (post-delete) purge step.
    #[tokio::test]
    async fn delete_repository_failed_delete_keeps_oci_upload_temp_objects() {
        let Some(fx) = tdh::Fixture::setup("local", "docker").await else {
            return;
        };
        let location = crate::storage::StorageLocation {
            backend: "filesystem".to_string(),
            path: fx.storage_dir.to_string_lossy().into_owned(),
        };
        let storage = fx
            .state
            .storage_for_repo(&location)
            .expect("resolve storage");
        let temp_key = seed_oci_upload_temp_object(&fx.pool, &storage, fx.repo_id).await;

        // A trigger name/function unique to this repo so concurrent DB tests
        // sharing the `repositories` table never collide.
        let fn_name = format!("ph_block_repo_delete_{}", fx.repo_id.simple());
        let trg_name = format!("ph_block_repo_delete_trg_{}", fx.repo_id.simple());
        sqlx::query(&format!(
            "CREATE FUNCTION {fn_name}() RETURNS trigger AS \
             $$ BEGIN RAISE EXCEPTION 'ph blocked repo delete'; END; $$ LANGUAGE plpgsql"
        ))
        .execute(&fx.pool)
        .await
        .expect("create blocking trigger function");
        sqlx::query(&format!(
            "CREATE TRIGGER {trg_name} BEFORE DELETE ON repositories \
             FOR EACH ROW WHEN (OLD.id = '{}'::uuid) EXECUTE FUNCTION {fn_name}()",
            fx.repo_id
        ))
        .execute(&fx.pool)
        .await
        .expect("create blocking trigger");

        let mut auth = tdh::make_auth(fx.user_id, &fx.username);
        auth.is_admin = true;

        let res = delete_repository(
            State(fx.state.clone()),
            Extension(Some(auth)),
            Path(fx.repo_key.clone()),
        )
        .await;
        assert!(
            res.is_err(),
            "the repository delete must fail (blocking trigger present)"
        );

        assert!(
            storage
                .exists(&temp_key)
                .await
                .expect("exists after failed delete"),
            "a FAILED repository delete must NOT purge the OCI upload temp object"
        );

        // Drop the trigger (and function) so the fixture can tear down cleanly.
        sqlx::query(&format!("DROP TRIGGER {trg_name} ON repositories"))
            .execute(&fx.pool)
            .await
            .expect("drop blocking trigger");
        sqlx::query(&format!("DROP FUNCTION {fn_name}()"))
            .execute(&fx.pool)
            .await
            .expect("drop blocking trigger function");
        let _ = storage.delete(&temp_key).await;
        fx.teardown().await;
    }

    /// F2 (batching): a cleanup-key backlog larger than one batch must be fully
    /// collected — the batched keyset query loops until the backlog is drained
    /// rather than issuing a single unbounded SELECT.
    #[tokio::test]
    async fn collect_repo_oci_upload_temp_keys_drains_large_backlog() {
        let Some(fx) = tdh::Fixture::setup("local", "docker").await else {
            return;
        };
        // One more than the batch size guarantees at least two query pages, so a
        // non-looping implementation would miss the overflow key.
        let total = (OCI_UPLOAD_TEMP_KEY_BATCH + 1) as usize;
        let mut expected: Vec<String> = Vec::with_capacity(total);
        for _ in 0..total {
            let key = format!("oci-uploads/{}", Uuid::new_v4());
            sqlx::query(
                "INSERT INTO oci_upload_cleanup_keys (repository_id, storage_key, storage_write_completed_at) \
                 VALUES ($1, $2, NOW())",
            )
            .bind(fx.repo_id)
            .bind(&key)
            .execute(&fx.pool)
            .await
            .expect("register cleanup key");
            expected.push(key);
        }

        let mut got = collect_repo_oci_upload_temp_keys(&fx.state, fx.repo_id).await;
        got.sort();
        got.dedup();
        expected.sort();
        assert_eq!(
            got, expected,
            "the batched collector must return every key in a large backlog"
        );

        fx.teardown().await;
    }

    #[tokio::test]
    async fn delete_repository_purges_artifact_objects() {
        let Some(fx) = tdh::Fixture::setup("local", "generic").await else {
            return;
        };
        let state = tdh::build_state(fx.pool.clone(), fx.storage_dir.to_str().unwrap());
        let location = crate::storage::StorageLocation {
            backend: "filesystem".to_string(),
            path: fx.storage_dir.to_string_lossy().into_owned(),
        };
        let storage = state.storage_for_repo(&location).expect("resolve storage");

        let insert_artifact = |repo_id: Uuid, path: &'static str, key: String| {
            let pool = fx.pool.clone();
            async move {
                sqlx::query(
                    "INSERT INTO artifacts \
                     (repository_id, path, name, size_bytes, checksum_sha256, content_type, storage_key) \
                     VALUES ($1, $2, $3, $4, $5, $6, $7)",
                )
                .bind(repo_id)
                .bind(path)
                .bind("file.bin")
                .bind(6_i64)
                .bind("0".repeat(64))
                .bind("application/octet-stream")
                .bind(key)
                .execute(&pool)
                .await
                .expect("insert artifact row");
            }
        };

        // Object owned solely by this repository: must be purged.
        let owned_key = format!("generic/{}/owned.bin", Uuid::new_v4());
        storage
            .put(&owned_key, bytes::Bytes::from_static(b"owned!"))
            .await
            .expect("put owned object");
        insert_artifact(fx.repo_id, "a/owned.bin", owned_key.clone()).await;

        // Object whose storage_key is also referenced by a SECOND repository
        // (content-addressed dedup): must NOT be purged.
        let (other_repo_id, _key, _dir) = tdh::create_repo(&fx.pool, "local", "generic").await;
        let shared_key = format!("generic/{}/shared.bin", Uuid::new_v4());
        storage
            .put(&shared_key, bytes::Bytes::from_static(b"shared"))
            .await
            .expect("put shared object");
        insert_artifact(fx.repo_id, "s/shared-a.bin", shared_key.clone()).await;
        insert_artifact(other_repo_id, "s/shared-b.bin", shared_key.clone()).await;

        assert!(storage.exists(&owned_key).await.expect("owned exists"));
        assert!(storage.exists(&shared_key).await.expect("shared exists"));

        purge_repo_artifact_objects(&state, fx.repo_id, &location).await;

        assert!(
            !storage
                .exists(&owned_key)
                .await
                .expect("owned exists after"),
            "exclusively-owned object must be purged"
        );
        assert!(
            storage
                .exists(&shared_key)
                .await
                .expect("shared exists after"),
            "object referenced by another repository must be kept"
        );

        // Clean up the second repo (its artifacts CASCADE).
        sqlx::query("DELETE FROM repositories WHERE id = $1")
            .bind(other_repo_id)
            .execute(&fx.pool)
            .await
            .expect("delete other repo");
        fx.teardown().await;
    }

    /// Regression for the #1598 data-loss bug: on cloud backends (S3/GCS/Azure)
    /// every repository shares ONE flat global keyspace (no per-repo path
    /// isolation), so an OCI manifest object `oci-manifests/<digest>` can be
    /// referenced by a SECOND repository via `oci_tags`/`oci_manifest_refs`
    /// WITHOUT any matching `artifacts` row. The original purge SELECT guarded
    /// over-deletion only with `NOT EXISTS (artifacts b ...)`, which cannot see
    /// such an OCI-table-only reference, so deleting repo A purged a manifest
    /// repo B was still serving.
    ///
    /// This test deliberately defeats path isolation: both repos resolve to the
    /// SAME `location` (one shared root, mimicking a flat cloud keyspace) and
    /// repo B references the manifest ONLY through `oci_tags` +
    /// `oci_manifest_refs` (no `artifacts` row). The fix excludes
    /// `oci-manifests/%` / `oci-blobs/%` from the purge, so the shared manifest
    /// MUST survive repo A's deletion.
    #[tokio::test]
    async fn delete_repository_keeps_oci_manifest_shared_via_oci_tables_on_flat_backend() {
        let Some(fx) = tdh::Fixture::setup("local", "docker").await else {
            return;
        };
        let state = tdh::build_state(fx.pool.clone(), fx.storage_dir.to_str().unwrap());
        // A single shared root for BOTH repos == flat global keyspace, no
        // per-repo path isolation (the property that hid the bug on filesystem).
        let location = crate::storage::StorageLocation {
            backend: "filesystem".to_string(),
            path: fx.storage_dir.to_string_lossy().into_owned(),
        };
        let storage = state.storage_for_repo(&location).expect("resolve storage");

        // Helper: write an OCI manifest object to the shared root AND give repo A
        // (the repo being deleted) an `artifacts` row pointing at it. Returns the
        // storage key so the assertions can probe it afterwards.
        let put_repo_a_manifest = |digest: &str, content_type: &'static str| {
            let pool = fx.pool.clone();
            let repo_id = fx.repo_id;
            let storage = storage.clone();
            let key = format!("oci-manifests/{digest}");
            async move {
                storage
                    .put(&key, bytes::Bytes::from(format!("bytes for {key}")))
                    .await
                    .expect("put manifest object");
                sqlx::query(
                    "INSERT INTO artifacts \
                     (repository_id, path, name, size_bytes, checksum_sha256, content_type, storage_key) \
                     VALUES ($1, $2, $3, $4, $5, $6, $7)",
                )
                .bind(repo_id)
                .bind(format!("app/{}", &key))
                .bind("manifest")
                .bind(16_i64)
                .bind("f".repeat(64))
                .bind(content_type)
                .bind(&key)
                .execute(&pool)
                .await
                .expect("insert repo A artifact row for manifest");
                key
            }
        };

        // Repo A owns an index manifest (referenced cross-repo by repo B via an
        // oci_tags row) and a child manifest (referenced via oci_manifest_refs).
        // Digests are randomized per run so they never collide with rows left by
        // other tests in the shared test DB (a fixed digest could be referenced
        // by an unrelated repo's leftover artifacts row, which would mask the bug
        // by satisfying the artifacts-only NOT EXISTS guard for the wrong reason).
        let index_digest = format!("sha256:{:0>64}", Uuid::new_v4().simple());
        let child_digest = format!("sha256:{:0>64}", Uuid::new_v4().simple());
        let manifest_key =
            put_repo_a_manifest(&index_digest, "application/vnd.oci.image.index.v1+json").await;
        let child_key =
            put_repo_a_manifest(&child_digest, "application/vnd.oci.image.manifest.v1+json").await;

        // Repo B references BOTH manifest objects WITHOUT any artifacts row:
        //   - the index via an oci_tags row (digest reference), and
        //   - the child via an oci_manifest_refs row (index -> child).
        // This is exactly what the artifacts-only NOT EXISTS guard cannot see.
        let (other_repo_id, _key, _dir) = tdh::create_repo(&fx.pool, "local", "docker").await;
        sqlx::query(
            "INSERT INTO oci_tags \
             (repository_id, name, tag, manifest_digest, manifest_content_type) \
             VALUES ($1, $2, $3, $4, $5)",
        )
        .bind(other_repo_id)
        .bind("app")
        .bind("v1")
        .bind(&index_digest)
        .bind("application/vnd.oci.image.index.v1+json")
        .execute(&fx.pool)
        .await
        .expect("insert repo B oci_tags row");
        sqlx::query(
            "INSERT INTO oci_manifest_refs (parent_digest, child_digest, repository_id) \
             VALUES ($1, $2, $3)",
        )
        .bind(&index_digest)
        .bind(&child_digest)
        .bind(other_repo_id)
        .execute(&fx.pool)
        .await
        .expect("insert repo B oci_manifest_refs row");

        assert!(storage
            .exists(&manifest_key)
            .await
            .expect("manifest exists"));
        assert!(storage.exists(&child_key).await.expect("child exists"));

        // Delete repo A's objects. The shared OCI manifest objects MUST survive
        // because repo B still serves them (via oci_tags / oci_manifest_refs).
        purge_repo_artifact_objects(&state, fx.repo_id, &location).await;

        assert!(
            storage
                .exists(&manifest_key)
                .await
                .expect("manifest exists after purge"),
            "OCI manifest referenced by another repo via oci_tags must NOT be purged \
             on a flat (no path isolation) backend"
        );
        assert!(
            storage
                .exists(&child_key)
                .await
                .expect("child exists after purge"),
            "OCI child manifest referenced by another repo via oci_manifest_refs must \
             NOT be purged on a flat (no path isolation) backend"
        );

        // Clean up the second repo (its oci_tags / oci_manifest_refs CASCADE).
        sqlx::query("DELETE FROM repositories WHERE id = $1")
            .bind(other_repo_id)
            .execute(&fx.pool)
            .await
            .expect("delete other repo");
        fx.teardown().await;
    }

    #[tokio::test]
    async fn purge_repo_artifact_objects_is_best_effort_when_backend_unresolvable() {
        // The purge resolves the repository's OWN configured backend via
        // `storage_for_repo` (StorageRegistry::backend_for), so a repo on an
        // unregistered/cloud backend that cannot be resolved in this process
        // must NOT panic or block the delete — it logs and returns. This pins
        // the "never blocks the delete" contract and the backend-aware
        // resolution path (an unknown backend name yields Err, not a silent
        // fallback to the local/primary backend).
        let Some(fx) = tdh::Fixture::setup("local", "generic").await else {
            return;
        };
        let state = tdh::build_state(fx.pool.clone(), fx.storage_dir.to_str().unwrap());

        // A location naming a backend that is not registered in this process.
        // `backend_for` returns Err for any non-"filesystem" name absent from
        // the registry, exercising the early-return best-effort branch.
        let unresolved = crate::storage::StorageLocation {
            backend: "s3-not-registered-in-this-process".to_string(),
            path: "irrelevant".to_string(),
        };
        assert!(
            state.storage_for_repo(&unresolved).is_err(),
            "an unregistered backend must not resolve to a fallback backend"
        );

        // Must return cleanly without panicking even though storage cannot be
        // resolved (best-effort: failures are logged and swallowed).
        purge_repo_artifact_objects(&state, fx.repo_id, &unresolved).await;

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
    // Generic upload Content-Type resolution (#1782)
    //
    // The handler must honour a client-declared `Content-Type` header instead
    // of always guessing from the file extension. Multipart wrappers describe
    // the request envelope, not the stored object, so they must NOT win.
    // ---------------------------------------------------------------------

    #[test]
    fn test_resolve_upload_content_type_honours_declared_header() {
        // A valid declared MIME type wins over the mime_guess of `.bin`
        // (which would be application/octet-stream).
        assert_eq!(
            resolve_upload_content_type(
                Some("application/vnd.my-company.binary"),
                "pkg/v1/binary.bin"
            ),
            "application/vnd.my-company.binary"
        );
    }

    #[test]
    fn test_resolve_upload_content_type_preserves_charset_params() {
        assert_eq!(
            resolve_upload_content_type(Some("text/plain; charset=utf-8"), "x"),
            "text/plain; charset=utf-8"
        );
    }

    #[test]
    fn test_resolve_upload_content_type_ignores_multipart_wrapper() {
        // multipart/form-data only describes the upload envelope. Fall back to
        // mime_guess (here `.txt` -> text/plain).
        let ct =
            resolve_upload_content_type(Some("multipart/form-data; boundary=----abc"), "notes.txt");
        assert!(ct.starts_with("text/plain"), "got {ct}");
    }

    #[test]
    fn test_resolve_upload_content_type_falls_back_to_mime_guess() {
        // No declared header -> guess from extension.
        let ct = resolve_upload_content_type(None, "archive.json");
        assert_eq!(ct, "application/json");
    }

    #[test]
    fn test_resolve_upload_content_type_ignores_empty_and_invalid() {
        // Empty / malformed (no slash) declared values fall back to guess.
        assert_eq!(
            resolve_upload_content_type(Some("   "), "data.json"),
            "application/json"
        );
        assert_eq!(
            resolve_upload_content_type(Some("not-a-mime"), "data.json"),
            "application/json"
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

    #[tokio::test]
    async fn test_upload_artifact_admin_blocked_on_promotion_only_repo_403() {
        // Regression for the promotion_only direct-upload bypass: an admin
        // direct PUT to a promotion_only repository must be rejected with 403
        // (AppError::Authorization). Artifacts may only enter such a repo via
        // the promotion workflow. A normal (non-promotion_only) repo continues
        // to accept the same admin upload (201). Skips gracefully when no
        // DATABASE_URL is configured.
        let Some(fx) = tdh::Fixture::setup("local", "generic").await else {
            return;
        };

        // Flip the fixture repo to promotion_only.
        sqlx::query("UPDATE repositories SET promotion_only = true WHERE id = $1")
            .bind(fx.repo_id)
            .execute(&fx.pool)
            .await
            .expect("set promotion_only");

        // Build an ADMIN auth for the fixture user (the realistic actor that
        // previously bypassed the gate via the `&& !is_admin` exemption).
        let mut auth = tdh::make_auth(fx.user_id, &fx.username);
        auth.is_admin = true;

        let blocked = upload_artifact(
            State(fx.state.clone()),
            Extension(Some(auth.clone())),
            Path((fx.repo_key.clone(), "foo/bar.txt".to_string())),
            HeaderMap::new(),
            Bytes::from_static(b"directwrite"),
        )
        .await;

        let err = blocked.expect_err("admin direct upload to promotion_only repo must be blocked");
        // AppError::Authorization maps to 403 Forbidden (see error.rs).
        assert!(
            matches!(err, AppError::Authorization(_)),
            "admin direct upload to promotion_only repo must surface as Authorization (403), got {err:?}",
        );

        // Legit path: revert to a normal repo and the same admin upload succeeds.
        sqlx::query("UPDATE repositories SET promotion_only = false WHERE id = $1")
            .bind(fx.repo_id)
            .execute(&fx.pool)
            .await
            .expect("clear promotion_only");

        let (status, _) = upload_artifact(
            State(fx.state.clone()),
            Extension(Some(auth)),
            Path((fx.repo_key.clone(), "foo/bar.txt".to_string())),
            HeaderMap::new(),
            Bytes::from_static(b"directwrite"),
        )
        .await
        .expect("admin upload to a normal repo must succeed");
        assert_eq!(status, StatusCode::CREATED);

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

    // -----------------------------------------------------------------------
    // WASM plugin format fallback in create_repository (regression tests)
    //
    // Format-string resolution lives in `RepositoryService::resolve_format`
    // (see `services/repository_service.rs`). These end-to-end tests drive
    // the HTTP handler so we verify both the resolve path and the wiring of
    // the resolved `format_key` into the persisted row.
    // -----------------------------------------------------------------------

    /// Insert a `format_handlers` row for testing.  Returns the `format_key`
    /// that was inserted.  The caller is responsible for deleting the row
    /// after the test (use `cleanup_format_handler`).
    async fn insert_format_handler(pool: &sqlx::PgPool, format_key: &str, is_enabled: bool) {
        sqlx::query(
            "INSERT INTO format_handlers \
             (format_key, handler_type, display_name, is_enabled) \
             VALUES ($1, 'wasm', $2, $3) \
             ON CONFLICT (format_key) DO UPDATE \
             SET is_enabled = EXCLUDED.is_enabled",
        )
        .bind(format_key)
        .bind(format!("Test handler for {}", format_key))
        .bind(is_enabled)
        .execute(pool)
        .await
        .expect("insert format_handler");
    }

    async fn cleanup_format_handler(pool: &sqlx::PgPool, format_key: &str) {
        sqlx::query("DELETE FROM format_handlers WHERE format_key = $1")
            .bind(format_key)
            .execute(pool)
            .await
            .expect("cleanup format_handler");
    }

    /// Helper: build an admin `AuthExtension` so the permission gate in
    /// `create_repository` is bypassed without needing a database permission row.
    fn admin_auth(user_id: Uuid, username: &str) -> crate::api::middleware::auth::AuthExtension {
        crate::api::middleware::auth::AuthExtension {
            user_id,
            username: username.to_string(),
            email: format!("{}@test.local", username),
            is_admin: true,
            is_api_token: false,
            is_service_account: false,
            scopes: None,
            allowed_repo_ids: AccessScope::Admin,
            iat_ms: None,
        }
    }

    /// Build a `CreateRepositoryRequest` body as raw bytes from a minimal
    /// JSON object, merging in `overrides` so individual tests only specify
    /// the fields they care about. Returns bytes (matching the handler's
    /// post-#1438 signature) so tests don't need to round-trip through the
    /// `CreateRepositoryRequest` struct, which is `Deserialize`-only.
    fn make_create_request(
        key: &str,
        name: &str,
        format: &str,
        overrides: serde_json::Value,
    ) -> Bytes {
        let mut base = serde_json::json!({
            "key": key,
            "name": name,
            "format": format,
            "repo_type": "local"
        });
        if let (serde_json::Value::Object(b), serde_json::Value::Object(o)) = (&mut base, overrides)
        {
            b.extend(o);
        }
        Bytes::from(serde_json::to_vec(&base).expect("serialize create-repo payload"))
    }

    /// When a format string is not a built-in variant but there IS an
    /// **enabled** row in `format_handlers`, `create_repository` must succeed
    /// and the resulting repository must have `format = Generic` and
    /// `format_key = <the plugin key>`.
    #[tokio::test]
    async fn test_create_repository_with_enabled_plugin_format() {
        use crate::api::handlers::test_db_helpers as tdh;
        use axum::extract::{Extension, State};

        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let (user_id, username) = tdh::create_user(&pool).await;
        let storage_dir = std::env::temp_dir().join(format!("pk-test-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&storage_dir).expect("create storage dir");
        let state = tdh::build_state(pool.clone(), storage_dir.to_str().unwrap());

        let format_key = format!("test-wasm-{}", Uuid::new_v4().simple());
        insert_format_handler(&pool, &format_key, true).await;

        let repo_key = format!("wasm-repo-{}", Uuid::new_v4().simple());
        let payload = make_create_request(
            &repo_key,
            "WASM plugin repo",
            &format_key,
            serde_json::json!({}),
        );

        let result = create_repository(
            State(state.clone()),
            Extension(Some(admin_auth(user_id, &username))),
            payload,
        )
        .await;

        let Json(resp) = result.expect("create_repository with enabled plugin format must succeed");
        assert_eq!(
            resp.format, "generic",
            "plugin-backed repo must be stored as Generic format"
        );

        // Verify the format_key was persisted to the DB (RepositoryResponse does
        // not expose format_key directly).
        let stored: Option<String> =
            sqlx::query_scalar("SELECT format_key FROM repositories WHERE key = $1")
                .bind(&repo_key)
                .fetch_optional(&pool)
                .await
                .expect("query format_key");

        // Cleanup after reading so we don't delete the row before asserting.
        sqlx::query("DELETE FROM repositories WHERE key = $1")
            .bind(&repo_key)
            .execute(&pool)
            .await
            .ok();
        cleanup_format_handler(&pool, &format_key).await;
        sqlx::query("DELETE FROM users WHERE id = $1")
            .bind(user_id)
            .execute(&pool)
            .await
            .ok();
        let _ = std::fs::remove_dir_all(&storage_dir);

        assert_eq!(
            stored.as_deref(),
            Some(format_key.as_str()),
            "plugin format key must be persisted to the repositories.format_key column"
        );
    }

    /// When the format string maps to a **disabled** `format_handlers` row,
    /// `create_repository` must return a `Validation` error whose message
    /// mentions "disabled".
    #[tokio::test]
    async fn test_create_repository_with_disabled_plugin_format() {
        use crate::api::handlers::test_db_helpers as tdh;
        use axum::extract::{Extension, State};

        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let (user_id, username) = tdh::create_user(&pool).await;
        let storage_dir = std::env::temp_dir().join(format!("pk-test-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&storage_dir).expect("create storage dir");
        let state = tdh::build_state(pool.clone(), storage_dir.to_str().unwrap());

        let format_key = format!("test-disabled-{}", Uuid::new_v4().simple());
        insert_format_handler(&pool, &format_key, false).await;

        let payload = make_create_request(
            &format!("disabled-repo-{}", Uuid::new_v4().simple()),
            "Disabled plugin repo",
            &format_key,
            serde_json::json!({}),
        );

        let result = create_repository(
            State(state.clone()),
            Extension(Some(admin_auth(user_id, &username))),
            payload,
        )
        .await;

        cleanup_format_handler(&pool, &format_key).await;
        sqlx::query("DELETE FROM users WHERE id = $1")
            .bind(user_id)
            .execute(&pool)
            .await
            .ok();
        let _ = std::fs::remove_dir_all(&storage_dir);

        let err = result.expect_err("disabled plugin format must be rejected");
        assert!(
            matches!(err, AppError::Validation(ref msg) if msg.contains("disabled")),
            "disabled plugin format must produce a Validation error mentioning 'disabled', got {err:?}",
        );
    }

    /// When the format string is unknown and has **no** `format_handlers` row
    /// at all, `create_repository` must return a `Validation` error.
    #[tokio::test]
    async fn test_create_repository_with_unknown_format() {
        use crate::api::handlers::test_db_helpers as tdh;
        use axum::extract::{Extension, State};

        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let (user_id, username) = tdh::create_user(&pool).await;
        let storage_dir = std::env::temp_dir().join(format!("pk-test-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&storage_dir).expect("create storage dir");
        let state = tdh::build_state(pool.clone(), storage_dir.to_str().unwrap());

        let payload = make_create_request(
            &format!("unknown-repo-{}", Uuid::new_v4().simple()),
            "Unknown format repo",
            // A format string that will never match any built-in or plugin.
            "totally-unknown-zzz",
            serde_json::json!({}),
        );

        let result = create_repository(
            State(state.clone()),
            Extension(Some(admin_auth(user_id, &username))),
            payload,
        )
        .await;

        sqlx::query("DELETE FROM users WHERE id = $1")
            .bind(user_id)
            .execute(&pool)
            .await
            .ok();
        let _ = std::fs::remove_dir_all(&storage_dir);

        let err = result.expect_err("unknown format must be rejected");
        assert!(
            matches!(err, AppError::Validation(_)),
            "unknown format must surface as Validation (400), got {err:?}",
        );
    }

    /// Build a non-admin `AuthExtension`. Used to confirm that the same
    /// admin/create-repo gate that protects built-in format creation also
    /// guards the WASM-plugin codepath. Without this, a plugin-format string
    /// could be a route around the gate.
    fn non_admin_auth(
        user_id: Uuid,
        username: &str,
    ) -> crate::api::middleware::auth::AuthExtension {
        crate::api::middleware::auth::AuthExtension {
            user_id,
            username: username.to_string(),
            email: format!("{}@test.local", username),
            is_admin: false,
            is_api_token: false,
            is_service_account: false,
            scopes: None,
            allowed_repo_ids: AccessScope::Admin,
            iat_ms: None,
        }
    }

    /// A non-admin caller with no `system:admin` permission must receive an
    /// `Authorization` error even when the requested format is a valid,
    /// enabled WASM plugin format. The plugin codepath inherits the same
    /// permission gate as built-in formats; there is no privileged shortcut.
    #[tokio::test]
    async fn test_create_repository_plugin_format_rejects_non_admin() {
        use crate::api::handlers::test_db_helpers as tdh;
        use axum::extract::{Extension, State};

        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let (user_id, username) = tdh::create_user(&pool).await;
        let storage_dir = std::env::temp_dir().join(format!("pk-test-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&storage_dir).expect("create storage dir");
        let state = tdh::build_state(pool.clone(), storage_dir.to_str().unwrap());

        let format_key = format!("test-noadmin-{}", Uuid::new_v4().simple());
        insert_format_handler(&pool, &format_key, true).await;

        let repo_key = format!("noadmin-repo-{}", Uuid::new_v4().simple());
        let payload = make_create_request(
            &repo_key,
            "Non-admin plugin repo",
            &format_key,
            serde_json::json!({}),
        );

        let result = create_repository(
            State(state.clone()),
            Extension(Some(non_admin_auth(user_id, &username))),
            payload,
        )
        .await;

        // Cleanup: the request should NOT have created a repo row, but delete
        // defensively in case the assertion below fails.
        sqlx::query("DELETE FROM repositories WHERE key = $1")
            .bind(&repo_key)
            .execute(&pool)
            .await
            .ok();
        cleanup_format_handler(&pool, &format_key).await;
        sqlx::query("DELETE FROM users WHERE id = $1")
            .bind(user_id)
            .execute(&pool)
            .await
            .ok();
        let _ = std::fs::remove_dir_all(&storage_dir);

        let err = result.expect_err("non-admin must be denied even for plugin formats");
        assert!(
            matches!(err, AppError::Authorization(_)),
            "non-admin plugin-format creation must surface as Authorization (403), got {err:?}",
        );
    }

    // ---------------------------------------------------------------------
    // #1443 regression: lookup_path_candidates + is_npm_family_format
    //
    // npm publish stores tarballs under the version-segmented shape, but
    // external callers (release-gate smoke test, JFrog-compatible
    // tooling) supply the canonical npm download-URL shape
    // (`<name>/-/<name>-<version>.tgz`). `get_artifact_metadata` walks
    // this list of candidates so the literal request always wins for
    // formats that don't normalise, and npm-family repos quietly fall
    // back to the stored path on the second probe.
    // ---------------------------------------------------------------------

    #[test]
    fn test_delete_blocked_by_immutability_matches_classification() {
        // A released (versioned) Maven jar is immutable -> a non-admin,
        // non-replication delete must be refused. This is the soft-delete +
        // re-upload mutation bypass the gate closes.
        let immutable_path = "com/acme/widget/3.0.0/widget-3.0.0.jar";
        assert!(delete_blocked_by_immutability(
            &RepositoryFormat::Maven,
            immutable_path,
            false, // not admin
            false, // not a trusted replication request
        ));

        // The replication exemption is keyed on a *trusted* machine identity,
        // not the raw client-supplied replication header. A forged header on an
        // ordinary user token does not produce `replication_trusted`, so the
        // delete is still blocked -> the header-forgery bypass is closed.
        assert!(delete_blocked_by_immutability(
            &RepositoryFormat::Maven,
            immutable_path,
            false, // not admin
            false, // forged header on a normal user yields replication_trusted = false
        ));

        // Same coordinates: an admin retraction is allowed.
        assert!(!delete_blocked_by_immutability(
            &RepositoryFormat::Maven,
            immutable_path,
            true,
            false,
        ));

        // Same coordinates: a genuine peer replication delete under a
        // service-account or admin peer token (replication_trusted = true) is
        // allowed -> legitimate peer replication still works.
        assert!(!delete_blocked_by_immutability(
            &RepositoryFormat::Maven,
            immutable_path,
            false,
            true,
        ));

        // Mutable coordinates (SNAPSHOT directory metadata, maven-metadata.xml)
        // are deletable by anyone with the delete scope -> no regression.
        assert!(!delete_blocked_by_immutability(
            &RepositoryFormat::Maven,
            "com/acme/widget/maven-metadata.xml",
            false,
            false,
        ));
        assert!(!delete_blocked_by_immutability(
            &RepositoryFormat::Maven,
            "com/acme/widget/1.0-SNAPSHOT/",
            false,
            false,
        ));

        // The decision tracks the central classifier for other formats too.
        assert!(delete_blocked_by_immutability(
            &RepositoryFormat::Npm,
            "lodash/-/lodash-4.17.21.tgz",
            false,
            false,
        ));
        assert!(!delete_blocked_by_immutability(
            &RepositoryFormat::Npm,
            "lodash",
            false,
            false,
        ));
    }

    #[test]
    fn test_replication_exemption_requires_trusted_identity() {
        // A forged replication header on an ordinary human-user token (no admin,
        // no service account) must NOT grant the exemption -> immutability holds.
        assert!(!replication_exemption_trusted(true, false, false));

        // Without the replication marker at all, identity is irrelevant.
        assert!(!replication_exemption_trusted(false, true, false));
        assert!(!replication_exemption_trusted(false, false, true));
        assert!(!replication_exemption_trusted(false, false, false));

        // Genuine peer replication runs under a service-account or admin token
        // carrying the marker -> the exemption is honored.
        assert!(replication_exemption_trusted(true, false, true));
        assert!(replication_exemption_trusted(true, true, false));
        assert!(replication_exemption_trusted(true, true, true));
    }

    #[test]
    fn test_lookup_path_candidates_npm_url_shape_adds_stored_fallback() {
        let candidates =
            lookup_path_candidates("rfs-pkg/-/rfs-pkg-1.0.0.tgz", &RepositoryFormat::Npm);
        assert_eq!(
            candidates,
            vec![
                "rfs-pkg/-/rfs-pkg-1.0.0.tgz".to_string(),
                "rfs-pkg/1.0.0/rfs-pkg-1.0.0.tgz".to_string(),
            ]
        );
    }

    #[test]
    fn test_lookup_path_candidates_npm_scoped_url_shape() {
        let candidates =
            lookup_path_candidates("@angular/core/-/core-17.0.0.tgz", &RepositoryFormat::Npm);
        assert_eq!(
            candidates,
            vec![
                "@angular/core/-/core-17.0.0.tgz".to_string(),
                "@angular/core/17.0.0/core-17.0.0.tgz".to_string(),
            ]
        );
    }

    #[test]
    fn test_lookup_path_candidates_npm_stored_shape_passthrough() {
        // When the caller already supplies the stored shape,
        // normalize_lookup_path returns None and we issue exactly one
        // query against the literal path.
        let candidates =
            lookup_path_candidates("rfs-pkg/1.0.0/rfs-pkg-1.0.0.tgz", &RepositoryFormat::Npm);
        assert_eq!(
            candidates,
            vec!["rfs-pkg/1.0.0/rfs-pkg-1.0.0.tgz".to_string()]
        );
    }

    #[test]
    fn test_lookup_path_candidates_npm_metadata_path_not_rewritten() {
        // package.json / packument paths don't end in .tgz so
        // normalize_lookup_path returns None and only the literal path
        // is tried.
        let candidates = lookup_path_candidates("lodash/package.json", &RepositoryFormat::Npm);
        assert_eq!(candidates, vec!["lodash/package.json".to_string()]);
    }

    #[test]
    fn test_lookup_path_candidates_non_npm_format_unchanged() {
        // Maven repos must never have their paths rewritten by the npm
        // normaliser, even if a path coincidentally matches `/-/` (it
        // doesn't here, but the guard fires before normalisation
        // anyway).
        let candidates =
            lookup_path_candidates("com/example/lib/1.0/lib-1.0.jar", &RepositoryFormat::Maven);
        assert_eq!(
            candidates,
            vec!["com/example/lib/1.0/lib-1.0.jar".to_string()]
        );

        // And even a path that looks npm-shaped is left alone outside
        // npm-family repos.
        let candidates = lookup_path_candidates("foo/-/foo-1.0.0.tgz", &RepositoryFormat::Generic);
        assert_eq!(candidates, vec!["foo/-/foo-1.0.0.tgz".to_string()]);
    }

    #[test]
    fn test_lookup_path_candidates_yarn_pnpm_bower_apply_normalisation() {
        // Yarn, pnpm, and bower all wrap the npm wire format. They
        // share the publish/download layout so the same normalisation
        // must fire for them.
        for fmt in [
            RepositoryFormat::Yarn,
            RepositoryFormat::Pnpm,
            RepositoryFormat::Bower,
        ] {
            let candidates = lookup_path_candidates("foo/-/foo-1.0.0.tgz", &fmt);
            assert_eq!(
                candidates,
                vec![
                    "foo/-/foo-1.0.0.tgz".to_string(),
                    "foo/1.0.0/foo-1.0.0.tgz".to_string(),
                ],
                "format {fmt:?} must inherit npm path normalisation",
            );
        }
    }

    #[test]
    fn test_is_npm_family_format_membership() {
        assert!(is_npm_family_format(&RepositoryFormat::Npm));
        assert!(is_npm_family_format(&RepositoryFormat::Yarn));
        assert!(is_npm_family_format(&RepositoryFormat::Pnpm));
        assert!(is_npm_family_format(&RepositoryFormat::Bower));
        // Negative cases: every format outside the npm wire-protocol
        // family must NOT inherit npm path normalisation.
        assert!(!is_npm_family_format(&RepositoryFormat::Maven));
        assert!(!is_npm_family_format(&RepositoryFormat::Pypi));
        assert!(!is_npm_family_format(&RepositoryFormat::Docker));
        assert!(!is_npm_family_format(&RepositoryFormat::Generic));
        assert!(!is_npm_family_format(&RepositoryFormat::Cargo));
    }

    /// HTTP-level regression test for #1444: GET /:key/members against a
    /// freshly-created virtual repo (no members yet) must return 2xx, not 404.
    ///
    /// This is the load-bearing assertion behind the user-reported "the
    /// reproducer still fails" comment on #1444. Pre-fix, the chain was:
    ///   1. test infra POSTs `/api/v1/repositories` for a virtual repo WITHOUT
    ///      `member_repos` (the standard deferred-population shape).
    ///   2. #1281's validator 400'd that request, so the virtual was never
    ///      created.
    ///   3. The follow-up POST `/repositories/{key}/members` then 404'd because
    ///      the repo did not exist -- which the release-gate report classified
    ///      as "the members sub-router is unmounted".
    ///
    /// Post-fix, step 1 succeeds with an empty-virtual repo. The /members
    /// router has always been mounted; this test exercises it via the actual
    /// axum `Router` (built from `router()`) so a future refactor that DOES
    /// unmount the route fails this test in addition to the source-text pin
    /// in `virtual_member_router_registration`.
    #[tokio::test]
    async fn test_members_route_returns_2xx_on_freshly_created_empty_virtual_1444() {
        use crate::api::handlers::test_db_helpers as tdh;
        use axum::body::Body;
        use axum::extract::{Extension, State};
        use axum::http::{Request, StatusCode};

        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let (user_id, username) = tdh::create_user(&pool).await;
        let storage_dir =
            std::env::temp_dir().join(format!("members-1444-{}", Uuid::new_v4().simple()));
        std::fs::create_dir_all(&storage_dir).expect("create storage dir");
        let state = tdh::build_state(pool.clone(), storage_dir.to_str().unwrap());

        // Step 1: create the virtual repo via the actual `create_repository`
        // handler with `member_repos` OMITTED -- the deferred-population shape
        // every E2E test helper uses.
        let repo_key = format!("v-1444-{}", Uuid::new_v4().simple());
        let payload = make_create_request(
            &repo_key,
            "Virtual 1444 regression",
            "generic",
            serde_json::json!({ "repo_type": "virtual" }),
        );
        // Post-#1438 `create_repository` takes `body: Bytes` so auth runs
        // before body deserialisation. `make_create_request` already returns
        // `Bytes`; pass it through directly (no `Json(...)` wrapper).
        let create_result = create_repository(
            State(state.clone()),
            Extension(Some(admin_auth(user_id, &username))),
            payload,
        )
        .await;
        // The whole point of #1444 is that this NO LONGER returns 400.
        let _created = create_result
            .expect("create_repository must accept virtual repo with member_repos omitted (#1444)");

        // Step 2: drive the actual /members route via axum::Router::oneshot.
        // We mount `router()` as-is, wrap it in the auth-injection layer the
        // production router applies, and hit GET /{key}/members.
        let router = tdh::router_with_auth(
            super::router(),
            state.clone(),
            admin_auth(user_id, &username),
        );
        let req = Request::builder()
            .method("GET")
            .uri(format!("/{}/members", repo_key))
            .body(Body::empty())
            .expect("build GET /members request");
        let (status, body) = tdh::send(router, req).await;

        // Cleanup before asserting so a panic does not leak DB state.
        sqlx::query(
            "DELETE FROM virtual_repo_members WHERE virtual_repo_id IN \
                     (SELECT id FROM repositories WHERE key = $1)",
        )
        .bind(&repo_key)
        .execute(&pool)
        .await
        .ok();
        sqlx::query("DELETE FROM repositories WHERE key = $1")
            .bind(&repo_key)
            .execute(&pool)
            .await
            .ok();
        sqlx::query("DELETE FROM users WHERE id = $1")
            .bind(user_id)
            .execute(&pool)
            .await
            .ok();
        let _ = std::fs::remove_dir_all(&storage_dir);

        assert_ne!(
            status,
            StatusCode::NOT_FOUND,
            "GET /:key/members on a freshly-created empty virtual must NOT return \
             404 (regression of #1444 -- the symptom that the release-gate Full \
             Suite classified as \"members sub-router unmounted\"); got body: {}",
            String::from_utf8_lossy(&body)
        );
        assert!(
            status.is_success(),
            "GET /:key/members on a freshly-created empty virtual must return 2xx; \
             got {} with body: {}",
            status,
            String::from_utf8_lossy(&body)
        );
    }

    /// PEP 708 (#1600): a PyPI virtual isolates a locally-owned project name by
    /// default (so an unrelated public package of the same name is never served
    /// through the virtual), and only unblocks the cross-member union when an
    /// operator `tracks` declaration exists on the owning member.
    #[tokio::test]
    async fn pypi_virtual_isolates_locally_owned_name_until_tracks_declared() {
        use crate::api::handlers::test_db_helpers as tdh;
        let Some(pool) = tdh::try_pool().await else {
            return;
        };

        let (local_id, _lk, local_dir) = tdh::create_repo(&pool, "local", "pypi").await;
        let (remote_id, _rk, remote_dir) = tdh::create_repo(&pool, "remote", "pypi").await;
        let (virtual_id, _vk, virtual_dir) = tdh::create_repo(&pool, "virtual", "pypi").await;

        for (member, priority) in [(local_id, 1_i32), (remote_id, 2_i32)] {
            sqlx::query(
                "INSERT INTO virtual_repo_members (virtual_repo_id, member_repo_id, priority) \
                 VALUES ($1, $2, $3)",
            )
            .bind(virtual_id)
            .bind(member)
            .bind(priority)
            .execute(&pool)
            .await
            .expect("insert virtual member");
        }

        // The local member owns the internal project `acme-sdk`.
        sqlx::query(
            "INSERT INTO artifacts \
             (repository_id, path, name, size_bytes, checksum_sha256, content_type, storage_key) \
             VALUES ($1, $2, $3, $4, $5, $6, $7)",
        )
        .bind(local_id)
        .bind("acme-sdk/1.0.0/acme_sdk-1.0.0-py3-none-any.whl")
        .bind("acme-sdk")
        .bind(1_i64)
        .bind("0".repeat(64))
        .bind("application/octet-stream")
        .bind("pypi/acme/1")
        .execute(&pool)
        .await
        .expect("seed local artifact");

        // Default: owned locally, no tracks -> ISOLATE (do not merge upstream).
        assert!(
            matches!(
                proxy_helpers::pypi_virtual_isolates_name(&pool, virtual_id, "acme-sdk").await,
                Ok(true)
            ),
            "a locally-owned name with no tracks declaration must be isolated"
        );

        // A name the local member does not own -> proxy normally (no isolation).
        assert!(
            matches!(
                proxy_helpers::pypi_virtual_isolates_name(&pool, virtual_id, "six").await,
                Ok(false)
            ),
            "a name no local member owns must not be isolated"
        );

        // Operator declares the local project tracks upstream -> union allowed.
        sqlx::query(
            "INSERT INTO pypi_project_tracks (repository_id, normalized_name, tracks_url) \
             VALUES ($1, $2, $3)",
        )
        .bind(local_id)
        .bind("acme-sdk")
        .bind("https://pypi.org/simple/acme-sdk/")
        .execute(&pool)
        .await
        .expect("declare tracks");

        assert!(
            matches!(
                proxy_helpers::pypi_virtual_isolates_name(&pool, virtual_id, "acme-sdk").await,
                Ok(false)
            ),
            "a tracks declaration must re-enable the cross-member union"
        );

        sqlx::query("DELETE FROM repositories WHERE id = ANY($1)")
            .bind(vec![local_id, remote_id, virtual_id])
            .execute(&pool)
            .await
            .ok();
        let _ = std::fs::remove_dir_all(&local_dir);
        let _ = std::fs::remove_dir_all(&remote_dir);
        let _ = std::fs::remove_dir_all(&virtual_dir);
    }

    // -----------------------------------------------------------------------
    // #2269: the generic download/delete handlers must resolve the canonical
    // npm `/-/` URL shape the Web UI emits to the version-segmented path a
    // tarball is actually stored under. `lookup_path_candidates` is the guard
    // predicate: it yields `[url, stored]` (len 2) for an npm `/-/` tarball URL
    // and `[literal]` (len 1) for everything else, so the resolver only takes
    // the extra DB roundtrip when a normalized candidate can exist.
    // -----------------------------------------------------------------------

    #[test]
    fn lookup_path_candidates_pairs_npm_url_and_stored_shapes() {
        // Unscoped `/-/` URL -> [url, version-segmented stored].
        let unscoped =
            lookup_path_candidates("npm-test/-/npm-test-1.0.0.tgz", &RepositoryFormat::Npm);
        assert_eq!(
            unscoped,
            vec![
                "npm-test/-/npm-test-1.0.0.tgz".to_string(),
                "npm-test/1.0.0/npm-test-1.0.0.tgz".to_string(),
            ],
            "an npm `/-/` tarball URL must expand to [url, stored] so the guard resolves it"
        );

        // Scoped `/-/` URL -> [url, version-segmented stored].
        let scoped = lookup_path_candidates("@scope/pkg/-/pkg-2.1.0.tgz", &RepositoryFormat::Npm);
        assert_eq!(
            scoped,
            vec![
                "@scope/pkg/-/pkg-2.1.0.tgz".to_string(),
                "@scope/pkg/2.1.0/pkg-2.1.0.tgz".to_string(),
            ],
        );

        // yarn is npm-family too.
        assert_eq!(
            lookup_path_candidates("npm-test/-/npm-test-1.0.0.tgz", &RepositoryFormat::Yarn).len(),
            2,
        );

        // An already-stored version-segmented npm path has no distinct
        // normalized shape -> single candidate, guard short-circuits.
        assert_eq!(
            lookup_path_candidates("npm-test/1.0.0/npm-test-1.0.0.tgz", &RepositoryFormat::Npm)
                .len(),
            1,
        );

        // Non-npm formats never expand -> single candidate, byte-identical path.
        assert_eq!(
            lookup_path_candidates("com/acme/app/1.0.0/app-1.0.0.jar", &RepositoryFormat::Maven)
                .len(),
            1,
        );
        assert_eq!(
            lookup_path_candidates("some/raw/file.bin", &RepositoryFormat::Generic).len(),
            1,
        );
    }

    /// Build a bodyless GET request for `download_artifact`.
    #[cfg(test)]
    fn get_request() -> axum::http::Request<axum::body::Body> {
        axum::http::Request::builder()
            .method(axum::http::Method::GET)
            .uri("/")
            .body(axum::body::Body::empty())
            .expect("request")
    }

    /// #2269: an npm tarball stored under the version-segmented layout must be
    /// downloadable AND deletable from the canonical `/-/` URL shape the Web UI
    /// emits, while the literal stored path and a bogus path behave as before.
    #[tokio::test]
    async fn npm_generic_download_delete_resolve_canonical_url_db() {
        use crate::api::handlers::test_db_helpers as tdh;
        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let (user_id, username) = tdh::create_user(&pool).await;
        let (repo_id, key, dir) = tdh::create_repo(&pool, "local", "npm").await;
        tdh::grant_repo_access(&pool, repo_id, user_id).await;
        let state = tdh::build_state(pool.clone(), dir.to_string_lossy().as_ref());
        let auth = Some(tdh::make_auth(user_id, &username));

        // Publish tarballs under the exact version-segmented layout
        // `npm::store_npm_version` writes.
        let unscoped_stored = "npm-test/1.0.0/npm-test-1.0.0.tgz".to_string();
        let scoped_stored = "@scope/pkg/2.1.0/pkg-2.1.0.tgz".to_string();
        for p in [&unscoped_stored, &scoped_stored] {
            upload_artifact(
                State(state.clone()),
                Extension(auth.clone()),
                Path((key.clone(), p.clone())),
                HeaderMap::new(),
                Bytes::from_static(b"TARBALL-BYTES"),
            )
            .await
            .expect("publish must succeed");
        }

        // (1) Download via the canonical `/-/` URL shape -> 200 (was 404).
        let dl = download_artifact(
            State(state.clone()),
            Extension(auth.clone()),
            Path((key.clone(), "npm-test/-/npm-test-1.0.0.tgz".to_string())),
            get_request(),
        )
        .await;
        assert_eq!(
            dl.expect("download via /-/ shape must resolve")
                .into_response()
                .status(),
            StatusCode::OK,
            "generic download of a version-segmented npm tarball via /-/ must be 200 (#2269)"
        );

        // (2) Download via the literal stored path still resolves (literal-first).
        let dl_literal = download_artifact(
            State(state.clone()),
            Extension(auth.clone()),
            Path((key.clone(), unscoped_stored.clone())),
            get_request(),
        )
        .await;
        assert_eq!(
            dl_literal
                .expect("download via literal path must resolve")
                .into_response()
                .status(),
            StatusCode::OK,
        );

        // (3) A bogus `/-/` path (no matching row) must still 404 — the resolver
        // leaves the path unchanged on a miss so downstream lookup fails cleanly.
        let dl_bogus = download_artifact(
            State(state.clone()),
            Extension(auth.clone()),
            Path((key.clone(), "nope/-/nope-9.9.9.tgz".to_string())),
            get_request(),
        )
        .await;
        assert!(
            matches!(dl_bogus, Err(AppError::NotFound(_))),
            "an unknown npm tarball must still 404 (resolver leaves a miss path unchanged)"
        );

        // (4) Scoped delete via the canonical `/-/` URL shape -> Ok (was 404),
        // and the row is soft-deleted. npm tarballs classify Mutable (no `/-/`
        // in the resolved stored path) so the immutability gate permits this.
        let del_scoped = delete_artifact(
            State(state.clone()),
            Extension(auth.clone()),
            Path((key.clone(), "@scope/pkg/-/pkg-2.1.0.tgz".to_string())),
            HeaderMap::new(),
        )
        .await;
        assert!(
            del_scoped.is_ok(),
            "scoped npm delete via /-/ shape must succeed (#2269), got: {del_scoped:?}"
        );
        let scoped_live: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM artifacts WHERE repository_id = $1 AND path = $2 AND is_deleted = false",
        )
        .bind(repo_id)
        .bind(&scoped_stored)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(scoped_live, 0, "the scoped tarball must be soft-deleted");

        // (5) Unscoped delete via the canonical `/-/` URL shape -> Ok, row gone.
        let del_unscoped = delete_artifact(
            State(state.clone()),
            Extension(auth.clone()),
            Path((key.clone(), "npm-test/-/npm-test-1.0.0.tgz".to_string())),
            HeaderMap::new(),
        )
        .await;
        assert!(
            del_unscoped.is_ok(),
            "unscoped npm delete via /-/ shape must succeed (#2269), got: {del_unscoped:?}"
        );
        let unscoped_live: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM artifacts WHERE repository_id = $1 AND path = $2 AND is_deleted = false",
        )
        .bind(repo_id)
        .bind(&unscoped_stored)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(
            unscoped_live, 0,
            "the unscoped tarball must be soft-deleted"
        );

        tdh::cleanup(&pool, repo_id, user_id).await;
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// #2269 short-circuit guard: a non-npm (generic) repo must be completely
    /// unaffected — an exact-path download still 200 and a bogus path still 404,
    /// with no path rewriting (the `candidates.len() > 1` guard skips the
    /// resolver for formats that have no `/-/` normalization).
    #[tokio::test]
    async fn generic_non_npm_download_unchanged_db() {
        use crate::api::handlers::test_db_helpers as tdh;
        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let (user_id, username) = tdh::create_user(&pool).await;
        let (repo_id, key, dir) = tdh::create_repo(&pool, "local", "generic").await;
        tdh::grant_repo_access(&pool, repo_id, user_id).await;
        let state = tdh::build_state(pool.clone(), dir.to_string_lossy().as_ref());
        let auth = Some(tdh::make_auth(user_id, &username));

        let path = "tools/build-1.0.0.bin".to_string();
        upload_artifact(
            State(state.clone()),
            Extension(auth.clone()),
            Path((key.clone(), path.clone())),
            HeaderMap::new(),
            Bytes::from_static(b"GENERIC-BYTES"),
        )
        .await
        .expect("publish must succeed");

        let dl = download_artifact(
            State(state.clone()),
            Extension(auth.clone()),
            Path((key.clone(), path.clone())),
            get_request(),
        )
        .await;
        assert_eq!(
            dl.expect("exact-path download must resolve")
                .into_response()
                .status(),
            StatusCode::OK,
        );

        let dl_bogus = download_artifact(
            State(state.clone()),
            Extension(auth.clone()),
            Path((key.clone(), "tools/does-not-exist.bin".to_string())),
            get_request(),
        )
        .await;
        assert!(
            matches!(dl_bogus, Err(AppError::NotFound(_))),
            "an unknown generic path must still 404 (guard short-circuits for non-npm)"
        );

        tdh::cleanup(&pool, repo_id, user_id).await;
        let _ = std::fs::remove_dir_all(&dir);
    }
}
