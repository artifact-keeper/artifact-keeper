//! Repository-scoped access token management.
//!
//! Allows repository administrators (users with write scope or global admins)
//! to create, list, and revoke API tokens scoped to a specific repository.
//! Tokens created through these endpoints are automatically restricted to the
//! repository they were created on via the `api_token_repositories` join table.

use std::sync::Arc;

use axum::{
    extract::{Extension, Path, State},
    routing::get,
    Json, Router,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use utoipa::{OpenApi, ToSchema};
use uuid::Uuid;

use crate::api::middleware::auth::AuthExtension;
use crate::api::SharedState;
use crate::error::{AppError, Result};
use crate::services::auth_service::AuthService;
use crate::services::repository_service::RepositoryService;
use crate::services::token_service::{is_token_expired, validate_scopes_pure};

/// Routes nested under /api/v1/repositories/:key/tokens
pub fn repo_tokens_router() -> Router<SharedState> {
    Router::new()
        .route(
            "/:key/tokens",
            get(list_repo_tokens).post(create_repo_token),
        )
        .route(
            "/:key/tokens/:token_id",
            get(get_repo_token).delete(revoke_repo_token),
        )
}

// ---------------------------------------------------------------------------
// Request / response types
// ---------------------------------------------------------------------------

/// Request to create an access token scoped to a repository.
#[derive(Debug, Deserialize, ToSchema)]
pub struct CreateRepoTokenRequest {
    /// Display name for the token.
    pub name: String,
    /// Permission scopes for the token.
    pub scopes: Vec<String>,
    /// Number of days until the token expires (1-365). Omit for no expiration.
    pub expires_in_days: Option<i64>,
    /// Optional human-readable description.
    pub description: Option<String>,
}

/// Response returned when a repository token is created. The `token` field
/// contains the plaintext value and is only shown once.
#[derive(Debug, Serialize, ToSchema)]
pub struct CreateRepoTokenResponse {
    pub id: Uuid,
    /// The full token value (only returned at creation time).
    pub token: String,
    pub name: String,
    pub repository_key: String,
}

/// Summary of a repository-scoped token.
#[derive(Debug, Serialize, ToSchema)]
pub struct RepoTokenResponse {
    pub id: Uuid,
    pub name: String,
    pub token_prefix: String,
    pub scopes: Vec<String>,
    pub expires_at: Option<DateTime<Utc>>,
    pub last_used_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub is_expired: bool,
    pub is_revoked: bool,
    pub description: Option<String>,
    pub created_by: Option<String>,
}

/// List of tokens configured on a repository.
#[derive(Debug, Serialize, ToSchema)]
pub struct RepoTokenListResponse {
    pub items: Vec<RepoTokenResponse>,
}

// ---------------------------------------------------------------------------
// Pure helpers
// ---------------------------------------------------------------------------

/// Validate `expires_in_days` is within the allowed range (1..=365) or None.
pub(crate) fn validate_expiry_days(days: Option<i64>) -> Result<()> {
    if let Some(d) = days {
        if !(1..=365).contains(&d) {
            return Err(AppError::Validation(
                "Token expiration must be between 1 and 365 days".to_string(),
            ));
        }
    }
    Ok(())
}

/// Whether `auth` may read or revoke a token whose owning user is
/// `created_by_user_id`.
///
/// A global admin may manage any token. Otherwise the caller must be the
/// token's creator. A `NULL` owner (legacy rows that predate
/// `created_by_user_id`, migration 057) is owned by nobody, so a non-admin is
/// denied — a safe deny-by-default that still lets an admin clean them up.
fn caller_owns_token(auth: &AuthExtension, created_by_user_id: Option<Uuid>) -> bool {
    auth.is_admin || created_by_user_id == Some(auth.user_id)
}

/// Require that the caller is authenticated and has write scope on repos
/// (or is a global admin).
fn require_repo_write(auth: Option<AuthExtension>) -> Result<AuthExtension> {
    let auth =
        auth.ok_or_else(|| AppError::Authentication("Authentication required".to_string()))?;
    if auth.is_admin {
        return Ok(auth);
    }
    auth.require_scope("write:repositories")?;
    Ok(auth)
}

/// Authorize the caller for a repo-tokens endpoint and resolve the target
/// repository. Returns the validated `(auth, repo)` pair on success.
///
/// This collapses the three-step pre-amble shared by every handler in this
/// module: `require_repo_write`, `RepositoryService::get_by_key`, and the
/// per-caller `can_access_repo` visibility check. The `NotFound` (rather
/// than `Forbidden`) response on visibility failure is intentional: it
/// prevents an unauthorized caller from probing repository existence.
async fn authorize_repo_for_tokens(
    state: &SharedState,
    auth: Option<AuthExtension>,
    key: &str,
) -> Result<(AuthExtension, crate::models::repository::Repository)> {
    let auth = require_repo_write(auth)?;

    let repo_service = RepositoryService::new(state.db.clone());
    let repo = repo_service.get_by_key(key).await?;

    if !auth.can_access_repo(repo.id) {
        return Err(AppError::NotFound(format!(
            "Repository '{}' not found",
            key
        )));
    }

    // Per-repo authorization (mirrors `require_visible` in the repositories
    // handler). The `can_access_repo` check above only enforces the *token's*
    // repo scope — a broad `write:repositories` token (`allowed_repo_ids =
    // None`) passes it for ANY repo. Without this DB-level check, any
    // authenticated user with the write scope could mint repo-scoped tokens on
    // a PRIVATE repository they cannot see (#1783). A private repo is visible
    // only to an admin or a user with a role assignment scoped to it.
    if !repo.is_public
        && !auth.is_admin
        && !repo_service
            .user_can_access_repo(repo.id, auth.user_id)
            .await?
    {
        return Err(AppError::NotFound(format!(
            "Repository '{}' not found",
            key
        )));
    }

    Ok((auth, repo))
}

// ---------------------------------------------------------------------------
// Row types for unchecked queries
// ---------------------------------------------------------------------------

/// Row returned when listing tokens for a repository.
#[derive(Debug, sqlx::FromRow)]
struct TokenRow {
    id: Uuid,
    name: String,
    token_prefix: String,
    scopes: Vec<String>,
    expires_at: Option<DateTime<Utc>>,
    last_used_at: Option<DateTime<Utc>>,
    created_at: DateTime<Utc>,
    revoked_at: Option<DateTime<Utc>>,
    description: Option<String>,
    created_by_username: Option<String>,
    /// Owning user (the token's creator). `NULL` for legacy rows that
    /// predate `created_by_user_id` — treated as owned by nobody, so only a
    /// global admin may read/revoke them.
    created_by_user_id: Option<Uuid>,
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

/// List all access tokens configured on a repository.
#[utoipa::path(
    get,
    path = "/{key}/tokens",
    context_path = "/api/v1/repositories",
    tag = "repository_tokens",
    params(("key" = String, Path, description = "Repository key")),
    responses(
        (status = 200, description = "List of tokens on this repository", body = RepoTokenListResponse),
        (status = 401, description = "Not authenticated"),
        (status = 403, description = "Insufficient permissions"),
        (status = 404, description = "Repository not found"),
    ),
    security(("bearer_auth" = []))
)]
pub async fn list_repo_tokens(
    State(state): State<SharedState>,
    Extension(auth): Extension<Option<AuthExtension>>,
    Path(key): Path<String>,
) -> Result<Json<RepoTokenListResponse>> {
    let (auth, repo) = authorize_repo_for_tokens(&state, auth, &key).await?;

    let rows: Vec<TokenRow> = sqlx::query_as(
        r#"
        SELECT
            t.id,
            t.name,
            t.token_prefix,
            t.scopes,
            t.expires_at,
            t.last_used_at,
            t.created_at,
            t.revoked_at,
            t.description,
            u.username AS created_by_username,
            t.created_by_user_id
        FROM api_tokens t
        INNER JOIN api_token_repositories atr ON atr.token_id = t.id
        LEFT JOIN users u ON u.id = t.created_by_user_id
        WHERE atr.repo_id = $1
        ORDER BY t.created_at DESC
        "#,
    )
    .bind(repo.id)
    .fetch_all(&state.db)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;

    // Per-token ownership filter: repo access is shared by every same-tenant
    // member with `write:repositories`, so without this a peer could enumerate
    // (and via the detail/revoke endpoints, act on) another member's tokens.
    // Non-admins only see the tokens they created; admins see all (CWE-639).
    let items = rows
        .into_iter()
        .filter(|r| caller_owns_token(&auth, r.created_by_user_id))
        .map(|r| RepoTokenResponse {
            id: r.id,
            name: r.name,
            token_prefix: r.token_prefix,
            scopes: r.scopes.clone(),
            expires_at: r.expires_at,
            last_used_at: r.last_used_at,
            created_at: r.created_at,
            is_expired: is_token_expired(r.expires_at),
            is_revoked: r.revoked_at.is_some(),
            description: r.description,
            created_by: r.created_by_username,
        })
        .collect();

    Ok(Json(RepoTokenListResponse { items }))
}

/// Create a new access token scoped to a repository.
///
/// The token is automatically restricted to this repository. The plaintext
/// token value is returned only in this response and cannot be retrieved later.
#[utoipa::path(
    post,
    path = "/{key}/tokens",
    context_path = "/api/v1/repositories",
    tag = "repository_tokens",
    params(("key" = String, Path, description = "Repository key")),
    request_body = CreateRepoTokenRequest,
    responses(
        (status = 200, description = "Token created (value shown once)", body = CreateRepoTokenResponse),
        (status = 400, description = "Validation error"),
        (status = 401, description = "Not authenticated"),
        (status = 403, description = "Insufficient permissions"),
        (status = 404, description = "Repository not found"),
    ),
    security(("bearer_auth" = []))
)]
pub async fn create_repo_token(
    State(state): State<SharedState>,
    Extension(auth): Extension<Option<AuthExtension>>,
    Path(key): Path<String>,
    Json(payload): Json<CreateRepoTokenRequest>,
) -> Result<Json<CreateRepoTokenResponse>> {
    let (auth, repo) = authorize_repo_for_tokens(&state, auth, &key).await?;

    // Validate inputs
    validate_scopes_pure(&payload.scopes).map_err(AppError::Validation)?;
    validate_expiry_days(payload.expires_in_days)?;

    if payload.name.trim().is_empty() {
        return Err(AppError::Validation(
            "Token name must not be empty".to_string(),
        ));
    }

    // Refuse admin-class scopes from non-admin callers. The legacy check
    // only blocked the literal "admin" scope, leaving non-admins able to
    // mint `*`, `delete:artifacts`, `delete:repositories`, and
    // `write:users` via this repo-scoped endpoint. See
    // `token_service::ADMIN_ONLY_SCOPES` for the policy list and rationale.
    crate::services::token_service::enforce_admin_only_scopes(&payload.scopes, auth.is_admin)
        .map_err(AppError::Authorization)?;

    // Generate the token
    let auth_service = AuthService::new(state.db.clone(), Arc::new(state.config.clone()));
    let (token, token_id) = auth_service
        .generate_api_token(
            auth.user_id,
            &payload.name,
            payload.scopes,
            payload.expires_in_days,
        )
        .await?;

    // Restrict the token to this repository
    sqlx::query("INSERT INTO api_token_repositories (token_id, repo_id) VALUES ($1, $2)")
        .bind(token_id)
        .bind(repo.id)
        .execute(&state.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

    // Store created_by and description
    sqlx::query("UPDATE api_tokens SET created_by_user_id = $1, description = $2 WHERE id = $3")
        .bind(auth.user_id)
        .bind(payload.description.as_deref())
        .bind(token_id)
        .execute(&state.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

    Ok(Json(CreateRepoTokenResponse {
        id: token_id,
        token,
        name: payload.name,
        repository_key: key,
    }))
}

/// Get details of a specific token on a repository.
#[utoipa::path(
    get,
    path = "/{key}/tokens/{token_id}",
    context_path = "/api/v1/repositories",
    tag = "repository_tokens",
    params(
        ("key" = String, Path, description = "Repository key"),
        ("token_id" = Uuid, Path, description = "Token ID"),
    ),
    responses(
        (status = 200, description = "Token details", body = RepoTokenResponse),
        (status = 401, description = "Not authenticated"),
        (status = 403, description = "Insufficient permissions"),
        (status = 404, description = "Repository or token not found"),
    ),
    security(("bearer_auth" = []))
)]
pub async fn get_repo_token(
    State(state): State<SharedState>,
    Extension(auth): Extension<Option<AuthExtension>>,
    Path((key, token_id)): Path<(String, Uuid)>,
) -> Result<Json<RepoTokenResponse>> {
    let (auth, repo) = authorize_repo_for_tokens(&state, auth, &key).await?;

    let row: TokenRow = sqlx::query_as(
        r#"
        SELECT
            t.id,
            t.name,
            t.token_prefix,
            t.scopes,
            t.expires_at,
            t.last_used_at,
            t.created_at,
            t.revoked_at,
            t.description,
            u.username AS created_by_username,
            t.created_by_user_id
        FROM api_tokens t
        INNER JOIN api_token_repositories atr ON atr.token_id = t.id
        LEFT JOIN users u ON u.id = t.created_by_user_id
        WHERE atr.repo_id = $1 AND t.id = $2
        "#,
    )
    .bind(repo.id)
    .bind(token_id)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?
    .ok_or_else(|| AppError::NotFound("Token not found on this repository".to_string()))?;

    // Per-token ownership gate (CWE-639). Repo access is shared by every member
    // with `write:repositories`, so the repo-level check above is not enough to
    // read another member's token. Return the same existence-hiding 404 as a
    // missing token so this does not become an owner-probing oracle.
    if !caller_owns_token(&auth, row.created_by_user_id) {
        return Err(AppError::NotFound(
            "Token not found on this repository".to_string(),
        ));
    }

    Ok(Json(RepoTokenResponse {
        id: row.id,
        name: row.name,
        token_prefix: row.token_prefix,
        scopes: row.scopes.clone(),
        expires_at: row.expires_at,
        last_used_at: row.last_used_at,
        created_at: row.created_at,
        is_expired: is_token_expired(row.expires_at),
        is_revoked: row.revoked_at.is_some(),
        description: row.description,
        created_by: row.created_by_username,
    }))
}

/// Revoke an access token from a repository.
///
/// This soft-revokes the token by setting `revoked_at`. The token will
/// immediately stop working for authentication.
#[utoipa::path(
    delete,
    path = "/{key}/tokens/{token_id}",
    context_path = "/api/v1/repositories",
    tag = "repository_tokens",
    params(
        ("key" = String, Path, description = "Repository key"),
        ("token_id" = Uuid, Path, description = "Token ID"),
    ),
    responses(
        (status = 204, description = "Token revoked"),
        (status = 401, description = "Not authenticated"),
        (status = 403, description = "Insufficient permissions"),
        (status = 404, description = "Repository or token not found"),
    ),
    security(("bearer_auth" = []))
)]
pub async fn revoke_repo_token(
    State(state): State<SharedState>,
    Extension(auth): Extension<Option<AuthExtension>>,
    Path((key, token_id)): Path<(String, Uuid)>,
) -> Result<axum::http::StatusCode> {
    let (auth, repo) = authorize_repo_for_tokens(&state, auth, &key).await?;

    // Verify the token belongs to this repository
    let exists: Option<(Uuid,)> = sqlx::query_as(
        "SELECT token_id FROM api_token_repositories WHERE token_id = $1 AND repo_id = $2",
    )
    .bind(token_id)
    .bind(repo.id)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;

    if exists.is_none() {
        return Err(AppError::NotFound(
            "Token not found on this repository".to_string(),
        ));
    }

    // Look up the owning user_id so we can revoke through the standard path,
    // and the creator so we can enforce per-token ownership. `user_id` is the
    // token's auth principal; `created_by_user_id` is the creator that owns
    // management of the token.
    let owner: (Uuid, Option<Uuid>) =
        sqlx::query_as("SELECT user_id, created_by_user_id FROM api_tokens WHERE id = $1")
            .bind(token_id)
            .fetch_optional(&state.db)
            .await
            .map_err(|e| AppError::Database(e.to_string()))?
            .ok_or_else(|| AppError::NotFound("Token not found".to_string()))?;

    // Per-token ownership gate (CWE-639). Without this, any same-tenant member
    // with repo access could silently revoke a peer's token (a DoS), since the
    // revoke below self-supplies the token's own owner to satisfy
    // `revoke_api_token`'s owner filter. Same existence-hiding 404 as a missing
    // token so this is not an owner-probing oracle.
    if !caller_owns_token(&auth, owner.1) {
        return Err(AppError::NotFound(
            "Token not found on this repository".to_string(),
        ));
    }

    let auth_service = AuthService::new(state.db.clone(), Arc::new(state.config.clone()));
    auth_service.revoke_api_token(token_id, owner.0).await?;

    Ok(axum::http::StatusCode::NO_CONTENT)
}

// ---------------------------------------------------------------------------
// OpenAPI
// ---------------------------------------------------------------------------

#[derive(OpenApi)]
#[openapi(
    paths(
        list_repo_tokens,
        create_repo_token,
        get_repo_token,
        revoke_repo_token,
    ),
    components(schemas(
        CreateRepoTokenRequest,
        CreateRepoTokenResponse,
        RepoTokenResponse,
        RepoTokenListResponse,
    )),
    tags(
        (name = "repository_tokens", description = "Repository-scoped access token management"),
    )
)]
pub struct RepoTokensApiDoc;

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // validate_expiry_days
    // -----------------------------------------------------------------------

    #[test]
    fn test_validate_expiry_days_valid_range() {
        assert!(validate_expiry_days(Some(1)).is_ok());
        assert!(validate_expiry_days(Some(30)).is_ok());
        assert!(validate_expiry_days(Some(365)).is_ok());
    }

    #[test]
    fn test_validate_expiry_days_none_is_valid() {
        assert!(validate_expiry_days(None).is_ok());
    }

    #[test]
    fn test_validate_expiry_days_zero_rejected() {
        assert!(validate_expiry_days(Some(0)).is_err());
    }

    #[test]
    fn test_validate_expiry_days_negative_rejected() {
        assert!(validate_expiry_days(Some(-1)).is_err());
    }

    #[test]
    fn test_validate_expiry_days_over_365_rejected() {
        assert!(validate_expiry_days(Some(366)).is_err());
    }

    #[test]
    fn test_validate_expiry_days_large_value_rejected() {
        assert!(validate_expiry_days(Some(1000)).is_err());
    }

    // -----------------------------------------------------------------------
    // require_repo_write
    // -----------------------------------------------------------------------

    fn make_auth(is_admin: bool, scopes: Option<Vec<String>>) -> AuthExtension {
        AuthExtension {
            user_id: Uuid::new_v4(),
            username: "tester".to_string(),
            email: "test@example.com".to_string(),
            is_admin,
            is_api_token: scopes.is_some(),
            is_service_account: false,
            scopes,
            allowed_repo_ids: None,
        }
    }

    #[test]
    fn test_require_repo_write_admin_allowed() {
        let auth = make_auth(true, None);
        assert!(require_repo_write(Some(auth)).is_ok());
    }

    #[test]
    fn test_require_repo_write_jwt_user_allowed() {
        // JWT sessions (non-API-token) always pass scope checks
        let auth = make_auth(false, None);
        assert!(require_repo_write(Some(auth)).is_ok());
    }

    #[test]
    fn test_require_repo_write_api_token_with_scope_allowed() {
        let auth = make_auth(false, Some(vec!["write:repositories".to_string()]));
        assert!(require_repo_write(Some(auth)).is_ok());
    }

    #[test]
    fn test_require_repo_write_api_token_wildcard_allowed() {
        let auth = make_auth(false, Some(vec!["*".to_string()]));
        assert!(require_repo_write(Some(auth)).is_ok());
    }

    #[test]
    fn test_require_repo_write_api_token_wrong_scope_rejected() {
        let auth = make_auth(false, Some(vec!["read:artifacts".to_string()]));
        assert!(require_repo_write(Some(auth)).is_err());
    }

    #[test]
    fn test_require_repo_write_none_rejected() {
        assert!(require_repo_write(None).is_err());
    }

    // -----------------------------------------------------------------------
    // caller_owns_token (per-token ownership gate, CWE-639)
    // -----------------------------------------------------------------------

    #[test]
    fn test_caller_owns_token_creator_allowed() {
        let auth = make_auth(false, None);
        assert!(caller_owns_token(&auth, Some(auth.user_id)));
    }

    #[test]
    fn test_caller_owns_token_peer_denied() {
        let auth = make_auth(false, None);
        let peer = Uuid::new_v4();
        assert!(!caller_owns_token(&auth, Some(peer)));
    }

    #[test]
    fn test_caller_owns_token_admin_allowed_for_any_owner() {
        let auth = make_auth(true, None);
        assert!(caller_owns_token(&auth, Some(Uuid::new_v4())));
        assert!(caller_owns_token(&auth, None));
    }

    #[test]
    fn test_caller_owns_token_null_owner_denied_for_non_admin() {
        let auth = make_auth(false, None);
        assert!(!caller_owns_token(&auth, None));
    }

    // -----------------------------------------------------------------------
    // CreateRepoTokenRequest deserialization
    // -----------------------------------------------------------------------

    #[test]
    fn test_create_repo_token_request_full() {
        let json = r#"{
            "name": "deploy-key",
            "scopes": ["read:artifacts", "write:artifacts"],
            "expires_in_days": 90,
            "description": "CI/CD pipeline token"
        }"#;
        let req: CreateRepoTokenRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.name, "deploy-key");
        assert_eq!(req.scopes.len(), 2);
        assert_eq!(req.expires_in_days, Some(90));
        assert_eq!(req.description.as_deref(), Some("CI/CD pipeline token"));
    }

    #[test]
    fn test_create_repo_token_request_minimal() {
        let json = r#"{"name": "basic", "scopes": ["read:artifacts"]}"#;
        let req: CreateRepoTokenRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.name, "basic");
        assert!(req.expires_in_days.is_none());
        assert!(req.description.is_none());
    }

    #[test]
    fn test_create_repo_token_request_missing_name_fails() {
        let json = r#"{"scopes": ["read:artifacts"]}"#;
        assert!(serde_json::from_str::<CreateRepoTokenRequest>(json).is_err());
    }

    #[test]
    fn test_create_repo_token_request_empty_scopes() {
        let json = r#"{"name": "empty-scopes", "scopes": []}"#;
        let req: CreateRepoTokenRequest = serde_json::from_str(json).unwrap();
        assert!(req.scopes.is_empty());
    }

    // -----------------------------------------------------------------------
    // CreateRepoTokenResponse serialization
    // -----------------------------------------------------------------------

    #[test]
    fn test_create_repo_token_response_serialize() {
        let resp = CreateRepoTokenResponse {
            id: Uuid::nil(),
            token: "ak_abc12345_secretvalue".to_string(),
            name: "my-token".to_string(),
            repository_key: "maven-releases".to_string(),
        };
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["token"], "ak_abc12345_secretvalue");
        assert_eq!(json["name"], "my-token");
        assert_eq!(json["repository_key"], "maven-releases");
    }

    // -----------------------------------------------------------------------
    // RepoTokenResponse serialization
    // -----------------------------------------------------------------------

    #[test]
    fn test_repo_token_response_serialize_active() {
        let now = Utc::now();
        let resp = RepoTokenResponse {
            id: Uuid::nil(),
            name: "ci-key".to_string(),
            token_prefix: "ak_abcd".to_string(),
            scopes: vec!["read:artifacts".to_string()],
            expires_at: Some(now + chrono::Duration::days(30)),
            last_used_at: Some(now - chrono::Duration::hours(2)),
            created_at: now - chrono::Duration::days(5),
            is_expired: false,
            is_revoked: false,
            description: Some("Build agent token".to_string()),
            created_by: Some("admin".to_string()),
        };
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["name"], "ci-key");
        assert_eq!(json["is_expired"], false);
        assert_eq!(json["is_revoked"], false);
        assert_eq!(json["created_by"], "admin");
        assert_eq!(json["description"], "Build agent token");
    }

    #[test]
    fn test_repo_token_response_serialize_expired() {
        let now = Utc::now();
        let resp = RepoTokenResponse {
            id: Uuid::new_v4(),
            name: "old-key".to_string(),
            token_prefix: "ak_wxyz".to_string(),
            scopes: vec!["*".to_string()],
            expires_at: Some(now - chrono::Duration::days(1)),
            last_used_at: None,
            created_at: now - chrono::Duration::days(100),
            is_expired: true,
            is_revoked: false,
            description: None,
            created_by: None,
        };
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["is_expired"], true);
        assert!(json["description"].is_null());
        assert!(json["created_by"].is_null());
        assert!(json["last_used_at"].is_null());
    }

    #[test]
    fn test_repo_token_response_serialize_revoked() {
        let resp = RepoTokenResponse {
            id: Uuid::new_v4(),
            name: "revoked-key".to_string(),
            token_prefix: "ak_1234".to_string(),
            scopes: vec!["read:artifacts".to_string()],
            expires_at: None,
            last_used_at: None,
            created_at: Utc::now(),
            is_expired: false,
            is_revoked: true,
            description: None,
            created_by: None,
        };
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["is_revoked"], true);
    }

    // -----------------------------------------------------------------------
    // RepoTokenListResponse serialization
    // -----------------------------------------------------------------------

    #[test]
    fn test_repo_token_list_response_empty() {
        let resp = RepoTokenListResponse { items: vec![] };
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["items"].as_array().unwrap().len(), 0);
    }

    #[test]
    fn test_repo_token_list_response_multiple() {
        let resp = RepoTokenListResponse {
            items: vec![
                RepoTokenResponse {
                    id: Uuid::new_v4(),
                    name: "token-1".to_string(),
                    token_prefix: "ak_aaaa".to_string(),
                    scopes: vec!["read:artifacts".to_string()],
                    expires_at: None,
                    last_used_at: None,
                    created_at: Utc::now(),
                    is_expired: false,
                    is_revoked: false,
                    description: None,
                    created_by: None,
                },
                RepoTokenResponse {
                    id: Uuid::new_v4(),
                    name: "token-2".to_string(),
                    token_prefix: "ak_bbbb".to_string(),
                    scopes: vec!["write:artifacts".to_string()],
                    expires_at: None,
                    last_used_at: None,
                    created_at: Utc::now(),
                    is_expired: false,
                    is_revoked: false,
                    description: None,
                    created_by: None,
                },
            ],
        };
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["items"].as_array().unwrap().len(), 2);
    }

    // -----------------------------------------------------------------------
    // TokenRow fields
    // -----------------------------------------------------------------------

    #[test]
    fn test_token_row_debug() {
        let row = TokenRow {
            id: Uuid::nil(),
            name: "debug-test".to_string(),
            token_prefix: "ak_test".to_string(),
            scopes: vec!["read:artifacts".to_string()],
            expires_at: None,
            last_used_at: None,
            created_at: Utc::now(),
            revoked_at: None,
            description: None,
            created_by_username: None,
            created_by_user_id: None,
        };
        let debug = format!("{:?}", row);
        assert!(debug.contains("debug-test"));
        assert!(debug.contains("TokenRow"));
    }
}

// ---------------------------------------------------------------------------
// Admin-only token-scope enforcement tests (repo-scoped token endpoint)
//
// Sibling of `users::admin_scope_policy_tests` and the profile-endpoint
// test. The same policy must apply to
// `POST /api/v1/repositories/:key/tokens`, otherwise a non-admin with
// `write:repositories` (a delegatable scope) can pivot here to mint a
// token with `*` / `delete:artifacts` / `delete:repositories` /
// `write:users` and bypass every scope-only authorization gate.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod admin_scope_policy_tests {
    use super::*;
    use crate::api::handlers::test_db_helpers as tdh;
    use axum::body::Body;
    use axum::http::{Method, Request, StatusCode};
    use axum::Extension as AxumExtension;
    use serde_json::json;

    /// Build the repo-tokens router with the production middleware chain's
    /// `Option<AuthExtension>` extractor shape.
    fn build_app(state: SharedState, auth: AuthExtension) -> axum::Router {
        repo_tokens_router()
            .with_state(state)
            .layer(AxumExtension::<Option<AuthExtension>>(Some(auth)))
    }

    async fn setup() -> Option<(sqlx::PgPool, SharedState, Uuid, String, String)> {
        let pool = tdh::try_pool().await?;
        let (user_id, username) = tdh::create_user(&pool).await;
        let (_repo_id, repo_key, _storage_dir) = tdh::create_repo(&pool, "local", "maven").await;
        // These tests assert the admin-scope 403 gate, not repo visibility. The
        // #1783 private-repo check returns 404 before that gate for a private,
        // rule-less repo, so make the setup repo public to reach the scope gate.
        // The dedicated private-repo test flips this back to private itself.
        sqlx::query("UPDATE repositories SET is_public = true WHERE key = $1")
            .bind(&repo_key)
            .execute(&pool)
            .await
            .expect("make setup repo public");
        let state = tdh::build_state(pool.clone(), "/tmp");
        Some((pool, state, user_id, username, repo_key))
    }

    async fn cleanup(pool: &sqlx::PgPool, user_id: Uuid, repo_key: &str) {
        let _ = sqlx::query("DELETE FROM api_tokens WHERE user_id = $1")
            .bind(user_id)
            .execute(pool)
            .await;
        let _ = sqlx::query("DELETE FROM repositories WHERE key = $1")
            .bind(repo_key)
            .execute(pool)
            .await;
        let _ = sqlx::query("DELETE FROM users WHERE id = $1")
            .bind(user_id)
            .execute(pool)
            .await;
    }

    /// Build a `POST /{repo_key}/tokens` request with the given token name
    /// and scopes. Centralizing this avoids repeating the Request::builder
    /// chain across every admin-scope policy test.
    fn post_repo_token_request(repo_key: &str, name: &str, scopes: &[&str]) -> Request<Body> {
        let body = json!({
            "name": name,
            "scopes": scopes,
            "expires_in_days": 30_i64,
        })
        .to_string();
        Request::builder()
            .method(Method::POST)
            .uri(format!("/{}/tokens", repo_key))
            .header("content-type", "application/json")
            .body(Body::from(body))
            .unwrap()
    }

    /// Each ADMIN_ONLY_SCOPES entry, submitted alone by a non-admin with
    /// the delegatable `write:repositories` scope, must be refused at the
    /// handler. Iterating means a future addition to the policy list is
    /// covered automatically.
    #[tokio::test]
    async fn non_admin_cannot_mint_admin_only_scopes_on_repo_tokens_endpoint() {
        let Some((pool, state, user_id, username, repo_key)) = setup().await else {
            return;
        };
        // Caller is a non-admin API token with write:repositories so it
        // passes `require_repo_write` and reaches the policy gate.
        let mut auth = tdh::make_auth(user_id, &username);
        auth.is_api_token = true;
        auth.scopes = Some(vec!["write:repositories".to_string()]);

        for admin_scope in crate::services::token_service::ADMIN_ONLY_SCOPES {
            let app = build_app(state.clone(), auth.clone());
            let req = post_repo_token_request(
                &repo_key,
                &format!("probe-{}", admin_scope),
                &[admin_scope],
            );
            let (status, body_bytes) = tdh::send(app, req).await;

            assert_eq!(
                status,
                StatusCode::FORBIDDEN,
                "non-admin minting repo token with admin-class scope {:?} MUST 403; got {} body: {}",
                admin_scope,
                status,
                String::from_utf8_lossy(&body_bytes),
            );
        }

        cleanup(&pool, user_id, &repo_key).await;
    }

    /// #1783: a non-admin holding only the broad `write:repositories` scope
    /// (token `allowed_repo_ids = None`, so `can_access_repo` passes for ANY
    /// repo) must NOT be able to mint a repo token on a PRIVATE repository it
    /// has no role on. Before the fix the endpoint returned 200/created; it
    /// must now 404 (existence-hiding), exactly like `require_visible`.
    #[tokio::test]
    async fn non_admin_without_role_cannot_mint_token_on_private_repo() {
        let Some((pool, state, user_id, username, repo_key)) = setup().await else {
            return;
        };
        // Make the repo private; the user from setup() has no role on it.
        sqlx::query("UPDATE repositories SET is_public = false WHERE key = $1")
            .bind(&repo_key)
            .execute(&pool)
            .await
            .expect("set repo private");

        // Non-admin API token with the delegatable write scope but no repo
        // restriction, requesting a SAFE (non-admin) scope so it clears the
        // admin-scope gate and reaches the visibility check.
        let mut auth = tdh::make_auth(user_id, &username);
        auth.is_api_token = true;
        auth.scopes = Some(vec!["write:repositories".to_string()]);

        let app = build_app(state, auth);
        let req = post_repo_token_request(&repo_key, "probe-private", &["read:artifacts"]);
        let (status, body_bytes) = tdh::send(app, req).await;

        assert_eq!(
            status,
            StatusCode::NOT_FOUND,
            "non-admin without a role must not mint tokens on a private repo (existence-hiding); got {} body: {}",
            status,
            String::from_utf8_lossy(&body_bytes),
        );

        cleanup(&pool, user_id, &repo_key).await;
    }

    /// A non-admin must not smuggle an admin-only scope through this
    /// endpoint by burying it in a list of otherwise-safe scopes.
    #[tokio::test]
    async fn non_admin_cannot_smuggle_admin_scope_in_a_mixed_list_repo_endpoint() {
        let Some((pool, state, user_id, username, repo_key)) = setup().await else {
            return;
        };
        let mut auth = tdh::make_auth(user_id, &username);
        auth.is_api_token = true;
        auth.scopes = Some(vec!["write:repositories".to_string()]);
        let app = build_app(state, auth);

        let req = post_repo_token_request(
            &repo_key,
            "smuggle-attempt",
            &["read:artifacts", "write:artifacts", "*"],
        );
        let (status, _) = tdh::send(app, req).await;

        assert_eq!(
            status,
            StatusCode::FORBIDDEN,
            "non-admin smuggling '*' on /repositories/{{key}}/tokens MUST 403"
        );

        cleanup(&pool, user_id, &repo_key).await;
    }

    /// Admin callers retain the ability to grant admin-class scopes on
    /// repository-scoped tokens (e.g. for CI service accounts that need to
    /// purge artifacts during release rollback).
    #[tokio::test]
    async fn admin_can_mint_admin_only_scopes_on_repo_tokens_endpoint() {
        let Some((pool, state, user_id, username, repo_key)) = setup().await else {
            return;
        };
        let mut auth = tdh::make_auth(user_id, &username);
        auth.is_admin = true;
        let app = build_app(state, auth);

        let req = post_repo_token_request(&repo_key, "admin-repo-token", &["delete:artifacts"]);
        let (status, body_bytes) = tdh::send(app, req).await;

        assert_eq!(
            status,
            StatusCode::OK,
            "admin minting a delete-scoped repo token MUST succeed; got {} body: {}",
            status,
            String::from_utf8_lossy(&body_bytes),
        );

        cleanup(&pool, user_id, &repo_key).await;
    }
}

// ---------------------------------------------------------------------------
// Per-token ownership gate tests (CWE-639 / BOLA)
//
// Repository-scoped token GET/DELETE and list-detail were authorized only via
// `authorize_repo_for_tokens` (repo-level access), which every same-tenant
// member with `write:repositories` passes. These tests prove the per-token
// ownership gate: a peer cannot read, enumerate, or revoke another member's
// repo token; the creator and global admins still can.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod ownership_gate_tests {
    use super::*;
    use crate::api::handlers::test_db_helpers as tdh;
    use axum::body::Body;
    use axum::http::{Method, Request, StatusCode};
    use axum::Extension as AxumExtension;
    use serde_json::json;

    /// Build the repo-tokens router scoped to a single caller's auth, matching
    /// the production `Option<AuthExtension>` extractor shape.
    fn app_as(state: SharedState, auth: AuthExtension) -> axum::Router {
        repo_tokens_router()
            .with_state(state)
            .layer(AxumExtension::<Option<AuthExtension>>(Some(auth)))
    }

    /// A non-admin caller with the delegatable `write:repositories` scope (so
    /// it clears `require_repo_write`).
    fn member_auth(user_id: Uuid, username: &str) -> AuthExtension {
        let mut auth = tdh::make_auth(user_id, username);
        auth.is_api_token = true;
        auth.scopes = Some(vec!["write:repositories".to_string()]);
        auth
    }

    /// Seed a repo token owned by `creator` via the real create handler, so the
    /// `created_by_user_id`/`api_token_repositories` wiring matches production.
    /// Returns the new token id.
    async fn create_token_as(state: &SharedState, creator: AuthExtension, repo_key: &str) -> Uuid {
        let body = json!({"name": "victors-token", "scopes": ["read:artifacts"]}).to_string();
        let req = Request::builder()
            .method(Method::POST)
            .uri(format!("/{}/tokens", repo_key))
            .header("content-type", "application/json")
            .body(Body::from(body))
            .unwrap();
        let (status, bytes) = tdh::send(app_as(state.clone(), creator), req).await;
        assert_eq!(status, StatusCode::OK, "seed create must succeed");
        let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        Uuid::parse_str(v["id"].as_str().unwrap()).unwrap()
    }

    fn get_token_req(repo_key: &str, token_id: Uuid) -> Request<Body> {
        Request::builder()
            .method(Method::GET)
            .uri(format!("/{}/tokens/{}", repo_key, token_id))
            .body(Body::empty())
            .unwrap()
    }

    fn delete_token_req(repo_key: &str, token_id: Uuid) -> Request<Body> {
        Request::builder()
            .method(Method::DELETE)
            .uri(format!("/{}/tokens/{}", repo_key, token_id))
            .body(Body::empty())
            .unwrap()
    }

    fn list_tokens_req(repo_key: &str) -> Request<Body> {
        Request::builder()
            .method(Method::GET)
            .uri(format!("/{}/tokens", repo_key))
            .body(Body::empty())
            .unwrap()
    }

    async fn revoked_at(pool: &sqlx::PgPool, token_id: Uuid) -> Option<DateTime<Utc>> {
        let row: (Option<DateTime<Utc>>,) =
            sqlx::query_as("SELECT revoked_at FROM api_tokens WHERE id = $1")
                .bind(token_id)
                .fetch_one(pool)
                .await
                .expect("fetch revoked_at");
        row.0
    }

    /// Full public-repo setup with two members (victor=creator, sam=peer) and a
    /// token seeded on the repo by victor. The repo is public so the #1783
    /// private-repo gate is satisfied and the gate under test is purely
    /// per-token, not visibility.
    struct Fixture {
        pool: sqlx::PgPool,
        state: SharedState,
        repo_key: String,
        repo_id: Uuid,
        victor: Uuid,
        sam: Uuid,
        token_id: Uuid,
    }

    async fn fixture() -> Option<Fixture> {
        let pool = tdh::try_pool().await?;
        let (repo_id, repo_key, _dir) = tdh::create_repo(&pool, "local", "maven").await;
        sqlx::query("UPDATE repositories SET is_public = true WHERE id = $1")
            .bind(repo_id)
            .execute(&pool)
            .await
            .expect("make repo public");
        let (victor, victor_name) = tdh::create_user(&pool).await;
        let (sam, _sam_name) = tdh::create_user(&pool).await;
        let state = tdh::build_state(pool.clone(), "/tmp");
        let token_id = create_token_as(&state, member_auth(victor, &victor_name), &repo_key).await;
        Some(Fixture {
            pool,
            state,
            repo_key,
            repo_id,
            victor,
            sam,
            token_id,
        })
    }

    async fn teardown(f: &Fixture) {
        let _ = sqlx::query("DELETE FROM api_token_repositories WHERE repo_id = $1")
            .bind(f.repo_id)
            .execute(&f.pool)
            .await;
        let _ = sqlx::query("DELETE FROM api_tokens WHERE created_by_user_id = $1")
            .bind(f.victor)
            .execute(&f.pool)
            .await;
        let _ = sqlx::query("DELETE FROM repositories WHERE id = $1")
            .bind(f.repo_id)
            .execute(&f.pool)
            .await;
        for u in [f.victor, f.sam] {
            let _ = sqlx::query("DELETE FROM users WHERE id = $1")
                .bind(u)
                .execute(&f.pool)
                .await;
        }
    }

    /// (1) A peer GET of another member's token returns 404 (was 200).
    #[tokio::test]
    async fn peer_get_token_is_404() {
        let Some(f) = fixture().await else { return };
        let app = app_as(f.state.clone(), member_auth(f.sam, "sam"));
        let (status, _) = tdh::send(app, get_token_req(&f.repo_key, f.token_id)).await;
        assert_eq!(status, StatusCode::NOT_FOUND, "peer GET must 404");
        teardown(&f).await;
    }

    /// (2) A peer DELETE returns 404 and the token is NOT revoked.
    #[tokio::test]
    async fn peer_delete_token_is_404_and_not_revoked() {
        let Some(f) = fixture().await else { return };
        let app = app_as(f.state.clone(), member_auth(f.sam, "sam"));
        let (status, _) = tdh::send(app, delete_token_req(&f.repo_key, f.token_id)).await;
        assert_eq!(status, StatusCode::NOT_FOUND, "peer DELETE must 404");
        assert!(
            revoked_at(&f.pool, f.token_id).await.is_none(),
            "peer DELETE must NOT revoke the token"
        );
        teardown(&f).await;
    }

    /// (3) The creator can GET their own token.
    #[tokio::test]
    async fn creator_get_own_token_is_200() {
        let Some(f) = fixture().await else { return };
        let app = app_as(f.state.clone(), member_auth(f.victor, "victor"));
        let (status, _) = tdh::send(app, get_token_req(&f.repo_key, f.token_id)).await;
        assert_eq!(status, StatusCode::OK, "creator GET must 200");
        teardown(&f).await;
    }

    /// (4) The creator can DELETE their own token; revoked_at is set.
    #[tokio::test]
    async fn creator_delete_own_token_is_204_and_revoked() {
        let Some(f) = fixture().await else { return };
        let app = app_as(f.state.clone(), member_auth(f.victor, "victor"));
        let (status, _) = tdh::send(app, delete_token_req(&f.repo_key, f.token_id)).await;
        assert_eq!(status, StatusCode::NO_CONTENT, "creator DELETE must 204");
        assert!(
            revoked_at(&f.pool, f.token_id).await.is_some(),
            "creator DELETE must revoke the token"
        );
        teardown(&f).await;
    }

    /// (5) A global admin can GET and DELETE a peer's token.
    #[tokio::test]
    async fn admin_get_and_delete_peer_token() {
        let Some(f) = fixture().await else { return };
        let mut admin = tdh::make_auth(f.sam, "admin");
        admin.is_admin = true;

        let (status, _) = tdh::send(
            app_as(f.state.clone(), admin.clone()),
            get_token_req(&f.repo_key, f.token_id),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "admin GET peer token must 200");

        let (status, _) = tdh::send(
            app_as(f.state.clone(), admin),
            delete_token_req(&f.repo_key, f.token_id),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::NO_CONTENT,
            "admin DELETE peer token must 204"
        );
        assert!(
            revoked_at(&f.pool, f.token_id).await.is_some(),
            "admin DELETE must revoke"
        );
        teardown(&f).await;
    }

    /// (6) The list omits a peer's token for a non-admin, but an admin sees all.
    #[tokio::test]
    async fn list_scopes_to_owner_for_non_admin_and_all_for_admin() {
        let Some(f) = fixture().await else { return };

        // Peer sees no items (victor's token is filtered out).
        let app = app_as(f.state.clone(), member_auth(f.sam, "sam"));
        let (status, bytes) = tdh::send(app, list_tokens_req(&f.repo_key)).await;
        assert_eq!(status, StatusCode::OK);
        let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        let peer_ids: Vec<&str> = v["items"]
            .as_array()
            .unwrap()
            .iter()
            .map(|i| i["id"].as_str().unwrap())
            .collect();
        assert!(
            !peer_ids.contains(&f.token_id.to_string().as_str()),
            "peer list must not contain victor's token"
        );

        // Creator sees their own token.
        let app = app_as(f.state.clone(), member_auth(f.victor, "victor"));
        let (_s, bytes) = tdh::send(app, list_tokens_req(&f.repo_key)).await;
        let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(
            v["items"].as_array().unwrap().len(),
            1,
            "creator list must contain their token"
        );

        // Admin sees all tokens on the repo.
        let mut admin = tdh::make_auth(f.sam, "admin");
        admin.is_admin = true;
        let (_s, bytes) =
            tdh::send(app_as(f.state.clone(), admin), list_tokens_req(&f.repo_key)).await;
        let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(
            v["items"].as_array().unwrap().len(),
            1,
            "admin list must contain the token"
        );

        teardown(&f).await;
    }
}
