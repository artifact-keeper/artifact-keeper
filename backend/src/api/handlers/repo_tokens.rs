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
    let auth = require_repo_write(auth)?;

    let repo_service = RepositoryService::new(state.db.clone());
    let repo = repo_service.get_by_key(&key).await?;

    if !auth.can_access_repo(repo.id) {
        return Err(AppError::NotFound(format!(
            "Repository '{}' not found",
            key
        )));
    }

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
            u.username AS created_by_username
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

    let items = rows
        .into_iter()
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
    let auth = require_repo_write(auth)?;

    let repo_service = RepositoryService::new(state.db.clone());
    let repo = repo_service.get_by_key(&key).await?;

    if !auth.can_access_repo(repo.id) {
        return Err(AppError::NotFound(format!(
            "Repository '{}' not found",
            key
        )));
    }

    // Validate inputs
    validate_scopes_pure(&payload.scopes).map_err(AppError::Validation)?;
    validate_expiry_days(payload.expires_in_days)?;

    if payload.name.trim().is_empty() {
        return Err(AppError::Validation(
            "Token name must not be empty".to_string(),
        ));
    }

    // Non-admin users cannot request the "admin" scope
    if !auth.is_admin && payload.scopes.iter().any(|s| s == "admin") {
        return Err(AppError::Authorization(
            "Only administrators can create tokens with the 'admin' scope".to_string(),
        ));
    }

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
    let auth = require_repo_write(auth)?;

    let repo_service = RepositoryService::new(state.db.clone());
    let repo = repo_service.get_by_key(&key).await?;

    if !auth.can_access_repo(repo.id) {
        return Err(AppError::NotFound(format!(
            "Repository '{}' not found",
            key
        )));
    }

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
            u.username AS created_by_username
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
    let auth = require_repo_write(auth)?;

    let repo_service = RepositoryService::new(state.db.clone());
    let repo = repo_service.get_by_key(&key).await?;

    if !auth.can_access_repo(repo.id) {
        return Err(AppError::NotFound(format!(
            "Repository '{}' not found",
            key
        )));
    }

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

    // Look up the owning user_id so we can revoke through the standard path
    let owner: (Uuid,) = sqlx::query_as("SELECT user_id FROM api_tokens WHERE id = $1")
        .bind(token_id)
        .fetch_optional(&state.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?
        .ok_or_else(|| AppError::NotFound("Token not found".to_string()))?;

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
        };
        let debug = format!("{:?}", row);
        assert!(debug.contains("debug-test"));
        assert!(debug.contains("TokenRow"));
    }
}
