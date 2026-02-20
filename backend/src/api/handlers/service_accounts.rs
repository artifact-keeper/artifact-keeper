//! Service account management handlers.
//!
//! All routes require admin authentication. Service accounts are machine
//! identities that own API tokens independently of any human user.

use std::sync::Arc;

use axum::{
    extract::{Extension, Path, State},
    routing::get,
    Json, Router,
};
use serde::{Deserialize, Serialize};
use utoipa::{OpenApi, ToSchema};
use uuid::Uuid;

use crate::api::middleware::auth::AuthExtension;
use crate::api::SharedState;
use crate::error::{AppError, Result};
use crate::services::auth_service::AuthService;
use crate::services::service_account_service::{ServiceAccountService, ServiceAccountSummary};
use crate::services::token_service::TokenService;

/// Create service account routes (all require admin)
pub fn router() -> Router<SharedState> {
    Router::new()
        .route("/", get(list_service_accounts).post(create_service_account))
        .route(
            "/:id",
            get(get_service_account)
                .patch(update_service_account)
                .delete(delete_service_account),
        )
        .route("/:id/tokens", get(list_tokens).post(create_token))
        .route("/:id/tokens/:token_id", axum::routing::delete(revoke_token))
        .route(
            "/repo-selector/preview",
            axum::routing::post(preview_repo_selector),
        )
}

// ---------------------------------------------------------------------------
// Request / response types
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize, ToSchema)]
pub struct CreateServiceAccountRequest {
    /// Name for the service account (will be prefixed with "svc-")
    pub name: String,
    /// Optional description
    pub description: Option<String>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct ServiceAccountResponse {
    pub id: Uuid,
    pub username: String,
    pub display_name: Option<String>,
    pub is_active: bool,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct ServiceAccountListResponse {
    pub items: Vec<ServiceAccountSummaryResponse>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct ServiceAccountSummaryResponse {
    pub id: Uuid,
    pub username: String,
    pub display_name: Option<String>,
    pub is_active: bool,
    pub token_count: i64,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

impl From<ServiceAccountSummary> for ServiceAccountSummaryResponse {
    fn from(s: ServiceAccountSummary) -> Self {
        Self {
            id: s.id,
            username: s.username,
            display_name: s.display_name,
            is_active: s.is_active,
            token_count: s.token_count,
            created_at: s.created_at,
            updated_at: s.updated_at,
        }
    }
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct UpdateServiceAccountRequest {
    pub display_name: Option<String>,
    pub is_active: Option<bool>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct CreateTokenRequest {
    pub name: String,
    pub scopes: Vec<String>,
    pub expires_in_days: Option<i64>,
    pub description: Option<String>,
    /// Explicit repository IDs to restrict access to. Mutually exclusive with `repo_selector`.
    pub repository_ids: Option<Vec<Uuid>>,
    /// Dynamic repository selector (match by labels, formats, name pattern).
    /// Mutually exclusive with `repository_ids`. When set, matched repos are
    /// resolved at auth time so new repos that match the selector are picked up
    /// automatically.
    #[schema(value_type = Option<Object>)]
    pub repo_selector: Option<serde_json::Value>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct CreateTokenResponse {
    pub id: Uuid,
    pub token: String,
    pub name: String,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct TokenInfoResponse {
    pub id: Uuid,
    pub name: String,
    pub token_prefix: String,
    pub scopes: Vec<String>,
    pub expires_at: Option<chrono::DateTime<chrono::Utc>>,
    pub last_used_at: Option<chrono::DateTime<chrono::Utc>>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub is_expired: bool,
    /// Dynamic repository selector, if configured.
    #[schema(value_type = Option<Object>)]
    pub repo_selector: Option<serde_json::Value>,
    /// Explicit repository IDs this token is restricted to (from join table).
    pub repository_ids: Vec<Uuid>,
}

/// Request body for previewing which repositories a selector matches.
#[derive(Debug, Deserialize, ToSchema)]
pub struct PreviewRepoSelectorRequest {
    /// The repository selector to evaluate.
    #[schema(value_type = Object)]
    pub repo_selector: serde_json::Value,
}

/// Response for the repo selector preview endpoint.
#[derive(Debug, Serialize, ToSchema)]
pub struct PreviewRepoSelectorResponse {
    pub matched_repositories: Vec<MatchedRepoResponse>,
    pub total: usize,
}

/// A single matched repository in the preview response.
#[derive(Debug, Serialize, ToSchema)]
pub struct MatchedRepoResponse {
    pub id: Uuid,
    pub key: String,
    pub format: String,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct TokenListResponse {
    pub items: Vec<TokenInfoResponse>,
}

// ---------------------------------------------------------------------------
// Helper
// ---------------------------------------------------------------------------

pub(crate) fn require_admin(auth: &AuthExtension) -> Result<()> {
    if !auth.is_admin {
        return Err(AppError::Authorization("Admin access required".to_string()));
    }
    Ok(())
}

pub(crate) fn validate_create_token_exclusivity(
    repo_selector: &Option<serde_json::Value>,
    repository_ids: &Option<Vec<Uuid>>,
) -> Result<()> {
    if repo_selector.is_some() && repository_ids.is_some() {
        return Err(AppError::Validation(
            "Cannot specify both repo_selector and repository_ids".to_string(),
        ));
    }
    Ok(())
}

pub(crate) fn build_repo_map(
    rows: Vec<(Uuid, Uuid)>,
) -> std::collections::HashMap<Uuid, Vec<Uuid>> {
    let mut map: std::collections::HashMap<Uuid, Vec<Uuid>> = std::collections::HashMap::new();
    for (token_id, repo_id) in rows {
        map.entry(token_id).or_default().push(repo_id);
    }
    map
}

pub(crate) fn build_selector_map(
    rows: Vec<(Uuid, Option<serde_json::Value>)>,
) -> std::collections::HashMap<Uuid, Option<serde_json::Value>> {
    let mut map: std::collections::HashMap<Uuid, Option<serde_json::Value>> =
        std::collections::HashMap::new();
    for (id, selector) in rows {
        map.insert(id, selector);
    }
    map
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn build_token_info_response(
    id: Uuid,
    name: String,
    token_prefix: String,
    scopes: Vec<String>,
    expires_at: Option<chrono::DateTime<chrono::Utc>>,
    last_used_at: Option<chrono::DateTime<chrono::Utc>>,
    created_at: chrono::DateTime<chrono::Utc>,
    is_expired: bool,
    repo_ids: Vec<Uuid>,
    selector: Option<serde_json::Value>,
) -> TokenInfoResponse {
    TokenInfoResponse {
        id,
        name,
        token_prefix,
        scopes,
        expires_at,
        last_used_at,
        created_at,
        is_expired,
        repo_selector: selector,
        repository_ids: repo_ids,
    }
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

/// List all service accounts
#[utoipa::path(
    get,
    path = "",
    context_path = "/api/v1/service-accounts",
    tag = "service_accounts",
    responses(
        (status = 200, description = "List of service accounts", body = ServiceAccountListResponse),
        (status = 403, description = "Not admin"),
    ),
    security(("bearer_auth" = []))
)]
pub async fn list_service_accounts(
    State(state): State<SharedState>,
    Extension(auth): Extension<AuthExtension>,
) -> Result<Json<ServiceAccountListResponse>> {
    require_admin(&auth)?;

    let svc = ServiceAccountService::new(state.db.clone());
    let accounts = svc.list(true).await?;

    Ok(Json(ServiceAccountListResponse {
        items: accounts.into_iter().map(Into::into).collect(),
    }))
}

/// Create a new service account
#[utoipa::path(
    post,
    path = "",
    context_path = "/api/v1/service-accounts",
    tag = "service_accounts",
    request_body = CreateServiceAccountRequest,
    responses(
        (status = 201, description = "Service account created", body = ServiceAccountResponse),
        (status = 403, description = "Not admin"),
        (status = 400, description = "Validation error"),
    ),
    security(("bearer_auth" = []))
)]
pub async fn create_service_account(
    State(state): State<SharedState>,
    Extension(auth): Extension<AuthExtension>,
    Json(payload): Json<CreateServiceAccountRequest>,
) -> Result<Json<ServiceAccountResponse>> {
    require_admin(&auth)?;

    let svc = ServiceAccountService::new(state.db.clone());
    let user = svc
        .create(&payload.name, payload.description.as_deref())
        .await?;

    Ok(Json(ServiceAccountResponse {
        id: user.id,
        username: user.username,
        display_name: user.display_name,
        is_active: user.is_active,
        created_at: user.created_at,
        updated_at: user.updated_at,
    }))
}

/// Get a service account by ID
#[utoipa::path(
    get,
    path = "/{id}",
    context_path = "/api/v1/service-accounts",
    tag = "service_accounts",
    params(("id" = Uuid, Path, description = "Service account ID")),
    responses(
        (status = 200, description = "Service account details", body = ServiceAccountResponse),
        (status = 404, description = "Not found"),
    ),
    security(("bearer_auth" = []))
)]
pub async fn get_service_account(
    State(state): State<SharedState>,
    Extension(auth): Extension<AuthExtension>,
    Path(id): Path<Uuid>,
) -> Result<Json<ServiceAccountResponse>> {
    require_admin(&auth)?;

    let svc = ServiceAccountService::new(state.db.clone());
    let user = svc.get(id).await?;

    Ok(Json(ServiceAccountResponse {
        id: user.id,
        username: user.username,
        display_name: user.display_name,
        is_active: user.is_active,
        created_at: user.created_at,
        updated_at: user.updated_at,
    }))
}

/// Update a service account
#[utoipa::path(
    patch,
    path = "/{id}",
    context_path = "/api/v1/service-accounts",
    tag = "service_accounts",
    params(("id" = Uuid, Path, description = "Service account ID")),
    request_body = UpdateServiceAccountRequest,
    responses(
        (status = 200, description = "Updated", body = ServiceAccountResponse),
        (status = 404, description = "Not found"),
    ),
    security(("bearer_auth" = []))
)]
pub async fn update_service_account(
    State(state): State<SharedState>,
    Extension(auth): Extension<AuthExtension>,
    Path(id): Path<Uuid>,
    Json(payload): Json<UpdateServiceAccountRequest>,
) -> Result<Json<ServiceAccountResponse>> {
    require_admin(&auth)?;

    let svc = ServiceAccountService::new(state.db.clone());
    let user = svc
        .update(id, payload.display_name.as_deref(), payload.is_active)
        .await?;

    Ok(Json(ServiceAccountResponse {
        id: user.id,
        username: user.username,
        display_name: user.display_name,
        is_active: user.is_active,
        created_at: user.created_at,
        updated_at: user.updated_at,
    }))
}

/// Delete a service account
#[utoipa::path(
    delete,
    path = "/{id}",
    context_path = "/api/v1/service-accounts",
    tag = "service_accounts",
    params(("id" = Uuid, Path, description = "Service account ID")),
    responses(
        (status = 204, description = "Deleted"),
        (status = 404, description = "Not found"),
    ),
    security(("bearer_auth" = []))
)]
pub async fn delete_service_account(
    State(state): State<SharedState>,
    Extension(auth): Extension<AuthExtension>,
    Path(id): Path<Uuid>,
) -> Result<axum::http::StatusCode> {
    require_admin(&auth)?;

    let svc = ServiceAccountService::new(state.db.clone());
    svc.delete(id).await?;

    Ok(axum::http::StatusCode::NO_CONTENT)
}

/// List tokens for a service account
#[utoipa::path(
    get,
    path = "/{id}/tokens",
    context_path = "/api/v1/service-accounts",
    tag = "service_accounts",
    params(("id" = Uuid, Path, description = "Service account ID")),
    responses(
        (status = 200, description = "Token list", body = TokenListResponse),
        (status = 404, description = "Service account not found"),
    ),
    security(("bearer_auth" = []))
)]
pub async fn list_tokens(
    State(state): State<SharedState>,
    Extension(auth): Extension<AuthExtension>,
    Path(id): Path<Uuid>,
) -> Result<Json<TokenListResponse>> {
    require_admin(&auth)?;

    // Verify the service account exists
    let svc = ServiceAccountService::new(state.db.clone());
    svc.get(id).await?;

    let token_svc = TokenService::new(state.db.clone(), Arc::new(state.config.clone()));
    let tokens = token_svc.list_tokens(id).await?;

    // Batch-fetch explicit repo restrictions from the join table
    let token_ids: Vec<Uuid> = tokens.iter().map(|t| t.id).collect();
    let repo_rows = sqlx::query!(
        "SELECT token_id, repo_id FROM api_token_repositories WHERE token_id = ANY($1)",
        &token_ids
    )
    .fetch_all(&state.db)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;

    let mut repo_map = build_repo_map(
        repo_rows
            .into_iter()
            .map(|r| (r.token_id, r.repo_id))
            .collect(),
    );

    // Fetch repo_selector values from the tokens table
    let selector_rows = sqlx::query!(
        "SELECT id, repo_selector FROM api_tokens WHERE id = ANY($1)",
        &token_ids
    )
    .fetch_all(&state.db)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;

    let selector_map = build_selector_map(
        selector_rows
            .into_iter()
            .map(|r| (r.id, r.repo_selector))
            .collect(),
    );

    Ok(Json(TokenListResponse {
        items: tokens
            .into_iter()
            .map(|t| {
                let repo_ids = repo_map.remove(&t.id).unwrap_or_default();
                let selector = selector_map.get(&t.id).and_then(|s| s.clone());
                build_token_info_response(
                    t.id,
                    t.name,
                    t.token_prefix,
                    t.scopes,
                    t.expires_at,
                    t.last_used_at,
                    t.created_at,
                    t.is_expired,
                    repo_ids,
                    selector,
                )
            })
            .collect(),
    }))
}

/// Create a token for a service account
#[utoipa::path(
    post,
    path = "/{id}/tokens",
    context_path = "/api/v1/service-accounts",
    tag = "service_accounts",
    params(("id" = Uuid, Path, description = "Service account ID")),
    request_body = CreateTokenRequest,
    responses(
        (status = 200, description = "Token created (value shown once)", body = CreateTokenResponse),
        (status = 404, description = "Service account not found"),
    ),
    security(("bearer_auth" = []))
)]
pub async fn create_token(
    State(state): State<SharedState>,
    Extension(auth): Extension<AuthExtension>,
    Path(id): Path<Uuid>,
    Json(payload): Json<CreateTokenRequest>,
) -> Result<Json<CreateTokenResponse>> {
    require_admin(&auth)?;

    // Validate mutual exclusivity
    validate_create_token_exclusivity(&payload.repo_selector, &payload.repository_ids)?;

    // Verify the service account exists
    let svc = ServiceAccountService::new(state.db.clone());
    svc.get(id).await?;

    let auth_service = AuthService::new(state.db.clone(), Arc::new(state.config.clone()));
    let (token, token_id) = auth_service
        .generate_api_token(id, &payload.name, payload.scopes, payload.expires_in_days)
        .await?;

    // Store repo_selector or explicit repository_ids (mutually exclusive)
    if let Some(selector) = &payload.repo_selector {
        sqlx::query!(
            "UPDATE api_tokens SET repo_selector = $1 WHERE id = $2",
            selector,
            token_id
        )
        .execute(&state.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;
    } else if let Some(repo_ids) = &payload.repository_ids {
        for repo_id in repo_ids {
            sqlx::query!(
                "INSERT INTO api_token_repositories (token_id, repo_id) VALUES ($1, $2)",
                token_id,
                repo_id
            )
            .execute(&state.db)
            .await
            .map_err(|e| AppError::Database(e.to_string()))?;
        }
    }

    // Update the created_by_user_id and description
    sqlx::query!(
        "UPDATE api_tokens SET created_by_user_id = $1, description = $2 WHERE id = $3",
        auth.user_id,
        payload.description,
        token_id
    )
    .execute(&state.db)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;

    Ok(Json(CreateTokenResponse {
        id: token_id,
        token,
        name: payload.name,
    }))
}

/// Preview which repositories match a given repo selector.
///
/// Does not create or modify anything. Useful for testing selectors before
/// attaching them to a token.
#[utoipa::path(
    post,
    path = "/repo-selector/preview",
    context_path = "/api/v1/service-accounts",
    tag = "service_accounts",
    request_body = PreviewRepoSelectorRequest,
    responses(
        (status = 200, description = "Matched repositories", body = PreviewRepoSelectorResponse),
        (status = 400, description = "Invalid selector"),
        (status = 403, description = "Not admin"),
    ),
    security(("bearer_auth" = []))
)]
pub async fn preview_repo_selector(
    State(state): State<SharedState>,
    Extension(auth): Extension<AuthExtension>,
    Json(payload): Json<PreviewRepoSelectorRequest>,
) -> Result<Json<PreviewRepoSelectorResponse>> {
    require_admin(&auth)?;

    use crate::services::repo_selector_service::{RepoSelector, RepoSelectorService};

    let selector: RepoSelector = serde_json::from_value(payload.repo_selector)
        .map_err(|e| AppError::Validation(format!("Invalid repo_selector: {e}")))?;

    let svc = RepoSelectorService::new(state.db.clone());
    let matched = svc.resolve(&selector).await?;

    let total = matched.len();
    let items: Vec<MatchedRepoResponse> = matched
        .into_iter()
        .map(|r| MatchedRepoResponse {
            id: r.id,
            key: r.key,
            format: r.format,
        })
        .collect();

    Ok(Json(PreviewRepoSelectorResponse {
        matched_repositories: items,
        total,
    }))
}

/// Revoke a token from a service account
#[utoipa::path(
    delete,
    path = "/{id}/tokens/{token_id}",
    context_path = "/api/v1/service-accounts",
    tag = "service_accounts",
    params(
        ("id" = Uuid, Path, description = "Service account ID"),
        ("token_id" = Uuid, Path, description = "Token ID"),
    ),
    responses(
        (status = 204, description = "Token revoked"),
        (status = 404, description = "Not found"),
    ),
    security(("bearer_auth" = []))
)]
pub async fn revoke_token(
    State(state): State<SharedState>,
    Extension(auth): Extension<AuthExtension>,
    Path((id, token_id)): Path<(Uuid, Uuid)>,
) -> Result<axum::http::StatusCode> {
    require_admin(&auth)?;

    // Verify the service account exists
    let svc = ServiceAccountService::new(state.db.clone());
    svc.get(id).await?;

    let auth_service = AuthService::new(state.db.clone(), Arc::new(state.config.clone()));
    auth_service.revoke_api_token(token_id, id).await?;

    Ok(axum::http::StatusCode::NO_CONTENT)
}

// ---------------------------------------------------------------------------
// OpenAPI
// ---------------------------------------------------------------------------

#[derive(OpenApi)]
#[openapi(
    paths(
        list_service_accounts,
        create_service_account,
        get_service_account,
        update_service_account,
        delete_service_account,
        list_tokens,
        create_token,
        revoke_token,
        preview_repo_selector,
    ),
    components(schemas(
        CreateServiceAccountRequest,
        ServiceAccountResponse,
        ServiceAccountListResponse,
        ServiceAccountSummaryResponse,
        UpdateServiceAccountRequest,
        CreateTokenRequest,
        CreateTokenResponse,
        TokenInfoResponse,
        TokenListResponse,
        PreviewRepoSelectorRequest,
        PreviewRepoSelectorResponse,
        MatchedRepoResponse,
    )),
    tags(
        (name = "service_accounts", description = "Service account management"),
    )
)]
pub struct ServiceAccountsApiDoc;

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

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

    fn non_admin_auth() -> AuthExtension {
        AuthExtension {
            user_id: Uuid::new_v4(),
            username: "user".to_string(),
            email: "user@example.com".to_string(),
            is_admin: false,
            is_api_token: false,
            is_service_account: false,
            scopes: None,
            allowed_repo_ids: None,
        }
    }

    fn sample_summary() -> ServiceAccountSummary {
        let now = Utc::now();
        ServiceAccountSummary {
            id: Uuid::nil(),
            username: "svc-ci-runner".to_string(),
            display_name: Some("CI Runner".to_string()),
            is_active: true,
            token_count: 3,
            created_at: now,
            updated_at: now,
        }
    }

    // -----------------------------------------------------------------------
    // require_admin
    // -----------------------------------------------------------------------

    #[test]
    fn test_require_admin_allows_admin() {
        let auth = admin_auth();
        assert!(require_admin(&auth).is_ok());
    }

    #[test]
    fn test_require_admin_rejects_non_admin() {
        let auth = non_admin_auth();
        let err = require_admin(&auth).unwrap_err();
        match err {
            AppError::Authorization(msg) => assert_eq!(msg, "Admin access required"),
            other => panic!("Expected Authorization error, got: {:?}", other),
        }
    }

    // -----------------------------------------------------------------------
    // From<ServiceAccountSummary> for ServiceAccountSummaryResponse
    // -----------------------------------------------------------------------

    #[test]
    fn test_summary_conversion_preserves_all_fields() {
        let summary = sample_summary();
        let id = summary.id;
        let created = summary.created_at;
        let updated = summary.updated_at;
        let resp: ServiceAccountSummaryResponse = summary.into();

        assert_eq!(resp.id, id);
        assert_eq!(resp.username, "svc-ci-runner");
        assert_eq!(resp.display_name, Some("CI Runner".to_string()));
        assert!(resp.is_active);
        assert_eq!(resp.token_count, 3);
        assert_eq!(resp.created_at, created);
        assert_eq!(resp.updated_at, updated);
    }

    #[test]
    fn test_summary_conversion_none_display_name() {
        let now = Utc::now();
        let summary = ServiceAccountSummary {
            id: Uuid::new_v4(),
            username: "svc-deploy".to_string(),
            display_name: None,
            is_active: false,
            token_count: 0,
            created_at: now,
            updated_at: now,
        };
        let resp: ServiceAccountSummaryResponse = summary.into();
        assert!(resp.display_name.is_none());
        assert!(!resp.is_active);
        assert_eq!(resp.token_count, 0);
    }

    // -----------------------------------------------------------------------
    // validate_create_token_exclusivity
    // -----------------------------------------------------------------------

    #[test]
    fn test_exclusivity_both_none_ok() {
        assert!(validate_create_token_exclusivity(&None, &None).is_ok());
    }

    #[test]
    fn test_exclusivity_only_selector_ok() {
        let selector = Some(serde_json::json!({"match_formats": ["docker"]}));
        assert!(validate_create_token_exclusivity(&selector, &None).is_ok());
    }

    #[test]
    fn test_exclusivity_only_repo_ids_ok() {
        let repo_ids = Some(vec![Uuid::new_v4()]);
        assert!(validate_create_token_exclusivity(&None, &repo_ids).is_ok());
    }

    #[test]
    fn test_exclusivity_both_set_fails() {
        let selector = Some(serde_json::json!({"match_formats": ["npm"]}));
        let repo_ids = Some(vec![Uuid::new_v4()]);
        let err = validate_create_token_exclusivity(&selector, &repo_ids).unwrap_err();
        match err {
            AppError::Validation(msg) => {
                assert!(msg.contains("repo_selector"));
                assert!(msg.contains("repository_ids"));
            }
            other => panic!("Expected Validation error, got: {:?}", other),
        }
    }

    // -----------------------------------------------------------------------
    // build_repo_map
    // -----------------------------------------------------------------------

    #[test]
    fn test_build_repo_map_empty() {
        let map = build_repo_map(vec![]);
        assert!(map.is_empty());
    }

    #[test]
    fn test_build_repo_map_single_token_single_repo() {
        let token_id = Uuid::new_v4();
        let repo_id = Uuid::new_v4();
        let map = build_repo_map(vec![(token_id, repo_id)]);
        assert_eq!(map.len(), 1);
        assert_eq!(map[&token_id], vec![repo_id]);
    }

    #[test]
    fn test_build_repo_map_single_token_multiple_repos() {
        let token_id = Uuid::new_v4();
        let repo1 = Uuid::new_v4();
        let repo2 = Uuid::new_v4();
        let map = build_repo_map(vec![(token_id, repo1), (token_id, repo2)]);
        assert_eq!(map.len(), 1);
        assert_eq!(map[&token_id].len(), 2);
        assert!(map[&token_id].contains(&repo1));
        assert!(map[&token_id].contains(&repo2));
    }

    #[test]
    fn test_build_repo_map_multiple_tokens() {
        let t1 = Uuid::new_v4();
        let t2 = Uuid::new_v4();
        let r1 = Uuid::new_v4();
        let r2 = Uuid::new_v4();
        let r3 = Uuid::new_v4();
        let map = build_repo_map(vec![(t1, r1), (t1, r2), (t2, r3)]);
        assert_eq!(map.len(), 2);
        assert_eq!(map[&t1].len(), 2);
        assert_eq!(map[&t2].len(), 1);
    }

    // -----------------------------------------------------------------------
    // build_selector_map
    // -----------------------------------------------------------------------

    #[test]
    fn test_build_selector_map_empty() {
        let map = build_selector_map(vec![]);
        assert!(map.is_empty());
    }

    #[test]
    fn test_build_selector_map_with_selectors() {
        let id1 = Uuid::new_v4();
        let id2 = Uuid::new_v4();
        let sel = serde_json::json!({"match_formats": ["maven"]});
        let map = build_selector_map(vec![(id1, Some(sel.clone())), (id2, None)]);
        assert_eq!(map.len(), 2);
        assert_eq!(map[&id1], Some(sel));
        assert_eq!(map[&id2], None);
    }

    #[test]
    fn test_build_selector_map_last_wins_on_duplicate() {
        let id = Uuid::new_v4();
        let sel1 = serde_json::json!({"match_formats": ["docker"]});
        let sel2 = serde_json::json!({"match_formats": ["npm"]});
        let map = build_selector_map(vec![(id, Some(sel1)), (id, Some(sel2.clone()))]);
        assert_eq!(map.len(), 1);
        assert_eq!(map[&id], Some(sel2));
    }

    // -----------------------------------------------------------------------
    // build_token_info_response
    // -----------------------------------------------------------------------

    #[test]
    fn test_build_token_info_response_full() {
        let id = Uuid::new_v4();
        let now = Utc::now();
        let repo_id = Uuid::new_v4();
        let selector = serde_json::json!({"match_labels": {"env": "prod"}});
        let resp = build_token_info_response(
            id,
            "deploy-token".to_string(),
            "ak_abc".to_string(),
            vec!["read".to_string(), "write".to_string()],
            Some(now),
            Some(now),
            now,
            false,
            vec![repo_id],
            Some(selector.clone()),
        );

        assert_eq!(resp.id, id);
        assert_eq!(resp.name, "deploy-token");
        assert_eq!(resp.token_prefix, "ak_abc");
        assert_eq!(resp.scopes, vec!["read", "write"]);
        assert_eq!(resp.expires_at, Some(now));
        assert_eq!(resp.last_used_at, Some(now));
        assert_eq!(resp.created_at, now);
        assert!(!resp.is_expired);
        assert_eq!(resp.repository_ids, vec![repo_id]);
        assert_eq!(resp.repo_selector, Some(selector));
    }

    #[test]
    fn test_build_token_info_response_minimal() {
        let id = Uuid::new_v4();
        let now = Utc::now();
        let resp = build_token_info_response(
            id,
            "ci-token".to_string(),
            "ak_xyz".to_string(),
            vec![],
            None,
            None,
            now,
            true,
            vec![],
            None,
        );

        assert_eq!(resp.id, id);
        assert!(resp.expires_at.is_none());
        assert!(resp.last_used_at.is_none());
        assert!(resp.is_expired);
        assert!(resp.repository_ids.is_empty());
        assert!(resp.repo_selector.is_none());
    }

    // -----------------------------------------------------------------------
    // CreateServiceAccountRequest serialization
    // -----------------------------------------------------------------------

    #[test]
    fn test_create_service_account_request_deserialize() {
        let json = r#"{"name":"ci-runner","description":"CI/CD service account"}"#;
        let req: CreateServiceAccountRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.name, "ci-runner");
        assert_eq!(req.description, Some("CI/CD service account".to_string()));
    }

    #[test]
    fn test_create_service_account_request_no_description() {
        let json = r#"{"name":"deploy-bot"}"#;
        let req: CreateServiceAccountRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.name, "deploy-bot");
        assert!(req.description.is_none());
    }

    #[test]
    fn test_create_service_account_request_missing_name() {
        let json = r#"{"description":"no name"}"#;
        let result = serde_json::from_str::<CreateServiceAccountRequest>(json);
        assert!(result.is_err());
    }

    // -----------------------------------------------------------------------
    // ServiceAccountResponse serialization
    // -----------------------------------------------------------------------

    #[test]
    fn test_service_account_response_serialize() {
        let now = Utc::now();
        let resp = ServiceAccountResponse {
            id: Uuid::nil(),
            username: "svc-test".to_string(),
            display_name: Some("Test Account".to_string()),
            is_active: true,
            created_at: now,
            updated_at: now,
        };
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["username"], "svc-test");
        assert_eq!(json["display_name"], "Test Account");
        assert_eq!(json["is_active"], true);
        assert!(json["id"].is_string());
        assert!(json["created_at"].is_string());
        assert!(json["updated_at"].is_string());
    }

    #[test]
    fn test_service_account_response_null_display_name() {
        let now = Utc::now();
        let resp = ServiceAccountResponse {
            id: Uuid::nil(),
            username: "svc-bot".to_string(),
            display_name: None,
            is_active: false,
            created_at: now,
            updated_at: now,
        };
        let json = serde_json::to_value(&resp).unwrap();
        assert!(json["display_name"].is_null());
        assert_eq!(json["is_active"], false);
    }

    // -----------------------------------------------------------------------
    // ServiceAccountListResponse serialization
    // -----------------------------------------------------------------------

    #[test]
    fn test_list_response_serialize_empty() {
        let resp = ServiceAccountListResponse { items: vec![] };
        let json = serde_json::to_value(&resp).unwrap();
        assert!(json["items"].as_array().unwrap().is_empty());
    }

    #[test]
    fn test_list_response_serialize_with_items() {
        let now = Utc::now();
        let resp = ServiceAccountListResponse {
            items: vec![ServiceAccountSummaryResponse {
                id: Uuid::nil(),
                username: "svc-build".to_string(),
                display_name: None,
                is_active: true,
                token_count: 2,
                created_at: now,
                updated_at: now,
            }],
        };
        let json = serde_json::to_value(&resp).unwrap();
        let items = json["items"].as_array().unwrap();
        assert_eq!(items.len(), 1);
        assert_eq!(items[0]["token_count"], 2);
    }

    // -----------------------------------------------------------------------
    // UpdateServiceAccountRequest serialization
    // -----------------------------------------------------------------------

    #[test]
    fn test_update_request_all_fields() {
        let json = r#"{"display_name":"New Name","is_active":false}"#;
        let req: UpdateServiceAccountRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.display_name, Some("New Name".to_string()));
        assert_eq!(req.is_active, Some(false));
    }

    #[test]
    fn test_update_request_partial_display_name_only() {
        let json = r#"{"display_name":"Just Name"}"#;
        let req: UpdateServiceAccountRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.display_name, Some("Just Name".to_string()));
        assert!(req.is_active.is_none());
    }

    #[test]
    fn test_update_request_partial_is_active_only() {
        let json = r#"{"is_active":true}"#;
        let req: UpdateServiceAccountRequest = serde_json::from_str(json).unwrap();
        assert!(req.display_name.is_none());
        assert_eq!(req.is_active, Some(true));
    }

    #[test]
    fn test_update_request_empty_body() {
        let json = r#"{}"#;
        let req: UpdateServiceAccountRequest = serde_json::from_str(json).unwrap();
        assert!(req.display_name.is_none());
        assert!(req.is_active.is_none());
    }

    // -----------------------------------------------------------------------
    // CreateTokenRequest serialization
    // -----------------------------------------------------------------------

    #[test]
    fn test_create_token_request_minimal() {
        let json = r#"{"name":"deploy","scopes":["read"]}"#;
        let req: CreateTokenRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.name, "deploy");
        assert_eq!(req.scopes, vec!["read"]);
        assert!(req.expires_in_days.is_none());
        assert!(req.description.is_none());
        assert!(req.repository_ids.is_none());
        assert!(req.repo_selector.is_none());
    }

    #[test]
    fn test_create_token_request_full() {
        let id = Uuid::nil();
        let json = format!(
            r#"{{"name":"ci","scopes":["read","write"],"expires_in_days":30,"description":"CI token","repository_ids":["{}"],"repo_selector":null}}"#,
            id
        );
        let req: CreateTokenRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(req.name, "ci");
        assert_eq!(req.scopes, vec!["read", "write"]);
        assert_eq!(req.expires_in_days, Some(30));
        assert_eq!(req.description, Some("CI token".to_string()));
        assert_eq!(req.repository_ids, Some(vec![id]));
        assert!(req.repo_selector.is_none());
    }

    #[test]
    fn test_create_token_request_with_selector() {
        let json = r#"{"name":"auto","scopes":["*"],"repo_selector":{"match_formats":["docker","maven"]}}"#;
        let req: CreateTokenRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.name, "auto");
        assert!(req.repo_selector.is_some());
        let sel = req.repo_selector.unwrap();
        let formats = sel["match_formats"].as_array().unwrap();
        assert_eq!(formats.len(), 2);
    }

    #[test]
    fn test_create_token_request_missing_name() {
        let json = r#"{"scopes":["read"]}"#;
        assert!(serde_json::from_str::<CreateTokenRequest>(json).is_err());
    }

    #[test]
    fn test_create_token_request_missing_scopes() {
        let json = r#"{"name":"deploy"}"#;
        assert!(serde_json::from_str::<CreateTokenRequest>(json).is_err());
    }

    #[test]
    fn test_create_token_request_empty_scopes() {
        let json = r#"{"name":"empty","scopes":[]}"#;
        let req: CreateTokenRequest = serde_json::from_str(json).unwrap();
        assert!(req.scopes.is_empty());
    }

    // -----------------------------------------------------------------------
    // CreateTokenResponse serialization
    // -----------------------------------------------------------------------

    #[test]
    fn test_create_token_response_serialize() {
        let resp = CreateTokenResponse {
            id: Uuid::nil(),
            token: "ak_secret_abc123".to_string(),
            name: "my-token".to_string(),
        };
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["token"], "ak_secret_abc123");
        assert_eq!(json["name"], "my-token");
        assert!(json["id"].is_string());
    }

    // -----------------------------------------------------------------------
    // TokenInfoResponse serialization
    // -----------------------------------------------------------------------

    #[test]
    fn test_token_info_response_serialize_full() {
        let now = Utc::now();
        let repo_id = Uuid::new_v4();
        let resp = TokenInfoResponse {
            id: Uuid::nil(),
            name: "deploy-token".to_string(),
            token_prefix: "ak_abc".to_string(),
            scopes: vec!["read".to_string(), "write".to_string()],
            expires_at: Some(now),
            last_used_at: Some(now),
            created_at: now,
            is_expired: false,
            repo_selector: Some(serde_json::json!({"match_formats": ["npm"]})),
            repository_ids: vec![repo_id],
        };
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["name"], "deploy-token");
        assert_eq!(json["token_prefix"], "ak_abc");
        assert_eq!(json["scopes"].as_array().unwrap().len(), 2);
        assert_eq!(json["is_expired"], false);
        assert!(json["repo_selector"].is_object());
        assert_eq!(json["repository_ids"].as_array().unwrap().len(), 1);
    }

    #[test]
    fn test_token_info_response_serialize_minimal() {
        let now = Utc::now();
        let resp = TokenInfoResponse {
            id: Uuid::nil(),
            name: "read-only".to_string(),
            token_prefix: "ak_xyz".to_string(),
            scopes: vec![],
            expires_at: None,
            last_used_at: None,
            created_at: now,
            is_expired: true,
            repo_selector: None,
            repository_ids: vec![],
        };
        let json = serde_json::to_value(&resp).unwrap();
        assert!(json["expires_at"].is_null());
        assert!(json["last_used_at"].is_null());
        assert!(json["repo_selector"].is_null());
        assert!(json["repository_ids"].as_array().unwrap().is_empty());
        assert_eq!(json["is_expired"], true);
    }

    // -----------------------------------------------------------------------
    // TokenListResponse serialization
    // -----------------------------------------------------------------------

    #[test]
    fn test_token_list_response_serialize_empty() {
        let resp = TokenListResponse { items: vec![] };
        let json = serde_json::to_value(&resp).unwrap();
        assert!(json["items"].as_array().unwrap().is_empty());
    }

    // -----------------------------------------------------------------------
    // PreviewRepoSelectorRequest serialization
    // -----------------------------------------------------------------------

    #[test]
    fn test_preview_repo_selector_request_deserialize() {
        let json =
            r#"{"repo_selector":{"match_formats":["docker"],"match_labels":{"env":"prod"}}}"#;
        let req: PreviewRepoSelectorRequest = serde_json::from_str(json).unwrap();
        assert!(req.repo_selector.is_object());
        assert_eq!(
            req.repo_selector["match_formats"].as_array().unwrap().len(),
            1
        );
    }

    #[test]
    fn test_preview_repo_selector_request_missing_selector() {
        let json = r#"{}"#;
        assert!(serde_json::from_str::<PreviewRepoSelectorRequest>(json).is_err());
    }

    #[test]
    fn test_preview_repo_selector_request_empty_selector() {
        let json = r#"{"repo_selector":{}}"#;
        let req: PreviewRepoSelectorRequest = serde_json::from_str(json).unwrap();
        assert!(req.repo_selector.is_object());
        assert!(req.repo_selector.as_object().unwrap().is_empty());
    }

    // -----------------------------------------------------------------------
    // PreviewRepoSelectorResponse serialization
    // -----------------------------------------------------------------------

    #[test]
    fn test_preview_response_serialize() {
        let resp = PreviewRepoSelectorResponse {
            matched_repositories: vec![
                MatchedRepoResponse {
                    id: Uuid::nil(),
                    key: "docker-prod".to_string(),
                    format: "docker".to_string(),
                },
                MatchedRepoResponse {
                    id: Uuid::new_v4(),
                    key: "maven-snapshots".to_string(),
                    format: "maven".to_string(),
                },
            ],
            total: 2,
        };
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["total"], 2);
        let repos = json["matched_repositories"].as_array().unwrap();
        assert_eq!(repos.len(), 2);
        assert_eq!(repos[0]["key"], "docker-prod");
        assert_eq!(repos[0]["format"], "docker");
        assert_eq!(repos[1]["key"], "maven-snapshots");
    }

    #[test]
    fn test_preview_response_serialize_empty() {
        let resp = PreviewRepoSelectorResponse {
            matched_repositories: vec![],
            total: 0,
        };
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["total"], 0);
        assert!(json["matched_repositories"].as_array().unwrap().is_empty());
    }

    // -----------------------------------------------------------------------
    // MatchedRepoResponse serialization
    // -----------------------------------------------------------------------

    #[test]
    fn test_matched_repo_response_serialize() {
        let resp = MatchedRepoResponse {
            id: Uuid::nil(),
            key: "npm-hosted".to_string(),
            format: "npm".to_string(),
        };
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["key"], "npm-hosted");
        assert_eq!(json["format"], "npm");
        assert!(json["id"].is_string());
    }

    // -----------------------------------------------------------------------
    // RepoSelector deserialization (used by preview_repo_selector handler)
    // -----------------------------------------------------------------------

    #[test]
    fn test_repo_selector_from_json_full() {
        use crate::services::repo_selector_service::RepoSelector;
        let json = serde_json::json!({
            "match_labels": {"env": "production", "team": "backend"},
            "match_formats": ["docker", "maven"],
            "match_pattern": "libs-*",
            "match_repos": ["00000000-0000-0000-0000-000000000000"]
        });
        let selector: RepoSelector = serde_json::from_value(json).unwrap();
        assert_eq!(selector.match_labels.len(), 2);
        assert_eq!(selector.match_labels["env"], "production");
        assert_eq!(selector.match_formats.len(), 2);
        assert_eq!(selector.match_pattern, Some("libs-*".to_string()));
        assert_eq!(selector.match_repos.len(), 1);
    }

    #[test]
    fn test_repo_selector_from_json_empty() {
        use crate::services::repo_selector_service::RepoSelector;
        let json = serde_json::json!({});
        let selector: RepoSelector = serde_json::from_value(json).unwrap();
        assert!(selector.match_labels.is_empty());
        assert!(selector.match_formats.is_empty());
        assert!(selector.match_pattern.is_none());
        assert!(selector.match_repos.is_empty());
    }

    #[test]
    fn test_repo_selector_from_json_partial() {
        use crate::services::repo_selector_service::RepoSelector;
        let json = serde_json::json!({"match_formats": ["pypi"]});
        let selector: RepoSelector = serde_json::from_value(json).unwrap();
        assert!(selector.match_labels.is_empty());
        assert_eq!(selector.match_formats, vec!["pypi"]);
        assert!(selector.match_pattern.is_none());
    }

    #[test]
    fn test_repo_selector_invalid_json_rejected() {
        use crate::services::repo_selector_service::RepoSelector;
        let json = serde_json::json!("not an object");
        assert!(serde_json::from_value::<RepoSelector>(json).is_err());
    }

    // -----------------------------------------------------------------------
    // OpenAPI doc validation
    // -----------------------------------------------------------------------

    #[test]
    fn test_openapi_doc_has_paths() {
        let doc = ServiceAccountsApiDoc::openapi();
        let paths = doc.paths.paths.len();
        assert!(paths >= 4, "Expected at least 4 paths, got {}", paths);
    }

    #[test]
    fn test_openapi_doc_has_schemas() {
        let doc = ServiceAccountsApiDoc::openapi();
        let schemas = doc.components.as_ref().unwrap().schemas.len();
        assert!(
            schemas >= 10,
            "Expected at least 10 schemas, got {}",
            schemas
        );
    }

    // -----------------------------------------------------------------------
    // Round-trip serialization tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_create_service_account_round_trip() {
        let original = r#"{"name":"svc-test","description":"round trip"}"#;
        let req: CreateServiceAccountRequest = serde_json::from_str(original).unwrap();
        assert_eq!(req.name, "svc-test");
        assert_eq!(req.description, Some("round trip".to_string()));
    }

    #[test]
    fn test_summary_response_round_trip() {
        let now = Utc::now();
        let resp = ServiceAccountSummaryResponse {
            id: Uuid::nil(),
            username: "svc-round".to_string(),
            display_name: Some("Round Trip".to_string()),
            is_active: true,
            token_count: 5,
            created_at: now,
            updated_at: now,
        };
        let serialized = serde_json::to_string(&resp).unwrap();
        let json: serde_json::Value = serde_json::from_str(&serialized).unwrap();
        assert_eq!(json["username"], "svc-round");
        assert_eq!(json["token_count"], 5);
    }

    // -----------------------------------------------------------------------
    // router()
    // -----------------------------------------------------------------------

    #[test]
    fn test_router_returns_valid_router() {
        let _router = router();
    }

    // -----------------------------------------------------------------------
    // OpenAPI doc: tag, path, and operation coverage
    // -----------------------------------------------------------------------

    #[test]
    fn test_openapi_doc_has_service_accounts_tag() {
        let doc = ServiceAccountsApiDoc::openapi();
        let tags = doc.tags.as_ref().expect("OpenAPI doc should have tags");
        let tag_names: Vec<&str> = tags.iter().map(|t| t.name.as_str()).collect();
        assert!(
            tag_names.contains(&"service_accounts"),
            "Expected 'service_accounts' tag, found: {:?}",
            tag_names
        );
    }

    #[test]
    fn test_openapi_doc_contains_base_path() {
        let doc = ServiceAccountsApiDoc::openapi();
        let paths: Vec<&str> = doc.paths.paths.keys().map(|k| k.as_str()).collect();
        assert!(
            paths.contains(&"/api/v1/service-accounts"),
            "Expected base path '/api/v1/service-accounts', found: {:?}",
            paths
        );
    }

    #[test]
    fn test_openapi_doc_contains_id_path() {
        let doc = ServiceAccountsApiDoc::openapi();
        let paths: Vec<&str> = doc.paths.paths.keys().map(|k| k.as_str()).collect();
        assert!(
            paths.contains(&"/api/v1/service-accounts/{id}"),
            "Expected path '/api/v1/service-accounts/{{id}}', found: {:?}",
            paths
        );
    }

    #[test]
    fn test_openapi_doc_contains_tokens_path() {
        let doc = ServiceAccountsApiDoc::openapi();
        let paths: Vec<&str> = doc.paths.paths.keys().map(|k| k.as_str()).collect();
        assert!(
            paths.contains(&"/api/v1/service-accounts/{id}/tokens"),
            "Expected tokens path, found: {:?}",
            paths
        );
    }

    #[test]
    fn test_openapi_doc_contains_token_revoke_path() {
        let doc = ServiceAccountsApiDoc::openapi();
        let paths: Vec<&str> = doc.paths.paths.keys().map(|k| k.as_str()).collect();
        assert!(
            paths.contains(&"/api/v1/service-accounts/{id}/tokens/{token_id}"),
            "Expected token revoke path, found: {:?}",
            paths
        );
    }

    #[test]
    fn test_openapi_doc_contains_repo_selector_preview_path() {
        let doc = ServiceAccountsApiDoc::openapi();
        let paths: Vec<&str> = doc.paths.paths.keys().map(|k| k.as_str()).collect();
        assert!(
            paths.contains(&"/api/v1/service-accounts/repo-selector/preview"),
            "Expected repo-selector preview path, found: {:?}",
            paths
        );
    }

    #[test]
    fn test_openapi_doc_base_path_has_get_and_post() {
        let doc = ServiceAccountsApiDoc::openapi();
        let base = doc.paths.paths.get("/api/v1/service-accounts").unwrap();
        assert!(base.get.is_some(), "Base path should have GET (list)");
        assert!(base.post.is_some(), "Base path should have POST (create)");
    }

    #[test]
    fn test_openapi_doc_id_path_has_get_patch_delete() {
        let doc = ServiceAccountsApiDoc::openapi();
        let id_path = doc
            .paths
            .paths
            .get("/api/v1/service-accounts/{id}")
            .unwrap();
        assert!(id_path.get.is_some(), "ID path should have GET");
        assert!(id_path.patch.is_some(), "ID path should have PATCH");
        assert!(id_path.delete.is_some(), "ID path should have DELETE");
    }

    #[test]
    fn test_openapi_doc_tokens_path_has_get_and_post() {
        let doc = ServiceAccountsApiDoc::openapi();
        let tokens = doc
            .paths
            .paths
            .get("/api/v1/service-accounts/{id}/tokens")
            .unwrap();
        assert!(tokens.get.is_some(), "Tokens path should have GET (list)");
        assert!(
            tokens.post.is_some(),
            "Tokens path should have POST (create)"
        );
    }

    #[test]
    fn test_openapi_doc_token_revoke_path_has_delete() {
        let doc = ServiceAccountsApiDoc::openapi();
        let revoke = doc
            .paths
            .paths
            .get("/api/v1/service-accounts/{id}/tokens/{token_id}")
            .unwrap();
        assert!(
            revoke.delete.is_some(),
            "Token revoke path should have DELETE"
        );
    }

    #[test]
    fn test_openapi_doc_preview_path_has_post() {
        let doc = ServiceAccountsApiDoc::openapi();
        let preview = doc
            .paths
            .paths
            .get("/api/v1/service-accounts/repo-selector/preview")
            .unwrap();
        assert!(preview.post.is_some(), "Preview path should have POST");
    }

    #[test]
    fn test_openapi_doc_has_all_expected_schemas() {
        let doc = ServiceAccountsApiDoc::openapi();
        let schemas = doc.components.as_ref().unwrap();
        let schema_names: Vec<&str> = schemas.schemas.keys().map(|k| k.as_str()).collect();
        let expected = [
            "CreateServiceAccountRequest",
            "ServiceAccountResponse",
            "ServiceAccountListResponse",
            "ServiceAccountSummaryResponse",
            "UpdateServiceAccountRequest",
            "CreateTokenRequest",
            "CreateTokenResponse",
            "TokenInfoResponse",
            "TokenListResponse",
            "PreviewRepoSelectorRequest",
            "PreviewRepoSelectorResponse",
            "MatchedRepoResponse",
        ];
        for name in &expected {
            assert!(
                schema_names.contains(name),
                "Missing schema '{}' in OpenAPI doc. Found: {:?}",
                name,
                schema_names
            );
        }
    }

    #[test]
    fn test_openapi_doc_path_count_is_exact() {
        let doc = ServiceAccountsApiDoc::openapi();
        assert_eq!(
            doc.paths.paths.len(),
            5,
            "Expected exactly 5 paths in OpenAPI doc"
        );
    }

    #[test]
    fn test_openapi_doc_total_operation_count() {
        let doc = ServiceAccountsApiDoc::openapi();
        let mut count = 0;
        for item in doc.paths.paths.values() {
            if item.get.is_some() {
                count += 1;
            }
            if item.post.is_some() {
                count += 1;
            }
            if item.patch.is_some() {
                count += 1;
            }
            if item.delete.is_some() {
                count += 1;
            }
            if item.put.is_some() {
                count += 1;
            }
        }
        assert_eq!(
            count, 9,
            "Expected 9 operations total (matches 9 handler fns)"
        );
    }

    // -----------------------------------------------------------------------
    // build_token_info_response: additional edge cases
    // -----------------------------------------------------------------------

    #[test]
    fn test_build_token_info_response_multiple_scopes() {
        let id = Uuid::new_v4();
        let now = Utc::now();
        let scopes = vec![
            "read".to_string(),
            "write".to_string(),
            "delete".to_string(),
            "admin".to_string(),
        ];
        let resp = build_token_info_response(
            id,
            "multi-scope".to_string(),
            "ak_ms".to_string(),
            scopes.clone(),
            None,
            None,
            now,
            false,
            vec![],
            None,
        );
        assert_eq!(resp.scopes, scopes);
        assert_eq!(resp.scopes.len(), 4);
    }

    #[test]
    fn test_build_token_info_response_multiple_repos_no_selector() {
        let id = Uuid::new_v4();
        let now = Utc::now();
        let r1 = Uuid::new_v4();
        let r2 = Uuid::new_v4();
        let r3 = Uuid::new_v4();
        let resp = build_token_info_response(
            id,
            "multi-repo".to_string(),
            "ak_mr".to_string(),
            vec!["read".to_string()],
            None,
            None,
            now,
            false,
            vec![r1, r2, r3],
            None,
        );
        assert_eq!(resp.repository_ids.len(), 3);
        assert!(resp.repository_ids.contains(&r1));
        assert!(resp.repository_ids.contains(&r2));
        assert!(resp.repository_ids.contains(&r3));
        assert!(resp.repo_selector.is_none());
    }

    // -----------------------------------------------------------------------
    // build_repo_map: additional edge cases
    // -----------------------------------------------------------------------

    #[test]
    fn test_build_repo_map_preserves_insertion_order_per_token() {
        let t = Uuid::new_v4();
        let r1 = Uuid::new_v4();
        let r2 = Uuid::new_v4();
        let r3 = Uuid::new_v4();
        let map = build_repo_map(vec![(t, r1), (t, r2), (t, r3)]);
        let repos = &map[&t];
        assert_eq!(repos[0], r1);
        assert_eq!(repos[1], r2);
        assert_eq!(repos[2], r3);
    }

    #[test]
    fn test_build_repo_map_many_tokens_each_with_one_repo() {
        let pairs: Vec<(Uuid, Uuid)> = (0..10).map(|_| (Uuid::new_v4(), Uuid::new_v4())).collect();
        let map = build_repo_map(pairs.clone());
        assert_eq!(map.len(), 10);
        for (token_id, repo_id) in &pairs {
            assert_eq!(map[token_id], vec![*repo_id]);
        }
    }

    // -----------------------------------------------------------------------
    // build_selector_map: additional edge cases
    // -----------------------------------------------------------------------

    #[test]
    fn test_build_selector_map_all_none_selectors() {
        let ids: Vec<Uuid> = (0..3).map(|_| Uuid::new_v4()).collect();
        let rows: Vec<(Uuid, Option<serde_json::Value>)> =
            ids.iter().map(|id| (*id, None)).collect();
        let map = build_selector_map(rows);
        assert_eq!(map.len(), 3);
        for id in &ids {
            assert_eq!(map[id], None);
        }
    }

    #[test]
    fn test_build_selector_map_complex_selector_values() {
        let id = Uuid::new_v4();
        let complex = serde_json::json!({
            "match_formats": ["docker", "maven", "npm"],
            "match_labels": {"env": "staging", "team": "platform"},
            "match_pattern": "libs-*-snapshot"
        });
        let map = build_selector_map(vec![(id, Some(complex.clone()))]);
        let stored = map[&id].as_ref().unwrap();
        assert_eq!(stored["match_formats"].as_array().unwrap().len(), 3);
        assert_eq!(stored["match_labels"]["team"], "platform");
        assert_eq!(stored["match_pattern"], "libs-*-snapshot");
    }

    // -----------------------------------------------------------------------
    // DTO serialization: additional coverage
    // -----------------------------------------------------------------------

    #[test]
    fn test_create_token_request_with_repo_ids_and_no_selector() {
        let id1 = Uuid::new_v4();
        let id2 = Uuid::new_v4();
        let json = format!(
            r#"{{"name":"scoped","scopes":["read"],"repository_ids":["{}","{}"],"repo_selector":null}}"#,
            id1, id2
        );
        let req: CreateTokenRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(req.repository_ids.as_ref().unwrap().len(), 2);
        assert!(req.repository_ids.as_ref().unwrap().contains(&id1));
        assert!(req.repository_ids.as_ref().unwrap().contains(&id2));
        assert!(req.repo_selector.is_none());
    }

    #[test]
    fn test_create_token_request_negative_expires_in_days() {
        let json = r#"{"name":"neg","scopes":["read"],"expires_in_days":-1}"#;
        let req: CreateTokenRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.expires_in_days, Some(-1));
    }

    #[test]
    fn test_create_token_response_round_trip() {
        let id = Uuid::new_v4();
        let resp = CreateTokenResponse {
            id,
            token: "ak_secret_xyz789".to_string(),
            name: "roundtrip-token".to_string(),
        };
        let serialized = serde_json::to_string(&resp).unwrap();
        let json: serde_json::Value = serde_json::from_str(&serialized).unwrap();
        assert_eq!(json["id"], id.to_string());
        assert_eq!(json["token"], "ak_secret_xyz789");
        assert_eq!(json["name"], "roundtrip-token");
    }

    #[test]
    fn test_token_list_response_with_multiple_items() {
        let now = Utc::now();
        let resp = TokenListResponse {
            items: vec![
                TokenInfoResponse {
                    id: Uuid::new_v4(),
                    name: "token-a".to_string(),
                    token_prefix: "ak_aaa".to_string(),
                    scopes: vec!["read".to_string()],
                    expires_at: Some(now),
                    last_used_at: None,
                    created_at: now,
                    is_expired: false,
                    repo_selector: None,
                    repository_ids: vec![],
                },
                TokenInfoResponse {
                    id: Uuid::new_v4(),
                    name: "token-b".to_string(),
                    token_prefix: "ak_bbb".to_string(),
                    scopes: vec!["write".to_string()],
                    expires_at: None,
                    last_used_at: Some(now),
                    created_at: now,
                    is_expired: true,
                    repo_selector: Some(serde_json::json!({"match_formats": ["cargo"]})),
                    repository_ids: vec![Uuid::new_v4()],
                },
            ],
        };
        let json = serde_json::to_value(&resp).unwrap();
        let items = json["items"].as_array().unwrap();
        assert_eq!(items.len(), 2);
        assert_eq!(items[0]["name"], "token-a");
        assert_eq!(items[0]["is_expired"], false);
        assert_eq!(items[1]["name"], "token-b");
        assert_eq!(items[1]["is_expired"], true);
        assert!(items[1]["repo_selector"].is_object());
    }

    #[test]
    fn test_service_account_response_round_trip() {
        let now = Utc::now();
        let id = Uuid::new_v4();
        let resp = ServiceAccountResponse {
            id,
            username: "svc-pipeline".to_string(),
            display_name: Some("Pipeline Bot".to_string()),
            is_active: true,
            created_at: now,
            updated_at: now,
        };
        let serialized = serde_json::to_string(&resp).unwrap();
        let deserialized: serde_json::Value = serde_json::from_str(&serialized).unwrap();
        assert_eq!(deserialized["id"], id.to_string());
        assert_eq!(deserialized["username"], "svc-pipeline");
        assert_eq!(deserialized["display_name"], "Pipeline Bot");
        assert_eq!(deserialized["is_active"], true);
    }

    #[test]
    fn test_matched_repo_response_round_trip() {
        let id = Uuid::new_v4();
        let resp = MatchedRepoResponse {
            id,
            key: "docker-staging".to_string(),
            format: "docker".to_string(),
        };
        let serialized = serde_json::to_string(&resp).unwrap();
        let deserialized: serde_json::Value = serde_json::from_str(&serialized).unwrap();
        assert_eq!(deserialized["id"], id.to_string());
        assert_eq!(deserialized["key"], "docker-staging");
        assert_eq!(deserialized["format"], "docker");
    }

    #[test]
    fn test_preview_response_round_trip_with_items() {
        let id = Uuid::new_v4();
        let resp = PreviewRepoSelectorResponse {
            matched_repositories: vec![MatchedRepoResponse {
                id,
                key: "npm-releases".to_string(),
                format: "npm".to_string(),
            }],
            total: 1,
        };
        let serialized = serde_json::to_string(&resp).unwrap();
        let deserialized: serde_json::Value = serde_json::from_str(&serialized).unwrap();
        assert_eq!(deserialized["total"], 1);
        let repos = deserialized["matched_repositories"].as_array().unwrap();
        assert_eq!(repos.len(), 1);
        assert_eq!(repos[0]["id"], id.to_string());
    }

    #[test]
    fn test_update_request_deserialize_null_fields() {
        let json = r#"{"display_name":null,"is_active":null}"#;
        let req: UpdateServiceAccountRequest = serde_json::from_str(json).unwrap();
        assert!(req.display_name.is_none());
        assert!(req.is_active.is_none());
    }

    #[test]
    fn test_create_service_account_request_unicode_name() {
        let json = r#"{"name":"svc-日本語","description":"Unicode test"}"#;
        let req: CreateServiceAccountRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.name, "svc-日本語");
    }

    #[test]
    fn test_create_service_account_request_empty_name() {
        let json = r#"{"name":""}"#;
        let req: CreateServiceAccountRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.name, "");
    }

    #[test]
    fn test_preview_repo_selector_request_array_selector() {
        let json = r#"{"repo_selector":[1,2,3]}"#;
        let req: PreviewRepoSelectorRequest = serde_json::from_str(json).unwrap();
        assert!(req.repo_selector.is_array());
    }

    // -----------------------------------------------------------------------
    // From<ServiceAccountSummary>: additional edge cases
    // -----------------------------------------------------------------------

    #[test]
    fn test_summary_conversion_large_token_count() {
        let now = Utc::now();
        let summary = ServiceAccountSummary {
            id: Uuid::new_v4(),
            username: "svc-heavy".to_string(),
            display_name: Some("Heavy User".to_string()),
            is_active: true,
            token_count: i64::MAX,
            created_at: now,
            updated_at: now,
        };
        let resp: ServiceAccountSummaryResponse = summary.into();
        assert_eq!(resp.token_count, i64::MAX);
    }

    #[test]
    fn test_summary_conversion_inactive_account() {
        let now = Utc::now();
        let summary = ServiceAccountSummary {
            id: Uuid::new_v4(),
            username: "svc-disabled".to_string(),
            display_name: None,
            is_active: false,
            token_count: 0,
            created_at: now,
            updated_at: now,
        };
        let resp: ServiceAccountSummaryResponse = summary.into();
        assert!(!resp.is_active);
        assert!(resp.display_name.is_none());
        assert_eq!(resp.token_count, 0);
        assert_eq!(resp.username, "svc-disabled");
    }
}
