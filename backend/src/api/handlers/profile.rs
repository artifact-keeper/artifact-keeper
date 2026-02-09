//! Profile handlers — endpoints scoped to the authenticated user.

use axum::{
    extract::{Extension, Path, State},
    routing::{delete, get},
    Json, Router,
};
use serde::Deserialize;
use std::sync::Arc;
use uuid::Uuid;

use crate::api::middleware::auth::AuthExtension;
use crate::api::SharedState;
use crate::error::Result;
use crate::services::auth_service::AuthService;

use super::users::{ApiTokenCreatedResponse, ApiTokenListResponse, ApiTokenResponse};

/// Create profile routes
pub fn router() -> Router<SharedState> {
    Router::new()
        .route(
            "/access-tokens",
            get(list_access_tokens).post(create_access_token),
        )
        .route("/access-tokens/:token_id", delete(revoke_access_token))
}

#[derive(Debug, Deserialize)]
pub struct CreateAccessTokenRequest {
    pub name: String,
    pub scopes: Option<Vec<String>>,
    pub expires_in_days: Option<i64>,
}

/// List the authenticated user's API tokens.
async fn list_access_tokens(
    State(state): State<SharedState>,
    Extension(auth): Extension<AuthExtension>,
) -> Result<Json<ApiTokenListResponse>> {
    let tokens = sqlx::query!(
        r#"
        SELECT id, name, token_prefix, scopes, expires_at, last_used_at, created_at
        FROM api_tokens
        WHERE user_id = $1
        ORDER BY created_at DESC
        "#,
        auth.user_id
    )
    .fetch_all(&state.db)
    .await
    .map_err(|e| crate::error::AppError::Database(e.to_string()))?;

    let items = tokens
        .into_iter()
        .map(|t| ApiTokenResponse {
            id: t.id,
            name: t.name,
            token_prefix: t.token_prefix,
            scopes: t.scopes,
            expires_at: t.expires_at,
            last_used_at: t.last_used_at,
            created_at: t.created_at,
        })
        .collect();

    Ok(Json(ApiTokenListResponse { items }))
}

/// Create an API token for the authenticated user.
async fn create_access_token(
    State(state): State<SharedState>,
    Extension(auth): Extension<AuthExtension>,
    Json(payload): Json<CreateAccessTokenRequest>,
) -> Result<Json<ApiTokenCreatedResponse>> {
    let auth_service = AuthService::new(state.db.clone(), Arc::new(state.config.clone()));
    let scopes = payload.scopes.unwrap_or_else(|| vec!["read".to_string()]);
    let (token, token_id) = auth_service
        .generate_api_token(auth.user_id, &payload.name, scopes, payload.expires_in_days)
        .await?;

    Ok(Json(ApiTokenCreatedResponse {
        id: token_id,
        name: payload.name,
        token,
    }))
}

/// Revoke an API token belonging to the authenticated user.
async fn revoke_access_token(
    State(state): State<SharedState>,
    Extension(auth): Extension<AuthExtension>,
    Path(token_id): Path<Uuid>,
) -> Result<()> {
    let auth_service = AuthService::new(state.db.clone(), Arc::new(state.config.clone()));
    auth_service
        .revoke_api_token(token_id, auth.user_id)
        .await?;
    Ok(())
}
