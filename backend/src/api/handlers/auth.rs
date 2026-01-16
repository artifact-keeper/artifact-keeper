//! Authentication handlers.

use std::sync::Arc;

use axum::{
    extract::{Extension, State},
    routing::{get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::api::middleware::auth::AuthExtension;
use crate::api::SharedState;
use crate::error::{AppError, Result};
use crate::services::auth_service::AuthService;

/// Create public auth routes (no auth required)
pub fn public_router() -> Router<SharedState> {
    Router::new()
        .route("/login", post(login))
        .route("/logout", post(logout))
        .route("/refresh", post(refresh_token))
}

/// Create protected auth routes (auth required)
pub fn protected_router() -> Router<SharedState> {
    Router::new()
        .route("/me", get(get_current_user))
}

#[derive(Debug, Deserialize)]
pub struct LoginRequest {
    pub username: String,
    pub password: String,
}

#[derive(Debug, Serialize)]
pub struct LoginResponse {
    pub access_token: String,
    pub refresh_token: String,
    pub expires_in: u64,
    pub token_type: String,
    pub must_change_password: bool,
}

#[derive(Debug, Deserialize)]
pub struct RefreshTokenRequest {
    pub refresh_token: String,
}

#[derive(Debug, Serialize)]
pub struct UserResponse {
    pub id: Uuid,
    pub username: String,
    pub email: String,
    pub display_name: Option<String>,
    pub is_admin: bool,
}

/// Login with credentials
pub async fn login(
    State(state): State<SharedState>,
    Json(payload): Json<LoginRequest>,
) -> Result<Json<LoginResponse>> {
    let auth_service = AuthService::new(state.db.clone(), Arc::new(state.config.clone()));

    let (user, tokens) = auth_service
        .authenticate(&payload.username, &payload.password)
        .await?;

    Ok(Json(LoginResponse {
        access_token: tokens.access_token,
        refresh_token: tokens.refresh_token,
        expires_in: tokens.expires_in,
        token_type: "Bearer".to_string(),
        must_change_password: user.must_change_password,
    }))
}

/// Logout current session
pub async fn logout(State(_state): State<SharedState>) -> Result<()> {
    // JWT tokens are stateless, so logout is handled client-side
    // For API tokens, the client should delete the token
    // In a production system, you might maintain a token blacklist
    Ok(())
}

/// Refresh access token
pub async fn refresh_token(
    State(state): State<SharedState>,
    Json(payload): Json<RefreshTokenRequest>,
) -> Result<Json<LoginResponse>> {
    let auth_service = AuthService::new(state.db.clone(), Arc::new(state.config.clone()));

    let (user, tokens) = auth_service.refresh_tokens(&payload.refresh_token).await?;

    Ok(Json(LoginResponse {
        access_token: tokens.access_token,
        refresh_token: tokens.refresh_token,
        expires_in: tokens.expires_in,
        token_type: "Bearer".to_string(),
        must_change_password: user.must_change_password,
    }))
}

/// Get current user info
pub async fn get_current_user(
    State(state): State<SharedState>,
    Extension(auth): Extension<AuthExtension>,
) -> Result<Json<UserResponse>> {
    // Fetch full user details from database
    let user = sqlx::query!(
        r#"
        SELECT id, username, email, display_name, is_admin
        FROM users
        WHERE id = $1 AND is_active = true
        "#,
        auth.user_id
    )
    .fetch_optional(&state.db)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?
    .ok_or_else(|| AppError::NotFound("User not found".to_string()))?;

    Ok(Json(UserResponse {
        id: user.id,
        username: user.username,
        email: user.email,
        display_name: user.display_name,
        is_admin: user.is_admin,
    }))
}

/// Create API token request
#[derive(Debug, Deserialize)]
pub struct CreateApiTokenRequest {
    pub name: String,
    pub scopes: Vec<String>,
    pub expires_in_days: Option<i64>,
}

/// Create API token response
#[derive(Debug, Serialize)]
pub struct CreateApiTokenResponse {
    pub id: Uuid,
    pub token: String,
    pub name: String,
}

/// Create a new API token for the current user
pub async fn create_api_token(
    State(state): State<SharedState>,
    Extension(auth): Extension<AuthExtension>,
    Json(payload): Json<CreateApiTokenRequest>,
) -> Result<Json<CreateApiTokenResponse>> {
    let auth_service = AuthService::new(state.db.clone(), Arc::new(state.config.clone()));

    let (token, id) = auth_service
        .generate_api_token(
            auth.user_id,
            &payload.name,
            payload.scopes,
            payload.expires_in_days,
        )
        .await?;

    Ok(Json(CreateApiTokenResponse {
        id,
        token,
        name: payload.name,
    }))
}

/// Revoke an API token
pub async fn revoke_api_token(
    State(state): State<SharedState>,
    Extension(auth): Extension<AuthExtension>,
    axum::extract::Path(token_id): axum::extract::Path<Uuid>,
) -> Result<()> {
    let auth_service = AuthService::new(state.db.clone(), Arc::new(state.config.clone()));

    auth_service
        .revoke_api_token(token_id, auth.user_id)
        .await?;

    Ok(())
}
