//! Authentication handlers.

use std::sync::Arc;

use axum::http::header::{COOKIE, SET_COOKIE};
use axum::http::HeaderMap;
use axum::{
    extract::{Extension, State},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use utoipa::{OpenApi, ToSchema};
use uuid::Uuid;

use crate::api::middleware::auth::AuthExtension;
use crate::api::SharedState;
use crate::error::{AppError, Result};
use crate::services::auth_config_service::AuthConfigService;
use crate::services::auth_service::AuthService;
use std::sync::atomic::Ordering;

/// Create public auth routes (no auth required)
pub fn public_router() -> Router<SharedState> {
    Router::new()
        .route("/login", post(login))
        .route("/logout", post(logout))
        .route("/refresh", post(refresh_token))
}

/// Setup status endpoint (public, no auth required)
pub fn setup_router() -> Router<SharedState> {
    Router::new().route("/status", get(setup_status))
}

/// Response body for the setup status endpoint.
#[derive(Debug, Serialize, ToSchema)]
pub struct SetupStatusResponse {
    /// Whether the initial admin password change is still required.
    pub setup_required: bool,
}

/// Returns whether initial setup (password change) is required.
#[utoipa::path(
    get,
    path = "/status",
    context_path = "/api/v1/setup",
    tag = "auth",
    responses(
        (status = 200, description = "Setup status retrieved", body = SetupStatusResponse),
    )
)]
pub async fn setup_status(State(state): State<SharedState>) -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "setup_required": state.setup_required.load(Ordering::Relaxed)
    }))
}

/// Create protected auth routes (auth required)
pub fn protected_router() -> Router<SharedState> {
    Router::new()
        .route("/me", get(get_current_user))
        .route("/ticket", post(create_download_ticket))
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct LoginRequest {
    pub username: String,
    pub password: String,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct LoginResponse {
    pub access_token: String,
    pub refresh_token: String,
    pub expires_in: u64,
    pub token_type: String,
    pub must_change_password: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub totp_required: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub totp_token: Option<String>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct RefreshTokenRequest {
    pub refresh_token: Option<String>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct UserResponse {
    pub id: Uuid,
    pub username: String,
    pub email: String,
    pub display_name: Option<String>,
    pub is_admin: bool,
    pub totp_enabled: bool,
}

/// Login with credentials
#[utoipa::path(
    post,
    path = "/login",
    context_path = "/api/v1/auth",
    tag = "auth",
    request_body = LoginRequest,
    responses(
        (status = 200, description = "Login successful", body = LoginResponse),
        (status = 401, description = "Invalid credentials", body = super::super::openapi::ErrorResponse),
    )
)]
pub async fn login(
    State(state): State<SharedState>,
    Json(payload): Json<LoginRequest>,
) -> Result<Response> {
    let auth_service = AuthService::new(state.db.clone(), Arc::new(state.config.clone()));

    let (user, tokens) = auth_service
        .authenticate(&payload.username, &payload.password)
        .await?;

    // If TOTP is enabled, return a pending token instead of real tokens
    if user.totp_enabled {
        let totp_token = auth_service.generate_totp_pending_token(&user)?;
        let body = LoginResponse {
            access_token: String::new(),
            refresh_token: String::new(),
            expires_in: tokens.expires_in,
            token_type: "Bearer".to_string(),
            must_change_password: user.must_change_password,
            totp_required: Some(true),
            totp_token: Some(totp_token),
        };
        return Ok(Json(body).into_response());
    }

    let body = LoginResponse {
        access_token: tokens.access_token.clone(),
        refresh_token: tokens.refresh_token.clone(),
        expires_in: tokens.expires_in,
        token_type: "Bearer".to_string(),
        must_change_password: user.must_change_password,
        totp_required: None,
        totp_token: None,
    };

    let mut response = Json(body).into_response();
    set_auth_cookies(
        response.headers_mut(),
        &tokens.access_token,
        &tokens.refresh_token,
        tokens.expires_in,
    );
    Ok(response)
}

/// Logout current session
#[utoipa::path(
    post,
    path = "/logout",
    context_path = "/api/v1/auth",
    tag = "auth",
    responses(
        (status = 200, description = "Logout successful, auth cookies cleared"),
    )
)]
pub async fn logout(State(_state): State<SharedState>) -> Result<Response> {
    let mut response = ().into_response();
    clear_auth_cookies(response.headers_mut());
    Ok(response)
}

/// Refresh access token
#[utoipa::path(
    post,
    path = "/refresh",
    context_path = "/api/v1/auth",
    tag = "auth",
    request_body = RefreshTokenRequest,
    responses(
        (status = 200, description = "Token refreshed successfully", body = LoginResponse),
        (status = 401, description = "Invalid or expired refresh token", body = super::super::openapi::ErrorResponse),
    )
)]
pub async fn refresh_token(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Json(payload): Json<RefreshTokenRequest>,
) -> Result<Response> {
    let auth_service = AuthService::new(state.db.clone(), Arc::new(state.config.clone()));

    // Try body first, then fall back to cookie
    let refresh_token_str = payload
        .refresh_token
        .or_else(|| extract_cookie(&headers, "ak_refresh_token").map(String::from))
        .ok_or_else(|| AppError::Authentication("Missing refresh token".into()))?;

    let (user, tokens) = auth_service.refresh_tokens(&refresh_token_str).await?;

    let body = LoginResponse {
        access_token: tokens.access_token.clone(),
        refresh_token: tokens.refresh_token.clone(),
        expires_in: tokens.expires_in,
        token_type: "Bearer".to_string(),
        must_change_password: user.must_change_password,
        totp_required: None,
        totp_token: None,
    };

    let mut response = Json(body).into_response();
    set_auth_cookies(
        response.headers_mut(),
        &tokens.access_token,
        &tokens.refresh_token,
        tokens.expires_in,
    );
    Ok(response)
}

/// Get current user info
#[utoipa::path(
    get,
    path = "/me",
    context_path = "/api/v1/auth",
    tag = "auth",
    security(("bearer_auth" = [])),
    responses(
        (status = 200, description = "Current user info", body = UserResponse),
        (status = 401, description = "Not authenticated", body = super::super::openapi::ErrorResponse),
        (status = 404, description = "User not found", body = super::super::openapi::ErrorResponse),
    )
)]
pub async fn get_current_user(
    State(state): State<SharedState>,
    Extension(auth): Extension<AuthExtension>,
) -> Result<Json<UserResponse>> {
    let user = sqlx::query!(
        r#"
        SELECT id, username, email, display_name, is_admin, totp_enabled
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
        totp_enabled: user.totp_enabled,
    }))
}

/// Create API token request
#[derive(Debug, Deserialize, ToSchema)]
pub struct CreateApiTokenRequest {
    pub name: String,
    pub scopes: Vec<String>,
    pub expires_in_days: Option<i64>,
}

/// Create API token response
#[derive(Debug, Serialize, ToSchema)]
pub struct CreateApiTokenResponse {
    pub id: Uuid,
    pub token: String,
    pub name: String,
}

/// Create a new API token for the current user
#[utoipa::path(
    post,
    path = "/tokens",
    context_path = "/api/v1/auth",
    tag = "auth",
    security(("bearer_auth" = [])),
    request_body = CreateApiTokenRequest,
    responses(
        (status = 200, description = "API token created", body = CreateApiTokenResponse),
        (status = 401, description = "Not authenticated", body = super::super::openapi::ErrorResponse),
    )
)]
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

/// Extract a cookie value by name from request headers.
pub(crate) fn extract_cookie<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers
        .get(COOKIE)
        .and_then(|h| h.to_str().ok())
        .and_then(|cookies| {
            cookies
                .split(';')
                .map(|c| c.trim())
                .find_map(|c| c.strip_prefix(&format!("{}=", name)))
        })
}

/// Returns the `Secure;` cookie flag unless running in development mode,
/// where cookies must work over plain HTTP on localhost.
fn secure_flag() -> &'static str {
    if std::env::var("ENVIRONMENT").unwrap_or_default() == "development" {
        ""
    } else {
        " Secure;"
    }
}

/// Set httpOnly auth cookies on a response.
pub(crate) fn set_auth_cookies(
    headers: &mut HeaderMap,
    access_token: &str,
    refresh_token: &str,
    expires_in: u64,
) {
    let flag = secure_flag();
    let access_cookie = format!(
        "ak_access_token={}; HttpOnly;{} SameSite=Strict; Path=/; Max-Age={}",
        access_token, flag, expires_in
    );
    let refresh_cookie =
        format!(
        "ak_refresh_token={}; HttpOnly;{} SameSite=Strict; Path=/api/v1/auth/refresh; Max-Age={}",
        refresh_token, flag, 7 * 24 * 3600
    );
    headers.append(SET_COOKIE, access_cookie.parse().unwrap());
    headers.append(SET_COOKIE, refresh_cookie.parse().unwrap());
}

/// Clear auth cookies by setting Max-Age=0.
fn clear_auth_cookies(headers: &mut HeaderMap) {
    let flag = secure_flag();
    let clear_access = format!(
        "ak_access_token=; HttpOnly;{} SameSite=Strict; Path=/; Max-Age=0",
        flag
    );
    let clear_refresh = format!(
        "ak_refresh_token=; HttpOnly;{} SameSite=Strict; Path=/api/v1/auth/refresh; Max-Age=0",
        flag
    );
    headers.append(SET_COOKIE, clear_access.parse().unwrap());
    headers.append(SET_COOKIE, clear_refresh.parse().unwrap());
}

/// Revoke an API token
#[utoipa::path(
    delete,
    path = "/tokens/{token_id}",
    context_path = "/api/v1/auth",
    tag = "auth",
    security(("bearer_auth" = [])),
    params(
        ("token_id" = Uuid, Path, description = "ID of the API token to revoke"),
    ),
    responses(
        (status = 200, description = "API token revoked"),
        (status = 401, description = "Not authenticated", body = super::super::openapi::ErrorResponse),
        (status = 404, description = "Token not found", body = super::super::openapi::ErrorResponse),
    )
)]
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

// ---------------------------------------------------------------------------
// Download tickets
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize, ToSchema)]
pub struct CreateTicketRequest {
    pub purpose: String,
    pub resource_path: Option<String>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct TicketResponse {
    pub ticket: String,
    pub expires_in: u64,
}

/// Create a short-lived, single-use download/stream ticket for the current user.
/// The ticket can be passed as a `?ticket=` query parameter on endpoints that
/// cannot use `Authorization` headers (e.g. `<a>` downloads, `EventSource` SSE).
#[utoipa::path(
    post,
    path = "/ticket",
    context_path = "/api/v1/auth",
    tag = "auth",
    security(("bearer_auth" = [])),
    request_body = CreateTicketRequest,
    responses(
        (status = 200, description = "Download ticket created", body = TicketResponse),
        (status = 401, description = "Not authenticated", body = super::super::openapi::ErrorResponse),
    )
)]
pub async fn create_download_ticket(
    State(state): State<SharedState>,
    Extension(auth): Extension<AuthExtension>,
    Json(payload): Json<CreateTicketRequest>,
) -> Result<Json<TicketResponse>> {
    let ticket = AuthConfigService::create_download_ticket(
        &state.db,
        auth.user_id,
        &payload.purpose,
        payload.resource_path.as_deref(),
    )
    .await?;

    Ok(Json(TicketResponse {
        ticket,
        expires_in: 30,
    }))
}

// ---------------------------------------------------------------------------
// OpenAPI documentation
// ---------------------------------------------------------------------------

#[derive(OpenApi)]
#[openapi(
    paths(
        setup_status,
        login,
        logout,
        refresh_token,
        get_current_user,
        create_api_token,
        revoke_api_token,
        create_download_ticket,
    ),
    components(schemas(
        SetupStatusResponse,
        LoginRequest,
        LoginResponse,
        RefreshTokenRequest,
        UserResponse,
        CreateApiTokenRequest,
        CreateApiTokenResponse,
        CreateTicketRequest,
        TicketResponse,
    ))
)]
pub struct AuthApiDoc;
