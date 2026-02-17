//! Authentication handlers.

use std::sync::Arc;

use axum::http::header::{COOKIE, SET_COOKIE};
use axum::http::HeaderMap;
use axum::{
    extract::{Extension, State},
    response::{IntoResponse, Response},
    routing::{delete, get, post},
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
        .route("/tokens", post(create_api_token))
        .route("/tokens/:token_id", delete(revoke_api_token))
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
    // Non-admin users cannot request the "admin" scope
    if !auth.is_admin && payload.scopes.iter().any(|s| s == "admin") {
        return Err(AppError::Authorization(
            "Only administrators can create tokens with the 'admin' scope".to_string(),
        ));
    }

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

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::header::{COOKIE, SET_COOKIE};
    use axum::http::HeaderMap;

    // -----------------------------------------------------------------------
    // LoginRequest deserialization
    // -----------------------------------------------------------------------

    #[test]
    fn test_login_request_deserialize() {
        let json = r#"{"username": "admin", "password": "secret123"}"#;
        let req: LoginRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.username, "admin");
        assert_eq!(req.password, "secret123");
    }

    #[test]
    fn test_login_request_missing_field() {
        let json = r#"{"username": "admin"}"#;
        let result = serde_json::from_str::<LoginRequest>(json);
        assert!(result.is_err());
    }

    #[test]
    fn test_login_request_empty_strings() {
        let json = r#"{"username": "", "password": ""}"#;
        let req: LoginRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.username, "");
        assert_eq!(req.password, "");
    }

    // -----------------------------------------------------------------------
    // LoginResponse serialization
    // -----------------------------------------------------------------------

    #[test]
    fn test_login_response_serialize_without_totp() {
        let resp = LoginResponse {
            access_token: "access123".to_string(),
            refresh_token: "refresh456".to_string(),
            expires_in: 3600,
            token_type: "Bearer".to_string(),
            must_change_password: false,
            totp_required: None,
            totp_token: None,
        };
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["access_token"], "access123");
        assert_eq!(json["refresh_token"], "refresh456");
        assert_eq!(json["expires_in"], 3600);
        assert_eq!(json["token_type"], "Bearer");
        assert_eq!(json["must_change_password"], false);
        // totp_required and totp_token should be absent (skip_serializing_if)
        assert!(json.get("totp_required").is_none());
        assert!(json.get("totp_token").is_none());
    }

    #[test]
    fn test_login_response_serialize_with_totp() {
        let resp = LoginResponse {
            access_token: "".to_string(),
            refresh_token: "".to_string(),
            expires_in: 3600,
            token_type: "Bearer".to_string(),
            must_change_password: false,
            totp_required: Some(true),
            totp_token: Some("pending-token-123".to_string()),
        };
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["totp_required"], true);
        assert_eq!(json["totp_token"], "pending-token-123");
    }

    #[test]
    fn test_login_response_serialize_totp_not_required() {
        let resp = LoginResponse {
            access_token: "tok".to_string(),
            refresh_token: "ref".to_string(),
            expires_in: 1800,
            token_type: "Bearer".to_string(),
            must_change_password: true,
            totp_required: Some(false),
            totp_token: None,
        };
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["must_change_password"], true);
        assert_eq!(json["totp_required"], false);
        assert!(json.get("totp_token").is_none());
    }

    // -----------------------------------------------------------------------
    // RefreshTokenRequest deserialization
    // -----------------------------------------------------------------------

    #[test]
    fn test_refresh_token_request_with_token() {
        let json = r#"{"refresh_token": "some_token"}"#;
        let req: RefreshTokenRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.refresh_token, Some("some_token".to_string()));
    }

    #[test]
    fn test_refresh_token_request_without_token() {
        let json = r#"{}"#;
        let req: RefreshTokenRequest = serde_json::from_str(json).unwrap();
        assert!(req.refresh_token.is_none());
    }

    #[test]
    fn test_refresh_token_request_null_token() {
        let json = r#"{"refresh_token": null}"#;
        let req: RefreshTokenRequest = serde_json::from_str(json).unwrap();
        assert!(req.refresh_token.is_none());
    }

    // -----------------------------------------------------------------------
    // UserResponse serialization
    // -----------------------------------------------------------------------

    #[test]
    fn test_user_response_serialize() {
        let id = Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000").unwrap();
        let resp = UserResponse {
            id,
            username: "testuser".to_string(),
            email: "test@example.com".to_string(),
            display_name: Some("Test User".to_string()),
            is_admin: true,
            totp_enabled: false,
        };
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["id"], "550e8400-e29b-41d4-a716-446655440000");
        assert_eq!(json["username"], "testuser");
        assert_eq!(json["email"], "test@example.com");
        assert_eq!(json["display_name"], "Test User");
        assert_eq!(json["is_admin"], true);
        assert_eq!(json["totp_enabled"], false);
    }

    #[test]
    fn test_user_response_serialize_no_display_name() {
        let id = Uuid::new_v4();
        let resp = UserResponse {
            id,
            username: "user".to_string(),
            email: "user@test.com".to_string(),
            display_name: None,
            is_admin: false,
            totp_enabled: true,
        };
        let json = serde_json::to_value(&resp).unwrap();
        assert!(json["display_name"].is_null());
        assert_eq!(json["totp_enabled"], true);
    }

    // -----------------------------------------------------------------------
    // CreateApiTokenRequest deserialization
    // -----------------------------------------------------------------------

    #[test]
    fn test_create_api_token_request() {
        let json = r#"{"name": "deploy-key", "scopes": ["read", "write"], "expires_in_days": 30}"#;
        let req: CreateApiTokenRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.name, "deploy-key");
        assert_eq!(req.scopes, vec!["read", "write"]);
        assert_eq!(req.expires_in_days, Some(30));
    }

    #[test]
    fn test_create_api_token_request_no_expiry() {
        let json = r#"{"name": "permanent", "scopes": []}"#;
        let req: CreateApiTokenRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.name, "permanent");
        assert!(req.scopes.is_empty());
        assert!(req.expires_in_days.is_none());
    }

    // -----------------------------------------------------------------------
    // CreateApiTokenResponse serialization
    // -----------------------------------------------------------------------

    #[test]
    fn test_create_api_token_response_serialize() {
        let id = Uuid::new_v4();
        let resp = CreateApiTokenResponse {
            id,
            token: "ak_token_abc123".to_string(),
            name: "ci-key".to_string(),
        };
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["token"], "ak_token_abc123");
        assert_eq!(json["name"], "ci-key");
        assert!(json.get("id").is_some());
    }

    // -----------------------------------------------------------------------
    // SetupStatusResponse serialization
    // -----------------------------------------------------------------------

    #[test]
    fn test_setup_status_response_serialize() {
        let resp = SetupStatusResponse {
            setup_required: true,
        };
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["setup_required"], true);
    }

    #[test]
    fn test_setup_status_response_serialize_not_required() {
        let resp = SetupStatusResponse {
            setup_required: false,
        };
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["setup_required"], false);
    }

    // -----------------------------------------------------------------------
    // extract_cookie
    // -----------------------------------------------------------------------

    #[test]
    fn test_extract_cookie_found() {
        let mut headers = HeaderMap::new();
        headers.insert(
            COOKIE,
            "ak_access_token=abc123; ak_refresh_token=xyz"
                .parse()
                .unwrap(),
        );
        let result = extract_cookie(&headers, "ak_access_token");
        assert_eq!(result, Some("abc123"));
    }

    #[test]
    fn test_extract_cookie_second_cookie() {
        let mut headers = HeaderMap::new();
        headers.insert(
            COOKIE,
            "ak_access_token=abc; ak_refresh_token=xyz789"
                .parse()
                .unwrap(),
        );
        let result = extract_cookie(&headers, "ak_refresh_token");
        assert_eq!(result, Some("xyz789"));
    }

    #[test]
    fn test_extract_cookie_not_found() {
        let mut headers = HeaderMap::new();
        headers.insert(COOKIE, "other_cookie=value".parse().unwrap());
        let result = extract_cookie(&headers, "ak_access_token");
        assert!(result.is_none());
    }

    #[test]
    fn test_extract_cookie_no_cookie_header() {
        let headers = HeaderMap::new();
        let result = extract_cookie(&headers, "ak_access_token");
        assert!(result.is_none());
    }

    #[test]
    fn test_extract_cookie_empty_value() {
        let mut headers = HeaderMap::new();
        headers.insert(COOKIE, "ak_access_token=".parse().unwrap());
        let result = extract_cookie(&headers, "ak_access_token");
        assert_eq!(result, Some(""));
    }

    #[test]
    fn test_extract_cookie_with_spaces() {
        let mut headers = HeaderMap::new();
        headers.insert(
            COOKIE,
            "  ak_access_token=spaced ; other=val ".parse().unwrap(),
        );
        let result = extract_cookie(&headers, "ak_access_token");
        assert_eq!(result, Some("spaced"));
    }

    // -----------------------------------------------------------------------
    // set_auth_cookies
    // -----------------------------------------------------------------------

    #[test]
    fn test_set_auth_cookies_adds_two_cookies() {
        let mut headers = HeaderMap::new();
        set_auth_cookies(&mut headers, "access_tok", "refresh_tok", 3600);
        let cookies: Vec<_> = headers.get_all(SET_COOKIE).iter().collect();
        assert_eq!(cookies.len(), 2);
    }

    #[test]
    fn test_set_auth_cookies_access_token_format() {
        let mut headers = HeaderMap::new();
        set_auth_cookies(&mut headers, "myaccess", "myrefresh", 3600);
        let cookies: Vec<_> = headers
            .get_all(SET_COOKIE)
            .iter()
            .map(|v| v.to_str().unwrap().to_string())
            .collect();
        let access_cookie = cookies
            .iter()
            .find(|c| c.contains("ak_access_token="))
            .unwrap();
        assert!(access_cookie.contains("ak_access_token=myaccess"));
        assert!(access_cookie.contains("HttpOnly"));
        assert!(access_cookie.contains("SameSite=Strict"));
        assert!(access_cookie.contains("Path=/"));
        assert!(access_cookie.contains("Max-Age=3600"));
    }

    #[test]
    fn test_set_auth_cookies_refresh_token_path() {
        let mut headers = HeaderMap::new();
        set_auth_cookies(&mut headers, "acc", "ref", 1800);
        let cookies: Vec<_> = headers
            .get_all(SET_COOKIE)
            .iter()
            .map(|v| v.to_str().unwrap().to_string())
            .collect();
        let refresh_cookie = cookies
            .iter()
            .find(|c| c.contains("ak_refresh_token="))
            .unwrap();
        assert!(refresh_cookie.contains("ak_refresh_token=ref"));
        assert!(refresh_cookie.contains("Path=/api/v1/auth/refresh"));
        // 7 days in seconds
        assert!(refresh_cookie.contains("Max-Age=604800"));
    }

    // -----------------------------------------------------------------------
    // clear_auth_cookies
    // -----------------------------------------------------------------------

    #[test]
    fn test_clear_auth_cookies_sets_max_age_zero() {
        let mut headers = HeaderMap::new();
        clear_auth_cookies(&mut headers);
        let cookies: Vec<_> = headers
            .get_all(SET_COOKIE)
            .iter()
            .map(|v| v.to_str().unwrap().to_string())
            .collect();
        assert_eq!(cookies.len(), 2);
        for cookie in &cookies {
            assert!(
                cookie.contains("Max-Age=0"),
                "Cookie should have Max-Age=0: {}",
                cookie
            );
        }
    }

    #[test]
    fn test_clear_auth_cookies_empties_values() {
        let mut headers = HeaderMap::new();
        clear_auth_cookies(&mut headers);
        let cookies: Vec<_> = headers
            .get_all(SET_COOKIE)
            .iter()
            .map(|v| v.to_str().unwrap().to_string())
            .collect();
        let access = cookies
            .iter()
            .find(|c| c.starts_with("ak_access_token="))
            .unwrap();
        assert!(access.starts_with("ak_access_token=;"));
    }

    // -----------------------------------------------------------------------
    // CreateTicketRequest deserialization
    // -----------------------------------------------------------------------

    #[test]
    fn test_create_ticket_request_with_resource_path() {
        let json = r#"{"purpose": "download", "resource_path": "/artifacts/mylib/1.0.jar"}"#;
        let req: CreateTicketRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.purpose, "download");
        assert_eq!(
            req.resource_path,
            Some("/artifacts/mylib/1.0.jar".to_string())
        );
    }

    #[test]
    fn test_create_ticket_request_without_resource_path() {
        let json = r#"{"purpose": "stream"}"#;
        let req: CreateTicketRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.purpose, "stream");
        assert!(req.resource_path.is_none());
    }

    // -----------------------------------------------------------------------
    // TicketResponse serialization
    // -----------------------------------------------------------------------

    #[test]
    fn test_ticket_response_serialize() {
        let resp = TicketResponse {
            ticket: "ticket_abc123".to_string(),
            expires_in: 30,
        };
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["ticket"], "ticket_abc123");
        assert_eq!(json["expires_in"], 30);
    }
}
