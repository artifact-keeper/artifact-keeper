//! OIDC Device Authorization Grant (RFC 8628) handlers.
//!
//! Endpoints:
//! - POST /api/v1/auth/oidc/device/code  — initiate device flow
//! - POST /api/v1/auth/oidc/device/token — poll for access token
//! - POST /api/v1/auth/oidc/device/approve — approve a pending device session (authenticated)
//! - GET  /device — browser placeholder page

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Mutex, OnceLock};
use std::time::Instant;

use axum::extract::{ConnectInfo, State};
use axum::http::StatusCode;
use axum::response::{Html, IntoResponse, Response};
use axum::routing::{get, post};
use axum::Router;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::api::extractors::{Json, RequestBaseUrl};
use crate::api::middleware::auth::AuthExtension;
use crate::api::SharedState;
use crate::error::{AppError, Result};
use crate::services::audit_service::{
    audit_fire_and_forget, AuditAction, AuditEntry, ResourceType,
};
use crate::services::auth_config_service::AuthConfigService;
use crate::services::auth_service::AuthService;
use crate::services::oidc_device_service::{DevicePollResult, OidcDeviceService};

// ---------------------------------------------------------------------------
// Rate limiter for device code creation: max 10 per IP per minute
// ---------------------------------------------------------------------------

static DEVICE_CODE_RATE_LIMITER: OnceLock<Mutex<HashMap<IpAddr, (u32, Instant)>>> = OnceLock::new();

fn check_device_code_rate_limit(ip: IpAddr) -> bool {
    let limiter = DEVICE_CODE_RATE_LIMITER.get_or_init(|| Mutex::new(HashMap::new()));
    let mut map = limiter.lock().unwrap();
    let now = Instant::now();
    let entry = map.entry(ip).or_insert((0, now));
    if now.duration_since(entry.1).as_secs() >= 60 {
        *entry = (1, now);
        true
    } else if entry.0 < 10 {
        entry.0 += 1;
        true
    } else {
        false
    }
}

// ---------------------------------------------------------------------------
// Allowed scopes for device flow
// ---------------------------------------------------------------------------

const ALLOWED_SCOPES: &[&str] = &[
    "openid",
    "profile",
    "email",
    "read:artifacts",
    "write:artifacts",
];

// ---------------------------------------------------------------------------
// Request / response types
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct DeviceCodeRequest {
    pub provider_id: Uuid,
    pub client_id: String,
    #[serde(default)]
    pub scopes: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct DeviceCodeResponse {
    pub device_code: String,
    pub user_code: String,
    pub verification_uri: String,
    pub verification_uri_complete: String,
    pub expires_in: u64,
    pub interval: u64,
}

#[derive(Debug, Deserialize)]
pub struct DeviceTokenForm {
    pub grant_type: String,
    pub device_code: String,
    pub client_id: String,
}

#[derive(Debug, Serialize)]
pub struct TokenResponse {
    pub access_token: String,
    pub token_type: String,
    pub expires_in: u64,
    pub refresh_token: String,
}

#[derive(Debug, Serialize)]
pub struct OAuthErrorResponse {
    pub error: String,
    pub error_description: String,
}

#[derive(Debug, Deserialize)]
pub struct ApproveDeviceRequest {
    pub user_code: String,
}

// ---------------------------------------------------------------------------
// Routers
// ---------------------------------------------------------------------------

pub fn public_router() -> Router<SharedState> {
    Router::new()
        .route("/code", post(create_device_code))
        .route("/token", post(poll_device_token))
}

pub fn device_page_router() -> Router<SharedState> {
    Router::new().route("/device", get(device_page))
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

/// GET /device — placeholder browser approval page.
pub async fn device_page() -> impl IntoResponse {
    Html(
        r#"<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><title>Device Activation</title></head>
<body>
<h1>Device Activation</h1>
<p>Enter the code displayed on your device to authorize access.</p>
<p><em>Full browser flow coming soon. Use the authenticated
<code>POST /api/v1/auth/oidc/device/approve</code> endpoint for now.</em></p>
</body>
</html>"#,
    )
}

/// POST /api/v1/auth/oidc/device/code — initiate device authorization flow.
pub async fn create_device_code(
    State(state): State<SharedState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    base_url: RequestBaseUrl,
    Json(req): Json<DeviceCodeRequest>,
) -> Result<impl IntoResponse> {
    // Rate limit
    if !check_device_code_rate_limit(addr.ip()) {
        return Err(AppError::Validation(
            "Too many device code requests. Please wait before trying again.".into(),
        ));
    }

    // Validate scopes
    for scope in &req.scopes {
        if !ALLOWED_SCOPES.contains(&scope.as_str()) {
            return Err(AppError::Validation(format!(
                "Scope '{}' is not allowed. Allowed scopes: {}",
                scope,
                ALLOWED_SCOPES.join(", ")
            )));
        }
    }

    // Verify provider exists and is enabled
    let provider = AuthConfigService::get_oidc(&state.db, req.provider_id).await?;
    if !provider.is_enabled {
        return Err(AppError::Validation(format!(
            "OIDC provider '{}' is disabled",
            provider.name
        )));
    }

    let svc = OidcDeviceService::new(state.db.clone());
    let session = svc
        .create_session(
            req.provider_id,
            req.client_id,
            req.scopes,
            base_url.as_str(),
        )
        .await?;

    let verification_uri_complete = format!(
        "{}?user_code={}",
        session.verification_uri, session.user_code
    );

    Ok((
        StatusCode::OK,
        axum::Json(DeviceCodeResponse {
            device_code: session.device_code,
            user_code: session.user_code,
            verification_uri: session.verification_uri,
            verification_uri_complete,
            expires_in: 600,
            interval: session.interval_secs as u64,
        }),
    ))
}

/// POST /api/v1/auth/oidc/device/token — poll for tokens (RFC 8628 §3.4).
///
/// Uses `application/x-www-form-urlencoded` body per the RFC.
pub async fn poll_device_token(
    State(state): State<SharedState>,
    axum::extract::Form(form): axum::extract::Form<DeviceTokenForm>,
) -> Response {
    const DEVICE_GRANT_TYPE: &str = "urn:ietf:params:oauth:grant-type:device_code";

    if form.grant_type != DEVICE_GRANT_TYPE {
        return (
            StatusCode::BAD_REQUEST,
            axum::Json(OAuthErrorResponse {
                error: "unsupported_grant_type".into(),
                error_description: format!("grant_type must be '{}'", DEVICE_GRANT_TYPE),
            }),
        )
            .into_response();
    }

    let svc = OidcDeviceService::new(state.db.clone());
    let result = match svc.poll_token(&form.device_code, &form.client_id).await {
        Ok(r) => r,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                axum::Json(OAuthErrorResponse {
                    error: "server_error".into(),
                    error_description: e.to_string(),
                }),
            )
                .into_response();
        }
    };

    match result {
        DevicePollResult::Pending => (
            StatusCode::BAD_REQUEST,
            axum::Json(OAuthErrorResponse {
                error: "authorization_pending".into(),
                error_description: "The user has not yet authorized the device.".into(),
            }),
        )
            .into_response(),

        DevicePollResult::SlowDown => (
            StatusCode::BAD_REQUEST,
            axum::Json(OAuthErrorResponse {
                error: "slow_down".into(),
                error_description: "Polling too frequently. Please wait before retrying.".into(),
            }),
        )
            .into_response(),

        DevicePollResult::Denied => (
            StatusCode::BAD_REQUEST,
            axum::Json(OAuthErrorResponse {
                error: "access_denied".into(),
                error_description: "The user denied the device authorization request.".into(),
            }),
        )
            .into_response(),

        DevicePollResult::Expired => (
            StatusCode::BAD_REQUEST,
            axum::Json(OAuthErrorResponse {
                error: "expired_token".into(),
                error_description: "The device code has expired.".into(),
            }),
        )
            .into_response(),

        DevicePollResult::Approved { user_id } => {
            // Load the user
            let user = match sqlx::query_as::<_, crate::models::user::User>(
                "SELECT * FROM users WHERE id = $1",
            )
            .bind(user_id)
            .fetch_optional(&state.db)
            .await
            {
                Ok(Some(u)) => u,
                Ok(None) => {
                    return (
                        StatusCode::BAD_REQUEST,
                        axum::Json(OAuthErrorResponse {
                            error: "server_error".into(),
                            error_description: "Approved user not found.".into(),
                        }),
                    )
                        .into_response();
                }
                Err(e) => {
                    return (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        axum::Json(OAuthErrorResponse {
                            error: "server_error".into(),
                            error_description: e.to_string(),
                        }),
                    )
                        .into_response();
                }
            };

            let auth_service =
                AuthService::new(state.db.clone(), std::sync::Arc::new(state.config.clone()));
            let tokens = match auth_service.generate_tokens(&user) {
                Ok(t) => t,
                Err(e) => {
                    return (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        axum::Json(OAuthErrorResponse {
                            error: "server_error".into(),
                            error_description: e.to_string(),
                        }),
                    )
                        .into_response();
                }
            };

            // Fire audit event
            let entry = AuditEntry::new(AuditAction::Login, ResourceType::User)
                .user(user.id)
                .details(serde_json::json!({
                    "auth_method": "oidc_device_flow",
                    "client_id": form.client_id,
                }));
            tokio::spawn(audit_fire_and_forget(state.db.clone(), entry));

            (
                StatusCode::OK,
                axum::Json(TokenResponse {
                    token_type: "Bearer".into(),
                    expires_in: 900,
                    access_token: tokens.access_token,
                    refresh_token: tokens.refresh_token,
                }),
            )
                .into_response()
        }
    }
}

/// POST /api/v1/auth/oidc/device/approve — approve a pending device session.
///
/// The caller must be authenticated (JWT required). This allows an already
/// logged-in user to approve a device session identified by `user_code`.
pub async fn approve_session_handler(
    State(state): State<SharedState>,
    axum::extract::Extension(auth): axum::extract::Extension<AuthExtension>,
    Json(req): Json<ApproveDeviceRequest>,
) -> Result<impl IntoResponse> {
    let svc = OidcDeviceService::new(state.db.clone());
    svc.approve_session(
        &req.user_code,
        auth.user_id,
        String::new(), // oidc_sub not available in this path
        String::new(), // oidc_email not available in this path
        String::new(), // oidc_name not available in this path
    )
    .await?;
    Ok((StatusCode::OK, axum::Json(serde_json::json!({"ok": true}))))
}
