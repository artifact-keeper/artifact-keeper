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
    Router::new()
        .route("/device", get(device_page))
        .route("/device/app.js", get(device_page_script))
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

/// GET /device — browser approval page for the RFC 8628 device flow.
///
/// Reads `?user_code=` (from `verification_uri_complete`) or lets the user
/// type the code, verifies the browser session via `GET /api/v1/auth/me`,
/// and approves with a same-origin `fetch` that carries the
/// `X-Requested-With` header required by the cookie-auth CSRF guard.
pub async fn device_page() -> impl IntoResponse {
    Html(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Device Activation</title>
<style>
  body { font-family: system-ui, sans-serif; display: flex; justify-content: center;
         padding-top: 8vh; background: #f6f8fa; margin: 0; }
  .card { background: #fff; border: 1px solid #d0d7de; border-radius: 8px;
          padding: 2rem; max-width: 24rem; width: 100%; text-align: center; }
  h1 { font-size: 1.25rem; }
  input { font-size: 1.5rem; letter-spacing: .2em; text-align: center; width: 100%;
          box-sizing: border-box; padding: .5rem; border: 1px solid #d0d7de;
          border-radius: 6px; text-transform: uppercase; font-family: monospace; }
  button { margin-top: 1rem; width: 100%; padding: .6rem; font-size: 1rem;
           border: 0; border-radius: 6px; background: #1f883d; color: #fff;
           cursor: pointer; }
  button:disabled { background: #94d3a2; cursor: default; }
  .msg { margin-top: 1rem; min-height: 1.2em; }
  .ok { color: #1a7f37; } .err { color: #cf222e; }
  a { color: #0969da; }
</style>
</head>
<body>
<div class="card">
  <h1>Device Activation</h1>
  <p>Enter the code displayed in the app or on the device you're signing in to.
     Never enter a code sent to you by someone else.</p>
  <input id="code" placeholder="XXXX-XXXX" maxlength="9" autocomplete="off" spellcheck="false">
  <button id="approve" disabled>Approve</button>
  <div class="msg" id="msg"></div>
</div>
<script src="/device/app.js" defer></script>
</body>
</html>"#,
    )
}

/// GET /device/app.js — the activation page script, served as a separate
/// same-origin file so it runs under the `script-src 'self'` CSP (inline
/// scripts are blocked).
pub async fn device_page_script() -> impl IntoResponse {
    (
        [(axum::http::header::CONTENT_TYPE, "application/javascript")],
        r#"(function () {
  var input = document.getElementById('code');
  var btn = document.getElementById('approve');
  var msg = document.getElementById('msg');
  var authed = false;

  function setMsg(text, cls) { msg.textContent = text; msg.className = 'msg ' + (cls || ''); }
  function normalize(v) {
    var raw = v.toUpperCase().replace(/[^A-Z]/g, '').slice(0, 8);
    return raw.length > 4 ? raw.slice(0, 4) + '-' + raw.slice(4) : raw;
  }
  function refresh() {
    input.value = normalize(input.value);
    btn.disabled = !(authed && input.value.length === 9);
  }
  input.addEventListener('input', refresh);

  var params = new URLSearchParams(window.location.search);
  input.value = normalize(params.get('user_code') || '');

  fetch('/api/v1/auth/me', { credentials: 'same-origin' }).then(function (r) {
    if (r.ok) { authed = true; refresh(); return r.json(); }
    setMsg('You are not signed in. Sign in first, then return to this page ' +
           '(use the link shown by your device).', 'err');
    msg.insertAdjacentHTML('beforeend', ' <a href="/">Sign in</a>');
    return null;
  }).then(function (me) {
    if (me) { setMsg('Signed in as ' + me.username + '.', 'ok'); }
  }).catch(function () { setMsg('Could not verify your session.', 'err'); });

  btn.addEventListener('click', function () {
    btn.disabled = true;
    setMsg('Approving…');
    fetch('/api/v1/auth/oidc/device/approve', {
      method: 'POST',
      credentials: 'same-origin',
      headers: {
        'Content-Type': 'application/json',
        'X-Requested-With': 'XMLHttpRequest'
      },
      body: JSON.stringify({ user_code: input.value })
    }).then(function (r) {
      if (r.ok) {
        setMsg('Device approved. You can return to your device.', 'ok');
      } else {
        return r.text().then(function (t) {
          setMsg('Approval failed (' + r.status + '): ' + t.slice(0, 200), 'err');
          btn.disabled = false;
        });
      }
    }).catch(function (e) {
      setMsg('Approval failed: ' + e, 'err');
      btn.disabled = false;
    });
  });
})();"#,
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
                    // Report the real configured access-token TTL
                    // (JWT_ACCESS_TOKEN_EXPIRY_MINUTES), not a hardcoded value.
                    expires_in: state.config.jwt_access_token_expiry_minutes.max(0) as u64 * 60,
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

#[allow(clippy::disallowed_methods)]
#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::{to_bytes, Body};
    use axum::extract::Form;
    use axum::http::Request;
    use serde_json::Value;
    use std::net::{Ipv4Addr, Ipv6Addr};

    async fn seed_oidc_provider(pool: &sqlx::PgPool, enabled: bool) -> Uuid {
        let id = Uuid::new_v4();
        let name = format!("oidc-device-handler-provider-{id}");
        sqlx::query(
            r#"
            INSERT INTO oidc_configs
                (id, name, issuer_url, client_id, client_secret_encrypted,
                 scopes, attribute_mapping, is_enabled)
            VALUES ($1, $2, $3, $4, $5, $6, '{}'::jsonb, $7)
            "#,
        )
        .bind(id)
        .bind(name)
        .bind(format!("https://issuer-{id}.example.com"))
        .bind(format!("client-{id}"))
        .bind("encrypted-secret")
        .bind(vec!["openid".to_string(), "email".to_string()])
        .bind(enabled)
        .execute(pool)
        .await
        .expect("seed oidc provider");
        id
    }

    async fn seed_user(pool: &sqlx::PgPool) -> Uuid {
        let id = Uuid::new_v4();
        let username = format!("oidc-device-handler-user-{id}");
        sqlx::query(
            r#"
            INSERT INTO users (id, username, email, password_hash, auth_provider, is_active, is_admin)
            VALUES ($1, $2, $3, 'unused', 'local', true, false)
            "#,
        )
        .bind(id)
        .bind(&username)
        .bind(format!("{username}@example.com"))
        .execute(pool)
        .await
        .expect("seed user");
        id
    }

    fn storage_path(label: &str) -> String {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("target")
            .join("oidc-device-tests")
            .join(label)
            .join(Uuid::new_v4().to_string());
        std::fs::create_dir_all(&path).expect("create test storage dir");
        path.to_string_lossy().into_owned()
    }

    fn state(pool: sqlx::PgPool, label: &str) -> SharedState {
        crate::api::handlers::test_db_helpers::build_state(pool, &storage_path(label))
    }

    async fn response_json(response: Response) -> (StatusCode, Value) {
        let status = response.status();
        let body = to_bytes(response.into_body(), 64 * 1024)
            .await
            .expect("read response body");
        let json = serde_json::from_slice(&body).expect("json response");
        (status, json)
    }

    async fn poll_json(
        state: SharedState,
        grant_type: &str,
        device_code: &str,
        client_id: &str,
    ) -> (StatusCode, Value) {
        response_json(
            poll_device_token(
                State(state),
                Form(DeviceTokenForm {
                    grant_type: grant_type.to_string(),
                    device_code: device_code.to_string(),
                    client_id: client_id.to_string(),
                }),
            )
            .await,
        )
        .await
    }

    async fn cleanup_provider(pool: &sqlx::PgPool, provider_id: Uuid) {
        let _ = sqlx::query("DELETE FROM oidc_device_sessions WHERE provider_id = $1")
            .bind(provider_id)
            .execute(pool)
            .await;
        let _ = sqlx::query("DELETE FROM oidc_configs WHERE id = $1")
            .bind(provider_id)
            .execute(pool)
            .await;
    }

    async fn cleanup_user(pool: &sqlx::PgPool, user_id: Uuid) {
        let _ = sqlx::query("DELETE FROM users WHERE id = $1")
            .bind(user_id)
            .execute(pool)
            .await;
    }

    #[test]
    fn oidc_device_code_rate_limiter_allows_ten_per_ip_per_minute() {
        let ip = IpAddr::V6(Ipv6Addr::from(Uuid::new_v4().as_u128()));
        for _ in 0..10 {
            assert!(check_device_code_rate_limit(ip));
        }
        assert!(!check_device_code_rate_limit(ip));

        let other_ip = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 42));
        assert!(check_device_code_rate_limit(other_ip));
    }

    #[tokio::test]
    async fn oidc_device_page_returns_activation_html() {
        let response = device_page().await.into_response();
        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), 64 * 1024)
            .await
            .expect("read device page");
        let html = std::str::from_utf8(&body).expect("utf8 html");
        assert!(html.contains("Device Activation"));
        // CSP is script-src 'self': the page must reference the external
        // script, never inline it.
        assert!(html.contains("/device/app.js"));
        assert!(!html.contains("<script>"));

        let response = device_page_script().await.into_response();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response
                .headers()
                .get(axum::http::header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok()),
            Some("application/javascript")
        );
        let body = to_bytes(response.into_body(), 64 * 1024)
            .await
            .expect("read device page script");
        let js = std::str::from_utf8(&body).expect("utf8 js");
        assert!(js.contains("/api/v1/auth/oidc/device/approve"));
        assert!(js.contains("X-Requested-With"));
    }

    #[tokio::test]
    async fn oidc_device_create_code_validates_scopes_and_builds_response() {
        let Some(pool) = crate::api::handlers::test_db_helpers::try_pool().await else {
            return;
        };
        let state = state(pool.clone(), "create-code");
        let addr = SocketAddr::from((Ipv4Addr::new(198, 51, 100, 10), 12345));

        let invalid_scope = create_device_code(
            State(state.clone()),
            ConnectInfo(addr),
            RequestBaseUrl("https://registry.example.com/root/".to_string()),
            Json(DeviceCodeRequest {
                provider_id: Uuid::new_v4(),
                client_id: "handler-client".to_string(),
                scopes: vec!["openid".to_string(), "admin".to_string()],
            }),
        )
        .await;
        assert!(matches!(
            invalid_scope,
            Err(AppError::Validation(message)) if message.contains("Scope 'admin' is not allowed")
        ));

        let disabled_provider_id = seed_oidc_provider(&pool, false).await;
        let disabled_provider = create_device_code(
            State(state.clone()),
            ConnectInfo(addr),
            RequestBaseUrl("https://registry.example.com".to_string()),
            Json(DeviceCodeRequest {
                provider_id: disabled_provider_id,
                client_id: "handler-client".to_string(),
                scopes: vec!["openid".to_string()],
            }),
        )
        .await;
        assert!(matches!(
            disabled_provider,
            Err(AppError::Validation(message)) if message.contains("is disabled")
        ));

        let provider_id = seed_oidc_provider(&pool, true).await;
        let response = create_device_code(
            State(state),
            ConnectInfo(addr),
            RequestBaseUrl("https://registry.example.com/root/".to_string()),
            Json(DeviceCodeRequest {
                provider_id,
                client_id: "handler-client".to_string(),
                scopes: vec!["openid".to_string(), "read:artifacts".to_string()],
            }),
        )
        .await
        .expect("create device code")
        .into_response();
        let (status, json) = response_json(response).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(json["expires_in"], 600);
        assert_eq!(json["interval"], 5);
        assert_eq!(
            json["verification_uri"],
            "https://registry.example.com/root/device"
        );
        assert_eq!(
            json["verification_uri_complete"],
            format!(
                "{}?user_code={}",
                json["verification_uri"].as_str().unwrap(),
                json["user_code"].as_str().unwrap()
            )
        );
        assert_eq!(json["device_code"].as_str().unwrap().len(), 64);
        assert_eq!(json["user_code"].as_str().unwrap().len(), 9);

        cleanup_provider(&pool, disabled_provider_id).await;
        cleanup_provider(&pool, provider_id).await;
    }

    #[tokio::test]
    async fn oidc_device_poll_token_maps_rfc8628_errors_and_success() {
        let Some(pool) = crate::api::handlers::test_db_helpers::try_pool().await else {
            return;
        };
        let state = state(pool.clone(), "poll-token");
        let expected_expiry_secs = state.config.jwt_access_token_expiry_minutes.max(0) as u64 * 60;
        let provider_id = seed_oidc_provider(&pool, true).await;
        let user_id = seed_user(&pool).await;
        let svc = OidcDeviceService::new(pool.clone());
        const GRANT: &str = "urn:ietf:params:oauth:grant-type:device_code";

        let (status, json) = poll_json(
            state.clone(),
            "client_credentials",
            "missing-device",
            "handler-client",
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(json["error"], "unsupported_grant_type");

        let (status, json) =
            poll_json(state.clone(), GRANT, "missing-device", "handler-client").await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(json["error"], "expired_token");

        let pending = svc
            .create_session(
                provider_id,
                "handler-client".to_string(),
                vec!["openid".to_string()],
                "https://registry.example.com",
            )
            .await
            .expect("create pending session");
        let (status, json) =
            poll_json(state.clone(), GRANT, &pending.device_code, "handler-client").await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(json["error"], "authorization_pending");
        let (status, json) =
            poll_json(state.clone(), GRANT, &pending.device_code, "handler-client").await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(json["error"], "slow_down");

        let denied = svc
            .create_session(
                provider_id,
                "handler-client".to_string(),
                vec!["openid".to_string()],
                "https://registry.example.com",
            )
            .await
            .expect("create denied session");
        svc.deny_session(&denied.user_code)
            .await
            .expect("deny session");
        let (status, json) =
            poll_json(state.clone(), GRANT, &denied.device_code, "handler-client").await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(json["error"], "access_denied");

        let expired = svc
            .create_session(
                provider_id,
                "handler-client".to_string(),
                vec!["openid".to_string()],
                "https://registry.example.com",
            )
            .await
            .expect("create expired session");
        sqlx::query(
            "UPDATE oidc_device_sessions SET expires_at = now() - interval '1 second' WHERE id = $1",
        )
        .bind(expired.id)
        .execute(&pool)
        .await
        .expect("expire session");
        let (status, json) =
            poll_json(state.clone(), GRANT, &expired.device_code, "handler-client").await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(json["error"], "expired_token");

        let approved = svc
            .create_session(
                provider_id,
                "handler-client".to_string(),
                vec!["openid".to_string()],
                "https://registry.example.com",
            )
            .await
            .expect("create approved session");
        svc.approve_session(
            &approved.user_code,
            user_id,
            "oidc-sub".to_string(),
            "user@example.com".to_string(),
            "Example User".to_string(),
        )
        .await
        .expect("approve session");
        let (status, json) = poll_json(state, GRANT, &approved.device_code, "handler-client").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(json["token_type"], "Bearer");
        // expires_in mirrors the configured access-token TTL
        // (JWT_ACCESS_TOKEN_EXPIRY_MINUTES), not a hardcoded constant.
        assert_eq!(json["expires_in"], expected_expiry_secs);
        assert!(json["access_token"].as_str().unwrap().len() > 20);
        assert!(json["refresh_token"].as_str().unwrap().len() > 20);

        cleanup_provider(&pool, provider_id).await;
        cleanup_user(&pool, user_id).await;
    }

    #[tokio::test]
    async fn oidc_device_approve_handler_marks_session_for_authenticated_user() {
        let Some(pool) = crate::api::handlers::test_db_helpers::try_pool().await else {
            return;
        };
        let state = state(pool.clone(), "approve-handler");
        let provider_id = seed_oidc_provider(&pool, true).await;
        let user_id = seed_user(&pool).await;
        let svc = OidcDeviceService::new(pool.clone());
        let session = svc
            .create_session(
                provider_id,
                "approve-client".to_string(),
                vec!["openid".to_string()],
                "https://registry.example.com",
            )
            .await
            .expect("create session");
        let auth = crate::api::handlers::test_db_helpers::make_auth(user_id, "device-user");

        let response = approve_session_handler(
            State(state),
            axum::extract::Extension(auth),
            Json(ApproveDeviceRequest {
                user_code: session.user_code.clone(),
            }),
        )
        .await
        .expect("approve handler")
        .into_response();
        let (status, json) = response_json(response).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(json["ok"], true);

        let row: (String, Option<Uuid>) = sqlx::query_as(
            "SELECT status, approved_user_id FROM oidc_device_sessions WHERE id = $1",
        )
        .bind(session.id)
        .fetch_one(&pool)
        .await
        .expect("load approved session");
        assert_eq!(row.0, "approved");
        assert_eq!(row.1, Some(user_id));

        cleanup_provider(&pool, provider_id).await;
        cleanup_user(&pool, user_id).await;
    }

    #[tokio::test]
    async fn oidc_device_public_router_rejects_bad_form_grant() {
        let Some(pool) = crate::api::handlers::test_db_helpers::try_pool().await else {
            return;
        };
        let app = public_router().with_state(state(pool, "public-router"));
        let request = Request::builder()
            .method("POST")
            .uri("/token")
            .header("content-type", "application/x-www-form-urlencoded")
            .body(Body::from(
                "grant_type=not-device&device_code=abc&client_id=handler-client",
            ))
            .expect("request");
        let response = tower::ServiceExt::oneshot(app, request)
            .await
            .expect("oneshot");
        let (status, json) = response_json(response).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(json["error"], "unsupported_grant_type");
    }
}
