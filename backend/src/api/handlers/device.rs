//! Device Authorization Grant (RFC 8628) handlers.
//!
//! Endpoints:
//! - POST /api/v1/auth/device/code  — initiate device flow
//! - POST /api/v1/auth/device/token — poll for access token
//! - POST /api/v1/auth/device/approve — approve a pending device session (authenticated)
//! - GET  /device — browser placeholder page

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{Html, IntoResponse, Response};
use axum::routing::{get, post};
use axum::Router;
use serde::{Deserialize, Serialize};
use utoipa::{OpenApi, ToSchema};

use crate::api::extractors::{Json, RequestBaseUrl};
use crate::api::middleware::auth::AuthExtension;
use crate::api::SharedState;
use crate::error::{AppError, Result};
use crate::services::audit_service::{
    audit_fire_and_forget, AuditAction, AuditEntry, ResourceType,
};
use crate::services::auth_service::AuthService;
use crate::services::device_service::{DevicePollResult, DeviceService};

/// OpenAPI registration for the device authorization surface. The wire
/// contract is RFC 8628 form encoding; endpoint details remain documented in
/// the handler comments because the bounded body extractor accepts both
/// standard form clients and AK JSON clients.
#[derive(OpenApi)]
#[openapi(
    info(title = "Device Authorization", version = "1"),
    paths(create_device_code, poll_device_token, approve_session_handler),
    components(schemas(
        DeviceCodeRequest,
        DeviceCodeForm,
        DeviceCodeResponse,
        DeviceTokenForm,
        TokenResponse,
        OAuthErrorResponse,
        ApproveDeviceRequest
    ))
)]
pub struct DeviceApiDoc;

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

#[derive(Debug, Deserialize, ToSchema)]
pub struct DeviceCodeRequest {
    pub client_id: String,
    #[serde(default)]
    pub scopes: Vec<String>,
}

/// RFC 8628 §3.1 form shape (`application/x-www-form-urlencoded`), as sent
/// by standard OAuth tooling: `client_id` and space-delimited `scope`.
#[derive(Debug, Deserialize, ToSchema)]
pub struct DeviceCodeForm {
    pub client_id: String,
    #[serde(default)]
    pub scope: String,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct DeviceCodeResponse {
    pub device_code: String,
    pub user_code: String,
    pub verification_uri: String,
    pub expires_in: u64,
    pub interval: u64,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct DeviceTokenForm {
    pub grant_type: String,
    pub device_code: String,
    pub client_id: String,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct TokenResponse {
    pub access_token: String,
    pub token_type: String,
    pub expires_in: u64,
    pub refresh_token: String,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct OAuthErrorResponse {
    pub error: String,
    pub error_description: String,
}

#[derive(Debug, Deserialize, ToSchema)]
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
/// Lets the user type the code, verifies the browser session via `GET /api/v1/auth/me`,
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
  var loginUrl = null;

  function refresh() {
    input.value = normalize(input.value);
    btn.disabled = !((authed || loginUrl) && input.value.length === 9);
  }
  input.addEventListener('input', refresh);

  input.value = '';

  function offerSsoLogin() {
    // Not signed in: turn Approve into a sign-in redirect that returns to
    // this exact page (code preserved) after the SSO round-trip.
    fetch('/api/v1/auth/sso/providers', { credentials: 'same-origin' })
      .then(function (r) { return r.ok ? r.json() : []; })
      .then(function (providers) {
        var oidc = (providers || []).filter(function (p) {
          return p.provider_type === 'oidc';
        });
        if (oidc.length > 0) {
          loginUrl = oidc[0].login_url;
          btn.textContent = 'Sign in to approve';
          setMsg('You will be redirected to ' + oidc[0].name +
                 ' to sign in, then brought back here.', '');
          refresh();
        } else {
          setMsg('You are not signed in. Sign in first, then return to this ' +
                 'page (use the link shown by your device).', 'err');
          msg.insertAdjacentHTML('beforeend', ' <a href="/">Sign in</a>');
        }
      })
      .catch(function () {
        setMsg('You are not signed in. Sign in first, then return to this ' +
               'page (use the link shown by your device).', 'err');
        msg.insertAdjacentHTML('beforeend', ' <a href="/">Sign in</a>');
      });
  }

  fetch('/api/v1/auth/me', { credentials: 'same-origin' }).then(function (r) {
    if (r.ok) { authed = true; refresh(); return r.json(); }
    offerSsoLogin();
    return null;
  }).then(function (me) {
    if (me) { setMsg('Signed in as ' + me.username + '.', 'ok'); }
  }).catch(function () { setMsg('Could not verify your session.', 'err'); });

  btn.addEventListener('click', function () {
    if (!authed && loginUrl) {
      window.location.assign(loginUrl);
      return;
    }
    btn.disabled = true;
    setMsg('Approving…');
    fetch('/api/v1/auth/device/approve', {
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

/// POST /api/v1/auth/device/code — initiate device authorization flow.
#[utoipa::path(
    post,
    path = "/api/v1/auth/device/code",
    request_body = DeviceCodeRequest,
    responses(
        (status = 200, body = DeviceCodeResponse),
        (status = 400, body = OAuthErrorResponse)
    ),
    tag = "auth"
)]
pub async fn create_device_code(
    State(state): State<SharedState>,
    base_url: RequestBaseUrl,
    headers: axum::http::HeaderMap,
    body: bytes::Bytes,
) -> Result<impl IntoResponse> {
    // Accept both the AK JSON shape and the RFC 8628 §3.1 form encoding
    // (client_id + space-delimited scope), so standard OAuth tooling
    // (oauth2c, oauthlib, ...) can call this endpoint directly. The `Bytes`
    // extractor is bounded by the router's request body limit, so this
    // cannot buffer unbounded input (.clippy.toml / #1608 policy).
    let is_form = headers
        .get(axum::http::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(|ct| ct.starts_with("application/x-www-form-urlencoded"))
        .unwrap_or(false);
    let req: DeviceCodeRequest = if is_form {
        let form: DeviceCodeForm = serde_urlencoded::from_bytes(&body)
            .map_err(|e| AppError::Validation(format!("Invalid form body: {e}")))?;
        DeviceCodeRequest {
            client_id: form.client_id,
            scopes: form.scope.split_whitespace().map(str::to_string).collect(),
        }
    } else {
        serde_json::from_slice(&body)
            .map_err(|e| AppError::Validation(format!("Invalid JSON body: {e}")))?
    };

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

    let svc = DeviceService::new(state.db.clone());
    let session = svc
        .create_session(req.client_id, req.scopes, base_url.as_str())
        .await?;

    Ok((
        StatusCode::OK,
        axum::Json(DeviceCodeResponse {
            device_code: session.device_code,
            user_code: session.user_code,
            verification_uri: session.verification_uri,
            expires_in: 600,
            interval: session.interval_secs as u64,
        }),
    ))
}

/// POST /api/v1/auth/device/token — poll for tokens (RFC 8628 §3.4).
///
/// Uses `application/x-www-form-urlencoded` body per the RFC.
#[utoipa::path(
    post,
    path = "/api/v1/auth/device/token",
    request_body = DeviceTokenForm,
    responses(
        (status = 200, body = TokenResponse),
        (status = 400, body = OAuthErrorResponse)
    ),
    tag = "auth"
)]
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

    let svc = DeviceService::new(state.db.clone());
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
            let consumed = match svc
                .consume_approved(&form.device_code, &form.client_id)
                .await
            {
                Ok(Some(session)) => session,
                Ok(None) => {
                    return (
                        StatusCode::BAD_REQUEST,
                        axum::Json(OAuthErrorResponse {
                            error: "invalid_grant".into(),
                            error_description: "The device code has already been used.".into(),
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
            let tokens = match auth_service.generate_tokens_with_scope(
                &user,
                Some(consumed.scopes),
                consumed.allowed_repo_ids.clone(),
            ) {
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
                    "auth_method": "device_flow",
                    "client_id": form.client_id,
                }));
            tokio::spawn(audit_fire_and_forget(state.db.clone(), entry));

            (
                StatusCode::OK,
                [(axum::http::header::CACHE_CONTROL, "no-store")],
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

/// POST /api/v1/auth/device/approve — approve a pending device session.
///
/// The caller must be authenticated (JWT required). This allows an already
/// logged-in user to approve a device session identified by `user_code`.
#[utoipa::path(
    post,
    path = "/api/v1/auth/device/approve",
    request_body = ApproveDeviceRequest,
    responses(
        (status = 200),
        (status = 400, body = OAuthErrorResponse),
        (status = 401)
    ),
    security(("bearer_auth" = [])),
    tag = "auth"
)]
pub async fn approve_session_handler(
    State(state): State<SharedState>,
    axum::extract::Extension(auth): axum::extract::Extension<AuthExtension>,
    Json(req): Json<ApproveDeviceRequest>,
) -> Result<impl IntoResponse> {
    if auth.is_api_token || auth.is_service_account {
        return Err(AppError::Authorization(
            "Only interactive users may approve device authorizations".into(),
        ));
    }
    let ceiling = ALLOWED_SCOPES
        .iter()
        .filter(|scope| auth.has_scope(scope))
        .map(|scope| (*scope).to_string())
        .collect();
    let svc = DeviceService::new(state.db.clone());
    let allowed_repo_ids = auth
        .access_scope()
        .as_allowed_repo_ids()
        .map(|ids| ids.to_vec());
    svc.approve_session(&req.user_code, auth.user_id, allowed_repo_ids, ceiling)
        .await?;
    Ok((StatusCode::OK, axum::Json(serde_json::json!({"ok": true}))))
}
