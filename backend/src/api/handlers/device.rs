//! Device Authorization Grant (RFC 8628) handlers (#3461).
//!
//! A plain Artifact Keeper device grant: the approving user signs in however
//! AK already accepts, and the client receives AK-native tokens. It is not an
//! OpenID Connect flow (AK publishes no OIDC discovery document and issues no
//! `id_token`), so `openid`/`profile`/`email` are not valid scopes here.
//!
//! Endpoints (all answer 404 unless `DEVICE_AUTH_ENABLED=true`):
//! - `POST /api/v1/auth/device/code`    client starts a flow (public, §3.1)
//! - `POST /api/v1/auth/device/token`   client polls and redeems (public, §3.4)
//! - `POST /api/v1/auth/device/verify`  signed-in user looks up a user code
//! - `POST /api/v1/auth/device/approve` signed-in user approves it
//! - `POST /api/v1/auth/device/deny`    signed-in user denies it
//! - `GET  /device` (+ `/device/app.js`, `/device/app.css`) approval page
//!
//! # Threat model
//!
//! * **Token laundering.** Only an interactive browser/CLI *session* JWT may
//!   verify, approve or deny. API tokens, service accounts, download tickets,
//!   Basic credentials, and JWTs that carry a scope ceiling or a repository
//!   restriction (every JWT exchanged from an API token) are refused, so a
//!   restricted or expiring credential cannot mint itself a broader or
//!   longer-lived refresh family. The minted pair is additionally capped at
//!   the intersection of the requested scopes and what the approver may grant
//!   ([`approval_scope_ceiling`]), carries the approver's repository ceiling,
//!   and never includes `*` or `admin`.
//! * **Replay.** A device code is redeemed by one conditional
//!   `UPDATE ... RETURNING` and yields tokens exactly once; every later poll
//!   is `invalid_grant` and audited.
//! * **User-code guessing.** Codes are 8 characters from a 20-letter alphabet
//!   (~2^34.6), live `DEVICE_AUTH_CODE_TTL_SECS` (default 10 minutes), and a
//!   guess requires a signed-in session. Wrong codes are charged against a
//!   per-user and a per-IP budget ([`DeviceApprovalThrottle`]) that ignores
//!   rate-limit exemptions and the global rate-limit switch.
//! * **Phishing.** There is no `verification_uri_complete` and the page never
//!   pre-fills a code from the URL, so a link cannot carry an approvable code.
//!   The page shows the requested scopes, never the client-chosen `client_id`.
//! * **CSRF / clickjacking.** The approval endpoints are JSON POSTs behind
//!   `auth_middleware`, which enforces the cookie CSRF contract (#3065); the
//!   page sets `frame-ancestors 'none'` and `X-Frame-Options: DENY`.
//! * **Polling abuse.** Polls inside the interval get `slow_down` and raise
//!   the interval by 5 s; both public endpoints sit behind per-IP limiters
//!   that honour `RATE_LIMIT_TRUSTED_PROXY_CIDRS` and answer 429 in the OAuth
//!   error shape.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use axum::extract::{ConnectInfo, Extension, Request, State};
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::Router;
use serde::{Deserialize, Serialize};
use utoipa::{OpenApi, ToSchema};
use uuid::Uuid;

use crate::api::extractors::{Json, RequestBaseUrl};
use crate::api::middleware::auth::{AuthExtension, DownloadTicketAuth};
use crate::api::middleware::rate_limit::{resolve_client_ip_addr, CidrRange, RateLimiter};
use crate::api::SharedState;
use crate::config::DeviceAuthConfig;
use crate::error::{AppError, Result};
use crate::models::access_scope::AccessScope;
use crate::models::user::User;
use crate::services::audit_service::{
    audit_fire_and_forget, AuditAction, AuditEntry, ResourceType,
};
use crate::services::auth_service::{AuthService, TokenPair};
use crate::services::device_service::{
    normalize_user_code, DeviceService, DeviceSession, PollOutcome,
};
use crate::services::token_service::{
    enforce_admin_only_scopes, scopes_grant_access, ADMIN_ONLY_SCOPES, ALLOWED_SCOPES,
};

/// RFC 8628 §3.4 `grant_type`.
pub const DEVICE_GRANT_TYPE: &str = "urn:ietf:params:oauth:grant-type:device_code";
/// Scope used when the client names none (RFC 6749 §3.3 lets the server pick
/// a default): the least privilege that is still useful to a CLI.
pub const DEFAULT_DEVICE_SCOPE: &str = "read:artifacts";
/// Longest `client_id` accepted. The value is unregistered and client-chosen.
const MAX_CLIENT_ID_LEN: usize = 128;
/// Longest `device_code` worth looking up (ours are 64 hex characters).
const MAX_DEVICE_CODE_LEN: usize = 128;

/// OpenAPI registration for the device authorization surface.
#[derive(OpenApi)]
#[openapi(
    info(title = "Device Authorization", version = "1"),
    paths(
        create_device_code,
        poll_device_token,
        verify_user_code,
        approve_device,
        deny_device
    ),
    components(schemas(
        DeviceCodeRequest,
        DeviceCodeResponse,
        DeviceTokenForm,
        TokenResponse,
        OAuthErrorResponse,
        UserCodeRequest,
        VerifyUserCodeResponse,
        DeviceDecisionResponse
    ))
)]
pub struct DeviceApiDoc;

// ---------------------------------------------------------------------------
// Request / response types
// ---------------------------------------------------------------------------

/// RFC 8628 §3.1 device authorization request. Sent as
/// `application/x-www-form-urlencoded` by standard OAuth clients; a JSON body
/// with the same fields is also accepted.
#[derive(Debug, Default, Deserialize, ToSchema)]
pub struct DeviceCodeRequest {
    /// Client identifier. Unregistered; 1-128 printable ASCII characters.
    pub client_id: String,
    /// Space-delimited AK scopes, e.g. `read:artifacts write:artifacts`.
    /// Defaults to `read:artifacts`. `*` and `admin` are never grantable.
    #[serde(default)]
    pub scope: Option<String>,
    /// JSON-only convenience: scopes as an array instead of `scope`.
    #[serde(default)]
    pub scopes: Option<Vec<String>>,
}

/// RFC 8628 §3.2 device authorization response.
#[derive(Debug, Serialize, ToSchema)]
pub struct DeviceCodeResponse {
    pub device_code: String,
    /// Shown to the user, `XXXX-XXXX`.
    pub user_code: String,
    pub verification_uri: String,
    pub expires_in: u64,
    pub interval: u64,
}

/// RFC 8628 §3.4 device access token request
/// (`application/x-www-form-urlencoded`).
#[derive(Debug, Deserialize, ToSchema)]
pub struct DeviceTokenForm {
    /// Must be `urn:ietf:params:oauth:grant-type:device_code`.
    pub grant_type: String,
    pub device_code: String,
    /// Must equal the `client_id` of the device authorization request.
    pub client_id: String,
}

/// RFC 6749 §5.1 access token response.
#[derive(Debug, Serialize, ToSchema)]
pub struct TokenResponse {
    pub access_token: String,
    pub token_type: String,
    pub expires_in: u64,
    pub refresh_token: String,
    /// Space-delimited scopes actually granted.
    pub scope: String,
}

/// RFC 6749 §5.2 error response, used by both public device endpoints.
#[derive(Debug, Serialize, ToSchema)]
pub struct OAuthErrorResponse {
    pub error: String,
    pub error_description: String,
}

/// A user code typed by the signed-in user. Case and hyphens are ignored.
#[derive(Debug, Deserialize, ToSchema)]
pub struct UserCodeRequest {
    pub user_code: String,
}

/// What the user is about to approve.
#[derive(Debug, Serialize, ToSchema)]
pub struct VerifyUserCodeResponse {
    /// Scopes the device will receive if this user approves: the requested
    /// scopes capped by what the user may grant.
    pub scopes: Vec<String>,
    /// Requested scopes this user cannot grant; they will be dropped.
    pub withheld_scopes: Vec<String>,
    /// Seconds until the code expires.
    pub expires_in: i64,
}

/// Outcome of an approve or deny.
#[derive(Debug, Serialize, ToSchema)]
pub struct DeviceDecisionResponse {
    /// `approved` or `denied`.
    pub status: String,
    /// Scopes granted (empty for a denial).
    pub scopes: Vec<String>,
}

// ---------------------------------------------------------------------------
// Routers and middleware
// ---------------------------------------------------------------------------

/// Signed-in user endpoints, mounted at `/api/v1/auth/device` behind
/// `auth_middleware`. Needs a [`DeviceApprovalThrottle`] extension. The two
/// public endpoints (`/code`, `/token`) are routed in `routes.rs`, each with
/// its own per-IP limiter.
pub fn approval_router() -> Router<SharedState> {
    Router::new()
        .route("/verify", post(verify_user_code))
        .route("/approve", post(approve_device))
        .route("/deny", post(deny_device))
}

/// The browser approval page (the `verification_uri`), served by the backend
/// so the flow works when the separate web frontend is not deployed.
pub fn device_page_router() -> Router<SharedState> {
    Router::new()
        .route("/device", get(device_page))
        .route("/device/app.js", get(device_page_script))
        .route("/device/app.css", get(device_page_style))
}

/// Kill switch: every device route answers 404 unless the grant is enabled.
pub async fn require_device_auth_enabled(
    State(state): State<SharedState>,
    request: Request,
    next: Next,
) -> Response {
    if !state.config.device_auth.enabled {
        return StatusCode::NOT_FOUND.into_response();
    }
    next.run(request).await
}

/// Convert shared rate-limiter rejections into the RFC 6749 §5.2 error shape
/// both public endpoints use, keeping the 429 status and `Retry-After`.
pub async fn oauth_rate_limit_response(request: Request, next: Next) -> Response {
    let response = next.run(request).await;
    if response.status() != StatusCode::TOO_MANY_REQUESTS {
        return response;
    }

    let headers = response.headers().clone();
    let mut oauth_response = oauth_error(
        StatusCode::TOO_MANY_REQUESTS,
        "slow_down",
        "Too many device authorization requests. Retry later.",
    );
    for name in [
        header::RETRY_AFTER,
        header::HeaderName::from_static("x-ratelimit-limit"),
        header::HeaderName::from_static("x-ratelimit-remaining"),
    ] {
        if let Some(value) = headers.get(&name) {
            oauth_response.headers_mut().insert(name, value.clone());
        }
    }
    oauth_response
}

/// Failed-attempt budgets for user-code entry.
///
/// Only *failures* (a malformed, unknown, expired or already-decided code) are
/// charged, so a user approving several devices is never locked out by their
/// own successes. Two independent budgets apply, and exhausting either one
/// refuses further verify/approve/deny calls with 429 until its window rolls:
///
/// * per user: one account cannot keep guessing;
/// * per client IP (resolved through `RATE_LIMIT_TRUSTED_PROXY_CIDRS`): one
///   host cannot multiply its guesses across many accounts.
///
/// This is a security control, not load shedding, so unlike the request
/// limiters it honours neither the rate-limit exemptions nor
/// `RATE_LIMIT_ENABLED=false`. Budgets are per process: N replicas allow up to
/// N times the budget, which the code entropy and lifetime still cover.
#[derive(Clone, Debug)]
pub struct DeviceApprovalThrottle {
    per_user: Arc<RateLimiter>,
    per_ip: Arc<RateLimiter>,
    trusted_proxies: Arc<Vec<CidrRange>>,
}

impl DeviceApprovalThrottle {
    pub fn new(config: &DeviceAuthConfig, trusted_proxies: Arc<Vec<CidrRange>>) -> Self {
        Self {
            per_user: Arc::new(RateLimiter::new(
                config.max_failed_attempts_per_user,
                config.failed_attempt_window_secs,
            )),
            per_ip: Arc::new(RateLimiter::new(
                config.max_failed_attempts_per_ip,
                config.failed_attempt_window_secs,
            )),
            trusted_proxies,
        }
    }

    fn keys(user_id: Uuid, ip: Option<IpAddr>) -> (String, String) {
        let ip = ip.map_or_else(|| "unknown".to_string(), |ip| ip.to_string());
        (format!("device-user:{user_id}"), format!("device-ip:{ip}"))
    }

    /// `Err(retry_after_secs)` when either budget is spent.
    async fn check(&self, user_id: Uuid, ip: Option<IpAddr>) -> std::result::Result<(), u64> {
        let (user_key, ip_key) = Self::keys(user_id, ip);
        self.per_user.peek_rate_limit(&user_key).await?;
        self.per_ip.peek_rate_limit(&ip_key).await?;
        Ok(())
    }

    async fn record_failure(&self, user_id: Uuid, ip: Option<IpAddr>) {
        let (user_key, ip_key) = Self::keys(user_id, ip);
        self.per_user.record_attempt(&user_key).await;
        self.per_ip.record_attempt(&ip_key).await;
    }

    /// Drop expired buckets; called from the periodic limiter sweep.
    pub async fn cleanup_expired(&self) {
        self.per_user.cleanup_expired().await;
        self.per_ip.cleanup_expired().await;
    }
}

// ---------------------------------------------------------------------------
// Approval page
// ---------------------------------------------------------------------------

/// Headers for the approval page and its assets: a CSP tighter than the
/// global one (no inline script or style at all, no form posts, no framing),
/// and no caching or referrer leakage.
fn page_headers(content_type: &'static str) -> [(header::HeaderName, &'static str); 5] {
    [
        (header::CONTENT_TYPE, content_type),
        (
            header::CONTENT_SECURITY_POLICY,
            "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; \
             frame-ancestors 'none'; base-uri 'none'; form-action 'none'",
        ),
        (header::X_FRAME_OPTIONS, "DENY"),
        (header::CACHE_CONTROL, "no-store"),
        (header::REFERRER_POLICY, "no-referrer"),
    ]
}

/// GET /device — the RFC 8628 `verification_uri`.
///
/// The user types the code shown by their device, sees the scopes it asks
/// for, and approves or denies it from their signed-in session. The page never
/// reads a code from its URL.
pub async fn device_page() -> impl IntoResponse {
    (
        page_headers("text/html; charset=utf-8"),
        r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="referrer" content="no-referrer">
<title>Device Activation</title>
<link rel="stylesheet" href="/device/app.css">
</head>
<body>
<main class="card">
  <h1>Device Activation</h1>
  <p id="who" class="msg"></p>
  <section id="enter">
    <p>Enter the code shown by the app or device you are signing in to.
       Only enter a code from a device you started yourself; never one someone
       sent you.</p>
    <label for="code">Code</label>
    <input id="code" placeholder="XXXX-XXXX" maxlength="9" autocomplete="off"
           autocapitalize="characters" spellcheck="false">
    <button id="continue" type="button" disabled>Continue</button>
  </section>
  <section id="confirm" hidden>
    <p>A device is asking to act as you with these permissions:</p>
    <ul id="scopes"></ul>
    <p id="withheld" class="note" hidden></p>
    <p id="expiry" class="note"></p>
    <p>Approve only if you started this sign-in yourself.</p>
    <div class="actions">
      <button id="deny" type="button" class="secondary">Deny</button>
      <button id="approve" type="button">Approve</button>
    </div>
  </section>
  <p id="msg" class="msg" role="status" aria-live="polite"></p>
</main>
<script src="/device/app.js" defer></script>
</body>
</html>"#,
    )
}

/// GET /device/app.css — page styles, served as a file so the page CSP can
/// forbid inline styles.
pub async fn device_page_style() -> impl IntoResponse {
    (
        page_headers("text/css; charset=utf-8"),
        r#"body { font-family: system-ui, sans-serif; display: flex; justify-content: center;
       padding: 8vh 16px 0; background: #f6f8fa; margin: 0; color: #1f2328; }
.card { background: #fff; border: 1px solid #d0d7de; border-radius: 8px;
        padding: 2rem; max-width: 26rem; width: 100%; box-sizing: border-box; }
h1 { font-size: 1.25rem; margin-top: 0; }
label { display: block; font-weight: 600; margin-bottom: .25rem; }
input { font-size: 1.5rem; letter-spacing: .2em; text-align: center; width: 100%;
        box-sizing: border-box; padding: .5rem; border: 1px solid #d0d7de;
        border-radius: 6px; text-transform: uppercase; font-family: monospace; }
button { margin-top: 1rem; width: 100%; padding: .6rem; font-size: 1rem; border: 0;
         border-radius: 6px; background: #1f883d; color: #fff; cursor: pointer; }
button.secondary { background: #eaeef2; color: #1f2328; }
button:disabled { opacity: .5; cursor: default; }
.actions { display: flex; gap: .75rem; }
ul { padding-left: 1.25rem; font-family: monospace; }
.msg { min-height: 1.2em; }
.note { color: #59636e; font-size: .9rem; }
.ok { color: #1a7f37; } .err { color: #cf222e; }
a { color: #0969da; }
"#,
    )
}

/// GET /device/app.js — the page script, served as a same-origin file so it
/// runs under `script-src 'self'`. All server text is inserted with
/// `textContent`, never as HTML.
pub async fn device_page_script() -> impl IntoResponse {
    (
        page_headers("application/javascript; charset=utf-8"),
        r#"(function () {
  'use strict';
  var $ = function (id) { return document.getElementById(id); };
  var input = $('code'), cont = $('continue'), approve = $('approve'), deny = $('deny');
  var msg = $('msg'), who = $('who');
  var authed = false, current = null;

  function setMsg(el, text, cls) { el.textContent = text; el.className = 'msg ' + (cls || ''); }
  function normalize(v) {
    var raw = v.toUpperCase().replace(/[^A-Z]/g, '').slice(0, 8);
    return raw.length > 4 ? raw.slice(0, 4) + '-' + raw.slice(4) : raw;
  }
  function refresh() {
    input.value = normalize(input.value);
    cont.disabled = !(authed && input.value.length === 9);
  }
  function post(path, code) {
    return fetch('/api/v1/auth/device/' + path, {
      method: 'POST',
      credentials: 'same-origin',
      headers: { 'Content-Type': 'application/json', 'X-Requested-With': 'XMLHttpRequest' },
      body: JSON.stringify({ user_code: code })
    }).then(function (r) {
      return r.json().catch(function () { return {}; }).then(function (b) {
        return { ok: r.ok, status: r.status, body: b };
      });
    });
  }
  function failure(res) {
    if (res.status === 429) { return 'Too many incorrect codes. Wait a few minutes and try again.'; }
    if (res.status === 403) { return 'This sign-in cannot approve devices. Sign in to the web UI with your own account.'; }
    if (res.status === 400 || res.status === 404 || res.status === 409) {
      return 'That code is not valid or has expired. Check the code on your device.';
    }
    return 'Something went wrong (' + res.status + '). Try again.';
  }
  function reset(text, cls) {
    current = null;
    $('confirm').hidden = true;
    $('enter').hidden = false;
    approve.disabled = false; deny.disabled = false;
    setMsg(msg, text || '', cls);
    refresh();
  }

  input.value = '';
  input.addEventListener('input', refresh);

  fetch('/api/v1/auth/me', { credentials: 'same-origin' }).then(function (r) {
    if (!r.ok) { return null; }
    return r.json();
  }).then(function (me) {
    if (me && me.username) {
      authed = true;
      setMsg(who, 'Signed in as ' + me.username + '.', 'ok');
      refresh();
    } else {
      setMsg(who, 'You are not signed in. Sign in to Artifact Keeper in this browser, then come back to this page.', 'err');
      var link = document.createElement('a');
      link.href = '/';
      link.textContent = ' Sign in';
      who.appendChild(link);
    }
  }).catch(function () { setMsg(who, 'Could not verify your session.', 'err'); });

  cont.addEventListener('click', function () {
    var code = input.value;
    cont.disabled = true;
    setMsg(msg, 'Checking code…');
    post('verify', code).then(function (res) {
      if (!res.ok) { reset(failure(res), 'err'); return; }
      current = code;
      var list = $('scopes');
      while (list.firstChild) { list.removeChild(list.firstChild); }
      (res.body.scopes || []).forEach(function (s) {
        var li = document.createElement('li'); li.textContent = String(s); list.appendChild(li);
      });
      var withheld = res.body.withheld_scopes || [];
      $('withheld').hidden = withheld.length === 0;
      $('withheld').textContent = withheld.length
        ? 'Also requested, but not granted because your account cannot grant them: ' + withheld.join(', ')
        : '';
      var mins = Math.max(1, Math.round((res.body.expires_in || 0) / 60));
      $('expiry').textContent = 'This code expires in about ' + mins + ' minute(s).';
      $('enter').hidden = true;
      $('confirm').hidden = false;
      setMsg(msg, '');
    }).catch(function () { reset('Could not reach the server.', 'err'); });
  });

  function decide(path, done) {
    if (!current) { return; }
    approve.disabled = true; deny.disabled = true;
    post(path, current).then(function (res) {
      if (!res.ok) { reset(failure(res), 'err'); return; }
      $('confirm').hidden = true;
      current = null;
      setMsg(msg, done, 'ok');
    }).catch(function () { reset('Could not reach the server.', 'err'); });
  }
  approve.addEventListener('click', function () {
    decide('approve', 'Device approved. You can return to your device.');
  });
  deny.addEventListener('click', function () {
    decide('deny', 'Request denied. The device will not be signed in.');
  });
})();
"#,
    )
}

// ---------------------------------------------------------------------------
// Public client endpoints
// ---------------------------------------------------------------------------

/// Build an RFC 6749 §5.2 error response. Token-endpoint responses must not
/// be cached (§5.1), and neither should these.
fn oauth_error(
    status: StatusCode,
    error: &'static str,
    description: impl Into<String>,
) -> Response {
    (
        status,
        [
            (header::CACHE_CONTROL, "no-store"),
            (header::PRAGMA, "no-cache"),
        ],
        axum::Json(OAuthErrorResponse {
            error: error.to_string(),
            error_description: description.into(),
        }),
    )
        .into_response()
}

/// Opaque 500: the cause goes to the log, never to an unauthenticated client.
fn oauth_server_error(context: &'static str, error: &AppError) -> Response {
    tracing::error!(%error, "device authorization: {context}");
    oauth_error(
        StatusCode::INTERNAL_SERVER_ERROR,
        "server_error",
        "The server could not process the request.",
    )
}

fn is_form(headers: &HeaderMap) -> bool {
    headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|ct| ct.starts_with("application/x-www-form-urlencoded"))
}

/// RFC 6749 client identifiers are VSCHAR (%x20-7E).
fn valid_client_id(client_id: &str) -> bool {
    !client_id.trim().is_empty()
        && client_id.len() <= MAX_CLIENT_ID_LEN
        && client_id.bytes().all(|b| (0x20..=0x7e).contains(&b))
}

/// Scopes a device authorization may carry: every AK scope except the
/// wildcard and `admin`, which would make the device an unscoped admin.
fn is_device_grantable(scope: &str) -> bool {
    ALLOWED_SCOPES.contains(&scope) && !matches!(scope, "*" | "admin")
}

/// Parse and validate the requested scopes: deduplicated, order kept,
/// defaulting to [`DEFAULT_DEVICE_SCOPE`], each one device-grantable.
fn requested_scopes(request: &DeviceCodeRequest) -> std::result::Result<Vec<String>, String> {
    let raw: Vec<String> = match (&request.scope, &request.scopes) {
        (Some(scope), _) => scope.split_whitespace().map(str::to_string).collect(),
        (None, Some(list)) => list.clone(),
        (None, None) => Vec::new(),
    };
    let mut scopes: Vec<String> = Vec::new();
    for scope in raw {
        if !is_device_grantable(&scope) {
            return Err(format!(
                "Scope '{}' cannot be requested through the device grant",
                scope.chars().take(64).collect::<String>()
            ));
        }
        if !scopes.contains(&scope) {
            scopes.push(scope);
        }
    }
    if scopes.is_empty() {
        scopes.push(DEFAULT_DEVICE_SCOPE.to_string());
    }
    Ok(scopes)
}

fn client_ip(
    headers: &HeaderMap,
    connect: Option<&ConnectInfo<SocketAddr>>,
    trusted_proxies: &[CidrRange],
) -> Option<IpAddr> {
    resolve_client_ip_addr(headers, connect.map(|c| c.0.ip()), trusted_proxies)
}

/// POST /api/v1/auth/device/code — start a device authorization (RFC 8628 §3.1).
#[utoipa::path(
    post,
    path = "/api/v1/auth/device/code",
    request_body(content = DeviceCodeRequest, content_type = "application/x-www-form-urlencoded"),
    responses(
        (status = 200, body = DeviceCodeResponse),
        (status = 400, description = "invalid_request or invalid_scope", body = OAuthErrorResponse),
        (status = 404, description = "Device authorization is disabled"),
        (status = 429, description = "slow_down: per-IP limit reached", body = OAuthErrorResponse),
        (status = 503, description = "temporarily_unavailable", body = OAuthErrorResponse)
    ),
    tag = "auth"
)]
pub async fn create_device_code(
    State(state): State<SharedState>,
    base_url: RequestBaseUrl,
    connect: Option<ConnectInfo<SocketAddr>>,
    headers: HeaderMap,
    body: bytes::Bytes,
) -> Response {
    // The bounded `Bytes` extractor (router body limit) accepts both the RFC
    // form encoding and JSON without buffering unbounded input (#1608).
    let parsed: std::result::Result<DeviceCodeRequest, String> = if is_form(&headers) {
        serde_urlencoded::from_bytes(&body).map_err(|e| e.to_string())
    } else {
        serde_json::from_slice(&body).map_err(|e| e.to_string())
    };
    let request = match parsed {
        Ok(request) => request,
        Err(error) => {
            return oauth_error(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                format!("Malformed request body: {error}"),
            )
        }
    };
    if !valid_client_id(&request.client_id) {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "client_id must be 1-128 printable ASCII characters",
        );
    }
    let scopes = match requested_scopes(&request) {
        Ok(scopes) => scopes,
        Err(message) => return oauth_error(StatusCode::BAD_REQUEST, "invalid_scope", message),
    };

    let config = &state.config.device_auth;
    let created = match DeviceService::new(state.db.clone())
        .create_session(
            &request.client_id,
            &scopes,
            config.code_ttl_secs,
            config.poll_interval_secs,
        )
        .await
    {
        Ok(created) => created,
        Err(AppError::ServiceUnavailable(message)) => {
            return oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "temporarily_unavailable",
                message,
            )
        }
        Err(error) => return oauth_server_error("create device session", &error),
    };

    let mut entry = AuditEntry::new(AuditAction::DeviceCodeIssued, ResourceType::User).details(
        serde_json::json!({
            "auth_method": "device_flow",
            "session_id": created.session.id,
            "client_id": request.client_id,
            "scopes": scopes,
        }),
    );
    if let Some(ip) = client_ip(
        &headers,
        connect.as_ref(),
        &state.config.rate_limit_trusted_proxy_cidrs,
    ) {
        entry = entry.ip(ip);
    }
    audit_fire_and_forget(state.db.clone(), entry).await;

    (
        StatusCode::OK,
        [
            (header::CACHE_CONTROL, "no-store"),
            (header::PRAGMA, "no-cache"),
        ],
        axum::Json(DeviceCodeResponse {
            device_code: created.device_code,
            user_code: created.user_code,
            verification_uri: format!("{}/device", base_url.as_str().trim_end_matches('/')),
            expires_in: u64::from(config.code_ttl_secs),
            interval: created.session.interval_secs.max(1) as u64,
        }),
    )
        .into_response()
}

/// POST /api/v1/auth/device/token — poll for, and redeem, tokens (RFC 8628 §3.4).
///
/// Answers `authorization_pending`, `slow_down`, `access_denied`,
/// `expired_token` or `invalid_grant` (unknown code, wrong `client_id`, or a
/// code that was already redeemed) until the user approves; the first poll
/// after approval receives the tokens and consumes the code.
#[utoipa::path(
    post,
    path = "/api/v1/auth/device/token",
    request_body(content = DeviceTokenForm, content_type = "application/x-www-form-urlencoded"),
    responses(
        (status = 200, body = TokenResponse),
        (status = 400, description = "RFC 8628 §3.5 / RFC 6749 §5.2 error", body = OAuthErrorResponse),
        (status = 404, description = "Device authorization is disabled"),
        (status = 429, description = "slow_down: per-IP limit reached", body = OAuthErrorResponse)
    ),
    tag = "auth"
)]
pub async fn poll_device_token(
    State(state): State<SharedState>,
    connect: Option<ConnectInfo<SocketAddr>>,
    headers: HeaderMap,
    body: bytes::Bytes,
) -> Response {
    let form: DeviceTokenForm = match serde_urlencoded::from_bytes(&body) {
        Ok(form) => form,
        Err(error) => {
            return oauth_error(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                format!("Malformed form body: {error}"),
            )
        }
    };
    if form.grant_type != DEVICE_GRANT_TYPE {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "unsupported_grant_type",
            format!("grant_type must be '{DEVICE_GRANT_TYPE}'"),
        );
    }
    if form.device_code.is_empty()
        || form.device_code.len() > MAX_DEVICE_CODE_LEN
        || !valid_client_id(&form.client_id)
    {
        return invalid_grant();
    }

    let ip = client_ip(
        &headers,
        connect.as_ref(),
        &state.config.rate_limit_trusted_proxy_cidrs,
    );
    let outcome = match DeviceService::new(state.db.clone())
        .poll(&form.device_code, &form.client_id)
        .await
    {
        Ok(outcome) => outcome,
        Err(error) => return oauth_server_error("poll device session", &error),
    };

    match outcome {
        PollOutcome::Pending => oauth_error(
            StatusCode::BAD_REQUEST,
            "authorization_pending",
            "The user has not yet approved the request.",
        ),
        PollOutcome::SlowDown { interval_secs } => oauth_error(
            StatusCode::BAD_REQUEST,
            "slow_down",
            format!("Polling too fast. Wait at least {interval_secs} seconds between requests."),
        ),
        PollOutcome::Denied => oauth_error(
            StatusCode::BAD_REQUEST,
            "access_denied",
            "The user denied the request.",
        ),
        PollOutcome::Expired => oauth_error(
            StatusCode::BAD_REQUEST,
            "expired_token",
            "The device code has expired. Start a new device authorization.",
        ),
        PollOutcome::Invalid => invalid_grant(),
        PollOutcome::Replayed(session) => {
            audit_token_rejected(&state, &session, ip, "replay").await;
            invalid_grant()
        }
        PollOutcome::Redeemed(session) => redeem(&state, session, ip).await,
    }
}

fn invalid_grant() -> Response {
    oauth_error(
        StatusCode::BAD_REQUEST,
        "invalid_grant",
        "The device code is invalid, was issued to another client, or has already been used.",
    )
}

/// Mint tokens for a session this poll just consumed.
///
/// The approver is re-checked: an account disabled, deleted or turned into a
/// service account since approving gets nothing, and an approver who lost
/// admin since approving loses any admin-only scope they granted.
async fn redeem(state: &SharedState, session: DeviceSession, ip: Option<IpAddr>) -> Response {
    let Some(user_id) = session.decided_by_user_id else {
        return oauth_server_error(
            "consumed device session has no approver",
            &AppError::Internal(format!("device session {}", session.id)),
        );
    };
    let user = match sqlx::query_as::<_, User>("SELECT * FROM users WHERE id = $1")
        .bind(user_id)
        .fetch_optional(&state.db)
        .await
    {
        Ok(Some(user)) if user.is_active && !user.is_service_account => user,
        Ok(_) => {
            audit_token_rejected(state, &session, ip, "approver_not_eligible").await;
            return invalid_grant();
        }
        Err(error) => return oauth_server_error("load approver", &AppError::from(error)),
    };

    let granted: Vec<String> = session
        .granted_scopes
        .clone()
        .unwrap_or_default()
        .into_iter()
        .filter(|scope| is_device_grantable(scope))
        .filter(|scope| user.is_admin || !ADMIN_ONLY_SCOPES.contains(&scope.as_str()))
        .collect();
    if granted.is_empty() {
        audit_token_rejected(state, &session, ip, "no_grantable_scope").await;
        return invalid_grant();
    }

    let auth_service = AuthService::new(state.db.clone(), Arc::new(state.config.clone()));
    let tokens = match mint_device_tokens(
        &auth_service,
        &user,
        granted.clone(),
        session.allowed_repo_ids.clone(),
    )
    .await
    {
        Ok(tokens) => tokens,
        Err(error) => return oauth_server_error("mint device tokens", &error),
    };

    let mut entry = AuditEntry::new(AuditAction::Login, ResourceType::User)
        .user(user.id)
        .resource(user.id)
        .details(serde_json::json!({
            "auth_method": "device_flow",
            "session_id": session.id,
            "client_id": session.client_id,
            "scopes": granted,
        }));
    if let Some(ip) = ip {
        entry = entry.ip(ip);
    }
    audit_fire_and_forget(state.db.clone(), entry).await;

    (
        StatusCode::OK,
        [
            (header::CACHE_CONTROL, "no-store"),
            (header::PRAGMA, "no-cache"),
        ],
        axum::Json(TokenResponse {
            access_token: tokens.access_token,
            token_type: "Bearer".into(),
            expires_in: tokens.expires_in,
            refresh_token: tokens.refresh_token,
            scope: granted.join(" "),
        }),
    )
        .into_response()
}

/// Mint the pair through the scoped minter and register the refresh `jti`,
/// so the family takes part in rotation, replay detection and logout
/// revocation like any other session (#1819).
async fn mint_device_tokens(
    auth_service: &AuthService,
    user: &User,
    scopes: Vec<String>,
    allowed_repo_ids: Option<Vec<Uuid>>,
) -> Result<TokenPair> {
    let tokens = auth_service.generate_tokens_with_scope(user, Some(scopes), allowed_repo_ids)?;
    auth_service
        .persist_refresh_jti_from_pair(&tokens, user.id)
        .await?;
    Ok(tokens)
}

async fn audit_token_rejected(
    state: &SharedState,
    session: &DeviceSession,
    ip: Option<IpAddr>,
    reason: &'static str,
) {
    let mut entry = AuditEntry::new(AuditAction::DeviceTokenRejected, ResourceType::User).details(
        serde_json::json!({
            "auth_method": "device_flow",
            "session_id": session.id,
            "client_id": session.client_id,
            "reason": reason,
        }),
    );
    if let Some(user_id) = session.decided_by_user_id {
        entry = entry.user(user_id).resource(user_id);
    }
    if let Some(ip) = ip {
        entry = entry.ip(ip);
    }
    audit_fire_and_forget(state.db.clone(), entry).await;
}

// ---------------------------------------------------------------------------
// Signed-in user endpoints
// ---------------------------------------------------------------------------

/// Why a principal may not verify, approve or deny, or `None` if it may.
///
/// Only an interactive session JWT qualifies. Everything else is either a
/// machine credential or a credential whose reach is deliberately narrower
/// or shorter-lived than a session, and letting it approve would let it mint
/// a fresh, refreshable session family: the laundering #2430 and #3460
/// closed for the other credential exchanges.
fn refusal_reason(auth: &AuthExtension, via_download_ticket: bool) -> Option<&'static str> {
    if auth.is_api_token {
        Some("api_token")
    } else if auth.is_service_account {
        Some("service_account")
    } else if via_download_ticket {
        Some("download_ticket")
    } else if auth.iat_ms.is_none() {
        // Not a JWT: Basic username/password and similar.
        Some("not_a_session")
    } else if auth.scopes.is_some() {
        // Session JWTs carry no scope ceiling; exchanged ones (#2430) and
        // device-issued ones do.
        Some("scoped_credential")
    } else if !matches!(auth.allowed_repo_ids, AccessScope::Admin) {
        Some("repository_restricted_credential")
    } else {
        None
    }
}

/// Scopes `auth` may grant a device, in [`ALLOWED_SCOPES`] order.
///
/// min(approver, device-grantable): never `*`/`admin`; admin-only scopes only
/// for an effective admin; and, should a scoped credential ever reach here,
/// only what its own ceiling covers.
pub(crate) fn approval_scope_ceiling(auth: &AuthExtension, approver_is_admin: bool) -> Vec<String> {
    ALLOWED_SCOPES
        .iter()
        .filter(|scope| is_device_grantable(scope))
        .filter(|scope| approver_is_admin || !ADMIN_ONLY_SCOPES.contains(scope))
        .filter(|scope| {
            auth.scopes
                .as_ref()
                .is_none_or(|held| scopes_grant_access(held, scope))
        })
        .map(|scope| (*scope).to_string())
        .collect()
}

/// Split requested scopes into (granted, withheld) against a ceiling,
/// preserving the requested order.
fn cap_scopes(requested: &[String], ceiling: &[String]) -> (Vec<String>, Vec<String>) {
    requested
        .iter()
        .cloned()
        .partition(|scope| ceiling.contains(scope))
}

/// Which approval endpoint is running, for the audit trail.
#[derive(Clone, Copy)]
enum Step {
    Verify,
    Approve,
    Deny,
}

impl Step {
    fn as_str(self) -> &'static str {
        match self {
            Step::Verify => "verify",
            Step::Approve => "approve",
            Step::Deny => "deny",
        }
    }
}

/// Context shared by the three signed-in endpoints once the caller passed
/// the principal and throttle checks.
struct Approver {
    user: User,
    ip: Option<IpAddr>,
    /// Canonical user code, or `None` if the input could not be one.
    user_code: Option<String>,
}

async fn audit_approval(
    state: &SharedState,
    action: AuditAction,
    user_id: Uuid,
    ip: Option<IpAddr>,
    details: serde_json::Value,
) {
    let mut entry = AuditEntry::new(action, ResourceType::User)
        .user(user_id)
        .resource(user_id)
        .details(details);
    if let Some(ip) = ip {
        entry = entry.ip(ip);
    }
    audit_fire_and_forget(state.db.clone(), entry).await;
}

fn too_many_attempts(retry_after: u64) -> Response {
    let mut response =
        AppError::Validation("Too many incorrect device codes. Wait before trying again.".into())
            .into_response();
    *response.status_mut() = StatusCode::TOO_MANY_REQUESTS;
    if let Ok(value) = HeaderValue::from_str(&retry_after.to_string()) {
        response.headers_mut().insert(header::RETRY_AFTER, value);
    }
    response
}

/// Principal gate, then throttle gate, then user-code parsing. Returns the
/// ready [`Approver`] or the response to send.
async fn admit(
    state: &SharedState,
    auth: &AuthExtension,
    via_download_ticket: bool,
    throttle: &DeviceApprovalThrottle,
    ip: Option<IpAddr>,
    step: Step,
    raw_user_code: &str,
) -> std::result::Result<Approver, Response> {
    if let Some(reason) = refusal_reason(auth, via_download_ticket) {
        audit_approval(
            state,
            AuditAction::DeviceAuthorizationFailed,
            auth.user_id,
            ip,
            serde_json::json!({"auth_method": "device_flow", "step": step.as_str(), "reason": reason}),
        )
        .await;
        return Err(AppError::Authorization(
            "Device authorizations can only be verified, approved or denied from an \
             interactive sign-in session"
                .into(),
        )
        .into_response());
    }

    let user = match sqlx::query_as::<_, User>("SELECT * FROM users WHERE id = $1")
        .bind(auth.user_id)
        .fetch_optional(&state.db)
        .await
    {
        Ok(Some(user)) if user.is_active && !user.is_service_account => user,
        Ok(_) => {
            audit_approval(
                state,
                AuditAction::DeviceAuthorizationFailed,
                auth.user_id,
                ip,
                serde_json::json!({"auth_method": "device_flow", "step": step.as_str(), "reason": "account_not_eligible"}),
            )
            .await;
            return Err(AppError::Authorization(
                "This account cannot approve device authorizations".into(),
            )
            .into_response());
        }
        Err(error) => return Err(AppError::from(error).into_response()),
    };

    if let Err(retry_after) = throttle.check(user.id, ip).await {
        audit_approval(
            state,
            AuditAction::DeviceAuthorizationFailed,
            user.id,
            ip,
            serde_json::json!({"auth_method": "device_flow", "step": step.as_str(), "reason": "throttled"}),
        )
        .await;
        return Err(too_many_attempts(retry_after));
    }

    Ok(Approver {
        user,
        ip,
        user_code: normalize_user_code(raw_user_code),
    })
}

/// A wrong, malformed, expired or already-decided user code: charge the
/// failed-attempt budgets, audit, and answer with one indistinguishable 400.
async fn bad_code(
    state: &SharedState,
    throttle: &DeviceApprovalThrottle,
    approver: &Approver,
    step: Step,
) -> Response {
    throttle.record_failure(approver.user.id, approver.ip).await;
    audit_approval(
        state,
        AuditAction::DeviceAuthorizationFailed,
        approver.user.id,
        approver.ip,
        serde_json::json!({"auth_method": "device_flow", "step": step.as_str(), "reason": "invalid_or_expired_code"}),
    )
    .await;
    AppError::Validation("The code is invalid or has expired".into()).into_response()
}

fn approver_is_admin(auth: &AuthExtension, user: &User) -> bool {
    auth.is_admin && user.is_admin
}

/// POST /api/v1/auth/device/verify — look up a user code before deciding.
///
/// Returns the scopes the device would receive if this user approved it.
/// Wrong codes count against the failed-attempt budgets.
#[utoipa::path(
    post,
    path = "/api/v1/auth/device/verify",
    request_body = UserCodeRequest,
    responses(
        (status = 200, body = VerifyUserCodeResponse),
        (status = 400, description = "Invalid or expired code"),
        (status = 401, description = "Not signed in"),
        (status = 403, description = "Not an interactive session, or the account cannot approve"),
        (status = 404, description = "Device authorization is disabled"),
        (status = 429, description = "Too many incorrect codes")
    ),
    security(("bearer_auth" = [])),
    tag = "auth"
)]
pub async fn verify_user_code(
    State(state): State<SharedState>,
    Extension(auth): Extension<AuthExtension>,
    ticket: Option<Extension<DownloadTicketAuth>>,
    Extension(throttle): Extension<DeviceApprovalThrottle>,
    connect: Option<ConnectInfo<SocketAddr>>,
    headers: HeaderMap,
    Json(request): Json<UserCodeRequest>,
) -> Response {
    let step = Step::Verify;
    let ip = client_ip(&headers, connect.as_ref(), &throttle.trusted_proxies);
    let approver = match admit(
        &state,
        &auth,
        ticket.is_some(),
        &throttle,
        ip,
        step,
        &request.user_code,
    )
    .await
    {
        Ok(approver) => approver,
        Err(response) => return response,
    };
    let Some(code) = approver.user_code.as_deref() else {
        return bad_code(&state, &throttle, &approver, step).await;
    };
    let session = match DeviceService::new(state.db.clone())
        .find_pending(code)
        .await
    {
        Ok(Some(session)) => session,
        Ok(None) => return bad_code(&state, &throttle, &approver, step).await,
        Err(error) => return error.into_response(),
    };

    let ceiling = approval_scope_ceiling(&auth, approver_is_admin(&auth, &approver.user));
    let (scopes, withheld_scopes) = cap_scopes(&session.requested_scopes, &ceiling);
    (
        StatusCode::OK,
        [(header::CACHE_CONTROL, "no-store")],
        axum::Json(VerifyUserCodeResponse {
            scopes,
            withheld_scopes,
            expires_in: (session.expires_at - chrono::Utc::now())
                .num_seconds()
                .max(0),
        }),
    )
        .into_response()
}

/// POST /api/v1/auth/device/approve — approve a pending device authorization.
///
/// The device receives the requested scopes capped by what this user may
/// grant, plus this user's repository restriction. Approving is refused (403)
/// when none of the requested scopes can be granted.
#[utoipa::path(
    post,
    path = "/api/v1/auth/device/approve",
    request_body = UserCodeRequest,
    responses(
        (status = 200, body = DeviceDecisionResponse),
        (status = 400, description = "Invalid or expired code"),
        (status = 401, description = "Not signed in"),
        (status = 403, description = "Not an interactive session, the account cannot approve, or no requested scope can be granted"),
        (status = 404, description = "Device authorization is disabled"),
        (status = 409, description = "The request was decided concurrently"),
        (status = 429, description = "Too many incorrect codes")
    ),
    security(("bearer_auth" = [])),
    tag = "auth"
)]
pub async fn approve_device(
    State(state): State<SharedState>,
    Extension(auth): Extension<AuthExtension>,
    ticket: Option<Extension<DownloadTicketAuth>>,
    Extension(throttle): Extension<DeviceApprovalThrottle>,
    connect: Option<ConnectInfo<SocketAddr>>,
    headers: HeaderMap,
    Json(request): Json<UserCodeRequest>,
) -> Response {
    let step = Step::Approve;
    let ip = client_ip(&headers, connect.as_ref(), &throttle.trusted_proxies);
    let approver = match admit(
        &state,
        &auth,
        ticket.is_some(),
        &throttle,
        ip,
        step,
        &request.user_code,
    )
    .await
    {
        Ok(approver) => approver,
        Err(response) => return response,
    };
    let Some(code) = approver.user_code.as_deref() else {
        return bad_code(&state, &throttle, &approver, step).await;
    };
    let service = DeviceService::new(state.db.clone());
    let session = match service.find_pending(code).await {
        Ok(Some(session)) => session,
        Ok(None) => return bad_code(&state, &throttle, &approver, step).await,
        Err(error) => return error.into_response(),
    };

    let is_admin = approver_is_admin(&auth, &approver.user);
    let ceiling = approval_scope_ceiling(&auth, is_admin);
    let (granted, withheld) = cap_scopes(&session.requested_scopes, &ceiling);
    if granted.is_empty() || enforce_admin_only_scopes(&granted, is_admin).is_err() {
        audit_approval(
            &state,
            AuditAction::DeviceAuthorizationFailed,
            approver.user.id,
            ip,
            serde_json::json!({
                "auth_method": "device_flow",
                "step": step.as_str(),
                "reason": "no_grantable_scope",
                "session_id": session.id,
                "withheld_scopes": withheld,
            }),
        )
        .await;
        return AppError::Authorization(
            "Your account cannot grant any of the permissions this device requested".into(),
        )
        .into_response();
    }
    // Defense in depth: refusal_reason already rejected restricted
    // credentials, so this is `None` for every caller that gets here.
    let allowed_repo_ids = match auth.mint_repo_ceiling(false) {
        Ok(ids) => ids,
        Err(error) => return error.into_response(),
    };

    match service
        .approve(
            session.id,
            approver.user.id,
            &granted,
            allowed_repo_ids.as_deref(),
        )
        .await
    {
        Ok(true) => {}
        Ok(false) => {
            return AppError::Conflict("This request was already decided or has expired".into())
                .into_response()
        }
        Err(error) => return error.into_response(),
    }

    audit_approval(
        &state,
        AuditAction::DeviceAuthorizationApproved,
        approver.user.id,
        ip,
        serde_json::json!({
            "auth_method": "device_flow",
            "session_id": session.id,
            "client_id": session.client_id,
            "scopes": granted,
            "withheld_scopes": withheld,
        }),
    )
    .await;
    (
        StatusCode::OK,
        axum::Json(DeviceDecisionResponse {
            status: "approved".into(),
            scopes: granted,
        }),
    )
        .into_response()
}

/// POST /api/v1/auth/device/deny — refuse a pending device authorization.
/// The device's next poll receives `access_denied`.
#[utoipa::path(
    post,
    path = "/api/v1/auth/device/deny",
    request_body = UserCodeRequest,
    responses(
        (status = 200, body = DeviceDecisionResponse),
        (status = 400, description = "Invalid or expired code"),
        (status = 401, description = "Not signed in"),
        (status = 403, description = "Not an interactive session, or the account cannot approve"),
        (status = 404, description = "Device authorization is disabled"),
        (status = 429, description = "Too many incorrect codes")
    ),
    security(("bearer_auth" = [])),
    tag = "auth"
)]
pub async fn deny_device(
    State(state): State<SharedState>,
    Extension(auth): Extension<AuthExtension>,
    ticket: Option<Extension<DownloadTicketAuth>>,
    Extension(throttle): Extension<DeviceApprovalThrottle>,
    connect: Option<ConnectInfo<SocketAddr>>,
    headers: HeaderMap,
    Json(request): Json<UserCodeRequest>,
) -> Response {
    let step = Step::Deny;
    let ip = client_ip(&headers, connect.as_ref(), &throttle.trusted_proxies);
    let approver = match admit(
        &state,
        &auth,
        ticket.is_some(),
        &throttle,
        ip,
        step,
        &request.user_code,
    )
    .await
    {
        Ok(approver) => approver,
        Err(response) => return response,
    };
    let Some(code) = approver.user_code.as_deref() else {
        return bad_code(&state, &throttle, &approver, step).await;
    };
    let session_id = match DeviceService::new(state.db.clone())
        .deny(code, approver.user.id)
        .await
    {
        Ok(Some(id)) => id,
        Ok(None) => return bad_code(&state, &throttle, &approver, step).await,
        Err(error) => return error.into_response(),
    };

    audit_approval(
        &state,
        AuditAction::DeviceAuthorizationDenied,
        approver.user.id,
        ip,
        serde_json::json!({"auth_method": "device_flow", "session_id": session_id}),
    )
    .await;
    (
        StatusCode::OK,
        axum::Json(DeviceDecisionResponse {
            status: "denied".into(),
            scopes: Vec::new(),
        }),
    )
        .into_response()
}

/// Expiry sweep, run from the 60-second limiter cleanup loop: delete expired
/// device sessions and audit approvals that no device ever redeemed.
pub async fn sweep_expired_sessions(db: sqlx::PgPool) {
    match DeviceService::new(db.clone()).cleanup_expired().await {
        Ok((removed, unredeemed)) => {
            if removed > 0 {
                tracing::debug!(removed, "deleted expired device authorizations");
            }
            for approval in unredeemed {
                let mut entry =
                    AuditEntry::new(AuditAction::DeviceAuthorizationExpired, ResourceType::User)
                        .details(serde_json::json!({
                            "auth_method": "device_flow",
                            "session_id": approval.id,
                            "client_id": approval.client_id,
                            "reason": "approved_but_not_redeemed",
                        }))
                        // After `details`: it merges its label into them.
                        .system_actor("system:device_authorization_sweep");
                if let Some(user_id) = approval.decided_by_user_id {
                    entry = entry.resource(user_id);
                }
                audit_fire_and_forget(db.clone(), entry).await;
            }
        }
        Err(error) => tracing::warn!(%error, "failed to clean up expired device sessions"),
    }
}

#[cfg(ak_test_shard = "handlers-1")]
#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::handlers::test_db_helpers::{self as h, try_pool};
    use axum::body::Body;
    use axum::http::Request as HttpRequest;
    use tower::ServiceExt;

    const CLIENT: &str = "ak-cli";

    fn state(pool: sqlx::PgPool, mutate: impl FnOnce(&mut DeviceAuthConfig)) -> SharedState {
        h::build_state_with(pool, "/tmp/ak-device-flow-tests", |config| {
            config.device_auth.enabled = true;
            // Tests poll back-to-back; the interval gets its own test.
            config.device_auth.poll_interval_secs = 1;
            mutate(&mut config.device_auth);
        })
    }

    fn throttle(state: &SharedState) -> DeviceApprovalThrottle {
        DeviceApprovalThrottle::new(&state.config.device_auth, Arc::new(Vec::new()))
    }

    /// The device routes as `routes.rs` mounts them, minus the request-rate
    /// limiters, with `auth` injected the way `auth_middleware` would.
    fn app(
        state: &SharedState,
        auth: Option<AuthExtension>,
        throttle: &DeviceApprovalThrottle,
    ) -> Router {
        let router = Router::new()
            .route("/code", post(create_device_code))
            .route("/token", post(poll_device_token))
            .merge(approval_router().layer(Extension(throttle.clone())))
            .merge(device_page_router())
            .route_layer(axum::middleware::from_fn_with_state(
                state.clone(),
                require_device_auth_enabled,
            ))
            .with_state(state.clone());
        match auth {
            Some(auth) => router
                .layer(Extension(auth.clone()))
                .layer(Extension(Some(auth))),
            None => router,
        }
    }

    /// A browser/CLI session JWT principal: no scope ceiling, unrestricted
    /// repositories, and a JWT `iat`.
    fn session(user_id: Uuid, username: &str) -> AuthExtension {
        AuthExtension {
            iat_ms: Some(chrono::Utc::now().timestamp_millis()),
            ..h::make_auth(user_id, username)
        }
    }

    async fn send(
        app: Router,
        request: HttpRequest<Body>,
    ) -> (StatusCode, HeaderMap, serde_json::Value) {
        let response = app.oneshot(request).await.expect("response");
        let status = response.status();
        let headers = response.headers().clone();
        let body = axum::body::to_bytes(response.into_body(), 1 << 20)
            .await
            .expect("body");
        let json = serde_json::from_slice(&body).unwrap_or(serde_json::Value::Null);
        (status, headers, json)
    }

    fn form(uri: &str, body: &str) -> HttpRequest<Body> {
        HttpRequest::post(uri)
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(Body::from(body.to_string()))
            .unwrap()
    }

    fn json(uri: &str, body: serde_json::Value) -> HttpRequest<Body> {
        HttpRequest::post(uri)
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(body.to_string()))
            .unwrap()
    }

    async fn start(app: Router, scope: &str) -> (String, String) {
        let (status, headers, body) = send(
            app,
            form(
                "/code",
                &format!("client_id={CLIENT}&scope={}", scope.replace(' ', "+")),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(headers.get(header::CACHE_CONTROL).unwrap(), "no-store");
        (
            body["device_code"].as_str().unwrap().to_string(),
            body["user_code"].as_str().unwrap().to_string(),
        )
    }

    fn token_form(device_code: &str) -> HttpRequest<Body> {
        form(
            "/token",
            &format!(
                "grant_type={}&device_code={device_code}&client_id={CLIENT}",
                DEVICE_GRANT_TYPE.replace(':', "%3A")
            ),
        )
    }

    async fn session_status(pool: &sqlx::PgPool, user_code: &str) -> Option<String> {
        let code = normalize_user_code(user_code).expect("valid user code");
        let digest = hex::encode(<sha2::Sha256 as sha2::Digest>::digest(code.as_bytes()));
        sqlx::query_scalar("SELECT status FROM device_sessions WHERE user_code_hash = $1")
            .bind(digest)
            .fetch_optional(pool)
            .await
            .expect("status")
    }

    /// Audit writes are fire-and-forget; wait for the row.
    async fn audit_count(pool: &sqlx::PgPool, action: &str, filter: (&str, String)) -> i64 {
        let sql = match filter.0 {
            "user_id::text" => {
                "SELECT COUNT(*) FROM audit_log WHERE action = $1 AND user_id::text = $2"
            }
            "details->>'session_id'" => {
                "SELECT COUNT(*) FROM audit_log WHERE action = $1 AND details->>'session_id' = $2"
            }
            "details->>'reason'" => {
                "SELECT COUNT(*) FROM audit_log WHERE action = $1 AND details->>'reason' = $2"
            }
            other => panic!("unsupported audit filter {other}"),
        };
        let mut count = 0;
        for _ in 0..60 {
            count = sqlx::query_scalar(sql)
                .bind(action)
                .bind(&filter.1)
                .fetch_one(pool)
                .await
                .expect("count audit rows");
            if count > 0 {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
        count
    }

    async fn cleanup_user(pool: &sqlx::PgPool, user_id: Uuid) {
        sqlx::query("DELETE FROM users WHERE id = $1")
            .bind(user_id)
            .execute(pool)
            .await
            .expect("cleanup user");
    }

    // --- pure policy ------------------------------------------------------

    #[test]
    fn ceiling_never_offers_wildcard_or_admin() {
        let admin = AuthExtension {
            is_admin: true,
            ..Default::default()
        };
        let ceiling = approval_scope_ceiling(&admin, true);
        assert!(!ceiling.iter().any(|s| s == "*" || s == "admin"));
        assert!(ceiling.iter().any(|s| s == "delete:artifacts"));
        assert!(ceiling.iter().any(|s| s == "write:artifacts"));
    }

    #[test]
    fn ceiling_excludes_admin_only_scopes_for_non_admins() {
        let ceiling = approval_scope_ceiling(&AuthExtension::default(), false);
        for scope in &ceiling {
            assert!(!ADMIN_ONLY_SCOPES.contains(&scope.as_str()), "{scope}");
        }
        assert!(ceiling.iter().any(|s| s == "read:artifacts"));
        assert!(ceiling.iter().any(|s| s == "write:artifacts"));
    }

    #[test]
    fn ceiling_is_capped_by_a_scoped_credential() {
        let scoped = AuthExtension {
            scopes: Some(vec!["read:artifacts".into()]),
            ..Default::default()
        };
        assert_eq!(
            approval_scope_ceiling(&scoped, true),
            vec!["read:artifacts".to_string()]
        );
    }

    #[test]
    fn cap_scopes_keeps_request_order() {
        let (granted, withheld) = cap_scopes(
            &[
                "write:artifacts".into(),
                "delete:artifacts".into(),
                "read:artifacts".into(),
            ],
            &["read:artifacts".into(), "write:artifacts".into()],
        );
        assert_eq!(granted, vec!["write:artifacts", "read:artifacts"]);
        assert_eq!(withheld, vec!["delete:artifacts"]);
    }

    #[test]
    fn only_interactive_sessions_may_decide() {
        // `AuthExtension::default()` fails closed (repository scope
        // `Restricted([])`), so spell out an unrestricted session.
        let session = AuthExtension {
            iat_ms: Some(1),
            allowed_repo_ids: AccessScope::Admin,
            ..Default::default()
        };
        assert_eq!(refusal_reason(&session, false), None);
        let cases = [
            (
                AuthExtension {
                    is_api_token: true,
                    scopes: Some(vec!["read:artifacts".into()]),
                    ..session.clone()
                },
                false,
                "api_token",
            ),
            (
                AuthExtension {
                    is_service_account: true,
                    ..session.clone()
                },
                false,
                "service_account",
            ),
            (session.clone(), true, "download_ticket"),
            (
                AuthExtension {
                    iat_ms: None,
                    ..session.clone()
                },
                false,
                "not_a_session",
            ),
            (
                AuthExtension {
                    scopes: Some(vec!["*".into()]),
                    ..session.clone()
                },
                false,
                "scoped_credential",
            ),
            (
                AuthExtension {
                    allowed_repo_ids: AccessScope::Restricted(vec![Uuid::new_v4()]),
                    ..session.clone()
                },
                false,
                "repository_restricted_credential",
            ),
        ];
        for (auth, ticket, expected) in cases {
            assert_eq!(refusal_reason(&auth, ticket), Some(expected));
        }
    }

    #[test]
    fn requested_scopes_default_dedupe_and_refuse_ungrantable() {
        let parse = |scope: Option<&str>, scopes: Option<Vec<&str>>| {
            requested_scopes(&DeviceCodeRequest {
                client_id: CLIENT.into(),
                scope: scope.map(str::to_string),
                scopes: scopes.map(|v| v.into_iter().map(str::to_string).collect()),
            })
        };
        assert_eq!(parse(None, None).unwrap(), vec![DEFAULT_DEVICE_SCOPE]);
        assert_eq!(parse(Some("  "), None).unwrap(), vec![DEFAULT_DEVICE_SCOPE]);
        assert_eq!(
            parse(Some("write:artifacts read:artifacts write:artifacts"), None).unwrap(),
            vec!["write:artifacts", "read:artifacts"]
        );
        assert_eq!(
            parse(None, Some(vec!["read:artifacts"])).unwrap(),
            vec!["read:artifacts"]
        );
        for bad in ["*", "admin", "openid", "profile", "read:everything"] {
            assert!(parse(Some(bad), None).is_err(), "{bad} must be refused");
        }
    }

    #[test]
    fn client_id_must_be_short_printable_ascii() {
        assert!(valid_client_id("ak-cli"));
        assert!(valid_client_id("my client 1.0"));
        assert!(!valid_client_id(""));
        assert!(!valid_client_id("   "));
        assert!(!valid_client_id(&"a".repeat(129)));
        assert!(!valid_client_id("line\nbreak"));
        assert!(!valid_client_id("caf\u{e9}"));
    }

    #[tokio::test]
    async fn oauth_rate_limit_adapter_returns_oauth_envelope() {
        let app = Router::new()
            .route(
                "/",
                get(|| async {
                    (
                        StatusCode::TOO_MANY_REQUESTS,
                        [(header::RETRY_AFTER, "7")],
                        "limited",
                    )
                }),
            )
            .route("/ok", get(|| async { "fine" }))
            .layer(axum::middleware::from_fn(oauth_rate_limit_response));
        let (status, headers, body) = send(
            app.clone(),
            HttpRequest::get("/").body(Body::empty()).unwrap(),
        )
        .await;
        assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(headers.get(header::RETRY_AFTER).unwrap(), "7");
        assert_eq!(body["error"], "slow_down");
        assert!(body["error_description"].is_string());

        let (status, _, _) = send(app, HttpRequest::get("/ok").body(Body::empty()).unwrap()).await;
        assert_eq!(status, StatusCode::OK);
    }

    // --- page -------------------------------------------------------------

    #[tokio::test]
    async fn page_is_unframeable_script_free_and_never_prefills() {
        let state = state(h::lazy_pool(), |_| {});
        let app = app(&state, None, &throttle(&state));
        for path in ["/device", "/device/app.js", "/device/app.css"] {
            let response = app
                .clone()
                .oneshot(HttpRequest::get(path).body(Body::empty()).unwrap())
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK, "{path}");
            let headers = response.headers();
            let csp = headers
                .get(header::CONTENT_SECURITY_POLICY)
                .unwrap()
                .to_str()
                .unwrap();
            assert!(csp.contains("frame-ancestors 'none'"), "{path}: {csp}");
            assert!(csp.contains("script-src 'self'"), "{path}: {csp}");
            assert!(!csp.contains("unsafe-inline"), "{path}: {csp}");
            assert_eq!(headers.get(header::X_FRAME_OPTIONS).unwrap(), "DENY");
            assert_eq!(headers.get(header::CACHE_CONTROL).unwrap(), "no-store");
        }

        let html = device_page().await.into_response();
        let html = axum::body::to_bytes(html.into_body(), 1 << 20)
            .await
            .unwrap();
        let html = String::from_utf8(html.to_vec()).unwrap();
        // No inline script or style for the CSP to have to allow.
        assert!(html.contains(r#"<script src="/device/app.js" defer></script>"#));
        assert_eq!(html.matches("<script").count(), 1);
        assert!(!html.contains("<style"));
        assert!(!html.contains(" style="));

        let js = device_page_script().await.into_response();
        let js = axum::body::to_bytes(js.into_body(), 1 << 20).await.unwrap();
        let js = String::from_utf8(js.to_vec()).unwrap();
        // The code is never taken from the URL, and server text never
        // becomes markup.
        assert!(!js.contains("location"));
        assert!(!js.contains("URLSearchParams"));
        assert!(!js.contains("innerHTML"));
        assert!(!js.contains("insertAdjacentHTML"));
        assert!(js.contains("'X-Requested-With': 'XMLHttpRequest'"));
    }

    #[tokio::test]
    async fn disabled_grant_answers_404_everywhere() {
        let state = h::build_state_with(h::lazy_pool(), "/tmp/ak-device-flow-tests", |_| {});
        assert!(!state.config.device_auth.enabled, "off by default");
        let user_id = Uuid::new_v4();
        let app = app(&state, Some(session(user_id, "u")), &throttle(&state));
        let requests = vec![
            form("/code", "client_id=x"),
            token_form("abc"),
            json("/verify", serde_json::json!({"user_code": "BCDF-GHJK"})),
            json("/approve", serde_json::json!({"user_code": "BCDF-GHJK"})),
            json("/deny", serde_json::json!({"user_code": "BCDF-GHJK"})),
            HttpRequest::get("/device").body(Body::empty()).unwrap(),
            HttpRequest::get("/device/app.js")
                .body(Body::empty())
                .unwrap(),
        ];
        for request in requests {
            let uri = request.uri().clone();
            let (status, _, _) = send(app.clone(), request).await;
            assert_eq!(status, StatusCode::NOT_FOUND, "{uri}");
        }
    }

    // --- /code and /token input handling ------------------------------------

    #[tokio::test]
    async fn code_endpoint_validates_and_answers_in_oauth_shape() {
        let Some(pool) = try_pool().await else {
            return;
        };
        let state = state(pool.clone(), |_| {});
        let app = app(&state, None, &throttle(&state));

        for (body, error) in [
            ("client_id=ak-cli&scope=*", "invalid_scope"),
            ("client_id=ak-cli&scope=admin", "invalid_scope"),
            (
                "client_id=ak-cli&scope=openid+read:artifacts",
                "invalid_scope",
            ),
            ("client_id=&scope=read:artifacts", "invalid_request"),
            ("scope=read:artifacts", "invalid_request"),
        ] {
            let (status, headers, json) = send(app.clone(), form("/code", body)).await;
            assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
            assert_eq!(json["error"], error, "{body}: {json}");
            assert!(json["error_description"].is_string());
            assert_eq!(headers.get(header::CACHE_CONTROL).unwrap(), "no-store");
        }
        let (status, _, body) = send(
            app.clone(),
            HttpRequest::post("/code")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from("{not json"))
                .unwrap(),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body["error"], "invalid_request");

        // JSON with no scope: defaults to read:artifacts. The response is
        // RFC 8628 §3.2 without the optional verification_uri_complete.
        let (status, _, body) = send(
            app.clone(),
            json("/code", serde_json::json!({"client_id": CLIENT})),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert!(body.get("verification_uri_complete").is_none());
        assert_eq!(body["expires_in"], 600);
        assert_eq!(body["interval"], 1);
        assert!(body["verification_uri"]
            .as_str()
            .unwrap()
            .ends_with("/device"));
        let user_code = body["user_code"].as_str().unwrap();
        assert!(normalize_user_code(user_code).is_some(), "{user_code}");
        let requested: Vec<String> = sqlx::query_scalar(
            "SELECT requested_scopes FROM device_sessions WHERE user_code_hash = $1",
        )
        .bind(hex::encode(<sha2::Sha256 as sha2::Digest>::digest(
            normalize_user_code(user_code).unwrap().as_bytes(),
        )))
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(requested, vec![DEFAULT_DEVICE_SCOPE]);
    }

    #[tokio::test]
    async fn token_endpoint_rejects_bad_grants() {
        let Some(pool) = try_pool().await else {
            return;
        };
        let state = state(pool.clone(), |_| {});
        let app = app(&state, None, &throttle(&state));
        let (device_code, _) = start(app.clone(), "read:artifacts").await;

        let (status, _, body) = send(
            app.clone(),
            form(
                "/token",
                &format!("grant_type=password&device_code={device_code}&client_id={CLIENT}"),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body["error"], "unsupported_grant_type");

        let (_, _, body) = send(app.clone(), form("/token", "grant_type=x")).await;
        assert_eq!(body["error"], "invalid_request");

        // Unknown code, and the right code presented by a different client.
        let (_, _, body) = send(app.clone(), token_form(&"f".repeat(64))).await;
        assert_eq!(body["error"], "invalid_grant");
        let (_, _, body) = send(
            app.clone(),
            form(
                "/token",
                &format!(
                    "grant_type={}&device_code={device_code}&client_id=other",
                    DEVICE_GRANT_TYPE.replace(':', "%3A")
                ),
            ),
        )
        .await;
        assert_eq!(body["error"], "invalid_grant");

        let (status, headers, body) = send(app.clone(), token_form(&device_code)).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body["error"], "authorization_pending");
        assert_eq!(headers.get(header::CACHE_CONTROL).unwrap(), "no-store");
    }

    // --- the audit blockers ---------------------------------------------------

    /// Audit blockers 1, 2 and 4: an approved code yields one scoped,
    /// refreshable, replay-tracked pair, and every later poll is refused.
    #[tokio::test]
    async fn approved_code_redeems_once_for_a_scoped_tracked_pair() {
        let Some(pool) = try_pool().await else {
            return;
        };
        let (user_id, username) = h::create_user(&pool).await;
        let state = state(pool.clone(), |_| {});
        let throttle = throttle(&state);
        let (device_code, user_code) = start(
            app(&state, None, &throttle),
            "read:artifacts write:artifacts",
        )
        .await;

        let approver = app(&state, Some(session(user_id, &username)), &throttle);
        let (status, _, body) = send(
            approver.clone(),
            json(
                "/verify",
                serde_json::json!({"user_code": user_code.to_lowercase()}),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(
            body["scopes"],
            serde_json::json!(["read:artifacts", "write:artifacts"])
        );
        assert!(body["expires_in"].as_i64().unwrap() > 500);
        // Verifying decides nothing.
        assert_eq!(
            session_status(&pool, &user_code).await.as_deref(),
            Some("pending")
        );

        let (status, _, body) = send(
            approver,
            json("/approve", serde_json::json!({"user_code": user_code})),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["status"], "approved");

        let (status, headers, body) =
            send(app(&state, None, &throttle), token_form(&device_code)).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(headers.get(header::CACHE_CONTROL).unwrap(), "no-store");
        assert_eq!(body["token_type"], "Bearer");
        assert_eq!(body["scope"], "read:artifacts write:artifacts");
        assert!(body["expires_in"].as_u64().unwrap() > 0);

        let auth_service = AuthService::new(pool.clone(), Arc::new(state.config.clone()));
        let claims = auth_service
            .validate_access_token(body["access_token"].as_str().unwrap())
            .expect("valid access token");
        assert_eq!(claims.sub, user_id);
        assert_eq!(
            claims.scopes,
            Some(vec![
                "read:artifacts".to_string(),
                "write:artifacts".to_string()
            ])
        );
        assert!(!claims.is_admin);

        // Blocker 4: the refresh family is registered, so replay detection
        // and logout revocation see it, and a refresh keeps the ceiling.
        let families: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM refresh_token_jti WHERE user_id = $1")
                .bind(user_id)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(families, 1);
        let (_, refreshed) = auth_service
            .refresh_tokens(body["refresh_token"].as_str().unwrap())
            .await
            .expect("refresh");
        let refreshed = auth_service
            .validate_access_token(&refreshed.access_token)
            .expect("refreshed access token");
        assert_eq!(refreshed.scopes, claims.scopes);

        // Blocker 1: the code is spent. Later polls are invalid_grant and
        // each one is audited as a replay.
        for _ in 0..3 {
            let (status, _, body) =
                send(app(&state, None, &throttle), token_form(&device_code)).await;
            assert_eq!(status, StatusCode::BAD_REQUEST);
            assert_eq!(body["error"], "invalid_grant");
        }
        assert_eq!(
            session_status(&pool, &user_code).await.as_deref(),
            Some("consumed")
        );
        assert!(
            audit_count(
                &pool,
                "DEVICE_TOKEN_REJECTED",
                ("user_id::text", user_id.to_string())
            )
            .await
                >= 1
        );
        assert_eq!(
            audit_count(&pool, "LOGIN", ("user_id::text", user_id.to_string())).await,
            1
        );
        assert_eq!(
            audit_count(
                &pool,
                "DEVICE_AUTHORIZATION_APPROVED",
                ("user_id::text", user_id.to_string())
            )
            .await,
            1
        );

        cleanup_user(&pool, user_id).await;
    }

    /// Audit blocker 3: machine and restricted credentials cannot approve,
    /// deny or even verify; the session stays pending and each refusal is
    /// audited.
    #[tokio::test]
    async fn non_interactive_credentials_cannot_approve() {
        let Some(pool) = try_pool().await else {
            return;
        };
        let (user_id, username) = h::create_user(&pool).await;
        let state = state(pool.clone(), |_| {});
        let throttle = throttle(&state);
        let (device_code, user_code) = start(app(&state, None, &throttle), "read:artifacts").await;

        let base = session(user_id, &username);
        let read_only_api_token = AuthExtension {
            is_api_token: true,
            iat_ms: None,
            scopes: Some(vec!["read:artifacts".into()]),
            ..base.clone()
        };
        let principals = vec![
            read_only_api_token,
            AuthExtension {
                is_service_account: true,
                ..base.clone()
            },
            // A JWT exchanged from an API token (#2430) carries its ceiling.
            AuthExtension {
                scopes: Some(vec!["read:artifacts".into(), "write:artifacts".into()]),
                ..base.clone()
            },
            AuthExtension {
                allowed_repo_ids: AccessScope::Restricted(vec![Uuid::new_v4()]),
                ..base.clone()
            },
            // Basic username/password: not a session JWT.
            AuthExtension {
                iat_ms: None,
                ..base.clone()
            },
        ];
        for principal in principals {
            for path in ["/verify", "/approve", "/deny"] {
                let (status, _, body) = send(
                    app(&state, Some(principal.clone()), &throttle),
                    json(path, serde_json::json!({"user_code": user_code})),
                )
                .await;
                assert_eq!(status, StatusCode::FORBIDDEN, "{path}: {body}");
            }
        }
        // A download ticket rides a real session identity but is refused too.
        let (status, _, _) = send(
            app(&state, Some(base.clone()), &throttle).layer(Extension(DownloadTicketAuth)),
            json("/approve", serde_json::json!({"user_code": user_code})),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);

        assert_eq!(
            session_status(&pool, &user_code).await.as_deref(),
            Some("pending")
        );
        let (_, _, body) = send(app(&state, None, &throttle), token_form(&device_code)).await;
        assert_eq!(body["error"], "authorization_pending");
        assert!(
            audit_count(
                &pool,
                "DEVICE_AUTHORIZATION_FAILED",
                ("details->>'reason'", "api_token".into())
            )
            .await
                >= 1
        );

        // A service account row is refused even behind a session-shaped JWT.
        let (sa_id, sa_name) = h::create_service_account(&pool).await;
        let (status, _, _) = send(
            app(&state, Some(session(sa_id, &sa_name)), &throttle),
            json("/approve", serde_json::json!({"user_code": user_code})),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(
            session_status(&pool, &user_code).await.as_deref(),
            Some("pending")
        );

        cleanup_user(&pool, user_id).await;
        cleanup_user(&pool, sa_id).await;
    }

    /// Audit blocker 2 / spec item 2: the minted scope is at most the
    /// approver's.
    #[tokio::test]
    async fn minted_scope_is_capped_by_the_approver() {
        let Some(pool) = try_pool().await else {
            return;
        };
        let (user_id, username) = h::create_user(&pool).await;
        let state = state(pool.clone(), |_| {});
        let throttle = throttle(&state);
        let approver = app(&state, Some(session(user_id, &username)), &throttle);

        // A non-admin cannot grant delete:artifacts: it is withheld, shown as
        // such, and absent from the token.
        let (device_code, user_code) = start(
            app(&state, None, &throttle),
            "read:artifacts delete:artifacts",
        )
        .await;
        let (_, _, body) = send(
            approver.clone(),
            json("/verify", serde_json::json!({"user_code": user_code})),
        )
        .await;
        assert_eq!(body["scopes"], serde_json::json!(["read:artifacts"]));
        assert_eq!(
            body["withheld_scopes"],
            serde_json::json!(["delete:artifacts"])
        );
        let (status, _, body) = send(
            approver.clone(),
            json("/approve", serde_json::json!({"user_code": user_code})),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["scopes"], serde_json::json!(["read:artifacts"]));
        let (_, _, body) = send(app(&state, None, &throttle), token_form(&device_code)).await;
        assert_eq!(body["scope"], "read:artifacts");
        let claims = AuthService::new(pool.clone(), Arc::new(state.config.clone()))
            .validate_access_token(body["access_token"].as_str().unwrap())
            .unwrap();
        assert_eq!(claims.scopes, Some(vec!["read:artifacts".to_string()]));

        // Nothing grantable at all: approval is refused and stays pending.
        let (_, user_code) =
            start(app(&state, None, &throttle), "delete:artifacts write:users").await;
        let (status, _, _) = send(
            approver.clone(),
            json("/approve", serde_json::json!({"user_code": user_code})),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(
            session_status(&pool, &user_code).await.as_deref(),
            Some("pending")
        );

        // An approver who loses admin between approving and redemption loses
        // the admin-only scopes they granted.
        sqlx::query("UPDATE users SET is_admin = true WHERE id = $1")
            .bind(user_id)
            .execute(&pool)
            .await
            .unwrap();
        let admin = AuthExtension {
            is_admin: true,
            ..session(user_id, &username)
        };
        let (device_code, user_code) = start(
            app(&state, None, &throttle),
            "read:artifacts delete:artifacts",
        )
        .await;
        let (_, _, body) = send(
            app(&state, Some(admin), &throttle),
            json("/approve", serde_json::json!({"user_code": user_code})),
        )
        .await;
        assert_eq!(
            body["scopes"],
            serde_json::json!(["read:artifacts", "delete:artifacts"])
        );
        sqlx::query("UPDATE users SET is_admin = false WHERE id = $1")
            .bind(user_id)
            .execute(&pool)
            .await
            .unwrap();
        let (_, _, body) = send(app(&state, None, &throttle), token_form(&device_code)).await;
        assert_eq!(body["scope"], "read:artifacts", "{body}");

        cleanup_user(&pool, user_id).await;
    }

    /// An approver deactivated after approving gets no tokens.
    #[tokio::test]
    async fn deactivated_approver_gets_no_tokens() {
        let Some(pool) = try_pool().await else {
            return;
        };
        let (user_id, username) = h::create_user(&pool).await;
        let state = state(pool.clone(), |_| {});
        let throttle = throttle(&state);
        let (device_code, user_code) = start(app(&state, None, &throttle), "read:artifacts").await;
        let (status, _, _) = send(
            app(&state, Some(session(user_id, &username)), &throttle),
            json("/approve", serde_json::json!({"user_code": user_code})),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        sqlx::query("UPDATE users SET is_active = false WHERE id = $1")
            .bind(user_id)
            .execute(&pool)
            .await
            .unwrap();
        let (status, _, body) = send(app(&state, None, &throttle), token_form(&device_code)).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body["error"], "invalid_grant");
        assert!(body.get("access_token").is_none());
        assert!(
            audit_count(
                &pool,
                "DEVICE_TOKEN_REJECTED",
                ("details->>'reason'", "approver_not_eligible".into())
            )
            .await
                >= 1
        );

        cleanup_user(&pool, user_id).await;
    }

    #[tokio::test]
    async fn expired_code_is_refused() {
        let Some(pool) = try_pool().await else {
            return;
        };
        let _expiry = h::device_expiry_serial_lock().await;
        let (user_id, username) = h::create_user(&pool).await;
        let state = state(pool.clone(), |_| {});
        let throttle = throttle(&state);
        let (device_code, user_code) = start(app(&state, None, &throttle), "read:artifacts").await;
        let digest = hex::encode(<sha2::Sha256 as sha2::Digest>::digest(
            device_code.as_bytes(),
        ));
        sqlx::query(
            "UPDATE device_sessions SET expires_at = now() - interval '1 second' \
             WHERE device_code_hash = $1",
        )
        .bind(digest)
        .execute(&pool)
        .await
        .unwrap();

        let (status, _, body) = send(app(&state, None, &throttle), token_form(&device_code)).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body["error"], "expired_token");
        let (status, _, _) = send(
            app(&state, Some(session(user_id, &username)), &throttle),
            json("/approve", serde_json::json!({"user_code": user_code})),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);

        cleanup_user(&pool, user_id).await;
    }

    #[tokio::test]
    async fn polling_too_fast_gets_slow_down() {
        let Some(pool) = try_pool().await else {
            return;
        };
        let state = state(pool.clone(), |config| config.poll_interval_secs = 5);
        let throttle = throttle(&state);
        let app = app(&state, None, &throttle);
        let (device_code, _) = start(app.clone(), "read:artifacts").await;

        let (_, _, body) = send(app.clone(), token_form(&device_code)).await;
        assert_eq!(body["error"], "authorization_pending");
        let (status, _, body) = send(app.clone(), token_form(&device_code)).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body["error"], "slow_down");
        assert!(body["error_description"]
            .as_str()
            .unwrap()
            .contains("10 seconds"));
    }

    #[tokio::test]
    async fn denied_code_answers_access_denied() {
        let Some(pool) = try_pool().await else {
            return;
        };
        let (user_id, username) = h::create_user(&pool).await;
        let state = state(pool.clone(), |_| {});
        let throttle = throttle(&state);
        let (device_code, user_code) = start(app(&state, None, &throttle), "read:artifacts").await;
        let approver = app(&state, Some(session(user_id, &username)), &throttle);
        let (status, _, body) = send(
            approver.clone(),
            json("/deny", serde_json::json!({"user_code": user_code})),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["status"], "denied");

        let (_, _, body) = send(app(&state, None, &throttle), token_form(&device_code)).await;
        assert_eq!(body["error"], "access_denied");
        // A denied code can no longer be approved.
        let (status, _, _) = send(
            approver,
            json("/approve", serde_json::json!({"user_code": user_code})),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(
            audit_count(
                &pool,
                "DEVICE_AUTHORIZATION_DENIED",
                ("user_id::text", user_id.to_string())
            )
            .await,
            1
        );

        cleanup_user(&pool, user_id).await;
    }

    /// Audit blocker 5: wrong user codes are throttled per user, then even
    /// the right code is refused until the window rolls; every failure is
    /// audited.
    #[tokio::test]
    async fn wrong_user_codes_are_rate_limited_per_user() {
        let Some(pool) = try_pool().await else {
            return;
        };
        let (user_id, username) = h::create_user(&pool).await;
        let state = state(pool.clone(), |config| {
            config.max_failed_attempts_per_user = 3;
            config.max_failed_attempts_per_ip = 100;
        });
        let throttle = throttle(&state);
        let (_, user_code) = start(app(&state, None, &throttle), "read:artifacts").await;
        let approver = app(&state, Some(session(user_id, &username)), &throttle);

        for guess in ["ZZZZ-ZZZZ", "not a code", "ZZZZ-ZZZX"] {
            let (status, _, _) = send(
                approver.clone(),
                json("/approve", serde_json::json!({"user_code": guess})),
            )
            .await;
            assert_eq!(status, StatusCode::BAD_REQUEST, "{guess}");
        }
        for path in ["/verify", "/approve", "/deny"] {
            let (status, headers, _) = send(
                approver.clone(),
                json(path, serde_json::json!({"user_code": user_code})),
            )
            .await;
            assert_eq!(status, StatusCode::TOO_MANY_REQUESTS, "{path}");
            assert!(headers.get(header::RETRY_AFTER).is_some());
        }
        assert_eq!(
            session_status(&pool, &user_code).await.as_deref(),
            Some("pending")
        );
        let failures: i64 = {
            audit_count(
                &pool,
                "DEVICE_AUTHORIZATION_FAILED",
                ("user_id::text", user_id.to_string()),
            )
            .await;
            // Let the remaining fire-and-forget writes land.
            tokio::time::sleep(std::time::Duration::from_millis(300)).await;
            sqlx::query_scalar(
                "SELECT COUNT(*) FROM audit_log WHERE action = 'DEVICE_AUTHORIZATION_FAILED' \
                 AND user_id = $1",
            )
            .bind(user_id)
            .fetch_one(&pool)
            .await
            .unwrap()
        };
        assert_eq!(failures, 6, "3 wrong codes + 3 throttled attempts");

        // Another user is unaffected by this user's budget.
        let (other_id, other_name) = h::create_user(&pool).await;
        let (status, _, _) = send(
            app(&state, Some(session(other_id, &other_name)), &throttle),
            json("/approve", serde_json::json!({"user_code": user_code})),
        )
        .await;
        assert_eq!(status, StatusCode::OK);

        cleanup_user(&pool, user_id).await;
        cleanup_user(&pool, other_id).await;
    }

    /// The per-IP budget stops one host from spreading guesses over accounts.
    #[tokio::test]
    async fn wrong_user_codes_are_rate_limited_per_ip() {
        let Some(pool) = try_pool().await else {
            return;
        };
        let state = state(pool.clone(), |config| {
            config.max_failed_attempts_per_user = 100;
            config.max_failed_attempts_per_ip = 2;
        });
        let throttle = throttle(&state);
        let mut users = Vec::new();
        for _ in 0..3 {
            users.push(h::create_user(&pool).await);
        }
        let guess = |app: Router| async move {
            let mut request = json("/verify", serde_json::json!({"user_code": "ZZZZ-ZZZZ"}));
            request
                .headers_mut()
                .insert("x-forwarded-for", HeaderValue::from_static("203.0.113.9"));
            send(app, request).await.0
        };
        assert_eq!(
            guess(app(
                &state,
                Some(session(users[0].0, &users[0].1)),
                &throttle
            ))
            .await,
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            guess(app(
                &state,
                Some(session(users[1].0, &users[1].1)),
                &throttle
            ))
            .await,
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            guess(app(
                &state,
                Some(session(users[2].0, &users[2].1)),
                &throttle
            ))
            .await,
            StatusCode::TOO_MANY_REQUESTS
        );
        for (id, _) in users {
            cleanup_user(&pool, id).await;
        }
    }

    #[tokio::test]
    async fn code_issuance_and_unredeemed_expiry_are_audited() {
        let Some(pool) = try_pool().await else {
            return;
        };
        let _expiry = h::device_expiry_serial_lock().await;
        let (user_id, username) = h::create_user(&pool).await;
        let state = state(pool.clone(), |_| {});
        let throttle = throttle(&state);
        let (device_code, user_code) = start(app(&state, None, &throttle), "read:artifacts").await;
        let session_id: Uuid =
            sqlx::query_scalar("SELECT id FROM device_sessions WHERE device_code_hash = $1")
                .bind(hex::encode(<sha2::Sha256 as sha2::Digest>::digest(
                    device_code.as_bytes(),
                )))
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(
            audit_count(
                &pool,
                "DEVICE_CODE_ISSUED",
                ("details->>'session_id'", session_id.to_string())
            )
            .await,
            1
        );
        // Neither code is ever written to the audit trail.
        let leaked: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM audit_log WHERE details::text LIKE $1 OR details::text LIKE $2",
        )
        .bind(format!("%{device_code}%"))
        .bind(format!("%{}%", normalize_user_code(&user_code).unwrap()))
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(leaked, 0);

        let (status, _, _) = send(
            app(&state, Some(session(user_id, &username)), &throttle),
            json("/approve", serde_json::json!({"user_code": user_code})),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        sqlx::query(
            "UPDATE device_sessions SET expires_at = now() - interval '1 second' WHERE id = $1",
        )
        .bind(session_id)
        .execute(&pool)
        .await
        .unwrap();
        sweep_expired_sessions(pool.clone()).await;
        assert_eq!(
            audit_count(
                &pool,
                "DEVICE_AUTHORIZATION_EXPIRED",
                ("details->>'session_id'", session_id.to_string())
            )
            .await,
            1
        );
        let left: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM device_sessions WHERE id = $1")
            .bind(session_id)
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(left, 0);

        cleanup_user(&pool, user_id).await;
    }
}
