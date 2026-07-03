//! Authentication handlers.

use std::sync::Arc;

use axum::http::header::{COOKIE, SET_COOKIE};
use axum::http::HeaderMap;
use axum::{
    extract::{Extension, State},
    response::{IntoResponse, Response},
    routing::{delete, get, post},
    Router,
};
// Custom Json extractor: maps malformed/missing-field request bodies to
// 400 VALIDATION_ERROR (structured envelope) instead of Axum's stock 422
// + plain-text body. Drop-in for both request extraction and responses
// (#1783 LOW: POST /auth/login returned 422 for missing `username`).
use crate::api::extractors::Json;
use serde::{Deserialize, Serialize};
use utoipa::{OpenApi, ToSchema};
use uuid::Uuid;

use crate::api::middleware::auth::AuthExtension;
use crate::api::SharedState;
use crate::error::{AppError, Result};
use crate::services::audit_service::{AuditAction, AuditEntry, AuditService, ResourceType};
use crate::services::auth_config_service::AuthConfigService;
use crate::services::auth_service::AuthService;
use std::sync::atomic::Ordering;

/// Fire-and-forget auth audit log. Failures are silently ignored so audit
/// issues never break the auth flow.
async fn audit_auth(
    state: &SharedState,
    action: AuditAction,
    user_id: Option<Uuid>,
    details: serde_json::Value,
) {
    let mut entry = AuditEntry::new(action, ResourceType::User).details(details);
    if let Some(id) = user_id {
        entry = entry.user(id).resource(id);
    }
    let _ = AuditService::new(state.db.clone()).log(entry).await;
}

/// Build a login/refresh response with auth cookies set.
fn login_response(
    tokens: &crate::services::auth_service::TokenPair,
    must_change_password: bool,
) -> Response {
    let body = LoginResponse {
        access_token: tokens.access_token.clone(),
        refresh_token: tokens.refresh_token.clone(),
        expires_in: tokens.expires_in,
        token_type: "Bearer".to_string(),
        must_change_password,
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
    response
}

/// Create the login route (no auth required).
///
/// Split out from [`public_router`] so the login path can carry the
/// per-`(username, IP)` `login_rate_limit_middleware` while `/logout` and
/// `/refresh` — which carry no `username` field — keep the unchanged IP-keyed
/// `rate_limit_middleware`.
pub fn login_router() -> Router<SharedState> {
    Router::new().route("/login", post(login))
}

/// Create public auth routes (no auth required).
///
/// `/login` is intentionally NOT included here; it is wired separately via
/// [`login_router`] so only it gets the username-peeking login limiter.
pub fn public_router() -> Router<SharedState> {
    Router::new()
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

/// Outcome of the local-login policy decision in [`local_login_gate`].
#[derive(Debug, PartialEq, Eq)]
enum LocalLoginGate {
    /// Local login may proceed.
    Allow,
    /// Local login is rejected because SSO is enforced for this user.
    RejectSso,
}

/// Decide whether a *verified* local credential may complete login.
///
/// Evaluated AFTER `AuthService::authenticate` succeeds, so `user_is_admin`
/// is a proven property of the caller, not a claim from the request. When any
/// SSO provider is enabled (issue #213) non-admin local login stays disabled,
/// but a verified admin retains a break-glass recovery path by default so a
/// misconfigured SSO provider can be repaired in-band (issue #443). The
/// legacy `ALLOW_LOCAL_ADMIN_LOGIN` flag (`allow_local_admin_login`) is kept
/// as a back-compat input; it only ever applied to the admin account and must
/// never broaden access for non-admin users.
///
/// A deployment that wants strict "SSO-only, no exceptions" enforcement can
/// opt in via `SSO_DISABLE_ADMIN_BREAK_GLASS` (`disable_admin_break_glass`,
/// #2018): when set, even the verified-admin break-glass is rejected while SSO
/// is enabled. The flag defaults to `false`, so the historical break-glass
/// behaviour is unchanged for existing deployments.
fn local_login_gate(
    sso_enabled: bool,
    user_is_admin: bool,
    allow_local_admin_login: bool,
    disable_admin_break_glass: bool,
) -> LocalLoginGate {
    match (
        sso_enabled,
        user_is_admin,
        allow_local_admin_login,
        disable_admin_break_glass,
    ) {
        // No SSO providers enabled: local login is unchanged for everyone.
        (false, _, _, _) => LocalLoginGate::Allow,
        // Opt-in strict SSO-only (#2018): the admin break-glass is disabled,
        // so even a verified admin must use SSO. This is the stricter posture
        // and takes precedence over the legacy allow-local-admin flag.
        (true, true, _, true) => LocalLoginGate::RejectSso,
        // Verified-admin break-glass (default; supersedes the legacy flag,
        // which only ever allowed the admin account).
        (true, true, _, false) => LocalLoginGate::Allow,
        // Non-admins must use SSO; neither flag ever broadens them.
        (true, false, _, _) => LocalLoginGate::RejectSso,
    }
}

/// DB-backed enforcement of the local-login SSO policy for an already-verified
/// user. Returns whether any SSO provider is enabled (so the caller can emit the
/// admin break-glass warning), or an `Authentication` error when the user must
/// use SSO. Split out of the `login` handler so the policy decision — the SSO
/// lookup plus [`local_login_gate`] plus the reject-side audit — is unit-testable
/// against a seeded database without standing up the full login path.
async fn enforce_local_login_sso_policy(
    state: &SharedState,
    user_id: Uuid,
    username: &str,
    user_is_admin: bool,
) -> Result<bool> {
    let sso_enabled = !AuthConfigService::list_enabled_providers(&state.db)
        .await?
        .is_empty();
    match local_login_gate(
        sso_enabled,
        user_is_admin,
        state.config.allow_local_admin_login,
        state.config.sso_disable_admin_break_glass,
    ) {
        LocalLoginGate::Allow => Ok(sso_enabled),
        LocalLoginGate::RejectSso => {
            audit_auth(
                state,
                AuditAction::LoginFailed,
                Some(user_id),
                serde_json::json!({
                    "username": username,
                    "reason": "local_login_disabled_sso",
                }),
            )
            .await;
            Err(AppError::Authentication(
                "Local login is disabled when SSO is configured. Use your organization's SSO provider to sign in.".to_string(),
            ))
        }
    }
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
    // The bcrypt-bound auth-concurrency cap (#991, #1088) is enforced
    // inside `AuthService::verify_password` itself, so every entry point
    // that runs bcrypt (local login, API-token verify, basic-auth
    // fallback, SSO post-auth) shares the same shed boundary. Acquiring
    // a permit here as well would double-count slots and cause spurious
    // 503s under moderate load.
    let auth_service = AuthService::new(state.db.clone(), Arc::new(state.config.clone()));

    let (user, tokens) = match auth_service
        .authenticate(&payload.username, &payload.password)
        .await
    {
        Ok(result) => result,
        Err(err) => {
            audit_auth(
                &state,
                AuditAction::LoginFailed,
                None,
                serde_json::json!({ "username": payload.username }),
            )
            .await;
            return Err(err);
        }
    };

    // Local-login policy when SSO providers are configured (issue #213).
    // Evaluated AFTER authentication so the decision is based on the
    // *verified* `is_admin` flag: admins keep a break-glass recovery path
    // for a misconfigured SSO provider (issue #443), while non-admin local
    // login stays disabled. The DB-backed decision lives in
    // `enforce_local_login_sso_policy` so it can be unit-tested directly.
    let sso_enabled =
        enforce_local_login_sso_policy(&state, user.id, &user.username, user.is_admin).await?;
    if sso_enabled {
        tracing::warn!(
            username = %user.username,
            "Local admin break-glass login while SSO is enabled"
        );
    }

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

    let mut login_details = serde_json::json!({ "username": user.username });
    if sso_enabled {
        // Only verified admins reach this point with SSO enabled; mark the
        // break-glass login so it is visible in the audit trail.
        login_details["sso_break_glass"] = serde_json::json!(true);
    }
    audit_auth(&state, AuditAction::Login, Some(user.id), login_details).await;

    Ok(login_response(&tokens, user.must_change_password))
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
pub async fn logout(
    State(state): State<SharedState>,
    headers: HeaderMap,
    auth: Option<Extension<AuthExtension>>,
    body: Option<Json<RefreshTokenRequest>>,
) -> Result<Response> {
    if let Some(Extension(auth)) = auth {
        // Revoke the refresh-token family for THIS session so the presented
        // refresh token (and its rotation lineage) stop working after logout
        // (#1807). Scoped to the session's family_id rather than a user-wide
        // watermark, so other concurrent sessions stay alive. Browser clients
        // carry the refresh token in the ak_refresh_token cookie; CLI/mobile
        // clients pass it in the request body (like /auth/refresh). A missing
        // or malformed refresh token is ignored: logout still clears cookies
        // and succeeds.
        let refresh = body
            .and_then(|Json(b)| b.refresh_token)
            .or_else(|| extract_cookie(&headers, "ak_refresh_token").map(String::from));
        if let Some(refresh) = refresh {
            let auth_service = AuthService::new(state.db.clone(), Arc::new(state.config.clone()));
            if let Err(err) = auth_service.revoke_refresh_token_family_for(&refresh).await {
                tracing::warn!(
                    user_id = %auth.user_id,
                    error = %err,
                    "logout: failed to revoke refresh-token family",
                );
            }
        }

        audit_auth(
            &state,
            AuditAction::Logout,
            Some(auth.user_id),
            serde_json::json!({}),
        )
        .await;
    }

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

    audit_auth(
        &state,
        AuditAction::Login,
        Some(user.id),
        serde_json::json!({ "method": "token_refresh" }),
    )
    .await;

    Ok(login_response(&tokens, user.must_change_password))
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
    // Refuse admin-class scopes from non-admin callers. The legacy check
    // only blocked the literal "admin" scope, leaving non-admins able to
    // mint `*`, `delete:artifacts`, `delete:repositories`, and
    // `write:users` via this endpoint. See
    // `token_service::ADMIN_ONLY_SCOPES` for the policy list and rationale.
    crate::services::token_service::enforce_admin_only_scopes(&payload.scopes, auth.is_admin)
        .map_err(AppError::Authorization)?;

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

/// Validate and normalize a ticket-bound `resource_path` at mint time.
///
/// The consumer middleware compares `bound_path == request.uri().path()` by
/// byte equality, which means the minter is responsible for picking the exact
/// form the consumer will see. Format handlers normalize incoming paths
/// (PyPI/NuGet/Go lowercase the package-name segment, see
/// `backend/src/formats/pypi.rs` and `backend/src/formats/nuget.rs`), so a
/// minter who passes `/pypi/foo/simple/Django/` would produce a ticket that
/// no real client request can match — and the first attempt would silently
/// burn the ticket.
///
/// Policy enforced here:
///   1. Path must be absolute (starts with `/`).
///   2. No `..` segments (no path traversal).
///   3. No percent-encoded slashes or backslashes (`%2F`, `%2f`, `%5C`, `%5c`)
///      and no `%25` (double-encoding) — these would change semantics after
///      URL-decode and are common bypass vectors.
///   4. No control characters (`\0`..`\x1f`, `\x7f`) or whitespace.
///   5. Collapse repeated `/` to a single `/`.
///   6. Strip a trailing `/` (except for root `/`).
///   7. Lowercase the package-name segment for paths whose first component is
///      a known case-folding format (`/pypi/...`, `/nuget/...`, `/go/...`).
///      The package name lives at the third segment for these formats
///      (`/{format}/{repo_key}/{name}/...`).
///
/// What is NOT enforced here (deliberate):
///   - Authz reach: this function does not verify that the minting user can
///     actually access the requested path. The consumer middleware re-runs
///     `repo_visibility_middleware` / `can_access_repo` at consume time, so a
///     ticket bound to a path the minter cannot reach is harmless. A defense-
///     in-depth check is tracked for v1.2.0 hardening.
fn validate_and_normalize_resource_path(input: &str) -> std::result::Result<String, AppError> {
    if input.is_empty() {
        return Err(AppError::Validation(
            "resource_path must not be empty".into(),
        ));
    }
    if !input.starts_with('/') {
        return Err(AppError::Validation(
            "resource_path must start with '/'".into(),
        ));
    }

    // Reject control chars, whitespace, embedded NUL.
    for b in input.as_bytes() {
        if *b < 0x20 || *b == 0x7f || *b == b' ' {
            return Err(AppError::Validation(
                "resource_path must not contain whitespace or control characters".into(),
            ));
        }
    }

    // Reject percent-encoded slashes / backslashes / percent itself. These
    // forms decode to characters that change path semantics after axum/hyper
    // serve them as raw paths, so allowing them would let a minter bind to
    // `/foo%2F..%2Fbar` and rely on a future decoder normalizing it.
    let lower = input.to_ascii_lowercase();
    for needle in ["%2f", "%5c", "%25", "%00"] {
        if lower.contains(needle) {
            return Err(AppError::Validation(format!(
                "resource_path must not contain encoded sequence '{}'",
                needle
            )));
        }
    }

    // Split, reject `..` and `.` segments, collapse repeated `/`.
    let mut segments: Vec<&str> = Vec::new();
    for seg in input.split('/') {
        if seg.is_empty() {
            // collapses `//` into single `/` and skips leading/trailing empty segs
            continue;
        }
        if seg == ".." {
            return Err(AppError::Validation(
                "resource_path must not contain '..' segments".into(),
            ));
        }
        if seg == "." {
            return Err(AppError::Validation(
                "resource_path must not contain '.' segments".into(),
            ));
        }
        segments.push(seg);
    }

    if segments.is_empty() {
        // input was just `/` or `///` — bind to the root literal `/`.
        return Ok("/".to_string());
    }

    // For known case-folding format prefixes, lowercase the package-name
    // segment so the bound path matches what the format handler will see
    // after its own normalization. We deliberately do NOT lowercase the
    // repository key (segment 1) — repo keys are validated as lowercase
    // already at creation time.
    //
    // Layout: segments[0] = format, segments[1] = repo_key,
    // segments[2..] = format-specific (package name, version, file).
    const CASE_FOLDED_FORMATS: &[&str] = &["pypi", "nuget", "go"];
    if segments.len() >= 3 {
        let format = segments[0].to_ascii_lowercase();
        if CASE_FOLDED_FORMATS.contains(&format.as_str()) {
            // Build owned strings for the segments we need to mutate.
            let mut owned: Vec<String> = segments.iter().map(|s| s.to_string()).collect();
            owned[0] = format;
            // PyPI's PEP-503 normalize is more aggressive than just lowercase
            // (it collapses non-alphanumeric runs to '-'), but applying that
            // here would mask legitimate user intent; the simpler and safer
            // choice is to lowercase only. A client that depends on PEP-503
            // normalization can pre-normalize before minting.
            owned[2] = owned[2].to_ascii_lowercase();
            let normalized = format!("/{}", owned.join("/"));
            return Ok(normalized);
        }
    }

    Ok(format!("/{}", segments.join("/")))
}

/// Create a short-lived, single-use download/stream ticket for the current user.
/// The ticket can be passed as a `?ticket=` query parameter on endpoints that
/// cannot use `Authorization` headers (e.g. `<a>` downloads, `EventSource` SSE).
///
/// Security note: the resulting ticket value will appear in webserver access
/// logs, browser history, and `Referer` headers if it is embedded in a URL.
/// The mitigation is single-use consumption plus a 30-second TTL plus 256-bit
/// entropy. Clients should consume the ticket immediately and never share or
/// log the URL that contains it.
#[utoipa::path(
    post,
    path = "/ticket",
    context_path = "/api/v1/auth",
    tag = "auth",
    security(("bearer_auth" = [])),
    request_body = CreateTicketRequest,
    responses(
        (status = 200, description = "Download ticket created", body = TicketResponse),
        (status = 400, description = "Invalid resource_path", body = super::super::openapi::ErrorResponse),
        (status = 401, description = "Not authenticated", body = super::super::openapi::ErrorResponse),
    )
)]
pub async fn create_download_ticket(
    State(state): State<SharedState>,
    Extension(auth): Extension<AuthExtension>,
    Json(payload): Json<CreateTicketRequest>,
) -> Result<Json<TicketResponse>> {
    // Validate and canonicalize the bound path before storage. See
    // `validate_and_normalize_resource_path` for the full policy.
    let normalized_path = match payload.resource_path.as_deref() {
        Some(p) => Some(validate_and_normalize_resource_path(p)?),
        None => None,
    };

    let ticket = AuthConfigService::create_download_ticket(
        &state.db,
        auth.user_id,
        &payload.purpose,
        normalized_path.as_deref(),
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

#[allow(clippy::disallowed_methods)]
// streaming-invariant: test module exempt — buffering response bodies in test assertions is not an artifact path (#1608)
#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::header::{COOKIE, SET_COOKIE};
    use axum::http::HeaderMap;

    // -----------------------------------------------------------------------
    // local_login_gate — SSO local-login policy (issues #213 / #443)
    //
    // Full decision matrix: with no SSO providers everyone may log in
    // locally; with SSO enabled only a *verified* admin passes (break-glass
    // recovery for a misconfigured provider), and the legacy
    // ALLOW_LOCAL_ADMIN_LOGIN flag never broadens access for non-admins.
    // -----------------------------------------------------------------------

    #[test]
    fn test_local_login_gate_no_sso_allows_everyone() {
        // With no SSO, local login is allowed regardless of either flag,
        // including the opt-in strict break-glass toggle (#2018).
        for legacy in [false, true] {
            for strict in [false, true] {
                assert_eq!(
                    local_login_gate(false, true, legacy, strict),
                    LocalLoginGate::Allow
                );
                assert_eq!(
                    local_login_gate(false, false, legacy, strict),
                    LocalLoginGate::Allow
                );
            }
        }
    }

    #[test]
    fn test_local_login_gate_sso_admin_break_glass_allowed() {
        // Default (break-glass on): verified admin retains a recovery path,
        // with or without the legacy flag.
        assert_eq!(
            local_login_gate(true, true, false, false),
            LocalLoginGate::Allow
        );
        assert_eq!(
            local_login_gate(true, true, true, false),
            LocalLoginGate::Allow
        );
    }

    #[test]
    fn test_local_login_gate_sso_non_admin_rejected() {
        assert_eq!(
            local_login_gate(true, false, false, false),
            LocalLoginGate::RejectSso
        );
    }

    #[test]
    fn test_local_login_gate_legacy_flag_never_broadens_non_admins() {
        // Neither the legacy allow-local-admin flag nor the strict toggle
        // ever grants a non-admin a local login under SSO.
        for strict in [false, true] {
            assert_eq!(
                local_login_gate(true, false, true, strict),
                LocalLoginGate::RejectSso
            );
        }
    }

    #[test]
    fn test_local_login_gate_strict_disables_admin_break_glass() {
        // #2018 opt-in hardening: with SSO_DISABLE_ADMIN_BREAK_GLASS set, even
        // a verified admin is rejected while SSO is enabled. The strict toggle
        // takes precedence over the legacy allow-local-admin flag.
        assert_eq!(
            local_login_gate(true, true, false, true),
            LocalLoginGate::RejectSso
        );
        assert_eq!(
            local_login_gate(true, true, true, true),
            LocalLoginGate::RejectSso
        );
    }

    /// DB-backed: exercises the full SSO policy enforcement that the `login`
    /// handler delegates to — the enabled-provider lookup, the gate decision,
    /// and the reject-side audit — without standing up the bcrypt/authenticate
    /// path. Skips cleanly when no DATABASE_URL is configured (try_pool).
    #[tokio::test]
    async fn test_enforce_local_login_sso_policy_db() {
        use crate::api::handlers::test_db_helpers as tdh;
        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let dir = std::env::temp_dir().join(format!("ph-sso-{}", Uuid::new_v4()));
        let state = tdh::build_state(pool.clone(), dir.to_string_lossy().as_ref());
        let uid = Uuid::new_v4();
        let provider = format!("ph-test-ldap-{uid}");

        // No SSO providers enabled: local login is allowed for everyone and the
        // returned sso_enabled flag is false (no break-glass warning).
        let none = enforce_local_login_sso_policy(&state, uid, "alice", false).await;
        assert!(!none.expect("no-SSO non-admin must be allowed"));

        // Enable one LDAP provider. list_enabled_providers only reads id+name,
        // so the remaining columns can take their schema defaults.
        sqlx::query(
            "INSERT INTO ldap_configs (name, server_url, user_base_dn, is_enabled) \
             VALUES ($1, 'ldap://test.invalid', 'dc=test', true)",
        )
        .bind(&provider)
        .execute(&pool)
        .await
        .expect("seed enabled LDAP provider");

        // SSO enabled + non-admin -> rejected with the SSO message (and audited).
        let denied = enforce_local_login_sso_policy(&state, uid, "alice", false).await;
        assert!(
            matches!(denied, Err(AppError::Authentication(_))),
            "non-admin local login must be rejected when SSO is enabled: {denied:?}"
        );

        // SSO enabled + verified admin -> break-glass allowed; sso_enabled=true.
        let allowed = enforce_local_login_sso_policy(&state, uid, "admin", true).await;
        assert!(
            allowed.expect("admin break-glass must be allowed"),
            "admin must keep local login and observe sso_enabled=true"
        );

        let _ = sqlx::query("DELETE FROM ldap_configs WHERE name = $1")
            .bind(&provider)
            .execute(&pool)
            .await;
    }

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

    /// Regression (#1783 LOW): POST /auth/login with a missing required field
    /// must surface as HTTP 400 + `{"code":"VALIDATION_ERROR"}`, not Axum's
    /// stock 422 + plain-text body. The login handler now extracts via the
    /// custom `crate::api::extractors::Json`; this exercises that exact path
    /// for the `LoginRequest` shape (missing `username`).
    #[tokio::test]
    async fn test_login_missing_username_returns_400_validation_error() {
        use axum::body::Body;
        use axum::extract::FromRequest;
        use axum::http::{header, Request, StatusCode};
        use axum::response::IntoResponse;

        let req = Request::builder()
            .method("POST")
            .uri("/api/v1/auth/login")
            .header(header::CONTENT_TYPE, "application/json")
            // Value is irrelevant — this test only checks that a MISSING
            // `username` is rejected. Kept low-entropy so secret scanners
            // (GitGuardian) don't flag it as a credential.
            .body(Body::from(r#"{"password": "placeholder"}"#))
            .unwrap();

        // `Json` here is the custom extractor (imported at module top).
        let result = Json::<LoginRequest>::from_request(req, &()).await;
        let err = result.expect_err("missing username must be rejected");
        let response = err.into_response();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);

        let body_bytes = axum::body::to_bytes(response.into_body(), 65_536)
            .await
            .unwrap();
        let body: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
        assert_eq!(body["code"], "VALIDATION_ERROR");
        assert!(body["message"].is_string());
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

    // -----------------------------------------------------------------------
    // validate_and_normalize_resource_path
    // -----------------------------------------------------------------------

    #[test]
    fn test_validate_path_rejects_empty() {
        assert!(validate_and_normalize_resource_path("").is_err());
    }

    #[test]
    fn test_validate_path_rejects_relative() {
        assert!(validate_and_normalize_resource_path("foo/bar").is_err());
        assert!(validate_and_normalize_resource_path("./foo").is_err());
    }

    #[test]
    fn test_validate_path_rejects_traversal() {
        assert!(validate_and_normalize_resource_path("/foo/../bar").is_err());
        assert!(validate_and_normalize_resource_path("/..").is_err());
        assert!(validate_and_normalize_resource_path("/a/b/..").is_err());
    }

    #[test]
    fn test_validate_path_rejects_dot_segments() {
        assert!(validate_and_normalize_resource_path("/a/./b").is_err());
        assert!(validate_and_normalize_resource_path("/.").is_err());
    }

    #[test]
    fn test_validate_path_rejects_encoded_slash() {
        assert!(validate_and_normalize_resource_path("/foo%2Fbar").is_err());
        assert!(validate_and_normalize_resource_path("/foo%2fbar").is_err());
    }

    #[test]
    fn test_validate_path_rejects_encoded_backslash() {
        assert!(validate_and_normalize_resource_path("/foo%5Cbar").is_err());
        assert!(validate_and_normalize_resource_path("/foo%5cbar").is_err());
    }

    #[test]
    fn test_validate_path_rejects_double_encoding() {
        // %25 is encoded `%`, blocking double-encoded sequences like %252F.
        assert!(validate_and_normalize_resource_path("/foo%252Fbar").is_err());
    }

    #[test]
    fn test_validate_path_rejects_null_byte() {
        assert!(validate_and_normalize_resource_path("/foo%00bar").is_err());
        assert!(validate_and_normalize_resource_path("/foo\0bar").is_err());
    }

    #[test]
    fn test_validate_path_rejects_whitespace_and_control() {
        assert!(validate_and_normalize_resource_path("/foo bar").is_err());
        assert!(validate_and_normalize_resource_path("/foo\tbar").is_err());
        assert!(validate_and_normalize_resource_path("/foo\nbar").is_err());
    }

    #[test]
    fn test_validate_path_collapses_repeated_slashes() {
        let got = validate_and_normalize_resource_path("/foo//bar///baz").unwrap();
        assert_eq!(got, "/foo/bar/baz");
    }

    #[test]
    fn test_validate_path_strips_trailing_slash() {
        let got = validate_and_normalize_resource_path("/api/v1/repositories/foo/").unwrap();
        assert_eq!(got, "/api/v1/repositories/foo");
    }

    #[test]
    fn test_validate_path_root_is_preserved() {
        // Bare `/` is unusual but harmless: it normalizes to `/` and the
        // consumer's exact-equality check will require an actual root request.
        let got = validate_and_normalize_resource_path("/").unwrap();
        assert_eq!(got, "/");
    }

    #[test]
    fn test_validate_path_passthrough_simple_case() {
        let got =
            validate_and_normalize_resource_path("/api/v1/repositories/foo/blob.tar.gz").unwrap();
        assert_eq!(got, "/api/v1/repositories/foo/blob.tar.gz");
    }

    #[test]
    fn test_validate_path_lowercases_pypi_package() {
        // PyPI handler lowercases the package name segment, so the bound path
        // must be lowercased at mint time or no client request will match.
        let got = validate_and_normalize_resource_path("/pypi/myrepo/Django/").unwrap();
        assert_eq!(got, "/pypi/myrepo/django");
    }

    #[test]
    fn test_validate_path_lowercases_nuget_package() {
        let got = validate_and_normalize_resource_path("/nuget/myrepo/Newtonsoft.Json/").unwrap();
        assert_eq!(got, "/nuget/myrepo/newtonsoft.json");
    }

    #[test]
    fn test_validate_path_lowercases_go_module() {
        let got =
            validate_and_normalize_resource_path("/go/myrepo/Github.com/Foo/Bar/@v/list").unwrap();
        // segments[2] is lowercased; deeper path retained verbatim.
        assert_eq!(got, "/go/myrepo/github.com/Foo/Bar/@v/list");
    }

    #[test]
    fn test_validate_path_does_not_lowercase_non_case_folding_format() {
        // Maven and npm preserve case (Java packages and scoped npm names).
        let got = validate_and_normalize_resource_path("/maven/myrepo/Com/Acme/Foo").unwrap();
        assert_eq!(got, "/maven/myrepo/Com/Acme/Foo");
    }

    #[test]
    fn test_validate_path_does_not_lowercase_when_too_short() {
        // Without a package-name segment (segments < 3), the lowercase rule
        // does not apply.
        let got = validate_and_normalize_resource_path("/pypi/Mixed-Case-Repo").unwrap();
        // Leaves repo segment alone; pypi-format check needs len >= 3.
        assert_eq!(got, "/pypi/Mixed-Case-Repo");
    }

    #[test]
    fn test_validate_path_does_not_lowercase_repo_key() {
        // Repo keys are validated as lowercase at creation, but a minter
        // could still pass uppercase. We deliberately do NOT lowercase here:
        // the repo key segment is segment 1 and the format-specific rule
        // touches only segment 2 (the package name).
        let got = validate_and_normalize_resource_path("/pypi/MyRepo/Django").unwrap();
        assert_eq!(got, "/pypi/MyRepo/django");
    }
}

// ---------------------------------------------------------------------------
// Admin-only token-scope enforcement tests (auth::create_api_token)
//
// Sibling of `users::admin_scope_policy_tests` and the repo-tokens
// endpoint tests. The same policy must apply to
// `POST /api/v1/auth/tokens`, otherwise any logged-in user can pivot
// here to mint a token with `*` / `admin` / `delete:artifacts` /
// `delete:repositories` / `write:users` and bypass every scope-only
// authorization gate.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod admin_scope_policy_tests {
    use super::*;
    use crate::api::handlers::test_db_helpers as tdh;
    use axum::body::Body;
    use axum::http::{Method, Request, StatusCode};
    use axum::Extension as AxumExtension;
    use serde_json::json;

    /// Build the auth router with a bare `Extension<AuthExtension>` layer
    /// (the shape this handler's extractor expects).
    fn build_app(state: SharedState, auth: AuthExtension) -> axum::Router {
        protected_router()
            .with_state(state)
            .layer(AxumExtension::<AuthExtension>(auth))
    }

    async fn setup() -> Option<(sqlx::PgPool, SharedState, Uuid, String)> {
        let pool = tdh::try_pool().await?;
        let (user_id, username) = tdh::create_user(&pool).await;
        let state = tdh::build_state(pool.clone(), "/tmp");
        Some((pool, state, user_id, username))
    }

    async fn cleanup(pool: &sqlx::PgPool, user_id: Uuid) {
        let _ = sqlx::query("DELETE FROM api_tokens WHERE user_id = $1")
            .bind(user_id)
            .execute(pool)
            .await;
        let _ = sqlx::query("DELETE FROM users WHERE id = $1")
            .bind(user_id)
            .execute(pool)
            .await;
    }

    /// Each ADMIN_ONLY_SCOPES entry submitted alone by a non-admin must
    /// be refused at the handler. Iterates so a future addition to the
    /// policy list is automatically covered.
    #[tokio::test]
    async fn non_admin_cannot_mint_admin_only_scopes_on_auth_tokens_endpoint() {
        let Some((pool, state, user_id, username)) = setup().await else {
            return;
        };
        let auth = tdh::make_auth(user_id, &username); // is_admin: false

        for admin_scope in crate::services::token_service::ADMIN_ONLY_SCOPES {
            let app = build_app(state.clone(), auth.clone());
            let body = json!({
                "name": format!("probe-{}", admin_scope),
                "scopes": [admin_scope],
                "expires_in_days": 30_i64,
            })
            .to_string();
            let req = Request::builder()
                .method(Method::POST)
                .uri("/tokens")
                .header("content-type", "application/json")
                .body(Body::from(body))
                .unwrap();
            let (status, body_bytes) = tdh::send(app, req).await;

            assert_eq!(
                status,
                StatusCode::FORBIDDEN,
                "non-admin minting auth token with admin-class scope {:?} MUST 403; got {} body: {}",
                admin_scope,
                status,
                String::from_utf8_lossy(&body_bytes),
            );
        }

        cleanup(&pool, user_id).await;
    }

    /// A non-admin must not smuggle an admin-only scope through this
    /// endpoint by burying it in a list of otherwise-safe scopes.
    #[tokio::test]
    async fn non_admin_cannot_smuggle_admin_scope_in_a_mixed_list_auth_endpoint() {
        let Some((pool, state, user_id, username)) = setup().await else {
            return;
        };
        let auth = tdh::make_auth(user_id, &username);
        let app = build_app(state, auth);

        let body = json!({
            "name": "smuggle-attempt",
            "scopes": ["read:artifacts", "write:artifacts", "delete:repositories"],
            "expires_in_days": 30_i64,
        })
        .to_string();
        let req = Request::builder()
            .method(Method::POST)
            .uri("/tokens")
            .header("content-type", "application/json")
            .body(Body::from(body))
            .unwrap();
        let (status, _) = tdh::send(app, req).await;

        assert_eq!(
            status,
            StatusCode::FORBIDDEN,
            "non-admin smuggling 'delete:repositories' on /auth/tokens MUST 403"
        );

        cleanup(&pool, user_id).await;
    }

    /// Admin callers retain the ability to grant the entire policy
    /// surface via this endpoint. Pinning this prevents the policy from
    /// accidentally locking out legitimate admin token issuance.
    #[tokio::test]
    async fn admin_can_mint_admin_only_scopes_on_auth_tokens_endpoint() {
        let Some((pool, state, user_id, username)) = setup().await else {
            return;
        };
        let mut auth = tdh::make_auth(user_id, &username);
        auth.is_admin = true;
        let app = build_app(state, auth);

        let body = json!({
            "name": "admin-token",
            "scopes": ["*"],
            "expires_in_days": 30_i64,
        })
        .to_string();
        let req = Request::builder()
            .method(Method::POST)
            .uri("/tokens")
            .header("content-type", "application/json")
            .body(Body::from(body))
            .unwrap();
        let (status, body_bytes) = tdh::send(app, req).await;

        assert_eq!(
            status,
            StatusCode::OK,
            "admin minting a wildcard auth token MUST succeed; got {} body: {}",
            status,
            String::from_utf8_lossy(&body_bytes),
        );

        cleanup(&pool, user_id).await;
    }
}
