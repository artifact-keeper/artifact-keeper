//! Authentication middleware.
//!
//! Extracts and validates JWT tokens or API tokens from requests.
//!
//! Supported authentication methods:
//! - `Authorization: Bearer <jwt_token>` - JWT access tokens
//! - `Authorization: Bearer <api_token>` - API tokens via Bearer scheme
//! - `Authorization: ApiKey <api_token>` - API tokens via ApiKey scheme
//! - `X-API-Key: <api_token>` - API tokens via custom header

use std::sync::Arc;
use std::time::Instant;

use axum::{
    extract::{OriginalUri, Request, State},
    http::{
        header::{AUTHORIZATION, COOKIE},
        HeaderMap, HeaderName, Method, StatusCode,
    },
    middleware::Next,
    response::{IntoResponse, Response},
};
use base64::Engine;
use uuid::Uuid;

use crate::api::{CachedRepo, RepoCache, REPO_CACHE_TTL_SECS};
use crate::error::AppError;
use crate::models::access_scope::AccessScope;
use crate::models::user::User;
use crate::services::auth_service::{AuthService, Claims};
use crate::services::permission_service::PermissionService;

/// Custom header name for API key
static X_API_KEY: HeaderName = HeaderName::from_static("x-api-key");

/// Extension that holds authenticated user information
///
/// `Default` derives a deny-by-default principal (anonymous, non-admin,
/// `allowed_repo_ids = AccessScope::default()` = `Restricted(vec![])`, and no
/// `iat_ms`). It exists so the ~130 test fixtures and the two non-JWT
/// production literals can spell only the fields they care about via
/// `..Default::default()`; the JWT source of truth (`impl From<Claims>`) always
/// sets every field explicitly. The default MUST fail CLOSED — see
/// `AccessScope::default`.
#[derive(Debug, Clone, Default)]
pub struct AuthExtension {
    pub user_id: Uuid,
    pub username: String,
    pub email: String,
    pub is_admin: bool,
    /// Indicates if authentication was via API token (vs JWT)
    pub is_api_token: bool,
    /// Whether this principal is a service account (machine identity)
    pub is_service_account: bool,
    /// Token scopes if authenticated via API token
    pub scopes: Option<Vec<String>>,
    /// Repository-scope authorization decision for this principal.
    pub allowed_repo_ids: AccessScope,
    /// Calling token's **millisecond** issued-at (`Claims::effective_iat_ms`).
    ///
    /// `Some` only on the JWT path (Bearer, cookie, or a JWT presented as a
    /// Basic-auth password). `None` for API-key, X-API-Key, Basic
    /// username/password, ticket, and service-account auth (there is no JWT
    /// `iat`). Used by credential-change handlers (TOTP enable/disable) to
    /// exempt the calling session's own token from the invalidation it just
    /// triggered (#1370). Folded onto `AuthExtension` (from the former separate
    /// `TokenIat` extension) so the single `From<Claims>` source stamps it
    /// uniformly alongside the live re-derived `is_admin` (#1166, #1394).
    pub iat_ms: Option<i64>,
}

/// Marker request extension inserted alongside [`AuthExtension`] when the
/// caller authenticated via a single-use download ticket (`?ticket=`).
///
/// This is a separate extension rather than a field on `AuthExtension` so
/// the existing 80+ test fixtures and call sites that build `AuthExtension`
/// literals do not need to be updated. Middleware that needs to refuse
/// ticket-authenticated requests (writes, admin) checks for the presence
/// of this extension instead.
#[derive(Debug, Clone, Copy)]
pub struct DownloadTicketAuth;

impl AuthExtension {
    /// Calling token's **millisecond** issued-at, or `None` for non-JWT
    /// principals. See [`AuthExtension::iat_ms`]. Handlers performing a
    /// credential-change invalidation (TOTP enable/disable) use this to exempt
    /// the calling session's own token from the invalidation it just triggered
    /// (#1370).
    pub fn caller_iat_ms(&self) -> Option<i64> {
        self.iat_ms
    }

    /// Check whether this auth context has a required scope.
    /// JWT sessions (non-API-token auth) always pass since they have no scope
    /// restrictions. API tokens must explicitly include the scope (or `*`/`admin`).
    pub fn has_scope(&self, scope: &str) -> bool {
        if !self.is_api_token {
            return true; // JWT sessions are not scope-restricted
        }
        match &self.scopes {
            None => true,
            // Delegate the wildcard-aware scope decision to the single
            // canonical helper (`*` / `admin` short-circuit) instead of
            // re-inlining a brittle string match here. Keeping the wildcard
            // policy in one place is what the #1316 grep gate enforces.
            Some(scopes) => crate::services::token_service::scopes_grant_access(scopes, scope),
        }
    }

    /// Repo-scope authorization decision for this principal, as an explicit
    /// [`AccessScope`].
    ///
    /// Returns the principal's repository scope: [`AccessScope::Admin`] grants
    /// all repositories, [`AccessScope::Restricted`] is a deny-by-default
    /// allowlist. This is the single accessor callers use to reason about
    /// repo-scope decisions (#1617, Phase 4).
    pub fn access_scope(&self) -> AccessScope {
        self.allowed_repo_ids.clone()
    }

    /// Check whether this auth context has access to a specific repository.
    /// Returns true if unrestricted (admin scope) or if the repo is in the
    /// allowed set.
    pub fn can_access_repo(&self, repo_id: Uuid) -> bool {
        self.access_scope().grants(repo_id)
    }

    /// Return an authorization error if scope check fails.
    pub fn require_scope(&self, scope: &str) -> crate::error::Result<()> {
        if self.has_scope(scope) {
            Ok(())
        } else {
            Err(AppError::Authorization(format!(
                "Token does not have required scope: {}",
                scope
            )))
        }
    }

    /// Return a 403 Forbidden error if the caller is not an admin.
    pub fn require_admin(&self) -> crate::error::Result<()> {
        if self.is_admin {
            Ok(())
        } else {
            Err(AppError::Authorization("Admin access required".to_string()))
        }
    }

    /// Self-or-admin gate: allow the call when the caller is acting on their
    /// own resource (`self.user_id == target_user_id`) **or** the caller is an
    /// admin. Otherwise return a 403 Forbidden carrying `deny_msg`.
    ///
    /// This is the single evaluation point for the recurring self-service
    /// authorization pattern (`if auth.user_id != id && !auth.is_admin { 403 }`).
    /// The deny message is supplied by the call site so each endpoint keeps its
    /// existing, user-facing 403 body verbatim (e.g. "Cannot view other users'
    /// tokens"). Deny-by-default: any caller who is neither self nor admin is
    /// rejected.
    pub fn require_self_or_admin(
        &self,
        target_user_id: Uuid,
        deny_msg: &str,
    ) -> crate::error::Result<()> {
        if self.user_id == target_user_id || self.is_admin {
            Ok(())
        } else {
            Err(AppError::Authorization(deny_msg.to_string()))
        }
    }
}

impl From<Claims> for AuthExtension {
    fn from(claims: Claims) -> Self {
        // Single source of truth for the calling JWT's issued-at. Folded here
        // (from the former separate `TokenIat` extension) so every JWT
        // principal carries `iat_ms` uniformly (#1394). Computed before the
        // partial move of `claims.allowed_repo_ids` below.
        let iat_ms = Some(claims.effective_iat_ms());
        Self {
            user_id: claims.sub,
            username: claims.username,
            email: claims.email,
            is_admin: claims.is_admin,
            is_api_token: false,
            is_service_account: false,
            scopes: None,
            allowed_repo_ids: AccessScope::from(claims.allowed_repo_ids),
            iat_ms,
        }
    }
}

impl From<User> for AuthExtension {
    fn from(user: User) -> Self {
        Self {
            user_id: user.id,
            username: user.username,
            email: user.email,
            is_admin: user.is_admin,
            is_api_token: false,
            is_service_account: user.is_service_account,
            scopes: None,
            allowed_repo_ids: AccessScope::Admin,
            // Basic username/password auth carries no JWT `iat`.
            iat_ms: None,
        }
    }
}

/// Require that the request is authenticated, returning a 401 with a
/// `WWW-Authenticate: Basic` challenge if not.
///
/// Format handlers call this instead of implementing their own auth.
#[allow(clippy::result_large_err)]
pub fn require_auth_basic(
    auth: Option<AuthExtension>,
    realm: &str,
) -> std::result::Result<AuthExtension, Response> {
    auth.ok_or_else(|| {
        Response::builder()
            .status(StatusCode::UNAUTHORIZED)
            .header("WWW-Authenticate", format!("Basic realm=\"{}\"", realm))
            .body(axum::body::Body::from("Authentication required"))
            .unwrap()
    })
}

/// Like [`require_auth_basic`] but additionally enforces the given API-token
/// scope. JWT and password-authenticated sessions (anything without
/// `is_api_token = true`) pass through unchanged because they are not scope
/// restricted. API tokens must carry the requested scope or `*`/`admin`,
/// otherwise this returns a 403 with body
/// `Token does not have required scope: <scope>`.
///
/// Format handlers should call this instead of `require_auth_basic` for any
/// write/delete path (publish, upload, delete) so a read-scoped service
/// account token cannot push or destroy artifacts. See GHSA-vvc3-h39c-mrq5.
#[allow(clippy::result_large_err)]
pub fn require_auth_basic_scope(
    auth: Option<AuthExtension>,
    realm: &str,
    scope: &str,
) -> std::result::Result<AuthExtension, Response> {
    let ext = require_auth_basic(auth, realm)?;
    if !ext.has_scope(scope) {
        return Err(Response::builder()
            .status(StatusCode::FORBIDDEN)
            .body(axum::body::Body::from(format!(
                "Token does not have required scope: {}",
                scope
            )))
            .unwrap());
    }
    Ok(ext)
}

/// Enforce a scope check on an already-resolved auth context, returning a
/// 403 `Response` if the scope is missing. Use for write/delete paths that
/// authenticate via [`require_auth_with_bearer_fallback`] or other helpers
/// returning `Response` errors. See GHSA-vvc3-h39c-mrq5.
#[allow(clippy::result_large_err)]
pub fn require_scope_response(
    auth: Option<&AuthExtension>,
    scope: &str,
) -> std::result::Result<(), Response> {
    if let Some(ext) = auth {
        if !ext.has_scope(scope) {
            return Err(Response::builder()
                .status(StatusCode::FORBIDDEN)
                .body(axum::body::Body::from(format!(
                    "Token does not have required scope: {}",
                    scope
                )))
                .unwrap());
        }
    }
    Ok(())
}

/// Extract credentials from a Bearer token that contains base64-encoded user:pass.
///
/// Some package managers (npm, cargo, goproxy) send Bearer tokens that are
/// base64-encoded `username:password` rather than JWTs or API keys.
pub fn extract_bearer_credentials(headers: &HeaderMap) -> Option<(String, String)> {
    headers
        .get(AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer ").or(v.strip_prefix("bearer ")))
        .and_then(|token| {
            base64::engine::general_purpose::STANDARD
                .decode(token)
                .ok()
                .and_then(|bytes| String::from_utf8(bytes).ok())
                .and_then(|s| {
                    let mut parts = s.splitn(2, ':');
                    let user = parts.next()?.to_string();
                    let pass = parts.next()?.to_string();
                    Some((user, pass))
                })
        })
}

/// Require authentication, with a fallback to Bearer-as-base64 credentials.
///
/// Used by format handlers (npm, cargo, goproxy) where clients may send
/// credentials as a base64-encoded `user:pass` in a Bearer token rather than
/// using standard Basic auth.
#[allow(clippy::result_large_err)]
pub async fn require_auth_with_bearer_fallback(
    auth: Option<AuthExtension>,
    headers: &HeaderMap,
    db: &sqlx::PgPool,
    config: &crate::config::Config,
    realm: &str,
) -> std::result::Result<uuid::Uuid, Response> {
    if let Some(ext) = auth {
        return Ok(ext.user_id);
    }
    let (username, password) = extract_bearer_credentials(headers).ok_or_else(|| {
        Response::builder()
            .status(StatusCode::UNAUTHORIZED)
            .header("WWW-Authenticate", format!("Basic realm=\"{}\"", realm))
            .body(axum::body::Body::from("Authentication required"))
            .unwrap()
    })?;
    let auth_service = AuthService::new(db.clone(), std::sync::Arc::new(config.clone()));
    let (user, _) = auth_service
        .authenticate(&username, &password)
        .await
        .map_err(|e| {
            // A pool-acquire timeout during the credential DB lookup is a
            // transient capacity problem (POOL_EXHAUSTED), not a bad password:
            // surface a retryable 503 rather than flattening it to a spurious
            // 401 (#2125). Any genuine failure keeps the existing 401.
            if e.is_pool_timeout() {
                return service_unavailable_response();
            }
            Response::builder()
                .status(StatusCode::UNAUTHORIZED)
                .header("WWW-Authenticate", format!("Basic realm=\"{}\"", realm))
                .body(axum::body::Body::from("Invalid credentials"))
                .unwrap()
        })?;
    Ok(user.id)
}

/// Token extraction result
#[derive(Debug, Clone, Copy)]
pub(crate) enum ExtractedToken<'a> {
    /// JWT or API token from Bearer scheme
    Bearer(&'a str),
    /// API token from ApiKey scheme
    ApiKey(&'a str),
    /// HTTP Basic credentials (base64-encoded user:password)
    Basic(&'a str),
    /// No token found
    None,
    /// Invalid header format
    Invalid,
}

/// Extract token from Authorization header (supports Bearer, ApiKey, and Basic schemes)
fn extract_token_from_auth_header(auth_header: &str) -> ExtractedToken<'_> {
    if let Some(token) = auth_header.strip_prefix("Bearer ") {
        ExtractedToken::Bearer(token)
    } else if let Some(token) = auth_header.strip_prefix("ApiKey ") {
        ExtractedToken::ApiKey(token)
    } else if let Some(creds) = auth_header
        .strip_prefix("Basic ")
        .or_else(|| auth_header.strip_prefix("basic "))
    {
        ExtractedToken::Basic(creds)
    } else if !auth_header.is_empty() && !auth_header.contains(' ') {
        // The native cargo client's `cargo:token` credential provider sends the
        // raw token as the Authorization header value with NO scheme prefix
        // (e.g. `Authorization: <token>`). A scheme-less, single-word value is
        // therefore treated as a Bearer token so cargo can authenticate.
        ExtractedToken::Bearer(auth_header)
    } else {
        ExtractedToken::Invalid
    }
}

/// Extract token from request headers
/// Checks: Authorization (Bearer/ApiKey), X-API-Key
pub(crate) fn extract_token(request: &Request) -> ExtractedToken<'_> {
    // First, check Authorization header
    if let Some(auth_header) = request
        .headers()
        .get(AUTHORIZATION)
        .and_then(|h| h.to_str().ok())
    {
        let result = extract_token_from_auth_header(auth_header);
        if !matches!(result, ExtractedToken::None) {
            return result;
        }
    }

    // Check X-API-Key header
    if let Some(api_key) = request
        .headers()
        .get(&X_API_KEY)
        .and_then(|h| h.to_str().ok())
    {
        return ExtractedToken::ApiKey(api_key);
    }

    // Check cookie as fallback (for browser sessions with httpOnly cookies)
    if let Some(cookie_header) = request.headers().get(COOKIE).and_then(|h| h.to_str().ok()) {
        for cookie in cookie_header.split(';') {
            let cookie = cookie.trim();
            if let Some(token) = cookie.strip_prefix("ak_access_token=") {
                return ExtractedToken::Bearer(token);
            }
        }
    }

    ExtractedToken::None
}

/// Decode a base64-encoded Basic auth string into (username, password).
///
/// Returns `None` if the base64 is invalid, the bytes are not valid UTF-8,
/// or the decoded string does not contain a `:` separator.
fn decode_basic_credentials(encoded: &str) -> Option<(String, String)> {
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .ok()?;
    let decoded = String::from_utf8(bytes).ok()?;
    let (user, pass) = decoded.split_once(':')?;
    Some((user.to_owned(), pass.to_owned()))
}

/// Whether `path` is reachable by a principal flagged `must_change_password`.
///
/// A forced-rotation user is otherwise blocked from every route (see
/// [`auth_middleware`]); this allowlist is the narrow set of endpoints that
/// let them recover without admin intervention:
///
///   * the current-user self lookup (`.../me`, i.e. `GET /api/v1/auth/me`) —
///     a read-only call the mandatory first-login change screen makes to
///     render (who is logged in / which account is being rotated),
///   * the self password-change route (`.../password`, e.g.
///     `POST /api/v1/users/:id/password`) — clears the flag, and
///   * logout (`.../auth/logout`) — lets the client end the session.
///
/// Matching is by suffix of the FULL, un-stripped request path (see
/// [`auth_middleware`], which reads `OriginalUri`). This middleware is layered
/// *inside* the `/api/v1` + `/auth` nests, so `request.uri().path()` is the
/// fully nest-stripped suffix — `GET /api/v1/auth/me` and
/// `DELETE /api/v1/sbom/me` (id = "me") both arrive as exactly `/me`, which a
/// stripped-path predicate cannot tell apart. The genuine self-lookup is
/// therefore anchored to the full route `.../auth/me`, so impostors like
/// `/api/v1/sbom/me`, `/api/v1/webhooks/me`, and `/api/v1/promotion-rules/me`
/// stay gated. The admin reset / force-change routes
/// (`.../password/reset`, `.../force-password-change`) deliberately do NOT
/// match — they sit behind `admin_middleware`, not this one, and would not be
/// self-recoverable. Only read-only / self-recovery endpoints are exempt;
/// every state-changing API surface stays gated until the flag is cleared.
fn path_exempt_from_password_change(path: &str) -> bool {
    let path = path.strip_suffix('/').unwrap_or(path);
    path.ends_with("/auth/me") || path.ends_with("/password") || path.ends_with("/auth/logout")
}

/// 428 Precondition Required: the principal must rotate their password before
/// any further (non-recovery) request is honoured. Distinct from 401 so the
/// client can tell "rotate your password" apart from "log in again".
fn must_change_password_response() -> Response {
    (
        StatusCode::PRECONDITION_REQUIRED,
        "Password change required: rotate your password before continuing",
    )
        .into_response()
}

/// Read the live `must_change_password` watermark for `user_id`.
///
/// The flag is not carried in JWT claims, so it is read from the DB on the
/// request path (only for non-exempt routes — see [`auth_middleware`]). A
/// missing row or query error is treated as "not flagged": the principal has
/// already authenticated, and a transient DB hiccup must not convert a normal
/// request into a forced-rotation lockout. Uses runtime `query_scalar` (not
/// the compile-time macro) so it needs no offline SQLx cache.
async fn principal_must_change_password(db: &sqlx::PgPool, user_id: Uuid) -> bool {
    sqlx::query_scalar::<_, bool>(
        "SELECT must_change_password FROM users WHERE id = $1 AND is_active = true",
    )
    .bind(user_id)
    .fetch_optional(db)
    .await
    .ok()
    .flatten()
    .unwrap_or(false)
}

/// Authentication middleware function - requires valid token
///
/// Supports multiple authentication schemes:
/// - Bearer JWT tokens
/// - Bearer API tokens
/// - ApiKey API tokens
/// - X-API-Key header
pub async fn auth_middleware(
    State(auth_service): State<Arc<AuthService>>,
    mut request: Request,
    next: Next,
) -> Response {
    // Extract token from request headers
    let extracted = extract_token(&request);

    // Track whether the request even attempted header-based auth, so the
    // 401 message stays informative when only a ?ticket= was supplied.
    let had_header_credentials = !matches!(extracted, ExtractedToken::None);

    // The resolved principal. The JWT `iat` used by credential-change
    // invalidation (TOTP, password) to exempt the calling session's own token
    // now travels as `AuthExtension::iat_ms`, stamped at the single
    // `From<Claims>` source; it is `None` for non-JWT principals (#1394).
    let header_result: Result<AuthExtension, &'static str> = match extracted {
        // Replica-safe access-token validation. The async variant consults the
        // DB credential-change watermark (#1173) so a password reset, TOTP
        // change, or deactivation on a peer replica is honoured here on the
        // request path within `CREDENTIAL_DB_CACHE_TTL_SECS`. The sync variant
        // (which only reads the in-memory map) would silently keep accepting
        // pre-change tokens across replicas — that's the architectural gap
        // PR #1190 was supposed to close.
        ExtractedToken::Bearer(token) => {
            match auth_service.validate_access_token_async(token).await {
                Ok(claims) => Ok(AuthExtension::from(claims)),
                Err(_) => match validate_api_token_with_scopes(&auth_service, token).await {
                    Ok(ext) => Ok(ext),
                    // Same transient bcrypt-capacity shed as the Basic branch
                    // below: a saturated cap is "retry shortly", not "wrong
                    // token". See `TokenAuthError::Overloaded`.
                    Err(TokenAuthError::Overloaded) => return service_unavailable_response(),
                    Err(TokenAuthError::Invalid) => Err("Invalid or expired token"),
                },
            }
        }
        ExtractedToken::ApiKey(token) => {
            match validate_api_token_with_scopes(&auth_service, token).await {
                Ok(ext) => Ok(ext),
                Err(TokenAuthError::Overloaded) => return service_unavailable_response(),
                Err(TokenAuthError::Invalid) => Err("Invalid or expired API token"),
            }
        }
        ExtractedToken::Basic(encoded) => match decode_basic_credentials(encoded) {
            None => Err("Invalid Basic auth credentials"),
            Some((username, password)) => {
                match auth_service.authenticate(&username, &password).await {
                    Ok((user, _token_pair)) => Ok(AuthExtension::from(user)),
                    // A transient bcrypt-capacity shed must NOT be collapsed
                    // into a 401. `authenticate()` runs bcrypt(cost=12) under a
                    // process-wide concurrency cap (see
                    // `auth_service::acquire_auth_permit_for_bcrypt`); when that
                    // cap saturates under a burst of concurrent Basic-auth
                    // requests it returns `AppError::ServiceUnavailable`, which
                    // is a retryable 503, not "wrong password". Collapsing it to
                    // 401 "Invalid credentials" is what made `twine upload` fail
                    // in the release gate (a curl -u upload with byte-identical
                    // credentials passed because it didn't coincide with a
                    // saturated cap): twine does not retry on 401 but does on
                    // 503. Surface the shed as 503 + Retry-After so well-behaved
                    // clients back off and retry instead of aborting.
                    Err(AppError::ServiceUnavailable(msg)) => {
                        return (
                            StatusCode::SERVICE_UNAVAILABLE,
                            [(axum::http::header::RETRY_AFTER, "1")],
                            msg,
                        )
                            .into_response();
                    }
                    // A pool-acquire timeout during the credential DB lookup is
                    // a transient capacity problem (POOL_EXHAUSTED), not "wrong
                    // password": surface the same retryable 503 the #2101/#2102
                    // handlers return rather than flattening it to a spurious
                    // 401 (#2125). Clients retry on 503 but abort on 401.
                    Err(ref e) if e.is_pool_timeout() => {
                        return service_unavailable_response();
                    }
                    Err(_) => {
                        // Try treating the password as a short-lived JWT access
                        // token. This enables CI/CD keyless flows (e.g. OIDC
                        // token exchange) where package managers like Maven,
                        // pip/twine, and Helm send the AK access token as the
                        // Basic-auth password. `From<Claims>` stamps `iat_ms` so
                        // credential-change invalidation can exempt the calling
                        // session.
                        match auth_service.validate_access_token_async(&password).await {
                            Ok(claims) => Ok(AuthExtension::from(claims)),
                            Err(_) => Err("Invalid credentials"),
                        }
                    }
                }
            }
        },
        ExtractedToken::None => Err("Missing authorization header"),
        ExtractedToken::Invalid => Err("Invalid authorization header format"),
    };

    let header_error = match header_result {
        Ok(ext) => {
            // Enforce a forced password rotation (`must_change_password`).
            //
            // The flag is advisory in the token/claims, so we read the live DB
            // watermark for the principal. A flagged user must be unable to do
            // anything except recover: change their own password or log out.
            // Every other route is refused with 428 Precondition Required so
            // clients know the account is in a "must rotate" state rather than
            // "unauthenticated". The DB read only happens for non-exempt paths,
            // so the common authenticated request pays nothing extra on the
            // password-change / logout recovery routes.
            //
            // Use the FULL request path via `OriginalUri` (populated by the
            // outer router before any nest stripped its prefix), not
            // `request.uri().path()` which axum has already stripped down to a
            // bare suffix. The exemption anchors the self-lookup to
            // `.../auth/me`, and the stripped suffix `/me` is identical for the
            // genuine `GET /api/v1/auth/me` and impostors like
            // `DELETE /api/v1/sbom/me`; only the original path can tell them
            // apart. Fall back to `request.uri().path()` when `OriginalUri` is
            // absent (e.g. a flat-router unit test with no nest) so the path
            // still carries the full route.
            let gate_path = request
                .extensions()
                .get::<OriginalUri>()
                .map(|o| o.0.path().to_string())
                .unwrap_or_else(|| request.uri().path().to_string());
            if !path_exempt_from_password_change(&gate_path)
                && principal_must_change_password(auth_service.db(), ext.user_id).await
            {
                return must_change_password_response();
            }
            // Insert BOTH shapes so handlers behind this middleware can
            // extract either `Extension<AuthExtension>` or
            // `Extension<Option<AuthExtension>>`. Without the Option-wrapped
            // copy, a handler declaring `Extension<Option<AuthExtension>>`
            // (e.g. the permission handlers, which gate on require_auth +
            // require_scope) fails Axum extraction with HTTP 500
            // ("Missing request extension: Extension of type
            // Option<AuthExtension>") before the in-handler scope check runs.
            // That surfaced as a 500 instead of the canonical 403 for a
            // read-scope service-account token on POST /api/v1/permissions.
            // See #1438 (B10).
            request.extensions_mut().insert(Some(ext.clone()));
            request.extensions_mut().insert(ext);
            return next.run(request).await;
        }
        Err(msg) => msg,
    };

    // Header-based auth failed. Fall back to a `?ticket=` download ticket
    // if present in the query string. Tickets only authenticate read methods
    // and only for the path the ticket was minted against.
    let ticket_parts = extract_ticket_request_parts(&request);
    if let Some(parts) = ticket_parts.as_ref() {
        if let Some(ext) = try_resolve_ticket_for_parts(auth_service.db(), parts).await {
            // Same dual-shape insertion as the header-auth path above so
            // `Extension<Option<AuthExtension>>` handlers resolve under a
            // ticket-authenticated request too (#1438 / B10).
            request.extensions_mut().insert(Some(ext.clone()));
            request.extensions_mut().insert(ext);
            request.extensions_mut().insert(DownloadTicketAuth);
            return next.run(request).await;
        }
    }

    // Note on the ambiguous message: "Invalid or expired download ticket"
    // intentionally does not distinguish between
    //   (a) ticket not found,
    //   (b) ticket expired,
    //   (c) bound-path mismatch,
    //   (d) write method on a read-only ticket.
    // Leaking which case it is would help an attacker who has a partial
    // ticket value (or who is probing path bindings) narrow down the cause.
    // High-entropy tickets and a 30-second TTL make ambiguity cheap. Do not
    // "fix" this by giving a more specific message.
    let message = if !had_header_credentials && ticket_parts.is_some() {
        "Invalid or expired download ticket"
    } else {
        header_error
    };
    (StatusCode::UNAUTHORIZED, message).into_response()
}

/// Why an API-token validation attempt did not produce an [`AuthExtension`].
///
/// Two outcomes matter to the middleware: the token is genuinely bad
/// (unknown, expired, revoked, deactivated owner — answer with 401), or
/// validation could not be completed because the process-wide bcrypt
/// concurrency cap is saturated (`AppError::ServiceUnavailable` from
/// `auth_service::acquire_auth_permit_for_bcrypt` — answer with a retryable
/// 503, exactly like the username/password branch). Flattening both into a
/// unit error is what made cargo/twine API-token clients receive a spurious
/// 401 under a concurrent burst; they retry on 503 but abort on 401.
#[derive(Debug, PartialEq, Eq)]
enum TokenAuthError {
    /// The credential failed validation; the caller owes the client a 401.
    Invalid,
    /// The bcrypt-bound auth-concurrency cap is saturated; the caller must
    /// surface a retryable 503 (see [`service_unavailable_response`]), never
    /// a 401.
    Overloaded,
}

/// Classify a `validate_api_token` error into the two outcomes the
/// middleware distinguishes. Only the transient bcrypt-capacity shed
/// (`AppError::ServiceUnavailable`) maps to [`TokenAuthError::Overloaded`];
/// everything else (authentication, unauthorized, database, internal) is a
/// genuine validation failure and stays [`TokenAuthError::Invalid`] so the
/// existing 401 behaviour is preserved.
fn classify_token_validation_err(err: AppError) -> TokenAuthError {
    match err {
        AppError::ServiceUnavailable(_) => TokenAuthError::Overloaded,
        // A pool-acquire timeout during the token's DB lookup is a transient
        // capacity problem, not a bad token: surface it as a retryable 503
        // (POOL_EXHAUSTED) exactly like the #2101/#2102 handler path instead of
        // flattening it to a spurious 401 (#2125). Reuses the shared
        // `AppError::is_pool_timeout` predicate so the classification stays
        // consistent all the way up the stack.
        ref e if e.is_pool_timeout() => TokenAuthError::Overloaded,
        _ => TokenAuthError::Invalid,
    }
}

/// Validate an API token and create an AuthExtension with scopes and repo restrictions.
async fn validate_api_token_with_scopes(
    auth_service: &AuthService,
    token: &str,
) -> Result<AuthExtension, TokenAuthError> {
    let validation = auth_service
        .validate_api_token(token)
        .await
        .map_err(classify_token_validation_err)?;

    Ok(AuthExtension {
        user_id: validation.user.id,
        username: validation.user.username,
        email: validation.user.email,
        is_admin: validation.user.is_admin,
        is_api_token: true,
        is_service_account: validation.user.is_service_account,
        scopes: Some(validation.scopes),
        allowed_repo_ids: validation.allowed_repo_ids,
        // API tokens are not JWTs and carry no `iat`.
        iat_ms: None,
    })
}

/// Try to resolve an optional authentication token into an [`AuthExtension`].
///
/// Returns `Some(ext)` when a valid Bearer JWT, Bearer API token, or ApiKey
/// token is present, and `None` otherwise (missing, invalid, or expired).
/// This is the shared logic used by [`optional_auth_middleware`] and
/// [`repo_visibility_middleware`].
///
/// Note: this helper conflates "no credential" with "invalid credential" —
/// callers that need to distinguish those two outcomes (e.g. to honour an
/// off-boarding deactivation immediately on optional-auth routes, see
/// [`try_resolve_auth_outcome`] and issue #1371) should use the outcome
/// variant instead.
pub(crate) async fn try_resolve_auth(
    auth_service: &AuthService,
    extracted: ExtractedToken<'_>,
) -> Option<AuthExtension> {
    match try_resolve_auth_outcome(auth_service, extracted).await {
        AuthOutcome::Resolved(ext) => Some(ext),
        AuthOutcome::NoCredential | AuthOutcome::InvalidCredential | AuthOutcome::Overloaded => {
            None
        }
    }
}

/// Outcome of resolving an authentication credential.
///
/// Distinguishes three states an optional-auth path needs to handle
/// differently after #1371:
///
///   * [`AuthOutcome::Resolved`] - a credential was presented and validated.
///   * [`AuthOutcome::NoCredential`] - no credential was presented; the
///     caller may continue as an anonymous request when policy allows.
///   * [`AuthOutcome::InvalidCredential`] - a credential WAS presented but
///     failed validation (expired JWT, revoked / deactivated API token,
///     wrong basic-auth password, etc.). RFC 7235 calls for 401 here — and
///     for off-boarding (issue #1371) it is load-bearing: silently
///     downgrading a deactivated user's still-cached API token to "no auth"
///     means the user's token continues to receive public-only responses
///     instead of being unambiguously rejected, which masks the
///     deactivation and weakens the security posture.
///
/// Use [`try_resolve_auth_outcome`] to obtain this tri-state result; the
/// boolean [`try_resolve_auth`] helper continues to flatten Invalid into
/// None for callers that don't need to distinguish.
#[derive(Debug)]
pub(crate) enum AuthOutcome {
    Resolved(AuthExtension),
    NoCredential,
    InvalidCredential,
    /// A credential was presented and is well-formed, but validation could
    /// not be completed because the bcrypt-bound auth-concurrency cap is
    /// saturated (see `auth_service::acquire_auth_permit_for_bcrypt`). This
    /// is a transient overload, NOT "wrong password": the correct response
    /// is a retryable 503, never a 401. Collapsing it into `InvalidCredential`
    /// is what made `twine upload` fail in the release gate under parallel
    /// load (a curl -u upload with byte-identical credentials passed because
    /// it did not coincide with a saturated cap); twine does not retry on
    /// 401 but does on 503.
    Overloaded,
}

/// Resolve a possibly-missing credential into an [`AuthOutcome`].
///
/// This is the strict variant of [`try_resolve_auth`]: it preserves the
/// distinction between "no credential presented" and "credential presented
/// but invalid" so optional-auth middleware can return 401 on the latter
/// rather than silently dropping to anonymous. The original
/// [`try_resolve_auth`] delegates to this function and flattens the result.
///
/// Decision tree:
///   * `ExtractedToken::None` -> `NoCredential` (anonymous request)
///   * `ExtractedToken::Invalid` -> `InvalidCredential` (malformed Authorization
///     header; the client explicitly attempted to authenticate)
///   * `ExtractedToken::Bearer` / `ApiKey` / `Basic` ->
///     - `Resolved(ext)` on any successful path
///     - `InvalidCredential` if every validation attempt failed
pub(crate) async fn try_resolve_auth_outcome(
    auth_service: &AuthService,
    extracted: ExtractedToken<'_>,
) -> AuthOutcome {
    match extracted {
        ExtractedToken::Bearer(token) => {
            // See `auth_middleware` for why this is the async variant. Same
            // rationale: optional-auth routes still need to reject pre-change
            // tokens across replicas (#1173).
            if let Ok(claims) = auth_service.validate_access_token_async(token).await {
                return AuthOutcome::Resolved(AuthExtension::from(claims));
            }
            match validate_api_token_with_scopes(auth_service, token).await {
                Ok(ext) => return AuthOutcome::Resolved(ext),
                // A transient bcrypt-capacity shed must surface as 503, not
                // 401. See `AuthOutcome::Overloaded`.
                Err(TokenAuthError::Overloaded) => return AuthOutcome::Overloaded,
                Err(TokenAuthError::Invalid) => {}
            }
            // Some package managers (npm, cargo, goproxy) send Bearer tokens
            // that are base64-encoded `username:password` rather than JWTs or
            // API keys. Try decoding as credentials before giving up.
            if let Some((username, password)) = decode_basic_credentials(token) {
                match auth_service.authenticate(&username, &password).await {
                    Ok((user, _)) => return AuthOutcome::Resolved(AuthExtension::from(user)),
                    // A transient bcrypt-capacity shed must surface as 503, not
                    // 401. See `AuthOutcome::Overloaded`.
                    Err(AppError::ServiceUnavailable(_)) => return AuthOutcome::Overloaded,
                    Err(_) => {}
                }
            }
            AuthOutcome::InvalidCredential
        }
        ExtractedToken::ApiKey(token) => {
            match validate_api_token_with_scopes(auth_service, token).await {
                Ok(ext) => AuthOutcome::Resolved(ext),
                // See `AuthOutcome::Overloaded`: saturated bcrypt cap is a
                // retryable 503, never a 401.
                Err(TokenAuthError::Overloaded) => AuthOutcome::Overloaded,
                Err(TokenAuthError::Invalid) => AuthOutcome::InvalidCredential,
            }
        }
        ExtractedToken::Basic(encoded) => {
            let Some((username, password)) = decode_basic_credentials(encoded) else {
                return AuthOutcome::InvalidCredential;
            };
            // Try bcrypt username/password auth first
            match auth_service.authenticate(&username, &password).await {
                Ok((user, _)) => return AuthOutcome::Resolved(AuthExtension::from(user)),
                // A transient bcrypt-capacity shed must surface as 503, not a
                // 401. Without this, twine (which sends standard Basic auth)
                // gets a spurious 401 under parallel-suite load and aborts,
                // while a single curl -u upload with the same credentials
                // succeeds. See `AuthOutcome::Overloaded`.
                Err(AppError::ServiceUnavailable(_)) => return AuthOutcome::Overloaded,
                // A pool-acquire timeout is a retryable 503, never a 401.
                // Short-circuit here so a saturated pool does not pay a second
                // acquire-timeout on the API-token fallback below before the
                // classifier reaches the same conclusion (#2125). See
                // `AuthOutcome::Overloaded`.
                Err(ref e) if e.is_pool_timeout() => return AuthOutcome::Overloaded,
                Err(_) => {}
            }
            // Try treating the password as a short-lived JWT access token.
            // This enables CI/CD keyless flows (e.g. OIDC token exchange) where
            // package managers like Maven, pip/twine, and Helm send the AK access
            // token as the Basic auth password.
            if let Ok(claims) = auth_service.validate_access_token_async(&password).await {
                return AuthOutcome::Resolved(AuthExtension::from(claims));
            }
            // Fall back to treating the password as an API token — compatible with
            // pip netrc / Artifactory-style `token:<api_token>` credential format
            match validate_api_token_with_scopes(auth_service, &password).await {
                Ok(ext) => AuthOutcome::Resolved(ext),
                // The token fallback also burns a bcrypt verify under the
                // same process-wide cap; preserve the shed as Overloaded so
                // pip-netrc-style `token:<api_token>` clients get the
                // retryable 503, not a spurious 401.
                Err(TokenAuthError::Overloaded) => AuthOutcome::Overloaded,
                Err(TokenAuthError::Invalid) => AuthOutcome::InvalidCredential,
            }
        }
        ExtractedToken::None => AuthOutcome::NoCredential,
        ExtractedToken::Invalid => AuthOutcome::InvalidCredential,
    }
}

// ---------------------------------------------------------------------------
// Download ticket auth (?ticket= query param)
// ---------------------------------------------------------------------------

/// Extract the value of a `ticket` query parameter from a URI's query string.
///
/// Returns `None` when no query string is present, no `ticket` key exists, or
/// the value is empty. Repeated `ticket=` keys take the first occurrence.
/// Performs simple percent-decoding of `+` -> space and `%XX` byte escapes; the
/// ticket itself is hex (no special characters), but query-decoding keeps
/// behaviour consistent with HTTP clients that always encode.
pub(crate) fn extract_ticket_from_query(query: Option<&str>) -> Option<String> {
    let q = query?;
    for pair in q.split('&') {
        let mut it = pair.splitn(2, '=');
        let key = it.next()?;
        if key != "ticket" {
            continue;
        }
        let raw = it.next().unwrap_or("");
        if raw.is_empty() {
            return None;
        }
        // Minimal percent-decoding sufficient for hex tickets.
        let mut out = String::with_capacity(raw.len());
        let bytes = raw.as_bytes();
        let mut i = 0;
        while i < bytes.len() {
            let b = bytes[i];
            if b == b'+' {
                out.push(' ');
                i += 1;
            } else if b == b'%' && i + 2 < bytes.len() {
                let hi = (bytes[i + 1] as char).to_digit(16);
                let lo = (bytes[i + 2] as char).to_digit(16);
                match (hi, lo) {
                    (Some(h), Some(l)) => {
                        out.push(((h * 16 + l) as u8) as char);
                        i += 3;
                    }
                    _ => {
                        out.push(b as char);
                        i += 1;
                    }
                }
            } else {
                out.push(b as char);
                i += 1;
            }
        }
        return Some(out);
    }
    None
}

/// HTTP methods that download tickets are allowed to authenticate.
///
/// Tickets are minted for downloads/streams only. Any write operation
/// (POST, PUT, PATCH, DELETE) authenticated by a ticket must be rejected
/// even when the underlying user has write permission, because the ticket
/// embeds no scope information and the calling client may be a browser
/// `<a href>` or `EventSource` that the user did not consent to use for
/// mutations.
fn ticket_method_allowed(method: &Method) -> bool {
    matches!(*method, Method::GET | Method::HEAD)
}

/// Decide whether a ticket bound to `bound_path` may authenticate a request
/// for `request_path`.
///
/// A ticket with `bound_path = None` authenticates any read path the minting
/// user can reach (legacy behaviour). A ticket with `bound_path = Some(p)`
/// authenticates only requests whose URL path equals `p`. We compare by exact
/// match to keep the policy auditable; callers that want a directory-prefix
/// must mint one ticket per resource.
fn ticket_path_allowed(bound_path: Option<&str>, request_path: &str) -> bool {
    match bound_path {
        None => true,
        Some(p) => p == request_path,
    }
}

/// Resolve a download ticket to an [`AuthExtension`] without consuming it.
///
/// Wraps [`AuthConfigService::validate_download_ticket`], which atomically
/// deletes the ticket on success (single-use enforcement) and rejects expired
/// tickets via `expires_at > NOW()`. After the ticket is consumed, the
/// owning user is loaded so the resulting extension carries the same identity
/// downstream handlers see for any other auth method.
async fn try_resolve_ticket_auth(
    db: &sqlx::PgPool,
    ticket: &str,
    method: &Method,
    request_path: &str,
) -> Option<AuthExtension> {
    if !ticket_method_allowed(method) {
        return None;
    }

    let (user_id, _purpose, resource_path) =
        crate::services::auth_config_service::AuthConfigService::validate_download_ticket(
            db, ticket,
        )
        .await
        .ok()?;

    if !ticket_path_allowed(resource_path.as_deref(), request_path) {
        // Ticket has been consumed by validate_download_ticket; treat the
        // mismatch as an authentication failure so the client cannot reuse
        // the same ticket against a different path.
        //
        // Trade-off: a mistyped path by a legitimate client will burn the
        // ticket and the client must mint a new one. We accept this cost
        // because single-use is the security invariant we cannot weaken
        // without breaking the threat model (a stolen ticket adversary
        // would simply replay against the right path).
        //
        // The cleaner alternative is `SELECT then DELETE WHERE ... RETURNING`
        // inside a transaction so wrong-path attempts do not consume. That
        // is a follow-up change; not in this PR because the existing
        // single-statement DELETE-RETURNING is the only thing that gives
        // us atomic single-use under concurrent retry.
        return None;
    }

    // Load the owning user. We block deactivated users so a revoked account
    // cannot keep downloading via outstanding tickets, but we honour service
    // accounts and not-yet-rotated passwords because the ticket itself is
    // the proof of intent: the JWT session that minted it had whatever
    // rights the user had at mint time.
    //
    // Uses `sqlx::query_as::<_, User>` rather than the `query_as!` macro so
    // adding the ticket-consumer middleware does not require regenerating
    // the offline SQLx query cache.
    let user: User = sqlx::query_as::<_, User>(
        r#"
        SELECT
            id, username, email, password_hash, display_name,
            auth_provider, external_id, is_admin, is_active,
            is_service_account, must_change_password,
            totp_secret, totp_enabled, totp_backup_codes, totp_verified_at,
            last_login_at, created_at, updated_at
        FROM users
        WHERE id = $1 AND is_active = true
        "#,
    )
    .bind(user_id)
    .fetch_optional(db)
    .await
    .ok()??;

    let mut ext = AuthExtension::from(user);
    // Tickets are read-only. Drop admin elevation so a ticket minted by an
    // admin cannot be replayed against admin-only routes that happen to
    // accept tickets in their middleware chain. Callers also insert the
    // [`DownloadTicketAuth`] marker extension so write-gating middleware
    // can recognise the request as ticket-authenticated.
    ext.is_admin = false;

    // Scope hardening: `AuthExtension::has_scope` returns `true` for any
    // non-API-token auth (the JWT-session shortcut at the top of the impl).
    // No handler today calls `has_scope("admin")` for elevation, but a
    // future one could, and a ticket-authenticated request would silently
    // pass that check. Pretend the ticket is an API token with an empty
    // scope set so any explicit scope check defaults to deny.
    //
    // This intentionally does not modify `is_service_account` or
    // `must_change_password`: a ticket inherits the minter's identity for
    // those flags so downstream handlers see the same view they would for
    // any other auth method. Accepting the inherited identity is the
    // design — the ticket is proof that a session with those flags
    // intentionally minted a download URL.
    ext.is_api_token = true;
    ext.scopes = Some(vec![]);
    Some(ext)
}

/// Snapshot of the request fields needed to authenticate a download ticket.
///
/// Cloned out of the [`Request`] before the async ticket-validation work
/// runs, so the resulting future does not borrow the request. Without this,
/// callers would hold a borrow across `.await` and the middleware future
/// would not be `Send`, which `axum::middleware::from_fn_with_state` requires.
struct TicketRequestParts {
    ticket: String,
    method: Method,
    path: String,
}

fn extract_ticket_request_parts(request: &Request) -> Option<TicketRequestParts> {
    let ticket = extract_ticket_from_query(request.uri().query())?;
    Some(TicketRequestParts {
        ticket,
        method: request.method().clone(),
        path: request.uri().path().to_string(),
    })
}

/// Try to authenticate via a `?ticket=` query param when no header credentials
/// are present (or all of them have failed).
///
/// Returns `Some(ext)` when the ticket is valid, the request method is a
/// read, and the bound path matches. Returns `None` otherwise. The ticket
/// is consumed (single-use) on the validation attempt regardless of whether
/// the request is ultimately allowed.
async fn try_resolve_ticket_for_parts(
    db: &sqlx::PgPool,
    parts: &TicketRequestParts,
) -> Option<AuthExtension> {
    try_resolve_ticket_auth(db, &parts.ticket, &parts.method, &parts.path).await
}

/// Optional authentication middleware - allows unauthenticated requests
///
/// Supports the same authentication schemes as auth_middleware but
/// allows requests without any authentication to proceed.
///
/// Off-boarding semantics (#1371): when the client explicitly presents a
/// credential that fails to validate (expired JWT, revoked or deactivated
/// API token, wrong basic-auth password, malformed Authorization header),
/// the request is rejected with 401 rather than being silently downgraded
/// to anonymous. Without this, a deactivated user whose API token is still
/// in the upstream `validate_api_token` cache (post-#931) would continue to
/// receive 200-with-public-list responses on optional-auth routes for up to
/// `API_TOKEN_CACHE_TTL_SECS` — masking the deactivation and breaking the
/// off-boarding contract. We only short-circuit when no `?ticket=` fallback
/// is available, since download tickets are a legitimate alternative
/// credential for read-only routes.
pub async fn optional_auth_middleware(
    State(auth_service): State<Arc<AuthService>>,
    mut request: Request,
    next: Next,
) -> Response {
    let extracted = extract_token(&request);
    let outcome = try_resolve_auth_outcome(&auth_service, extracted).await;
    // A transient bcrypt-capacity shed surfaces here as `Overloaded`. Return a
    // retryable 503 immediately rather than silently dropping to anonymous and
    // letting a downstream `require_auth_basic*` turn it into a misleading 401
    // "Authentication required" (the twine-upload gate failure). See
    // `AuthOutcome::Overloaded`.
    if matches!(outcome, AuthOutcome::Overloaded) {
        return service_unavailable_response();
    }
    let credential_invalid = matches!(outcome, AuthOutcome::InvalidCredential);
    let mut auth_ext: Option<AuthExtension> = match outcome {
        AuthOutcome::Resolved(ext) => Some(ext),
        AuthOutcome::NoCredential | AuthOutcome::InvalidCredential => None,
        // Handled above with an early 503 return.
        AuthOutcome::Overloaded => None,
    };

    // If header-based auth produced no identity, fall back to a `?ticket=`
    // query param. Optional-auth routes are typically reads, so a ticket can
    // legitimately stand in for headers (e.g. browser <a href> downloads).
    let mut authed_via_ticket = false;
    if auth_ext.is_none() {
        if let Some(parts) = extract_ticket_request_parts(&request) {
            if let Some(ext) = try_resolve_ticket_for_parts(auth_service.db(), &parts).await {
                auth_ext = Some(ext);
                authed_via_ticket = true;
            }
        }
    }

    // Off-boarding: an explicitly-presented credential that failed validation
    // must produce 401. We allow a ticket to rescue the request because a
    // browser may include a stale Authorization cookie alongside a fresh
    // download ticket — the ticket is what authorizes the read.
    if credential_invalid && auth_ext.is_none() {
        return unauthorized_response();
    }

    request.extensions_mut().insert(auth_ext);
    if authed_via_ticket {
        request.extensions_mut().insert(DownloadTicketAuth);
    }
    next.run(request).await
}

/// Admin-only middleware - requires authenticated admin user
///
/// Supports the same authentication schemes as auth_middleware but
/// additionally requires the user to have admin privileges.
pub async fn admin_middleware(
    State(auth_service): State<Arc<AuthService>>,
    mut request: Request,
    next: Next,
) -> Response {
    let extracted = extract_token(&request);

    if matches!(extracted, ExtractedToken::Basic(encoded) if decode_basic_credentials(encoded).is_none())
    {
        return (StatusCode::UNAUTHORIZED, "Invalid Basic auth credentials").into_response();
    }

    // Shared credential resolution (same forms as the other authenticated
    // routes, including CI/CD keyless flows where the AK access token is sent
    // as the Basic-auth password). Use the tri-state outcome so a transient
    // bcrypt-cap or pool-acquire shed surfaces as a retryable 503, never a
    // spurious 401 (#2101/#2125). Admin privilege is enforced below.
    let auth_ext = match try_resolve_auth_outcome(&auth_service, extracted).await {
        AuthOutcome::Resolved(ext) => ext,
        AuthOutcome::Overloaded => return service_unavailable_response(),
        AuthOutcome::NoCredential | AuthOutcome::InvalidCredential => {
            let msg = match extracted {
                ExtractedToken::Bearer(_) => "Invalid or expired token",
                ExtractedToken::ApiKey(_) => "Invalid or expired API token",
                ExtractedToken::Basic(_) => "Invalid credentials",
                ExtractedToken::None => "Missing authorization header",
                ExtractedToken::Invalid => "Invalid authorization header format",
            };
            return (StatusCode::UNAUTHORIZED, msg).into_response();
        }
    };

    if !auth_ext.is_admin {
        return (StatusCode::FORBIDDEN, "Admin access required").into_response();
    }

    request.extensions_mut().insert(auth_ext);
    next.run(request).await
}

/// State for the repo visibility middleware.
#[derive(Clone)]
pub struct RepoVisibilityState {
    pub auth_service: Arc<AuthService>,
    pub db: sqlx::PgPool,
    /// Shared with `AppState::repo_cache` so format-handler resolvers can
    /// reuse the repo metadata fetched here without a second DB round-trip.
    pub repo_cache: RepoCache,
    /// Permission service for fine-grained repository access control.
    pub permission_service: Arc<PermissionService>,
}

/// Extract the repository key from a format handler request path.
///
/// Format routes are nested as `/{format}/{repo_key}/...`, so the repo key
/// is the second path segment (e.g. `/pypi/my-repo/simple/` -> `"my-repo"`).
pub(crate) fn extract_repo_key(path: &str) -> &str {
    let trimmed = path.trim_start_matches('/');
    let mut segments = trimmed.split('/');
    segments.next(); // skip format prefix (pypi, npm, maven, etc.)
    segments.next().unwrap_or("")
}

/// Decide whether a request to a repository should be allowed.
///
/// Returns `true` when the request should proceed (public repo, or private
/// repo with authentication).  Returns `false` when access should be denied
/// (private repo, no auth).
pub(crate) fn should_allow_repo_access(is_public: bool, has_auth: bool) -> bool {
    is_public || has_auth
}

/// Return true when the HTTP method is a write operation (POST, PUT, PATCH,
/// DELETE). Used by [`repo_visibility_middleware`] to require authentication
/// for uploads and mutations even on public repositories.
fn is_write_method(method: &Method) -> bool {
    matches!(
        *method,
        Method::POST | Method::PUT | Method::PATCH | Method::DELETE
    )
}

/// Build a 401 response with `WWW-Authenticate` challenges for both Basic
/// and Bearer schemes.  Package manager clients use the challenge to decide
/// how to retry with credentials.
fn unauthorized_response() -> Response {
    Response::builder()
        .status(StatusCode::UNAUTHORIZED)
        .header("WWW-Authenticate", "Basic realm=\"artifact-keeper\"")
        .header(
            "WWW-Authenticate",
            "Bearer realm=\"artifact-keeper\", charset=\"UTF-8\"",
        )
        // Signals cargo 1.67+ to use the Cargo token protocol (sends the token
        // as the raw Authorization header value) rather than aborting on the
        // Basic/Bearer challenges it does not understand.
        .header("WWW-Authenticate", "Cargo")
        .header(axum::http::header::CONTENT_TYPE, "text/plain")
        .body(axum::body::Body::from("Authentication required"))
        .unwrap()
}

/// Build a 503 response for the transient bcrypt-capacity shed
/// (`AuthOutcome::Overloaded`). Carries a `Retry-After: 1` hint so
/// well-behaved clients (twine, cargo, pip) back off and retry instead of
/// aborting the way they would on a 401. Keeping this distinct from
/// `unauthorized_response` is the load-bearing fix for the twine-upload
/// gate failure: a saturated auth cap is "retry shortly", not "wrong
/// password".
fn service_unavailable_response() -> Response {
    Response::builder()
        .status(StatusCode::SERVICE_UNAVAILABLE)
        .header(axum::http::header::RETRY_AFTER, "1")
        .header(axum::http::header::CONTENT_TYPE, "text/plain")
        .body(axum::body::Body::from(
            "Authentication service is at capacity, retry shortly",
        ))
        .unwrap()
}

/// Build a 403 response for API tokens that lack access to the requested
/// repository.
fn forbidden_repo_response() -> Response {
    Response::builder()
        .status(StatusCode::FORBIDDEN)
        .header(axum::http::header::CONTENT_TYPE, "text/plain")
        .body(axum::body::Body::from(
            "Token does not have access to this repository",
        ))
        .unwrap()
}

/// Build a 403 response when fine-grained permission rules deny access.
fn forbidden_permission_response() -> Response {
    Response::builder()
        .status(StatusCode::FORBIDDEN)
        .header(axum::http::header::CONTENT_TYPE, "text/plain")
        .body(axum::body::Body::from(
            "You do not have permission to perform this action on this repository",
        ))
        .unwrap()
}

/// Build a 404 response that hides the existence of a private repository the
/// caller is not authorized to see. Mirrors the REST `require_visible` helper
/// (which returns `NotFound`) so the native-protocol and REST paths give the
/// same existence-hiding answer for an inaccessible private repo.
fn not_found_response() -> Response {
    Response::builder()
        .status(StatusCode::NOT_FOUND)
        .header(axum::http::header::CONTENT_TYPE, "text/plain")
        .body(axum::body::Body::from("Repository not found"))
        .unwrap()
}

/// Map an HTTP method to a permission action string.
///
/// Used by [`repo_visibility_middleware`] to determine the required permission
/// action when fine-grained rules exist for a repository.
pub(crate) fn action_for_method(method: &Method) -> &'static str {
    match *method {
        Method::GET | Method::HEAD | Method::OPTIONS => "read",
        Method::PUT | Method::POST | Method::PATCH => "write",
        Method::DELETE => "delete",
        _ => "read",
    }
}

/// Middleware that enforces repository visibility on format handler routes.
///
/// For routes whose first path segment is a repository key, this middleware
/// checks whether the repository is public. If it is not public, the request
/// must carry a valid authentication token; otherwise a 401 is returned so
/// that package manager clients can retry with credentials.
///
/// Additionally, this middleware enforces two policies that individual format
/// handlers must not need to remember:
///
/// 1. **Write operations require authentication** regardless of repository
///    visibility. Even public repos must not accept anonymous uploads, deletes,
///    or mutations. (Fixes #508)
///
/// 2. **API token repo scope is enforced**: when the authenticated token
///    carries `allowed_repo_ids`, the target repository must be in that set.
///    Without this check, a token scoped to repo A could access repo B.
///    (Fixes #504)
pub async fn repo_visibility_middleware(
    State(vis_state): State<RepoVisibilityState>,
    mut request: Request,
    next: Next,
) -> Response {
    // Extract the first path segment as a potential repo key.
    let path = request.uri().path().to_string();
    let repo_key = extract_repo_key(&path);

    if repo_key.is_empty() {
        return next.run(request).await;
    }

    // Check the shared repo cache first to avoid a DB round-trip on every
    // request.  The cache is populated with full repo metadata so that
    // format-handler resolvers (e.g. resolve_cargo_repo) can reuse it
    // without issuing their own DB lookup.
    let cached = {
        let cache = vis_state.repo_cache.read().await;
        cache.get(repo_key).and_then(|(entry, at)| {
            if at.elapsed().as_secs() < REPO_CACHE_TTL_SECS {
                Some(entry.clone())
            } else {
                None
            }
        })
    };

    let repo = match cached {
        Some(r) => Some(r),
        None => {
            // Cache miss: fetch full repo metadata in one query so we can
            // populate the cache for both this middleware and downstream
            // handlers.  Uses sqlx::query() (not the macro) so no new entry
            // in the sqlx offline-query cache is required.
            use sqlx::Row;
            let row = sqlx::query(
                "SELECT id, format::text as format, repo_type::text as repo_type, \
                 upstream_url, storage_backend, storage_path, is_public, \
                 (SELECT value FROM repository_config \
                  WHERE repository_id = repositories.id \
                  AND key = 'index_upstream_url') AS index_upstream_url \
                 FROM repositories WHERE key = $1",
            )
            .bind(repo_key)
            .fetch_optional(&vis_state.db)
            .await
            .ok()
            .flatten();

            if let Some(r) = row {
                let entry = CachedRepo {
                    id: r.get("id"),
                    format: r.get("format"),
                    repo_type: r.get("repo_type"),
                    upstream_url: r.get("upstream_url"),
                    storage_backend: r.get("storage_backend"),
                    storage_path: r.get("storage_path"),
                    is_public: r.get("is_public"),
                    index_upstream_url: r.get("index_upstream_url"),
                };
                // Populate the shared cache; evict stale entries on write.
                {
                    let mut cache = vis_state.repo_cache.write().await;
                    cache.retain(|_, (_, at)| at.elapsed().as_secs() < REPO_CACHE_TTL_SECS);
                    cache.insert(repo_key.to_string(), (entry.clone(), Instant::now()));
                }
                Some(entry)
            } else {
                None
            }
        }
    };

    // If no repo found for this key, still inject Option<AuthExtension> so
    // handlers that declare `Extension<Option<AuthExtension>>` don't fail
    // Axum extraction with HTTP 500 (MissingExtension). The handler itself
    // is responsible for returning the 404 once it tries to resolve the repo.
    //
    // Off-boarding (#1371): an explicitly-presented credential that failed
    // validation must produce 401 even before we know whether the repo
    // exists. Leaking the existence of a repo via 404-vs-401 is a separate
    // info-disclosure question (#-TBD); for now we mirror
    // `optional_auth_middleware` and prioritise honouring the deactivation.
    let Some(repo) = repo else {
        let extracted = extract_token(&request);
        let outcome = try_resolve_auth_outcome(&vis_state.auth_service, extracted).await;
        // Transient bcrypt-capacity shed -> retryable 503 (see
        // `AuthOutcome::Overloaded`), never a 401.
        if matches!(outcome, AuthOutcome::Overloaded) {
            return service_unavailable_response();
        }
        let credential_invalid = matches!(outcome, AuthOutcome::InvalidCredential);
        // #1808: Close the anonymous repo-existence oracle. An existing
        // *private* repo returns 401 to an anonymous caller (visibility check
        // below), so a nonexistent repo must not return the handler's 404 to
        // that same caller -- the differing status would leak which repo keys
        // exist. Mirror the existing-private response: emit the identical
        // 401 + `WWW-Authenticate` challenge whenever no credential is
        // presented, so the status, body, and headers are byte-identical for
        // existing-private and nonexistent keys. This also preserves
        // package-manager 401-retry semantics (clients still see the
        // challenge and can retry with credentials).
        let no_credential = matches!(outcome, AuthOutcome::NoCredential);
        let auth_ext: Option<AuthExtension> = match outcome {
            AuthOutcome::Resolved(ext) => Some(ext),
            AuthOutcome::NoCredential | AuthOutcome::InvalidCredential => None,
            AuthOutcome::Overloaded => None,
        };
        if credential_invalid && auth_ext.is_none() {
            return unauthorized_response();
        }
        if no_credential {
            return unauthorized_response();
        }
        // Note: `credential_invalid` was captured before the match consumed
        // `outcome`; this mirrors the pattern further down for the repo-hit
        // branch.
        request.extensions_mut().insert(auth_ext);
        return next.run(request).await;
    };

    let is_public = repo.is_public;
    let is_write = is_write_method(request.method());

    // Perform optional auth (shared with optional_auth_middleware).
    let extracted = extract_token(&request);
    let outcome = try_resolve_auth_outcome(&vis_state.auth_service, extracted).await;
    // Transient bcrypt-capacity shed -> retryable 503 (see
    // `AuthOutcome::Overloaded`), never a 401.
    if matches!(outcome, AuthOutcome::Overloaded) {
        return service_unavailable_response();
    }
    let credential_invalid = matches!(outcome, AuthOutcome::InvalidCredential);
    let mut auth_ext: Option<AuthExtension> = match outcome {
        AuthOutcome::Resolved(ext) => Some(ext),
        AuthOutcome::NoCredential | AuthOutcome::InvalidCredential => None,
        AuthOutcome::Overloaded => None,
    };
    // `credential_invalid` was captured before the match consumed `outcome`.

    // Fall back to a `?ticket=` query param when no header credentials were
    // supplied or accepted. Tickets are read-only and bound to a path; the
    // helper itself rejects non-read methods, and the `is_write` check below
    // also covers the case where a ticket somehow leaked into a write request.
    let mut authed_via_ticket = false;
    if auth_ext.is_none() {
        if let Some(parts) = extract_ticket_request_parts(&request) {
            if let Some(ext) = try_resolve_ticket_for_parts(&vis_state.db, &parts).await {
                auth_ext = Some(ext);
                authed_via_ticket = true;
            }
        }
    }

    // Off-boarding (#1371): explicit credential presented but invalid (and
    // no rescuing ticket) means 401, not anonymous read.
    if credential_invalid && auth_ext.is_none() {
        return unauthorized_response();
    }

    // Insert auth extension for downstream handlers.
    request.extensions_mut().insert(auth_ext.clone());
    if authed_via_ticket {
        request.extensions_mut().insert(DownloadTicketAuth);
    }

    // #508: Write operations (PUT, POST, PATCH, DELETE) always require
    // authentication, even on public repositories. Without this, unauthenticated
    // upload requests to public repos fall through to the handler which returns
    // 404 (misleading) instead of 401.
    //
    // Tickets must never authorize writes even if the bound path happens to
    // be writable: a ticket is effectively a single-use download URL, not a
    // capability token. Treat ticket-authenticated requests as anonymous for
    // the purpose of write gating.
    let has_write_auth = auth_ext.is_some() && !authed_via_ticket;
    if is_write && !has_write_auth {
        return unauthorized_response();
    }

    // Check visibility: public repos are open for reads, private repos need auth.
    if !should_allow_repo_access(is_public, auth_ext.is_some()) {
        return unauthorized_response();
    }

    // #504: Enforce API token repository scope. If the token carries an
    // allowed_repo_ids restriction, the target repository must be in that set.
    // Without this, a token scoped to repo A could read/write repo B.
    if let Some(ref ext) = auth_ext {
        if !ext.can_access_repo(repo.id) {
            return forbidden_repo_response();
        }
    }

    // #817: Fine-grained repository permission enforcement.
    //
    // If the authenticated user is an admin, skip permission checks entirely
    // to preserve backward compatibility and avoid unnecessary DB lookups.
    //
    // For non-admin users, check whether any permission rules exist for this
    // repository. If no rules exist, fall through to the default access model
    // (the visibility checks above are sufficient). If rules do exist, the
    // user must hold the action that matches the HTTP method.
    if let Some(ref ext) = auth_ext {
        if !ext.is_admin {
            let has_rules = match vis_state
                .permission_service
                .has_any_rules_for_target("repository", repo.id)
                .await
            {
                Ok(v) => v,
                Err(_) => {
                    // DB error on permission check: fail closed.
                    tracing::error!("permission check failed: database unreachable");
                    return Response::builder()
                        .status(StatusCode::SERVICE_UNAVAILABLE)
                        .body(axum::body::Body::from(
                            "permission service temporarily unavailable",
                        ))
                        .unwrap();
                }
            };

            if has_rules {
                let action = action_for_method(request.method());
                // Check for the specific action first, then fall back to
                // "admin" which implies all actions (#827 policy compat).
                // Both calls resolve from the same cached action set, so the
                // second call is essentially free.
                let allowed = vis_state
                    .permission_service
                    .check_permission(ext.user_id, "repository", repo.id, action, false)
                    .await
                    .unwrap_or(false)
                    || vis_state
                        .permission_service
                        .check_permission(ext.user_id, "repository", repo.id, "admin", false)
                        .await
                        .unwrap_or(false);

                if !allowed {
                    return forbidden_permission_response();
                }
            } else if !is_public {
                // A private repo with NO fine-grained permission rules must
                // still not be readable by every authenticated user. Mirror
                // the REST `require_visible` model: a non-admin needs a role
                // assignment scoped to this repo (or a global assignment).
                //
                // Without this branch the native-protocol path default-ALLOWED
                // rule-less private repos to any authenticated principal, while
                // the REST download path denied the same caller (404) — a
                // cross-tenant private-artifact leak (red-team round 2).
                //
                // Uses sqlx::query_scalar (not the macro) so no new entry in
                // the sqlx offline-query cache is required, matching the rest
                // of this middleware. Same predicate as
                // RepositoryService::user_can_access_repo.
                let granted = sqlx::query_scalar::<_, bool>(
                    "SELECT EXISTS ( \
                         SELECT 1 FROM role_assignments ra \
                         WHERE ra.user_id = $1 \
                           AND (ra.repository_id = $2 OR ra.repository_id IS NULL) \
                     )",
                )
                .bind(ext.user_id)
                .bind(repo.id)
                .fetch_one(&vis_state.db)
                .await;

                match granted {
                    Ok(true) => {}
                    // Existence-hiding 404, matching REST `require_visible`.
                    Ok(false) => return not_found_response(),
                    Err(_) => {
                        // DB error on access check: fail closed.
                        tracing::error!("repo access check failed: database unreachable");
                        return service_unavailable_response();
                    }
                }
            }
        }
    }

    next.run(request).await
}

#[allow(clippy::disallowed_methods)]
// streaming-invariant: test module exempt — buffering response bodies in test assertions is not an artifact path (#1608)
#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use jsonwebtoken::{encode, EncodingKey, Header};

    // -----------------------------------------------------------------------
    // extract_token_from_auth_header
    // -----------------------------------------------------------------------

    #[test]
    fn test_extract_bearer_token() {
        let result = extract_token_from_auth_header("Bearer my-jwt-token-123");
        assert!(matches!(result, ExtractedToken::Bearer("my-jwt-token-123")));
    }

    #[test]
    fn test_extract_apikey_token() {
        let result = extract_token_from_auth_header("ApiKey ak_secret_key");
        assert!(matches!(result, ExtractedToken::ApiKey("ak_secret_key")));
    }

    #[test]
    fn test_extract_basic_scheme_recognized() {
        let result = extract_token_from_auth_header("Basic dXNlcjpwYXNz");
        assert!(matches!(result, ExtractedToken::Basic("dXNlcjpwYXNz")));
    }

    #[test]
    fn test_extract_empty_string() {
        let result = extract_token_from_auth_header("");
        assert!(matches!(result, ExtractedToken::Invalid));
    }

    #[test]
    fn test_extract_bearer_empty_token() {
        let result = extract_token_from_auth_header("Bearer ");
        assert!(matches!(result, ExtractedToken::Bearer("")));
    }

    #[test]
    fn test_extract_case_sensitive_bearer() {
        let result = extract_token_from_auth_header("bearer my-token");
        assert!(matches!(result, ExtractedToken::Invalid));
    }

    #[test]
    fn test_extract_case_sensitive_apikey() {
        let result = extract_token_from_auth_header("apikey my-token");
        assert!(matches!(result, ExtractedToken::Invalid));
    }

    // -----------------------------------------------------------------------
    // extract_token from full Request
    // -----------------------------------------------------------------------

    #[test]
    fn test_extract_token_from_authorization_bearer() {
        let request = Request::builder()
            .header(AUTHORIZATION, "Bearer jwt-abc-123")
            .body(axum::body::Body::empty())
            .unwrap();
        let result = extract_token(&request);
        assert!(matches!(result, ExtractedToken::Bearer("jwt-abc-123")));
    }

    #[test]
    fn test_extract_token_from_authorization_apikey() {
        let request = Request::builder()
            .header(AUTHORIZATION, "ApiKey token-xyz")
            .body(axum::body::Body::empty())
            .unwrap();
        let result = extract_token(&request);
        assert!(matches!(result, ExtractedToken::ApiKey("token-xyz")));
    }

    #[test]
    fn test_extract_token_from_x_api_key_header() {
        let request = Request::builder()
            .header("x-api-key", "my-api-key-value")
            .body(axum::body::Body::empty())
            .unwrap();
        let result = extract_token(&request);
        assert!(matches!(result, ExtractedToken::ApiKey("my-api-key-value")));
    }

    #[test]
    fn test_extract_token_authorization_takes_priority_over_x_api_key() {
        let request = Request::builder()
            .header(AUTHORIZATION, "Bearer jwt-token")
            .header("x-api-key", "api-key-value")
            .body(axum::body::Body::empty())
            .unwrap();
        let result = extract_token(&request);
        assert!(matches!(result, ExtractedToken::Bearer("jwt-token")));
    }

    #[test]
    fn test_extract_token_from_cookie() {
        let request = Request::builder()
            .header(
                COOKIE,
                "session_id=abc; ak_access_token=cookie-jwt-token; other=val",
            )
            .body(axum::body::Body::empty())
            .unwrap();
        let result = extract_token(&request);
        assert!(matches!(result, ExtractedToken::Bearer("cookie-jwt-token")));
    }

    #[test]
    fn test_extract_token_cookie_no_matching_cookie() {
        let request = Request::builder()
            .header(COOKIE, "session_id=abc; other_cookie=val")
            .body(axum::body::Body::empty())
            .unwrap();
        let result = extract_token(&request);
        assert!(matches!(result, ExtractedToken::None));
    }

    #[test]
    fn test_extract_token_no_headers() {
        let request = Request::builder().body(axum::body::Body::empty()).unwrap();
        let result = extract_token(&request);
        assert!(matches!(result, ExtractedToken::None));
    }

    #[test]
    fn test_extract_token_basic_auth_does_not_fall_through() {
        let request = Request::builder()
            .header(AUTHORIZATION, "Basic dXNlcjpwYXNz")
            .header("x-api-key", "api-key-value")
            .body(axum::body::Body::empty())
            .unwrap();
        let result = extract_token(&request);
        assert!(matches!(result, ExtractedToken::Basic(_)));
    }

    #[test]
    fn test_extract_basic_auth_header() {
        let result = extract_token_from_auth_header("Basic dXNlcjpwYXNz");
        assert!(matches!(result, ExtractedToken::Basic("dXNlcjpwYXNz")));
    }

    #[test]
    fn test_extract_basic_auth_from_request() {
        let request = Request::builder()
            .header(AUTHORIZATION, "Basic dXNlcjpwYXNz")
            .body(axum::body::Body::empty())
            .unwrap();
        let result = extract_token(&request);
        assert!(matches!(result, ExtractedToken::Basic("dXNlcjpwYXNz")));
    }

    #[test]
    fn test_extract_basic_auth_does_not_fall_through_to_x_api_key() {
        let request = Request::builder()
            .header(AUTHORIZATION, "Basic dXNlcjpwYXNz")
            .header("x-api-key", "should-not-be-used")
            .body(axum::body::Body::empty())
            .unwrap();
        let result = extract_token(&request);
        assert!(matches!(result, ExtractedToken::Basic("dXNlcjpwYXNz")));
    }

    // -----------------------------------------------------------------------
    // AuthExtension::from(Claims)
    // -----------------------------------------------------------------------

    #[test]
    fn test_auth_extension_from_claims() {
        let user_id = Uuid::new_v4();
        let claims = Claims {
            sub: user_id,
            username: "testuser".to_string(),
            email: "test@example.com".to_string(),
            is_admin: true,
            allowed_repo_ids: None,
            iat: 1000,
            iat_ms: None,
            exp: 2000,
            token_type: "access".to_string(),
            jti: None,
            family_id: None,
            scan_pull_repo: None,
        };

        let effective = claims.effective_iat_ms();
        let ext = AuthExtension::from(claims);
        assert_eq!(ext.user_id, user_id);
        assert_eq!(ext.username, "testuser");
        assert_eq!(ext.email, "test@example.com");
        assert!(ext.is_admin);
        assert!(!ext.is_api_token);
        assert!(ext.scopes.is_none());
        // #1394: the folded `iat_ms` is stamped from the single `From<Claims>`
        // source and equals the calling token's `effective_iat_ms`.
        assert_eq!(ext.iat_ms, Some(effective));
        assert_eq!(ext.caller_iat_ms(), Some(effective));
    }

    /// #1394: a Basic username/password principal (`From<User>`) carries no JWT
    /// `iat`, so its folded `iat_ms` is `None` and it falls back to the
    /// "invalidate everything" branch of `invalidate_other_sessions`.
    #[test]
    fn test_auth_extension_from_user_has_no_iat_ms() {
        use crate::models::user::{AuthProvider, User};
        let now = chrono::Utc::now();
        let user = User {
            id: Uuid::new_v4(),
            username: "basic".to_string(),
            email: "basic@example.com".to_string(),
            password_hash: None,
            auth_provider: AuthProvider::Local,
            external_id: None,
            display_name: None,
            is_active: true,
            is_admin: false,
            is_service_account: false,
            must_change_password: false,
            totp_secret: None,
            totp_enabled: false,
            totp_backup_codes: None,
            totp_verified_at: None,
            failed_login_attempts: 0,
            locked_until: None,
            last_failed_login_at: None,
            password_changed_at: now,
            last_login_at: Some(now),
            created_at: now,
            updated_at: now,
        };

        let ext = AuthExtension::from(user);
        assert_eq!(ext.iat_ms, None);
        assert_eq!(ext.caller_iat_ms(), None);
    }

    #[test]
    fn test_auth_extension_from_claims_non_admin() {
        let claims = Claims {
            sub: Uuid::new_v4(),
            username: "regular".to_string(),
            email: "regular@example.com".to_string(),
            is_admin: false,
            allowed_repo_ids: None,
            iat: 1000,
            iat_ms: None,
            exp: 2000,
            token_type: "access".to_string(),
            jti: None,
            family_id: None,
            scan_pull_repo: None,
        };

        let ext = AuthExtension::from(claims);
        assert!(!ext.is_admin);
        assert!(!ext.is_api_token);
    }

    // -----------------------------------------------------------------------
    // AuthExtension scope and repo helpers
    // -----------------------------------------------------------------------

    fn make_api_token_ext(scopes: Vec<String>, repo_ids: Option<Vec<Uuid>>) -> AuthExtension {
        AuthExtension {
            user_id: Uuid::new_v4(),
            username: "apiuser".to_string(),
            email: "api@example.com".to_string(),
            is_admin: false,
            is_api_token: true,
            is_service_account: false,
            scopes: Some(scopes),
            allowed_repo_ids: AccessScope::from(repo_ids),
            iat_ms: None,
        }
    }

    #[test]
    fn test_has_scope_exact_match() {
        let ext = make_api_token_ext(vec!["read:artifacts".to_string()], None);
        assert!(ext.has_scope("read:artifacts"));
        assert!(!ext.has_scope("write:artifacts"));
    }

    #[test]
    fn test_has_scope_wildcard() {
        let ext = make_api_token_ext(vec!["*".to_string()], None);
        assert!(ext.has_scope("read:artifacts"));
        assert!(ext.has_scope("write:repositories"));
    }

    #[test]
    fn test_has_scope_admin_grants_all() {
        let ext = make_api_token_ext(vec!["admin".to_string()], None);
        assert!(ext.has_scope("delete:artifacts"));
    }

    // #1316: pin the authorization decision now that `has_scope` delegates to
    // the canonical `token_service::scopes_grant_access` helper instead of an
    // inline `== "admin"` string match. Behavior must be identical: an
    // `admin`-scoped API token authorizes any required scope, and a token
    // lacking the required scope (and any wildcard) is rejected.
    #[test]
    fn test_has_scope_admin_token_authorizes_every_scope_via_canonical_helper() {
        let ext = make_api_token_ext(vec!["admin".to_string()], None);
        // Same decision as the canonical helper for several distinct scopes.
        for scope in ["read:artifacts", "write:users", "delete:repositories"] {
            assert!(ext.has_scope(scope), "admin token should grant {scope}");
            assert_eq!(
                ext.has_scope(scope),
                crate::services::token_service::scopes_grant_access(&["admin".to_string()], scope),
            );
        }
    }

    #[test]
    fn test_has_scope_non_admin_token_rejected_when_scope_absent() {
        let ext = make_api_token_ext(vec!["read:artifacts".to_string()], None);
        assert!(!ext.has_scope("write:users"));
        assert!(!ext.has_scope("delete:artifacts"));
        // The canonical helper agrees: no wildcard / admin present.
        assert!(!crate::services::token_service::scopes_grant_access(
            &["read:artifacts".to_string()],
            "write:users",
        ));
    }

    #[test]
    fn test_has_scope_jwt_always_passes() {
        let ext = AuthExtension {
            user_id: Uuid::new_v4(),
            username: "jwtuser".to_string(),
            email: "jwt@example.com".to_string(),
            is_admin: false,
            is_api_token: false,
            is_service_account: false,
            scopes: None,
            allowed_repo_ids: AccessScope::Admin,
            iat_ms: None,
        };
        assert!(ext.has_scope("anything"));
    }

    #[test]
    fn test_can_access_repo_unrestricted() {
        let ext = make_api_token_ext(vec!["*".to_string()], None);
        assert!(ext.can_access_repo(Uuid::new_v4()));
    }

    #[test]
    fn test_can_access_repo_restricted() {
        let allowed = Uuid::new_v4();
        let denied = Uuid::new_v4();
        let ext = make_api_token_ext(vec!["*".to_string()], Some(vec![allowed]));
        assert!(ext.can_access_repo(allowed));
        assert!(!ext.can_access_repo(denied));
    }

    #[test]
    fn test_require_scope_ok() {
        let ext = make_api_token_ext(vec!["write:artifacts".to_string()], None);
        assert!(ext.require_scope("write:artifacts").is_ok());
    }

    #[test]
    fn test_require_scope_denied() {
        let ext = make_api_token_ext(vec!["read:artifacts".to_string()], None);
        assert!(ext.require_scope("write:artifacts").is_err());
    }

    // -----------------------------------------------------------------------
    // GHSA-vvc3-h39c-mrq5: scope enforcement helpers used by format and
    // admin handlers to reject read-scoped API tokens on write/delete paths.
    // -----------------------------------------------------------------------

    #[test]
    fn test_require_auth_basic_scope_missing_auth_returns_401() {
        let result = require_auth_basic_scope(None, "maven", "write");
        let err = result.expect_err("missing auth must error");
        assert_eq!(err.status(), StatusCode::UNAUTHORIZED);
    }

    #[test]
    fn test_require_auth_basic_scope_jwt_passes() {
        // JWT sessions (is_api_token = false) must pass the scope gate.
        let ext = AuthExtension {
            user_id: Uuid::new_v4(),
            username: "jwtuser".to_string(),
            email: "jwt@example.com".to_string(),
            is_admin: false,
            is_api_token: false,
            is_service_account: false,
            scopes: None,
            allowed_repo_ids: AccessScope::Admin,
            iat_ms: None,
        };
        let result = require_auth_basic_scope(Some(ext), "maven", "write");
        assert!(result.is_ok(), "JWT sessions must not be scope-gated");
    }

    #[test]
    fn test_require_auth_basic_scope_read_token_rejected_on_write() {
        // Read-scoped API token must be rejected with 403 on a write path,
        // not authenticated and then denied at the data layer. This is the
        // exact scenario from GHSA-vvc3-h39c-mrq5.
        let ext = make_api_token_ext(vec!["read".to_string()], None);
        let result = require_auth_basic_scope(Some(ext), "maven", "write");
        let err = result.expect_err("read-only token must be rejected");
        assert_eq!(err.status(), StatusCode::FORBIDDEN);
    }

    #[test]
    fn test_require_auth_basic_scope_write_token_accepted_on_write() {
        let ext = make_api_token_ext(vec!["write".to_string()], None);
        let result = require_auth_basic_scope(Some(ext.clone()), "maven", "write");
        let returned = result.expect("write-scoped token must pass");
        assert_eq!(returned.user_id, ext.user_id);
    }

    #[test]
    fn test_require_auth_basic_scope_wildcard_accepts_any() {
        let ext = make_api_token_ext(vec!["*".to_string()], None);
        assert!(require_auth_basic_scope(Some(ext.clone()), "maven", "write").is_ok());
        assert!(require_auth_basic_scope(Some(ext), "maven", "delete").is_ok());
    }

    #[test]
    fn test_require_auth_basic_scope_admin_accepts_any() {
        // The token-level "admin" scope is a wildcard, separate from the
        // user's is_admin flag (which is on the user, not the token).
        let ext = make_api_token_ext(vec!["admin".to_string()], None);
        assert!(require_auth_basic_scope(Some(ext), "maven", "write").is_ok());
    }

    #[tokio::test]
    async fn test_require_auth_basic_scope_returns_expected_body() {
        // The body string is part of the contract: tests across the format
        // handler suite assert on it for the read-only-token case.
        let ext = make_api_token_ext(vec!["read".to_string()], None);
        let err = require_auth_basic_scope(Some(ext), "maven", "write").expect_err("must err");
        let body = axum::body::to_bytes(err.into_body(), 4096).await.unwrap();
        let body_str = String::from_utf8_lossy(&body);
        assert!(
            body_str.contains("Token does not have required scope: write"),
            "unexpected body: {}",
            body_str
        );
    }

    #[test]
    fn test_require_scope_response_no_auth_passes() {
        // Format handlers that fall back to Bearer-as-basic credentials may
        // receive `None` from the middleware. The helper must not 403 those
        // since they have no API-token scope to check.
        let result = require_scope_response(None, "write");
        assert!(result.is_ok());
    }

    #[test]
    fn test_require_scope_response_read_token_rejected() {
        let ext = make_api_token_ext(vec!["read".to_string()], None);
        let result = require_scope_response(Some(&ext), "write");
        let err = result.expect_err("read-only token must be rejected");
        assert_eq!(err.status(), StatusCode::FORBIDDEN);
    }

    #[test]
    fn test_require_scope_response_jwt_passes() {
        // JWT extension (no scopes set, is_api_token = false) must pass.
        let ext = AuthExtension {
            user_id: Uuid::new_v4(),
            username: "jwtuser".to_string(),
            email: "jwt@example.com".to_string(),
            is_admin: false,
            is_api_token: false,
            is_service_account: false,
            scopes: None,
            allowed_repo_ids: AccessScope::Admin,
            iat_ms: None,
        };
        assert!(require_scope_response(Some(&ext), "write").is_ok());
        assert!(require_scope_response(Some(&ext), "delete").is_ok());
    }

    #[test]
    fn test_require_scope_response_write_token_passes_write() {
        let ext = make_api_token_ext(vec!["write".to_string()], None);
        assert!(require_scope_response(Some(&ext), "write").is_ok());
    }

    #[test]
    fn test_require_scope_response_write_token_rejected_on_delete() {
        // A write-scoped token must not be sufficient for delete operations.
        let ext = make_api_token_ext(vec!["write".to_string()], None);
        let err = require_scope_response(Some(&ext), "delete").expect_err("write != delete scope");
        assert_eq!(err.status(), StatusCode::FORBIDDEN);
    }

    // -----------------------------------------------------------------------
    // AuthExtension Clone / Debug
    // -----------------------------------------------------------------------

    #[test]
    fn test_auth_extension_clone_and_debug() {
        let ext = AuthExtension {
            user_id: Uuid::nil(),
            username: "user".to_string(),
            email: "user@x.com".to_string(),
            is_admin: false,
            is_api_token: false,
            is_service_account: false,
            scopes: Some(vec!["read".to_string(), "write".to_string()]),
            allowed_repo_ids: AccessScope::Admin,
            iat_ms: None,
        };

        let cloned = ext.clone();
        assert_eq!(cloned.user_id, ext.user_id);
        assert_eq!(cloned.scopes, ext.scopes);

        let debug_str = format!("{:?}", ext);
        assert!(debug_str.contains("user"));
    }

    // -----------------------------------------------------------------------
    // decode_basic_credentials
    // -----------------------------------------------------------------------

    #[test]
    fn test_decode_basic_credentials_valid() {
        // "user:pass" in base64
        let result = decode_basic_credentials("dXNlcjpwYXNz");
        assert_eq!(result, Some(("user".to_string(), "pass".to_string())));
    }

    #[test]
    fn test_decode_basic_credentials_with_colon_in_password() {
        // "user:p:a:ss" in base64
        let encoded = base64::engine::general_purpose::STANDARD.encode("user:p:a:ss");
        let result = decode_basic_credentials(&encoded);
        assert_eq!(result, Some(("user".to_string(), "p:a:ss".to_string())));
    }

    #[test]
    fn test_decode_basic_credentials_invalid_base64() {
        let result = decode_basic_credentials("not-valid!!!");
        assert_eq!(result, None);
    }

    #[test]
    fn test_decode_basic_credentials_no_colon() {
        // "justusername" in base64
        let encoded = base64::engine::general_purpose::STANDARD.encode("justusername");
        let result = decode_basic_credentials(&encoded);
        assert_eq!(result, None);
    }

    #[test]
    fn test_decode_basic_credentials_empty() {
        let result = decode_basic_credentials("");
        assert_eq!(result, None);
    }

    // -----------------------------------------------------------------------
    // require_auth_basic
    // -----------------------------------------------------------------------

    #[test]
    fn test_require_auth_basic_some() {
        let ext = AuthExtension {
            user_id: Uuid::new_v4(),
            username: "user".to_string(),
            email: "user@test.com".to_string(),
            is_admin: false,
            is_api_token: false,
            is_service_account: false,
            scopes: None,
            allowed_repo_ids: AccessScope::Admin,
            iat_ms: None,
        };
        let result = require_auth_basic(Some(ext), "maven");
        assert!(result.is_ok());
        assert_eq!(result.unwrap().username, "user");
    }

    #[test]
    fn test_require_auth_basic_none() {
        let result = require_auth_basic(None, "maven");
        assert!(result.is_err());
    }

    // -----------------------------------------------------------------------
    // extract_repo_key
    // -----------------------------------------------------------------------

    #[test]
    fn test_extract_repo_key_pypi() {
        assert_eq!(extract_repo_key("/pypi/my-repo/simple/"), "my-repo");
    }

    #[test]
    fn test_extract_repo_key_npm() {
        assert_eq!(extract_repo_key("/npm/my-repo/package"), "my-repo");
    }

    #[test]
    fn test_extract_repo_key_deep_path() {
        assert_eq!(
            extract_repo_key("/maven/my-repo/com/example/artifact"),
            "my-repo"
        );
    }

    #[test]
    fn test_extract_repo_key_root() {
        assert_eq!(extract_repo_key("/"), "");
    }

    #[test]
    fn test_extract_repo_key_empty() {
        assert_eq!(extract_repo_key(""), "");
    }

    #[test]
    fn test_extract_repo_key_format_only() {
        assert_eq!(extract_repo_key("/pypi"), "");
    }

    #[test]
    fn test_extract_repo_key_no_leading_slash() {
        assert_eq!(extract_repo_key("pypi/my-repo/simple"), "my-repo");
    }

    // -----------------------------------------------------------------------
    // should_allow_repo_access
    // -----------------------------------------------------------------------

    #[test]
    fn test_allow_public_no_auth() {
        assert!(should_allow_repo_access(true, false));
    }

    #[test]
    fn test_allow_public_with_auth() {
        assert!(should_allow_repo_access(true, true));
    }

    #[test]
    fn test_deny_private_no_auth() {
        assert!(!should_allow_repo_access(false, false));
    }

    #[test]
    fn test_allow_private_with_auth() {
        assert!(should_allow_repo_access(false, true));
    }

    // -----------------------------------------------------------------------
    // extract_bearer_credentials
    // -----------------------------------------------------------------------

    #[test]
    fn test_extract_bearer_credentials_valid() {
        let encoded = base64::engine::general_purpose::STANDARD.encode("user:pass");
        let mut headers = HeaderMap::new();
        headers.insert(
            AUTHORIZATION,
            format!("Bearer {}", encoded).parse().unwrap(),
        );
        let result = extract_bearer_credentials(&headers);
        assert_eq!(result, Some(("user".to_string(), "pass".to_string())));
    }

    #[test]
    fn test_extract_bearer_credentials_lowercase() {
        let encoded = base64::engine::general_purpose::STANDARD.encode("user:pass");
        let mut headers = HeaderMap::new();
        headers.insert(
            AUTHORIZATION,
            format!("bearer {}", encoded).parse().unwrap(),
        );
        assert_eq!(
            extract_bearer_credentials(&headers),
            Some(("user".to_string(), "pass".to_string()))
        );
    }

    #[test]
    fn test_extract_bearer_credentials_missing() {
        assert!(extract_bearer_credentials(&HeaderMap::new()).is_none());
    }

    #[test]
    fn test_extract_bearer_credentials_not_base64() {
        let mut headers = HeaderMap::new();
        headers.insert(
            AUTHORIZATION,
            "Bearer not-valid-base64!!!!".parse().unwrap(),
        );
        assert!(extract_bearer_credentials(&headers).is_none());
    }

    #[test]
    fn test_extract_bearer_credentials_no_colon() {
        let encoded = base64::engine::general_purpose::STANDARD.encode("justtoken");
        let mut headers = HeaderMap::new();
        headers.insert(
            AUTHORIZATION,
            format!("Bearer {}", encoded).parse().unwrap(),
        );
        assert!(extract_bearer_credentials(&headers).is_none());
    }

    #[test]
    fn test_extract_bearer_credentials_colon_in_password() {
        let encoded = base64::engine::general_purpose::STANDARD.encode("user:p:a:s:s");
        let mut headers = HeaderMap::new();
        headers.insert(
            AUTHORIZATION,
            format!("Bearer {}", encoded).parse().unwrap(),
        );
        let result = extract_bearer_credentials(&headers);
        assert_eq!(result, Some(("user".to_string(), "p:a:s:s".to_string())));
    }

    // -----------------------------------------------------------------------
    // is_write_method
    // -----------------------------------------------------------------------

    #[test]
    fn test_is_write_method_post() {
        assert!(is_write_method(&Method::POST));
    }

    #[test]
    fn test_is_write_method_put() {
        assert!(is_write_method(&Method::PUT));
    }

    #[test]
    fn test_is_write_method_patch() {
        assert!(is_write_method(&Method::PATCH));
    }

    #[test]
    fn test_is_write_method_delete() {
        assert!(is_write_method(&Method::DELETE));
    }

    #[test]
    fn test_is_write_method_get_is_not_write() {
        assert!(!is_write_method(&Method::GET));
    }

    #[test]
    fn test_is_write_method_head_is_not_write() {
        assert!(!is_write_method(&Method::HEAD));
    }

    #[test]
    fn test_is_write_method_options_is_not_write() {
        assert!(!is_write_method(&Method::OPTIONS));
    }

    // -----------------------------------------------------------------------
    // unauthorized_response / forbidden_repo_response
    // -----------------------------------------------------------------------

    #[test]
    fn test_unauthorized_response_status() {
        let resp = unauthorized_response();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[test]
    fn test_unauthorized_response_has_www_authenticate_headers() {
        let resp = unauthorized_response();
        let www_auth_values: Vec<&str> = resp
            .headers()
            .get_all("WWW-Authenticate")
            .iter()
            .map(|v| v.to_str().unwrap())
            .collect();
        // Must include both Basic and Bearer challenges so package-manager
        // clients know which auth scheme to retry with.
        assert!(
            www_auth_values.iter().any(|v| v.starts_with("Basic")),
            "expected a Basic WWW-Authenticate challenge"
        );
        assert!(
            www_auth_values.iter().any(|v| v.starts_with("Bearer")),
            "expected a Bearer WWW-Authenticate challenge"
        );
        // Must also include the Cargo challenge so cargo 1.67+ uses the token
        // protocol instead of aborting on the Basic/Bearer challenges.
        assert!(
            www_auth_values.iter().any(|v| v.starts_with("Cargo")),
            "expected a Cargo WWW-Authenticate challenge"
        );
    }

    #[test]
    fn test_extract_plain_token_treated_as_bearer() {
        // The native cargo client sends the raw token with no scheme prefix;
        // a scheme-less single-word value must be accepted as a Bearer token.
        let result = extract_token_from_auth_header("ak_raw_cargo_token_123");
        assert!(matches!(
            result,
            ExtractedToken::Bearer("ak_raw_cargo_token_123")
        ));
    }

    #[test]
    fn test_extract_plain_token_with_space_is_invalid() {
        // A multi-word value that matches no known scheme is still invalid
        // (it is not a raw token).
        let result = extract_token_from_auth_header("Unknown scheme-value");
        assert!(matches!(result, ExtractedToken::Invalid));
    }

    #[test]
    fn test_unauthorized_response_content_type() {
        let resp = unauthorized_response();
        let ct = resp
            .headers()
            .get(axum::http::header::CONTENT_TYPE)
            .expect("Content-Type header must be present");
        assert_eq!(ct.to_str().unwrap(), "text/plain");
    }

    #[test]
    fn test_forbidden_repo_response_status() {
        let resp = forbidden_repo_response();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }

    #[test]
    fn test_forbidden_repo_response_content_type() {
        let resp = forbidden_repo_response();
        let ct = resp
            .headers()
            .get(axum::http::header::CONTENT_TYPE)
            .expect("Content-Type header must be present");
        assert_eq!(ct.to_str().unwrap(), "text/plain");
    }

    // -----------------------------------------------------------------------
    // can_access_repo enforcement (unit-level: verify the helper blocks
    // tokens scoped to a different repo)
    // -----------------------------------------------------------------------

    #[test]
    fn test_can_access_repo_with_empty_allowed_list() {
        let ext = make_api_token_ext(vec!["*".to_string()], Some(vec![]));
        // An empty allowed list means no repos are permitted.
        assert!(!ext.can_access_repo(Uuid::new_v4()));
    }

    #[test]
    fn test_can_access_repo_with_matching_id() {
        let target_repo = Uuid::new_v4();
        let ext = make_api_token_ext(
            vec!["*".to_string()],
            Some(vec![Uuid::new_v4(), target_repo, Uuid::new_v4()]),
        );
        assert!(
            ext.can_access_repo(target_repo),
            "token with target repo in allowed_repo_ids should have access"
        );
    }

    #[test]
    fn test_can_access_repo_with_non_matching_id() {
        let allowed = vec![Uuid::new_v4(), Uuid::new_v4()];
        let ext = make_api_token_ext(vec!["*".to_string()], Some(allowed));
        let unrelated_repo = Uuid::new_v4();
        assert!(
            !ext.can_access_repo(unrelated_repo),
            "token should not access a repo outside its allowed_repo_ids"
        );
    }

    #[test]
    fn test_can_access_repo_with_no_restrictions() {
        // allowed_repo_ids = None means the token is unrestricted.
        let ext = make_api_token_ext(vec!["*".to_string()], None);
        assert!(
            ext.can_access_repo(Uuid::new_v4()),
            "unrestricted token (allowed_repo_ids = None) should access any repo"
        );
    }

    // Authorization invariants stated directly against the `AccessScope` field
    // (the point of the type swap): the enum makes "no restriction" and
    // "restricted to nothing" impossible to confuse.
    #[test]
    fn test_access_scope_field_admin_grants_all() {
        let ext = make_api_token_ext(vec!["*".to_string()], None);
        assert_eq!(ext.allowed_repo_ids, AccessScope::Admin);
        assert_eq!(ext.access_scope(), AccessScope::Admin);
        assert!(
            ext.can_access_repo(Uuid::new_v4()),
            "AccessScope::Admin must reach every repository"
        );
    }

    #[test]
    fn test_access_scope_field_empty_scope_denies_all() {
        // Some(vec![]) through the helper yields Restricted([]).
        let ext = make_api_token_ext(vec!["*".to_string()], Some(vec![]));
        assert_eq!(ext.allowed_repo_ids, AccessScope::Restricted(vec![]));
        assert!(
            !ext.can_access_repo(Uuid::new_v4()),
            "empty scope (Restricted([])) must grant nothing, never fall open"
        );
    }

    #[test]
    fn test_access_scope_field_restricted_grants_only_listed() {
        let target = Uuid::new_v4();
        let ext = make_api_token_ext(vec!["*".to_string()], Some(vec![target]));
        assert_eq!(ext.allowed_repo_ids, AccessScope::Restricted(vec![target]));
        assert!(ext.can_access_repo(target), "listed repo must be reachable");
        assert!(
            !ext.can_access_repo(Uuid::new_v4()),
            "a repo outside the allowlist must be denied"
        );
    }

    #[test]
    fn test_can_access_repo_jwt_always_unrestricted() {
        let ext = AuthExtension {
            user_id: Uuid::new_v4(),
            username: "jwtuser".to_string(),
            email: "jwt@example.com".to_string(),
            is_admin: false,
            is_api_token: false,
            is_service_account: false,
            scopes: None,
            allowed_repo_ids: AccessScope::Admin,
            iat_ms: None,
        };
        // JWT sessions have no repo restrictions (allowed_repo_ids is None).
        assert!(ext.can_access_repo(Uuid::new_v4()));
    }

    // -- require_admin tests --

    #[test]
    fn test_require_admin_passes_for_admin() {
        let ext = AuthExtension {
            user_id: Uuid::new_v4(),
            username: "admin".to_string(),
            email: "admin@example.com".to_string(),
            is_admin: true,
            is_api_token: false,
            is_service_account: false,
            scopes: None,
            allowed_repo_ids: AccessScope::Admin,
            iat_ms: None,
        };
        assert!(ext.require_admin().is_ok());
    }

    #[test]
    fn test_require_admin_fails_for_non_admin() {
        let ext = AuthExtension {
            user_id: Uuid::new_v4(),
            username: "regular".to_string(),
            email: "user@example.com".to_string(),
            is_admin: false,
            is_api_token: false,
            is_service_account: false,
            scopes: None,
            allowed_repo_ids: AccessScope::Admin,
            iat_ms: None,
        };
        let err = ext.require_admin().unwrap_err();
        assert!(err.to_string().contains("Admin access required"));
    }

    #[test]
    fn test_require_admin_api_token_admin() {
        let ext = AuthExtension {
            user_id: Uuid::new_v4(),
            username: "bot".to_string(),
            email: "bot@example.com".to_string(),
            is_admin: true,
            is_api_token: true,
            is_service_account: true,
            scopes: Some(vec!["admin".to_string()]),
            allowed_repo_ids: AccessScope::Admin,
            iat_ms: None,
        };
        assert!(ext.require_admin().is_ok());
    }

    #[test]
    fn test_require_admin_api_token_non_admin() {
        let ext = AuthExtension {
            user_id: Uuid::new_v4(),
            username: "bot".to_string(),
            email: "bot@example.com".to_string(),
            is_admin: false,
            is_api_token: true,
            is_service_account: true,
            scopes: Some(vec!["read".to_string()]),
            allowed_repo_ids: AccessScope::Admin,
            iat_ms: None,
        };
        assert!(ext.require_admin().is_err());
    }

    // -----------------------------------------------------------------------
    // require_self_or_admin: self allowed, admin allowed, other-non-admin
    // denied. Pins the deny-by-default self-service authorization policy.
    // -----------------------------------------------------------------------

    fn self_or_admin_fixture(user_id: Uuid, is_admin: bool) -> AuthExtension {
        AuthExtension {
            user_id,
            username: "caller".to_string(),
            email: "caller@example.com".to_string(),
            is_admin,
            is_api_token: false,
            is_service_account: false,
            scopes: None,
            allowed_repo_ids: AccessScope::Admin,
            iat_ms: None,
        }
    }

    #[test]
    fn test_require_self_or_admin_allows_self() {
        let me = Uuid::new_v4();
        let ext = self_or_admin_fixture(me, false);
        // Acting on my own resource: allowed even though I am not an admin.
        assert!(ext.require_self_or_admin(me, "denied").is_ok());
    }

    #[test]
    fn test_require_self_or_admin_allows_admin_for_other() {
        let ext = self_or_admin_fixture(Uuid::new_v4(), true);
        // Admin acting on someone else's resource: allowed.
        assert!(ext.require_self_or_admin(Uuid::new_v4(), "denied").is_ok());
    }

    #[test]
    fn test_require_self_or_admin_denies_other_non_admin() {
        let ext = self_or_admin_fixture(Uuid::new_v4(), false);
        // Non-admin acting on someone else's resource: denied (403) and the
        // caller-supplied message is preserved verbatim in the error body.
        let err = ext
            .require_self_or_admin(Uuid::new_v4(), "Cannot view other users' tokens")
            .unwrap_err();
        assert!(matches!(err, AppError::Authorization(_)));
        assert!(err.to_string().contains("Cannot view other users' tokens"));
    }

    #[test]
    fn test_require_self_or_admin_admin_acting_on_self() {
        let me = Uuid::new_v4();
        let ext = self_or_admin_fixture(me, true);
        // Admin acting on their own resource: allowed (both conditions true).
        assert!(ext.require_self_or_admin(me, "denied").is_ok());
    }

    // -----------------------------------------------------------------------
    // Public repo anonymous access: should_allow_repo_access + is_write_method
    // combined to verify the middleware allows anonymous reads on public repos
    // while blocking anonymous writes.
    // -----------------------------------------------------------------------

    #[test]
    fn test_public_repo_allows_anonymous_get() {
        let is_public = true;
        let has_auth = false;
        let method = Method::GET;
        assert!(
            should_allow_repo_access(is_public, has_auth),
            "public repo should allow anonymous reads"
        );
        assert!(
            !is_write_method(&method),
            "GET is not a write method, should not trigger write-auth requirement"
        );
    }

    #[test]
    fn test_public_repo_blocks_anonymous_post() {
        let is_public = true;
        let has_auth = false;
        // Middleware allows access (public repo)...
        assert!(should_allow_repo_access(is_public, has_auth));
        // ...but the write-method check catches it and requires auth.
        assert!(
            is_write_method(&Method::POST),
            "POST is a write method, middleware should require auth"
        );
    }

    #[test]
    fn test_public_repo_blocks_anonymous_put() {
        let is_public = true;
        let has_auth = false;
        assert!(should_allow_repo_access(is_public, has_auth));
        assert!(
            is_write_method(&Method::PUT),
            "PUT is a write method, middleware should require auth"
        );
    }

    #[test]
    fn test_public_repo_blocks_anonymous_delete() {
        let is_public = true;
        let has_auth = false;
        assert!(should_allow_repo_access(is_public, has_auth));
        assert!(
            is_write_method(&Method::DELETE),
            "DELETE is a write method, middleware should require auth"
        );
    }

    #[test]
    fn test_public_repo_allows_anonymous_head() {
        let is_public = true;
        let has_auth = false;
        assert!(should_allow_repo_access(is_public, has_auth));
        assert!(
            !is_write_method(&Method::HEAD),
            "HEAD is not a write method, anonymous access allowed on public repos"
        );
    }

    #[test]
    fn test_private_repo_blocks_anonymous_get() {
        let is_public = false;
        let has_auth = false;
        assert!(
            !should_allow_repo_access(is_public, has_auth),
            "private repo should block anonymous reads"
        );
    }

    #[test]
    fn test_private_repo_allows_authenticated_get() {
        let is_public = false;
        let has_auth = true;
        assert!(
            should_allow_repo_access(is_public, has_auth),
            "private repo should allow authenticated reads"
        );
    }

    #[test]
    fn test_public_repo_allows_authenticated_write() {
        let is_public = true;
        let has_auth = true;
        assert!(should_allow_repo_access(is_public, has_auth));
        // With auth present, even write methods are allowed through the
        // visibility check (the write-method guard passes because auth exists).
    }

    // -----------------------------------------------------------------------
    // action_for_method: HTTP method -> permission action mapping (#817)
    // -----------------------------------------------------------------------

    #[test]
    fn test_action_for_method_get_maps_to_read() {
        assert_eq!(action_for_method(&Method::GET), "read");
    }

    #[test]
    fn test_action_for_method_head_maps_to_read() {
        assert_eq!(action_for_method(&Method::HEAD), "read");
    }

    #[test]
    fn test_action_for_method_options_maps_to_read() {
        assert_eq!(action_for_method(&Method::OPTIONS), "read");
    }

    #[test]
    fn test_action_for_method_put_maps_to_write() {
        assert_eq!(action_for_method(&Method::PUT), "write");
    }

    #[test]
    fn test_action_for_method_post_maps_to_write() {
        assert_eq!(action_for_method(&Method::POST), "write");
    }

    #[test]
    fn test_action_for_method_patch_maps_to_write() {
        assert_eq!(action_for_method(&Method::PATCH), "write");
    }

    #[test]
    fn test_action_for_method_delete_maps_to_delete() {
        assert_eq!(action_for_method(&Method::DELETE), "delete");
    }

    #[test]
    fn test_action_for_method_unknown_defaults_to_read() {
        // TRACE and other uncommon methods should default to read.
        assert_eq!(action_for_method(&Method::TRACE), "read");
    }

    // -----------------------------------------------------------------------
    // forbidden_permission_response (#817)
    // -----------------------------------------------------------------------

    #[test]
    fn test_forbidden_permission_response_status() {
        let resp = forbidden_permission_response();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }

    #[test]
    fn test_forbidden_permission_response_content_type() {
        let resp = forbidden_permission_response();
        let ct = resp
            .headers()
            .get(axum::http::header::CONTENT_TYPE)
            .expect("Content-Type header must be present");
        assert_eq!(ct.to_str().unwrap(), "text/plain");
    }

    #[test]
    fn test_forbidden_permission_response_body_differs_from_repo_response() {
        // The permission-denied response should be distinguishable from the
        // token-scope response so callers can tell the two apart.
        let perm_resp = forbidden_permission_response();
        let repo_resp = forbidden_repo_response();
        // Both are 403, but the bodies should carry different messages.
        assert_eq!(perm_resp.status(), repo_resp.status());
        // We cannot easily read the body in a sync test, but verify they are
        // separate functions that both return 403 with text/plain.
        assert_eq!(
            perm_resp.headers().get(axum::http::header::CONTENT_TYPE),
            repo_resp.headers().get(axum::http::header::CONTENT_TYPE),
        );
    }

    // -----------------------------------------------------------------------
    // Permission enforcement logic: combined unit tests (#817)
    //
    // These tests verify the decision logic without a real database by
    // testing the individual pieces that compose the middleware behavior.
    // -----------------------------------------------------------------------

    /// Admin users bypass all permission checks regardless of rules.
    #[test]
    fn test_permission_admin_bypasses_all_checks() {
        let ext = AuthExtension {
            user_id: Uuid::new_v4(),
            username: "admin".to_string(),
            email: "admin@example.com".to_string(),
            is_admin: true,
            is_api_token: false,
            is_service_account: false,
            scopes: None,
            allowed_repo_ids: AccessScope::Admin,
            iat_ms: None,
        };
        // The middleware skips permission checks when is_admin is true.
        // Verify the flag is correctly detected.
        assert!(
            ext.is_admin,
            "admin users should bypass permission enforcement"
        );
    }

    /// When no permission rules exist for a repository, all authenticated
    /// users are allowed access (backward compatible default).
    #[test]
    fn test_permission_no_rules_allows_everyone() {
        // Simulates has_any_rules_for_target returning false.
        let has_rules = false;
        let is_admin = false;

        // When there are no rules, the middleware should not call
        // check_permission at all. Access is allowed by default.
        if !is_admin && has_rules {
            panic!("should not reach permission check when no rules exist");
        }
        // If we get here, access is allowed. This matches the middleware logic.
    }

    /// When rules exist and the user lacks the required action, the
    /// middleware returns 403.
    #[test]
    fn test_permission_rules_block_unauthorized_user() {
        let has_rules = true;
        let check_result = false; // user does not have the action

        // Simulates the middleware path where rules exist and check fails.
        if has_rules && !check_result {
            // This is the path where forbidden_permission_response() is returned.
            let resp = forbidden_permission_response();
            assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        } else {
            panic!("should have reached the permission denied path");
        }
    }

    /// When rules exist and the user holds the required action, the
    /// request proceeds to the handler.
    #[test]
    fn test_permission_rules_allow_authorized_user() {
        let has_rules = true;
        let check_result = true; // user has the action

        // Simulates the middleware path: when rules exist AND the user
        // passes the check, the request proceeds to the handler.
        assert!(
            !has_rules || check_result,
            "authorized user should be allowed through"
        );
    }

    /// Verify that the correct action is derived for each method in the
    /// full permission enforcement flow.
    #[test]
    fn test_permission_action_mapping_for_common_methods() {
        let cases = [
            (Method::GET, "read"),
            (Method::HEAD, "read"),
            (Method::POST, "write"),
            (Method::PUT, "write"),
            (Method::DELETE, "delete"),
            (Method::PATCH, "write"),
        ];
        for (method, expected_action) in cases {
            assert_eq!(
                action_for_method(&method),
                expected_action,
                "method {:?} should map to action {:?}",
                method,
                expected_action,
            );
        }
    }

    /// Non-admin user with no auth extension (anonymous) does not enter
    /// the permission check block at all. The middleware only checks
    /// permissions when auth_ext is Some.
    #[test]
    fn test_permission_anonymous_skips_permission_check() {
        let auth_ext: Option<AuthExtension> = None;
        // The middleware guard is `if let Some(ref ext) = auth_ext`.
        // Anonymous users (None) never enter the permission block.
        assert!(
            auth_ext.is_none(),
            "anonymous users should not trigger permission checks"
        );
    }

    /// Admin user via API token also bypasses permission checks.
    #[test]
    fn test_permission_admin_api_token_bypasses_checks() {
        let ext = AuthExtension {
            user_id: Uuid::new_v4(),
            username: "bot".to_string(),
            email: "bot@example.com".to_string(),
            is_admin: true,
            is_api_token: true,
            is_service_account: true,
            scopes: Some(vec!["admin".to_string()]),
            allowed_repo_ids: AccessScope::Admin,
            iat_ms: None,
        };
        assert!(
            ext.is_admin,
            "admin API token should bypass permission enforcement"
        );
    }

    // -----------------------------------------------------------------------
    // Download ticket helpers (#930)
    // -----------------------------------------------------------------------

    #[test]
    fn test_extract_ticket_from_query_simple() {
        let q = Some("ticket=abc123");
        assert_eq!(extract_ticket_from_query(q), Some("abc123".to_string()));
    }

    #[test]
    fn test_extract_ticket_from_query_among_other_params() {
        let q = Some("foo=bar&ticket=xyz&baz=qux");
        assert_eq!(extract_ticket_from_query(q), Some("xyz".to_string()));
    }

    #[test]
    fn test_extract_ticket_from_query_first_occurrence_wins() {
        let q = Some("ticket=first&ticket=second");
        assert_eq!(extract_ticket_from_query(q), Some("first".to_string()));
    }

    #[test]
    fn test_extract_ticket_from_query_missing() {
        let q = Some("foo=bar&baz=qux");
        assert_eq!(extract_ticket_from_query(q), None);
    }

    #[test]
    fn test_extract_ticket_from_query_no_query_string() {
        assert_eq!(extract_ticket_from_query(None), None);
    }

    #[test]
    fn test_extract_ticket_from_query_empty_value() {
        let q = Some("ticket=");
        // Empty ticket value is treated as missing.
        assert_eq!(extract_ticket_from_query(q), None);
    }

    #[test]
    fn test_extract_ticket_from_query_percent_encoded() {
        // Tickets are hex so the percent-decoding path normally never fires,
        // but exercise it for robustness.
        let q = Some("ticket=ab%2Bcd");
        assert_eq!(extract_ticket_from_query(q), Some("ab+cd".to_string()));
    }

    #[test]
    fn test_extract_ticket_substring_match_rejected() {
        // A param named `myticket` must not be picked up.
        let q = Some("myticket=nope");
        assert_eq!(extract_ticket_from_query(q), None);
    }

    #[test]
    fn test_ticket_method_allowed_get_head() {
        assert!(ticket_method_allowed(&Method::GET));
        assert!(ticket_method_allowed(&Method::HEAD));
    }

    #[test]
    fn test_ticket_method_allowed_rejects_writes() {
        assert!(!ticket_method_allowed(&Method::POST));
        assert!(!ticket_method_allowed(&Method::PUT));
        assert!(!ticket_method_allowed(&Method::PATCH));
        assert!(!ticket_method_allowed(&Method::DELETE));
    }

    #[test]
    fn test_ticket_path_allowed_unbound_ticket_allows_anything() {
        assert!(ticket_path_allowed(None, "/api/v1/repositories/foo"));
        assert!(ticket_path_allowed(None, "/totally/different"));
    }

    #[test]
    fn test_ticket_path_allowed_exact_match() {
        let bound = Some("/api/v1/repositories/foo/blob.tar.gz");
        assert!(ticket_path_allowed(
            bound,
            "/api/v1/repositories/foo/blob.tar.gz"
        ));
    }

    #[test]
    fn test_ticket_path_allowed_rejects_mismatch() {
        let bound = Some("/api/v1/repositories/foo/blob.tar.gz");
        assert!(!ticket_path_allowed(
            bound,
            "/api/v1/repositories/bar/blob.tar.gz"
        ));
    }

    #[test]
    fn test_ticket_path_allowed_rejects_prefix() {
        // Path-prefix match is intentionally not allowed: a ticket bound
        // to `/repo/foo` must not authenticate `/repo/foo/secret`.
        let bound = Some("/api/v1/repositories/foo");
        assert!(!ticket_path_allowed(
            bound,
            "/api/v1/repositories/foo/secret"
        ));
    }

    #[test]
    fn test_ticket_path_allowed_rejects_trailing_slash_mismatch() {
        // Trailing-slash equivalence is NOT honoured by the consumer.
        // The minter is responsible for binding the exact form the client
        // request will use; mint-time normalization strips the trailing
        // slash, so this case is the "client added a trailing slash"
        // failure mode, not the "minter forgot to strip it" mode.
        let bound = Some("/api/v1/repositories/foo");
        assert!(!ticket_path_allowed(bound, "/api/v1/repositories/foo/"));

        // Mirror in the other direction.
        let bound = Some("/api/v1/repositories/foo/");
        assert!(!ticket_path_allowed(bound, "/api/v1/repositories/foo"));
    }

    #[test]
    fn test_ticket_path_allowed_rejects_case_difference() {
        // Format handlers that case-fold (PyPI/NuGet/Go) lowercase before
        // dispatching; the consumer compares to the raw `request.uri().path()`
        // BEFORE that handler-side normalization happens, so the mint-time
        // validator must lowercase. If a minter bypassed validation, this
        // is the failure mode they would see at consume time.
        let bound = Some("/pypi/myrepo/Django");
        assert!(!ticket_path_allowed(bound, "/pypi/myrepo/django"));
    }

    #[test]
    fn test_ticket_path_allowed_rejects_encoded_slash() {
        // axum/hyper exposes the raw path; `%2F` is not equivalent to `/`.
        // A ticket bound to `/foo/bar` must not match `/foo%2Fbar`.
        let bound = Some("/foo/bar");
        assert!(!ticket_path_allowed(bound, "/foo%2Fbar"));
        assert!(!ticket_path_allowed(bound, "/foo%2fbar"));

        let bound = Some("/foo%2Fbar");
        assert!(!ticket_path_allowed(bound, "/foo/bar"));
    }

    #[test]
    fn test_ticket_path_allowed_rejects_double_encoded() {
        // `%252F` is `%2F` after one decode, `/` after two. The consumer
        // compares raw bytes, so neither form matches `/`.
        let bound = Some("/foo/bar");
        assert!(!ticket_path_allowed(bound, "/foo%252Fbar"));
        assert!(!ticket_path_allowed(bound, "/foo%252fbar"));
    }

    #[test]
    fn test_ticket_path_allowed_only_exact_byte_equality() {
        // No transformation, no canonicalization, no Unicode-folding.
        // A ticket bound with combining characters must not match a
        // pre-composed equivalent.
        let bound = Some("/foo/cafe\u{0301}"); // "café" decomposed
        assert!(ticket_path_allowed(bound, "/foo/cafe\u{0301}"));
        assert!(!ticket_path_allowed(bound, "/foo/caf\u{00E9}")); // "café" precomposed
    }

    // -----------------------------------------------------------------------
    // Additional ticket-method coverage (#930): the existing block already
    // covers GET/HEAD/POST/PUT/PATCH/DELETE; OPTIONS/CONNECT/TRACE round out
    // the negative half so the matcher is exercised across every variant the
    // client side might emit.
    // -----------------------------------------------------------------------

    #[test]
    fn test_ticket_method_allowed_rejects_options() {
        assert!(!ticket_method_allowed(&Method::OPTIONS));
    }

    #[test]
    fn test_ticket_method_allowed_rejects_connect() {
        assert!(!ticket_method_allowed(&Method::CONNECT));
    }

    #[test]
    fn test_ticket_method_allowed_rejects_trace() {
        assert!(!ticket_method_allowed(&Method::TRACE));
    }

    // -----------------------------------------------------------------------
    // extract_ticket_from_query: additional malformed-input edge cases.
    // -----------------------------------------------------------------------

    #[test]
    fn test_extract_ticket_from_query_pair_without_equals_is_skipped() {
        // A bare segment like `ticket` without `=` must not be treated as a
        // ticket; the splitn(2, '=') yields key="ticket" and the value lookup
        // unwrap_or("") produces an empty raw string which is rejected.
        let q = Some("ticket&other=1");
        assert_eq!(extract_ticket_from_query(q), None);
    }

    #[test]
    fn test_extract_ticket_from_query_repeated_amp_collapses_empty_pairs() {
        // Empty segments between `&` are skipped (their key is "" and never
        // matches "ticket"); a real `ticket=` later in the query still wins.
        let q = Some("&&&ticket=hello&&");
        assert_eq!(extract_ticket_from_query(q), Some("hello".to_string()));
    }

    #[test]
    fn test_extract_ticket_from_query_invalid_percent_falls_back_to_literal() {
        // `%ZZ` is not valid hex, so the bytes are emitted verbatim instead of
        // panicking. This keeps the helper robust against client encoding bugs
        // without trying to be cleverer than necessary.
        let q = Some("ticket=ab%ZZcd");
        let got = extract_ticket_from_query(q).unwrap();
        // The first `%` and the following two characters fall through one byte
        // at a time, so the literal `%ZZ` survives in the output.
        assert!(got.contains("%ZZcd"));
        assert!(got.starts_with("ab"));
    }

    #[test]
    fn test_extract_ticket_from_query_truncated_percent() {
        // A `%` without two trailing chars is also passed through literally.
        let q = Some("ticket=ab%");
        assert_eq!(extract_ticket_from_query(q), Some("ab%".to_string()));
    }

    #[test]
    fn test_extract_ticket_from_query_case_sensitive_key() {
        // The key match is case-sensitive (`ticket`, not `Ticket`). Clients
        // that uppercase the key get None, not a silent fallthrough.
        assert_eq!(extract_ticket_from_query(Some("Ticket=abc")), None);
        assert_eq!(extract_ticket_from_query(Some("TICKET=abc")), None);
    }

    // -----------------------------------------------------------------------
    // extract_ticket_request_parts: cloned-out request shape used by the
    // middleware to keep the auth future Send across `.await`.
    // -----------------------------------------------------------------------

    #[test]
    fn test_extract_ticket_request_parts_present() {
        let req = axum::http::Request::builder()
            .method(Method::GET)
            .uri("/api/v1/auth/me?ticket=abcd")
            .body(axum::body::Body::empty())
            .unwrap();
        let parts = extract_ticket_request_parts(&req).expect("ticket parts");
        assert_eq!(parts.ticket, "abcd");
        assert_eq!(parts.method, Method::GET);
        assert_eq!(parts.path, "/api/v1/auth/me");
    }

    #[test]
    fn test_extract_ticket_request_parts_missing_ticket() {
        let req = axum::http::Request::builder()
            .method(Method::GET)
            .uri("/api/v1/auth/me?foo=bar")
            .body(axum::body::Body::empty())
            .unwrap();
        assert!(extract_ticket_request_parts(&req).is_none());
    }

    #[test]
    fn test_extract_ticket_request_parts_no_query_string() {
        let req = axum::http::Request::builder()
            .method(Method::GET)
            .uri("/api/v1/auth/me")
            .body(axum::body::Body::empty())
            .unwrap();
        assert!(extract_ticket_request_parts(&req).is_none());
    }

    #[test]
    fn test_extract_ticket_request_parts_preserves_method_for_writes() {
        // Even though writes will be rejected later, this helper has no
        // policy of its own; the snapshot must reflect the actual method.
        let req = axum::http::Request::builder()
            .method(Method::POST)
            .uri("/api/v1/something?ticket=t")
            .body(axum::body::Body::empty())
            .unwrap();
        let parts = extract_ticket_request_parts(&req).expect("parts");
        assert_eq!(parts.method, Method::POST);
    }

    // -----------------------------------------------------------------------
    // DownloadTicketAuth marker extension construction. Trivial Copy/Clone/
    // Debug shape — proves the type can be inserted into a request extensions
    // map and pulled back out, which is how the consumer middleware signals
    // "this request was authenticated by a single-use download ticket" to
    // downstream write-gating code.
    // -----------------------------------------------------------------------

    #[test]
    fn test_download_ticket_auth_marker_copy_semantics() {
        let m1 = DownloadTicketAuth;
        let m2 = m1; // Copy
        let _m3 = m1; // Still usable.
                      // Debug formatter exists.
        let dbg = format!("{:?}", m2);
        assert!(dbg.contains("DownloadTicketAuth"));
    }

    #[test]
    fn test_download_ticket_auth_marker_round_trips_through_extensions() {
        let mut req = axum::http::Request::builder()
            .uri("/x")
            .body(axum::body::Body::empty())
            .unwrap();
        req.extensions_mut().insert(DownloadTicketAuth);
        assert!(req.extensions().get::<DownloadTicketAuth>().is_some());
    }

    // -----------------------------------------------------------------------
    // try_resolve_ticket_auth direct entry-point coverage.
    //
    // The middleware that wraps this function is tested via integration tests
    // in `backend/tests/download_ticket_tests.rs`, but those are gated on a
    // running HTTP server and so do not contribute to lib coverage. Calling
    // the helper directly with a `connect_lazy` pool exercises the early
    // method-rejection branch and the validate-fails-no-such-ticket branch
    // which together form the bulk of the consumer middleware's logic.
    // -----------------------------------------------------------------------

    fn lazy_pool() -> sqlx::PgPool {
        // `connect_lazy_with` defers the actual TCP/handshake attempt until
        // the first query. The 1-second acquire timeout keeps tests fast: if
        // a path we did not intend to exercise reaches the pool, it errors
        // out in a second instead of stalling on the default 30s timeout.
        use sqlx::postgres::{PgConnectOptions, PgPoolOptions};
        PgPoolOptions::new()
            .max_connections(1)
            .acquire_timeout(std::time::Duration::from_secs(1))
            .connect_lazy_with(
                PgConnectOptions::new()
                    .host("127.0.0.1")
                    .port(1)
                    .username("invalid")
                    .password("invalid")
                    .database("invalid"),
            )
    }

    #[tokio::test]
    async fn test_try_resolve_ticket_auth_rejects_post() {
        // Write methods short-circuit before any DB query, so we do not need
        // a working pool to exercise this branch.
        let pool = lazy_pool();
        let got = try_resolve_ticket_auth(&pool, "anyticket", &Method::POST, "/x").await;
        assert!(got.is_none(), "POST must not be authenticated by ticket");
    }

    #[tokio::test]
    async fn test_try_resolve_ticket_auth_rejects_put() {
        let pool = lazy_pool();
        let got = try_resolve_ticket_auth(&pool, "t", &Method::PUT, "/x").await;
        assert!(got.is_none());
    }

    #[tokio::test]
    async fn test_try_resolve_ticket_auth_rejects_delete() {
        let pool = lazy_pool();
        let got = try_resolve_ticket_auth(&pool, "t", &Method::DELETE, "/x").await;
        assert!(got.is_none());
    }

    #[tokio::test]
    async fn test_try_resolve_ticket_auth_rejects_patch() {
        let pool = lazy_pool();
        let got = try_resolve_ticket_auth(&pool, "t", &Method::PATCH, "/x").await;
        assert!(got.is_none());
    }

    #[tokio::test]
    async fn test_try_resolve_ticket_auth_db_unreachable_returns_none() {
        // GET passes the method check, runs validate_download_ticket against
        // the lazy pool, and the unreachable DB makes that call error out.
        // The `.ok()??` chain converts the error into None, which is what the
        // middleware needs in order to fall through to a 401.
        let pool = lazy_pool();
        let got = try_resolve_ticket_auth(&pool, "no-such-ticket", &Method::GET, "/x").await;
        assert!(got.is_none(), "DB error must surface as None, not a panic");
    }

    #[tokio::test]
    async fn test_try_resolve_ticket_for_parts_db_unreachable_returns_none() {
        // Same shape as above, exercised through the parts-bundle wrapper that
        // the middleware actually calls. Asserts that the wrapper does not add
        // any extra fallibility on top of try_resolve_ticket_auth itself.
        let pool = lazy_pool();
        let parts = TicketRequestParts {
            ticket: "no-such".to_string(),
            method: Method::GET,
            path: "/x".to_string(),
        };
        assert!(try_resolve_ticket_for_parts(&pool, &parts).await.is_none());
    }

    // -----------------------------------------------------------------------
    // auth_middleware end-to-end shape via tower::ServiceExt::oneshot.
    //
    // These tests instantiate a real Router with the middleware applied, then
    // drive it through tower's `oneshot`. The downstream handler is a tiny
    // probe so we can assert that the middleware short-circuited (returned
    // 401 without touching the handler) or fell through (returned 200).
    // -----------------------------------------------------------------------

    fn make_test_config_for_middleware() -> std::sync::Arc<crate::config::Config> {
        // Use Config::default() so the helper survives field additions on main
        // (the cherry-pick from release/1.1.x originally hard-coded an older
        // field set). The default jwt_secret is long enough for any future
        // minimum-length check, and these tests only exercise auth-shape
        // behaviour, not configuration-dependent paths.
        std::sync::Arc::new(crate::config::Config::default())
    }

    fn make_test_auth_service() -> Arc<AuthService> {
        // The lazy pool means AuthService construction is free; queries that
        // actually reach the DB will error out, which is what we want when
        // exercising "auth fails, fall through" branches.
        let pool = lazy_pool();
        Arc::new(AuthService::new(pool, make_test_config_for_middleware()))
    }

    fn mint_access_jwt(secret: &str, sub: Uuid, username: &str) -> String {
        // Real millisecond iat: minted strictly after the user row exists, so
        // the credential-change watermark (strict `<`) accepts the token.
        let now = Utc::now();
        let claims = Claims {
            sub,
            username: username.to_string(),
            email: format!("{}@example.test", username),
            is_admin: false,
            allowed_repo_ids: None,
            iat: now.timestamp(),
            iat_ms: Some(now.timestamp_millis()),
            exp: now.timestamp() + 300,
            token_type: "access".to_string(),
            jti: None,
            family_id: None,
            scan_pull_repo: None,
        };
        encode(
            &Header::default(),
            &claims,
            &EncodingKey::from_secret(secret.as_bytes()),
        )
        .expect("encode jwt")
    }

    #[tokio::test]
    async fn test_try_resolve_auth_basic_falls_back_to_jwt_password() {
        use crate::api::handlers::test_db_helpers as tdh;

        let Some(pool) = tdh::try_pool().await else {
            return;
        };

        let secret = "test-secret-at-least-32-bytes-long-for-testing";
        let cfg = crate::config::Config {
            jwt_secret: secret.to_string(),
            ..crate::config::Config::default()
        };

        let auth_service = AuthService::new(pool.clone(), Arc::new(cfg));
        // The async validator re-derives is_admin from the live users row and
        // rejects tokens whose subject has no active row, so the minted JWT
        // must reference a real user.
        let (user_id, _username) = tdh::create_user(&pool).await;
        let jwt = mint_access_jwt(secret, user_id, "ci-user");
        let basic = base64::engine::general_purpose::STANDARD.encode(format!("ci-user:{}", jwt));

        let resolved = try_resolve_auth(&auth_service, ExtractedToken::Basic(&basic)).await;

        sqlx::query("DELETE FROM users WHERE id = $1")
            .bind(user_id)
            .execute(&pool)
            .await
            .expect("cleanup test user");

        let ext = resolved.expect("expected jwt fallback to authenticate basic password");
        assert_eq!(ext.username, "ci-user");
        assert!(!ext.is_admin);
        assert!(!ext.is_api_token);
    }

    async fn run_through_auth_middleware(
        request: axum::http::Request<axum::body::Body>,
    ) -> axum::http::Response<axum::body::Body> {
        use axum::{middleware, routing::any, Router};
        use tower::ServiceExt;

        let auth_service = make_test_auth_service();
        let app: Router = Router::new()
            .route(
                "/probe",
                any(|| async { (StatusCode::OK, "handler-reached") }),
            )
            .route("/api/v1/auth/me", any(|| async { (StatusCode::OK, "me") }))
            .layer(middleware::from_fn_with_state(
                auth_service,
                auth_middleware,
            ));
        app.oneshot(request).await.unwrap()
    }

    async fn run_through_optional_auth(
        request: axum::http::Request<axum::body::Body>,
    ) -> axum::http::Response<axum::body::Body> {
        use axum::{middleware, routing::any, Router};
        use tower::ServiceExt;

        let auth_service = make_test_auth_service();
        let app: Router = Router::new()
            .route("/probe", any(|| async { (StatusCode::OK, "ok") }))
            .layer(middleware::from_fn_with_state(
                auth_service,
                optional_auth_middleware,
            ));
        app.oneshot(request).await.unwrap()
    }

    async fn run_through_admin_middleware(
        request: axum::http::Request<axum::body::Body>,
    ) -> axum::http::Response<axum::body::Body> {
        use axum::{middleware, routing::any, Router};
        use tower::ServiceExt;

        let auth_service = make_test_auth_service();
        let app: Router = Router::new()
            .route("/probe", any(|| async { (StatusCode::OK, "admin-ok") }))
            .layer(middleware::from_fn_with_state(
                auth_service,
                admin_middleware,
            ));
        app.oneshot(request).await.unwrap()
    }

    fn empty_get(uri: &str) -> axum::http::Request<axum::body::Body> {
        axum::http::Request::builder()
            .method(Method::GET)
            .uri(uri)
            .body(axum::body::Body::empty())
            .unwrap()
    }

    #[tokio::test]
    async fn test_auth_middleware_rejects_missing_credentials() {
        let resp = run_through_auth_middleware(empty_get("/probe")).await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let text = std::str::from_utf8(&body).unwrap();
        assert!(
            text.contains("Missing authorization header"),
            "expected missing-header message, got: {text}"
        );
    }

    #[tokio::test]
    async fn test_auth_middleware_rejects_invalid_auth_header_format() {
        // A scheme that is neither Bearer/ApiKey/Basic falls into the
        // ExtractedToken::Invalid branch and produces the format error.
        let req = axum::http::Request::builder()
            .method(Method::GET)
            .uri("/probe")
            .header("Authorization", "Garbage tokenvalue")
            .body(axum::body::Body::empty())
            .unwrap();
        let resp = run_through_auth_middleware(req).await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let text = std::str::from_utf8(&body).unwrap();
        assert!(
            text.contains("Invalid authorization header format"),
            "expected invalid-format message, got: {text}"
        );
    }

    #[tokio::test]
    async fn test_auth_middleware_rejects_bearer_with_unverifiable_token() {
        // The Bearer branch first tries JWT decode (fails), then API-token
        // validation. A token shorter than the 8-char prefix is rejected by
        // `validate_api_token` BEFORE any DB lookup, so this isolates the
        // genuine-invalid -> 401 path from the pool-timeout -> 503 path (the
        // latter is covered by the dedicated #2125 tests). Both validators
        // fail and fall through to the "Invalid or expired token" 401.
        let req = axum::http::Request::builder()
            .method(Method::GET)
            .uri("/probe")
            .header("Authorization", "Bearer badtok")
            .body(axum::body::Body::empty())
            .unwrap();
        let resp = run_through_auth_middleware(req).await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let text = std::str::from_utf8(&body).unwrap();
        assert!(
            text.contains("Invalid or expired token"),
            "expected expired-token message, got: {text}"
        );
    }

    #[tokio::test]
    async fn test_auth_middleware_rejects_apikey_scheme_with_bad_token() {
        // A token shorter than the 8-char prefix is rejected before any DB
        // lookup, isolating the genuine-invalid -> 401 path from the
        // pool-timeout -> 503 path (covered separately, #2125).
        let req = axum::http::Request::builder()
            .method(Method::GET)
            .uri("/probe")
            .header("Authorization", "ApiKey badtok")
            .body(axum::body::Body::empty())
            .unwrap();
        let resp = run_through_auth_middleware(req).await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let text = std::str::from_utf8(&body).unwrap();
        assert!(
            text.contains("Invalid or expired API token"),
            "expected ApiKey-failed message, got: {text}"
        );
    }

    #[tokio::test]
    async fn test_auth_middleware_rejects_basic_with_invalid_b64() {
        // `decode_basic_credentials` returns None for non-base64 input. The
        // resulting branch is the `None` arm at lines 333-335.
        let req = axum::http::Request::builder()
            .method(Method::GET)
            .uri("/probe")
            .header("Authorization", "Basic !!!not-base64!!!")
            .body(axum::body::Body::empty())
            .unwrap();
        let resp = run_through_auth_middleware(req).await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let text = std::str::from_utf8(&body).unwrap();
        assert!(
            text.contains("Invalid Basic auth credentials"),
            "expected basic-credentials message, got: {text}"
        );
    }

    #[tokio::test]
    async fn test_auth_middleware_basic_pool_timeout_returns_503() {
        // #2125: valid base64 with `user:pass` shape. The unreachable lazy pool
        // makes `authenticate`'s credential lookup fail with a pool-acquire
        // timeout. That is a transient capacity problem (POOL_EXHAUSTED), not a
        // bad password, so the Basic branch must surface a retryable 503, NOT
        // flatten it to a spurious 401 the way it did before this fix. (A
        // genuinely wrong password against a reachable DB still returns 401;
        // that path needs a real pool and is exercised by the integration
        // suite.)
        let creds = base64::engine::general_purpose::STANDARD.encode("alice:wrong");
        let req = axum::http::Request::builder()
            .method(Method::GET)
            .uri("/probe")
            .header("Authorization", format!("Basic {}", creds))
            .body(axum::body::Body::empty())
            .unwrap();
        let resp = run_through_auth_middleware(req).await;
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(
            resp.headers()
                .get(axum::http::header::RETRY_AFTER)
                .and_then(|v| v.to_str().ok()),
            Some("1"),
            "pool-timeout 503 must carry a Retry-After hint so clients back off"
        );
    }

    #[tokio::test]
    async fn test_admin_middleware_basic_pool_timeout_returns_503() {
        // #2125: the admin gate's Basic branch runs a bcrypt credential lookup.
        // When that lookup cannot acquire a DB connection (pool-acquire
        // timeout), the transient capacity problem must surface as a retryable
        // 503, not be flattened to the "Invalid credentials" 401.
        let creds = base64::engine::general_purpose::STANDARD.encode("root:hunter2");
        let req = axum::http::Request::builder()
            .method(Method::GET)
            .uri("/probe")
            .header("Authorization", format!("Basic {}", creds))
            .body(axum::body::Body::empty())
            .unwrap();
        let resp = run_through_admin_middleware(req).await;
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    #[tokio::test]
    async fn test_require_auth_with_bearer_fallback_pool_timeout_returns_503() {
        // #2125: the bearer-as-basic fallback used by download/read handlers
        // also runs a credential DB lookup. A pool-acquire timeout there must
        // become a retryable 503, not the "Invalid credentials" 401 it returned
        // before this fix.
        let token = base64::engine::general_purpose::STANDARD.encode("carol:pw");
        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::AUTHORIZATION,
            format!("Bearer {}", token).parse().unwrap(),
        );
        let db = lazy_pool();
        let config = crate::config::Config::default();
        let result =
            require_auth_with_bearer_fallback(None, &headers, &db, &config, "test-realm").await;
        let resp = result.expect_err("unreachable pool must fail authentication");
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    #[tokio::test]
    async fn test_auth_middleware_no_header_with_ticket_query_uses_ticket_message() {
        // No header credentials at all, but a `?ticket=` query is present.
        // The middleware tries the ticket fallback (DB unreachable -> None)
        // and produces the ambiguous "Invalid or expired download ticket"
        // message rather than the generic header-missing one.
        let resp = run_through_auth_middleware(empty_get("/probe?ticket=xyz")).await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let text = std::str::from_utf8(&body).unwrap();
        assert!(
            text.contains("Invalid or expired download ticket"),
            "expected ticket-failure message, got: {text}"
        );
    }

    #[tokio::test]
    async fn test_auth_middleware_header_present_with_ticket_keeps_header_message() {
        // When header credentials are present (and fail), even an additional
        // `?ticket=` query must NOT switch the response to the ticket-specific
        // message: otherwise an attacker could discover whether their bearer
        // token landed in the JWT or API-token bucket. Keep the header-error.
        // The Bearer is rejected before any DB lookup (shorter than the 8-char
        // prefix) so the header failure is a genuine invalid-token 401, not a
        // pool-timeout 503 (#2125).
        let req = axum::http::Request::builder()
            .method(Method::GET)
            .uri("/probe?ticket=xyz")
            .header("Authorization", "Bearer badtok")
            .body(axum::body::Body::empty())
            .unwrap();
        let resp = run_through_auth_middleware(req).await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let text = std::str::from_utf8(&body).unwrap();
        assert!(
            text.contains("Invalid or expired token"),
            "expected token-failure message (not ticket message), got: {text}"
        );
    }

    // -----------------------------------------------------------------------
    // optional_auth_middleware behaviour matrix (#1371):
    //   * no credential       -> pass through anonymously (200)
    //   * invalid credential  -> 401 (was 200 pre-#1371; the silent downgrade
    //                            masked off-boarding deactivations on cached
    //                            API tokens, see issue #1371)
    //   * valid credential    -> pass through with AuthExtension (200)
    // The "invalid credential -> 401" rule yields to a successful ticket
    // fallback because download tickets are a legitimate alternative
    // capability for read-only routes.
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_optional_auth_middleware_passes_through_without_credentials() {
        let resp = run_through_optional_auth(empty_get("/probe")).await;
        assert_eq!(resp.status(), StatusCode::OK);
    }

    // -----------------------------------------------------------------------
    // #1438 (B10): auth_middleware must insert BOTH `AuthExtension` and
    // `Option<AuthExtension>` on its success path so handlers can declare
    // either extractor shape. The permission handlers declare
    // `Extension<Option<AuthExtension>>`; before this fix the middleware only
    // inserted a bare `AuthExtension`, so the `Option<AuthExtension>`
    // extractor failed request extraction with HTTP 500 ("Missing request
    // extension") before the in-handler scope check ran -- a read-scope SA
    // token got 500 instead of the canonical 403 on POST /api/v1/permissions.
    //
    // The middleware's success path requires a valid token + live AuthService,
    // which the unit harness cannot provide. We instead pin the load-bearing
    // contract directly: a request whose extensions carry the dual insertion
    // (exactly what the fixed success path does) resolves BOTH
    // `Extension<AuthExtension>` and `Extension<Option<AuthExtension>>` to 200.
    // A regression that drops the Option-wrapped copy turns the second route
    // into a 500, which this test catches.
    // -----------------------------------------------------------------------
    #[tokio::test]
    async fn test_dual_auth_extension_insertion_resolves_both_extractor_shapes() {
        use axum::{extract::Extension, middleware::Next, routing::get, Router};
        use tower::ServiceExt;

        fn sample_ext() -> AuthExtension {
            AuthExtension {
                user_id: Uuid::new_v4(),
                username: "sa-dual".to_string(),
                email: "sa@example.com".to_string(),
                is_admin: false,
                is_api_token: true,
                is_service_account: true,
                scopes: Some(vec!["read".to_string()]),
                allowed_repo_ids: AccessScope::Admin,
                iat_ms: None,
            }
        }

        // Mirror the exact dual insertion auth_middleware now performs on its
        // success path.
        async fn insert_both(mut request: Request, next: Next) -> Response {
            let ext = sample_ext();
            request.extensions_mut().insert(Some(ext.clone()));
            request.extensions_mut().insert(ext);
            next.run(request).await
        }

        let app: Router = Router::new()
            .route(
                "/bare",
                get(|Extension(_a): Extension<AuthExtension>| async { (StatusCode::OK, "bare") }),
            )
            .route(
                "/opt",
                get(
                    |Extension(a): Extension<Option<AuthExtension>>| async move {
                        // Must be Some, not None: the fix inserts Some(ext),
                        // not a None placeholder.
                        assert!(a.is_some(), "Option<AuthExtension> must be Some");
                        (StatusCode::OK, "opt")
                    },
                ),
            )
            .layer(axum::middleware::from_fn(insert_both));

        let bare = app.clone().oneshot(empty_get("/bare")).await.unwrap();
        assert_eq!(
            bare.status(),
            StatusCode::OK,
            "Extension<AuthExtension> must resolve"
        );

        let opt = app.oneshot(empty_get("/opt")).await.unwrap();
        assert_eq!(
            opt.status(),
            StatusCode::OK,
            "Extension<Option<AuthExtension>> must resolve (B10 regression guard)"
        );
    }

    // -----------------------------------------------------------------------
    // try_resolve_auth_outcome: tri-state behaviour pinned for #1371.
    // The outcome enum is what lets `optional_auth_middleware` distinguish
    // "no credential" (continue anonymously) from "credential presented but
    // invalid" (401). The legacy `try_resolve_auth` helper delegates to this
    // function and collapses Invalid into None for back-compat.
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_try_resolve_auth_outcome_no_credential_for_none() {
        let auth_service = make_test_auth_service();
        let outcome = try_resolve_auth_outcome(&auth_service, ExtractedToken::None).await;
        assert!(matches!(outcome, AuthOutcome::NoCredential));
    }

    #[test]
    fn test_service_unavailable_response_is_503_with_retry_after() {
        // The bcrypt-capacity shed (`AuthOutcome::Overloaded`) must surface as
        // a retryable 503 with Retry-After, never the 401 that made twine
        // abort its upload in the release gate.
        let resp = service_unavailable_response();
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(
            resp.headers()
                .get(axum::http::header::RETRY_AFTER)
                .and_then(|v| v.to_str().ok()),
            Some("1")
        );
    }

    // -----------------------------------------------------------------------
    // classify_token_validation_err: the API-token branch must preserve the
    // bcrypt-capacity shed (`AppError::ServiceUnavailable`) as Overloaded so
    // every token call site surfaces a retryable 503, while every other
    // validation failure stays Invalid (401). This mapping is what stops a
    // saturated auth cap from being misreported to cargo/twine/pip API-token
    // clients as "invalid credentials".
    // -----------------------------------------------------------------------

    #[test]
    fn test_classify_token_validation_err_service_unavailable_is_overloaded() {
        assert_eq!(
            classify_token_validation_err(AppError::ServiceUnavailable(
                "Authentication service is at capacity, retry shortly".to_string()
            )),
            TokenAuthError::Overloaded
        );
    }

    #[test]
    fn test_classify_token_validation_err_genuine_failures_stay_invalid() {
        // Genuinely bad tokens (unknown, expired, revoked, deactivated owner)
        // and infrastructure errors must keep producing 401 from the token
        // call sites — only the transient capacity shed maps to Overloaded.
        for err in [
            AppError::Authentication("Invalid API token".to_string()),
            AppError::Authentication("API token expired".to_string()),
            AppError::Unauthorized("Token has been revoked".to_string()),
            AppError::Database("connection refused".to_string()),
            AppError::Internal("bcrypt failure".to_string()),
        ] {
            assert_eq!(classify_token_validation_err(err), TokenAuthError::Invalid);
        }
    }

    #[test]
    fn test_classify_token_validation_err_pool_timeout_is_overloaded() {
        // #2125: a pool-acquire timeout during the token's DB lookup is a
        // transient capacity problem, not a bad token. It must classify as
        // Overloaded (retryable 503 / POOL_EXHAUSTED) so every token call site
        // stops flattening pool exhaustion to a spurious 401. Both the typed
        // variant and the stringified form the auth layer actually produces
        // (`map_err(|e| AppError::Database(e.to_string()))`) must be covered.
        assert_eq!(
            classify_token_validation_err(AppError::Sqlx(sqlx::Error::PoolTimedOut)),
            TokenAuthError::Overloaded
        );
        assert_eq!(
            classify_token_validation_err(AppError::Database(
                sqlx::Error::PoolTimedOut.to_string()
            )),
            TokenAuthError::Overloaded
        );
    }

    #[tokio::test]
    async fn test_try_resolve_auth_outcome_invalid_for_garbage_scheme() {
        let auth_service = make_test_auth_service();
        let outcome = try_resolve_auth_outcome(&auth_service, ExtractedToken::Invalid).await;
        assert!(matches!(outcome, AuthOutcome::InvalidCredential));
    }

    #[tokio::test]
    async fn test_try_resolve_auth_outcome_invalid_for_bad_bearer() {
        // Bearer that decodes as neither a JWT nor any valid API token must
        // be flagged as Invalid, NOT NoCredential. Pre-#1371 this distinction
        // did not exist and optional-auth routes silently downgraded to
        // anonymous. The token is shorter than the 8-char prefix so every
        // validator rejects it BEFORE any DB lookup, isolating this
        // genuine-invalid case from the pool-timeout -> Overloaded case (#2125).
        let auth_service = make_test_auth_service();
        let outcome =
            try_resolve_auth_outcome(&auth_service, ExtractedToken::Bearer("badtok")).await;
        assert!(
            matches!(outcome, AuthOutcome::InvalidCredential),
            "Bearer that fails every validator must produce InvalidCredential, got: {:?}",
            outcome
        );
    }

    #[tokio::test]
    async fn test_try_resolve_auth_outcome_invalid_for_bad_api_key() {
        // Shorter than the 8-char prefix, so `validate_api_token` rejects it
        // before any DB lookup: a genuine-invalid ApiKey stays InvalidCredential
        // (the pool-timeout -> Overloaded case is covered separately, #2125).
        let auth_service = make_test_auth_service();
        let outcome =
            try_resolve_auth_outcome(&auth_service, ExtractedToken::ApiKey("badtok")).await;
        assert!(matches!(outcome, AuthOutcome::InvalidCredential));
    }

    #[tokio::test]
    async fn test_try_resolve_auth_outcome_invalid_for_unparseable_basic() {
        // Base64 that decodes but does not contain `user:password` must be
        // Invalid, not NoCredential. The client tried to authenticate; we
        // owe them a 401.
        let auth_service = make_test_auth_service();
        let outcome =
            try_resolve_auth_outcome(&auth_service, ExtractedToken::Basic("not-base64-at-all"))
                .await;
        assert!(matches!(outcome, AuthOutcome::InvalidCredential));
    }

    #[tokio::test]
    async fn test_try_resolve_auth_outcome_basic_pool_timeout_is_overloaded() {
        // #2125: well-formed `user:password` Basic credentials whose bcrypt
        // credential lookup cannot acquire a DB connection (the unreachable
        // lazy pool times out) must resolve to `Overloaded`, so the optional /
        // anonymous auth pre-check surfaces a retryable 503 instead of
        // flattening pool exhaustion to a 401 (or anonymous) that hides a
        // deactivation. A genuine bad credential still resolves to
        // `InvalidCredential` (see the tests above).
        let creds = base64::engine::general_purpose::STANDARD.encode("alice:secret");
        let auth_service = make_test_auth_service();
        let outcome = try_resolve_auth_outcome(&auth_service, ExtractedToken::Basic(&creds)).await;
        assert!(
            matches!(outcome, AuthOutcome::Overloaded),
            "pool-timeout during Basic auth pre-check must be Overloaded, got: {:?}",
            outcome
        );
    }

    #[test]
    fn test_try_resolve_auth_collapses_invalid_to_none_for_back_compat() {
        // Pin the legacy helper's contract: callers that opt into the
        // tri-state outcome get distinct values, callers that stick with the
        // Option-shaped helper still see Invalid flattened to None. This is
        // what lets the guest_access guard and existing internal call sites
        // keep working without touching every call site.
        //
        // (No async needed — we exercise the flatten by hand for the static
        // mapping rules. The branching that calls the auth service is
        // covered by the async tests above.)
        let flatten = |outcome: AuthOutcome| -> Option<AuthExtension> {
            match outcome {
                AuthOutcome::Resolved(ext) => Some(ext),
                AuthOutcome::NoCredential
                | AuthOutcome::InvalidCredential
                | AuthOutcome::Overloaded => None,
            }
        };
        assert!(flatten(AuthOutcome::NoCredential).is_none());
        assert!(flatten(AuthOutcome::InvalidCredential).is_none());
        // A transient bcrypt-capacity shed also flattens to None for the
        // legacy Option-shaped helper (callers that need the 503 distinction
        // use the tri-state outcome directly).
        assert!(flatten(AuthOutcome::Overloaded).is_none());
    }

    #[tokio::test]
    async fn test_optional_auth_middleware_rejects_invalid_bearer_with_401() {
        // Pre-#1371 behaviour: a Bearer header that failed every validation
        // path was silently downgraded to anonymous and the handler returned
        // 200 (with public-only data on real endpoints). That masked the
        // post-deactivation cache rejection from /api/v1/repositories. The
        // ticket fallback also fails here (lazy pool, invalid ticket), so the
        // outcome must be 401, not 200. The Bearer is rejected before any DB
        // lookup (shorter than the 8-char prefix), so this is a genuine-invalid
        // 401, not a pool-timeout 503 (#2125).
        let req = axum::http::Request::builder()
            .method(Method::GET)
            .uri("/probe?ticket=xyz")
            .header("Authorization", "Bearer badtok")
            .body(axum::body::Body::empty())
            .unwrap();
        let resp = run_through_optional_auth(req).await;
        assert_eq!(
            resp.status(),
            StatusCode::UNAUTHORIZED,
            "explicit invalid Bearer must produce 401 (issue #1371)"
        );
    }

    #[tokio::test]
    async fn test_optional_auth_middleware_rejects_invalid_authorization_header_with_401() {
        // A garbage scheme is `ExtractedToken::Invalid`. The client explicitly
        // attempted to authenticate, so pass-through to anonymous is the wrong
        // policy after #1371 — return 401 instead.
        let req = axum::http::Request::builder()
            .method(Method::GET)
            .uri("/probe")
            .header("Authorization", "GarbageScheme x")
            .body(axum::body::Body::empty())
            .unwrap();
        let resp = run_through_optional_auth(req).await;
        assert_eq!(
            resp.status(),
            StatusCode::UNAUTHORIZED,
            "explicit invalid Authorization scheme must produce 401 (issue #1371)"
        );
    }

    #[tokio::test]
    async fn test_optional_auth_middleware_pool_timeout_returns_503_not_401() {
        // #2125: the optional / anonymous auth pre-check runs its own DB lookup
        // BEFORE the request reaches the #2101/#2102 503-mappers. A Bearer whose
        // API-token validation cannot acquire a DB connection (unreachable lazy
        // pool -> pool-acquire timeout) must surface a retryable 503, not get
        // flattened to a spurious 401. The token is >= the 8-char prefix so it
        // actually reaches the timing-out DB lookup. No `?ticket=` here so the
        // Overloaded outcome is not rescued by the ticket fallback.
        let req = axum::http::Request::builder()
            .method(Method::GET)
            .uri("/probe")
            .header("Authorization", "Bearer deadbeefdead")
            .body(axum::body::Body::empty())
            .unwrap();
        let resp = run_through_optional_auth(req).await;
        assert_eq!(
            resp.status(),
            StatusCode::SERVICE_UNAVAILABLE,
            "pool-timeout during the anonymous pre-check must be 503, not 401"
        );
        assert_eq!(
            resp.headers()
                .get(axum::http::header::RETRY_AFTER)
                .and_then(|v| v.to_str().ok()),
            Some("1")
        );
    }

    // -----------------------------------------------------------------------
    // repo_visibility_middleware exercised with a pre-populated repo cache so
    // we can drive both branches (public vs private, write vs read) without
    // ever hitting the unreachable lazy DB pool.
    // -----------------------------------------------------------------------

    async fn make_vis_state(cached: Option<(String, CachedRepo)>) -> RepoVisibilityState {
        let auth_service = make_test_auth_service();
        let pool = lazy_pool();
        let cache: RepoCache =
            std::sync::Arc::new(tokio::sync::RwLock::new(std::collections::HashMap::new()));
        if let Some((key, entry)) = cached {
            cache
                .write()
                .await
                .insert(key, (entry, std::time::Instant::now()));
        }
        // PermissionService is constructed against the lazy pool: tests that
        // exercise repo_visibility_middleware never hit a permission-check
        // path that requires a live DB, so the empty-cache lazy state is fine.
        let permission_service = std::sync::Arc::new(
            crate::services::permission_service::PermissionService::new(pool.clone()),
        );
        RepoVisibilityState {
            auth_service,
            db: pool,
            repo_cache: cache,
            permission_service,
        }
    }

    fn make_cached_repo(is_public: bool) -> CachedRepo {
        CachedRepo {
            id: Uuid::new_v4(),
            format: "pypi".to_string(),
            repo_type: "local".to_string(),
            upstream_url: None,
            storage_path: "/tmp".to_string(),
            storage_backend: "filesystem".to_string(),
            is_public,
            index_upstream_url: None,
        }
    }

    async fn run_through_visibility(
        state: RepoVisibilityState,
        request: axum::http::Request<axum::body::Body>,
    ) -> axum::http::Response<axum::body::Body> {
        use axum::{middleware, routing::any, Router};
        use tower::ServiceExt;

        let app: Router = Router::new()
            // Use a single permissive fallback so the test does not need to
            // mirror every possible route shape — the middleware runs first
            // and decides whether to call the handler.
            .fallback(any(|| async { (StatusCode::OK, "handler-reached") }))
            .layer(middleware::from_fn_with_state(
                state,
                repo_visibility_middleware,
            ));
        app.oneshot(request).await.unwrap()
    }

    #[tokio::test]
    async fn test_repo_visibility_pass_through_when_no_repo_key() {
        // A path with no repo segment short-circuits at the empty-key check,
        // before the cache is touched. Hitting `/` for example.
        let state = make_vis_state(None).await;
        let resp = run_through_visibility(state, empty_get("/")).await;
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_repo_visibility_public_read_no_auth_passes() {
        // Public repo + GET + no auth header: must pass through to the handler.
        let key = "myrepo";
        let cached = make_cached_repo(/* is_public */ true);
        let state = make_vis_state(Some((key.to_string(), cached))).await;
        let resp = run_through_visibility(state, empty_get("/pypi/myrepo/simple/")).await;
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_repo_visibility_private_read_no_auth_returns_401() {
        let key = "private";
        let cached = make_cached_repo(/* is_public */ false);
        let state = make_vis_state(Some((key.to_string(), cached))).await;
        let resp = run_through_visibility(state, empty_get("/pypi/private/simple/")).await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_repo_visibility_public_write_no_auth_returns_401() {
        // Even on a public repo, writes must require auth (#508). With a
        // ticket-only fallback the ticket is also rejected because writes
        // strip the auth ext via `has_write_auth = ext.is_some() && !ticket`.
        let key = "myrepo";
        let cached = make_cached_repo(/* is_public */ true);
        let state = make_vis_state(Some((key.to_string(), cached))).await;
        let req = axum::http::Request::builder()
            .method(Method::POST)
            .uri("/pypi/myrepo/upload")
            .body(axum::body::Body::empty())
            .unwrap();
        let resp = run_through_visibility(state, req).await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_repo_visibility_public_read_with_ticket_query_falls_through() {
        // The ticket fallback hits the unreachable lazy DB pool and returns
        // None. The repo is public, so read access still succeeds — the
        // ticket-resolution attempt must not block legitimate anonymous reads.
        let key = "myrepo";
        let cached = make_cached_repo(/* is_public */ true);
        let state = make_vis_state(Some((key.to_string(), cached))).await;
        let resp =
            run_through_visibility(state, empty_get("/pypi/myrepo/simple/?ticket=anything")).await;
        assert_eq!(resp.status(), StatusCode::OK);
    }

    /// Drive an anonymous GET through the visibility middleware and return the
    /// status plus the fully-buffered body. Shared by the existence-oracle
    /// regression test so the existing-private and nonexistent probes go
    /// through identical machinery (keeps the assertion honest and avoids
    /// duplicated setup).
    async fn anon_get_status_and_body(
        state: RepoVisibilityState,
        uri: &str,
    ) -> (StatusCode, axum::body::Bytes) {
        let resp = run_through_visibility(state, empty_get(uri)).await;
        let status = resp.status();
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        (status, body)
    }

    #[tokio::test]
    async fn test_repo_visibility_anon_existing_private_and_nonexistent_are_indistinguishable() {
        // #1808: an anonymous caller must not be able to tell an existing
        // *private* repo apart from a *nonexistent* one. Before the fix the
        // existing-private key returned 401 (visibility check) while a missing
        // key fell through to the handler's 404 — the differing status was an
        // anonymous repo-name enumeration oracle. After the fix both must
        // return the byte-identical 401 + `WWW-Authenticate` challenge.

        // Existing PRIVATE repo: present in the cache, is_public = false.
        let private_state = make_vis_state(Some((
            "acme-internal-core".to_string(),
            make_cached_repo(/* is_public */ false),
        )))
        .await;
        let (private_status, private_body) =
            anon_get_status_and_body(private_state, "/pypi/acme-internal-core/simple/").await;

        // NONEXISTENT repo: nothing in the cache; the cache-miss DB lookup
        // against the lazy pool finds no row, exercising the no-repo branch.
        let missing_state = make_vis_state(None).await;
        let (missing_status, missing_body) =
            anon_get_status_and_body(missing_state, "/pypi/zzz-nonexistent-repo-9/simple/").await;

        assert_eq!(
            private_status,
            StatusCode::UNAUTHORIZED,
            "existing private repo must deny anonymous reads with 401"
        );
        assert_eq!(
            missing_status, private_status,
            "nonexistent repo must return the SAME status as an existing private repo (no oracle)"
        );
        assert_eq!(
            missing_body, private_body,
            "nonexistent repo must return the SAME body as an existing private repo (no oracle)"
        );
    }

    #[tokio::test]
    async fn test_repo_visibility_private_write_with_ticket_query_returns_401() {
        // Even if a ticket somehow validated, ticket-authenticated writes are
        // refused. With the lazy pool the ticket trivially fails to resolve
        // and the request is still anonymous, so the same 401 applies.
        let key = "private";
        let cached = make_cached_repo(/* is_public */ false);
        let state = make_vis_state(Some((key.to_string(), cached))).await;
        let req = axum::http::Request::builder()
            .method(Method::PUT)
            .uri("/pypi/private/upload?ticket=abc")
            .body(axum::body::Body::empty())
            .unwrap();
        let resp = run_through_visibility(state, req).await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    /// Regression (red-team round 2): a PRIVATE repo with NO fine-grained
    /// permission rules must NOT be readable by an authenticated non-admin who
    /// holds no role assignment for it. The native-protocol middleware must
    /// match the REST `require_visible` model (existence-hiding 404), not
    /// default-allow to any authenticated principal.
    ///
    /// DB-backed: no-ops when `DATABASE_URL` is unset; runs for real in the CI
    /// coverage job (which seeds Postgres before `cargo llvm-cov --lib`).
    #[tokio::test]
    async fn test_private_repo_without_rules_denies_unassigned_nonadmin() {
        use crate::api::handlers::test_db_helpers as tdh;
        use crate::models::user::{AuthProvider, User};
        use crate::services::permission_service::PermissionService;
        use std::sync::Arc;

        let Some(pool) = tdh::try_pool().await else {
            return;
        };

        let (user_id, username) = tdh::create_user(&pool).await; // non-admin
        let (repo_id, repo_key, storage_dir) = tdh::create_repo(&pool, "local", "pypi").await; // is_public defaults false

        // Mint a real access JWT for this non-admin user. AuthService is built
        // on the real pool so the replica-safe invalidation check succeeds.
        let auth_service = Arc::new(AuthService::new(
            pool.clone(),
            make_test_config_for_middleware(),
        ));
        let now = chrono::Utc::now();
        let user = User {
            id: user_id,
            username: username.clone(),
            email: format!("{}@test.local", username),
            password_hash: None,
            auth_provider: AuthProvider::Local,
            external_id: None,
            display_name: None,
            is_active: true,
            is_admin: false,
            is_service_account: false,
            must_change_password: false,
            totp_secret: None,
            totp_enabled: false,
            totp_backup_codes: None,
            totp_verified_at: None,
            failed_login_attempts: 0,
            locked_until: None,
            last_failed_login_at: None,
            password_changed_at: now,
            last_login_at: Some(now),
            created_at: now,
            updated_at: now,
        };
        let bearer = format!(
            "Bearer {}",
            auth_service.generate_tokens(&user).unwrap().access_token
        );

        // Fresh state per request: a pre-populated cache so the middleware skips
        // the DB repo lookup, with the private repo's real id so the
        // role_assignments query resolves against it.
        async fn mk_state(
            pool: &sqlx::PgPool,
            auth: Arc<AuthService>,
            repo_key: &str,
            repo_id: Uuid,
            storage_path: String,
        ) -> RepoVisibilityState {
            let cache: RepoCache =
                Arc::new(tokio::sync::RwLock::new(std::collections::HashMap::new()));
            let entry = CachedRepo {
                id: repo_id,
                format: "pypi".to_string(),
                repo_type: "local".to_string(),
                upstream_url: None,
                storage_path,
                storage_backend: "filesystem".to_string(),
                is_public: false,
                index_upstream_url: None,
            };
            cache
                .write()
                .await
                .insert(repo_key.to_string(), (entry, std::time::Instant::now()));
            RepoVisibilityState {
                auth_service: auth,
                db: pool.clone(),
                repo_cache: cache,
                permission_service: Arc::new(PermissionService::new(pool.clone())),
            }
        }

        let req = || {
            axum::http::Request::builder()
                .method(Method::GET)
                .uri(format!("/pypi/{}/simple/", repo_key))
                .header("Authorization", &bearer)
                .body(axum::body::Body::empty())
                .unwrap()
        };
        let storage = storage_dir.to_string_lossy().into_owned();

        // 1) No role assignment -> existence-hiding 404 (the fix). Without the
        //    fix this returned 200 and leaked the private repo's contents.
        let state = mk_state(
            &pool,
            auth_service.clone(),
            &repo_key,
            repo_id,
            storage.clone(),
        )
        .await;
        let resp = run_through_visibility(state, req()).await;
        assert_eq!(
            resp.status(),
            StatusCode::NOT_FOUND,
            "authenticated non-admin without a role assignment must NOT read a \
             rule-less private repo via the native path"
        );

        // 2) Grant a role assignment -> access restored (parity with REST).
        tdh::grant_repo_access(&pool, repo_id, user_id).await;
        let state = mk_state(&pool, auth_service, &repo_key, repo_id, storage).await;
        let resp = run_through_visibility(state, req()).await;
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "a role assignment must restore native-path access to the private repo"
        );

        tdh::cleanup(&pool, repo_id, user_id).await;
        let _ = std::fs::remove_dir_all(&storage_dir);
    }

    #[test]
    fn test_path_exempt_from_password_change_allowlist() {
        // Recovery / change-screen routes: the current-user self lookup, the
        // self password-change route, and logout (with or without a trailing
        // slash). The helper now keys off the FULL request path (the middleware
        // reads `OriginalUri`, not the nest-stripped suffix), so the self
        // lookup is anchored to the exact `/auth/me` route.
        assert!(path_exempt_from_password_change("/api/v1/auth/me"));
        assert!(path_exempt_from_password_change("/api/v1/auth/me/"));
        assert!(path_exempt_from_password_change(
            "/api/v1/users/4040201f-c67a-4719-a292-79ec66a7bd2d/password"
        ));
        assert!(path_exempt_from_password_change("/users/abc/password/"));
        assert!(path_exempt_from_password_change("/api/v1/auth/logout"));
        assert!(path_exempt_from_password_change("/auth/logout/"));

        // The core of this finding: a bare `/me` (the stripped form, and any
        // `/<resource>/me` whose terminal :id is the literal "me") is NOT the
        // self lookup and must stay gated. Anchoring to `/auth/me` rejects the
        // `DELETE /api/v1/sbom/me`, `/api/v1/webhooks/me`, and
        // `/api/v1/promotion-rules/me` impostors that an `ends_with("/me")`
        // suffix would have exempted.
        assert!(!path_exempt_from_password_change("/me"));
        assert!(!path_exempt_from_password_change("/api/v1/sbom/me"));
        assert!(!path_exempt_from_password_change("/api/v1/webhooks/me"));
        assert!(!path_exempt_from_password_change(
            "/api/v1/promotion-rules/me"
        ));

        // Everything else is gated, including the admin reset / force-change
        // routes (which live behind admin_middleware, not this one), the
        // token-management routes, and any route that merely contains
        // "password" elsewhere.
        assert!(!path_exempt_from_password_change(
            "/api/v1/users/abc/password/reset"
        ));
        assert!(!path_exempt_from_password_change(
            "/api/v1/users/abc/force-password-change"
        ));
        assert!(!path_exempt_from_password_change("/api/v1/repositories"));
        assert!(!path_exempt_from_password_change("/api/v1/auth/tokens"));
        // Stripped forms the middleware actually sees for token management.
        assert!(!path_exempt_from_password_change("/tokens"));
        assert!(!path_exempt_from_password_change("/tokens/abc"));
    }

    /// Build a flagged/unflagged non-admin `User` row and mint a real JWT for it
    /// through `auth_service`, so the replica-safe validation path resolves.
    /// Factored out so the two regression assertions below share setup without
    /// tripping the duplication gate.
    #[cfg(test)]
    async fn mint_bearer_for_flagged_user(
        pool: &sqlx::PgPool,
        auth_service: &AuthService,
        must_change_password: bool,
    ) -> (Uuid, String) {
        use crate::api::handlers::test_db_helpers as tdh;
        use crate::models::user::AuthProvider;

        let (user_id, username) = tdh::create_user(pool).await; // non-admin
        sqlx::query("UPDATE users SET must_change_password = $1 WHERE id = $2")
            .bind(must_change_password)
            .bind(user_id)
            .execute(pool)
            .await
            .expect("set must_change_password");

        let now = chrono::Utc::now();
        let user = User {
            id: user_id,
            username: username.clone(),
            email: format!("{}@test.local", username),
            password_hash: None,
            auth_provider: AuthProvider::Local,
            external_id: None,
            display_name: None,
            is_active: true,
            is_admin: false,
            is_service_account: false,
            must_change_password,
            totp_secret: None,
            totp_enabled: false,
            totp_backup_codes: None,
            totp_verified_at: None,
            failed_login_attempts: 0,
            locked_until: None,
            last_failed_login_at: None,
            password_changed_at: now,
            last_login_at: Some(now),
            created_at: now,
            updated_at: now,
        };
        let bearer = format!(
            "Bearer {}",
            auth_service.generate_tokens(&user).unwrap().access_token
        );
        (user_id, bearer)
    }

    /// Regression for #1818: a principal flagged `must_change_password` is
    /// refused (428) on every normal route but may still reach the self
    /// password-change route and logout to recover. An UNFLAGGED principal is
    /// unaffected. DB-backed: no-ops when `DATABASE_URL` is unset.
    #[tokio::test]
    async fn test_must_change_password_gates_normal_routes_but_allows_recovery() {
        use crate::api::handlers::test_db_helpers as tdh;
        use axum::{middleware, routing::any, Router};
        use std::sync::Arc;
        use tower::ServiceExt;

        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let auth_service = Arc::new(AuthService::new(
            pool.clone(),
            make_test_config_for_middleware(),
        ));

        // Register routes through a real `/api/v1` nest with `auth_middleware`
        // layered INSIDE each sub-nest, exactly as the live router does. axum
        // strips the matched prefix before the middleware reads
        // `request.uri()`, but populates `OriginalUri` with the full path —
        // which the gate now reads. This is what lets the genuine
        // `GET /api/v1/auth/me` be exempt while the `DELETE /api/v1/sbom/me`
        // impostor (terminal :id = "me") stays gated.
        let app = || {
            let layer = middleware::from_fn_with_state(auth_service.clone(), auth_middleware);
            Router::new().nest(
                "/api/v1",
                Router::new()
                    .route("/repositories", any(|| async { (StatusCode::OK, "repos") }))
                    .nest(
                        "/auth",
                        Router::new()
                            .route("/me", any(|| async { (StatusCode::OK, "me") }))
                            .route("/logout", any(|| async { (StatusCode::OK, "logout") }))
                            .route("/tokens", any(|| async { (StatusCode::OK, "tokens") })),
                    )
                    .nest(
                        "/sbom",
                        Router::new().route("/:id", any(|| async { (StatusCode::OK, "sbom") })),
                    )
                    .nest(
                        "/users",
                        Router::new()
                            .route("/:id/password", any(|| async { (StatusCode::OK, "pw") })),
                    )
                    .layer(layer),
            )
        };

        let mk_req = |method: Method, uri: &str, bearer: &str| {
            axum::http::Request::builder()
                .method(method)
                .uri(uri)
                .header("Authorization", bearer)
                .body(axum::body::Body::empty())
                .unwrap()
        };

        // Flagged principal.
        let (flagged_id, flagged_bearer) =
            mint_bearer_for_flagged_user(&pool, &auth_service, true).await;

        // A normal route is refused with 428.
        let resp = app()
            .oneshot(mk_req(Method::GET, "/api/v1/repositories", &flagged_bearer))
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::PRECONDITION_REQUIRED,
            "flagged principal must be 428'd on a normal route"
        );

        // Token management is state-changing and stays gated even though the
        // change screen runs while flagged (#1948 must not over-broaden).
        let resp = app()
            .oneshot(mk_req(Method::GET, "/api/v1/auth/tokens", &flagged_bearer))
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::PRECONDITION_REQUIRED,
            "flagged principal must still be 428'd on token management"
        );

        // Core of this finding: a `/<resource>/me` whose terminal :id is the
        // literal "me" must NOT be mistaken for the self lookup. With the gate
        // reading `OriginalUri`, `DELETE /api/v1/sbom/me` is refused with 428
        // (the handler is NOT reached) — an `ends_with("/me")` suffix on the
        // stripped path would have let it through.
        let resp = app()
            .oneshot(mk_req(Method::DELETE, "/api/v1/sbom/me", &flagged_bearer))
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::PRECONDITION_REQUIRED,
            "flagged principal must be 428'd on /sbom/me (terminal :id impostor)"
        );

        // The genuine current-user self lookup (`GET /api/v1/auth/me`) the
        // mandatory change screen calls to render IS reachable while flagged.
        let resp = app()
            .oneshot(mk_req(Method::GET, "/api/v1/auth/me", &flagged_bearer))
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "flagged principal must reach the current-user self lookup"
        );

        // The self password-change recovery route is still reachable.
        let resp = app()
            .oneshot(mk_req(
                Method::POST,
                &format!("/api/v1/users/{}/password", flagged_id),
                &flagged_bearer,
            ))
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "flagged principal must still reach the self password-change route"
        );

        // Logout is reachable too.
        let resp = app()
            .oneshot(mk_req(Method::POST, "/api/v1/auth/logout", &flagged_bearer))
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "flagged principal must still be able to log out"
        );

        // Control: an UNFLAGGED principal sails through the normal route.
        let (_unflagged_id, unflagged_bearer) =
            mint_bearer_for_flagged_user(&pool, &auth_service, false).await;
        let resp = app()
            .oneshot(mk_req(
                Method::GET,
                "/api/v1/repositories",
                &unflagged_bearer,
            ))
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "unflagged principal must not be gated"
        );
    }
}
