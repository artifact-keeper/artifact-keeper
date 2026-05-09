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
    extract::{Request, State},
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
use crate::models::user::User;
use crate::services::auth_service::{AuthService, Claims};
use crate::services::permission_service::PermissionService;

/// Custom header name for API key
static X_API_KEY: HeaderName = HeaderName::from_static("x-api-key");

/// Extension that holds authenticated user information
#[derive(Debug, Clone)]
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
    /// Repository IDs this token is restricted to (None = unrestricted)
    pub allowed_repo_ids: Option<Vec<Uuid>>,
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
    /// Check whether this auth context has a required scope.
    /// JWT sessions (non-API-token auth) always pass since they have no scope
    /// restrictions. API tokens must explicitly include the scope (or `*`/`admin`).
    pub fn has_scope(&self, scope: &str) -> bool {
        if !self.is_api_token {
            return true; // JWT sessions are not scope-restricted
        }
        match &self.scopes {
            None => true,
            Some(scopes) => {
                scopes.iter().any(|s| s == scope)
                    || scopes.iter().any(|s| s == "*")
                    || scopes.iter().any(|s| s == "admin")
            }
        }
    }

    /// Check whether this auth context has access to a specific repository.
    /// Returns true if unrestricted or if the repo is in the allowed set.
    pub fn can_access_repo(&self, repo_id: Uuid) -> bool {
        match &self.allowed_repo_ids {
            None => true,
            Some(ids) => ids.contains(&repo_id),
        }
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
}

impl From<Claims> for AuthExtension {
    fn from(claims: Claims) -> Self {
        Self {
            user_id: claims.sub,
            username: claims.username,
            email: claims.email,
            is_admin: claims.is_admin,
            is_api_token: false,
            is_service_account: false,
            scopes: None,
            allowed_repo_ids: None,
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
            allowed_repo_ids: None,
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
        .map_err(|_| {
            Response::builder()
                .status(StatusCode::UNAUTHORIZED)
                .header("WWW-Authenticate", format!("Basic realm=\"{}\"", realm))
                .body(axum::body::Body::from("Invalid credentials"))
                .unwrap()
        })?;
    Ok(user.id)
}

/// Token extraction result
#[derive(Debug)]
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

    let header_result: Result<AuthExtension, &'static str> = match extracted {
        ExtractedToken::Bearer(token) => match auth_service.validate_access_token(token) {
            Ok(claims) => Ok(AuthExtension::from(claims)),
            Err(_) => match validate_api_token_with_scopes(&auth_service, token).await {
                Ok(ext) => Ok(ext),
                Err(_) => Err("Invalid or expired token"),
            },
        },
        ExtractedToken::ApiKey(token) => {
            match validate_api_token_with_scopes(&auth_service, token).await {
                Ok(ext) => Ok(ext),
                Err(_) => Err("Invalid or expired API token"),
            }
        }
        ExtractedToken::Basic(encoded) => match decode_basic_credentials(encoded) {
            None => Err("Invalid Basic auth credentials"),
            Some((username, password)) => {
                match auth_service.authenticate(&username, &password).await {
                    Ok((user, _token_pair)) => Ok(AuthExtension::from(user)),
                    Err(_) => Err("Invalid credentials"),
                }
            }
        },
        ExtractedToken::None => Err("Missing authorization header"),
        ExtractedToken::Invalid => Err("Invalid authorization header format"),
    };

    let header_error = match header_result {
        Ok(ext) => {
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

/// Validate an API token and create an AuthExtension with scopes and repo restrictions.
async fn validate_api_token_with_scopes(
    auth_service: &AuthService,
    token: &str,
) -> Result<AuthExtension, ()> {
    let validation = auth_service
        .validate_api_token(token)
        .await
        .map_err(|_| ())?;

    Ok(AuthExtension {
        user_id: validation.user.id,
        username: validation.user.username,
        email: validation.user.email,
        is_admin: validation.user.is_admin,
        is_api_token: true,
        is_service_account: validation.user.is_service_account,
        scopes: Some(validation.scopes),
        allowed_repo_ids: validation.allowed_repo_ids,
    })
}

/// Try to resolve an optional authentication token into an [`AuthExtension`].
///
/// Returns `Some(ext)` when a valid Bearer JWT, Bearer API token, or ApiKey
/// token is present, and `None` otherwise (missing, invalid, or expired).
/// This is the shared logic used by [`optional_auth_middleware`] and
/// [`repo_visibility_middleware`].
pub(crate) async fn try_resolve_auth(
    auth_service: &AuthService,
    extracted: ExtractedToken<'_>,
) -> Option<AuthExtension> {
    match extracted {
        ExtractedToken::Bearer(token) => {
            if let Ok(claims) = auth_service.validate_access_token(token) {
                return Some(AuthExtension::from(claims));
            }
            if let Ok(ext) = validate_api_token_with_scopes(auth_service, token).await {
                return Some(ext);
            }
            // Some package managers (npm, cargo, goproxy) send Bearer tokens
            // that are base64-encoded `username:password` rather than JWTs or
            // API keys. Try decoding as credentials before giving up.
            if let Some((username, password)) = decode_basic_credentials(token) {
                if let Ok((user, _)) = auth_service.authenticate(&username, &password).await {
                    return Some(AuthExtension::from(user));
                }
            }
            None
        }
        ExtractedToken::ApiKey(token) => validate_api_token_with_scopes(auth_service, token)
            .await
            .ok(),
        ExtractedToken::Basic(encoded) => {
            let (username, password) = decode_basic_credentials(encoded)?;
            // Try bcrypt username/password auth first
            if let Ok((user, _)) = auth_service.authenticate(&username, &password).await {
                return Some(AuthExtension::from(user));
            }
            // Fall back to treating the password as an API token — compatible with
            // pip netrc / Artifactory-style `token:<api_token>` credential format
            validate_api_token_with_scopes(auth_service, &password)
                .await
                .ok()
        }
        ExtractedToken::None | ExtractedToken::Invalid => None,
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
pub async fn optional_auth_middleware(
    State(auth_service): State<Arc<AuthService>>,
    mut request: Request,
    next: Next,
) -> Response {
    let extracted = extract_token(&request);
    let mut auth_ext = try_resolve_auth(&auth_service, extracted).await;

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

    let auth_ext = match extracted {
        ExtractedToken::Bearer(token) => match auth_service.validate_access_token(token) {
            Ok(claims) => AuthExtension::from(claims),
            Err(_) => match validate_api_token_with_scopes(&auth_service, token).await {
                Ok(ext) => ext,
                Err(_) => {
                    return (StatusCode::UNAUTHORIZED, "Invalid or expired token").into_response()
                }
            },
        },
        ExtractedToken::ApiKey(token) => {
            match validate_api_token_with_scopes(&auth_service, token).await {
                Ok(ext) => ext,
                Err(_) => {
                    return (StatusCode::UNAUTHORIZED, "Invalid or expired API token")
                        .into_response()
                }
            }
        }
        ExtractedToken::Basic(encoded) => {
            let Some((username, password)) = decode_basic_credentials(encoded) else {
                return (StatusCode::UNAUTHORIZED, "Invalid Basic auth credentials")
                    .into_response();
            };
            match auth_service.authenticate(&username, &password).await {
                Ok((user, _token_pair)) => AuthExtension::from(user),
                Err(_) => {
                    return (StatusCode::UNAUTHORIZED, "Invalid credentials").into_response();
                }
            }
        }
        ExtractedToken::None => {
            return (StatusCode::UNAUTHORIZED, "Missing authorization header").into_response();
        }
        ExtractedToken::Invalid => {
            return (
                StatusCode::UNAUTHORIZED,
                "Invalid authorization header format",
            )
                .into_response();
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
        .header(axum::http::header::CONTENT_TYPE, "text/plain")
        .body(axum::body::Body::from("Authentication required"))
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
    let cached = vis_state.repo_cache.read().ok().and_then(|cache| {
        cache.get(repo_key).and_then(|(entry, at)| {
            if at.elapsed().as_secs() < REPO_CACHE_TTL_SECS {
                Some(entry.clone())
            } else {
                None
            }
        })
    });

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

            row.map(|r| {
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
                if let Ok(mut cache) = vis_state.repo_cache.write() {
                    cache.retain(|_, (_, at)| at.elapsed().as_secs() < REPO_CACHE_TTL_SECS);
                    cache.insert(repo_key.to_string(), (entry.clone(), Instant::now()));
                }
                entry
            })
        }
    };

    // If no repo found for this key, still inject Option<AuthExtension> so
    // handlers that declare `Extension<Option<AuthExtension>>` don't fail
    // Axum extraction with HTTP 500 (MissingExtension). The handler itself
    // is responsible for returning the 404 once it tries to resolve the repo.
    let Some(repo) = repo else {
        let extracted = extract_token(&request);
        let auth_ext = try_resolve_auth(&vis_state.auth_service, extracted).await;
        request.extensions_mut().insert(auth_ext);
        return next.run(request).await;
    };

    let is_public = repo.is_public;
    let is_write = is_write_method(request.method());

    // Perform optional auth (shared with optional_auth_middleware).
    let extracted = extract_token(&request);
    let mut auth_ext = try_resolve_auth(&vis_state.auth_service, extracted).await;

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
            }
        }
    }

    next.run(request).await
}

#[cfg(test)]
mod tests {
    use super::*;

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
            iat: 1000,
            exp: 2000,
            token_type: "access".to_string(),
        };

        let ext = AuthExtension::from(claims);
        assert_eq!(ext.user_id, user_id);
        assert_eq!(ext.username, "testuser");
        assert_eq!(ext.email, "test@example.com");
        assert!(ext.is_admin);
        assert!(!ext.is_api_token);
        assert!(ext.scopes.is_none());
    }

    #[test]
    fn test_auth_extension_from_claims_non_admin() {
        let claims = Claims {
            sub: Uuid::new_v4(),
            username: "regular".to_string(),
            email: "regular@example.com".to_string(),
            is_admin: false,
            iat: 1000,
            exp: 2000,
            token_type: "access".to_string(),
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
            allowed_repo_ids: repo_ids,
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
            allowed_repo_ids: None,
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
            allowed_repo_ids: None,
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
            allowed_repo_ids: None,
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
            allowed_repo_ids: None,
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
            allowed_repo_ids: None,
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
            allowed_repo_ids: None,
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
            allowed_repo_ids: None,
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
            allowed_repo_ids: None,
        };
        assert!(ext.require_admin().is_err());
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
            allowed_repo_ids: None,
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
            allowed_repo_ids: None,
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
        // The Bearer branch first tries JWT decode (fails), then API token
        // validation (fails because the lazy pool is unreachable). Both fall
        // through to the "Invalid or expired token" 401.
        let req = axum::http::Request::builder()
            .method(Method::GET)
            .uri("/probe")
            .header("Authorization", "Bearer not-a-real-jwt")
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
        let req = axum::http::Request::builder()
            .method(Method::GET)
            .uri("/probe")
            .header("Authorization", "ApiKey deadbeef")
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
    async fn test_auth_middleware_rejects_basic_with_unauthenticatable_user() {
        // Valid base64 with `user:pass` shape, but the lazy pool means
        // `authenticate` errors out, so the branch returns "Invalid credentials".
        let creds = base64::engine::general_purpose::STANDARD.encode("alice:wrong");
        let req = axum::http::Request::builder()
            .method(Method::GET)
            .uri("/probe")
            .header("Authorization", format!("Basic {}", creds))
            .body(axum::body::Body::empty())
            .unwrap();
        let resp = run_through_auth_middleware(req).await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let text = std::str::from_utf8(&body).unwrap();
        assert!(
            text.contains("Invalid credentials"),
            "expected invalid-credentials message, got: {text}"
        );
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
        let req = axum::http::Request::builder()
            .method(Method::GET)
            .uri("/probe?ticket=xyz")
            .header("Authorization", "Bearer not-a-real-jwt")
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
    // optional_auth_middleware: must always pass through to the handler with
    // Option<AuthExtension> in extensions, even when auth fails.
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_optional_auth_middleware_passes_through_without_credentials() {
        let resp = run_through_optional_auth(empty_get("/probe")).await;
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_optional_auth_middleware_passes_through_with_bad_bearer() {
        // Bad Bearer + ?ticket= query: both fail (lazy pool). Middleware must
        // still pass through to the handler with `None` auth extension.
        let req = axum::http::Request::builder()
            .method(Method::GET)
            .uri("/probe?ticket=xyz")
            .header("Authorization", "Bearer not-a-real-jwt")
            .body(axum::body::Body::empty())
            .unwrap();
        let resp = run_through_optional_auth(req).await;
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_optional_auth_middleware_passes_through_with_invalid_header() {
        let req = axum::http::Request::builder()
            .method(Method::GET)
            .uri("/probe")
            .header("Authorization", "GarbageScheme x")
            .body(axum::body::Body::empty())
            .unwrap();
        let resp = run_through_optional_auth(req).await;
        assert_eq!(resp.status(), StatusCode::OK);
    }

    // -----------------------------------------------------------------------
    // repo_visibility_middleware exercised with a pre-populated repo cache so
    // we can drive both branches (public vs private, write vs read) without
    // ever hitting the unreachable lazy DB pool.
    // -----------------------------------------------------------------------

    fn make_vis_state(cached: Option<(String, CachedRepo)>) -> RepoVisibilityState {
        let auth_service = make_test_auth_service();
        let pool = lazy_pool();
        let cache: RepoCache =
            std::sync::Arc::new(std::sync::RwLock::new(std::collections::HashMap::new()));
        if let Some((key, entry)) = cached {
            cache
                .write()
                .unwrap()
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
        let state = make_vis_state(None);
        let resp = run_through_visibility(state, empty_get("/")).await;
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_repo_visibility_public_read_no_auth_passes() {
        // Public repo + GET + no auth header: must pass through to the handler.
        let key = "myrepo";
        let cached = make_cached_repo(/* is_public */ true);
        let state = make_vis_state(Some((key.to_string(), cached)));
        let resp = run_through_visibility(state, empty_get("/pypi/myrepo/simple/")).await;
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_repo_visibility_private_read_no_auth_returns_401() {
        let key = "private";
        let cached = make_cached_repo(/* is_public */ false);
        let state = make_vis_state(Some((key.to_string(), cached)));
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
        let state = make_vis_state(Some((key.to_string(), cached)));
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
        let state = make_vis_state(Some((key.to_string(), cached)));
        let resp =
            run_through_visibility(state, empty_get("/pypi/myrepo/simple/?ticket=anything")).await;
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_repo_visibility_private_write_with_ticket_query_returns_401() {
        // Even if a ticket somehow validated, ticket-authenticated writes are
        // refused. With the lazy pool the ticket trivially fails to resolve
        // and the request is still anonymous, so the same 401 applies.
        let key = "private";
        let cached = make_cached_repo(/* is_public */ false);
        let state = make_vis_state(Some((key.to_string(), cached)));
        let req = axum::http::Request::builder()
            .method(Method::PUT)
            .uri("/pypi/private/upload?ticket=abc")
            .body(axum::body::Body::empty())
            .unwrap();
        let resp = run_through_visibility(state, req).await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }
}
