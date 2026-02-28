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

use axum::{
    extract::{Request, State},
    http::{
        header::{AUTHORIZATION, COOKIE},
        HeaderName, StatusCode,
    },
    middleware::Next,
    response::{IntoResponse, Response},
};
use uuid::Uuid;

use crate::error::AppError;
use crate::services::auth_service::{AuthService, Claims};

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

/// Token extraction result
#[derive(Debug)]
enum ExtractedToken<'a> {
    /// JWT or API token from Bearer scheme
    Bearer(&'a str),
    /// API token from ApiKey scheme
    ApiKey(&'a str),
    /// No token found
    None,
    /// Invalid header format
    Invalid,
}

/// Extract token from Authorization header (supports Bearer and ApiKey schemes)
fn extract_token_from_auth_header(auth_header: &str) -> ExtractedToken<'_> {
    if let Some(token) = auth_header.strip_prefix("Bearer ") {
        ExtractedToken::Bearer(token)
    } else if let Some(token) = auth_header.strip_prefix("ApiKey ") {
        ExtractedToken::ApiKey(token)
    } else {
        ExtractedToken::Invalid
    }
}

/// Extract token from request headers
/// Checks: Authorization (Bearer/ApiKey), X-API-Key
fn extract_token(request: &Request) -> ExtractedToken<'_> {
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

    match extracted {
        ExtractedToken::Bearer(token) => {
            // Try JWT token first for Bearer scheme
            match auth_service.validate_access_token(token) {
                Ok(claims) => {
                    request.extensions_mut().insert(AuthExtension::from(claims));
                    next.run(request).await
                }
                Err(_) => {
                    // Fall back to API token
                    match validate_api_token_with_scopes(&auth_service, token).await {
                        Ok(auth_ext) => {
                            request.extensions_mut().insert(auth_ext);
                            next.run(request).await
                        }
                        Err(_) => {
                            (StatusCode::UNAUTHORIZED, "Invalid or expired token").into_response()
                        }
                    }
                }
            }
        }
        ExtractedToken::ApiKey(token) => {
            // ApiKey scheme is always an API token
            match validate_api_token_with_scopes(&auth_service, token).await {
                Ok(auth_ext) => {
                    request.extensions_mut().insert(auth_ext);
                    next.run(request).await
                }
                Err(_) => {
                    (StatusCode::UNAUTHORIZED, "Invalid or expired API token").into_response()
                }
            }
        }
        ExtractedToken::None => {
            (StatusCode::UNAUTHORIZED, "Missing authorization header").into_response()
        }
        ExtractedToken::Invalid => (
            StatusCode::UNAUTHORIZED,
            "Invalid authorization header format",
        )
            .into_response(),
    }
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
async fn try_resolve_auth(
    auth_service: &AuthService,
    extracted: ExtractedToken<'_>,
) -> Option<AuthExtension> {
    match extracted {
        ExtractedToken::Bearer(token) => {
            if let Ok(claims) = auth_service.validate_access_token(token) {
                Some(AuthExtension::from(claims))
            } else {
                validate_api_token_with_scopes(auth_service, token)
                    .await
                    .ok()
            }
        }
        ExtractedToken::ApiKey(token) => validate_api_token_with_scopes(auth_service, token)
            .await
            .ok(),
        ExtractedToken::None | ExtractedToken::Invalid => None,
    }
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
    let auth_ext = try_resolve_auth(&auth_service, extracted).await;

    request.extensions_mut().insert(auth_ext);
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

/// Middleware that enforces repository visibility on format handler routes.
///
/// For routes whose first path segment is a repository key, this middleware
/// checks whether the repository is public. If it is not public, the request
/// must carry a valid authentication token; otherwise a 404 is returned (to
/// avoid leaking the existence of private repos).
///
/// This provides defence-in-depth: even if individual format handlers forget
/// to check visibility, this middleware blocks anonymous access to private
/// repository content.
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

    // Look up whether this repo is public.
    let is_public: Option<bool> =
        sqlx::query_scalar("SELECT is_public FROM repositories WHERE key = $1")
            .bind(repo_key)
            .fetch_optional(&vis_state.db)
            .await
            .ok()
            .flatten();

    // If no repo found for this key, let the handler return its own 404.
    let Some(is_public) = is_public else {
        return next.run(request).await;
    };

    // Perform optional auth (shared with optional_auth_middleware).
    let extracted = extract_token(&request);
    let auth_ext = try_resolve_auth(&vis_state.auth_service, extracted).await;

    // Insert auth extension for downstream handlers.
    request.extensions_mut().insert(auth_ext.clone());

    // Check visibility: public repos are open, private repos need auth.
    if should_allow_repo_access(is_public, auth_ext.is_some()) {
        return next.run(request).await;
    }

    (StatusCode::NOT_FOUND, "Not found").into_response()
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
    fn test_extract_invalid_scheme() {
        let result = extract_token_from_auth_header("Basic dXNlcjpwYXNz");
        assert!(matches!(result, ExtractedToken::Invalid));
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
    fn test_extract_token_invalid_auth_header_does_not_fall_through() {
        let request = Request::builder()
            .header(AUTHORIZATION, "Basic dXNlcjpwYXNz")
            .header("x-api-key", "api-key-value")
            .body(axum::body::Body::empty())
            .unwrap();
        let result = extract_token(&request);
        assert!(matches!(result, ExtractedToken::Invalid));
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
}
