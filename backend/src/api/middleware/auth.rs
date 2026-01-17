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
    http::{header::AUTHORIZATION, HeaderName, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
};
use uuid::Uuid;

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
    /// Token scopes if authenticated via API token
    pub scopes: Option<Vec<String>>,
}

impl From<Claims> for AuthExtension {
    fn from(claims: Claims) -> Self {
        Self {
            user_id: claims.sub,
            username: claims.username,
            email: claims.email,
            is_admin: claims.is_admin,
            is_api_token: false,
            scopes: None,
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
    if auth_header.starts_with("Bearer ") {
        ExtractedToken::Bearer(&auth_header[7..])
    } else if auth_header.starts_with("ApiKey ") {
        ExtractedToken::ApiKey(&auth_header[7..])
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
        ExtractedToken::Invalid => {
            (StatusCode::UNAUTHORIZED, "Invalid authorization header format").into_response()
        }
    }
}

/// Helper function to validate API token and create AuthExtension
///
/// Note: Scopes are not loaded here for performance. Use TokenService
/// if scope validation is needed in handlers.
async fn validate_api_token_with_scopes(
    auth_service: &AuthService,
    token: &str,
) -> Result<AuthExtension, ()> {
    let user = auth_service.validate_api_token(token).await.map_err(|_| ())?;

    Ok(AuthExtension {
        user_id: user.id,
        username: user.username,
        email: user.email,
        is_admin: user.is_admin,
        is_api_token: true,
        scopes: None, // Scopes loaded on-demand via TokenService
    })
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

    let auth_ext = match extracted {
        ExtractedToken::Bearer(token) => {
            // Try JWT token first
            if let Ok(claims) = auth_service.validate_access_token(token) {
                Some(AuthExtension::from(claims))
            } else if let Ok(user) = auth_service.validate_api_token(token).await {
                Some(AuthExtension {
                    user_id: user.id,
                    username: user.username,
                    email: user.email,
                    is_admin: user.is_admin,
                    is_api_token: true,
                    scopes: None,
                })
            } else {
                None
            }
        }
        ExtractedToken::ApiKey(token) => {
            if let Ok(user) = auth_service.validate_api_token(token).await {
                Some(AuthExtension {
                    user_id: user.id,
                    username: user.username,
                    email: user.email,
                    is_admin: user.is_admin,
                    is_api_token: true,
                    scopes: None,
                })
            } else {
                None
            }
        }
        ExtractedToken::None | ExtractedToken::Invalid => None,
    };

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
        ExtractedToken::Bearer(token) => {
            // Try JWT token first
            match auth_service.validate_access_token(token) {
                Ok(claims) => AuthExtension::from(claims),
                Err(_) => {
                    // Try API token
                    match auth_service.validate_api_token(token).await {
                        Ok(user) => AuthExtension {
                            user_id: user.id,
                            username: user.username,
                            email: user.email,
                            is_admin: user.is_admin,
                            is_api_token: true,
                            scopes: None,
                        },
                        Err(_) => {
                            return (StatusCode::UNAUTHORIZED, "Invalid or expired token")
                                .into_response()
                        }
                    }
                }
            }
        }
        ExtractedToken::ApiKey(token) => {
            // ApiKey scheme is always an API token
            match auth_service.validate_api_token(token).await {
                Ok(user) => AuthExtension {
                    user_id: user.id,
                    username: user.username,
                    email: user.email,
                    is_admin: user.is_admin,
                    is_api_token: true,
                    scopes: None,
                },
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
            return (StatusCode::UNAUTHORIZED, "Invalid authorization header format")
                .into_response();
        }
    };

    if !auth_ext.is_admin {
        return (StatusCode::FORBIDDEN, "Admin access required").into_response();
    }

    request.extensions_mut().insert(auth_ext);
    next.run(request).await
}
