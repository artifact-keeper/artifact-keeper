//! Authentication middleware.
//!
//! Extracts and validates JWT tokens or API tokens from requests.

use std::sync::Arc;

use axum::{
    extract::{Request, State},
    http::{header::AUTHORIZATION, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
};
use uuid::Uuid;

use crate::services::auth_service::{AuthService, Claims};

/// Extension that holds authenticated user information
#[derive(Debug, Clone)]
pub struct AuthExtension {
    pub user_id: Uuid,
    pub username: String,
    pub email: String,
    pub is_admin: bool,
}

impl From<Claims> for AuthExtension {
    fn from(claims: Claims) -> Self {
        Self {
            user_id: claims.sub,
            username: claims.username,
            email: claims.email,
            is_admin: claims.is_admin,
        }
    }
}

/// Extract token from Authorization header
fn extract_bearer_token(auth_header: &str) -> Option<&str> {
    if auth_header.starts_with("Bearer ") {
        Some(&auth_header[7..])
    } else {
        None
    }
}

/// Authentication middleware function - requires valid token
pub async fn auth_middleware(
    State(auth_service): State<Arc<AuthService>>,
    mut request: Request,
    next: Next,
) -> Response {
    // Extract Authorization header
    let auth_header = request
        .headers()
        .get(AUTHORIZATION)
        .and_then(|h| h.to_str().ok());

    let token = match auth_header {
        Some(header) => {
            if let Some(token) = extract_bearer_token(header) {
                token
            } else {
                return (StatusCode::UNAUTHORIZED, "Invalid authorization header").into_response();
            }
        }
        None => {
            return (StatusCode::UNAUTHORIZED, "Missing authorization header").into_response();
        }
    };

    // Try JWT token first
    match auth_service.validate_access_token(token) {
        Ok(claims) => {
            request.extensions_mut().insert(AuthExtension::from(claims));
            next.run(request).await
        }
        Err(_) => {
            // Try API token
            match auth_service.validate_api_token(token).await {
                Ok(user) => {
                    request.extensions_mut().insert(AuthExtension {
                        user_id: user.id,
                        username: user.username,
                        email: user.email,
                        is_admin: user.is_admin,
                    });
                    next.run(request).await
                }
                Err(_) => (StatusCode::UNAUTHORIZED, "Invalid or expired token").into_response(),
            }
        }
    }
}

/// Optional authentication middleware - allows unauthenticated requests
pub async fn optional_auth_middleware(
    State(auth_service): State<Arc<AuthService>>,
    mut request: Request,
    next: Next,
) -> Response {
    // Extract Authorization header
    let auth_header = request
        .headers()
        .get(AUTHORIZATION)
        .and_then(|h| h.to_str().ok());

    let auth_ext = if let Some(header) = auth_header {
        if let Some(token) = extract_bearer_token(header) {
            // Try JWT token first
            if let Ok(claims) = auth_service.validate_access_token(token) {
                Some(AuthExtension::from(claims))
            } else if let Ok(user) = auth_service.validate_api_token(token).await {
                Some(AuthExtension {
                    user_id: user.id,
                    username: user.username,
                    email: user.email,
                    is_admin: user.is_admin,
                })
            } else {
                None
            }
        } else {
            None
        }
    } else {
        None
    };

    request.extensions_mut().insert(auth_ext);
    next.run(request).await
}

/// Admin-only middleware - requires authenticated admin user
pub async fn admin_middleware(
    State(auth_service): State<Arc<AuthService>>,
    mut request: Request,
    next: Next,
) -> Response {
    // Extract Authorization header
    let auth_header = request
        .headers()
        .get(AUTHORIZATION)
        .and_then(|h| h.to_str().ok());

    let token = match auth_header {
        Some(header) => {
            if let Some(token) = extract_bearer_token(header) {
                token
            } else {
                return (StatusCode::UNAUTHORIZED, "Invalid authorization header").into_response();
            }
        }
        None => {
            return (StatusCode::UNAUTHORIZED, "Missing authorization header").into_response();
        }
    };

    // Try JWT token first
    let auth_ext = match auth_service.validate_access_token(token) {
        Ok(claims) => AuthExtension::from(claims),
        Err(_) => {
            // Try API token
            match auth_service.validate_api_token(token).await {
                Ok(user) => AuthExtension {
                    user_id: user.id,
                    username: user.username,
                    email: user.email,
                    is_admin: user.is_admin,
                },
                Err(_) => {
                    return (StatusCode::UNAUTHORIZED, "Invalid or expired token").into_response()
                }
            }
        }
    };

    if !auth_ext.is_admin {
        return (StatusCode::FORBIDDEN, "Admin access required").into_response();
    }

    request.extensions_mut().insert(auth_ext);
    next.run(request).await
}
