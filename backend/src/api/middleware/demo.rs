//! Demo mode middleware that blocks write operations.

use axum::{
    body::Body,
    extract::State,
    http::{Method, Request, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
    Json,
};
use serde_json::json;
use std::sync::Arc;

use crate::api::AppState;

/// Auth-related paths that may accept write methods even while the instance is
/// in demo mode, because they are part of the login/session lifecycle rather
/// than state-mutating operations.
///
/// This is an explicit allowlist so the guard is deny-by-default: any new write
/// endpoint added under `/api/v1/auth` (for example API token creation) is
/// blocked in demo mode unless it is intentionally added here. The previous
/// implementation exempted the whole `/api/v1/auth` prefix, which let
/// `POST /api/v1/auth/tokens` (create API token) and
/// `DELETE /api/v1/auth/tokens/{id}` (revoke) slip through.
fn is_allowed_auth_write(path: &str) -> bool {
    const EXACT_ALLOWED: &[&str] = &[
        "/api/v1/auth/login",
        "/api/v1/auth/logout",
        "/api/v1/auth/refresh",
        // Short-lived download tickets are read-oriented (they authorize a
        // download), so they stay available in a read-only demo.
        "/api/v1/auth/ticket",
    ];

    if EXACT_ALLOWED.contains(&path) {
        return true;
    }

    // TOTP 2FA and SSO sub-trees carry their own login/verify/callback steps
    // that must work for users to authenticate.
    path.starts_with("/api/v1/auth/totp/") || path.starts_with("/api/v1/auth/sso/")
}

/// Returns true when a request must be blocked by the demo guard.
///
/// Reads (GET/HEAD/OPTIONS) are always allowed. Writes are blocked unless they
/// target an explicitly allowlisted auth/session endpoint.
fn should_block(method: &Method, path: &str) -> bool {
    let is_read_only = matches!(*method, Method::GET | Method::HEAD | Method::OPTIONS);
    if is_read_only {
        return false;
    }
    !is_allowed_auth_write(path)
}

/// Middleware that rejects write operations (POST/PUT/DELETE/PATCH) in demo mode.
///
/// Login and session endpoints are exempted so users can authenticate, but all
/// other writes, including API token creation and revocation, are blocked.
pub async fn demo_guard(
    State(state): State<Arc<AppState>>,
    request: Request<Body>,
    next: Next,
) -> Response {
    if !state.config.demo_mode {
        return next.run(request).await;
    }

    if should_block(request.method(), request.uri().path()) {
        return (
            StatusCode::FORBIDDEN,
            Json(json!({
                "error": "Write operations are disabled in the demo. Deploy your own instance to get full access."
            })),
        )
            .into_response();
    }

    next.run(request).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_are_never_blocked() {
        for method in [Method::GET, Method::HEAD, Method::OPTIONS] {
            assert!(!should_block(&method, "/api/v1/repositories"));
            assert!(!should_block(&method, "/api/v1/auth/tokens"));
        }
    }

    #[test]
    fn token_writes_are_blocked() {
        assert!(should_block(&Method::POST, "/api/v1/auth/tokens"));
        assert!(should_block(&Method::DELETE, "/api/v1/auth/tokens/abc-123"));
        assert!(!is_allowed_auth_write("/api/v1/auth/tokens"));
        assert!(!is_allowed_auth_write("/api/v1/auth/tokens/abc-123"));
    }

    #[test]
    fn login_session_writes_are_allowed() {
        for path in [
            "/api/v1/auth/login",
            "/api/v1/auth/logout",
            "/api/v1/auth/refresh",
            "/api/v1/auth/ticket",
            "/api/v1/auth/totp/verify",
            "/api/v1/auth/sso/callback",
        ] {
            assert!(is_allowed_auth_write(path), "{path} should be allowed");
            assert!(
                !should_block(&Method::POST, path),
                "{path} should not block"
            );
        }
    }

    #[test]
    fn non_auth_writes_are_blocked() {
        assert!(should_block(&Method::POST, "/api/v1/repositories"));
        assert!(should_block(&Method::PUT, "/api/v1/admin/settings"));
        assert!(should_block(&Method::PATCH, "/api/v1/users/123"));
        assert!(should_block(&Method::DELETE, "/api/v1/repositories/abc"));
    }

    #[test]
    fn unrelated_auth_prefix_paths_do_not_leak() {
        // A path that merely starts with the auth string but is not an
        // allowlisted login endpoint must still be blocked for writes.
        assert!(should_block(&Method::POST, "/api/v1/auth/tokens/extra"));
        assert!(should_block(&Method::POST, "/api/v1/authzzz"));
    }
}
