//! Setup mode middleware that locks the API until the admin password is changed.

use axum::{
    body::Body,
    extract::State,
    http::{Request, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
    Json,
};
use serde_json::json;
use std::sync::atomic::Ordering;
use std::sync::Arc;

use crate::api::AppState;

/// Middleware that blocks most API requests when setup is required.
///
/// When `state.setup_required` is true, only health/readiness checks,
/// auth endpoints (login, refresh), the password-change endpoint, and
/// the setup status endpoint are allowed. Everything else gets a 403
/// with instructions on how to complete setup.
pub async fn setup_guard(
    State(state): State<Arc<AppState>>,
    request: Request<Body>,
    next: Next,
) -> Response {
    if !state.setup_required.load(Ordering::Relaxed) {
        return next.run(request).await;
    }

    let path = request.uri().path();

    // Always allow health/readiness/metrics
    if path == "/health" || path == "/ready" || path == "/metrics" {
        return next.run(request).await;
    }

    // Allow auth endpoints (login, refresh, logout, me, SSO)
    if path.starts_with("/api/v1/auth") {
        return next.run(request).await;
    }

    // Allow setup status check
    if path == "/api/v1/setup/status" {
        return next.run(request).await;
    }

    // Allow password change: POST /api/v1/users/:id/password
    if path.starts_with("/api/v1/users/") && path.ends_with("/password") {
        return next.run(request).await;
    }

    // Block everything else
    (
        StatusCode::FORBIDDEN,
        Json(json!({
            "error": "SETUP_REQUIRED",
            "message": "Initial setup is required. Change the admin password to unlock the API.",
            "instructions": [
                "1. Read the generated password: docker exec artifact-keeper-backend cat /data/storage/admin.password && echo",
                "2. Login: POST /api/v1/auth/login with {\"username\":\"admin\",\"password\":\"<from-file>\"}",
                "3. Change password: POST /api/v1/users/<id>/password with {\"new_password\":\"<your-password>\"}",
                "4. The API will unlock automatically after the password is changed."
            ]
        })),
    )
        .into_response()
}
