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

/// Middleware that rejects write operations (POST/PUT/DELETE/PATCH) in demo mode.
/// Auth endpoints are exempted so users can log in.
pub async fn demo_guard(
    State(state): State<Arc<AppState>>,
    request: Request<Body>,
    next: Next,
) -> Response {
    if !state.config.demo_mode {
        return next.run(request).await;
    }

    let method = request.method().clone();
    let path = request.uri().path().to_string();

    // Allow all read operations
    if method == Method::GET || method == Method::HEAD || method == Method::OPTIONS {
        return next.run(request).await;
    }

    // Allow auth endpoints (login, refresh, etc.)
    if path.starts_with("/api/v1/auth") {
        return next.run(request).await;
    }

    // Block all other write operations
    (
        StatusCode::FORBIDDEN,
        Json(json!({
            "error": "Write operations are disabled in the demo. Deploy your own instance to get full access."
        })),
    )
        .into_response()
}
