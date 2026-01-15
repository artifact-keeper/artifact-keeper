//! Route definitions for the API.

use axum::{middleware, routing::get, Router};
use std::sync::Arc;

use super::handlers;
use super::middleware::auth::{auth_middleware, optional_auth_middleware};
use super::SharedState;
use crate::services::auth_service::AuthService;

/// Create the main API router
pub fn create_router(state: SharedState) -> Router {
    Router::new()
        // Health endpoints (no auth required)
        .route("/health", get(handlers::health::health_check))
        .route("/ready", get(handlers::health::readiness_check))
        .route("/metrics", get(handlers::health::metrics))
        // API v1 routes
        .nest("/api/v1", api_v1_routes(state.clone()))
        .with_state(state)
}

/// API v1 routes
fn api_v1_routes(state: SharedState) -> Router<SharedState> {
    // Create an AuthService for middleware use
    let auth_service = Arc::new(AuthService::new(state.db.clone(), Arc::new(state.config.clone())));

    Router::new()
        // Auth routes (no auth required)
        .nest("/auth", handlers::auth::router())
        // Repository routes with optional auth middleware
        // (some endpoints require auth, others are optional - handlers will check)
        .nest(
            "/repositories",
            handlers::repositories::router()
                .layer(middleware::from_fn_with_state(
                    auth_service.clone(),
                    optional_auth_middleware,
                ))
        )
        // Artifact routes (standalone by ID) with optional auth
        .nest(
            "/artifacts",
            handlers::artifacts::router()
                .layer(middleware::from_fn_with_state(
                    auth_service.clone(),
                    optional_auth_middleware,
                ))
        )
        // User routes with auth middleware
        .nest(
            "/users",
            handlers::users::router()
                .layer(middleware::from_fn_with_state(
                    auth_service.clone(),
                    auth_middleware,
                ))
        )
        // Search routes with optional auth
        .nest(
            "/search",
            handlers::search::router()
                .layer(middleware::from_fn_with_state(
                    auth_service.clone(),
                    optional_auth_middleware,
                ))
        )
        // Edge node routes with auth middleware
        .nest(
            "/edge-nodes",
            handlers::edge::router()
                .layer(middleware::from_fn_with_state(
                    auth_service.clone(),
                    auth_middleware,
                ))
        )
        // Admin routes with auth middleware
        .nest(
            "/admin",
            handlers::admin::router()
                .layer(middleware::from_fn_with_state(
                    auth_service.clone(),
                    auth_middleware,
                ))
        )
        // Plugin routes with auth middleware
        .nest(
            "/plugins",
            handlers::plugins::router()
                .layer(middleware::from_fn_with_state(
                    auth_service.clone(),
                    auth_middleware,
                ))
        )
        // Webhook routes with auth middleware
        .nest(
            "/webhooks",
            handlers::webhooks::router()
                .layer(middleware::from_fn_with_state(
                    auth_service,
                    auth_middleware,
                ))
        )
}
