//! Route definitions for the API.

use axum::{routing::get, Router};

use super::handlers;
use super::SharedState;

/// Create the main API router
pub fn create_router(state: SharedState) -> Router {
    Router::new()
        // Health endpoints (no auth required)
        .route("/health", get(handlers::health::health_check))
        .route("/ready", get(handlers::health::readiness_check))
        .route("/metrics", get(handlers::health::metrics))
        // API v1 routes
        .nest("/api/v1", api_v1_routes())
        .with_state(state)
}

/// API v1 routes
fn api_v1_routes() -> Router<SharedState> {
    Router::new()
        // Auth routes
        .nest("/auth", handlers::auth::router())
        // Repository routes
        .nest("/repositories", handlers::repositories::router())
        // Artifact routes (standalone by ID)
        .nest("/artifacts", handlers::artifacts::router())
        // User routes
        .nest("/users", handlers::users::router())
        // Search routes
        .nest("/search", handlers::search::router())
        // Edge node routes
        .nest("/edge-nodes", handlers::edge::router())
        // Admin routes
        .nest("/admin", handlers::admin::router())
        // Plugin routes
        .nest("/plugins", handlers::plugins::router())
        // Webhook routes
        .nest("/webhooks", handlers::webhooks::router())
}
