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
        // Docker Registry V2 API (OCI Distribution Spec)
        .route("/v2/", handlers::oci_v2::version_check_handler())
        .nest("/v2", handlers::oci_v2::router())
        // npm Registry API
        .nest("/npm", handlers::npm::router())
        // PyPI Simple Repository API (PEP 503)
        .nest("/maven", handlers::maven::router())
        .nest("/pypi", handlers::pypi::router())
        // Debian/APT Repository API
        .nest("/debian", handlers::debian::router())
        // NuGet v3 API
        .nest("/nuget", handlers::nuget::router())
        // RPM/YUM Repository API
        .nest("/rpm", handlers::rpm::router())
        // Cargo sparse registry API
        .nest("/cargo", handlers::cargo::router())
        // RubyGems API
        .nest("/gems", handlers::rubygems::router())
        // Git LFS API
        .nest("/lfs", handlers::gitlfs::router())
        // Pub (Dart/Flutter) Repository API
        .nest("/pub", handlers::pub_registry::router())
        // Go Proxy API (GOPROXY protocol)
        .nest("/go", handlers::goproxy::router())
        // Helm Chart Repository API
        .nest("/helm", handlers::helm::router())
        // Composer (PHP) Repository API
        .nest("/composer", handlers::composer::router())
        // Conan v2 Repository API (C/C++ packages)
        .nest("/conan", handlers::conan::router())
        // Alpine/APK Repository API
        .nest("/alpine", handlers::alpine::router())
        // Conda Channel API
        .nest("/conda", handlers::conda::router())
        // Swift Package Registry (SE-0292)
        .nest("/swift", handlers::swift::router())
        // Terraform Registry Protocol
        .nest("/terraform", handlers::terraform::router())
        // CocoaPods Spec Repo API
        .nest("/cocoapods", handlers::cocoapods::router())
        // Hex.pm Repository API (Elixir/Erlang packages)
        .nest("/hex", handlers::hex::router())
        // HuggingFace Hub API
        .nest("/huggingface", handlers::huggingface::router())
        // JetBrains Plugin Repository API
        .nest("/jetbrains", handlers::jetbrains::router())
        // Chef Supermarket API
        .nest("/chef", handlers::chef::router())
        // Puppet Forge API
        .nest("/puppet", handlers::puppet::router())
        // Ansible Galaxy API
        .nest("/ansible", handlers::ansible::router())
        // CRAN Repository API (R packages)
        .nest("/cran", handlers::cran::router())
        // SBT/Ivy Repository API (Scala/Java packages)
        .nest("/ivy", handlers::sbt::router())
        // VS Code Extension Marketplace API
        .nest("/vscode", handlers::vscode::router())
        .with_state(state)
}

/// API v1 routes
fn api_v1_routes(state: SharedState) -> Router<SharedState> {
    // Create an AuthService for middleware use
    let auth_service = Arc::new(AuthService::new(
        state.db.clone(),
        Arc::new(state.config.clone()),
    ));

    Router::new()
        // Auth routes - split into public and protected
        .nest("/auth", handlers::auth::public_router())
        .nest(
            "/auth",
            handlers::auth::protected_router().layer(middleware::from_fn_with_state(
                auth_service.clone(),
                auth_middleware,
            )),
        )
        // Repository routes with optional auth middleware
        // (some endpoints require auth, others are optional - handlers will check)
        .nest(
            "/repositories",
            handlers::repositories::router().layer(middleware::from_fn_with_state(
                auth_service.clone(),
                optional_auth_middleware,
            )),
        )
        // Artifact routes (standalone by ID) with optional auth
        .nest(
            "/artifacts",
            handlers::artifacts::router().layer(middleware::from_fn_with_state(
                auth_service.clone(),
                optional_auth_middleware,
            )),
        )
        // User routes with auth middleware
        .nest(
            "/users",
            handlers::users::router().layer(middleware::from_fn_with_state(
                auth_service.clone(),
                auth_middleware,
            )),
        )
        // Group routes with auth middleware
        .nest(
            "/groups",
            handlers::groups::router().layer(middleware::from_fn_with_state(
                auth_service.clone(),
                auth_middleware,
            )),
        )
        // Permission routes with auth middleware
        .nest(
            "/permissions",
            handlers::permissions::router().layer(middleware::from_fn_with_state(
                auth_service.clone(),
                auth_middleware,
            )),
        )
        // Build routes with optional auth
        .nest(
            "/builds",
            handlers::builds::router().layer(middleware::from_fn_with_state(
                auth_service.clone(),
                optional_auth_middleware,
            )),
        )
        // Package routes with optional auth
        .nest(
            "/packages",
            handlers::packages::router().layer(middleware::from_fn_with_state(
                auth_service.clone(),
                optional_auth_middleware,
            )),
        )
        // Search routes with optional auth
        .nest(
            "/search",
            handlers::search::router().layer(middleware::from_fn_with_state(
                auth_service.clone(),
                optional_auth_middleware,
            )),
        )
        // Edge node routes with auth middleware
        .nest(
            "/edge-nodes",
            handlers::edge::router()
                .nest("/:id/transfer", handlers::transfer::router())
                .nest("/:id/peers", handlers::peer::peer_router())
                .nest("/:id/chunks", handlers::peer::chunk_router())
                .merge(handlers::peer::network_profile_router())
                .layer(middleware::from_fn_with_state(
                    auth_service.clone(),
                    auth_middleware,
                )),
        )
        // Admin routes with auth middleware
        .nest(
            "/admin",
            handlers::admin::router().layer(middleware::from_fn_with_state(
                auth_service.clone(),
                auth_middleware,
            )),
        )
        // Plugin routes with auth middleware
        .nest(
            "/plugins",
            handlers::plugins::router().layer(middleware::from_fn_with_state(
                auth_service.clone(),
                auth_middleware,
            )),
        )
        // Format handler routes with optional auth (list is public, enable/disable requires auth)
        .nest(
            "/formats",
            handlers::plugins::format_router().layer(middleware::from_fn_with_state(
                auth_service.clone(),
                optional_auth_middleware,
            )),
        )
        // Webhook routes with auth middleware
        .nest(
            "/webhooks",
            handlers::webhooks::router().layer(middleware::from_fn_with_state(
                auth_service.clone(),
                auth_middleware,
            )),
        )
        // Signing key management routes with auth middleware
        .nest(
            "/signing",
            handlers::signing::router().layer(middleware::from_fn_with_state(
                auth_service.clone(),
                auth_middleware,
            )),
        )
        // Security routes with auth middleware
        .nest(
            "/security",
            handlers::security::router().layer(middleware::from_fn_with_state(
                auth_service.clone(),
                auth_middleware,
            )),
        )
        // Migration routes with auth middleware
        .nest(
            "/migrations",
            handlers::migration::router().layer(middleware::from_fn_with_state(
                auth_service,
                auth_middleware,
            )),
        )
}
