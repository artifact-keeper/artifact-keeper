//! Route definitions for the API.

use axum::{extract::DefaultBodyLimit, middleware, routing::get, Router};
use std::sync::Arc;
use utoipa_swagger_ui::SwaggerUi;

use super::handlers;
use super::middleware::auth::{
    admin_middleware, auth_middleware, optional_auth_middleware, repo_visibility_middleware,
    RepoVisibilityState,
};
use super::middleware::demo::demo_guard;
use super::middleware::rate_limit::{rate_limit_middleware, RateLimiter};
use super::middleware::setup::setup_guard;
use super::middleware::tracing::correlation_id_middleware;
use super::SharedState;
use crate::services::auth_service::AuthService;

/// Create the main API router
pub fn create_router(state: SharedState) -> Router {
    // Build OpenAPI spec once at startup
    let openapi = super::openapi::build_openapi();

    // Build repo-visibility state used by all format-handler routes.
    // This middleware performs optional auth + private-repo gating in a
    // single pass so that every format handler is protected by default.
    let vis_auth_service = Arc::new(AuthService::new(
        state.db.clone(),
        Arc::new(state.config.clone()),
    ));
    // Register this long-lived AuthService's token cache with the global
    // invalidation registry so user deactivations (issue #931) flush its
    // cached API-token validations immediately rather than waiting for the
    // 5-minute TTL.
    vis_auth_service.register_for_global_flush();
    let vis_state = RepoVisibilityState {
        auth_service: vis_auth_service,
        db: state.db.clone(),
        repo_cache: state.repo_cache.clone(),
    };

    // All native-protocol format handlers share the repo visibility
    // middleware: anonymous users can only access public repositories.
    //
    // The upload body limit is read from config (MAX_UPLOAD_SIZE env var,
    // default 10 GB). A value of 0 disables the limit entirely.
    let upload_limit = state.config.max_upload_size_bytes;

    let format_routes = Router::new()
        .nest("/npm", handlers::npm::router())
        .nest("/maven", handlers::maven::router())
        .nest("/pypi", handlers::pypi::router())
        .nest("/debian", handlers::debian::router())
        .nest("/nuget", handlers::nuget::router())
        .nest("/rpm", handlers::rpm::router())
        .nest("/cargo", handlers::cargo::router())
        .nest("/gems", handlers::rubygems::router())
        .nest("/lfs", handlers::gitlfs::router())
        .nest("/pub", handlers::pub_registry::router())
        .nest("/go", handlers::goproxy::router())
        .nest("/helm", handlers::helm::router())
        .nest("/composer", handlers::composer::router())
        .nest("/conan", handlers::conan::router())
        .nest("/alpine", handlers::alpine::router())
        .nest("/conda", handlers::conda::router())
        .nest("/conda/t", handlers::conda::token_router())
        .nest("/swift", handlers::swift::router())
        .nest("/terraform", handlers::terraform::router())
        .nest("/cocoapods", handlers::cocoapods::router())
        .nest("/hex", handlers::hex::router())
        .nest("/huggingface", handlers::huggingface::router())
        .nest("/jetbrains", handlers::jetbrains::router())
        .nest("/chef", handlers::chef::router())
        .nest("/puppet", handlers::puppet::router())
        .nest("/ansible", handlers::ansible::router())
        .nest("/cran", handlers::cran::router())
        .nest("/ivy", handlers::sbt::router())
        .nest("/vscode", handlers::vscode::router())
        .nest("/proto", handlers::protobuf::router())
        .nest("/incus", handlers::incus::router())
        .nest("/ext", handlers::wasm_proxy::router())
        .layer(middleware::from_fn_with_state(
            vis_state,
            repo_visibility_middleware,
        ));

    // Apply the configurable upload body limit to all format handler routes.
    // Handlers that need a different limit (e.g. OCI, incus, Git LFS,
    // protobuf) keep their own per-router layer which takes precedence.
    let format_routes = if upload_limit == 0 {
        format_routes.layer(DefaultBodyLimit::disable())
    } else {
        format_routes.layer(DefaultBodyLimit::max(upload_limit as usize))
    };

    let swagger_enabled = {
        let env = std::env::var("ENVIRONMENT").unwrap_or_else(|_| "development".into());
        env == "development" || std::env::var("ENABLE_SWAGGER").is_ok()
    };

    let mut router = Router::new()
        // Health endpoints (no auth required)
        .route("/health", get(handlers::health::health_check))
        .route("/healthz", get(handlers::health::health_check))
        .route("/ready", get(handlers::health::readiness_check))
        .route("/readyz", get(handlers::health::readiness_check))
        .route("/livez", get(handlers::health::liveness_check));

    // Only mount Swagger UI and OpenAPI spec in development or when explicitly enabled
    if swagger_enabled {
        router = router.merge(SwaggerUi::new("/swagger-ui").url("/api/v1/openapi.json", openapi));
    }

    let mut router = router
        // API v1 routes
        .nest("/api/v1", api_v1_routes(state.clone()))
        // Docker Registry V2 API (OCI Distribution Spec)
        .route("/v2/", handlers::oci_v2::version_check_handler())
        .nest("/v2", handlers::oci_v2::router())
        // All native-protocol format handler routes (repo visibility enforced)
        .merge(format_routes);

    // Disable the global body limit. This is an artifact registry — uploads
    // can be multiple GB. Without this, Axum's 2 MB default silently truncates
    // uploads on routes that lack an explicit limit. Individual format handlers
    // set their own limits where appropriate (e.g. 512 MB for most formats).
    router = router.layer(DefaultBodyLimit::disable());

    // Apply setup guard (locks API until admin password is changed)
    router = router.layer(middleware::from_fn_with_state(state.clone(), setup_guard));

    // Apply demo mode guard if enabled
    if state.config.demo_mode {
        tracing::info!("Demo mode enabled — write operations will be blocked");
        router = router.layer(middleware::from_fn_with_state(state.clone(), demo_guard));
    }

    // Correlation ID middleware (outermost layer — runs first on every request).
    // Extracts or generates a correlation ID and sets the X-Correlation-ID
    // response header.
    router = router.layer(middleware::from_fn(correlation_id_middleware));

    router.with_state(state)
}

/// API v1 routes
fn api_v1_routes(state: SharedState) -> Router<SharedState> {
    // Create an AuthService for middleware use
    let auth_service = Arc::new(AuthService::new(
        state.db.clone(),
        Arc::new(state.config.clone()),
    ));
    // Register the middleware AuthService's token cache for global flush
    // on user deactivation (issue #931).
    auth_service.register_for_global_flush();

    let upload_limit = state.config.max_upload_size_bytes;

    // Rate limiters, configurable via environment variables:
    //   RATE_LIMIT_AUTH_PER_MIN  - max auth requests per window (default: 120)
    //   RATE_LIMIT_API_PER_MIN   - max API requests per window  (default: 5000)
    //   RATE_LIMIT_WINDOW_SECS   - window duration in seconds   (default: 60)
    let auth_rate_limit = std::env::var("RATE_LIMIT_AUTH_PER_MIN")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(120);
    let api_rate_limit = std::env::var("RATE_LIMIT_API_PER_MIN")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(5000);
    let rate_limit_window = std::env::var("RATE_LIMIT_WINDOW_SECS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(60u64);

    let auth_rate_limiter = Arc::new(RateLimiter::new(auth_rate_limit, rate_limit_window));
    let api_rate_limiter = Arc::new(RateLimiter::new(api_rate_limit, rate_limit_window));

    // Spawn periodic cleanup of expired rate-limiter entries to prevent
    // unbounded HashMap growth from unique client IPs over time.
    {
        let auth_cleanup = Arc::clone(&auth_rate_limiter);
        let api_cleanup = Arc::clone(&api_rate_limiter);
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(60));
            loop {
                interval.tick().await;
                auth_cleanup.cleanup_expired().await;
                api_cleanup.cleanup_expired().await;
            }
        });
    }

    Router::new()
        // Setup status (public, no auth)
        .nest("/setup", handlers::auth::setup_router())
        // Auth routes - split into public and protected (rate limited)
        .nest(
            "/auth",
            handlers::auth::public_router().layer(middleware::from_fn_with_state(
                auth_rate_limiter,
                rate_limit_middleware,
            )),
        )
        .nest("/auth/sso", handlers::sso::router())
        .nest(
            "/auth",
            handlers::auth::protected_router().layer(middleware::from_fn_with_state(
                auth_service.clone(),
                auth_middleware,
            )),
        )
        // TOTP 2FA routes
        .nest("/auth/totp", handlers::totp::public_router())
        .nest(
            "/auth/totp",
            handlers::totp::protected_router().layer(middleware::from_fn_with_state(
                auth_service.clone(),
                auth_middleware,
            )),
        )
        // Repository routes with optional auth middleware
        // (some endpoints require auth, others are optional - handlers will check)
        .nest(
            "/repositories",
            handlers::repositories::router()
                .layer(if upload_limit == 0 {
                    DefaultBodyLimit::disable()
                } else {
                    DefaultBodyLimit::max(upload_limit as usize)
                })
                .layer(middleware::from_fn_with_state(
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
        // User management routes require admin privileges
        .nest(
            "/users",
            handlers::users::router()
                .layer(DefaultBodyLimit::max(1024 * 1024)) // 1 MB
                .layer(middleware::from_fn_with_state(
                    auth_service.clone(),
                    admin_middleware,
                )),
        )
        // Profile routes (authenticated user context) with auth middleware
        .nest(
            "/profile",
            handlers::profile::router()
                .layer(DefaultBodyLimit::max(1024 * 1024)) // 1 MB
                .layer(middleware::from_fn_with_state(
                    auth_service.clone(),
                    auth_middleware,
                )),
        )
        // Group routes with auth middleware
        .nest(
            "/groups",
            handlers::groups::router()
                .layer(DefaultBodyLimit::max(1024 * 1024)) // 1 MB
                .layer(middleware::from_fn_with_state(
                    auth_service.clone(),
                    auth_middleware,
                )),
        )
        // Permission routes with auth middleware
        .nest(
            "/permissions",
            handlers::permissions::router()
                .layer(DefaultBodyLimit::max(1024 * 1024)) // 1 MB
                .layer(middleware::from_fn_with_state(
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
        // Tree browser routes with optional auth
        .nest(
            "/tree",
            handlers::tree::router().layer(middleware::from_fn_with_state(
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
        // Peer instance routes with auth middleware
        .nest(
            "/peers",
            handlers::peers::router()
                .merge(handlers::peer_instance_labels::peer_labels_router())
                .nest("/:id/transfer", handlers::transfer::router())
                .nest("/:id/connections", handlers::peer::peer_router())
                .nest("/:id/chunks", handlers::peer::chunk_router())
                .merge(handlers::peer::network_profile_router())
                .layer(middleware::from_fn_with_state(
                    auth_service.clone(),
                    auth_middleware,
                )),
        )
        // Sync policy routes with auth middleware
        .nest(
            "/sync-policies",
            handlers::sync_policies::router()
                .layer(DefaultBodyLimit::max(1024 * 1024)) // 1 MB
                .layer(middleware::from_fn_with_state(
                    auth_service.clone(),
                    auth_middleware,
                )),
        )
        // Admin routes with admin middleware (requires is_admin)
        .nest(
            "/admin",
            handlers::admin::router()
                .route("/metrics", get(handlers::health::metrics))
                .nest("/analytics", handlers::analytics::router())
                .nest("/lifecycle", handlers::lifecycle::router())
                .nest("/storage-gc", handlers::storage_gc::router())
                .nest("/search", handlers::search::admin_router())
                .nest("/telemetry", handlers::telemetry::router())
                .nest("/monitoring", handlers::monitoring::router())
                .nest("/sso", handlers::sso_admin::router())
                .layer(DefaultBodyLimit::max(1024 * 1024)) // 1 MB
                .layer(middleware::from_fn_with_state(
                    auth_service.clone(),
                    admin_middleware,
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
        // Format handler read-only routes (list, get) with optional auth
        .nest(
            "/formats",
            handlers::plugins::format_router().layer(middleware::from_fn_with_state(
                auth_service.clone(),
                optional_auth_middleware,
            )),
        )
        // Format handler mutating routes (enable, disable, test) require admin
        .nest(
            "/formats",
            handlers::plugins::format_admin_router().layer(middleware::from_fn_with_state(
                auth_service.clone(),
                admin_middleware,
            )),
        )
        // Webhook routes split between read-only (any authenticated user) and
        // mutating handlers (admin only). Webhook subscriptions can receive
        // cross-tenant event metadata (e.g. repository.created, user.created on
        // global webhooks where repository_id = NULL), so create/delete/enable/
        // disable/test/redeliver are gated to admin only until per-tenant
        // scoping lands (#948). Each sub-router applies its own auth layer
        // before being merged under /webhooks.
        .nest(
            "/webhooks",
            handlers::webhooks::router()
                .layer(middleware::from_fn_with_state(
                    auth_service.clone(),
                    auth_middleware,
                ))
                .merge(
                    handlers::webhooks::admin_router().layer(middleware::from_fn_with_state(
                        auth_service.clone(),
                        admin_middleware,
                    )),
                )
                .layer(DefaultBodyLimit::max(1024 * 1024)), // 1 MB
        )
        // Domain event stream (SSE) with auth middleware
        .nest(
            "/events",
            handlers::events::router().layer(middleware::from_fn_with_state(
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
        // SBOM routes with auth middleware
        .nest(
            "/sbom",
            handlers::sbom::router().layer(middleware::from_fn_with_state(
                auth_service.clone(),
                auth_middleware,
            )),
        )
        // Promotion routes with auth middleware (staging -> release workflow)
        .nest(
            "/promotion",
            handlers::promotion::router().layer(middleware::from_fn_with_state(
                auth_service.clone(),
                auth_middleware,
            )),
        )
        // Auto-promotion rules with auth middleware
        .nest(
            "/promotion-rules",
            handlers::promotion_rules::router().layer(middleware::from_fn_with_state(
                auth_service.clone(),
                auth_middleware,
            )),
        )
        // Promotion approval workflow routes with auth middleware
        .nest(
            "/approval",
            handlers::approval::router().layer(middleware::from_fn_with_state(
                auth_service.clone(),
                auth_middleware,
            )),
        )
        // Quality gates and health scoring routes with auth middleware
        .nest(
            "/quality",
            handlers::quality_gates::router().layer(middleware::from_fn_with_state(
                auth_service.clone(),
                auth_middleware,
            )),
        )
        // Package curation routes with auth middleware
        .nest(
            "/curation",
            handlers::curation::router().layer(middleware::from_fn_with_state(
                auth_service.clone(),
                auth_middleware,
            )),
        )
        // Dependency-Track proxy routes with auth middleware
        .nest(
            "/dependency-track",
            handlers::dependency_track::router().layer(middleware::from_fn_with_state(
                auth_service.clone(),
                auth_middleware,
            )),
        )
        // Remote instance management & proxy routes with auth middleware
        .nest(
            "/instances",
            handlers::remote_instances::router().layer(middleware::from_fn_with_state(
                auth_service.clone(),
                auth_middleware,
            )),
        )
        // Service account management routes with auth middleware
        .nest(
            "/service-accounts",
            handlers::service_accounts::router().layer(middleware::from_fn_with_state(
                auth_service.clone(),
                auth_middleware,
            )),
        )
        // Migration routes with auth middleware
        .nest(
            "/migrations",
            handlers::migration::router().layer(middleware::from_fn_with_state(
                auth_service.clone(),
                auth_middleware,
            )),
        )
        // Chunked/resumable upload routes with auth middleware
        .nest(
            "/uploads",
            handlers::upload::router().layer(middleware::from_fn_with_state(
                auth_service,
                auth_middleware,
            )),
        )
        // General API rate limiting (100 req/min per IP/user)
        .layer(middleware::from_fn_with_state(
            api_rate_limiter,
            rate_limit_middleware,
        ))
}
