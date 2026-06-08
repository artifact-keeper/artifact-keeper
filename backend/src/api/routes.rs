//! Route definitions for the API.

use axum::{
    error_handling::HandleErrorLayer, extract::DefaultBodyLimit, middleware, routing::get,
    BoxError, Router,
};
use std::sync::Arc;
use std::time::Duration;
use tower::{
    limit::GlobalConcurrencyLimitLayer, load_shed::LoadShedLayer, timeout::TimeoutLayer,
    ServiceBuilder,
};
use utoipa_swagger_ui::SwaggerUi;

use crate::error::AppError;

use super::handlers;
use super::middleware::auth::{
    admin_middleware, auth_middleware, optional_auth_middleware, repo_visibility_middleware,
    RepoVisibilityState,
};
use super::middleware::demo::demo_guard;
use super::middleware::guest_access::{guest_access_guard, GuestAccessState};
use super::middleware::rate_limit::{
    login_rate_limit_middleware, rate_limit_by_ip_middleware, rate_limit_middleware,
    LoginRateLimitState, RateLimitExemptions, RateLimitState, RateLimiter,
};
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
        permission_service: state.permission_service.clone(),
    };

    // All native-protocol format handlers share the repo visibility
    // middleware: anonymous users can only access public repositories.
    //
    // The upload body limit is read from config (MAX_UPLOAD_SIZE env var,
    // default 10 GB). A value of 0 disables the limit entirely.
    let upload_limit = state.config.max_upload_size_bytes;

    let format_routes = Router::new()
        .nest("/general", handlers::general::router())
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
        // `lxc` is the same wire protocol and same handler as `incus`; the
        // `IncusHandler` accepts both `format='incus'` and `format='lxc'`
        // repositories (see `resolve_incus_repo`). Without this alias,
        // repositories created with `format: lxc` 404 on every request
        // because no `/lxc/*` route existed (#1272). The SimpleStreams index
        // served via this prefix currently references `/incus/...` download
        // URLs; making those URLs prefix-aware is tracked as a follow-up.
        .nest("/lxc", handlers::incus::router())
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

    // Apply guest-access guard (issue #850). When guest access is disabled,
    // unauthenticated requests are rejected with 401 (with an allowlist for
    // login/setup/health/OCI challenge). The guard performs its own token
    // resolution so it can run as a global outer layer regardless of which
    // inner auth middleware (if any) the matched route uses.
    //
    // Register this long-lived AuthService's token cache with the global
    // invalidation registry so a deactivation (issue #931 / #1371) flushes
    // its cached API-token validations immediately. Without this the guard
    // would keep accepting a deactivated user's API token from its own cache
    // even though the inner auth_service rejects it, because the guard runs
    // FIRST and its `pass/fail` decision is what produces the 401 here when
    // `guest_access_enabled=false`.
    let guest_auth_service = Arc::new(AuthService::new(
        state.db.clone(),
        Arc::new(state.config.clone()),
    ));
    guest_auth_service.register_for_global_flush();
    let guest_access_state = GuestAccessState {
        guest_access_enabled: state.config.guest_access_enabled,
        auth_service: guest_auth_service,
    };
    router = router.layer(middleware::from_fn_with_state(
        guest_access_state,
        guest_access_guard,
    ));

    // Apply setup guard (locks API until admin password is changed)
    router = router.layer(middleware::from_fn_with_state(state.clone(), setup_guard));

    // Apply demo mode guard if enabled
    if state.config.demo_mode {
        tracing::info!("Demo mode enabled — write operations will be blocked");
        router = router.layer(middleware::from_fn_with_state(state.clone(), demo_guard));
    }

    // Correlation ID middleware (runs first on every request after the global
    // backstop below). Extracts or generates a correlation ID and sets the
    // X-Correlation-ID response header.
    router = router.layer(middleware::from_fn(correlation_id_middleware));

    // Defense-in-depth backstop (outermost layer). A router-wide load-shed +
    // concurrency limit (+ optional request timeout) so that NO request path —
    // even one that runs an unbounded CPU-bound operation (bcrypt,
    // decompression) on a worker thread — can pin every worker and starve the
    // accept loop. Excess concurrent requests are shed with 503 + Retry-After
    // instead of queueing; a request exceeding the global timeout is aborted
    // with 503. Both limits are config-driven with generous defaults and a `0`
    // sentinel that disables the respective layer (see config.rs). Layered
    // OUTSIDE correlation-id (after `with_state`) so shedding happens before
    // any real work.
    let max_concurrency = state.config.global_max_concurrency;
    let request_timeout_secs = state.config.global_request_timeout_secs;
    apply_global_backstop(
        router.with_state(state),
        max_concurrency,
        request_timeout_secs,
    )
}

/// Map a backstop layer error (load-shed `Overloaded` or timeout `Elapsed`)
/// onto a 503 so clients back off and retry, mirroring the auth-semaphore
/// shed policy. `Retry-After` is attached by `AppError`'s `IntoResponse`.
async fn handle_backstop_error(err: BoxError) -> AppError {
    AppError::ServiceUnavailable(format!("Server overloaded, please retry: {err}"))
}

/// Wrap `router` in the outermost defense-in-depth backstop. Each layer is
/// applied only when its config value is non-zero (`0` disables it), so the
/// behaviour is identical to the unpatched router when both are disabled.
///
/// `HandleErrorLayer` requires the error type of the inner stack to be fixed,
/// which `ServiceBuilder::option_layer` (its `Either`/`Infallible` branches)
/// makes ambiguous — so the on/off combinations are spelled out explicitly,
/// each building a homogeneous fallible stack before `HandleErrorLayer`
/// collapses it back to an infallible axum service mapping shed/timeout
/// errors to 503.
fn apply_global_backstop(
    router: Router,
    max_concurrency: usize,
    request_timeout_secs: u64,
) -> Router {
    let concurrency_on = max_concurrency != 0;
    let timeout_on = request_timeout_secs != 0;
    let timeout = Duration::from_secs(request_timeout_secs);

    match (concurrency_on, timeout_on) {
        // Nothing enabled -> router untouched (no extra layer cost).
        (false, false) => router,
        // Concurrency limit + load-shed only.
        (true, false) => router.layer(
            ServiceBuilder::new()
                .layer(HandleErrorLayer::new(handle_backstop_error))
                .layer(LoadShedLayer::new())
                .layer(GlobalConcurrencyLimitLayer::new(max_concurrency)),
        ),
        // Request timeout only.
        (false, true) => router.layer(
            ServiceBuilder::new()
                .layer(HandleErrorLayer::new(handle_backstop_error))
                .layer(TimeoutLayer::new(timeout)),
        ),
        // Full backstop: load-shed + concurrency limit + timeout.
        (true, true) => router.layer(
            ServiceBuilder::new()
                .layer(HandleErrorLayer::new(handle_backstop_error))
                .layer(LoadShedLayer::new())
                .layer(GlobalConcurrencyLimitLayer::new(max_concurrency))
                .layer(TimeoutLayer::new(timeout)),
        ),
    }
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

    // Rate limiters and exemptions, driven by Config fields.
    let exemptions = Arc::new(RateLimitExemptions::with_cidrs(
        state.config.rate_limit_exempt_usernames.clone(),
        state.config.rate_limit_exempt_service_accounts,
        state.config.rate_limit_trusted_cidrs.clone(),
    ));

    // Trusted reverse-proxy CIDRs (#2023). `X-Forwarded-For` is believed for
    // client-IP resolution only when the immediate TCP peer falls within one
    // of these ranges; empty (the default) means XFF is never trusted and the
    // real TCP peer is always the rate-limit key. Shared by every limiter
    // state so the policy is uniform across endpoints.
    let trusted_proxies = Arc::new(state.config.rate_limit_trusted_proxy_cidrs.clone());

    let auth_rate_limiter = Arc::new(RateLimiter::new(
        state.config.rate_limit_auth_per_window,
        state.config.rate_limit_window_secs,
    ));
    let api_rate_limiter = Arc::new(RateLimiter::new(
        state.config.rate_limit_api_per_window,
        state.config.rate_limit_window_secs,
    ));
    let search_rate_limiter = Arc::new(RateLimiter::new(
        state.config.rate_limit_search_per_window,
        state.config.rate_limit_window_secs,
    ));
    // Stricter per-IP bucket for endpoints that mint presigned download
    // URLs. See #1053.
    let presign_rate_limiter = Arc::new(RateLimiter::new(
        state.config.rate_limit_presign_per_window,
        state.config.rate_limit_window_secs,
    ));
    // Global shedding backstop for the login path. The login limiter keys
    // per-(username, IP); this single-bucket backstop bounds the total login
    // volume per window (and therefore the size of the per-key map) so a
    // username-cycling attacker cannot exhaust memory via unbounded distinct
    // keys. Sized far above any legitimate concurrent-login volume so real
    // users never reach it; it sheds rather than starves.
    let login_global_rate_limiter = Arc::new(RateLimiter::new(
        state.config.rate_limit_login_global_per_window,
        state.config.rate_limit_window_secs,
    ));
    // Stricter per-user bucket for self-password-change attempts. The
    // handler bcrypt-verifies the current password, so an attacker who
    // already holds the victim's JWT can otherwise drive ~`api/min`
    // password guesses through this endpoint and CPU-grind the bcrypt
    // verifier. Default: 5 attempts / 15 minutes per user. See #1026.
    let password_change_rate_limiter = Arc::new(RateLimiter::new(
        state.config.rate_limit_password_change_per_window,
        state.config.rate_limit_password_change_window_secs,
    ));

    // Master on/off switch (#1602). When disabled, every rate-limit layer
    // short-circuits before touching its limiter so no request is limited.
    let rate_limit_enabled = state.config.rate_limit_enabled;
    if !rate_limit_enabled {
        tracing::warn!(
            "Rate limiting is DISABLED (RATE_LIMIT_ENABLED=false); no requests will be rate limited"
        );
    }

    let auth_rate_limit_state = RateLimitState {
        limiter: Arc::clone(&auth_rate_limiter),
        exemptions: Arc::clone(&exemptions),
        enabled: rate_limit_enabled,
        trusted_proxies: Arc::clone(&trusted_proxies),
    };
    // Login-only state: keys the shared auth limiter per-(username, IP) and
    // gates it behind the global shedding backstop. Applied only to /login so
    // /logout and /refresh keep the plain IP-keyed limiter.
    let login_rate_limit_state = LoginRateLimitState {
        inner: RateLimitState {
            limiter: Arc::clone(&auth_rate_limiter),
            exemptions: Arc::clone(&exemptions),
            enabled: rate_limit_enabled,
            trusted_proxies: Arc::clone(&trusted_proxies),
        },
        backstop: Arc::clone(&login_global_rate_limiter),
    };
    // Separate state for the unauthenticated TOTP second-factor endpoint
    // (`/auth/totp/verify`). Shares the `auth_rate_limiter` window so the
    // 2FA code is no more brute-forceable than the password it backs (#1820).
    let totp_rate_limit_state = RateLimitState {
        limiter: Arc::clone(&auth_rate_limiter),
        exemptions: Arc::clone(&exemptions),
        enabled: rate_limit_enabled,
        trusted_proxies: Arc::clone(&trusted_proxies),
    };
    let api_rate_limit_state = RateLimitState {
        limiter: Arc::clone(&api_rate_limiter),
        exemptions: Arc::clone(&exemptions),
        enabled: rate_limit_enabled,
        trusted_proxies: Arc::clone(&trusted_proxies),
    };
    let search_rate_limit_state = RateLimitState {
        limiter: Arc::clone(&search_rate_limiter),
        exemptions: Arc::clone(&exemptions),
        enabled: rate_limit_enabled,
        trusted_proxies: Arc::clone(&trusted_proxies),
    };
    let presign_rate_limit_state = RateLimitState {
        limiter: Arc::clone(&presign_rate_limiter),
        exemptions: Arc::clone(&exemptions),
        enabled: rate_limit_enabled,
        trusted_proxies: Arc::clone(&trusted_proxies),
    };
    let password_change_rate_limit_state = RateLimitState {
        limiter: Arc::clone(&password_change_rate_limiter),
        exemptions: Arc::clone(&exemptions),
        enabled: rate_limit_enabled,
        trusted_proxies: Arc::clone(&trusted_proxies),
    };

    // Spawn periodic cleanup of expired rate-limiter entries to prevent
    // unbounded HashMap growth from unique client IPs over time.
    {
        let auth_cleanup = Arc::clone(&auth_rate_limiter);
        let api_cleanup = Arc::clone(&api_rate_limiter);
        let search_cleanup = Arc::clone(&search_rate_limiter);
        let presign_cleanup = Arc::clone(&presign_rate_limiter);
        let login_global_cleanup = Arc::clone(&login_global_rate_limiter);
        let password_change_cleanup = Arc::clone(&password_change_rate_limiter);
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(60));
            loop {
                interval.tick().await;
                auth_cleanup.cleanup_expired().await;
                api_cleanup.cleanup_expired().await;
                search_cleanup.cleanup_expired().await;
                presign_cleanup.cleanup_expired().await;
                login_global_cleanup.cleanup_expired().await;
                password_change_cleanup.cleanup_expired().await;
            }
        });
    }

    Router::new()
        // System configuration. The endpoint is reachable without auth so
        // frontends can discover login/upload affordances pre-authentication,
        // but it runs through `optional_auth_middleware` so the handler can
        // tell whether the caller is an admin. Security-posture fields
        // (scanner/auth-provider/permission/plugin-signing/storage state) are
        // redacted for anonymous and non-admin callers and only returned to
        // admins — anonymous callers should not be able to fingerprint the
        // instance's defensive configuration.
        .nest(
            "/system",
            handlers::system_config::router().layer(middleware::from_fn_with_state(
                auth_service.clone(),
                optional_auth_middleware,
            )),
        )
        // Setup status (public, no auth)
        .nest("/setup", handlers::auth::setup_router())
        // Auth routes - split into login / public / protected (rate limited).
        // /login carries the per-(username, IP) login limiter so a junk flood
        // against one identity/origin cannot lock out other accounts; /logout
        // and /refresh (no `username` field) keep the plain IP-keyed limiter.
        .nest(
            "/auth",
            handlers::auth::login_router().layer(middleware::from_fn_with_state(
                login_rate_limit_state,
                login_rate_limit_middleware,
            )),
        )
        .nest(
            "/auth",
            handlers::auth::public_router().layer(middleware::from_fn_with_state(
                auth_rate_limit_state,
                rate_limit_middleware,
            )),
        )
        .nest("/auth/sso", handlers::sso::router())
        // CI OIDC token exchange (public, no auth — JWT is the credential)
        .nest("/auth/ci", handlers::ci_auth::router())
        .nest(
            "/auth",
            handlers::auth::protected_router().layer(middleware::from_fn_with_state(
                auth_service.clone(),
                auth_middleware,
            )),
        )
        // TOTP 2FA routes. The public `/verify` endpoint is the second-factor
        // exchange; rate-limit it like `/auth` above so the 6-digit code and
        // backup codes cannot be brute-forced (#1820).
        .nest(
            "/auth/totp",
            handlers::totp::public_router().layer(middleware::from_fn_with_state(
                totp_rate_limit_state,
                rate_limit_middleware,
            )),
        )
        .nest(
            "/auth/totp",
            handlers::totp::protected_router().layer(middleware::from_fn_with_state(
                auth_service.clone(),
                auth_middleware,
            )),
        )
        // Repository routes with optional auth middleware. The download
        // route (`/:key/download/*path`) carries an additional stricter
        // per-IP rate limit (#1053) on top of the general API limit
        // because it mints presigned URLs at O(1) memory cost per
        // request - an attacker can drive much higher concurrency on
        // this path than on memory-buffered endpoints.
        .nest(
            "/repositories",
            handlers::repositories::router()
                .merge(handlers::repositories::download_router().layer(
                    middleware::from_fn_with_state(
                        presign_rate_limit_state,
                        rate_limit_by_ip_middleware,
                    ),
                ))
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
        // User-management routes are split across two `/users` nests by
        // authorization model. The combined story spans #1250 (self-service
        // password change must reach a non-admin's own user-id) and #1257
        // (the same split is needed for the token CRUD + GET /:id paths,
        // which the admin_middleware was 403'ing for non-admin self-action).
        //
        //   * auth_middleware nest (first nest below):
        //     - `self_password_router`   : POST /:id/password
        //                                  (rate-limited, #1026)
        //     - `self_or_admin_router`   : GET /:id, GET/POST /:id/tokens,
        //                                  DELETE /:id/tokens/:token_id
        //     Each handler enforces `auth.user_id != id && !auth.is_admin`
        //     (or `change_password`'s ownership check), so widening the
        //     middleware here does NOT let one non-admin act on another.
        //     Defense-in-depth `if !auth.is_admin` guards are present on
        //     the admin handlers in the second nest below.
        //
        //   * admin_middleware nest (second nest):
        //     - `router`                 : list / create / update / delete /
        //                                  role-management
        //     - `admin_password_router`  : reset / force-change
        //                                  (rate-limited, #1026)
        .nest(
            "/users",
            handlers::users::self_password_router()
                .layer(middleware::from_fn_with_state(
                    password_change_rate_limit_state.clone(),
                    rate_limit_middleware,
                ))
                .merge(handlers::users::self_or_admin_router())
                .layer(DefaultBodyLimit::max(1024 * 1024)) // 1 MB
                .layer(middleware::from_fn_with_state(
                    auth_service.clone(),
                    auth_middleware,
                )),
        )
        .nest(
            "/users",
            handlers::users::router()
                .merge(handlers::users::admin_password_router().layer(
                    middleware::from_fn_with_state(
                        password_change_rate_limit_state,
                        rate_limit_middleware,
                    ),
                ))
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
        // Group routes with optional auth middleware
        // (list/get are public, mutating endpoints check auth in handlers)
        .nest(
            "/groups",
            handlers::groups::router()
                .layer(DefaultBodyLimit::max(1024 * 1024)) // 1 MB
                .layer(middleware::from_fn_with_state(
                    auth_service.clone(),
                    optional_auth_middleware,
                )),
        )
        // Permission routes with auth middleware.
        //
        // The permission handlers declare `Extension<Option<AuthExtension>>`
        // and do their own authorization (require_auth + require_scope /
        // require_admin). `auth_middleware` now injects BOTH the bare
        // `AuthExtension` and an `Option<AuthExtension>` (see its body), so
        // either extractor shape resolves. Before that fix the
        // `Option<AuthExtension>` extractor failed during request extraction
        // with HTTP 500 ("Missing request extension: Extension of type
        // Option<AuthExtension>") before the in-handler scope check ran, so a
        // read-scope service-account token got 500 instead of the canonical
        // 403 on POST /api/v1/permissions. Hard auth (401 for anonymous) is
        // preserved because auth_middleware still rejects unauthenticated
        // requests up front. See #1438 (B10).
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
        // Search routes with optional auth and dedicated rate limiting (300 req/min).
        //
        // Layer ORDER matters: Tower applies the LAST `.layer()` as the
        // OUTERMOST wrapper (it runs first on the request path). The rate-limit
        // middleware keys authenticated callers by `user:<id>` and falls back to
        // `ip:<addr>` only when no `AuthExtension` is present. For that per-user
        // keying to work, `optional_auth_middleware` must run BEFORE the limiter
        // so the auth extension is populated when the limiter reads it.
        //
        // Therefore the limiter is applied FIRST here (making it the inner layer)
        // and the auth middleware LAST (the outer layer). The previous order had
        // them reversed, so the limiter ran before auth was set and keyed EVERY
        // search request by source IP — collapsing all callers (authenticated and
        // anonymous alike) behind a shared egress IP into a single 300/min bucket
        // and defeating the per-user design (a fleet-wide search outage under
        // load). See `search_rate_limit_layer_runs_after_auth`.
        .nest(
            "/search",
            handlers::search::router()
                .layer(middleware::from_fn_with_state(
                    search_rate_limit_state,
                    rate_limit_middleware,
                ))
                .layer(middleware::from_fn_with_state(
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
            {
                let admin =
                    handlers::admin::router().route("/metrics", get(handlers::health::metrics));
                #[cfg(feature = "profiling")]
                let admin = admin
                    .route("/memory-stats", get(handlers::health::memory_stats))
                    .route("/heap-profile", get(handlers::health::heap_profile));
                admin
            }
            .nest("/analytics", handlers::analytics::router())
            .nest("/lifecycle", handlers::lifecycle::router())
            .nest("/storage-gc", handlers::storage_gc::router())
            .nest("/search", handlers::search::admin_router())
            .nest("/telemetry", handlers::telemetry::router())
            .nest("/monitoring", handlers::monitoring::router())
            .nest("/sso", handlers::sso_admin::router())
            .nest("/ci-oidc", handlers::ci_auth_admin::router())
            .nest("/smtp", handlers::smtp::router())
            .layer(DefaultBodyLimit::max(1024 * 1024)) // 1 MB
            .layer(middleware::from_fn_with_state(
                auth_service.clone(),
                admin_middleware,
            )),
        )
        // Plugin read-only routes with auth middleware
        .nest(
            "/plugins",
            handlers::plugins::router().layer(middleware::from_fn_with_state(
                auth_service.clone(),
                auth_middleware,
            )),
        )
        // Plugin install + lifecycle routes require admin (loads arbitrary WASM)
        .nest(
            "/plugins",
            handlers::plugins::admin_router().layer(middleware::from_fn_with_state(
                auth_service.clone(),
                admin_middleware,
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
        // Webhook routes with auth middleware
        .nest(
            "/webhooks",
            handlers::webhooks::router()
                .layer(DefaultBodyLimit::max(1024 * 1024)) // 1 MB
                .layer(middleware::from_fn_with_state(
                    auth_service.clone(),
                    auth_middleware,
                )),
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
        // #1784: axum 0.7 nest matches `/sbom` (no slash) against the inner `/`
        // route but does NOT match the trailing-slash form `/sbom/`, which 404'd
        // with an empty body instead of behaving like the list endpoint. Add an
        // explicit redirect from the trailing-slash form to the canonical path
        // so clients that append a slash still reach the list handler.
        .route(
            "/sbom/",
            get(|| async { axum::response::Redirect::permanent("/api/v1/sbom") }),
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
        // Quarantine management routes with auth middleware
        .nest(
            "/quarantine",
            handlers::quarantine::router().layer(middleware::from_fn_with_state(
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
            api_rate_limit_state,
            rate_limit_middleware,
        ))
}

#[cfg(test)]
mod tests {
    //! Source-level meta-tests pinning the `lxc` -> `incus` route alias
    //! introduced for #1272. Repositories created with `format: lxc` 404'd
    //! on every request because no `/lxc/*` route existed in the router,
    //! even though the rest of the stack (enum variant, format dispatch,
    //! repo resolver) accepted `lxc`. These assertions read the source of
    //! `create_router` and fail loudly if a future refactor drops the
    //! `/lxc` nest, since a runtime test would need full app state + a DB
    //! fixture to reproduce the regression. The intent is to keep the two
    //! prefixes wired to the same handler until the `lxc` format is either
    //! folded into `incus` or given its own handler with prefix-aware URL
    //! construction (tracked as a follow-up to #1272).
    const ROUTES_RS_SRC: &str = include_str!("routes.rs");

    #[test]
    fn lxc_route_is_registered_alongside_incus() {
        assert!(
            ROUTES_RS_SRC.contains(".nest(\"/incus\", handlers::incus::router())"),
            "incus route registration missing -- the lxc alias test below \
             would otherwise be vacuously true; refactor needs to update \
             this meta-test to match the new shape"
        );
        assert!(
            ROUTES_RS_SRC.contains(".nest(\"/lxc\", handlers::incus::router())"),
            "/lxc route alias missing; lxc-format repositories will 404 \
             on every request (regression of #1272)"
        );
    }

    #[test]
    fn lxc_and_incus_share_the_same_handler() {
        // Pin the invariant that both prefixes mount the same router. If
        // someone splits them into separate handlers in the future, this
        // test should be updated alongside the routing decision so the
        // intent stays explicit in source.
        let incus_count = ROUTES_RS_SRC.matches("handlers::incus::router()").count();
        assert!(
            incus_count >= 2,
            "expected handlers::incus::router() to be referenced at least \
             twice (once for /incus, once for /lxc); found {incus_count}"
        );
    }

    #[test]
    fn sbom_trailing_slash_is_handled() {
        // Regression for #1784: axum 0.7's `.nest("/sbom", ...)` resolves the
        // no-slash form `/sbom` (against the inner `/` route) but 404's the
        // trailing-slash form `/sbom/` with an empty body. The fix registers an
        // explicit redirect route for the trailing-slash form. A runtime test
        // would need full app state + a DB; pin the routing decision in source.
        assert!(
            ROUTES_RS_SRC.contains(".nest(\n            \"/sbom\","),
            "sbom nest registration missing; the trailing-slash redirect test \
             below would otherwise be vacuously true"
        );
        assert!(
            ROUTES_RS_SRC.contains(".route(\n            \"/sbom/\","),
            "/sbom/ trailing-slash redirect missing; GET /api/v1/sbom/ will \
             404 with an empty body instead of reaching the list handler \
             (regression of #1784)"
        );
        assert!(
            ROUTES_RS_SRC.contains("Redirect::permanent(\"/api/v1/sbom\")"),
            "/sbom/ route must redirect to the canonical /api/v1/sbom path"
        );
    }

    #[test]
    fn plugin_install_and_lifecycle_require_admin() {
        // Installing a plugin loads arbitrary WASM, and enabling/disabling or
        // uninstalling one changes the running plugin set. These routes must be
        // mounted via `plugins::admin_router` under `admin_middleware`, not the
        // plain `auth_middleware` (which any authenticated user passes). A
        // regression here re-opens the supply-chain path where a non-admin can
        // drive the WASM plugin installer.
        let admin_nest = ROUTES_RS_SRC
            .split("handlers::plugins::admin_router()")
            .nth(1)
            .expect("plugins::admin_router() must be nested under /plugins");
        // The nest immediately following admin_router() must wire admin_middleware.
        let next_middleware = admin_nest
            .split("from_fn_with_state")
            .nth(1)
            .expect("admin_router() nest must attach a middleware layer");
        assert!(
            next_middleware.contains("admin_middleware"),
            "plugin install + lifecycle routes must be gated by admin_middleware"
        );
    }
}
