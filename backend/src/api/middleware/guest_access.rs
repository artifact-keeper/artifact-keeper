//! Guest-access guard middleware (issue #850).
//!
//! Enforces a server-wide policy that disables anonymous (unauthenticated)
//! access. When `config.guest_access_enabled` is `false`, this middleware
//! returns `401 Unauthorized` for any request that does not present valid
//! credentials, with a small allowlist for endpoints that must remain
//! reachable so users and package clients can authenticate:
//!
//! * `/api/v1/auth/*`              login, refresh, logout, SSO callbacks
//! * `/api/v1/setup/*`             initial setup wizard
//! * `/api/v1/system/config`       web UI fetches before login
//! * `/health`, `/healthz`,
//!   `/ready`, `/readyz`, `/livez`  Kubernetes / load-balancer probes
//! * `/v2/`, `/v2/*`               OCI Distribution Spec challenge / push
//!
//! When `guest_access_enabled` is `true` (the default), the middleware is a
//! no-op so existing deployments are unaffected.
//!
//! ### Why we resolve auth ourselves
//!
//! The guard is registered as an outer (global) layer in `routes::create_router`,
//! which means it runs **before** the inner `auth_middleware` /
//! `optional_auth_middleware` / `repo_visibility_middleware` layers populate
//! request extensions. To make the gating decision we therefore resolve auth
//! directly (the same path the optional and visibility middlewares use) and
//! short-circuit if the path is not allowlisted. Inner middlewares run again on
//! requests that pass the guard and populate the extensions used by handlers.
//!
//! We resolve via [`try_resolve_auth_outcome`] and match on the full
//! [`AuthOutcome`] rather than a boolean "is there a principal?" check, so a
//! transient [`AuthOutcome::Overloaded`] shed (the bcrypt-capacity cap
//! saturating) becomes a retryable **503**, not a 401. Flattening `Overloaded`
//! into an "unauthenticated" 401 would fail requests carrying valid credentials
//! under load — the exact regression `AuthOutcome::Overloaded` exists to prevent
//! (a saturated auth cap is retryable; non-retrying clients such as twine abort
//! on 401). The guard therefore returns the same 503 the inner middlewares do.

use std::sync::Arc;

use axum::{
    extract::{Request, State},
    http::{header, HeaderValue, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
    Json,
};
use serde_json::json;

use crate::api::middleware::auth::{
    extract_token, service_unavailable_response, try_resolve_auth_outcome, AuthOutcome,
};
use crate::services::auth_service::AuthService;

/// Shared state for the guest-access guard.
///
/// Holds the policy flag and the `AuthService` needed to validate tokens.
#[derive(Clone)]
pub struct GuestAccessState {
    pub guest_access_enabled: bool,
    pub auth_service: Arc<AuthService>,
}

/// Endpoints that remain reachable without authentication even when
/// `guest_access_enabled` is `false`.
///
/// The list is intentionally tight: only the endpoints required for users
/// to log in, finish first-run setup, run liveness probes, or for OCI
/// clients to perform the unauthenticated challenge handshake.
fn is_allowlisted(path: &str) -> bool {
    // Exact-match health and readiness paths.
    matches!(
        path,
        "/health"
            | "/healthz"
            | "/ready"
            | "/readyz"
            | "/livez"
            | "/api/v1/system/config"
            // OCI Distribution Spec challenge endpoint. Some registries
            // serve this path with and without the trailing slash, so we
            // accept both.
            | "/v2"
            | "/v2/"
    ) || path.starts_with("/api/v1/auth/")
        || path == "/api/v1/auth"
        || path.starts_with("/api/v1/setup/")
        || path == "/api/v1/setup"
        // OCI clients fan out from /v2/ for the registry challenge and
        // subsequent token-protected operations. The registry must respond
        // with the WWW-Authenticate header for clients to learn where to
        // fetch a bearer token; downstream OCI handlers continue to enforce
        // their own auth on the actual blob/manifest operations.
        || path.starts_with("/v2/")
}

/// 401 response body returned when guest access is disabled.
/// Includes `WWW-Authenticate` headers (Basic, Bearer, Cargo) so
/// RFC 7235-compliant clients (Maven, pip, npm, etc.) can determine
/// the auth scheme and retry with credentials.
fn unauthorized_response() -> Response {
    let mut response = (
        StatusCode::UNAUTHORIZED,
        Json(json!({
            "error": "GUEST_ACCESS_DISABLED",
            "message": "This instance requires authentication. Please log in.",
        })),
    )
        .into_response();

    response.headers_mut().insert(
        header::WWW_AUTHENTICATE,
        HeaderValue::from_static("Basic realm=\"artifact-keeper\""),
    );
    response.headers_mut().append(
        header::WWW_AUTHENTICATE,
        HeaderValue::from_static("Bearer realm=\"artifact-keeper\", charset=\"UTF-8\""),
    );
    response
        .headers_mut()
        .append(header::WWW_AUTHENTICATE, HeaderValue::from_static("Cargo"));

    response
}

/// Map a resolved [`AuthOutcome`] to the guard's short-circuit response, or
/// `None` when the request should be allowed through to the inner layers.
///
/// This is the load-bearing distinction: an `Overloaded` shed must yield a
/// retryable **503**, NOT a 401. Collapsing it into the "unauthenticated" 401
/// would make valid credentials fail under transient auth-cap saturation. Kept
/// as a pure function so the mapping is unit-testable without a live auth backend.
fn guard_short_circuit(outcome: &AuthOutcome) -> Option<Response> {
    match outcome {
        // A principal resolved — let the request through; inner middlewares
        // re-resolve and populate request extensions for handlers.
        AuthOutcome::Resolved(_) => None,
        // Transient bcrypt-capacity shed: retryable 503, never a 401.
        AuthOutcome::Overloaded => Some(service_unavailable_response()),
        // No/invalid credential presented: guest access is disabled → 401.
        AuthOutcome::NoCredential | AuthOutcome::InvalidCredential => Some(unauthorized_response()),
    }
}

/// Middleware that blocks unauthenticated requests when guest access is
/// disabled server-wide. See module docs for behaviour and allowlist.
pub async fn guest_access_guard(
    State(state): State<GuestAccessState>,
    request: Request,
    next: Next,
) -> Response {
    if state.guest_access_enabled {
        return next.run(request).await;
    }

    let path = request.uri().path();
    if is_allowlisted(path) {
        return next.run(request).await;
    }

    // Resolve auth from the request headers via `try_resolve_auth_outcome` and
    // match the full outcome so a transient `AuthOutcome::Overloaded` shed
    // becomes a retryable 503 rather than a spurious 401 — see module docs.
    // Inner middlewares re-resolve and populate request extensions for handlers
    // on requests that pass the guard.
    let extracted = extract_token(&request);
    let outcome = try_resolve_auth_outcome(&state.auth_service, extracted).await;
    match guard_short_circuit(&outcome) {
        Some(response) => response,
        None => next.run(request).await,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // -- is_allowlisted --

    #[test]
    fn allowlist_health_and_readiness() {
        for p in ["/health", "/healthz", "/ready", "/readyz", "/livez"] {
            assert!(is_allowlisted(p), "{} should be allowlisted", p);
        }
    }

    #[test]
    fn allowlist_auth_namespace() {
        assert!(is_allowlisted("/api/v1/auth"));
        assert!(is_allowlisted("/api/v1/auth/login"));
        assert!(is_allowlisted("/api/v1/auth/refresh"));
        assert!(is_allowlisted("/api/v1/auth/sso/callback"));
        assert!(is_allowlisted("/api/v1/auth/totp/verify"));
    }

    #[test]
    fn allowlist_setup_namespace() {
        assert!(is_allowlisted("/api/v1/setup"));
        assert!(is_allowlisted("/api/v1/setup/status"));
    }

    #[test]
    fn allowlist_system_config_only() {
        assert!(is_allowlisted("/api/v1/system/config"));
        // A different system endpoint must not be allowlisted by accident.
        assert!(!is_allowlisted("/api/v1/system/config-extra"));
        assert!(!is_allowlisted("/api/v1/system/internal"));
    }

    #[test]
    fn allowlist_oci_v2_challenge() {
        assert!(is_allowlisted("/v2"));
        assert!(is_allowlisted("/v2/"));
        // OCI clients also probe /v2/<repo>/manifests/<tag> etc.; downstream
        // handlers enforce their own auth, but the path must reach them so
        // the WWW-Authenticate response is returned.
        assert!(is_allowlisted("/v2/library/nginx/manifests/latest"));
    }

    #[test]
    fn allowlist_rejects_unrelated_paths() {
        assert!(!is_allowlisted("/api/v1/repositories"));
        assert!(!is_allowlisted("/api/v1/artifacts"));
        assert!(!is_allowlisted("/api/v1/users"));
        assert!(!is_allowlisted("/api/v1/admin/metrics"));
        assert!(!is_allowlisted("/npm/some-pkg"));
        assert!(!is_allowlisted("/maven/group/artifact"));
        assert!(!is_allowlisted("/"));
    }

    #[test]
    fn allowlist_does_not_match_substring_attacks() {
        // Make sure naive `contains` style checks aren't used: paths that
        // merely include an allowlisted prefix as a substring must not pass.
        assert!(!is_allowlisted("/foo/api/v1/auth"));
        assert!(!is_allowlisted("/proxy/v2/library"));
        assert!(!is_allowlisted("/api/v1/authentication"));
    }

    // -- guard_short_circuit (Overloaded must be 503, never 401) --

    #[test]
    fn short_circuit_overloaded_is_503_not_401() {
        // Regression: a transient bcrypt-capacity shed must surface as a
        // retryable 503 through the guard. Collapsing it into the
        // GUEST_ACCESS_DISABLED 401 is what broke preemptive-auth clients
        // (twine, uv/pip token-in-url, CI X-API-Key) under concurrent load.
        let resp =
            guard_short_circuit(&AuthOutcome::Overloaded).expect("Overloaded must short-circuit");
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert!(
            resp.headers().contains_key(axum::http::header::RETRY_AFTER),
            "503 shed should carry a Retry-After hint"
        );
    }

    #[test]
    fn short_circuit_no_credential_is_401() {
        let resp = guard_short_circuit(&AuthOutcome::NoCredential)
            .expect("NoCredential must short-circuit");
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[test]
    fn short_circuit_invalid_credential_is_401() {
        let resp = guard_short_circuit(&AuthOutcome::InvalidCredential)
            .expect("InvalidCredential must short-circuit");
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    // -- unauthorized_response --

    #[test]
    fn unauthorized_response_status_and_body() {
        let resp = unauthorized_response();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        let ct = resp
            .headers()
            .get(axum::http::header::CONTENT_TYPE)
            .map(|v| v.to_str().unwrap_or("").to_string())
            .unwrap_or_default();
        assert!(ct.starts_with("application/json"));
    }

    #[test]
    fn unauthorized_response_includes_www_authenticate_basic() {
        let resp = unauthorized_response();
        let challenges: Vec<&str> = resp
            .headers()
            .get_all(header::WWW_AUTHENTICATE)
            .iter()
            .filter_map(|v| v.to_str().ok())
            .collect();
        assert!(
            challenges.contains(&"Basic realm=\"artifact-keeper\""),
            "expected Basic challenge, got: {:?}",
            challenges
        );
    }

    #[test]
    fn unauthorized_response_includes_www_authenticate_bearer() {
        let resp = unauthorized_response();
        let challenges: Vec<&str> = resp
            .headers()
            .get_all(header::WWW_AUTHENTICATE)
            .iter()
            .filter_map(|v| v.to_str().ok())
            .collect();
        assert!(
            challenges.contains(&"Bearer realm=\"artifact-keeper\", charset=\"UTF-8\""),
            "expected Bearer challenge, got: {:?}",
            challenges
        );
    }

    #[test]
    fn unauthorized_response_includes_www_authenticate_cargo() {
        let resp = unauthorized_response();
        let challenges: Vec<&str> = resp
            .headers()
            .get_all(header::WWW_AUTHENTICATE)
            .iter()
            .filter_map(|v| v.to_str().ok())
            .collect();
        assert!(
            challenges.contains(&"Cargo"),
            "expected Cargo challenge, got: {:?}",
            challenges
        );
    }

    // -- end-to-end behaviour via Axum router (ServiceExt::oneshot) --

    use crate::api::middleware::auth::AuthExtension;
    use crate::config::Config;
    use crate::services::auth_service::AuthService;
    use axum::body::Body;
    use axum::http::header::AUTHORIZATION;
    use axum::http::Request;
    use axum::middleware::from_fn_with_state;
    use axum::routing::get;
    use axum::Router;
    use sqlx::postgres::PgPoolOptions;
    use tower::ServiceExt;

    /// Construct a test pool that points at a non-existent database. The
    /// guard tests below never reach the DB because token validation only
    /// hits Postgres for API tokens, and we exercise the JWT path. Connecting
    /// lazily means construction does not fail when there is no DB available.
    fn lazy_pool() -> sqlx::PgPool {
        PgPoolOptions::new()
            .max_connections(1)
            // This pool can only ever fail (the DB does not exist); a short
            // acquire deadline makes that failure prompt. sqlx's default 30s
            // otherwise stalls every guard test that touches the API-token
            // path for the full timeout under parallel coverage runs.
            .acquire_timeout(std::time::Duration::from_secs(1))
            .connect_lazy("postgresql://localhost/__guest_access_unit_test__")
            .expect("lazy connect should succeed without contacting the DB")
    }

    fn make_state(guest_access_enabled: bool) -> GuestAccessState {
        let mut config = Config::test_config();
        config.guest_access_enabled = guest_access_enabled;
        let auth_service = Arc::new(AuthService::new(lazy_pool(), Arc::new(config)));
        GuestAccessState {
            guest_access_enabled,
            auth_service,
        }
    }

    fn make_app(state: GuestAccessState) -> Router {
        Router::new()
            .route("/", get(|| async { "root" }))
            .route("/api/v1/repositories", get(|| async { "repos" }))
            .route("/api/v1/auth/login", get(|| async { "login" }))
            .route("/api/v1/setup/status", get(|| async { "setup" }))
            .route("/api/v1/system/config", get(|| async { "config" }))
            .route("/health", get(|| async { "ok" }))
            .route("/v2/", get(|| async { "oci" }))
            .route("/v2/library/nginx/manifests/latest", get(|| async { "m" }))
            .layer(from_fn_with_state(state, guest_access_guard))
    }

    #[tokio::test]
    async fn guard_is_noop_when_guest_access_enabled() {
        let app = make_app(make_state(true));
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/api/v1/repositories")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn guard_blocks_unauth_when_disabled() {
        let app = make_app(make_state(false));
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/api/v1/repositories")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn guard_allows_login_path_when_disabled() {
        let app = make_app(make_state(false));
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/api/v1/auth/login")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn guard_allows_setup_path_when_disabled() {
        let app = make_app(make_state(false));
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/api/v1/setup/status")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn guard_allows_system_config_when_disabled() {
        let app = make_app(make_state(false));
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/api/v1/system/config")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn guard_allows_health_when_disabled() {
        let app = make_app(make_state(false));
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/health")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn guard_allows_oci_v2_root_when_disabled() {
        let app = make_app(make_state(false));
        let resp = app
            .oneshot(Request::builder().uri("/v2/").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn guard_allows_oci_v2_subpath_when_disabled() {
        let app = make_app(make_state(false));
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/v2/library/nginx/manifests/latest")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn guard_allows_request_with_valid_jwt_when_disabled() {
        // Build a config / auth service pair that we can use to mint a real
        // JWT; the guard then accepts the request because the token resolves.
        //
        // After PR #1190 (the replica-safe rewiring for #1173), JWT validation
        // on the request path goes through `validate_access_token_async`,
        // which consults the DB credential-change watermark. That means this
        // test needs a real DB connection (the previous lazy pool would error
        // on the first DB query and the token would fall through to the
        // API-token path and 401). When `DATABASE_URL` is unset we skip the
        // assertion so local `cargo test --lib` keeps passing without docker;
        // CI runs the test against the real postgres service.
        let url = match std::env::var("DATABASE_URL") {
            Ok(v) => v,
            Err(_) => return,
        };
        let pool = match sqlx::PgPool::connect(&url).await {
            Ok(p) => p,
            Err(_) => return,
        };

        let mut config = Config::test_config();
        config.guest_access_enabled = false;
        let cfg = Arc::new(config);
        let auth_service = Arc::new(AuthService::new(pool.clone(), cfg.clone()));

        // Insert a real user so the DB watermark check has a row to consult.
        // Backdate ALL credential-bearing columns so the token's `iat` is
        // strictly after them and the async validator accepts. This must
        // include `privileges_changed_at` (migration 131, DEFAULT NOW()): it
        // is folded into the credential-change watermark GREATEST(...), so
        // omitting it pins the watermark to insert time and the token minted
        // microseconds later intermittently 401s under parallel test load.
        // Runtime `sqlx::query` (not `query!`) keeps SQLX_OFFLINE builds
        // working without regenerating .sqlx metadata for a test-only insert.
        let user_id = uuid::Uuid::new_v4();
        let username = format!("guest_jwt_{}", &user_id.to_string()[..8]);
        sqlx::query(
            "INSERT INTO users (id, username, email, password_hash, auth_provider, \
                                is_active, is_admin, password_changed_at, \
                                privileges_changed_at, failed_login_attempts, \
                                created_at, updated_at) \
             VALUES ($1, $2, $3, 'unused', 'local', true, false, \
                     NOW() - INTERVAL '60 seconds', \
                     NOW() - INTERVAL '60 seconds', 0, \
                     NOW() - INTERVAL '60 seconds', \
                     NOW() - INTERVAL '60 seconds')",
        )
        .bind(user_id)
        .bind(&username)
        .bind(format!("{username}@test.com"))
        .execute(&pool)
        .await
        .expect("insert test user");

        let now = chrono::Utc::now();
        let user = crate::models::user::User {
            id: user_id,
            username,
            email: "alice@example.com".to_string(),
            password_hash: None,
            auth_provider: crate::models::user::AuthProvider::Local,
            external_id: None,
            display_name: None,
            is_active: true,
            is_admin: false,
            is_service_account: false,
            must_change_password: false,
            totp_secret: None,
            totp_enabled: false,
            totp_backup_codes: None,
            totp_verified_at: None,
            failed_login_attempts: 0,
            locked_until: None,
            last_failed_login_at: None,
            password_changed_at: now,
            last_login_at: None,
            created_at: now,
            updated_at: now,
        };
        let pair = auth_service
            .generate_tokens(&user)
            .expect("should mint a JWT pair");

        // Suppress unused-variable warning on AuthExtension import in
        // case this test module is compiled without the type being touched
        // elsewhere.
        let _phantom: Option<AuthExtension> = None;

        let state = GuestAccessState {
            guest_access_enabled: false,
            auth_service,
        };
        let app = make_app(state);

        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/api/v1/repositories")
                    .header(AUTHORIZATION, format!("Bearer {}", pair.access_token))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        // Cleanup.
        let _ = sqlx::query!("DELETE FROM users WHERE id = $1", user_id)
            .execute(&pool)
            .await;
    }

    #[tokio::test]
    async fn guard_rejects_request_with_invalid_bearer_when_disabled() {
        let app = make_app(make_state(false));
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/api/v1/repositories")
                    .header(AUTHORIZATION, "Bearer not-a-real-token")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }
}
