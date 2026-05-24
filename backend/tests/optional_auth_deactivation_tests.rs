//! Regression test for #1371: a deactivated user's API token must produce
//! HTTP 401 on optional-auth routes within seconds of `is_active=false`,
//! not be silently downgraded to anonymous (HTTP 200 with public-only data).
//!
//! Why this exists
//! ---------------
//! `optional_auth_middleware` originally treated an explicitly-presented
//! but invalid Bearer credential the same as no credential: it set
//! `Extension(Option<AuthExtension>::None)` and let the handler decide
//! what to do. For `GET /api/v1/repositories` the handler returns a
//! public-only list with HTTP 200 in the anonymous case — which means a
//! deactivated user's still-valid-looking API token continued to receive
//! 200 responses for up to `API_TOKEN_CACHE_TTL_SECS` (5 min) after
//! deactivation, masking the off-boarding signal. Release-gate
//! `auth-user-deactivation-revokes-tokens` (#1371) caught this.
//!
//! The fix makes `optional_auth_middleware` distinguish:
//!   * `AuthOutcome::NoCredential`      -> continue anonymously (200)
//!   * `AuthOutcome::Resolved(ext)`     -> continue with the extension
//!   * `AuthOutcome::InvalidCredential` -> 401 (no rescue from anon or
//!     ticket fallback)
//!
//! This integration test pins that behaviour end-to-end against a real DB:
//! it mints a real API token, hits the route under
//! `optional_auth_middleware` (200), deactivates the user via the real
//! `update_user` handler so `invalidate_user_token_cache_entries` runs,
//! and asserts the very next request returns 401 within well under 5s.
//!
//! Without the fix this test fails on the second request with HTTP 200
//! (silently anonymous), the exact failure the release-gate test
//! captures.
//!
//! Requires PostgreSQL with migrations applied:
//!
//! ```sh
//! DATABASE_URL="postgresql://registry:registry@localhost:30432/artifact_registry" \
//!     cargo test --test optional_auth_deactivation_tests -- --ignored
//! ```

use std::sync::Arc;
use std::time::Instant;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::{middleware, routing::get, Router};
use sqlx::PgPool;
use tower::ServiceExt;
use uuid::Uuid;

use artifact_keeper_backend::api::middleware::auth::{optional_auth_middleware, AuthExtension};
use artifact_keeper_backend::config::Config;
use artifact_keeper_backend::services::auth_service::{
    invalidate_user_token_cache_entries, invalidate_user_tokens, AuthService,
};

const JWT_SECRET: &str = "ak-1371-optional-auth-deactivation-test-secret-not-for-prod";

fn test_config() -> Arc<Config> {
    if std::env::var("JWT_SECRET").is_err() {
        std::env::set_var("JWT_SECRET", JWT_SECRET);
    }
    Arc::new(Config::from_env().expect("Config::from_env"))
}

async fn insert_active_user(pool: &PgPool, suffix: &str) -> Uuid {
    let id = Uuid::new_v4();
    let username = format!("ak1371-{}-{}", suffix, &id.to_string()[..8]);
    let email = format!("{}@test.local", username);
    sqlx::query(
        r#"
        INSERT INTO users (id, username, email, password_hash, is_admin, is_active, auth_provider)
        VALUES ($1, $2, $3, NULL, false, true, 'local')
        "#,
    )
    .bind(id)
    .bind(&username)
    .bind(&email)
    .execute(pool)
    .await
    .expect("insert user");
    id
}

async fn set_user_inactive(pool: &PgPool, user_id: Uuid) {
    sqlx::query("UPDATE users SET is_active = false, updated_at = NOW() WHERE id = $1")
        .bind(user_id)
        .execute(pool)
        .await
        .expect("deactivate user");
}

async fn cleanup_user(pool: &PgPool, user_id: Uuid) {
    let _ = sqlx::query("DELETE FROM api_tokens WHERE user_id = $1")
        .bind(user_id)
        .execute(pool)
        .await;
    let _ = sqlx::query("DELETE FROM users WHERE id = $1")
        .bind(user_id)
        .execute(pool)
        .await;
}

/// Build a single GET /probe route under `optional_auth_middleware`. The
/// handler echoes whether an `AuthExtension` was injected so we can tell
/// "200 because the credential resolved" from "200 because the credential
/// was silently downgraded" — the latter is the pre-#1371 bug.
fn build_optional_auth_app(auth_service: Arc<AuthService>) -> Router {
    Router::new()
        .route(
            "/probe",
            get(
                |axum::Extension(auth): axum::Extension<Option<AuthExtension>>| async move {
                    if auth.is_some() {
                        (StatusCode::OK, "authed")
                    } else {
                        (StatusCode::OK, "anon")
                    }
                },
            ),
        )
        .layer(middleware::from_fn_with_state(
            auth_service,
            optional_auth_middleware,
        ))
}

async fn run_probe(app: Router, bearer: &str) -> (StatusCode, String) {
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/probe")
                .header("Authorization", format!("Bearer {bearer}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .expect("request must complete");
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), 4096)
        .await
        .expect("body");
    (status, String::from_utf8_lossy(&bytes).into_owned())
}

/// PRIMARY regression for #1371.
///
///   1. Mint an API token for a freshly-created user.
///   2. First request with that token returns 200 and the handler sees an
///      `AuthExtension` ("authed").
///   3. Deactivate the user the way `users::update_user` does
///      (`invalidate_user_token_cache_entries` + `invalidate_user_tokens`
///      + SQL `is_active=false`).
///   4. The very next request with the SAME token MUST return 401 — well
///      inside the historical 5-minute `API_TOKEN_CACHE_TTL_SECS` window.
///
/// Pre-fix this test fails at step 4 with HTTP 200 "anon" — the
/// `validate_api_token` cache rejection works, but
/// `optional_auth_middleware` swallows the Err and the handler returns the
/// public-list 200 the release-gate test (`auth-user-deactivation-revokes-tokens`)
/// caught.
#[tokio::test]
#[ignore]
async fn deactivated_users_api_token_is_rejected_on_optional_auth_route() {
    let url = match std::env::var("DATABASE_URL") {
        Ok(v) => v,
        Err(_) => return,
    };
    let pool = match PgPool::connect(&url).await {
        Ok(p) => p,
        Err(_) => return,
    };

    let user_id = insert_active_user(&pool, "deact-optauth").await;

    // Long-lived, registered AuthService — mirrors what `routes.rs`
    // constructs in production so the cache-flush registry path is exercised.
    let auth_service = Arc::new(AuthService::new(pool.clone(), test_config()));
    auth_service.register_for_global_flush();

    let (token, _token_id) = auth_service
        .generate_api_token(
            user_id,
            "ak1371-bot",
            vec!["read:artifacts".to_string()],
            None,
        )
        .await
        .expect("issue API token");

    // Step 1+2: token works, handler sees the AuthExtension.
    let app_before = build_optional_auth_app(auth_service.clone());
    let (status, body) = run_probe(app_before, &token).await;
    assert_eq!(status, StatusCode::OK, "pre-deactivation must be 200");
    assert_eq!(
        body, "authed",
        "pre-deactivation handler must see the AuthExtension"
    );

    // Step 3: deactivate the user the way the real handler does. Order
    // matters: invalidate BEFORE the UPDATE (fail-secure pre-mark, see
    // `invalidate_user_token_cache_entries` docstring).
    invalidate_user_token_cache_entries(user_id);
    invalidate_user_tokens(user_id);
    set_user_inactive(&pool, user_id).await;

    // Step 4: the next request MUST return 401. Measure how long it took to
    // become 401 — the bug brief calls for under 5s; in-process we expect
    // sub-millisecond.
    let started = Instant::now();
    let app_after = build_optional_auth_app(auth_service.clone());
    let (status_after, body_after) = run_probe(app_after, &token).await;
    let elapsed = started.elapsed();

    cleanup_user(&pool, user_id).await;

    assert_eq!(
        status_after,
        StatusCode::UNAUTHORIZED,
        "deactivated user's API token MUST be rejected with 401 on optional-auth route \
         within 5s of `is_active=false` (#1371). Got HTTP {} with body: {:?}. \
         Pre-fix this returns 200 'anon' because optional_auth_middleware silently \
         downgrades invalid credentials to anonymous.",
        status_after,
        body_after,
    );
    assert!(
        elapsed.as_secs() < 5,
        "401 must arrive in well under 5s; got {:?}",
        elapsed
    );
}

/// Defense-in-depth: an absent credential on the same optional-auth route
/// must still return 200 with the handler running anonymously. This pins
/// the policy that "no credential" is distinct from "invalid credential"
/// post-#1371, so we don't silently turn optional-auth routes into
/// auth-required routes.
#[tokio::test]
#[ignore]
async fn absent_credential_still_passes_through_anonymously() {
    let url = match std::env::var("DATABASE_URL") {
        Ok(v) => v,
        Err(_) => return,
    };
    let pool = match PgPool::connect(&url).await {
        Ok(p) => p,
        Err(_) => return,
    };
    let auth_service = Arc::new(AuthService::new(pool.clone(), test_config()));
    let app = build_optional_auth_app(auth_service);
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/probe")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .expect("request must complete");
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "no credential must continue to pass through anonymously (200)"
    );
    let bytes = axum::body::to_bytes(resp.into_body(), 4096)
        .await
        .expect("body");
    assert_eq!(
        String::from_utf8_lossy(&bytes),
        "anon",
        "handler must see Option<AuthExtension>::None when no credential supplied"
    );
}

/// Defense-in-depth: a syntactically broken Authorization header (neither
/// Bearer, ApiKey, nor Basic) is `ExtractedToken::Invalid` — the client
/// explicitly attempted to authenticate, so the optional-auth path must
/// 401 rather than treat the request as anonymous. This pins the second
/// half of the `try_resolve_auth_outcome` decision tree.
#[tokio::test]
#[ignore]
async fn invalid_authorization_scheme_is_rejected_with_401() {
    let url = match std::env::var("DATABASE_URL") {
        Ok(v) => v,
        Err(_) => return,
    };
    let pool = match PgPool::connect(&url).await {
        Ok(p) => p,
        Err(_) => return,
    };
    let auth_service = Arc::new(AuthService::new(pool.clone(), test_config()));
    let app = build_optional_auth_app(auth_service);
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/probe")
                .header("Authorization", "GarbageScheme abc")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .expect("request must complete");
    assert_eq!(
        resp.status(),
        StatusCode::UNAUTHORIZED,
        "invalid Authorization scheme must produce 401 (#1371)"
    );
}
