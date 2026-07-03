//! Regression test for the route-middleware composition that lets a
//! non-admin call `POST /api/v1/users/:id/password` to change their own
//! password.
//!
//! Bug surfaced by release-gate `tests/auth/test-jwt-after-password-change.sh`:
//!
//!   FAIL: OLD_JWT should be rejected after password change, got HTTP 200
//!         (regression of PR #931)
//!   FAIL: login with new password failed
//!   FAIL: password change returned 403
//!
//! Root cause: every password-mutating route in `users::password_router`
//! (the original combined `self-service + reset + force-change` router)
//! was merged INTO `users::router` and then the merged whole was wrapped
//! in `admin_middleware`. So a non-admin calling `POST /:id/password`
//! tripped "Admin access required" (403) before reaching the
//! `change_password` handler — and the cascade failed every downstream
//! assertion (the OLD JWT was never invalidated because the password
//! change never happened, and the "login with new password" step had
//! nothing to log in against).
//!
//! This is the same shape as PR #1010 (which originally split
//! `password_router` out of `router` and mounted it under
//! `auth_middleware`). #1010 landed on `release/1.1.x` but never got
//! forward-ported to `main`; the merge that brought the
//! password-mutation rate limit (#1026) to main reintroduced the bug.
//!
//! Fix: split the combined `password_router` into
//! [`self_password_router`] — just `/:id/password`, mounted under
//! `auth_middleware` — and [`admin_password_router`] (carrying
//! `/:id/password/reset` and `/:id/force-password-change`, kept under
//! `admin_middleware`). The `change_password` handler retains its
//! ownership check (`auth.user_id == id` OR `auth.is_admin`) and the
//! required-current-password verification, so the split does NOT
//! widen who can mutate someone else's password — only who can reach
//! the handler for their own user ID.
//!
//! End-to-end coverage (OLD-JWT rejection after a successful self-service
//! password change) lives in `tests/auth/test-jwt-after-password-change.sh`,
//! which exercises a real running server. This Rust-side test pins the
//! routing/middleware composition that makes the bash test reach the
//! handler in the first place.

#![allow(clippy::disallowed_methods)] // streaming-invariant: test file exempt — buffering response bodies in test assertions is not an artifact path (#1608)
use std::sync::Arc;

use axum::body::{to_bytes, Body};
use axum::http::{Request, StatusCode};
use axum::{middleware, Router};
use sqlx::PgPool;
use tower::ServiceExt;
use uuid::Uuid;

use artifact_keeper_backend::api::handlers::users::{
    admin_password_router, router as users_admin_router, self_password_router,
};
use artifact_keeper_backend::api::middleware::auth::{admin_middleware, auth_middleware};
use artifact_keeper_backend::api::{AppState, SharedState};
use artifact_keeper_backend::config::Config;
use artifact_keeper_backend::services::auth_service::AuthService;
use artifact_keeper_backend::storage::filesystem::FilesystemStorage;
use artifact_keeper_backend::storage::{StorageBackend, StorageRegistry};

const JWT_SECRET: &str = "users-self-password-routing-test-secret-not-for-prod";

fn make_test_config() -> Config {
    if std::env::var("JWT_SECRET").is_err() {
        std::env::set_var("JWT_SECRET", JWT_SECRET);
    }
    Config::from_env().expect("Config::from_env")
}

fn build_state(pool: PgPool, cfg: Config) -> SharedState {
    let storage: Arc<dyn StorageBackend> = Arc::new(FilesystemStorage::new(&cfg.storage_path));
    let registry = Arc::new(StorageRegistry::new(
        std::collections::HashMap::new(),
        "filesystem".to_string(),
    ));
    Arc::new(AppState::new(cfg, pool, storage, registry))
}

/// Build the `/users` mount the way `routes.rs::api_v1_routes` does
/// post-fix: `self_password_router` under `auth_middleware`, and the
/// admin router (`router().merge(admin_password_router())`) under
/// `admin_middleware`. The production handlers run end-to-end because
/// we mount a real DB pool and create real user rows. We do NOT use
/// stubs here — the load-bearing detail under test is the middleware
/// composition, and stubs would let a future re-merge slip past
/// unnoticed.
fn build_users_app(state: SharedState, auth_service: Arc<AuthService>) -> Router {
    let self_users: Router<SharedState> = Router::new()
        .nest("/users", self_password_router())
        .layer(middleware::from_fn_with_state(
            auth_service.clone(),
            auth_middleware,
        ));

    let admin_users: Router<SharedState> = Router::new()
        .nest(
            "/users",
            users_admin_router().merge(admin_password_router()),
        )
        .layer(middleware::from_fn_with_state(
            auth_service,
            admin_middleware,
        ));

    self_users.merge(admin_users).with_state(state)
}

/// Mint an access JWT for a synthetic user via the real
/// `AuthService::generate_tokens`, so the bearer header the production
/// `auth_middleware` decodes matches exactly what a normal login would
/// produce.
fn mint_user_jwt(auth_service: &AuthService, user_id: Uuid, is_admin: bool) -> String {
    use artifact_keeper_backend::models::user::{AuthProvider, User};
    let user = User {
        id: user_id,
        username: format!("u-{}", &user_id.to_string()[..8]),
        email: format!("u-{}@test.local", &user_id.to_string()[..8]),
        password_hash: None,
        auth_provider: AuthProvider::Local,
        external_id: None,
        display_name: None,
        is_active: true,
        is_admin,
        is_service_account: false,
        must_change_password: false,
        totp_secret: None,
        totp_enabled: false,
        totp_backup_codes: None,
        totp_verified_at: None,
        failed_login_attempts: 0,
        locked_until: None,
        last_failed_login_at: None,
        // Backdate the watermark so `is_token_invalidated_replica_safe`
        // accepts the freshly-minted JWT. (Bug 1's boundary is fixed in a
        // separate commit; we sidestep it here because this test is about
        // the RBAC / routing layer above it.)
        password_changed_at: chrono::Utc::now() - chrono::Duration::seconds(60),
        last_login_at: None,
        created_at: chrono::Utc::now() - chrono::Duration::seconds(60),
        updated_at: chrono::Utc::now() - chrono::Duration::seconds(60),
    };
    auth_service
        .generate_tokens(&user)
        .expect("generate_tokens")
        .access_token
}

async fn insert_user(pool: &PgPool, username_prefix: &str) -> Uuid {
    let id = Uuid::new_v4();
    let username = format!("{}-{}", username_prefix, &id.to_string()[..8]);
    let pw_hash = AuthService::hash_password("OldPass_AAA123!")
        .await
        .expect("hash");
    sqlx::query(
        r#"
        INSERT INTO users (id, username, email, password_hash, auth_provider,
                           is_admin, is_active, failed_login_attempts,
                           password_changed_at)
        VALUES ($1, $2, $3, $4, 'local', false, true, 0,
                NOW() - INTERVAL '60 seconds')
        "#,
    )
    .bind(id)
    .bind(&username)
    .bind(format!("{}@test.local", username))
    .bind(&pw_hash)
    .execute(pool)
    .await
    .expect("insert user");
    id
}

async fn cleanup(pool: &PgPool, user_id: Uuid) {
    let _ = sqlx::query("DELETE FROM users WHERE id = $1")
        .bind(user_id)
        .execute(pool)
        .await;
}

async fn body_text(resp: axum::http::Response<Body>) -> (StatusCode, String) {
    let status = resp.status();
    let bytes = to_bytes(resp.into_body(), 16 * 1024).await.expect("body");
    (status, String::from_utf8_lossy(&bytes).into_owned())
}

/// PRIMARY regression: a non-admin must be able to call
/// `POST /api/v1/users/<their-own-id>/password`. Pre-fix the entire
/// `/users` nest was wrapped in `admin_middleware`, so the request
/// 403'd with "Admin access required" before the handler ran.
#[tokio::test]
#[ignore]
async fn non_admin_can_change_own_password_routes_through_auth_middleware() {
    let url = match std::env::var("DATABASE_URL") {
        Ok(v) => v,
        Err(_) => return,
    };
    let pool = match PgPool::connect(&url).await {
        Ok(p) => p,
        Err(_) => return,
    };

    let user_id = insert_user(&pool, "self-pw").await;

    let cfg = make_test_config();
    let auth_service = Arc::new(AuthService::new(pool.clone(), Arc::new(cfg.clone())));
    let state = build_state(pool.clone(), cfg);

    let token = mint_user_jwt(&auth_service, user_id, /*is_admin=*/ false);

    let app = build_users_app(state, auth_service);

    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/users/{}/password", user_id))
                .header("Authorization", format!("Bearer {}", token))
                .header("Content-Type", "application/json")
                .body(Body::from(
                    r#"{"current_password":"OldPass_AAA123!","new_password":"NewPass_BBB456!"}"#,
                ))
                .unwrap(),
        )
        .await
        .expect("oneshot");

    let (status, body) = body_text(resp).await;

    cleanup(&pool, user_id).await;

    // Post-fix: the request reaches `change_password`. The handler may
    // succeed (200) or reject the request with a non-403 code (e.g. 422
    // for password-policy failure, 400 for missing field, 401 for bad
    // current password). The regression we are guarding against is
    // specifically 403 from `admin_middleware` — that proves the route
    // is still merged into the admin nest.
    assert_ne!(
        status,
        StatusCode::FORBIDDEN,
        "non-admin must reach `change_password` for their own user. \
         A 403 here means the `/:id/password` route is still gated by \
         `admin_middleware` (release-gate \
         `tests/auth/test-jwt-after-password-change.sh` regression). \
         Body: {body}",
    );
}

/// SECURITY CONTROL: a non-admin must NOT be able to change another
/// user's password through the self-service router. The handler's
/// ownership check (`auth.user_id == id`) catches this and returns 403
/// (or 401 for current-password mismatch); either way it must NOT
/// silently succeed. This pins the `change_password` ownership check so
/// the route-split fix does not accidentally widen who can mutate
/// someone else's password.
#[tokio::test]
#[ignore]
async fn non_admin_cannot_change_other_users_password() {
    let url = match std::env::var("DATABASE_URL") {
        Ok(v) => v,
        Err(_) => return,
    };
    let pool = match PgPool::connect(&url).await {
        Ok(p) => p,
        Err(_) => return,
    };

    let caller_id = insert_user(&pool, "caller").await;
    let target_id = insert_user(&pool, "target").await;

    let cfg = make_test_config();
    let auth_service = Arc::new(AuthService::new(pool.clone(), Arc::new(cfg.clone())));
    let state = build_state(pool.clone(), cfg);

    let token = mint_user_jwt(&auth_service, caller_id, /*is_admin=*/ false);

    let app = build_users_app(state, auth_service);

    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/users/{}/password", target_id))
                .header("Authorization", format!("Bearer {}", token))
                .header("Content-Type", "application/json")
                .body(Body::from(
                    r#"{"current_password":"OldPass_AAA123!","new_password":"NewPass_BBB456!"}"#,
                ))
                .unwrap(),
        )
        .await
        .expect("oneshot");

    let (status, body) = body_text(resp).await;

    cleanup(&pool, caller_id).await;
    cleanup(&pool, target_id).await;

    // The handler's ownership check (`auth.user_id == id`) must fire and
    // return 403 ("Cannot change other users' passwords"). It is also
    // acceptable for the handler to return 401 if it fails the bcrypt
    // check first (defense-in-depth); what is NOT acceptable is a 200.
    assert!(
        status == StatusCode::FORBIDDEN || status == StatusCode::UNAUTHORIZED,
        "non-admin must NOT be able to change a different user's password. \
         Expected 403 (ownership check) or 401 (current-password mismatch). \
         Got: {status}. Body: {body}",
    );
}

/// Admin-only routes must reject non-admin callers with 403. Pins that
/// `admin_password_router` stayed behind `admin_middleware` after the
/// split — if it were accidentally moved alongside the self-service
/// router, a non-admin could reset arbitrary passwords without proving
/// knowledge of the current one.
#[tokio::test]
#[ignore]
async fn non_admin_cannot_reach_password_reset_endpoint() {
    let url = match std::env::var("DATABASE_URL") {
        Ok(v) => v,
        Err(_) => return,
    };
    let pool = match PgPool::connect(&url).await {
        Ok(p) => p,
        Err(_) => return,
    };

    let user_id = insert_user(&pool, "reset-test").await;

    let cfg = make_test_config();
    let auth_service = Arc::new(AuthService::new(pool.clone(), Arc::new(cfg.clone())));
    let state = build_state(pool.clone(), cfg);

    let token = mint_user_jwt(&auth_service, user_id, /*is_admin=*/ false);
    let app = build_users_app(state, auth_service);

    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/users/{}/password/reset", user_id))
                .header("Authorization", format!("Bearer {}", token))
                .header("Content-Type", "application/json")
                .body(Body::from("{}"))
                .unwrap(),
        )
        .await
        .expect("oneshot");

    let (status, _body) = body_text(resp).await;
    cleanup(&pool, user_id).await;

    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "non-admin must NOT be able to reach `/:id/password/reset` — \
         that route MUST stay behind `admin_middleware`. Got: {status}",
    );
}
