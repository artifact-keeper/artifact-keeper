//! Regression tests for issue #2492: in a multi-replica deployment, the
//! first-time-setup password change unlocked ONLY the replica that served
//! the request. Every other replica kept its process-local
//! `setup_required` flag set until it was restarted, so it kept answering
//! `403 SETUP_REQUIRED` to (almost) every API call and kept reporting
//! `setup_required: true` from `/api/v1/setup/status` — which the web UI
//! surfaces as a login failure right after the admin set their new
//! password.
//!
//! The fix makes the DB row (`users.must_change_password` on the admin
//! account) the authority: while a replica's local flag still says setup
//! is pending, the setup guard and the status endpoint re-check the DB and
//! latch the flag to `false` once the DB confirms completion. On DB errors
//! the lock is kept (fail closed).
//!
//! These tests require PostgreSQL with all migrations applied:
//!
//! ```sh
//! DATABASE_URL="postgresql://registry:registry@localhost:5432/artifact_registry" \
//!     cargo test --test setup_replica_unlock_tests -- --ignored
//! ```

#![allow(clippy::disallowed_methods)] // test file: buffering small response bodies is fine

mod common;

use std::sync::atomic::Ordering;
use std::sync::Arc;

use axum::body::{to_bytes, Body};
use axum::http::{Request, StatusCode};
use axum::routing::get;
use axum::{middleware, Router};
use sqlx::PgPool;
use tower::ServiceExt;
use uuid::Uuid;

use artifact_keeper_backend::api::handlers::auth::setup_router;
use artifact_keeper_backend::api::handlers::users::self_password_router;
use artifact_keeper_backend::api::middleware::auth::auth_middleware;
use artifact_keeper_backend::api::middleware::setup::setup_guard;
use artifact_keeper_backend::api::{AppState, SharedState};
use artifact_keeper_backend::config::Config;
use artifact_keeper_backend::services::auth_service::AuthService;
use artifact_keeper_backend::storage::filesystem::FilesystemStorage;
use artifact_keeper_backend::storage::{StorageBackend, StorageRegistry};

use common::{require_db_pool, test_config_with_default_jwt};

const USER_PREFIX: &str = "setup-unlock";
const INIT_PASSWORD: &str = "InitBootstrapPass_2492!a";
const NEW_PASSWORD: &str = "FreshAdminPass_2492!b";

fn make_test_config() -> Config {
    let mut cfg = (*test_config_with_default_jwt()).clone();
    // Point storage at a scratch dir so the change-password handler's
    // best-effort `admin.password` file delete cannot touch real state.
    let scratch = std::env::temp_dir().join(format!("ak-setup-unlock-{}", Uuid::new_v4()));
    let _ = std::fs::create_dir_all(&scratch);
    cfg.storage_path = scratch.to_string_lossy().into_owned();
    cfg
}

fn build_state(pool: PgPool, cfg: Config) -> SharedState {
    let storage: Arc<dyn StorageBackend> = Arc::new(FilesystemStorage::new(&cfg.storage_path));
    let registry = Arc::new(StorageRegistry::new(
        std::collections::HashMap::new(),
        "filesystem".to_string(),
    ));
    Arc::new(AppState::new(cfg, pool, storage, registry))
}

/// Build a minimal app for a "replica": one representative protected route
/// plus the real `/api/v1/setup/status` route, with the production
/// `setup_guard` layered over the whole router exactly like
/// `routes.rs::create_router` does.
fn build_replica_app(state: SharedState) -> Router {
    Router::new()
        .route("/api/v1/repositories", get(|| async { StatusCode::OK }))
        .nest("/api/v1/setup", setup_router())
        .layer(middleware::from_fn_with_state(state.clone(), setup_guard))
        .with_state(state)
}

/// Mint an access JWT for the bootstrap admin the way a real login with the
/// initialization password would.
fn mint_admin_jwt(auth_service: &AuthService, user_id: Uuid, username: &str) -> String {
    use artifact_keeper_backend::models::user::{AuthProvider, User};
    let user = User {
        id: user_id,
        username: username.to_string(),
        email: format!("{}@test.local", username),
        password_hash: None,
        auth_provider: AuthProvider::Local,
        external_id: None,
        display_name: None,
        is_active: true,
        is_admin: true,
        is_service_account: false,
        must_change_password: true,
        totp_secret: None,
        totp_enabled: false,
        totp_backup_codes: None,
        totp_verified_at: None,
        failed_login_attempts: 0,
        locked_until: None,
        last_failed_login_at: None,
        // Backdate so the replica-safe token-invalidation check accepts the
        // freshly-minted JWT (same pattern as users_password_routing_tests).
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

/// Insert a bootstrap-style admin: `is_admin = true`,
/// `must_change_password = true`, known "initialization" password.
async fn insert_bootstrap_admin(pool: &PgPool) -> (Uuid, String) {
    let id = Uuid::new_v4();
    let username = format!("{}-{}", USER_PREFIX, &id.to_string()[..8]);
    let pw_hash = AuthService::hash_password(INIT_PASSWORD)
        .await
        .expect("hash");
    sqlx::query(
        r#"
        INSERT INTO users (id, username, email, password_hash, auth_provider,
                           is_admin, is_active, must_change_password,
                           failed_login_attempts, password_changed_at)
        VALUES ($1, $2, $3, $4, 'local', true, true, true, 0,
                NOW() - INTERVAL '60 seconds')
        "#,
    )
    .bind(id)
    .bind(&username)
    .bind(format!("{}@test.local", username))
    .bind(&pw_hash)
    .execute(pool)
    .await
    .expect("insert bootstrap admin");
    (id, username)
}

/// Remove leftovers from previous (possibly crashed) runs, and neutralize
/// any pre-existing `is_admin AND must_change_password` rows so the
/// DB-authority re-check under test sees exactly the state this test
/// controls. The DB-gated suites run against a throwaway database
/// (`require_db_pool` contract), single-threaded in CI.
async fn reset_setup_state(pool: &PgPool) {
    let _ = sqlx::query("DELETE FROM users WHERE username LIKE $1")
        .bind(format!("{}-%", USER_PREFIX))
        .execute(pool)
        .await;
    let _ = sqlx::query(
        "UPDATE users SET must_change_password = false \
         WHERE is_admin = true AND must_change_password = true",
    )
    .execute(pool)
    .await;
}

async fn cleanup(pool: &PgPool, user_id: Uuid) {
    let _ = sqlx::query("DELETE FROM users WHERE id = $1")
        .bind(user_id)
        .execute(pool)
        .await;
}

async fn status_and_body(resp: axum::http::Response<Body>) -> (StatusCode, String) {
    let status = resp.status();
    let bytes = to_bytes(resp.into_body(), 64 * 1024).await.expect("body");
    (status, String::from_utf8_lossy(&bytes).into_owned())
}

async fn get_path(app: &Router, path: &str) -> (StatusCode, String) {
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(path)
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("oneshot");
    status_and_body(resp).await
}

/// PRIMARY regression (#2492): complete first-time setup through the real
/// change-password handler on replica A, then — in the same process,
/// without any "restart" of replica B — assert that replica B immediately
/// (1) accepts a login with the NEW password, (2) stops blocking API
/// requests with 403 SETUP_REQUIRED, and (3) reports
/// `setup_required: false` from `/api/v1/setup/status`.
///
/// Pre-fix, steps (2) and (3) fail: replica B's process-local flag is
/// never cleared, so it keeps blocking and keeps reporting setup mode
/// until the process is restarted.
#[tokio::test]
#[ignore] // requires PostgreSQL (DATABASE_URL)
async fn peer_replica_unlocks_without_restart_after_setup_completes() {
    let pool = require_db_pool().await;
    reset_setup_state(&pool).await;
    let (admin_id, admin_username) = insert_bootstrap_admin(&pool).await;

    // Two "replicas": independent AppStates sharing the same database,
    // both booted while the admin password change was still pending.
    let state_a = build_state(pool.clone(), make_test_config());
    let state_b = build_state(pool.clone(), make_test_config());
    state_a.setup_required.store(true, Ordering::Relaxed);
    state_b.setup_required.store(true, Ordering::Relaxed);

    let app_b = build_replica_app(state_b.clone());

    // While setup is genuinely pending, replica B must keep blocking
    // (the DB re-check must NOT unlock early) and report setup mode.
    let (status, body) = get_path(&app_b, "/api/v1/repositories").await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "guard must block while the DB still says setup is pending; body: {body}"
    );
    assert!(body.contains("SETUP_REQUIRED"), "unexpected body: {body}");
    let (status, body) = get_path(&app_b, "/api/v1/setup/status").await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        body.contains("\"setup_required\":true"),
        "status must report setup pending while the DB agrees; body: {body}"
    );

    // Replica A serves the real first-time password change (the handler
    // that clears must_change_password and A's own in-process flag).
    let auth_service = Arc::new(AuthService::new(
        pool.clone(),
        Arc::new(state_a.config.clone()),
    ));
    let app_a: Router = Router::new()
        .nest("/api/v1/users", self_password_router())
        .layer(middleware::from_fn_with_state(
            auth_service.clone(),
            auth_middleware,
        ))
        .with_state(state_a.clone());
    let jwt = mint_admin_jwt(&auth_service, admin_id, &admin_username);
    let resp = app_a
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/api/v1/users/{}/password", admin_id))
                .header("Authorization", format!("Bearer {jwt}"))
                .header("Content-Type", "application/json")
                .body(Body::from(format!(
                    r#"{{"current_password":"{INIT_PASSWORD}","new_password":"{NEW_PASSWORD}"}}"#
                )))
                .expect("request"),
        )
        .await
        .expect("oneshot");
    let (status, body) = status_and_body(resp).await;
    assert_eq!(status, StatusCode::OK, "password change failed: {body}");
    assert!(
        !state_a.setup_required.load(Ordering::Relaxed),
        "replica A must clear its own flag (pre-existing behaviour)"
    );

    // (1) The issue's literal symptom: logging in with the NEW password
    // immediately, in the same process, must succeed (no pod restart).
    let login = AuthService::new(pool.clone(), Arc::new(state_b.config.clone()))
        .authenticate(&admin_username, NEW_PASSWORD)
        .await;
    assert!(
        login.is_ok(),
        "login with the freshly-set password must succeed immediately: {:?}",
        login.err()
    );

    // (2) Replica B — which did NOT serve the password change and was NOT
    // restarted — must stop blocking API requests.
    let (status, body) = get_path(&app_b, "/api/v1/repositories").await;
    assert_eq!(
        status,
        StatusCode::OK,
        "replica B must unlock without a restart once the DB says setup \
         completed (#2492); body: {body}"
    );

    // (3) ...and must stop reporting setup mode to the web UI.
    let (status, body) = get_path(&app_b, "/api/v1/setup/status").await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        body.contains("\"setup_required\":false"),
        "setup status must reflect DB truth on peer replicas; body: {body}"
    );

    // The flag latches: no further DB re-checks once confirmed.
    assert!(!state_b.setup_required.load(Ordering::Relaxed));

    cleanup(&pool, admin_id).await;
}

/// Fail-closed contract: if the DB re-check cannot run (connection lost),
/// a replica that believes setup is pending must KEEP blocking rather
/// than fall open.
#[tokio::test]
#[ignore] // requires PostgreSQL (DATABASE_URL)
async fn guard_keeps_lock_when_db_recheck_fails() {
    // Dedicated pool so closing it cannot disturb other tests.
    let dedicated = require_db_pool().await;
    let state = build_state(dedicated.clone(), make_test_config());
    state.setup_required.store(true, Ordering::Relaxed);
    let app = build_replica_app(state.clone());

    dedicated.close().await;

    let (status, body) = get_path(&app, "/api/v1/repositories").await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "guard must fail closed when the setup re-check cannot reach the DB; body: {body}"
    );
    assert!(body.contains("SETUP_REQUIRED"), "unexpected body: {body}");
    assert!(
        state.setup_required.load(Ordering::Relaxed),
        "flag must not be cleared on DB errors"
    );
}
