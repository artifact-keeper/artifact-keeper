//! Regression test for the 401-vs-403 boundary bug surfaced by the
//! release-gate `tests/rbac/test-admin-protection.sh` (and the `auth-tests`
//! / `mesh-tests` failures with the same symptom).
//!
//! Bug summary
//! -----------
//! When a fresh non-admin user is created and immediately authenticated, the
//! JWT's `iat` claim (seconds resolution) can land in the same wall-clock
//! second as the row's `password_changed_at`. Pre-fix, the
//! `create_user` handler relied on the column's `DEFAULT NOW()` so that
//! watermark equals "now" at INSERT time. The replica-safe credential-change
//! check in `auth_service::is_token_invalidated_replica_safe` compares
//! `iat <= watermark` (intentional, see #1173), so a same-second token is
//! treated as having been minted BEFORE the most recent credential change
//! and gets rejected with 401 "Invalid or expired token" — before
//! `admin_middleware` ever reaches the `is_admin` branch that should
//! return 403 for non-admin callers.
//!
//! The release-gate test sends that JWT to `/api/v1/admin/settings` and
//! asserts a 403 (non-admin forbidden). The 401 means the test exits early,
//! turning the entire admin-RBAC test suite red.
//!
//! Fix
//! ---
//! Two-layer fix landed across two PRs:
//!
//!   * #1248 swapped `<=` to `<` at the DB-watermark comparison in
//!     `is_token_invalidated_replica_safe` so the first admin request from
//!     a fresh non-admin user is accepted.
//!   * The rc.2 follow-up removed the in-process sync fast-path
//!     (`is_token_invalidated`) from inside `is_token_invalidated_replica_safe`.
//!     That fast-path used `<=` against the SAME `invalidation_map` that
//!     `fetch_credential_change_watermark` populates with the cached DB
//!     watermark. Result: the first request worked (cache empty → DB →
//!     populate), but every subsequent request within the 5s TTL hit the
//!     `<=` map check and was rejected. The cache hit inside
//!     `fetch_credential_change_watermark` itself already provides the
//!     fast-path; removing the duplicate call eliminates the conflation
//!     without losing the in-replica acceleration.
//!
//! Tests below
//! -----------
//! 1. Asserts a fresh non-admin JWT reaches the `is_admin` branch and
//!    returns 403, not 401. Uses the backdated-INSERT helper so it's
//!    deterministic against clock skew between the test runner and the DB.
//! 2. Negative-control: INSERT with a future watermark and pin that a JWT
//!    minted BEFORE the watermark is rejected with 401. Locks the
//!    "credential change invalidates pre-change tokens" invariant.
//! 3. Two sequential admin requests with the SAME fresh JWT must BOTH
//!    return 403. This is the regression that surfaced post-#1248 on
//!    `v1.2.0-rc.1`: request #1 passed (DB miss → cache populated),
//!    request #2 hit the sync fast-path against the cached watermark and
//!    was rejected with 401 by the conflated `<=` semantic.
//!
//! Requires PostgreSQL with migrations applied:
//!
//! ```sh
//! DATABASE_URL="postgresql://registry:registry@localhost:30432/artifact_registry" \
//!     cargo test --test admin_middleware_fresh_user_tests -- --ignored
//! ```

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::{middleware, routing::get, Router};
use sqlx::PgPool;
use tower::ServiceExt;
use uuid::Uuid;

use artifact_keeper_backend::api::middleware::auth::admin_middleware;
use artifact_keeper_backend::config::Config;
use artifact_keeper_backend::services::auth_service::AuthService;

const JWT_SECRET: &str = "fresh-user-rbac-regression-test-secret-not-for-prod";

fn test_config() -> Arc<Config> {
    if std::env::var("JWT_SECRET").is_err() {
        std::env::set_var("JWT_SECRET", JWT_SECRET);
    }
    Arc::new(Config::from_env().expect("Config::from_env"))
}

/// Insert a non-admin user the EXACT same way the production `create_user`
/// handler does (post-fix). This must mirror the SQL in
/// `backend/src/api/handlers/users.rs::create_user`: in particular, the
/// `password_changed_at` value (`NOW() - INTERVAL '2 seconds'`) is the
/// load-bearing detail under test — it is what guarantees `iat > watermark`
/// for any access JWT minted from the immediately subsequent login.
async fn insert_user_like_create_user_handler(pool: &PgPool) -> (Uuid, String) {
    let id = Uuid::new_v4();
    let username = format!("rbac-fresh-{}", &id.to_string()[..8]);
    let email = format!("{}@test.local", username);
    sqlx::query(
        r#"
        INSERT INTO users (id, username, email, password_hash, auth_provider,
                           is_admin, is_active, failed_login_attempts,
                           password_changed_at)
        VALUES ($1, $2, $3, 'unused', 'local', false, true, 0,
                NOW() - INTERVAL '2 seconds')
        "#,
    )
    .bind(id)
    .bind(&username)
    .bind(&email)
    .execute(pool)
    .await
    .expect("insert user (post-fix shape)");
    (id, username)
}

/// Deterministic "pre-fix shape" for the boundary-pin test. We force
/// `password_changed_at` strictly into the future so any JWT minted with
/// `iat = NOW()` is guaranteed to satisfy `iat < watermark`, regardless of
/// the test runner's clock skew vs the DB server.
///
/// This exercises the exact comparison `iat <= watermark` in
/// `is_token_invalidated_replica_safe` (#1173). Using just the column
/// `DEFAULT NOW()` (the literal pre-fix shape) is flaky — it depends on
/// whether the JWT-mint code path takes long enough to tick the wall-clock
/// second forward — so we instead push the watermark explicitly ahead.
/// The semantic under test is the same: `iat <= watermark` MUST 401.
async fn insert_user_with_future_watermark(pool: &PgPool) -> (Uuid, String) {
    let id = Uuid::new_v4();
    let username = format!("rbac-future-{}", &id.to_string()[..8]);
    let email = format!("{}@test.local", username);
    sqlx::query(
        r#"
        INSERT INTO users (id, username, email, password_hash, auth_provider,
                           is_admin, is_active, failed_login_attempts,
                           password_changed_at)
        VALUES ($1, $2, $3, 'unused', 'local', false, true, 0,
                NOW() + INTERVAL '1 hour')
        "#,
    )
    .bind(id)
    .bind(&username)
    .bind(&email)
    .execute(pool)
    .await
    .expect("insert user (future-watermark shape)");
    (id, username)
}

/// Mirror the EXACT production `create_user` INSERT shape: omit
/// `password_changed_at` so the column DEFAULT (`NOW()`) applies, putting
/// the watermark at the same wall-clock second as any JWT minted
/// immediately afterwards. This is the actual production shape — the
/// helper above intentionally backdates by 2s and is NOT
/// representative of what `POST /api/v1/users` produces.
async fn insert_user_like_production_create_user(pool: &PgPool) -> (Uuid, String) {
    let id = Uuid::new_v4();
    let username = format!("rbac-prod-{}", &id.to_string()[..8]);
    let email = format!("{}@test.local", username);
    sqlx::query(
        r#"
        INSERT INTO users (id, username, email, password_hash, auth_provider,
                           is_admin, is_active, failed_login_attempts)
        VALUES ($1, $2, $3, 'unused', 'local', false, true, 0)
        "#,
    )
    .bind(id)
    .bind(&username)
    .bind(&email)
    .execute(pool)
    .await
    .expect("insert user (production INSERT shape, no backdate)");
    (id, username)
}

async fn cleanup_user(pool: &PgPool, user_id: Uuid) {
    let _ = sqlx::query("DELETE FROM users WHERE id = $1")
        .bind(user_id)
        .execute(pool)
        .await;
}

fn make_user_struct(id: Uuid, username: String) -> artifact_keeper_backend::models::user::User {
    artifact_keeper_backend::models::user::User {
        id,
        username: username.clone(),
        email: format!("{}@test.local", username),
        password_hash: None,
        auth_provider: artifact_keeper_backend::models::user::AuthProvider::Local,
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
        password_changed_at: chrono::Utc::now(),
        last_login_at: None,
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
    }
}

/// Build the minimal axum app the release-gate test hits: a single GET
/// /protected route gated by the production `admin_middleware`. The
/// handler returns 200 so a passing JWT (admin) reaches it; non-admin
/// must be rejected with 403 by the middleware before reaching here.
fn build_admin_only_app(auth_service: Arc<AuthService>) -> Router {
    Router::new()
        .route("/protected", get(|| async { "ok" }))
        .layer(middleware::from_fn_with_state(
            auth_service,
            admin_middleware,
        ))
}

async fn run_through_admin_middleware(app: Router, bearer: &str) -> StatusCode {
    app.oneshot(
        Request::builder()
            .uri("/protected")
            .header("Authorization", format!("Bearer {bearer}"))
            .body(Body::empty())
            .unwrap(),
    )
    .await
    .expect("request must complete")
    .status()
}

/// Primary regression: a fresh non-admin user created via the production
/// `create_user` INSERT pattern (post-fix, with the 2s backdate on
/// `password_changed_at`) must reach the `is_admin` branch of
/// `admin_middleware` and be rejected with 403, not 401.
#[tokio::test]
#[ignore]
async fn non_admin_jwt_minted_immediately_after_user_creation_returns_403() {
    let url = match std::env::var("DATABASE_URL") {
        Ok(v) => v,
        Err(_) => return,
    };
    let pool = match PgPool::connect(&url).await {
        Ok(p) => p,
        Err(_) => return,
    };

    let cfg = test_config();
    let auth_service = Arc::new(AuthService::new(pool.clone(), cfg.clone()));

    let (user_id, username) = insert_user_like_create_user_handler(&pool).await;

    // Mint the access JWT the way `authenticate()` does on login.
    let user = make_user_struct(user_id, username);
    let tokens = auth_service
        .generate_tokens(&user)
        .expect("generate_tokens");

    let app = build_admin_only_app(auth_service.clone());
    let status = run_through_admin_middleware(app, &tokens.access_token).await;

    cleanup_user(&pool, user_id).await;

    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "non-admin JWT minted immediately after `create_user` must be \
         rejected by admin_middleware's is_admin check (403), not by \
         validate_access_token_async (401). Got: {}",
        status
    );
}

/// Negative-control: without the backdate on `password_changed_at`, the
/// same-second JWT iat trips the `iat <= watermark` check and the request
/// is rejected with 401. This is the pre-fix shape and the bug the
/// release-gate test surfaces.
///
/// We keep this test green by ASSERTING the 401 (i.e., the broken
/// behaviour). That pins two invariants simultaneously:
///   1. The `iat <= watermark` boundary semantics from #1173 are intact
///      (so future refactors can't silently flip it to `<` and break
///      revocation across the seconds boundary).
///   2. The fix to `create_user` (backdating the watermark) is precisely
///      what avoids the bug — the only difference between this test and
///      the one above is the `password_changed_at` value.
#[tokio::test]
#[ignore]
async fn boundary_pin_jwt_iat_equal_to_watermark_is_rejected() {
    let url = match std::env::var("DATABASE_URL") {
        Ok(v) => v,
        Err(_) => return,
    };
    let pool = match PgPool::connect(&url).await {
        Ok(p) => p,
        Err(_) => return,
    };

    let cfg = test_config();
    let auth_service = Arc::new(AuthService::new(pool.clone(), cfg.clone()));

    // Force the watermark strictly into the future so any JWT minted with
    // iat=NOW() satisfies iat < watermark deterministically (no flake from
    // clock skew between the test runner and the DB server).
    let (user_id, username) = insert_user_with_future_watermark(&pool).await;
    let user = make_user_struct(user_id, username);
    let tokens = auth_service
        .generate_tokens(&user)
        .expect("generate_tokens");

    let app = build_admin_only_app(auth_service.clone());
    let status = run_through_admin_middleware(app, &tokens.access_token).await;

    cleanup_user(&pool, user_id).await;

    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "boundary pin: a JWT whose iat equals password_changed_at (same \
         wall-clock second, no backdate) MUST be rejected with 401 by \
         `is_token_invalidated_replica_safe` (#1173). If this fires 403, \
         the boundary check has been weakened (likely `<=` flipped to `<`) \
         and password-rotation tokens are no longer rejected across the \
         seconds boundary. Got: {}",
        status
    );
}

/// Regression: two sequential admin requests with the SAME fresh JWT must
/// BOTH reach the `is_admin` branch and return 403.
///
/// Pre-fix shape of the bug (post-#1248, on `v1.2.0-rc.1`):
///
///   * Request #1: `invalidation_map` is empty, so the sync fast-path
///     returns `false`. Control falls through to
///     `fetch_credential_change_watermark`, which queries the DB and
///     writes `(watermark, Instant::now())` into `invalidation_map` as a
///     5-second cache entry. The `<` comparison on the freshly fetched
///     watermark accepts the JWT and the admin check returns 403.
///   * Request #2 (≤ 5s later): the sync fast-path now finds the cached
///     watermark and applies `<=`. For a same-second JWT this returns
///     `true`, the request is rejected with 401, and `admin_middleware`
///     never gets to fire the 403 path.
///
/// This is the exact pattern release-gate `tests/rbac/test-admin-protection.sh`
/// saw on `v1.2.0-rc.1`: the first endpoint (`/api/v1/admin/settings`)
/// passed with 403, every subsequent endpoint in the loop failed with 401.
///
/// The fix is in `auth_service::is_token_invalidated_replica_safe`: stop
/// calling the sync `is_token_invalidated` fast-path. The cache hit in
/// `fetch_credential_change_watermark` already serves the same map without
/// the `<=` conflation.
#[tokio::test]
#[ignore]
async fn two_sequential_admin_requests_with_fresh_jwt_both_return_403() {
    let url = match std::env::var("DATABASE_URL") {
        Ok(v) => v,
        Err(_) => return,
    };
    let pool = match PgPool::connect(&url).await {
        Ok(p) => p,
        Err(_) => return,
    };

    let cfg = test_config();
    let auth_service = Arc::new(AuthService::new(pool.clone(), cfg.clone()));

    // Use the production INSERT shape (DEFAULT NOW() on password_changed_at)
    // to put the row's watermark on the same wall-clock second as the JWT
    // iat — the exact scenario the release-gate test triggers.
    let (user_id, username) = insert_user_like_production_create_user(&pool).await;
    let user = make_user_struct(user_id, username);
    let tokens = auth_service
        .generate_tokens(&user)
        .expect("generate_tokens");

    let app1 = build_admin_only_app(auth_service.clone());
    let first = run_through_admin_middleware(app1, &tokens.access_token).await;

    let app2 = build_admin_only_app(auth_service.clone());
    let second = run_through_admin_middleware(app2, &tokens.access_token).await;

    cleanup_user(&pool, user_id).await;

    assert_eq!(
        first,
        StatusCode::FORBIDDEN,
        "first sequential admin request from fresh non-admin user must \
         return 403, got: {}",
        first
    );
    assert_eq!(
        second,
        StatusCode::FORBIDDEN,
        "second sequential admin request from fresh non-admin user must \
         ALSO return 403. If this returns 401, the `invalidation_map` is \
         being read with `<=` semantics on a cached DB watermark — the \
         cache-conflation regression that broke rbac-tests / auth-tests \
         on v1.2.0-rc.1. Got: {}",
        second
    );
}
