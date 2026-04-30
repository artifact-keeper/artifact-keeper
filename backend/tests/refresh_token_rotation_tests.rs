//! Integration tests for refresh-token rotation (issue #929).
//!
//! Asserts that refresh tokens are single-use: once a refresh token has
//! been redeemed for a fresh token pair, subsequent attempts to refresh
//! with the same token are rejected.
//!
//! Requires PostgreSQL:
//! ```sh
//! DATABASE_URL="postgresql://registry:registry@localhost:30432/artifact_registry" \
//!     cargo test --test refresh_token_rotation_tests -- --ignored
//! ```

use std::sync::Arc;

use artifact_keeper_backend::config::Config;
use artifact_keeper_backend::services::auth_service::AuthService;
use sqlx::PgPool;
use uuid::Uuid;

async fn connect_db() -> PgPool {
    let url = std::env::var("DATABASE_URL").unwrap_or_else(|_| {
        "postgresql://registry:registry@localhost:30432/artifact_registry".into()
    });
    PgPool::connect(&url)
        .await
        .expect("failed to connect to test database")
}

fn make_test_config() -> Arc<Config> {
    Arc::new(Config {
        jwt_secret: "test-secret-key-for-refresh-rotation-integration-tests-must-be-long"
            .to_string(),
        ..Config::default()
    })
}

/// Insert a disposable test user and return its id, username, and password.
/// The user is created with a unique username so parallel tests do not collide.
async fn create_test_user(pool: &PgPool) -> (Uuid, String, String) {
    let username = format!("rotation-test-{}", Uuid::new_v4().as_simple());
    let email = format!("{}@rotation.test", username);
    let password = "rotation-test-password".to_string();
    let password_hash = AuthService::hash_password(&password)
        .await
        .expect("hash test password");

    let row: (Uuid,) = sqlx::query_as(
        r#"
        INSERT INTO users (username, email, password_hash, auth_provider, is_admin, is_active)
        VALUES ($1, $2, $3, 'local', false, true)
        RETURNING id
        "#,
    )
    .bind(&username)
    .bind(&email)
    .bind(&password_hash)
    .fetch_one(pool)
    .await
    .expect("insert test user");

    (row.0, username, password)
}

async fn cleanup_test_user(pool: &PgPool, user_id: Uuid) {
    // used_refresh_jtis cascades via FK; user_roles has no cascade, but the
    // test user has none assigned. Just delete the row.
    let _ = sqlx::query("DELETE FROM users WHERE id = $1")
        .bind(user_id)
        .execute(pool)
        .await;
}

#[tokio::test]
#[ignore] // requires PostgreSQL
async fn test_refresh_token_rotation_happy_path() {
    let pool = connect_db().await;
    let (user_id, username, password) = create_test_user(&pool).await;
    let auth = AuthService::new(pool.clone(), make_test_config());

    // Step 1: login -> token pair #1
    let (_user, pair1) = auth
        .authenticate(&username, &password)
        .await
        .expect("initial login should succeed");

    // Step 2: refresh with refresh_token_1 -> get a fresh pair (#2)
    let (_user, pair2) = auth
        .refresh_tokens(&pair1.refresh_token)
        .await
        .expect("first refresh of refresh_token_1 should succeed");
    assert_ne!(
        pair1.refresh_token, pair2.refresh_token,
        "rotation must mint a new refresh token"
    );

    // Step 3: replay refresh_token_1 -> 401 (already used)
    let replay = auth.refresh_tokens(&pair1.refresh_token).await;
    assert!(
        replay.is_err(),
        "second use of refresh_token_1 must be rejected"
    );

    // Step 4: refresh_token_2 still works -> pair #3
    let (_user, pair3) = auth
        .refresh_tokens(&pair2.refresh_token)
        .await
        .expect("first use of refresh_token_2 should succeed");
    assert_ne!(pair2.refresh_token, pair3.refresh_token);

    // Step 5: refresh_token_2 replay also rejected
    let replay2 = auth.refresh_tokens(&pair2.refresh_token).await;
    assert!(
        replay2.is_err(),
        "second use of refresh_token_2 must be rejected"
    );

    cleanup_test_user(&pool, user_id).await;
}

#[tokio::test]
#[ignore] // requires PostgreSQL
async fn test_refresh_token_rotation_records_jti() {
    let pool = connect_db().await;
    let (user_id, username, password) = create_test_user(&pool).await;
    let auth = AuthService::new(pool.clone(), make_test_config());

    let (_user, pair1) = auth
        .authenticate(&username, &password)
        .await
        .expect("login");
    let _pair2 = auth
        .refresh_tokens(&pair1.refresh_token)
        .await
        .expect("first refresh");

    // Verify a row landed in used_refresh_jtis for this user.
    let count: (i64,) =
        sqlx::query_as("SELECT COUNT(*)::BIGINT FROM used_refresh_jtis WHERE user_id = $1")
            .bind(user_id)
            .fetch_one(&pool)
            .await
            .expect("count used_refresh_jtis");
    assert_eq!(
        count.0, 1,
        "exactly one jti should be recorded after a single refresh"
    );

    cleanup_test_user(&pool, user_id).await;
}

#[tokio::test]
#[ignore] // requires PostgreSQL
async fn test_refresh_token_replay_invalidates_user_access_tokens() {
    let pool = connect_db().await;
    let (user_id, username, password) = create_test_user(&pool).await;
    let auth = AuthService::new(pool.clone(), make_test_config());

    let (_user, pair1) = auth
        .authenticate(&username, &password)
        .await
        .expect("login");
    let (_user, pair2) = auth
        .refresh_tokens(&pair1.refresh_token)
        .await
        .expect("first refresh");

    // Access tokens minted at-or-before the replay should still validate
    // BEFORE the replay attempt.
    auth.validate_access_token(&pair2.access_token)
        .expect("fresh access token validates before replay");

    // Sleep so the invalidation timestamp produced by the replay below is
    // strictly greater than pair2.access_token.iat (timestamps are
    // second-granularity). Without this, in-second races can leave the
    // token marginally valid.
    tokio::time::sleep(std::time::Duration::from_secs(2)).await;

    // Replay refresh_token_1 -> rejected, AND triggers invalidation.
    let replay = auth.refresh_tokens(&pair1.refresh_token).await;
    assert!(replay.is_err(), "replay must fail");

    let post_replay = auth.validate_access_token(&pair2.access_token);
    assert!(
        post_replay.is_err(),
        "access tokens issued before replay should be invalidated"
    );

    cleanup_test_user(&pool, user_id).await;
}

#[tokio::test]
#[ignore] // requires PostgreSQL
async fn test_gc_used_refresh_jtis_removes_old_rows() {
    let pool = connect_db().await;
    let (user_id, _, _) = create_test_user(&pool).await;
    let auth = AuthService::new(pool.clone(), make_test_config());

    // Insert an aged jti row (older than the 7-day TTL).
    let old_jti = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO used_refresh_jtis (jti, user_id, used_at) VALUES ($1, $2, NOW() - INTERVAL '8 days')",
    )
    .bind(old_jti)
    .bind(user_id)
    .execute(&pool)
    .await
    .expect("insert aged jti");

    // Insert a fresh jti row (must NOT be reaped).
    let fresh_jti = Uuid::new_v4();
    sqlx::query("INSERT INTO used_refresh_jtis (jti, user_id, used_at) VALUES ($1, $2, NOW())")
        .bind(fresh_jti)
        .bind(user_id)
        .execute(&pool)
        .await
        .expect("insert fresh jti");

    let removed = auth.gc_used_refresh_jtis().await.expect("gc");
    assert!(
        removed >= 1,
        "GC should reap at least the aged row, removed = {}",
        removed
    );

    let exists_old: (bool,) =
        sqlx::query_as("SELECT EXISTS(SELECT 1 FROM used_refresh_jtis WHERE jti = $1)")
            .bind(old_jti)
            .fetch_one(&pool)
            .await
            .expect("check old jti");
    assert!(!exists_old.0, "aged jti must be reaped");

    let exists_fresh: (bool,) =
        sqlx::query_as("SELECT EXISTS(SELECT 1 FROM used_refresh_jtis WHERE jti = $1)")
            .bind(fresh_jti)
            .fetch_one(&pool)
            .await
            .expect("check fresh jti");
    assert!(exists_fresh.0, "fresh jti must be preserved");

    cleanup_test_user(&pool, user_id).await;
}

/// Fires N concurrent `refresh_tokens` calls with the same valid refresh
/// token and asserts exactly one succeeds. This exercises the load-bearing
/// claim of the design (issue #929): the atomic
/// `INSERT ... ON CONFLICT DO NOTHING` against `used_refresh_jtis` must
/// serialize concurrent redemptions race-free, with the unique row
/// constraint on `jti` acting as the single point of mutual exclusion.
#[tokio::test]
#[ignore] // requires PostgreSQL
async fn test_refresh_token_concurrent_redemption_only_one_succeeds() {
    let pool = connect_db().await;
    let (user_id, username, password) = create_test_user(&pool).await;
    let auth = Arc::new(AuthService::new(pool.clone(), make_test_config()));

    let (_user, pair1) = auth
        .authenticate(&username, &password)
        .await
        .expect("login");

    // Spawn N concurrent refresh attempts with the same token.
    const N: usize = 10;
    let mut handles = Vec::with_capacity(N);
    for _ in 0..N {
        let auth = auth.clone();
        let token = pair1.refresh_token.clone();
        handles.push(tokio::spawn(
            async move { auth.refresh_tokens(&token).await },
        ));
    }

    let mut successes = 0usize;
    let mut failures = 0usize;
    for h in handles {
        match h.await.expect("task panicked") {
            Ok(_) => successes += 1,
            Err(_) => failures += 1,
        }
    }

    assert_eq!(
        successes, 1,
        "exactly one concurrent refresh must succeed, got {}",
        successes
    );
    assert_eq!(
        failures,
        N - 1,
        "remaining {} attempts must be rejected as replays",
        N - 1
    );

    // Sanity check: only one jti should have landed for this user.
    let count: (i64,) =
        sqlx::query_as("SELECT COUNT(*)::BIGINT FROM used_refresh_jtis WHERE user_id = $1")
            .bind(user_id)
            .fetch_one(&pool)
            .await
            .expect("count used_refresh_jtis");
    assert_eq!(
        count.0, 1,
        "exactly one jti row should be persisted regardless of concurrency"
    );

    cleanup_test_user(&pool, user_id).await;
}

/// Mints a legacy-style refresh token (no `jti` claim) directly with
/// `jsonwebtoken::encode`, using the same secret two distinct AuthService
/// instances share, then verifies that the second instance rejects the
/// token as a replay even though its in-process state is empty. This
/// proves the legacy guard now survives restarts and is shared across
/// replicas (issue #929 review HIGH-2).
#[tokio::test]
#[ignore] // requires PostgreSQL
async fn test_legacy_refresh_token_replay_rejected_across_auth_instances() {
    use jsonwebtoken::{encode, EncodingKey, Header};
    use serde::Serialize;

    let pool = connect_db().await;
    let (user_id, _username, _password) = create_test_user(&pool).await;
    let cfg = make_test_config();

    // Mint a legacy refresh token: no `jti` field at all (mirrors pre-#929
    // tokens issued by older versions). We construct a minimal claims
    // struct so the field is omitted entirely from the encoded JWT, not
    // serialized as `null`.
    #[derive(Serialize)]
    struct LegacyClaims {
        sub: Uuid,
        username: String,
        email: String,
        is_admin: bool,
        iat: i64,
        exp: i64,
        token_type: String,
    }

    let now = chrono::Utc::now().timestamp();
    let exp = now + 3600;
    let legacy = LegacyClaims {
        sub: user_id,
        username: "legacy-user".to_string(),
        email: "legacy@example.test".to_string(),
        is_admin: false,
        iat: now,
        exp,
        token_type: "refresh".to_string(),
    };

    let legacy_token = encode(
        &Header::default(),
        &legacy,
        &EncodingKey::from_secret(cfg.jwt_secret.as_bytes()),
    )
    .expect("encode legacy refresh token");

    // Two distinct AuthService instances backed by the same DB simulate
    // either a process restart or two replicas behind a load balancer.
    let auth_a = AuthService::new(pool.clone(), cfg.clone());
    let auth_b = AuthService::new(pool.clone(), cfg.clone());

    // First instance redeems successfully.
    let first = auth_a.refresh_tokens(&legacy_token).await;
    assert!(
        first.is_ok(),
        "first redemption of legacy token must succeed: {:?}",
        first.err()
    );

    // Second instance, which has never seen the token before in process
    // memory, must still reject it as a replay because the DB blocklist
    // is shared.
    let second = auth_b.refresh_tokens(&legacy_token).await;
    assert!(
        second.is_err(),
        "legacy token must be rejected by a fresh AuthService instance \
         (proves the guard survives restarts and is shared across replicas)"
    );

    cleanup_test_user(&pool, user_id).await;
}

/// Verifies that `blocklist_refresh_token` (used by the logout handler)
/// renders an outstanding refresh token unusable.
#[tokio::test]
#[ignore] // requires PostgreSQL
async fn test_logout_blocklist_renders_refresh_token_unusable() {
    let pool = connect_db().await;
    let (user_id, username, password) = create_test_user(&pool).await;
    let auth = AuthService::new(pool.clone(), make_test_config());

    let (_user, pair) = auth
        .authenticate(&username, &password)
        .await
        .expect("login");

    // Logout: blocklist the refresh token without rotating.
    auth.blocklist_refresh_token(&pair.refresh_token)
        .await
        .expect("blocklist refresh token");

    // Subsequent attempt to refresh with the now-blocklisted token must fail.
    let post_logout = auth.refresh_tokens(&pair.refresh_token).await;
    assert!(
        post_logout.is_err(),
        "blocklisted refresh token must be rejected"
    );

    cleanup_test_user(&pool, user_id).await;
}
