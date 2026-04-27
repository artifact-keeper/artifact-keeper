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
        database_url: "postgresql://unused".to_string(),
        bind_address: "0.0.0.0:8080".to_string(),
        log_level: "info".to_string(),
        storage_backend: "filesystem".to_string(),
        storage_path: "/tmp/test".to_string(),
        s3_bucket: None,
        gcs_bucket: None,
        s3_region: None,
        s3_endpoint: None,
        jwt_secret: "test-secret-key-for-refresh-rotation-integration-tests-must-be-long"
            .to_string(),
        jwt_expiration_secs: 86400,
        jwt_access_token_expiry_minutes: 30,
        jwt_refresh_token_expiry_days: 7,
        oidc_issuer: None,
        oidc_client_id: None,
        oidc_client_secret: None,
        ldap_url: None,
        ldap_base_dn: None,
        trivy_url: None,
        openscap_url: None,
        openscap_profile: "standard".to_string(),
        meilisearch_url: None,
        meilisearch_api_key: None,
        scan_workspace_path: "/tmp".to_string(),
        demo_mode: false,
        peer_instance_name: "test".to_string(),
        peer_public_endpoint: "http://localhost:8080".to_string(),
        peer_api_key: "test-key".to_string(),
        dependency_track_url: None,
        otel_exporter_otlp_endpoint: None,
        otel_service_name: "test".to_string(),
        gc_schedule: "0 0 * * * *".to_string(),
        lifecycle_check_interval_secs: 60,
        max_upload_size_bytes: 10_737_418_240,
        allow_local_admin_login: false,
        proxy_max_concurrent_fetches: 20,
        proxy_max_artifact_size_bytes: 2_147_483_648,
        proxy_queue_timeout_secs: 30,
        metrics_port: None,
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
