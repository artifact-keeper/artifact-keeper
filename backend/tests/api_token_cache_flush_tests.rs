//! Integration tests for API-token cache invalidation on user deactivation
//! (issue #931).
//!
//! These tests require PostgreSQL with all migrations applied.
//!
//! ```sh
//! DATABASE_URL="postgresql://registry:registry@localhost:30432/artifact_registry" \
//!     cargo test --test api_token_cache_flush_tests -- --ignored
//! ```
//!
//! What they verify: when an admin sets `is_active=false` on a user, every
//! cached API-token validation for that user must be rejected on the next
//! request, well inside the 5-minute cache TTL window. Without the fix the
//! cache hit would keep returning a valid `ApiTokenValidation` until the TTL
//! elapsed.

use std::sync::Arc;

use sqlx::PgPool;
use uuid::Uuid;

use artifact_keeper_backend::config::Config;
use artifact_keeper_backend::services::auth_service::{
    invalidate_user_token_cache_entries, AuthService,
};

fn test_config() -> Arc<Config> {
    // Config::from_env() requires DATABASE_URL and JWT_SECRET. Default the
    // JWT secret if the test runner didn't set one explicitly.
    if std::env::var("JWT_SECRET").is_err() {
        std::env::set_var(
            "JWT_SECRET",
            "ak-931-integration-test-jwt-secret-not-for-prod-use-please",
        );
    }
    Arc::new(Config::from_env().expect("Config::from_env failed"))
}

/// Insert a freshly-minted, active local user. Returns the user_id.
async fn insert_active_user(pool: &PgPool, suffix: &str) -> Uuid {
    let id = Uuid::new_v4();
    let username = format!("ak931-{}-{}", suffix, &id.to_string()[..8]);
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
    .expect("failed to insert user");
    id
}

/// Mark `is_active=false` on the user, mirroring what the PATCH /users/{id}
/// handler does on its UPDATE.
async fn set_user_inactive(pool: &PgPool, user_id: Uuid) {
    sqlx::query("UPDATE users SET is_active = false, updated_at = NOW() WHERE id = $1")
        .bind(user_id)
        .execute(pool)
        .await
        .expect("failed to deactivate user");
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

#[tokio::test]
#[ignore]
async fn issued_token_validates_then_rejects_after_deactivation() {
    let pool = PgPool::connect(&std::env::var("DATABASE_URL").expect("DATABASE_URL must be set"))
        .await
        .expect("failed to connect to db");

    let user_id = insert_active_user(&pool, "active-then-deact").await;

    let auth_service = AuthService::new(pool.clone(), test_config());

    // Mint an API token for the user, just like POST /users/:id/tokens.
    let (token, _token_id) = auth_service
        .generate_api_token(user_id, "ci-bot", vec!["read:artifacts".to_string()], None)
        .await
        .expect("failed to issue API token");

    // First validation: warm the cache. This goes through the bcrypt path
    // and inserts an entry into the per-instance token_cache.
    let validation = auth_service
        .validate_api_token(&token)
        .await
        .expect("token must validate while user is active");
    assert_eq!(validation.user.id, user_id);
    assert!(
        validation.user.is_active,
        "user must be active on first validation"
    );

    // Sanity: a second immediate validation also succeeds (cache hit).
    auth_service
        .validate_api_token(&token)
        .await
        .expect("cache hit should still pass while active");

    // Now deactivate the user, then immediately invalidate the in-memory
    // caches the way the PATCH /users/:id handler does.
    set_user_inactive(&pool, user_id).await;
    invalidate_user_token_cache_entries(user_id);

    // The next request must be rejected even though the cache TTL is far
    // from elapsed (300 s) and the entry is still in self.token_cache.
    let result = auth_service.validate_api_token(&token).await;
    assert!(
        result.is_err(),
        "validation must fail immediately after deactivation, got: {:?}",
        result
    );
    let err_str = format!("{}", result.unwrap_err());
    assert!(
        err_str.to_lowercase().contains("deactivat")
            || err_str.to_lowercase().contains("not found")
            || err_str.to_lowercase().contains("user account"),
        "unexpected error message: {}",
        err_str
    );

    cleanup_user(&pool, user_id).await;
}

#[tokio::test]
#[ignore]
async fn deactivation_does_not_affect_other_users_tokens() {
    let pool = PgPool::connect(&std::env::var("DATABASE_URL").expect("DATABASE_URL must be set"))
        .await
        .expect("failed to connect to db");

    let user_keep = insert_active_user(&pool, "keep").await;
    let user_drop = insert_active_user(&pool, "drop").await;

    let auth_service = AuthService::new(pool.clone(), test_config());

    let (token_keep, _) = auth_service
        .generate_api_token(
            user_keep,
            "keep-bot",
            vec!["read:artifacts".to_string()],
            None,
        )
        .await
        .expect("issue keep token");
    let (token_drop, _) = auth_service
        .generate_api_token(
            user_drop,
            "drop-bot",
            vec!["read:artifacts".to_string()],
            None,
        )
        .await
        .expect("issue drop token");

    // Warm both caches.
    auth_service.validate_api_token(&token_keep).await.unwrap();
    auth_service.validate_api_token(&token_drop).await.unwrap();

    // Deactivate ONLY user_drop.
    set_user_inactive(&pool, user_drop).await;
    invalidate_user_token_cache_entries(user_drop);

    // user_keep's token must still validate from cache.
    let keep = auth_service.validate_api_token(&token_keep).await;
    assert!(
        keep.is_ok(),
        "non-deactivated user's token must still validate, got: {:?}",
        keep
    );

    // user_drop's token must be rejected.
    let drop = auth_service.validate_api_token(&token_drop).await;
    assert!(
        drop.is_err(),
        "deactivated user's token must be rejected, got: {:?}",
        drop
    );

    cleanup_user(&pool, user_keep).await;
    cleanup_user(&pool, user_drop).await;
}

#[tokio::test]
#[ignore]
async fn flush_user_token_cache_entries_drops_in_memory_entries() {
    let pool = PgPool::connect(&std::env::var("DATABASE_URL").expect("DATABASE_URL must be set"))
        .await
        .expect("failed to connect to db");

    let user_id = insert_active_user(&pool, "flush").await;
    let auth_service = AuthService::new(pool.clone(), test_config());

    let (token, _) = auth_service
        .generate_api_token(
            user_id,
            "flush-bot",
            vec!["read:artifacts".to_string()],
            None,
        )
        .await
        .expect("issue token");

    // Warm the cache.
    auth_service.validate_api_token(&token).await.unwrap();

    // The flush helper should drop the entry. Subsequent verification will
    // re-bcrypt against the DB.
    let removed = auth_service.flush_user_token_cache_entries(user_id);
    assert!(
        removed >= 1,
        "expected to flush at least one cache entry, got {}",
        removed
    );

    // Without deactivation, the token still validates (re-populating the cache).
    auth_service
        .validate_api_token(&token)
        .await
        .expect("active user token still valid after flush");

    cleanup_user(&pool, user_id).await;
}
