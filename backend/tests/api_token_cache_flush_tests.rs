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
use artifact_keeper_backend::models::user::AuthProvider;
use artifact_keeper_backend::services::auth_service::{
    invalidate_user_token_cache_entries, invalidate_user_tokens, AuthService,
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

/// Hard-delete path coverage: simulates `DELETE /api/v1/users/:id` and
/// confirms cached API-token validations are rejected immediately.
#[tokio::test]
#[ignore]
async fn issued_token_rejected_after_user_delete() {
    let pool = PgPool::connect(&std::env::var("DATABASE_URL").expect("DATABASE_URL must be set"))
        .await
        .expect("failed to connect to db");

    let user_id = insert_active_user(&pool, "delete-path").await;

    let auth_service = AuthService::new(pool.clone(), test_config());

    let (token, _token_id) = auth_service
        .generate_api_token(user_id, "del-bot", vec!["read:artifacts".to_string()], None)
        .await
        .expect("failed to issue API token");

    // Warm the cache.
    auth_service
        .validate_api_token(&token)
        .await
        .expect("token must validate while user exists");

    // Mirror the DELETE handler: pre-mark invalidation, then DELETE the row.
    invalidate_user_token_cache_entries(user_id);
    invalidate_user_tokens(user_id);
    sqlx::query("DELETE FROM api_tokens WHERE user_id = $1")
        .bind(user_id)
        .execute(&pool)
        .await
        .expect("failed to delete tokens");
    sqlx::query("DELETE FROM users WHERE id = $1")
        .bind(user_id)
        .execute(&pool)
        .await
        .expect("failed to delete user");

    // Subsequent validation must be rejected. The cache hit path sees the
    // invalidation timestamp and rejects; the bcrypt path no longer finds
    // the row at all.
    let result = auth_service.validate_api_token(&token).await;
    assert!(
        result.is_err(),
        "validation must fail after user deletion, got: {:?}",
        result
    );
}

/// Re-activation regression: false -> true -> false must invalidate again.
/// LOW-1 in the security review.
#[tokio::test]
#[ignore]
async fn reactivation_then_redeactivation_rejects_old_cache_entries() {
    let pool = PgPool::connect(&std::env::var("DATABASE_URL").expect("DATABASE_URL must be set"))
        .await
        .expect("failed to connect to db");

    let user_id = insert_active_user(&pool, "reactivate").await;

    let auth_service = AuthService::new(pool.clone(), test_config());

    let (token, _) = auth_service
        .generate_api_token(
            user_id,
            "react-bot",
            vec!["read:artifacts".to_string()],
            None,
        )
        .await
        .expect("issue token");

    // First deactivation, mirroring the PATCH handler.
    set_user_inactive(&pool, user_id).await;
    invalidate_user_token_cache_entries(user_id);

    // Re-activate the user (no invalidation is the intended behavior).
    sqlx::query("UPDATE users SET is_active = true, updated_at = NOW() WHERE id = $1")
        .bind(user_id)
        .execute(&pool)
        .await
        .expect("failed to reactivate user");

    // Token validates again now that the user is active. This warms the cache
    // with a NEW entry inserted strictly after the first invalidation.
    auth_service
        .validate_api_token(&token)
        .await
        .expect("token validates after reactivation");

    // Sleep so the second invalidation timestamp is strictly after the warm
    // cache entry's insertion timestamp.
    tokio::time::sleep(std::time::Duration::from_millis(20)).await;

    // Second deactivation. The cache entry from the active window must now
    // be rejected.
    set_user_inactive(&pool, user_id).await;
    invalidate_user_token_cache_entries(user_id);

    let result = auth_service.validate_api_token(&token).await;
    assert!(
        result.is_err(),
        "second deactivation must invalidate the cache entry warmed during reactivation, got: {:?}",
        result
    );

    cleanup_user(&pool, user_id).await;
}

/// Insert a service account row directly (mirrors what
/// `ServiceAccountService::create` does, minus the username generation
/// niceties). Returns the user_id.
async fn insert_active_service_account(pool: &PgPool, suffix: &str) -> Uuid {
    let id = Uuid::new_v4();
    let username = format!("svc-ak931-{}-{}", suffix, &id.to_string()[..8]);
    let email = format!("{}@svc.local", username);
    sqlx::query(
        r#"
        INSERT INTO users (
            id, username, email, password_hash, is_admin, is_active,
            is_service_account, auth_provider
        )
        VALUES ($1, $2, $3, NULL, false, true, true, 'local')
        "#,
    )
    .bind(id)
    .bind(&username)
    .bind(&email)
    .execute(pool)
    .await
    .expect("failed to insert service account");
    id
}

/// HIGH-1 coverage: service-account PATCH must invalidate the API-token cache.
#[tokio::test]
#[ignore]
async fn service_account_patch_deactivation_rejects_cached_tokens() {
    let pool = PgPool::connect(&std::env::var("DATABASE_URL").expect("DATABASE_URL must be set"))
        .await
        .expect("failed to connect to db");

    let svc_id = insert_active_service_account(&pool, "patch").await;

    let auth_service = AuthService::new(pool.clone(), test_config());

    let (token, _) = auth_service
        .generate_api_token(
            svc_id,
            "ci-bot-patch",
            vec!["read:artifacts".to_string()],
            None,
        )
        .await
        .expect("issue token for service account");

    // Warm the cache.
    auth_service
        .validate_api_token(&token)
        .await
        .expect("token must validate while service account is active");

    // Mirror the service_accounts PATCH handler: pre-mark invalidation, then
    // flip is_active=false.
    invalidate_user_token_cache_entries(svc_id);
    invalidate_user_tokens(svc_id);
    sqlx::query("UPDATE users SET is_active = false, updated_at = NOW() WHERE id = $1")
        .bind(svc_id)
        .execute(&pool)
        .await
        .expect("failed to deactivate service account");

    let result = auth_service.validate_api_token(&token).await;
    assert!(
        result.is_err(),
        "deactivated service account token must be rejected, got: {:?}",
        result
    );

    cleanup_user(&pool, svc_id).await;
}

/// HIGH-1 coverage: service-account DELETE must invalidate the API-token cache.
#[tokio::test]
#[ignore]
async fn service_account_delete_rejects_cached_tokens() {
    let pool = PgPool::connect(&std::env::var("DATABASE_URL").expect("DATABASE_URL must be set"))
        .await
        .expect("failed to connect to db");

    let svc_id = insert_active_service_account(&pool, "delete").await;

    let auth_service = AuthService::new(pool.clone(), test_config());

    let (token, _) = auth_service
        .generate_api_token(
            svc_id,
            "ci-bot-delete",
            vec!["read:artifacts".to_string()],
            None,
        )
        .await
        .expect("issue token for service account");

    // Warm the cache.
    auth_service
        .validate_api_token(&token)
        .await
        .expect("token must validate while service account is active");

    // Mirror the service_accounts DELETE handler.
    invalidate_user_token_cache_entries(svc_id);
    invalidate_user_tokens(svc_id);
    sqlx::query("DELETE FROM api_tokens WHERE user_id = $1")
        .bind(svc_id)
        .execute(&pool)
        .await
        .expect("delete tokens");
    sqlx::query("DELETE FROM users WHERE id = $1 AND is_service_account = true")
        .bind(svc_id)
        .execute(&pool)
        .await
        .expect("delete service account");

    let result = auth_service.validate_api_token(&token).await;
    assert!(
        result.is_err(),
        "deleted service account token must be rejected, got: {:?}",
        result
    );
}

/// HIGH-2 coverage: AuthService::deactivate_missing_users must invalidate the
/// API-token cache for every deactivated user, in a single SSO sync.
#[tokio::test]
#[ignore]
async fn deactivate_missing_users_invalidates_each_deactivated_user() {
    let pool = PgPool::connect(&std::env::var("DATABASE_URL").expect("DATABASE_URL must be set"))
        .await
        .expect("failed to connect to db");

    // Create two LDAP users with external IDs. One will be "missing" from
    // the active list (offboarded), one will be kept.
    let drop_id = Uuid::new_v4();
    let drop_username = format!("ldap-drop-{}", &drop_id.to_string()[..8]);
    let drop_external = format!("ext-drop-{}", &drop_id.to_string()[..8]);
    sqlx::query(
        r#"
        INSERT INTO users (id, username, email, password_hash, is_admin, is_active, auth_provider, external_id)
        VALUES ($1, $2, $3, NULL, false, true, 'ldap', $4)
        "#,
    )
    .bind(drop_id)
    .bind(&drop_username)
    .bind(format!("{}@test.local", drop_username))
    .bind(&drop_external)
    .execute(&pool)
    .await
    .expect("insert drop user");

    let keep_id = Uuid::new_v4();
    let keep_username = format!("ldap-keep-{}", &keep_id.to_string()[..8]);
    let keep_external = format!("ext-keep-{}", &keep_id.to_string()[..8]);
    sqlx::query(
        r#"
        INSERT INTO users (id, username, email, password_hash, is_admin, is_active, auth_provider, external_id)
        VALUES ($1, $2, $3, NULL, false, true, 'ldap', $4)
        "#,
    )
    .bind(keep_id)
    .bind(&keep_username)
    .bind(format!("{}@test.local", keep_username))
    .bind(&keep_external)
    .execute(&pool)
    .await
    .expect("insert keep user");

    let auth_service = AuthService::new(pool.clone(), test_config());

    // Issue tokens for both and warm the caches.
    let (token_drop, _) = auth_service
        .generate_api_token(
            drop_id,
            "ldap-drop-bot",
            vec!["read:artifacts".into()],
            None,
        )
        .await
        .expect("issue drop token");
    let (token_keep, _) = auth_service
        .generate_api_token(
            keep_id,
            "ldap-keep-bot",
            vec!["read:artifacts".into()],
            None,
        )
        .await
        .expect("issue keep token");

    auth_service.validate_api_token(&token_drop).await.unwrap();
    auth_service.validate_api_token(&token_keep).await.unwrap();

    // Run the reaper with only `keep_external` in the active list.
    let active_ids = vec![keep_external.clone()];
    let deactivated = auth_service
        .deactivate_missing_users(AuthProvider::Ldap, &active_ids)
        .await
        .expect("deactivate_missing_users must succeed");
    assert!(
        deactivated >= 1,
        "expected at least the drop user to be deactivated, got {}",
        deactivated
    );

    // The drop user's cached token must now be rejected.
    let drop_result = auth_service.validate_api_token(&token_drop).await;
    assert!(
        drop_result.is_err(),
        "deactivate_missing_users must invalidate the offboarded user's cache, got: {:?}",
        drop_result
    );

    // The keep user's cached token must still validate.
    let keep_result = auth_service.validate_api_token(&token_keep).await;
    assert!(
        keep_result.is_ok(),
        "kept user's cache must remain intact, got: {:?}",
        keep_result
    );

    cleanup_user(&pool, drop_id).await;
    cleanup_user(&pool, keep_id).await;
}
