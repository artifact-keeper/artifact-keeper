//! Integration tests for cross-replica cache-invalidation fanout over
//! Postgres `LISTEN`/`NOTIFY` (multi-replica stale-authorization windows).
//!
//! These tests require PostgreSQL with all migrations applied:
//!
//! ```sh
//! DATABASE_URL="postgresql://registry:registry@localhost:30432/artifact_registry" \
//!     cargo test --test cache_invalidation_fanout_tests -- --ignored
//! ```
//!
//! Two layers are covered:
//!
//! 1. **Trigger emission contract** — the migration-142 triggers must emit
//!    exactly one versioned JSON event on the `ak_cache_invalidation_v1`
//!    channel for each security-relevant write (API-token revocation, user
//!    deactivation/delete, repository auth-metadata change/delete, permission
//!    CRUD, group membership/lifecycle), and must stay silent for benign
//!    writes such as package-activity `updated_at` bumps.
//!
//! 2. **Two-instance fanout behavior** — a listener-equipped "replica" whose
//!    caches were warmed must evict/reject within seconds of a write that
//!    bypassed its process-local invalidation helpers (simulating a write
//!    handled by a different replica), well inside each cache's TTL (60 s
//!    repo, 30 s permission, 300 s API token).

mod common;

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use sqlx::postgres::PgListener;
use sqlx::PgPool;
use tokio::sync::RwLock;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

use artifact_keeper_backend::api::{CachedRepo, RepoCache};
use artifact_keeper_backend::services::auth_service::AuthService;
use artifact_keeper_backend::services::cache_invalidation::{
    parse_invalidation_payload, start_cache_invalidation_listener, CacheInvalidationHandles,
    InvalidationEvent, CACHE_INVALIDATION_CHANNEL,
};
use artifact_keeper_backend::services::permission_service::PermissionService;

use common::{insert_active_user, require_db_pool, test_config_with_default_jwt};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Open a dedicated listening connection on the invalidation channel.
/// Notifications committed after this point will be delivered to it.
async fn subscribe(pool: &PgPool) -> PgListener {
    let mut listener = PgListener::connect_with(pool)
        .await
        .expect("failed to open a listener connection");
    listener
        .listen(CACHE_INVALIDATION_CHANNEL)
        .await
        .expect("LISTEN must succeed");
    listener
}

/// Drain notifications until one parses into an event matching `predicate`,
/// panicking after `timeout_secs`. Non-matching events are skipped so
/// concurrent activity on a shared database cannot fail the test.
async fn expect_event<F>(
    listener: &mut PgListener,
    timeout_secs: u64,
    what: &str,
    mut predicate: F,
) -> InvalidationEvent
where
    F: FnMut(&InvalidationEvent) -> bool,
{
    let deadline = tokio::time::Instant::now() + Duration::from_secs(timeout_secs);
    loop {
        let now = tokio::time::Instant::now();
        assert!(
            now < deadline,
            "timed out after {timeout_secs}s waiting for {what}"
        );
        match tokio::time::timeout(deadline - now, listener.recv()).await {
            Ok(Ok(notification)) => {
                if let Ok(event) = parse_invalidation_payload(notification.payload()) {
                    if predicate(&event) {
                        return event;
                    }
                }
            }
            Ok(Err(e)) => panic!("listener connection error while waiting for {what}: {e}"),
            Err(_) => panic!("timed out after {timeout_secs}s waiting for {what}"),
        }
    }
}

/// Assert that no event matching `predicate` arrives within `window_secs`.
async fn expect_no_event<F>(listener: &mut PgListener, window_secs: u64, what: &str, predicate: F)
where
    F: Fn(&InvalidationEvent) -> bool,
{
    let deadline = tokio::time::Instant::now() + Duration::from_secs(window_secs);
    loop {
        let now = tokio::time::Instant::now();
        if now >= deadline {
            return;
        }
        match tokio::time::timeout(deadline - now, listener.recv()).await {
            Ok(Ok(notification)) => {
                if let Ok(event) = parse_invalidation_payload(notification.payload()) {
                    assert!(!predicate(&event), "unexpected event for {what}: {event:?}");
                }
            }
            Ok(Err(e)) => panic!("listener connection error during {what}: {e}"),
            Err(_) => return,
        }
    }
}

/// Poll `cond` every 100 ms until it holds, panicking after `timeout`.
async fn wait_until<F, Fut>(what: &str, timeout: Duration, mut cond: F)
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = bool>,
{
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        if cond().await {
            return;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "timed out after {timeout:?} waiting for {what}"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

fn unique(prefix: &str) -> String {
    format!("{}-{}", prefix, &Uuid::new_v4().to_string()[..8])
}

async fn insert_repo(pool: &PgPool, key: &str, is_public: bool) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        r#"
        INSERT INTO repositories (id, key, name, format, repo_type, storage_backend, storage_path, is_public)
        VALUES ($1, $2, $2, 'generic'::repository_format, 'local'::repository_type, 'filesystem', $3, $4)
        "#,
    )
    .bind(id)
    .bind(key)
    .bind(format!("/data/{key}"))
    .bind(is_public)
    .execute(pool)
    .await
    .expect("failed to insert repository");
    id
}

/// Insert an api_tokens row directly (no bcrypt work needed: these tests
/// only exercise the revocation trigger, never token verification).
async fn insert_api_token_row(pool: &PgPool, user_id: Uuid) -> Uuid {
    let id = Uuid::new_v4();
    let prefix: String = id.to_string().chars().take(8).collect();
    sqlx::query(
        r#"
        INSERT INTO api_tokens (id, user_id, name, token_hash, token_prefix, scopes)
        VALUES ($1, $2, 'fanout-test-token', 'not-a-real-hash', $3, ARRAY['read:artifacts'])
        "#,
    )
    .bind(id)
    .bind(user_id)
    .bind(prefix)
    .execute(pool)
    .await
    .expect("failed to insert api token row");
    id
}

async fn insert_user_permission(pool: &PgPool, user_id: Uuid, repo_id: Uuid) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        r#"
        INSERT INTO permissions (id, principal_type, principal_id, target_type, target_id, actions)
        VALUES ($1, 'user', $2, 'repository', $3, ARRAY['read'])
        "#,
    )
    .bind(id)
    .bind(user_id)
    .bind(repo_id)
    .execute(pool)
    .await
    .expect("failed to insert permission");
    id
}

fn fresh_handles(pool: &PgPool) -> CacheInvalidationHandles {
    CacheInvalidationHandles {
        repo_cache: Arc::new(RwLock::new(HashMap::new())),
        permission_service: Arc::new(PermissionService::new(pool.clone())),
    }
}

/// Warm a repo-cache entry the way the repo-visibility middleware would.
async fn warm_repo_cache(cache: &RepoCache, repo_id: Uuid, key: &str) {
    let entry = CachedRepo {
        id: repo_id,
        format: "generic".into(),
        repo_type: "local".into(),
        upstream_url: None,
        storage_path: format!("/data/{key}"),
        storage_backend: "filesystem".into(),
        is_public: true,
        index_upstream_url: None,
    };
    cache
        .write()
        .await
        .insert(key.to_string(), (entry, Instant::now()));
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

async fn cleanup_repo(pool: &PgPool, repo_id: Uuid) {
    let _ = sqlx::query("DELETE FROM repositories WHERE id = $1")
        .bind(repo_id)
        .execute(pool)
        .await;
}

// ---------------------------------------------------------------------------
// 1. Trigger emission contract
// ---------------------------------------------------------------------------

#[tokio::test]
#[ignore]
async fn revoking_api_token_emits_api_token_revoked() {
    let pool = require_db_pool().await;
    let user_id = insert_active_user(&pool, "trg-revoke").await;
    let token_id = insert_api_token_row(&pool, user_id).await;

    let mut listener = subscribe(&pool).await;

    // Benign, non-transition update must stay silent.
    sqlx::query("UPDATE api_tokens SET last_used_at = NOW() WHERE id = $1")
        .bind(token_id)
        .execute(&pool)
        .await
        .expect("benign token update failed");
    expect_no_event(&mut listener, 2, "benign api_tokens update", |e| {
        *e == InvalidationEvent::ApiTokenRevoked { token_id }
    })
    .await;

    // The NULL -> non-NULL revoked_at transition must notify.
    sqlx::query("UPDATE api_tokens SET revoked_at = NOW() WHERE id = $1")
        .bind(token_id)
        .execute(&pool)
        .await
        .expect("revocation update failed");
    expect_event(&mut listener, 5, "api_token_revoked", |e| {
        *e == InvalidationEvent::ApiTokenRevoked { token_id }
    })
    .await;

    // Re-touching an already-revoked token must not notify again.
    sqlx::query("UPDATE api_tokens SET last_used_at = NOW() WHERE id = $1")
        .bind(token_id)
        .execute(&pool)
        .await
        .expect("post-revocation touch failed");
    expect_no_event(&mut listener, 2, "already-revoked token touch", |e| {
        *e == InvalidationEvent::ApiTokenRevoked { token_id }
    })
    .await;

    cleanup_user(&pool, user_id).await;
}

#[tokio::test]
#[ignore]
async fn user_deactivation_and_delete_emit_user_api_tokens_invalidated() {
    let pool = require_db_pool().await;
    let deactivated_id = insert_active_user(&pool, "trg-deact").await;
    let deleted_id = insert_active_user(&pool, "trg-del").await;

    let mut listener = subscribe(&pool).await;

    // Benign profile-ish update must stay silent.
    sqlx::query("UPDATE users SET updated_at = NOW() WHERE id = $1")
        .bind(deactivated_id)
        .execute(&pool)
        .await
        .expect("benign user update failed");
    expect_no_event(&mut listener, 2, "benign user update", |e| {
        matches!(e, InvalidationEvent::UserApiTokensInvalidated { user_id }
            if *user_id == deactivated_id || *user_id == deleted_id)
    })
    .await;

    // is_active true -> false must notify.
    sqlx::query("UPDATE users SET is_active = false, updated_at = NOW() WHERE id = $1")
        .bind(deactivated_id)
        .execute(&pool)
        .await
        .expect("deactivation failed");
    expect_event(&mut listener, 5, "user deactivation event", |e| {
        *e == InvalidationEvent::UserApiTokensInvalidated {
            user_id: deactivated_id,
        }
    })
    .await;

    // Hard delete must notify as well (offboarding via DELETE).
    sqlx::query("DELETE FROM users WHERE id = $1")
        .bind(deleted_id)
        .execute(&pool)
        .await
        .expect("user delete failed");
    expect_event(&mut listener, 5, "user delete event", |e| {
        *e == InvalidationEvent::UserApiTokensInvalidated {
            user_id: deleted_id,
        }
    })
    .await;

    cleanup_user(&pool, deactivated_id).await;
}

#[tokio::test]
#[ignore]
async fn repository_visibility_flip_emits_changed_but_package_activity_does_not() {
    let pool = require_db_pool().await;
    let key = unique("trg-repo-vis");
    let repo_id = insert_repo(&pool, &key, true).await;

    let mut listener = subscribe(&pool).await;

    // Package-activity bump (updated_at only) must stay silent, or package
    // writes would constantly flush repo metadata across the fleet.
    sqlx::query("UPDATE repositories SET updated_at = NOW() WHERE id = $1")
        .bind(repo_id)
        .execute(&pool)
        .await
        .expect("benign repo update failed");
    expect_no_event(
        &mut listener,
        2,
        "package-activity repo bump",
        |e| matches!(e, InvalidationEvent::RepositoryChanged { old_key, .. } if *old_key == key),
    )
    .await;

    // Public -> private is the security-critical flip.
    sqlx::query("UPDATE repositories SET is_public = false, updated_at = NOW() WHERE id = $1")
        .bind(repo_id)
        .execute(&pool)
        .await
        .expect("visibility flip failed");
    let event = expect_event(
        &mut listener,
        5,
        "repository_changed",
        |e| matches!(e, InvalidationEvent::RepositoryChanged { old_key, .. } if *old_key == key),
    )
    .await;
    assert_eq!(
        event,
        InvalidationEvent::RepositoryChanged {
            old_key: key.clone(),
            new_key: key.clone(),
        },
        "an in-place change must carry the same old and new key"
    );

    cleanup_repo(&pool, repo_id).await;
}

#[tokio::test]
#[ignore]
async fn repository_rename_emits_changed_with_both_keys() {
    let pool = require_db_pool().await;
    let old_key = unique("trg-repo-old");
    let new_key = unique("trg-repo-new");
    let repo_id = insert_repo(&pool, &old_key, true).await;

    let mut listener = subscribe(&pool).await;

    sqlx::query("UPDATE repositories SET key = $2, updated_at = NOW() WHERE id = $1")
        .bind(repo_id)
        .bind(&new_key)
        .execute(&pool)
        .await
        .expect("repo rename failed");

    expect_event(&mut listener, 5, "repository rename event", |e| {
        *e == InvalidationEvent::RepositoryChanged {
            old_key: old_key.clone(),
            new_key: new_key.clone(),
        }
    })
    .await;

    cleanup_repo(&pool, repo_id).await;
}

#[tokio::test]
#[ignore]
async fn repository_delete_emits_repository_deleted() {
    let pool = require_db_pool().await;
    let key = unique("trg-repo-del");
    let repo_id = insert_repo(&pool, &key, true).await;

    let mut listener = subscribe(&pool).await;

    sqlx::query("DELETE FROM repositories WHERE id = $1")
        .bind(repo_id)
        .execute(&pool)
        .await
        .expect("repo delete failed");

    expect_event(&mut listener, 5, "repository_deleted", |e| {
        *e == InvalidationEvent::RepositoryDeleted { key: key.clone() }
    })
    .await;
}

#[tokio::test]
#[ignore]
async fn permission_crud_emits_permissions_changed() {
    let pool = require_db_pool().await;
    let user_id = insert_active_user(&pool, "trg-perm").await;
    let repo_id = insert_repo(&pool, &unique("trg-perm-repo"), false).await;

    let mut listener = subscribe(&pool).await;

    let permission_id = insert_user_permission(&pool, user_id, repo_id).await;
    expect_event(&mut listener, 5, "permissions_changed on INSERT", |e| {
        *e == InvalidationEvent::PermissionsChanged
    })
    .await;

    sqlx::query("UPDATE permissions SET actions = ARRAY['read','write'] WHERE id = $1")
        .bind(permission_id)
        .execute(&pool)
        .await
        .expect("permission update failed");
    expect_event(&mut listener, 5, "permissions_changed on UPDATE", |e| {
        *e == InvalidationEvent::PermissionsChanged
    })
    .await;

    sqlx::query("DELETE FROM permissions WHERE id = $1")
        .bind(permission_id)
        .execute(&pool)
        .await
        .expect("permission delete failed");
    expect_event(&mut listener, 5, "permissions_changed on DELETE", |e| {
        *e == InvalidationEvent::PermissionsChanged
    })
    .await;

    cleanup_repo(&pool, repo_id).await;
    cleanup_user(&pool, user_id).await;
}

#[tokio::test]
#[ignore]
async fn group_membership_and_group_delete_emit_permissions_changed() {
    let pool = require_db_pool().await;
    let user_id = insert_active_user(&pool, "trg-grp").await;
    let group_id = Uuid::new_v4();
    sqlx::query("INSERT INTO groups (id, name) VALUES ($1, $2)")
        .bind(group_id)
        .bind(unique("trg-group"))
        .execute(&pool)
        .await
        .expect("group insert failed");

    let mut listener = subscribe(&pool).await;

    sqlx::query("INSERT INTO user_group_members (user_id, group_id) VALUES ($1, $2)")
        .bind(user_id)
        .bind(group_id)
        .execute(&pool)
        .await
        .expect("membership insert failed");
    expect_event(&mut listener, 5, "permissions_changed on member add", |e| {
        *e == InvalidationEvent::PermissionsChanged
    })
    .await;

    sqlx::query("DELETE FROM user_group_members WHERE user_id = $1 AND group_id = $2")
        .bind(user_id)
        .bind(group_id)
        .execute(&pool)
        .await
        .expect("membership delete failed");
    expect_event(
        &mut listener,
        5,
        "permissions_changed on member remove",
        |e| *e == InvalidationEvent::PermissionsChanged,
    )
    .await;

    sqlx::query("DELETE FROM groups WHERE id = $1")
        .bind(group_id)
        .execute(&pool)
        .await
        .expect("group delete failed");
    expect_event(
        &mut listener,
        5,
        "permissions_changed on group delete",
        |e| *e == InvalidationEvent::PermissionsChanged,
    )
    .await;

    cleanup_user(&pool, user_id).await;
}

// ---------------------------------------------------------------------------
// 2. Two-instance fanout behavior
//
// The "other replica" is simulated by mutating the database directly, which
// bypasses every process-local invalidation helper exactly like a write
// handled by a different pod would. The listener under test must close the
// gap well inside each cache's TTL; every wait below is capped far below the
// TTL it protects against so a regression to TTL-bound staleness fails loudly.
// ---------------------------------------------------------------------------

#[tokio::test]
#[ignore]
async fn listener_startup_conservatively_flushes_the_repo_cache() {
    let pool = require_db_pool().await;
    let handles = fresh_handles(&pool);
    let shutdown = CancellationToken::new();

    let key = unique("fan-startup");
    warm_repo_cache(&handles.repo_cache, Uuid::new_v4(), &key).await;

    // Notifications may have been missed before the listener existed, so
    // startup itself must flush; no database mutation happens in this test.
    let handle =
        start_cache_invalidation_listener(pool.clone(), handles.clone(), shutdown.clone()).await;

    wait_until("startup conservative flush", Duration::from_secs(5), || {
        let repo_cache = handles.repo_cache.clone();
        let key = key.clone();
        async move { !repo_cache.read().await.contains_key(&key) }
    })
    .await;

    shutdown.cancel();
    let _ = handle.await;
}

#[tokio::test]
#[ignore]
async fn repo_visibility_flip_on_another_replica_evicts_local_repo_cache() {
    let pool = require_db_pool().await;
    let handles = fresh_handles(&pool);
    let shutdown = CancellationToken::new();

    let key = unique("fan-repo-vis");
    let repo_id = insert_repo(&pool, &key, true).await;

    // Start listening first (startup flush included), then warm, so the
    // eviction observed below can only come from the notification.
    let handle =
        start_cache_invalidation_listener(pool.clone(), handles.clone(), shutdown.clone()).await;
    warm_repo_cache(&handles.repo_cache, repo_id, &key).await;

    sqlx::query("UPDATE repositories SET is_public = false, updated_at = NOW() WHERE id = $1")
        .bind(repo_id)
        .execute(&pool)
        .await
        .expect("visibility flip failed");

    // Well under REPO_CACHE_TTL_SECS (60 s): TTL expiry cannot explain this.
    wait_until(
        "repo cache eviction after visibility flip",
        Duration::from_secs(10),
        || {
            let repo_cache = handles.repo_cache.clone();
            let key = key.clone();
            async move { !repo_cache.read().await.contains_key(&key) }
        },
    )
    .await;

    shutdown.cancel();
    let _ = handle.await;
    cleanup_repo(&pool, repo_id).await;
}

#[tokio::test]
#[ignore]
async fn permission_revocation_on_another_replica_is_seen_within_seconds() {
    let pool = require_db_pool().await;
    let handles = fresh_handles(&pool);
    let shutdown = CancellationToken::new();

    let user_id = insert_active_user(&pool, "fan-perm").await;
    let repo_id = insert_repo(&pool, &unique("fan-perm-repo"), false).await;
    let permission_id = insert_user_permission(&pool, user_id, repo_id).await;

    let handle =
        start_cache_invalidation_listener(pool.clone(), handles.clone(), shutdown.clone()).await;

    // Warm the permission cache with the granted action.
    assert!(
        handles
            .permission_service
            .check_permission(user_id, "repository", repo_id, "read", false)
            .await
            .expect("permission check failed"),
        "grant must be visible before revocation"
    );

    // Revoke on "another replica".
    sqlx::query("DELETE FROM permissions WHERE id = $1")
        .bind(permission_id)
        .execute(&pool)
        .await
        .expect("permission delete failed");

    // Well under the 30 s permission-cache TTL.
    wait_until(
        "permission revocation visibility",
        Duration::from_secs(10),
        || {
            let permission_service = handles.permission_service.clone();
            async move {
                !permission_service
                    .check_permission(user_id, "repository", repo_id, "read", false)
                    .await
                    .expect("permission re-check failed")
            }
        },
    )
    .await;

    shutdown.cancel();
    let _ = handle.await;
    cleanup_repo(&pool, repo_id).await;
    cleanup_user(&pool, user_id).await;
}

#[tokio::test]
#[ignore]
async fn group_membership_removal_on_another_replica_revokes_derived_grant() {
    let pool = require_db_pool().await;
    let handles = fresh_handles(&pool);
    let shutdown = CancellationToken::new();

    let user_id = insert_active_user(&pool, "fan-grp").await;
    let repo_id = insert_repo(&pool, &unique("fan-grp-repo"), false).await;
    let group_id = Uuid::new_v4();
    sqlx::query("INSERT INTO groups (id, name) VALUES ($1, $2)")
        .bind(group_id)
        .bind(unique("fan-group"))
        .execute(&pool)
        .await
        .expect("group insert failed");
    sqlx::query("INSERT INTO user_group_members (user_id, group_id) VALUES ($1, $2)")
        .bind(user_id)
        .bind(group_id)
        .execute(&pool)
        .await
        .expect("membership insert failed");
    // Grant to the group, not the user: the derived grant is what must die.
    sqlx::query(
        r#"
        INSERT INTO permissions (id, principal_type, principal_id, target_type, target_id, actions)
        VALUES ($1, 'group', $2, 'repository', $3, ARRAY['read'])
        "#,
    )
    .bind(Uuid::new_v4())
    .bind(group_id)
    .bind(repo_id)
    .execute(&pool)
    .await
    .expect("group permission insert failed");

    let handle =
        start_cache_invalidation_listener(pool.clone(), handles.clone(), shutdown.clone()).await;

    assert!(
        handles
            .permission_service
            .check_permission(user_id, "repository", repo_id, "read", false)
            .await
            .expect("permission check failed"),
        "group-derived grant must be visible before membership removal"
    );

    // Offboard on "another replica" (mirrors SSO group sync).
    sqlx::query("DELETE FROM user_group_members WHERE user_id = $1 AND group_id = $2")
        .bind(user_id)
        .bind(group_id)
        .execute(&pool)
        .await
        .expect("membership delete failed");

    wait_until(
        "group-derived grant revocation visibility",
        Duration::from_secs(10),
        || {
            let permission_service = handles.permission_service.clone();
            async move {
                !permission_service
                    .check_permission(user_id, "repository", repo_id, "read", false)
                    .await
                    .expect("permission re-check failed")
            }
        },
    )
    .await;

    shutdown.cancel();
    let _ = handle.await;
    let _ = sqlx::query("DELETE FROM groups WHERE id = $1")
        .bind(group_id)
        .execute(&pool)
        .await;
    cleanup_repo(&pool, repo_id).await;
    cleanup_user(&pool, user_id).await;
}

#[tokio::test]
#[ignore]
async fn token_revocation_on_another_replica_rejects_cached_validation() {
    let pool = require_db_pool().await;
    let handles = fresh_handles(&pool);
    let shutdown = CancellationToken::new();

    let user_id = insert_active_user(&pool, "fan-revoke").await;
    let auth_service = AuthService::new(pool.clone(), test_config_with_default_jwt());
    let (token, token_id) = auth_service
        .generate_api_token(user_id, "fan-bot", vec!["read:artifacts".to_string()], None)
        .await
        .expect("failed to issue API token");

    let handle =
        start_cache_invalidation_listener(pool.clone(), handles.clone(), shutdown.clone()).await;

    // Warm this replica's validation cache.
    auth_service
        .validate_api_token(&token)
        .await
        .expect("token must validate before revocation");

    // Revoke on "another replica": DB write only, no local helper calls.
    sqlx::query("UPDATE api_tokens SET revoked_at = NOW() WHERE id = $1")
        .bind(token_id)
        .execute(&pool)
        .await
        .expect("revocation update failed");

    // Well under API_TOKEN_CACHE_TTL_SECS (300 s).
    wait_until(
        "cached validation rejection after revocation",
        Duration::from_secs(10),
        || {
            let auth_service = &auth_service;
            let token = token.clone();
            async move { auth_service.validate_api_token(&token).await.is_err() }
        },
    )
    .await;

    shutdown.cancel();
    let _ = handle.await;
    cleanup_user(&pool, user_id).await;
}

#[tokio::test]
#[ignore]
async fn user_deactivation_on_another_replica_rejects_cached_validation() {
    let pool = require_db_pool().await;
    let handles = fresh_handles(&pool);
    let shutdown = CancellationToken::new();

    let user_id = insert_active_user(&pool, "fan-deact").await;
    let auth_service = AuthService::new(pool.clone(), test_config_with_default_jwt());
    let (token, _token_id) = auth_service
        .generate_api_token(
            user_id,
            "fan-deact-bot",
            vec!["read:artifacts".to_string()],
            None,
        )
        .await
        .expect("failed to issue API token");

    let handle =
        start_cache_invalidation_listener(pool.clone(), handles.clone(), shutdown.clone()).await;

    auth_service
        .validate_api_token(&token)
        .await
        .expect("token must validate before deactivation");

    // Offboard on "another replica": DB write only, no local helper calls.
    sqlx::query("UPDATE users SET is_active = false, updated_at = NOW() WHERE id = $1")
        .bind(user_id)
        .execute(&pool)
        .await
        .expect("deactivation failed");

    // Well under API_TOKEN_CACHE_TTL_SECS (300 s).
    wait_until(
        "cached validation rejection after deactivation",
        Duration::from_secs(10),
        || {
            let auth_service = &auth_service;
            let token = token.clone();
            async move { auth_service.validate_api_token(&token).await.is_err() }
        },
    )
    .await;

    shutdown.cancel();
    let _ = handle.await;
    cleanup_user(&pool, user_id).await;
}
