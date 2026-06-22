//! DB-backed integration tests for webhook object-level authorization
//! (companion coverage for the BOLA fix in PR #1942).
//!
//! The fix added `authorize_webhook_access` (an async wrapper around the pure
//! `webhook_access_allowed` decision) in front of every per-webhook handler
//! — get/delete/enable/disable/test/deliveries/redeliver/rotate — plus
//! `created_by` recording on create and owner/repo scoping on list. The
//! pure decision is unit-tested in `security_regression_tests.rs`; this file
//! exercises the *async* seam and each handler end-to-end against a real
//! Postgres so the new authorization lines are covered:
//!
//!   - cross-user access to another principal's webhook returns 404
//!     (existence-hiding) on every gated endpoint,
//!   - the owner and an admin are allowed,
//!   - a repo member is allowed only for a repo-attached webhook,
//!   - legacy NULL-`created_by` global rows are admin-only,
//!   - `list_webhooks` is scoped (owner sees own, admin sees all, repo
//!     member sees repo-attached),
//!   - `create_webhook` stamps `created_by` with the caller.
//!
//! Requires a PostgreSQL database with all migrations applied:
//!
//! ```sh
//! DATABASE_URL="postgresql://registry:registry@localhost:5599/artifact_registry" \
//!   cargo test --test webhook_object_level_authz_tests -- --ignored
//! ```

#![allow(clippy::unwrap_used)]

use std::collections::HashMap;
use std::sync::Arc;

use sqlx::PgPool;
use uuid::Uuid;

use artifact_keeper_backend::api::handlers::webhooks::{
    self, CreateWebhookRequest, ListDeliveriesQuery, ListWebhooksQuery,
};
use artifact_keeper_backend::api::middleware::auth::AuthExtension;
use artifact_keeper_backend::api::{AppState, SharedState};
use artifact_keeper_backend::config::Config;
use artifact_keeper_backend::error::AppError;

// ===========================================================================
// Test harness
// ===========================================================================

fn test_config() -> Config {
    Config {
        database_url: std::env::var("DATABASE_URL").unwrap_or_default(),
        storage_path: std::env::temp_dir().to_string_lossy().to_string(),
        jwt_secret: "test-secret-at-least-32-bytes-long-for-testing".into(),
        ..Default::default()
    }
}

fn build_state(pool: PgPool) -> SharedState {
    let storage_path = std::env::temp_dir().to_string_lossy().to_string();
    let storage: Arc<dyn artifact_keeper_backend::storage::StorageBackend> = Arc::new(
        artifact_keeper_backend::storage::filesystem::FilesystemStorage::new(&storage_path),
    );
    let registry = Arc::new(artifact_keeper_backend::storage::StorageRegistry::new(
        HashMap::new(),
        "filesystem".to_string(),
    ));
    Arc::new(AppState::new(test_config(), pool, storage, registry))
}

/// Build an `AuthExtension` for a JWT-style (non-token) caller.
fn auth_for(user_id: Uuid, is_admin: bool) -> AuthExtension {
    AuthExtension {
        user_id,
        username: format!("u-{}", &user_id.to_string()[..8]),
        email: format!("{}@test.local", &user_id.to_string()[..8]),
        is_admin,
        is_api_token: false,
        is_service_account: false,
        scopes: None,
        allowed_repo_ids: None,
    }
}

async fn create_user(pool: &PgPool, is_admin: bool) -> Uuid {
    let id = Uuid::new_v4();
    let username = format!("wh1942-{}", &id.to_string()[..8]);
    sqlx::query(
        "INSERT INTO users (id, username, email, password_hash, auth_provider, is_admin, is_active) \
         VALUES ($1, $2, $3, 'x', 'local', $4, true)",
    )
    .bind(id)
    .bind(&username)
    .bind(format!("{}@test.local", username))
    .bind(is_admin)
    .execute(pool)
    .await
    .expect("insert user");
    id
}

async fn create_repo(pool: &PgPool) -> Uuid {
    let id = Uuid::new_v4();
    let key = format!("wh1942-repo-{}", &id.to_string()[..8]);
    sqlx::query(
        "INSERT INTO repositories (id, key, name, storage_path, repo_type, format, is_public) \
         VALUES ($1, $2, $2, '/tmp/wh1942', 'local', 'docker'::repository_format, false)",
    )
    .bind(id)
    .bind(&key)
    .execute(pool)
    .await
    .expect("insert repo");
    id
}

/// Grant `user` access to `repo` via a per-repo role assignment (the same
/// boundary `user_can_access_repo` consults).
async fn grant_repo_access(pool: &PgPool, user: Uuid, repo: Uuid) {
    let role_id: Uuid = sqlx::query_scalar("SELECT id FROM roles WHERE name = 'developer'")
        .fetch_one(pool)
        .await
        .expect("developer role must exist");
    sqlx::query(
        "INSERT INTO role_assignments (user_id, role_id, repository_id) VALUES ($1, $2, $3) \
         ON CONFLICT DO NOTHING",
    )
    .bind(user)
    .bind(role_id)
    .bind(repo)
    .execute(pool)
    .await
    .expect("grant repo access");
}

/// Insert a webhook row directly. `created_by`/`repository_id` are the two
/// ownership anchors the authz decision keys off; both may be NULL.
async fn insert_webhook(
    pool: &PgPool,
    created_by: Option<Uuid>,
    repository_id: Option<Uuid>,
) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO webhooks (id, name, url, events, is_enabled, repository_id, \
                               payload_template, event_schema_version, created_by) \
         VALUES ($1, $2, 'http://198.51.100.7/hook', ARRAY['artifact.created'], true, $3, \
                 'default', '2026-04-01', $4)",
    )
    .bind(id)
    .bind(format!("wh-{}", &id.to_string()[..8]))
    .bind(repository_id)
    .bind(created_by)
    .execute(pool)
    .await
    .expect("insert webhook");
    id
}

async fn webhook_exists(pool: &PgPool, id: Uuid) -> bool {
    sqlx::query_scalar::<_, bool>("SELECT EXISTS(SELECT 1 FROM webhooks WHERE id = $1)")
        .bind(id)
        .fetch_one(pool)
        .await
        .unwrap()
}

async fn is_enabled(pool: &PgPool, id: Uuid) -> bool {
    sqlx::query_scalar::<_, bool>("SELECT is_enabled FROM webhooks WHERE id = $1")
        .bind(id)
        .fetch_one(pool)
        .await
        .unwrap()
}

fn is_not_found<T: std::fmt::Debug>(r: &artifact_keeper_backend::error::Result<T>) -> bool {
    matches!(r, Err(AppError::NotFound(_)))
}

async fn cleanup(pool: &PgPool, repos: &[Uuid], users: &[Uuid]) {
    // role_assignments + webhooks cascade off repos/users via FKs, but be
    // explicit so a partial run leaves nothing behind.
    for u in users {
        sqlx::query("DELETE FROM role_assignments WHERE user_id = $1")
            .bind(u)
            .execute(pool)
            .await
            .ok();
    }
    sqlx::query("DELETE FROM webhooks WHERE created_by = ANY($1) OR repository_id = ANY($2)")
        .bind(users)
        .bind(repos)
        .execute(pool)
        .await
        .ok();
    for r in repos {
        sqlx::query("DELETE FROM webhooks WHERE repository_id = $1")
            .bind(r)
            .execute(pool)
            .await
            .ok();
        sqlx::query("DELETE FROM repositories WHERE id = $1")
            .bind(r)
            .execute(pool)
            .await
            .ok();
    }
    for u in users {
        sqlx::query("DELETE FROM users WHERE id = $1")
            .bind(u)
            .execute(pool)
            .await
            .ok();
    }
}

async fn connect() -> PgPool {
    PgPool::connect(&std::env::var("DATABASE_URL").unwrap())
        .await
        .unwrap()
}

// ===========================================================================
// get_webhook — read path across all four authz outcomes
// ===========================================================================

#[tokio::test]
#[ignore = "requires DATABASE_URL pointed at a Postgres with migrations applied"]
async fn get_webhook_authz_matrix() {
    let pool = connect().await;
    let owner = create_user(&pool, false).await;
    let stranger = create_user(&pool, false).await;
    let admin = create_user(&pool, true).await;
    let repo = create_repo(&pool).await;
    let state = build_state(pool.clone());

    // A global (repository-less) webhook owned by `owner`.
    let global_wh = insert_webhook(&pool, Some(owner), None).await;
    // A repo-attached webhook owned by `owner`; `stranger` gets repo access.
    let repo_wh = insert_webhook(&pool, Some(owner), Some(repo)).await;
    grant_repo_access(&pool, stranger, repo).await;
    // A legacy row: no creator, no repo (admin-only).
    let legacy_wh = insert_webhook(&pool, None, None).await;

    // Owner reads their own global webhook.
    assert!(
        webhooks::get_webhook(
            axum::extract::State(state.clone()),
            axum::Extension(auth_for(owner, false)),
            axum::extract::Path(global_wh),
        )
        .await
        .is_ok(),
        "owner must read own global webhook"
    );

    // Stranger (non-admin, non-owner) is denied on the GLOBAL webhook -> 404.
    // This is the exact cross-user/cross-tenant BOLA the fix closes.
    let r = webhooks::get_webhook(
        axum::extract::State(state.clone()),
        axum::Extension(auth_for(stranger, false)),
        axum::extract::Path(global_wh),
    )
    .await;
    assert!(
        is_not_found(&r),
        "stranger must get 404 on global webhook, got {r:?}"
    );

    // Admin reads any webhook, including the legacy NULL-owner row...
    assert!(webhooks::get_webhook(
        axum::extract::State(state.clone()),
        axum::Extension(auth_for(admin, true)),
        axum::extract::Path(global_wh),
    )
    .await
    .is_ok());
    assert!(webhooks::get_webhook(
        axum::extract::State(state.clone()),
        axum::Extension(auth_for(admin, true)),
        axum::extract::Path(legacy_wh),
    )
    .await
    .is_ok());

    // ...but a non-admin is denied the legacy NULL-owner row.
    assert!(is_not_found(
        &webhooks::get_webhook(
            axum::extract::State(state.clone()),
            axum::Extension(auth_for(stranger, false)),
            axum::extract::Path(legacy_wh),
        )
        .await
    ));

    // Repo member can read the repo-attached webhook (not its owner)...
    assert!(
        webhooks::get_webhook(
            axum::extract::State(state.clone()),
            axum::Extension(auth_for(stranger, false)),
            axum::extract::Path(repo_wh),
        )
        .await
        .is_ok(),
        "repo member must read repo-attached webhook"
    );
    // ...but a non-member, non-owner cannot.
    let outsider = create_user(&pool, false).await;
    assert!(is_not_found(
        &webhooks::get_webhook(
            axum::extract::State(state.clone()),
            axum::Extension(auth_for(outsider, false)),
            axum::extract::Path(repo_wh),
        )
        .await
    ));

    cleanup(&pool, &[repo], &[owner, stranger, admin, outsider]).await;
}

// ===========================================================================
// delete_webhook — mutating path; denial must not delete the row
// ===========================================================================

#[tokio::test]
#[ignore = "requires DATABASE_URL pointed at a Postgres with migrations applied"]
async fn delete_webhook_authz() {
    let pool = connect().await;
    let owner = create_user(&pool, false).await;
    let stranger = create_user(&pool, false).await;
    let admin = create_user(&pool, true).await;
    let state = build_state(pool.clone());

    let wh = insert_webhook(&pool, Some(owner), None).await;

    // Stranger denied: 404 AND the row survives.
    assert!(is_not_found(
        &webhooks::delete_webhook(
            axum::extract::State(state.clone()),
            axum::Extension(auth_for(stranger, false)),
            axum::extract::Path(wh),
        )
        .await
    ));
    assert!(
        webhook_exists(&pool, wh).await,
        "denied delete must not remove the row"
    );

    // Owner can delete their own.
    assert!(webhooks::delete_webhook(
        axum::extract::State(state.clone()),
        axum::Extension(auth_for(owner, false)),
        axum::extract::Path(wh),
    )
    .await
    .is_ok());
    assert!(!webhook_exists(&pool, wh).await);

    // Admin can delete another principal's webhook.
    let wh2 = insert_webhook(&pool, Some(owner), None).await;
    assert!(webhooks::delete_webhook(
        axum::extract::State(state.clone()),
        axum::Extension(auth_for(admin, true)),
        axum::extract::Path(wh2),
    )
    .await
    .is_ok());
    assert!(!webhook_exists(&pool, wh2).await);

    cleanup(&pool, &[], &[owner, stranger, admin]).await;
}

// ===========================================================================
// enable_webhook / disable_webhook — toggle paths
// ===========================================================================

#[tokio::test]
#[ignore = "requires DATABASE_URL pointed at a Postgres with migrations applied"]
async fn enable_disable_webhook_authz() {
    let pool = connect().await;
    let owner = create_user(&pool, false).await;
    let stranger = create_user(&pool, false).await;
    let state = build_state(pool.clone());

    let wh = insert_webhook(&pool, Some(owner), None).await;

    // Stranger denied on disable -> 404, state unchanged (still enabled).
    assert!(is_not_found(
        &webhooks::disable_webhook(
            axum::extract::State(state.clone()),
            axum::Extension(auth_for(stranger, false)),
            axum::extract::Path(wh),
        )
        .await
    ));
    assert!(
        is_enabled(&pool, wh).await,
        "denied disable must not change state"
    );

    // Owner can disable then enable.
    assert!(webhooks::disable_webhook(
        axum::extract::State(state.clone()),
        axum::Extension(auth_for(owner, false)),
        axum::extract::Path(wh),
    )
    .await
    .is_ok());
    assert!(!is_enabled(&pool, wh).await);

    assert!(webhooks::enable_webhook(
        axum::extract::State(state.clone()),
        axum::Extension(auth_for(owner, false)),
        axum::extract::Path(wh),
    )
    .await
    .is_ok());
    assert!(is_enabled(&pool, wh).await);

    // Stranger denied on enable too.
    assert!(is_not_found(
        &webhooks::enable_webhook(
            axum::extract::State(state.clone()),
            axum::Extension(auth_for(stranger, false)),
            axum::extract::Path(wh),
        )
        .await
    ));

    cleanup(&pool, &[], &[owner, stranger]).await;
}

// ===========================================================================
// test_webhook — denial must short-circuit BEFORE any outbound delivery
// ===========================================================================

#[tokio::test]
#[ignore = "requires DATABASE_URL pointed at a Postgres with migrations applied"]
async fn test_webhook_denied_cross_user() {
    let pool = connect().await;
    let owner = create_user(&pool, false).await;
    let stranger = create_user(&pool, false).await;
    let state = build_state(pool.clone());

    let wh = insert_webhook(&pool, Some(owner), None).await;

    // Stranger denied -> 404 (authz runs before the delivery attempt, so no
    // outbound request is made for another principal's endpoint).
    assert!(is_not_found(
        &webhooks::test_webhook(
            axum::extract::State(state.clone()),
            axum::Extension(auth_for(stranger, false)),
            axum::extract::Path(wh),
        )
        .await
    ));

    cleanup(&pool, &[], &[owner, stranger]).await;
}

// ===========================================================================
// list_deliveries — read path inheriting parent-webhook authz
// ===========================================================================

#[tokio::test]
#[ignore = "requires DATABASE_URL pointed at a Postgres with migrations applied"]
async fn list_deliveries_authz() {
    let pool = connect().await;
    let owner = create_user(&pool, false).await;
    let stranger = create_user(&pool, false).await;
    let state = build_state(pool.clone());

    let wh = insert_webhook(&pool, Some(owner), None).await;

    // Owner can list deliveries of their own webhook.
    assert!(webhooks::list_deliveries(
        axum::extract::State(state.clone()),
        axum::Extension(auth_for(owner, false)),
        axum::extract::Path(wh),
        axum::extract::Query(ListDeliveriesQuery {
            status: None,
            page: None,
            per_page: None,
        }),
    )
    .await
    .is_ok());

    // Stranger denied -> 404 (delivery listing inherits webhook authz).
    assert!(is_not_found(
        &webhooks::list_deliveries(
            axum::extract::State(state.clone()),
            axum::Extension(auth_for(stranger, false)),
            axum::extract::Path(wh),
            axum::extract::Query(ListDeliveriesQuery {
                status: None,
                page: None,
                per_page: None,
            }),
        )
        .await
    ));

    cleanup(&pool, &[], &[owner, stranger]).await;
}

// ===========================================================================
// redeliver — denial must short-circuit before re-sending
// ===========================================================================

#[tokio::test]
#[ignore = "requires DATABASE_URL pointed at a Postgres with migrations applied"]
async fn redeliver_denied_cross_user() {
    let pool = connect().await;
    let owner = create_user(&pool, false).await;
    let stranger = create_user(&pool, false).await;
    let state = build_state(pool.clone());

    let wh = insert_webhook(&pool, Some(owner), None).await;
    let delivery_id = Uuid::new_v4();

    // Stranger denied -> 404 from the webhook authz gate, before the
    // delivery row is ever looked up or re-sent.
    assert!(is_not_found(
        &webhooks::redeliver(
            axum::extract::State(state.clone()),
            axum::Extension(auth_for(stranger, false)),
            axum::extract::Path((wh, delivery_id)),
        )
        .await
    ));

    cleanup(&pool, &[], &[owner, stranger]).await;
}

// ===========================================================================
// rotate_webhook_secret — mutating path
// ===========================================================================

#[tokio::test]
#[ignore = "requires DATABASE_URL pointed at a Postgres with migrations applied"]
async fn rotate_secret_authz() {
    let pool = connect().await;
    let owner = create_user(&pool, false).await;
    let stranger = create_user(&pool, false).await;
    let admin = create_user(&pool, true).await;
    let state = build_state(pool.clone());

    let wh = insert_webhook(&pool, Some(owner), None).await;

    // Stranger denied -> 404.
    assert!(is_not_found(
        &webhooks::rotate_webhook_secret(
            axum::extract::State(state.clone()),
            axum::Extension(auth_for(stranger, false)),
            axum::extract::Path(wh),
        )
        .await
    ));

    // Owner passes the authz gate (the rotation may still fail later if the
    // deployment has no `AK_WEBHOOK_SECRET_KEY` configured for encryption —
    // that is orthogonal to authorization, so we only assert it is NOT the
    // existence-hiding 404 the gate emits on denial).
    assert!(
        !is_not_found(
            &webhooks::rotate_webhook_secret(
                axum::extract::State(state.clone()),
                axum::Extension(auth_for(owner, false)),
                axum::extract::Path(wh),
            )
            .await
        ),
        "owner must pass the rotate authz gate"
    );

    // Admin passes the authz gate on another principal's webhook.
    assert!(
        !is_not_found(
            &webhooks::rotate_webhook_secret(
                axum::extract::State(state.clone()),
                axum::Extension(auth_for(admin, true)),
                axum::extract::Path(wh),
            )
            .await
        ),
        "admin must pass the rotate authz gate"
    );

    cleanup(&pool, &[], &[owner, stranger, admin]).await;
}

// ===========================================================================
// list_webhooks — scoping: owner sees own, admin sees all, repo member
// sees repo-attached.
// ===========================================================================

#[tokio::test]
#[ignore = "requires DATABASE_URL pointed at a Postgres with migrations applied"]
async fn list_webhooks_scoping() {
    let pool = connect().await;
    let owner = create_user(&pool, false).await;
    let stranger = create_user(&pool, false).await;
    let member = create_user(&pool, false).await;
    let admin = create_user(&pool, true).await;
    let repo = create_repo(&pool).await;
    grant_repo_access(&pool, member, repo).await;
    let state = build_state(pool.clone());

    let owner_global = insert_webhook(&pool, Some(owner), None).await;
    let owner_repo = insert_webhook(&pool, Some(owner), Some(repo)).await;

    let empty_query = || ListWebhooksQuery {
        repository_id: None,
        enabled: None,
        page: None,
        per_page: Some(100),
    };

    // Owner sees both of their own webhooks.
    let owner_list = webhooks::list_webhooks(
        axum::extract::State(state.clone()),
        axum::Extension(auth_for(owner, false)),
        axum::extract::Query(empty_query()),
    )
    .await
    .unwrap();
    let owner_ids: Vec<Uuid> = owner_list.0.items.iter().map(|w| w.id).collect();
    assert!(
        owner_ids.contains(&owner_global),
        "owner must see own global webhook"
    );
    assert!(
        owner_ids.contains(&owner_repo),
        "owner must see own repo webhook"
    );

    // Stranger (no ownership, no repo role) sees neither.
    let stranger_list = webhooks::list_webhooks(
        axum::extract::State(state.clone()),
        axum::Extension(auth_for(stranger, false)),
        axum::extract::Query(empty_query()),
    )
    .await
    .unwrap();
    let stranger_ids: Vec<Uuid> = stranger_list.0.items.iter().map(|w| w.id).collect();
    assert!(
        !stranger_ids.contains(&owner_global) && !stranger_ids.contains(&owner_repo),
        "stranger must not see other principals' webhooks"
    );

    // Repo member sees the repo-attached one but not the owner's global one.
    let member_list = webhooks::list_webhooks(
        axum::extract::State(state.clone()),
        axum::Extension(auth_for(member, false)),
        axum::extract::Query(empty_query()),
    )
    .await
    .unwrap();
    let member_ids: Vec<Uuid> = member_list.0.items.iter().map(|w| w.id).collect();
    assert!(
        member_ids.contains(&owner_repo),
        "repo member must see repo-attached webhook"
    );
    assert!(
        !member_ids.contains(&owner_global),
        "repo member must not see foreign global webhook"
    );

    // Admin sees everything (scope predicate disabled).
    let admin_list = webhooks::list_webhooks(
        axum::extract::State(state.clone()),
        axum::Extension(auth_for(admin, true)),
        axum::extract::Query(empty_query()),
    )
    .await
    .unwrap();
    let admin_ids: Vec<Uuid> = admin_list.0.items.iter().map(|w| w.id).collect();
    assert!(
        admin_ids.contains(&owner_global) && admin_ids.contains(&owner_repo),
        "admin must see all webhooks"
    );

    cleanup(&pool, &[repo], &[owner, stranger, member, admin]).await;
}

// ===========================================================================
// create_webhook — stamps created_by with the caller (ownership anchor).
// ===========================================================================

#[tokio::test]
#[ignore = "requires DATABASE_URL pointed at a Postgres with migrations applied"]
async fn create_webhook_records_created_by() {
    let pool = connect().await;
    let creator = create_user(&pool, false).await;
    let state = build_state(pool.clone());

    let resp = webhooks::create_webhook(
        axum::extract::State(state.clone()),
        axum::Extension(auth_for(creator, false)),
        axum::Json(CreateWebhookRequest {
            name: format!("created-by-{}", &creator.to_string()[..8]),
            url: "http://198.51.100.9/hook".to_string(),
            events: vec!["artifact.created".to_string()],
            repository_id: None,
            headers: None,
            secret: None,
            payload_template: Default::default(),
            event_schema_version: None,
        }),
    )
    .await
    .expect("create webhook");

    let new_id = resp.0.webhook.id;
    let stored: Option<Uuid> = sqlx::query_scalar("SELECT created_by FROM webhooks WHERE id = $1")
        .bind(new_id)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(
        stored,
        Some(creator),
        "create_webhook must stamp created_by with the caller"
    );

    // And the creator can immediately reach it (owner path), confirming the
    // ownership anchor is wired through to the authz decision.
    assert!(webhooks::get_webhook(
        axum::extract::State(state.clone()),
        axum::Extension(auth_for(creator, false)),
        axum::extract::Path(new_id),
    )
    .await
    .is_ok());

    cleanup(&pool, &[], &[creator]).await;
}
