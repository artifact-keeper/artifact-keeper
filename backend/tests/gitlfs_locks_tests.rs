//! HTTP-level integration tests for the Git LFS file-locking API.
//!
//! The locking endpoints (`POST/GET /lfs/:repo/locks`, `POST /lfs/:repo/locks/
//! verify`, `POST /lfs/:repo/locks/:id/unlock`) previously stored each lock as a
//! row in `artifact_metadata` keyed by the *repository* id in the `artifact_id`
//! column. That column is `UUID UNIQUE NOT NULL REFERENCES artifacts(id)`, so
//! every `create_lock` INSERT failed the foreign key with a 500 and the whole
//! locking subsystem was dead (see the format-conformance `gitlfs` finding). The
//! fix gives locks their own `lfs_locks` table (migration 165).
//!
//! These tests pin the round-trip against a live database over the real router:
//! create (201), duplicate path (409), list, verify (ours/theirs partition),
//! delete, and force-delete. Each is guarded by [`try_pool`] so it skips
//! cleanly when no database is reachable.
//!
//! Requires a PostgreSQL database with all migrations applied:
//!
//! ```sh
//! DATABASE_URL="postgresql://registry:registry@localhost:30432/artifact_registry" \
//!   cargo test --test gitlfs_locks_tests -- --ignored
//! ```

#![allow(clippy::unwrap_used)]
// streaming-invariant: test file exempt — buffering a small JSON response body
// in an assertion is not an artifact path (#1608).
#![allow(clippy::disallowed_methods)]

use std::collections::HashMap;
use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::Extension;
use sqlx::PgPool;
use tower::ServiceExt;
use uuid::Uuid;

use artifact_keeper_backend::api::handlers::gitlfs;
use artifact_keeper_backend::api::middleware::auth::AuthExtension;
use artifact_keeper_backend::api::{AppState, SharedState};
use artifact_keeper_backend::config::Config;
use artifact_keeper_backend::models::access_scope::AccessScope;

const LFS_CT: &str = "application/vnd.git-lfs+json";

/// Connect to the test database. Returns `None` when `DATABASE_URL` is unset or
/// unreachable so the suite no-ops gracefully instead of flaking.
async fn try_pool() -> Option<PgPool> {
    let url = std::env::var("DATABASE_URL").ok()?;
    sqlx::postgres::PgPoolOptions::new()
        .max_connections(3)
        .acquire_timeout(std::time::Duration::from_secs(30))
        .connect(&url)
        .await
        .ok()
}

fn test_config(storage_path: &str) -> Config {
    Config {
        database_url: std::env::var("DATABASE_URL").unwrap_or_default(),
        storage_path: storage_path.into(),
        jwt_secret: "test-secret-at-least-32-bytes-long-for-testing".into(),
        ..Default::default()
    }
}

fn build_state(pool: PgPool, storage_path: &str) -> SharedState {
    let storage: Arc<dyn artifact_keeper_backend::storage::StorageBackend> = Arc::new(
        artifact_keeper_backend::storage::filesystem::FilesystemStorage::new(storage_path),
    );
    let registry = Arc::new(artifact_keeper_backend::storage::StorageRegistry::new(
        HashMap::new(),
        "filesystem".to_string(),
    ));
    Arc::new(AppState::new(
        test_config(storage_path),
        pool,
        storage,
        registry,
    ))
}

async fn create_test_user(pool: &PgPool, username: &str) -> Uuid {
    let id = Uuid::new_v4();
    let hash = bcrypt::hash("pw", 4).expect("bcrypt hash failed");
    sqlx::query(
        r#"
        INSERT INTO users (id, username, email, password_hash, auth_provider, is_admin, is_active)
        VALUES ($1, $2, $3, $4, 'local', false, true)
        "#,
    )
    .bind(id)
    .bind(username)
    .bind(format!("{}@test.local", username))
    .bind(&hash)
    .execute(pool)
    .await
    .expect("failed to create test user");
    id
}

/// Create a gitlfs-format local repo. Returns (repo_id, key).
async fn create_lfs_repo(pool: &PgPool, label: &str) -> (Uuid, String) {
    let id = Uuid::new_v4();
    let key = format!("lfslock-{}-{}", label, &id.to_string()[..8]);
    let storage_path = std::env::temp_dir().join(&key);
    std::fs::create_dir_all(&storage_path).expect("create storage dir");
    sqlx::query(
        "INSERT INTO repositories (id, key, name, storage_path, repo_type, format, is_public) \
         VALUES ($1, $2, $2, $3, 'local', 'gitlfs'::repository_format, true)",
    )
    .bind(id)
    .bind(&key)
    .bind(storage_path.to_string_lossy().as_ref())
    .execute(pool)
    .await
    .expect("insert gitlfs repo");
    (id, key)
}

fn auth_for(user_id: Uuid, username: &str) -> AuthExtension {
    AuthExtension {
        user_id,
        username: username.to_string(),
        email: format!("{}@test.local", username),
        is_admin: false,
        is_api_token: false,
        is_service_account: false,
        scopes: None,
        allowed_repo_ids: AccessScope::Admin,
        iat_ms: None,
    }
}

async fn cleanup(pool: &PgPool, repo_ids: &[Uuid], user_ids: &[Uuid]) {
    for id in repo_ids {
        sqlx::query("DELETE FROM lfs_locks WHERE repository_id = $1")
            .bind(id)
            .execute(pool)
            .await
            .ok();
        sqlx::query("DELETE FROM repositories WHERE id = $1")
            .bind(id)
            .execute(pool)
            .await
            .ok();
    }
    for id in user_ids {
        sqlx::query("DELETE FROM users WHERE id = $1")
            .bind(id)
            .execute(pool)
            .await
            .ok();
    }
}

/// Dispatch one request against the LFS router with the given (optional) auth
/// context injected exactly as the auth middleware would. Returns (status, body).
async fn send(
    state: &SharedState,
    method: &str,
    uri: &str,
    auth: Option<AuthExtension>,
    body: &str,
) -> (StatusCode, serde_json::Value) {
    let app = gitlfs::router()
        .with_state(state.clone())
        .layer(Extension::<Option<AuthExtension>>(auth));
    let req = Request::builder()
        .method(method)
        .uri(uri)
        .header("Content-Type", LFS_CT)
        .body(Body::from(body.to_string()))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let json = serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
    (status, json)
}

// ---------------------------------------------------------------------------
// create (201) + list + delete round-trip
// ---------------------------------------------------------------------------
#[tokio::test]
#[ignore = "requires DATABASE_URL pointed at a Postgres with migrations applied"]
async fn create_list_delete_lock_round_trip() {
    let Some(pool) = try_pool().await else {
        return;
    };
    let username = format!("alice-{}", &Uuid::new_v4().to_string()[..8]);
    let user_id = create_test_user(&pool, &username).await;
    let (repo_id, key) = create_lfs_repo(&pool, "rt").await;
    let state = build_state(pool.clone(), "/tmp");
    let auth = auth_for(user_id, &username);

    // Create -> 201 with an id. The owner name is resolved from the user record,
    // not the request, so it reflects the authenticated principal.
    let (status, body) = send(
        &state,
        "POST",
        &format!("/{key}/locks"),
        Some(auth.clone()),
        r#"{"path":"assets/model.bin"}"#,
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "create lock must 201: {body}");
    let lock_id = body["lock"]["id"].as_str().expect("lock id").to_string();
    assert_eq!(body["lock"]["path"], "assets/model.bin");
    assert_eq!(body["lock"]["owner"]["name"], username);

    // Anonymous list -> 401 (no enumeration without auth).
    let (anon_status, _) = send(&state, "GET", &format!("/{key}/locks"), None, "").await;
    assert_eq!(anon_status, StatusCode::UNAUTHORIZED);

    // Authenticated list -> shows our lock.
    let (status, body) = send(
        &state,
        "GET",
        &format!("/{key}/locks"),
        Some(auth.clone()),
        "",
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["locks"].as_array().unwrap().len(), 1);
    assert_eq!(body["locks"][0]["path"], "assets/model.bin");

    // Unlock -> 200; then it is gone.
    let (status, _) = send(
        &state,
        "POST",
        &format!("/{key}/locks/{lock_id}/unlock"),
        Some(auth.clone()),
        "{}",
    )
    .await;
    assert_eq!(status, StatusCode::OK, "owner unlock must 200");

    let (status, body) = send(&state, "GET", &format!("/{key}/locks"), Some(auth), "").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        body["locks"].as_array().unwrap().len(),
        0,
        "lock must be gone after unlock"
    );

    cleanup(&pool, &[repo_id], &[user_id]).await;
}

// ---------------------------------------------------------------------------
// duplicate path -> 409 conflict (single lock per path)
// ---------------------------------------------------------------------------
#[tokio::test]
#[ignore = "requires DATABASE_URL pointed at a Postgres with migrations applied"]
async fn duplicate_path_conflicts() {
    let Some(pool) = try_pool().await else {
        return;
    };
    let user_id =
        create_test_user(&pool, &format!("bob-{}", &Uuid::new_v4().to_string()[..8])).await;
    let (repo_id, key) = create_lfs_repo(&pool, "dup").await;
    let state = build_state(pool.clone(), "/tmp");
    let auth = auth_for(user_id, "bob");

    let (status, _) = send(
        &state,
        "POST",
        &format!("/{key}/locks"),
        Some(auth.clone()),
        r#"{"path":"data/big.bin"}"#,
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);

    // Second lock on the same path must conflict, and the 409 must carry the
    // existing lock (Git LFS locking spec).
    let (status, body) = send(
        &state,
        "POST",
        &format!("/{key}/locks"),
        Some(auth),
        r#"{"path":"data/big.bin"}"#,
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT, "duplicate path must 409");
    assert_eq!(body["lock"]["path"], "data/big.bin");

    cleanup(&pool, &[repo_id], &[user_id]).await;
}

// ---------------------------------------------------------------------------
// verify partitions locks into ours / theirs by owner
// ---------------------------------------------------------------------------
#[tokio::test]
#[ignore = "requires DATABASE_URL pointed at a Postgres with migrations applied"]
async fn verify_partitions_ours_and_theirs() {
    let Some(pool) = try_pool().await else {
        return;
    };
    let alice = create_test_user(
        &pool,
        &format!("alice-{}", &Uuid::new_v4().to_string()[..8]),
    )
    .await;
    let bob = create_test_user(&pool, &format!("bob-{}", &Uuid::new_v4().to_string()[..8])).await;
    let (repo_id, key) = create_lfs_repo(&pool, "vfy").await;
    let state = build_state(pool.clone(), "/tmp");
    let alice_auth = auth_for(alice, "alice");
    let bob_auth = auth_for(bob, "bob");

    // alice locks path A, bob locks path B.
    send(
        &state,
        "POST",
        &format!("/{key}/locks"),
        Some(alice_auth.clone()),
        r#"{"path":"a.bin"}"#,
    )
    .await;
    send(
        &state,
        "POST",
        &format!("/{key}/locks"),
        Some(bob_auth),
        r#"{"path":"b.bin"}"#,
    )
    .await;

    // Verify as alice: a.bin is ours, b.bin is theirs.
    let (status, body) = send(
        &state,
        "POST",
        &format!("/{key}/locks/verify"),
        Some(alice_auth),
        "{}",
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let ours: Vec<&str> = body["ours"]
        .as_array()
        .unwrap()
        .iter()
        .map(|l| l["path"].as_str().unwrap())
        .collect();
    let theirs: Vec<&str> = body["theirs"]
        .as_array()
        .unwrap()
        .iter()
        .map(|l| l["path"].as_str().unwrap())
        .collect();
    assert_eq!(ours, vec!["a.bin"], "alice's lock must be in `ours`");
    assert_eq!(theirs, vec!["b.bin"], "bob's lock must be in `theirs`");

    cleanup(&pool, &[repo_id], &[alice, bob]).await;
}

// ---------------------------------------------------------------------------
// force-unlock: a non-owner is denied without force, allowed with force
// ---------------------------------------------------------------------------
#[tokio::test]
#[ignore = "requires DATABASE_URL pointed at a Postgres with migrations applied"]
async fn force_unlock_of_another_users_lock() {
    let Some(pool) = try_pool().await else {
        return;
    };
    let alice = create_test_user(
        &pool,
        &format!("alice-{}", &Uuid::new_v4().to_string()[..8]),
    )
    .await;
    let bob = create_test_user(&pool, &format!("bob-{}", &Uuid::new_v4().to_string()[..8])).await;
    let (repo_id, key) = create_lfs_repo(&pool, "force").await;
    let state = build_state(pool.clone(), "/tmp");
    let alice_auth = auth_for(alice, "alice");
    let bob_auth = auth_for(bob, "bob");

    let (_, body) = send(
        &state,
        "POST",
        &format!("/{key}/locks"),
        Some(alice_auth),
        r#"{"path":"shared.bin"}"#,
    )
    .await;
    let lock_id = body["lock"]["id"].as_str().unwrap().to_string();

    // Bob cannot unlock alice's lock without force.
    let (status, _) = send(
        &state,
        "POST",
        &format!("/{key}/locks/{lock_id}/unlock"),
        Some(bob_auth.clone()),
        "{}",
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "non-owner must be 403");

    // With force, bob can.
    let (status, _) = send(
        &state,
        "POST",
        &format!("/{key}/locks/{lock_id}/unlock"),
        Some(bob_auth),
        r#"{"force":true}"#,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "force unlock must 200");

    cleanup(&pool, &[repo_id], &[alice, bob]).await;
}
