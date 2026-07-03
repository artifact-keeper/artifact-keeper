//! Integration tests for OCI/Docker chunked-upload cross-repo session
//! rejection (issue #1317 companion coverage for `oci_v2.rs`).
//!
//! The original fix in PR #1504 bound the URL's repo into the
//! `oci_upload_sessions` lookup so that a session created against repo A
//! cannot be driven (chunked or finalized) via repo B's URL. The matching
//! incus paths already have an integration test
//! (`incus_upload_tests::test_chunked_upload_cross_repo_session_rejected`);
//! the OCI v2 `handle_patch_upload` and `handle_complete_upload` branches
//! had no equivalent. This file covers them.
//!
//! Requires a PostgreSQL database with all migrations applied:
//!
//! ```sh
//! DATABASE_URL="postgresql://registry:registry@localhost:30432/artifact_registry" \
//!   cargo test --test oci_chunked_upload_cross_repo_tests -- --ignored
//! ```

#![allow(clippy::unwrap_used)]
#![allow(clippy::disallowed_methods)] // streaming-invariant: test file exempt — buffering response bodies in test assertions is not an artifact path (#1608)
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use sqlx::PgPool;
use tower::ServiceExt;
use uuid::Uuid;

use artifact_keeper_backend::api::handlers::oci_v2;
use artifact_keeper_backend::api::{AppState, SharedState};
use artifact_keeper_backend::config::Config;

// ===========================================================================
// Test helpers
// ===========================================================================

fn test_config(storage_path: &str) -> Config {
    Config {
        database_url: std::env::var("DATABASE_URL").unwrap_or_default(),
        storage_path: storage_path.into(),
        jwt_secret: "test-secret-at-least-32-bytes-long-for-testing".into(),
        ..Default::default()
    }
}

fn basic_auth_header(username: &str, password: &str) -> String {
    use base64::Engine;
    let encoded =
        base64::engine::general_purpose::STANDARD.encode(format!("{}:{}", username, password));
    format!("Basic {}", encoded)
}

async fn create_test_user(pool: &PgPool, username: &str, password: &str) -> Uuid {
    let id = Uuid::new_v4();
    let hash = bcrypt::hash(password, 4).expect("bcrypt hash failed");
    sqlx::query(
        r#"
        INSERT INTO users (id, username, email, password_hash, auth_provider, is_admin, is_active)
        VALUES ($1, $2, $3, $4, 'local', true, true)
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

/// Create a docker-format local repo. Returns (repo_id, key, storage_path).
async fn create_docker_repo(pool: &PgPool, label: &str) -> (Uuid, String, PathBuf) {
    let id = Uuid::new_v4();
    let key = format!("oci1317-{}-{}", label, &id.to_string()[..8]);
    let storage_path = std::env::temp_dir().join(format!("oci1317-{}", id));
    std::fs::create_dir_all(&storage_path).expect("create storage dir");
    sqlx::query(
        "INSERT INTO repositories (id, key, name, storage_path, repo_type, format, is_public) \
         VALUES ($1, $2, $2, $3, 'local', 'docker'::repository_format, true)",
    )
    .bind(id)
    .bind(&key)
    .bind(storage_path.to_string_lossy().as_ref())
    .execute(pool)
    .await
    .expect("insert docker repo");
    (id, key, storage_path)
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

async fn cleanup(pool: &PgPool, repo_ids: &[Uuid], user_id: Uuid) {
    for id in repo_ids {
        sqlx::query("DELETE FROM oci_upload_sessions WHERE repository_id = $1")
            .bind(id)
            .execute(pool)
            .await
            .ok();
        sqlx::query("DELETE FROM oci_blobs WHERE repository_id = $1")
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
    sqlx::query("DELETE FROM users WHERE id = $1")
        .bind(user_id)
        .execute(pool)
        .await
        .ok();
}

fn sha256_hex(data: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(data);
    format!("{:x}", hasher.finalize())
}

// ===========================================================================
// Issue #1317 regression: OCI chunked-upload session lookups must be
// scoped to the URL's repo so a session created in repo A cannot be
// driven (PATCH chunk) or finalized (PUT complete) via repo B's URL.
//
// Cross-repo attempts must return 404 (same shape as "session does not
// exist") to avoid leaking session existence across repos. Same-repo
// flow must still succeed.
// ===========================================================================

#[tokio::test]
#[ignore = "requires DATABASE_URL pointed at a Postgres with migrations applied"]
async fn test_oci_chunked_upload_cross_repo_session_rejected() {
    let pool = PgPool::connect(&std::env::var("DATABASE_URL").unwrap())
        .await
        .unwrap();
    let username = format!("oci1317-{}", &Uuid::new_v4().to_string()[..8]);
    let user_id = create_test_user(&pool, &username, "pushpass").await;
    let (repo_a_id, key_a, storage_path) = create_docker_repo(&pool, "a").await;
    let (repo_b_id, key_b, _storage_path_b) = create_docker_repo(&pool, "b").await;
    let state = build_state(pool.clone(), storage_path.to_str().unwrap());
    let auth = basic_auth_header(&username, "pushpass");

    let make_app = || oci_v2::router().with_state(state.clone());

    // POST start under repo A.
    let req = Request::builder()
        .method("POST")
        .uri(format!("/{}/myimage/blobs/uploads/", key_a))
        .header("Authorization", &auth)
        .body(Body::empty())
        .unwrap();
    let resp = make_app().oneshot(req).await.unwrap();
    let status = resp.status();
    let body = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let body_str = String::from_utf8_lossy(&body);
    assert_eq!(
        status,
        StatusCode::ACCEPTED,
        "POST start under repo A should return 202: {}",
        body_str
    );

    // Pull the session UUID out of the Docker-Upload-UUID location header.
    // The Location header is `/v2/{name}/blobs/uploads/{uuid}` and the
    // server also emits `Docker-Upload-UUID: {uuid}`. We re-issue a GET
    // on the most recent session row so the test does not depend on
    // exact header propagation order.
    let session_id: Uuid = sqlx::query_scalar(
        "SELECT id FROM oci_upload_sessions WHERE repository_id = $1 ORDER BY created_at DESC LIMIT 1",
    )
    .bind(repo_a_id)
    .fetch_one(&pool)
    .await
    .expect("session row must exist after POST start");

    // Attack: PATCH the same session under repo B's URL. Must be rejected
    // with 404 (issue #1317).
    let req = Request::builder()
        .method("PATCH")
        .uri(format!("/{}/myimage/blobs/uploads/{}", key_b, session_id))
        .header("Authorization", &auth)
        .body(Body::from(b"chunk-bytes".to_vec()))
        .unwrap();
    let resp = make_app().oneshot(req).await.unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::NOT_FOUND,
        "PATCH chunk under wrong repo must be 404 (issue #1317)"
    );

    // Sanity check: PATCH under repo A succeeds and exercises the
    // happy-path branch of the new session lookup.
    let chunk = b"chunk-bytes".to_vec();
    let req = Request::builder()
        .method("PATCH")
        .uri(format!("/{}/myimage/blobs/uploads/{}", key_a, session_id))
        .header("Authorization", &auth)
        .body(Body::from(chunk.clone()))
        .unwrap();
    let resp = make_app().oneshot(req).await.unwrap();
    let status = resp.status();
    let body = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let body_str = String::from_utf8_lossy(&body);
    assert_eq!(
        status,
        StatusCode::ACCEPTED,
        "PATCH under owning repo should succeed: {}",
        body_str
    );

    // Attack: PUT complete under repo B's URL must also be rejected.
    // We need a valid digest header to make sure the 404 is from the
    // session-scoping check and not from later digest validation.
    let digest = format!("sha256:{}", sha256_hex(&chunk));
    let req = Request::builder()
        .method("PUT")
        .uri(format!(
            "/{}/myimage/blobs/uploads/{}?digest={}",
            key_b, session_id, digest
        ))
        .header("Authorization", &auth)
        .body(Body::empty())
        .unwrap();
    let resp = make_app().oneshot(req).await.unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::NOT_FOUND,
        "PUT complete under wrong repo must be 404 (issue #1317)"
    );

    // Session row must still exist under repo A: cross-repo attempts
    // must not have side-effected (deleted or mutated) the original row.
    let still_there: i64 =
        sqlx::query_scalar("SELECT count(*) FROM oci_upload_sessions WHERE id = $1")
            .bind(session_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(
        still_there, 1,
        "cross-repo attempts must not delete the legitimate session"
    );

    // Legitimate PUT complete under repo A should succeed and tear the
    // session down. We re-PATCH first to keep digest math simple (one
    // chunk worth of bytes on disk after this point).
    let req = Request::builder()
        .method("PUT")
        .uri(format!(
            "/{}/myimage/blobs/uploads/{}?digest={}",
            key_a, session_id, digest
        ))
        .header("Authorization", &auth)
        .body(Body::empty())
        .unwrap();
    let resp = make_app().oneshot(req).await.unwrap();
    let status = resp.status();
    let body = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let body_str = String::from_utf8_lossy(&body);
    assert_eq!(
        status,
        StatusCode::CREATED,
        "PUT complete under owning repo should return 201: {}",
        body_str
    );

    // Cleanup
    let _ = std::fs::remove_dir_all(&storage_path);
    cleanup(&pool, &[repo_a_id, repo_b_id], user_id).await;
}
