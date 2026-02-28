//! Integration tests for Incus/LXC streaming and chunked uploads.
//!
//! These tests require a PostgreSQL database with migrations applied.
//! Set DATABASE_URL and run:
//!
//! ```sh
//! DATABASE_URL="postgresql://registry:registry@localhost:30432/artifact_registry" \
//!   cargo test --test incus_upload_tests -- --ignored
//! ```

use std::path::PathBuf;
use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use sqlx::{PgPool, Row};
use tower::ServiceExt;
use uuid::Uuid;

use artifact_keeper_backend::api::handlers::incus;
use artifact_keeper_backend::api::{AppState, SharedState};
use artifact_keeper_backend::config::Config;

// ===========================================================================
// Test helpers
// ===========================================================================

fn test_config(storage_path: &str) -> Config {
    Config {
        database_url: std::env::var("DATABASE_URL").unwrap(),
        bind_address: "127.0.0.1:0".into(),
        log_level: "error".into(),
        storage_backend: "filesystem".into(),
        storage_path: storage_path.into(),
        s3_bucket: None,
        s3_region: None,
        s3_endpoint: None,
        jwt_secret: "test-secret-at-least-32-bytes-long-for-testing".into(),
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
        openscap_profile: "standard".into(),
        meilisearch_url: None,
        meilisearch_api_key: None,
        scan_workspace_path: "/tmp/scan".into(),
        demo_mode: false,
        peer_instance_name: "test".into(),
        peer_public_endpoint: "http://localhost:8080".into(),
        peer_api_key: "test-key".into(),
        dependency_track_url: None,
        otel_exporter_otlp_endpoint: None,
        otel_service_name: "test".into(),
        gc_schedule: "0 0 * * * *".into(),
        lifecycle_check_interval_secs: 60,
    }
}

fn basic_auth_header(username: &str, password: &str) -> String {
    use base64::Engine;
    let encoded =
        base64::engine::general_purpose::STANDARD.encode(format!("{}:{}", username, password));
    format!("Basic {}", encoded)
}

/// Create a test user with bcrypt-hashed password.
async fn create_test_user(pool: &PgPool, username: &str, password: &str) -> Uuid {
    let id = Uuid::new_v4();
    let hash = bcrypt::hash(password, 4).expect("bcrypt hash failed"); // cost=4 for speed in tests
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

/// Create a test Incus repository. Returns (repo_id, storage_path).
async fn create_incus_repo(pool: &PgPool, name: &str) -> (Uuid, PathBuf) {
    let id = Uuid::new_v4();
    let key = format!("incus-test-{}", id);
    let storage_path = std::env::temp_dir().join(format!("incus-test-{}", id));
    std::fs::create_dir_all(&storage_path).expect("create storage dir");

    sqlx::query(
        "INSERT INTO repositories (id, key, name, storage_path, repo_type, format) VALUES ($1, $2, $3, $4, 'local', 'incus')",
    )
    .bind(id)
    .bind(&key)
    .bind(name)
    .bind(storage_path.to_string_lossy().as_ref())
    .execute(pool)
    .await
    .expect("failed to create test repository");

    (id, storage_path)
}

/// Get the repo key from a repo id.
async fn repo_key(pool: &PgPool, repo_id: Uuid) -> String {
    let row = sqlx::query("SELECT key FROM repositories WHERE id = $1")
        .bind(repo_id)
        .fetch_one(pool)
        .await
        .expect("repo not found");
    row.get("key")
}

/// Clean up all test data.
async fn cleanup(pool: &PgPool, repo_id: Uuid, user_id: Uuid) {
    sqlx::query("DELETE FROM incus_upload_sessions WHERE repository_id = $1")
        .bind(repo_id)
        .execute(pool)
        .await
        .ok();
    sqlx::query("DELETE FROM artifact_metadata WHERE artifact_id IN (SELECT id FROM artifacts WHERE repository_id = $1)")
        .bind(repo_id)
        .execute(pool)
        .await
        .ok();
    sqlx::query("DELETE FROM artifacts WHERE repository_id = $1")
        .bind(repo_id)
        .execute(pool)
        .await
        .ok();
    sqlx::query("DELETE FROM repositories WHERE id = $1")
        .bind(repo_id)
        .execute(pool)
        .await
        .ok();
    sqlx::query("DELETE FROM users WHERE id = $1")
        .bind(user_id)
        .execute(pool)
        .await
        .ok();
}

/// Build a SharedState for the incus router.
fn build_state(pool: PgPool, storage_path: &str) -> SharedState {
    let storage: std::sync::Arc<dyn artifact_keeper_backend::storage::StorageBackend> =
        std::sync::Arc::new(
            artifact_keeper_backend::storage::filesystem::FilesystemStorage::new(storage_path),
        );
    Arc::new(AppState::new(test_config(storage_path), pool, storage))
}

/// Generate deterministic test data of a given size.
fn test_data(size: usize) -> Vec<u8> {
    (0..size).map(|i| (i % 251) as u8).collect()
}

/// Compute SHA256 hex of bytes.
fn sha256_hex(data: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(data);
    format!("{:x}", hasher.finalize())
}

// ===========================================================================
// 1. Monolithic streaming upload — PUT a file, verify artifact + checksum
// ===========================================================================

#[tokio::test]
#[ignore]
async fn test_monolithic_streaming_upload() {
    let pool = PgPool::connect(&std::env::var("DATABASE_URL").unwrap())
        .await
        .unwrap();
    let user_id = create_test_user(
        &pool,
        &format!("incus-u1-{}", Uuid::new_v4()),
        "testpass123",
    )
    .await;
    let (repo_id, storage_path) = create_incus_repo(&pool, "mono-test").await;
    let key = repo_key(&pool, repo_id).await;
    let state = build_state(pool.clone(), storage_path.to_str().unwrap());

    let data = test_data(1024 * 100); // 100 KB
    let expected_sha = sha256_hex(&data);

    let username: String = sqlx::query_scalar("SELECT username FROM users WHERE id = $1")
        .bind(user_id)
        .fetch_one(&pool)
        .await
        .unwrap();

    let app = incus::router().with_state(state);
    let req = Request::builder()
        .method("PUT")
        .uri(format!("/{}/images/ubuntu/24.04/rootfs.tar.xz", key))
        .header("Authorization", basic_auth_header(&username, "testpass123"))
        .body(Body::from(data.clone()))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    let status = resp.status();
    let body = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let body_str = String::from_utf8_lossy(&body);
    assert_eq!(
        status,
        StatusCode::CREATED,
        "monolithic upload should return 201, got: {}",
        body_str
    );

    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

    assert_eq!(json["sha256"].as_str().unwrap(), expected_sha);
    assert_eq!(json["size"].as_i64().unwrap(), 1024 * 100);

    // Verify artifact in DB
    let artifact = sqlx::query("SELECT size_bytes, checksum_sha256, content_type FROM artifacts WHERE repository_id = $1 AND path = 'ubuntu/24.04/rootfs.tar.xz'")
        .bind(repo_id)
        .fetch_one(&pool)
        .await
        .expect("artifact should exist in DB");
    assert_eq!(artifact.get::<i64, _>("size_bytes"), 1024 * 100);
    assert_eq!(artifact.get::<String, _>("checksum_sha256"), expected_sha);
    assert_eq!(
        artifact.get::<String, _>("content_type"),
        "application/x-xz"
    );

    // Cleanup
    let _ = std::fs::remove_dir_all(&storage_path);
    cleanup(&pool, repo_id, user_id).await;
}

// ===========================================================================
// 2. Chunked upload happy path — POST → 3x PATCH → PUT finalize
// ===========================================================================

#[tokio::test]
#[ignore]
async fn test_chunked_upload_happy_path() {
    let pool = PgPool::connect(&std::env::var("DATABASE_URL").unwrap())
        .await
        .unwrap();
    let username = format!("incus-chunk-{}", &Uuid::new_v4().to_string()[..8]);
    let user_id = create_test_user(&pool, &username, "chunkpass").await;
    let (repo_id, storage_path) = create_incus_repo(&pool, "chunk-test").await;
    let key = repo_key(&pool, repo_id).await;
    let state = build_state(pool.clone(), storage_path.to_str().unwrap());

    // Generate 300 KB of test data, split into 3 chunks
    let full_data = test_data(1024 * 300);
    let expected_sha = sha256_hex(&full_data);
    let chunk1 = &full_data[..1024 * 100];
    let chunk2 = &full_data[1024 * 100..1024 * 200];
    let chunk3 = &full_data[1024 * 200..];

    let auth = basic_auth_header(&username, "chunkpass");

    // POST — start chunked upload (with first chunk as body)
    let app = incus::router().with_state(state.clone());
    let req = Request::builder()
        .method("POST")
        .uri(format!("/{}/images/debian/12/rootfs.tar.gz/uploads", key))
        .header("Authorization", &auth)
        .body(Body::from(chunk1.to_vec()))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::ACCEPTED,
        "POST start should return 202"
    );

    let body = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let session_id = json["session_id"].as_str().unwrap().to_string();
    assert_eq!(json["bytes_received"].as_i64().unwrap(), 1024 * 100);

    // PATCH — upload second chunk
    let app = incus::router().with_state(state.clone());
    let req = Request::builder()
        .method("PATCH")
        .uri(format!("/{}/uploads/{}", key, session_id))
        .header("Authorization", &auth)
        .body(Body::from(chunk2.to_vec()))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::ACCEPTED,
        "PATCH chunk2 should return 202"
    );

    // PATCH — upload third chunk
    let app = incus::router().with_state(state.clone());
    let req = Request::builder()
        .method("PATCH")
        .uri(format!("/{}/uploads/{}", key, session_id))
        .header("Authorization", &auth)
        .body(Body::from(chunk3.to_vec()))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::ACCEPTED,
        "PATCH chunk3 should return 202"
    );

    // PUT — complete upload
    let app = incus::router().with_state(state.clone());
    let req = Request::builder()
        .method("PUT")
        .uri(format!("/{}/uploads/{}", key, session_id))
        .header("Authorization", &auth)
        .header("X-Checksum-Sha256", &expected_sha)
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::CREATED,
        "PUT complete should return 201"
    );

    let body = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["sha256"].as_str().unwrap(), expected_sha);
    assert_eq!(json["size"].as_i64().unwrap(), 1024 * 300);

    // Verify artifact in DB
    let artifact = sqlx::query("SELECT size_bytes, checksum_sha256 FROM artifacts WHERE repository_id = $1 AND path = 'debian/12/rootfs.tar.gz'")
        .bind(repo_id)
        .fetch_one(&pool)
        .await
        .expect("chunked artifact should exist");
    assert_eq!(artifact.get::<i64, _>("size_bytes"), 1024 * 300);
    assert_eq!(artifact.get::<String, _>("checksum_sha256"), expected_sha);

    // Verify session is cleaned up
    let session_count: i64 =
        sqlx::query_scalar("SELECT count(*) FROM incus_upload_sessions WHERE id = $1::uuid")
            .bind(&session_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(
        session_count, 0,
        "session should be deleted after completion"
    );

    // Cleanup
    let _ = std::fs::remove_dir_all(&storage_path);
    cleanup(&pool, repo_id, user_id).await;
}

// ===========================================================================
// 3. Chunked upload with cancel — verify temp file + session cleaned up
// ===========================================================================

#[tokio::test]
#[ignore]
async fn test_chunked_upload_cancel() {
    let pool = PgPool::connect(&std::env::var("DATABASE_URL").unwrap())
        .await
        .unwrap();
    let username = format!("incus-cancel-{}", &Uuid::new_v4().to_string()[..8]);
    let user_id = create_test_user(&pool, &username, "cancelpass").await;
    let (repo_id, storage_path) = create_incus_repo(&pool, "cancel-test").await;
    let key = repo_key(&pool, repo_id).await;
    let state = build_state(pool.clone(), storage_path.to_str().unwrap());
    let auth = basic_auth_header(&username, "cancelpass");

    // POST — start upload with some data
    let app = incus::router().with_state(state.clone());
    let req = Request::builder()
        .method("POST")
        .uri(format!("/{}/images/alpine/3.19/rootfs.tar.xz/uploads", key))
        .header("Authorization", &auth)
        .body(Body::from(test_data(1024 * 50)))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::ACCEPTED);

    let body = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let session_id = json["session_id"].as_str().unwrap().to_string();

    // Verify temp file exists
    let session_row =
        sqlx::query("SELECT storage_temp_path FROM incus_upload_sessions WHERE id = $1::uuid")
            .bind(&session_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    let temp_path: String = session_row.get("storage_temp_path");
    assert!(
        std::path::Path::new(&temp_path).exists(),
        "temp file should exist before cancel"
    );

    // DELETE — cancel
    let app = incus::router().with_state(state.clone());
    let req = Request::builder()
        .method("DELETE")
        .uri(format!("/{}/uploads/{}", key, session_id))
        .header("Authorization", &auth)
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::NO_CONTENT,
        "cancel should return 204"
    );

    // Verify temp file is deleted
    assert!(
        !std::path::Path::new(&temp_path).exists(),
        "temp file should be deleted after cancel"
    );

    // Verify session is deleted
    let session_count: i64 =
        sqlx::query_scalar("SELECT count(*) FROM incus_upload_sessions WHERE id = $1::uuid")
            .bind(&session_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(session_count, 0, "session should be deleted after cancel");

    // Cleanup
    let _ = std::fs::remove_dir_all(&storage_path);
    cleanup(&pool, repo_id, user_id).await;
}

// ===========================================================================
// 4. Upload progress check — POST → PATCH → GET progress
// ===========================================================================

#[tokio::test]
#[ignore]
async fn test_upload_progress_check() {
    let pool = PgPool::connect(&std::env::var("DATABASE_URL").unwrap())
        .await
        .unwrap();
    let username = format!("incus-prog-{}", &Uuid::new_v4().to_string()[..8]);
    let user_id = create_test_user(&pool, &username, "progpass").await;
    let (repo_id, storage_path) = create_incus_repo(&pool, "progress-test").await;
    let key = repo_key(&pool, repo_id).await;
    let state = build_state(pool.clone(), storage_path.to_str().unwrap());
    let auth = basic_auth_header(&username, "progpass");

    // POST — start with 10 KB
    let app = incus::router().with_state(state.clone());
    let req = Request::builder()
        .method("POST")
        .uri(format!("/{}/images/centos/9/rootfs.tar.xz/uploads", key))
        .header("Authorization", &auth)
        .body(Body::from(test_data(1024 * 10)))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    let body = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let session_id = json["session_id"].as_str().unwrap().to_string();

    // PATCH — add 20 KB
    let app = incus::router().with_state(state.clone());
    let req = Request::builder()
        .method("PATCH")
        .uri(format!("/{}/uploads/{}", key, session_id))
        .header("Authorization", &auth)
        .body(Body::from(test_data(1024 * 20)))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::ACCEPTED);

    // GET — check progress
    let app = incus::router().with_state(state.clone());
    let req = Request::builder()
        .method("GET")
        .uri(format!("/{}/uploads/{}", key, session_id))
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "progress check should return 200"
    );

    let body = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(
        json["bytes_received"].as_i64().unwrap(),
        1024 * 30,
        "should show 30 KB received"
    );

    // Cleanup (cancel the session first)
    let app = incus::router().with_state(state.clone());
    let req = Request::builder()
        .method("DELETE")
        .uri(format!("/{}/uploads/{}", key, session_id))
        .header("Authorization", &auth)
        .body(Body::empty())
        .unwrap();
    let _ = app.oneshot(req).await;
    let _ = std::fs::remove_dir_all(&storage_path);
    cleanup(&pool, repo_id, user_id).await;
}

// ===========================================================================
// 5. Checksum mismatch rejection
// ===========================================================================

#[tokio::test]
#[ignore]
async fn test_checksum_mismatch_rejection() {
    let pool = PgPool::connect(&std::env::var("DATABASE_URL").unwrap())
        .await
        .unwrap();
    let username = format!("incus-cksum-{}", &Uuid::new_v4().to_string()[..8]);
    let user_id = create_test_user(&pool, &username, "cksumpass").await;
    let (repo_id, storage_path) = create_incus_repo(&pool, "checksum-test").await;
    let key = repo_key(&pool, repo_id).await;
    let state = build_state(pool.clone(), storage_path.to_str().unwrap());
    let auth = basic_auth_header(&username, "cksumpass");

    // POST — start upload
    let app = incus::router().with_state(state.clone());
    let req = Request::builder()
        .method("POST")
        .uri(format!("/{}/images/fedora/40/rootfs.tar.xz/uploads", key))
        .header("Authorization", &auth)
        .body(Body::from(test_data(1024 * 50)))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    let body = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let session_id = json["session_id"].as_str().unwrap().to_string();

    // Get the temp path before completion to verify cleanup
    let session_row =
        sqlx::query("SELECT storage_temp_path FROM incus_upload_sessions WHERE id = $1::uuid")
            .bind(&session_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    let temp_path: String = session_row.get("storage_temp_path");

    // PUT — complete with wrong checksum
    let app = incus::router().with_state(state.clone());
    let req = Request::builder()
        .method("PUT")
        .uri(format!("/{}/uploads/{}", key, session_id))
        .header("Authorization", &auth)
        .header(
            "X-Checksum-Sha256",
            "0000000000000000000000000000000000000000000000000000000000000000",
        )
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::BAD_REQUEST,
        "wrong checksum should return 400"
    );

    // Verify temp file is cleaned up
    assert!(
        !std::path::Path::new(&temp_path).exists(),
        "temp file should be deleted on checksum mismatch"
    );

    // Verify session is cleaned up
    let session_count: i64 =
        sqlx::query_scalar("SELECT count(*) FROM incus_upload_sessions WHERE id = $1::uuid")
            .bind(&session_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(
        session_count, 0,
        "session should be deleted on checksum mismatch"
    );

    // Cleanup
    let _ = std::fs::remove_dir_all(&storage_path);
    cleanup(&pool, repo_id, user_id).await;
}

// ===========================================================================
// 6. Resume after partial upload — start → chunk → GET progress → more → complete
// ===========================================================================

#[tokio::test]
#[ignore]
async fn test_resume_after_partial_upload() {
    let pool = PgPool::connect(&std::env::var("DATABASE_URL").unwrap())
        .await
        .unwrap();
    let username = format!("incus-resume-{}", &Uuid::new_v4().to_string()[..8]);
    let user_id = create_test_user(&pool, &username, "resumepass").await;
    let (repo_id, storage_path) = create_incus_repo(&pool, "resume-test").await;
    let key = repo_key(&pool, repo_id).await;
    let state = build_state(pool.clone(), storage_path.to_str().unwrap());
    let auth = basic_auth_header(&username, "resumepass");

    let full_data = test_data(1024 * 200);
    let expected_sha = sha256_hex(&full_data);

    // POST — start with first 80 KB
    let app = incus::router().with_state(state.clone());
    let req = Request::builder()
        .method("POST")
        .uri(format!("/{}/images/arch/2024/rootfs.tar.xz/uploads", key))
        .header("Authorization", &auth)
        .body(Body::from(full_data[..1024 * 80].to_vec()))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    let body = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let session_id = json["session_id"].as_str().unwrap().to_string();

    // GET — check progress to simulate resume
    let app = incus::router().with_state(state.clone());
    let req = Request::builder()
        .method("GET")
        .uri(format!("/{}/uploads/{}", key, session_id))
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    let body = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let progress: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let received = progress["bytes_received"].as_i64().unwrap() as usize;
    assert_eq!(received, 1024 * 80, "should have received 80 KB");

    // PATCH — resume with remaining data
    let app = incus::router().with_state(state.clone());
    let req = Request::builder()
        .method("PATCH")
        .uri(format!("/{}/uploads/{}", key, session_id))
        .header("Authorization", &auth)
        .body(Body::from(full_data[received..].to_vec()))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::ACCEPTED);

    // PUT — complete with checksum verification
    let app = incus::router().with_state(state.clone());
    let req = Request::builder()
        .method("PUT")
        .uri(format!("/{}/uploads/{}", key, session_id))
        .header("Authorization", &auth)
        .header("X-Checksum-Sha256", &expected_sha)
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::CREATED,
        "resume + complete should return 201"
    );

    let body = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["size"].as_i64().unwrap(), 1024 * 200);
    assert_eq!(json["sha256"].as_str().unwrap(), expected_sha);

    // Cleanup
    let _ = std::fs::remove_dir_all(&storage_path);
    cleanup(&pool, repo_id, user_id).await;
}

// ===========================================================================
// 7. Duplicate upload (upsert) — upload same path twice, verify only one record
// ===========================================================================

#[tokio::test]
#[ignore]
async fn test_duplicate_upload_upserts() {
    let pool = PgPool::connect(&std::env::var("DATABASE_URL").unwrap())
        .await
        .unwrap();
    let username = format!("incus-dup-{}", &Uuid::new_v4().to_string()[..8]);
    let user_id = create_test_user(&pool, &username, "duppass").await;
    let (repo_id, storage_path) = create_incus_repo(&pool, "dup-test").await;
    let key = repo_key(&pool, repo_id).await;
    let state = build_state(pool.clone(), storage_path.to_str().unwrap());
    let auth = basic_auth_header(&username, "duppass");

    // First upload — 50 KB
    let data1 = test_data(1024 * 50);
    let sha1 = sha256_hex(&data1);
    let app = incus::router().with_state(state.clone());
    let req = Request::builder()
        .method("PUT")
        .uri(format!("/{}/images/ubuntu/22.04/rootfs.tar.xz", key))
        .header("Authorization", &auth)
        .body(Body::from(data1))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);

    // Second upload — 75 KB to same path (different content)
    let data2: Vec<u8> = (0..1024 * 75).map(|i| ((i + 7) % 251) as u8).collect();
    let sha2 = sha256_hex(&data2);
    let app = incus::router().with_state(state.clone());
    let req = Request::builder()
        .method("PUT")
        .uri(format!("/{}/images/ubuntu/22.04/rootfs.tar.xz", key))
        .header("Authorization", &auth)
        .body(Body::from(data2))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);

    // Verify only one artifact record exists
    let count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM artifacts WHERE repository_id = $1 AND path = 'ubuntu/22.04/rootfs.tar.xz'",
    )
    .bind(repo_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(
        count, 1,
        "should have exactly one artifact record after upsert"
    );

    // Verify the artifact has the second upload's data
    let artifact = sqlx::query("SELECT size_bytes, checksum_sha256 FROM artifacts WHERE repository_id = $1 AND path = 'ubuntu/22.04/rootfs.tar.xz'")
        .bind(repo_id)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(artifact.get::<i64, _>("size_bytes"), 1024 * 75);
    assert_eq!(artifact.get::<String, _>("checksum_sha256"), sha2);
    assert_ne!(sha1, sha2, "sanity check: checksums should differ");

    // Cleanup
    let _ = std::fs::remove_dir_all(&storage_path);
    cleanup(&pool, repo_id, user_id).await;
}

// ===========================================================================
// 8. Stale session cleanup — create, backdate, cleanup, verify removed
// ===========================================================================

#[tokio::test]
#[ignore]
async fn test_stale_session_cleanup() {
    let pool = PgPool::connect(&std::env::var("DATABASE_URL").unwrap())
        .await
        .unwrap();
    let username = format!("incus-stale-{}", &Uuid::new_v4().to_string()[..8]);
    let user_id = create_test_user(&pool, &username, "stalepass").await;
    let (repo_id, storage_path) = create_incus_repo(&pool, "stale-test").await;
    let key = repo_key(&pool, repo_id).await;
    let state = build_state(pool.clone(), storage_path.to_str().unwrap());
    let auth = basic_auth_header(&username, "stalepass");

    // POST — start an upload session
    let app = incus::router().with_state(state.clone());
    let req = Request::builder()
        .method("POST")
        .uri(format!("/{}/images/void/latest/rootfs.tar.xz/uploads", key))
        .header("Authorization", &auth)
        .body(Body::from(test_data(1024 * 10)))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::ACCEPTED);

    let body = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let session_id = json["session_id"].as_str().unwrap().to_string();

    // Get temp file path
    let session_row =
        sqlx::query("SELECT storage_temp_path FROM incus_upload_sessions WHERE id = $1::uuid")
            .bind(&session_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    let temp_path: String = session_row.get("storage_temp_path");
    assert!(
        std::path::Path::new(&temp_path).exists(),
        "temp file should exist"
    );

    // Backdate the session to 25 hours ago (stale)
    sqlx::query("UPDATE incus_upload_sessions SET updated_at = NOW() - INTERVAL '25 hours' WHERE id = $1::uuid")
        .bind(&session_id)
        .execute(&pool)
        .await
        .unwrap();

    // Run cleanup (24-hour threshold)
    let cleaned = incus::cleanup_stale_sessions(&pool, 24).await.unwrap();
    assert!(cleaned >= 1, "should have cleaned at least 1 stale session");

    // Verify session is gone
    let session_count: i64 =
        sqlx::query_scalar("SELECT count(*) FROM incus_upload_sessions WHERE id = $1::uuid")
            .bind(&session_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(session_count, 0, "stale session should be deleted");

    // Verify temp file is gone
    assert!(
        !std::path::Path::new(&temp_path).exists(),
        "temp file should be deleted by cleanup"
    );

    // Cleanup
    let _ = std::fs::remove_dir_all(&storage_path);
    cleanup(&pool, repo_id, user_id).await;
}
