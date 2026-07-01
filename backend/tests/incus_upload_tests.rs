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
use artifact_keeper_backend::api::middleware::auth::optional_auth_middleware;
use artifact_keeper_backend::api::{AppState, SharedState};
use artifact_keeper_backend::config::Config;
use artifact_keeper_backend::services::auth_service::AuthService;

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
        gcs_bucket: None,
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
        trivy_adapter_url: None,
        scan_token_ttl_seconds: 300,
        openscap_url: None,
        openscap_profile: "standard".into(),
        opensearch_url: None,
        opensearch_username: None,
        opensearch_password: None,
        opensearch_allow_invalid_certs: false,
        scan_workspace_path: "/tmp/scan".into(),
        demo_mode: false,
        guest_access_enabled: true,
        plugins_require_signed: true,
        plugins_trusted_pubkey: None,
        peer_instance_name: "test".into(),
        peer_public_endpoint: "http://localhost:8080".into(),
        peer_api_key: "test-key".into(),
        dependency_track_url: None,
        dependency_track_enabled: false,
        otel_exporter_otlp_endpoint: None,
        otel_service_name: "test".into(),
        gc_schedule: "0 0 * * * *".into(),
        blob_gc_enabled: false,
        lifecycle_check_interval_secs: 60,
        stuck_scan_threshold_secs: 1800,
        stuck_scan_check_interval_secs: 600,
        stuck_scan_reap_limit: 1000,
        allow_local_admin_login: false,
        max_upload_size_bytes: 10_737_418_240,
        metrics_port: None,
        database_max_connections: 20,
        database_min_connections: 5,
        database_acquire_timeout_secs: 30,
        database_idle_timeout_secs: 600,
        database_max_lifetime_secs: 1800,
        auth_max_concurrency: 8,
        global_max_concurrency: 512,
        global_request_timeout_secs: 120,
        rate_limit_enabled: true,
        rate_limit_auth_per_window: 120,
        rate_limit_api_per_window: 5000,
        rate_limit_search_per_window: 300,
        rate_limit_presign_per_window: 30,
        rate_limit_password_change_per_window: 5,
        rate_limit_password_change_window_secs: 900,
        rate_limit_login_global_per_window: 8192,
        rate_limit_window_secs: 60,
        rate_limit_exempt_usernames: Vec::new(),
        rate_limit_exempt_service_accounts: false,
        rate_limit_trusted_cidrs: Vec::new(),
        rate_limit_trusted_proxy_cidrs: Vec::new(),
        account_lockout_threshold: 5,
        account_lockout_duration_minutes: 30,
        quarantine_enabled: false,
        quarantine_duration_minutes: 60,
        password_history_count: 0,
        password_expiry_days: 0,
        password_expiry_warning_days: vec![14, 7, 1],
        password_expiry_check_interval_secs: 3600,
        password_min_length: 8,
        password_max_length: 128,
        password_require_uppercase: false,
        password_require_lowercase: false,
        password_require_digit: false,
        password_require_special: false,
        password_min_strength: 0,
        presigned_downloads_enabled: false,
        presigned_download_expiry_secs: 300,
        smtp_host: None,
        smtp_port: 587,
        smtp_username: None,
        smtp_password: None,
        smtp_from_address: "noreply@artifact-keeper.local".to_string(),
        smtp_tls_mode: "starttls".to_string(),
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

/// Build the `AuthService` used by the optional-auth middleware so the routers
/// resolve the `Authorization: Basic ...` header into an `AuthExtension`
/// exactly as they do in production. Without this layer the handlers'
/// mandatory `Extension<Option<AuthExtension>>` extractor is missing and every
/// request 500s ("Missing request extension").
fn auth_service(state: &SharedState, storage_path: &str) -> Arc<AuthService> {
    Arc::new(AuthService::new(
        state.db.clone(),
        Arc::new(test_config(storage_path)),
    ))
}

/// Build a SharedState for the incus router.
fn build_state(pool: PgPool, storage_path: &str) -> SharedState {
    let storage: std::sync::Arc<dyn artifact_keeper_backend::storage::StorageBackend> =
        std::sync::Arc::new(
            artifact_keeper_backend::storage::filesystem::FilesystemStorage::new(storage_path),
        );
    let registry = Arc::new(artifact_keeper_backend::storage::StorageRegistry::new(
        std::collections::HashMap::new(),
        "filesystem".to_string(),
    ));
    Arc::new(AppState::new(
        test_config(storage_path),
        pool,
        storage,
        registry,
    ))
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

/// Poll `GET /{key}/uploads/{id}` until the async finalize reaches a terminal
/// status, returning the final progress JSON. Panics on timeout. Monolithic
/// PUT and chunked `complete` now return 202 and finalize on a background
/// task, so artifact-row / download assertions must wait for this first.
async fn await_finalize(state: &SharedState, key: &str, session_id: &str) -> serde_json::Value {
    for _ in 0..400 {
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
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        match json["status"].as_str() {
            Some("completed") | Some("failed") => return json,
            _ => tokio::time::sleep(std::time::Duration::from_millis(25)).await,
        }
    }
    panic!("finalize did not reach a terminal status in time");
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

    let app = incus::router().with_state(state.clone());
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
        StatusCode::ACCEPTED,
        "monolithic upload should return 202 (async finalize), got: {}",
        body_str
    );

    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

    assert_eq!(json["sha256"].as_str().unwrap(), expected_sha);
    assert_eq!(json["size"].as_i64().unwrap(), 1024 * 100);
    let session_id = json["session_id"].as_str().unwrap().to_string();

    // Wait for the background finalize before asserting durable state.
    let progress = await_finalize(&state, &key, &session_id).await;
    assert_eq!(progress["status"].as_str(), Some("completed"));

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
        StatusCode::ACCEPTED,
        "PUT complete should return 202 (async finalize)"
    );

    let body = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["sha256"].as_str().unwrap(), expected_sha);
    assert_eq!(json["size"].as_i64().unwrap(), 1024 * 300);

    // Wait for the background finalize.
    let progress = await_finalize(&state, &key, &session_id).await;
    assert_eq!(progress["status"].as_str(), Some("completed"));

    // Verify artifact in DB
    let artifact = sqlx::query("SELECT size_bytes, checksum_sha256 FROM artifacts WHERE repository_id = $1 AND path = 'debian/12/rootfs.tar.gz'")
        .bind(repo_id)
        .fetch_one(&pool)
        .await
        .expect("chunked artifact should exist");
    assert_eq!(artifact.get::<i64, _>("size_bytes"), 1024 * 300);
    assert_eq!(artifact.get::<String, _>("checksum_sha256"), expected_sha);

    // The session row is now retained (status='completed') for polling, not
    // deleted on completion; the stale-session reaper removes it later.
    let session_status: String =
        sqlx::query_scalar("SELECT status FROM incus_upload_sessions WHERE id = $1::uuid")
            .bind(&session_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(
        session_status, "completed",
        "session should be retained as completed after finalize"
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
        StatusCode::ACCEPTED,
        "resume + complete should return 202 (async finalize)"
    );

    let body = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["size"].as_i64().unwrap(), 1024 * 200);
    assert_eq!(json["sha256"].as_str().unwrap(), expected_sha);

    let progress = await_finalize(&state, &key, &session_id).await;
    assert_eq!(progress["status"].as_str(), Some("completed"));

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
    assert_eq!(resp.status(), StatusCode::ACCEPTED);
    let body = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let session1 = serde_json::from_slice::<serde_json::Value>(&body).unwrap()["session_id"]
        .as_str()
        .unwrap()
        .to_string();
    let progress = await_finalize(&state, &key, &session1).await;
    assert_eq!(progress["status"].as_str(), Some("completed"));

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
    assert_eq!(resp.status(), StatusCode::ACCEPTED);
    let body = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let session2 = serde_json::from_slice::<serde_json::Value>(&body).unwrap()["session_id"]
        .as_str()
        .unwrap()
        .to_string();
    let progress = await_finalize(&state, &key, &session2).await;
    assert_eq!(progress["status"].as_str(), Some("completed"));

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

// ===========================================================================
// Issue #1317 regression: cross-repo session use is rejected.
//
// Reproduce: a user creates an upload session under repo A, then attempts to
// chunk, finalize, cancel, or read progress under repo B's URL using A's
// session_id. All four operations must return 404 (we deliberately use the
// same status as "session does not exist" to avoid leaking session existence
// across repos).
// ===========================================================================

#[tokio::test]
#[ignore]
async fn test_chunked_upload_cross_repo_session_rejected() {
    let pool = PgPool::connect(&std::env::var("DATABASE_URL").unwrap())
        .await
        .unwrap();
    let username = format!("incus-1317-{}", &Uuid::new_v4().to_string()[..8]);
    let user_id = create_test_user(&pool, &username, "crosspass").await;
    let (repo_a_id, storage_path) = create_incus_repo(&pool, "1317-repo-a").await;
    let (repo_b_id, _storage_path_b) = create_incus_repo(&pool, "1317-repo-b").await;
    let key_a = repo_key(&pool, repo_a_id).await;
    let key_b = repo_key(&pool, repo_b_id).await;
    let state = build_state(pool.clone(), storage_path.to_str().unwrap());
    let auth_svc = auth_service(&state, storage_path.to_str().unwrap());
    let auth = basic_auth_header(&username, "crosspass");

    let make_app = || {
        incus::router()
            .layer(axum::middleware::from_fn_with_state(
                auth_svc.clone(),
                optional_auth_middleware,
            ))
            .with_state(state.clone())
    };

    // POST start under repo A.
    let req = Request::builder()
        .method("POST")
        .uri(format!(
            "/{}/images/alpine/3.20/rootfs.tar.gz/uploads",
            key_a
        ))
        .header("Authorization", &auth)
        .body(Body::from(test_data(1024)))
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
        "POST start should return 202: {}",
        body_str
    );
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let session_id = json["session_id"].as_str().unwrap().to_string();

    // Sanity check: PATCH under repo A succeeds.
    let req = Request::builder()
        .method("PATCH")
        .uri(format!("/{}/uploads/{}", key_a, session_id))
        .header("Authorization", &auth)
        .body(Body::from(test_data(512)))
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

    // Attack: PATCH the same session under repo B's URL. Must be rejected.
    let req = Request::builder()
        .method("PATCH")
        .uri(format!("/{}/uploads/{}", key_b, session_id))
        .header("Authorization", &auth)
        .body(Body::from(test_data(512)))
        .unwrap();
    let resp = make_app().oneshot(req).await.unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::NOT_FOUND,
        "PATCH chunk under wrong repo must be 404 (issue #1317)"
    );

    // Attack: GET progress under repo B. Must be rejected.
    let req = Request::builder()
        .method("GET")
        .uri(format!("/{}/uploads/{}", key_b, session_id))
        .header("Authorization", &auth)
        .body(Body::empty())
        .unwrap();
    let resp = make_app().oneshot(req).await.unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::NOT_FOUND,
        "GET progress under wrong repo must be 404 (issue #1317)"
    );

    // Attack: PUT complete under repo B. Must be rejected.
    let req = Request::builder()
        .method("PUT")
        .uri(format!("/{}/uploads/{}", key_b, session_id))
        .header("Authorization", &auth)
        .body(Body::empty())
        .unwrap();
    let resp = make_app().oneshot(req).await.unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::NOT_FOUND,
        "PUT complete under wrong repo must be 404 (issue #1317)"
    );

    // Attack: DELETE cancel under repo B. Must be rejected.
    let req = Request::builder()
        .method("DELETE")
        .uri(format!("/{}/uploads/{}", key_b, session_id))
        .header("Authorization", &auth)
        .body(Body::empty())
        .unwrap();
    let resp = make_app().oneshot(req).await.unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::NOT_FOUND,
        "DELETE cancel under wrong repo must be 404 (issue #1317)"
    );

    // Session must still exist under repo A (the cross-repo attempts must
    // not have side-effected the original session row).
    let session_count: i64 =
        sqlx::query_scalar("SELECT count(*) FROM incus_upload_sessions WHERE id = $1::uuid")
            .bind(&session_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(
        session_count, 1,
        "cross-repo attempts must not delete the legitimate session"
    );

    // Legitimate cancel under repo A still works.
    let req = Request::builder()
        .method("DELETE")
        .uri(format!("/{}/uploads/{}", key_a, session_id))
        .header("Authorization", &auth)
        .body(Body::empty())
        .unwrap();
    let resp = make_app().oneshot(req).await.unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::NO_CONTENT,
        "legitimate cancel under owning repo should succeed"
    );

    // Cleanup
    let _ = std::fs::remove_dir_all(&storage_path);
    cleanup(&pool, repo_a_id, user_id).await;
    sqlx::query("DELETE FROM repositories WHERE id = $1")
        .bind(repo_b_id)
        .execute(&pool)
        .await
        .ok();
}

// ===========================================================================
// Range support on download (#1847)
//
// The incus image download previously ignored HTTP `Range` and always returned
// a full `200`, so a dropped multi-GiB transfer could never resume. It now
// routes through the same range-aware streaming helper as the generic artifact
// download: a `200` advertises `Accept-Ranges: bytes`, a satisfiable range
// returns `206` + `Content-Range` + the sliced body, and an unsatisfiable range
// returns `416`.
// ===========================================================================

#[tokio::test]
#[ignore]
async fn test_incus_download_honours_range() {
    let pool = PgPool::connect(&std::env::var("DATABASE_URL").unwrap())
        .await
        .unwrap();
    let username = format!("incus-range-{}", &Uuid::new_v4().to_string()[..8]);
    let user_id = create_test_user(&pool, &username, "testpass123").await;
    let (repo_id, storage_path) = create_incus_repo(&pool, "range-test").await;
    let key = repo_key(&pool, repo_id).await;
    let state = build_state(pool.clone(), storage_path.to_str().unwrap());

    let data = test_data(4096);
    let sha = sha256_hex(&data);

    // Stage the artifact directly (row + stored bytes) so the test isolates the
    // *download* path rather than exercising the async upload/finalize flow.
    let repo =
        artifact_keeper_backend::services::repository_service::RepositoryService::new(pool.clone())
            .get_by_id(repo_id)
            .await
            .unwrap();
    let storage = state.storage_for_repo(&repo.storage_location()).unwrap();
    let storage_key = format!("range-test/{}", Uuid::new_v4());
    storage
        .put(&storage_key, bytes::Bytes::from(data.clone()))
        .await
        .unwrap();
    sqlx::query(
        "INSERT INTO artifacts (repository_id, path, name, version, size_bytes, checksum_sha256, content_type, storage_key, uploaded_by) \
         VALUES ($1, 'ubuntu/24.04/rootfs.tar.xz', 'rootfs', '24.04', $2, $3, 'application/x-xz', $4, $5)",
    )
    .bind(repo_id)
    .bind(data.len() as i64)
    .bind(&sha)
    .bind(&storage_key)
    .bind(user_id)
    .execute(&pool)
    .await
    .expect("insert artifact row");

    let dl_uri = format!("/{}/images/ubuntu/24.04/rootfs.tar.xz", key);

    // (a) No Range -> 200 and Accept-Ranges advertised (regression: was absent).
    let resp = incus::router()
        .with_state(state.clone())
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(&dl_uri)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(
        resp.headers()
            .get("accept-ranges")
            .and_then(|v| v.to_str().ok()),
        Some("bytes"),
        "200 response must advertise Accept-Ranges: bytes"
    );

    // (b) bytes=0-1023 -> 206, Content-Range, and exactly the first 1024 bytes.
    let resp = incus::router()
        .with_state(state.clone())
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(&dl_uri)
                .header("Range", "bytes=0-1023")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::PARTIAL_CONTENT,
        "ranged GET must return 206 Partial Content"
    );
    assert_eq!(
        resp.headers()
            .get("content-range")
            .and_then(|v| v.to_str().ok()),
        Some("bytes 0-1023/4096")
    );
    let part = axum::body::to_bytes(resp.into_body(), 1 << 20)
        .await
        .unwrap();
    assert_eq!(part.len(), 1024);
    assert_eq!(&part[..], &data[0..1024]);

    // (c) Unsatisfiable range -> 416 + Content-Range: bytes */<total>.
    let resp = incus::router()
        .with_state(state.clone())
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(&dl_uri)
                .header("Range", "bytes=999999-")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::RANGE_NOT_SATISFIABLE);
    assert_eq!(
        resp.headers()
            .get("content-range")
            .and_then(|v| v.to_str().ok()),
        Some("bytes */4096")
    );

    let _ = std::fs::remove_dir_all(&storage_path);
    cleanup(&pool, repo_id, user_id).await;
}
