//! Conan error-path integration tests for issue #990.
//!
//! Validates that the Conan v2 handler returns the expected HTTP status
//! codes for the three pre-existing gaps surfaced by `test-conan-errors.sh`:
//!
//! 1. PUT to a non-existent repository must return 404 (not 500).
//! 2. GET /v2/ping on a non-existent repository must return 404 (not 200).
//! 3. PUT with a 300-char path segment must return a 4xx (not 500).
//!
//! These tests require a PostgreSQL database with all migrations applied.
//! Run with:
//!
//! ```sh
//! DATABASE_URL="postgresql://registry:registry@localhost:30432/artifact_registry" \
//!   cargo test --test conan_error_paths_tests -- --ignored
//! ```

use std::path::PathBuf;
use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use sqlx::PgPool;
use tower::ServiceExt;
use uuid::Uuid;

use artifact_keeper_backend::api::handlers::conan;
use artifact_keeper_backend::api::{AppState, SharedState};
use artifact_keeper_backend::config::Config;

// ===========================================================================
// Test helpers (mirrors incus_upload_tests.rs)
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
        allow_local_admin_login: false,
        max_upload_size_bytes: 10_737_418_240,
        proxy_max_concurrent_fetches: 20,
        proxy_max_artifact_size_bytes: 2_147_483_648,
        proxy_queue_timeout_secs: 30,
        metrics_port: None,
        rate_limit_exempt_usernames: Vec::new(),
        rate_limit_exempt_service_accounts: false,
    }
}

fn basic_auth_header(username: &str, password: &str) -> String {
    use base64::Engine;
    let encoded =
        base64::engine::general_purpose::STANDARD.encode(format!("{}:{}", username, password));
    format!("Basic {}", encoded)
}

async fn connect_pool() -> PgPool {
    PgPool::connect(&std::env::var("DATABASE_URL").unwrap())
        .await
        .unwrap()
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

async fn create_conan_repo(pool: &PgPool, name: &str) -> (Uuid, String, PathBuf) {
    let id = Uuid::new_v4();
    let key = format!("conan-err-{}", &id.to_string()[..8]);
    let storage_path = std::env::temp_dir().join(format!("conan-err-{}", id));
    std::fs::create_dir_all(&storage_path).expect("create storage dir");

    sqlx::query(
        "INSERT INTO repositories (id, key, name, storage_path, repo_type, format) \
         VALUES ($1, $2, $3, $4, 'local', 'conan')",
    )
    .bind(id)
    .bind(&key)
    .bind(name)
    .bind(storage_path.to_string_lossy().as_ref())
    .execute(pool)
    .await
    .expect("failed to create conan repository");

    (id, key, storage_path)
}

async fn cleanup(pool: &PgPool, repo_id: Uuid, user_id: Uuid) {
    let _ = sqlx::query(
        "DELETE FROM artifact_metadata WHERE artifact_id IN \
         (SELECT id FROM artifacts WHERE repository_id = $1)",
    )
    .bind(repo_id)
    .execute(pool)
    .await;
    let _ = sqlx::query("DELETE FROM artifacts WHERE repository_id = $1")
        .bind(repo_id)
        .execute(pool)
        .await;
    let _ = sqlx::query("DELETE FROM repositories WHERE id = $1")
        .bind(repo_id)
        .execute(pool)
        .await;
    let _ = sqlx::query("DELETE FROM users WHERE id = $1")
        .bind(user_id)
        .execute(pool)
        .await;
}

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

// ===========================================================================
// 1. PUT to a non-existent repo returns 404 (issue #990, sub-test #7)
// ===========================================================================

#[tokio::test]
#[ignore]
async fn test_990_upload_to_nonexistent_repo_returns_404() {
    let pool = connect_pool().await;
    let username = format!("conan-err-u-{}", &Uuid::new_v4().to_string()[..8]);
    let user_id = create_test_user(&pool, &username, "errpass").await;
    let storage_path = std::env::temp_dir().join("conan-err-bogus-upload");
    std::fs::create_dir_all(&storage_path).ok();
    let state = build_state(pool.clone(), storage_path.to_str().unwrap());

    let bogus_repo = format!("bogus-conan-{}", &Uuid::new_v4().to_string()[..8]);
    let app = conan::router().with_state(state);

    let req = Request::builder()
        .method("PUT")
        .uri(format!(
            "/{}/v2/conans/pkg/1.0.0/_/_/revisions/dead/files/conanfile.py",
            bogus_repo
        ))
        .header("Authorization", basic_auth_header(&username, "errpass"))
        .header("Content-Type", "application/octet-stream")
        .body(Body::from("dummy content".as_bytes().to_vec()))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    let status = resp.status();
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "PUT to a non-existent repo must return 404, not {}",
        status.as_u16()
    );

    let _ = std::fs::remove_dir_all(&storage_path);
    let _ = sqlx::query("DELETE FROM users WHERE id = $1")
        .bind(user_id)
        .execute(&pool)
        .await;
}

// ===========================================================================
// 2. GET /v2/ping on a non-existent repo returns 404 (issue #990, sub-test #12)
// ===========================================================================

#[tokio::test]
#[ignore]
async fn test_990_ping_on_nonexistent_repo_returns_404() {
    let pool = connect_pool().await;
    let storage_path = std::env::temp_dir().join("conan-err-bogus-ping");
    std::fs::create_dir_all(&storage_path).ok();
    let state = build_state(pool.clone(), storage_path.to_str().unwrap());

    let bogus_repo = format!("bogus-conan-{}", &Uuid::new_v4().to_string()[..8]);
    let app = conan::router().with_state(state);

    let req = Request::builder()
        .method("GET")
        .uri(format!("/{}/v2/ping", bogus_repo))
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    let status = resp.status();
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "GET /v2/ping on a non-existent repo must return 404, not {}",
        status.as_u16()
    );

    let _ = std::fs::remove_dir_all(&storage_path);
}

// ===========================================================================
// 2b. GET /v2/ping on an EXISTING repo still returns 200
// ===========================================================================

#[tokio::test]
#[ignore]
async fn test_990_ping_on_existing_repo_returns_200() {
    let pool = connect_pool().await;
    let user_id = create_test_user(
        &pool,
        &format!("conan-ping-u-{}", &Uuid::new_v4().to_string()[..8]),
        "pingpass",
    )
    .await;
    let (repo_id, key, storage_path) = create_conan_repo(&pool, "conan-ping-test").await;
    let state = build_state(pool.clone(), storage_path.to_str().unwrap());

    let app = conan::router().with_state(state);
    let req = Request::builder()
        .method("GET")
        .uri(format!("/{}/v2/ping", key))
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    let status = resp.status();
    let caps = resp
        .headers()
        .get("X-Conan-Server-Capabilities")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    assert_eq!(
        status,
        StatusCode::OK,
        "GET /v2/ping on an existing repo must return 200"
    );
    assert!(
        caps.contains("revisions"),
        "X-Conan-Server-Capabilities must advertise 'revisions', got '{}'",
        caps
    );

    let _ = std::fs::remove_dir_all(&storage_path);
    cleanup(&pool, repo_id, user_id).await;
}

// ===========================================================================
// 3. PUT with a 300-char path segment returns a 4xx (issue #990, sub-test #15)
// ===========================================================================

#[tokio::test]
#[ignore]
async fn test_990_long_path_segment_returns_4xx() {
    let pool = connect_pool().await;
    let username = format!("conan-long-u-{}", &Uuid::new_v4().to_string()[..8]);
    let user_id = create_test_user(&pool, &username, "longpass").await;
    let (repo_id, key, storage_path) = create_conan_repo(&pool, "conan-long-test").await;
    let state = build_state(pool.clone(), storage_path.to_str().unwrap());

    let long_name: String = "a".repeat(300);
    let app = conan::router().with_state(state);

    let req = Request::builder()
        .method("PUT")
        .uri(format!(
            "/{}/v2/conans/{}/1.0.0/_/_/revisions/rev/files/conanfile.py",
            key, long_name
        ))
        .header("Authorization", basic_auth_header(&username, "longpass"))
        .header("Content-Type", "application/octet-stream")
        .body(Body::from("dummy".as_bytes().to_vec()))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    let status = resp.status();
    assert!(
        status.is_client_error(),
        "PUT with a 300-char path segment must return 4xx, not {}",
        status.as_u16()
    );
    // We specifically choose 414 URI Too Long, but the contract only requires
    // a structured 4xx (no opaque 500).
    assert_ne!(
        status,
        StatusCode::INTERNAL_SERVER_ERROR,
        "must not surface filesystem ENAMETOOLONG as a 500"
    );

    let _ = std::fs::remove_dir_all(&storage_path);
    cleanup(&pool, repo_id, user_id).await;
}
