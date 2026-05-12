//! Conan error-path and middleware integration tests.
//!
//! Covers two related concerns surfaced under issues #990, #1045, and #1046:
//!
//! Error-path coverage (#990, #1045): validates that the Conan v2 handler
//! returns the expected HTTP status codes for the three pre-existing gaps
//! surfaced by `test-conan-errors.sh`:
//!
//! 1. PUT to a non-existent repository must return 404 (not 500).
//! 2. GET /v2/ping on a non-existent repository must return 404 (not 200).
//! 3. PUT with a 300-char path segment must return a 4xx (not 500).
//!
//! Middleware integration coverage (#1046): builds the production composition
//! (`/conan` nested under `repo_visibility_middleware`) and pins the
//! auth/visibility behavior so silent regressions in either layer are caught:
//!
//! 4. Unknown repo with no auth returns 404.
//! 5. Private repo with no auth returns 401.
//! 6. Private repo with valid auth runs the handler (no 401).
//! 7. Public repo with no auth runs the handler (no 401).
//!
//! These tests require a PostgreSQL database with all migrations applied:
//!
//! ```sh
//! DATABASE_URL="postgresql://registry:registry@localhost:30432/artifact_registry" \
//!   cargo test --test conan_error_paths_tests -- --ignored
//! ```

use std::path::PathBuf;
use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::middleware;
use axum::Router;
use sqlx::PgPool;
use tower::ServiceExt;
use uuid::Uuid;

use artifact_keeper_backend::api::handlers::conan;
use artifact_keeper_backend::api::middleware::auth::{
    repo_visibility_middleware, RepoVisibilityState,
};
use artifact_keeper_backend::api::{AppState, SharedState};
use artifact_keeper_backend::config::Config;
use artifact_keeper_backend::services::auth_service::AuthService;

// ===========================================================================
// Test helpers (mirrors incus_upload_tests.rs)
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

/// Insert a Conan repo. `is_public=false` produces a private repo so the
/// visibility middleware requires auth. The repo key is UUID-suffixed to
/// avoid collisions with concurrent tests.
async fn create_conan_repo(pool: &PgPool, name: &str, is_public: bool) -> (Uuid, String, PathBuf) {
    let id = Uuid::new_v4();
    let key = format!("conan-err-{}", &id.to_string()[..8]);
    let storage_path = std::env::temp_dir().join(format!("conan-err-{}", id));
    std::fs::create_dir_all(&storage_path).expect("create storage dir");

    sqlx::query(
        "INSERT INTO repositories (id, key, name, storage_path, repo_type, format, is_public) \
         VALUES ($1, $2, $3, $4, 'local', 'conan', $5)",
    )
    .bind(id)
    .bind(&key)
    .bind(name)
    .bind(storage_path.to_string_lossy().as_ref())
    .bind(is_public)
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
    let storage: Arc<dyn artifact_keeper_backend::storage::StorageBackend> = Arc::new(
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

/// Build the production-shaped Conan composition: the same `/conan` mount
/// point used in `api/routes.rs` (nested router + repo_visibility_middleware
/// layer). Routing tests that bypass this middleware miss the auth-extension
/// injection contract; this helper ensures the middleware chain is exercised.
fn build_full_stack_router(state: SharedState) -> Router {
    let auth_service = Arc::new(AuthService::new(
        state.db.clone(),
        Arc::new(state.config.clone()),
    ));
    let vis_state = RepoVisibilityState {
        auth_service,
        db: state.db.clone(),
        repo_cache: state.repo_cache.clone(),
        permission_service: state.permission_service.clone(),
    };
    Router::new()
        .nest("/conan", conan::router())
        .layer(middleware::from_fn_with_state(
            vis_state,
            repo_visibility_middleware,
        ))
        .with_state(state)
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
    let (repo_id, key, storage_path) = create_conan_repo(&pool, "conan-ping-test", true).await;
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
    let (repo_id, key, storage_path) = create_conan_repo(&pool, "conan-long-test", true).await;
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

// ===========================================================================
// Full-stack middleware integration tests (#1046)
//
// These tests build the actual production composition (router + middleware
// chain) and exercise the cases security review walked through manually:
// unknown repo, private repo, public repo, with and without auth.
// ===========================================================================

/// Unknown repo + no auth must surface as 404. The repo lookup is owned by
/// the visibility middleware on the public path and by the handler's
/// `resolve_conan_repo` on the authenticated path; either way the final
/// status must be 404, never 401 or 500.
#[tokio::test]
#[ignore]
async fn test_1046_unknown_repo_no_auth_returns_404() {
    let pool = connect_pool().await;
    let storage_path = std::env::temp_dir().join("conan-fs-unknown");
    std::fs::create_dir_all(&storage_path).ok();
    let state = build_state(pool.clone(), storage_path.to_str().unwrap());

    let bogus = format!("bogus-conan-{}", &Uuid::new_v4().to_string()[..8]);
    let app = build_full_stack_router(state);

    let req = Request::builder()
        .method("GET")
        .uri(format!("/conan/{}/v2/ping", bogus))
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    let status = resp.status();
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "unknown repo + no auth must return 404, got {}",
        status.as_u16()
    );

    let _ = std::fs::remove_dir_all(&storage_path);
}

/// Existing private repo + no auth must return 401 (the middleware blocks
/// before the handler runs).
#[tokio::test]
#[ignore]
async fn test_1046_private_repo_no_auth_returns_401() {
    let pool = connect_pool().await;
    let (repo_id, key, storage_path) =
        create_conan_repo(&pool, "conan-fs-private-noauth", false).await;
    let state = build_state(pool.clone(), storage_path.to_str().unwrap());
    let app = build_full_stack_router(state);

    let req = Request::builder()
        .method("GET")
        .uri(format!("/conan/{}/v2/ping", key))
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    let status = resp.status();
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "private repo + no auth must return 401, got {}",
        status.as_u16()
    );

    let _ = std::fs::remove_dir_all(&storage_path);
    let _ = sqlx::query("DELETE FROM repositories WHERE id = $1")
        .bind(repo_id)
        .execute(&pool)
        .await;
}

/// Existing private repo + valid Basic auth must reach the handler. The
/// `/v2/ping` handler does not itself require auth, so success is a 200.
/// What matters is that the middleware did not short-circuit with 401/403.
#[tokio::test]
#[ignore]
async fn test_1046_private_repo_with_auth_reaches_handler() {
    let pool = connect_pool().await;
    let username = format!("conan-fs-u-{}", &Uuid::new_v4().to_string()[..8]);
    let user_id = create_test_user(&pool, &username, "okpass").await;
    let (repo_id, key, storage_path) =
        create_conan_repo(&pool, "conan-fs-private-auth", false).await;
    let state = build_state(pool.clone(), storage_path.to_str().unwrap());
    let app = build_full_stack_router(state);

    let req = Request::builder()
        .method("GET")
        .uri(format!("/conan/{}/v2/ping", key))
        .header("Authorization", basic_auth_header(&username, "okpass"))
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    let status = resp.status();
    assert_eq!(
        status,
        StatusCode::OK,
        "private repo + valid auth must reach the handler (200), got {}",
        status.as_u16()
    );

    let _ = std::fs::remove_dir_all(&storage_path);
    cleanup(&pool, repo_id, user_id).await;
}

/// Existing public repo + no auth must reach the handler (no 401 from the
/// middleware). Public visibility is the only path that admits anonymous
/// reads; if the middleware regresses to "always require auth" the test
/// will surface it as a 401.
#[tokio::test]
#[ignore]
async fn test_1046_public_repo_no_auth_reaches_handler() {
    let pool = connect_pool().await;
    let (repo_id, key, storage_path) =
        create_conan_repo(&pool, "conan-fs-public-noauth", true).await;
    let state = build_state(pool.clone(), storage_path.to_str().unwrap());
    let app = build_full_stack_router(state);

    let req = Request::builder()
        .method("GET")
        .uri(format!("/conan/{}/v2/ping", key))
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    let status = resp.status();
    assert_eq!(
        status,
        StatusCode::OK,
        "public repo + no auth must reach the handler (200), got {}",
        status.as_u16()
    );

    let _ = std::fs::remove_dir_all(&storage_path);
    let _ = sqlx::query("DELETE FROM repositories WHERE id = $1")
        .bind(repo_id)
        .execute(&pool)
        .await;
}
