//! Shared fixtures for the conda integration targets (#4158).
//!
//! The conda wave's behaviors were previously covered only by in-crate
//! (`--lib`) tests that reach handler internals through `pub(crate)` test
//! helpers — several of which silently pass with no database. These helpers
//! build the same fixtures through the crate's PUBLIC API plus raw SQL, which
//! is all an out-of-process (`backend/tests/`) target may use.
//!
//! Every entry point here hard-requires the database: the targets are
//! `#[ignore]`d and run under `--run-ignored ignored-only` with
//! `AK_TESTS_REQUIRE_DB=1` in CI, so a missing database is a loud failure,
//! never a silent skip-and-PASS.

#![allow(dead_code)]

use std::path::{Path, PathBuf};
use std::sync::Arc;

use axum::middleware;
use axum::Router;
use sqlx::PgPool;
use uuid::Uuid;

use artifact_keeper_backend::api::middleware::auth::{
    auth_middleware, optional_auth_middleware, repo_visibility_middleware, RepoVisibilityState,
};
use artifact_keeper_backend::api::{AppState, SharedState};
use artifact_keeper_backend::config::Config;
use artifact_keeper_backend::services::auth_service::AuthService;

/// Build a `Config` rooted at `storage_path` with a test-grade JWT secret.
pub fn test_config(storage_path: &str) -> Config {
    Config {
        database_url: std::env::var("DATABASE_URL").unwrap_or_default(),
        storage_path: storage_path.into(),
        jwt_secret: "conda-integration-test-secret-32-bytes-minimum".into(),
        setup_password_hint: None,
        ..Default::default()
    }
}

/// Connect to the test database, loudly. A DB-gated conda test that cannot
/// connect must FAIL (the `AK_TESTS_REQUIRE_DB=1` contract), never skip.
pub async fn require_pool() -> PgPool {
    let url = std::env::var("DATABASE_URL")
        .expect("DATABASE_URL must be set for the DB-gated conda integration tests");
    PgPool::connect(&url)
        .await
        .expect("failed to connect to the test database")
}

/// Build a `SharedState` over filesystem storage rooted at `storage_path`.
pub fn build_state(pool: PgPool, storage_path: &str) -> SharedState {
    let storage: Arc<dyn artifact_keeper_backend::storage::StorageBackend> = Arc::new(
        artifact_keeper_backend::storage::filesystem::FilesystemStorage::new(storage_path),
    );
    let registry = Arc::new(
        artifact_keeper_backend::storage::StorageRegistry::new(
            std::collections::HashMap::new(),
            "filesystem".to_string(),
        )
        .with_filesystem_bucket_root(storage_path),
    );
    Arc::new(AppState::new(
        test_config(storage_path),
        pool,
        storage,
        registry,
    ))
}

/// Insert a local user with a bcrypt-hashed password. `is_admin` mirrors the
/// global-admin flag (the withdrawal and scan-config paths are admin-gated).
pub async fn create_user(pool: &PgPool, username: &str, password: &str, is_admin: bool) -> Uuid {
    let id = Uuid::new_v4();
    let hash = bcrypt::hash(password, 4).expect("bcrypt hash failed");
    sqlx::query(
        "INSERT INTO users (id, username, email, password_hash, auth_provider, is_admin, is_active) \
         VALUES ($1, $2, $3, $4, 'local', $5, true)",
    )
    .bind(id)
    .bind(username)
    .bind(format!("{}@test.local", username))
    .bind(&hash)
    .bind(is_admin)
    .execute(pool)
    .await
    .expect("failed to create test user");
    id
}

/// Grant the user the `developer` role on the repository (read + write),
/// the same row `test_db_helpers::grant_repo_access` writes for lib tests.
pub async fn grant_developer_role(pool: &PgPool, repo_id: Uuid, user_id: Uuid) {
    sqlx::query(
        "INSERT INTO role_assignments (user_id, role_id, repository_id) \
         SELECT $1, r.id, $2 FROM roles r WHERE r.name = 'developer' \
         ON CONFLICT (user_id, role_id, repository_id) DO NOTHING",
    )
    .bind(user_id)
    .bind(repo_id)
    .execute(pool)
    .await
    .expect("grant developer role");
}

/// Insert a repository with a temp storage dir. Returns `(id, key, storage_path)`.
pub async fn create_repo(
    pool: &PgPool,
    prefix: &str,
    repo_type: &str,
    format: &str,
    is_public: bool,
) -> (Uuid, String, PathBuf) {
    let id = Uuid::new_v4();
    let key = format!("{}-{}", prefix, &id.to_string()[..8]);
    let storage_path = std::env::temp_dir().join(format!("{}-{}", prefix, id));
    std::fs::create_dir_all(&storage_path).expect("create storage dir");
    sqlx::query(
        "INSERT INTO repositories (id, key, name, storage_path, repo_type, format, is_public) \
         VALUES ($1, $2, $3, $4, $5, $6, $7)",
    )
    .bind(id)
    .bind(&key)
    .bind(&key)
    .bind(&*storage_path.to_string_lossy())
    .bind(repo_type)
    .bind(format)
    .bind(is_public)
    .execute(pool)
    .await
    .expect("failed to create repository");
    (id, key, storage_path)
}

/// A unique username for one test.
pub fn unique_name(prefix: &str) -> String {
    format!("{}-{}", prefix, &Uuid::new_v4().to_string()[..8])
}

/// `Authorization: Basic …` header value.
pub fn basic_auth(username: &str, password: &str) -> String {
    use base64::Engine;
    let encoded =
        base64::engine::general_purpose::STANDARD.encode(format!("{}:{}", username, password));
    format!("Basic {}", encoded)
}

/// The `RepoVisibilityState` the production `/conda` mount builds.
fn vis_state(state: &SharedState) -> RepoVisibilityState {
    RepoVisibilityState {
        auth_service: Arc::new(AuthService::new(
            state.db.clone(),
            Arc::new(state.config.clone()),
        )),
        db: state.db.clone(),
        repo_cache: state.repo_cache.clone(),
        repo_miss_cache: state.repo_miss_cache.clone(),
        permission_service: state.permission_service.clone(),
    }
}

/// The production conda composition: `conda::router()` mounted at `/conda`
/// under `repo_visibility_middleware`, exactly as `api::routes` nests it.
pub fn conda_full_stack(state: SharedState) -> Router {
    Router::new()
        .nest(
            "/conda",
            artifact_keeper_backend::api::handlers::conda::router(),
        )
        .layer(middleware::from_fn_with_state(
            vis_state(&state),
            repo_visibility_middleware,
        ))
        .with_state(state)
}

/// The production composition of the repository-scoped environment routes:
/// `environments::repo_router()` nested at `/api/v1/repositories` under the
/// optional-auth middleware.
pub fn environments_repo_stack(state: SharedState) -> Router {
    let auth_service = Arc::new(AuthService::new(
        state.db.clone(),
        Arc::new(state.config.clone()),
    ));
    Router::new()
        .nest(
            "/api/v1/repositories",
            artifact_keeper_backend::api::handlers::environments::repo_router(),
        )
        .layer(middleware::from_fn_with_state(
            auth_service,
            optional_auth_middleware,
        ))
        .with_state(state)
}

/// The production composition of the global environment reverse index:
/// `environments::router()` nested at `/api/v1/environments` under the
/// required-auth middleware.
pub fn environments_global_stack(state: SharedState) -> Router {
    let auth_service = Arc::new(AuthService::new(
        state.db.clone(),
        Arc::new(state.config.clone()),
    ));
    Router::new()
        .nest(
            "/api/v1/environments",
            artifact_keeper_backend::api::handlers::environments::router(),
        )
        .layer(middleware::from_fn_with_state(
            auth_service,
            auth_middleware,
        ))
        .with_state(state)
}

/// Build a minimal but valid conda v1 package: a bzip2 tar carrying
/// `info/index.json` whose fields agree with the filename (the upload path
/// parses it for ingest).
pub fn conda_v1_package(name: &str, version: &str, build: &str) -> Vec<u8> {
    let index = serde_json::json!({
        "name": name,
        "version": version,
        "build": build,
        "build_number": 0,
        "subdir": "noarch",
    });
    let index_bytes = serde_json::to_vec(&index).unwrap();

    let mut tar_data = Vec::new();
    {
        let mut builder = tar::Builder::new(&mut tar_data);
        let mut header = tar::Header::new_gnu();
        header.set_path("info/index.json").unwrap();
        header.set_size(index_bytes.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        builder.append(&header, &index_bytes[..]).unwrap();
        builder.finish().unwrap();
    }

    let mut enc = bzip2::write::BzEncoder::new(Vec::new(), bzip2::Compression::default());
    std::io::Write::write_all(&mut enc, &tar_data).unwrap();
    enc.finish().unwrap()
}

/// Drop every row a test created, in dependency order. Best-effort by design:
/// each statement tolerates its table already being clean.
pub async fn cleanup_repo(pool: &PgPool, repo_id: Uuid) {
    let _ = sqlx::query(
        "DELETE FROM scan_findings WHERE scan_result_id IN \
         (SELECT id FROM scan_results WHERE repository_id = $1)",
    )
    .bind(repo_id)
    .execute(pool)
    .await;
    let _ = sqlx::query("DELETE FROM scan_results WHERE repository_id = $1")
        .bind(repo_id)
        .execute(pool)
        .await;
    let _ = sqlx::query("DELETE FROM repo_security_scores WHERE repository_id = $1")
        .bind(repo_id)
        .execute(pool)
        .await;
    let _ = sqlx::query("DELETE FROM scan_configs WHERE repository_id = $1")
        .bind(repo_id)
        .execute(pool)
        .await;
    let _ = sqlx::query("DELETE FROM scan_policies WHERE repository_id = $1")
        .bind(repo_id)
        .execute(pool)
        .await;
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
    let _ = sqlx::query("DELETE FROM role_assignments WHERE repository_id = $1")
        .bind(repo_id)
        .execute(pool)
        .await;
    let _ = sqlx::query("DELETE FROM repositories WHERE id = $1")
        .bind(repo_id)
        .execute(pool)
        .await;
}

/// Remove a test user and its role assignments.
pub async fn cleanup_user(pool: &PgPool, user_id: Uuid) {
    let _ = sqlx::query("DELETE FROM role_assignments WHERE user_id = $1")
        .bind(user_id)
        .execute(pool)
        .await;
    let _ = sqlx::query("DELETE FROM users WHERE id = $1")
        .bind(user_id)
        .execute(pool)
        .await;
}

/// Remove a storage dir, ignoring "already gone".
pub fn cleanup_storage(dir: &Path) {
    let _ = std::fs::remove_dir_all(dir);
}
