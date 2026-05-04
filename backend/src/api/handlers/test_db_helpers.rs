//! Shared test scaffolding for DB-backed handler tests.
//!
//! Every helper here is a no-op stub when `DATABASE_URL` is unset (so the
//! tests skip cleanly in environments without Postgres). The CI coverage
//! job seeds Postgres + applies migrations before running `cargo llvm-cov
//! --lib`, so these helpers are exercised in CI and instrument the
//! handler-call paths refactored to use `proxy_helpers`.
//!
//! Tests in sibling modules call:
//!
//!     use crate::api::handlers::test_db_helpers as tdh;
//!     let Some(pool) = tdh::try_pool().await else { return; };

#![allow(dead_code)]

use std::path::PathBuf;
use std::sync::Arc;

use axum::body::{to_bytes, Body};
use axum::http::{Request, StatusCode};
use axum::{Extension, Router};
use bytes::Bytes;
use sqlx::PgPool;
use tower::ServiceExt;
use uuid::Uuid;

use crate::api::middleware::auth::AuthExtension;
use crate::api::{AppState, SharedState};
use crate::config::Config;

/// Connect to the test database. Returns `None` when `DATABASE_URL` is
/// unset or unreachable so suites no-op gracefully.
pub async fn try_pool() -> Option<PgPool> {
    let url = std::env::var("DATABASE_URL").ok()?;
    sqlx::postgres::PgPoolOptions::new()
        .max_connections(3)
        .acquire_timeout(std::time::Duration::from_secs(3))
        .connect(&url)
        .await
        .ok()
}

fn cfg(storage_path: &str) -> Config {
    Config {
        database_url: std::env::var("DATABASE_URL").unwrap_or_default(),
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
        opensearch_url: None,
        opensearch_username: None,
        opensearch_password: None,
        opensearch_allow_invalid_certs: false,
        scan_workspace_path: "/tmp/scan".into(),
        demo_mode: false,
        guest_access_enabled: true,
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
        metrics_port: None,
        database_max_connections: 20,
        database_min_connections: 5,
        database_acquire_timeout_secs: 30,
        database_idle_timeout_secs: 600,
        database_max_lifetime_secs: 1800,
        rate_limit_auth_per_window: 120,
        rate_limit_api_per_window: 5000,
        rate_limit_search_per_window: 300,
        rate_limit_window_secs: 60,
        rate_limit_exempt_usernames: Vec::new(),
        rate_limit_exempt_service_accounts: false,
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
        smtp_from_address: "noreply@test.local".to_string(),
        smtp_tls_mode: "starttls".to_string(),
    }
}

pub fn build_state(pool: PgPool, storage_path: &str) -> SharedState {
    let storage: Arc<dyn crate::storage::StorageBackend> = Arc::new(
        crate::storage::filesystem::FilesystemStorage::new(storage_path),
    );
    let registry = Arc::new(crate::storage::StorageRegistry::new(
        std::collections::HashMap::new(),
        "filesystem".to_string(),
    ));
    Arc::new(AppState::new(cfg(storage_path), pool, storage, registry))
}

pub async fn create_user(pool: &PgPool) -> (Uuid, String) {
    let id = Uuid::new_v4();
    let username = format!("ph-test-u-{}", id);
    sqlx::query(
        r#"
        INSERT INTO users (id, username, email, password_hash, auth_provider, is_admin, is_active)
        VALUES ($1, $2, $3, 'unused', 'local', false, true)
        "#,
    )
    .bind(id)
    .bind(&username)
    .bind(format!("{}@test.local", username))
    .execute(pool)
    .await
    .expect("create user");
    (id, username)
}

/// Insert a repository row of the given type and format. `format` must be
/// a valid `repository_format` enum value (e.g. "ansible", "helm", "rpm").
pub async fn create_repo(pool: &PgPool, repo_type: &str, format: &str) -> (Uuid, String, PathBuf) {
    let id = Uuid::new_v4();
    let key = format!("ph-test-{}-{}", format, id);
    let storage_dir = std::env::temp_dir().join(format!("ph-test-{}", id));
    std::fs::create_dir_all(&storage_dir).expect("create storage dir");
    let upstream: Option<&str> = if repo_type == "remote" {
        Some("https://upstream.example.test")
    } else {
        None
    };
    let sql = format!(
        "INSERT INTO repositories (id, key, name, storage_path, repo_type, format, upstream_url) \
         VALUES ($1, $2, $3, $4, '{}'::repository_type, '{}'::repository_format, $5)",
        repo_type, format
    );
    sqlx::query(&sql)
        .bind(id)
        .bind(&key)
        .bind(&key)
        .bind(storage_dir.to_string_lossy().as_ref())
        .bind(upstream)
        .execute(pool)
        .await
        .expect("create repo");
    (id, key, storage_dir)
}

pub fn make_auth(user_id: Uuid, username: &str) -> AuthExtension {
    AuthExtension {
        user_id,
        username: username.to_string(),
        email: format!("{}@test.local", username),
        is_admin: false,
        is_api_token: false,
        is_service_account: false,
        scopes: None,
        allowed_repo_ids: None,
    }
}

/// Wrap any Router<SharedState> in `with_state` + auth-injection layer.
pub fn router_with_auth(
    router: Router<SharedState>,
    state: SharedState,
    auth: AuthExtension,
) -> Router {
    router
        .with_state(state)
        .layer(Extension::<Option<AuthExtension>>(Some(auth)))
}

pub fn router_anon(router: Router<SharedState>, state: SharedState) -> Router {
    router
        .with_state(state)
        .layer(Extension::<Option<AuthExtension>>(None))
}

pub async fn send(app: Router, req: Request<Body>) -> (StatusCode, Bytes) {
    let resp = app.oneshot(req).await.expect("oneshot");
    let status = resp.status();
    let body = to_bytes(resp.into_body(), 16 * 1024 * 1024)
        .await
        .expect("body");
    (status, body)
}

pub async fn cleanup(pool: &PgPool, repo_id: Uuid, user_id: Uuid) {
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

/// Build a `Basic <base64(user:pass)>` header value.
pub fn basic_auth(user: &str, pass: &str) -> String {
    use base64::Engine;
    let encoded = base64::engine::general_purpose::STANDARD.encode(format!("{}:{}", user, pass));
    format!("Basic {}", encoded)
}

/// Build a `RepoInfo` shaped for handler tests. `repo_type` is the
/// stringified repository_type ("local", "remote", "virtual").
pub fn make_repo_info(
    repo_id: Uuid,
    repo_key: &str,
    storage_dir: &std::path::Path,
    repo_type: &str,
    upstream_url: Option<&str>,
) -> crate::api::handlers::proxy_helpers::RepoInfo {
    crate::api::handlers::proxy_helpers::RepoInfo {
        id: repo_id,
        key: repo_key.to_string(),
        storage_path: storage_dir.to_string_lossy().into_owned(),
        storage_backend: "filesystem".to_string(),
        repo_type: repo_type.to_string(),
        upstream_url: upstream_url.map(|s| s.to_string()),
    }
}

/// Seed a single artifact: write `content` to `storage_key` and insert
/// an `artifacts` row at `path`. Returns the inserted artifact id.
///
/// Centralizes the put+insert pattern shared by every handler smoke test.
#[allow(clippy::too_many_arguments)]
pub async fn seed_artifact(
    state: &SharedState,
    pool: &PgPool,
    repo: &crate::api::handlers::proxy_helpers::RepoInfo,
    storage_key: &str,
    path: &str,
    name: &str,
    version: &str,
    content_type: &str,
    content: Bytes,
    uploaded_by: Uuid,
) -> Uuid {
    crate::api::handlers::proxy_helpers::put_artifact_bytes(
        state,
        repo,
        storage_key,
        content.clone(),
    )
    .await
    .expect("seed put_artifact_bytes");
    crate::api::handlers::proxy_helpers::insert_artifact(
        pool,
        crate::api::handlers::proxy_helpers::NewArtifact {
            repository_id: repo.id,
            path,
            name,
            version,
            size_bytes: content.len() as i64,
            checksum_sha256: "test-seed",
            content_type,
            storage_key,
            uploaded_by,
        },
    )
    .await
    .expect("seed insert_artifact")
}

/// Build a GET request with no body. Centralizes the
/// `Request::builder().method("GET").uri(...).body(empty)` boilerplate.
pub fn get(uri: String) -> Request<Body> {
    Request::builder()
        .method("GET")
        .uri(uri)
        .body(Body::empty())
        .expect("build GET request")
}

/// Build a POST request with the given body and content-type header.
pub fn post(uri: String, content_type: &str, body: Bytes) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri(uri)
        .header("content-type", content_type)
        .body(Body::from(body))
        .expect("build POST request")
}

/// Build a PUT request with raw body bytes.
pub fn put(uri: String, body: Bytes) -> Request<Body> {
    Request::builder()
        .method("PUT")
        .uri(uri)
        .body(Body::from(body))
        .expect("build PUT request")
}

/// Bundles all the per-test scaffolding so each handler test body is a
/// single helper call followed by assertions. Returned `None` indicates
/// the test should skip (no `DATABASE_URL`).
pub struct Fixture {
    pub pool: PgPool,
    pub user_id: Uuid,
    pub username: String,
    pub repo_id: Uuid,
    pub repo_key: String,
    pub storage_dir: PathBuf,
    pub state: SharedState,
}

impl Fixture {
    /// Spin up a pool, user, repository, and SharedState. Returns `None`
    /// when no `DATABASE_URL` is available so the test no-ops gracefully.
    /// `repo_type` is "local" / "remote" / "virtual"; `format` matches a
    /// `repository_format` enum value (e.g. "ansible", "cran").
    pub async fn setup(repo_type: &str, format: &str) -> Option<Self> {
        let pool = try_pool().await?;
        let (user_id, username) = create_user(&pool).await;
        let (repo_id, repo_key, storage_dir) = create_repo(&pool, repo_type, format).await;
        let state = build_state(pool.clone(), storage_dir.to_str().unwrap());
        Some(Self {
            pool,
            user_id,
            username,
            repo_id,
            repo_key,
            storage_dir,
            state,
        })
    }

    /// Build a `RepoInfo` matching this fixture's repository. Mirrors the
    /// shape callers need for direct `proxy_helpers` invocations.
    pub fn repo_info(
        &self,
        repo_type: &str,
        upstream_url: Option<&str>,
    ) -> crate::api::handlers::proxy_helpers::RepoInfo {
        make_repo_info(
            self.repo_id,
            &self.repo_key,
            &self.storage_dir,
            repo_type,
            upstream_url,
        )
    }

    /// Build a router with no auth injected (handler will see `None`).
    pub fn router_anon(&self, router: Router<SharedState>) -> Router {
        router_anon(router, self.state.clone())
    }

    /// Build a router with auth injected for the fixture's user.
    pub fn router_with_auth(&self, router: Router<SharedState>) -> Router {
        let auth = make_auth(self.user_id, &self.username);
        router_with_auth(router, self.state.clone(), auth)
    }

    /// Drop all rows owned by this fixture and remove the storage dir.
    pub async fn teardown(&self) {
        cleanup(&self.pool, self.repo_id, self.user_id).await;
        let _ = std::fs::remove_dir_all(&self.storage_dir);
    }
}
