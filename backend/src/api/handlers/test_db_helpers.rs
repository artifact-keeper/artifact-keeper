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
// streaming-invariant: test scaffolding exempt — buffering response bodies in
// DB-backed handler tests is not an artifact path (#1608).
#![allow(clippy::disallowed_methods)]

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

/// Advisory-lock key for [`scan_dedup_serial_lock`] (#2000).
///
/// A single-key `pg_advisory_lock(bigint)` — a lock space distinct from the
/// two-key `pg_advisory_xact_lock(int4, int4)` used by
/// `ScanResultService::prepare_scan_placeholder` and from the scheduler locks
/// (9001-9099) documented in `scan_result_service`, so it cannot collide with
/// application locks.
const SCAN_DEDUP_TEST_LOCK_KEY: i64 = 0x5644_2000; // "SD" + issue #2000

/// Cross-process serialization guard for the DB-backed scan-dedup tests
/// (#2000). Holds a Postgres *session* advisory lock on a dedicated
/// connection; the lock is released when the guard is dropped (its connection
/// closes, ending the session), including on panic.
///
/// This exists because the `Code Coverage` CI job runs the suite under
/// `cargo nextest`, which executes **each test in its own process**. An
/// in-process `Mutex` (or the `serial_test` crate) therefore does NOT
/// serialize tests across nextest processes. A database advisory lock does:
/// every test process contends for the same key in the shared database, so
/// only one scan-dedup test mutates `scan_results` at a time. That removes the
/// cross-test interference that made
/// `scanner_service::tests::test_prepare_artifact_scan_without_bypass_reuses_existing`
/// intermittently fail under the coverage job's parallelism.
pub struct ScanDedupSerialGuard {
    _conn: Option<sqlx::PgConnection>,
}

/// Acquire the process-wide scan-dedup test lock, blocking until it is free.
///
/// Returns an inert guard (no lock held) when `DATABASE_URL` is unset or the
/// database is unreachable, mirroring [`try_pool`] so DB-free environments
/// still no-op cleanly. Call this as the first line of a scan-dedup DB test
/// and bind the result for the whole test body.
pub async fn scan_dedup_serial_lock() -> ScanDedupSerialGuard {
    use sqlx::Connection;
    let Ok(url) = std::env::var("DATABASE_URL") else {
        return ScanDedupSerialGuard { _conn: None };
    };
    let mut conn = match sqlx::PgConnection::connect(&url).await {
        Ok(c) => c,
        Err(_) => return ScanDedupSerialGuard { _conn: None },
    };
    if sqlx::query("SELECT pg_advisory_lock($1)")
        .bind(SCAN_DEDUP_TEST_LOCK_KEY)
        .execute(&mut conn)
        .await
        .is_err()
    {
        return ScanDedupSerialGuard { _conn: None };
    }
    ScanDedupSerialGuard { _conn: Some(conn) }
}

/// Build a lazily-connecting pool that never actually opens a connection
/// unless a query is issued. Useful for DB-free unit tests of code paths that
/// short-circuit before touching the database.
pub fn lazy_pool() -> PgPool {
    let url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://invalid:invalid@127.0.0.1:1/none".to_string());
    sqlx::postgres::PgPoolOptions::new()
        .connect_lazy(&url)
        .expect("lazy pool")
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
        trivy_adapter_url: None,
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
        sso_disable_admin_break_glass: false,
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

        rate_limit_login_global_per_window: 8192,
        rate_limit_password_change_per_window: 5,
        rate_limit_password_change_window_secs: 900,
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
        proxy_singleflight_advisory_locks_enabled: false,
        proxy_singleflight_lock_poll_interval_ms: 200,
        proxy_singleflight_lock_wait_timeout_secs: 65,
        smtp_host: None,
        smtp_port: 587,
        smtp_username: None,
        smtp_password: None,
        smtp_from_address: "noreply@test.local".to_string(),
        smtp_tls_mode: "starttls".to_string(),
        scan_token_ttl_seconds: 300,
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

/// Like [`router_with_auth`] but also injects the **non-Option**
/// `Extension<AuthExtension>`, exactly as the production `auth_middleware`
/// does (it inserts both `Some(ext)` and `ext`). Handlers that extract
/// `Extension<AuthExtension>` directly (e.g. the admin-gated peer-label
/// handlers) require this raw copy to be present, otherwise the extractor
/// fails with a 500 before the in-handler authorization check ever runs.
pub fn router_with_auth_ext(
    router: Router<SharedState>,
    state: SharedState,
    auth: AuthExtension,
) -> Router {
    router
        .with_state(state)
        .layer(Extension::<AuthExtension>(auth.clone()))
        .layer(Extension::<Option<AuthExtension>>(Some(auth)))
}

/// Register a peer instance via the real `PeerInstanceService` and return its
/// id. `name_prefix` namespaces the generated peer name so concurrent suites do
/// not collide (e.g. "probe", "labels-authz", "map-err"). Centralizes the
/// `register(RegisterPeerInstanceRequest { .. })` boilerplate shared by every
/// DB-backed peer test module.
pub async fn register_test_peer(pool: &PgPool, name_prefix: &str, tag: &str) -> Uuid {
    use crate::services::peer_instance_service::{
        PeerInstanceService, RegisterPeerInstanceRequest,
    };
    let svc = PeerInstanceService::new(pool.clone());
    let id = Uuid::new_v4();
    svc.register(RegisterPeerInstanceRequest {
        name: format!("{}-{}-{}", name_prefix, tag, &id.to_string()[..8]),
        endpoint_url: "https://peer.example.test".to_string(),
        region: Some("us-east".to_string()),
        cache_size_bytes: 1024,
        sync_filter: None,
        api_key: "k".to_string(),
    })
    .await
    .expect("register peer")
    .id
}

pub async fn send(app: Router, req: Request<Body>) -> (StatusCode, Bytes) {
    let resp = app.oneshot(req).await.expect("oneshot");
    let status = resp.status();
    let body = to_bytes(resp.into_body(), 16 * 1024 * 1024)
        .await
        .expect("body");
    (status, body)
}

/// Grant `user_id` the `developer` role scoped to `repo_id`, mirroring the
/// owner auto-grant that `RepositoryService::create` performs for real
/// callers. Handler smoke tests authenticate as the fixture user, so without
/// this grant the per-repo authorization check in `require_visible` /
/// `require_repo_write_access` would reject them on private repositories.
pub async fn grant_repo_access(pool: &PgPool, repo_id: Uuid, user_id: Uuid) {
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

pub async fn cleanup(pool: &PgPool, repo_id: Uuid, user_id: Uuid) {
    let _ = sqlx::query("DELETE FROM role_assignments WHERE repository_id = $1")
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
        promotion_only: false,
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

/// Build a PUT request carrying a JSON body (sets `content-type` so the
/// `Json` extractor accepts it; the raw [`put`] helper omits it, which yields
/// a 415 for handlers that extract `Json<_>`).
pub fn put_json(uri: String, body: Bytes) -> Request<Body> {
    Request::builder()
        .method("PUT")
        .uri(uri)
        .header("content-type", "application/json")
        .body(Body::from(body))
        .expect("build PUT JSON request")
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
        // Owner auto-grant: the fixture user is the de-facto owner of the
        // fixture repo, so grant them per-repo access. This keeps the
        // authenticated-router smoke tests valid under per-repo authorization
        // (private repos now require a role assignment, not just a token).
        grant_repo_access(&pool, repo_id, user_id).await;
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

    /// Flag the fixture repository as `promotion_only` (or clear the flag).
    /// Used by the format-native publish-gate tests to assert that a direct
    /// upload to a promotion_only repository is rejected.
    pub async fn set_promotion_only(&self, value: bool) {
        sqlx::query("UPDATE repositories SET promotion_only = $1 WHERE id = $2")
            .bind(value)
            .bind(self.repo_id)
            .execute(&self.pool)
            .await
            .expect("set promotion_only");
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

/// Build a [`crate::services::proxy_service::ProxyService`] backed by a
/// filesystem cache at `storage_path`.
///
/// Pass a real `PgPool` from [`try_pool`] — `ProxyService::fetch_from_upstream`
/// calls `load_upstream_auth` which queries the database before every HTTP
/// request. A lazy/fake pool will cause that query to fail and the fetch to
/// return BAD_GATEWAY.
pub fn build_proxy_service_with_fs(
    pool: PgPool,
    storage_path: &str,
) -> Arc<crate::services::proxy_service::ProxyService> {
    use crate::services::storage_service::{FilesystemBackend, StorageService};
    let backend = Arc::new(FilesystemBackend::new(std::path::PathBuf::from(
        storage_path,
    )));
    Arc::new(crate::services::proxy_service::ProxyService::new(
        pool,
        Arc::new(StorageService::new(backend)),
    ))
}

/// Build a [`SharedState`] that includes `proxy` as the proxy service.
/// Accepts any `PgPool` so callers can supply a lazy/fake pool for tests
/// that do not need a real database.
/// Construct an [`AppState`] from `config` plus a fresh filesystem storage
/// backend + empty registry rooted at `storage_path`. Shared spine of the
/// `build_state*` constructors.
fn app_state_with(config: Config, pool: PgPool, storage_path: &str) -> crate::api::AppState {
    let storage: Arc<dyn crate::storage::StorageBackend> = Arc::new(
        crate::storage::filesystem::FilesystemStorage::new(storage_path),
    );
    let registry = Arc::new(crate::storage::StorageRegistry::new(
        std::collections::HashMap::new(),
        "filesystem".to_string(),
    ));
    crate::api::AppState::new(config, pool, storage, registry)
}

pub fn build_state_with_proxy(
    pool: PgPool,
    storage_path: &str,
    proxy: Arc<crate::services::proxy_service::ProxyService>,
) -> crate::api::SharedState {
    let mut state = app_state_with(cfg(storage_path), pool, storage_path);
    state.set_proxy_service(proxy);
    Arc::new(state)
}

/// Like [`build_state_with_proxy`] but with `presigned_downloads_enabled = true`
/// so tests can drive the presigned-redirect gate (#1555). The filesystem
/// backend still reports `supports_redirect() == false`, so the redirect path
/// short-circuits to streaming — exactly the non-S3 fallback we want to cover.
pub fn build_state_with_proxy_presigned(
    pool: PgPool,
    storage_path: &str,
    proxy: Arc<crate::services::proxy_service::ProxyService>,
) -> crate::api::SharedState {
    let mut config = cfg(storage_path);
    config.presigned_downloads_enabled = true;
    let mut state = app_state_with(config, pool, storage_path);
    state.set_proxy_service(proxy);
    Arc::new(state)
}
