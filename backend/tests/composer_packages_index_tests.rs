//! Integration test for #1341: Composer (PHP) uploads must appear in the
//! WebUI Packages tab.
//!
//! The WebUI Packages tab is backed by the `/api/v1/packages` list endpoint,
//! which reads the `packages` table (NOT `artifacts`). Before the fix, the
//! Composer upload handler inserted into `artifacts` + `artifact_metadata`
//! but never called `PackageService`, so a successfully published Composer
//! package was served over the Composer wire protocol yet never showed up in
//! the WebUI. npm / pypi / nuget all call `PackageService` after their
//! artifact insert; Composer did not.
//!
//! This test publishes a Composer package over the real Composer wire
//! protocol, then queries the same `list_packages` handler the WebUI uses and
//! asserts the package is listed.
//!
//! Requires a PostgreSQL database with migrations applied:
//!
//! ```sh
//! DATABASE_URL="postgresql://registry:registry@localhost:30432/artifact_registry" \
//!   cargo test --test composer_packages_index_tests -- --ignored
//! ```

use std::io::Write;
use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use sqlx::{PgPool, Row};
use tower::ServiceExt;
use uuid::Uuid;

use artifact_keeper_backend::api::handlers::{composer, packages};
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

/// Create a public hosted Composer repository. Returns (repo_id, repo_key, storage_path).
async fn create_composer_repo(pool: &PgPool) -> (Uuid, String, std::path::PathBuf) {
    let id = Uuid::new_v4();
    let key = format!("composer-test-{}", id);
    let storage_path = std::env::temp_dir().join(format!("composer-test-{}", id));
    std::fs::create_dir_all(&storage_path).expect("create storage dir");

    sqlx::query(
        "INSERT INTO repositories (id, key, name, storage_path, repo_type, format, is_public) \
         VALUES ($1, $2, $3, $4, 'local', 'composer', true)",
    )
    .bind(id)
    .bind(&key)
    .bind("composer-index-test")
    .bind(storage_path.to_string_lossy().as_ref())
    .execute(pool)
    .await
    .expect("failed to create test repository");

    (id, key, storage_path)
}

/// Build a minimal Composer package zip archive containing a composer.json.
fn build_composer_zip(name: &str, version: &str, description: &str) -> Vec<u8> {
    let composer_json = serde_json::json!({
        "name": name,
        "version": version,
        "description": description,
        "type": "library",
        "license": "MIT",
    });

    let mut cursor = std::io::Cursor::new(Vec::new());
    {
        let mut zip = zip::ZipWriter::new(&mut cursor);
        let options: zip::write::FileOptions<'_, ()> =
            zip::write::FileOptions::default().compression_method(zip::CompressionMethod::Stored);
        zip.start_file("composer.json", options)
            .expect("start composer.json");
        zip.write_all(serde_json::to_string(&composer_json).unwrap().as_bytes())
            .expect("write composer.json");
        zip.finish().expect("finish zip");
    }
    cursor.into_inner()
}

/// Clean up all test data.
async fn cleanup(pool: &PgPool, repo_id: Uuid, user_id: Uuid) {
    sqlx::query("DELETE FROM package_versions WHERE package_id IN (SELECT id FROM packages WHERE repository_id = $1)")
        .bind(repo_id)
        .execute(pool)
        .await
        .ok();
    sqlx::query("DELETE FROM packages WHERE repository_id = $1")
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

/// Build a SharedState for the composer / packages routers.
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

/// Build the `AuthService` used by the optional-auth middleware so the routers
/// resolve the `Authorization: Basic ...` header into an `AuthExtension`
/// exactly as they do in production. Without this layer the handlers' mandatory
/// `Extension<Option<AuthExtension>>` extractor is missing and every request
/// 500s ("Missing request extension").
fn auth_service(state: &SharedState, storage_path: &str) -> Arc<AuthService> {
    Arc::new(AuthService::new(
        state.db.clone(),
        Arc::new(test_config(storage_path)),
    ))
}

// ===========================================================================
// #1341: uploaded Composer package appears in the WebUI Packages list
// ===========================================================================

#[tokio::test]
#[ignore]
async fn test_composer_upload_appears_in_packages_list() {
    let pool = PgPool::connect(&std::env::var("DATABASE_URL").unwrap())
        .await
        .unwrap();
    let username = format!("composer-u1-{}", &Uuid::new_v4().to_string()[..8]);
    let user_id = create_test_user(&pool, &username, "composerpass").await;
    let (repo_id, repo_key, storage_path) = create_composer_repo(&pool).await;
    let state = build_state(pool.clone(), storage_path.to_str().unwrap());
    let auth = auth_service(&state, storage_path.to_str().unwrap());

    let pkg_name = "acme/widget";
    let pkg_version = "1.2.3";
    let pkg_description = "A widget library for testing #1341";
    let archive = build_composer_zip(pkg_name, pkg_version, pkg_description);

    // --- Publish over the Composer wire protocol ---------------------------
    let app = composer::router()
        .layer(axum::middleware::from_fn_with_state(
            auth.clone(),
            optional_auth_middleware,
        ))
        .with_state(state.clone());
    let req = Request::builder()
        .method("PUT")
        .uri(format!("/{}/api/packages", repo_key))
        .header(
            "Authorization",
            basic_auth_header(&username, "composerpass"),
        )
        .body(Body::from(archive))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    let status = resp.status();
    let body = axum::body::to_bytes(resp.into_body(), 4 * 1024 * 1024)
        .await
        .unwrap();
    let body_str = String::from_utf8_lossy(&body);
    assert_eq!(
        status,
        StatusCode::CREATED,
        "composer upload should return 201, got {}: {}",
        status,
        body_str
    );

    // The artifact row must exist (pre-fix behaviour was already correct here).
    let artifact_count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM artifacts WHERE repository_id = $1 AND name = $2 AND version = $3 AND is_deleted = false",
    )
    .bind(repo_id)
    .bind(pkg_name)
    .bind(pkg_version)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(artifact_count, 1, "exactly one artifact row expected");

    // --- The actual regression assertion: the package must be listed by the
    // same `list_packages` handler the WebUI Packages tab calls. The handler
    // reads the `packages` table. Before the fix this returned an empty list.
    // The packages router is mounted behind optional auth in production. We
    // make an anonymous request (no Authorization header); the repo is public
    // so the `public_only` filter still returns it. The same optional-auth
    // middleware resolves the absent credential to an anonymous identity.
    let app = packages::router()
        .layer(axum::middleware::from_fn_with_state(
            auth.clone(),
            optional_auth_middleware,
        ))
        .with_state(state.clone());
    let req = Request::builder()
        .method("GET")
        .uri(format!("/?repository_key={}", repo_key))
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "packages list endpoint should return 200"
    );
    let body = axum::body::to_bytes(resp.into_body(), 4 * 1024 * 1024)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

    let items = json["items"]
        .as_array()
        .expect("packages list must have an items array");
    assert_eq!(
        items.len(),
        1,
        "WebUI Packages tab should list exactly the uploaded Composer package; \
         got an empty/oversized list which is the #1341 regression. Body: {}",
        json
    );
    let item = &items[0];
    assert_eq!(item["name"].as_str().unwrap(), pkg_name);
    assert_eq!(item["version"].as_str().unwrap(), pkg_version);
    assert_eq!(item["format"].as_str().unwrap(), "composer");
    assert_eq!(item["repository_key"].as_str().unwrap(), repo_key);
    assert_eq!(item["description"].as_str().unwrap(), pkg_description);

    // The `packages` table row backing the WebUI must exist directly too.
    let pkg_row = sqlx::query(
        "SELECT name, version, description FROM packages WHERE repository_id = $1 AND name = $2 AND version = $3",
    )
    .bind(repo_id)
    .bind(pkg_name)
    .bind(pkg_version)
    .fetch_one(&pool)
    .await
    .expect("packages row should exist after composer upload (#1341)");
    assert_eq!(pkg_row.get::<String, _>("name"), pkg_name);
    assert_eq!(pkg_row.get::<String, _>("version"), pkg_version);
    assert_eq!(
        pkg_row.get::<Option<String>, _>("description").as_deref(),
        Some(pkg_description)
    );

    // Cleanup
    let _ = std::fs::remove_dir_all(&storage_path);
    cleanup(&pool, repo_id, user_id).await;
}
