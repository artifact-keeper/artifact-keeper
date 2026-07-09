//! Integration tests: Docker/OCI pushes must appear in the WebUI Packages tab.
//!
//! The WebUI Packages tab is backed by the `/api/v1/packages` list endpoint,
//! which reads the `packages` table (NOT `artifacts`). Before the fix, the
//! OCI v2 manifest-PUT handler inserted `oci_tags` + `artifacts` rows but
//! never called `PackageService`, so a successfully pushed image was pullable
//! over the registry protocol yet never showed up in the WebUI. composer /
//! debian / incus / maven / npm / nuget / pypi and the generic upload path
//! all call `PackageService` after their artifact insert; OCI did not.
//!
//! These tests push manifests over the real /v2 wire protocol, then query the
//! same `list_packages` handler the WebUI uses and assert on the catalog rows.
//!
//! Requires a PostgreSQL database with migrations applied:
//!
//! ```sh
//! DATABASE_URL="postgresql://registry:registry@localhost:30432/artifact_registry" \
//!   cargo test --test oci_packages_index_tests -- --ignored
//! ```

#![allow(clippy::unwrap_used)]
#![allow(clippy::disallowed_methods)] // streaming-invariant: test file exempt — buffering response bodies in test assertions is not an artifact path (#1608)
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use sqlx::{PgPool, Row};
use tower::ServiceExt;
use uuid::Uuid;

use artifact_keeper_backend::api::handlers::{oci_v2, packages};
use artifact_keeper_backend::api::middleware::auth::optional_auth_middleware;
use artifact_keeper_backend::api::{AppState, SharedState};
use artifact_keeper_backend::config::Config;
use artifact_keeper_backend::services::auth_service::AuthService;

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

/// Create a public docker-format local repo. Returns (repo_id, key, storage_path).
async fn create_docker_repo(pool: &PgPool) -> (Uuid, String, PathBuf) {
    let id = Uuid::new_v4();
    let key = format!("ocipkg-{}", &id.to_string()[..8]);
    let storage_path = std::env::temp_dir().join(format!("ocipkg-{}", id));
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

fn auth_service(state: &SharedState, storage_path: &str) -> Arc<AuthService> {
    Arc::new(AuthService::new(
        state.db.clone(),
        Arc::new(test_config(storage_path)),
    ))
}

async fn cleanup(pool: &PgPool, repo_id: Uuid, user_id: Uuid) {
    sqlx::query("DELETE FROM package_versions WHERE package_id IN (SELECT id FROM packages WHERE repository_id = $1)")
        .bind(repo_id)
        .execute(pool)
        .await
        .ok();
    for table in [
        "packages",
        "manifest_blob_refs",
        "oci_manifest_refs",
        "oci_tags",
        "artifacts",
        "repositories",
    ] {
        let (sql, bind_id) = if table == "repositories" {
            (format!("DELETE FROM {} WHERE id = $1", table), repo_id)
        } else {
            (
                format!("DELETE FROM {} WHERE repository_id = $1", table),
                repo_id,
            )
        };
        sqlx::query(&sql).bind(bind_id).execute(pool).await.ok();
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

/// PUT a manifest over the /v2 wire protocol. Returns the response status.
async fn put_manifest(
    state: &SharedState,
    auth: &str,
    repo_key: &str,
    image: &str,
    reference: &str,
    content_type: &str,
    body: &[u8],
) -> StatusCode {
    let app = oci_v2::router().with_state(state.clone());
    let req = Request::builder()
        .method("PUT")
        .uri(format!("/{}/{}/manifests/{}", repo_key, image, reference))
        .header("Authorization", auth)
        .header("Content-Type", content_type)
        .body(Body::from(body.to_vec()))
        .unwrap();
    app.oneshot(req).await.unwrap().status()
}

/// Fetch (name, version, size_bytes) for every catalog row in the repo.
async fn fetch_catalog_rows(pool: &PgPool, repo_id: Uuid) -> Vec<(String, String, i64)> {
    sqlx::query(
        "SELECT p.name, v.version, v.size_bytes \
         FROM packages p JOIN package_versions v ON v.package_id = p.id \
         WHERE p.repository_id = $1 ORDER BY p.name, v.version",
    )
    .bind(repo_id)
    .fetch_all(pool)
    .await
    .expect("failed to query packages catalog")
    .into_iter()
    .map(|r| (r.get("name"), r.get("version"), r.get("size_bytes")))
    .collect()
}

const IMAGE_MANIFEST_TYPE: &str = "application/vnd.oci.image.manifest.v1+json";
const INDEX_MANIFEST_TYPE: &str = "application/vnd.oci.image.index.v1+json";

/// Minimal image manifest: config 1000 bytes + layers 2000/3000 = 6000 total.
const IMAGE_MANIFEST_BODY: &[u8] = br#"{
    "schemaVersion": 2,
    "mediaType": "application/vnd.oci.image.manifest.v1+json",
    "config": {"mediaType": "application/vnd.oci.image.config.v1+json", "size": 1000, "digest": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
    "layers": [
        {"mediaType": "application/vnd.oci.image.layer.v1.tar+gzip", "size": 2000, "digest": "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"},
        {"mediaType": "application/vnd.oci.image.layer.v1.tar+gzip", "size": 3000, "digest": "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"}
    ]
}"#;

// ===========================================================================
// Regression: pushed image appears in the WebUI Packages list
// ===========================================================================

#[tokio::test]
#[ignore = "requires DATABASE_URL pointed at a Postgres with migrations applied"]
async fn test_docker_push_appears_in_packages_list() {
    let pool = PgPool::connect(&std::env::var("DATABASE_URL").unwrap())
        .await
        .unwrap();
    let username = format!("ocipkg-u1-{}", &Uuid::new_v4().to_string()[..8]);
    let user_id = create_test_user(&pool, &username, "pushpass").await;
    let (repo_id, repo_key, storage_path) = create_docker_repo(&pool).await;
    let state = build_state(pool.clone(), storage_path.to_str().unwrap());
    let auth = basic_auth_header(&username, "pushpass");

    let status = put_manifest(
        &state,
        &auth,
        &repo_key,
        "acme/app",
        "1.0.0",
        IMAGE_MANIFEST_TYPE,
        IMAGE_MANIFEST_BODY,
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "manifest PUT should 201");

    // The catalog rows behind the WebUI Packages tab must exist.
    let rows = fetch_catalog_rows(&pool, repo_id).await;
    assert_eq!(
        rows,
        vec![("acme/app".to_string(), "1.0.0".to_string(), 6000)],
        "docker push must create exactly one packages/package_versions pair \
         (name = image, version = tag, size = config + layers)"
    );

    // And the same `list_packages` handler the WebUI calls must list it.
    // Anonymous request on a public repo, resolved by the same optional-auth
    // middleware production mounts.
    let svc = auth_service(&state, storage_path.to_str().unwrap());
    let app = packages::router()
        .layer(axum::middleware::from_fn_with_state(
            svc,
            optional_auth_middleware,
        ))
        .with_state(state.clone());
    let req = Request::builder()
        .method("GET")
        .uri(format!("/?repository_key={}", repo_key))
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = axum::body::to_bytes(resp.into_body(), 4 * 1024 * 1024)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let items = json["items"].as_array().expect("items array");
    assert_eq!(
        items.len(),
        1,
        "WebUI Packages tab should list the pushed image; empty list is the \
         pre-fix regression. Body: {}",
        json
    );
    assert_eq!(items[0]["name"].as_str().unwrap(), "acme/app");
    assert_eq!(items[0]["version"].as_str().unwrap(), "1.0.0");

    // Re-push of the same tag must not duplicate catalog rows (UPSERT).
    let status = put_manifest(
        &state,
        &auth,
        &repo_key,
        "acme/app",
        "1.0.0",
        IMAGE_MANIFEST_TYPE,
        IMAGE_MANIFEST_BODY,
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    let rows = fetch_catalog_rows(&pool, repo_id).await;
    assert_eq!(rows.len(), 1, "re-push must UPSERT, not duplicate");

    let _ = std::fs::remove_dir_all(&storage_path);
    cleanup(&pool, repo_id, user_id).await;
}

// ===========================================================================
// Digest-only pushes (multi-arch index children, push-by-digest) must NOT
// create catalog rows — they are not user-facing versions.
// ===========================================================================

#[tokio::test]
#[ignore = "requires DATABASE_URL pointed at a Postgres with migrations applied"]
async fn test_digest_push_creates_no_catalog_row() {
    let pool = PgPool::connect(&std::env::var("DATABASE_URL").unwrap())
        .await
        .unwrap();
    let username = format!("ocipkg-u2-{}", &Uuid::new_v4().to_string()[..8]);
    let user_id = create_test_user(&pool, &username, "pushpass").await;
    let (repo_id, repo_key, storage_path) = create_docker_repo(&pool).await;
    let state = build_state(pool.clone(), storage_path.to_str().unwrap());
    let auth = basic_auth_header(&username, "pushpass");

    let digest_ref = format!("sha256:{}", sha256_hex(IMAGE_MANIFEST_BODY));
    let status = put_manifest(
        &state,
        &auth,
        &repo_key,
        "acme/app",
        &digest_ref,
        IMAGE_MANIFEST_TYPE,
        IMAGE_MANIFEST_BODY,
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "digest PUT should 201");

    let rows = fetch_catalog_rows(&pool, repo_id).await;
    assert!(
        rows.is_empty(),
        "a digest-only push must not create catalog rows, got: {:?}",
        rows
    );

    let _ = std::fs::remove_dir_all(&storage_path);
    cleanup(&pool, repo_id, user_id).await;
}

// ===========================================================================
// Multi-arch: a tagged image index folds in its child manifests' sizes
// (an index body itself has no config/layers), mirroring the docker_tag
// grouping endpoint's size semantics.
// ===========================================================================

#[tokio::test]
#[ignore = "requires DATABASE_URL pointed at a Postgres with migrations applied"]
async fn test_index_push_folds_child_manifest_sizes() {
    let pool = PgPool::connect(&std::env::var("DATABASE_URL").unwrap())
        .await
        .unwrap();
    let username = format!("ocipkg-u3-{}", &Uuid::new_v4().to_string()[..8]);
    let user_id = create_test_user(&pool, &username, "pushpass").await;
    let (repo_id, repo_key, storage_path) = create_docker_repo(&pool).await;
    let state = build_state(pool.clone(), storage_path.to_str().unwrap());
    let auth = basic_auth_header(&username, "pushpass");

    // Child image manifest pushed by digest first (docker push order).
    let child_digest = format!("sha256:{}", sha256_hex(IMAGE_MANIFEST_BODY));
    let status = put_manifest(
        &state,
        &auth,
        &repo_key,
        "acme/multi",
        &child_digest,
        IMAGE_MANIFEST_TYPE,
        IMAGE_MANIFEST_BODY,
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "child digest PUT should 201");

    // Then the tagged index referencing the child.
    let index_body = format!(
        r#"{{
            "schemaVersion": 2,
            "mediaType": "{}",
            "manifests": [
                {{"mediaType": "{}", "size": {}, "digest": "{}",
                  "platform": {{"architecture": "amd64", "os": "linux"}}}}
            ]
        }}"#,
        INDEX_MANIFEST_TYPE,
        IMAGE_MANIFEST_TYPE,
        IMAGE_MANIFEST_BODY.len(),
        child_digest,
    );
    let status = put_manifest(
        &state,
        &auth,
        &repo_key,
        "acme/multi",
        "2.0.0",
        INDEX_MANIFEST_TYPE,
        index_body.as_bytes(),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "index PUT should 201");

    // Only the tagged index creates a catalog row; its size is the child
    // image's config+layers total (6000), not the ~0 of the index body.
    let rows = fetch_catalog_rows(&pool, repo_id).await;
    assert_eq!(
        rows,
        vec![("acme/multi".to_string(), "2.0.0".to_string(), 6000)],
        "tagged index must create one catalog row sized from its children"
    );

    let _ = std::fs::remove_dir_all(&storage_path);
    cleanup(&pool, repo_id, user_id).await;
}
