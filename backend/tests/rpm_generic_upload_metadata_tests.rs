//! Integration tests for RPM header-metadata extraction on the generic
//! chunked upload path (#2588).
//!
//! RPMs pushed via `/api/v1/uploads` (create session → chunk → complete)
//! used to store no `artifact_metadata` row at all, so `primary.xml` fell
//! back to filename parsing and emitted blank `Source:`/summary/etc. These
//! tests pin that a generically-pushed `.rpm`:
//!
//! 1. records the same header-derived metadata the native RPM PUT records,
//! 2. surfaces that metadata (summary/sourcerpm) in `primary.xml`, and
//! 3. non-RPM companion objects in an RPM repo record no metadata and never
//!    fail the upload.
//!
//! Requires a PostgreSQL database with all migrations applied:
//!
//! ```sh
//! DATABASE_URL="postgresql://registry:registry@localhost:30432/artifact_registry" \
//!   cargo test --test rpm_generic_upload_metadata_tests -- --ignored
//! ```

#![allow(clippy::unwrap_used)]
#![allow(clippy::disallowed_methods)] // test file: buffering response bodies in assertions is not an artifact path (#1608)

use std::collections::HashMap;
use std::io::Read;
use std::path::PathBuf;
use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use sqlx::PgPool;
use tower::ServiceExt;
use uuid::Uuid;

use artifact_keeper_backend::api::handlers::{rpm, upload};
use artifact_keeper_backend::api::middleware::auth::AuthExtension;
use artifact_keeper_backend::api::{AppState, SharedState};
use artifact_keeper_backend::config::Config;
use artifact_keeper_backend::models::access_scope::AccessScope;

/// Real minimal noarch RPM built with rpmbuild (Summary/License/URL set).
const TEST_RPM: &[u8] = include_bytes!("fixtures/ak-meta-test-1.0-1.noarch.rpm");
const TEST_RPM_FILENAME: &str = "ak-meta-test-1.0-1.noarch.rpm";
const TEST_RPM_SUMMARY: &str = "Artifact Keeper metadata test package";
const TEST_RPM_SOURCE_RPM: &str = "ak-meta-test-1.0-1.src.rpm";

// ===========================================================================
// Test helpers
// ===========================================================================

fn build_state(pool: PgPool, storage_path: &str) -> SharedState {
    let config = Config {
        database_url: std::env::var("DATABASE_URL").unwrap_or_default(),
        storage_path: storage_path.into(),
        jwt_secret: "test-secret-at-least-32-bytes-long-for-testing".into(),
        totp_policy: artifact_keeper_backend::config::TotpPolicy::Disabled,
        setup_password_hint: None,
        ..Default::default()
    };
    let storage: Arc<dyn artifact_keeper_backend::storage::StorageBackend> = Arc::new(
        artifact_keeper_backend::storage::filesystem::FilesystemStorage::new(storage_path),
    );
    let registry = Arc::new(artifact_keeper_backend::storage::StorageRegistry::new(
        HashMap::new(),
        "filesystem".to_string(),
    ));
    Arc::new(AppState::new(config, pool, storage, registry))
}

/// The `AuthExtension` shape the real auth middleware injects for an admin
/// JWT login. Layered directly so the routers run without the middleware.
fn admin_auth(user_id: Uuid) -> AuthExtension {
    AuthExtension {
        user_id,
        username: format!("rpm2588-{}", &user_id.to_string()[..8]),
        email: "rpm2588@test.local".to_string(),
        is_admin: true,
        is_api_token: false,
        is_service_account: false,
        scopes: None,
        allowed_repo_ids: AccessScope::Admin,
        iat_ms: None,
    }
}

async fn create_admin_user(pool: &PgPool) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO users (id, username, email, password_hash, auth_provider, is_admin, is_active) \
         VALUES ($1, $2, $3, NULL, 'local', true, true)",
    )
    .bind(id)
    .bind(format!("rpm2588-{}", &id.to_string()[..8]))
    .bind(format!("rpm2588-{}@test.local", &id.to_string()[..8]))
    .execute(pool)
    .await
    .expect("insert admin user");
    id
}

/// Create an rpm-format local repo. Returns (repo_id, key, storage_path).
async fn create_rpm_repo(pool: &PgPool, label: &str) -> (Uuid, String, PathBuf) {
    let id = Uuid::new_v4();
    let key = format!("rpm2588-{}-{}", label, &id.to_string()[..8]);
    let storage_path = std::env::temp_dir().join(&key);
    std::fs::create_dir_all(&storage_path).expect("create storage dir");
    sqlx::query(
        "INSERT INTO repositories (id, key, name, storage_path, repo_type, format, is_public) \
         VALUES ($1, $2, $2, $3, 'local', 'rpm'::repository_format, true)",
    )
    .bind(id)
    .bind(&key)
    .bind(storage_path.to_string_lossy().as_ref())
    .execute(pool)
    .await
    .expect("insert rpm repo");
    (id, key, storage_path)
}

async fn cleanup(pool: &PgPool, repo_ids: &[Uuid], user_id: Uuid) {
    for id in repo_ids {
        for q in [
            "DELETE FROM upload_sessions WHERE repository_id = $1",
            "DELETE FROM artifact_metadata WHERE artifact_id IN \
             (SELECT id FROM artifacts WHERE repository_id = $1)",
            "DELETE FROM artifacts WHERE repository_id = $1",
            "DELETE FROM repositories WHERE id = $1",
        ] {
            sqlx::query(q).bind(id).execute(pool).await.ok();
        }
    }
    sqlx::query("DELETE FROM users WHERE id = $1")
        .bind(user_id)
        .execute(pool)
        .await
        .ok();
}

fn sha256_hex(data: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    format!("{:x}", Sha256::digest(data))
}

fn upload_router(state: &SharedState, auth: &AuthExtension) -> axum::Router {
    upload::router()
        .layer(axum::Extension(auth.clone()))
        .with_state(state.clone())
}

async fn json_body(resp: axum::response::Response) -> serde_json::Value {
    let body = axum::body::to_bytes(resp.into_body(), 10 * 1024 * 1024)
        .await
        .unwrap();
    serde_json::from_slice(&body).unwrap()
}

/// Drive the full generic chunked flow (create session → PATCH chunk →
/// complete) for `content` at `artifact_path`. Returns the artifact id.
async fn generic_upload(
    state: &SharedState,
    auth: &AuthExtension,
    repo_key: &str,
    artifact_path: &str,
    content: &[u8],
) -> Uuid {
    // 1. Create session
    let req_body = serde_json::json!({
        "repository_key": repo_key,
        "artifact_path": artifact_path,
        "total_size": content.len(),
        "checksum_sha256": sha256_hex(content),
        "content_type": "application/octet-stream",
    });
    let resp = upload_router(state, auth)
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/")
                .header("content-type", "application/json")
                .body(Body::from(req_body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED, "create session");
    let session_id = json_body(resp).await["session_id"]
        .as_str()
        .unwrap()
        .to_string();

    // 2. Upload the single chunk
    let resp = upload_router(state, auth)
        .oneshot(
            Request::builder()
                .method("PATCH")
                .uri(format!("/{session_id}"))
                .header(
                    "content-range",
                    format!("bytes 0-{}/{}", content.len() - 1, content.len()),
                )
                .body(Body::from(content.to_vec()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK, "upload chunk");

    // 3. Complete
    let resp = upload_router(state, auth)
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri(format!("/{session_id}/complete"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK, "complete upload");
    Uuid::parse_str(json_body(resp).await["artifact_id"].as_str().unwrap()).unwrap()
}

async fn fetch_metadata(pool: &PgPool, artifact_id: Uuid) -> Option<(String, serde_json::Value)> {
    sqlx::query_as::<_, (String, serde_json::Value)>(
        "SELECT format, metadata FROM artifact_metadata WHERE artifact_id = $1",
    )
    .bind(artifact_id)
    .fetch_optional(pool)
    .await
    .expect("query artifact_metadata")
}

// ===========================================================================
// 1. Generic upload of a real .rpm records header metadata + primary.xml
// ===========================================================================

#[tokio::test]
#[ignore]
async fn test_generic_upload_rpm_records_header_metadata() {
    let pool = PgPool::connect(&std::env::var("DATABASE_URL").unwrap())
        .await
        .unwrap();
    let user_id = create_admin_user(&pool).await;
    let (repo_id, key, storage_path) = create_rpm_repo(&pool, "gen").await;
    let state = build_state(pool.clone(), storage_path.to_str().unwrap());
    let auth = admin_auth(user_id);

    let artifact_id = generic_upload(&state, &auth, &key, TEST_RPM_FILENAME, TEST_RPM).await;

    // The blank-metadata bug: before #2588 no artifact_metadata row existed
    // at all for generically-pushed RPMs.
    let (format, meta) = fetch_metadata(&pool, artifact_id)
        .await
        .expect("generically-pushed .rpm must record artifact_metadata");
    assert_eq!(format, "rpm");
    assert_eq!(meta["name"], "ak-meta-test");
    assert_eq!(meta["version"], "1.0");
    assert_eq!(meta["release"], "1");
    assert_eq!(meta["arch"], "noarch");
    assert_eq!(meta["summary"], TEST_RPM_SUMMARY);
    assert_eq!(meta["license"], "MIT");
    assert_eq!(meta["source_rpm"], TEST_RPM_SOURCE_RPM);

    // And primary.xml must surface it (this is what dnf's `Source:` reads).
    let resp = rpm::router()
        .with_state(state.clone())
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!("/{key}/repodata/primary.xml.gz"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let gz = axum::body::to_bytes(resp.into_body(), 10 * 1024 * 1024)
        .await
        .unwrap();
    let mut xml = String::new();
    flate2::read::GzDecoder::new(&gz[..])
        .read_to_string(&mut xml)
        .unwrap();
    assert!(
        xml.contains(&format!("<summary>{TEST_RPM_SUMMARY}</summary>")),
        "primary.xml must carry the header summary: {xml}"
    );
    assert!(
        xml.contains(&format!(
            "<rpm:sourcerpm>{TEST_RPM_SOURCE_RPM}</rpm:sourcerpm>"
        )),
        "primary.xml must carry the header sourcerpm: {xml}"
    );
    assert!(
        xml.contains("<rpm:license>MIT</rpm:license>"),
        "primary.xml must carry the header license: {xml}"
    );

    cleanup(&pool, &[repo_id], user_id).await;
}

// ===========================================================================
// 2. Generic path metadata matches the native RPM PUT path
// ===========================================================================

#[tokio::test]
#[ignore]
async fn test_generic_upload_rpm_metadata_matches_native_path() {
    let pool = PgPool::connect(&std::env::var("DATABASE_URL").unwrap())
        .await
        .unwrap();
    let user_id = create_admin_user(&pool).await;
    let (gen_repo_id, gen_key, gen_storage) = create_rpm_repo(&pool, "geneq").await;
    let (nat_repo_id, nat_key, _nat_storage) = create_rpm_repo(&pool, "nateq").await;
    let state = build_state(pool.clone(), gen_storage.to_str().unwrap());
    let auth = admin_auth(user_id);

    // Generic chunked push into repo A.
    let gen_artifact_id =
        generic_upload(&state, &auth, &gen_key, TEST_RPM_FILENAME, TEST_RPM).await;

    // Native RPM PUT into repo B.
    let resp = rpm::router()
        .layer(axum::Extension(Some(auth.clone())))
        .with_state(state.clone())
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri(format!("/{nat_key}/packages/{TEST_RPM_FILENAME}"))
                .body(Body::from(TEST_RPM.to_vec()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED, "native RPM PUT");
    let nat_artifact_id: Uuid = sqlx::query_scalar(
        "SELECT id FROM artifacts WHERE repository_id = $1 AND is_deleted = false",
    )
    .bind(nat_repo_id)
    .fetch_one(&pool)
    .await
    .expect("native artifact row");

    let (_, gen_meta) = fetch_metadata(&pool, gen_artifact_id)
        .await
        .expect("generic metadata");
    let (_, nat_meta) = fetch_metadata(&pool, nat_artifact_id)
        .await
        .expect("native metadata");

    // Both paths must yield the same header-derived format metadata.
    for field in [
        "name",
        "version",
        "release",
        "arch",
        "filename",
        "summary",
        "description",
        "license",
        "url",
        "source_rpm",
    ] {
        assert_eq!(
            gen_meta.get(field),
            nat_meta.get(field),
            "generic vs native mismatch on '{field}'"
        );
    }

    cleanup(&pool, &[gen_repo_id, nat_repo_id], user_id).await;
}

// ===========================================================================
// 3. Non-RPM companion objects: no metadata row, upload still succeeds
// ===========================================================================

#[tokio::test]
#[ignore]
async fn test_generic_upload_non_rpm_object_records_no_metadata() {
    let pool = PgPool::connect(&std::env::var("DATABASE_URL").unwrap())
        .await
        .unwrap();
    let user_id = create_admin_user(&pool).await;
    let (repo_id, key, storage_path) = create_rpm_repo(&pool, "txt").await;
    let state = build_state(pool.clone(), storage_path.to_str().unwrap());
    let auth = admin_auth(user_id);

    // A checksum sidecar: not a package, must not be described as one.
    let artifact_id =
        generic_upload(&state, &auth, &key, "CHECKSUMS.sha256", b"abc  file.rpm\n").await;
    assert!(
        fetch_metadata(&pool, artifact_id).await.is_none(),
        "non-.rpm objects must not record rpm metadata"
    );

    // A .rpm-named blob with unparseable content and a non-NEVRA name:
    // upload succeeds, no metadata row (graceful degradation).
    let artifact_id = generic_upload(&state, &auth, &key, "bad.rpm", b"not really an rpm").await;
    assert!(
        fetch_metadata(&pool, artifact_id).await.is_none(),
        "unparseable .rpm with non-NEVRA name records no metadata"
    );

    cleanup(&pool, &[repo_id], user_id).await;
}
