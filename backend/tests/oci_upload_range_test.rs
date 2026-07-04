//! HTTP-level integration tests for the OCI upload `Range` response header
//! (issue #1410, follow-up to PR #1345 which fixed the inclusive Range
//! arithmetic in `upload_progress_range()`).
//!
//! PR #1345 added a strong *unit* test for `upload_progress_range()` but no
//! HTTP-level test asserting the actual header value emitted by the PATCH
//! handler. A refactor that dropped the helper call and inlined
//! `format!("0-{}", new_bytes)` (without the `- 1`) would silently regress the
//! inclusive-range contract while keeping the unit test green. These tests pin
//! the boundary: for a PATCH body of length `N` the `Range` header must be
//! `0-<N-1>`, so such an inlining would flip `0-0` to `0-1` for `N == 1` and
//! fail here.
//!
//! Requires a PostgreSQL database with all migrations applied:
//!
//! ```sh
//! DATABASE_URL="postgresql://registry:registry@localhost:30432/artifact_registry" \
//!   cargo test --test oci_upload_range_test -- --ignored
//! ```
//!
//! Each test is additionally guarded by [`try_pool`], so it skips cleanly (no
//! panic) when no database is reachable.

#![allow(clippy::unwrap_used)]
#![allow(clippy::disallowed_methods)] // streaming-invariant: test file exempt — buffering response bodies in test assertions is not an artifact path (#1608)
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;

use axum::body::Body;
use axum::http::{HeaderMap, Request, StatusCode};
use sqlx::PgPool;
use tower::ServiceExt;
use uuid::Uuid;

use artifact_keeper_backend::api::handlers::oci_v2;
use artifact_keeper_backend::api::{AppState, SharedState};
use artifact_keeper_backend::config::Config;

// ===========================================================================
// Test helpers (mirrors oci_chunked_upload_cross_repo_tests.rs)
// ===========================================================================

/// Connect to the test database. Returns `None` when `DATABASE_URL` is unset or
/// unreachable so the suite no-ops gracefully instead of flaking.
async fn try_pool() -> Option<PgPool> {
    let url = std::env::var("DATABASE_URL").ok()?;
    sqlx::postgres::PgPoolOptions::new()
        .max_connections(3)
        .acquire_timeout(std::time::Duration::from_secs(3))
        .connect(&url)
        .await
        .ok()
}

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

/// Create a docker-format local repo. Returns (repo_id, key, storage_path).
async fn create_typed_oci_repo(pool: &PgPool, label: &str) -> (Uuid, String, PathBuf) {
    let id = Uuid::new_v4();
    let key = format!("oci1410-{}-{}", label, &id.to_string()[..8]);
    let storage_path = std::env::temp_dir().join(format!("oci1410-{}", id));
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

async fn cleanup(pool: &PgPool, repo_ids: &[Uuid], user_id: Uuid) {
    for id in repo_ids {
        sqlx::query("DELETE FROM oci_upload_sessions WHERE repository_id = $1")
            .bind(id)
            .execute(pool)
            .await
            .ok();
        sqlx::query("DELETE FROM oci_blobs WHERE repository_id = $1")
            .bind(id)
            .execute(pool)
            .await
            .ok();
        sqlx::query("DELETE FROM repositories WHERE id = $1")
            .bind(id)
            .execute(pool)
            .await
            .ok();
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

fn range_header(headers: &HeaderMap) -> String {
    headers
        .get("Range")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_string()
}

/// POST a fresh upload session under `repo_key`/`image` and return its session
/// UUID (from the `Docker-Upload-UUID` response header).
async fn start_upload(state: &SharedState, repo_key: &str, image: &str, auth: &str) -> Uuid {
    let app = oci_v2::router().with_state(state.clone());
    let req = Request::builder()
        .method("POST")
        .uri(format!("/{}/{}/blobs/uploads/", repo_key, image))
        .header("Authorization", auth)
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::ACCEPTED,
        "POST start upload should return 202"
    );
    resp.headers()
        .get("Docker-Upload-UUID")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| Uuid::parse_str(v).ok())
        .expect("POST start must emit a Docker-Upload-UUID header")
}

// ===========================================================================
// #1410: the Range response header must be the inclusive `0-<n-1>`.
// ===========================================================================

#[tokio::test]
#[ignore = "requires DATABASE_URL pointed at a Postgres with migrations applied"]
async fn patch_range_header_is_inclusive_for_various_lengths() {
    let Some(pool) = try_pool().await else {
        return;
    };
    let username = format!("oci1410-{}", &Uuid::new_v4().to_string()[..8]);
    let user_id = create_test_user(&pool, &username, "pushpass").await;
    let (repo_id, key, storage_path) = create_typed_oci_repo(&pool, "len").await;
    let state = build_state(pool.clone(), storage_path.to_str().unwrap());
    let auth = basic_auth_header(&username, "pushpass");

    // A single PATCH of exactly N bytes on a fresh session must report the
    // inclusive byte range `0-<N-1>`. N == 1 is the discriminating case: an
    // inlined `format!("0-{}", new_bytes)` would emit `0-1` here.
    for n in [1usize, 2, 17, 4096] {
        let session_id = start_upload(&state, &key, "img", &auth).await;
        let app = oci_v2::router().with_state(state.clone());
        let body = vec![b'a'; n];
        let req = Request::builder()
            .method("PATCH")
            .uri(format!("/{}/img/blobs/uploads/{}", key, session_id))
            .header("Authorization", &auth)
            .body(Body::from(body))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        let status = resp.status();
        let range = range_header(resp.headers());
        assert_eq!(
            status,
            StatusCode::ACCEPTED,
            "PATCH of {n} bytes should 202"
        );
        assert_eq!(
            range,
            format!("0-{}", n - 1),
            "PATCH of {n} bytes must report inclusive Range 0-{}",
            n - 1
        );
    }

    let _ = std::fs::remove_dir_all(&storage_path);
    cleanup(&pool, &[repo_id], user_id).await;
}

#[tokio::test]
#[ignore = "requires DATABASE_URL pointed at a Postgres with migrations applied"]
async fn patch_zero_byte_body_range_is_zero_zero() {
    let Some(pool) = try_pool().await else {
        return;
    };
    let username = format!("oci1410-{}", &Uuid::new_v4().to_string()[..8]);
    let user_id = create_test_user(&pool, &username, "pushpass").await;
    let (repo_id, key, storage_path) = create_typed_oci_repo(&pool, "zero").await;
    let state = build_state(pool.clone(), storage_path.to_str().unwrap());
    let auth = basic_auth_header(&username, "pushpass");

    let session_id = start_upload(&state, &key, "img", &auth).await;
    let app = oci_v2::router().with_state(state.clone());
    let req = Request::builder()
        .method("PATCH")
        .uri(format!("/{}/img/blobs/uploads/{}", key, session_id))
        .header("Authorization", &auth)
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    let status = resp.status();
    let range = range_header(resp.headers());
    assert_eq!(status, StatusCode::ACCEPTED, "empty PATCH should 202");
    // A 0-byte upload reports `0-0` (registry convention, pinned by design).
    assert_eq!(range, "0-0", "0-byte upload must report Range 0-0");

    let _ = std::fs::remove_dir_all(&storage_path);
    cleanup(&pool, &[repo_id], user_id).await;
}

#[tokio::test]
#[ignore = "requires DATABASE_URL pointed at a Postgres with migrations applied"]
async fn resume_contract_honors_returned_range_and_digest_verifies() {
    let Some(pool) = try_pool().await else {
        return;
    };
    let username = format!("oci1410-{}", &Uuid::new_v4().to_string()[..8]);
    let user_id = create_test_user(&pool, &username, "pushpass").await;
    let (repo_id, key, storage_path) = create_typed_oci_repo(&pool, "resume").await;
    let state = build_state(pool.clone(), storage_path.to_str().unwrap());
    let auth = basic_auth_header(&username, "pushpass");

    let part_a = b"the-first-chunk-of-bytes".to_vec();
    let part_b = b"and-the-second-chunk".to_vec();
    let mut whole = part_a.clone();
    whole.extend_from_slice(&part_b);
    let digest = format!("sha256:{}", sha256_hex(&whole));

    let session_id = start_upload(&state, &key, "img", &auth).await;

    // First PATCH: offset 0. The returned inclusive Range end is the last byte
    // written, so the next write must start at end + 1.
    let app = oci_v2::router().with_state(state.clone());
    let req = Request::builder()
        .method("PATCH")
        .uri(format!("/{}/img/blobs/uploads/{}", key, session_id))
        .header("Authorization", &auth)
        .body(Body::from(part_a.clone()))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::ACCEPTED);
    let range = range_header(resp.headers());
    assert_eq!(range, format!("0-{}", part_a.len() - 1));
    let next_offset: i64 = range
        .split_once('-')
        .and_then(|(_, end)| end.parse::<i64>().ok())
        .expect("Range must be `start-end`")
        + 1;
    assert_eq!(next_offset, part_a.len() as i64);

    // Second PATCH: resume at the offset the server just reported, asserted via
    // an explicit inclusive Content-Range. If the offset math were wrong the
    // server's `Content-Range starts at .. expected ..` guard would reject it.
    let app = oci_v2::router().with_state(state.clone());
    let content_range = format!("{}-{}", next_offset, whole.len() - 1);
    let req = Request::builder()
        .method("PATCH")
        .uri(format!("/{}/img/blobs/uploads/{}", key, session_id))
        .header("Authorization", &auth)
        .header("Content-Range", &content_range)
        .header("Content-Length", part_b.len().to_string())
        .body(Body::from(part_b.clone()))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    let status = resp.status();
    let range = range_header(resp.headers());
    assert_eq!(
        status,
        StatusCode::ACCEPTED,
        "resumed PATCH at correct offset should 202"
    );
    assert_eq!(
        range,
        format!("0-{}", whole.len() - 1),
        "after resume the cumulative Range must cover the whole body"
    );

    // Finalize honoring the returned progress: the concatenated bytes must hash
    // to the requested digest, or completion fails with DIGEST_INVALID.
    let app = oci_v2::router().with_state(state.clone());
    let req = Request::builder()
        .method("PUT")
        .uri(format!(
            "/{}/img/blobs/uploads/{}?digest={}",
            key, session_id, digest
        ))
        .header("Authorization", &auth)
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    let status = resp.status();
    let content_digest = resp
        .headers()
        .get("Docker-Content-Digest")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_string();
    assert_eq!(
        status,
        StatusCode::CREATED,
        "final PUT with the correct digest should 201"
    );
    assert_eq!(
        content_digest, digest,
        "the finalized blob digest must match the resumed upload"
    );

    let _ = std::fs::remove_dir_all(&storage_path);
    cleanup(&pool, &[repo_id], user_id).await;
}
