//! Integration tests for per-repository storage backend selection.
//!
//! These tests require a running backend HTTP server.
//!
//! ```sh
//! export TEST_BASE_URL="http://127.0.0.1:9080"
//! cargo test --test storage_backend_tests -- --ignored
//! ```

#![allow(clippy::disallowed_methods)] // streaming-invariant: test file exempt — buffering response bodies in test assertions is not an artifact path (#1608)
use reqwest::Client;
use serde_json::{json, Value};
use std::env;

fn base_url() -> String {
    env::var("TEST_BASE_URL").unwrap_or_else(|_| "http://127.0.0.1:9080".into())
}

async fn admin_login() -> String {
    let client = Client::new();
    let resp = client
        .post(format!("{}/api/v1/auth/login", base_url()))
        .json(&json!({
            "username": "admin",
            "password": "admin123"
        }))
        .send()
        .await
        .expect("login request failed");

    let body: Value = resp.json().await.expect("login response not JSON");
    body["access_token"]
        .as_str()
        .expect("no access_token in login response")
        .to_string()
}

fn unique_key(prefix: &str) -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis();
    format!("{}-{}", prefix, ts)
}

// ---------------------------------------------------------------------------
// Default backend applied when storage_backend is omitted
// ---------------------------------------------------------------------------

#[tokio::test]
#[ignore]
async fn test_create_repo_default_backend() {
    let token = admin_login().await;
    let client = Client::new();
    let key = unique_key("sb-default");

    let resp = client
        .post(format!("{}/api/v1/repositories", base_url()))
        .header("Authorization", format!("Bearer {}", token))
        .json(&json!({
            "key": key,
            "name": "Default Backend Test",
            "format": "generic",
            "repo_type": "local",
            "is_public": true
        }))
        .send()
        .await
        .expect("create repo request failed");

    assert!(
        resp.status().is_success(),
        "expected 200, got {}",
        resp.status()
    );
}

// ---------------------------------------------------------------------------
// Explicit filesystem backend works
// ---------------------------------------------------------------------------

#[tokio::test]
#[ignore]
async fn test_create_repo_explicit_filesystem_backend() {
    let token = admin_login().await;
    let client = Client::new();
    let key = unique_key("sb-fs");

    let resp = client
        .post(format!("{}/api/v1/repositories", base_url()))
        .header("Authorization", format!("Bearer {}", token))
        .json(&json!({
            "key": key,
            "name": "Filesystem Backend Test",
            "format": "generic",
            "repo_type": "local",
            "is_public": true,
            "storage_backend": "filesystem"
        }))
        .send()
        .await
        .expect("create repo request failed");

    assert!(
        resp.status().is_success(),
        "expected 200, got {}",
        resp.status()
    );
}

// ---------------------------------------------------------------------------
// Unavailable backend returns 400
// ---------------------------------------------------------------------------

#[tokio::test]
#[ignore]
async fn test_create_repo_unavailable_backend_returns_400() {
    let token = admin_login().await;
    let client = Client::new();
    let key = unique_key("sb-unavail");

    // Request a backend that is almost certainly not configured in the test env
    let resp = client
        .post(format!("{}/api/v1/repositories", base_url()))
        .header("Authorization", format!("Bearer {}", token))
        .json(&json!({
            "key": key,
            "name": "Unavailable Backend Test",
            "format": "generic",
            "repo_type": "local",
            "is_public": true,
            "storage_backend": "gcs"
        }))
        .send()
        .await
        .expect("create repo request failed");

    assert_eq!(
        resp.status().as_u16(),
        400,
        "expected 400 for unavailable backend, got {}",
        resp.status()
    );
}

// ---------------------------------------------------------------------------
// Admin storage-backends endpoint returns list including filesystem
// ---------------------------------------------------------------------------

#[tokio::test]
#[ignore]
async fn test_admin_storage_backends_endpoint() {
    let token = admin_login().await;
    let client = Client::new();

    let resp = client
        .get(format!("{}/api/v1/admin/storage-backends", base_url()))
        .header("Authorization", format!("Bearer {}", token))
        .send()
        .await
        .expect("storage-backends request failed");

    assert!(
        resp.status().is_success(),
        "expected 200, got {}",
        resp.status()
    );

    let backends: Vec<String> = resp.json().await.expect("response not JSON array");
    assert!(
        backends.contains(&"filesystem".to_string()),
        "filesystem should always be available, got: {:?}",
        backends
    );
}

// ---------------------------------------------------------------------------
// Unauthenticated request to admin endpoint returns 401
// ---------------------------------------------------------------------------

#[tokio::test]
#[ignore]
async fn test_admin_storage_backends_requires_auth() {
    let client = Client::new();

    let resp = client
        .get(format!("{}/api/v1/admin/storage-backends", base_url()))
        .send()
        .await
        .expect("storage-backends request failed");

    assert_eq!(
        resp.status().as_u16(),
        401,
        "expected 401 without auth, got {}",
        resp.status()
    );
}

// ---------------------------------------------------------------------------
// Artifact upload and download works with explicit filesystem backend
// ---------------------------------------------------------------------------

#[tokio::test]
#[ignore]
async fn test_upload_download_with_explicit_filesystem_backend() {
    let token = admin_login().await;
    let client = Client::new();
    let key = unique_key("sb-upload");

    // Create repo with explicit filesystem backend
    let resp = client
        .post(format!("{}/api/v1/repositories", base_url()))
        .header("Authorization", format!("Bearer {}", token))
        .json(&json!({
            "key": key,
            "name": "Upload Test",
            "format": "generic",
            "repo_type": "local",
            "is_public": true,
            "storage_backend": "filesystem"
        }))
        .send()
        .await
        .expect("create repo request failed");
    assert!(resp.status().is_success(), "repo creation failed");

    // Upload an artifact
    let content = b"hello storage backend test";
    let resp = client
        .put(format!(
            "{}/api/v1/repositories/{}/artifacts/test.txt",
            base_url(),
            key
        ))
        .header("Authorization", format!("Bearer {}", token))
        .header("Content-Type", "application/octet-stream")
        .body(content.to_vec())
        .send()
        .await
        .expect("upload request failed");
    assert!(
        resp.status().is_success(),
        "upload failed with {}",
        resp.status()
    );

    // Download the artifact
    let resp = client
        .get(format!(
            "{}/api/v1/repositories/{}/artifacts/test.txt",
            base_url(),
            key
        ))
        .header("Authorization", format!("Bearer {}", token))
        .send()
        .await
        .expect("download request failed");
    assert!(
        resp.status().is_success(),
        "download failed with {}",
        resp.status()
    );

    let body = resp.bytes().await.expect("failed to read body");
    assert_eq!(body.as_ref(), content, "downloaded content does not match");
}
