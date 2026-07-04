//! S3 integration tests that exercise the object_store-based S3Backend
//! against a real AWS S3 bucket.
//!
//! Run with:
//!   S3_BUCKET=ak-s3-integration-test-567 \
//!   S3_REGION=us-east-1 \
//!   S3_ACCESS_KEY_ID=... \
//!   S3_SECRET_ACCESS_KEY=... \
//!   cargo test --test s3_integration -- --ignored --nocapture

#![allow(clippy::disallowed_methods)] // streaming-invariant: test file exempt — buffering response bodies in test assertions is not an artifact path (#1608)
use artifact_keeper_backend::storage::s3::{S3Backend, S3Config};
use artifact_keeper_backend::storage::StorageBackend;
use bytes::Bytes;
use std::time::Duration;

fn test_prefix() -> String {
    format!(
        "integration-test-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis()
    )
}

fn skip_unless_configured() -> Option<(String, String, String, String)> {
    let bucket = std::env::var("S3_BUCKET").ok()?;
    let region = std::env::var("S3_REGION").unwrap_or_else(|_| "us-east-1".to_string());
    let ak = std::env::var("S3_ACCESS_KEY_ID").ok()?;
    let sk = std::env::var("S3_SECRET_ACCESS_KEY").ok()?;
    Some((bucket, region, ak, sk))
}

async fn make_backend(prefix: &str, redirect: bool) -> S3Backend {
    let bucket = std::env::var("S3_BUCKET").expect("S3_BUCKET");
    let region = std::env::var("S3_REGION").unwrap_or_else(|_| "us-east-1".to_string());
    let endpoint = std::env::var("S3_ENDPOINT").ok();
    let mut config = S3Config::new(bucket, region, endpoint, Some(prefix.to_string()))
        .with_redirect_downloads(redirect)
        .with_presign_expiry(Duration::from_secs(300));

    // Pick up TLS config from env (same as from_env() does)
    if let Ok(ca_path) = std::env::var("S3_CA_CERT_PATH") {
        config = config.with_ca_cert_path(ca_path);
    }
    if std::env::var("S3_INSECURE_TLS")
        .map(|v| v.to_lowercase() == "true" || v == "1")
        .unwrap_or(false)
    {
        config = config.with_insecure_tls(true);
    }

    S3Backend::new(config).await.expect("S3Backend::new failed")
}

// ========= Core StorageBackend operations =========

#[tokio::test]
#[ignore]
async fn test_put_and_get() {
    if skip_unless_configured().is_none() {
        println!("Skipping: S3 not configured");
        return;
    }
    let prefix = test_prefix();
    let backend = make_backend(&prefix, false).await;

    let key = "test-put-get.txt";
    let content = Bytes::from("hello from object_store integration test");

    // PUT
    backend.put(key, content.clone()).await.expect("put failed");
    println!("PUT ok: {key}");

    // GET
    let got = backend.get(key).await.expect("get failed");
    assert_eq!(got, content, "GET content mismatch");
    println!("GET ok: {key} ({} bytes)", got.len());

    // Cleanup
    backend.delete(key).await.expect("delete failed");
    println!("Cleanup ok");
}

#[tokio::test]
#[ignore]
async fn test_exists_and_not_exists() {
    if skip_unless_configured().is_none() {
        return;
    }
    let prefix = test_prefix();
    let backend = make_backend(&prefix, false).await;

    let key = "test-exists.txt";
    backend
        .put(key, Bytes::from("exists"))
        .await
        .expect("put failed");

    assert!(backend.exists(key).await.expect("exists failed"));
    println!("EXISTS (true) ok: {key}");

    assert!(!backend
        .exists("does-not-exist.txt")
        .await
        .expect("exists failed"));
    println!("EXISTS (false) ok: does-not-exist.txt");

    backend.delete(key).await.expect("delete failed");
}

#[tokio::test]
#[ignore]
async fn test_delete_idempotent() {
    if skip_unless_configured().is_none() {
        return;
    }
    let prefix = test_prefix();
    let backend = make_backend(&prefix, false).await;

    // Delete a key that never existed -- S3 returns 204, should be Ok
    backend
        .delete("never-existed.txt")
        .await
        .expect("idempotent delete failed");
    println!("DELETE idempotent ok");
}

#[tokio::test]
#[ignore]
async fn test_get_not_found() {
    if skip_unless_configured().is_none() {
        return;
    }
    let prefix = test_prefix();
    let backend = make_backend(&prefix, false).await;

    let result = backend.get("not-found.txt").await;
    assert!(result.is_err(), "GET non-existent should error");
    let err = result.unwrap_err().to_string();
    assert!(
        err.contains("not found") || err.contains("NotFound") || err.contains("Not Found"),
        "Error should indicate not found, got: {err}"
    );
    println!("GET NotFound ok: {err}");
}

// ========= Extended operations =========

#[tokio::test]
#[ignore]
async fn test_list() {
    if skip_unless_configured().is_none() {
        return;
    }
    let prefix = test_prefix();
    let backend = make_backend(&prefix, false).await;

    // Put 3 objects
    for i in 0..3 {
        let key = format!("list-test/file-{i}.txt");
        backend
            .put(&key, Bytes::from(format!("content-{i}")))
            .await
            .expect("put failed");
    }

    let keys = backend.list(Some("list-test/")).await.expect("list failed");
    assert_eq!(keys.len(), 3, "Expected 3 items, got {}", keys.len());
    println!("LIST ok: {} items", keys.len());
    for k in &keys {
        println!("  - {k}");
    }

    // Cleanup
    for i in 0..3 {
        backend
            .delete(&format!("list-test/file-{i}.txt"))
            .await
            .expect("delete failed");
    }
}

#[tokio::test]
#[ignore]
async fn test_copy() {
    if skip_unless_configured().is_none() {
        return;
    }
    let prefix = test_prefix();
    let backend = make_backend(&prefix, false).await;

    let src = "copy-src.txt";
    let dst = "copy-dst.txt";
    let content = Bytes::from("copy me");

    backend.put(src, content.clone()).await.expect("put failed");
    backend.copy(src, dst).await.expect("copy failed");

    let got = backend.get(dst).await.expect("get dst failed");
    assert_eq!(got, content, "Copied content mismatch");
    println!("COPY ok: {src} -> {dst}");

    backend.delete(src).await.ok();
    backend.delete(dst).await.ok();
}

#[tokio::test]
#[ignore]
async fn test_size() {
    if skip_unless_configured().is_none() {
        return;
    }
    let prefix = test_prefix();
    let backend = make_backend(&prefix, false).await;

    let key = "size-test.txt";
    let content = Bytes::from("exactly 20 bytes!!!!");
    assert_eq!(content.len(), 20);

    backend.put(key, content).await.expect("put failed");
    let size = backend.size(key).await.expect("size failed");
    assert_eq!(size, 20, "Size mismatch: expected 20, got {size}");
    println!("SIZE ok: {size} bytes");

    backend.delete(key).await.ok();
}

// ========= Presigned URLs =========

#[tokio::test]
#[ignore]
async fn test_presigned_url_generation_and_download() {
    if skip_unless_configured().is_none() {
        return;
    }
    let prefix = test_prefix();
    let backend = make_backend(&prefix, true).await;

    let key = "presign-test.txt";
    let content = Bytes::from("presigned content");

    backend.put(key, content.clone()).await.expect("put failed");

    assert!(backend.supports_redirect());

    let presigned = backend
        .get_presigned_url(key, Duration::from_secs(300))
        .await
        .expect("presign failed");

    let presigned = presigned.expect("presign should return Some when redirect enabled");
    assert!(
        presigned.url.contains("X-Amz-Signature"),
        "URL should contain signature: {}",
        presigned.url
    );
    println!("Presigned URL: {}...", &presigned.url[..80]);

    // Actually download via the presigned URL
    let client = reqwest::Client::new();
    let resp = client
        .get(&presigned.url)
        .send()
        .await
        .expect("fetch failed");
    assert!(resp.status().is_success(), "Status: {}", resp.status());
    let body = resp.bytes().await.expect("body read failed");
    assert_eq!(body.as_ref(), content.as_ref(), "Content mismatch");
    println!("Presigned download ok: {} bytes", body.len());

    backend.delete(key).await.ok();
}

#[tokio::test]
#[ignore]
async fn test_presigned_url_not_returned_when_redirect_disabled() {
    if skip_unless_configured().is_none() {
        return;
    }
    let prefix = test_prefix();
    let backend = make_backend(&prefix, false).await;

    assert!(!backend.supports_redirect());

    let presigned = backend
        .get_presigned_url("any-key", Duration::from_secs(300))
        .await
        .expect("presign call failed");
    assert!(
        presigned.is_none(),
        "Should return None when redirect disabled"
    );
    println!("Presigned URL correctly None when redirect disabled");
}

// ========= Health check =========

#[tokio::test]
#[ignore]
async fn test_health_check() {
    if skip_unless_configured().is_none() {
        return;
    }
    let prefix = test_prefix();
    let backend = make_backend(&prefix, false).await;

    backend.health_check().await.expect("health check failed");
    println!("Health check ok");
}

// ========= Binary content =========

#[tokio::test]
#[ignore]
async fn test_binary_content_roundtrip() {
    if skip_unless_configured().is_none() {
        return;
    }
    let prefix = test_prefix();
    let backend = make_backend(&prefix, false).await;

    let key = "binary-test.bin";
    // All byte values 0-255
    let content = Bytes::from((0u8..=255).collect::<Vec<u8>>());

    backend.put(key, content.clone()).await.expect("put failed");
    let got = backend.get(key).await.expect("get failed");
    assert_eq!(got, content, "Binary roundtrip mismatch");
    println!("Binary roundtrip ok: {} bytes", got.len());

    backend.delete(key).await.ok();
}

// ========= Large object =========

#[tokio::test]
#[ignore]
async fn test_large_object_1mb() {
    if skip_unless_configured().is_none() {
        return;
    }
    let prefix = test_prefix();
    let backend = make_backend(&prefix, false).await;

    let key = "large-1mb.bin";
    let content = Bytes::from(vec![0xABu8; 1_048_576]);

    backend.put(key, content.clone()).await.expect("put failed");

    let size = backend.size(key).await.expect("size failed");
    assert_eq!(size, 1_048_576, "Size: {size}");

    let got = backend.get(key).await.expect("get failed");
    assert_eq!(got.len(), 1_048_576, "GET len: {}", got.len());
    assert_eq!(got, content, "Content mismatch");
    println!("Large object (1MB) roundtrip ok");

    backend.delete(key).await.ok();
}
