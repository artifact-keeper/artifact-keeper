//! Live integration tests for Azure Shared Key auth (backwards compatibility)
//! and Put Blob From URL signed with it (#4963).
//!
//! Requires env vars:
//!   AZURE_STORAGE_ACCOUNT, AZURE_STORAGE_CONTAINER, AZURE_STORAGE_ACCESS_KEY
//!
//! Run with:
//!   cargo nextest run -p artifact-keeper-backend --test azure_shared_key_live_test --run-ignored all
//!
//! SAS URLs carry signatures, and when Azure refuses a signature its error body
//! quotes the string it signed, source SAS included. The backend's errors leave
//! that body out (#5181), but this file also reads Azure's responses directly,
//! so nothing here prints either: errors go through `redacted` before they
//! reach a panic message.

use artifact_keeper_backend::storage::azure::{AzureBackend, AzureConfig, AzureCopyPath};
use artifact_keeper_backend::storage::{StorageBackend, StoragePathFormat};
use bytes::{Bytes, BytesMut};
use futures::{StreamExt, TryStreamExt};
use std::future::Future;
use std::sync::Arc;
use std::time::Duration;
use wiremock::matchers::{header_exists, method, query_param};
use wiremock::{Mock, MockServer, ResponseTemplate};

/// Prefix every Put Blob From URL test blob lives under.
const LIVE_PREFIX: &str = "ak-4963-live";
/// Larger than `AZURE_BLOCK_CHUNK_SIZE` (4 MiB), so the block-upload fallback
/// would have to commit several blocks, and small enough to stay cheap. The Put
/// Blob From URL ceiling (5000 MiB) is out of reach of a test this size.
const BIG_BLOB_LEN: usize = 32 * 1024 * 1024;

fn live_config() -> AzureConfig {
    let account = std::env::var("AZURE_STORAGE_ACCOUNT").expect("AZURE_STORAGE_ACCOUNT not set");
    let container =
        std::env::var("AZURE_STORAGE_CONTAINER").expect("AZURE_STORAGE_CONTAINER not set");
    let access_key =
        std::env::var("AZURE_STORAGE_ACCESS_KEY").expect("AZURE_STORAGE_ACCESS_KEY not set");

    println!("Testing Azure Shared Key against {}/{}", account, container);

    AzureConfig {
        account_name: account,
        container_name: container,
        access_key: Some(access_key),
        endpoint: None,
        public_endpoint: None,
        redirect_downloads: true,
        sas_expiry: Duration::from_secs(3600),
        path_format: StoragePathFormat::Native,
        copy_timeout_floor: Duration::ZERO,
    }
}

async fn live_backend() -> AzureBackend {
    let backend = AzureBackend::new(live_config())
        .await
        .expect("Failed to create Azure Shared Key backend");
    assert!(!backend.is_rbac(), "Backend should be in Shared Key mode");
    backend
}

/// An error's text with SAS and request signatures removed. Azure's code,
/// message and the string it signed stay readable.
fn redacted(error: impl std::fmt::Display) -> String {
    let text = error.to_string();
    let text = regex::Regex::new(r"sig=[^&\s'<]*")
        .unwrap()
        .replace_all(&text, "sig=REDACTED");
    regex::Regex::new(r"(?s)MAC signature found in the HTTP request '[^']*'")
        .unwrap()
        .replace_all(&text, "MAC signature found in the HTTP request 'REDACTED'")
        .into_owned()
}

/// Bytes that do not repeat, so a truncated or misordered copy cannot match.
fn patterned_bytes(len: usize, seed: u64) -> Bytes {
    let mut state = seed | 1;
    let mut out = BytesMut::with_capacity(len + 8);
    while out.len() < len {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        out.extend_from_slice(&state.to_le_bytes());
    }
    out.truncate(len);
    out.freeze()
}

async fn delete_prefix(backend: &AzureBackend, prefix: &str) -> Result<Vec<String>, String> {
    for key in backend.list(Some(prefix)).await.map_err(redacted)? {
        backend.delete(&key).await.map_err(redacted)?;
    }
    backend.list(Some(prefix)).await.map_err(redacted)
}

/// Run `body` against the live account under a fresh prefix, and delete what it
/// created whether it passes or panics.
async fn with_live_prefix<F, Fut>(body: F)
where
    F: FnOnce(Arc<AzureBackend>, String) -> Fut,
    Fut: Future<Output = ()> + Send + 'static,
{
    let backend = Arc::new(live_backend().await);
    let prefix = format!("{}/{}/", LIVE_PREFIX, uuid::Uuid::new_v4());
    let outcome = tokio::spawn(body(backend.clone(), prefix.clone())).await;
    let cleanup = delete_prefix(&backend, &prefix).await;
    if let Err(error) = outcome {
        std::panic::resume_unwind(error.into_panic());
    }
    let leftovers = cleanup.expect("cleanup failed");
    assert!(leftovers.is_empty(), "blobs left behind: {:?}", leftovers);
}

/// The number of committed blocks Azure reports for `key` (Get Block List).
///
/// This is Azure's own record of how a blob was written, independent of what
/// the backend says it did: a block upload ends in Put Block List and has
/// committed blocks, Put Blob From URL has none.
async fn committed_blocks(backend: &AzureBackend, key: &str) -> usize {
    let url = backend
        .generate_sas_url(key, Duration::from_secs(300))
        .map_err(redacted)
        .expect("SAS for Get Block List");
    let response = reqwest::get(format!("{}&comp=blocklist&blocklisttype=committed", url))
        .await
        .map_err(|e| redacted(e.without_url()))
        .expect("Get Block List request");
    let status = response.status();
    let body = response.text().await.unwrap_or_default();
    assert!(
        status.is_success(),
        "Get Block List answered {}: {}",
        status,
        redacted(&body)
    );
    body.matches("<Block>").count()
}

async fn read_all(backend: &AzureBackend, key: &str) -> Bytes {
    let chunks: Vec<Bytes> = backend
        .get_stream(key)
        .await
        .map_err(redacted)
        .expect("open read stream")
        .map_err(redacted)
        .try_collect()
        .await
        .expect("read stream");
    let mut out = BytesMut::new();
    for chunk in chunks {
        out.extend_from_slice(&chunk);
    }
    out.freeze()
}

/// `dest` holds exactly `expected`, and Azure's block list shows it was not
/// written by a block upload.
async fn assert_server_side_copy(backend: &AzureBackend, dest: &str, expected: &Bytes) {
    assert_eq!(
        committed_blocks(backend, dest).await,
        0,
        "the destination was written by a block upload, so the fallback ran"
    );
    let size = backend.size(dest).await.map_err(redacted).expect("size");
    assert_eq!(size, expected.len() as u64, "destination length");
    let copied = read_all(backend, dest).await;
    assert_eq!(copied.len(), expected.len(), "destination bytes read back");
    // Not assert_eq!: a failure must not print megabytes of blob.
    assert!(copied == *expected, "destination bytes differ from source");
}

/// Copy `content` from a fresh source through the production path and prove
/// Put Blob From URL did it.
async fn copy_and_verify(backend: &AzureBackend, prefix: &str, content: Bytes) {
    let source = format!("{}source", prefix);
    let dest = format!("{}dest", prefix);
    backend
        .put(&source, content.clone())
        .await
        .map_err(redacted)
        .expect("upload source");
    let path = backend
        .copy_reporting_path(&source, &dest)
        .await
        .map_err(redacted)
        .expect("Put Blob From URL with Shared Key");
    assert_eq!(path, AzureCopyPath::PutBlobFromUrl);
    assert_server_side_copy(backend, &dest, &content).await;
    println!("  copied {} bytes server-side", content.len());
}

#[tokio::test]
#[ignore]
async fn test_azure_shared_key_put_get_exists_delete() {
    let backend = live_backend().await;
    assert!(
        backend.supports_redirect(),
        "Shared Key mode should support SAS redirects"
    );

    let test_key = format!("sharedkey-test/{}", uuid::Uuid::new_v4());
    let test_data = Bytes::from("Hello from Azure Shared Key integration test!");

    // PUT
    println!("  PUT {}", test_key);
    backend
        .put(&test_key, test_data.clone())
        .await
        .expect("PUT failed");

    // EXISTS
    println!("  EXISTS {}", test_key);
    let exists = backend.exists(&test_key).await.expect("EXISTS failed");
    assert!(exists, "Blob should exist after PUT");

    // GET
    println!("  GET {}", test_key);
    let retrieved = backend.get(&test_key).await.expect("GET failed");
    assert_eq!(retrieved, test_data, "Retrieved data should match");

    // PRESIGNED URL
    println!("  PRESIGNED URL {}", test_key);
    let presigned = backend
        .get_presigned_url(&test_key, std::time::Duration::from_secs(300))
        .await
        .expect("PRESIGNED URL failed");
    assert!(presigned.is_some(), "Should generate SAS URL");
    let sas_url = presigned.unwrap();
    assert!(sas_url.url.contains("sig="), "SAS URL should contain sig");

    // PUT (empty body) — regression for the Shared Key string-to-sign:
    // Azure requires the Content-Length field to be empty (not "0") for a
    // zero-length body, and OCI upload-session creation writes an empty blob.
    let empty_key = format!("{}.empty", test_key);
    println!("  PUT (empty) {}", empty_key);
    backend
        .put(&empty_key, Bytes::new())
        .await
        .expect("Empty-body PUT failed");
    let empty = backend.get(&empty_key).await.expect("GET empty failed");
    assert!(empty.is_empty(), "Empty blob should round-trip empty");
    backend
        .delete(&empty_key)
        .await
        .expect("DELETE empty failed");

    // DELETE
    println!("  DELETE {}", test_key);
    backend.delete(&test_key).await.expect("DELETE failed");

    // EXISTS after delete
    println!("  EXISTS (after delete) {}", test_key);
    let exists_after = backend
        .exists(&test_key)
        .await
        .expect("EXISTS after delete failed");
    assert!(!exists_after, "Blob should not exist after DELETE");

    println!("  All Shared Key operations passed!");
}

#[tokio::test]
#[ignore]
async fn test_put_blob_from_url_small_blob_4963() {
    with_live_prefix(|backend, prefix| async move {
        copy_and_verify(&backend, &prefix, patterned_bytes(1024, 0x4963)).await;
    })
    .await;
}

#[tokio::test]
#[ignore]
async fn test_put_blob_from_url_empty_blob_4963() {
    with_live_prefix(|backend, prefix| async move {
        copy_and_verify(&backend, &prefix, Bytes::new()).await;
    })
    .await;
}

/// The source goes up as a block upload, the way a staged upload does, which
/// also checks the block-list signal: the same request has to see blocks here.
#[tokio::test]
#[ignore]
async fn test_put_blob_from_url_big_blob_4963() {
    with_live_prefix(|backend, prefix| async move {
        let content = patterned_bytes(BIG_BLOB_LEN, 0x4963_0001);
        let source = format!("{}source", prefix);
        let dest = format!("{}dest", prefix);
        let chunks: Vec<_> = content
            .chunks(1024 * 1024)
            .map(|c| Ok(Bytes::copy_from_slice(c)))
            .collect();
        backend
            .put_stream(&source, futures::stream::iter(chunks).boxed())
            .await
            .map_err(redacted)
            .expect("block upload of the source");
        let source_blocks = committed_blocks(&backend, &source).await;
        assert!(
            source_blocks > 1,
            "a block upload should show committed blocks, saw {}",
            source_blocks
        );

        let path = backend
            .copy_reporting_path(&source, &dest)
            .await
            .map_err(redacted)
            .expect("Put Blob From URL with Shared Key");
        assert_eq!(path, AzureCopyPath::PutBlobFromUrl);
        assert_server_side_copy(&backend, &dest, &content).await;
        println!(
            "  copied {} bytes server-side; source had {} committed blocks",
            content.len(),
            source_blocks
        );
    })
    .await;
}

/// The trait method every caller uses, on the characters a proxy-cache key can
/// carry, onto a destination that already exists. Only Azure's block list can
/// tell the path here, since the trait method returns nothing.
#[tokio::test]
#[ignore]
async fn test_put_blob_from_url_through_trait_copy_overwrites_4963() {
    with_live_prefix(|backend, prefix| async move {
        let content = patterned_bytes(64 * 1024, 0x4963_0002);
        let source = format!("{}proxy-cache-staging/{}", prefix, uuid::Uuid::new_v4());
        let dest = format!("{}proxy-cache/npm/@scope/pkg/-/pkg-1.0.0+b1.tgz", prefix);
        for (key, bytes) in [
            (&source, content.clone()),
            (&dest, Bytes::from_static(b"stale destination")),
        ] {
            backend
                .put(key, bytes)
                .await
                .map_err(redacted)
                .expect("seed blob");
        }
        StorageBackend::copy(backend.as_ref(), &source, &dest)
            .await
            .map_err(redacted)
            .expect("Put Blob From URL with Shared Key");
        assert_server_side_copy(&backend, &dest, &content).await;
    })
    .await;
}

/// Run last, on its own: nothing from any of these tests is left in the account.
#[tokio::test]
#[ignore]
async fn test_no_live_test_blobs_remain_4963() {
    let backend = live_backend().await;
    for prefix in [LIVE_PREFIX, "sharedkey-test/"] {
        let left = backend
            .list(Some(prefix))
            .await
            .map_err(redacted)
            .expect("list");
        assert!(left.is_empty(), "under {}: {:?}", prefix, left);
    }
}

/// The signal the live tests rest on, without an account: a 501 reports the
/// fallback, a 201 reports Put Blob From URL, and a 403 is an error that never
/// reaches the fallback.
#[tokio::test]
async fn test_copy_reporting_path_tells_the_paths_apart_4963() {
    // The mock is plain HTTP. nextest gives each test its own process, so this
    // reaches no other test.
    std::env::set_var("ALLOW_HTTP_INTEGRATIONS", "1");
    for status in [201u16, 501, 403] {
        let server = MockServer::start().await;
        Mock::given(method("HEAD"))
            .respond_with(ResponseTemplate::new(200).insert_header("Content-Length", "10"))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(&b"small-copy"[..]))
            .mount(&server)
            .await;
        Mock::given(method("PUT"))
            .and(header_exists("x-ms-copy-source"))
            .respond_with(ResponseTemplate::new(status))
            .mount(&server)
            .await;
        for comp in ["block", "blocklist"] {
            Mock::given(method("PUT"))
                .and(query_param("comp", comp))
                .respond_with(ResponseTemplate::new(201))
                .mount(&server)
                .await;
        }
        let backend = AzureBackend::new(AzureConfig {
            account_name: "devstoreaccount1".to_string(),
            container_name: "c".to_string(),
            access_key: Some("dGVzdC1rZXk=".to_string()),
            endpoint: Some(format!("{}/devstoreaccount1", server.uri())),
            public_endpoint: None,
            redirect_downloads: false,
            sas_expiry: Duration::from_secs(3600),
            path_format: StoragePathFormat::Native,
            copy_timeout_floor: Duration::ZERO,
        })
        .await
        .unwrap();

        let result = backend.copy_reporting_path("source", "dest").await;
        match status {
            201 => assert_eq!(result.unwrap(), AzureCopyPath::PutBlobFromUrl),
            501 => assert_eq!(result.unwrap(), AzureCopyPath::BlockUpload),
            _ => assert!(result.is_err(), "a 403 is a failure, not a fallback"),
        }
    }
}
