//! Integration tests for the OCI virtual-repo resolver (#1348 round 1).
//!
//! Companion tests for PR #1348 (`fix(oci): forward-port virtual
//! resolution source fixes`). Round-1 review surfaced three concerns
//! that the unit tests in `oci_v2.rs::tests` cannot reach because the
//! resolvers walk both the database and an upstream HTTP endpoint:
//!
//! 1. Multi-member walk: a virtual repo with three remote members where
//!    only the third has the blob must succeed (and must reach the
//!    third upstream, exactly once).
//! 2. None-of-N: when no member has the blob, the resolver must return
//!    `None` (and the negative cache must short-circuit a second probe
//!    so we don't re-walk 2N upstreams immediately).
//! 3. Digest-ref tampering: when the manifest reference IS a digest
//!    (`sha256:...`) and the upstream returns bytes whose sha256 does
//!    NOT match, the resolver must refuse to serve and continue past
//!    the misbehaving upstream.
//!
//! Requires a PostgreSQL database with all migrations applied:
//!
//! ```sh
//! DATABASE_URL="postgresql://registry:registry@localhost:30432/artifact_registry" \
//!   cargo test --test oci_virtual_resolution_tests -- --ignored
//! ```

#![allow(clippy::unwrap_used)]

use std::collections::HashMap;
use std::sync::Arc;

use sqlx::PgPool;
use uuid::Uuid;
use wiremock::matchers::{method, path as wm_path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use artifact_keeper_backend::api::handlers::oci_v2::{
    resolve_virtual_blob, resolve_virtual_manifest, virtual_negative_cache_clear,
    VirtualBlobResolution,
};
use artifact_keeper_backend::api::{AppState, SharedState};
use artifact_keeper_backend::config::Config;
use artifact_keeper_backend::services::proxy_service::ProxyService;
use artifact_keeper_backend::services::storage_service::{FilesystemBackend, StorageService};

// ===========================================================================
// Fixture helpers
// ===========================================================================

fn test_config(storage_path: &str) -> Config {
    Config {
        database_url: std::env::var("DATABASE_URL").unwrap_or_default(),
        storage_path: storage_path.into(),
        jwt_secret: "test-secret-at-least-32-bytes-long-for-testing".into(),
        ..Default::default()
    }
}

async fn connect_pool() -> PgPool {
    PgPool::connect(&std::env::var("DATABASE_URL").unwrap())
        .await
        .unwrap()
}

fn build_state(pool: PgPool, storage_path: &str) -> SharedState {
    let storage: Arc<dyn artifact_keeper_backend::storage::StorageBackend> = Arc::new(
        artifact_keeper_backend::storage::filesystem::FilesystemStorage::new(storage_path),
    );
    let registry = Arc::new(artifact_keeper_backend::storage::StorageRegistry::new(
        HashMap::new(),
        "filesystem".to_string(),
    ));
    let mut state = AppState::new(test_config(storage_path), pool.clone(), storage, registry);

    // ProxyService takes its own storage backend (the `services::` trait,
    // not the `storage::` trait — different abstractions live under each).
    let proxy_backend = Arc::new(FilesystemBackend::new(std::path::PathBuf::from(
        storage_path,
    )));
    let storage_service = Arc::new(StorageService::new(proxy_backend));
    state.proxy_service = Some(Arc::new(ProxyService::new(pool, storage_service)));

    Arc::new(state)
}

/// Insert a remote OCI repo whose upstream points at the given wiremock
/// URL. Keys are UUID-suffixed to keep parallel tests collision-free.
async fn create_remote_repo(pool: &PgPool, label: &str, upstream_url: &str) -> (Uuid, String) {
    let id = Uuid::new_v4();
    let key = format!("oci-{}-{}", label, &id.to_string()[..8]);
    let storage_path = format!("/tmp/oci-virtres-{}", id);
    sqlx::query(
        "INSERT INTO repositories (id, key, name, storage_path, repo_type, format, upstream_url, is_public)
         VALUES ($1, $2, $2, $3, 'remote', 'docker'::repository_format, $4, true)",
    )
    .bind(id)
    .bind(&key)
    .bind(&storage_path)
    .bind(upstream_url)
    .execute(pool)
    .await
    .expect("insert remote repo");
    (id, key)
}

async fn create_virtual_repo(pool: &PgPool, label: &str) -> (Uuid, String) {
    let id = Uuid::new_v4();
    let key = format!("oci-virt-{}-{}", label, &id.to_string()[..8]);
    let storage_path = format!("/tmp/oci-virtres-virt-{}", id);
    sqlx::query(
        "INSERT INTO repositories (id, key, name, storage_path, repo_type, format, is_public)
         VALUES ($1, $2, $2, $3, 'virtual', 'docker'::repository_format, true)",
    )
    .bind(id)
    .bind(&key)
    .bind(&storage_path)
    .execute(pool)
    .await
    .expect("insert virtual repo");
    (id, key)
}

async fn add_member(pool: &PgPool, virtual_id: Uuid, member_id: Uuid, priority: i32) {
    sqlx::query(
        "INSERT INTO virtual_repo_members (virtual_repo_id, member_repo_id, priority)
         VALUES ($1, $2, $3)",
    )
    .bind(virtual_id)
    .bind(member_id)
    .bind(priority)
    .execute(pool)
    .await
    .expect("insert virtual member");
}

async fn cleanup(pool: &PgPool, ids: &[Uuid]) {
    for id in ids {
        let _ = sqlx::query(
            "DELETE FROM virtual_repo_members WHERE virtual_repo_id = $1 OR member_repo_id = $1",
        )
        .bind(id)
        .execute(pool)
        .await;
        let _ = sqlx::query("DELETE FROM repositories WHERE id = $1")
            .bind(id)
            .execute(pool)
            .await;
    }
}

fn sha256_hex(data: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(data);
    format!("{:x}", hasher.finalize())
}

// ===========================================================================
// Concern #4(a): 3 members, only the 3rd has the blob
// ===========================================================================

#[tokio::test]
#[ignore = "requires DATABASE_URL pointed at a Postgres with migrations applied"]
async fn resolve_virtual_blob_walks_to_third_member_when_first_two_404() {
    virtual_negative_cache_clear();
    let pool = connect_pool().await;
    let storage_path = format!("/tmp/oci-virtres-{}", Uuid::new_v4());
    std::fs::create_dir_all(&storage_path).unwrap();

    // Set up three wiremock upstreams. Only the third serves the blob.
    let blob_body = b"layer-content-bytes".to_vec();
    let blob_digest = format!("sha256:{}", sha256_hex(&blob_body));

    let server_a = MockServer::start().await;
    let server_b = MockServer::start().await;
    let server_c = MockServer::start().await;

    Mock::given(method("GET"))
        .and(wm_path(format!("/v2/myimage/blobs/{}", blob_digest)))
        .respond_with(ResponseTemplate::new(404))
        .expect(1)
        .mount(&server_a)
        .await;
    Mock::given(method("GET"))
        .and(wm_path(format!("/v2/myimage/blobs/{}", blob_digest)))
        .respond_with(ResponseTemplate::new(404))
        .expect(1)
        .mount(&server_b)
        .await;
    Mock::given(method("GET"))
        .and(wm_path(format!("/v2/myimage/blobs/{}", blob_digest)))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_bytes(blob_body.clone())
                .insert_header("Content-Type", "application/octet-stream"),
        )
        .expect(1)
        .mount(&server_c)
        .await;

    let (member_a, _) = create_remote_repo(&pool, "a", &server_a.uri()).await;
    let (member_b, _) = create_remote_repo(&pool, "b", &server_b.uri()).await;
    let (member_c, _) = create_remote_repo(&pool, "c", &server_c.uri()).await;
    let (virt_id, _) = create_virtual_repo(&pool, "blob-walk").await;
    add_member(&pool, virt_id, member_a, 1).await;
    add_member(&pool, virt_id, member_b, 2).await;
    add_member(&pool, virt_id, member_c, 3).await;

    let state = build_state(pool.clone(), &storage_path);
    let res = resolve_virtual_blob(&state, virt_id, "myimage", &blob_digest).await;

    match res {
        Some(VirtualBlobResolution::Remote { content, .. }) => {
            assert_eq!(content.as_ref(), blob_body.as_slice());
        }
        other => panic!(
            "expected Remote resolution from server_c, got {:?}",
            other.map(|_| "Local")
        ),
    }

    cleanup(&pool, &[virt_id, member_a, member_b, member_c]).await;
}

// ===========================================================================
// Concern #4(b): none-of-N returns 404 and the negative cache short-circuits
// the next probe (#1348 round 1, concern #2).
// ===========================================================================

#[tokio::test]
#[ignore = "requires DATABASE_URL pointed at a Postgres with migrations applied"]
async fn resolve_virtual_blob_returns_none_when_no_member_has_it_and_negative_caches() {
    virtual_negative_cache_clear();
    let pool = connect_pool().await;
    let storage_path = format!("/tmp/oci-virtres-{}", Uuid::new_v4());
    std::fs::create_dir_all(&storage_path).unwrap();

    let blob_digest = format!("sha256:{}", sha256_hex(b"never-served"));

    let server_a = MockServer::start().await;
    let server_b = MockServer::start().await;

    // Each mock asserts it is called AT MOST ONCE. The negative cache
    // should prevent a second walk.
    Mock::given(method("GET"))
        .and(wm_path(format!("/v2/missing/blobs/{}", blob_digest)))
        .respond_with(ResponseTemplate::new(404))
        .expect(1)
        .mount(&server_a)
        .await;
    Mock::given(method("GET"))
        .and(wm_path(format!("/v2/missing/blobs/{}", blob_digest)))
        .respond_with(ResponseTemplate::new(404))
        .expect(1)
        .mount(&server_b)
        .await;

    let (member_a, _) = create_remote_repo(&pool, "a", &server_a.uri()).await;
    let (member_b, _) = create_remote_repo(&pool, "b", &server_b.uri()).await;
    let (virt_id, _) = create_virtual_repo(&pool, "blob-miss").await;
    add_member(&pool, virt_id, member_a, 1).await;
    add_member(&pool, virt_id, member_b, 2).await;

    let state = build_state(pool.clone(), &storage_path);

    // First probe: walks both upstreams, gets None.
    let first = resolve_virtual_blob(&state, virt_id, "missing", &blob_digest).await;
    assert!(first.is_none(), "expected None on first probe");

    // Second probe immediately after: should hit the negative cache and
    // NOT re-walk the upstreams. The mock `.expect(1)` enforces this on
    // server drop.
    let second = resolve_virtual_blob(&state, virt_id, "missing", &blob_digest).await;
    assert!(
        second.is_none(),
        "expected None on second probe (negative cache hit)"
    );

    // Drop the servers explicitly so .expect(1) is verified before
    // cleanup.
    drop(server_a);
    drop(server_b);

    cleanup(&pool, &[virt_id, member_a, member_b]).await;
}

// ===========================================================================
// Concern #4(c): digest-ref manifest tampering must be rejected.
// ===========================================================================

#[tokio::test]
#[ignore = "requires DATABASE_URL pointed at a Postgres with migrations applied"]
async fn resolve_virtual_manifest_rejects_digest_ref_mismatch_and_falls_through() {
    virtual_negative_cache_clear();
    let pool = connect_pool().await;
    let storage_path = format!("/tmp/oci-virtres-{}", Uuid::new_v4());
    std::fs::create_dir_all(&storage_path).unwrap();

    // The client asks for `sha256:<digest_of_honest>` but member_a
    // returns *different* bytes whose sha256 obviously does not match.
    // Resolver must refuse member_a's payload and continue to member_b
    // which serves the truthful bytes.
    let honest_body =
        br#"{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json"}"#.to_vec();
    let digest = format!("sha256:{}", sha256_hex(&honest_body));
    let tampered_body = br#"{"schemaVersion":2,"evil":true}"#.to_vec();
    assert_ne!(
        sha256_hex(&honest_body),
        sha256_hex(&tampered_body),
        "fixture invariant: tampered body must differ"
    );

    let server_a = MockServer::start().await;
    let server_b = MockServer::start().await;

    // member_a serves tampered bytes under the requested digest.
    Mock::given(method("GET"))
        .and(wm_path(format!("/v2/myimage/manifests/{}", digest)))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_bytes(tampered_body.clone())
                .insert_header("Content-Type", "application/vnd.oci.image.manifest.v1+json"),
        )
        .mount(&server_a)
        .await;
    // member_b serves the truthful bytes.
    Mock::given(method("GET"))
        .and(wm_path(format!("/v2/myimage/manifests/{}", digest)))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_bytes(honest_body.clone())
                .insert_header("Content-Type", "application/vnd.oci.image.manifest.v1+json"),
        )
        .mount(&server_b)
        .await;

    let (member_a, _) = create_remote_repo(&pool, "tamper", &server_a.uri()).await;
    let (member_b, _) = create_remote_repo(&pool, "honest", &server_b.uri()).await;
    let (virt_id, _) = create_virtual_repo(&pool, "manifest-verify").await;
    add_member(&pool, virt_id, member_a, 1).await;
    add_member(&pool, virt_id, member_b, 2).await;

    let state = build_state(pool.clone(), &storage_path);
    let res = resolve_virtual_manifest(&state, virt_id, "myimage", &digest, None).await;

    match res {
        Some((returned_digest, _ct, body)) => {
            assert_eq!(
                returned_digest, digest,
                "returned digest must equal requested digest"
            );
            assert_eq!(
                body.as_ref(),
                honest_body.as_slice(),
                "must have skipped tampered member_a and served honest member_b"
            );
        }
        None => panic!("expected honest member_b to satisfy the request"),
    }

    cleanup(&pool, &[virt_id, member_a, member_b]).await;
}

// ===========================================================================
// Bonus: when ALL members tamper, resolver returns None (and does not
// serve fraudulent bytes under the requested digest).
// ===========================================================================

#[tokio::test]
#[ignore = "requires DATABASE_URL pointed at a Postgres with migrations applied"]
async fn resolve_virtual_manifest_returns_none_when_every_member_tampers() {
    virtual_negative_cache_clear();
    let pool = connect_pool().await;
    let storage_path = format!("/tmp/oci-virtres-{}", Uuid::new_v4());
    std::fs::create_dir_all(&storage_path).unwrap();

    let honest_body =
        br#"{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json"}"#.to_vec();
    let digest = format!("sha256:{}", sha256_hex(&honest_body));
    let tampered_body = br#"{"evil":true}"#.to_vec();

    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(wm_path(format!("/v2/myimage/manifests/{}", digest)))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(tampered_body.clone()))
        .mount(&server)
        .await;

    let (member, _) = create_remote_repo(&pool, "tamper-only", &server.uri()).await;
    let (virt_id, _) = create_virtual_repo(&pool, "manifest-tamper-only").await;
    add_member(&pool, virt_id, member, 1).await;

    let state = build_state(pool.clone(), &storage_path);
    let res = resolve_virtual_manifest(&state, virt_id, "myimage", &digest, None).await;

    assert!(
        res.is_none(),
        "must refuse to serve when no member can prove digest integrity"
    );

    cleanup(&pool, &[virt_id, member]).await;
}
