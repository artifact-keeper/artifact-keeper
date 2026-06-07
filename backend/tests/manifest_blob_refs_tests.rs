//! Integration tests for `manifest_blob_refs` push-time writes (#1635).
//!
//! These tests require a PostgreSQL database with migrations applied
//! (including migration 120). Set DATABASE_URL and run:
//!
//! ```sh
//! DATABASE_URL="postgresql://registry:registry@localhost:30432/artifact_registry" \
//!   cargo test --test manifest_blob_refs_tests -- --ignored
//! ```
//!
//! ADDITIVE ONLY (#1635): these tests only exercise reference recording.
//! No deletion path exists or is tested here.

use sqlx::{PgPool, Row};
use uuid::Uuid;

use artifact_keeper_backend::api::handlers::oci_v2::record_manifest_blob_refs;

/// Create a test repository and return its ID.
async fn create_test_repo(pool: &PgPool) -> Uuid {
    let id = Uuid::new_v4();
    let key = format!("test-{}", id);
    let storage_path = format!("/tmp/test-artifacts/{}", id);
    sqlx::query(
        "INSERT INTO repositories (id, key, name, storage_path, repo_type, format) \
         VALUES ($1, $2, $2, $3, 'local', 'oci')",
    )
    .bind(id)
    .bind(&key)
    .bind(&storage_path)
    .execute(pool)
    .await
    .expect("failed to create test repository");
    id
}

async fn cleanup(pool: &PgPool, repo_id: Uuid) {
    sqlx::query("DELETE FROM manifest_blob_refs WHERE repository_id = $1")
        .bind(repo_id)
        .execute(pool)
        .await
        .ok();
    sqlx::query("DELETE FROM repositories WHERE id = $1")
        .bind(repo_id)
        .execute(pool)
        .await
        .ok();
}

/// Fetch (blob_digest, kind) edges for a manifest, ordered by blob_digest.
async fn fetch_edges(pool: &PgPool, repo_id: Uuid, manifest_digest: &str) -> Vec<(String, String)> {
    sqlx::query(
        "SELECT blob_digest, kind FROM manifest_blob_refs \
         WHERE repository_id = $1 AND manifest_digest = $2 ORDER BY blob_digest",
    )
    .bind(repo_id)
    .bind(manifest_digest)
    .fetch_all(pool)
    .await
    .expect("failed to query manifest_blob_refs")
    .into_iter()
    .map(|r| (r.get("blob_digest"), r.get("kind")))
    .collect()
}

async fn connect() -> PgPool {
    let url = std::env::var("DATABASE_URL").expect("DATABASE_URL must be set for these tests");
    PgPool::connect(&url)
        .await
        .expect("failed to connect to test database")
}

#[tokio::test]
#[ignore = "requires PostgreSQL with migrations applied"]
async fn image_manifest_writes_config_and_layer_edges() {
    let pool = connect().await;
    let repo_id = create_test_repo(&pool).await;

    let manifest_digest = "sha256:manifest0";
    let body = br#"{
        "schemaVersion": 2,
        "mediaType": "application/vnd.oci.image.manifest.v1+json",
        "config": {"size": 7023, "digest": "sha256:config0"},
        "layers": [
            {"size": 32654, "digest": "sha256:layer1"},
            {"size": 16724, "digest": "sha256:layer2"}
        ]
    }"#;

    let inserted = record_manifest_blob_refs(&pool, repo_id, manifest_digest, body)
        .await
        .expect("record_manifest_blob_refs failed");
    assert_eq!(inserted, 3, "expected one config + two layer edges");

    let edges = fetch_edges(&pool, repo_id, manifest_digest).await;
    assert_eq!(
        edges,
        vec![
            ("sha256:config0".to_string(), "config".to_string()),
            ("sha256:layer1".to_string(), "layer".to_string()),
            ("sha256:layer2".to_string(), "layer".to_string()),
        ]
    );

    cleanup(&pool, repo_id).await;
}

#[tokio::test]
#[ignore = "requires PostgreSQL with migrations applied"]
async fn index_manifest_writes_no_blob_edges() {
    let pool = connect().await;
    let repo_id = create_test_repo(&pool).await;

    let manifest_digest = "sha256:index0";
    // An image index has no config/layers, so no blob edges must be written
    // even if (defensively) it is passed to the writer.
    let body = br#"{
        "schemaVersion": 2,
        "mediaType": "application/vnd.oci.image.index.v1+json",
        "manifests": [
            {"digest": "sha256:childamd64", "platform": {"architecture": "amd64", "os": "linux"}},
            {"digest": "sha256:childarm64", "platform": {"architecture": "arm64", "os": "linux"}}
        ]
    }"#;

    let inserted = record_manifest_blob_refs(&pool, repo_id, manifest_digest, body)
        .await
        .expect("record_manifest_blob_refs failed");
    assert_eq!(inserted, 0, "image index must produce zero blob edges");
    assert!(fetch_edges(&pool, repo_id, manifest_digest)
        .await
        .is_empty());

    cleanup(&pool, repo_id).await;
}

#[tokio::test]
#[ignore = "requires PostgreSQL with migrations applied"]
async fn recording_is_idempotent() {
    let pool = connect().await;
    let repo_id = create_test_repo(&pool).await;

    let manifest_digest = "sha256:manifestidem";
    let body = br#"{
        "config": {"digest": "sha256:cfg"},
        "layers": [{"digest": "sha256:l1"}]
    }"#;

    let first = record_manifest_blob_refs(&pool, repo_id, manifest_digest, body)
        .await
        .expect("first record failed");
    assert_eq!(first, 2);

    // Second call must insert nothing (ON CONFLICT DO NOTHING) and leave
    // exactly the same rows.
    let second = record_manifest_blob_refs(&pool, repo_id, manifest_digest, body)
        .await
        .expect("second record failed");
    assert_eq!(second, 0, "re-recording the same manifest inserts no rows");

    let edges = fetch_edges(&pool, repo_id, manifest_digest).await;
    assert_eq!(edges.len(), 2);

    cleanup(&pool, repo_id).await;
}
