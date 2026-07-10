//! Integration test: Swift virtual repositories must resolve package lookups
//! across their members.
//!
//! Regression test for #1554. The read endpoints `list_releases`,
//! `get_release_metadata`, and `fetch_manifest` previously queried the
//! `artifacts` table using the *virtual* repo's own id. Virtual repos own no
//! artifacts, so every lookup returned 404 even when a member served the
//! package. The fix fans out across Local/Staging members in priority order:
//! single-version lookups return the first hit, while `list_releases`
//! aggregates versions across all members, deduplicated with the
//! highest-priority member winning on conflict (#2307).
//!
//! Requires a PostgreSQL database with migrations applied. Run with:
//!
//! ```sh
//! DATABASE_URL="postgresql://registry:registry@localhost:30432/artifact_registry" \
//!   cargo test --test swift_virtual_lookup_tests -- --ignored
//! ```

use sqlx::PgPool;
use uuid::Uuid;

use artifact_keeper_backend::api::handlers::swift::{
    query_release_metadata_virtual, query_release_versions_virtual,
};

async fn pool() -> PgPool {
    PgPool::connect(
        &std::env::var("DATABASE_URL")
            .expect("DATABASE_URL must be set to run this integration test"),
    )
    .await
    .expect("connect")
}

async fn insert_repo(pool: &PgPool, key: &str, repo_type: &str) -> Uuid {
    let id = Uuid::new_v4();
    let storage_path = format!("/tmp/test-artifacts/{}", id);
    let upstream_url: Option<String> = if repo_type == "remote" {
        Some("https://example.invalid/test".to_string())
    } else {
        None
    };
    sqlx::query(
        r#"
        INSERT INTO repositories (id, key, name, format, repo_type, storage_path, upstream_url)
        VALUES ($1, $2, $2, 'swift'::repository_format, $3::repository_type, $4, $5)
        "#,
    )
    .bind(id)
    .bind(key)
    .bind(repo_type)
    .bind(&storage_path)
    .bind(&upstream_url)
    .execute(pool)
    .await
    .expect("failed to insert test repository");
    id
}

async fn add_virtual_member(pool: &PgPool, virtual_id: Uuid, member_id: Uuid, priority: i32) {
    sqlx::query(
        "INSERT INTO virtual_repo_members (virtual_repo_id, member_repo_id, priority) \
         VALUES ($1, $2, $3)",
    )
    .bind(virtual_id)
    .bind(member_id)
    .bind(priority)
    .execute(pool)
    .await
    .expect("failed to insert virtual member");
}

/// Insert a Swift artifact row the way `publish_release` stores it: `name` is
/// the `scope.name` package id and `metadata.manifest` holds the manifest text.
async fn insert_swift_artifact(
    pool: &PgPool,
    repo_id: Uuid,
    package_id: &str,
    version: &str,
    manifest: Option<&str>,
) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        r#"
        INSERT INTO artifacts (
            id, repository_id, path, name, version,
            size_bytes, checksum_sha256, content_type, storage_key
        )
        VALUES ($1, $2, $3, $4, $5, 0, $6, 'application/zip', $7)
        "#,
    )
    .bind(id)
    .bind(repo_id)
    .bind(format!("{}/{}/pkg.zip", package_id, version))
    .bind(package_id)
    .bind(version)
    .bind(format!("test-{}", id))
    .bind(format!("artifacts/{}", id))
    .execute(pool)
    .await
    .expect("failed to insert test artifact");

    let meta = serde_json::json!({
        "manifest": manifest,
        "swift_metadata": { "package_id": package_id, "version": version },
    });
    sqlx::query(
        "INSERT INTO artifact_metadata (artifact_id, format, metadata) \
         VALUES ($1, 'swift', $2)",
    )
    .bind(id)
    .bind(meta)
    .execute(pool)
    .await
    .expect("failed to insert artifact metadata");
    id
}

async fn cleanup(pool: &PgPool, virtual_id: Uuid, member_ids: &[Uuid]) {
    sqlx::query("DELETE FROM virtual_repo_members WHERE virtual_repo_id = $1")
        .bind(virtual_id)
        .execute(pool)
        .await
        .ok();
    for &m in member_ids {
        // artifact_metadata rows cascade via artifact_id FK; delete artifacts.
        sqlx::query("DELETE FROM artifacts WHERE repository_id = $1")
            .bind(m)
            .execute(pool)
            .await
            .ok();
    }
    let mut ids = member_ids.to_vec();
    ids.push(virtual_id);
    sqlx::query("DELETE FROM repositories WHERE id = ANY($1)")
        .bind(&ids)
        .execute(pool)
        .await
        .ok();
}

/// Core #1554 regression: a package owned by a Local member must be found
/// through the virtual repo's list + metadata lookups.
#[tokio::test]
#[ignore]
async fn swift_virtual_resolves_release_from_local_member() {
    let pool = pool().await;
    let suffix = Uuid::new_v4();
    let virtual_id = insert_repo(&pool, &format!("sw-virt-{}", suffix), "virtual").await;
    let local_id = insert_repo(&pool, &format!("sw-local-{}", suffix), "local").await;
    add_virtual_member(&pool, virtual_id, local_id, 1).await;

    let package_id = "macos.lib";
    insert_swift_artifact(&pool, local_id, package_id, "12.5.2", Some("// manifest")).await;

    // list_releases fan-out
    let versions = query_release_versions_virtual(&pool, virtual_id, package_id)
        .await
        .expect("virtual list lookup must succeed");
    assert_eq!(
        versions,
        vec!["12.5.2".to_string()],
        "virtual repo must surface the local member's release versions (#1554)"
    );

    // get_release_metadata fan-out
    let row = query_release_metadata_virtual(&pool, virtual_id, package_id, "12.5.2")
        .await
        .expect("virtual metadata lookup must succeed")
        .expect("release must be found via the member");
    assert!(!row.checksum_sha256.is_empty());
    assert!(row
        .metadata
        .as_ref()
        .and_then(|m| m.get("manifest"))
        .is_some());

    cleanup(&pool, virtual_id, &[local_id]).await;
}

/// Aggregation (#2307): `list_releases` must union versions across ALL
/// Local/Staging members, not just the first member that owns the package.
#[tokio::test]
#[ignore]
async fn swift_virtual_aggregates_versions_across_members() {
    let pool = pool().await;
    let suffix = Uuid::new_v4();
    let virtual_id = insert_repo(&pool, &format!("sw-virt-agg-{}", suffix), "virtual").await;
    let local_a = insert_repo(&pool, &format!("sw-a-{}", suffix), "local").await;
    let local_b = insert_repo(&pool, &format!("sw-b-{}", suffix), "local").await;
    add_virtual_member(&pool, virtual_id, local_a, 1).await;
    add_virtual_member(&pool, virtual_id, local_b, 2).await;

    let package_id = "apple.swift-log";
    insert_swift_artifact(&pool, local_a, package_id, "1.0.0", None).await;
    insert_swift_artifact(&pool, local_b, package_id, "2.0.0", None).await;

    let versions = query_release_versions_virtual(&pool, virtual_id, package_id)
        .await
        .expect("lookup must succeed");
    assert!(
        versions.contains(&"1.0.0".to_string()),
        "member A's version must appear in the aggregated list, got {:?}",
        versions
    );
    assert!(
        versions.contains(&"2.0.0".to_string()),
        "member B's version must appear in the aggregated list, got {:?}",
        versions
    );
    assert_eq!(
        versions.len(),
        2,
        "no duplicates or extras, got {:?}",
        versions
    );

    cleanup(&pool, virtual_id, &[local_a, local_b]).await;
}

/// Deduplication (#2307): when the same version exists in multiple members it
/// must appear exactly once (the highest-priority member's entry wins).
#[tokio::test]
#[ignore]
async fn swift_virtual_dedupes_versions_across_members() {
    let pool = pool().await;
    let suffix = Uuid::new_v4();
    let virtual_id = insert_repo(&pool, &format!("sw-virt-dedup-{}", suffix), "virtual").await;
    let local_a = insert_repo(&pool, &format!("sw-da-{}", suffix), "local").await;
    let local_b = insert_repo(&pool, &format!("sw-db-{}", suffix), "local").await;
    add_virtual_member(&pool, virtual_id, local_a, 1).await;
    add_virtual_member(&pool, virtual_id, local_b, 2).await;

    let package_id = "apple.swift-nio";
    insert_swift_artifact(&pool, local_a, package_id, "3.1.0", None).await;
    insert_swift_artifact(&pool, local_b, package_id, "3.1.0", None).await;
    insert_swift_artifact(&pool, local_b, package_id, "3.2.0", None).await;

    let versions = query_release_versions_virtual(&pool, virtual_id, package_id)
        .await
        .expect("lookup must succeed");
    assert_eq!(
        versions.iter().filter(|v| v.as_str() == "3.1.0").count(),
        1,
        "a version present in both members must appear exactly once, got {:?}",
        versions
    );
    assert!(
        versions.contains(&"3.2.0".to_string()),
        "the second member's unique version must still appear, got {:?}",
        versions
    );
    assert_eq!(
        versions.len(),
        2,
        "expected exactly two versions, got {:?}",
        versions
    );

    cleanup(&pool, virtual_id, &[local_a, local_b]).await;
}

/// Negative: a package no member owns yields an empty list / None, which the
/// handlers map to 404 (matching the direct-repo behavior).
#[tokio::test]
#[ignore]
async fn swift_virtual_missing_package_returns_empty() {
    let pool = pool().await;
    let suffix = Uuid::new_v4();
    let virtual_id = insert_repo(&pool, &format!("sw-virt-miss-{}", suffix), "virtual").await;
    let local_id = insert_repo(&pool, &format!("sw-local-miss-{}", suffix), "local").await;
    add_virtual_member(&pool, virtual_id, local_id, 1).await;

    let versions = query_release_versions_virtual(&pool, virtual_id, "nope.absent")
        .await
        .expect("lookup must succeed");
    assert!(
        versions.is_empty(),
        "unknown package must yield no versions"
    );

    let row = query_release_metadata_virtual(&pool, virtual_id, "nope.absent", "1.0.0")
        .await
        .expect("lookup must succeed");
    assert!(row.is_none(), "unknown release must yield None");

    cleanup(&pool, virtual_id, &[local_id]).await;
}
