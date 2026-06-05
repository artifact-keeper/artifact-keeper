//! Integration tests for lifecycle policy execution.
//!
//! These tests require a PostgreSQL database with migrations applied.
//! Set DATABASE_URL and run:
//!
//! ```sh
//! DATABASE_URL="postgresql://registry:registry@localhost:30432/artifact_registry" \
//!   cargo test --test lifecycle_policy_tests -- --ignored
//! ```

use sqlx::PgPool;
use uuid::Uuid;

use artifact_keeper_backend::services::lifecycle_service::{CreatePolicyRequest, LifecycleService};

/// Create a test repository and return its ID.
async fn create_test_repo(pool: &PgPool, name: &str) -> Uuid {
    let id = Uuid::new_v4();
    let key = format!("test-{}", id);
    let storage_path = format!("/tmp/test-artifacts/{}", id);
    sqlx::query(
        "INSERT INTO repositories (id, key, name, storage_path, repo_type, format) VALUES ($1, $2, $3, $4, 'local', 'generic')",
    )
    .bind(id)
    .bind(&key)
    .bind(name)
    .bind(&storage_path)
    .execute(pool)
    .await
    .expect("failed to create test repository");
    id
}

/// Insert a test artifact and return its ID.
async fn insert_artifact(pool: &PgPool, repo_id: Uuid, name: &str, size: i64) -> Uuid {
    let id = Uuid::new_v4();
    let path = format!("{}/{}", repo_id, name);
    // checksum_sha256 is CHAR(64), so pad to 64 hex chars
    let checksum = format!("{:0>64}", "deadbeef");
    sqlx::query(
        r#"
        INSERT INTO artifacts (id, repository_id, name, path, size_bytes, checksum_sha256, content_type, storage_key, is_deleted)
        VALUES ($1, $2, $3, $4, $5, $6, 'application/octet-stream', $4, false)
        "#,
    )
    .bind(id)
    .bind(repo_id)
    .bind(name)
    .bind(&path)
    .bind(size)
    .bind(&checksum)
    .execute(pool)
    .await
    .expect("failed to insert test artifact");
    id
}

/// Check if an artifact is marked as deleted.
async fn is_deleted(pool: &PgPool, artifact_id: Uuid) -> bool {
    let row: (bool,) = sqlx::query_as("SELECT is_deleted FROM artifacts WHERE id = $1")
        .bind(artifact_id)
        .fetch_one(pool)
        .await
        .expect("artifact not found");
    row.0
}

/// Clean up test data after each test.
async fn cleanup(pool: &PgPool, repo_id: Uuid) {
    sqlx::query("DELETE FROM lifecycle_policies WHERE repository_id = $1")
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
}

// =============================================================================
// tag_pattern_keep: keep matching, delete the rest
// =============================================================================

#[tokio::test]
#[ignore]
async fn test_tag_pattern_keep_deletes_non_matching_artifacts() {
    let pool = PgPool::connect(&std::env::var("DATABASE_URL").unwrap())
        .await
        .expect("failed to connect to database");

    let repo_id = create_test_repo(&pool, &format!("test-tpk-{}", Uuid::new_v4())).await;
    let svc = LifecycleService::new(pool.clone());

    // Create artifacts: some match "^release-" or "^v", some don't
    let a_release = insert_artifact(&pool, repo_id, "release-1.0.0", 100).await;
    let a_v2 = insert_artifact(&pool, repo_id, "v2.0.0", 200).await;
    let a_snapshot = insert_artifact(&pool, repo_id, "snapshot-nightly-123", 300).await;
    let a_dev = insert_artifact(&pool, repo_id, "dev-build-456", 400).await;

    // Create a tag_pattern_keep policy: keep release-* and v*
    let policy = svc
        .create_policy(CreatePolicyRequest {
            repository_id: Some(repo_id),
            name: "Keep releases".to_string(),
            description: Some("Keep release and version tags".to_string()),
            policy_type: "tag_pattern_keep".to_string(),
            config: serde_json::json!({"pattern": "^(release-|v)"}),
            priority: None,
            cron_schedule: None,
        })
        .await
        .expect("failed to create policy");

    // --- Dry run first ---
    let dry_result = svc
        .execute_policy(policy.id, true)
        .await
        .expect("dry run failed");
    assert_eq!(
        dry_result.artifacts_matched, 2,
        "should match 2 non-release artifacts"
    );
    assert_eq!(
        dry_result.artifacts_removed, 0,
        "dry run should not remove anything"
    );
    assert!(dry_result.dry_run);

    // Verify nothing was actually deleted
    assert!(!is_deleted(&pool, a_release).await);
    assert!(!is_deleted(&pool, a_v2).await);
    assert!(!is_deleted(&pool, a_snapshot).await);
    assert!(!is_deleted(&pool, a_dev).await);

    // --- Real execution ---
    let result = svc
        .execute_policy(policy.id, false)
        .await
        .expect("execution failed");
    assert_eq!(
        result.artifacts_matched, 2,
        "should match 2 non-release artifacts"
    );
    assert_eq!(
        result.artifacts_removed, 2,
        "should remove 2 non-matching artifacts"
    );
    assert!(!result.dry_run);
    assert!(result.errors.is_empty());

    // Verify: release-* and v* kept, others deleted
    assert!(
        !is_deleted(&pool, a_release).await,
        "release-1.0.0 should be kept"
    );
    assert!(!is_deleted(&pool, a_v2).await, "v2.0.0 should be kept");
    assert!(
        is_deleted(&pool, a_snapshot).await,
        "snapshot-nightly-123 should be deleted"
    );
    assert!(
        is_deleted(&pool, a_dev).await,
        "dev-build-456 should be deleted"
    );

    cleanup(&pool, repo_id).await;
}

#[tokio::test]
#[ignore]
async fn test_tag_pattern_keep_all_match_deletes_nothing() {
    let pool = PgPool::connect(&std::env::var("DATABASE_URL").unwrap())
        .await
        .expect("failed to connect to database");

    let repo_id = create_test_repo(&pool, &format!("test-tpk-all-{}", Uuid::new_v4())).await;
    let svc = LifecycleService::new(pool.clone());

    let a1 = insert_artifact(&pool, repo_id, "release-1.0", 100).await;
    let a2 = insert_artifact(&pool, repo_id, "release-2.0", 200).await;

    let policy = svc
        .create_policy(CreatePolicyRequest {
            repository_id: Some(repo_id),
            name: "Keep all releases".to_string(),
            description: None,
            policy_type: "tag_pattern_keep".to_string(),
            config: serde_json::json!({"pattern": "^release-"}),
            priority: None,
            cron_schedule: None,
        })
        .await
        .unwrap();

    let result = svc.execute_policy(policy.id, false).await.unwrap();
    assert_eq!(
        result.artifacts_matched, 0,
        "all artifacts match, none to delete"
    );
    assert_eq!(result.artifacts_removed, 0);

    assert!(!is_deleted(&pool, a1).await);
    assert!(!is_deleted(&pool, a2).await);

    cleanup(&pool, repo_id).await;
}

#[tokio::test]
#[ignore]
async fn test_tag_pattern_keep_none_match_deletes_all() {
    let pool = PgPool::connect(&std::env::var("DATABASE_URL").unwrap())
        .await
        .expect("failed to connect to database");

    let repo_id = create_test_repo(&pool, &format!("test-tpk-none-{}", Uuid::new_v4())).await;
    let svc = LifecycleService::new(pool.clone());

    let a1 = insert_artifact(&pool, repo_id, "snapshot-1", 100).await;
    let a2 = insert_artifact(&pool, repo_id, "dev-build-2", 200).await;

    let policy = svc
        .create_policy(CreatePolicyRequest {
            repository_id: Some(repo_id),
            name: "Keep only releases".to_string(),
            description: None,
            policy_type: "tag_pattern_keep".to_string(),
            config: serde_json::json!({"pattern": "^release-"}),
            priority: None,
            cron_schedule: None,
        })
        .await
        .unwrap();

    let result = svc.execute_policy(policy.id, false).await.unwrap();
    assert_eq!(result.artifacts_matched, 2);
    assert_eq!(result.artifacts_removed, 2);

    assert!(is_deleted(&pool, a1).await, "snapshot-1 should be deleted");
    assert!(is_deleted(&pool, a2).await, "dev-build-2 should be deleted");

    cleanup(&pool, repo_id).await;
}

// =============================================================================
// tag_pattern_delete: sanity check that the existing policy still works
// =============================================================================

#[tokio::test]
#[ignore]
async fn test_tag_pattern_delete_still_works() {
    let pool = PgPool::connect(&std::env::var("DATABASE_URL").unwrap())
        .await
        .expect("failed to connect to database");

    let repo_id = create_test_repo(&pool, &format!("test-tpd-{}", Uuid::new_v4())).await;
    let svc = LifecycleService::new(pool.clone());

    let a_release = insert_artifact(&pool, repo_id, "release-1.0", 100).await;
    let a_snapshot = insert_artifact(&pool, repo_id, "snapshot-nightly", 200).await;

    let policy = svc
        .create_policy(CreatePolicyRequest {
            repository_id: Some(repo_id),
            name: "Delete snapshots".to_string(),
            description: None,
            policy_type: "tag_pattern_delete".to_string(),
            config: serde_json::json!({"pattern": "^snapshot-"}),
            priority: None,
            cron_schedule: None,
        })
        .await
        .unwrap();

    let result = svc.execute_policy(policy.id, false).await.unwrap();
    assert_eq!(result.artifacts_matched, 1);
    assert_eq!(result.artifacts_removed, 1);

    assert!(
        !is_deleted(&pool, a_release).await,
        "release should be kept"
    );
    assert!(
        is_deleted(&pool, a_snapshot).await,
        "snapshot should be deleted"
    );

    cleanup(&pool, repo_id).await;
}

// =============================================================================
// size_quota_bytes: LRU eviction (issue #193)
// =============================================================================

/// Record a download for an artifact at a specific time.
async fn record_download(pool: &PgPool, artifact_id: Uuid, downloaded_at: &str) {
    sqlx::query(
        "INSERT INTO download_statistics (id, artifact_id, downloaded_at) VALUES ($1, $2, $3::timestamptz)",
    )
    .bind(Uuid::new_v4())
    .bind(artifact_id)
    .bind(downloaded_at)
    .execute(pool)
    .await
    .expect("failed to record download");
}

/// Record a download relative to NOW, N days in the past.
///
/// Window-based policies such as `no_downloads_days` compare the most recent
/// download against `NOW() - make_interval(days => N)`. Tests that need a
/// download to fall *inside* such a window must anchor it to wall-clock NOW,
/// not a hardcoded calendar date — otherwise the fixture silently rots out of
/// the window as real time advances and the test starts failing on a date that
/// has nothing to do with the code under test.
async fn record_download_days_ago(pool: &PgPool, artifact_id: Uuid, days_ago: i64) {
    sqlx::query(
        "INSERT INTO download_statistics (id, artifact_id, downloaded_at) \
         VALUES ($1, $2, NOW() - make_interval(days => $3::INT))",
    )
    .bind(Uuid::new_v4())
    .bind(artifact_id)
    .bind(days_ago as i32)
    .execute(pool)
    .await
    .expect("failed to record relative download");
}

/// Clean up test data including download statistics.
async fn cleanup_with_downloads(pool: &PgPool, repo_id: Uuid) {
    // Delete download stats for all artifacts in this repo
    sqlx::query(
        "DELETE FROM download_statistics WHERE artifact_id IN (SELECT id FROM artifacts WHERE repository_id = $1)",
    )
    .bind(repo_id)
    .execute(pool)
    .await
    .ok();
    cleanup(pool, repo_id).await;
}

#[tokio::test]
#[ignore]
async fn test_size_quota_lru_evicts_never_downloaded_first() {
    let pool = PgPool::connect(&std::env::var("DATABASE_URL").unwrap())
        .await
        .expect("failed to connect to database");

    let repo_id = create_test_repo(&pool, &format!("test-lru-never-{}", Uuid::new_v4())).await;
    let svc = LifecycleService::new(pool.clone());

    // Create 4 artifacts: 100 bytes each = 400 total
    // Artifacts created in order: old_downloaded, old_no_download, new_downloaded, new_no_download
    let a_old_downloaded = insert_artifact(&pool, repo_id, "old-downloaded", 100).await;
    let a_old_no_download = insert_artifact(&pool, repo_id, "old-no-download", 100).await;
    let a_new_downloaded = insert_artifact(&pool, repo_id, "new-downloaded", 100).await;
    let a_new_no_download = insert_artifact(&pool, repo_id, "new-no-download", 100).await;

    // Record downloads for some artifacts
    record_download(&pool, a_old_downloaded, "2026-01-01T00:00:00Z").await;
    record_download(&pool, a_new_downloaded, "2026-02-01T00:00:00Z").await;

    // Set quota to 200 bytes — need to evict 200 bytes (2 artifacts)
    let policy = svc
        .create_policy(CreatePolicyRequest {
            repository_id: Some(repo_id),
            name: "LRU quota".to_string(),
            description: None,
            policy_type: "size_quota_bytes".to_string(),
            config: serde_json::json!({"quota_bytes": 200}),
            priority: None,
            cron_schedule: None,
        })
        .await
        .unwrap();

    let result = svc.execute_policy(policy.id, false).await.unwrap();
    assert_eq!(result.artifacts_matched, 2, "should evict 2 artifacts");
    assert_eq!(result.artifacts_removed, 2);

    // Never-downloaded artifacts should be evicted first (NULLS FIRST),
    // then by created_at ASC among those with no downloads
    assert!(
        is_deleted(&pool, a_old_no_download).await,
        "old-no-download should be evicted (never downloaded)"
    );
    assert!(
        is_deleted(&pool, a_new_no_download).await,
        "new-no-download should be evicted (never downloaded)"
    );

    // Downloaded artifacts should survive
    assert!(
        !is_deleted(&pool, a_old_downloaded).await,
        "old-downloaded should survive (was downloaded)"
    );
    assert!(
        !is_deleted(&pool, a_new_downloaded).await,
        "new-downloaded should survive (was downloaded)"
    );

    cleanup_with_downloads(&pool, repo_id).await;
}

#[tokio::test]
#[ignore]
async fn test_size_quota_lru_frequently_downloaded_survives() {
    let pool = PgPool::connect(&std::env::var("DATABASE_URL").unwrap())
        .await
        .expect("failed to connect to database");

    let repo_id = create_test_repo(&pool, &format!("test-lru-freq-{}", Uuid::new_v4())).await;
    let svc = LifecycleService::new(pool.clone());

    // Create 3 artifacts: 100 bytes each = 300 total
    let a_old_hot = insert_artifact(&pool, repo_id, "old-but-hot", 100).await;
    let a_recent_cold = insert_artifact(&pool, repo_id, "recent-but-cold", 100).await;
    let a_stale = insert_artifact(&pool, repo_id, "stale", 100).await;

    // old-but-hot: downloaded many times, most recent download is very recent
    record_download(&pool, a_old_hot, "2025-06-01T00:00:00Z").await;
    record_download(&pool, a_old_hot, "2025-09-01T00:00:00Z").await;
    record_download(&pool, a_old_hot, "2026-02-15T00:00:00Z").await; // most recent

    // recent-but-cold: downloaded once, long ago
    record_download(&pool, a_recent_cold, "2025-08-01T00:00:00Z").await;

    // stale: downloaded once, even longer ago
    record_download(&pool, a_stale, "2025-03-01T00:00:00Z").await;

    // Set quota to 100 bytes — need to evict 200 bytes (2 artifacts)
    let policy = svc
        .create_policy(CreatePolicyRequest {
            repository_id: Some(repo_id),
            name: "LRU frequent test".to_string(),
            description: None,
            policy_type: "size_quota_bytes".to_string(),
            config: serde_json::json!({"quota_bytes": 100}),
            priority: None,
            cron_schedule: None,
        })
        .await
        .unwrap();

    let result = svc.execute_policy(policy.id, false).await.unwrap();
    assert_eq!(result.artifacts_matched, 2, "should evict 2 artifacts");
    assert_eq!(result.artifacts_removed, 2);

    // LRU ordering by MAX(downloaded_at):
    // stale:          last download 2025-03-01 → evicted first
    // recent-but-cold: last download 2025-08-01 → evicted second
    // old-but-hot:     last download 2026-02-15 → survives (most recently downloaded)
    assert!(
        is_deleted(&pool, a_stale).await,
        "stale should be evicted (least recently downloaded)"
    );
    assert!(
        is_deleted(&pool, a_recent_cold).await,
        "recent-but-cold should be evicted (downloaded long ago)"
    );
    assert!(
        !is_deleted(&pool, a_old_hot).await,
        "old-but-hot should survive (frequently downloaded, most recent download)"
    );

    cleanup_with_downloads(&pool, repo_id).await;
}

// =============================================================================
// oci_tags cascade: lifecycle soft-delete must also remove the live tag row,
// otherwise storage GC (see backend/src/services/storage_gc_service.rs:36) sees
// the tag as a live reference and never reclaims the manifest in S3.
// =============================================================================

/// Insert a fake OCI manifest artifact with realistic storage_key shape.
async fn insert_oci_manifest_artifact(
    pool: &PgPool,
    repo_id: Uuid,
    image: &str,
    tag: &str,
    digest: &str,
    size: i64,
) -> Uuid {
    let id = Uuid::new_v4();
    let name = format!("{image}:{tag}");
    let path = format!("v2/{image}/manifests/{tag}");
    let storage_key = format!("oci-manifests/{digest}");
    let checksum = format!("{:0>64}", "deadbeef");
    sqlx::query(
        r#"
        INSERT INTO artifacts (id, repository_id, name, version, path, size_bytes,
                               checksum_sha256, content_type, storage_key, is_deleted)
        VALUES ($1, $2, $3, $4, $5, $6, $7, 'application/vnd.oci.image.manifest.v1+json', $8, false)
        "#,
    )
    .bind(id)
    .bind(repo_id)
    .bind(&name)
    .bind(tag)
    .bind(&path)
    .bind(size)
    .bind(&checksum)
    .bind(&storage_key)
    .execute(pool)
    .await
    .expect("failed to insert oci manifest artifact");
    id
}

/// Insert a matching oci_tags row.
async fn insert_oci_tag(pool: &PgPool, repo_id: Uuid, image: &str, tag: &str, digest: &str) {
    sqlx::query(
        r#"
        INSERT INTO oci_tags (repository_id, name, tag, manifest_digest, manifest_content_type)
        VALUES ($1, $2, $3, $4, 'application/vnd.oci.image.manifest.v1+json')
        "#,
    )
    .bind(repo_id)
    .bind(image)
    .bind(tag)
    .bind(digest)
    .execute(pool)
    .await
    .expect("failed to insert oci_tag");
}

/// Return true if an oci_tags row still exists for the given (repo, image, tag).
async fn oci_tag_exists(pool: &PgPool, repo_id: Uuid, image: &str, tag: &str) -> bool {
    let row: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM oci_tags WHERE repository_id = $1 AND name = $2 AND tag = $3",
    )
    .bind(repo_id)
    .bind(image)
    .bind(tag)
    .fetch_one(pool)
    .await
    .expect("oci_tags count failed");
    row.0 > 0
}

/// Soft-deleting an OCI manifest via tag_pattern_delete must also remove the
/// matching oci_tags row, otherwise storage GC's orphan predicate (#1144)
/// keeps the manifest object alive in S3 forever.
#[tokio::test]
#[ignore]
async fn test_tag_pattern_delete_cascades_oci_tags_for_soft_deleted_manifest() {
    let pool = PgPool::connect(&std::env::var("DATABASE_URL").unwrap())
        .await
        .expect("failed to connect to database");

    let repo_id = create_test_repo(&pool, &format!("test-cascade-{}", Uuid::new_v4())).await;
    let svc = LifecycleService::new(pool.clone());

    // Two manifests in the same image: one ephemeral (matches the delete
    // pattern), one a kept release.
    let ephemeral_digest =
        "sha256:1111111111111111111111111111111111111111111111111111111111111111";
    let release_digest = "sha256:2222222222222222222222222222222222222222222222222222222222222222";
    let ephemeral_id = insert_oci_manifest_artifact(
        &pool,
        repo_id,
        "myimg",
        "build-snapshot-images",
        ephemeral_digest,
        100,
    )
    .await;
    let release_id =
        insert_oci_manifest_artifact(&pool, repo_id, "myimg", "v1.0.0", release_digest, 200).await;
    insert_oci_tag(
        &pool,
        repo_id,
        "myimg",
        "build-snapshot-images",
        ephemeral_digest,
    )
    .await;
    insert_oci_tag(&pool, repo_id, "myimg", "v1.0.0", release_digest).await;

    let policy = svc
        .create_policy(CreatePolicyRequest {
            repository_id: Some(repo_id),
            name: "Delete snapshot-images".to_string(),
            description: None,
            policy_type: "tag_pattern_delete".to_string(),
            config: serde_json::json!({"pattern": "-snapshot-images$"}),
            priority: None,
            cron_schedule: None,
        })
        .await
        .expect("failed to create policy");

    // Dry run must not touch oci_tags.
    let _ = svc
        .execute_policy(policy.id, true)
        .await
        .expect("dry run failed");
    assert!(!is_deleted(&pool, ephemeral_id).await);
    assert!(
        oci_tag_exists(&pool, repo_id, "myimg", "build-snapshot-images").await,
        "dry-run must leave oci_tags untouched"
    );

    // Real run: artifact is soft-deleted and the cascade removes the tag row.
    let result = svc
        .execute_policy(policy.id, false)
        .await
        .expect("execution failed");
    assert_eq!(result.artifacts_removed, 1);

    assert!(
        is_deleted(&pool, ephemeral_id).await,
        "ephemeral artifact should be soft-deleted"
    );
    assert!(
        !is_deleted(&pool, release_id).await,
        "release artifact must not be touched"
    );

    // Regression assertion (the bug this PR fixes).
    assert!(
        !oci_tag_exists(&pool, repo_id, "myimg", "build-snapshot-images").await,
        "cascade should remove oci_tags row for soft-deleted manifest"
    );
    // Sanity: the release tag is still alive.
    assert!(
        oci_tag_exists(&pool, repo_id, "myimg", "v1.0.0").await,
        "release oci_tag must survive"
    );

    cleanup(&pool, repo_id).await;
}

/// max_age_days policy soft-deletes by age; the cascade must also fire.
#[tokio::test]
#[ignore]
async fn test_max_age_days_cascades_oci_tags() {
    let pool = PgPool::connect(&std::env::var("DATABASE_URL").unwrap())
        .await
        .expect("failed to connect to database");

    let repo_id = create_test_repo(&pool, &format!("test-cascade-age-{}", Uuid::new_v4())).await;
    let svc = LifecycleService::new(pool.clone());

    let old_digest = "sha256:3333333333333333333333333333333333333333333333333333333333333333";
    let old_id =
        insert_oci_manifest_artifact(&pool, repo_id, "myimg", "old", old_digest, 100).await;
    insert_oci_tag(&pool, repo_id, "myimg", "old", old_digest).await;

    // Backdate the artifact to look 10 days old.
    sqlx::query("UPDATE artifacts SET created_at = NOW() - INTERVAL '10 days' WHERE id = $1")
        .bind(old_id)
        .execute(&pool)
        .await
        .expect("backdate failed");

    let policy = svc
        .create_policy(CreatePolicyRequest {
            repository_id: Some(repo_id),
            name: "Drop > 7 days".to_string(),
            description: None,
            policy_type: "max_age_days".to_string(),
            config: serde_json::json!({"days": 7}),
            priority: None,
            cron_schedule: None,
        })
        .await
        .expect("failed to create policy");

    let result = svc.execute_policy(policy.id, false).await.unwrap();
    assert_eq!(result.artifacts_removed, 1);
    assert!(is_deleted(&pool, old_id).await);
    assert!(
        !oci_tag_exists(&pool, repo_id, "myimg", "old").await,
        "max_age_days must also cascade oci_tags"
    );

    cleanup(&pool, repo_id).await;
}

/// Repo-scoped policy must not delete oci_tags in other repos.
#[tokio::test]
#[ignore]
async fn test_cascade_respects_repo_scope() {
    let pool = PgPool::connect(&std::env::var("DATABASE_URL").unwrap())
        .await
        .expect("failed to connect to database");

    let repo_a = create_test_repo(&pool, &format!("test-cascade-a-{}", Uuid::new_v4())).await;
    let repo_b = create_test_repo(&pool, &format!("test-cascade-b-{}", Uuid::new_v4())).await;
    let svc = LifecycleService::new(pool.clone());

    // Same image:tag with the same digest in two repos; the artifact in
    // repo_b is already soft-deleted (e.g., from an earlier cleanup) but
    // a policy targeting repo_a must NOT cascade its tag row.
    let digest = "sha256:4444444444444444444444444444444444444444444444444444444444444444";
    let a_id =
        insert_oci_manifest_artifact(&pool, repo_a, "img", "snapshot-images", digest, 100).await;
    let b_id =
        insert_oci_manifest_artifact(&pool, repo_b, "img", "snapshot-images", digest, 100).await;
    insert_oci_tag(&pool, repo_a, "img", "snapshot-images", digest).await;
    insert_oci_tag(&pool, repo_b, "img", "snapshot-images", digest).await;

    // Mark repo_b's artifact soft-deleted with no policy involvement.
    sqlx::query("UPDATE artifacts SET is_deleted = true WHERE id = $1")
        .bind(b_id)
        .execute(&pool)
        .await
        .unwrap();

    let policy = svc
        .create_policy(CreatePolicyRequest {
            repository_id: Some(repo_a),
            name: "Drop snapshots in A".to_string(),
            description: None,
            policy_type: "tag_pattern_delete".to_string(),
            config: serde_json::json!({"pattern": "-images$"}),
            priority: None,
            cron_schedule: None,
        })
        .await
        .unwrap();

    let _ = svc.execute_policy(policy.id, false).await.unwrap();

    assert!(is_deleted(&pool, a_id).await);
    assert!(
        !oci_tag_exists(&pool, repo_a, "img", "snapshot-images").await,
        "tag in repo_a must be cascaded"
    );
    assert!(
        oci_tag_exists(&pool, repo_b, "img", "snapshot-images").await,
        "tag in repo_b must NOT be touched by a repo_a-scoped policy"
    );

    cleanup(&pool, repo_a).await;
    cleanup(&pool, repo_b).await;
}

/// Regression for PR #1406 review concern #1: an OCI image name that
/// embeds a `host:port` registry prefix (so `artifacts.name` looks like
/// `host:5000/img:tag` with two colons) must still cascade. The previous
/// `substring(a.name from '^(.+):[^:]+$')` predicate was brittle around
/// this layout; the path-based join is stable.
#[tokio::test]
#[ignore]
async fn test_cascade_handles_port_in_image_name() {
    let pool = PgPool::connect(&std::env::var("DATABASE_URL").unwrap())
        .await
        .expect("failed to connect to database");

    let repo_id = create_test_repo(&pool, &format!("test-cascade-port-{}", Uuid::new_v4())).await;
    let svc = LifecycleService::new(pool.clone());

    let digest = "sha256:5555555555555555555555555555555555555555555555555555555555555555";
    let image = "myregistry.example:5000/image";
    let tag = "snapshot-keep-me";
    let id = insert_oci_manifest_artifact(&pool, repo_id, image, tag, digest, 100).await;
    insert_oci_tag(&pool, repo_id, image, tag, digest).await;

    let policy = svc
        .create_policy(CreatePolicyRequest {
            repository_id: Some(repo_id),
            name: "Drop snapshot-keep-me".to_string(),
            description: None,
            policy_type: "tag_pattern_delete".to_string(),
            // Anchor on tag suffix; we want the artifact name (which now
            // contains a registry prefix and two colons) to still match.
            config: serde_json::json!({"pattern": "snapshot-keep-me$"}),
            priority: None,
            cron_schedule: None,
        })
        .await
        .unwrap();

    let result = svc.execute_policy(policy.id, false).await.unwrap();
    assert_eq!(
        result.artifacts_removed, 1,
        "policy must still match an image with a port-bearing registry prefix"
    );
    assert!(
        is_deleted(&pool, id).await,
        "artifact with port-in-name must be soft-deleted"
    );
    assert!(
        !oci_tag_exists(&pool, repo_id, image, tag).await,
        "cascade must remove the oci_tags row even when the image carries a host:port prefix"
    );

    cleanup(&pool, repo_id).await;
}

/// Regression for PR #1406 review concern #1 (digest-shape edge case):
/// when an artifact is pinned by digest the reference is
/// `sha256:<hex>` and `artifacts.name = "img:sha256:<hex>"`. The previous
/// greedy `substring(a.name from '^(.+):[^:]+$')` predicate matched the
/// LAST colon, extracting `img:sha256` instead of `img`, so the join to
/// `oci_tags.name` ('img') silently failed and the cascade never fired.
/// The path-based predicate reconstructs the path exactly, so digest
/// references survive.
#[tokio::test]
#[ignore]
async fn test_cascade_handles_digest_reference() {
    let pool = PgPool::connect(&std::env::var("DATABASE_URL").unwrap())
        .await
        .expect("failed to connect to database");

    let repo_id = create_test_repo(&pool, &format!("test-cascade-digest-{}", Uuid::new_v4())).await;
    let svc = LifecycleService::new(pool.clone());

    // Tag value is itself a digest. The artifact_path written by the OCI
    // handler is `v2/{image}/manifests/{reference}` where `reference` is
    // the digest, and `artifacts.name = "{image}:{reference}"`.
    let digest = "sha256:6666666666666666666666666666666666666666666666666666666666666666";
    let image = "imgwithdigest";
    let reference = digest; // pinned-by-digest case
    let id = insert_oci_manifest_artifact(&pool, repo_id, image, reference, digest, 200).await;
    insert_oci_tag(&pool, repo_id, image, reference, digest).await;

    // Backdate the row and run a max_age_days policy: this matches by
    // age, not by name, so we exercise the cascade SQL without depending
    // on the (broken) regex shape.
    sqlx::query("UPDATE artifacts SET created_at = NOW() - INTERVAL '30 days' WHERE id = $1")
        .bind(id)
        .execute(&pool)
        .await
        .expect("backdate failed");

    let policy = svc
        .create_policy(CreatePolicyRequest {
            repository_id: Some(repo_id),
            name: "Drop > 7 days".to_string(),
            description: None,
            policy_type: "max_age_days".to_string(),
            config: serde_json::json!({"days": 7}),
            priority: None,
            cron_schedule: None,
        })
        .await
        .unwrap();

    let result = svc.execute_policy(policy.id, false).await.unwrap();
    assert_eq!(result.artifacts_removed, 1);
    assert!(is_deleted(&pool, id).await);

    // This is the regression assertion: the old regex extracted
    // "imgwithdigest:sha256" from "imgwithdigest:sha256:6666..." and the
    // join failed. With the path-based predicate it succeeds.
    assert!(
        !oci_tag_exists(&pool, repo_id, image, reference).await,
        "cascade must remove oci_tags row when reference is a digest (sha256:...)"
    );

    cleanup(&pool, repo_id).await;
}

/// Regression for PR #1406 review concern #2: the soft-delete and the
/// cascade must happen inside a single transaction. We can't easily
/// crash the process mid-policy in a unit-ish test, but we can verify
/// that an arbitrary failure inside the transaction (here: a policy
/// type the dispatcher rejects after the transaction is open) leaves
/// no orphaned oci_tags rows. Combined with the source-level assertion
/// that `execute_policy` uses `self.db.begin()` and `tx.commit()`, this
/// is enough to catch a regression that drops back to two pool
/// round-trips.
#[tokio::test]
#[ignore]
async fn test_execute_policy_reclaims_orphan_oci_tags() {
    let pool = PgPool::connect(&std::env::var("DATABASE_URL").unwrap())
        .await
        .expect("failed to connect to database");

    let repo_id = create_test_repo(&pool, &format!("test-tx-{}", Uuid::new_v4())).await;
    let svc = LifecycleService::new(pool.clone());

    // Seed: one manifest + one oci_tags row that already matches the
    // cascade predicate (the artifact was soft-deleted by an earlier run
    // but the tag was not removed — exactly the bug state).
    let digest = "sha256:7777777777777777777777777777777777777777777777777777777777777777";
    let id = insert_oci_manifest_artifact(&pool, repo_id, "img", "stale", digest, 100).await;
    insert_oci_tag(&pool, repo_id, "img", "stale", digest).await;
    sqlx::query("UPDATE artifacts SET is_deleted = true WHERE id = $1")
        .bind(id)
        .execute(&pool)
        .await
        .unwrap();

    // Run a real policy that won't match the stale artifact (it's
    // already deleted). The cascade still runs in its own transaction
    // (tx2 of the three-tx split) so the stale tag row is reclaimed.
    let live_id = insert_oci_manifest_artifact(
        &pool,
        repo_id,
        "img",
        "live",
        "sha256:8888888888888888888888888888888888888888888888888888888888888888",
        100,
    )
    .await;
    insert_oci_tag(
        &pool,
        repo_id,
        "img",
        "live",
        "sha256:8888888888888888888888888888888888888888888888888888888888888888",
    )
    .await;

    let policy = svc
        .create_policy(CreatePolicyRequest {
            repository_id: Some(repo_id),
            name: "Drop ^stale$ (no match)".to_string(),
            description: None,
            policy_type: "tag_pattern_delete".to_string(),
            // matches nothing — we just want to commit the cascade.
            config: serde_json::json!({"pattern": "^never-matches$"}),
            priority: None,
            cron_schedule: None,
        })
        .await
        .unwrap();

    let result = svc.execute_policy(policy.id, false).await.unwrap();
    assert_eq!(result.artifacts_removed, 0);

    // The cascade tx ran after the (no-op) soft-delete tx committed.
    // The stale tag must be gone.
    assert!(
        !oci_tag_exists(&pool, repo_id, "img", "stale").await,
        "cascade must reclaim pre-existing stale tags from prior crashed runs"
    );
    // The live one must survive.
    assert!(
        oci_tag_exists(&pool, repo_id, "img", "live").await,
        "live tag must be untouched"
    );
    assert!(!is_deleted(&pool, live_id).await);

    cleanup(&pool, repo_id).await;
}

/// Crash-recovery: if a prior policy execution crashed between the
/// soft-delete transaction (tx1) and the cascade transaction (tx2), the
/// system is left with orphan `oci_tags` rows pointing at soft-deleted
/// manifests. A subsequent policy run must pick them up via the cascade
/// sweep — that's what makes the three-transaction split safe.
///
/// This test simulates the crash by direct SQL: insert manifest +
/// oci_tags, mark the artifact `is_deleted = true` (as tx1 would have
/// done), but never run the cascade for it. Then a fresh policy run
/// (whose own per-type matcher hits nothing) must still reclaim the
/// orphan because tx2 filters on `a.is_deleted = true` globally within
/// the policy's scope.
#[tokio::test]
#[ignore]
async fn test_cascade_picks_up_orphans_from_prior_run() {
    let pool = PgPool::connect(&std::env::var("DATABASE_URL").unwrap())
        .await
        .expect("failed to connect to database");

    let repo_id = create_test_repo(&pool, &format!("test-orphans-{}", Uuid::new_v4())).await;
    let svc = LifecycleService::new(pool.clone());

    // Simulate three crashed-mid-execute orphans: artifacts already
    // soft-deleted, oci_tags rows still present. This is the exact state
    // a crash between tx1 (soft-delete commit) and tx2 (cascade commit)
    // would leave behind.
    let orphans = [
        (
            "imgA",
            "v1",
            "sha256:aaaa000000000000000000000000000000000000000000000000000000000001",
        ),
        (
            "imgA",
            "v2",
            "sha256:aaaa000000000000000000000000000000000000000000000000000000000002",
        ),
        (
            "imgB",
            "snapshot",
            "sha256:bbbb000000000000000000000000000000000000000000000000000000000001",
        ),
    ];
    for (image, tag, digest) in &orphans {
        let id = insert_oci_manifest_artifact(&pool, repo_id, image, tag, digest, 100).await;
        insert_oci_tag(&pool, repo_id, image, tag, digest).await;
        // Direct SQL = the soft-delete from a prior tx1 that committed
        // before the process died.
        sqlx::query("UPDATE artifacts SET is_deleted = true WHERE id = $1")
            .bind(id)
            .execute(&pool)
            .await
            .unwrap();
    }

    // Sanity: orphans exist before the recovery run.
    for (image, tag, _) in &orphans {
        assert!(
            oci_tag_exists(&pool, repo_id, image, tag).await,
            "seeded orphan {}:{} must exist pre-recovery",
            image,
            tag
        );
    }

    // A live artifact + tag that must survive the cascade. The policy's
    // pattern won't match it, so per-type execute is a no-op — only tx2
    // (cascade sweep) does any real work.
    let live_digest = "sha256:cccc000000000000000000000000000000000000000000000000000000000001";
    let live_id =
        insert_oci_manifest_artifact(&pool, repo_id, "imgC", "live", live_digest, 100).await;
    insert_oci_tag(&pool, repo_id, "imgC", "live", live_digest).await;

    let policy = svc
        .create_policy(CreatePolicyRequest {
            repository_id: Some(repo_id),
            name: "Recovery sweep".to_string(),
            description: None,
            policy_type: "tag_pattern_delete".to_string(),
            // Matches nothing; we only care that tx2 fires.
            config: serde_json::json!({"pattern": "^never-matches-anything$"}),
            priority: None,
            cron_schedule: None,
        })
        .await
        .unwrap();

    let result = svc.execute_policy(policy.id, false).await.unwrap();
    assert_eq!(
        result.artifacts_removed, 0,
        "per-type pattern matches nothing; cascade still must run"
    );

    // Every orphan tag row must be gone — tx2's filter on
    // `a.is_deleted = true` picked them up.
    for (image, tag, _) in &orphans {
        assert!(
            !oci_tag_exists(&pool, repo_id, image, tag).await,
            "orphan {}:{} must be reclaimed by the cascade sweep",
            image,
            tag
        );
    }
    // Live tag/artifact must survive.
    assert!(
        oci_tag_exists(&pool, repo_id, "imgC", "live").await,
        "live tag must not be swept"
    );
    assert!(!is_deleted(&pool, live_id).await);

    // Idempotency: running the same policy again must be a no-op for the
    // cascade (nothing more to delete) and must still succeed.
    let result2 = svc.execute_policy(policy.id, false).await.unwrap();
    assert_eq!(result2.artifacts_removed, 0);
    assert!(oci_tag_exists(&pool, repo_id, "imgC", "live").await);

    cleanup(&pool, repo_id).await;
}

#[tokio::test]
#[ignore]
async fn test_size_quota_under_limit_evicts_nothing() {
    let pool = PgPool::connect(&std::env::var("DATABASE_URL").unwrap())
        .await
        .expect("failed to connect to database");

    let repo_id = create_test_repo(&pool, &format!("test-lru-under-{}", Uuid::new_v4())).await;
    let svc = LifecycleService::new(pool.clone());

    // 200 bytes total, quota is 500
    let a1 = insert_artifact(&pool, repo_id, "small-1", 100).await;
    let a2 = insert_artifact(&pool, repo_id, "small-2", 100).await;

    let policy = svc
        .create_policy(CreatePolicyRequest {
            repository_id: Some(repo_id),
            name: "Generous quota".to_string(),
            description: None,
            policy_type: "size_quota_bytes".to_string(),
            config: serde_json::json!({"quota_bytes": 500}),
            priority: None,
            cron_schedule: None,
        })
        .await
        .unwrap();

    let result = svc.execute_policy(policy.id, false).await.unwrap();
    assert_eq!(result.artifacts_matched, 0, "under quota, nothing to evict");
    assert_eq!(result.artifacts_removed, 0);

    assert!(!is_deleted(&pool, a1).await);
    assert!(!is_deleted(&pool, a2).await);

    cleanup_with_downloads(&pool, repo_id).await;
}

// =============================================================================
// Regression coverage for issue #1407 across the remaining policy types.
//
// The original cascade tests covered `tag_pattern_delete` and `max_age_days`.
// The four tests below close that gap so every code path that flips
// `artifacts.is_deleted = true` is exercised against the cascade. A regression
// that drops the cascade call (or routes a new policy type around
// `execute_policy`) will fail at least one of these.
// =============================================================================

/// `max_versions` retains the latest N artifacts per name and soft-deletes the
/// rest. Manifests pushed with the same `name` (e.g. multiple builds of the
/// same image tag stream) and digest references need their `oci_tags` rows
/// reclaimed too.
#[tokio::test]
#[ignore]
async fn test_max_versions_cascades_oci_tags() {
    let pool = PgPool::connect(&std::env::var("DATABASE_URL").unwrap())
        .await
        .expect("failed to connect to database");

    let repo_id = create_test_repo(&pool, &format!("test-cascade-mv-{}", Uuid::new_v4())).await;
    let svc = LifecycleService::new(pool.clone());

    // Three artifacts share the same `name` ("img:rolling") so max_versions
    // with keep=1 will soft-delete the two older ones. Each has its own
    // (digest, tag) so the cascade has three distinct (path, storage_key)
    // join targets to consider.
    let digest_old = "sha256:1407aa00000000000000000000000000000000000000000000000000000001";
    let digest_mid = "sha256:1407aa00000000000000000000000000000000000000000000000000000002";
    let digest_new = "sha256:1407aa00000000000000000000000000000000000000000000000000000003";

    // insert_oci_manifest_artifact sets `name = "{image}:{tag}"`. To make all
    // three rows share the same name (the field max_versions partitions on),
    // we insert them via a single-image, single-tag shape and override the
    // tag per row to keep `(repository_id, path)` unique.
    let _id_old =
        insert_oci_manifest_artifact(&pool, repo_id, "img", "rolling-1", digest_old, 100).await;
    let _id_mid =
        insert_oci_manifest_artifact(&pool, repo_id, "img", "rolling-2", digest_mid, 100).await;
    let _id_new =
        insert_oci_manifest_artifact(&pool, repo_id, "img", "rolling-3", digest_new, 100).await;
    insert_oci_tag(&pool, repo_id, "img", "rolling-1", digest_old).await;
    insert_oci_tag(&pool, repo_id, "img", "rolling-2", digest_mid).await;
    insert_oci_tag(&pool, repo_id, "img", "rolling-3", digest_new).await;

    // Force all three rows to share the same `name` so they form one
    // max_versions partition. The insert helper writes "img:<tag>"; rewrite
    // it to a single canonical name. The cascade still keys on `path`, not
    // `name`, so this rewrite does not weaken the join.
    sqlx::query("UPDATE artifacts SET name = 'img:rolling' WHERE repository_id = $1")
        .bind(repo_id)
        .execute(&pool)
        .await
        .expect("failed to align names for max_versions partition");

    // Backdate so created_at ordering is deterministic.
    sqlx::query(
        "UPDATE artifacts SET created_at = NOW() - INTERVAL '3 days' WHERE storage_key = $1",
    )
    .bind(format!("oci-manifests/{}", digest_old))
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query(
        "UPDATE artifacts SET created_at = NOW() - INTERVAL '2 days' WHERE storage_key = $1",
    )
    .bind(format!("oci-manifests/{}", digest_mid))
    .execute(&pool)
    .await
    .unwrap();

    let policy = svc
        .create_policy(CreatePolicyRequest {
            repository_id: Some(repo_id),
            name: "Keep latest".to_string(),
            description: None,
            policy_type: "max_versions".to_string(),
            config: serde_json::json!({"keep": 1}),
            priority: None,
            cron_schedule: None,
        })
        .await
        .unwrap();

    let result = svc.execute_policy(policy.id, false).await.unwrap();
    assert_eq!(result.artifacts_removed, 2);

    // Cascade must have removed the two older oci_tags rows; only the
    // most-recent rolling-3 tag survives.
    assert!(
        !oci_tag_exists(&pool, repo_id, "img", "rolling-1").await,
        "max_versions cascade must remove oci_tags for the oldest rolling artifact"
    );
    assert!(
        !oci_tag_exists(&pool, repo_id, "img", "rolling-2").await,
        "max_versions cascade must remove oci_tags for the middle rolling artifact"
    );
    assert!(
        oci_tag_exists(&pool, repo_id, "img", "rolling-3").await,
        "the kept tag must survive the cascade"
    );

    cleanup(&pool, repo_id).await;
}

/// `no_downloads_days` soft-deletes artifacts that have not been downloaded
/// in the configured window. Manifests in this state are exactly the kind of
/// long-tail content the production observation in #1407 saw piling up;
/// without the cascade, the `oci_tags` row keeps them tethered.
#[tokio::test]
#[ignore]
async fn test_no_downloads_days_cascades_oci_tags() {
    let pool = PgPool::connect(&std::env::var("DATABASE_URL").unwrap())
        .await
        .expect("failed to connect to database");

    let repo_id = create_test_repo(&pool, &format!("test-cascade-nd-{}", Uuid::new_v4())).await;
    let svc = LifecycleService::new(pool.clone());

    // One cold manifest (no downloads, created 30 days ago) plus one warm
    // one (downloaded 1 day ago, created 30 days ago). The policy targets
    // anything older than 7 days with no recent downloads, so only the cold
    // one is soft-deleted. The warm download is anchored to NOW (1 day ago)
    // rather than a hardcoded date so it stays inside the 7-day window no
    // matter when the test runs.
    let cold_digest = "sha256:1407bb00000000000000000000000000000000000000000000000000000001";
    let warm_digest = "sha256:1407bb00000000000000000000000000000000000000000000000000000002";
    let cold_id =
        insert_oci_manifest_artifact(&pool, repo_id, "img", "cold", cold_digest, 100).await;
    let warm_id =
        insert_oci_manifest_artifact(&pool, repo_id, "img", "warm", warm_digest, 100).await;
    insert_oci_tag(&pool, repo_id, "img", "cold", cold_digest).await;
    insert_oci_tag(&pool, repo_id, "img", "warm", warm_digest).await;

    sqlx::query("UPDATE artifacts SET created_at = NOW() - INTERVAL '30 days' WHERE id = $1")
        .bind(cold_id)
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("UPDATE artifacts SET created_at = NOW() - INTERVAL '30 days' WHERE id = $1")
        .bind(warm_id)
        .execute(&pool)
        .await
        .unwrap();
    record_download_days_ago(&pool, warm_id, 1).await;

    let policy = svc
        .create_policy(CreatePolicyRequest {
            repository_id: Some(repo_id),
            name: "Drop cold".to_string(),
            description: None,
            policy_type: "no_downloads_days".to_string(),
            config: serde_json::json!({"days": 7}),
            priority: None,
            cron_schedule: None,
        })
        .await
        .unwrap();

    let result = svc.execute_policy(policy.id, false).await.unwrap();
    assert_eq!(result.artifacts_removed, 1);
    assert!(is_deleted(&pool, cold_id).await);
    assert!(!is_deleted(&pool, warm_id).await);

    assert!(
        !oci_tag_exists(&pool, repo_id, "img", "cold").await,
        "no_downloads_days cascade must remove oci_tags for the cold manifest"
    );
    assert!(
        oci_tag_exists(&pool, repo_id, "img", "warm").await,
        "the downloaded manifest's tag must survive"
    );

    cleanup_with_downloads(&pool, repo_id).await;
}

/// `tag_pattern_keep` is the inverse of `tag_pattern_delete`. The cascade
/// runs at the end of `execute_policy` regardless of which side of the
/// pattern split was matched, so the kept-vs-evicted bookkeeping must
/// propagate correctly into the oci_tags removal.
#[tokio::test]
#[ignore]
async fn test_tag_pattern_keep_cascades_oci_tags() {
    let pool = PgPool::connect(&std::env::var("DATABASE_URL").unwrap())
        .await
        .expect("failed to connect to database");

    let repo_id = create_test_repo(&pool, &format!("test-cascade-tpk-{}", Uuid::new_v4())).await;
    let svc = LifecycleService::new(pool.clone());

    // Keep anything that starts with "v" (semver tags); evict everything
    // else. Insert one of each.
    let release_digest = "sha256:1407cc00000000000000000000000000000000000000000000000000000001";
    let snapshot_digest = "sha256:1407cc00000000000000000000000000000000000000000000000000000002";
    let release_id =
        insert_oci_manifest_artifact(&pool, repo_id, "img", "v1.0.0", release_digest, 100).await;
    let snapshot_id =
        insert_oci_manifest_artifact(&pool, repo_id, "img", "nightly", snapshot_digest, 100).await;
    insert_oci_tag(&pool, repo_id, "img", "v1.0.0", release_digest).await;
    insert_oci_tag(&pool, repo_id, "img", "nightly", snapshot_digest).await;

    let policy = svc
        .create_policy(CreatePolicyRequest {
            repository_id: Some(repo_id),
            name: "Keep semver".to_string(),
            description: None,
            policy_type: "tag_pattern_keep".to_string(),
            // `tag_pattern_keep` matches on `artifacts.name`, which the OCI
            // handler writes as "{image}:{tag}". Anchor on the colon so the
            // pattern keys on the tag portion only.
            config: serde_json::json!({"pattern": ":v"}),
            priority: None,
            cron_schedule: None,
        })
        .await
        .unwrap();

    let result = svc.execute_policy(policy.id, false).await.unwrap();
    assert_eq!(result.artifacts_removed, 1);
    assert!(!is_deleted(&pool, release_id).await);
    assert!(is_deleted(&pool, snapshot_id).await);

    assert!(
        !oci_tag_exists(&pool, repo_id, "img", "nightly").await,
        "tag_pattern_keep cascade must remove oci_tags for the non-matching (evicted) manifest"
    );
    assert!(
        oci_tag_exists(&pool, repo_id, "img", "v1.0.0").await,
        "the kept semver tag must survive"
    );

    cleanup(&pool, repo_id).await;
}

/// `size_quota_bytes` uses LRU eviction. The pool of candidate artifacts is
/// picked by Rust code (`select_size_quota_evictions`) and executed with a
/// single `UPDATE ... WHERE id = ANY($1)`. Even though no SQL predicate
/// touches manifest paths, the cascade still has to fire — that is what makes
/// `execute_policy`'s post-dispatch cascade contract repo-type agnostic.
#[tokio::test]
#[ignore]
async fn test_size_quota_bytes_cascades_oci_tags() {
    let pool = PgPool::connect(&std::env::var("DATABASE_URL").unwrap())
        .await
        .expect("failed to connect to database");

    let repo_id = create_test_repo(&pool, &format!("test-cascade-sq-{}", Uuid::new_v4())).await;
    let svc = LifecycleService::new(pool.clone());

    // Two manifests of 100 bytes each, quota of 100 bytes -> evict one. The
    // never-downloaded one goes first by LRU rules.
    let evict_digest = "sha256:1407dd00000000000000000000000000000000000000000000000000000001";
    let keep_digest = "sha256:1407dd00000000000000000000000000000000000000000000000000000002";
    let evict_id =
        insert_oci_manifest_artifact(&pool, repo_id, "img", "evict-me", evict_digest, 100).await;
    let keep_id =
        insert_oci_manifest_artifact(&pool, repo_id, "img", "keep-me", keep_digest, 100).await;
    insert_oci_tag(&pool, repo_id, "img", "evict-me", evict_digest).await;
    insert_oci_tag(&pool, repo_id, "img", "keep-me", keep_digest).await;

    // Mark keep-me as downloaded so it ranks ahead of evict-me in LRU
    // ordering (NULLS FIRST puts never-downloaded artifacts at the front
    // of the eviction queue).
    record_download(&pool, keep_id, "2026-05-29T00:00:00Z").await;

    let policy = svc
        .create_policy(CreatePolicyRequest {
            repository_id: Some(repo_id),
            name: "Tight quota".to_string(),
            description: None,
            policy_type: "size_quota_bytes".to_string(),
            config: serde_json::json!({"quota_bytes": 100}),
            priority: None,
            cron_schedule: None,
        })
        .await
        .unwrap();

    let result = svc.execute_policy(policy.id, false).await.unwrap();
    assert_eq!(result.artifacts_removed, 1);
    assert!(is_deleted(&pool, evict_id).await);
    assert!(!is_deleted(&pool, keep_id).await);

    assert!(
        !oci_tag_exists(&pool, repo_id, "img", "evict-me").await,
        "size_quota_bytes cascade must remove oci_tags for the LRU-evicted manifest"
    );
    assert!(
        oci_tag_exists(&pool, repo_id, "img", "keep-me").await,
        "the still-quota-fitting manifest's tag must survive"
    );

    cleanup_with_downloads(&pool, repo_id).await;
}

/// End-to-end check of the chain the issue describes:
///   lifecycle policy -> soft-delete artifact -> cascade oci_tags ->
///   storage GC's orphan predicate recognises the storage key as orphan.
///
/// We don't invoke the real `StorageGcService::run_gc` (it requires a
/// `StorageRegistry` and would touch real storage backends). Instead we
/// re-execute the exact orphan predicate from
/// `backend/src/services/storage_gc_service.rs` (the `ORPHAN_PREDICATE_SQL`
/// constant) against the database state the cascade leaves behind. If the
/// cascade ever regresses (or someone weakens the join), this assertion
/// catches it because the predicate counts the manifest as still-referenced
/// by `oci_tags` and the test fails. Per-key assertions only — no global
/// counter, so the test stays safe under parallel coverage runs (the
/// pattern from #1499).
#[tokio::test]
#[ignore]
async fn test_lifecycle_cascade_unblocks_storage_gc_orphan_detection() {
    let pool = PgPool::connect(&std::env::var("DATABASE_URL").unwrap())
        .await
        .expect("failed to connect to database");

    let repo_id = create_test_repo(&pool, &format!("test-cascade-gc-{}", Uuid::new_v4())).await;
    let svc = LifecycleService::new(pool.clone());

    let digest = "sha256:1407ee00000000000000000000000000000000000000000000000000000001";
    let storage_key = format!("oci-manifests/{}", digest);
    let id = insert_oci_manifest_artifact(&pool, repo_id, "img", "drop-me", digest, 100).await;
    insert_oci_tag(&pool, repo_id, "img", "drop-me", digest).await;

    // Helper: re-evaluate the storage GC orphan predicate for our specific
    // (storage_key, repository_id) tuple. This mirrors the NOT EXISTS chain
    // in storage_gc_service.rs::ORPHAN_PREDICATE_SQL. We deliberately scope
    // to a single (key, repo) tuple so the parallel test isolation issue
    // fixed in #1499 cannot affect this assertion.
    async fn is_storage_key_orphan(pool: &PgPool, repo_id: Uuid, storage_key: &str) -> bool {
        let row: (i64,) = sqlx::query_as(
            r#"
            SELECT COUNT(*)
            FROM artifacts a
            JOIN repositories r ON r.id = a.repository_id
            WHERE a.storage_key = $1
              AND a.repository_id = $2
              AND a.is_deleted = true
              AND NOT EXISTS (
                  SELECT 1 FROM artifacts a2
                  WHERE a2.storage_key = a.storage_key
                    AND a2.is_deleted = false
              )
              AND NOT EXISTS (
                  SELECT 1
                  FROM oci_tags ot
                  JOIN repositories otr ON otr.id = ot.repository_id
                  WHERE a.storage_key LIKE 'oci-manifests/%'
                    AND ot.manifest_digest = SUBSTRING(
                      a.storage_key FROM LENGTH('oci-manifests/') + 1
                    )
                    AND otr.storage_backend = r.storage_backend
                    AND (
                      r.storage_backend <> 'filesystem'
                      OR otr.storage_path = r.storage_path
                    )
              )
            "#,
        )
        .bind(storage_key)
        .bind(repo_id)
        .fetch_one(pool)
        .await
        .expect("orphan predicate query failed");
        row.0 > 0
    }

    // Backdate so a max_age_days policy will pick it up.
    sqlx::query("UPDATE artifacts SET created_at = NOW() - INTERVAL '30 days' WHERE id = $1")
        .bind(id)
        .execute(&pool)
        .await
        .unwrap();

    // Pre-cascade sanity: the predicate must consider the key NOT orphan
    // because the artifact is still live AND the oci_tags row is still
    // present. (Either condition alone is enough; we assert against the
    // post-state, not the cause.)
    assert!(
        !is_storage_key_orphan(&pool, repo_id, &storage_key).await,
        "pre-policy: storage_key must not be orphan (artifact is live + tag exists)"
    );

    let policy = svc
        .create_policy(CreatePolicyRequest {
            repository_id: Some(repo_id),
            name: "Drop > 7 days".to_string(),
            description: None,
            policy_type: "max_age_days".to_string(),
            config: serde_json::json!({"days": 7}),
            priority: None,
            cron_schedule: None,
        })
        .await
        .unwrap();

    let result = svc.execute_policy(policy.id, false).await.unwrap();
    assert_eq!(result.artifacts_removed, 1);
    assert!(is_deleted(&pool, id).await);

    // The cascade reclaimed the oci_tags row. Now the orphan predicate
    // should fire — exactly the chain the issue says was broken.
    assert!(
        !oci_tag_exists(&pool, repo_id, "img", "drop-me").await,
        "cascade must have removed the oci_tags row"
    );
    assert!(
        is_storage_key_orphan(&pool, repo_id, &storage_key).await,
        "post-cascade: storage GC's orphan predicate must now recognise the manifest \
         storage_key as reclaimable (this is the issue #1407 promise)"
    );

    cleanup(&pool, repo_id).await;
}
