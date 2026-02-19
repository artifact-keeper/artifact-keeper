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

use artifact_keeper_backend::services::lifecycle_service::{
    CreatePolicyRequest, LifecycleService,
};

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
        })
        .await
        .expect("failed to create policy");

    // --- Dry run first ---
    let dry_result = svc
        .execute_policy(policy.id, true)
        .await
        .expect("dry run failed");
    assert_eq!(dry_result.artifacts_matched, 2, "should match 2 non-release artifacts");
    assert_eq!(dry_result.artifacts_removed, 0, "dry run should not remove anything");
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
    assert_eq!(result.artifacts_matched, 2, "should match 2 non-release artifacts");
    assert_eq!(result.artifacts_removed, 2, "should remove 2 non-matching artifacts");
    assert!(!result.dry_run);
    assert!(result.errors.is_empty());

    // Verify: release-* and v* kept, others deleted
    assert!(!is_deleted(&pool, a_release).await, "release-1.0.0 should be kept");
    assert!(!is_deleted(&pool, a_v2).await, "v2.0.0 should be kept");
    assert!(is_deleted(&pool, a_snapshot).await, "snapshot-nightly-123 should be deleted");
    assert!(is_deleted(&pool, a_dev).await, "dev-build-456 should be deleted");

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
        })
        .await
        .unwrap();

    let result = svc.execute_policy(policy.id, false).await.unwrap();
    assert_eq!(result.artifacts_matched, 0, "all artifacts match, none to delete");
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
        })
        .await
        .unwrap();

    let result = svc.execute_policy(policy.id, false).await.unwrap();
    assert_eq!(result.artifacts_matched, 1);
    assert_eq!(result.artifacts_removed, 1);

    assert!(!is_deleted(&pool, a_release).await, "release should be kept");
    assert!(is_deleted(&pool, a_snapshot).await, "snapshot should be deleted");

    cleanup(&pool, repo_id).await;
}
