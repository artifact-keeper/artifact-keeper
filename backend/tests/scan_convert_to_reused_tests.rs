//! Integration tests for `ScanResultService::convert_to_reused`.
//!
//! These tests require a PostgreSQL database with migrations applied.
//! Set DATABASE_URL and run:
//!
//! ```sh
//! DATABASE_URL="postgresql://registry:registry@localhost:30432/artifact_registry" \
//!   cargo test --test scan_convert_to_reused_tests -- --ignored
//! ```
//!
//! These tests cover the review feedback on PR #1005:
//! - happy path: a `running` row gets flipped to `completed`/`is_reused = true`
//!   with counts copied from the source scan and findings inserted.
//! - idempotency: a second call on the same target row is a no-op (status
//!   guard kicks in, no duplicate findings get inserted).
//! - transactionality is exercised structurally by both tests; an explicit
//!   "INSERT findings fails -> UPDATE rolled back" case would require fault
//!   injection on the pool and is left as a future addition.

use sqlx::PgPool;
use uuid::Uuid;

use artifact_keeper_backend::services::scan_result_service::ScanResultService;

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

async fn create_test_repo(pool: &PgPool) -> Uuid {
    let id = Uuid::new_v4();
    let key = format!("test-convert-reused-{}", id);
    let storage_path = format!("/tmp/test-artifacts/{}", id);
    sqlx::query(
        "INSERT INTO repositories (id, key, name, storage_path, repo_type, format) \
         VALUES ($1, $2, $3, $4, 'local', 'generic')",
    )
    .bind(id)
    .bind(&key)
    .bind(format!("convert-reused-{}", id))
    .bind(&storage_path)
    .execute(pool)
    .await
    .expect("failed to create test repository");
    id
}

async fn insert_artifact(pool: &PgPool, repo_id: Uuid, name: &str) -> Uuid {
    let id = Uuid::new_v4();
    let path = format!("{}/{}", repo_id, name);
    let checksum = format!("{:0>64}", format!("{:x}", id.as_u128() & 0xffff_ffff));
    sqlx::query(
        r#"
        INSERT INTO artifacts (id, repository_id, name, path, size_bytes, checksum_sha256,
                               content_type, storage_key, is_deleted)
        VALUES ($1, $2, $3, $4, $5, $6, 'application/octet-stream', $4, false)
        "#,
    )
    .bind(id)
    .bind(repo_id)
    .bind(name)
    .bind(&path)
    .bind(1024_i64)
    .bind(&checksum)
    .execute(pool)
    .await
    .expect("failed to insert test artifact");
    id
}

/// Insert a completed source scan with a known set of findings to be copied.
/// Returns the source scan_result id.
async fn insert_source_scan_with_findings(
    pool: &PgPool,
    artifact_id: Uuid,
    repo_id: Uuid,
    findings_count: i32,
    critical: i32,
    high: i32,
) -> Uuid {
    let scan_id = Uuid::new_v4();
    sqlx::query(
        r#"
        INSERT INTO scan_results (
            id, artifact_id, repository_id, scan_type, status,
            findings_count, critical_count, high_count, medium_count, low_count, info_count,
            started_at, completed_at
        )
        VALUES ($1, $2, $3, 'dependency', 'completed', $4, $5, $6, 0, 0, 0, NOW(), NOW())
        "#,
    )
    .bind(scan_id)
    .bind(artifact_id)
    .bind(repo_id)
    .bind(findings_count)
    .bind(critical)
    .bind(high)
    .execute(pool)
    .await
    .expect("failed to insert source scan_result");

    // One finding per critical, one per high, so the COPY...SELECT in
    // convert_to_reused has rows to move.
    for i in 0..critical {
        sqlx::query(
            r#"
            INSERT INTO scan_findings (scan_result_id, artifact_id, severity, title, source)
            VALUES ($1, $2, 'critical', $3, 'test')
            "#,
        )
        .bind(scan_id)
        .bind(artifact_id)
        .bind(format!("critical finding {}", i))
        .execute(pool)
        .await
        .expect("failed to insert critical finding");
    }
    for i in 0..high {
        sqlx::query(
            r#"
            INSERT INTO scan_findings (scan_result_id, artifact_id, severity, title, source)
            VALUES ($1, $2, 'high', $3, 'test')
            "#,
        )
        .bind(scan_id)
        .bind(artifact_id)
        .bind(format!("high finding {}", i))
        .execute(pool)
        .await
        .expect("failed to insert high finding");
    }

    scan_id
}

/// Pre-allocate a `running` scan_result row that the trigger handler would
/// have inserted before it knew dedup was possible. Returns its id.
async fn insert_running_target(pool: &PgPool, artifact_id: Uuid, repo_id: Uuid) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        r#"
        INSERT INTO scan_results (
            id, artifact_id, repository_id, scan_type, status, started_at
        )
        VALUES ($1, $2, $3, 'dependency', 'running', NOW())
        "#,
    )
    .bind(id)
    .bind(artifact_id)
    .bind(repo_id)
    .execute(pool)
    .await
    .expect("failed to insert pre-allocated target scan_result");
    id
}

async fn count_findings_for(pool: &PgPool, scan_result_id: Uuid) -> i64 {
    let row: (i64,) =
        sqlx::query_as("SELECT COUNT(*) FROM scan_findings WHERE scan_result_id = $1")
            .bind(scan_result_id)
            .fetch_one(pool)
            .await
            .expect("count_findings_for failed");
    row.0
}

async fn cleanup(pool: &PgPool, repo_id: Uuid) {
    // Findings -> results -> artifacts -> repo. Findings cascade off
    // scan_results, but be explicit so a failed prior run does not leave
    // orphans behind.
    sqlx::query(
        "DELETE FROM scan_findings WHERE scan_result_id IN \
         (SELECT id FROM scan_results WHERE repository_id = $1)",
    )
    .bind(repo_id)
    .execute(pool)
    .await
    .ok();
    sqlx::query("DELETE FROM scan_results WHERE repository_id = $1")
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

// ---------------------------------------------------------------------------
// Happy path
// ---------------------------------------------------------------------------

#[tokio::test]
#[ignore] // Requires database
async fn test_convert_to_reused_happy_path_updates_target_and_copies_findings() {
    let pool = PgPool::connect(&std::env::var("DATABASE_URL").expect("DATABASE_URL"))
        .await
        .expect("failed to connect to database");

    let repo_id = create_test_repo(&pool).await;
    let source_artifact = insert_artifact(&pool, repo_id, "source.tgz").await;
    let target_artifact = insert_artifact(&pool, repo_id, "target.tgz").await;

    // Source: 3 findings (2 critical, 1 high).
    let source_scan_id =
        insert_source_scan_with_findings(&pool, source_artifact, repo_id, 3, 2, 1).await;

    // Target: pre-allocated `running` row, mirroring what the trigger handler
    // would have committed before the dedup decision was made.
    let target_scan_id = insert_running_target(&pool, target_artifact, repo_id).await;

    let svc = ScanResultService::new(pool.clone());
    let returned = svc
        .convert_to_reused(target_scan_id, source_scan_id, target_artifact)
        .await
        .expect("convert_to_reused happy path must succeed");

    // Returned row reflects the post-update state.
    assert_eq!(
        returned.id, target_scan_id,
        "must update in place, not insert"
    );
    assert_eq!(returned.status, "completed");
    assert!(returned.is_reused);
    assert_eq!(returned.source_scan_id, Some(source_scan_id));
    assert_eq!(returned.findings_count, 3);
    assert_eq!(returned.critical_count, 2);
    assert_eq!(returned.high_count, 1);

    // The findings table got 3 rows attributed to the target id (one row per
    // source finding, owned by the target artifact).
    assert_eq!(
        count_findings_for(&pool, target_scan_id).await,
        3,
        "convert_to_reused must copy every source finding to the target row"
    );

    cleanup(&pool, repo_id).await;
}

// ---------------------------------------------------------------------------
// Idempotency / status guard
// ---------------------------------------------------------------------------

#[tokio::test]
#[ignore] // Requires database
async fn test_convert_to_reused_second_call_is_no_op_no_duplicate_findings() {
    let pool = PgPool::connect(&std::env::var("DATABASE_URL").expect("DATABASE_URL"))
        .await
        .expect("failed to connect to database");

    let repo_id = create_test_repo(&pool).await;
    let source_artifact = insert_artifact(&pool, repo_id, "source.tgz").await;
    let target_artifact = insert_artifact(&pool, repo_id, "target.tgz").await;

    // Source: 4 findings (1 critical, 3 high).
    let source_scan_id =
        insert_source_scan_with_findings(&pool, source_artifact, repo_id, 4, 1, 3).await;
    let target_scan_id = insert_running_target(&pool, target_artifact, repo_id).await;

    let svc = ScanResultService::new(pool.clone());

    // First call: full conversion.
    let first = svc
        .convert_to_reused(target_scan_id, source_scan_id, target_artifact)
        .await
        .expect("first convert_to_reused must succeed");
    assert_eq!(first.status, "completed");
    assert!(first.is_reused);
    assert_eq!(count_findings_for(&pool, target_scan_id).await, 4);

    // Second call on the same target: must be a no-op. The status guard
    // (WHERE status = 'running') matches zero rows, the (no-op) transaction
    // is rolled back, and the existing scan row is returned unchanged.
    let second = svc
        .convert_to_reused(target_scan_id, source_scan_id, target_artifact)
        .await
        .expect("second convert_to_reused must succeed (idempotent no-op)");

    // Same row, still flagged as reused, still pointing at the same source.
    assert_eq!(second.id, target_scan_id);
    assert_eq!(second.status, "completed");
    assert!(second.is_reused);
    assert_eq!(second.source_scan_id, Some(source_scan_id));
    assert_eq!(second.findings_count, 4);

    // Critically: the second call must NOT re-insert findings. Any duplicate
    // here would mean the status guard was missing and clients would see
    // double-counted vulnerabilities on retry.
    assert_eq!(
        count_findings_for(&pool, target_scan_id).await,
        4,
        "second convert_to_reused must not duplicate findings on the target"
    );

    cleanup(&pool, repo_id).await;
}
