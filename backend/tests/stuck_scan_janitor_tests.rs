//! Integration tests for the stuck-`running` scan_results janitor (#1015).
//!
//! Pre-allocated scan_results rows can get stuck in `status='running'` when a
//! scanner pod crashes mid-scan, the scheduler is killed, or
//! `convert_to_reused`/the scan worker never reaches its terminal UPDATE. The
//! janitor reaps such rows by transitioning them to `status='failed'` with a
//! diagnostic `error_message` once `started_at` falls outside the configured
//! threshold. Rows still inside the threshold and rows already in a terminal
//! state must not be touched.
//!
//! Requires PostgreSQL with all migrations applied:
//!
//! ```sh
//! podman run -d --rm --name ak-test-pg -p 35432:5432 \
//!     -e POSTGRES_PASSWORD=registry -e POSTGRES_USER=registry \
//!     -e POSTGRES_DB=artifact_registry docker.io/library/postgres:16
//! # apply backend/migrations/*.sql
//! DATABASE_URL="postgres://registry:registry@localhost:35432/artifact_registry" \
//!     cargo test --test stuck_scan_janitor_tests -- --ignored --test-threads=1
//! ```
//!
//! **`--test-threads=1` is required**, not a suggestion: the audit-failure
//! test installs a table-level CHECK constraint on `audit_log` for the
//! duration of its run. Other tests in this file that emit `SCAN_REAPED`
//! audit rows would be rejected by that constraint if they ran in parallel.
//! The constraint is also globally visible to any other process connected
//! to the same `audit_log` table — run this suite against a per-process DB
//! (the `podman run` above creates one), not a shared CI database.
#![cfg(test)]

use sqlx::PgPool;
use std::time::Duration;
use uuid::Uuid;

use artifact_keeper_backend::services::scan_result_service::ScanResultService;

async fn connect_db() -> PgPool {
    let url = std::env::var("DATABASE_URL")
        .expect("DATABASE_URL must be set; see module docstring for setup");
    PgPool::connect(&url)
        .await
        .expect("failed to connect to test database")
}

/// Insert a test repository, returning its id.
async fn create_test_repo(pool: &PgPool) -> Uuid {
    let id = Uuid::new_v4();
    let key = format!("stuck-scan-{}", id.as_simple());
    let storage_path = format!("/tmp/test-artifacts/{}", id);
    sqlx::query(
        "INSERT INTO repositories (id, key, name, storage_path, repo_type, format)
         VALUES ($1, $2, $2, $3, 'local', 'generic')",
    )
    .bind(id)
    .bind(&key)
    .bind(&storage_path)
    .execute(pool)
    .await
    .expect("insert repo");
    id
}

/// Insert an artifact in the given repo, returning its id.
async fn create_test_artifact(pool: &PgPool, repo_id: Uuid) -> Uuid {
    let id = Uuid::new_v4();
    let path = format!("{}/pkg.tar.gz", id.as_simple());
    let checksum = format!("{:0>64}", id.as_simple());
    sqlx::query(
        r#"
        INSERT INTO artifacts (id, repository_id, name, path, size_bytes,
            checksum_sha256, content_type, storage_key, is_deleted)
        VALUES ($1, $2, 'pkg.tar.gz', $3, 1024, $4,
            'application/octet-stream', $3, false)
        "#,
    )
    .bind(id)
    .bind(repo_id)
    .bind(&path)
    .bind(&checksum)
    .execute(pool)
    .await
    .expect("insert artifact");
    id
}

/// Insert a `running` scan_results row with a caller-controlled `started_at`.
/// Returns the row id.
async fn insert_running_scan(
    pool: &PgPool,
    artifact_id: Uuid,
    repo_id: Uuid,
    started_at: chrono::DateTime<chrono::Utc>,
) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        r#"
        INSERT INTO scan_results (id, artifact_id, repository_id, scan_type,
            status, started_at)
        VALUES ($1, $2, $3, 'dependency', 'running', $4)
        "#,
    )
    .bind(id)
    .bind(artifact_id)
    .bind(repo_id)
    .bind(started_at)
    .execute(pool)
    .await
    .expect("insert running scan");
    id
}

async fn fetch_status_and_error(pool: &PgPool, scan_id: Uuid) -> (String, Option<String>) {
    let row: (String, Option<String>) =
        sqlx::query_as("SELECT status, error_message FROM scan_results WHERE id = $1")
            .bind(scan_id)
            .fetch_one(pool)
            .await
            .expect("fetch scan");
    row
}

async fn cleanup(pool: &PgPool, repo_id: Uuid) {
    let _ = sqlx::query("DELETE FROM scan_findings WHERE artifact_id IN (SELECT id FROM artifacts WHERE repository_id = $1)")
        .bind(repo_id)
        .execute(pool)
        .await;
    // Audit entries reference scan_results via resource_id but do not have a
    // FK, so we clean them up explicitly to keep test runs idempotent.
    let _ = sqlx::query(
        r#"
        DELETE FROM audit_log
        WHERE action = 'SCAN_REAPED'
          AND resource_id IN (SELECT id FROM scan_results WHERE repository_id = $1)
        "#,
    )
    .bind(repo_id)
    .execute(pool)
    .await;
    let _ = sqlx::query("DELETE FROM scan_results WHERE repository_id = $1")
        .bind(repo_id)
        .execute(pool)
        .await;
    let _ = sqlx::query("DELETE FROM artifacts WHERE repository_id = $1")
        .bind(repo_id)
        .execute(pool)
        .await;
    let _ = sqlx::query("DELETE FROM repositories WHERE id = $1")
        .bind(repo_id)
        .execute(pool)
        .await;
}

// =============================================================================
// Reproduction: stuck row past threshold gets failed with a diagnostic message,
// fresh row inside threshold is left alone, and already-terminal rows are not
// touched.
// =============================================================================

#[tokio::test]
#[ignore]
async fn test_cleanup_stuck_scans_marks_old_running_as_failed() {
    let pool = connect_db().await;
    let repo_id = create_test_repo(&pool).await;
    let artifact_id = create_test_artifact(&pool, repo_id).await;
    let svc = ScanResultService::new(pool.clone());

    // Stuck row: started 31 min ago, still running.
    let stuck_started = chrono::Utc::now() - chrono::Duration::minutes(31);
    let stuck_id = insert_running_scan(&pool, artifact_id, repo_id, stuck_started).await;

    let cleaned = svc
        .cleanup_stuck_scans(Duration::from_secs(30 * 60))
        .await
        .expect("janitor should succeed");

    assert!(
        cleaned >= 1,
        "expected at least 1 row reaped, got {}",
        cleaned
    );

    let (status, error) = fetch_status_and_error(&pool, stuck_id).await;
    assert_eq!(
        status, "failed",
        "stuck row should be transitioned to failed"
    );
    let err = error.expect("failed row should have a diagnostic error_message");
    assert!(
        err.to_lowercase().contains("janitor")
            || err.to_lowercase().contains("stuck")
            || err.to_lowercase().contains("did not complete"),
        "error_message should explain the reaping (got: {:?})",
        err
    );

    cleanup(&pool, repo_id).await;
}

#[tokio::test]
#[ignore]
async fn test_cleanup_stuck_scans_leaves_fresh_running_rows_alone() {
    let pool = connect_db().await;
    let repo_id = create_test_repo(&pool).await;
    let artifact_id = create_test_artifact(&pool, repo_id).await;
    let svc = ScanResultService::new(pool.clone());

    // Fresh row: started 1 minute ago, still well inside the 30-min threshold.
    let fresh_started = chrono::Utc::now() - chrono::Duration::minutes(1);
    let fresh_id = insert_running_scan(&pool, artifact_id, repo_id, fresh_started).await;

    let _ = svc
        .cleanup_stuck_scans(Duration::from_secs(30 * 60))
        .await
        .expect("janitor should succeed");

    let (status, error) = fetch_status_and_error(&pool, fresh_id).await;
    assert_eq!(
        status, "running",
        "fresh in-progress row must not be reaped"
    );
    assert!(
        error.is_none(),
        "fresh row must not get an error_message (got {:?})",
        error
    );

    // Zero rows reaped must emit zero SCAN_REAPED audit entries — a regression
    // that fires an audit row on every tick (even with nothing to reap) would
    // flood operators' incident-investigation queries.
    let count: (i64,) = sqlx::query_as(
        r#"
        SELECT COUNT(*)
        FROM audit_log
        WHERE action = 'SCAN_REAPED'
          AND resource_id IN (SELECT id FROM scan_results WHERE repository_id = $1)
        "#,
    )
    .bind(repo_id)
    .fetch_one(&pool)
    .await
    .expect("count audit entries");
    assert_eq!(
        count.0, 0,
        "no audit entries should be written when no rows are reaped"
    );

    cleanup(&pool, repo_id).await;
}

#[tokio::test]
#[ignore]
async fn test_cleanup_stuck_scans_does_not_touch_terminal_rows() {
    let pool = connect_db().await;
    let repo_id = create_test_repo(&pool).await;
    let artifact_id = create_test_artifact(&pool, repo_id).await;
    let svc = ScanResultService::new(pool.clone());

    // Insert an old completed row and an old failed row -- both must be left
    // alone even though they predate the threshold.
    let old_started = chrono::Utc::now() - chrono::Duration::hours(2);
    let completed_id = Uuid::new_v4();
    sqlx::query(
        r#"
        INSERT INTO scan_results (id, artifact_id, repository_id, scan_type,
            status, started_at, completed_at)
        VALUES ($1, $2, $3, 'dependency', 'completed', $4, $4)
        "#,
    )
    .bind(completed_id)
    .bind(artifact_id)
    .bind(repo_id)
    .bind(old_started)
    .execute(&pool)
    .await
    .expect("insert completed scan");

    let preexisting_failed_id = Uuid::new_v4();
    sqlx::query(
        r#"
        INSERT INTO scan_results (id, artifact_id, repository_id, scan_type,
            status, started_at, completed_at, error_message)
        VALUES ($1, $2, $3, 'dependency', 'failed', $4, $4, 'pre-existing failure')
        "#,
    )
    .bind(preexisting_failed_id)
    .bind(artifact_id)
    .bind(repo_id)
    .bind(old_started)
    .execute(&pool)
    .await
    .expect("insert failed scan");

    let _ = svc
        .cleanup_stuck_scans(Duration::from_secs(30 * 60))
        .await
        .expect("janitor should succeed");

    let (status, _) = fetch_status_and_error(&pool, completed_id).await;
    assert_eq!(status, "completed", "completed rows must not be reaped");

    let (status, error) = fetch_status_and_error(&pool, preexisting_failed_id).await;
    assert_eq!(status, "failed");
    assert_eq!(
        error.as_deref(),
        Some("pre-existing failure"),
        "pre-existing failed row's error_message must not be overwritten"
    );

    // Already-terminal rows must not produce SCAN_REAPED audit entries even
    // though they predate the threshold. Locks the WHERE filter semantics.
    let count: (i64,) = sqlx::query_as(
        r#"
        SELECT COUNT(*)
        FROM audit_log
        WHERE action = 'SCAN_REAPED'
          AND resource_id = ANY($1)
        "#,
    )
    .bind(&[completed_id, preexisting_failed_id][..])
    .fetch_one(&pool)
    .await
    .expect("count audit entries for terminal rows");
    assert_eq!(
        count.0, 0,
        "terminal-state rows must not produce SCAN_REAPED audit entries"
    );

    cleanup(&pool, repo_id).await;
}

#[tokio::test]
#[ignore]
async fn test_cleanup_stuck_scans_returns_count_of_reaped_rows() {
    let pool = connect_db().await;
    let repo_id = create_test_repo(&pool).await;
    let artifact_id = create_test_artifact(&pool, repo_id).await;
    let svc = ScanResultService::new(pool.clone());

    // Three stuck rows + one fresh row. Janitor should report exactly 3.
    let stuck_started = chrono::Utc::now() - chrono::Duration::minutes(45);
    let _ = insert_running_scan(&pool, artifact_id, repo_id, stuck_started).await;
    let _ = insert_running_scan(&pool, artifact_id, repo_id, stuck_started).await;
    let _ = insert_running_scan(&pool, artifact_id, repo_id, stuck_started).await;
    let fresh_started = chrono::Utc::now() - chrono::Duration::seconds(30);
    let _ = insert_running_scan(&pool, artifact_id, repo_id, fresh_started).await;

    let cleaned = svc
        .cleanup_stuck_scans(Duration::from_secs(30 * 60))
        .await
        .expect("janitor should succeed");

    assert_eq!(
        cleaned, 3u64,
        "janitor should report exactly the rows it reaped"
    );

    cleanup(&pool, repo_id).await;
}

// =============================================================================
// Audit emission (#1063): reaping a stuck scan writes one SCAN_REAPED audit_log
// entry per row, populated with scan_id / artifact_id / repository_id /
// started_at / reaped_at so operators investigating an incident can see which
// vulnerability scans never completed.
// =============================================================================

#[tokio::test]
#[ignore]
async fn test_cleanup_stuck_scans_emits_audit_event_per_reaped_row() {
    let pool = connect_db().await;
    let repo_id = create_test_repo(&pool).await;
    let artifact_id = create_test_artifact(&pool, repo_id).await;
    let svc = ScanResultService::new(pool.clone());

    let stuck_started = chrono::Utc::now() - chrono::Duration::minutes(45);
    let stuck_id = insert_running_scan(&pool, artifact_id, repo_id, stuck_started).await;
    let fresh_started = chrono::Utc::now() - chrono::Duration::seconds(30);
    let _ = insert_running_scan(&pool, artifact_id, repo_id, fresh_started).await;

    let threshold = Duration::from_secs(30 * 60);
    let cleaned = svc
        .cleanup_stuck_scans(threshold)
        .await
        .expect("janitor should succeed");
    assert_eq!(cleaned, 1u64, "exactly one stuck row should be reaped");

    // Exactly one SCAN_REAPED audit entry for this scan, with full context.
    // `user_id` is included because janitor reaps are system-initiated and the
    // entry should carry NULL there (no user actor) — locking the convention.
    let row: (
        String,
        String,
        Option<Uuid>,
        Option<Uuid>,
        Option<serde_json::Value>,
    ) = sqlx::query_as(
        r#"
        SELECT action, resource_type, resource_id, user_id, details
        FROM audit_log
        WHERE action = 'SCAN_REAPED'
          AND resource_id = $1
        "#,
    )
    .bind(stuck_id)
    .fetch_one(&pool)
    .await
    .expect("audit_log should have one SCAN_REAPED entry for the reaped scan");

    let stuck_id_str = stuck_id.to_string();
    let artifact_id_str = artifact_id.to_string();
    let repo_id_str = repo_id.to_string();

    assert_eq!(row.0, "SCAN_REAPED");
    assert_eq!(row.1, "scan_result");
    assert_eq!(row.2, Some(stuck_id));
    assert!(
        row.3.is_none(),
        "system-initiated janitor reap must set user_id = NULL (got {:?})",
        row.3
    );
    let details = row.4.expect("audit entry should carry details");
    assert_eq!(
        details.get("scan_id").and_then(|v| v.as_str()),
        Some(stuck_id_str.as_str()),
        "details.scan_id must match the reaped row id"
    );
    assert_eq!(
        details.get("artifact_id").and_then(|v| v.as_str()),
        Some(artifact_id_str.as_str())
    );
    assert_eq!(
        details.get("repository_id").and_then(|v| v.as_str()),
        Some(repo_id_str.as_str())
    );
    assert!(
        details.get("started_at").is_some(),
        "details.started_at must be populated"
    );
    assert!(
        details.get("reaped_at").is_some(),
        "details.reaped_at must be populated"
    );
    assert_eq!(
        details.get("reason").and_then(|v| v.as_str()),
        Some("stuck_running_janitor")
    );
    assert_eq!(
        details.get("threshold_secs").and_then(|v| v.as_i64()),
        Some(threshold.as_secs() as i64),
        "details.threshold_secs must reflect the configured threshold"
    );
    assert_eq!(
        details.get("actor").and_then(|v| v.as_str()),
        Some("system:stuck_scan_janitor"),
        "details.actor must identify this as a system-initiated event so SIEM/SOAR \
         rules can filter system entries from human-initiated audit traffic"
    );

    // Sweep across all rows: exactly one SCAN_REAPED event was written for this
    // repository's scans (the fresh row must NOT have produced an audit entry).
    let total: (i64,) = sqlx::query_as(
        r#"
        SELECT COUNT(*)
        FROM audit_log
        WHERE action = 'SCAN_REAPED'
          AND resource_id IN (SELECT id FROM scan_results WHERE repository_id = $1)
        "#,
    )
    .bind(repo_id)
    .fetch_one(&pool)
    .await
    .expect("count audit entries");
    assert_eq!(
        total.0, 1,
        "exactly one SCAN_REAPED audit event should exist for the repository"
    );

    // Idempotency: a second pass must reap zero rows and must not duplicate the
    // audit entry. Locks the WHERE filter against a regression that re-emits
    // audit rows for already-failed scans.
    let again = svc
        .cleanup_stuck_scans(threshold)
        .await
        .expect("idempotent second pass should succeed");
    assert_eq!(again, 0u64, "second pass should reap zero rows");
    let total_after: (i64,) = sqlx::query_as(
        r#"
        SELECT COUNT(*)
        FROM audit_log
        WHERE action = 'SCAN_REAPED'
          AND resource_id IN (SELECT id FROM scan_results WHERE repository_id = $1)
        "#,
    )
    .bind(repo_id)
    .fetch_one(&pool)
    .await
    .expect("count audit entries after second pass");
    assert_eq!(
        total_after.0, 1,
        "second pass must not duplicate audit entries"
    );

    cleanup(&pool, repo_id).await;
}

#[tokio::test]
#[ignore]
async fn test_cleanup_stuck_scans_emits_one_audit_event_per_row_batch() {
    let pool = connect_db().await;
    let repo_id = create_test_repo(&pool).await;
    let artifact_id = create_test_artifact(&pool, repo_id).await;
    let svc = ScanResultService::new(pool.clone());

    // Five stuck rows: every one should generate its own SCAN_REAPED entry.
    let stuck_started = chrono::Utc::now() - chrono::Duration::hours(2);
    for _ in 0..5 {
        let _ = insert_running_scan(&pool, artifact_id, repo_id, stuck_started).await;
    }

    let cleaned = svc
        .cleanup_stuck_scans(Duration::from_secs(30 * 60))
        .await
        .expect("janitor should succeed");
    assert_eq!(cleaned, 5u64);

    let total: (i64,) = sqlx::query_as(
        r#"
        SELECT COUNT(*)
        FROM audit_log
        WHERE action = 'SCAN_REAPED'
          AND resource_id IN (SELECT id FROM scan_results WHERE repository_id = $1)
        "#,
    )
    .bind(repo_id)
    .fetch_one(&pool)
    .await
    .expect("count audit entries");
    assert_eq!(
        total.0, 5,
        "one SCAN_REAPED audit event per reaped scan_results row"
    );

    cleanup(&pool, repo_id).await;
}

// =============================================================================
// Best-effort audit emission: the doc-comment on cleanup_stuck_scans declares
// that an audit-log INSERT failure must NOT roll back the reap, since leaving
// a row wedged in `running` is worse than missing an audit entry. Pin that
// contract with a test that forces audit INSERTs to fail and verifies the
// scan_results row is still transitioned to `failed`.
//
// Implementation: install a CHECK constraint that rejects SCAN_REAPED rows
// for the duration of the test, then drop it unconditionally afterwards so
// schema state does not leak to other tests. Requires --test-threads=1 (the
// repo convention for #[ignore] integration tests), which the module docstring
// already documents.
// =============================================================================

#[tokio::test]
#[ignore]
async fn test_cleanup_stuck_scans_reaps_row_even_when_audit_insert_fails() {
    let pool = connect_db().await;
    let repo_id = create_test_repo(&pool).await;
    let artifact_id = create_test_artifact(&pool, repo_id).await;
    let svc = ScanResultService::new(pool.clone());

    let stuck_started = chrono::Utc::now() - chrono::Duration::minutes(45);
    let stuck_id = insert_running_scan(&pool, artifact_id, repo_id, stuck_started).await;

    // Self-heal from a prior aborted run (Ctrl+C, OOM, CI timeout between
    // ADD and DROP would otherwise leave the constraint behind and break
    // every subsequent run with `constraint ... already exists`).
    let _ = sqlx::query("ALTER TABLE audit_log DROP CONSTRAINT IF EXISTS test_block_scan_reaped")
        .execute(&pool)
        .await;

    sqlx::query(
        "ALTER TABLE audit_log \
         ADD CONSTRAINT test_block_scan_reaped \
         CHECK (action <> 'SCAN_REAPED') NOT VALID",
    )
    .execute(&pool)
    .await
    .expect("install CHECK constraint");

    let result = svc.cleanup_stuck_scans(Duration::from_secs(30 * 60)).await;

    // Always drop the constraint, even if the assertion below fails, so the
    // schema does not leak to subsequent tests in the same DB.
    let _ = sqlx::query("ALTER TABLE audit_log DROP CONSTRAINT test_block_scan_reaped")
        .execute(&pool)
        .await;

    let cleaned = result.expect("reap must succeed even when audit INSERT is rejected");
    assert_eq!(cleaned, 1, "the stuck row must still be reaped");

    let (status, error) = fetch_status_and_error(&pool, stuck_id).await;
    assert_eq!(
        status, "failed",
        "scan_results row must be transitioned to failed despite audit failure"
    );
    assert!(
        error
            .as_deref()
            .map(|s| s.contains("janitor"))
            .unwrap_or(false),
        "diagnostic error_message must be set on the reaped row (got {:?})",
        error
    );

    // No audit entry exists for this scan — the CHECK rejected the INSERT,
    // and the janitor swallowed the error at warn level instead of rolling back.
    let count: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM audit_log WHERE action = 'SCAN_REAPED' AND resource_id = $1",
    )
    .bind(stuck_id)
    .fetch_one(&pool)
    .await
    .expect("count audit entries");
    assert_eq!(
        count.0, 0,
        "no audit entry expected when the INSERT was rejected by the CHECK constraint"
    );

    cleanup(&pool, repo_id).await;
}
