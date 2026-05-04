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
//!     cargo test --test stuck_scan_janitor_tests -- --ignored
//! ```
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
