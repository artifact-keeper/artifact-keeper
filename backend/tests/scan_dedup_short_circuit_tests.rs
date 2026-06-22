//! Integration tests for the same-artifact dedup short-circuit added by #1373.
//!
//! These tests require a PostgreSQL database with migrations applied.
//! Set DATABASE_URL and run:
//!
//! ```sh
//! DATABASE_URL="postgresql://registry:registry@localhost:30432/artifact_registry" \
//!   cargo test --test scan_dedup_short_circuit_tests -- --ignored
//! ```
//!
//! Why these tests exist
//! ----------------------
//! Release-gate run 26344757642 (security suite, scan-dedup-checksum) failed
//! on two assertions:
//!
//!   1. Second scan on identical bytes returns same scan_id (no duplicate row)
//!   2. Per-artifact scan list for B contains exactly one completed scan
//!
//! Both failures trace back to `prepare_artifact_scan` inserting a new
//! `running` placeholder row on every call, without first checking whether
//! the artifact already had a completed scan for the same checksum +
//! scan_type. The placeholder then fell through `scan_artifact_inner`'s
//! `should_skip_reuse_for_same_artifact` branch, which (pre-fix) skipped the
//! reuse-copy path AND ran a fresh scan, leaving two completed rows behind.
//!
//! The fix adds `find_existing_scan_for_artifact` (scan_result_service.rs),
//! short-circuits `prepare_artifact_scan` when an existing scan is found, and
//! teaches `scan_artifact_inner` to no-op when the matched reusable scan is
//! for the current artifact.
//!
//! Test coverage
//! -------------
//! * `find_existing_scan_for_artifact` returns Some for a matching artifact +
//!   checksum + scan_type within the TTL window.
//! * Returns None when scan_type does not match.
//! * Returns None when checksum does not match (different bytes).
//! * Returns None when the scan is for a different artifact (the cross-
//!   artifact dedup case is `find_reusable_scan`'s job, not this method's).
//! * Returns None when the scan is older than the TTL.
//! * Returns None when only a `running` row exists (status must be completed).

use sqlx::PgPool;
use uuid::Uuid;

use artifact_keeper_backend::services::scan_result_service::ScanResultService;

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

async fn create_test_repo(pool: &PgPool) -> Uuid {
    let id = Uuid::new_v4();
    let key = format!("test-dedup-short-circuit-{}", id);
    let storage_path = format!("/tmp/test-artifacts/{}", id);
    sqlx::query(
        "INSERT INTO repositories (id, key, name, storage_path, repo_type, format) \
         VALUES ($1, $2, $3, $4, 'local', 'generic')",
    )
    .bind(id)
    .bind(&key)
    .bind(format!("dedup-short-circuit-{}", id))
    .bind(&storage_path)
    .execute(pool)
    .await
    .expect("failed to create test repository");
    id
}

async fn insert_artifact(pool: &PgPool, repo_id: Uuid, name: &str, checksum: &str) -> Uuid {
    let id = Uuid::new_v4();
    let path = format!("{}/{}", repo_id, name);
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
    .bind(checksum)
    .execute(pool)
    .await
    .expect("failed to insert test artifact");
    id
}

/// Insert a completed scan_result row with the given checksum + scan_type +
/// status. `completed_at_offset_days` shifts the completed_at backwards by
/// that many days so the TTL-boundary case can be exercised.
async fn insert_scan(
    pool: &PgPool,
    artifact_id: Uuid,
    repo_id: Uuid,
    checksum: &str,
    scan_type: &str,
    status: &str,
    completed_at_offset_days: i32,
) -> Uuid {
    let scan_id = Uuid::new_v4();
    let completed_at = if status == "completed" {
        format!("NOW() - INTERVAL '{} days'", completed_at_offset_days)
    } else {
        "NULL".to_string()
    };
    let query = format!(
        r#"
        INSERT INTO scan_results (
            id, artifact_id, repository_id, scan_type, status,
            findings_count, critical_count, high_count, medium_count, low_count, info_count,
            scanner_version, started_at, completed_at, checksum_sha256
        )
        VALUES ($1, $2, $3, $4, $5, 0, 0, 0, 0, 0, 0,
                'trivy-0.50.0', NOW(), {}, $6)
        "#,
        completed_at,
    );
    sqlx::query(&query)
        .bind(scan_id)
        .bind(artifact_id)
        .bind(repo_id)
        .bind(scan_type)
        .bind(status)
        .bind(checksum)
        .execute(pool)
        .await
        .expect("failed to insert scan_result fixture");
    scan_id
}

async fn cleanup(pool: &PgPool, repo_id: Uuid) {
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

const CHECKSUM_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const CHECKSUM_B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

// ---------------------------------------------------------------------------
// Happy path: existing scan is returned
// ---------------------------------------------------------------------------

#[tokio::test]
#[ignore] // Requires database
async fn test_find_existing_returns_some_for_matching_artifact_and_checksum() {
    let pool = PgPool::connect(&std::env::var("DATABASE_URL").expect("DATABASE_URL"))
        .await
        .expect("failed to connect to database");

    let repo_id = create_test_repo(&pool).await;
    let artifact_id = insert_artifact(&pool, repo_id, "thing.tgz", CHECKSUM_A).await;
    let scan_id = insert_scan(
        &pool,
        artifact_id,
        repo_id,
        CHECKSUM_A,
        "dependency",
        "completed",
        0,
    )
    .await;

    let svc = ScanResultService::new(pool.clone());
    let found = svc
        .find_existing_scan_for_artifact(artifact_id, CHECKSUM_A, "dependency", 30, 30)
        .await
        .expect("query must not error");

    let row = found.expect("must find the completed scan for this artifact");
    assert_eq!(
        row.id, scan_id,
        "must return the existing scan's id verbatim"
    );
    assert_eq!(row.artifact_id, artifact_id);
    assert_eq!(row.status, "completed");

    cleanup(&pool, repo_id).await;
}

// ---------------------------------------------------------------------------
// Negative: different artifact => None
// ---------------------------------------------------------------------------

#[tokio::test]
#[ignore] // Requires database
async fn test_find_existing_returns_none_for_different_artifact_same_checksum() {
    // Two artifacts sharing one checksum (byte-identical uploads).
    // `find_existing_scan_for_artifact` scopes by artifact_id, so artifact A's
    // completed scan must NOT be returned when querying for artifact B. That
    // cross-artifact dedup is `find_reusable_scan`'s job.
    let pool = PgPool::connect(&std::env::var("DATABASE_URL").expect("DATABASE_URL"))
        .await
        .expect("failed to connect to database");

    let repo_id = create_test_repo(&pool).await;
    let artifact_a = insert_artifact(&pool, repo_id, "a.tgz", CHECKSUM_A).await;
    let artifact_b = insert_artifact(&pool, repo_id, "b.tgz", CHECKSUM_A).await;
    let _scan_a = insert_scan(
        &pool,
        artifact_a,
        repo_id,
        CHECKSUM_A,
        "dependency",
        "completed",
        0,
    )
    .await;

    let svc = ScanResultService::new(pool.clone());
    let found = svc
        .find_existing_scan_for_artifact(artifact_b, CHECKSUM_A, "dependency", 30, 30)
        .await
        .expect("query must not error");
    assert!(
        found.is_none(),
        "must NOT match artifact A's scan when querying for artifact B"
    );

    cleanup(&pool, repo_id).await;
}

// ---------------------------------------------------------------------------
// Negative: different checksum => None
// ---------------------------------------------------------------------------

#[tokio::test]
#[ignore] // Requires database
async fn test_find_existing_returns_none_when_checksum_differs() {
    let pool = PgPool::connect(&std::env::var("DATABASE_URL").expect("DATABASE_URL"))
        .await
        .expect("failed to connect to database");

    let repo_id = create_test_repo(&pool).await;
    let artifact_id = insert_artifact(&pool, repo_id, "thing.tgz", CHECKSUM_A).await;
    let _scan_id = insert_scan(
        &pool,
        artifact_id,
        repo_id,
        CHECKSUM_A,
        "dependency",
        "completed",
        0,
    )
    .await;

    let svc = ScanResultService::new(pool.clone());
    let found = svc
        .find_existing_scan_for_artifact(artifact_id, CHECKSUM_B, "dependency", 30, 30)
        .await
        .expect("query must not error");
    assert!(
        found.is_none(),
        "must NOT match when the requested checksum differs from the stored one"
    );

    cleanup(&pool, repo_id).await;
}

// ---------------------------------------------------------------------------
// Negative: different scan_type => None
// ---------------------------------------------------------------------------

#[tokio::test]
#[ignore] // Requires database
async fn test_find_existing_returns_none_when_scan_type_differs() {
    let pool = PgPool::connect(&std::env::var("DATABASE_URL").expect("DATABASE_URL"))
        .await
        .expect("failed to connect to database");

    let repo_id = create_test_repo(&pool).await;
    let artifact_id = insert_artifact(&pool, repo_id, "thing.tgz", CHECKSUM_A).await;
    let _scan_id = insert_scan(
        &pool,
        artifact_id,
        repo_id,
        CHECKSUM_A,
        "dependency",
        "completed",
        0,
    )
    .await;

    let svc = ScanResultService::new(pool.clone());
    let found = svc
        .find_existing_scan_for_artifact(artifact_id, CHECKSUM_A, "image", 30, 30)
        .await
        .expect("query must not error");
    assert!(
        found.is_none(),
        "must NOT match when scan_type differs (dependency scan != image scan)"
    );

    cleanup(&pool, repo_id).await;
}

// ---------------------------------------------------------------------------
// Negative: still running, never completed => None
// ---------------------------------------------------------------------------

#[tokio::test]
#[ignore] // Requires database
async fn test_find_existing_returns_none_for_running_scan() {
    // A `running` row must not satisfy the "already scanned" check. Otherwise
    // a stuck or in-flight scan would short-circuit a retry, and the artifact
    // would never get a real completed scan.
    let pool = PgPool::connect(&std::env::var("DATABASE_URL").expect("DATABASE_URL"))
        .await
        .expect("failed to connect to database");

    let repo_id = create_test_repo(&pool).await;
    let artifact_id = insert_artifact(&pool, repo_id, "thing.tgz", CHECKSUM_A).await;
    let _scan_id = insert_scan(
        &pool,
        artifact_id,
        repo_id,
        CHECKSUM_A,
        "dependency",
        "running",
        0,
    )
    .await;

    let svc = ScanResultService::new(pool.clone());
    let found = svc
        .find_existing_scan_for_artifact(artifact_id, CHECKSUM_A, "dependency", 30, 30)
        .await
        .expect("query must not error");
    assert!(
        found.is_none(),
        "must NOT short-circuit on a `running` row; only completed scans count"
    );

    cleanup(&pool, repo_id).await;
}

// ---------------------------------------------------------------------------
// Negative: scan is older than the TTL window => None
// ---------------------------------------------------------------------------

#[tokio::test]
#[ignore] // Requires database
async fn test_find_existing_returns_none_when_scan_is_older_than_ttl() {
    let pool = PgPool::connect(&std::env::var("DATABASE_URL").expect("DATABASE_URL"))
        .await
        .expect("failed to connect to database");

    let repo_id = create_test_repo(&pool).await;
    let artifact_id = insert_artifact(&pool, repo_id, "thing.tgz", CHECKSUM_A).await;
    // Completed 40 days ago; with ttl_days = 30 the row must be excluded so
    // stale artifacts get rescanned to pick up freshly-published advisories.
    let _scan_id = insert_scan(
        &pool,
        artifact_id,
        repo_id,
        CHECKSUM_A,
        "dependency",
        "completed",
        40,
    )
    .await;

    let svc = ScanResultService::new(pool.clone());
    let found = svc
        .find_existing_scan_for_artifact(artifact_id, CHECKSUM_A, "dependency", 30, 30)
        .await
        .expect("query must not error");
    assert!(
        found.is_none(),
        "must NOT short-circuit when the existing scan is older than the TTL window"
    );

    cleanup(&pool, repo_id).await;
}

// ---------------------------------------------------------------------------
// Most-recent wins: latest completed scan is returned when there are several.
// ---------------------------------------------------------------------------

#[tokio::test]
#[ignore] // Requires database
async fn test_find_existing_returns_most_recent_when_multiple_completed_exist() {
    let pool = PgPool::connect(&std::env::var("DATABASE_URL").expect("DATABASE_URL"))
        .await
        .expect("failed to connect to database");

    let repo_id = create_test_repo(&pool).await;
    let artifact_id = insert_artifact(&pool, repo_id, "thing.tgz", CHECKSUM_A).await;

    // Two completed scans for the same artifact + checksum + scan_type:
    // older completed first, then a newer one. The newer scan_id must win.
    let _old_scan = insert_scan(
        &pool,
        artifact_id,
        repo_id,
        CHECKSUM_A,
        "dependency",
        "completed",
        5,
    )
    .await;
    let new_scan = insert_scan(
        &pool,
        artifact_id,
        repo_id,
        CHECKSUM_A,
        "dependency",
        "completed",
        0,
    )
    .await;

    let svc = ScanResultService::new(pool.clone());
    let found = svc
        .find_existing_scan_for_artifact(artifact_id, CHECKSUM_A, "dependency", 30, 30)
        .await
        .expect("query must not error")
        .expect("must find a completed scan");

    assert_eq!(
        found.id, new_scan,
        "must return the most-recent completed scan (ORDER BY completed_at DESC)"
    );

    cleanup(&pool, repo_id).await;
}

// ---------------------------------------------------------------------------
// #1935: concurrent prepare must not create duplicate placeholders
// ---------------------------------------------------------------------------
//
// Regression for the check-then-act race in the #1373 short-circuit. The old
// `prepare_artifact_scan` did a bare SELECT followed by a separate INSERT with
// no lock/constraint/transaction, so N concurrent triggers on one fresh
// artifact each saw "no completed row" and each inserted its own `running`
// placeholder (issue reproducer: 10 concurrent triggers -> 10 completed rows
// for one scan_type). `prepare_scan_placeholder` serializes the decide-then-
// insert under a per-(artifact_id, scan_type) advisory lock, so the loser of
// the race reuses the winner's in-flight row.
//
// DB-backed: runtime-skips (does NOT fail) when DATABASE_URL is absent.

#[tokio::test]
async fn test_concurrent_prepare_creates_single_placeholder() {
    let Ok(database_url) = std::env::var("DATABASE_URL") else {
        eprintln!("DATABASE_URL not set; skipping DB-backed concurrency test");
        return;
    };
    let pool = PgPool::connect(&database_url)
        .await
        .expect("failed to connect to database");

    let repo_id = create_test_repo(&pool).await;
    let artifact_id = insert_artifact(&pool, repo_id, "concurrent.tgz", CHECKSUM_A).await;

    // Fire many concurrent preparers for the same artifact + scan_type, as a
    // burst of concurrent scan triggers would. Each task gets its own service
    // over a clone of the shared pool, mirroring independent request handlers.
    let mut handles = Vec::new();
    for _ in 0..10 {
        let svc = ScanResultService::new(pool.clone());
        handles.push(tokio::spawn(async move {
            svc.prepare_scan_placeholder(artifact_id, repo_id, CHECKSUM_A, "dependency", 30, 30)
                .await
        }));
    }

    let mut ids = Vec::new();
    let mut inserted_count = 0;
    for h in handles {
        let (id, inserted) = h
            .await
            .expect("task panicked")
            .expect("prepare must not error");
        ids.push(id);
        if inserted {
            inserted_count += 1;
        }
    }

    // Exactly one caller actually inserted a placeholder; all others reused it.
    assert_eq!(
        inserted_count, 1,
        "exactly one concurrent prepare must insert a placeholder; the rest reuse it"
    );

    // Every caller surfaced the same scan id.
    let first = ids[0];
    assert!(
        ids.iter().all(|id| *id == first),
        "all concurrent preparers must return the same scan id, got: {ids:?}"
    );

    // And the database holds exactly one row for this artifact + scan_type.
    let row_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM scan_results WHERE artifact_id = $1 AND scan_type = 'dependency'",
    )
    .bind(artifact_id)
    .fetch_one(&pool)
    .await
    .expect("count query must not error");
    assert_eq!(
        row_count, 1,
        "concurrent prepare must leave exactly one scan_results row, found {row_count}"
    );

    cleanup(&pool, repo_id).await;
}
