//! Integration tests for #1469: the scanner dedup TTL must not silently mask
//! a re-scan when the cached completed row has `findings_count = 0`.
//!
//! Database required. Run with:
//!
//! ```sh
//! DATABASE_URL="postgresql://registry:registry@localhost:30432/artifact_registry" \
//!   cargo test --test scan_dedup_zero_findings_ttl_tests -- --ignored
//! ```
//!
//! Why this suite exists
//! ---------------------
//! `find_reusable_scan` (cross-artifact dedup) and `find_existing_scan_for_artifact`
//! (same-artifact short-circuit, #1373) both used a uniform 30-day TTL on any
//! `completed` row. That uniform window has a hole: a scan that finished
//! successfully but produced zero findings is indistinguishable, at the
//! `scan_results` table level, from
//!
//!   1. a real "the artifact is clean" outcome, and
//!   2. a silent extraction failure (the staging tree was empty, so the
//!      scanner walked nothing and emitted no findings (see #1427 / #1428
//!      for a real instance)).
//!
//! Case (2) gets cached for 30 days and silently masks every rescan in that
//! window, so the operator-visible "rescan after fixing the extraction bug"
//! returns the cached false-clean result. The fix in this issue is to apply
//! a much shorter TTL to `findings_count = 0` rows (one day, per
//! `ZERO_FINDINGS_DEDUP_TTL_DAYS`) and to give the trigger handler an
//! explicit `bypass_dedup` knob for the impatient "rescan now" path.
//!
//! Coverage
//! --------
//! * Zero-findings row inside the standard 30-day window but outside the
//!   short window is NOT reused (the bug).
//! * Zero-findings row inside the short window IS reused (clean artifacts
//!   still dedup within the short window, so we don't burn scan time on
//!   genuinely-clean noisy uploads).
//! * Non-zero-findings row inside the 30-day window IS reused (the standard
//!   path is unchanged for rows that carry actual scanner output).
//! * Same coverage repeated for `find_existing_scan_for_artifact`, since
//!   `prepare_artifact_scan` reads through that method.

use sqlx::PgPool;
use uuid::Uuid;

use artifact_keeper_backend::services::scan_result_service::ScanResultService;

const STANDARD_TTL: i32 = 30;
const ZERO_TTL: i32 = 1;

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

async fn create_test_repo(pool: &PgPool) -> Uuid {
    let id = Uuid::new_v4();
    let key = format!("test-zero-findings-{}", id);
    let storage_path = format!("/tmp/test-artifacts/{}", id);
    sqlx::query(
        "INSERT INTO repositories (id, key, name, storage_path, repo_type, format) \
         VALUES ($1, $2, $3, $4, 'local', 'generic')",
    )
    .bind(id)
    .bind(&key)
    .bind(format!("zero-findings-{}", id))
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

/// Insert a completed `scan_results` row whose `completed_at` is `offset_days`
/// in the past and whose findings_count is set explicitly (so the test can
/// distinguish zero-finding rows from rows that carry real scanner output).
async fn insert_completed_scan(
    pool: &PgPool,
    artifact_id: Uuid,
    repo_id: Uuid,
    checksum: &str,
    scan_type: &str,
    findings_count: i32,
    offset_days: i32,
) -> Uuid {
    let scan_id = Uuid::new_v4();
    // Inline the offset into the SQL because `($n || ' days')::interval` is
    // the same trick the production query uses; it avoids a separate
    // bind-type dance for INTERVAL.
    let query = format!(
        r#"
        INSERT INTO scan_results (
            id, artifact_id, repository_id, scan_type, status,
            findings_count, critical_count, high_count, medium_count, low_count, info_count,
            scanner_version, started_at, completed_at, checksum_sha256
        )
        VALUES ($1, $2, $3, $4, 'completed',
                $5, 0, 0, 0, 0, 0,
                'trivy-0.50.0', NOW(), NOW() - INTERVAL '{} days', $6)
        "#,
        offset_days,
    );
    sqlx::query(&query)
        .bind(scan_id)
        .bind(artifact_id)
        .bind(repo_id)
        .bind(scan_type)
        .bind(findings_count)
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

/// Produce a unique 64-hex checksum per test. `find_reusable_scan` is not
/// scoped by repository, so two parallel tests sharing a literal checksum
/// will race against each other's fixtures. Building the checksum from a
/// fresh UUID per test gives every test an isolated key space.
fn unique_checksum() -> String {
    let id = Uuid::new_v4().simple().to_string();
    // 32 hex chars from the UUID, padded with `0` to reach 64.
    format!("{:0<64}", id)
}

// ---------------------------------------------------------------------------
// The bug: a zero-finding row 5 days old must NOT mask a rescan even though
// the standard 30-day window would still cover it.
// ---------------------------------------------------------------------------

#[tokio::test]
#[ignore] // Requires database
async fn test_find_reusable_skips_zero_finding_row_older_than_short_ttl() {
    // Reproduces #1469: a prior "completed" scan with findings_count = 0 from
    // 5 days ago would be returned as reusable under the old uniform 30-day
    // window, causing the rescan to silently inherit the (potentially false)
    // empty-findings result. With the short TTL = 1 day, the row falls
    // outside the window for zero-finding rows and the rescan proceeds.
    let pool = PgPool::connect(&std::env::var("DATABASE_URL").expect("DATABASE_URL"))
        .await
        .expect("failed to connect to database");

    let checksum = unique_checksum();
    let repo_id = create_test_repo(&pool).await;
    let artifact_id = insert_artifact(&pool, repo_id, "thing.tgz", &checksum).await;
    let _stale_zero =
        insert_completed_scan(&pool, artifact_id, repo_id, &checksum, "dependency", 0, 5).await;

    let svc = ScanResultService::new(pool.clone());

    let found_reusable = svc
        .find_reusable_scan(&checksum, "dependency", STANDARD_TTL, ZERO_TTL)
        .await
        .expect("query must not error");
    assert!(
        found_reusable.is_none(),
        "#1469 regression: a zero-finding completed row 5 days old must NOT be returned \
         as reusable when zero_findings_ttl_days = 1, even though the standard 30-day \
         window would still include it"
    );

    let found_same_artifact = svc
        .find_existing_scan_for_artifact(
            artifact_id,
            &checksum,
            "dependency",
            STANDARD_TTL,
            ZERO_TTL,
        )
        .await
        .expect("query must not error");
    assert!(
        found_same_artifact.is_none(),
        "#1469 regression: same-artifact short-circuit must also skip a stale \
         zero-finding row so a fresh trigger does not get short-circuited into \
         returning the cached scan_id"
    );

    cleanup(&pool, repo_id).await;
}

// ---------------------------------------------------------------------------
// Inside the short window: a zero-finding row IS still reused so we don't
// burn scan time re-running on every concurrent trigger of an upload that is
// genuinely clean.
// ---------------------------------------------------------------------------

#[tokio::test]
#[ignore] // Requires database
async fn test_find_reusable_keeps_zero_finding_row_inside_short_ttl() {
    let pool = PgPool::connect(&std::env::var("DATABASE_URL").expect("DATABASE_URL"))
        .await
        .expect("failed to connect to database");

    let checksum = unique_checksum();
    let repo_id = create_test_repo(&pool).await;
    let artifact_id = insert_artifact(&pool, repo_id, "thing.tgz", &checksum).await;
    let scan_id = insert_completed_scan(
        &pool,
        artifact_id,
        repo_id,
        &checksum,
        "dependency",
        0,
        0, // completed just now: well inside the 1-day zero-finding window
    )
    .await;

    let svc = ScanResultService::new(pool.clone());
    let found = svc
        .find_reusable_scan(&checksum, "dependency", STANDARD_TTL, ZERO_TTL)
        .await
        .expect("query must not error")
        .expect(
            "a zero-finding completed row inside the short window must still be reused \
             so concurrent triggers don't each spawn a fresh redundant scan",
        );
    assert_eq!(
        found.id, scan_id,
        "must return the just-completed zero-finding scan id verbatim"
    );

    cleanup(&pool, repo_id).await;
}

// ---------------------------------------------------------------------------
// Non-zero findings: the standard 30-day window still applies. A scan that
// produced real findings is unambiguous and the short window does not touch it.
// ---------------------------------------------------------------------------

#[tokio::test]
#[ignore] // Requires database
async fn test_find_reusable_keeps_non_zero_finding_row_inside_standard_ttl() {
    // A row with findings_count > 0 is unambiguous (the scanner did emit
    // output for these bytes), so the standard 30-day TTL applies and a
    // 5-day-old row must still be returned as reusable.
    let pool = PgPool::connect(&std::env::var("DATABASE_URL").expect("DATABASE_URL"))
        .await
        .expect("failed to connect to database");

    let checksum = unique_checksum();
    let repo_id = create_test_repo(&pool).await;
    let artifact_id = insert_artifact(&pool, repo_id, "thing.tgz", &checksum).await;
    let scan_id = insert_completed_scan(
        &pool,
        artifact_id,
        repo_id,
        &checksum,
        "dependency",
        3, // three findings: well inside "unambiguous" territory
        5,
    )
    .await;

    let svc = ScanResultService::new(pool.clone());
    let found = svc
        .find_reusable_scan(&checksum, "dependency", STANDARD_TTL, ZERO_TTL)
        .await
        .expect("query must not error")
        .expect(
            "a non-zero-finding completed row 5 days old must still be reused under \
             the standard 30-day TTL: the short window is a zero-findings-only policy",
        );
    assert_eq!(
        found.id, scan_id,
        "must return the existing non-zero-finding scan id verbatim"
    );

    let same_artifact = svc
        .find_existing_scan_for_artifact(
            artifact_id,
            &checksum,
            "dependency",
            STANDARD_TTL,
            ZERO_TTL,
        )
        .await
        .expect("query must not error")
        .expect("same-artifact short-circuit must also reuse the non-zero-finding row");
    assert_eq!(same_artifact.id, scan_id);

    cleanup(&pool, repo_id).await;
}

// ---------------------------------------------------------------------------
// Both rows present: non-zero-finding wins despite being older, because the
// stale zero-finding row falls outside the short window.
//
// This pins the operationally-important case: an artifact was scanned, real
// findings landed, then a later (broken) rescan recorded a zero-finding row.
// After the short window expires, queries must return the older real-finding
// row instead of the newer-but-stale zero-finding row, otherwise the
// vulnerability data effectively disappears.
// ---------------------------------------------------------------------------

#[tokio::test]
#[ignore] // Requires database
async fn test_find_reusable_prefers_real_finding_when_newer_zero_is_stale() {
    let pool = PgPool::connect(&std::env::var("DATABASE_URL").expect("DATABASE_URL"))
        .await
        .expect("failed to connect to database");

    let checksum = unique_checksum();
    let repo_id = create_test_repo(&pool).await;
    let artifact_id = insert_artifact(&pool, repo_id, "thing.tgz", &checksum).await;

    // Older row with real findings, still inside 30-day window.
    let real_scan =
        insert_completed_scan(&pool, artifact_id, repo_id, &checksum, "dependency", 5, 10).await;
    // Newer row with zero findings, outside the 1-day short window.
    let _stale_zero =
        insert_completed_scan(&pool, artifact_id, repo_id, &checksum, "dependency", 0, 3).await;

    let svc = ScanResultService::new(pool.clone());
    let found = svc
        .find_reusable_scan(&checksum, "dependency", STANDARD_TTL, ZERO_TTL)
        .await
        .expect("query must not error")
        .expect("must still surface the older real-finding scan, not return None");
    assert_eq!(
        found.id, real_scan,
        "must skip the newer stale zero-finding row and fall back to the older real-finding \
         scan inside the standard window; otherwise vulnerability data disappears from the \
         dedup path until the next fresh scan completes"
    );

    cleanup(&pool, repo_id).await;
}
