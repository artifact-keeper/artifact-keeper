//! Integration tests for scan finding aggregation (#962).
//!
//! Reproduces the dashboard / per-repo score inflation bug where rescanning
//! the same artifact N times made `get_dashboard_summary` and
//! `recalculate_score` count findings N times instead of once. The fix
//! restricts aggregation to the LATEST completed scan per
//! (artifact_id, scan_type) via a DISTINCT ON CTE.
//!
//! Requires PostgreSQL with all migrations applied (75 as of v1.1.x):
//!
//! ```sh
//! TEST_PG_PW="$(openssl rand -hex 16)"
//! podman run -d --rm --name ak-test-pg -p 5432:5432 \
//!     -e POSTGRES_PASSWORD="${TEST_PG_PW}" -e POSTGRES_DB=artifact_registry postgres:16
//! # apply backend/migrations/*.sql in lexicographic order
//! DATABASE_URL="postgres://postgres:${TEST_PG_PW}@localhost:5432/artifact_registry" \
//!     cargo test --test scan_dashboard_aggregation_tests -- --ignored
//! ```

use sqlx::PgPool;
use uuid::Uuid;

use artifact_keeper_backend::models::security::{RawFinding, Severity};
use artifact_keeper_backend::services::scan_result_service::ScanResultService;

async fn connect_db() -> PgPool {
    let url = std::env::var("DATABASE_URL")
        .expect("DATABASE_URL must be set; see module docstring for setup");
    PgPool::connect(&url)
        .await
        .expect("failed to connect to test database")
}

/// Insert a test repository and return its id. Uses a unique key so parallel
/// runs and earlier-test residue do not collide.
async fn create_test_repo(pool: &PgPool) -> Uuid {
    let id = Uuid::new_v4();
    let key = format!("scan-agg-{}", id.as_simple());
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

/// Insert a single artifact in the given repo and return its id.
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

/// Create N completed scans for the same (artifact, scan_type), each with the
/// same set of `findings_per_scan` findings. Returns ids of the scan_results
/// rows in insertion order. completed_at is staggered so DISTINCT ON has a
/// deterministic "latest".
async fn create_scans_with_findings(
    svc: &ScanResultService,
    pool: &PgPool,
    artifact_id: Uuid,
    repo_id: Uuid,
    scan_type: &str,
    n_scans: usize,
    findings_per_scan: usize,
) -> Vec<Uuid> {
    let mut scan_ids = Vec::with_capacity(n_scans);
    for i in 0..n_scans {
        // Use the service's own create + complete path so the test mirrors
        // production behaviour (status='completed', completed_at populated).
        let scan = svc
            .create_scan_result(artifact_id, repo_id, scan_type)
            .await
            .expect("create scan");

        // Build a deterministic finding set; varied severities so the
        // dashboard's critical/high buckets are also exercised.
        let findings: Vec<RawFinding> = (0..findings_per_scan)
            .map(|j| {
                let severity = match j % 4 {
                    0 => Severity::Critical,
                    1 => Severity::High,
                    2 => Severity::Medium,
                    _ => Severity::Low,
                };
                RawFinding {
                    severity,
                    title: format!("CVE-test-{}-{}", i, j),
                    description: None,
                    cve_id: Some(format!("CVE-2024-{:04}", j)),
                    affected_component: Some("libtest".to_string()),
                    affected_version: Some("1.0.0".to_string()),
                    fixed_version: Some("1.0.1".to_string()),
                    source: Some("test".to_string()),
                    source_url: None,
                }
            })
            .collect();

        svc.create_findings(scan.id, artifact_id, &findings)
            .await
            .expect("insert findings");

        // Severity tallies for complete_scan.
        let mut crit = 0;
        let mut high = 0;
        let mut med = 0;
        let mut low = 0;
        for f in &findings {
            match f.severity {
                Severity::Critical => crit += 1,
                Severity::High => high += 1,
                Severity::Medium => med += 1,
                Severity::Low => low += 1,
                Severity::Info => {}
            }
        }
        svc.complete_scan(scan.id, findings_per_scan as i32, crit, high, med, low, 0)
            .await
            .expect("complete scan");

        // Stagger completed_at so DISTINCT ON ordering is deterministic.
        // The most recently inserted scan is the "latest of record".
        sqlx::query("UPDATE scan_results SET completed_at = NOW() + ($2 || ' seconds')::interval WHERE id = $1")
            .bind(scan.id)
            .bind(i.to_string())
            .execute(pool)
            .await
            .expect("stagger completed_at");

        scan_ids.push(scan.id);
    }
    scan_ids
}

async fn cleanup(pool: &PgPool, repo_id: Uuid) {
    // scan_findings cascades from scan_results, scan_results from artifacts,
    // artifacts from repositories. Only need to delete the repo + its score.
    let _ = sqlx::query("DELETE FROM repo_security_scores WHERE repository_id = $1")
        .bind(repo_id)
        .execute(pool)
        .await;
    let _ = sqlx::query("DELETE FROM repositories WHERE id = $1")
        .bind(repo_id)
        .execute(pool)
        .await;
}

/// Reproduces #962: 1 artifact rescanned 10 times with 15 findings each
/// must NOT report 150 findings on the dashboard / repo score.
///
/// Exercises both code paths the fix touched:
///   - `recalculate_score(repository_id)` (per-repo, joins through artifacts)
///   - `get_dashboard_summary()` (global)
#[tokio::test]
async fn rescan_does_not_inflate_finding_counts() {
    const SCANS: usize = 10;
    const FINDINGS_PER_SCAN: usize = 15;
    const EXPECTED: i32 = FINDINGS_PER_SCAN as i32; // 15, not 150.

    let pool = connect_db().await;
    let svc = ScanResultService::new(pool.clone());

    // Take a baseline of the dashboard's global counters BEFORE we insert
    // anything, so the assertion is robust to other data already present in
    // a shared test database.
    let baseline = svc
        .get_dashboard_summary()
        .await
        .expect("baseline dashboard summary");

    let repo_id = create_test_repo(&pool).await;
    let artifact_id = create_test_artifact(&pool, repo_id).await;

    let scan_ids = create_scans_with_findings(
        &svc,
        &pool,
        artifact_id,
        repo_id,
        "dependency",
        SCANS,
        FINDINGS_PER_SCAN,
    )
    .await;
    assert_eq!(scan_ids.len(), SCANS, "should have created 10 scans");

    // Sanity check that the bug's preconditions are real: the raw
    // scan_findings table actually contains SCANS * FINDINGS_PER_SCAN rows
    // (150) for this artifact. Without that, asserting 15 below would
    // tautologically pass on broken code.
    let raw_count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM scan_findings WHERE artifact_id = $1")
            .bind(artifact_id)
            .fetch_one(&pool)
            .await
            .expect("count raw findings");
    assert_eq!(
        raw_count,
        (SCANS * FINDINGS_PER_SCAN) as i64,
        "test setup: every scan should own its own 15-row finding set"
    );

    // -------- Per-repo path: recalculate_score ----------------------------
    // This path filters by repository_id, so the assertion is exact and not
    // affected by other rows in the test DB.
    let score = svc
        .recalculate_score(repo_id)
        .await
        .expect("recalculate score");

    assert_eq!(
        score.total_findings, EXPECTED,
        "recalculate_score: expected {} findings (latest scan only), got {} \
         (10x inflation = bug #962)",
        EXPECTED, score.total_findings
    );

    // Severity buckets: 15 findings split as critical/high/medium/low across
    // j % 4 → 4/4/4/3.
    assert_eq!(
        score.critical_count + score.high_count + score.medium_count + score.low_count,
        EXPECTED,
        "severity buckets must sum to total (no double-counting)"
    );
    assert_eq!(score.critical_count, 4, "j%4==0 → 4 critical");
    assert_eq!(score.high_count, 4, "j%4==1 → 4 high");
    assert_eq!(score.medium_count, 4, "j%4==2 → 4 medium");
    assert_eq!(score.low_count, 3, "j%4==3 → 3 low");

    // -------- Global path: get_dashboard_summary --------------------------
    // Compare deltas against the baseline so other data in the shared test
    // DB does not pollute the assertion.
    let after = svc
        .get_dashboard_summary()
        .await
        .expect("dashboard summary");

    let delta_total = after.total_findings - baseline.total_findings;
    let delta_critical = after.critical_findings - baseline.critical_findings;
    let delta_high = after.high_findings - baseline.high_findings;

    assert_eq!(
        delta_total, EXPECTED as i64,
        "get_dashboard_summary: total_findings grew by {} (expected {}). \
         150 = bug #962 (one finding-set per rescan, multiplied by 10)",
        delta_total, EXPECTED
    );
    assert_eq!(
        delta_critical, 4,
        "dashboard critical_findings delta should be 4 (latest scan only)"
    );
    assert_eq!(
        delta_high, 4,
        "dashboard high_findings delta should be 4 (latest scan only)"
    );

    cleanup(&pool, repo_id).await;
}
