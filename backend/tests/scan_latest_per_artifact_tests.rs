//! Regression tests for #962: vulnerability counts must reflect the LATEST
//! completed scan per (artifact, scan_type), not the SUM of every scan ever
//! recorded for that artifact.
//!
//! Run with:
//!
//! ```sh
//! DATABASE_URL="postgresql://registry:registry@localhost:30432/artifact_registry" \
//!   cargo test --test scan_latest_per_artifact_tests -- --ignored
//! ```

use sqlx::PgPool;
use uuid::Uuid;

use artifact_keeper_backend::services::scan_result_service::ScanResultService;

async fn create_repo(pool: &PgPool, suffix: &str) -> Uuid {
    let id = Uuid::new_v4();
    let key = format!("test-962-{}-{}", suffix, id);
    sqlx::query(
        "INSERT INTO repositories (id, key, name, storage_path, repo_type, format) \
         VALUES ($1, $2, $3, $4, 'local', 'generic')",
    )
    .bind(id)
    .bind(&key)
    .bind(&key)
    .bind(format!("/tmp/test-{}", id))
    .execute(pool)
    .await
    .expect("insert repo");
    id
}

async fn create_artifact(pool: &PgPool, repo_id: Uuid, name: &str) -> Uuid {
    let id = Uuid::new_v4();
    let path = format!("{}/{}", repo_id, name);
    let checksum = format!("{:0>64}", format!("{:x}", id.as_u128() & 0xffff_ffff));
    sqlx::query(
        r#"
        INSERT INTO artifacts (id, repository_id, name, path, size_bytes, checksum_sha256,
                               content_type, storage_key, is_deleted)
        VALUES ($1, $2, $3, $4, 1024, $5, 'application/octet-stream', $4, false)
        "#,
    )
    .bind(id)
    .bind(repo_id)
    .bind(name)
    .bind(&path)
    .bind(&checksum)
    .execute(pool)
    .await
    .expect("insert artifact");
    id
}

/// Insert one completed scan with `n_critical + n_high` findings. Returns the
/// new scan_result id.
async fn insert_scan(
    pool: &PgPool,
    artifact_id: Uuid,
    repo_id: Uuid,
    scan_type: &str,
    completed_at_offset_seconds: i64,
    n_critical: i32,
    n_high: i32,
) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        r#"
        INSERT INTO scan_results (
            id, artifact_id, repository_id, scan_type, status,
            findings_count, critical_count, high_count, medium_count, low_count, info_count,
            started_at, completed_at
        )
        VALUES ($1, $2, $3, $4, 'completed', $5, $6, $7, 0, 0, 0,
                NOW() - make_interval(secs => $8::double precision),
                NOW() - make_interval(secs => $8::double precision))
        "#,
    )
    .bind(id)
    .bind(artifact_id)
    .bind(repo_id)
    .bind(scan_type)
    .bind(n_critical + n_high)
    .bind(n_critical)
    .bind(n_high)
    .bind(completed_at_offset_seconds as f64)
    .execute(pool)
    .await
    .expect("insert scan_result");

    for i in 0..n_critical {
        sqlx::query(
            "INSERT INTO scan_findings (scan_result_id, artifact_id, severity, title, source) \
             VALUES ($1, $2, 'critical', $3, 'test')",
        )
        .bind(id)
        .bind(artifact_id)
        .bind(format!("CVE-CRIT-{}-{}", id, i))
        .execute(pool)
        .await
        .expect("insert critical finding");
    }
    for i in 0..n_high {
        sqlx::query(
            "INSERT INTO scan_findings (scan_result_id, artifact_id, severity, title, source) \
             VALUES ($1, $2, 'high', $3, 'test')",
        )
        .bind(id)
        .bind(artifact_id)
        .bind(format!("CVE-HIGH-{}-{}", id, i))
        .execute(pool)
        .await
        .expect("insert high finding");
    }
    id
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

// ---------------------------------------------------------------------------
// #962 regression: dashboard summary counts only the latest scan
// ---------------------------------------------------------------------------

/// The exact scenario from the issue: scan one image ten times, each scan
/// reports 15 vulnerabilities (10 critical + 5 high). Before the fix the
/// dashboard reported 150 vulnerabilities; after the fix it reports 15.
#[tokio::test]
#[ignore]
async fn test_dashboard_summary_uses_latest_scan_per_artifact_not_sum() {
    let pool = PgPool::connect(&std::env::var("DATABASE_URL").expect("DATABASE_URL"))
        .await
        .expect("connect");

    let repo_id = create_repo(&pool, "dash-latest").await;
    let artifact_id = create_artifact(&pool, repo_id, "nginx-latest").await;

    // Ten scans of the same artifact, each with the same 15 findings.
    // completed_at offsets go from 10*60 to 60 seconds ago so the "newest"
    // scan is unambiguous regardless of created_at tie-breaking.
    let mut scan_ids = Vec::new();
    for i in 0..10 {
        let offset = (10 - i) * 60;
        scan_ids.push(insert_scan(&pool, artifact_id, repo_id, "image", offset, 10, 5).await);
    }

    // Baseline: the bug shape was a raw SUM of all scans' findings_count, so
    // verify the data we just inserted would surface as 150 under the broken
    // logic. This proves the test is actually exercising the bug condition.
    let raw_sum: (Option<i64>,) = sqlx::query_as(
        "SELECT SUM(findings_count)::bigint FROM scan_results WHERE artifact_id = $1",
    )
    .bind(artifact_id)
    .fetch_one(&pool)
    .await
    .expect("sum");
    assert_eq!(
        raw_sum.0,
        Some(150),
        "fixture must reproduce the #962 condition (10 scans x 15 findings each)"
    );

    let svc = ScanResultService::new(pool.clone());
    let summary = svc
        .get_dashboard_summary()
        .await
        .expect("get_dashboard_summary");

    // The fix: 15 findings total (10 critical + 5 high), not 150.
    assert_eq!(
        summary.total_findings, 15,
        "dashboard must report findings of the LATEST scan only, not the sum of all scans (#962)"
    );
    assert_eq!(
        summary.critical_findings, 10,
        "critical count must reflect latest scan only (#962)"
    );
    assert_eq!(
        summary.high_findings, 5,
        "high count must reflect latest scan only (#962)"
    );

    cleanup(&pool, repo_id).await;
}

/// Soft-deleted artifacts must not contribute to the dashboard's finding
/// counts. This catches a separate regression caused by hard-deletes leaving
/// scan_findings behind but is_deleted=true keeping them visible.
#[tokio::test]
#[ignore]
async fn test_dashboard_summary_excludes_soft_deleted_artifacts() {
    let pool = PgPool::connect(&std::env::var("DATABASE_URL").expect("DATABASE_URL"))
        .await
        .expect("connect");

    let repo_id = create_repo(&pool, "dash-soft-del").await;
    let live = create_artifact(&pool, repo_id, "live-app").await;
    let deleted = create_artifact(&pool, repo_id, "deleted-app").await;

    // Mark `deleted` as soft-deleted but keep its scan + findings.
    sqlx::query("UPDATE artifacts SET is_deleted = true WHERE id = $1")
        .bind(deleted)
        .execute(&pool)
        .await
        .expect("soft delete artifact");

    let _ = insert_scan(&pool, live, repo_id, "image", 60, 2, 3).await;
    let _ = insert_scan(&pool, deleted, repo_id, "image", 60, 7, 11).await;

    let svc = ScanResultService::new(pool.clone());
    let summary = svc.get_dashboard_summary().await.expect("summary");

    assert_eq!(
        summary.total_findings, 5,
        "only the live artifact's 5 findings should count, not 5 + 18"
    );
    assert_eq!(summary.critical_findings, 2);
    assert_eq!(summary.high_findings, 3);

    cleanup(&pool, repo_id).await;
}

// ---------------------------------------------------------------------------
// #1030 perf check: the new partial index is the chosen plan
// ---------------------------------------------------------------------------

/// Best-effort sanity check that PostgreSQL has the partial index available
/// for the latest-scan windowing. We do not assert on plan shape (EXPLAIN
/// output is environment-dependent), only on index existence.
#[tokio::test]
#[ignore]
async fn test_partial_index_for_latest_scan_exists() {
    let pool = PgPool::connect(&std::env::var("DATABASE_URL").expect("DATABASE_URL"))
        .await
        .expect("connect");

    let exists: (bool,) = sqlx::query_as(
        "SELECT EXISTS (
             SELECT 1 FROM pg_indexes
             WHERE schemaname = current_schema()
               AND tablename = 'scan_results'
               AND indexname = 'idx_scan_results_latest_per_artifact_type'
         )",
    )
    .fetch_one(&pool)
    .await
    .expect("query pg_indexes");

    assert!(
        exists.0,
        "migration 101 must install idx_scan_results_latest_per_artifact_type (#1030)"
    );
}
