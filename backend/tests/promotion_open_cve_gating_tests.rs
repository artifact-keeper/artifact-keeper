//! Regression tests for #1620: promotion gating must read open CVEs from the
//! populated `scan_findings` table, not the never-written `cve_history` table.
//!
//! Before the fix, `PromotionPolicyService::get_cve_summary` ran
//! `SELECT DISTINCT cve_id FROM cve_history WHERE artifact_id = $1 AND
//! status = 'open'`. `cve_history` has zero writers, so `open_cves` was always
//! empty and a "block on open CVEs" gate silently passed -- a security gate
//! that did nothing. The fix repoints the read at `scan_findings` (the source
//! the scanner pipeline actually writes), so the gate blocks as configured.
//! This also addresses the #1561 data-source confusion (#1616 umbrella).
//!
//! Run with:
//!
//! ```sh
//! DATABASE_URL="postgresql://registry:registry@localhost:30432/artifact_registry" \
//!   cargo test --test promotion_open_cve_gating_tests -- --ignored
//! ```

use sqlx::PgPool;
use uuid::Uuid;

use artifact_keeper_backend::models::sbom::PolicyAction;
use artifact_keeper_backend::services::promotion_policy_service::PromotionPolicyService;
use artifact_keeper_backend::services::sbom_service::SbomService;

async fn create_repo(pool: &PgPool, suffix: &str) -> Uuid {
    let id = Uuid::new_v4();
    let key = format!("test-1620-{}-{}", suffix, id);
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

/// Insert one completed scan, finished `age_seconds` ago, with a single
/// critical finding carrying `cve_id`. `acknowledged` controls the finding's
/// `is_acknowledged` flag. Returns the scan_result id.
async fn insert_scan_with_cve_at(
    pool: &PgPool,
    artifact_id: Uuid,
    repo_id: Uuid,
    cve_id: &str,
    acknowledged: bool,
    age_seconds: i64,
) -> Uuid {
    let scan_id = Uuid::new_v4();
    sqlx::query(
        r#"
        INSERT INTO scan_results (
            id, artifact_id, repository_id, scan_type, status,
            findings_count, critical_count, high_count, medium_count, low_count, info_count,
            started_at, completed_at
        )
        VALUES ($1, $2, $3, 'image', 'completed', 1, 1, 0, 0, 0, 0,
                NOW() - make_interval(secs => $4::double precision),
                NOW() - make_interval(secs => $4::double precision))
        "#,
    )
    .bind(scan_id)
    .bind(artifact_id)
    .bind(repo_id)
    .bind(age_seconds as f64)
    .execute(pool)
    .await
    .expect("insert scan_result");

    sqlx::query(
        "INSERT INTO scan_findings \
         (scan_result_id, artifact_id, severity, title, cve_id, source, is_acknowledged) \
         VALUES ($1, $2, 'critical', $3, $4, 'test', $5)",
    )
    .bind(scan_id)
    .bind(artifact_id)
    .bind(format!("Finding for {}", cve_id))
    .bind(cve_id)
    .bind(acknowledged)
    .execute(pool)
    .await
    .expect("insert scan_finding");

    scan_id
}

/// Convenience wrapper: a scan completed "now".
async fn insert_scan_with_cve(
    pool: &PgPool,
    artifact_id: Uuid,
    repo_id: Uuid,
    cve_id: &str,
    acknowledged: bool,
) -> Uuid {
    insert_scan_with_cve_at(pool, artifact_id, repo_id, cve_id, acknowledged, 0).await
}

/// Insert a repo-scoped scan policy that blocks on any CVE at/above critical.
async fn insert_blocking_policy(pool: &PgPool, repo_id: Uuid) {
    sqlx::query(
        "INSERT INTO scan_policies (id, name, repository_id, max_severity, block_on_fail, is_enabled) \
         VALUES ($1, $2, $3, 'critical', true, true)",
    )
    .bind(Uuid::new_v4())
    .bind("block-on-open-cves")
    .bind(repo_id)
    .execute(pool)
    .await
    .expect("insert scan_policy");
}

async fn cleanup(pool: &PgPool, repo_id: Uuid) {
    sqlx::query("DELETE FROM scan_policies WHERE repository_id = $1")
        .bind(repo_id)
        .execute(pool)
        .await
        .ok();
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

async fn connect() -> PgPool {
    PgPool::connect(&std::env::var("DATABASE_URL").expect("DATABASE_URL"))
        .await
        .expect("connect")
}

/// The #1620 regression: an artifact whose only CVE evidence lives in
/// `scan_findings` (unacknowledged) must surface a NON-EMPTY `open_cves` set
/// and BLOCK promotion. On `main` (reading the empty `cve_history`) this set
/// was empty and the gate silently passed.
#[tokio::test]
#[ignore]
async fn test_unacknowledged_scan_finding_blocks_promotion() {
    let pool = connect().await;
    let repo_id = create_repo(&pool, "block").await;
    let artifact_id = create_artifact(&pool, repo_id, "vuln-image").await;
    insert_scan_with_cve(&pool, artifact_id, repo_id, "CVE-2021-44228", false).await;
    insert_blocking_policy(&pool, repo_id).await;

    // Sanity: the legacy table the OLD query read is genuinely empty for this
    // artifact, so the pre-fix code path would have returned `open_cves = []`
    // and let the artifact through. This proves the test exercises the bug.
    let legacy_count: (i64,) =
        sqlx::query_as("SELECT COUNT(*) FROM cve_history WHERE artifact_id = $1")
            .bind(artifact_id)
            .fetch_one(&pool)
            .await
            .expect("count cve_history");
    assert_eq!(
        legacy_count.0, 0,
        "fixture must reproduce #1620: cve_history is empty, so the old read returned no open CVEs"
    );

    let svc = PromotionPolicyService::new(pool.clone());
    let result = svc
        .evaluate_artifact(artifact_id, repo_id)
        .await
        .expect("evaluate_artifact");

    let summary = result.cve_summary.expect("cve_summary present");
    assert_eq!(
        summary.open_cves,
        vec!["CVE-2021-44228".to_string()],
        "open_cves must be sourced from scan_findings, not the empty cve_history (#1620)"
    );
    assert!(
        !result.passed,
        "promotion must be BLOCKED when an unacknowledged scan_findings CVE exists (#1620)"
    );
    assert_eq!(
        result.action,
        PolicyAction::Block,
        "a configured block-on-CVE gate must produce PolicyAction::Block (#1620)"
    );

    cleanup(&pool, repo_id).await;
}

/// An acknowledged finding must NOT count as an open CVE: the repointed query
/// filters on `NOT is_acknowledged`. With no other open CVEs and no critical
/// counts in play, `open_cves` is empty.
#[tokio::test]
#[ignore]
async fn test_acknowledged_scan_finding_is_not_open() {
    let pool = connect().await;
    let repo_id = create_repo(&pool, "ack").await;
    let artifact_id = create_artifact(&pool, repo_id, "ack-image").await;
    insert_scan_with_cve(&pool, artifact_id, repo_id, "CVE-2019-10744", true).await;

    let svc = PromotionPolicyService::new(pool.clone());
    let result = svc
        .evaluate_artifact(artifact_id, repo_id)
        .await
        .expect("evaluate_artifact");

    let summary = result.cve_summary.expect("cve_summary present");
    assert!(
        summary.open_cves.is_empty(),
        "an acknowledged finding must not appear in open_cves (NOT is_acknowledged filter)"
    );

    cleanup(&pool, repo_id).await;
}

/// Only the LATEST completed scan defines the open-CVE set. A CVE that was
/// present in an older scan but absent from the newest completed scan must not
/// surface as open (it "fell off" on rescan).
#[tokio::test]
#[ignore]
async fn test_open_cves_use_latest_completed_scan_only() {
    let pool = connect().await;
    let repo_id = create_repo(&pool, "latest").await;
    let artifact_id = create_artifact(&pool, repo_id, "rescanned-image").await;

    // Older scan (1 hour ago) with a CVE that later gets fixed.
    insert_scan_with_cve_at(&pool, artifact_id, repo_id, "CVE-2020-0001", false, 3600).await;

    // Newer completed scan (now) with a DIFFERENT, still-open CVE; the old one
    // is gone from the latest scan.
    insert_scan_with_cve(&pool, artifact_id, repo_id, "CVE-2022-2222", false).await;

    let svc = PromotionPolicyService::new(pool.clone());
    let result = svc
        .evaluate_artifact(artifact_id, repo_id)
        .await
        .expect("evaluate_artifact");

    let summary = result.cve_summary.expect("cve_summary present");
    assert_eq!(
        summary.open_cves,
        vec!["CVE-2022-2222".to_string()],
        "open_cves must reflect the latest completed scan only; the fixed CVE must drop off"
    );

    cleanup(&pool, repo_id).await;
}

/// Companion to the promotion fix: the findings read path (`get_cve_history`)
/// must return the scan-derived entry for an artifact whose CVE evidence lives
/// only in `scan_findings`. On `main` this read started from the empty
/// `cve_history` table; the repointed code derives entries from `scan_findings`
/// directly (#1561 data source / #1616 umbrella).
#[tokio::test]
#[ignore]
async fn test_get_cve_history_returns_scan_derived_entry() {
    let pool = connect().await;
    let repo_id = create_repo(&pool, "history").await;
    let artifact_id = create_artifact(&pool, repo_id, "history-image").await;
    insert_scan_with_cve(&pool, artifact_id, repo_id, "CVE-2023-3333", false).await;

    // The legacy table is empty, so any returned entry must come from the
    // repointed scan_findings read.
    let legacy_count: (i64,) =
        sqlx::query_as("SELECT COUNT(*) FROM cve_history WHERE artifact_id = $1")
            .bind(artifact_id)
            .fetch_one(&pool)
            .await
            .expect("count cve_history");
    assert_eq!(
        legacy_count.0, 0,
        "cve_history must be empty for this fixture"
    );

    let svc = SbomService::new(pool.clone());
    let entries = svc
        .get_cve_history(artifact_id)
        .await
        .expect("get_cve_history");

    assert_eq!(
        entries.len(),
        1,
        "get_cve_history must surface the scan-derived CVE entry"
    );
    assert_eq!(entries[0].cve_id, "CVE-2023-3333");
    assert_eq!(entries[0].artifact_id, artifact_id);

    cleanup(&pool, repo_id).await;
}
