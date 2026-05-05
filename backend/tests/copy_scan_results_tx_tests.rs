//! Integration test for #1035: `copy_scan_results` must be wrapped in a
//! transaction so that a failure of the second INSERT (scan_findings) rolls
//! back the first INSERT (scan_results row).
//!
//! Without the transaction the dashboard's DISTINCT ON aggregation can pick
//! up the freshly-inserted scan_results row before its findings exist,
//! producing a transient under-count. Pre-fix, a hard failure of the second
//! INSERT also leaves an orphan completed scan_results row behind. This test
//! exercises the deterministic rollback half of that contract.
//!
//! Requires PostgreSQL with all migrations applied. Set DATABASE_URL, e.g.:
//!
//! ```sh
//! DATABASE_URL="postgres://registry:registry@localhost:35432/artifact_registry" \
//!     cargo test --test copy_scan_results_tx_tests
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

async fn create_test_repo(pool: &PgPool) -> Uuid {
    let id = Uuid::new_v4();
    let key = format!("copy-tx-{}", id.as_simple());
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

async fn create_test_artifact(pool: &PgPool, repo_id: Uuid, suffix: &str) -> (Uuid, String) {
    let id = Uuid::new_v4();
    let path = format!("{}/{}/pkg.tar.gz", id.as_simple(), suffix);
    // Unique per-call checksum so multiple artifacts in one test do not
    // collide on the checksum_sha256 unique index in `artifacts`.
    let checksum = format!("{:0>56}{:0>8}", id.as_simple(), suffix);
    let checksum = checksum.chars().take(64).collect::<String>();
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
    (id, checksum)
}

async fn cleanup(pool: &PgPool, repo_id: Uuid) {
    let _ = sqlx::query("DELETE FROM repo_security_scores WHERE repository_id = $1")
        .bind(repo_id)
        .execute(pool)
        .await;
    let _ = sqlx::query("DELETE FROM repositories WHERE id = $1")
        .bind(repo_id)
        .execute(pool)
        .await;
}

/// Count `scan_results` rows for a given artifact. Used to verify that the
/// transaction rollback in #1035 leaves no orphan rows behind.
async fn count_scan_results_for(pool: &PgPool, artifact_id: Uuid) -> i64 {
    sqlx::query_scalar("SELECT COUNT(*) FROM scan_results WHERE artifact_id = $1")
        .bind(artifact_id)
        .fetch_one(pool)
        .await
        .expect("count scan_results")
}

/// #1035 — `copy_scan_results` must roll back the first INSERT when the
/// second INSERT fails.
///
/// Setup:
///   - One source artifact with one completed scan_result + one finding.
///   - One destination artifact (different id, same repo, same scan_type).
///   - A `BEFORE INSERT` trigger on `scan_findings` that always raises so
///     the second INSERT (`INSERT INTO scan_findings ... SELECT ...`) fails
///     with a hard SQL error.
///
/// Assertions:
///   - `copy_scan_results` returns Err.
///   - **No** `scan_results` row exists for the destination artifact after
///     the failure. Pre-fix, the first INSERT was committed independently
///     of the second; with the fix both INSERTs share a transaction and
///     the orphan row is rolled back.
#[tokio::test]
async fn copy_scan_results_rolls_back_first_insert_when_findings_insert_fails() {
    let pool = connect_db().await;
    let svc = ScanResultService::new(pool.clone());

    let repo_id = create_test_repo(&pool).await;
    let (source_artifact_id, _) = create_test_artifact(&pool, repo_id, "src").await;
    let (dest_artifact_id, dest_checksum) = create_test_artifact(&pool, repo_id, "dst").await;

    // --- Build a real source scan with one finding so the second INSERT
    // actually has a row to copy (and therefore actually fires the trigger).
    let source_scan = svc
        .create_scan_result(source_artifact_id, repo_id, "dependency")
        .await
        .expect("create source scan");

    svc.create_findings(
        source_scan.id,
        source_artifact_id,
        &[RawFinding {
            severity: Severity::High,
            title: "CVE-test-1035".to_string(),
            description: None,
            cve_id: Some("CVE-2024-1035".to_string()),
            affected_component: Some("libtest".to_string()),
            affected_version: Some("1.0.0".to_string()),
            fixed_version: Some("1.0.1".to_string()),
            source: Some("test".to_string()),
            source_url: None,
        }],
    )
    .await
    .expect("insert source finding");

    svc.complete_scan(source_scan.id, 1, 0, 1, 0, 0, 0)
        .await
        .expect("complete source scan");

    // --- Install a trigger that fails INSERTs into scan_findings for the
    // destination artifact only. Scoping by artifact_id means the source
    // finding we just inserted is unaffected and concurrent tests sharing
    // this DB do not collide.
    let trigger_fn = format!(
        r#"
        CREATE OR REPLACE FUNCTION test_1035_fail_findings_insert()
        RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN
            IF NEW.artifact_id = '{aid}'::uuid THEN
                RAISE EXCEPTION 'test #1035: simulated failure of scan_findings INSERT';
            END IF;
            RETURN NEW;
        END;
        $$;
        "#,
        aid = dest_artifact_id
    );
    sqlx::query(&trigger_fn)
        .execute(&pool)
        .await
        .expect("install trigger function");

    sqlx::query("DROP TRIGGER IF EXISTS test_1035_trg ON scan_findings")
        .execute(&pool)
        .await
        .expect("drop pre-existing trigger");
    sqlx::query(
        "CREATE TRIGGER test_1035_trg BEFORE INSERT ON scan_findings
         FOR EACH ROW EXECUTE FUNCTION test_1035_fail_findings_insert()",
    )
    .execute(&pool)
    .await
    .expect("install trigger");

    // --- Sanity: pre-call, the destination has zero scan_results rows.
    let pre_count = count_scan_results_for(&pool, dest_artifact_id).await;
    assert_eq!(pre_count, 0, "destination must start with no scans");

    // --- Act: call copy_scan_results. Expected: returns Err because the
    // second INSERT fires the trigger and raises.
    let result = svc
        .copy_scan_results(
            source_scan.id,
            dest_artifact_id,
            repo_id,
            "dependency",
            &dest_checksum,
        )
        .await;

    assert!(
        result.is_err(),
        "copy_scan_results should fail when scan_findings INSERT errors, got: {:?}",
        result.as_ref().map(|s| s.id)
    );

    // --- The key assertion (#1035): the FIRST INSERT must not have
    // committed. Pre-fix, the row from step (1) was already in the table
    // when step (2) errored. Post-fix, both INSERTs share a transaction
    // so the row is rolled back.
    let post_count = count_scan_results_for(&pool, dest_artifact_id).await;
    assert_eq!(
        post_count, 0,
        "scan_results row from the first INSERT must be rolled back when the \
         second INSERT (scan_findings) fails. Found {} orphan row(s) — bug #1035.",
        post_count
    );

    // --- Tear down trigger so we don't leak into other tests.
    let _ = sqlx::query("DROP TRIGGER IF EXISTS test_1035_trg ON scan_findings")
        .execute(&pool)
        .await;
    let _ = sqlx::query("DROP FUNCTION IF EXISTS test_1035_fail_findings_insert()")
        .execute(&pool)
        .await;

    cleanup(&pool, repo_id).await;
}
