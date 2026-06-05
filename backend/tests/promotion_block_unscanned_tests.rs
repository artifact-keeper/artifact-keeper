//! Regression tests for #1643: the promotion gate must enforce
//! `scan_policies.block_unscanned` and must NOT fail open on unscanned
//! artifacts.
//!
//! Before the fix, `promotion_policy_service.rs` referenced `block_unscanned`
//! zero times and `evaluate_artifact` only ran CVE policy when a completed scan
//! produced a `cve_summary`. An artifact with no completed scan therefore
//! produced zero violations -> `passed = true, action = Allow`: a security gate
//! that promoted unvetted artifacts. The fix wires `block_unscanned` into the
//! gate and classifies scan state (never-scanned / in-progress / failed ->
//! blocked when the toggle is on; "not applicable" -> always allowed).
//!
//! Run with:
//!
//! ```sh
//! DATABASE_URL="postgresql://registry:registry@localhost:30432/artifact_registry" \
//!   cargo test --test promotion_block_unscanned_tests -- --ignored
//! ```

use sqlx::PgPool;
use uuid::Uuid;

use artifact_keeper_backend::models::sbom::PolicyAction;
use artifact_keeper_backend::services::promotion_policy_service::PromotionPolicyService;

async fn create_repo(pool: &PgPool, suffix: &str) -> Uuid {
    let id = Uuid::new_v4();
    let key = format!("test-1643-{}-{}", suffix, id);
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

/// Insert a repo-scoped scan policy. `block_unscanned` controls the toggle
/// under test; other gates are left permissive so the only thing that can fail
/// is the block-unscanned check.
async fn insert_policy(pool: &PgPool, repo_id: Uuid, block_unscanned: bool) {
    sqlx::query(
        "INSERT INTO scan_policies (id, name, repository_id, max_severity, block_unscanned, \
         block_on_fail, is_enabled) \
         VALUES ($1, $2, $3, 'critical', $4, false, true)",
    )
    .bind(Uuid::new_v4())
    .bind(format!("policy-{}", repo_id))
    .bind(repo_id)
    .bind(block_unscanned)
    .execute(pool)
    .await
    .expect("insert scan_policy");
}

/// Insert a single scan row with the given status / error_message. Completed
/// scans carry zero findings so no CVE gate fires -- isolating the
/// block-unscanned behavior.
async fn insert_scan(
    pool: &PgPool,
    artifact_id: Uuid,
    repo_id: Uuid,
    status: &str,
    err: Option<&str>,
) {
    sqlx::query(
        r#"
        INSERT INTO scan_results (
            id, artifact_id, repository_id, scan_type, status,
            findings_count, critical_count, high_count, medium_count, low_count, info_count,
            error_message
        )
        VALUES ($1, $2, $3, 'image', $4, 0, 0, 0, 0, 0, 0, $5)
        "#,
    )
    .bind(Uuid::new_v4())
    .bind(artifact_id)
    .bind(repo_id)
    .bind(status)
    .bind(err)
    .execute(pool)
    .await
    .expect("insert scan_result");
}

async fn cleanup(pool: &PgPool, repo_id: Uuid) {
    sqlx::query("DELETE FROM scan_policies WHERE repository_id = $1")
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

fn has_block_unscanned_violation(
    result: &artifact_keeper_backend::services::promotion_policy_service::PolicyEvaluationResult,
) -> bool {
    result
        .violations
        .iter()
        .any(|v| v.rule == "block-unscanned")
}

/// `block_unscanned = true` + no scan rows at all -> BLOCKED.
#[tokio::test]
#[ignore]
async fn test_block_unscanned_never_scanned_blocks() {
    let pool = connect().await;
    let repo_id = create_repo(&pool, "never").await;
    let artifact_id = create_artifact(&pool, repo_id, "never-scanned").await;
    insert_policy(&pool, repo_id, true).await;

    let svc = PromotionPolicyService::new(pool.clone());
    let result = svc
        .evaluate_artifact(artifact_id, repo_id)
        .await
        .expect("evaluate_artifact");

    assert!(
        !result.passed,
        "an artifact with no scan must be blocked when block_unscanned = true (#1643)"
    );
    assert_eq!(result.action, PolicyAction::Block);
    assert!(has_block_unscanned_violation(&result));

    cleanup(&pool, repo_id).await;
}

/// `block_unscanned = true` + latest scan failed (genuine crash) -> BLOCKED.
#[tokio::test]
#[ignore]
async fn test_block_unscanned_failed_scan_blocks() {
    let pool = connect().await;
    let repo_id = create_repo(&pool, "failed").await;
    let artifact_id = create_artifact(&pool, repo_id, "failed-scan").await;
    insert_policy(&pool, repo_id, true).await;
    insert_scan(
        &pool,
        artifact_id,
        repo_id,
        "failed",
        Some("scanner crashed"),
    )
    .await;

    let svc = PromotionPolicyService::new(pool.clone());
    let result = svc
        .evaluate_artifact(artifact_id, repo_id)
        .await
        .expect("evaluate_artifact");

    assert!(
        !result.passed,
        "a crashed scan must block when block_unscanned = true (#1643)"
    );
    assert_eq!(result.action, PolicyAction::Block);
    assert!(has_block_unscanned_violation(&result));

    cleanup(&pool, repo_id).await;
}

/// `block_unscanned = true` + scan in progress (running) -> BLOCKED.
#[tokio::test]
#[ignore]
async fn test_block_unscanned_in_progress_blocks() {
    let pool = connect().await;
    let repo_id = create_repo(&pool, "running").await;
    let artifact_id = create_artifact(&pool, repo_id, "running-scan").await;
    insert_policy(&pool, repo_id, true).await;
    insert_scan(&pool, artifact_id, repo_id, "running", None).await;

    let svc = PromotionPolicyService::new(pool.clone());
    let result = svc
        .evaluate_artifact(artifact_id, repo_id)
        .await
        .expect("evaluate_artifact");

    assert!(
        !result.passed,
        "an in-progress scan must block when block_unscanned = true (#1643)"
    );
    assert!(has_block_unscanned_violation(&result));

    cleanup(&pool, repo_id).await;
}

/// `block_unscanned = false` + no scan -> ALLOWED (fail-open by deliberate
/// policy choice; the WARN log path is exercised but cannot be asserted here).
#[tokio::test]
#[ignore]
async fn test_allow_unscanned_when_toggle_off() {
    let pool = connect().await;
    let repo_id = create_repo(&pool, "allow").await;
    let artifact_id = create_artifact(&pool, repo_id, "unscanned-allowed").await;
    insert_policy(&pool, repo_id, false).await;

    let svc = PromotionPolicyService::new(pool.clone());
    let result = svc
        .evaluate_artifact(artifact_id, repo_id)
        .await
        .expect("evaluate_artifact");

    assert!(
        result.passed,
        "block_unscanned = false must allow an unscanned artifact through (#1643)"
    );
    assert!(
        !has_block_unscanned_violation(&result),
        "no block-unscanned violation must be recorded when the toggle is off"
    );

    cleanup(&pool, repo_id).await;
}

/// `block_unscanned = true` + scan "not applicable" -> ALLOWED. A scanner that
/// does not apply to the artifact's format (stored as a failed row whose
/// error_message says "does not apply") must NOT be treated as unscanned.
#[tokio::test]
#[ignore]
async fn test_not_applicable_scan_passes_even_when_blocking() {
    let pool = connect().await;
    let repo_id = create_repo(&pool, "na").await;
    let artifact_id = create_artifact(&pool, repo_id, "not-applicable").await;
    insert_policy(&pool, repo_id, true).await;
    insert_scan(
        &pool,
        artifact_id,
        repo_id,
        "failed",
        Some("Scanner ImageScanner does not apply to this artifact format"),
    )
    .await;

    let svc = PromotionPolicyService::new(pool.clone());
    let result = svc
        .evaluate_artifact(artifact_id, repo_id)
        .await
        .expect("evaluate_artifact");

    assert!(
        result.passed,
        "a 'not applicable' scan must pass even with block_unscanned = true (#1643/#1470)"
    );
    assert!(!has_block_unscanned_violation(&result));

    cleanup(&pool, repo_id).await;
}

/// `block_unscanned = true` + completed clean scan -> ALLOWED.
#[tokio::test]
#[ignore]
async fn test_completed_clean_scan_passes() {
    let pool = connect().await;
    let repo_id = create_repo(&pool, "clean").await;
    let artifact_id = create_artifact(&pool, repo_id, "clean-scan").await;
    insert_policy(&pool, repo_id, true).await;
    insert_scan(&pool, artifact_id, repo_id, "completed", None).await;

    let svc = PromotionPolicyService::new(pool.clone());
    let result = svc
        .evaluate_artifact(artifact_id, repo_id)
        .await
        .expect("evaluate_artifact");

    assert!(
        result.passed,
        "a completed clean scan must pass under block_unscanned = true (#1643)"
    );
    assert!(!has_block_unscanned_violation(&result));

    cleanup(&pool, repo_id).await;
}

/// Default-change safety: a policy whose stored block_unscanned is false keeps
/// failing open even after migration 121 changed the COLUMN DEFAULT to true.
/// The migration must not rewrite existing rows.
#[tokio::test]
#[ignore]
async fn test_existing_policy_stored_false_unchanged_by_default_flip() {
    let pool = connect().await;
    let repo_id = create_repo(&pool, "existing").await;
    let artifact_id = create_artifact(&pool, repo_id, "legacy-policy").await;
    // Explicitly stored false, simulating a pre-existing operator choice.
    insert_policy(&pool, repo_id, false).await;

    let stored: bool =
        sqlx::query_scalar("SELECT block_unscanned FROM scan_policies WHERE repository_id = $1")
            .bind(repo_id)
            .fetch_one(&pool)
            .await
            .expect("read stored value");
    assert!(
        !stored,
        "existing stored false must remain false after the default flip"
    );

    let svc = PromotionPolicyService::new(pool.clone());
    let result = svc
        .evaluate_artifact(artifact_id, repo_id)
        .await
        .expect("evaluate_artifact");
    assert!(
        result.passed,
        "existing block_unscanned=false policy must still fail open (decision unchanged)"
    );

    cleanup(&pool, repo_id).await;
}
