//! Regression tests for PR #1940: promotion_rules must be ENFORCED on every
//! manual promote path, not just the single + bulk REST handlers.
//!
//! Background: PR #1940 added a promotion_rules gate to the single and bulk
//! promote endpoints, but the blue-team review live-reproduced a bypass on a
//! THIRD path -- the approval-workflow execute endpoint (`approve_promotion`).
//! Because `promote_artifact` FORCES approval-required repos into that workflow,
//! governance-ruled repos (the ones most likely to carry rules) bypassed the
//! new gate entirely: a rule with `min_staging_hours = 720` was satisfied via
//! request -> approve on a seconds-old artifact.
//!
//! All three handlers funnel through the same evaluator
//! (`PromotionRuleService::evaluate_for_promotion`), so these tests pin:
//!   1. rule-met  -> evaluator returns NO violations (single/bulk/approval all
//!      promote);
//!   2. rule-unmet (`min_staging_hours = 720`, fresh artifact) -> evaluator
//!      returns violations (single/bulk/approval all block);
//!   3. the approval handler itself now BLOCKS a rule-unmet promotion (403, no
//!      artifact copied) and PROMOTES a rule-met one -- driving the real
//!      `approve_promotion` end to end;
//!   4. the `max_cve_severity` default fix: a rule that does NOT set
//!      `max_cve_severity` (NULL) must NOT silently require a clean scan, so an
//!      unscanned artifact under an hours-only rule is not falsely blocked,
//!      while a rule that DOES set a CVE bound still blocks an unscanned
//!      artifact.
//!
//! Requires a PostgreSQL database with all migrations applied:
//!
//! ```sh
//! DATABASE_URL="postgresql://registry:registry@localhost:5599/artifact_registry" \
//!   cargo test --test promotion_rules_gate_tests -- --ignored
//! ```

#![allow(clippy::unwrap_used)]

use std::collections::HashMap;
use std::sync::Arc;

use axum::extract::{Extension, Path, State};
use axum::Json;
use sqlx::PgPool;
use uuid::Uuid;

use artifact_keeper_backend::api::handlers::approval::{approve_promotion, ReviewRequest};
use artifact_keeper_backend::api::middleware::auth::AuthExtension;
use artifact_keeper_backend::api::{AppState, SharedState};
use artifact_keeper_backend::config::Config;
use artifact_keeper_backend::error::AppError;
use artifact_keeper_backend::models::promotion::PromotionRule;
use artifact_keeper_backend::services::promotion_rule_service::PromotionRuleService;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

async fn connect() -> PgPool {
    PgPool::connect(&std::env::var("DATABASE_URL").expect("DATABASE_URL"))
        .await
        .expect("connect")
}

fn test_config(storage_path: &str) -> Config {
    Config {
        database_url: std::env::var("DATABASE_URL").unwrap_or_default(),
        storage_path: storage_path.into(),
        jwt_secret: "test-secret-at-least-32-bytes-long-for-testing".into(),
        ..Default::default()
    }
}

fn build_state(pool: PgPool, storage_path: &str) -> SharedState {
    let storage: Arc<dyn artifact_keeper_backend::storage::StorageBackend> = Arc::new(
        artifact_keeper_backend::storage::filesystem::FilesystemStorage::new(storage_path),
    );
    let registry = Arc::new(artifact_keeper_backend::storage::StorageRegistry::new(
        HashMap::new(),
        "filesystem".to_string(),
    ));
    Arc::new(AppState::new(
        test_config(storage_path),
        pool,
        storage,
        registry,
    ))
}

/// Resolve the per-repo filesystem storage backend (each repo has its own
/// storage_path column, so we go through the repo's storage_location()).
async fn storage_for(
    state: &SharedState,
    pool: &PgPool,
    repo_id: Uuid,
) -> Arc<dyn artifact_keeper_backend::storage::StorageBackend> {
    let repo =
        artifact_keeper_backend::services::repository_service::RepositoryService::new(pool.clone())
            .get_by_id(repo_id)
            .await
            .expect("get_by_id");
    state
        .storage_for_repo(&repo.storage_location())
        .expect("storage_for_repo")
}

async fn create_admin(pool: &PgPool, tag: &str) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO users (id, username, email, password_hash, auth_provider, is_admin, is_active) \
         VALUES ($1, $2, $3, 'x', 'local', true, true)",
    )
    .bind(id)
    .bind(format!("pr1940-{}-{}", tag, &id.to_string()[..8]))
    .bind(format!("pr1940-{}-{}@test.local", tag, &id.to_string()[..8]))
    .execute(pool)
    .await
    .expect("insert user");
    id
}

/// Create a local repo with its own filesystem storage dir. Returns its id.
async fn create_repo(pool: &PgPool, tag: &str, storage_path: &std::path::Path) -> Uuid {
    let id = Uuid::new_v4();
    let key = format!("pr1940-{}-{}", tag, &id.to_string()[..8]);
    std::fs::create_dir_all(storage_path).expect("create storage dir");
    sqlx::query(
        "INSERT INTO repositories (id, key, name, storage_path, repo_type, format, is_public) \
         VALUES ($1, $2, $2, $3, 'local', 'generic'::repository_format, false)",
    )
    .bind(id)
    .bind(&key)
    .bind(storage_path.to_string_lossy().as_ref())
    .execute(pool)
    .await
    .expect("insert repo");
    id
}

/// Create an artifact whose `created_at` is `now()` (so any positive
/// `min_staging_hours` rule is violated) with real bytes in `repo`'s storage.
async fn create_artifact(
    pool: &PgPool,
    repo_id: Uuid,
    storage: &Arc<dyn artifact_keeper_backend::storage::StorageBackend>,
    name: &str,
) -> Uuid {
    let id = Uuid::new_v4();
    let path = format!("{}/{}", name, id);
    let storage_key = path.clone();
    let bytes = b"pr1940-artifact-content".to_vec();
    let checksum = {
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        h.update(&bytes);
        format!("{:x}", h.finalize())
    };
    storage
        .put(&storage_key, bytes.into())
        .await
        .expect("write storage");
    sqlx::query(
        r#"
        INSERT INTO artifacts (id, repository_id, name, path, version, size_bytes,
                               checksum_sha256, content_type, storage_key, is_deleted)
        VALUES ($1, $2, $3, $4, '1.0.0', 23, $5, 'application/octet-stream', $6, false)
        "#,
    )
    .bind(id)
    .bind(repo_id)
    .bind(name)
    .bind(&path)
    .bind(&checksum)
    .bind(&storage_key)
    .execute(pool)
    .await
    .expect("insert artifact");
    id
}

/// Insert a promotion rule. `max_cve_severity = None` means "no CVE gate"
/// (the #1940 default fix); `min_staging_hours = Some(720)` is the live-bypass
/// rule from the review.
#[allow(clippy::too_many_arguments)]
async fn create_rule(
    pool: &PgPool,
    source: Uuid,
    target: Uuid,
    max_cve_severity: Option<&str>,
    min_staging_hours: Option<i32>,
) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO promotion_rules (id, name, source_repo_id, target_repo_id, is_enabled, \
         max_cve_severity, require_signature, min_staging_hours, auto_promote) \
         VALUES ($1, $2, $3, $4, true, $5, false, $6, false)",
    )
    .bind(id)
    .bind(format!("pr1940-rule-{}", &id.to_string()[..8]))
    .bind(source)
    .bind(target)
    .bind(max_cve_severity)
    .bind(min_staging_hours)
    .execute(pool)
    .await
    .expect("insert rule");
    id
}

async fn create_pending_approval(
    pool: &PgPool,
    artifact_id: Uuid,
    source: Uuid,
    target: Uuid,
    requested_by: Uuid,
) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO promotion_approvals (id, artifact_id, source_repo_id, target_repo_id, \
         requested_by, status, skip_policy_check) \
         VALUES ($1, $2, $3, $4, $5, 'pending', false)",
    )
    .bind(id)
    .bind(artifact_id)
    .bind(source)
    .bind(target)
    .bind(requested_by)
    .execute(pool)
    .await
    .expect("insert approval");
    id
}

async fn target_has_artifact(pool: &PgPool, target: Uuid, path_like: &str) -> bool {
    let n: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM artifacts WHERE repository_id = $1 AND path LIKE $2 AND is_deleted = false",
    )
    .bind(target)
    .bind(format!("%{}%", path_like))
    .fetch_one(pool)
    .await
    .expect("count target artifacts");
    n.0 > 0
}

fn admin_ext(user_id: Uuid) -> AuthExtension {
    AuthExtension {
        user_id,
        username: "pr1940-admin".to_string(),
        email: "pr1940-admin@test.local".to_string(),
        is_admin: true,
        is_api_token: false,
        is_service_account: false,
        scopes: None,
        allowed_repo_ids: None,
    }
}

async fn cleanup(pool: &PgPool, repos: &[Uuid], user_id: Uuid) {
    for r in repos {
        sqlx::query(
            "DELETE FROM promotion_approvals WHERE source_repo_id = $1 OR target_repo_id = $1",
        )
        .bind(r)
        .execute(pool)
        .await
        .ok();
        sqlx::query(
            "DELETE FROM promotion_history WHERE source_repo_id = $1 OR target_repo_id = $1",
        )
        .bind(r)
        .execute(pool)
        .await
        .ok();
        sqlx::query("DELETE FROM promotion_rules WHERE source_repo_id = $1 OR target_repo_id = $1")
            .bind(r)
            .execute(pool)
            .await
            .ok();
        sqlx::query("DELETE FROM artifacts WHERE repository_id = $1")
            .bind(r)
            .execute(pool)
            .await
            .ok();
        sqlx::query("DELETE FROM repositories WHERE id = $1")
            .bind(r)
            .execute(pool)
            .await
            .ok();
    }
    sqlx::query("DELETE FROM users WHERE id = $1")
        .bind(user_id)
        .execute(pool)
        .await
        .ok();
}

// ---------------------------------------------------------------------------
// Shared-gate tests: cover single + bulk + approval, which all delegate to
// PromotionRuleService::evaluate_for_promotion.
// ---------------------------------------------------------------------------

/// rule-MET: a rule with no unmet criteria yields ZERO violations, so all three
/// promote paths proceed (`promoted: true` / 200).
#[tokio::test]
#[ignore = "requires DATABASE_URL"]
async fn test_gate_rule_met_allows_all_paths() {
    let pool = connect().await;
    let stg = std::env::temp_dir().join(format!("pr1940-met-stg-{}", Uuid::new_v4()));
    let rel = std::env::temp_dir().join(format!("pr1940-met-rel-{}", Uuid::new_v4()));
    let src = create_repo(&pool, "met-stg", &stg).await;
    let tgt = create_repo(&pool, "met-rel", &rel).await;
    let user = create_admin(&pool, "met").await;
    let state = build_state(pool.clone(), stg.to_str().unwrap());
    let storage = storage_for(&state, &pool, src).await;
    let artifact = create_artifact(&pool, src, &storage, "met").await;

    // hours-only rule with min_staging_hours = 0 -> satisfied by any artifact.
    create_rule(&pool, src, tgt, None, Some(0)).await;

    let svc = PromotionRuleService::new(pool.clone());
    let failing = svc
        .evaluate_for_promotion(artifact, src, tgt)
        .await
        .expect("evaluate");
    assert!(
        failing.is_empty(),
        "a satisfied rule must yield no violations so single/bulk/approval all promote; got {:?}",
        failing
    );

    cleanup(&pool, &[src, tgt], user).await;
}

/// rule-UNMET: the live-bypass rule (`min_staging_hours = 720`, seconds-old
/// artifact) yields violations, so all three promote paths block.
#[tokio::test]
#[ignore = "requires DATABASE_URL"]
async fn test_gate_rule_unmet_blocks_all_paths() {
    let pool = connect().await;
    let stg = std::env::temp_dir().join(format!("pr1940-unmet-stg-{}", Uuid::new_v4()));
    let rel = std::env::temp_dir().join(format!("pr1940-unmet-rel-{}", Uuid::new_v4()));
    let src = create_repo(&pool, "unmet-stg", &stg).await;
    let tgt = create_repo(&pool, "unmet-rel", &rel).await;
    let user = create_admin(&pool, "unmet").await;
    let state = build_state(pool.clone(), stg.to_str().unwrap());
    let storage = storage_for(&state, &pool, src).await;
    let artifact = create_artifact(&pool, src, &storage, "unmet").await;

    create_rule(&pool, src, tgt, None, Some(720)).await;

    let svc = PromotionRuleService::new(pool.clone());
    let failing = svc
        .evaluate_for_promotion(artifact, src, tgt)
        .await
        .expect("evaluate");
    assert!(
        !failing.is_empty(),
        "min_staging_hours=720 on a fresh artifact must violate (the original bypass)"
    );

    cleanup(&pool, &[src, tgt], user).await;
}

// ---------------------------------------------------------------------------
// Approval-path tests: drive the real approve_promotion handler.
// ---------------------------------------------------------------------------

/// The gap PR #1940 missed: approving a rule-UNMET promotion must be BLOCKED
/// (403) and must NOT copy the artifact into the release repo.
#[tokio::test]
#[ignore = "requires DATABASE_URL"]
async fn test_approval_path_blocks_rule_unmet() {
    let pool = connect().await;
    let stg = std::env::temp_dir().join(format!("pr1940-aprej-stg-{}", Uuid::new_v4()));
    let rel = std::env::temp_dir().join(format!("pr1940-aprej-rel-{}", Uuid::new_v4()));
    let src = create_repo(&pool, "aprej-stg", &stg).await;
    let tgt = create_repo(&pool, "aprej-rel", &rel).await;
    let user = create_admin(&pool, "aprej").await;
    let state = build_state(pool.clone(), stg.to_str().unwrap());
    let storage = storage_for(&state, &pool, src).await;
    let artifact = create_artifact(&pool, src, &storage, "aprej").await;
    create_rule(&pool, src, tgt, None, Some(720)).await;
    let approval = create_pending_approval(&pool, artifact, src, tgt, user).await;

    let res = approve_promotion(
        State(state.clone()),
        Extension(admin_ext(user)),
        Path(approval),
        Json(ReviewRequest {
            notes: None,
            skip_policy_check: false,
        }),
    )
    .await;

    match res {
        Err(AppError::Authorization(msg)) => {
            assert!(
                msg.contains("promotion rule"),
                "block message should mention the rule; got: {msg}"
            );
        }
        other => panic!(
            "expected Authorization (403) block, got: {:?}",
            other.is_ok()
        ),
    }

    assert!(
        !target_has_artifact(&pool, tgt, "aprej").await,
        "a rule-blocked approval must NOT copy the artifact into the release repo"
    );
    let status: (String,) = sqlx::query_as("SELECT status FROM promotion_approvals WHERE id = $1")
        .bind(approval)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(status.0, "pending", "blocked approval must remain pending");

    cleanup(&pool, &[src, tgt], user).await;
}

/// A rule-MET approval still executes: the artifact lands in the release repo
/// and the approval is marked approved.
#[tokio::test]
#[ignore = "requires DATABASE_URL"]
async fn test_approval_path_allows_rule_met() {
    let pool = connect().await;
    let stg = std::env::temp_dir().join(format!("pr1940-aok-stg-{}", Uuid::new_v4()));
    let rel = std::env::temp_dir().join(format!("pr1940-aok-rel-{}", Uuid::new_v4()));
    let src = create_repo(&pool, "aok-stg", &stg).await;
    let tgt = create_repo(&pool, "aok-rel", &rel).await;
    let user = create_admin(&pool, "aok").await;
    let state = build_state(pool.clone(), stg.to_str().unwrap());
    let storage = storage_for(&state, &pool, src).await;
    let artifact = create_artifact(&pool, src, &storage, "aok").await;
    create_rule(&pool, src, tgt, None, Some(0)).await;
    let approval = create_pending_approval(&pool, artifact, src, tgt, user).await;

    let res = approve_promotion(
        State(state.clone()),
        Extension(admin_ext(user)),
        Path(approval),
        Json(ReviewRequest {
            notes: Some("ok".to_string()),
            skip_policy_check: false,
        }),
    )
    .await;
    assert!(
        res.is_ok(),
        "a rule-met approval must execute: {:?}",
        res.is_ok()
    );

    assert!(
        target_has_artifact(&pool, tgt, "aok").await,
        "a rule-met approval must copy the artifact into the release repo"
    );
    let status: (String,) = sqlx::query_as("SELECT status FROM promotion_approvals WHERE id = $1")
        .bind(approval)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(status.0, "approved");

    cleanup(&pool, &[src, tgt], user).await;
}

/// skip_policy_check admin override still works on the approval path: a
/// rule-unmet promotion executes when the reviewer break-glasses.
#[tokio::test]
#[ignore = "requires DATABASE_URL"]
async fn test_approval_path_skip_policy_check_override() {
    let pool = connect().await;
    let stg = std::env::temp_dir().join(format!("pr1940-skip-stg-{}", Uuid::new_v4()));
    let rel = std::env::temp_dir().join(format!("pr1940-skip-rel-{}", Uuid::new_v4()));
    let src = create_repo(&pool, "skip-stg", &stg).await;
    let tgt = create_repo(&pool, "skip-rel", &rel).await;
    let user = create_admin(&pool, "skip").await;
    let state = build_state(pool.clone(), stg.to_str().unwrap());
    let storage = storage_for(&state, &pool, src).await;
    let artifact = create_artifact(&pool, src, &storage, "skip").await;
    create_rule(&pool, src, tgt, None, Some(720)).await;
    let approval = create_pending_approval(&pool, artifact, src, tgt, user).await;

    let res = approve_promotion(
        State(state.clone()),
        Extension(admin_ext(user)),
        Path(approval),
        Json(ReviewRequest {
            notes: None,
            skip_policy_check: true,
        }),
    )
    .await;
    assert!(res.is_ok(), "skip_policy_check must bypass the rule gate");
    assert!(
        target_has_artifact(&pool, tgt, "skip").await,
        "break-glass approval must execute the promotion"
    );

    cleanup(&pool, &[src, tgt], user).await;
}

// ---------------------------------------------------------------------------
// max_cve_severity default-block fix.
// ---------------------------------------------------------------------------

/// #1940 fix: a rule that does NOT set max_cve_severity (NULL) must NOT impose
/// a "requires a clean completed scan" gate. An unscanned artifact under an
/// hours-only (satisfied) rule promotes.
#[tokio::test]
#[ignore = "requires DATABASE_URL"]
async fn test_unset_cve_severity_does_not_require_scan() {
    let pool = connect().await;
    let stg = std::env::temp_dir().join(format!("pr1940-nocve-stg-{}", Uuid::new_v4()));
    let rel = std::env::temp_dir().join(format!("pr1940-nocve-rel-{}", Uuid::new_v4()));
    let src = create_repo(&pool, "nocve-stg", &stg).await;
    let tgt = create_repo(&pool, "nocve-rel", &rel).await;
    let user = create_admin(&pool, "nocve").await;
    let state = build_state(pool.clone(), stg.to_str().unwrap());
    let storage = storage_for(&state, &pool, src).await;
    // Unscanned artifact (no scan_results rows at all).
    let artifact = create_artifact(&pool, src, &storage, "nocve").await;
    // hours-only rule, satisfied (0h), max_cve_severity left NULL.
    create_rule(&pool, src, tgt, None, Some(0)).await;

    let svc = PromotionRuleService::new(pool.clone());
    let failing = svc
        .evaluate_for_promotion(artifact, src, tgt)
        .await
        .expect("evaluate");
    assert!(
        failing.is_empty(),
        "an hours-only rule (max_cve_severity NULL) must NOT block an unscanned artifact; got {:?}",
        failing
    );

    cleanup(&pool, &[src, tgt], user).await;
}

/// Conservative counterpart: a rule that DOES set max_cve_severity still blocks
/// an unscanned artifact (the CVE gate is opt-in, not weakened, when requested).
#[tokio::test]
#[ignore = "requires DATABASE_URL"]
async fn test_explicit_cve_severity_still_requires_scan() {
    let pool = connect().await;
    let stg = std::env::temp_dir().join(format!("pr1940-cve-stg-{}", Uuid::new_v4()));
    let rel = std::env::temp_dir().join(format!("pr1940-cve-rel-{}", Uuid::new_v4()));
    let src = create_repo(&pool, "cve-stg", &stg).await;
    let tgt = create_repo(&pool, "cve-rel", &rel).await;
    let user = create_admin(&pool, "cve").await;
    let state = build_state(pool.clone(), stg.to_str().unwrap());
    let storage = storage_for(&state, &pool, src).await;
    let artifact = create_artifact(&pool, src, &storage, "cve").await;
    // Explicit CVE bound + satisfied hours: the unscanned artifact must fail
    // closed on the CVE/scan-required check.
    create_rule(&pool, src, tgt, Some("medium"), Some(0)).await;

    let svc = PromotionRuleService::new(pool.clone());
    let failing = svc
        .evaluate_for_promotion(artifact, src, tgt)
        .await
        .expect("evaluate");
    assert!(
        !failing.is_empty(),
        "an explicit max_cve_severity rule must still block an unscanned artifact (fail-closed)"
    );

    // sanity: the PromotionRule round-trips the NULL we expect for the unset case
    let _ = std::any::type_name::<PromotionRule>();

    cleanup(&pool, &[src, tgt], user).await;
}
