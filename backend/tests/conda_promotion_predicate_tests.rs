//! Integration target: conda policy-predicate enforcement on the promotion
//! gate (#4158, covering #4147's fix).
//!
//! Verified against a live deployment before #4147: a `scan_policies` row
//! carrying `predicates.conda.allowed_channels` blocked the artifact's
//! DOWNLOAD but waved it through a PROMOTION with `policy_violations: []` —
//! the promotion gate enforced the row's `max_severity` and never looked at
//! its `predicates` block, so the gate ran and only the predicate half was
//! inert. These tests drive `PromotionPolicyService::evaluate_artifact` —
//! the exact call the promotion handler makes with `skip_policy_check:
//! false` — through the public API, against a real database, because "the
//! predicate logic is right" was never the thing in doubt; "this gate
//! reaches the predicate logic at all" was.
//!
//! DB-gated: run under `--run-ignored ignored-only` with `DATABASE_URL` and
//! `AK_TESTS_REQUIRE_DB=1`.

mod common;

use sqlx::PgPool;
use uuid::Uuid;

use artifact_keeper_backend::models::sbom::PolicyAction;
use artifact_keeper_backend::services::promotion_policy_service::PromotionPolicyService;
use common::conda_support as cs;

/// A conda-format repository.
async fn seed_conda_repo(pool: &PgPool) -> (Uuid, String) {
    let id = Uuid::new_v4();
    let key = format!("conda-promo-{}", &id.to_string()[..8]);
    sqlx::query(
        "INSERT INTO repositories (id, key, name, storage_path, repo_type, format) \
         VALUES ($1, $2, $3, $4, 'local', 'conda')",
    )
    .bind(id)
    .bind(&key)
    .bind(&key)
    .bind(format!("/tmp/conda-promo-{}", id))
    .execute(pool)
    .await
    .expect("insert conda repo");
    (id, key)
}

/// A conda artifact plus the `artifact_metadata` row ingest writes. `channel`
/// is the `channel` qualifier of the identity purl; `None` records no
/// identity block at all, i.e. an unknown channel of origin.
async fn seed_conda_artifact(pool: &PgPool, repo: Uuid, channel: Option<&str>) -> Uuid {
    let path = format!(
        "linux-64/pkg-{}-1.0.0-py311_0.conda",
        Uuid::new_v4().as_simple()
    );
    let artifact = sqlx::query_scalar::<_, Uuid>(
        "INSERT INTO artifacts \
            (repository_id, path, name, version, size_bytes, checksum_sha256, \
             content_type, storage_key) \
         VALUES ($1, $2, $2, '1.0.0', 1, repeat('a', 64), \
                 'application/octet-stream', $2) \
         RETURNING id",
    )
    .bind(repo)
    .bind(&path)
    .fetch_one(pool)
    .await
    .expect("insert conda artifact");

    let metadata = match channel {
        Some(c) => serde_json::json!({
            "license": "MIT",
            "identity": {
                "purl": format!(
                    "pkg:conda/pkg@1.0.0?build=py311_0&channel={c}&subdir=linux-64&type=conda"
                )
            }
        }),
        None => serde_json::json!({ "license": "MIT" }),
    };
    sqlx::query(
        "INSERT INTO artifact_metadata (artifact_id, format, metadata) VALUES ($1, 'conda', $2)",
    )
    .bind(artifact)
    .bind(&metadata)
    .execute(pool)
    .await
    .expect("insert conda artifact_metadata");
    artifact
}

/// A repository-scoped, enabled policy carrying only a predicate document.
/// `max_severity` is `critical` and every legacy gate is off, so anything
/// this policy reports can only have come from `predicates`.
async fn seed_predicate_policy(pool: &PgPool, repo: Uuid, predicates: serde_json::Value) {
    sqlx::query(
        "INSERT INTO scan_policies \
            (name, repository_id, max_severity, block_unscanned, block_on_fail, \
             is_enabled, require_signature, predicates) \
         VALUES ($1, $2, 'critical', false, false, true, false, $3)",
    )
    .bind(format!("promo-predicates-{repo}"))
    .bind(repo)
    .bind(&predicates)
    .execute(pool)
    .await
    .expect("insert predicate policy");
}

/// The promotion gate enforces the conda channel allowlist: an unlisted
/// channel blocks, an allowlisted channel promotes, and an UNKNOWN channel
/// of origin fails the allowlist closed (it must not resolve to the
/// repository key).
#[tokio::test]
#[ignore]
async fn promotion_gate_enforces_conda_channel_allowlist() {
    let pool = cs::require_pool().await;
    let svc = PromotionPolicyService::new(pool.clone());
    let (repo, _key) = seed_conda_repo(&pool).await;
    seed_predicate_policy(
        &pool,
        repo,
        serde_json::json!({ "conda": { "allowed_channels": ["trusted-channel"] } }),
    )
    .await;

    let unlisted = seed_conda_artifact(&pool, repo, Some("evil-channel")).await;
    let allowed = seed_conda_artifact(&pool, repo, Some("trusted-channel")).await;
    let unknown = seed_conda_artifact(&pool, repo, None).await;

    let unlisted_result = svc
        .evaluate_artifact(unlisted, repo)
        .await
        .expect("evaluate unlisted");
    let allowed_result = svc
        .evaluate_artifact(allowed, repo)
        .await
        .expect("evaluate allowed");
    let unknown_result = svc
        .evaluate_artifact(unknown, repo)
        .await
        .expect("evaluate unknown-channel");

    cs::cleanup_repo(&pool, repo).await;

    assert!(
        !unlisted_result.passed,
        "an unlisted channel must block a promotion, got: {:?}",
        unlisted_result.violations
    );
    assert_eq!(
        unlisted_result.action,
        PolicyAction::Block,
        "a predicate violation must escalate the promotion action to Block"
    );
    assert!(
        unlisted_result.violations.iter().any(|v| {
            v.rule == "policy-predicate"
                && v.message.contains("[conda.channel]")
                && v.message.contains("evil-channel")
        }),
        "the promotion decision must record the fired predicate, got: {:?}",
        unlisted_result.violations
    );

    assert!(
        allowed_result.passed,
        "an allowlisted channel must still promote, got: {:?}",
        allowed_result.violations
    );

    assert!(
        !unknown_result.passed
            && unknown_result
                .violations
                .iter()
                .any(|v| v.message.contains("[conda.channel]") && v.message.contains("unknown")),
        "an unknown channel of origin must fail the allowlist closed on the \
         promotion path too, got: {:?}",
        unknown_result.violations
    );
}

/// The denylist half: `denied_channels` naming the declared channel and
/// `denied_licenses` naming the package's license both fire on the promotion
/// path.
#[tokio::test]
#[ignore]
async fn promotion_gate_enforces_conda_denylists() {
    let pool = cs::require_pool().await;
    let svc = PromotionPolicyService::new(pool.clone());
    let (repo, _key) = seed_conda_repo(&pool).await;
    seed_predicate_policy(
        &pool,
        repo,
        serde_json::json!({
            "conda": {
                "denied_channels": ["untrusted-channel"],
                "denied_licenses": ["mit"]
            }
        }),
    )
    .await;

    let artifact = seed_conda_artifact(&pool, repo, Some("untrusted-channel")).await;
    let result = svc
        .evaluate_artifact(artifact, repo)
        .await
        .expect("evaluate denied");

    cs::cleanup_repo(&pool, repo).await;

    assert!(
        !result.passed,
        "a denied channel must block a promotion, got: {:?}",
        result.violations
    );
    assert!(
        result
            .violations
            .iter()
            .any(|v| v.message.contains("[conda.channel]")),
        "the channel denylist must fire on the promotion path, got: {:?}",
        result.violations
    );
    assert!(
        result
            .violations
            .iter()
            .any(|v| v.message.contains("[conda.license]")),
        "the license denylist must fire on the promotion path, got: {:?}",
        result.violations
    );
}

/// A policy with no predicate document must behave exactly as before: the
/// predicate path adds nothing and costs no violation.
#[tokio::test]
#[ignore]
async fn promotion_gate_is_unchanged_without_predicates() {
    let pool = cs::require_pool().await;
    let svc = PromotionPolicyService::new(pool.clone());
    let (repo, _key) = seed_conda_repo(&pool).await;
    seed_predicate_policy(&pool, repo, serde_json::json!({})).await;

    let artifact = seed_conda_artifact(&pool, repo, None).await;
    let result = svc
        .evaluate_artifact(artifact, repo)
        .await
        .expect("evaluate predicate-free");

    cs::cleanup_repo(&pool, repo).await;

    assert!(
        result.passed,
        "a predicate-free policy must not block, got: {:?}",
        result.violations
    );
    assert_eq!(result.action, PolicyAction::Allow);
}
