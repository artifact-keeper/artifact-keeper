//! Integration tests for the age-based proxy quality gate.
//!
//! Requires PostgreSQL:
//!   DATABASE_URL=postgresql://registry:registry@localhost:30432/artifact_registry \
//!     cargo test --test age_gate_tests -- --ignored

use artifact_keeper_backend::models::repository::{RepositoryFormat, RepositoryType};
use artifact_keeper_backend::services::age_gate_service::{
    AgeGateDecision, AgeGateRepoParams, AgeGateService, AUTO_APPROVE_REASON,
};
use artifact_keeper_backend::services::event_bus::EventBus;
use chrono::{DateTime, Duration, Utc};
use sqlx::{PgPool, Row};
use std::sync::Arc;
use uuid::Uuid;

async fn connect_db() -> PgPool {
    let url = std::env::var("DATABASE_URL")
        .expect("DATABASE_URL must be set; see module docstring for setup");
    PgPool::connect(&url)
        .await
        .expect("failed to connect to test database")
}

async fn create_remote_npm_repo(pool: &PgPool, suffix: &str, min_age_days: i32) -> Uuid {
    let id = Uuid::new_v4();
    // Include the random id so the unique `repositories.key` constraint does not
    // collide with rows left behind by a previous (uncleaned) test run, keeping
    // these `--ignored` integration tests repeatable.
    let key = format!("age-gate-npm-{suffix}-{id}");
    sqlx::query(
        "INSERT INTO repositories (id, key, name, storage_path, repo_type, format, upstream_url, age_gate_enabled, age_gate_min_age_days)
         VALUES ($1, $2, $2, $3, 'remote', 'npm', 'https://registry.npmjs.org', true, $4)",
    )
    .bind(id)
    .bind(&key)
    .bind(format!("/tmp/test-artifacts/{id}"))
    .bind(min_age_days)
    .execute(pool)
    .await
    .expect("insert repo");
    id
}

fn npm_repo_params(id: Uuid, min_age_days: i32) -> AgeGateRepoParams {
    AgeGateRepoParams::from_parts(
        id,
        "age-gate-npm",
        RepositoryType::Remote,
        RepositoryFormat::Npm,
        true,
        min_age_days,
    )
}

async fn create_reviewer(pool: &PgPool) -> Uuid {
    let id = Uuid::new_v4();
    let username = format!("age-gate-reviewer-{id}");
    let email = format!("{username}@test.local");
    sqlx::query(
        "INSERT INTO users (id, username, email, password_hash, auth_provider, is_admin, is_active)
         VALUES ($1, $2, $3, 'unused', 'local', true, true)",
    )
    .bind(id)
    .bind(&username)
    .bind(&email)
    .execute(pool)
    .await
    .expect("insert reviewer");
    id
}

async fn insert_pending_review(
    pool: &PgPool,
    repo_id: Uuid,
    package: &str,
    version: &str,
    published_at: Option<DateTime<Utc>>,
) {
    sqlx::query(
        "INSERT INTO age_gate_reviews (repository_id, package_name, package_version, upstream_published_at, status)
         VALUES ($1, $2, $3, $4, 'pending')",
    )
    .bind(repo_id)
    .bind(package)
    .bind(version)
    .bind(published_at)
    .execute(pool)
    .await
    .expect("insert pending review");
}

async fn review_status(pool: &PgPool, repo_id: Uuid, package: &str, version: &str) -> String {
    let status: String = sqlx::query_scalar(
        "SELECT status FROM age_gate_reviews WHERE repository_id = $1 AND package_name = $2 AND package_version = $3",
    )
    .bind(repo_id)
    .bind(package)
    .bind(version)
    .fetch_one(pool)
    .await
    .expect("review status");
    status
}

fn young_packument(version: &str, published_at: &str) -> serde_json::Value {
    serde_json::json!({
        "name": "debounce-pkg",
        "dist-tags": { "latest": version },
        "versions": { version: { "name": "debounce-pkg", "version": version } },
        "time": { version: published_at },
    })
}

#[tokio::test]
#[ignore = "requires DATABASE_URL; run with --ignored"]
async fn young_version_is_blocked_and_queued() {
    let pool = connect_db().await;
    let bus = Arc::new(EventBus::new(16));
    let svc = AgeGateService::new(pool.clone(), bus);
    let repo_id = create_remote_npm_repo(&pool, "young", 7).await;
    let params = npm_repo_params(repo_id, 7);

    let published = Utc::now() - Duration::days(1);
    let decision = svc
        .check(&params, "lodash", "4.18.2", Some(published))
        .await
        .expect("check");

    match decision {
        AgeGateDecision::Block { review_id, .. } => {
            let review = svc.get_review_by_id(review_id).await.expect("review");
            assert_eq!(review.status, "pending");
            assert_eq!(review.package_name, "lodash");
        }
        AgeGateDecision::Allow => panic!("expected block for young version"),
    }
}

#[tokio::test]
#[ignore = "requires DATABASE_URL; run with --ignored"]
async fn lazy_auto_approve_after_threshold() {
    let pool = connect_db().await;
    let bus = Arc::new(EventBus::new(16));
    let svc = AgeGateService::new(pool.clone(), bus);
    let repo_id = create_remote_npm_repo(&pool, "auto", 7).await;
    let params = npm_repo_params(repo_id, 7);

    let young = Utc::now() - Duration::days(1);
    assert!(matches!(
        svc.check(&params, "express", "4.18.2", Some(young))
            .await
            .expect("first check"),
        AgeGateDecision::Block { .. }
    ));

    let old = Utc::now() - Duration::days(10);
    assert!(matches!(
        svc.check(&params, "express", "4.18.2", Some(old))
            .await
            .expect("second check"),
        AgeGateDecision::Allow
    ));

    let review = sqlx::query(
        "SELECT status, review_reason FROM age_gate_reviews WHERE repository_id = $1 AND package_name = 'express' AND package_version = '4.18.2'",
    )
    .bind(repo_id)
    .fetch_one(&pool)
    .await
    .expect("review row");
    let status: String = review.get("status");
    let review_reason: Option<String> = review.get("review_reason");
    assert_eq!(status, "approved");
    assert_eq!(review_reason.as_deref(), Some(AUTO_APPROVE_REASON));
}

#[tokio::test]
#[ignore = "requires DATABASE_URL; run with --ignored"]
async fn rejected_review_stays_blocked_after_threshold() {
    let pool = connect_db().await;
    let bus = Arc::new(EventBus::new(16));
    let svc = AgeGateService::new(pool.clone(), bus);
    let repo_id = create_remote_npm_repo(&pool, "reject", 7).await;
    let params = npm_repo_params(repo_id, 7);

    let young = Utc::now() - Duration::days(1);
    let decision = svc
        .check(&params, "left-pad", "1.0.0", Some(young))
        .await
        .expect("check");
    let review_id = match decision {
        AgeGateDecision::Block { review_id, .. } => review_id,
        AgeGateDecision::Allow => panic!("expected block"),
    };

    let reviewer = create_reviewer(&pool).await;
    svc.reject(review_id, reviewer, Some("too risky"))
        .await
        .expect("reject");

    let old = Utc::now() - Duration::days(30);
    assert!(matches!(
        svc.check(&params, "left-pad", "1.0.0", Some(old))
            .await
            .expect("recheck"),
        AgeGateDecision::Block { .. }
    ));
}

#[tokio::test]
#[ignore = "requires DATABASE_URL; run with --ignored"]
async fn per_repo_threshold_is_respected() {
    let pool = connect_db().await;
    let bus = Arc::new(EventBus::new(16));
    let svc = AgeGateService::new(pool.clone(), bus);
    let repo7 = create_remote_npm_repo(&pool, "d7", 7).await;
    let repo15 = create_remote_npm_repo(&pool, "d15", 15).await;

    let published = Utc::now() - Duration::days(10);
    assert!(matches!(
        svc.check(&npm_repo_params(repo7, 7), "pkg", "1.0.0", Some(published))
            .await
            .expect("repo7"),
        AgeGateDecision::Allow
    ));
    assert!(matches!(
        svc.check(
            &npm_repo_params(repo15, 15),
            "pkg",
            "1.0.0",
            Some(published)
        )
        .await
        .expect("repo15"),
        AgeGateDecision::Block { .. }
    ));
}

#[tokio::test]
#[ignore = "requires DATABASE_URL; run with --ignored"]
async fn scheduler_sweep_auto_approves_only_aged_pending_reviews() {
    let pool = connect_db().await;
    let bus = Arc::new(EventBus::new(16));
    let svc = AgeGateService::new(pool.clone(), bus);
    let repo_id = create_remote_npm_repo(&pool, "sweep", 7).await;

    // Aged pending review: the sweep should approve it.
    insert_pending_review(
        &pool,
        repo_id,
        "aged-pkg",
        "1.0.0",
        Some(Utc::now() - Duration::days(30)),
    )
    .await;
    // Young pending review: still under threshold, must stay pending.
    insert_pending_review(
        &pool,
        repo_id,
        "young-pkg",
        "2.0.0",
        Some(Utc::now() - Duration::days(1)),
    )
    .await;
    // No upstream timestamp: age cannot be proven, must stay pending (fail closed).
    insert_pending_review(&pool, repo_id, "notime-pkg", "3.0.0", None).await;

    let approved = svc.auto_approve_aged_reviews().await.expect("sweep");
    assert!(
        approved >= 1,
        "expected the sweep to approve at least the aged review"
    );

    assert_eq!(
        review_status(&pool, repo_id, "aged-pkg", "1.0.0").await,
        "approved"
    );
    assert_eq!(
        review_status(&pool, repo_id, "young-pkg", "2.0.0").await,
        "pending"
    );
    assert_eq!(
        review_status(&pool, repo_id, "notime-pkg", "3.0.0").await,
        "pending"
    );
}

#[tokio::test]
#[ignore = "requires DATABASE_URL; run with --ignored"]
async fn metadata_filter_debounces_request_count() {
    let pool = connect_db().await;
    let bus = Arc::new(EventBus::new(16));
    let svc = AgeGateService::new(pool.clone(), bus);
    let repo_id = create_remote_npm_repo(&pool, "debounce", 7).await;
    let params = npm_repo_params(repo_id, 7);

    let young = (Utc::now() - Duration::days(1)).to_rfc3339();

    // First listing creates the pending review (request_count = 1) and withholds 1.0.0.
    let mut p1 = young_packument("1.0.0", &young);
    svc.filter_npm_packument(&params, "debounce-pkg", &mut p1)
        .await
        .expect("filter 1");
    assert!(
        p1["versions"].get("1.0.0").is_none(),
        "young version must be withheld from the listing"
    );

    // Second listing within the debounce window must NOT re-bump request_count.
    let mut p2 = young_packument("1.0.0", &young);
    svc.filter_npm_packument(&params, "debounce-pkg", &mut p2)
        .await
        .expect("filter 2");
    assert!(
        p2["versions"].get("1.0.0").is_none(),
        "young version must still be withheld"
    );

    let count: i32 = sqlx::query_scalar(
        "SELECT request_count FROM age_gate_reviews WHERE repository_id = $1 AND package_name = 'debounce-pkg' AND package_version = '1.0.0'",
    )
    .bind(repo_id)
    .fetch_one(&pool)
    .await
    .expect("request_count");
    assert_eq!(
        count, 1,
        "request_count must be debounced (not bumped on the second listing within the window)"
    );
}
