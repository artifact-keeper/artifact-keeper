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
use chrono::{Duration, Utc};
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
    let key = format!("age-gate-npm-{suffix}");
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
        RepositoryType::Remote,
        RepositoryFormat::Npm,
        true,
        min_age_days,
    )
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

    let reviewer = Uuid::new_v4();
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
