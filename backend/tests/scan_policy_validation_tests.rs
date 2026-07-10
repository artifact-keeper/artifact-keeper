//! Integration tests for scan-policy create/update input validation (#2320).
//!
//! `POST /api/v1/security/policies` used to forward `max_severity` and
//! `repository_id` straight into the INSERT, so a mis-cased severity
//! ("Critical") or an unknown repository id tripped the DB CHECK / FK
//! constraint and surfaced as an opaque `500 DATABASE_ERROR`. These tests pin
//! the fixed contract: bad input is a 4xx (400 validation / 404 not-found),
//! mis-cased-but-known severities are canonicalized, and valid requests keep
//! succeeding.
//!
//! Requires PostgreSQL:
//!   DATABASE_URL=postgresql://registry:registry@localhost:5432/artifact_registry \
//!     cargo test --test scan_policy_validation_tests -- --ignored

use artifact_keeper_backend::error::AppError;
use artifact_keeper_backend::services::policy_service::PolicyService;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use sqlx::PgPool;
use uuid::Uuid;

async fn connect_db() -> PgPool {
    let url = std::env::var("DATABASE_URL")
        .expect("DATABASE_URL must be set; see module docstring for setup");
    PgPool::connect(&url)
        .await
        .expect("failed to connect to test database")
}

/// Insert a minimal repository row so repo-scoped policies have a real FK
/// target. The random id keeps the unique `repositories.key` constraint from
/// colliding with rows left behind by a previous (uncleaned) test run.
async fn create_repo(pool: &PgPool) -> Uuid {
    let id = Uuid::new_v4();
    let key = format!("scan-policy-val-{id}");
    sqlx::query(
        "INSERT INTO repositories (id, key, name, storage_path, repo_type, format)
         VALUES ($1, $2, $2, $3, 'local', 'npm')",
    )
    .bind(id)
    .bind(&key)
    .bind(format!("/tmp/test-artifacts/{id}"))
    .execute(pool)
    .await
    .expect("insert repo");
    id
}

async fn delete_repo(pool: &PgPool, id: Uuid) {
    // scan_policies.repository_id is ON DELETE CASCADE, so this also removes
    // any policies the test created against the repo.
    sqlx::query("DELETE FROM repositories WHERE id = $1")
        .bind(id)
        .execute(pool)
        .await
        .expect("delete repo");
}

async fn delete_policy(pool: &PgPool, id: Uuid) {
    sqlx::query("DELETE FROM scan_policies WHERE id = $1")
        .bind(id)
        .execute(pool)
        .await
        .expect("delete policy");
}

/// The HTTP status the error maps to via the real `IntoResponse` conversion —
/// what a client of `POST /api/v1/security/policies` actually observes.
fn status_of(err: AppError) -> StatusCode {
    err.into_response().status()
}

#[tokio::test]
#[ignore] // requires DATABASE_URL
async fn test_create_policy_invalid_max_severity_is_400_not_500() {
    let pool = connect_db().await;
    let svc = PolicyService::new(pool);

    let err = svc
        .create_policy(
            &format!("bad-severity-{}", Uuid::new_v4()),
            None,
            "severe", // not in {critical, high, medium, low}
            true,
            false,
            None,
            None,
            false,
        )
        .await
        .expect_err("unknown max_severity must be rejected");

    assert!(
        matches!(err, AppError::Validation(_)),
        "expected AppError::Validation, got: {err:?}"
    );
    assert_eq!(
        status_of(err),
        StatusCode::BAD_REQUEST,
        "#2320: invalid max_severity must surface as 400, not 500 DATABASE_ERROR"
    );
}

#[tokio::test]
#[ignore] // requires DATABASE_URL
async fn test_create_policy_miscased_max_severity_is_canonicalized() {
    let pool = connect_db().await;
    let svc = PolicyService::new(pool.clone());

    // #2320 regression: "Critical" used to violate the lowercase CHECK
    // constraint and return 500. It must now succeed and store canonical
    // lowercase.
    let policy = svc
        .create_policy(
            &format!("miscased-severity-{}", Uuid::new_v4()),
            None,
            "Critical",
            true,
            false,
            None,
            None,
            false,
        )
        .await
        .expect("mis-cased but known max_severity must be accepted");

    assert_eq!(policy.max_severity, "critical");
    delete_policy(&pool, policy.id).await;
}

#[tokio::test]
#[ignore] // requires DATABASE_URL
async fn test_create_policy_unknown_repository_is_404_not_500() {
    let pool = connect_db().await;
    let svc = PolicyService::new(pool);

    let err = svc
        .create_policy(
            &format!("bad-repo-{}", Uuid::new_v4()),
            Some(Uuid::new_v4()), // no such repository
            "high",
            true,
            false,
            None,
            None,
            false,
        )
        .await
        .expect_err("nonexistent repository_id must be rejected");

    assert!(
        matches!(err, AppError::NotFound(_)),
        "expected AppError::NotFound, got: {err:?}"
    );
    assert_eq!(
        status_of(err),
        StatusCode::NOT_FOUND,
        "#2320: unknown repository_id must surface as 404, not 500 (FK violation)"
    );
}

#[tokio::test]
#[ignore] // requires DATABASE_URL
async fn test_create_policy_valid_request_still_succeeds() {
    let pool = connect_db().await;
    let svc = PolicyService::new(pool.clone());
    let repo_id = create_repo(&pool).await;

    let policy = svc
        .create_policy(
            &format!("valid-policy-{}", Uuid::new_v4()),
            Some(repo_id),
            "medium",
            true,
            true,
            Some(24),
            Some(365),
            false,
        )
        .await
        .expect("a fully valid create must keep working unchanged");

    assert_eq!(policy.repository_id, Some(repo_id));
    assert_eq!(policy.max_severity, "medium");
    assert!(policy.block_unscanned);
    assert!(policy.block_on_fail);
    assert_eq!(policy.min_staging_hours, Some(24));
    assert_eq!(policy.max_artifact_age_days, Some(365));

    delete_repo(&pool, repo_id).await;
}

#[tokio::test]
#[ignore] // requires DATABASE_URL
async fn test_update_policy_miscased_max_severity_is_canonicalized() {
    let pool = connect_db().await;
    let svc = PolicyService::new(pool.clone());

    let policy = svc
        .create_policy(
            &format!("update-severity-{}", Uuid::new_v4()),
            None,
            "low",
            true,
            false,
            None,
            None,
            false,
        )
        .await
        .expect("create baseline policy");

    // Same normalization on the update path: "HIGH" used to trip the CHECK
    // constraint (500); it must now canonicalize and persist.
    let updated = svc
        .update_policy(
            policy.id,
            None,
            Some("HIGH"),
            None,
            None,
            None,
            None,
            None,
            None,
        )
        .await
        .expect("mis-cased but known max_severity must be accepted on update");
    assert_eq!(updated.max_severity, "high");

    let err = svc
        .update_policy(
            policy.id,
            None,
            Some("bogus"),
            None,
            None,
            None,
            None,
            None,
            None,
        )
        .await
        .expect_err("unknown max_severity must be rejected on update");
    assert_eq!(status_of(err), StatusCode::BAD_REQUEST);

    delete_policy(&pool, policy.id).await;
}
