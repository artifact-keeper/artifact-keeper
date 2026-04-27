//! Integration test: posting the same virtual-repo member twice must
//! produce HTTP 409 Conflict, not a generic 500.
//!
//! This test exercises the live end-to-end mapping of the Postgres
//! `unique_violation` (SQLSTATE 23505) on the
//! `virtual_repo_members_virtual_repo_id_member_repo_id_key` constraint
//! through `RepositoryService::add_virtual_member` and through the
//! `AppError -> IntoResponse` conversion that the HTTP handler uses.
//!
//! Requires a PostgreSQL database with migrations applied. Run with:
//!
//! ```sh
//! DATABASE_URL="postgresql://registry:registry@localhost:30432/artifact_registry" \
//!   cargo test --test virtual_members_duplicate_test -- --ignored
//! ```
//!
//! Companion to PR #936 / issue #916.

use axum::http::StatusCode;
use axum::response::IntoResponse;
use serde_json::Value;
use sqlx::PgPool;
use uuid::Uuid;

use artifact_keeper_backend::services::repository_service::RepositoryService;
use artifact_keeper_backend::AppError;

/// Insert a minimal `repositories` row directly via SQL so the test does
/// not depend on the higher-level create-repository flow (which has its
/// own validation, scope, and storage-provisioning concerns).
async fn insert_repo(pool: &PgPool, key: &str, repo_type: &str, format: &str) -> Uuid {
    let id = Uuid::new_v4();
    let storage_path = format!("/tmp/test-artifacts/{}", id);
    sqlx::query(
        r#"
        INSERT INTO repositories (id, key, name, format, repo_type, storage_path)
        VALUES ($1, $2, $2, $3::repository_format, $4::repository_type, $5)
        "#,
    )
    .bind(id)
    .bind(key)
    .bind(format)
    .bind(repo_type)
    .bind(&storage_path)
    .execute(pool)
    .await
    .expect("failed to insert test repository");
    id
}

async fn cleanup(pool: &PgPool, virtual_id: Uuid, member_id: Uuid) {
    sqlx::query("DELETE FROM virtual_repo_members WHERE virtual_repo_id = $1")
        .bind(virtual_id)
        .execute(pool)
        .await
        .ok();
    sqlx::query("DELETE FROM repositories WHERE id IN ($1, $2)")
        .bind(virtual_id)
        .bind(member_id)
        .execute(pool)
        .await
        .ok();
}

#[tokio::test]
#[ignore]
async fn duplicate_add_virtual_member_returns_conflict_not_500() {
    let database_url = std::env::var("DATABASE_URL")
        .expect("DATABASE_URL must be set to run this integration test");
    let pool = PgPool::connect(&database_url)
        .await
        .expect("failed to connect to database");

    // Use unique keys per run so concurrent test sessions don't collide.
    let suffix = Uuid::new_v4();
    let virtual_key = format!("test-virt-{}", suffix);
    let member_key = format!("test-member-{}", suffix);

    let virtual_id = insert_repo(&pool, &virtual_key, "virtual", "generic").await;
    let member_id = insert_repo(&pool, &member_key, "local", "generic").await;

    let svc = RepositoryService::new(pool.clone());

    // First insert succeeds.
    svc.add_virtual_member(virtual_id, member_id, 1)
        .await
        .expect("first add_virtual_member must succeed");

    // Second insert must produce AppError::Conflict (NOT Database/500).
    let err = svc
        .add_virtual_member(virtual_id, member_id, 2)
        .await
        .expect_err("second add_virtual_member must fail");

    let conflict_msg = match &err {
        AppError::Conflict(msg) => msg.clone(),
        other => {
            cleanup(&pool, virtual_id, member_id).await;
            panic!("expected AppError::Conflict on duplicate member insert, got {other:?}");
        }
    };
    assert!(
        conflict_msg.contains(&member_key) && conflict_msg.contains(&virtual_key),
        "conflict message should reference both repos: {conflict_msg}"
    );

    // Round-trip through the HTTP response layer to lock the wire shape:
    //   status: 409
    //   body:   { "code": "CONFLICT", "message": "..." }
    let response = err.into_response();
    assert_eq!(response.status(), StatusCode::CONFLICT);

    let body_bytes = axum::body::to_bytes(response.into_body(), 64 * 1024)
        .await
        .expect("failed to read response body");
    let body: Value =
        serde_json::from_slice(&body_bytes).expect("response body must be valid JSON");
    assert_eq!(body.get("code").and_then(Value::as_str), Some("CONFLICT"));
    let message = body
        .get("message")
        .and_then(Value::as_str)
        .expect("response body must include a message");
    assert!(
        message.contains(&member_key) && message.contains(&virtual_key),
        "response message should reference both repos: {message}"
    );

    cleanup(&pool, virtual_id, member_id).await;
}
