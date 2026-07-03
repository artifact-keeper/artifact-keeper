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

#![allow(clippy::disallowed_methods)] // streaming-invariant: test file exempt — buffering response bodies in test assertions is not an artifact path (#1608)
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
    svc.add_virtual_member(virtual_id, member_id, Some(1))
        .await
        .expect("first add_virtual_member must succeed");

    // Second insert must produce AppError::Conflict (NOT Database/500).
    let err = svc
        .add_virtual_member(virtual_id, member_id, Some(2))
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

/// ak-jhdq: when two concurrent POSTs to `add_virtual_member` arrive
/// with `priority = None`, the service must assign distinct priorities,
/// not the same MAX+1 value. The advisory lock taken inside the service
/// transaction serialises the MAX read with the INSERT.
#[tokio::test]
#[ignore]
async fn concurrent_add_virtual_member_assigns_distinct_priorities() {
    let database_url = std::env::var("DATABASE_URL")
        .expect("DATABASE_URL must be set to run this integration test");
    let pool = PgPool::connect(&database_url)
        .await
        .expect("failed to connect to database");

    let suffix = Uuid::new_v4();
    let virtual_key = format!("test-virt-race-{}", suffix);
    let member_a_key = format!("test-member-a-{}", suffix);
    let member_b_key = format!("test-member-b-{}", suffix);

    let virtual_id = insert_repo(&pool, &virtual_key, "virtual", "generic").await;
    let member_a = insert_repo(&pool, &member_a_key, "local", "generic").await;
    let member_b = insert_repo(&pool, &member_b_key, "local", "generic").await;

    let svc_a = RepositoryService::new(pool.clone());
    let svc_b = RepositoryService::new(pool.clone());

    // Two concurrent auto-priority adds: each computes MAX(priority)+1
    // inside the same advisory-locked tx, so the second one must observe
    // the first one's INSERT and assign the next value.
    let (a_res, b_res) = tokio::join!(
        svc_a.add_virtual_member(virtual_id, member_a, None),
        svc_b.add_virtual_member(virtual_id, member_b, None),
    );

    let a_prio = a_res.expect("add member a");
    let b_prio = b_res.expect("add member b");

    assert_ne!(
        a_prio, b_prio,
        "concurrent auto-priority inserts must produce distinct priorities"
    );
    let mut prios = [a_prio, b_prio];
    prios.sort();
    assert_eq!(
        prios,
        [1, 2],
        "first auto-priority is 1, second is 2, even under contention"
    );

    sqlx::query("DELETE FROM virtual_repo_members WHERE virtual_repo_id = $1")
        .bind(virtual_id)
        .execute(&pool)
        .await
        .ok();
    sqlx::query("DELETE FROM repositories WHERE id = ANY($1)")
        .bind(&[virtual_id, member_a, member_b][..])
        .execute(&pool)
        .await
        .ok();
}

/// Count the members of a virtual repository.
async fn member_count(pool: &PgPool, virtual_id: Uuid) -> i64 {
    sqlx::query_scalar::<_, i64>(
        "SELECT COUNT(*) FROM virtual_repo_members WHERE virtual_repo_id = $1",
    )
    .bind(virtual_id)
    .fetch_one(pool)
    .await
    .expect("count members")
}

/// B1: removing one member must delete exactly that member's row, leaving
/// every other member intact. A DELETE scoped only by `virtual_repo_id`
/// (missing the `member_repo_id` predicate) would empty the whole repo --
/// the regression this test pins.
#[tokio::test]
#[ignore]
async fn remove_virtual_member_deletes_only_the_targeted_row() {
    let database_url = std::env::var("DATABASE_URL")
        .expect("DATABASE_URL must be set to run this integration test");
    let pool = PgPool::connect(&database_url)
        .await
        .expect("failed to connect to database");

    let suffix = Uuid::new_v4();
    let virtual_id = insert_repo(
        &pool,
        &format!("test-virt-del-{}", suffix),
        "virtual",
        "generic",
    )
    .await;
    let member_a = insert_repo(&pool, &format!("test-del-a-{}", suffix), "local", "generic").await;
    let member_b = insert_repo(&pool, &format!("test-del-b-{}", suffix), "local", "generic").await;

    let svc = RepositoryService::new(pool.clone());
    svc.add_virtual_member(virtual_id, member_a, Some(1))
        .await
        .expect("add member a");
    svc.add_virtual_member(virtual_id, member_b, Some(2))
        .await
        .expect("add member b");
    assert_eq!(
        member_count(&pool, virtual_id).await,
        2,
        "two members before delete"
    );

    // Remove only A.
    svc.remove_virtual_member(virtual_id, member_a)
        .await
        .expect("remove member a must succeed");

    // Exactly B must remain.
    assert_eq!(
        member_count(&pool, virtual_id).await,
        1,
        "removing one member must not empty the repo (B1 regression)"
    );
    let remaining = sqlx::query_scalar::<_, Uuid>(
        "SELECT member_repo_id FROM virtual_repo_members WHERE virtual_repo_id = $1",
    )
    .bind(virtual_id)
    .fetch_one(&pool)
    .await
    .expect("fetch remaining member");
    assert_eq!(remaining, member_b, "the surviving member must be B, not A");

    sqlx::query("DELETE FROM virtual_repo_members WHERE virtual_repo_id = $1")
        .bind(virtual_id)
        .execute(&pool)
        .await
        .ok();
    sqlx::query("DELETE FROM repositories WHERE id = ANY($1)")
        .bind(&[virtual_id, member_a, member_b][..])
        .execute(&pool)
        .await
        .ok();
}

/// B3: removing a member that is not present (e.g. a repeat DELETE of an
/// already-removed member, where the repo still exists so key resolution
/// succeeds) must return `AppError::NotFound` (HTTP 404), not silently
/// succeed.
#[tokio::test]
#[ignore]
async fn remove_already_removed_member_returns_not_found() {
    let database_url = std::env::var("DATABASE_URL")
        .expect("DATABASE_URL must be set to run this integration test");
    let pool = PgPool::connect(&database_url)
        .await
        .expect("failed to connect to database");

    let suffix = Uuid::new_v4();
    let virtual_id = insert_repo(
        &pool,
        &format!("test-virt-404-{}", suffix),
        "virtual",
        "generic",
    )
    .await;
    let member_a = insert_repo(&pool, &format!("test-404-a-{}", suffix), "local", "generic").await;

    let svc = RepositoryService::new(pool.clone());
    svc.add_virtual_member(virtual_id, member_a, Some(1))
        .await
        .expect("add member a");

    // First removal succeeds.
    svc.remove_virtual_member(virtual_id, member_a)
        .await
        .expect("first remove must succeed");

    // Second removal of the same (now-missing) member must be NotFound.
    let err = svc
        .remove_virtual_member(virtual_id, member_a)
        .await
        .expect_err("repeat remove of an already-removed member must fail");
    assert!(
        matches!(err, AppError::NotFound(_)),
        "repeat remove must surface as NotFound (404), got {err:?}"
    );

    sqlx::query("DELETE FROM repositories WHERE id = ANY($1)")
        .bind(&[virtual_id, member_a][..])
        .execute(&pool)
        .await
        .ok();
}
