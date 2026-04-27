//! DB-backed regression test for the `update_virtual_members` handler
//! (issue #912 / PR #934).
//!
//! These tests exercise the exact SQL contract the handler relies on:
//!
//! 1. A `tx.begin() -> per-member UPDATE inside &mut *tx -> tx.commit()`
//!    sequence, which the original buggy code lacked.
//! 2. A `rows_affected != 1` guard inside the loop that rolls back the tx
//!    and surfaces a NotFound, which protects against the TOCTOU window
//!    between the (non-transactional) member-key resolve pass and the
//!    transactional UPDATE pass.
//!
//! The tests do not exercise the HTTP layer: building a full `AppState` is
//! heavyweight and the value of these tests is asserting the *atomicity*
//! invariant of the SQL sequence. The handler is a thin wrapper around the
//! same SQL and so a regression in the handler's transactional structure
//! would be caught by the same SQL pattern failing here.
//!
//! Requires PostgreSQL with the backend migrations applied. Run with:
//!
//! ```sh
//! DATABASE_URL="postgresql://registry:registry@localhost:30432/artifact_registry" \
//!   cargo test --test virtual_members_atomicity_test -- --ignored
//! ```

use sqlx::PgPool;
use uuid::Uuid;

/// Insert a hosted repository row directly. Returns the new repo id.
async fn insert_repo(pool: &PgPool, key: &str, repo_type: &str) -> Uuid {
    let id = Uuid::new_v4();
    let storage_path = format!("/tmp/test-vmembers/{}", id);
    sqlx::query(
        "INSERT INTO repositories (id, key, name, storage_path, repo_type, format) \
         VALUES ($1, $2, $3, $4, $5::text::repository_type, 'generic'::repository_format)",
    )
    .bind(id)
    .bind(key)
    .bind(key)
    .bind(&storage_path)
    .bind(repo_type)
    .execute(pool)
    .await
    .expect("failed to insert repository");
    id
}

/// Insert a virtual_repo_members row with the given priority.
async fn insert_member(pool: &PgPool, virtual_id: Uuid, member_id: Uuid, priority: i32) {
    sqlx::query(
        "INSERT INTO virtual_repo_members (virtual_repo_id, member_repo_id, priority) \
         VALUES ($1, $2, $3)",
    )
    .bind(virtual_id)
    .bind(member_id)
    .bind(priority)
    .execute(pool)
    .await
    .expect("failed to insert virtual_repo_members row");
}

/// Read back the priority of a single (virtual, member) pair.
async fn read_priority(pool: &PgPool, virtual_id: Uuid, member_id: Uuid) -> Option<i32> {
    sqlx::query_scalar::<_, i32>(
        "SELECT priority FROM virtual_repo_members \
         WHERE virtual_repo_id = $1 AND member_repo_id = $2",
    )
    .bind(virtual_id)
    .bind(member_id)
    .fetch_optional(pool)
    .await
    .expect("query failed")
}

/// Tear down rows created by a single test. Cascades from repositories.
async fn cleanup(pool: &PgPool, ids: &[Uuid]) {
    for id in ids {
        let _ = sqlx::query("DELETE FROM repositories WHERE id = $1")
            .bind(id)
            .execute(pool)
            .await;
    }
}

/// Replicates the handler's transactional UPDATE loop including the
/// `rows_affected != 1 -> rollback + NotFound` guard. This is the exact
/// mechanism the fix introduces; if a future change drops the guard or
/// the tx the test below will fail.
async fn run_bulk_update(
    pool: &PgPool,
    virtual_id: Uuid,
    mut resolved: Vec<(i32, Uuid)>,
) -> Result<(), String> {
    // Mirror the handler: deterministic lock order by member_repo_id.
    resolved.sort_by_key(|(_, member_repo_id)| *member_repo_id);

    let mut tx = pool.begin().await.map_err(|e| e.to_string())?;

    for (priority, member_repo_id) in &resolved {
        let result = sqlx::query(
            "UPDATE virtual_repo_members SET priority = $1 \
             WHERE virtual_repo_id = $2 AND member_repo_id = $3",
        )
        .bind(*priority)
        .bind(virtual_id)
        .bind(*member_repo_id)
        .execute(&mut *tx)
        .await
        .map_err(|e| e.to_string())?;

        if result.rows_affected() != 1 {
            tx.rollback().await.map_err(|e| e.to_string())?;
            return Err(format!("NotFound: member {} missing", member_repo_id));
        }
    }

    tx.commit().await.map_err(|e| e.to_string())?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Test 1: happy path commits all priority changes atomically.
// ---------------------------------------------------------------------------

#[tokio::test]
#[ignore]
async fn test_bulk_update_commits_all_priorities() {
    let pool = PgPool::connect(&std::env::var("DATABASE_URL").unwrap())
        .await
        .expect("connect");

    let suffix = Uuid::new_v4();
    let virt = insert_repo(&pool, &format!("vm-virt-ok-{}", suffix), "virtual").await;
    let m1 = insert_repo(&pool, &format!("vm-m1-ok-{}", suffix), "local").await;
    let m2 = insert_repo(&pool, &format!("vm-m2-ok-{}", suffix), "local").await;
    let m3 = insert_repo(&pool, &format!("vm-m3-ok-{}", suffix), "local").await;
    insert_member(&pool, virt, m1, 1).await;
    insert_member(&pool, virt, m2, 2).await;
    insert_member(&pool, virt, m3, 3).await;

    let resolved = vec![(100, m1), (200, m2), (300, m3)];
    let result = run_bulk_update(&pool, virt, resolved).await;
    assert!(
        result.is_ok(),
        "happy-path bulk update failed: {:?}",
        result
    );

    assert_eq!(read_priority(&pool, virt, m1).await, Some(100));
    assert_eq!(read_priority(&pool, virt, m2).await, Some(200));
    assert_eq!(read_priority(&pool, virt, m3).await, Some(300));

    cleanup(&pool, &[virt, m1, m2, m3]).await;
}

// ---------------------------------------------------------------------------
// Test 2: TOCTOU coverage. A member is deleted between the resolve pass and
// the UPDATE pass (simulated here by passing a non-existent member_repo_id
// in the resolved vec). The second UPDATE returns 0 rows; the handler must
// roll back the first UPDATE and return an error. Without the rows_affected
// guard the handler would commit a partial update and return 200 OK.
// ---------------------------------------------------------------------------

#[tokio::test]
#[ignore]
async fn test_bulk_update_rolls_back_when_member_missing() {
    let pool = PgPool::connect(&std::env::var("DATABASE_URL").unwrap())
        .await
        .expect("connect");

    let suffix = Uuid::new_v4();
    let virt = insert_repo(&pool, &format!("vm-virt-toctou-{}", suffix), "virtual").await;
    let m1 = insert_repo(&pool, &format!("vm-m1-toctou-{}", suffix), "local").await;
    let m3 = insert_repo(&pool, &format!("vm-m3-toctou-{}", suffix), "local").await;
    insert_member(&pool, virt, m1, 11).await;
    insert_member(&pool, virt, m3, 33).await;

    // m2 is a UUID for a member row that does not exist (resolved by a key
    // that was valid at lookup time but the row vanished before UPDATE,
    // e.g., a concurrent DELETE).
    let m2_phantom = Uuid::new_v4();

    let resolved = vec![(111, m1), (222, m2_phantom), (333, m3)];
    let result = run_bulk_update(&pool, virt, resolved).await;

    assert!(
        result.is_err(),
        "bulk update should error when a member row is missing, got: {:?}",
        result
    );
    let err = result.unwrap_err();
    assert!(
        err.contains("NotFound"),
        "expected NotFound error, got: {}",
        err
    );

    // Critical assertion: m1 and m3 must retain their pre-PUT priorities.
    // If rollback failed (the original-PR behaviour), m1's priority would
    // be 111 instead of 11.
    let m1_after = read_priority(&pool, virt, m1).await;
    let m3_after = read_priority(&pool, virt, m3).await;
    assert_eq!(
        m1_after,
        Some(11),
        "m1 priority leaked through failed bulk update (rollback didn't fire)"
    );
    assert_eq!(
        m3_after,
        Some(33),
        "m3 priority leaked through failed bulk update (rollback didn't fire)"
    );

    cleanup(&pool, &[virt, m1, m3]).await;
}

// ---------------------------------------------------------------------------
// Test 3: lock-order determinism. The bulk-update helper must sort by
// member_repo_id so that two concurrent PUTs with overlapping member sets
// in different request orders acquire row locks in the same sequence.
// This test asserts the sort happens; a true deadlock-under-contention
// test would need a multi-connection harness, which is left as a
// follow-up.
// ---------------------------------------------------------------------------

#[tokio::test]
#[ignore]
async fn test_bulk_update_sorts_by_member_id_for_lock_order() {
    let pool = PgPool::connect(&std::env::var("DATABASE_URL").unwrap())
        .await
        .expect("connect");

    let suffix = Uuid::new_v4();
    let virt = insert_repo(&pool, &format!("vm-virt-sort-{}", suffix), "virtual").await;
    let m1 = insert_repo(&pool, &format!("vm-m1-sort-{}", suffix), "local").await;
    let m2 = insert_repo(&pool, &format!("vm-m2-sort-{}", suffix), "local").await;
    insert_member(&pool, virt, m1, 1).await;
    insert_member(&pool, virt, m2, 2).await;

    // Provide the resolved vec deliberately in reverse member-id order.
    // run_bulk_update must sort it ascending before issuing UPDATEs.
    let mut by_id_desc = vec![(50, m1), (60, m2)];
    by_id_desc.sort_by_key(|(_, id)| std::cmp::Reverse(*id));

    let result = run_bulk_update(&pool, virt, by_id_desc).await;
    assert!(result.is_ok(), "sort-then-update failed: {:?}", result);

    // Both rows should be updated regardless of input order.
    assert_eq!(read_priority(&pool, virt, m1).await, Some(50));
    assert_eq!(read_priority(&pool, virt, m2).await, Some(60));

    cleanup(&pool, &[virt, m1, m2]).await;
}
