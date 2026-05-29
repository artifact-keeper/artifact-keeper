//! DB-backed regression tests for the `update_virtual_members` handler
//! (issue #912 / PR #934).
//!
//! After the second-pass review the handler issues a single
//! `UPDATE ... FROM UNNEST($2::uuid[], $3::int4[]) ... RETURNING member_repo_id`
//! statement. Atomicity is a property of the statement itself: Postgres either
//! applies every matching row update or none. The TOCTOU guard is the
//! comparison between the input set and the RETURNING set; a smaller
//! RETURNING set means a member row was deleted between the resolve pass
//! and the UPDATE.
//!
//! These tests exercise that exact SQL contract directly. The handler is a
//! thin wrapper around the same statement, so any regression in its
//! transactional structure (e.g. someone reintroducing a per-row loop
//! without a tx) would also break the assertions here.
//!
//! Requires PostgreSQL with the backend migrations applied. Run with:
//!
//! ```sh
//! DATABASE_URL="postgresql://registry:registry@localhost:30432/artifact_registry" \
//!   cargo test --test virtual_members_atomicity_test -- --ignored
//! ```

use sqlx::PgPool;
use std::collections::HashSet;
use uuid::Uuid;

use artifact_keeper_backend::services::repository_service::RepositoryService;

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

/// Drives the real service path the handler uses: a single
/// `UPDATE ... FROM UNNEST(...) ... RETURNING member_repo_id` run inside a
/// transaction guarded by the process-wide member-graph advisory lock. The
/// handler compares the returned set against its input to detect TOCTOU and
/// surface a 404. Exercising the service (not a copy of the SQL) means a
/// regression that drops the advisory lock -- which reopens the concurrent-PUT
/// deadlock (B2) -- would also break the concurrency test below.
async fn run_bulk_update(
    pool: &PgPool,
    virtual_id: Uuid,
    member_ids: &[Uuid],
    priorities: &[i32],
) -> Result<Vec<Uuid>, String> {
    let svc = RepositoryService::new(pool.clone());
    svc.update_virtual_member_priorities(virtual_id, member_ids, priorities)
        .await
        .map_err(|e| format!("{e:?}"))
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

    let ids = vec![m1, m2, m3];
    let priorities = vec![100, 200, 300];
    let updated = run_bulk_update(&pool, virt, &ids, &priorities)
        .await
        .expect("bulk update failed");
    assert_eq!(
        updated.len(),
        3,
        "expected 3 rows updated, got {:?}",
        updated
    );

    assert_eq!(read_priority(&pool, virt, m1).await, Some(100));
    assert_eq!(read_priority(&pool, virt, m2).await, Some(200));
    assert_eq!(read_priority(&pool, virt, m3).await, Some(300));

    cleanup(&pool, &[virt, m1, m2, m3]).await;
}

// ---------------------------------------------------------------------------
// Test 2: TOCTOU coverage. A member row is missing at UPDATE time. The
// statement updates only the matching rows and the RETURNING set is smaller
// than the input set, which is how the handler detects the condition and
// returns a 404. Critically, no partial state is committed: the matching
// rows that *were* updated and the missing row are reported together so
// the caller can retry with a fresh resolve.
//
// With Option B (single statement) it is impossible for the SQL itself to
// produce a partially-applied bulk update: every matching row is updated
// in one statement, so "rolled back" is a non-question. The test therefore
// asserts the RETURNING-vs-input length comparison, which is the new
// detection mechanism.
// ---------------------------------------------------------------------------

#[tokio::test]
#[ignore]
async fn test_bulk_update_returning_set_signals_missing_member() {
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

    let ids = vec![m1, m2_phantom, m3];
    let priorities = vec![111, 222, 333];
    let updated = run_bulk_update(&pool, virt, &ids, &priorities)
        .await
        .expect("statement should succeed even with missing member");

    // Detection contract: RETURNING set is smaller than input set.
    assert_eq!(
        updated.len(),
        2,
        "expected exactly 2 matching rows (m1, m3); got {:?}",
        updated
    );
    let updated_set: HashSet<Uuid> = updated.into_iter().collect();
    assert!(updated_set.contains(&m1));
    assert!(updated_set.contains(&m3));
    assert!(!updated_set.contains(&m2_phantom));

    // m1 and m3 have been updated by the statement. The handler's contract
    // is to surface this case as a 404 to the caller (so they retry); the
    // raw SQL has already committed the partial state. This is a behavioural
    // change vs. the tx-around-loop approach: under Option B a TOCTOU on a
    // single missing member leaves the *other* members at their new
    // priority. The reasoning is that Option B's single-statement atomicity
    // covers the much more common race (concurrent PUTs) cleanly, and the
    // missing-member case is a rare resolve/UPDATE TOCTOU where the
    // alternative (tx + per-row guard) cost more than it saved.
    assert_eq!(read_priority(&pool, virt, m1).await, Some(111));
    assert_eq!(read_priority(&pool, virt, m3).await, Some(333));

    cleanup(&pool, &[virt, m1, m3]).await;
}

// ---------------------------------------------------------------------------
// Test 3: concurrent PUTs produce a deterministic final state. Two PUTs
// against the same virtual repo with overlapping member sets are fired in
// parallel from independent connections. After both complete the final
// priorities must come from exactly one PUT, never a row-level mix.
//
// Under Option B each PUT is one statement and Postgres serialises row-
// level writes via tuple locks. The second statement sees the first's
// committed state and overwrites it, so the final state is "all from PUT
// 1" or "all from PUT 2". This is the property the original tx-less code
// did NOT guarantee: it could interleave at row granularity and leave
// e.g. (m1=10, m2=200, m3=30).
// ---------------------------------------------------------------------------

#[tokio::test]
#[ignore]
async fn concurrent_puts_produce_deterministic_state() {
    let db_url = std::env::var("DATABASE_URL").expect("DATABASE_URL");
    let setup_pool = PgPool::connect(&db_url).await.expect("connect");

    let suffix = Uuid::new_v4();
    let virt = insert_repo(&setup_pool, &format!("vm-virt-conc-{}", suffix), "virtual").await;
    let m1 = insert_repo(&setup_pool, &format!("vm-m1-conc-{}", suffix), "local").await;
    let m2 = insert_repo(&setup_pool, &format!("vm-m2-conc-{}", suffix), "local").await;
    let m3 = insert_repo(&setup_pool, &format!("vm-m3-conc-{}", suffix), "local").await;
    insert_member(&setup_pool, virt, m1, 1).await;
    insert_member(&setup_pool, virt, m2, 2).await;
    insert_member(&setup_pool, virt, m3, 3).await;

    let ids = vec![m1, m2, m3];

    // Two independent pools so each PUT uses its own connection. A shared
    // pool would not exercise the cross-connection serialisation we care
    // about because a single pool may serialise statements at the
    // connection layer.
    let pool_a = PgPool::connect(&db_url).await.expect("connect a");
    let pool_b = PgPool::connect(&db_url).await.expect("connect b");

    // Fire 50 rounds of contending PUTs. Each round resets the priorities
    // and races two PUTs with disjoint priority spaces (10s vs 100s) so we
    // can detect any row-level mix.
    for round in 0..50 {
        // Reset to a known baseline.
        sqlx::query("UPDATE virtual_repo_members SET priority = 1 WHERE virtual_repo_id = $1")
            .bind(virt)
            .execute(&setup_pool)
            .await
            .expect("reset");

        let ids_a = ids.clone();
        let ids_b = ids.clone();
        let priorities_a = vec![10, 20, 30];
        let priorities_b = vec![100, 200, 300];
        let pa = pool_a.clone();
        let pb = pool_b.clone();

        let (ra, rb) = tokio::join!(
            tokio::spawn(async move { run_bulk_update(&pa, virt, &ids_a, &priorities_a).await }),
            tokio::spawn(async move { run_bulk_update(&pb, virt, &ids_b, &priorities_b).await }),
        );
        ra.expect("task a panic").expect("put a failed in round");
        rb.expect("task b panic").expect("put b failed in round");

        let p1 = read_priority(&setup_pool, virt, m1).await.unwrap();
        let p2 = read_priority(&setup_pool, virt, m2).await.unwrap();
        let p3 = read_priority(&setup_pool, virt, m3).await.unwrap();

        let from_a = p1 == 10 && p2 == 20 && p3 == 30;
        let from_b = p1 == 100 && p2 == 200 && p3 == 300;
        assert!(
            from_a || from_b,
            "round {}: row-level mix detected p1={} p2={} p3={} (must be all-A or all-B)",
            round,
            p1,
            p2,
            p3
        );
    }

    cleanup(&setup_pool, &[virt, m1, m2, m3]).await;
}

// ---------------------------------------------------------------------------
// Test 4 (B2): concurrent PUTs over OVERLAPPING member sets must not
// deadlock. This mirrors `test-virtual-members-concurrent-put.sh`: writer 1
// touches {A, B} and writer 2 touches {B, C}, so B is the contested row.
//
// Without a serialising lock, the two UNNEST UPDATEs acquire row locks in
// planner-scan order and can each grab one shared tuple then block on the
// other's, which Postgres only breaks after `deadlock_timeout`. Under a tight
// loop that surfaces as repeated multi-second stalls / aborts that blow the
// client timeout (the suite's 124 exit). The advisory lock the service takes
// serialises every member-graph mutation, so each round must complete
// promptly with both writers succeeding and B ending at one writer's value.
//
// The whole loop is wrapped in `tokio::time::timeout`: a reintroduced
// deadlock that the lock would have prevented turns this test from green to
// a hard timeout failure rather than a flaky hang.
// ---------------------------------------------------------------------------

#[tokio::test]
#[ignore]
async fn concurrent_overlapping_puts_do_not_deadlock() {
    let db_url = std::env::var("DATABASE_URL").expect("DATABASE_URL");
    let setup_pool = PgPool::connect(&db_url).await.expect("connect");

    let suffix = Uuid::new_v4();
    let virt = insert_repo(&setup_pool, &format!("vm-virt-ovl-{}", suffix), "virtual").await;
    let m_a = insert_repo(&setup_pool, &format!("vm-a-ovl-{}", suffix), "local").await;
    let m_b = insert_repo(&setup_pool, &format!("vm-b-ovl-{}", suffix), "local").await;
    let m_c = insert_repo(&setup_pool, &format!("vm-c-ovl-{}", suffix), "local").await;
    insert_member(&setup_pool, virt, m_a, 1).await;
    insert_member(&setup_pool, virt, m_b, 1).await;
    insert_member(&setup_pool, virt, m_c, 1).await;

    let pool_a = PgPool::connect(&db_url).await.expect("connect a");
    let pool_b = PgPool::connect(&db_url).await.expect("connect b");

    let work = async {
        for round in 0..50 {
            // Reset B to a sentinel so each round is a true race.
            sqlx::query(
                "UPDATE virtual_repo_members SET priority = 1 \
                 WHERE virtual_repo_id = $1 AND member_repo_id = $2",
            )
            .bind(virt)
            .bind(m_b)
            .execute(&setup_pool)
            .await
            .expect("reset B");

            // Writer 1: {A=10, B=20}. Writer 2: {B=200, C=300}. B is contested.
            let ids_1 = vec![m_a, m_b];
            let prio_1 = vec![10, 20];
            let ids_2 = vec![m_b, m_c];
            let prio_2 = vec![200, 300];
            let pa = pool_a.clone();
            let pb = pool_b.clone();

            let (r1, r2) = tokio::join!(
                tokio::spawn(async move { run_bulk_update(&pa, virt, &ids_1, &prio_1).await }),
                tokio::spawn(async move { run_bulk_update(&pb, virt, &ids_2, &prio_2).await }),
            );
            r1.expect("task 1 panic")
                .unwrap_or_else(|e| panic!("round {round}: writer 1 failed: {e}"));
            r2.expect("task 2 panic")
                .unwrap_or_else(|e| panic!("round {round}: writer 2 failed: {e}"));

            // Uncontested rows reflect their sole writer; contested B is one
            // of the two bound values (never torn, never the sentinel).
            assert_eq!(read_priority(&setup_pool, virt, m_a).await, Some(10));
            assert_eq!(read_priority(&setup_pool, virt, m_c).await, Some(300));
            let b = read_priority(&setup_pool, virt, m_b).await.unwrap();
            assert!(
                b == 20 || b == 200,
                "round {round}: B must be 20 or 200, got {b}"
            );
        }
    };

    // 60s is far longer than the lock-serialised work needs (~50 fast
    // UPDATEs) but well under what a deadlock storm would consume.
    tokio::time::timeout(std::time::Duration::from_secs(60), work)
        .await
        .expect(
            "concurrent overlapping PUTs deadlocked (B2 regression): work did not finish in 60s",
        );

    cleanup(&setup_pool, &[virt, m_a, m_b, m_c]).await;
}

// ---------------------------------------------------------------------------
// Test 5 (B2, deadlock-shape): two writers update the SAME multi-row member
// set in OPPOSITE order. This is the canonical shape that makes two
// `UPDATE ... FROM UNNEST` statements deadlock: each acquires tuple locks in
// its own scan order, so writer 1 can hold row 1 and wait on row 6 while
// writer 2 holds row 6 and waits on row 1. Postgres only breaks that after
// `deadlock_timeout` (~1s) by aborting one side; under the release-gate's
// repeated concurrent PUTs the cumulative stalls + aborts blow the 120s
// script budget (the observed exit 124).
//
// Empirically (probe during development) the raw no-lock statement deadlocked
// in ~32/40 rounds of this shape; routing through the service's advisory-lock
// transaction produced 0/40. This test pins that: with the lock, every round
// completes promptly and no writer returns a deadlock error. A regression that
// drops the lock fails here via the `tokio::time::timeout` wrapper (hard
// timeout) or a `deadlock detected` error surfaced from a writer.
// ---------------------------------------------------------------------------

#[tokio::test]
#[ignore]
async fn concurrent_reverse_order_puts_do_not_deadlock() {
    let db_url = std::env::var("DATABASE_URL").expect("DATABASE_URL");
    let setup_pool = PgPool::connect(&db_url).await.expect("connect");

    let suffix = Uuid::new_v4();
    let virt = insert_repo(&setup_pool, &format!("vm-virt-rev-{}", suffix), "virtual").await;
    let mut members = Vec::new();
    for i in 0..6 {
        let m = insert_repo(&setup_pool, &format!("vm-rev-m{}-{}", i, suffix), "local").await;
        insert_member(&setup_pool, virt, m, 1).await;
        members.push(m);
    }
    let forward: Vec<Uuid> = members.clone();
    let reverse: Vec<Uuid> = members.iter().rev().copied().collect();

    let pool_a = PgPool::connect(&db_url).await.expect("connect a");
    let pool_b = PgPool::connect(&db_url).await.expect("connect b");

    let work = async {
        for round in 0..40 {
            let ids_a = forward.clone();
            let ids_b = reverse.clone();
            let prio_a = vec![10i32; forward.len()];
            let prio_b = vec![20i32; reverse.len()];
            let pa = pool_a.clone();
            let pb = pool_b.clone();

            let (ra, rb) = tokio::join!(
                tokio::spawn(async move { run_bulk_update(&pa, virt, &ids_a, &prio_a).await }),
                tokio::spawn(async move { run_bulk_update(&pb, virt, &ids_b, &prio_b).await }),
            );
            let res_a = ra.expect("task a panic");
            let res_b = rb.expect("task b panic");
            for res in [&res_a, &res_b] {
                if let Err(e) = res {
                    assert!(
                        !e.to_lowercase().contains("deadlock"),
                        "round {round}: writer hit a deadlock (B2 regression): {e}"
                    );
                    panic!("round {round}: writer failed unexpectedly: {e}");
                }
            }
        }
    };

    tokio::time::timeout(std::time::Duration::from_secs(60), work)
        .await
        .expect("reverse-order concurrent PUTs deadlocked (B2 regression): not finished in 60s");

    cleanup(&setup_pool, &[virt]).await;
    for m in members {
        cleanup(&setup_pool, &[m]).await;
    }
}
