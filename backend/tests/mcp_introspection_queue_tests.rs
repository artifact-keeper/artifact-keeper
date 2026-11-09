//! The MCP introspection job queue against Postgres (#5387): claims are fair
//! across repositories, and a `sandbox_run` timeout is retried once at most.
//!
//! Jobs are seeded straight into `mcp_introspection_jobs` with `not_before`
//! in the year 2000, so they are older than any job another suite could have
//! queued.
//!
//! ```sh
//! DATABASE_URL=... AK_TESTS_REQUIRE_DB=1 \
//!   cargo nextest run --run-ignored ignored-only --test mcp_introspection_queue_tests
//! ```

#![allow(clippy::unwrap_used)]
#![allow(clippy::expect_used)]

mod common;

use axum::http::StatusCode;
use uuid::Uuid;

use artifact_keeper_backend::models::access_scope::AccessScope;
use artifact_keeper_backend::services::mcp_capabilities::sha256_hex;
use artifact_keeper_backend::services::mcp_introspection::{
    claim, complete, get_job, parse_result, Completed, JobKind, WorkerResult,
};
use common::mcp_support::McpHarness;

/// An `mcp` repository with one published server version: (key, repository
/// id, artifact id).
async fn seed(h: &McpHarness, label: &str) -> (String, Uuid, Uuid) {
    let key = h.mcp_repo(label, "local", false).await;
    let doc = McpHarness::server_doc(&format!("io.github.acme/{label}-{}", h.tag), "1.0.0", label);
    let r = h
        .send("POST", &format!("/mcp/{key}/v0.1/publish"), true, Some(doc))
        .await;
    assert_eq!(r.status, StatusCode::OK, "publish: {}", r.json());
    let (repo, artifact): (Uuid, Uuid) = sqlx::query_as(
        "SELECT r.id, a.id FROM artifacts a JOIN repositories r ON r.id = a.repository_id \
         WHERE r.key = $1 AND a.is_deleted = false",
    )
    .bind(&key)
    .fetch_one(&h.pool)
    .await
    .unwrap();
    (key, repo, artifact)
}

/// A pending job due `minutes` after 2000-01-01.
async fn pending(h: &McpHarness, repo: Uuid, artifact: Uuid, target: &str, minutes: i32) -> Uuid {
    sqlx::query_scalar(
        "INSERT INTO mcp_introspection_jobs (repository_id, artifact_id, kind, target_key, \
           not_before, created_at) \
         VALUES ($1, $2, 'remote_probe', $3, \
           TIMESTAMPTZ '2000-01-01 00:00:00+00' + make_interval(mins => $4), \
           TIMESTAMPTZ '2000-01-01 00:00:00+00' + make_interval(mins => $4)) RETURNING id",
    )
    .bind(repo)
    .bind(artifact)
    .bind(target)
    .bind(minutes)
    .fetch_one(&h.pool)
    .await
    .unwrap()
}

/// A job of `kind` claimed by a worker (the harness admin's principal) on
/// its `attempts`-th attempt, with claim token `token`.
async fn claimed(
    h: &McpHarness,
    repo: Uuid,
    artifact: Uuid,
    kind: JobKind,
    target: &str,
    attempts: i32,
    token: &str,
) -> Uuid {
    sqlx::query_scalar(
        "INSERT INTO mcp_introspection_jobs (repository_id, artifact_id, kind, target_key, \
           status, attempts, max_attempts, claimed_by, claimed_at, lease_expires_at, \
           claim_token_hash, claimed_by_user_id) \
         VALUES ($1, $2, $3, $4, 'claimed', $5, 3, 'it-worker', NOW(), \
           NOW() + INTERVAL '10 minutes', $6, $7) RETURNING id",
    )
    .bind(repo)
    .bind(artifact)
    .bind(kind.as_str())
    .bind(target)
    .bind(attempts)
    .bind(sha256_hex(token.as_bytes()))
    .bind(h.admin)
    .fetch_one(&h.pool)
    .await
    .unwrap()
}

/// Post a `timeout` result for a claimed job.
async fn time_out(h: &McpHarness, id: Uuid, token: &str) -> Completed {
    let job = get_job(&h.pool, id).await.unwrap().unwrap();
    let result = WorkerResult {
        claim_token: token.into(),
        outcome: "timeout".into(),
        error: Some("sandbox wall clock exceeded".into()),
        ..Default::default()
    };
    let parsed = parse_result(&result).unwrap();
    complete(
        &h.pool,
        &job,
        &result,
        parsed,
        h.admin,
        &AccessScope::Admin,
        true,
    )
    .await
    .unwrap()
}

#[tokio::test]
#[ignore = "requires DATABASE_URL pointed at a Postgres with migrations applied"]
async fn claim_prefers_the_repository_with_fewer_claimed_jobs() {
    let Some(h) = McpHarness::new().await else {
        return;
    };
    let (key_a, repo_a, art_a) = seed(&h, "fair-a").await;
    let (key_b, repo_b, art_b) = seed(&h, "fair-b").await;
    // Repository A queued ten jobs, all older than repository B's one job.
    let mut a_jobs = Vec::new();
    for i in 0..10 {
        a_jobs.push(pending(&h, repo_a, art_a, &format!("remote:{i}"), i).await);
    }
    let b_job = pending(&h, repo_b, art_b, "remote:0", 24 * 60).await;
    let kinds = [JobKind::RemoteProbe];

    // Nothing is claimed yet: the oldest due job goes first.
    let first = claim(&h.pool, &kinds, "w1", h.admin, &AccessScope::Admin)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(first.job.id, a_jobs[0], "oldest job first");
    // A now has a job claimed and B none: B's job goes next although A's
    // nine others are older.
    let second = claim(&h.pool, &kinds, "w2", h.admin, &AccessScope::Admin)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        second.job.id, b_job,
        "a repository with a claimed job must not take the next worker \
         while another repository's job waits (got {})",
        second.job.target_key
    );
    // One claimed job each: back to the oldest, A's second job.
    let third = claim(&h.pool, &kinds, "w3", h.admin, &AccessScope::Admin)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(third.job.id, a_jobs[1]);

    h.teardown(&[key_a, key_b]).await;
}

#[tokio::test]
#[ignore = "requires DATABASE_URL pointed at a Postgres with migrations applied"]
async fn sandbox_timeout_on_second_attempt_is_final() {
    let Some(h) = McpHarness::new().await else {
        return;
    };
    let (key, repo, art) = seed(&h, "sbx-timeout").await;

    // First attempt of a sandbox run times out: one retry.
    let id = claimed(&h, repo, art, JobKind::SandboxRun, "package:0", 1, "t1").await;
    assert!(matches!(
        time_out(&h, id, "t1").await,
        Completed::Retry { .. }
    ));
    assert_eq!(
        get_job(&h.pool, id).await.unwrap().unwrap().status,
        "pending"
    );

    // Second attempt times out too: final, recorded as a timeout snapshot.
    let id = claimed(&h, repo, art, JobKind::SandboxRun, "package:1", 2, "t2").await;
    let done = time_out(&h, id, "t2").await;
    assert!(
        matches!(done, Completed::Stored { .. }),
        "a sandbox_run timeout on attempt 2 must not be retried: {done:?}"
    );
    let job = get_job(&h.pool, id).await.unwrap().unwrap();
    assert_eq!(job.status, "completed");
    assert!(job.snapshot_id.is_some());

    // A remote probe timeout keeps its full retry budget.
    let id = claimed(&h, repo, art, JobKind::RemoteProbe, "remote:0", 2, "t3").await;
    assert!(matches!(
        time_out(&h, id, "t3").await,
        Completed::Retry { .. }
    ));

    h.teardown(&[key]).await;
}
