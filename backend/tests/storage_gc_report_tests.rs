//! DB-backed regression test for the OCI blob footprint report (#2626).
//!
//! `oci_blob_footprint_report` bound `grace_hours: i64` (int8) into
//! `make_interval(hours => $1)`, which PostgreSQL only defines for int4 —
//! every call failed with "function make_interval(hours => bigint) does not
//! exist", so the admin oci-blob-report endpoint always returned 500. This
//! suite executes the real query against Postgres, which the `--lib` unit
//! tests (offline) can never catch.
//!
//! Assertions on global totals use inequalities: `oci_blobs` is shared
//! DB-wide and other DB-gated suites seed it concurrently. Per-repository
//! figures are isolated by our own repo ids and asserted exactly.

mod common;

use std::collections::HashMap;
use std::sync::Arc;

use common::require_db_pool;
use sqlx::PgPool;
use uuid::Uuid;

use artifact_keeper_backend::services::storage_gc_service::StorageGcService;
use artifact_keeper_backend::storage::StorageRegistry;

async fn seed_repo_with_blobs(pool: &PgPool, blobs: &[(&str, i64)]) -> Uuid {
    let id = Uuid::new_v4();
    let key = format!("gc-report-{}", &id.to_string()[..8]);
    sqlx::query(
        r#"
        INSERT INTO repositories (id, key, name, format, repo_type, storage_backend, storage_path, is_public)
        VALUES ($1, $2, $2, 'docker'::repository_format, 'local'::repository_type, 'filesystem', $3, true)
        "#,
    )
    .bind(id)
    .bind(&key)
    .bind(format!("/data/{key}"))
    .execute(pool)
    .await
    .expect("insert repository");
    for (digest, size) in blobs {
        sqlx::query(
            "INSERT INTO oci_blobs (id, repository_id, digest, size_bytes, storage_key) \
             VALUES ($1, $2, $3, $4, 'oci-blobs/' || $3)",
        )
        .bind(Uuid::new_v4())
        .bind(id)
        .bind(digest)
        .bind(size)
        .execute(pool)
        .await
        .expect("insert oci blob");
    }
    id
}

#[tokio::test]
#[ignore]
async fn oci_blob_footprint_report_executes() {
    let pool = require_db_pool().await;

    // One digest shared by two repos + one unique digest: exercises both the
    // logical-vs-physical split and the per-repo breakdown.
    let shared = format!("sha256:{}", Uuid::new_v4().simple());
    let only_a = format!("sha256:{}", Uuid::new_v4().simple());
    let repo_a = seed_repo_with_blobs(&pool, &[(&shared, 1_000), (&only_a, 300)]).await;
    let repo_b = seed_repo_with_blobs(&pool, &[(&shared, 1_000)]).await;

    let svc = StorageGcService::new(
        pool.clone(),
        Arc::new(StorageRegistry::new(
            HashMap::new(),
            "filesystem".to_string(),
        )),
    );

    // On main this errors with `function make_interval(hours => bigint) does
    // not exist` before any row is returned.
    let report = svc
        .oci_blob_footprint_report(24)
        .await
        .expect("footprint report must execute against a real Postgres");

    assert_eq!(report.grace_hours, 24);
    // Global totals include at least our seed (other suites may add more).
    assert!(report.total_blob_rows >= 3);
    assert!(report.distinct_digests >= 2);
    assert!(report.logical_bytes >= 2_300, "1000 + 300 + 1000 seeded");
    assert!(report.physical_bytes >= 1_300, "shared digest counted once");
    assert!(report.logical_bytes >= report.physical_bytes);
    // Freshly inserted blobs are inside the 24h grace window, so they must
    // not inflate the aged figures.
    assert!(report.aged_physical_bytes <= report.physical_bytes);

    // Per-repo rows are isolated to our repos and exact.
    let by_repo: HashMap<Uuid, (i64, i64)> = report
        .per_repository
        .iter()
        .map(|r| (r.repository_id, (r.blob_rows, r.logical_bytes)))
        .collect();
    assert_eq!(by_repo.get(&repo_a), Some(&(2, 1_300)));
    assert_eq!(by_repo.get(&repo_b), Some(&(1, 1_000)));

    for repo in [repo_a, repo_b] {
        let _ = sqlx::query("DELETE FROM repositories WHERE id = $1")
            .bind(repo)
            .execute(&pool)
            .await;
    }
}
