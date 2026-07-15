//! DB-backed integration tests for deduplicated storage accounting (#2056).
//!
//! These exercise `StorageStatsService::recompute_all` against a real Postgres
//! and assert the materialized `repository_storage_stats` figures. They are
//! `#[ignore]` and require `DATABASE_URL` (run via the DB-gated test job), like
//! the other `require_db_pool` integration suites.
//!
//! Coverage focus (FixSpec §8 integration cases):
//! - CAS blob referenced by N artifact rows in one repo dedups within repo.
//! - OCI *layer* bytes (`oci_blobs`) are now counted (regression: was 0).
//! - Backend-aware sharding: filesystem forces `shared_bytes = 0`.
//! - Proxy catalog rows sum into logical == physical == unique.
//! - The refresher lowers physical after a shared blob is removed.

mod common;

use common::require_db_pool;
use sqlx::PgPool;
use uuid::Uuid;

use artifact_keeper_backend::services::storage_stats_service::StorageStatsService;

fn unique(prefix: &str) -> String {
    format!("{}-{}", prefix, &Uuid::new_v4().to_string()[..8])
}

async fn insert_repo(pool: &PgPool, backend: &str) -> Uuid {
    let id = Uuid::new_v4();
    let key = unique("stats-repo");
    sqlx::query(
        r#"
        INSERT INTO repositories (id, key, name, format, repo_type, storage_backend, storage_path, is_public)
        VALUES ($1, $2, $2, 'generic'::repository_format, 'local'::repository_type, $3, $4, true)
        "#,
    )
    .bind(id)
    .bind(&key)
    .bind(backend)
    .bind(format!("/data/{key}"))
    .execute(pool)
    .await
    .expect("failed to insert repository");
    id
}

async fn insert_artifact(pool: &PgPool, repo: Uuid, path: &str, storage_key: &str, size: i64) {
    sqlx::query(
        r#"
        INSERT INTO artifacts
            (id, repository_id, path, name, size_bytes, checksum_sha256,
             content_type, storage_key, is_deleted)
        VALUES ($1, $2, $3, $3, $4, repeat('a', 64), 'application/octet-stream', $5, false)
        "#,
    )
    .bind(Uuid::new_v4())
    .bind(repo)
    .bind(path)
    .bind(size)
    .bind(storage_key)
    .execute(pool)
    .await
    .expect("failed to insert artifact");
}

async fn insert_oci_blob(pool: &PgPool, repo: Uuid, digest: &str, size: i64) {
    sqlx::query(
        r#"
        INSERT INTO oci_blobs (id, repository_id, digest, size_bytes, storage_key)
        VALUES ($1, $2, $3, $4, $5)
        "#,
    )
    .bind(Uuid::new_v4())
    .bind(repo)
    .bind(digest)
    .bind(size)
    .bind(format!("oci-blobs/{digest}"))
    .execute(pool)
    .await
    .expect("failed to insert oci blob");
}

async fn insert_proxy_cache(pool: &PgPool, repo: Uuid, path: &str, size: i64) {
    sqlx::query(
        r#"
        INSERT INTO proxy_cache_artifacts
            (id, repository_id, path, storage_key, metadata_key, size_bytes)
        VALUES ($1, $2, $3, $4, $5, $6)
        "#,
    )
    .bind(Uuid::new_v4())
    .bind(repo)
    .bind(path)
    .bind(format!("proxy-cache/{}/{}/__content__", repo, path))
    .bind(format!("proxy-cache/{}/{}/__cache_meta__.json", repo, path))
    .bind(size)
    .execute(pool)
    .await
    .expect("failed to insert proxy cache row");
}

struct Stats {
    logical: i64,
    physical: i64,
    unique: i64,
    shared: i64,
    blob_count: i64,
}

async fn read_stats(pool: &PgPool, repo: Uuid) -> Stats {
    let row = sqlx::query_as::<_, (i64, i64, i64, i64, i64)>(
        r#"
        SELECT logical_bytes, physical_bytes, unique_bytes, shared_bytes, blob_count
          FROM repository_storage_stats WHERE repository_id = $1
        "#,
    )
    .bind(repo)
    .fetch_one(pool)
    .await
    .expect("stats row missing");
    Stats {
        logical: row.0,
        physical: row.1,
        unique: row.2,
        shared: row.3,
        blob_count: row.4,
    }
}

async fn cleanup(pool: &PgPool, repo: Uuid) {
    let _ = sqlx::query("DELETE FROM repositories WHERE id = $1")
        .bind(repo)
        .execute(pool)
        .await;
}

#[tokio::test]
#[ignore]
async fn cas_blob_shared_by_three_rows_dedups_within_repo() {
    let pool = require_db_pool().await;
    let repo = insert_repo(&pool, "filesystem").await;
    // Same CAS storage key referenced by three artifact rows (different paths).
    let key = format!("cas/aa/bb/{}", Uuid::new_v4());
    insert_artifact(&pool, repo, "a/1", &key, 1000).await;
    insert_artifact(&pool, repo, "a/2", &key, 1000).await;
    insert_artifact(&pool, repo, "a/3", &key, 1000).await;

    StorageStatsService::new(pool.clone(), "filesystem")
        .recompute_all()
        .await
        .expect("recompute");

    let s = read_stats(&pool, repo).await;
    assert_eq!(s.logical, 3000, "logical = 3 references * size");
    assert_eq!(s.physical, 1000, "physical dedups to one object");
    assert_eq!(s.unique, 1000);
    assert_eq!(s.shared, 0);
    assert_eq!(s.blob_count, 1);

    cleanup(&pool, repo).await;
}

#[tokio::test]
#[ignore]
async fn oci_layer_bytes_are_counted() {
    // Regression assertion: OCI physical > 0. Layers live in oci_blobs and were
    // entirely omitted from the pre-#2056 SUM.
    let pool = require_db_pool().await;
    let repo = insert_repo(&pool, "filesystem").await;
    // Small manifest as an artifacts row + a big layer in oci_blobs.
    insert_artifact(
        &pool,
        repo,
        "manifest",
        &format!("oci-manifests/{}", Uuid::new_v4()),
        512,
    )
    .await;
    let layer = format!("sha256:{}", Uuid::new_v4().simple());
    insert_oci_blob(&pool, repo, &layer, 4096).await;

    StorageStatsService::new(pool.clone(), "filesystem")
        .recompute_all()
        .await
        .expect("recompute");

    let s = read_stats(&pool, repo).await;
    assert_eq!(s.physical, 512 + 4096, "manifest + layer both counted");
    assert!(
        s.physical > 512,
        "layer bytes must be included, not just manifest"
    );
    assert_eq!(s.blob_count, 2);

    cleanup(&pool, repo).await;
}

#[tokio::test]
#[ignore]
async fn filesystem_forces_shared_zero_across_repos() {
    let pool = require_db_pool().await;
    let a = insert_repo(&pool, "filesystem").await;
    let b = insert_repo(&pool, "filesystem").await;
    // Same digest in two repos: on filesystem these are two files.
    let digest = format!("sha256:{}", Uuid::new_v4().simple());
    insert_oci_blob(&pool, a, &digest, 800).await;
    insert_oci_blob(&pool, b, &digest, 800).await;

    StorageStatsService::new(pool.clone(), "filesystem")
        .recompute_all()
        .await
        .expect("recompute");

    let sa = read_stats(&pool, a).await;
    let sb = read_stats(&pool, b).await;
    assert_eq!(sa.physical, 800);
    assert_eq!(sa.shared, 0, "filesystem: nothing is shared");
    assert_eq!(sa.unique, 800);
    assert_eq!(sb.shared, 0);

    cleanup(&pool, a).await;
    cleanup(&pool, b).await;
}

#[tokio::test]
#[ignore]
async fn cloud_backend_shares_digest_across_repos() {
    // On a cloud backend one physical object backs a digest instance-wide, so
    // a digest in two repos is `shared` for both and the instance total counts
    // it once. Proves the backend-aware SQL feeds the classifier correct
    // per-digest repo counts.
    let pool = require_db_pool().await;
    let a = insert_repo(&pool, "s3").await;
    let b = insert_repo(&pool, "s3").await;
    let digest = format!("sha256:{}", Uuid::new_v4().simple());
    insert_oci_blob(&pool, a, &digest, 900).await;
    insert_oci_blob(&pool, b, &digest, 900).await;

    StorageStatsService::new(pool.clone(), "s3")
        .recompute_all()
        .await
        .expect("recompute");

    let sa = read_stats(&pool, a).await;
    let sb = read_stats(&pool, b).await;
    assert_eq!(sa.physical, 900);
    assert_eq!(sa.shared, 900, "cloud: digest in another repo is shared");
    assert_eq!(sa.unique, 0);
    assert_eq!(sb.shared, 900);

    let instance: i64 =
        sqlx::query_scalar("SELECT unique_bytes FROM instance_storage_stats WHERE id = true")
            .fetch_one(&pool)
            .await
            .expect("instance row");
    assert!(
        instance >= 900,
        "instance total counts the shared object once (>= 900)"
    );

    cleanup(&pool, a).await;
    cleanup(&pool, b).await;
}

#[tokio::test]
#[ignore]
async fn proxy_cache_rows_sum_into_unique() {
    let pool = require_db_pool().await;
    let repo = insert_repo(&pool, "filesystem").await;
    insert_proxy_cache(&pool, repo, "p/one", 111).await;
    insert_proxy_cache(&pool, repo, "p/two", 222).await;

    StorageStatsService::new(pool.clone(), "filesystem")
        .recompute_all()
        .await
        .expect("recompute");

    let s = read_stats(&pool, repo).await;
    assert_eq!(s.logical, 333);
    assert_eq!(s.physical, 333, "proxy rows never dedup");
    assert_eq!(s.unique, 333);
    assert_eq!(s.blob_count, 2);

    cleanup(&pool, repo).await;
}

#[tokio::test]
#[ignore]
async fn refresh_lowers_physical_after_blob_removed() {
    let pool = require_db_pool().await;
    let repo = insert_repo(&pool, "filesystem").await;
    let d1 = format!("sha256:{}", Uuid::new_v4().simple());
    let d2 = format!("sha256:{}", Uuid::new_v4().simple());
    insert_oci_blob(&pool, repo, &d1, 500).await;
    insert_oci_blob(&pool, repo, &d2, 700).await;

    let svc = StorageStatsService::new(pool.clone(), "filesystem");
    svc.recompute_all().await.expect("recompute");
    assert_eq!(read_stats(&pool, repo).await.physical, 1200);

    // Simulate a GC reclaim of one layer, then re-run the refresher.
    sqlx::query("DELETE FROM oci_blobs WHERE repository_id = $1 AND digest = $2")
        .bind(repo)
        .bind(&d2)
        .execute(&pool)
        .await
        .expect("delete blob");
    svc.recompute_all().await.expect("recompute after gc");

    assert_eq!(
        read_stats(&pool, repo).await.physical,
        500,
        "refresher settles to post-GC footprint"
    );

    cleanup(&pool, repo).await;
}

#[tokio::test]
#[ignore]
async fn quota_usage_unchanged_by_dedup_stats() {
    // Non-regression: the live logical SUM the quota path reads must be
    // byte-for-byte identical whether or not stats have been computed. The
    // deduped stats table is additive and never repoints quota.
    let pool = require_db_pool().await;
    let repo = insert_repo(&pool, "filesystem").await;
    let key = format!("cas/cc/dd/{}", Uuid::new_v4());
    // Duplicated CAS key: logical (quota) sees 3 rows; physical dedups.
    insert_artifact(&pool, repo, "q/1", &key, 400).await;
    insert_artifact(&pool, repo, "q/2", &key, 400).await;
    insert_artifact(&pool, repo, "q/3", &key, 400).await;

    // The quota SUM (repository_service::get_storage_usage semantics).
    let quota_usage: i64 = sqlx::query_scalar(
        r#"
        SELECT COALESCE(SUM(bytes), 0)::BIGINT FROM (
            SELECT size_bytes AS bytes FROM artifacts
             WHERE repository_id = $1 AND is_deleted = false
               AND storage_key NOT LIKE 'proxy-cache/%'
            UNION ALL
            SELECT size_bytes AS bytes FROM proxy_cache_artifacts
             WHERE repository_id = $1
        ) t
        "#,
    )
    .bind(repo)
    .fetch_one(&pool)
    .await
    .expect("quota sum");

    StorageStatsService::new(pool.clone(), "filesystem")
        .recompute_all()
        .await
        .expect("recompute");

    // Quota still reads the per-row logical total (1200), not the deduped 400.
    assert_eq!(quota_usage, 1200, "quota SUM stays per-row logical");
    let s = read_stats(&pool, repo).await;
    assert_eq!(s.logical, 1200);
    assert_eq!(s.physical, 400, "dedup stat is separate from quota");

    cleanup(&pool, repo).await;
}
