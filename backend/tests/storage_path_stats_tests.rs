//! DB-backed integration tests for the per-prefix (folder tree) storage
//! rollup (#2601, epic #2056 P2).
//!
//! These exercise `StorageStatsService::recompute_all` /
//! `recompute_path_stats` against a real Postgres and assert the materialized
//! `repository_path_storage_stats` rows. They are `#[ignore]` and require
//! `DATABASE_URL` (run via the DB-gated test job), like the other
//! `require_db_pool` integration suites.
//!
//! Coverage focus:
//! - Nested-prefix rollup: every ancestor level aggregates its subtree.
//! - Dedup: a CAS object shared across sibling subtrees counts once at the
//!   common ancestor but once in each subtree (sum(children.physical) >
//!   parent.physical is the dedup-saving signal).
//! - OCI layer bytes (no logical path) land in the root row's
//!   `unattributed_bytes`, while manifests group under `v2/<image>/`.
//! - Proxy-cache catalog rows are path-attributed.
//! - The refresher prunes rows for paths that no longer exist.
//! - Depth cap: pathological deep paths only materialize
//!   `MAX_MATERIALIZED_PATH_DEPTH` levels.

mod common;

use common::require_db_pool;
use sqlx::PgPool;
use uuid::Uuid;

use artifact_keeper_backend::services::storage_stats_service::{
    StorageStatsService, MAX_MATERIALIZED_PATH_DEPTH,
};

fn unique(prefix: &str) -> String {
    format!("{}-{}", prefix, &Uuid::new_v4().to_string()[..8])
}

async fn insert_repo(pool: &PgPool, backend: &str) -> Uuid {
    let id = Uuid::new_v4();
    let key = unique("pstats-repo");
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

#[derive(Debug)]
struct Node {
    depth: i32,
    logical: i64,
    physical: i64,
    files: i64,
    blobs: i64,
    unattributed: i64,
}

async fn read_node(pool: &PgPool, repo: Uuid, prefix: &str) -> Option<Node> {
    sqlx::query_as::<_, (i32, i64, i64, i64, i64, i64)>(
        r#"
        SELECT depth, logical_bytes, physical_bytes, file_count, blob_count,
               unattributed_bytes
          FROM repository_path_storage_stats
         WHERE repository_id = $1 AND prefix = $2
        "#,
    )
    .bind(repo)
    .bind(prefix)
    .fetch_optional(pool)
    .await
    .expect("query path stats")
    .map(
        |(depth, logical, physical, files, blobs, unattributed)| Node {
            depth,
            logical,
            physical,
            files,
            blobs,
            unattributed,
        },
    )
}

async fn recompute(pool: &PgPool) {
    StorageStatsService::new(pool.clone(), "filesystem")
        .recompute_all()
        .await
        .expect("recompute");
}

async fn cleanup(pool: &PgPool, repo: Uuid) {
    let _ = sqlx::query("DELETE FROM repositories WHERE id = $1")
        .bind(repo)
        .execute(pool)
        .await;
}

#[tokio::test]
#[ignore]
async fn nested_prefixes_roll_up_every_ancestor_level() {
    let pool = require_db_pool().await;
    let repo = insert_repo(&pool, "filesystem").await;
    insert_artifact(&pool, repo, "libs/app/a.jar", &unique("cas/k"), 100).await;
    insert_artifact(&pool, repo, "libs/app/b.jar", &unique("cas/k"), 50).await;
    insert_artifact(&pool, repo, "libs/core/c.jar", &unique("cas/k"), 25).await;
    insert_artifact(&pool, repo, "top.txt", &unique("cas/k"), 10).await;

    recompute(&pool).await;

    let root = read_node(&pool, repo, "").await.expect("root node");
    assert_eq!(root.depth, 0);
    assert_eq!(root.logical, 185, "root sums every reference");
    assert_eq!(root.files, 4);
    assert_eq!(root.blobs, 4);

    let libs = read_node(&pool, repo, "libs").await.expect("libs node");
    assert_eq!(libs.depth, 1);
    assert_eq!(libs.logical, 175);
    assert_eq!(libs.files, 3);

    let app = read_node(&pool, repo, "libs/app").await.expect("app node");
    assert_eq!(app.depth, 2);
    assert_eq!(app.logical, 150);
    assert_eq!(app.files, 2);

    let core = read_node(&pool, repo, "libs/core")
        .await
        .expect("core node");
    assert_eq!(core.logical, 25);
    assert_eq!(core.files, 1);

    // A file's full path is never itself a prefix node.
    assert!(read_node(&pool, repo, "top.txt").await.is_none());
    assert!(read_node(&pool, repo, "libs/app/a.jar").await.is_none());

    cleanup(&pool, repo).await;
}

#[tokio::test]
#[ignore]
async fn shared_object_counts_once_at_common_ancestor() {
    let pool = require_db_pool().await;
    let repo = insert_repo(&pool, "filesystem").await;
    // One CAS object referenced from two sibling subtrees (x twice, y once).
    let key = format!("cas/aa/bb/{}", Uuid::new_v4());
    insert_artifact(&pool, repo, "x/one.bin", &key, 1000).await;
    insert_artifact(&pool, repo, "x/two.bin", &key, 1000).await;
    insert_artifact(&pool, repo, "y/three.bin", &key, 1000).await;

    recompute(&pool).await;

    let root = read_node(&pool, repo, "").await.expect("root node");
    assert_eq!(root.logical, 3000, "logical = every reference");
    assert_eq!(root.physical, 1000, "one physical object at the root");
    assert_eq!(root.files, 3);
    assert_eq!(root.blobs, 1);

    let x = read_node(&pool, repo, "x").await.expect("x node");
    assert_eq!(x.logical, 2000);
    assert_eq!(x.physical, 1000, "the object counts once within x");
    assert_eq!(x.blobs, 1);

    let y = read_node(&pool, repo, "y").await.expect("y node");
    assert_eq!(y.logical, 1000);
    assert_eq!(y.physical, 1000);

    // The dedup signal: children's physical sums past the parent's because
    // the shared object appears in both subtrees but once at the ancestor.
    assert!(x.physical + y.physical > root.physical);

    cleanup(&pool, repo).await;
}

#[tokio::test]
#[ignore]
async fn oci_layer_bytes_land_in_root_unattributed() {
    let pool = require_db_pool().await;
    let repo = insert_repo(&pool, "filesystem").await;
    // Manifests are path-bearing artifact rows; layers have no logical path.
    insert_artifact(
        &pool,
        repo,
        "v2/library/nginx/manifests/latest",
        &format!("oci-manifests/{}", Uuid::new_v4()),
        512,
    )
    .await;
    let layer = format!("sha256:{}", Uuid::new_v4().simple());
    insert_oci_blob(&pool, repo, &layer, 4096).await;

    recompute(&pool).await;

    let root = read_node(&pool, repo, "").await.expect("root node");
    assert_eq!(root.logical, 512, "tree covers path-bearing rows only");
    assert_eq!(
        root.unattributed, 4096,
        "layer bytes surface as unattributed on the root"
    );
    // logical + unattributed reconciles with the repo-level logical total.
    assert_eq!(root.logical + root.unattributed, 512 + 4096);

    // The image still groups by name through its manifest path.
    let image = read_node(&pool, repo, "v2/library/nginx")
        .await
        .expect("image node");
    assert_eq!(image.logical, 512);
    assert_eq!(image.unattributed, 0, "unattributed is a root-only figure");

    cleanup(&pool, repo).await;
}

#[tokio::test]
#[ignore]
async fn blob_only_repo_gets_a_root_row() {
    let pool = require_db_pool().await;
    let repo = insert_repo(&pool, "filesystem").await;
    insert_oci_blob(
        &pool,
        repo,
        &format!("sha256:{}", Uuid::new_v4().simple()),
        2048,
    )
    .await;

    recompute(&pool).await;

    let root = read_node(&pool, repo, "").await.expect("root node");
    assert_eq!(root.logical, 0);
    assert_eq!(root.unattributed, 2048);

    cleanup(&pool, repo).await;
}

#[tokio::test]
#[ignore]
async fn proxy_cache_rows_are_path_attributed() {
    let pool = require_db_pool().await;
    let repo = insert_repo(&pool, "filesystem").await;
    insert_proxy_cache(&pool, repo, "simple/click/click-8.0.0.whl", 300).await;

    recompute(&pool).await;

    let root = read_node(&pool, repo, "").await.expect("root node");
    assert_eq!(root.logical, 300);
    let simple = read_node(&pool, repo, "simple").await.expect("simple node");
    assert_eq!(simple.logical, 300);
    let pkg = read_node(&pool, repo, "simple/click")
        .await
        .expect("package node");
    assert_eq!(pkg.logical, 300);
    assert_eq!(pkg.files, 1);

    cleanup(&pool, repo).await;
}

#[tokio::test]
#[ignore]
async fn recompute_prunes_stale_prefixes() {
    let pool = require_db_pool().await;
    let repo = insert_repo(&pool, "filesystem").await;
    insert_artifact(&pool, repo, "old/tree/file.bin", &unique("cas/k"), 100).await;

    recompute(&pool).await;
    assert!(read_node(&pool, repo, "old/tree").await.is_some());

    sqlx::query("UPDATE artifacts SET is_deleted = true WHERE repository_id = $1")
        .bind(repo)
        .execute(&pool)
        .await
        .expect("soft-delete artifacts");

    recompute(&pool).await;
    assert!(
        read_node(&pool, repo, "old/tree").await.is_none(),
        "stale prefix rows must be pruned by the rebuild"
    );

    cleanup(&pool, repo).await;
}

#[tokio::test]
#[ignore]
async fn pathological_deep_paths_are_depth_capped() {
    let pool = require_db_pool().await;
    let repo = insert_repo(&pool, "filesystem").await;
    // 40 segments: d1/d2/.../d40 — well past the materialization cap.
    let deep: Vec<String> = (1..=40).map(|i| format!("d{i}")).collect();
    insert_artifact(&pool, repo, &deep.join("/"), &unique("cas/k"), 100).await;

    recompute(&pool).await;

    // Materialized exactly at the cap...
    let at_cap = deep[..MAX_MATERIALIZED_PATH_DEPTH as usize].join("/");
    let node = read_node(&pool, repo, &at_cap).await.expect("cap node");
    assert_eq!(node.depth, MAX_MATERIALIZED_PATH_DEPTH);
    assert_eq!(node.logical, 100, "deep file rolls up into the cap node");

    // ...but not below it.
    let below_cap = deep[..(MAX_MATERIALIZED_PATH_DEPTH as usize + 1)].join("/");
    assert!(read_node(&pool, repo, &below_cap).await.is_none());

    // Root still accounts for the file once.
    let root = read_node(&pool, repo, "").await.expect("root node");
    assert_eq!(root.logical, 100);
    assert_eq!(root.files, 1);

    cleanup(&pool, repo).await;
}

#[tokio::test]
#[ignore]
async fn leading_slash_paths_normalize_into_the_same_tree() {
    let pool = require_db_pool().await;
    let repo = insert_repo(&pool, "filesystem").await;
    insert_artifact(&pool, repo, "/abs/one.bin", &unique("cas/k"), 40).await;
    insert_artifact(&pool, repo, "abs/two.bin", &unique("cas/k"), 60).await;

    recompute(&pool).await;

    let abs = read_node(&pool, repo, "abs").await.expect("abs node");
    assert_eq!(
        abs.logical, 100,
        "leading-slash and bare paths share one node"
    );
    assert_eq!(abs.files, 2);

    cleanup(&pool, repo).await;
}
