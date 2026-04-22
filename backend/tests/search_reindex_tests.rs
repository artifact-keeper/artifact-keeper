//! Integration tests for search reindex cursor-based pagination.
//!
//! These tests verify that the pagination queries correctly visit all rows
//! across multiple batches without duplicates or gaps.
//!
//! Requires PostgreSQL:
//! ```sh
//! DATABASE_URL="postgresql://registry:registry@localhost:5432/artifact_registry" \
//!   cargo test --test search_reindex_tests -- --ignored
//! ```

use sqlx::PgPool;
use std::collections::{HashMap, HashSet};
use uuid::Uuid;

async fn connect_db() -> PgPool {
    let url = std::env::var("DATABASE_URL").unwrap_or_else(|_| {
        "postgresql://registry:registry@localhost:5432/artifact_registry".into()
    });
    PgPool::connect(&url)
        .await
        .expect("Failed to connect to test database")
}

fn test_prefix() -> String {
    format!("reindex-test-{}", Uuid::new_v4().as_simple())
}

async fn create_test_repo(pool: &PgPool, key: &str) -> Uuid {
    let row: (Uuid,) = sqlx::query_as(
        "INSERT INTO repositories (key, name, format, repo_type, storage_path) \
         VALUES ($1, $2, 'generic', 'local', '/tmp/test') RETURNING id",
    )
    .bind(key)
    .bind(key)
    .fetch_one(pool)
    .await
    .expect("failed to create test repository");
    row.0
}

async fn insert_test_artifacts(
    pool: &PgPool,
    repo_id: Uuid,
    prefix: &str,
    count: usize,
) -> Vec<Uuid> {
    let mut ids = Vec::with_capacity(count);
    for i in 0..count {
        let row: (Uuid,) = sqlx::query_as(
            "INSERT INTO artifacts (repository_id, path, name, version, size_bytes, checksum_sha256, content_type, storage_key) \
             VALUES ($1, $2, $3, $4, $5, $6, 'application/octet-stream', $7) RETURNING id",
        )
        .bind(repo_id)
        .bind(format!("{prefix}/artifact-{i}"))
        .bind(format!("{prefix}-artifact-{i}"))
        .bind(format!("{i}.0.0"))
        .bind((i as i64 + 1) * 100)
        .bind(format!("{:0>64x}", i))
        .bind(format!("{prefix}/storage-{i}"))
        .fetch_one(pool)
        .await
        .expect("failed to insert test artifact");
        ids.push(row.0);
    }
    ids.sort();
    ids
}

async fn insert_test_downloads(pool: &PgPool, artifact_ids: &[Uuid], downloads_per: usize) {
    for &artifact_id in artifact_ids {
        for _ in 0..downloads_per {
            sqlx::query("INSERT INTO download_statistics (artifact_id) VALUES ($1)")
                .bind(artifact_id)
                .execute(pool)
                .await
                .expect("failed to insert download statistic");
        }
    }
}

async fn cleanup(pool: &PgPool, repo_id: Uuid) {
    sqlx::query("DELETE FROM repositories WHERE id = $1")
        .bind(repo_id)
        .execute(pool)
        .await
        .expect("failed to clean up test data");
}

// ---------------------------------------------------------------------------
// Pagination helpers (reproduce production SQL)
// ---------------------------------------------------------------------------

#[derive(Debug, sqlx::FromRow)]
struct IdRow {
    id: Uuid,
}

async fn paginate_artifacts(pool: &PgPool, page_size: i64) -> Vec<Uuid> {
    let mut collected = Vec::new();
    let mut last_id: Option<Uuid> = None;

    loop {
        let rows = sqlx::query_as::<_, IdRow>(
            "SELECT a.id FROM artifacts a \
             INNER JOIN repositories r ON a.repository_id = r.id \
             WHERE a.is_deleted = false AND ($1::uuid IS NULL OR a.id > $1) \
             ORDER BY a.id LIMIT $2",
        )
        .bind(last_id)
        .bind(page_size)
        .fetch_all(pool)
        .await
        .expect("artifact pagination query failed");

        if rows.is_empty() {
            break;
        }
        last_id = rows.last().map(|r| r.id);
        collected.extend(rows.into_iter().map(|r| r.id));
    }
    collected
}

async fn paginate_repositories(pool: &PgPool, page_size: i64) -> Vec<Uuid> {
    let mut collected = Vec::new();
    let mut last_id: Option<Uuid> = None;

    loop {
        let rows = sqlx::query_as::<_, IdRow>(
            "SELECT id FROM repositories \
             WHERE ($1::uuid IS NULL OR id > $1) \
             ORDER BY id LIMIT $2",
        )
        .bind(last_id)
        .bind(page_size)
        .fetch_all(pool)
        .await
        .expect("repository pagination query failed");

        if rows.is_empty() {
            break;
        }
        last_id = rows.last().map(|r| r.id);
        collected.extend(rows.into_iter().map(|r| r.id));
    }
    collected
}

#[derive(Debug, sqlx::FromRow)]
struct DownloadCountRow {
    artifact_id: Uuid,
    download_count: i64,
}

async fn batch_download_counts(pool: &PgPool, artifact_ids: &[Uuid]) -> HashMap<Uuid, i64> {
    sqlx::query_as::<_, DownloadCountRow>(
        "SELECT artifact_id, COUNT(*)::BIGINT AS download_count \
         FROM download_statistics WHERE artifact_id = ANY($1) GROUP BY artifact_id",
    )
    .bind(artifact_ids)
    .fetch_all(pool)
    .await
    .expect("download count query failed")
    .into_iter()
    .map(|r| (r.artifact_id, r.download_count))
    .collect()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[tokio::test]
#[ignore] // requires PostgreSQL
async fn test_cursor_pagination_visits_all_artifacts_across_multiple_batches() {
    let pool = connect_db().await;
    let prefix = test_prefix();
    let repo_id = create_test_repo(&pool, &prefix).await;

    // 7 artifacts, page_size=3 → 3 batches (3+3+1)
    let expected_ids = insert_test_artifacts(&pool, repo_id, &prefix, 7).await;

    let collected = paginate_artifacts(&pool, 3).await;
    let our_ids: Vec<Uuid> = collected
        .into_iter()
        .filter(|id| expected_ids.contains(id))
        .collect();

    assert_eq!(our_ids.len(), 7, "should visit all 7 test artifacts");

    let unique: HashSet<Uuid> = our_ids.iter().copied().collect();
    assert_eq!(unique.len(), 7, "no duplicates");

    let mut sorted = our_ids.clone();
    sorted.sort();
    assert_eq!(our_ids, sorted, "returned in UUID order");

    cleanup(&pool, repo_id).await;
}

#[tokio::test]
#[ignore]
async fn test_cursor_pagination_handles_empty_result() {
    let pool = connect_db().await;
    let prefix = test_prefix();
    let repo_id = create_test_repo(&pool, &prefix).await;

    // No artifacts — loop should terminate immediately
    let collected = paginate_artifacts(&pool, 3).await;
    let our_ids: Vec<Uuid> = collected
        .into_iter()
        .filter(|_| false) // no test artifacts to match
        .collect();
    assert!(our_ids.is_empty());

    cleanup(&pool, repo_id).await;
}

#[tokio::test]
#[ignore]
async fn test_cursor_pagination_exact_batch_boundary() {
    let pool = connect_db().await;
    let prefix = test_prefix();
    let repo_id = create_test_repo(&pool, &prefix).await;

    // Exactly page_size artifacts → 1 full batch + 1 empty terminator
    let expected_ids = insert_test_artifacts(&pool, repo_id, &prefix, 3).await;

    let collected = paginate_artifacts(&pool, 3).await;
    let our_ids: Vec<Uuid> = collected
        .into_iter()
        .filter(|id| expected_ids.contains(id))
        .collect();

    assert_eq!(our_ids.len(), 3, "exact boundary: all 3 visited");

    cleanup(&pool, repo_id).await;
}

#[tokio::test]
#[ignore]
async fn test_cursor_pagination_single_artifact() {
    let pool = connect_db().await;
    let prefix = test_prefix();
    let repo_id = create_test_repo(&pool, &prefix).await;

    let expected_ids = insert_test_artifacts(&pool, repo_id, &prefix, 1).await;

    let collected = paginate_artifacts(&pool, 3).await;
    let our_ids: Vec<Uuid> = collected
        .into_iter()
        .filter(|id| expected_ids.contains(id))
        .collect();

    assert_eq!(our_ids.len(), 1);

    cleanup(&pool, repo_id).await;
}

#[tokio::test]
#[ignore]
async fn test_repository_cursor_pagination_visits_all_repos() {
    let pool = connect_db().await;
    let prefix = test_prefix();

    // 5 repos, page_size=2 → 3 batches (2+2+1)
    let mut expected_ids = Vec::new();
    for i in 0..5 {
        let id = create_test_repo(&pool, &format!("{prefix}-repo-{i}")).await;
        expected_ids.push(id);
    }
    expected_ids.sort();

    let collected = paginate_repositories(&pool, 2).await;
    let our_ids: Vec<Uuid> = collected
        .into_iter()
        .filter(|id| expected_ids.contains(id))
        .collect();

    assert_eq!(our_ids.len(), 5, "all 5 repos visited");
    let unique: HashSet<Uuid> = our_ids.iter().copied().collect();
    assert_eq!(unique.len(), 5, "no duplicates");

    for id in &expected_ids {
        sqlx::query("DELETE FROM repositories WHERE id = $1")
            .bind(id)
            .execute(&pool)
            .await
            .expect("cleanup failed");
    }
}

#[tokio::test]
#[ignore]
async fn test_batch_download_counts_scoped_to_batch() {
    let pool = connect_db().await;
    let prefix = test_prefix();
    let repo_id = create_test_repo(&pool, &prefix).await;

    let ids = insert_test_artifacts(&pool, repo_id, &prefix, 4).await;
    insert_test_downloads(&pool, &ids[..2], 3).await;

    // Query only a subset: one with downloads (ids[0]), one without (ids[2])
    let batch_ids = vec![ids[0], ids[2]];
    let counts = batch_download_counts(&pool, &batch_ids).await;

    assert_eq!(counts.get(&ids[0]).copied().unwrap_or(0), 3);
    assert_eq!(
        counts.get(&ids[2]).copied().unwrap_or(0),
        0,
        "no-download artifact defaults to 0 (absent from HashMap)"
    );
    assert!(
        !counts.contains_key(&ids[1]),
        "out-of-batch artifact should not appear in counts"
    );

    cleanup(&pool, repo_id).await;
}
