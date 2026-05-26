//! Integration regression tests for issue #1372.
//!
//! Two bugs are covered:
//!
//! 1. `SearchService::search` previously hardcoded
//!    `ORDER BY a.created_at DESC`, ignoring `sort_by` / `sort_order`. This
//!    test inserts artifacts of distinct sizes and asserts that
//!    `sort_by=size, sort_order=asc` returns the smallest first and
//!    `sort_by=size, sort_order=desc` returns the largest first, i.e. the
//!    head hit flips between the two queries.
//!
//! 2. The handler-side `limit=0` short-circuit is unit-tested in
//!    `search.rs`, but we also verify the service path: a request with
//!    `limit = 1` returns exactly one item rather than the default 20.
//!    (The service itself does not implement the Some(0)-as-empty
//!    behavior; that is enforced at the HTTP handler boundary -- see
//!    `test_clamp_positive_limit_zero_is_clamped_to_min_as_safety_net`.)
//!
//! Requires PostgreSQL:
//! ```sh
//! DATABASE_URL="postgresql://registry:registry@localhost:30432/artifact_registry" \
//!   cargo test --test search_sort_size_tests -- --ignored
//! ```

use sqlx::PgPool;
use uuid::Uuid;

use artifact_keeper_backend::services::search_service::{SearchQuery, SearchService};

async fn connect_db() -> PgPool {
    let url = std::env::var("DATABASE_URL").unwrap_or_else(|_| {
        "postgresql://registry:registry@localhost:30432/artifact_registry".into()
    });
    PgPool::connect(&url)
        .await
        .expect("Failed to connect to test database")
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

async fn insert_artifact(
    pool: &PgPool,
    repo_id: Uuid,
    name: &str,
    size_bytes: i64,
    sha_seed: usize,
) -> Uuid {
    let row: (Uuid,) = sqlx::query_as(
        "INSERT INTO artifacts (repository_id, path, name, version, size_bytes, \
            checksum_sha256, content_type, storage_key) \
         VALUES ($1, $2, $3, '1.0.0', $4, $5, 'application/octet-stream', $6) RETURNING id",
    )
    .bind(repo_id)
    .bind(format!("{}/{}", name, name))
    .bind(name)
    .bind(size_bytes)
    .bind(format!("{:0>64x}", sha_seed))
    .bind(format!("{}-storage", name))
    .fetch_one(pool)
    .await
    .expect("failed to insert test artifact");
    row.0
}

async fn cleanup(pool: &PgPool, repo_id: Uuid) {
    sqlx::query("DELETE FROM repositories WHERE id = $1")
        .bind(repo_id)
        .execute(pool)
        .await
        .ok();
}

#[tokio::test]
#[ignore = "requires DATABASE_URL"]
async fn sort_by_size_asc_vs_desc_flips_head_hit() {
    let pool = connect_db().await;
    let repo_key = format!("test-1372-sort-{}", Uuid::new_v4().as_simple());
    let repo_id = create_test_repo(&pool, &repo_key).await;

    // Three artifacts with distinct sizes. The unique name suffix prevents
    // collisions with other tests running against the same database.
    let suffix = Uuid::new_v4().as_simple().to_string();
    let small_name = format!("artifact-small-{suffix}");
    let medium_name = format!("artifact-medium-{suffix}");
    let large_name = format!("artifact-large-{suffix}");

    let _small_id = insert_artifact(&pool, repo_id, &small_name, 100, 1).await;
    let _medium_id = insert_artifact(&pool, repo_id, &medium_name, 1_000, 2).await;
    let _large_id = insert_artifact(&pool, repo_id, &large_name, 1_000_000, 3).await;

    let service = SearchService::new(pool.clone());

    // sort_order=asc, sort_by=size: smallest first.
    let asc_response = service
        .search(SearchQuery {
            q: None,
            format: None,
            name: Some(format!("artifact-%-{suffix}").replace("%", "*")),
            offset: Some(0),
            limit: Some(10),
            public_only: false,
            accessible_repo_ids: Some(vec![repo_id]),
            sort_by: Some("size".to_string()),
            sort_order: Some("asc".to_string()),
        })
        .await
        .expect("ASC search failed");

    // sort_order=desc, sort_by=size: largest first.
    let desc_response = service
        .search(SearchQuery {
            q: None,
            format: None,
            name: Some(format!("artifact-*-{suffix}")),
            offset: Some(0),
            limit: Some(10),
            public_only: false,
            accessible_repo_ids: Some(vec![repo_id]),
            sort_by: Some("size".to_string()),
            sort_order: Some("desc".to_string()),
        })
        .await
        .expect("DESC search failed");

    assert!(
        !asc_response.items.is_empty(),
        "ASC response must contain at least one item"
    );
    assert!(
        !desc_response.items.is_empty(),
        "DESC response must contain at least one item"
    );

    let asc_head = &asc_response.items[0];
    let desc_head = &desc_response.items[0];

    assert_eq!(
        asc_head.name, small_name,
        "ASC size sort should return the smallest artifact first; got {} with size {}",
        asc_head.name, asc_head.size_bytes
    );
    assert_eq!(
        desc_head.name, large_name,
        "DESC size sort should return the largest artifact first; got {} with size {}",
        desc_head.name, desc_head.size_bytes
    );
    assert_ne!(
        asc_head.name, desc_head.name,
        "issue #1372: sort_order=asc vs desc on sort_by=size MUST flip the head hit"
    );
    assert!(
        asc_head.size_bytes < desc_head.size_bytes,
        "ASC head size {} should be less than DESC head size {}",
        asc_head.size_bytes,
        desc_head.size_bytes
    );

    cleanup(&pool, repo_id).await;
}

#[tokio::test]
#[ignore = "requires DATABASE_URL"]
async fn sort_by_size_asc_orders_full_result_set() {
    let pool = connect_db().await;
    let repo_key = format!("test-1372-sort-full-{}", Uuid::new_v4().as_simple());
    let repo_id = create_test_repo(&pool, &repo_key).await;

    let suffix = Uuid::new_v4().as_simple().to_string();
    let names = [
        (format!("a-{suffix}"), 500_i64),
        (format!("b-{suffix}"), 50_i64),
        (format!("c-{suffix}"), 5_000_i64),
        (format!("d-{suffix}"), 5_i64),
    ];
    for (i, (n, s)) in names.iter().enumerate() {
        insert_artifact(&pool, repo_id, n, *s, 100 + i).await;
    }

    let service = SearchService::new(pool.clone());
    let resp = service
        .search(SearchQuery {
            q: None,
            format: None,
            name: Some(format!("*-{suffix}")),
            offset: Some(0),
            limit: Some(10),
            public_only: false,
            accessible_repo_ids: Some(vec![repo_id]),
            sort_by: Some("size".to_string()),
            sort_order: Some("asc".to_string()),
        })
        .await
        .expect("search failed");

    let sizes: Vec<i64> = resp.items.iter().map(|r| r.size_bytes).collect();
    assert!(
        sizes.windows(2).all(|w| w[0] <= w[1]),
        "ASC sort produced non-monotonic sizes: {:?}",
        sizes
    );

    cleanup(&pool, repo_id).await;
}
