//! Invariant tests for keyset-paged grouped listings (#2520).
//!
//! The grouped Docker (`group_by=docker_tag`) and remote-Maven
//! (`group_by=maven_component`) listings previously materialized up to a
//! `MAX_FETCH = 10_000` row batch (Docker) or the ENTIRE catalog with no
//! LIMIT (remote Maven) and then sorted/paged in memory. Above the bound,
//! totals and page contents silently truncated: a repository with 10 001
//! tags reported `total == 10_000` and one tag could never be listed.
//!
//! These tests seed 10 001 rows — one past the old bound — and assert that
//! (a) `?count=exact` reports exactly 10 001 and (b) walking the full keyset
//! via `next_cursor` returns every row exactly once, in order. Both
//! assertions fail on the pre-#2520 implementation by construction.
//!
//! Requires a PostgreSQL database with migrations applied:
//!
//! ```sh
//! DATABASE_URL="postgresql://registry:registry@localhost:5432/artifact_registry" \
//!   cargo test --test grouped_listing_keyset_tests -- --ignored
//! ```

#![allow(clippy::unwrap_used)]

use std::collections::HashMap;
use std::sync::Arc;

use axum::extract::{Path, Query, State};
use axum::Extension;
use sqlx::PgPool;
use uuid::Uuid;

use artifact_keeper_backend::api::handlers::repositories::{
    list_artifacts, ArtifactListResponse, ListArtifactsQuery,
};
use artifact_keeper_backend::api::{AppState, SharedState};
use artifact_keeper_backend::config::Config;

mod common;

/// One row past the old in-memory materialization bound.
const SEEDED: i64 = 10_001;
const PER_PAGE: u32 = 100;

fn test_config(storage_path: &str) -> Config {
    Config {
        database_url: std::env::var("DATABASE_URL").unwrap_or_default(),
        storage_path: storage_path.into(),
        jwt_secret: "test-secret-at-least-32-bytes-long-for-testing".into(),
        setup_password_hint: None,
        ..Default::default()
    }
}

fn build_state(pool: PgPool, storage_path: &str) -> SharedState {
    let storage: Arc<dyn artifact_keeper_backend::storage::StorageBackend> = Arc::new(
        artifact_keeper_backend::storage::filesystem::FilesystemStorage::new(storage_path),
    );
    let registry = Arc::new(artifact_keeper_backend::storage::StorageRegistry::new(
        HashMap::new(),
        "filesystem".to_string(),
    ));
    Arc::new(AppState::new(
        test_config(storage_path),
        pool,
        storage,
        registry,
    ))
}

/// Call the real `list_artifacts` handler as an anonymous user against a
/// public repository, returning the deserializable response body.
async fn list(
    state: &SharedState,
    key: &str,
    group_by: &str,
    cursor: Option<String>,
    count_exact: bool,
) -> ArtifactListResponse {
    let query = ListArtifactsQuery {
        page: None,
        per_page: Some(PER_PAGE),
        q: None,
        path_prefix: None,
        group_by: Some(group_by.to_string()),
        cursor,
        count: count_exact.then(|| "exact".to_string()),
    };
    list_artifacts(
        State(state.clone()),
        Extension(None),
        Path(key.to_string()),
        Query(query),
    )
    .await
    .expect("list_artifacts failed")
    .0
}

/// Walk the whole listing via `next_cursor`, asserting exact-total on the
/// first page. Returns the pages' concatenated group values.
async fn walk_keyset<F>(state: &SharedState, key: &str, group_by: &str, extract: F) -> Vec<String>
where
    F: Fn(&ArtifactListResponse) -> Vec<String>,
{
    let mut collected: Vec<String> = Vec::new();
    let mut cursor: Option<String> = None;
    let mut pages = 0u32;
    loop {
        // Only ask for the exact count on the first page: the walk itself
        // must be exact without paying a COUNT per request.
        let resp = list(state, key, group_by, cursor.clone(), cursor.is_none()).await;
        if cursor.is_none() {
            assert_eq!(
                resp.pagination.total, SEEDED,
                "?count=exact total must be exact above the old 10k bound \
                 (pre-#2520 code reported the truncated batch size)"
            );
        }
        collected.extend(extract(&resp));
        pages += 1;
        assert!(pages <= 200, "cursor walk did not terminate");
        match (resp.has_more, resp.next_cursor) {
            (Some(true), Some(next)) => cursor = Some(next),
            (Some(false), None) => break,
            (has_more, next_cursor) => panic!(
                "inconsistent keyset paging signals: has_more={:?} next_cursor={:?}",
                has_more, next_cursor
            ),
        }
    }
    collected
}

async fn cleanup_repo(pool: &PgPool, repo_id: Uuid) {
    for table in ["packages", "oci_tags", "artifacts", "repositories"] {
        let sql = if table == "repositories" {
            format!("DELETE FROM {table} WHERE id = $1")
        } else {
            format!("DELETE FROM {table} WHERE repository_id = $1")
        };
        sqlx::query(&sql).bind(repo_id).execute(pool).await.ok();
    }
}

// ===========================================================================
// Docker: group_by=docker_tag over 10 001 (image, tag) rows
// ===========================================================================

#[tokio::test]
#[ignore] // requires DATABASE_URL with migrations applied
async fn docker_tag_grouping_is_exact_above_ten_thousand_tags() {
    let pool = common::require_db_pool().await;
    let repo_id = Uuid::new_v4();
    let key = format!("pf003-docker-{}", &repo_id.to_string()[..8]);
    let storage_path = std::env::temp_dir().join(format!("pf003-{repo_id}"));
    std::fs::create_dir_all(&storage_path).unwrap();

    sqlx::query(
        "INSERT INTO repositories (id, key, name, storage_path, repo_type, format, is_public) \
         VALUES ($1, $2, $2, $3, 'local', 'docker'::repository_format, true)",
    )
    .bind(repo_id)
    .bind(&key)
    .bind(storage_path.to_string_lossy().as_ref())
    .execute(&pool)
    .await
    .expect("insert docker repo");

    // Seed 10 001 tags for one image, each with the matching artifacts row
    // the grouped listing joins on (path = v2/{image}/manifests/{tag}).
    sqlx::query(
        "INSERT INTO artifacts \
             (repository_id, path, name, version, size_bytes, checksum_sha256, \
              content_type, storage_key) \
         SELECT $1, 'v2/app/manifests/t' || lpad(i::text, 6, '0'), 'app', NULL, 100 + i, \
                lpad(i::text, 64, '0'), \
                'application/vnd.docker.distribution.manifest.v2+json', \
                'pf003/' || lpad(i::text, 6, '0') \
         FROM generate_series(1, $2) AS g(i)",
    )
    .bind(repo_id)
    .bind(SEEDED)
    .execute(&pool)
    .await
    .expect("seed artifacts");
    sqlx::query(
        "INSERT INTO oci_tags \
             (repository_id, name, tag, manifest_digest, manifest_content_type) \
         SELECT $1, 'app', 't' || lpad(i::text, 6, '0'), \
                'sha256:' || lpad(i::text, 64, '0'), \
                'application/vnd.docker.distribution.manifest.v2+json' \
         FROM generate_series(1, $2) AS g(i)",
    )
    .bind(repo_id)
    .bind(SEEDED)
    .execute(&pool)
    .await
    .expect("seed oci_tags");

    let state = build_state(pool.clone(), storage_path.to_string_lossy().as_ref());

    let collected = walk_keyset(&state, &key, "docker_tag", |resp| {
        resp.docker_tags
            .as_ref()
            .expect("docker_tags present in grouped mode")
            .iter()
            .map(|t| t.tag.clone())
            .collect()
    })
    .await;

    // Every seeded tag, exactly once, in (image, tag) keyset order.
    assert_eq!(
        collected.len() as i64,
        SEEDED,
        "cursor walk must surface every tag (pre-#2520 code dropped rows past 10k)"
    );
    for (idx, tag) in collected.iter().enumerate() {
        assert_eq!(
            tag,
            &format!("t{:06}", idx + 1),
            "page contents must be exact and ordered at position {idx}"
        );
    }

    cleanup_repo(&pool, repo_id).await;
    std::fs::remove_dir_all(&storage_path).ok();
}

// ===========================================================================
// Remote Maven: group_by=maven_component over 10 001 catalog rows
// ===========================================================================

#[tokio::test]
#[ignore] // requires DATABASE_URL with migrations applied
async fn remote_maven_component_grouping_is_exact_above_ten_thousand_components() {
    let pool = common::require_db_pool().await;
    let repo_id = Uuid::new_v4();
    let key = format!("pf003-maven-{}", &repo_id.to_string()[..8]);
    let storage_path = std::env::temp_dir().join(format!("pf003-{repo_id}"));
    std::fs::create_dir_all(&storage_path).unwrap();

    sqlx::query(
        "INSERT INTO repositories \
             (id, key, name, storage_path, repo_type, format, upstream_url, is_public) \
         VALUES ($1, $2, $2, $3, 'remote', 'maven'::repository_format, \
                 'https://repo1.maven.org/maven2', true)",
    )
    .bind(repo_id)
    .bind(&key)
    .bind(storage_path.to_string_lossy().as_ref())
    .execute(&pool)
    .await
    .expect("insert remote maven repo");

    // Seed 10 001 well-formed `groupId:artifactId` catalog rows plus one
    // malformed row (no separator): the malformed row must be excluded from
    // both the exact count and the walked pages.
    sqlx::query(
        "INSERT INTO packages (repository_id, name, version, size_bytes, download_count) \
         SELECT $1, 'com.example:lib' || lpad(i::text, 6, '0'), '1.0.0', 10 + i, 0 \
         FROM generate_series(1, $2) AS g(i)",
    )
    .bind(repo_id)
    .bind(SEEDED)
    .execute(&pool)
    .await
    .expect("seed packages");
    sqlx::query(
        "INSERT INTO packages (repository_id, name, version, size_bytes, download_count) \
         VALUES ($1, 'malformed-no-separator', '9.9.9', 1, 0)",
    )
    .bind(repo_id)
    .execute(&pool)
    .await
    .expect("seed malformed package row");

    let state = build_state(pool.clone(), storage_path.to_string_lossy().as_ref());

    let collected = walk_keyset(&state, &key, "maven_component", |resp| {
        resp.components
            .as_ref()
            .expect("components present in grouped mode")
            .iter()
            .map(|c| format!("{}:{}", c.group_id, c.artifact_id))
            .collect()
    })
    .await;

    assert_eq!(
        collected.len() as i64,
        SEEDED,
        "cursor walk must surface every component exactly once \
         (pre-#2520 code fetched the whole catalog unbounded and paged in memory)"
    );
    for (idx, name) in collected.iter().enumerate() {
        assert_eq!(
            name,
            &format!("com.example:lib{:06}", idx + 1),
            "component order/contents must be exact at position {idx}"
        );
    }
    assert!(
        !collected.iter().any(|n| n.contains("malformed")),
        "malformed catalog rows must not surface as components"
    );

    cleanup_repo(&pool, repo_id).await;
    std::fs::remove_dir_all(&storage_path).ok();
}
