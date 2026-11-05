//! Pagination totals of the artifact listing (#5255).
//!
//! A remote repository's listing reported `pagination.total` and
//! `total_pages` as lower bounds that looked exact: with 10 cached items at
//! `per_page=3`, page 1 said `total=4, total_pages=2`, so a client that read
//! `total_pages` from the first response and looped to it fetched 6 of the
//! 10 items. A page past the end said `total=12`.
//!
//! These tests seed 10 rows and walk the listing both ways, by `page` up to
//! the first response's `total_pages` and by `next_cursor` while `has_more`,
//! asserting that every item is reached, that the remote listing's totals are
//! exact by default on `page=N` requests, that any lower-bound total is
//! flagged with `total_is_exact: false`, and that a page past the end
//! reports the real total.
//!
//! Requires a PostgreSQL database with migrations applied:
//!
//! ```sh
//! AK_TESTS_REQUIRE_DB=1 \
//! DATABASE_URL="postgresql://registry:registry@localhost:5432/artifact_registry" \
//!   cargo nextest run --run-ignored ignored-only --test listing_totals_tests
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

const SEEDED: usize = 10;
const PER_PAGE: u32 = 3;

fn build_state(pool: PgPool, storage_path: &str) -> SharedState {
    let config = Config {
        database_url: std::env::var("DATABASE_URL").unwrap_or_default(),
        storage_path: storage_path.into(),
        jwt_secret: "test-secret-at-least-32-bytes-long-for-testing".into(),
        setup_password_hint: None,
        ..Default::default()
    };
    let storage: Arc<dyn artifact_keeper_backend::storage::StorageBackend> = Arc::new(
        artifact_keeper_backend::storage::filesystem::FilesystemStorage::new(storage_path),
    );
    let registry = Arc::new(artifact_keeper_backend::storage::StorageRegistry::new(
        HashMap::new(),
        "filesystem".to_string(),
    ));
    Arc::new(AppState::new(config, pool, storage, registry))
}

/// One page of the real `list_artifacts` handler, as an anonymous caller of
/// a public repository.
async fn list(
    state: &SharedState,
    key: &str,
    page: Option<u32>,
    cursor: Option<String>,
    count: Option<&str>,
) -> ArtifactListResponse {
    let query = ListArtifactsQuery {
        page,
        per_page: Some(PER_PAGE),
        q: None,
        path_prefix: None,
        group_by: None,
        cursor,
        count: count.map(str::to_string),
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

fn paths(resp: &ArtifactListResponse) -> Vec<String> {
    resp.items.iter().map(|i| i.path.clone()).collect()
}

/// The naive client from #5255: read `total_pages` from page 1, fetch pages
/// 1..=total_pages. Returns (page-1 response, every path collected).
async fn walk_to_first_total_pages(
    state: &SharedState,
    key: &str,
    count: Option<&str>,
) -> (ArtifactListResponse, Vec<String>) {
    let first = list(state, key, Some(1), None, count).await;
    let mut collected = paths(&first);
    for page in 2..=first.pagination.total_pages {
        collected.extend(paths(&list(state, key, Some(page), None, count).await));
    }
    (first, collected)
}

/// Follow `next_cursor` while `has_more`. Returns every page's response.
async fn walk_cursor(
    state: &SharedState,
    key: &str,
    count: Option<&str>,
) -> Vec<ArtifactListResponse> {
    let mut pages = Vec::new();
    let mut cursor = None;
    loop {
        let resp = list(state, key, None, cursor.take(), count).await;
        assert!(pages.len() < 20, "cursor walk did not terminate");
        let next = match (resp.has_more, resp.next_cursor.clone()) {
            (Some(true), Some(next)) => Some(next),
            (Some(false), None) => None,
            (has_more, next) => {
                panic!("inconsistent paging signals: has_more={has_more:?} next_cursor={next:?}")
            }
        };
        pages.push(resp);
        match next {
            Some(next) => cursor = Some(next),
            None => break,
        }
    }
    pages
}

/// Follow `page + 1` while `has_more`. Returns every page's response.
async fn walk_pages_by_has_more(
    state: &SharedState,
    key: &str,
    count: Option<&str>,
) -> Vec<ArtifactListResponse> {
    let mut pages = Vec::new();
    for page in 1.. {
        let resp = list(state, key, Some(page), None, count).await;
        let more = resp.has_more == Some(true);
        pages.push(resp);
        assert!(pages.len() < 20, "page walk did not terminate");
        if !more {
            break;
        }
    }
    pages
}

async fn insert_repo(pool: &PgPool, repo_id: Uuid, key: &str, storage_path: &str, kind: &str) {
    sqlx::query(
        "INSERT INTO repositories \
             (id, key, name, storage_path, repo_type, format, is_public, upstream_url) \
         VALUES ($1, $2, $2, $3, $4::repository_type, 'generic'::repository_format, true, \
                 CASE WHEN $4 = 'remote' THEN 'https://upstream.invalid/' END)",
    )
    .bind(repo_id)
    .bind(key)
    .bind(storage_path)
    .bind(kind)
    .execute(pool)
    .await
    .expect("insert repository");
}

async fn cleanup_repo(pool: &PgPool, repo_id: Uuid) {
    for sql in [
        "DELETE FROM proxy_cache_artifacts WHERE repository_id = $1",
        "DELETE FROM artifacts WHERE repository_id = $1",
        "DELETE FROM repositories WHERE id = $1",
    ] {
        sqlx::query(sql).bind(repo_id).execute(pool).await.ok();
    }
}

fn expected_paths() -> Vec<String> {
    (1..=SEEDED)
        .map(|i| format!("v3.24/main/x86_64/pkg-{i:02}-1.0-r0.apk"))
        .collect()
}

/// A remote repository whose proxy-cache catalog holds the 10 expected
/// packages plus one cached index response, which the listing (and its
/// COUNT) must both leave out.
async fn seed_remote(pool: &PgPool) -> (Uuid, String, std::path::PathBuf) {
    let repo_id = Uuid::new_v4();
    let key = format!("totals-remote-{}", &repo_id.to_string()[..8]);
    let storage_path = std::env::temp_dir().join(format!("totals-{repo_id}"));
    std::fs::create_dir_all(&storage_path).unwrap();
    insert_repo(
        pool,
        repo_id,
        &key,
        storage_path.to_string_lossy().as_ref(),
        "remote",
    )
    .await;
    let mut cached = expected_paths();
    cached.push("simple/pkg/".to_string());
    for path in &cached {
        sqlx::query(
            "INSERT INTO proxy_cache_artifacts \
                 (repository_id, path, storage_key, metadata_key, size_bytes, checksum_sha256) \
             VALUES ($1, $2, $3, $4, 1282, 'f00d')",
        )
        .bind(repo_id)
        .bind(path)
        .bind(format!("proxy-cache/{key}/{path}/__content__"))
        .bind(format!("proxy-cache/{key}/{path}/__cache_meta__.json"))
        .execute(pool)
        .await
        .expect("seed catalog row");
    }
    (repo_id, key, storage_path)
}

/// A hosted repository holding the 10 expected paths.
async fn seed_hosted(pool: &PgPool) -> (Uuid, String, std::path::PathBuf) {
    let repo_id = Uuid::new_v4();
    let key = format!("totals-local-{}", &repo_id.to_string()[..8]);
    let storage_path = std::env::temp_dir().join(format!("totals-{repo_id}"));
    std::fs::create_dir_all(&storage_path).unwrap();
    insert_repo(
        pool,
        repo_id,
        &key,
        storage_path.to_string_lossy().as_ref(),
        "local",
    )
    .await;
    for (i, path) in expected_paths().iter().enumerate() {
        sqlx::query(
            "INSERT INTO artifacts \
                 (repository_id, path, name, version, size_bytes, checksum_sha256, \
                  content_type, storage_key) \
             VALUES ($1, $2, $3, '1.0', 1282, $4, 'application/octet-stream', $5)",
        )
        .bind(repo_id)
        .bind(path)
        .bind(format!("pkg-{:02}", i + 1))
        .bind(format!("{:064}", i + 1))
        .bind(format!("totals/{repo_id}/{i}"))
        .execute(pool)
        .await
        .expect("seed artifact");
    }
    (repo_id, key, storage_path)
}

// ===========================================================================
// Remote: exact by default
// ===========================================================================

#[tokio::test]
#[ignore] // requires DATABASE_URL with migrations applied
async fn remote_listing_totals_are_exact_and_every_walk_reaches_every_item() {
    let pool = common::require_db_pool().await;
    let (repo_id, key, storage_path) = seed_remote(&pool).await;
    let state = build_state(pool.clone(), storage_path.to_string_lossy().as_ref());
    let expected = expected_paths();

    // The #5255 client: loop to page 1's total_pages. Pre-fix page 1 said
    // total=4 / total_pages=2 and this walk collected 6 of the 10 items.
    let (first, collected) = walk_to_first_total_pages(&state, &key, None).await;
    assert_eq!(first.pagination.total, SEEDED as i64, "page 1 total");
    assert_eq!(first.pagination.total_pages, 4, "page 1 total_pages");
    assert_eq!(first.total_is_exact, Some(true));
    assert_eq!(collected, expected, "total_pages walk reaches every item");

    // `page + 1` while has_more: same items, the same exact total on every page.
    let pages = walk_pages_by_has_more(&state, &key, None).await;
    assert_eq!(pages.len(), 4);
    for (n, resp) in pages.iter().enumerate() {
        assert_eq!(resp.pagination.total, SEEDED as i64, "page {} total", n + 1);
        assert_eq!(resp.pagination.total_pages, 4, "page {} total_pages", n + 1);
        assert_eq!(resp.total_is_exact, Some(true), "page {}", n + 1);
    }
    let walked: Vec<String> = pages.iter().flat_map(paths).collect();
    assert_eq!(walked, expected, "page walk reaches every item");

    // Cursor walk: the first request (no cursor yet) is exact, so a cursor
    // client also learns the real total up front. Later `?cursor=` pages skip
    // the O(repository) COUNT by default, keeping the walk O(page) per
    // request, and say so.
    let pages = walk_cursor(&state, &key, None).await;
    assert_eq!(pages.len(), 4);
    assert_eq!(pages[0].pagination.total, SEEDED as i64);
    assert_eq!(pages[0].pagination.total_pages, 4);
    assert_eq!(pages[0].total_is_exact, Some(true));
    for (n, resp) in pages.iter().enumerate().skip(1) {
        assert_eq!(resp.total_is_exact, Some(false), "cursor page {}", n + 1);
    }
    let walked: Vec<String> = pages.iter().flat_map(paths).collect();
    assert_eq!(walked, expected, "cursor walk reaches every item");

    // `count=exact` makes cursor pages exact too.
    let pages = walk_cursor(&state, &key, Some("exact")).await;
    for (n, resp) in pages.iter().enumerate() {
        assert_eq!(
            resp.pagination.total,
            SEEDED as i64,
            "cursor page {}",
            n + 1
        );
        assert_eq!(resp.pagination.total_pages, 4, "cursor page {}", n + 1);
        assert_eq!(resp.total_is_exact, Some(true), "cursor page {}", n + 1);
    }
    let walked: Vec<String> = pages.iter().flat_map(paths).collect();
    assert_eq!(walked, expected, "cursor walk reaches every item");

    // Past the end: no items, and the real total (pre-fix: total=12).
    let past = list(&state, &key, Some(5), None, None).await;
    assert!(past.items.is_empty());
    assert_eq!(past.pagination.total, SEEDED as i64, "past-end total");
    assert_eq!(past.pagination.total_pages, 4);
    assert_eq!(past.has_more, Some(false));
    assert_eq!(past.total_is_exact, Some(true));

    cleanup_repo(&pool, repo_id).await;
    std::fs::remove_dir_all(&storage_path).ok();
}

#[tokio::test]
#[ignore] // requires DATABASE_URL with migrations applied
async fn remote_listing_lower_bound_opt_out_is_flagged() {
    let pool = common::require_db_pool().await;
    let (repo_id, key, storage_path) = seed_remote(&pool).await;
    let state = build_state(pool.clone(), storage_path.to_string_lossy().as_ref());
    let opt_out = Some("lower_bound");

    // `count=lower_bound` restores the cheap total, and says it is one.
    let pages = walk_pages_by_has_more(&state, &key, opt_out).await;
    let seen: Vec<(i64, u32, Option<bool>)> = pages
        .iter()
        .map(|r| {
            (
                r.pagination.total,
                r.pagination.total_pages,
                r.total_is_exact,
            )
        })
        .collect();
    assert_eq!(
        seen,
        [
            (4, 2, Some(false)),
            (7, 3, Some(false)),
            (10, 4, Some(false)),
            // The last page reached by OFFSET settles the total exactly.
            (10, 4, Some(true)),
        ]
    );
    let walked: Vec<String> = pages.iter().flat_map(paths).collect();
    assert_eq!(walked, expected_paths(), "has_more walk reaches every item");

    // Every cursor page is a lower bound: it does not know the rows before it.
    let pages = walk_cursor(&state, &key, opt_out).await;
    assert!(pages.iter().all(|r| r.total_is_exact == Some(false)));
    let walked: Vec<String> = pages.iter().flat_map(paths).collect();
    assert_eq!(walked, expected_paths(), "cursor walk reaches every item");

    // An empty page past the end counts, even in lower-bound mode.
    let past = list(&state, &key, Some(5), None, opt_out).await;
    assert!(past.items.is_empty());
    assert_eq!(past.pagination.total, SEEDED as i64, "past-end total");
    assert_eq!(past.total_is_exact, Some(true));

    // `count=exact` is still accepted and exact.
    let exact = list(&state, &key, Some(2), None, Some("exact")).await;
    assert_eq!(exact.pagination.total, SEEDED as i64);
    assert_eq!(exact.total_is_exact, Some(true));

    cleanup_repo(&pool, repo_id).await;
    std::fs::remove_dir_all(&storage_path).ok();
}

// ===========================================================================
// Hosted: same defaults as the remote listing
// ===========================================================================

#[tokio::test]
#[ignore] // requires DATABASE_URL with migrations applied
async fn hosted_listing_totals_are_exact_on_page_requests_and_flagged_on_cursor_pages() {
    let pool = common::require_db_pool().await;
    let (repo_id, key, storage_path) = seed_hosted(&pool).await;
    let state = build_state(pool.clone(), storage_path.to_string_lossy().as_ref());
    let expected = expected_paths();

    // The #5255 client against a hosted repository (pre-fix: 6 of 10).
    let (first, collected) = walk_to_first_total_pages(&state, &key, None).await;
    assert_eq!(first.pagination.total, SEEDED as i64);
    assert_eq!(first.pagination.total_pages, 4);
    assert_eq!(first.total_is_exact, Some(true));
    assert_eq!(collected, expected, "total_pages walk reaches every item");

    let pages = walk_pages_by_has_more(&state, &key, None).await;
    assert!(pages
        .iter()
        .all(|r| r.pagination.total == SEEDED as i64 && r.total_is_exact == Some(true)));
    let walked: Vec<String> = pages.iter().flat_map(paths).collect();
    assert_eq!(walked, expected, "has_more walk reaches every item");

    let pages = walk_cursor(&state, &key, None).await;
    let walked: Vec<String> = pages.iter().flat_map(paths).collect();
    assert_eq!(walked, expected, "cursor walk reaches every item");
    assert_eq!(pages[0].total_is_exact, Some(true));
    assert!(pages[1..].iter().all(|r| r.total_is_exact == Some(false)));

    // Past the end (pre-fix total=12), in both modes.
    for count in [None, Some("lower_bound")] {
        let past = list(&state, &key, Some(5), None, count).await;
        assert!(past.items.is_empty());
        assert_eq!(past.pagination.total, SEEDED as i64, "past-end total");
        assert_eq!(past.pagination.total_pages, 4);
        assert_eq!(past.total_is_exact, Some(true));
    }

    // `count=lower_bound` restores the PF-001 cheap total, flagged; the last
    // OFFSET page settles it exactly.
    let pages = walk_pages_by_has_more(&state, &key, Some("lower_bound")).await;
    let seen: Vec<(i64, Option<bool>)> = pages
        .iter()
        .map(|r| (r.pagination.total, r.total_is_exact))
        .collect();
    assert_eq!(
        seen,
        [
            (4, Some(false)),
            (7, Some(false)),
            (10, Some(false)),
            (10, Some(true))
        ]
    );

    cleanup_repo(&pool, repo_id).await;
    std::fs::remove_dir_all(&storage_path).ok();
}
