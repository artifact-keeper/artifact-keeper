//! Invariant tests for the keyset-paged flat catalog listing (PF-001 / #2518).
//!
//! The flat hosted/virtual artifact listing previously ran an exact
//! `COUNT(*)` over every matching row on EVERY page request and paged via
//! `OFFSET`, so a deep page identified and discarded all preceding rows;
//! the virtual listing additionally re-materialized and re-sorted the whole
//! de-duplicated member union per request. Work grew with catalog size, not
//! page size.
//!
//! These tests seed several pages of catalog entries and assert that
//! (a) walking the full listing via `next_cursor` returns every row exactly
//! once, in `path` order, with a consistent authoritative `has_more`;
//! (b) `?count=exact` is the opt-in that reports the exact total (the
//! default total is a lower bound);
//! (c) virtual listings keep the priority-shadowing de-duplication contract
//! across keyset pages; and
//! (d) substring search stays correct under the same cursor walk.
//!
//! (a) fails on the pre-#2518 implementation by construction: the flat
//! listing never populated `next_cursor`/`has_more`, so the walk's paging
//! signals are absent on the first page.
//!
//! Requires a PostgreSQL database with migrations applied:
//!
//! ```sh
//! DATABASE_URL="postgresql://registry:registry@localhost:5432/artifact_registry" \
//!   cargo test --test catalog_keyset_tests -- --ignored
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

/// Ten full pages plus one straggler row.
const SEEDED: i64 = 1_001;
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
    q: Option<&str>,
    page: Option<u32>,
    cursor: Option<String>,
    count_exact: bool,
) -> ArtifactListResponse {
    let query = ListArtifactsQuery {
        page,
        per_page: Some(PER_PAGE),
        q: q.map(str::to_string),
        path_prefix: None,
        group_by: None,
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

/// Walk the whole flat listing via `next_cursor`, asserting exact-total on
/// the first page. Returns the concatenated item paths.
async fn walk_keyset(
    state: &SharedState,
    key: &str,
    q: Option<&str>,
    expected_exact: i64,
) -> Vec<String> {
    let mut collected: Vec<String> = Vec::new();
    let mut cursor: Option<String> = None;
    let mut pages = 0u32;
    loop {
        // Only ask for the exact count on the first page: the walk itself
        // must be exact without paying a COUNT per request.
        let resp = list(state, key, q, None, cursor.clone(), cursor.is_none()).await;
        if cursor.is_none() {
            assert_eq!(
                resp.pagination.total, expected_exact,
                "?count=exact total must be exact \
                 (pre-#2518 the flat listing paid this COUNT on every page)"
            );
        }
        collected.extend(resp.items.iter().map(|i| i.path.clone()));
        pages += 1;
        assert!(pages <= 100, "cursor walk did not terminate");
        match (resp.has_more, resp.next_cursor) {
            (Some(true), Some(next)) => cursor = Some(next),
            (Some(false), None) => break,
            (has_more, next_cursor) => panic!(
                "inconsistent keyset paging signals: has_more={:?} next_cursor={:?} \
                 (the pre-#2518 flat listing emitted neither)",
                has_more, next_cursor
            ),
        }
    }
    collected
}

async fn insert_repo(pool: &PgPool, repo_id: Uuid, key: &str, storage_path: &str, kind: &str) {
    sqlx::query(
        "INSERT INTO repositories (id, key, name, storage_path, repo_type, format, is_public) \
         VALUES ($1, $2, $2, $3, $4::repository_type, 'generic'::repository_format, true)",
    )
    .bind(repo_id)
    .bind(key)
    .bind(storage_path)
    .bind(kind)
    .execute(pool)
    .await
    .expect("insert repository");
}

/// Seed `count` artifacts with paths `pkgs/<prefix><i>/file.bin` (zero-padded,
/// so path order == numeric order).
async fn seed_artifacts(pool: &PgPool, repo_id: Uuid, prefix: &str, from: i64, count: i64) {
    sqlx::query(
        "INSERT INTO artifacts \
             (repository_id, path, name, version, size_bytes, checksum_sha256, \
              content_type, storage_key) \
         SELECT $1, 'pkgs/' || $2 || lpad(i::text, 6, '0') || '/file.bin', \
                $2 || lpad(i::text, 6, '0'), '1.0.0', 10 + i, \
                lpad(i::text, 64, '0'), 'application/octet-stream', \
                'pf001/' || $2 || lpad(i::text, 6, '0') \
         FROM generate_series($3, $4) AS g(i)",
    )
    .bind(repo_id)
    .bind(prefix)
    .bind(from)
    .bind(from + count - 1)
    .execute(pool)
    .await
    .expect("seed artifacts");
}

async fn cleanup_repos(pool: &PgPool, repo_ids: &[Uuid]) {
    for repo_id in repo_ids {
        for table in ["virtual_repo_members", "artifacts", "repositories"] {
            let sql = match table {
                "repositories" => format!("DELETE FROM {table} WHERE id = $1"),
                "virtual_repo_members" => {
                    format!("DELETE FROM {table} WHERE virtual_repo_id = $1")
                }
                _ => format!("DELETE FROM {table} WHERE repository_id = $1"),
            };
            sqlx::query(&sql).bind(repo_id).execute(pool).await.ok();
        }
    }
}

// ===========================================================================
// Hosted: flat listing over 1 001 rows
// ===========================================================================

#[tokio::test]
#[ignore] // requires DATABASE_URL with migrations applied
async fn hosted_flat_listing_keyset_walk_is_exact_and_ordered() {
    let pool = common::require_db_pool().await;
    let repo_id = Uuid::new_v4();
    let key = format!("pf001-local-{}", &repo_id.to_string()[..8]);
    let storage_path = std::env::temp_dir().join(format!("pf001-{repo_id}"));
    std::fs::create_dir_all(&storage_path).unwrap();

    insert_repo(
        &pool,
        repo_id,
        &key,
        storage_path.to_string_lossy().as_ref(),
        "local",
    )
    .await;
    seed_artifacts(&pool, repo_id, "lib", 1, SEEDED).await;

    let state = build_state(pool.clone(), storage_path.to_string_lossy().as_ref());

    let collected = walk_keyset(&state, &key, None, SEEDED).await;
    assert_eq!(
        collected.len() as i64,
        SEEDED,
        "cursor walk must surface every artifact exactly once"
    );
    for (idx, path) in collected.iter().enumerate() {
        assert_eq!(
            path,
            &format!("pkgs/lib{:06}/file.bin", idx + 1),
            "page contents must be exact and in path order at position {idx}"
        );
    }

    // Legacy page=N addressing still works without a cursor, and the
    // default (no count=exact) total is a lower bound, not an exact COUNT.
    let page2 = list(&state, &key, None, Some(2), None, false).await;
    assert_eq!(page2.items.len(), PER_PAGE as usize);
    assert_eq!(page2.items[0].path, "pkgs/lib000101/file.bin");
    assert_eq!(page2.has_more, Some(true));
    assert!(
        page2.pagination.total > (2 * PER_PAGE) as i64,
        "default total must exceed rows-seen-so-far when more pages exist"
    );

    cleanup_repos(&pool, &[repo_id]).await;
    std::fs::remove_dir_all(&storage_path).ok();
}

// ===========================================================================
// Hosted: substring search stays correct under the keyset walk
// ===========================================================================

#[tokio::test]
#[ignore] // requires DATABASE_URL with migrations applied
async fn hosted_flat_listing_search_is_exact_under_keyset_walk() {
    let pool = common::require_db_pool().await;
    let repo_id = Uuid::new_v4();
    let key = format!("pf001-search-{}", &repo_id.to_string()[..8]);
    let storage_path = std::env::temp_dir().join(format!("pf001-{repo_id}"));
    std::fs::create_dir_all(&storage_path).unwrap();

    insert_repo(
        &pool,
        repo_id,
        &key,
        storage_path.to_string_lossy().as_ref(),
        "local",
    )
    .await;
    // 500 rows named lib*, 250 rows named needle* (interleaved numerically).
    seed_artifacts(&pool, repo_id, "lib", 1, 500).await;
    seed_artifacts(&pool, repo_id, "needle", 1, 250).await;

    let state = build_state(pool.clone(), storage_path.to_string_lossy().as_ref());

    // Case-insensitive substring match; only the needle* rows qualify.
    let collected = walk_keyset(&state, &key, Some("NeEdLe"), 250).await;
    assert_eq!(collected.len(), 250, "search walk must match exactly");
    for (idx, path) in collected.iter().enumerate() {
        assert_eq!(
            path,
            &format!("pkgs/needle{:06}/file.bin", idx + 1),
            "search results must be exact and ordered at position {idx}"
        );
    }

    cleanup_repos(&pool, &[repo_id]).await;
    std::fs::remove_dir_all(&storage_path).ok();
}

// ===========================================================================
// Virtual: priority de-duplication holds across keyset pages
// ===========================================================================

#[tokio::test]
#[ignore] // requires DATABASE_URL with migrations applied
async fn virtual_flat_listing_dedups_by_priority_across_keyset_pages() {
    let pool = common::require_db_pool().await;
    let virt_id = Uuid::new_v4();
    let member_a = Uuid::new_v4(); // higher priority
    let member_b = Uuid::new_v4();
    let key = format!("pf001-virt-{}", &virt_id.to_string()[..8]);
    let storage_path = std::env::temp_dir().join(format!("pf001-{virt_id}"));
    std::fs::create_dir_all(&storage_path).unwrap();
    let sp = storage_path.to_string_lossy();

    insert_repo(&pool, virt_id, &key, sp.as_ref(), "virtual").await;
    insert_repo(&pool, member_a, &format!("{key}-a"), sp.as_ref(), "local").await;
    insert_repo(&pool, member_b, &format!("{key}-b"), sp.as_ref(), "local").await;
    for (member, priority) in [(member_a, 1i32), (member_b, 2i32)] {
        sqlx::query(
            "INSERT INTO virtual_repo_members (virtual_repo_id, member_repo_id, priority) \
             VALUES ($1, $2, $3)",
        )
        .bind(virt_id)
        .bind(member)
        .bind(priority)
        .execute(&pool)
        .await
        .expect("insert virtual member");
    }

    // Member A: rows 1..=600. Member B: rows 301..=900. Overlap 301..=600
    // must be shadowed by member A; the de-duplicated union is 900 paths.
    seed_artifacts(&pool, member_a, "pkg", 1, 600).await;
    seed_artifacts(&pool, member_b, "pkg", 301, 600).await;

    let state = build_state(pool.clone(), sp.as_ref());

    let collected = walk_keyset(&state, &key, None, 900).await;
    assert_eq!(
        collected.len(),
        900,
        "virtual walk must de-duplicate overlapping paths exactly once"
    );
    for (idx, path) in collected.iter().enumerate() {
        assert_eq!(
            path,
            &format!("pkgs/pkg{:06}/file.bin", idx + 1),
            "virtual page contents must be exact and ordered at position {idx}"
        );
    }

    // Spot-check shadowing on a page that straddles the overlap: the
    // artifact ids for overlapping paths must come from member A. The
    // response does not expose repository_id, so resolve via the DB.
    let overlap_path = "pkgs/pkg000400/file.bin";
    let winner: Uuid = sqlx::query_scalar(
        "SELECT repository_id FROM artifacts WHERE path = $1 AND repository_id = ANY($2)
         ORDER BY array_position($2::uuid[], repository_id) LIMIT 1",
    )
    .bind(overlap_path)
    .bind(vec![member_a, member_b])
    .fetch_one(&pool)
    .await
    .expect("resolve overlap winner");
    assert_eq!(winner, member_a, "priority member must win the overlap");
    let served = collected.iter().filter(|p| *p == overlap_path).count();
    assert_eq!(served, 1, "overlapping path must be listed exactly once");

    cleanup_repos(&pool, &[virt_id, member_a, member_b]).await;
    std::fs::remove_dir_all(&storage_path).ok();
}
