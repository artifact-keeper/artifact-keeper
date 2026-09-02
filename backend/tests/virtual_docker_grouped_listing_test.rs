//! Integration tests: the Docker `group_by=docker_tag` grouped listing must
//! aggregate a virtual repository's members, exactly like the flat listing
//! and the Maven component grouping already do.
//!
//! A virtual repository owns no `oci_tags`/`artifacts` rows of its own —
//! pushes to it route to a hosted member. Before the fix, the grouped view
//! filtered by the virtual repo's own id and came back empty even though the
//! flat view (which expands members) listed the same artifacts.
//!
//! Requires a PostgreSQL database with migrations applied:
//!
//! ```sh
//! DATABASE_URL="postgresql://registry:registry@localhost:30432/artifact_registry" \
//!   cargo test --test virtual_docker_grouped_listing_test -- --ignored
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

async fn create_repo(pool: &PgPool, label: &str, repo_type: &str) -> (Uuid, String) {
    let id = Uuid::new_v4();
    let key = format!("vdg-{}-{}-{}", label, repo_type, &id.to_string()[..8]);
    let storage_path = format!("/tmp/vdg-{}", id);
    std::fs::create_dir_all(&storage_path).unwrap();
    sqlx::query(
        "INSERT INTO repositories (id, key, name, storage_path, repo_type, format, is_public) \
         VALUES ($1, $2, $2, $3, $4::repository_type, 'docker'::repository_format, true)",
    )
    .bind(id)
    .bind(&key)
    .bind(&storage_path)
    .bind(repo_type)
    .execute(pool)
    .await
    .expect("insert repo");
    (id, key)
}

async fn add_member(pool: &PgPool, virtual_id: Uuid, member_id: Uuid, priority: i32) {
    sqlx::query(
        "INSERT INTO virtual_repo_members (virtual_repo_id, member_repo_id, priority) \
         VALUES ($1, $2, $3)",
    )
    .bind(virtual_id)
    .bind(member_id)
    .bind(priority)
    .execute(pool)
    .await
    .expect("insert virtual member");
}

/// Insert the `oci_tags` row plus the matching `artifacts` row the grouped
/// listing JOINs on (`a.path = 'v2/' || name || '/manifests/' || tag`).
async fn insert_tag(pool: &PgPool, repo_id: Uuid, image: &str, tag: &str, digest: &str) {
    sqlx::query(
        "INSERT INTO oci_tags (repository_id, name, tag, manifest_digest, manifest_content_type) \
         VALUES ($1, $2, $3, $4, 'application/vnd.oci.image.manifest.v1+json')",
    )
    .bind(repo_id)
    .bind(image)
    .bind(tag)
    .bind(digest)
    .execute(pool)
    .await
    .expect("insert oci_tags");

    sqlx::query(
        "INSERT INTO artifacts \
             (repository_id, path, name, version, size_bytes, checksum_sha256, \
              content_type, storage_key) \
         VALUES ($1, $2, $3, NULL, 100, $4, \
                 'application/vnd.oci.image.manifest.v1+json', $5)",
    )
    .bind(repo_id)
    .bind(format!("v2/{image}/manifests/{tag}"))
    .bind(image)
    .bind(digest.trim_start_matches("sha256:"))
    .bind(format!("oci-manifests/{digest}"))
    .execute(pool)
    .await
    .expect("insert artifacts");
}

async fn list_grouped(state: &SharedState, key: &str) -> ArtifactListResponse {
    let query = ListArtifactsQuery {
        page: None,
        per_page: Some(100),
        q: None,
        path_prefix: None,
        group_by: Some("docker_tag".to_string()),
        cursor: None,
        count: Some("exact".to_string()),
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

async fn cleanup(pool: &PgPool, ids: &[Uuid]) {
    for id in ids {
        let _ = sqlx::query(
            "DELETE FROM virtual_repo_members WHERE virtual_repo_id = $1 OR member_repo_id = $1",
        )
        .bind(id)
        .execute(pool)
        .await;
        let _ = sqlx::query("DELETE FROM oci_tags WHERE repository_id = $1")
            .bind(id)
            .execute(pool)
            .await;
        let _ = sqlx::query("DELETE FROM artifacts WHERE repository_id = $1")
            .bind(id)
            .execute(pool)
            .await;
        let _ = sqlx::query("DELETE FROM repositories WHERE id = $1")
            .bind(id)
            .execute(pool)
            .await;
    }
}

/// Core regression: a virtual docker repo with a single local member must
/// surface the member's pushed tags in the `group_by=docker_tag` grouped
/// view (previously empty, while the flat view listed them).
#[tokio::test]
#[ignore = "requires DATABASE_URL pointed at a Postgres with migrations applied"]
async fn virtual_docker_grouped_view_lists_member_tags() {
    let pool = common::require_db_pool().await;
    let (virtual_id, virtual_key) = create_repo(&pool, "list", "virtual").await;
    let (member_id, _member_key) = create_repo(&pool, "list", "local").await;
    add_member(&pool, virtual_id, member_id, 1).await;

    insert_tag(&pool, member_id, "app", "latest", "sha256:aaaa").await;
    insert_tag(&pool, member_id, "app", "v1", "sha256:bbbb").await;

    let state = build_state(pool.clone(), "/tmp/vdg-state");
    std::fs::create_dir_all("/tmp/vdg-state").unwrap();

    let resp = list_grouped(&state, &virtual_key).await;

    let tags = resp
        .docker_tags
        .expect("docker_tags present in grouped mode");
    assert_eq!(
        tags.len(),
        2,
        "virtual grouped view must list both member tags"
    );
    assert_eq!(
        resp.pagination.total, 2,
        "exact total must count member tags"
    );
    for tag in &tags {
        assert_eq!(
            tag.repository_key, virtual_key,
            "aggregated tags are reported under the virtual repo's key"
        );
    }
    // Keyset order is (image, tag).
    assert_eq!(tags[0].tag, "latest");
    assert_eq!(tags[1].tag, "v1");

    cleanup(&pool, &[virtual_id, member_id]).await;
    let _ = std::fs::remove_dir_all("/tmp/vdg-state");
}

/// A duplicate `(image, tag)` across two members must collapse to a single
/// row, with the higher-priority member's manifest winning — matching the flat
/// listing's `DISTINCT ON (path)` shadowing contract.
#[tokio::test]
#[ignore = "requires DATABASE_URL pointed at a Postgres with migrations applied"]
async fn virtual_docker_grouped_view_dedupes_shadowed_tags() {
    let pool = common::require_db_pool().await;
    let (virtual_id, virtual_key) = create_repo(&pool, "dedup", "virtual").await;
    let (high_id, _high_key) = create_repo(&pool, "dedup", "local").await;
    let (low_id, _low_key) = create_repo(&pool, "dedup", "local").await;
    add_member(&pool, virtual_id, high_id, 1).await;
    add_member(&pool, virtual_id, low_id, 2).await;

    // Same tag in both members; priority 1 should win.
    insert_tag(&pool, high_id, "app", "latest", "sha256:high").await;
    insert_tag(&pool, low_id, "app", "latest", "sha256:low").await;

    let state = build_state(pool.clone(), "/tmp/vdg-dedup-state");
    std::fs::create_dir_all("/tmp/vdg-dedup-state").unwrap();

    let resp = list_grouped(&state, &virtual_key).await;

    let tags = resp
        .docker_tags
        .expect("docker_tags present in grouped mode");
    assert_eq!(
        tags.len(),
        1,
        "duplicate (image, tag) across members must collapse to one row"
    );
    assert_eq!(resp.pagination.total, 1);
    assert_eq!(
        tags[0].manifest_digest, "sha256:high",
        "the higher-priority member's manifest must shadow the lower one"
    );

    cleanup(&pool, &[virtual_id, high_id, low_id]).await;
    let _ = std::fs::remove_dir_all("/tmp/vdg-dedup-state");
}
