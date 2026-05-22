//! Integration test: Maven virtual-repo shadowing guard must consider
//! both `groupId` and `artifactId`, not just `artifactId` alone.
//!
//! Regression test for #1287. The original cross-format shadowing
//! guard (`virtual_non_remote_owns_name`) matches on the
//! `artifacts.name` column, which for Maven holds just the
//! artifactId. That made a local `com.example.mylib:common:1.0` shadow
//! every remote `com/android/tools/common/...` lookup, returning 404
//! instead of falling through to the remote member. The Maven-aware
//! variant `virtual_non_remote_owns_maven_ga` matches on the full
//! `groupId/artifactId/` path prefix, so only true GA collisions
//! activate the suppression.
//!
//! Requires a PostgreSQL database with migrations applied. Run with:
//!
//! ```sh
//! DATABASE_URL="postgresql://registry:registry@localhost:30432/artifact_registry" \
//!   cargo test --test maven_virtual_groupid_shadowing_test -- --ignored
//! ```

use sqlx::PgPool;
use uuid::Uuid;

use artifact_keeper_backend::api::handlers::proxy_helpers::virtual_non_remote_owns_maven_ga;

async fn insert_repo(pool: &PgPool, key: &str, repo_type: &str) -> Uuid {
    let id = Uuid::new_v4();
    let storage_path = format!("/tmp/test-artifacts/{}", id);
    // The `check_upstream_url` table constraint requires Remote repos
    // to have an upstream_url set; Local/Virtual repos must leave it
    // null. Mirror that here so the test fixture stays valid.
    let upstream_url: Option<String> = if repo_type == "remote" {
        Some("https://example.invalid/test".to_string())
    } else {
        None
    };
    sqlx::query(
        r#"
        INSERT INTO repositories (id, key, name, format, repo_type, storage_path, upstream_url)
        VALUES ($1, $2, $2, 'maven'::repository_format, $3::repository_type, $4, $5)
        "#,
    )
    .bind(id)
    .bind(key)
    .bind(repo_type)
    .bind(&storage_path)
    .bind(&upstream_url)
    .execute(pool)
    .await
    .expect("failed to insert test repository");
    id
}

async fn add_virtual_member(pool: &PgPool, virtual_id: Uuid, member_id: Uuid, priority: i32) {
    sqlx::query(
        "INSERT INTO virtual_repo_members (virtual_repo_id, member_repo_id, priority) \
         VALUES ($1, $2, $3)",
    )
    .bind(virtual_id)
    .bind(member_id)
    .bind(priority)
    .execute(pool)
    .await
    .expect("failed to insert virtual member");
}

/// Insert an artifact row that mirrors how Maven upload stores it:
/// `path` is the full Maven 2 path, `name` is just the artifactId.
async fn insert_maven_artifact(
    pool: &PgPool,
    repo_id: Uuid,
    path: &str,
    artifact_id: &str,
    version: &str,
) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        r#"
        INSERT INTO artifacts (
            id, repository_id, path, name, version,
            size_bytes, checksum_sha256, content_type, storage_key
        )
        VALUES ($1, $2, $3, $4, $5, 0, $6, 'application/xml', $7)
        "#,
    )
    .bind(id)
    .bind(repo_id)
    .bind(path)
    .bind(artifact_id)
    .bind(version)
    // Use the artifact id as a synthetic checksum so we satisfy the
    // NOT-NULL contract without colliding with real data.
    .bind(format!("test-{}", id))
    .bind(format!("artifacts/{}", id))
    .execute(pool)
    .await
    .expect("failed to insert test artifact");
    id
}

async fn cleanup(pool: &PgPool, virtual_id: Uuid, member_ids: &[Uuid]) {
    sqlx::query("DELETE FROM virtual_repo_members WHERE virtual_repo_id = $1")
        .bind(virtual_id)
        .execute(pool)
        .await
        .ok();
    for &m in member_ids {
        sqlx::query("DELETE FROM artifacts WHERE repository_id = $1")
            .bind(m)
            .execute(pool)
            .await
            .ok();
    }
    let mut ids = member_ids.to_vec();
    ids.push(virtual_id);
    sqlx::query("DELETE FROM repositories WHERE id = ANY($1)")
        .bind(&ids)
        .execute(pool)
        .await
        .ok();
}

/// #1287 core regression: a local artifact with the same artifactId
/// but a DIFFERENT groupId must NOT activate the shadowing guard for
/// the unrelated groupId.
#[tokio::test]
#[ignore]
async fn maven_shadowing_guard_does_not_fire_across_different_groupids() {
    let pool = PgPool::connect(
        &std::env::var("DATABASE_URL")
            .expect("DATABASE_URL must be set to run this integration test"),
    )
    .await
    .expect("connect");

    let suffix = Uuid::new_v4();
    let virtual_id = insert_repo(&pool, &format!("mv-virt-1287-{}", suffix), "virtual").await;
    let local_id = insert_repo(&pool, &format!("mv-local-1287-{}", suffix), "local").await;
    let remote_id = insert_repo(&pool, &format!("mv-remote-1287-{}", suffix), "remote").await;

    add_virtual_member(&pool, virtual_id, local_id, 1).await;
    add_virtual_member(&pool, virtual_id, remote_id, 2).await;

    // Local member owns `com.example.mylib:common:1.0.0` — artifactId
    // "common" collides with a popular remote artifactId, but the
    // groupId is different.
    insert_maven_artifact(
        &pool,
        local_id,
        "com/example/mylib/common/1.0.0/common-1.0.0.pom",
        "common",
        "1.0.0",
    )
    .await;

    // Querying for the REMOTE groupId+artifactId must return false:
    // the local member does not own this GA, so the guard must not
    // suppress remote resolution.
    let owns_remote_ga =
        virtual_non_remote_owns_maven_ga(&pool, virtual_id, "com.android.tools", "common")
            .await
            .expect("guard query should succeed");
    assert!(
        !owns_remote_ga,
        "local member's `com.example.mylib:common` must NOT shadow remote `com.android.tools:common` (#1287)"
    );

    // Sanity: querying for the LOCAL groupId+artifactId still returns
    // true (the guard still does its job for genuine collisions).
    let owns_local_ga =
        virtual_non_remote_owns_maven_ga(&pool, virtual_id, "com.example.mylib", "common")
            .await
            .expect("guard query should succeed");
    assert!(
        owns_local_ga,
        "guard must still fire when groupId+artifactId match the local artifact"
    );

    cleanup(&pool, virtual_id, &[local_id, remote_id]).await;
}

/// Sanity test: no non-remote members → guard returns false (matches
/// the cross-format primitive's "allow proxy fan-out" semantic).
#[tokio::test]
#[ignore]
async fn maven_shadowing_guard_no_non_remote_members_returns_false() {
    let pool = PgPool::connect(
        &std::env::var("DATABASE_URL")
            .expect("DATABASE_URL must be set to run this integration test"),
    )
    .await
    .expect("connect");

    let suffix = Uuid::new_v4();
    let virtual_id = insert_repo(&pool, &format!("mv-virt-rmonly-{}", suffix), "virtual").await;
    let remote_id = insert_repo(&pool, &format!("mv-remote-rmonly-{}", suffix), "remote").await;
    add_virtual_member(&pool, virtual_id, remote_id, 1).await;

    let owns = virtual_non_remote_owns_maven_ga(&pool, virtual_id, "com.foo", "bar")
        .await
        .expect("guard query should succeed");
    assert!(
        !owns,
        "with only remote members the guard returns false to allow proxy fan-out"
    );

    cleanup(&pool, virtual_id, &[remote_id]).await;
}

/// A LIKE-metacharacter inside the artifactId must not widen the
/// match: only true GA collisions activate the guard.
#[tokio::test]
#[ignore]
async fn maven_shadowing_guard_escapes_like_metachars() {
    let pool = PgPool::connect(
        &std::env::var("DATABASE_URL")
            .expect("DATABASE_URL must be set to run this integration test"),
    )
    .await
    .expect("connect");

    let suffix = Uuid::new_v4();
    let virtual_id = insert_repo(&pool, &format!("mv-virt-esc-{}", suffix), "virtual").await;
    let local_id = insert_repo(&pool, &format!("mv-local-esc-{}", suffix), "local").await;
    add_virtual_member(&pool, virtual_id, local_id, 1).await;

    // Insert a local artifact with a literal-`a`-character artifactId.
    insert_maven_artifact(
        &pool,
        local_id,
        "com/example/aaa/1.0.0/aaa-1.0.0.pom",
        "aaa",
        "1.0.0",
    )
    .await;

    // A LIKE-style query like `a%a` must not slip past escaping and
    // match the `aaa` artifact: the guard treats `%` as a literal.
    let widened = virtual_non_remote_owns_maven_ga(&pool, virtual_id, "com.example", "a%a")
        .await
        .expect("guard query should succeed");
    assert!(
        !widened,
        "% inside artifactId must be escaped, not act as a wildcard"
    );

    cleanup(&pool, virtual_id, &[local_id]).await;
}
