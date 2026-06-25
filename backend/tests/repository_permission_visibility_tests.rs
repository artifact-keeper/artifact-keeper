//! Integration tests for repository permission visibility (issue #1996).
//!
//! These tests verify that non-admin users can see private repositories they
//! have access to via the fine-grained `permissions` table, both through
//! direct user grants (`principal_type='user'`) and group-based grants
//! (`principal_type='group'` resolved through `user_group_members`).
//!
//! Without the fix, `build_visibility_clause_for()` only checks the legacy
//! `role_assignments` table, so repositories granted only via the
//! `permissions` table are invisible in the repository list.
//!
//! Requires PostgreSQL with all migrations applied:
//!
//! ```sh
//! DATABASE_URL="postgresql://registry:registry@localhost:30432/artifact_registry" \
//!     cargo test --test repository_permission_visibility_tests -- --ignored
//! ```

use sqlx::PgPool;
use uuid::Uuid;

use artifact_keeper_backend::services::repository_service::{RepoVisibility, RepositoryService};

/// Insert a test user. Returns the user id.
async fn insert_user(pool: &PgPool, suffix: &str) -> Uuid {
    let id = Uuid::new_v4();
    let username = format!("rpv-{}-{}", suffix, &id.to_string()[..8]);
    let email = format!("{}@test.local", username);
    sqlx::query(
        r#"
        INSERT INTO users (id, username, email, password_hash, auth_provider,
                           is_admin, is_active, failed_login_attempts)
        VALUES ($1, $2, $3, 'unused', 'local', false, true, 0)
        "#,
    )
    .bind(id)
    .bind(&username)
    .bind(&email)
    .execute(pool)
    .await
    .expect("insert user");
    id
}

/// Insert a test group. Returns the group id.
async fn insert_group(pool: &PgPool, suffix: &str) -> Uuid {
    let id = Uuid::new_v4();
    let name = format!("rpv-group-{}-{}", suffix, &id.to_string()[..8]);
    sqlx::query(
        r#"
        INSERT INTO groups (id, name, description)
        VALUES ($1, $2, '')
        "#,
    )
    .bind(id)
    .bind(&name)
    .execute(pool)
    .await
    .expect("insert group");
    id
}

/// Insert a private test repository. Returns the repository id.
async fn insert_repository(pool: &PgPool, suffix: &str) -> Uuid {
    let id = Uuid::new_v4();
    let key = format!("rpv-repo-{}-{}", suffix, &id.to_string()[..8]);
    let name = format!("rpv_repo_{}_{}", suffix, &id.to_string()[..8]);
    sqlx::query(
        r#"
        INSERT INTO repositories (id, key, name, format, repo_type,
                                  storage_backend, storage_path, is_public)
        VALUES ($1, $2, $3, 'maven', 'local',
                'default', '/test/storage', false)
        "#,
    )
    .bind(id)
    .bind(&key)
    .bind(&name)
    .execute(pool)
    .await
    .expect("insert repository");
    id
}

/// Add a user to a group.
async fn add_user_to_group(pool: &PgPool, user_id: Uuid, group_id: Uuid) {
    sqlx::query(
        r#"
        INSERT INTO user_group_members (user_id, group_id)
        VALUES ($1, $2)
        "#,
    )
    .bind(user_id)
    .bind(group_id)
    .execute(pool)
    .await
    .expect("add user to group");
}

/// Grant a permission on a repository to a principal.
async fn grant_permission(
    pool: &PgPool,
    principal_type: &str,
    principal_id: Uuid,
    target_id: Uuid,
    actions: &[&str],
) {
    let actions_array: Vec<String> = actions.iter().map(|a| a.to_string()).collect();
    sqlx::query(
        r#"
        INSERT INTO permissions (principal_type, principal_id, target_type, target_id, actions)
        VALUES ($1, $2, 'repository', $3, $4)
        "#,
    )
    .bind(principal_type)
    .bind(principal_id)
    .bind(target_id)
    .bind(&actions_array)
    .execute(pool)
    .await
    .expect("grant permission");
}

/// Clean up all test data for a user (deletes cascading data).
async fn cleanup_user(pool: &PgPool, user_id: Uuid) {
    let _ = sqlx::query("DELETE FROM users WHERE id = $1")
        .bind(user_id)
        .execute(pool)
        .await;
}

/// Clean up a test group.
async fn cleanup_group(pool: &PgPool, group_id: Uuid) {
    let _ = sqlx::query("DELETE FROM groups WHERE id = $1")
        .bind(group_id)
        .execute(pool)
        .await;
}

/// Clean up a test repository.
async fn cleanup_repository(pool: &PgPool, repo_id: Uuid) {
    let _ =
        sqlx::query("DELETE FROM permissions WHERE target_type = 'repository' AND target_id = $1")
            .bind(repo_id)
            .execute(pool)
            .await;
    let _ = sqlx::query("DELETE FROM role_assignments WHERE repository_id = $1")
        .bind(repo_id)
        .execute(pool)
        .await;
    let _ = sqlx::query("DELETE FROM repositories WHERE id = $1")
        .bind(repo_id)
        .execute(pool)
        .await;
}

/// A non-admin user with a direct `permissions` grant (principal_type='user')
/// on a private repository MUST see that repository in the repository list.
#[tokio::test]
#[ignore]
async fn test_direct_user_permission_visible_in_list() {
    let url = match std::env::var("DATABASE_URL") {
        Ok(v) => v,
        Err(_) => return,
    };
    let pool = match PgPool::connect(&url).await {
        Ok(p) => p,
        Err(_) => return,
    };

    let suffix = "direct";
    let user_id = insert_user(&pool, suffix).await;
    let repo_id = insert_repository(&pool, suffix).await;

    // Grant direct user permission (no role_assignments involved).
    grant_permission(&pool, "user", user_id, repo_id, &["read"]).await;

    // List repositories as this user.
    let service = RepositoryService::new(pool.clone());
    let (repos, total) = service
        .list(0, 50, None, None, RepoVisibility::User(user_id), None)
        .await
        .expect("list repositories");

    // Cleanup.
    cleanup_repository(&pool, repo_id).await;
    cleanup_user(&pool, user_id).await;

    assert!(
        total > 0,
        "User with direct permission (principal_type='user') should see the \
         repository in the list, but got total={}. This confirms issue #1996.",
        total
    );
    assert!(
        repos.iter().any(|r| r.id == repo_id),
        "Repository should be in the returned list, but was not found. \
         This confirms issue #1996."
    );
}

/// A non-admin user who is a member of a group that has a `permissions` grant
/// (principal_type='group') on a private repository MUST see that repository
/// in the repository list.
#[tokio::test]
#[ignore]
async fn test_group_permission_visible_in_list() {
    let url = match std::env::var("DATABASE_URL") {
        Ok(v) => v,
        Err(_) => return,
    };
    let pool = match PgPool::connect(&url).await {
        Ok(p) => p,
        Err(_) => return,
    };

    let suffix = "group";
    let user_id = insert_user(&pool, suffix).await;
    let group_id = insert_group(&pool, suffix).await;
    let repo_id = insert_repository(&pool, suffix).await;

    // Add user to group.
    add_user_to_group(&pool, user_id, group_id).await;

    // Grant group permission (no role_assignments involved).
    grant_permission(&pool, "group", group_id, repo_id, &["read"]).await;

    // List repositories as this user.
    let service = RepositoryService::new(pool.clone());
    let (repos, total) = service
        .list(0, 50, None, None, RepoVisibility::User(user_id), None)
        .await
        .expect("list repositories");

    // Cleanup.
    cleanup_repository(&pool, repo_id).await;
    cleanup_group(&pool, group_id).await;
    cleanup_user(&pool, user_id).await;

    assert!(
        total > 0,
        "User in group with group permission (principal_type='group') should \
         see the repository in the list, but got total={}. This confirms the \
         group-based permission visibility bug.",
        total
    );
    assert!(
        repos.iter().any(|r| r.id == repo_id),
        "Repository should be in the returned list, but was not found. \
         This confirms the group-based permission visibility bug."
    );
}

/// A non-admin user with only `role_assignments` (legacy system) still sees
/// the repository, ensuring backward compatibility is preserved.
#[tokio::test]
#[ignore]
async fn test_legacy_role_assignment_still_works() {
    let url = match std::env::var("DATABASE_URL") {
        Ok(v) => v,
        Err(_) => return,
    };
    let pool = match PgPool::connect(&url).await {
        Ok(p) => p,
        Err(_) => return,
    };

    let suffix = "legacy";
    let user_id = insert_user(&pool, suffix).await;
    let repo_id = insert_repository(&pool, suffix).await;

    // Grant via legacy role_assignments.
    sqlx::query(
        r#"
        INSERT INTO role_assignments (user_id, repository_id, role)
        VALUES ($1, $2, 'developer')
        "#,
    )
    .bind(user_id)
    .bind(repo_id)
    .execute(&pool)
    .await
    .expect("insert role_assignment");

    // List repositories as this user.
    let service = RepositoryService::new(pool.clone());
    let (repos, total) = service
        .list(0, 50, None, None, RepoVisibility::User(user_id), None)
        .await
        .expect("list repositories");

    // Cleanup.
    let _ = sqlx::query("DELETE FROM role_assignments WHERE user_id = $1")
        .bind(user_id)
        .execute(&pool)
        .await;
    cleanup_repository(&pool, repo_id).await;
    cleanup_user(&pool, user_id).await;

    assert!(
        total > 0,
        "User with legacy role_assignment should still see the repository. \
         Backward compatibility broken."
    );
    assert!(
        repos.iter().any(|r| r.id == repo_id),
        "Repository should be in the returned list via legacy role_assignment."
    );
}
