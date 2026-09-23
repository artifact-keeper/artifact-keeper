use super::*;
use crate::api::handlers::test_db_helpers as tdh;

#[test]
fn depth_path_bound_and_canonical_roots() {
    assert_eq!(MAX_REPODATA_DEPTH, 1023);
    assert!(validate_depth(1023).is_ok());
    assert!(validate_depth(1024).is_err());
    assert!(validate_path("old//unchanged", 0).is_ok());
    for (path, depth) in [
        ("build/pkg.rpm", 1),
        ("el9/x86_64/pkg.rpm", 2),
        ("el9/x86_64/deeper/pkg.rpm", 2),
        ("build & special/pkg-1-1.noarch.rpm", 1),
        ("build%/pkg.rpm", 1),
        ("packages/pkg.rpm", 1),
        ("upload/pkg.rpm", 1),
    ] {
        assert!(validate_path(path, depth).is_ok(), "{path}");
    }
    for path in [
        "pkg.rpm",
        "/build/pkg.rpm",
        "build//pkg.rpm",
        "build/",
        "build/../pkg.rpm",
        "./build/pkg.rpm",
        "build\\pkg.rpm",
        "build/%2E/pkg.rpm",
        "build/%2f/pkg.rpm",
        "build/%5c/pkg.rpm",
        "repodata/pkg.rpm",
        "build/repodata/pkg.rpm",
        "@2/pkg.rpm",
        "build/\n/pkg.rpm",
        "build/ pkg.rpm",
        "build/pkg.rpm ",
        "build/\u{a0}pkg.rpm",
    ] {
        assert!(validate_path(path, 1).is_err(), "{path:?}");
    }
    assert!(validate_path("el9/pkg.rpm", 2).is_err());
    assert!(validate_root("", 0).is_ok());
    assert!(validate_root("", 1).is_err());
    assert!(validate_root("el9/x86_64", 2).is_ok());
    assert!(validate_root("el9/x86_64/deeper", 2).is_err());
    assert!(validate_path(&format!("{}a", "a/".repeat(1023)), 1023).is_ok());
    assert!(validate_path(&format!("{}aa", "a/".repeat(1024)), 1023).is_err());
}

#[test]
fn hrefs_encode_segments_without_changing_separators() {
    assert_eq!(
        location_href("nested/pkg &\"%?#é-1-1.noarch.rpm"),
        "nested/pkg%20%26%22%25%3F%23%C3%A9-1-1.noarch.rpm"
    );
}

#[tokio::test]
async fn persistence_guards_configuration_layout_and_dependencies_4216() {
    let Some(f) = tdh::Fixture::setup("local", "rpm").await else {
        return;
    };
    let mut conn = f.pool.acquire().await.unwrap();
    set_depth(&mut conn, f.repo_id, 2).await.unwrap();
    assert_eq!(
        settings(&f.pool, &[f.repo_id]).await.unwrap()[&f.repo_id],
        (2, true)
    );
    for path in [
        "pkg.rpm",
        "el9/pkg.rpm",
        "el9/x86_64/repodata/pkg.rpm",
        "el9/x86_64/\u{a0}pkg.rpm",
    ] {
        let err = insert(&mut conn, f.repo_id, path).await.unwrap_err();
        assert!(err.to_string().contains("AK_RPM_DEPTH_PATH"), "{err}");
    }
    insert(&mut conn, f.repo_id, "el9/x86_64/pkg-1-1.noarch.rpm")
        .await
        .unwrap();
    set_depth(&mut conn, f.repo_id, 2).await.unwrap();
    for depth in [0, 1, 3] {
        assert!(set_depth(&mut conn, f.repo_id, depth)
            .await
            .unwrap_err()
            .to_string()
            .contains("AK_RPM_DEPTH_POPULATED"));
    }
    sqlx::query("UPDATE artifacts SET is_deleted = true WHERE repository_id = $1")
        .bind(f.repo_id)
        .execute(&mut *conn)
        .await
        .unwrap();
    assert!(!settings(&f.pool, &[f.repo_id]).await.unwrap()[&f.repo_id].1);
    assert!(set_depth(&mut conn, f.repo_id, 0).await.is_err());
    sqlx::query("UPDATE artifacts SET is_deleted = false WHERE repository_id = $1")
        .bind(f.repo_id)
        .execute(&mut *conn)
        .await
        .unwrap();
    for sql in [
        "UPDATE repositories SET curation_enabled = true WHERE id = $1",
        "UPDATE repositories SET format = 'generic' WHERE id = $1",
        "UPDATE repositories SET format_key = 'plugin:rpm' WHERE id = $1",
        "INSERT INTO repository_versions(repository_id, version_number) VALUES ($1, 1)",
    ] {
        assert!(sqlx::query(sql)
            .bind(f.repo_id)
            .execute(&mut *conn)
            .await
            .unwrap_err()
            .to_string()
            .contains("AK_RPM_DEPTH_UNSUPPORTED"));
    }
    drop(conn);
    f.teardown().await;
}

#[tokio::test]
async fn member_attachment_and_layout_edits_are_serialized_both_ways_4216() {
    let Some(f) = tdh::Fixture::setup("local", "rpm").await else {
        return;
    };
    let (virtual_id, _, directory) = tdh::create_repo(&f.pool, "virtual", "rpm").await;
    let attach = "INSERT INTO virtual_repo_members(virtual_repo_id,member_repo_id,priority) VALUES ($1,$2,0)";
    let mut edit = f.pool.begin().await.unwrap();
    set_depth(&mut edit, f.repo_id, 1).await.unwrap();
    let denied = tokio::time::timeout(
        std::time::Duration::from_secs(2),
        sqlx::query(attach)
            .bind(virtual_id)
            .bind(f.repo_id)
            .execute(&f.pool),
    )
    .await
    .unwrap()
    .unwrap_err();
    assert!(denied.to_string().contains("AK_RPM_DEPTH_BUSY"));
    edit.rollback().await.unwrap();
    let mut membership = f.pool.begin().await.unwrap();
    sqlx::query(attach)
        .bind(virtual_id)
        .bind(f.repo_id)
        .execute(&mut *membership)
        .await
        .unwrap();
    let mut config = f.pool.acquire().await.unwrap();
    assert!(set_depth(&mut config, f.repo_id, 1)
        .await
        .unwrap_err()
        .to_string()
        .contains("AK_RPM_DEPTH_BUSY"));
    membership.commit().await.unwrap();
    assert!(set_depth(&mut config, f.repo_id, 1)
        .await
        .unwrap_err()
        .to_string()
        .contains("AK_RPM_DEPTH_UNSUPPORTED"));
    drop(config);
    sqlx::query("DELETE FROM repositories WHERE id = $1")
        .bind(virtual_id)
        .execute(&f.pool)
        .await
        .unwrap();
    std::fs::remove_dir_all(directory).unwrap();
    f.teardown().await;
}

#[tokio::test]
async fn copy_preflight_rejects_flat_storage_and_shallow_paths_4216() {
    let Some(f) = tdh::Fixture::setup("local", "rpm").await else {
        return;
    };
    let checksum = "a".repeat(64);
    let path = "a/pkg.rpm";
    let mut config = f.pool.acquire().await.unwrap();
    set_depth(&mut config, f.repo_id, 1).await.unwrap();
    let error = validate_copy(&f.pool, f.repo_id, path, &checksum, "rpm/old/pkg.rpm")
        .await
        .unwrap_err();
    assert!(matches!(error, AppError::UnprocessableEntity(_)));
    let key = format!("aa/aa/{checksum}");
    validate_copy(&f.pool, f.repo_id, path, &checksum, &key)
        .await
        .unwrap();
    set_depth(&mut config, f.repo_id, 2).await.unwrap();
    assert!(matches!(
        validate_copy(&f.pool, f.repo_id, path, &checksum, &key)
            .await
            .unwrap_err(),
        AppError::Validation(_)
    ));
    drop(config);
    f.teardown().await;
}
async fn insert(
    conn: &mut PgConnection,
    repo: Uuid,
    path: &str,
) -> std::result::Result<(), sqlx::Error> {
    let checksum = "a".repeat(64);
    let key =
        crate::services::artifact_service::ArtifactService::storage_key_from_checksum(&checksum);
    sqlx::query(
        "INSERT INTO artifacts(repository_id,path,name,size_bytes,checksum_sha256,storage_key,content_type) \
         VALUES ($1,$2,'pkg',1,$3,$4,'application/x-rpm')",
    )
    .bind(repo)
    .bind(path)
    .bind(checksum)
    .bind(key)
    .execute(conn)
    .await?;
    Ok(())
}

#[tokio::test]
async fn upload_and_depth_edit_cannot_cross_layout_boundary_4216() {
    let Some(f) = tdh::Fixture::setup("local", "rpm").await else {
        return;
    };
    let mut upload = f.pool.begin().await.unwrap();
    insert(&mut upload, f.repo_id, "pkg.rpm").await.unwrap();
    let mut config = f.pool.acquire().await.unwrap();
    let conflict = tokio::time::timeout(
        std::time::Duration::from_secs(2),
        set_depth(&mut config, f.repo_id, 1),
    )
    .await
    .unwrap()
    .unwrap_err();
    assert!(conflict.to_string().contains("AK_RPM_DEPTH_BUSY"));
    upload.rollback().await.unwrap();
    set_depth(&mut config, f.repo_id, 1).await.unwrap();
    drop(config);
    let mut edit = f.pool.begin().await.unwrap();
    set_depth(&mut edit, f.repo_id, 2).await.unwrap();
    let mut write = f.pool.acquire().await.unwrap();
    let conflict = insert(&mut write, f.repo_id, "a/pkg.rpm")
        .await
        .unwrap_err();
    assert!(conflict.to_string().contains("AK_RPM_DEPTH_BUSY"));
    edit.commit().await.unwrap();
    let conflict = insert(&mut write, f.repo_id, "a/pkg.rpm")
        .await
        .unwrap_err();
    assert!(conflict.to_string().contains("AK_RPM_DEPTH_PATH"));
    insert(&mut write, f.repo_id, "a/b/pkg.rpm").await.unwrap();
    drop(write);
    f.teardown().await;
}

#[tokio::test]
async fn unsupported_modes_and_future_virtual_attach_are_guarded_4216() {
    let Some(pool) = tdh::try_pool().await else {
        return;
    };
    let mut conn = pool.acquire().await.unwrap();
    let mut repos = Vec::new();
    for (kind, format) in [
        ("local", "generic"),
        ("staging", "rpm"),
        ("remote", "rpm"),
        ("virtual", "rpm"),
    ] {
        let (id, _, dir) = tdh::create_repo(&pool, kind, format).await;
        set_depth(&mut conn, id, 0).await.unwrap();
        let err = set_depth(&mut conn, id, 1).await.unwrap_err();
        assert!(
            err.to_string().contains("AK_RPM_DEPTH_UNSUPPORTED"),
            "{kind}/{format}: {err}"
        );
        repos.push((id, dir));
    }
    let (id, _, dir) = tdh::create_repo(&pool, "local", "rpm").await;
    let virtual_id = repos.last().unwrap().0;
    set_depth(&mut conn, id, 1).await.unwrap();
    let error = sqlx::query("INSERT INTO virtual_repo_members(virtual_repo_id,member_repo_id,priority) VALUES ($1,$2,0)")
        .bind(virtual_id).bind(id).execute(&mut *conn).await.unwrap_err();
    assert!(error.to_string().contains("AK_RPM_DEPTH_UNSUPPORTED"));
    set_depth(&mut conn, id, 0).await.unwrap();
    sqlx::query("INSERT INTO virtual_repo_members(virtual_repo_id,member_repo_id,priority) VALUES ($1,$2,0)")
        .bind(virtual_id).bind(id).execute(&mut *conn).await.unwrap();
    assert!(set_depth(&mut conn, id, 1)
        .await
        .unwrap_err()
        .to_string()
        .contains("AK_RPM_DEPTH_UNSUPPORTED"));
    repos.push((id, dir));
    drop(conn);
    for (id, dir) in repos {
        sqlx::query("DELETE FROM repositories WHERE id = $1")
            .bind(id)
            .execute(&pool)
            .await
            .unwrap();
        std::fs::remove_dir_all(dir).unwrap();
    }
}

#[tokio::test]
async fn cross_repository_moves_preserve_layout_or_roll_back_4216() {
    let Some(f) = tdh::Fixture::setup("local", "rpm").await else {
        return;
    };
    let (target, _, directory) = tdh::create_repo(&f.pool, "local", "rpm").await;
    let mut conn = f.pool.acquire().await.unwrap();
    set_depth(&mut conn, f.repo_id, 1).await.unwrap();
    set_depth(&mut conn, target, 2).await.unwrap();
    insert(&mut conn, f.repo_id, "a/pkg.rpm").await.unwrap();
    let move_sql = "UPDATE artifacts SET repository_id=$1 WHERE repository_id=$2";
    let error = sqlx::query(move_sql)
        .bind(target)
        .bind(f.repo_id)
        .execute(&mut *conn)
        .await
        .unwrap_err();
    assert!(error.to_string().contains("AK_RPM_DEPTH_PATH"));
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM artifacts WHERE repository_id=$1")
        .bind(f.repo_id)
        .fetch_one(&mut *conn)
        .await
        .unwrap();
    assert_eq!(count, 1);
    sqlx::query("UPDATE artifacts SET path='a/b/pkg.rpm' WHERE repository_id=$1")
        .bind(f.repo_id)
        .execute(&mut *conn)
        .await
        .unwrap();
    let mut config = f.pool.begin().await.unwrap();
    set_depth(&mut config, target, 1).await.unwrap();
    let error = tokio::time::timeout(
        std::time::Duration::from_secs(2),
        sqlx::query(move_sql)
            .bind(target)
            .bind(f.repo_id)
            .execute(&mut *conn),
    )
    .await
    .unwrap()
    .unwrap_err();
    assert!(error.to_string().contains("AK_RPM_DEPTH_BUSY"));
    config.rollback().await.unwrap();
    sqlx::query(move_sql)
        .bind(target)
        .bind(f.repo_id)
        .execute(&mut *conn)
        .await
        .unwrap();
    assert_eq!(
        settings(&f.pool, &[f.repo_id, target]).await.unwrap()[&target],
        (2, false)
    );
    drop(conn);
    sqlx::query("DELETE FROM repositories WHERE id=$1")
        .bind(target)
        .execute(&f.pool)
        .await
        .unwrap();
    std::fs::remove_dir_all(directory).unwrap();
    f.teardown().await;
}

#[test]
fn database_layout_denials_use_explicit_safe_errors_4216() {
    for marker in ["PATH", "RANGE"] {
        assert!(matches!(
            database_error(&format!("AK_RPM_DEPTH_{marker}")),
            Some(AppError::Validation(_))
        ));
    }
    for marker in ["POPULATED", "BUSY"] {
        assert!(matches!(
            database_error(&format!("AK_RPM_DEPTH_{marker}")),
            Some(AppError::Conflict(_))
        ));
    }
    for marker in ["UNSUPPORTED", "STORAGE"] {
        assert!(matches!(
            database_error(&format!("AK_RPM_DEPTH_{marker}")),
            Some(AppError::UnprocessableEntity(_))
        ));
    }
    assert!(database_error("ordinary database failure").is_none());
}
