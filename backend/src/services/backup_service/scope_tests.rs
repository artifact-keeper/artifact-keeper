//! A scoped backup archives only the rows of its scope (#5884).
use super::restore_identity_tests::archive_tables;
use super::*;
use crate::api::handlers::test_db_helpers as tdh;
use crate::services::rpm_layout;
use crate::services::storage_service::FilesystemBackend;

async fn insert_artifact_with_a_download(pool: &PgPool, repo_id: Uuid, user_id: Uuid) -> Uuid {
    insert_artifact_updated_at(pool, repo_id, user_id, Utc::now()).await
}

/// An artifact last changed at `updated_at`, downloaded once now.
async fn insert_artifact_updated_at(
    pool: &PgPool,
    repo_id: Uuid,
    user_id: Uuid,
    updated_at: DateTime<Utc>,
) -> Uuid {
    // A content-addressed key, which an RPM repository with a repodata depth
    // requires (`ak_rpm_depth_artifact_guard`).
    let checksum = format!("{}{}", Uuid::new_v4().simple(), Uuid::new_v4().simple());
    let storage_key = format!("{}/{}/{checksum}", &checksum[..2], &checksum[2..4]);
    let artifact_id: Uuid = sqlx::query_scalar(
        "INSERT INTO artifacts \
             (repository_id, path, name, size_bytes, checksum_sha256, \
              content_type, storage_key, updated_at) \
         VALUES ($1, $2, '5884-artifact', 4, $3, 'application/octet-stream', $4, $5) \
         RETURNING id",
    )
    .bind(repo_id)
    .bind(format!("scope-5884/{}", Uuid::new_v4()))
    .bind(&checksum)
    .bind(&storage_key)
    .bind(updated_at)
    .fetch_one(pool)
    .await
    .expect("insert artifact");
    sqlx::query("INSERT INTO download_statistics (artifact_id, user_id) VALUES ($1, $2)")
        .bind(artifact_id)
        .bind(user_id)
        .execute(pool)
        .await
        .expect("insert download");
    artifact_id
}

fn backup_service(
    pool: &PgPool,
    fx: &tdh::Fixture,
    archive_root: &std::path::Path,
) -> BackupService {
    std::fs::create_dir_all(archive_root).expect("create archive dir");
    BackupService::new(
        pool.clone(),
        Arc::new(StorageService::new(Arc::new(FilesystemBackend::new(
            archive_root.to_path_buf(),
        )))),
    )
    .with_storage_registry(fx.state.storage_registry.clone())
}

/// Run a metadata backup with this scope and return its id and entries.
async fn back_up(
    service: &BackupService,
    repository_ids: Option<Vec<Uuid>>,
    exclude_repository_ids: Option<Vec<Uuid>>,
    since: Option<DateTime<Utc>>,
) -> (Uuid, Vec<(std::path::PathBuf, Vec<u8>)>) {
    let backup = service
        .create(CreateBackupRequest {
            backup_type: BackupType::Metadata,
            repository_ids,
            exclude_repository_ids,
            since,
            created_by: None,
            name: None,
        })
        .await
        .expect("create backup job");
    let run = service
        .execute_run(backup.id)
        .await
        .expect("execute backup");
    assert!(run.failure.is_none(), "{:?}", run.failure);
    let bytes = service
        .archive_storage
        .get(run.backup.storage_path.as_ref().expect("archive path"))
        .await
        .expect("archive readable");
    let entries = BackupService::extract_entries(&bytes).expect("extract archive");
    (backup.id, entries)
}

async fn forget_backups(pool: &PgPool, backup_ids: &[Uuid]) {
    sqlx::query("DELETE FROM backups WHERE id = ANY($1)")
        .bind(backup_ids.to_vec())
        .execute(pool)
        .await
        .expect("delete backup rows");
}

async fn delete_repositories(pool: &PgPool, repos: &[Uuid]) {
    for repo in repos {
        sqlx::query("DELETE FROM repositories WHERE id = $1")
            .bind(repo)
            .execute(pool)
            .await
            .expect("delete repository");
    }
}

fn ids(rows: &[serde_json::Value], column: &str) -> Vec<String> {
    let mut out: Vec<String> = rows
        .iter()
        .filter_map(|row| row.get(column)?.as_str().map(str::to_string))
        .collect();
    out.sort();
    out.dedup();
    out
}

/// A backup of repository A, taken while repository B (an RPM repository
/// with a repodata depth) holds an artifact that was downloaded, archives A's
/// repository row and A's download statistics only. B and its artifact are
/// then deleted, and so is A: the restore brings A back, `completed` with no
/// errors, and does not bring B back.
///
/// FAILS ON MAIN: `repositories` and `download_statistics` were exported
/// whole, so the archive held B's row and B's statistics. The restore
/// recreated B, and because B's depth made the archive depth-bearing, it ran
/// strictly and failed on B's statistics row (its artifact is gone).
#[tokio::test]
async fn a_repository_scoped_backup_archives_only_its_repositories_and_their_downloads_5884() {
    let Some(a) = tdh::Fixture::setup("local", "generic").await else {
        return;
    };
    let pool = a.pool.clone();
    let (b_id, _b_key, b_dir) = tdh::create_repo(&pool, "local", "rpm").await;
    {
        let mut conn = pool.acquire().await.expect("acquire");
        rpm_layout::set_depth(&mut conn, b_id, 1)
            .await
            .expect("set B's repodata depth");
    }
    let a_artifact = insert_artifact_with_a_download(&pool, a.repo_id, a.user_id).await;
    let b_artifact = insert_artifact_with_a_download(&pool, b_id, a.user_id).await;

    let archive_root = std::env::temp_dir().join(format!("bk-5884-{}", Uuid::new_v4()));
    let service = backup_service(&pool, &a, &archive_root);
    let (backup_id, entries) = back_up(&service, Some(vec![a.repo_id]), None, None).await;
    assert_eq!(
        ids(&archive_table_rows(&entries, "repositories"), "id"),
        vec![a.repo_id.to_string()],
        "the archive carries only the repository in scope"
    );
    assert_eq!(
        ids(&archive_table_rows(&entries, "artifacts"), "id"),
        vec![a_artifact.to_string()]
    );
    assert_eq!(
        ids(
            &archive_table_rows(&entries, "download_statistics"),
            "artifact_id"
        ),
        vec![a_artifact.to_string()],
        "the archive carries only the downloads of the artifacts it archives"
    );

    // Restore the tables the backup scopes, exactly as it archived them. The
    // server-wide tables (users, roles, user_roles, api_tokens, grants,
    // groups, settings) are exported whole by design (#5884 does not scope
    // them), so in the shared test database they hold the rows of every test
    // running alongside this one. Those tests create and delete their users
    // while this restore runs: a user that still exists when the `users` pass
    // skips its row and is gone by the `user_roles` pass fails that row's
    // foreign key and makes the restore `partial`, and a user deleted before
    // the restore would be brought back. Neither says anything about scoping.
    let scoped: Vec<(&str, serde_json::Value)> =
        ["repositories", "artifacts", "download_statistics"]
            .into_iter()
            .map(|table| {
                let rows = archive_table_rows(&entries, table);
                (table, serde_json::Value::Array(rows))
            })
            .collect();
    // `archive_tables` writes a full backup, which must carry the bytes its
    // artifact rows reference. This restore writes no objects.
    let a_bytes: Vec<(String, Vec<u8>)> = archive_table_rows(&entries, "artifacts")
        .iter()
        .filter_map(|row| row.get("storage_key")?.as_str())
        .map(|key| (key.to_string(), b"5884".to_vec()))
        .collect();
    let scoped_backup = archive_tables(&service, &scoped, &a_bytes).await;

    // B goes away entirely (its artifact and statistics cascade), then A.
    delete_repositories(&pool, &[b_id, a.repo_id]).await;

    let result = service
        .restore(
            scoped_backup,
            RestoreOptions {
                restore_database: true,
                restore_artifacts: false,
                target_repository_id: None,
                allow_unverified_archive: false,
                actor: None,
            },
        )
        .await
        .expect("restore runs");
    assert_eq!(
        result.status,
        RestoreStatus::Completed,
        "{:?}",
        result.errors
    );
    assert!(result.errors.is_empty(), "{:?}", result.errors);
    let back: Vec<Uuid> =
        sqlx::query_scalar("SELECT id FROM repositories WHERE id = ANY($1) ORDER BY id")
            .bind(vec![a.repo_id, b_id])
            .fetch_all(&pool)
            .await
            .expect("read repositories");
    assert_eq!(back, vec![a.repo_id], "A is back and B is not");
    let downloads: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM download_statistics WHERE artifact_id = ANY($1)")
            .bind(vec![a_artifact, b_artifact])
            .fetch_one(&pool)
            .await
            .expect("count downloads");
    assert_eq!(downloads, 1, "A's download is back and B's is not");

    delete_repositories(&pool, &[a.repo_id]).await;
    forget_backups(&pool, &[backup_id, scoped_backup]).await;
    let _ = std::fs::remove_dir_all(&archive_root);
    let _ = std::fs::remove_dir_all(&b_dir);
    let _ = std::fs::remove_dir_all(&a.storage_dir);
}

/// An incremental (`since`) backup archives the download statistics of the
/// artifacts it archives only: a download recorded now of an artifact last
/// changed before the cutoff stays out, with that artifact.
///
/// FAILS ON MAIN, and if the `download_statistics` scope is applied only
/// under a repository filter: the table was exported whole, so the older
/// artifact's download was archived without its artifact.
#[tokio::test]
async fn an_incremental_backup_archives_only_the_downloads_of_changed_artifacts_5884() {
    let Some(a) = tdh::Fixture::setup("local", "generic").await else {
        return;
    };
    let pool = a.pool.clone();
    let old = insert_artifact_updated_at(
        &pool,
        a.repo_id,
        a.user_id,
        Utc::now() - chrono::Duration::days(2),
    )
    .await;
    let new = insert_artifact_with_a_download(&pool, a.repo_id, a.user_id).await;

    let archive_root = std::env::temp_dir().join(format!("bk-5884-since-{}", Uuid::new_v4()));
    let service = backup_service(&pool, &a, &archive_root);
    let since = Utc::now() - chrono::Duration::hours(1);
    let (backup_id, entries) = back_up(&service, None, None, Some(since)).await;

    let artifacts = ids(&archive_table_rows(&entries, "artifacts"), "id");
    assert!(artifacts.contains(&new.to_string()), "{artifacts:?}");
    assert!(!artifacts.contains(&old.to_string()), "{artifacts:?}");
    let downloads = ids(
        &archive_table_rows(&entries, "download_statistics"),
        "artifact_id",
    );
    assert!(
        downloads.contains(&new.to_string()),
        "the changed artifact's download is archived: {downloads:?}"
    );
    assert!(
        !downloads.contains(&old.to_string()),
        "a download of an artifact the archive does not carry is left out: {downloads:?}"
    );

    delete_repositories(&pool, &[a.repo_id]).await;
    forget_backups(&pool, &[backup_id]).await;
    let _ = std::fs::remove_dir_all(&archive_root);
    let _ = std::fs::remove_dir_all(&a.storage_dir);
}

/// A backup that only excludes repositories archives every other repository
/// and its downloads, and neither the excluded repository's row nor its
/// downloads.
///
/// FAILS ON MAIN: `repositories` and `download_statistics` were exported
/// whole, so the excluded repository's row and download were archived.
#[tokio::test]
async fn an_exclude_only_backup_archives_neither_the_excluded_repository_nor_its_downloads_5884() {
    let Some(a) = tdh::Fixture::setup("local", "generic").await else {
        return;
    };
    let pool = a.pool.clone();
    let (b_id, _b_key, b_dir) = tdh::create_repo(&pool, "local", "generic").await;
    let a_artifact = insert_artifact_with_a_download(&pool, a.repo_id, a.user_id).await;
    let b_artifact = insert_artifact_with_a_download(&pool, b_id, a.user_id).await;

    let archive_root = std::env::temp_dir().join(format!("bk-5884-exclude-{}", Uuid::new_v4()));
    let service = backup_service(&pool, &a, &archive_root);
    let (backup_id, entries) = back_up(&service, None, Some(vec![b_id]), None).await;

    let repositories = ids(&archive_table_rows(&entries, "repositories"), "id");
    assert!(repositories.contains(&a.repo_id.to_string()));
    assert!(
        !repositories.contains(&b_id.to_string()),
        "the excluded repository's row is left out: {repositories:?}"
    );
    let downloads = ids(
        &archive_table_rows(&entries, "download_statistics"),
        "artifact_id",
    );
    assert!(downloads.contains(&a_artifact.to_string()), "{downloads:?}");
    assert!(
        !downloads.contains(&b_artifact.to_string()),
        "the excluded repository's download is left out: {downloads:?}"
    );

    delete_repositories(&pool, &[b_id, a.repo_id]).await;
    forget_backups(&pool, &[backup_id]).await;
    let _ = std::fs::remove_dir_all(&archive_root);
    let _ = std::fs::remove_dir_all(&b_dir);
    let _ = std::fs::remove_dir_all(&a.storage_dir);
}

/// An exclude-only filter lists the repositories of the backup's own
/// snapshot: a repository created once the snapshot is open is in neither
/// the filter nor the snapshot's rows.
///
/// FAILS if the filter is read outside the snapshot, as on main (before the
/// snapshot was opened, on the pool): the snapshot is then taken at its first
/// row query, after the repository was created, and holds a repository the
/// filter does not list, whose rows a backup would leave out although it was
/// never excluded.
#[tokio::test]
async fn an_exclude_only_filter_is_read_in_the_backup_snapshot_5884() {
    let Some(a) = tdh::Fixture::setup("local", "generic").await else {
        return;
    };
    let pool = a.pool.clone();
    let metadata = serde_json::json!({ "exclude_repository_ids": [a.repo_id] });
    let (mut snapshot, filter) = BackupService::open_export_snapshot(&pool, Some(&metadata))
        .await
        .expect("open the snapshot");
    let filter = filter.expect("an exclude-only filter");
    let (late_id, _late_key, late_dir) = tdh::create_repo(&pool, "local", "generic").await;

    let mut in_snapshot: Vec<Uuid> = sqlx::query_scalar("SELECT id FROM repositories")
        .fetch_all(&mut *snapshot)
        .await
        .expect("read the snapshot's repositories");
    in_snapshot.retain(|id| *id != a.repo_id);
    in_snapshot.sort();
    let mut filter_sorted = filter.clone();
    filter_sorted.sort();
    snapshot.rollback().await.expect("close the snapshot");
    assert!(!filter.contains(&a.repo_id), "the excluded repository");
    assert!(!filter.contains(&late_id), "created after the snapshot");
    assert_eq!(
        filter_sorted, in_snapshot,
        "the filter lists the snapshot's repositories but the excluded one"
    );

    delete_repositories(&pool, &[late_id, a.repo_id]).await;
    let _ = std::fs::remove_dir_all(&late_dir);
    let _ = std::fs::remove_dir_all(&a.storage_dir);
}

/// A scoped backup of a curation staging repository whose curation source is
/// out of scope archives the staging row with no source, and keeps a target
/// that is in scope. With the source and the staging repository deleted, the
/// restore brings the staging repository back `completed`.
///
/// FAILS ON MAIN: the archived row kept its `curation_source_repo_id`, which
/// names a repository the archive does not carry; once that repository is
/// gone the row fails `repositories_curation_source_repo_id_fkey` and the
/// restore is `partial`.
#[tokio::test]
async fn a_scoped_backup_drops_a_curation_reference_to_an_out_of_scope_repository_5884() {
    let Some(staging) = tdh::Fixture::setup("local", "generic").await else {
        return;
    };
    let pool = staging.pool.clone();
    let (source_id, _source_key, source_dir) = tdh::create_repo(&pool, "remote", "generic").await;
    let (target_id, _target_key, target_dir) = tdh::create_repo(&pool, "local", "generic").await;
    sqlx::query(
        "UPDATE repositories SET curation_enabled = true, \
         curation_source_repo_id = $2, curation_target_repo_id = $3 WHERE id = $1",
    )
    .bind(staging.repo_id)
    .bind(source_id)
    .bind(target_id)
    .execute(&pool)
    .await
    .expect("make a curation staging repository");

    let archive_root = std::env::temp_dir().join(format!("bk-5884-curation-{}", Uuid::new_v4()));
    let service = backup_service(&pool, &staging, &archive_root);
    let (backup_id, entries) =
        back_up(&service, Some(vec![staging.repo_id, target_id]), None, None).await;
    let rows = archive_table_rows(&entries, "repositories");
    let row = rows
        .iter()
        .find(|row| row["id"] == staging.repo_id.to_string())
        .expect("the staging row is archived");
    assert!(
        row["curation_source_repo_id"].is_null(),
        "an out-of-scope source is written as NULL: {row}"
    );
    assert_eq!(
        row["curation_target_repo_id"],
        target_id.to_string(),
        "an in-scope target is kept"
    );
    assert_eq!(row["curation_enabled"], true);

    // Restore the `repositories` table as archived (see the first test for
    // why the server-wide tables are left out).
    let scoped_backup = archive_tables(
        &service,
        &[("repositories", serde_json::Value::Array(rows.clone()))],
        &[],
    )
    .await;
    delete_repositories(&pool, &[source_id, staging.repo_id]).await;
    let result = service
        .restore(
            scoped_backup,
            RestoreOptions {
                restore_database: true,
                restore_artifacts: false,
                target_repository_id: None,
                allow_unverified_archive: false,
                actor: None,
            },
        )
        .await
        .expect("restore runs");
    assert_eq!(
        result.status,
        RestoreStatus::Completed,
        "{:?}",
        result.errors
    );
    assert!(result.errors.is_empty(), "{:?}", result.errors);
    let (source, target): (Option<Uuid>, Option<Uuid>) = sqlx::query_as(
        "SELECT curation_source_repo_id, curation_target_repo_id \
         FROM repositories WHERE id = $1",
    )
    .bind(staging.repo_id)
    .fetch_one(&pool)
    .await
    .expect("the staging repository is back");
    assert_eq!((source, target), (None, Some(target_id)));

    delete_repositories(&pool, &[staging.repo_id, target_id]).await;
    forget_backups(&pool, &[backup_id, scoped_backup]).await;
    let _ = std::fs::remove_dir_all(&archive_root);
    let _ = std::fs::remove_dir_all(&source_dir);
    let _ = std::fs::remove_dir_all(&target_dir);
    let _ = std::fs::remove_dir_all(&staging.storage_dir);
}
