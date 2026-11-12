//! A scoped backup archives only the rows of its scope (#5884).
use super::*;
use crate::api::handlers::test_db_helpers as tdh;
use crate::services::rpm_layout;
use crate::services::storage_service::FilesystemBackend;

async fn insert_artifact_with_a_download(pool: &PgPool, repo_id: Uuid, user_id: Uuid) -> Uuid {
    // A content-addressed key, which an RPM repository with a repodata depth
    // requires (`ak_rpm_depth_artifact_guard`).
    let checksum = format!("{}{}", Uuid::new_v4().simple(), Uuid::new_v4().simple());
    let storage_key = format!("{}/{}/{checksum}", &checksum[..2], &checksum[2..4]);
    let artifact_id: Uuid = sqlx::query_scalar(
        "INSERT INTO artifacts \
             (repository_id, path, name, size_bytes, checksum_sha256, \
              content_type, storage_key, updated_at) \
         VALUES ($1, $2, '5884-artifact', 4, $3, 'application/octet-stream', $4, NOW()) \
         RETURNING id",
    )
    .bind(repo_id)
    .bind(format!("scope-5884/{}", Uuid::new_v4()))
    .bind(&checksum)
    .bind(&storage_key)
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
    std::fs::create_dir_all(&archive_root).expect("create archive dir");
    let service = BackupService::new(
        pool.clone(),
        Arc::new(StorageService::new(Arc::new(FilesystemBackend::new(
            archive_root.clone(),
        )))),
    )
    .with_storage_registry(a.state.storage_registry.clone());
    let backup = service
        .create(CreateBackupRequest {
            backup_type: BackupType::Metadata,
            repository_ids: Some(vec![a.repo_id]),
            exclude_repository_ids: None,
            since: None,
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

    // B goes away entirely (its artifact and statistics cascade), then A.
    for repo in [b_id, a.repo_id] {
        sqlx::query("DELETE FROM repositories WHERE id = $1")
            .bind(repo)
            .execute(&pool)
            .await
            .expect("delete repository");
    }

    let result = service
        .restore(
            backup.id,
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

    sqlx::query("DELETE FROM repositories WHERE id = $1")
        .bind(a.repo_id)
        .execute(&pool)
        .await
        .expect("clean up A");
    let _ = std::fs::remove_dir_all(&archive_root);
    let _ = std::fs::remove_dir_all(&b_dir);
    let _ = std::fs::remove_dir_all(&a.storage_dir);
}
