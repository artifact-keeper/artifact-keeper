//! A restore whose object pass stops (#5857).

use super::restore_identity_tests::archive_tables;
use super::*;
use crate::api::handlers::test_db_helpers as tdh;
use crate::services::storage_service::{FilesystemBackend, StorageBackend};
use async_trait::async_trait;

fn options() -> RestoreOptions {
    RestoreOptions {
        restore_database: true,
        restore_artifacts: true,
        target_repository_id: None,
        allow_unverified_archive: false,
        actor: None,
    }
}

/// Archive storage whose second read of one key returns other bytes: the
/// archive changes between a restore's verify pass and its write pass.
struct ChangesOnSecondRead {
    inner: FilesystemBackend,
    swap: std::sync::Mutex<Option<(String, Bytes, usize)>>,
}

#[async_trait]
impl StorageBackend for ChangesOnSecondRead {
    async fn put(&self, key: &str, content: Bytes) -> Result<()> {
        self.inner.put(key, content).await
    }
    async fn get(&self, key: &str) -> Result<Bytes> {
        self.inner.get(key).await
    }
    async fn exists(&self, key: &str) -> Result<bool> {
        self.inner.exists(key).await
    }
    async fn delete(&self, key: &str) -> Result<()> {
        self.inner.delete(key).await
    }
    async fn list(&self, prefix: Option<&str>) -> Result<Vec<String>> {
        self.inner.list(prefix).await
    }
    async fn copy(&self, source: &str, dest: &str) -> Result<()> {
        self.inner.copy(source, dest).await
    }
    async fn size(&self, key: &str) -> Result<u64> {
        self.inner.size(key).await
    }
    async fn get_stream(&self, key: &str) -> Result<BoxStream<'static, Result<Bytes>>> {
        let changed = {
            let mut swap = self.swap.lock().unwrap();
            match swap.as_mut() {
                Some((swapped, bytes, reads)) if swapped == key => {
                    *reads += 1;
                    (*reads >= 2).then(|| bytes.clone())
                }
                _ => None,
            }
        };
        match changed {
            Some(bytes) => Ok(futures::stream::once(async move { Ok(bytes) }).boxed()),
            None => self.inner.get_stream(key).await,
        }
    }
}

/// The archive with the bytes of its last artifact entry flipped.
fn with_last_artifact_changed(archive: &[u8]) -> Vec<u8> {
    let entries = BackupService::extract_entries(archive).unwrap();
    let name = |p: &std::path::Path| p.to_string_lossy().into_owned();
    let mut tables = Vec::new();
    let mut artifacts: Vec<(String, Vec<u8>)> = Vec::new();
    let mut manifest = Vec::new();
    for (path, bytes) in entries {
        let path = name(&path);
        if let Some(table) = path
            .strip_prefix("database/")
            .and_then(|t| t.strip_suffix(".json"))
        {
            tables.push((table.to_string(), bytes));
        } else if let Some(key) = path.strip_prefix("artifacts/") {
            artifacts.push((key.to_string(), bytes));
        } else {
            manifest = bytes;
        }
    }
    let last = artifacts.last_mut().unwrap();
    last.1.iter_mut().for_each(|b| *b ^= 0xff);
    let tables: Vec<(&str, &[u8])> = tables
        .iter()
        .map(|(t, b)| (t.as_str(), b.as_slice()))
        .collect();
    let artifacts: Vec<(&str, &[u8])> = artifacts
        .iter()
        .map(|(k, b)| (k.as_str(), b.as_slice()))
        .collect();
    build_backup_tar(&tables, &artifacts, &manifest).unwrap()
}

#[tokio::test]
async fn a_restore_whose_object_pass_stops_restores_no_row_and_can_be_rerun_5857() {
    let Some(f) = tdh::Fixture::setup("local", "generic").await else {
        return;
    };
    let pool = &f.pool;
    let storage = Arc::new(StorageService::new(Arc::new(FilesystemBackend::new(
        f.storage_dir.clone(),
    ))));
    let archives = Arc::new(ChangesOnSecondRead {
        inner: FilesystemBackend::new(f.storage_dir.join("archives")),
        swap: std::sync::Mutex::new(None),
    });
    let service = BackupService::with_archive_storage(
        pool.clone(),
        storage.clone(),
        Arc::new(StorageService::new(archives.clone())),
    );

    let mut contents = Vec::new();
    for i in 0..3 {
        let key = format!("restore-5857/{}/{i}", Uuid::new_v4());
        let bytes = format!("object {i} of the #5857 archive").into_bytes();
        storage.put(&key, Bytes::from(bytes.clone())).await.unwrap();
        sqlx::query(
            "INSERT INTO artifacts (repository_id, path, name, size_bytes, checksum_sha256, \
             content_type, storage_key) VALUES ($1, $2, $2, $3, $4, 'text/plain', $5)",
        )
        .bind(f.repo_id)
        .bind(format!("o/{i}.txt"))
        .bind(bytes.len() as i64)
        .bind(crate::services::artifact_service::ArtifactService::calculate_sha256(&bytes))
        .bind(&key)
        .execute(pool)
        .await
        .unwrap();
        contents.push((key, bytes));
    }
    let mut conn = pool.acquire().await.unwrap();
    let repositories: Vec<serde_json::Value> =
        BackupService::export_table(&mut conn, "repositories")
            .await
            .unwrap()
            .as_array()
            .unwrap()
            .iter()
            .filter(|row| row["id"] == f.repo_id.to_string())
            .cloned()
            .collect();
    let artifacts = BackupService::export_artifacts(&mut conn, Some(&[f.repo_id]), None)
        .await
        .unwrap();
    drop(conn);
    let backup = archive_tables(
        &service,
        &[
            ("repositories", repositories.into()),
            ("artifacts", artifacts),
        ],
        &contents,
    )
    .await;
    let archive_key: String = sqlx::query_scalar("SELECT storage_path FROM backups WHERE id = $1")
        .bind(backup)
        .fetch_one(pool)
        .await
        .unwrap();
    let archive = archives.inner.get(&archive_key).await.unwrap();

    // The repository and its bytes are gone; the archive will change after
    // the restore has verified it.
    sqlx::query("DELETE FROM artifacts WHERE repository_id = $1")
        .bind(f.repo_id)
        .execute(pool)
        .await
        .unwrap();
    sqlx::query("DELETE FROM repositories WHERE id = $1")
        .bind(f.repo_id)
        .execute(pool)
        .await
        .unwrap();
    for (key, _) in &contents {
        storage.delete(key).await.unwrap();
    }
    *archives.swap.lock().unwrap() = Some((
        archive_key.clone(),
        Bytes::from(with_last_artifact_changed(&archive)),
        0,
    ));

    let stopped = service.restore(backup, options()).await;
    let rows_after_stop: i64 =
        sqlx::query_scalar("SELECT count(*) FROM repositories WHERE id = $1")
            .bind(f.repo_id)
            .fetch_one(pool)
            .await
            .unwrap();
    let artifact_rows_after_stop: i64 =
        sqlx::query_scalar("SELECT count(*) FROM artifacts WHERE repository_id = $1")
            .bind(f.repo_id)
            .fetch_one(pool)
            .await
            .unwrap();

    // Re-running with the intact archive restores everything.
    *archives.swap.lock().unwrap() = None;
    let rerun = service.restore(backup, options()).await;
    let rows_after_rerun: i64 =
        sqlx::query_scalar("SELECT count(*) FROM artifacts WHERE repository_id = $1")
            .bind(f.repo_id)
            .fetch_one(pool)
            .await
            .unwrap();
    let mut bytes_after_rerun = Vec::new();
    for (key, _) in &contents {
        bytes_after_rerun.push(storage.get(key).await.ok().map(|b| b.to_vec()));
    }
    f.teardown().await;

    let message = match stopped {
        Err(AppError::Validation(message)) => message,
        other => panic!("want a validation error, got {other:?}"),
    };
    assert!(
        message.contains("changed after it was verified"),
        "{message}"
    );
    assert!(
        message.contains("No database rows were restored"),
        "{message}"
    );
    assert!(message.contains("2 artifact object(s)"), "{message}");
    assert_eq!(rows_after_stop, 0, "the repository row was committed");
    assert_eq!(artifact_rows_after_stop, 0, "artifact rows were committed");

    let rerun = rerun.unwrap();
    assert_eq!(rerun.status, RestoreStatus::Completed, "{:?}", rerun.errors);
    assert_eq!(rows_after_rerun, 3);
    let want: Vec<Option<Vec<u8>>> = contents.iter().map(|(_, b)| Some(b.clone())).collect();
    assert_eq!(bytes_after_rerun, want);
}
