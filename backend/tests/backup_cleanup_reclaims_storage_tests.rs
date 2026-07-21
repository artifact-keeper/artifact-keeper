//! Regression test for #2787: `BackupService::cleanup` (the retention path
//! behind `POST /api/v1/admin/cleanup` with `cleanup_old_backups`) must remove
//! the backup archive from storage, not just the database row. Deleting only
//! the row strands the `.tar.gz` archive in object storage forever, because the
//! `storage_path` handle is lost with the row — the opposite of what a
//! space-reclaiming retention job is supposed to do.
//!
//! Set DATABASE_URL and run:
//!
//! DATABASE_URL="postgresql://registry:registry@localhost:30987/artifact_registry" \
//!   cargo test --test backup_cleanup_reclaims_storage_tests -- --ignored --nocapture

use std::sync::Arc;

use artifact_keeper_backend::services::backup_service::BackupService;
use artifact_keeper_backend::services::storage_service::{FilesystemBackend, StorageService};
use bytes::Bytes;
use sqlx::PgPool;
use uuid::Uuid;

async fn reset_backups(pool: &PgPool) {
    // Throwaway DB: isolate this test from any other rows so the global
    // retention query operates on a known set.
    sqlx::query("DELETE FROM backups")
        .execute(pool)
        .await
        .expect("reset backups table");
}

async fn insert_completed_backup(pool: &PgPool, storage_path: &str, age_days: i32) -> Uuid {
    sqlx::query_scalar::<_, Uuid>(
        r#"
        INSERT INTO backups (backup_type, status, storage_path, size_bytes, created_at)
        VALUES ('full', 'completed', $1, 1024, NOW() - make_interval(days => $2))
        RETURNING id
        "#,
    )
    .bind(storage_path)
    .bind(age_days)
    .fetch_one(pool)
    .await
    .expect("insert backup row")
}

#[tokio::test]
#[ignore]
async fn cleanup_deletes_backup_archive_from_storage() {
    let pool = PgPool::connect(&std::env::var("DATABASE_URL").unwrap())
        .await
        .expect("failed to connect to database");

    let tmp = tempfile::tempdir().expect("tempdir");
    let storage = Arc::new(StorageService::new(Arc::new(FilesystemBackend::new(
        tmp.path().to_path_buf(),
    ))));
    let svc = BackupService::new(pool.clone(), storage.clone());
    reset_backups(&pool).await;

    // An old completed backup whose archive is present in storage.
    let key = format!("backups/2020/01/01/{}.tar.gz", Uuid::new_v4());
    let id = insert_completed_backup(&pool, &key, 90).await;
    storage
        .put(&key, Bytes::from_static(b"fake-archive-bytes"))
        .await
        .expect("seed archive");
    assert!(
        storage.exists(&key).await.unwrap(),
        "precondition: archive should exist before cleanup"
    );

    // Retention: keep 0 recent, delete anything older than 0 days -> deletes it.
    let removed = svc.cleanup(0, 0).await.expect("cleanup");
    assert_eq!(removed, 1, "cleanup should report one backup removed");

    // Row is gone...
    let row_exists: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM backups WHERE id = $1)")
        .bind(id)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert!(!row_exists, "backup row should be deleted");

    // ...and so is the archive (this is the #2787 defect: previously leaked).
    assert!(
        !storage.exists(&key).await.unwrap(),
        "#2787: backup archive must be removed from storage, not orphaned"
    );
}

#[tokio::test]
#[ignore]
async fn cleanup_retains_recent_and_young_backups_and_their_archives() {
    let pool = PgPool::connect(&std::env::var("DATABASE_URL").unwrap())
        .await
        .expect("failed to connect to database");

    let tmp = tempfile::tempdir().expect("tempdir");
    let storage = Arc::new(StorageService::new(Arc::new(FilesystemBackend::new(
        tmp.path().to_path_buf(),
    ))));
    let svc = BackupService::new(pool.clone(), storage.clone());
    reset_backups(&pool).await;

    // A recent backup (young) must be retained even though it is "extra".
    let young_key = format!("backups/2020/06/01/{}.tar.gz", Uuid::new_v4());
    let young_id = insert_completed_backup(&pool, &young_key, 0).await;
    storage
        .put(&young_key, Bytes::from_static(b"young"))
        .await
        .unwrap();

    // keep_count=0 but keep_days=30 -> the young (age 0) backup is NOT older
    // than 30 days, so it must survive and its archive must remain.
    let _ = svc.cleanup(0, 30).await.expect("cleanup");

    let row_exists: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM backups WHERE id = $1)")
        .bind(young_id)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert!(row_exists, "young backup row must be retained");
    assert!(
        storage.exists(&young_key).await.unwrap(),
        "young backup archive must be retained (legit path intact)"
    );

    // cleanup of a fresh id.
    sqlx::query("DELETE FROM backups WHERE id = $1")
        .bind(young_id)
        .execute(&pool)
        .await
        .unwrap();
}
