//! Regression for #2025 and #2336: `MigrationService::create_repository` must
//! persist a `storage_path` and `storage_backend` consistent with the resolved
//! default backend.
//!
//! #2025: filesystem repos stored the bare repo key (a relative path).
//! `FilesystemStorage` then rooted that at the process cwd (`/app`), which is
//! read-only on hardened containers (`readOnlyRootFilesystem`), so every
//! migrated artifact write failed with `Read-only file system (os error 30)`.
//!
//! #2336: `storage_backend` was never bound on the INSERT, so every migrated
//! repo fell back to the column default `filesystem` — silently stranding
//! S3/GCS/Azure deployments' migrated artifacts on local disk.

use artifact_keeper_backend::services::migration_service::{
    FormatCompatibility, MigrationService, RepositoryMigrationConfig, RepositoryType,
};
use sqlx::PgPool;
use uuid::Uuid;

fn config_for(key: &str) -> RepositoryMigrationConfig {
    RepositoryMigrationConfig {
        source_key: key.to_string(),
        target_key: key.to_string(),
        repo_type: RepositoryType::Local,
        package_type: "maven".to_string(),
        description: None,
        format_compatibility: FormatCompatibility::Full,
        upstream_url: None,
        members: vec![],
    }
}

async fn read_storage(pool: &PgPool, repo_id: Uuid) -> (String, String) {
    let row: (String, String) =
        sqlx::query_as("SELECT storage_path, storage_backend FROM repositories WHERE id = $1")
            .bind(repo_id)
            .fetch_one(pool)
            .await
            .unwrap();
    // cleanup before asserting so a failure does not leak the row
    sqlx::query("DELETE FROM repositories WHERE id = $1")
        .bind(repo_id)
        .execute(pool)
        .await
        .ok();
    row
}

#[tokio::test]
#[ignore] // requires Postgres (Tier 2): cargo test --workspace -- --ignored
async fn create_repository_persists_absolute_storage_path_for_filesystem() {
    let pool = PgPool::connect(&std::env::var("DATABASE_URL").unwrap())
        .await
        .unwrap();

    let key = format!("mig-store-fs-{}", &Uuid::new_v4().to_string()[..8]);
    let storage_base = "/data/storage";

    let repo_id = MigrationService::new(pool.clone())
        .create_repository(&config_for(&key), storage_base, "filesystem")
        .await
        .expect("create_repository should succeed");

    let (storage_path, storage_backend) = read_storage(&pool, repo_id).await;

    // The bug stored `key` (relative). The fix stores `{storage_base}/{key}`.
    assert_eq!(storage_path, format!("{storage_base}/{key}"));
    assert!(
        storage_path.starts_with('/'),
        "storage_path must be absolute, got {storage_path:?}"
    );
    assert_eq!(storage_backend, "filesystem");
}

#[tokio::test]
#[ignore] // requires Postgres (Tier 2): cargo test --workspace -- --ignored
async fn create_repository_inherits_default_cloud_backend() {
    // Regression for #2336: when the server default backend is s3, a migrated
    // repo must record storage_backend=s3 and a bare-key storage_path — not
    // silently fall back to filesystem under the staging path.
    let pool = PgPool::connect(&std::env::var("DATABASE_URL").unwrap())
        .await
        .unwrap();

    let key = format!("mig-store-s3-{}", &Uuid::new_v4().to_string()[..8]);

    let repo_id = MigrationService::new(pool.clone())
        .create_repository(&config_for(&key), "/data/storage", "s3")
        .await
        .expect("create_repository should succeed");

    let (storage_path, storage_backend) = read_storage(&pool, repo_id).await;

    assert_eq!(storage_backend, "s3");
    // Cloud backends address objects by the bare repo key.
    assert_eq!(storage_path, key);
}
