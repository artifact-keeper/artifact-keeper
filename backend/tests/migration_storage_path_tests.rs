//! Regression for #2025: `MigrationService::create_repository` must persist an
//! ABSOLUTE `storage_path` under STORAGE_PATH.
//!
//! Pre-fix it stored the bare repo key (a relative path). `FilesystemStorage`
//! then rooted that at the process cwd (`/app`), which is read-only on hardened
//! containers (`readOnlyRootFilesystem`), so every migrated artifact write
//! failed with `Read-only file system (os error 30)`.

use artifact_keeper_backend::services::migration_service::{
    FormatCompatibility, MigrationService, RepositoryMigrationConfig, RepositoryType,
};
use sqlx::PgPool;
use uuid::Uuid;

#[tokio::test]
#[ignore] // requires Postgres (Tier 2): cargo test --workspace -- --ignored
async fn create_repository_persists_absolute_storage_path() {
    let pool = PgPool::connect(&std::env::var("DATABASE_URL").unwrap())
        .await
        .unwrap();

    let key = format!("mig-store-{}", &Uuid::new_v4().to_string()[..8]);
    let storage_base = "/data/storage";

    let config = RepositoryMigrationConfig {
        source_key: key.clone(),
        target_key: key.clone(),
        repo_type: RepositoryType::Local,
        package_type: "maven".to_string(),
        description: None,
        format_compatibility: FormatCompatibility::Full,
        upstream_url: None,
        members: vec![],
    };

    let repo_id = MigrationService::new(pool.clone())
        .create_repository(&config, storage_base)
        .await
        .expect("create_repository should succeed");

    let storage_path: String =
        sqlx::query_scalar("SELECT storage_path FROM repositories WHERE id = $1")
            .bind(repo_id)
            .fetch_one(&pool)
            .await
            .unwrap();

    // cleanup before asserting so a failure does not leak the row
    sqlx::query("DELETE FROM repositories WHERE id = $1")
        .bind(repo_id)
        .execute(&pool)
        .await
        .ok();

    // The bug stored `key` (relative). The fix stores `{storage_base}/{key}`.
    assert_eq!(storage_path, format!("{storage_base}/{key}"));
    assert!(
        storage_path.starts_with('/'),
        "storage_path must be absolute, got {storage_path:?}"
    );
}
