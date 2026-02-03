//! Package service.
//!
//! Auto-populates the `packages` and `package_versions` tables when artifacts
//! are uploaded. Uses UPSERT semantics so repeated publishes of the same
//! name+version are idempotent.

use serde_json::Value as JsonValue;
use sqlx::PgPool;
use tracing::warn;
use uuid::Uuid;

/// Service for managing package and package_version records.
pub struct PackageService {
    db: PgPool,
}

impl PackageService {
    /// Create a new package service.
    pub fn new(db: PgPool) -> Self {
        Self { db }
    }

    /// Create or update a package and its version record from an uploaded
    /// artifact.
    ///
    /// This is a best-effort operation: callers should log failures rather
    /// than propagate them so that the artifact upload itself is never
    /// blocked.
    ///
    /// Returns the `packages.id` on success.
    pub async fn create_or_update_from_artifact(
        &self,
        repository_id: Uuid,
        name: &str,
        version: &str,
        size_bytes: i64,
        checksum_sha256: &str,
        description: Option<&str>,
        metadata: Option<JsonValue>,
    ) -> anyhow::Result<Uuid> {
        // Upsert into `packages`
        let row: (Uuid,) = sqlx::query_as(
            r#"
            INSERT INTO packages (repository_id, name, version, description, size_bytes, metadata)
            VALUES ($1, $2, $3, $4, $5, $6)
            ON CONFLICT (repository_id, name, version) DO UPDATE SET
                size_bytes   = EXCLUDED.size_bytes,
                description  = COALESCE(EXCLUDED.description, packages.description),
                metadata     = COALESCE(EXCLUDED.metadata, packages.metadata),
                updated_at   = NOW()
            RETURNING id
            "#,
        )
        .bind(repository_id)
        .bind(name)
        .bind(version)
        .bind(description)
        .bind(size_bytes)
        .bind(&metadata)
        .fetch_one(&self.db)
        .await?;

        let package_id = row.0;

        // Upsert into `package_versions`
        sqlx::query(
            r#"
            INSERT INTO package_versions (package_id, version, size_bytes, checksum_sha256)
            VALUES ($1, $2, $3, $4)
            ON CONFLICT (package_id, version) DO UPDATE SET
                size_bytes      = EXCLUDED.size_bytes,
                checksum_sha256 = EXCLUDED.checksum_sha256
            "#,
        )
        .bind(package_id)
        .bind(version)
        .bind(size_bytes)
        .bind(checksum_sha256)
        .execute(&self.db)
        .await?;

        Ok(package_id)
    }

    /// Fire-and-forget wrapper that logs errors instead of propagating them.
    pub async fn try_create_or_update_from_artifact(
        &self,
        repository_id: Uuid,
        name: &str,
        version: &str,
        size_bytes: i64,
        checksum_sha256: &str,
        description: Option<&str>,
        metadata: Option<JsonValue>,
    ) {
        if let Err(e) = self
            .create_or_update_from_artifact(
                repository_id,
                name,
                version,
                size_bytes,
                checksum_sha256,
                description,
                metadata,
            )
            .await
        {
            warn!(
                "Failed to populate package record for {name}@{version} in repo {repository_id}: {e}"
            );
        }
    }
}
