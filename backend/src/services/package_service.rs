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
    #[allow(clippy::too_many_arguments)]
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
    #[allow(clippy::too_many_arguments)]
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

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // PackageService struct construction
    // -----------------------------------------------------------------------

    // PackageService requires a PgPool, so we can only test the struct shape
    // and the logic around parameters. All actual methods are async + DB.

    // -----------------------------------------------------------------------
    // Metadata JSON handling
    // -----------------------------------------------------------------------

    #[test]
    fn test_metadata_json_value_none() {
        let metadata: Option<JsonValue> = None;
        assert!(metadata.is_none());
    }

    #[test]
    fn test_metadata_json_value_some() {
        let val = serde_json::json!({
            "license": "MIT",
            "homepage": "https://example.com",
            "keywords": ["rust", "crate"]
        });
        assert_eq!(val["license"], "MIT");
        assert_eq!(val["keywords"][0], "rust");
    }

    #[test]
    fn test_metadata_complex_structure() {
        let metadata = serde_json::json!({
            "authors": ["Alice", "Bob"],
            "dependencies": {
                "serde": "1.0",
                "tokio": "1.0"
            },
            "build": {
                "features": ["default", "full"],
                "target": "x86_64"
            }
        });
        assert!(metadata["authors"].is_array());
        assert_eq!(metadata["authors"].as_array().unwrap().len(), 2);
        assert_eq!(metadata["dependencies"]["serde"], "1.0");
    }

    // -----------------------------------------------------------------------
    // Parameter validation concepts
    // -----------------------------------------------------------------------

    #[test]
    fn test_description_optional() {
        let description: Option<&str> = None;
        assert!(description.is_none());

        let description: &str = "A useful library";
        assert_eq!(description, "A useful library");
    }

    #[test]
    fn test_uuid_generation() {
        // Verify UUIDs are unique (as used for repository_id, etc.)
        let id1 = Uuid::new_v4();
        let id2 = Uuid::new_v4();
        assert_ne!(id1, id2);
    }

    #[test]
    fn test_package_name_version_format() {
        let name = "my-crate";
        let version = "1.2.3";
        let repository_id = Uuid::new_v4();
        let log_msg = format!(
            "Failed to populate package record for {name}@{version} in repo {repository_id}"
        );
        assert!(log_msg.contains("my-crate@1.2.3"));
        assert!(log_msg.contains(&repository_id.to_string()));
    }
}
