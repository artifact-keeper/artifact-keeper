//! Package service.
//!
//! Auto-populates the `packages` and `package_versions` tables when artifacts
//! are uploaded. Uses UPSERT semantics so repeated publishes of the same
//! package collapse into one `packages` row with many `package_versions`.

use serde_json::Value as JsonValue;
use sqlx::PgPool;
use tracing::warn;
use uuid::Uuid;

use crate::services::curation_service::version_compare;

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
        // Keep one package row per repository/name and let that row reflect
        // the latest known version.
        let inserted: Option<(Uuid,)> = sqlx::query_as(
            r#"
            INSERT INTO packages (repository_id, name, version, description, size_bytes, metadata)
            VALUES ($1, $2, $3, $4, $5, $6)
            ON CONFLICT (repository_id, name) DO NOTHING
            RETURNING id
            "#,
        )
        .bind(repository_id)
        .bind(name)
        .bind(version)
        .bind(description)
        .bind(size_bytes)
        .bind(&metadata)
        .fetch_optional(&self.db)
        .await?;

        let package_id = if let Some((package_id,)) = inserted {
            package_id
        } else {
            let existing: (Uuid, String) = sqlx::query_as(
                r#"
                SELECT id, version
                FROM packages
                WHERE repository_id = $1 AND name = $2
                "#,
            )
            .bind(repository_id)
            .bind(name)
            .fetch_one(&self.db)
            .await?;

            if version_compare(version, &existing.1) >= 0 {
                sqlx::query(
                    r#"
                    UPDATE packages
                    SET version = $2,
                        description = COALESCE($3, description),
                        size_bytes = $4,
                        metadata = COALESCE($5, metadata),
                        updated_at = NOW()
                    WHERE id = $1
                    "#,
                )
                .bind(existing.0)
                .bind(version)
                .bind(description)
                .bind(size_bytes)
                .bind(&metadata)
                .execute(&self.db)
                .await?;
            } else {
                sqlx::query(
                    r#"
                    UPDATE packages
                    SET updated_at = NOW()
                    WHERE id = $1
                    "#,
                )
                .bind(existing.0)
                .execute(&self.db)
                .await?;
            }

            existing.0
        };

        // Keep `package_versions` deterministic when a package format (PyPI in
        // particular) publishes multiple distributions for the same version.
        // Different peers may process wheel/sdist artifacts in different
        // orders during replication recovery, so "last writer wins" makes
        // otherwise-equivalent repositories diverge at the DB row level.
        sqlx::query(
            r#"
            INSERT INTO package_versions (package_id, version, size_bytes, checksum_sha256)
            VALUES ($1, $2, $3, $4)
            ON CONFLICT (package_id, version) DO UPDATE SET
                size_bytes      = EXCLUDED.size_bytes,
                checksum_sha256 = EXCLUDED.checksum_sha256
            WHERE (EXCLUDED.checksum_sha256, EXCLUDED.size_bytes)
                < (package_versions.checksum_sha256, package_versions.size_bytes)
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
fn should_replace_package_version(
    existing_checksum_sha256: &str,
    existing_size_bytes: i64,
    candidate_checksum_sha256: &str,
    candidate_size_bytes: i64,
) -> bool {
    (candidate_checksum_sha256, candidate_size_bytes)
        < (existing_checksum_sha256, existing_size_bytes)
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

    #[test]
    fn test_package_version_representative_is_checksum_deterministic() {
        assert!(should_replace_package_version("bbbb", 100, "aaaa", 500));
        assert!(!should_replace_package_version("aaaa", 500, "bbbb", 100));
    }

    #[test]
    fn test_package_version_representative_uses_size_tiebreaker() {
        assert!(should_replace_package_version("aaaa", 500, "aaaa", 100));
        assert!(!should_replace_package_version("aaaa", 100, "aaaa", 500));
        assert!(!should_replace_package_version("aaaa", 100, "aaaa", 100));
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
