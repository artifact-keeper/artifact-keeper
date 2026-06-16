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
        // the latest known version. The row's size is synchronized after the
        // deterministic `package_versions` upsert below so multi-asset package
        // formats do not depend on upload or replication order.
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

        let (package_id, should_update_package_row) = if let Some((package_id,)) = inserted {
            (package_id, true)
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

            (existing.0, version_compare(version, &existing.1) >= 0)
        };

        // Keep `package_versions` deterministic when a package format
        // publishes multiple physical assets for the same version. Different
        // peers may process Maven JAR/POM/module/classifier files or PyPI
        // wheel/sdist artifacts in different
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

        if should_update_package_row {
            sqlx::query(
                r#"
                UPDATE packages
                SET version = $2,
                    description = COALESCE($3, description),
                    size_bytes = (
                        SELECT pv.size_bytes
                        FROM package_versions pv
                        WHERE pv.package_id = packages.id
                          AND pv.version = $2
                    ),
                    metadata = COALESCE($4, metadata),
                    updated_at = NOW()
                WHERE id = $1
                "#,
            )
            .bind(package_id)
            .bind(version)
            .bind(description)
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
            .bind(package_id)
            .execute(&self.db)
            .await?;
        }

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

    #[tokio::test]
    async fn test_package_size_tracks_deterministic_version_representative() {
        use crate::api::handlers::test_db_helpers as tdh;

        let Some(fx) = tdh::Fixture::setup("local", "generic").await else {
            return;
        };

        let service = PackageService::new(fx.pool.clone());
        let package = "multi-asset-package";
        let version = "1.0.0";
        let checksum_b = "b".repeat(64);
        let checksum_a = "a".repeat(64);
        let checksum_c = "c".repeat(64);

        service
            .create_or_update_from_artifact(
                fx.repo_id,
                package,
                version,
                900,
                &checksum_b,
                None,
                None,
            )
            .await
            .expect("insert first representative");
        service
            .create_or_update_from_artifact(
                fx.repo_id,
                package,
                version,
                300,
                &checksum_a,
                None,
                None,
            )
            .await
            .expect("replace with lower checksum representative");
        service
            .create_or_update_from_artifact(
                fx.repo_id,
                package,
                version,
                100,
                &checksum_c,
                None,
                None,
            )
            .await
            .expect("ignore later non-representative asset");

        let row: (i64, i64, String) = sqlx::query_as(
            r#"
            SELECT p.size_bytes, pv.size_bytes, pv.checksum_sha256
            FROM packages p
            JOIN package_versions pv ON pv.package_id = p.id
            WHERE p.repository_id = $1
              AND p.name = $2
              AND pv.version = $3
            "#,
        )
        .bind(fx.repo_id)
        .bind(package)
        .bind(version)
        .fetch_one(&fx.pool)
        .await
        .expect("query deterministic package representative");

        fx.teardown().await;

        assert_eq!(row.0, 300);
        assert_eq!(row.1, 300);
        assert_eq!(row.2, checksum_a);
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
