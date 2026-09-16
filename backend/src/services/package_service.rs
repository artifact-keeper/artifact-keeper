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

/// Deterministic `package_versions` upsert, shared by both arms of the
/// combined catalog statement in
/// [`PackageService::create_or_update_from_artifact`] (#2110).
///
/// Binds: `$1` = package_id, `$2` = version, `$3` = size_bytes,
/// `$4` = checksum_sha256. The `WHERE` guard keeps the representative row
/// deterministic across peers (lexicographically smallest
/// `(checksum, size)` wins) instead of "last writer wins". `RETURNING`
/// exposes the post-upsert `size_bytes` to the outer statement when the
/// insert or update actually happened; an unreferenced data-modifying CTE
/// still executes exactly once.
const VERSION_UPSERT_CTE: &str = r#"
                WITH upserted AS (
                    INSERT INTO package_versions (package_id, version, size_bytes, checksum_sha256)
                    VALUES ($1, $2, $3, $4)
                    ON CONFLICT (package_id, version) DO UPDATE SET
                        size_bytes      = EXCLUDED.size_bytes,
                        checksum_sha256 = EXCLUDED.checksum_sha256
                    WHERE (EXCLUDED.checksum_sha256, EXCLUDED.size_bytes)
                        < (package_versions.checksum_sha256, package_versions.size_bytes)
                    RETURNING size_bytes
                )
"#;

// ---------------------------------------------------------------------------
// Catalog liveness (#3660)
// ---------------------------------------------------------------------------
//
// `package_versions` carries no `artifact_id`: a version row is tied to its
// bytes only by `(packages.repository_id, package_versions.checksum_sha256)`,
// which is the checksum every writer of the catalog passes in (the artifact's
// own SHA-256, or for OCI the manifest digest that the manifest's `artifacts`
// row also records). That pair is therefore the join the read paths use to
// decide whether a catalog row still has bytes behind it.
//
// Remote repositories are exempt. Proxy-cached artifacts are deliberately NOT
// written to the `artifacts` table (#1278 / #1280) while their catalog rows
// ARE written (#1999), so a liveness join would hide every proxy-cached
// package. For a remote repo "the artifact is gone" is a cache-expiry
// question, not a delete, and the catalog row is the only record there is.

/// `EXISTS` test for a live `artifacts` row backing one `package_versions`
/// row. Expects `p` (packages) and `pv` (package_versions) in scope.
const LIVE_ARTIFACT_EXISTS: &str = r#"EXISTS (
            SELECT 1
            FROM artifacts a_live
            WHERE a_live.repository_id = p.repository_id
              AND a_live.checksum_sha256 = pv.checksum_sha256
              AND a_live.is_deleted = false
        )"#;

/// SQL predicate that is true when a `packages` row still has at least one
/// version whose backing artifact is live (#3660).
///
/// Expects `p` (packages) and `r` (repositories) in scope. Soft-deleting the
/// last artifact of a package hides it from the catalog; restoring the
/// artifact (a re-upload flips `is_deleted` back to false) makes it reappear
/// with no catalog write, which is why the read paths filter rather than the
/// soft-delete path deleting rows.
pub fn live_package_predicate() -> String {
    format!(
        r#"(
    r.repo_type = 'remote'
    OR EXISTS (
        SELECT 1
        FROM package_versions pv
        WHERE pv.package_id = p.id
          AND {LIVE_ARTIFACT_EXISTS}
    )
)"#
    )
}

/// SQL predicate that is true when one `package_versions` row still has a live
/// backing artifact (#3660). Expects `pv`, `p` and `r` in scope.
pub fn live_package_version_predicate() -> String {
    format!(
        r#"(
    r.repo_type = 'remote'
    OR {LIVE_ARTIFACT_EXISTS}
)"#
    )
}

/// Rows removed by [`prune_catalog_for_purged_artifact`].
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct CatalogPrune {
    pub versions_removed: u64,
    pub packages_removed: u64,
}

/// Drop the catalog rows left behind by a HARD-deleted artifact (#3660).
///
/// Only genuine purges may call this. Every format-native delete route
/// (`delete_chart`, npm unpublish, the NuGet/Conan/Debian/Incus deletes, the
/// lifecycle sweeps) and `ArtifactService::delete` are SOFT deletes: they flip
/// `is_deleted`, and a restore must bring the catalog row back. Removing the
/// row there would make a restore unrecoverable, so soft deletes are handled
/// by the read-path filter ([`live_package_predicate`]) instead and only the
/// storage GC's hard delete — the single reaper of soft-deleted `artifacts`
/// rows — prunes.
///
/// The version row is kept while ANY `artifacts` row (live or soft-deleted)
/// still carries the checksum, so purging one of several peers leaves the
/// catalog intact. A `packages` row is removed only once its last version has
/// gone. Runs on the caller's connection so it can join the purge's
/// transaction.
pub async fn prune_catalog_for_purged_artifact(
    conn: &mut sqlx::PgConnection,
    repository_id: Uuid,
    checksum_sha256: &str,
) -> sqlx::Result<CatalogPrune> {
    // Catalog rows written without a usable digest (the streaming Maven proxy
    // path passes an empty string) have no link to prune through.
    if checksum_sha256.trim().len() != 64 {
        return Ok(CatalogPrune::default());
    }

    let package_ids: Vec<Uuid> = sqlx::query_scalar(
        r#"
        DELETE FROM package_versions pv
        USING packages p
        WHERE pv.package_id = p.id
          AND p.repository_id = $1
          AND pv.checksum_sha256 = $2
          AND NOT EXISTS (
              SELECT 1
              FROM artifacts a
              WHERE a.repository_id = p.repository_id
                AND a.checksum_sha256 = pv.checksum_sha256
          )
        RETURNING pv.package_id
        "#,
    )
    .bind(repository_id)
    .bind(checksum_sha256.trim())
    .fetch_all(&mut *conn)
    .await?;

    if package_ids.is_empty() {
        return Ok(CatalogPrune::default());
    }

    // Separate statement on purpose: a data-modifying CTE's outer subqueries
    // read the pre-statement snapshot, so an `EXISTS` folded into the delete
    // above would still see the version rows it just removed.
    let packages_removed = sqlx::query(
        r#"
        DELETE FROM packages p
        WHERE p.id = ANY($1)
          AND NOT EXISTS (
              SELECT 1 FROM package_versions pv WHERE pv.package_id = p.id
          )
        "#,
    )
    .bind(&package_ids)
    .execute(&mut *conn)
    .await?
    .rows_affected();

    Ok(CatalogPrune {
        versions_removed: package_ids.len() as u64,
        packages_removed,
    })
}

// ---------------------------------------------------------------------------
// Hosted publish registration (#3659)
// ---------------------------------------------------------------------------

/// Fire-and-forget catalog registration for a hosted publish (#3659).
///
/// The thin shape the native format handlers call right after their
/// `artifacts` INSERT: keyed on the format's own coordinates (never the
/// filename), tagged with the format in `metadata`, and unable to fail the
/// publish — [`PackageService::try_create_or_update_from_artifact`] swallows
/// and logs.
#[allow(clippy::too_many_arguments)]
pub async fn register_published_package(
    db: &PgPool,
    repository_id: Uuid,
    format: &str,
    name: &str,
    version: &str,
    size_bytes: i64,
    checksum_sha256: &str,
    description: Option<&str>,
) {
    PackageService::new(db.clone())
        .try_create_or_update_from_artifact(
            repository_id,
            name,
            version,
            size_bytes,
            checksum_sha256,
            description,
            Some(serde_json::json!({ "format": format })),
        )
        .await;
}

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
        //
        // On conflict the update is a deliberate no-op whose only purpose is
        // to make `RETURNING` yield the existing row (`ON CONFLICT DO
        // NOTHING` returns nothing), collapsing the previous
        // insert-then-select round trips into one (#2110). The returned
        // `version` is the pre-existing one on conflict and the incoming one
        // on a fresh insert, so the `version_compare(...) >= 0` gate below
        // reduces to the old behavior in both cases (a fresh insert compares
        // equal to itself and updates, matching the old `inserted => true`
        // arm). `updated_at` is bumped by the follow-up statement on every
        // path, exactly as before.
        let (package_id, current_version): (Uuid, String) = sqlx::query_as(
            r#"
            INSERT INTO packages (repository_id, name, version, description, size_bytes, metadata)
            VALUES ($1, $2, $3, $4, $5, $6)
            ON CONFLICT (repository_id, name) DO UPDATE
                SET updated_at = packages.updated_at
            RETURNING id, version
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

        let should_update_package_row = version_compare(version, &current_version) >= 0;

        // Keep `package_versions` deterministic when a package format
        // publishes multiple physical assets for the same version. Different
        // peers may process Maven JAR/POM/module/classifier files or PyPI
        // wheel/sdist artifacts in different
        // orders during replication recovery, so "last writer wins" makes
        // otherwise-equivalent repositories diverge at the DB row level.
        //
        // The `packages`-row synchronization is folded into the same
        // statement via a data-modifying CTE (#2110) — one round trip
        // instead of two. CTE visibility rules matter here: the outer
        // UPDATE's subqueries see the snapshot from BEFORE the statement, so
        // the representative `size_bytes` must come from the CTE's
        // `RETURNING` (fresh insert / winning update) and only fall back to
        // the pre-existing `package_versions` row when the deterministic
        // guard rejected the update (in which case that row is unchanged and
        // still the representative).
        if should_update_package_row {
            sqlx::query(sqlx::AssertSqlSafe(&*format!(
                r#"
                {VERSION_UPSERT_CTE}
                UPDATE packages
                SET version = $2,
                    description = COALESCE($5, description),
                    size_bytes = COALESCE(
                        (SELECT upserted.size_bytes FROM upserted),
                        (
                            SELECT pv.size_bytes
                            FROM package_versions pv
                            WHERE pv.package_id = packages.id
                              AND pv.version = $2
                        )
                    ),
                    metadata = COALESCE($6, metadata),
                    updated_at = NOW()
                WHERE id = $1
                "#
            )))
            .bind(package_id)
            .bind(version)
            .bind(size_bytes)
            .bind(checksum_sha256)
            .bind(description)
            .bind(&metadata)
            .execute(&self.db)
            .await?;
        } else {
            // Data-modifying CTEs execute exactly once even when
            // unreferenced, so the version upsert still runs.
            sqlx::query(sqlx::AssertSqlSafe(&*format!(
                r#"
                {VERSION_UPSERT_CTE}
                UPDATE packages
                SET updated_at = NOW()
                WHERE id = $1
                "#
            )))
            .bind(package_id)
            .bind(version)
            .bind(size_bytes)
            .bind(checksum_sha256)
            .execute(&self.db)
            .await?;
        }

        Ok(package_id)
    }

    /// Walk the live `artifacts` rows of every catalog-eligible hosted
    /// repository and upsert their catalog rows (#3659 backfill).
    ///
    /// The native format handlers only started writing `packages` /
    /// `package_versions` when their registration landed, so everything
    /// published before that stays off the Packages page until it is
    /// re-published. This replays those publishes through the same upsert the
    /// handlers call, which makes it idempotent: re-running it produces the
    /// same rows.
    ///
    /// Scope is deliberately the formats whose `artifacts` rows carry the
    /// catalog coordinates directly (see [`backfill_catalog_coordinates`]).
    /// Maven/OCI/npm/PyPI/NuGet/Composer/Conan/Debian/Incus derive their
    /// catalog name from parsed coordinates the `artifacts` row does not
    /// record, and have registered on publish for much longer; they are left
    /// to their own publish path.
    ///
    /// `repository_id` scopes the walk to one repository; `None` walks every
    /// hosted repository.
    pub async fn backfill_catalog(
        &self,
        repository_id: Option<Uuid>,
    ) -> anyhow::Result<CatalogBackfillReport> {
        const PAGE: i64 = 500;

        let mut report = CatalogBackfillReport::default();
        let mut cursor = Uuid::nil();

        loop {
            let rows: Vec<BackfillRow> = sqlx::query_as(
                r#"
                SELECT a.id, a.repository_id, r.format::text AS format, a.path, a.name,
                       a.version, a.size_bytes, a.checksum_sha256
                FROM artifacts a
                JOIN repositories r ON r.id = a.repository_id
                WHERE a.is_deleted = false
                  AND r.repo_type <> 'remote'
                  AND r.format::text = ANY($1)
                  AND ($4::uuid IS NULL OR a.repository_id = $4)
                  AND a.id > $2
                ORDER BY a.id
                LIMIT $3
                "#,
            )
            .bind(BACKFILL_FORMATS)
            .bind(cursor)
            .bind(PAGE)
            .bind(repository_id)
            .fetch_all(&self.db)
            .await?;

            if rows.is_empty() {
                break;
            }

            for row in &rows {
                report.artifacts_scanned += 1;
                let Some((name, version)) = backfill_catalog_coordinates(
                    &row.format,
                    &row.path,
                    &row.name,
                    row.version.as_deref(),
                ) else {
                    report.artifacts_skipped += 1;
                    continue;
                };

                // `description`/`metadata` stay `None`: the upsert COALESCEs
                // them, so a backfill never overwrites the richer values a
                // real publish already recorded, and the `format` shown on the
                // Packages page comes from the repository row anyway.
                match self
                    .create_or_update_from_artifact(
                        row.repository_id,
                        &name,
                        &version,
                        row.size_bytes,
                        row.checksum_sha256.trim(),
                        None,
                        None,
                    )
                    .await
                {
                    Ok(_) => report.packages_registered += 1,
                    Err(e) => {
                        report.artifacts_failed += 1;
                        warn!("Catalog backfill failed for {name}@{version}: {e}");
                    }
                }
            }

            cursor = rows[rows.len() - 1].id;
            if (rows.len() as i64) < PAGE {
                break;
            }
        }

        Ok(report)
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

/// Repository formats the catalog backfill walks (#3659).
///
/// Each of these writes `artifacts.name` / `artifacts.version` with the
/// format's own package coordinates at publish time (or, for `sbt`, encodes
/// them in the path), so the catalog row can be reconstructed from the
/// artifact row alone.
pub const BACKFILL_FORMATS: &[&str] = &[
    "alpine",
    "cargo",
    "chef",
    "cocoapods",
    "conda",
    "conda_native",
    "go",
    "helm",
    "huggingface",
    "jetbrains",
    "opentofu",
    "protobuf",
    "pub",
    "rpm",
    "sbt",
    "swift",
    "terraform",
    "vscode",
];

/// Counts reported by [`PackageService::backfill_catalog`].
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, serde::Serialize, utoipa::ToSchema)]
pub struct CatalogBackfillReport {
    /// Live artifact rows considered.
    pub artifacts_scanned: i64,
    /// Catalog upserts performed (one per considered artifact; repeated
    /// coordinates collapse into the same rows).
    pub packages_registered: i64,
    /// Rows with no derivable package coordinates (index/sidecar rows, rows
    /// with no version).
    pub artifacts_skipped: i64,
    /// Rows whose upsert errored. Non-fatal: the walk continues.
    pub artifacts_failed: i64,
}

#[derive(sqlx::FromRow)]
struct BackfillRow {
    id: Uuid,
    repository_id: Uuid,
    format: String,
    path: String,
    name: String,
    version: Option<String>,
    size_bytes: i64,
    checksum_sha256: String,
}

/// Derive the catalog `(name, version)` for one artifact row during the
/// backfill (#3659).
///
/// Pure so the per-format rules are unit-testable without a database. Returns
/// `None` for rows that are not packages (no version, index/label fixtures).
pub fn backfill_catalog_coordinates(
    format: &str,
    path: &str,
    name: &str,
    version: Option<&str>,
) -> Option<(String, String)> {
    let version = version.map(str::trim).filter(|v| !v.is_empty())?;

    match format {
        // SBT/Ivy stores the filename stem (which embeds the revision) in
        // `artifacts.name`; the package coordinate is the Ivy `org/module`,
        // which only the path carries.
        "sbt" => {
            let info = crate::formats::sbt::SbtHandler::parse_path(path).ok()?;
            let revision = info.revision?;
            let revision = revision.trim();
            if revision.is_empty() || info.org.is_empty() || info.module.is_empty() {
                return None;
            }
            Some((
                format!("{}/{}", info.org, info.module),
                revision.to_string(),
            ))
        }
        // The protobuf label index is an artifact row, not a module.
        "protobuf" if version == "_labels" => None,
        _ => {
            let name = name.trim();
            if name.is_empty() {
                return None;
            }
            Some((name.to_string(), version.to_string()))
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

    #[tokio::test]
    async fn test_repeat_upsert_same_version_is_idempotent() {
        use crate::api::handlers::test_db_helpers as tdh;

        let Some(fx) = tdh::Fixture::setup("local", "generic").await else {
            return;
        };

        let service = PackageService::new(fx.pool.clone());
        let package = "idempotent-package";
        let version = "1.0.0";
        let checksum = "d".repeat(64);

        // Same (name, version, size, checksum) twice — the shape of a proxy
        // cache-miss refetch (#2110). Both calls must succeed and collapse
        // into one packages row and one package_versions row.
        for _ in 0..2 {
            service
                .create_or_update_from_artifact(
                    fx.repo_id, package, version, 512, &checksum, None, None,
                )
                .await
                .expect("upsert package from artifact");
        }

        let (pkg_rows, ver_rows, pkg_version, pkg_size): (i64, i64, String, i64) = sqlx::query_as(
            r#"
                SELECT COUNT(DISTINCT p.id), COUNT(pv.id), MIN(p.version), MIN(p.size_bytes)
                FROM packages p
                JOIN package_versions pv ON pv.package_id = p.id
                WHERE p.repository_id = $1 AND p.name = $2
                "#,
        )
        .bind(fx.repo_id)
        .bind(package)
        .fetch_one(&fx.pool)
        .await
        .expect("count catalog rows");

        fx.teardown().await;

        assert_eq!(pkg_rows, 1);
        assert_eq!(ver_rows, 1);
        assert_eq!(pkg_version, version);
        assert_eq!(pkg_size, 512);
    }

    #[tokio::test]
    async fn test_older_version_does_not_downgrade_package_row() {
        use crate::api::handlers::test_db_helpers as tdh;

        let Some(fx) = tdh::Fixture::setup("local", "generic").await else {
            return;
        };

        let service = PackageService::new(fx.pool.clone());
        let package = "gated-package";
        let checksum = "e".repeat(64);

        // Publish 2.0.0 first, then a backfill of 1.0.0: the packages row
        // must keep reflecting the latest version (the version_compare gate),
        // while both versions get package_versions rows. A later 3.0.0 must
        // bump the row.
        for (version, size) in [("2.0.0", 200_i64), ("1.0.0", 100), ("3.0.0", 300)] {
            service
                .create_or_update_from_artifact(
                    fx.repo_id, package, version, size, &checksum, None, None,
                )
                .await
                .expect("upsert package version");

            let latest: (String, i64) = sqlx::query_as(
                r#"SELECT version, size_bytes FROM packages WHERE repository_id = $1 AND name = $2"#,
            )
            .bind(fx.repo_id)
            .bind(package)
            .fetch_one(&fx.pool)
            .await
            .expect("read package row");

            // After the 1.0.0 backfill the row must still say 2.0.0.
            let expected = if version == "1.0.0" {
                ("2.0.0", 200)
            } else {
                (version, size)
            };
            assert_eq!((latest.0.as_str(), latest.1), expected);
        }

        let ver_rows: (i64,) = sqlx::query_as(
            r#"
            SELECT COUNT(*) FROM package_versions pv
            JOIN packages p ON p.id = pv.package_id
            WHERE p.repository_id = $1 AND p.name = $2
            "#,
        )
        .bind(fx.repo_id)
        .bind(package)
        .fetch_one(&fx.pool)
        .await
        .expect("count version rows");

        fx.teardown().await;

        assert_eq!(ver_rows.0, 3);
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

// ---------------------------------------------------------------------------
// #3659 / #3660: backfill coordinates, catalog prune, catalog backfill.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod catalog_maintenance_tests {
    use super::*;
    use crate::api::handlers::test_db_helpers as tdh;

    // -- backfill_catalog_coordinates (pure) --------------------------------

    #[test]
    fn coordinates_default_to_the_artifact_name_and_version() {
        assert_eq!(
            backfill_catalog_coordinates(
                "alpine",
                "main/x86_64/curl-8.0-r0.apk",
                "curl",
                Some("8.0-r0")
            ),
            Some(("curl".to_string(), "8.0-r0".to_string()))
        );
    }

    #[test]
    fn coordinates_are_none_without_a_version() {
        assert_eq!(
            backfill_catalog_coordinates("rpm", "packages/x.rpm", "x", None),
            None
        );
        assert_eq!(
            backfill_catalog_coordinates("rpm", "packages/x.rpm", "x", Some("   ")),
            None
        );
    }

    #[test]
    fn sbt_coordinates_come_from_the_ivy_path_not_the_filename() {
        assert_eq!(
            backfill_catalog_coordinates(
                "sbt",
                "com.example/my-lib_2.13/1.0.0/jars/my-lib_2.13-1.0.0.jar",
                "my-lib_2.13-1.0.0",
                Some("1.0.0"),
            ),
            Some(("com.example/my-lib_2.13".to_string(), "1.0.0".to_string()))
        );
    }

    #[test]
    fn protobuf_label_index_rows_are_not_packages() {
        assert_eq!(
            backfill_catalog_coordinates(
                "protobuf",
                "acme/widgets/_labels",
                "acme/widgets",
                Some("_labels")
            ),
            None
        );
    }

    // -- prune_catalog_for_purged_artifact (DB) -----------------------------

    /// Seed one artifact plus its catalog rows and return the checksum.
    async fn seed(fx: &tdh::Fixture, name: &str, version: &str) -> String {
        use sha2::{Digest, Sha256};
        let checksum = format!("{:x}", Sha256::digest(format!("{name}@{version}")));

        sqlx::query(
            "INSERT INTO artifacts (repository_id, path, name, version, size_bytes, \
             checksum_sha256, content_type, storage_key) \
             VALUES ($1, $2, $3, $4, 1, $5, 'application/octet-stream', $2)",
        )
        .bind(fx.repo_id)
        .bind(format!("{name}/{version}/asset.bin"))
        .bind(name)
        .bind(version)
        .bind(&checksum)
        .execute(&fx.pool)
        .await
        .expect("seed artifact");

        PackageService::new(fx.pool.clone())
            .create_or_update_from_artifact(fx.repo_id, name, version, 1, &checksum, None, None)
            .await
            .expect("seed catalog row");

        checksum
    }

    async fn catalog_counts(fx: &tdh::Fixture) -> (i64, i64) {
        sqlx::query_as(
            "SELECT (SELECT COUNT(*) FROM packages WHERE repository_id = $1), \
                    (SELECT COUNT(*) FROM package_versions pv \
                     JOIN packages p ON p.id = pv.package_id WHERE p.repository_id = $1)",
        )
        .bind(fx.repo_id)
        .fetch_one(&fx.pool)
        .await
        .expect("count catalog rows")
    }

    async fn prune(fx: &tdh::Fixture, checksum: &str) -> CatalogPrune {
        let mut conn = fx.pool.acquire().await.expect("acquire");
        prune_catalog_for_purged_artifact(&mut conn, fx.repo_id, checksum)
            .await
            .expect("prune catalog")
    }

    /// A soft delete must leave the catalog rows alone (the read filter hides
    /// them, and a restore has to be able to bring them back); only the hard
    /// delete the storage GC performs may prune them.
    #[tokio::test]
    async fn prune_only_fires_once_the_artifact_row_is_really_gone() {
        let Some(fx) = tdh::Fixture::setup("local", "helm").await else {
            return;
        };
        let checksum = seed(&fx, "pruned-chart", "1.0.0").await;

        // Soft delete: the row is still there, so nothing is pruned.
        sqlx::query("UPDATE artifacts SET is_deleted = true WHERE repository_id = $1")
            .bind(fx.repo_id)
            .execute(&fx.pool)
            .await
            .expect("soft delete");
        let soft = prune(&fx, &checksum).await;
        let after_soft = catalog_counts(&fx).await;

        // Hard delete (what the GC does) then prune: both rows go.
        sqlx::query("DELETE FROM artifacts WHERE repository_id = $1")
            .bind(fx.repo_id)
            .execute(&fx.pool)
            .await
            .expect("hard delete");
        let hard = prune(&fx, &checksum).await;
        let after_hard = catalog_counts(&fx).await;

        fx.teardown().await;

        assert_eq!(
            soft,
            CatalogPrune::default(),
            "a soft delete prunes nothing"
        );
        assert_eq!(after_soft, (1, 1));
        assert_eq!(
            hard,
            CatalogPrune {
                versions_removed: 1,
                packages_removed: 1
            }
        );
        assert_eq!(after_hard, (0, 0));
    }

    /// Purging one version of a multi-version package removes that version
    /// row and keeps the package row.
    #[tokio::test]
    async fn prune_keeps_the_package_while_another_version_survives() {
        let Some(fx) = tdh::Fixture::setup("local", "helm").await else {
            return;
        };
        let old = seed(&fx, "kept-chart", "1.0.0").await;
        let _new = seed(&fx, "kept-chart", "2.0.0").await;

        sqlx::query("DELETE FROM artifacts WHERE repository_id = $1 AND checksum_sha256 = $2")
            .bind(fx.repo_id)
            .bind(&old)
            .execute(&fx.pool)
            .await
            .expect("hard delete one version");
        let pruned = prune(&fx, &old).await;
        let counts = catalog_counts(&fx).await;

        fx.teardown().await;

        assert_eq!(
            pruned,
            CatalogPrune {
                versions_removed: 1,
                packages_removed: 0
            }
        );
        assert_eq!(counts, (1, 1));
    }

    // -- backfill_catalog (DB) ---------------------------------------------

    /// Artifacts published before a format's registration landed must be
    /// reconstructible into catalog rows, idempotently.
    #[tokio::test]
    async fn backfill_registers_preexisting_artifacts_and_is_idempotent() {
        let Some(fx) = tdh::Fixture::setup("local", "alpine").await else {
            return;
        };
        // An artifact row with no catalog row at all: exactly what a
        // pre-upgrade publish left behind.
        sqlx::query(
            "INSERT INTO artifacts (repository_id, path, name, version, size_bytes, \
             checksum_sha256, content_type, storage_key) \
             VALUES ($1, $2, 'curl', '8.0-r0', 42, $3, 'application/octet-stream', $2)",
        )
        .bind(fx.repo_id)
        .bind("main/x86_64/curl-8.0-r0.apk")
        .bind("c".repeat(64))
        .execute(&fx.pool)
        .await
        .expect("seed pre-upgrade artifact");

        let service = PackageService::new(fx.pool.clone());
        let first = service
            .backfill_catalog(Some(fx.repo_id))
            .await
            .expect("backfill");
        let after_first = catalog_counts(&fx).await;
        let _second = service
            .backfill_catalog(Some(fx.repo_id))
            .await
            .expect("re-run backfill");
        let after_second = catalog_counts(&fx).await;
        let row = tdh::catalog_row(&fx.pool, fx.repo_id, "curl").await;

        fx.teardown().await;

        assert!(
            first.artifacts_scanned >= 1,
            "the walk must reach the seeded artifact"
        );
        assert_eq!(first.artifacts_failed, 0);
        assert_eq!(after_first, (1, 1));
        assert_eq!(after_second, after_first, "the backfill must be idempotent");
        let row = row.expect("the backfill must write a packages row");
        assert_eq!(row.version, "8.0-r0");
        assert_eq!(row.versions, vec!["8.0-r0".to_string()]);
    }

    /// Rows with no derivable coordinates are skipped rather than registered
    /// under a filename or an empty version.
    #[tokio::test]
    async fn backfill_skips_rows_without_package_coordinates() {
        let Some(fx) = tdh::Fixture::setup("local", "alpine").await else {
            return;
        };
        sqlx::query(
            "INSERT INTO artifacts (repository_id, path, name, size_bytes, \
             checksum_sha256, content_type, storage_key) \
             VALUES ($1, $2, 'APKINDEX.tar.gz', 1, $3, 'application/octet-stream', $2)",
        )
        .bind(fx.repo_id)
        .bind("main/x86_64/APKINDEX.tar.gz")
        .bind("d".repeat(64))
        .execute(&fx.pool)
        .await
        .expect("seed versionless artifact");

        let report = PackageService::new(fx.pool.clone())
            .backfill_catalog(Some(fx.repo_id))
            .await
            .expect("backfill");
        let counts = catalog_counts(&fx).await;

        fx.teardown().await;

        assert!(report.artifacts_skipped >= 1);
        assert_eq!(counts, (0, 0), "a versionless row must not be catalogued");
    }
}
