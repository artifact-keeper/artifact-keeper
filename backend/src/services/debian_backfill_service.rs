//! Source-free repair of a migrated Debian repository (#4740).
//!
//! A Debian repository imported before #4657 has `.deb` rows but no
//! `artifact_metadata` control document, catalog row, or maintainer-script
//! analysis for them, so `Packages` and the repository UI do not see the
//! packages. Re-running the migration job repairs it, but that needs the
//! source system. This service reads each package's `control.tar` member from
//! the repository's own storage and records exactly what a native upload
//! records, so the repository can be repaired in place.
//!
//! Scope and safety:
//! - Hosted Debian repositories only. A Remote caches upstream bytes and a
//!   Virtual has no rows of its own; neither is a migration target.
//! - Candidates are live `.deb`/`.udeb`/`.ddeb` rows outside `dists/` without
//!   a `format = 'debian'` metadata row. The head through the end of the
//!   `control.tar` member is read with ranged requests, so a multi-GiB
//!   package costs a few bounded reads, not a full download or buffer.
//! - Each package is filed under the component the migration importer now
//!   picks without the source (#4657, #4740): the path's own
//!   `pool/<component>/` segment, else `main` for a path with no component
//!   segment (`pool/<file>.deb`, the `pool/<letter>/<name>/` layout of a Nexus
//!   apt repository or an Ubuntu pool mirror, any other path). A row outside
//!   its component is moved to `pool/<component>/...` (same storage key); a
//!   live row already there with the same bytes keeps the package and the
//!   misfiled row is retired. A different package, or a trashed row, at the
//!   destination is reported and left alone.
//! - The source's own `dists/` index copies are not content on a hosted
//!   repository: AK renders and signs its own. Migration-origin `dists/` rows
//!   are soft-deleted from the artifact list, matching what the migration
//!   importer now skips; hosted rows are left alone.
//! - Idempotent: candidates are selected by the missing control document, so a
//!   second run does nothing. A package whose bytes are unreadable or whose
//!   control file disagrees with its file name is reported and skipped; the
//!   rest of the repository is still repaired.
//! - Bounded: at most `limit` candidates are examined per call. When more
//!   remain, the result is `truncated` and carries `next_after`, the cursor a
//!   follow-up call passes as `after`, so packages that keep failing never
//!   hold back the rest of the repository.
//! - One backfill per repository at a time (advisory lock). Each package is
//!   its own short statement or transaction; no table lock is taken.

use std::collections::HashMap;
use std::sync::Arc;

use serde::Serialize;
use sqlx::PgPool;
use utoipa::ToSchema;
use uuid::Uuid;

use crate::error::{AppError, Result};
use crate::models::repository::{Repository, RepositoryFormat};
use crate::services::artifact_service::ArtifactService;
use crate::services::cluster_lock::{lease_object_id, ClusterLock, PgAdvisoryLock};
use crate::storage::{StorageBackend, StorageRegistry};

/// Advisory-lock class for the per-repository Debian backfill.
pub const DEBIAN_BACKFILL_LOCK_CLASS: i32 = 0x4740;

/// Candidates fetched per page while walking the repository.
const CANDIDATE_PAGE: i64 = 500;

/// Sample cap for paths and errors in the response.
const SAMPLE_CAP: usize = 100;

/// Result of one source-free Debian backfill call.
#[derive(Debug, Default, Clone, Serialize, ToSchema)]
pub struct DebianBackfillResult {
    pub dry_run: bool,
    /// Candidate packages examined in this call.
    pub artifacts_scanned: u64,
    /// Control documents written (or, on a dry run, that would be written).
    pub packages_registered: u64,
    /// Registered packages that were moved under `pool/<component>/` (or, on
    /// a dry run, that would be). Included in `packages_registered`.
    pub packages_relocated: u64,
    /// Candidate rows that are not Debian package paths.
    pub artifacts_skipped: u64,
    /// Packages whose stored bytes or control file could not be used, or
    /// whose `pool/<component>/` destination is taken.
    pub artifacts_failed: u64,
    /// Migration-origin live `dists/` rows soft-deleted (or, on a dry run,
    /// that would be).
    pub dists_removed: u64,
    /// True when `limit` stopped the walk before every candidate was handled.
    pub truncated: bool,
    /// When `truncated`, the cursor to pass as `after` to continue the walk.
    #[schema(value_type = Option<String>, format = Uuid)]
    pub next_after: Option<Uuid>,
    /// Sample of registered package paths (the path each is filed under).
    pub registered_paths: Vec<String>,
    /// Sample of per-package failures.
    pub errors: Vec<String>,
}

#[derive(Debug, sqlx::FromRow)]
struct Candidate {
    id: Uuid,
    path: String,
    storage_key: String,
    size_bytes: i64,
    checksum_sha256: String,
}

/// Which row holds a package after [`DebianBackfillService::relocate`].
enum Relocated {
    /// The candidate row itself, now at the destination path.
    Moved,
    /// A live row with the same bytes already at the destination; the
    /// candidate row was retired.
    MergedInto(Uuid),
}

pub struct DebianBackfillService {
    db: PgPool,
    storage_registry: Arc<StorageRegistry>,
}

impl DebianBackfillService {
    pub fn new(db: PgPool, storage_registry: Arc<StorageRegistry>) -> Self {
        Self {
            db,
            storage_registry,
        }
    }

    /// Register every live package that has no Debian control document, and
    /// drop the source's stale `dists/` index rows. `after` resumes a walk a
    /// previous truncated call stopped (its `next_after`).
    pub async fn backfill(
        &self,
        repo: &Repository,
        dry_run: bool,
        limit: u64,
        after: Option<Uuid>,
    ) -> Result<DebianBackfillResult> {
        if repo.format != RepositoryFormat::Debian {
            return Err(AppError::UnprocessableEntity(format!(
                "Debian package backfill supports Debian repositories; '{}' is {:?}",
                repo.key, repo.format
            )));
        }
        if !repo.repo_type.is_hosted() {
            return Err(AppError::UnprocessableEntity(format!(
                "Debian package backfill repairs hosted repositories; '{}' is {}",
                repo.key,
                repo.repo_type.as_str()
            )));
        }

        let storage = self
            .storage_registry
            .backend_for(&repo.storage_location())?;
        let lease = PgAdvisoryLock::new(self.db.clone())
            .try_acquire(
                DEBIAN_BACKFILL_LOCK_CLASS,
                lease_object_id(&repo.id.to_string()),
            )
            .await?
            .ok_or_else(|| {
                AppError::Conflict(
                    "A Debian package backfill of this repository is already running".into(),
                )
            })?;
        let result = self
            .backfill_locked(repo, storage, dry_run, limit.max(1), after)
            .await;
        lease.release().await;
        result
    }

    async fn backfill_locked(
        &self,
        repo: &Repository,
        storage: Arc<dyn StorageBackend>,
        dry_run: bool,
        limit: u64,
        after: Option<Uuid>,
    ) -> Result<DebianBackfillResult> {
        let mut result = DebianBackfillResult {
            dry_run,
            ..Default::default()
        };
        let artifact_service = ArtifactService::new(self.db.clone(), storage.clone());

        let mut cursor = after.unwrap_or_else(Uuid::nil);
        let mut examined = 0u64;
        // Dry run only: destinations this call would have moved a row into.
        let mut dry_run_moves: HashMap<String, String> = HashMap::new();
        'walk: loop {
            let rows: Vec<Candidate> = sqlx::query_as(
                r#"
                SELECT a.id, a.path, a.storage_key, a.size_bytes, a.checksum_sha256
                FROM artifacts a
                WHERE a.repository_id = $1
                  AND a.is_deleted = false
                  AND a.path NOT LIKE 'dists/%'
                  AND lower(a.path) LIKE ANY (ARRAY['%.deb', '%.udeb', '%.ddeb'])
                  AND NOT EXISTS (
                      SELECT 1
                      FROM artifact_metadata am
                      WHERE am.artifact_id = a.id AND am.format = 'debian'
                  )
                  AND a.id > $2
                ORDER BY a.id
                LIMIT $3
                "#,
            )
            .bind(repo.id)
            .bind(cursor)
            .bind(CANDIDATE_PAGE)
            .fetch_all(&self.db)
            .await
            .map_err(|e| AppError::Database(e.to_string()))?;

            if rows.is_empty() {
                break;
            }

            for row in rows {
                if examined >= limit {
                    result.truncated = true;
                    result.next_after = Some(cursor);
                    break 'walk;
                }
                examined += 1;
                cursor = row.id;
                result.artifacts_scanned += 1;

                // The migration importer's placement without the source's
                // `deb.component` (#4657, #4740): the path's own component
                // segment, else `main`.
                let target_path =
                    crate::services::migration_worker::debian_destination_path(&row.path, None);
                let relocate = target_path != row.path;

                let package = match crate::api::handlers::debian::finalize_from_storage(
                    &target_path,
                    storage.as_ref(),
                    &row.storage_key,
                )
                .await
                {
                    Ok(Some(package)) => package,
                    Ok(None) => {
                        result.artifacts_skipped += 1;
                        continue;
                    }
                    Err(reason) => {
                        result.artifacts_failed += 1;
                        push_sample(&mut result.errors, &format!("{}: {reason}", row.path));
                        continue;
                    }
                };

                if dry_run {
                    // Check the destination the way the real run's move
                    // does, so a taken destination is reported as a failure
                    // here too instead of as a registration.
                    if relocate {
                        if let Err(reason) = self
                            .dry_run_destination(repo.id, &row, &target_path, &mut dry_run_moves)
                            .await
                        {
                            result.artifacts_failed += 1;
                            push_sample(&mut result.errors, &format!("{}: {reason}", row.path));
                            continue;
                        }
                        result.packages_relocated += 1;
                    }
                    result.packages_registered += 1;
                    push_sample(&mut result.registered_paths, &target_path);
                    continue;
                }

                let artifact_id = if relocate {
                    match self.relocate(repo.id, &row, &target_path).await {
                        Ok(Relocated::Moved) => row.id,
                        Ok(Relocated::MergedInto(id)) => id,
                        Err(reason) => {
                            result.artifacts_failed += 1;
                            push_sample(&mut result.errors, &format!("{}: {reason}", row.path));
                            continue;
                        }
                    }
                } else {
                    row.id
                };

                let (upload, deb_head) = package.parts();
                if let Err(e) = artifact_service
                    .set_metadata(
                        artifact_id,
                        "debian",
                        package.control_document().clone(),
                        serde_json::json!({}),
                    )
                    .await
                {
                    result.artifacts_failed += 1;
                    push_sample(
                        &mut result.errors,
                        &format!("{target_path}: could not record control document: {e}"),
                    );
                    continue;
                }
                crate::api::handlers::debian::record_debian_package_extras(
                    &self.db,
                    repo.id,
                    artifact_id,
                    row.size_bytes,
                    &row.checksum_sha256,
                    upload,
                    deb_head,
                )
                .await;
                result.packages_registered += 1;
                if relocate {
                    result.packages_relocated += 1;
                }
                push_sample(&mut result.registered_paths, &target_path);
            }
        }

        result.dists_removed = self.remove_migration_dists(repo.id, dry_run).await?;
        Ok(result)
    }

    /// Move a misfiled package row to `target_path` (same storage key, same
    /// bytes). `UNIQUE (repository_id, path)` covers trashed rows too, so the
    /// destination is checked under a row lock first: free, the row moves; a
    /// live row with the same checksum keeps the package and the misfiled row
    /// is retired; anything else is refused with a reason for the report.
    async fn relocate(
        &self,
        repo_id: Uuid,
        row: &Candidate,
        target_path: &str,
    ) -> std::result::Result<Relocated, String> {
        let db_err = |e: sqlx::Error| format!("could not move to {target_path}: {e}");
        let mut tx = self.db.begin().await.map_err(db_err)?;
        let existing: Option<(Uuid, bool, String)> = sqlx::query_as(
            "SELECT id, is_deleted, checksum_sha256 FROM artifacts \
             WHERE repository_id = $1 AND path = $2 FOR UPDATE",
        )
        .bind(repo_id)
        .bind(target_path)
        .fetch_optional(&mut *tx)
        .await
        .map_err(db_err)?;

        let existing = existing
            .as_ref()
            .map(|(id, deleted, checksum)| (*id, *deleted, checksum.as_str()));
        let outcome = match destination_verdict(existing, &row.checksum_sha256, target_path)? {
            None => {
                let moved = sqlx::query(
                    "UPDATE artifacts SET path = $3, updated_at = NOW() \
                     WHERE id = $1 AND repository_id = $2 AND is_deleted = false",
                )
                .bind(row.id)
                .bind(repo_id)
                .bind(target_path)
                .execute(&mut *tx)
                .await
                .map_err(db_err)?
                .rows_affected();
                if moved == 0 {
                    return Err("the row was deleted while the backfill ran".into());
                }
                Relocated::Moved
            }
            Some(id) => {
                sqlx::query(
                    "UPDATE artifacts SET is_deleted = true, updated_at = NOW() \
                     WHERE id = $1 AND repository_id = $2",
                )
                .bind(row.id)
                .bind(repo_id)
                .execute(&mut *tx)
                .await
                .map_err(db_err)?;
                Relocated::MergedInto(id)
            }
        };
        tx.commit().await.map_err(db_err)?;
        Ok(outcome)
    }

    /// The dry-run counterpart of [`Self::relocate`]: read the destination
    /// (no lock, no write) and apply the same verdict. `planned` holds the
    /// destinations earlier candidates of this dry run would have moved into,
    /// with their checksums, so two misfiled rows aimed at one destination are
    /// judged as the real run would judge them.
    async fn dry_run_destination(
        &self,
        repo_id: Uuid,
        row: &Candidate,
        target_path: &str,
        planned: &mut HashMap<String, String>,
    ) -> std::result::Result<(), String> {
        let verdict = if let Some(checksum) = planned.get(target_path) {
            destination_verdict(
                Some((row.id, false, checksum.as_str())),
                &row.checksum_sha256,
                target_path,
            )?
        } else {
            let existing: Option<(Uuid, bool, String)> = sqlx::query_as(
                "SELECT id, is_deleted, checksum_sha256 FROM artifacts \
                 WHERE repository_id = $1 AND path = $2",
            )
            .bind(repo_id)
            .bind(target_path)
            .fetch_optional(&self.db)
            .await
            .map_err(|e| format!("could not check {target_path}: {e}"))?;
            destination_verdict(
                existing
                    .as_ref()
                    .map(|(id, deleted, checksum)| (*id, *deleted, checksum.as_str())),
                &row.checksum_sha256,
                target_path,
            )?
        };
        if verdict.is_none() {
            planned.insert(target_path.to_string(), row.checksum_sha256.clone());
        }
        Ok(())
    }

    /// Drop the source's `dists/` copies from the artifact list. On a hosted
    /// Debian repository those are the source's signed indices, not content:
    /// AK generates and signs its own from the `pool/` rows. Only rows the
    /// migration stamped `origin->>'kind' = 'migration'` are removed; a
    /// native/generic upload under `dists/` is left for its owner to decide.
    async fn remove_migration_dists(&self, repo_id: Uuid, dry_run: bool) -> Result<u64> {
        if dry_run {
            let count: i64 = sqlx::query_scalar(
                "SELECT COUNT(*) FROM artifacts \
                 WHERE repository_id = $1 AND is_deleted = false AND path LIKE 'dists/%' \
                   AND origin->>'kind' = 'migration'",
            )
            .bind(repo_id)
            .fetch_one(&self.db)
            .await
            .map_err(|e| AppError::Database(e.to_string()))?;
            return Ok(count.max(0) as u64);
        }

        let removed = sqlx::query(
            "UPDATE artifacts SET is_deleted = true, updated_at = NOW() \
             WHERE repository_id = $1 AND is_deleted = false AND path LIKE 'dists/%' \
               AND origin->>'kind' = 'migration'",
        )
        .bind(repo_id)
        .execute(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?
        .rows_affected();
        Ok(removed)
    }
}

/// What moving a package with `checksum` to `target_path` does, given the
/// row (id, is_deleted, checksum) that holds the destination now: `None`, the
/// destination is free and the row moves; `Some(id)`, a live row with the same
/// bytes keeps the package; `Err`, the move is refused with the reason.
fn destination_verdict(
    existing: Option<(Uuid, bool, &str)>,
    checksum: &str,
    target_path: &str,
) -> std::result::Result<Option<Uuid>, String> {
    match existing {
        None => Ok(None),
        Some((id, false, theirs)) if theirs.trim() == checksum.trim() => Ok(Some(id)),
        Some((_, false, _)) => Err(format!(
            "belongs under {target_path}, which holds a different package"
        )),
        Some((_, true, _)) => Err(format!(
            "belongs under {target_path}, which holds a deleted row; \
             purge it from the trash and run the backfill again"
        )),
    }
}

fn push_sample(sample: &mut Vec<String>, value: &str) {
    if sample.len() < SAMPLE_CAP {
        sample.push(value.to_string());
    }
}

#[cfg(ak_test_shard = "services-1")]
#[cfg(test)]
mod tests {
    use bytes::Bytes;

    use super::*;
    use crate::api::handlers::debian::{minimal_deb, render_packages_index};
    use crate::api::handlers::test_db_helpers as tdh;
    use crate::services::artifact_origin::ArtifactOrigin;
    use crate::services::repository_service::RepositoryService;

    async fn fixture_repository(f: &tdh::Fixture) -> Repository {
        RepositoryService::new(f.pool.clone())
            .get_by_key(&f.repo_key)
            .await
            .expect("load fixture repository")
    }

    async fn seed_package(
        f: &tdh::Fixture,
        path: &str,
        package: &str,
        version: &str,
        bytes: Vec<u8>,
    ) -> Uuid {
        let storage_key = format!("debian-backfill-{}", Uuid::new_v4());
        tdh::seed_artifact(
            &f.state,
            &f.pool,
            &f.repo_info("local", None),
            &storage_key,
            path,
            package,
            version,
            "application/vnd.debian.binary-package",
            Bytes::from(bytes),
            f.user_id,
        )
        .await
    }

    async fn seed_dists_row(f: &tdh::Fixture, path: &str, origin: serde_json::Value) -> Uuid {
        sqlx::query_scalar(
            "INSERT INTO artifacts (repository_id, path, name, size_bytes, checksum_sha256, \
             content_type, storage_key, origin) \
             VALUES ($1, $2, 'dists-index', 1, repeat('0', 64), 'text/plain', $3, $4) \
             RETURNING id",
        )
        .bind(f.repo_id)
        .bind(path)
        .bind(format!("dists-backfill-{}", Uuid::new_v4()))
        .bind(origin)
        .fetch_one(&f.pool)
        .await
        .expect("seed dists row")
    }

    async fn artifact_path(pool: &PgPool, artifact_id: Uuid) -> String {
        sqlx::query_scalar("SELECT path FROM artifacts WHERE id = $1")
            .bind(artifact_id)
            .fetch_one(pool)
            .await
            .expect("load artifact path")
    }

    async fn is_deleted(pool: &PgPool, artifact_id: Uuid) -> bool {
        sqlx::query_scalar("SELECT is_deleted FROM artifacts WHERE id = $1")
            .bind(artifact_id)
            .fetch_one(pool)
            .await
            .expect("load is_deleted")
    }

    async fn metadata_count(pool: &PgPool, artifact_id: Uuid) -> i64 {
        sqlx::query_scalar(
            "SELECT COUNT(*) FROM artifact_metadata \
             WHERE artifact_id = $1 AND format = 'debian'",
        )
        .bind(artifact_id)
        .fetch_one(pool)
        .await
        .expect("count control documents")
    }

    /// A repository migrated before #4657 has pool rows but no control
    /// documents. The backfill must record the same metadata, catalog row and
    /// `Packages` entry a native upload does, remove the source's `dists/`
    /// copies, and be idempotent.
    #[tokio::test]
    async fn backfill_registers_packages_and_removes_dists() {
        let Some(f) = tdh::Fixture::setup("local", "debian").await else {
            return;
        };
        let repo = fixture_repository(&f).await;
        let path = "pool/main/h/hello/hello_1.0-1_amd64.deb";
        let artifact_id = seed_package(
            &f,
            path,
            "hello",
            "1.0-1",
            minimal_deb("hello", "1.0-1", "amd64", "backfill"),
        )
        .await;
        let imported_dists = seed_dists_row(
            &f,
            "dists/bookworm/Release",
            ArtifactOrigin::migration(&f.repo_key, None).to_json(),
        )
        .await;
        let hosted_dists = seed_dists_row(
            &f,
            "dists/bookworm/main/binary-amd64/Packages",
            ArtifactOrigin::hosted(&f.repo_key).to_json(),
        )
        .await;

        let service = DebianBackfillService::new(f.pool.clone(), f.state.storage_registry.clone());
        let result = service
            .backfill(&repo, false, 100, None)
            .await
            .expect("backfill succeeds");
        assert!(!result.dry_run);
        assert_eq!(result.artifacts_scanned, 1);
        assert_eq!(result.packages_registered, 1);
        assert_eq!(result.artifacts_skipped, 0);
        assert_eq!(result.artifacts_failed, 0);
        assert_eq!(result.dists_removed, 1);
        assert!(!result.truncated);
        assert_eq!(result.registered_paths, vec![path.to_string()]);

        assert_eq!(metadata_count(&f.pool, artifact_id).await, 1);
        let metadata: serde_json::Value =
            sqlx::query_scalar("SELECT metadata FROM artifact_metadata WHERE artifact_id = $1")
                .bind(artifact_id)
                .fetch_one(&f.pool)
                .await
                .expect("control document");
        assert_eq!(metadata["format"], "debian");
        assert_eq!(metadata["component"], "main");
        assert_eq!(metadata["control"]["package"], "hello");
        assert_eq!(metadata["control"]["version"], "1.0-1");

        let catalog: (String, String) = sqlx::query_as(
            "SELECT p.name, pv.version FROM packages p \
             JOIN package_versions pv ON pv.package_id = p.id \
             WHERE p.repository_id = $1",
        )
        .bind(f.repo_id)
        .fetch_one(&f.pool)
        .await
        .expect("catalog row");
        assert_eq!(catalog, ("hello".to_string(), "1.0-1".to_string()));

        let index = render_packages_index(&f.pool, f.repo_id, "main", "amd64")
            .await
            .expect("render Packages");
        assert!(index.contains("Package: hello\n"), "{index}");
        assert!(index.contains(&format!("Filename: {path}\n")), "{index}");

        let dists_live: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM artifacts \
             WHERE repository_id = $1 AND is_deleted = false AND path LIKE 'dists/%'",
        )
        .bind(f.repo_id)
        .fetch_one(&f.pool)
        .await
        .expect("count live dists");
        assert_eq!(dists_live, 1, "only the migration copy leaves the list");
        let imported_deleted: bool =
            sqlx::query_scalar("SELECT is_deleted FROM artifacts WHERE id = $1")
                .bind(imported_dists)
                .fetch_one(&f.pool)
                .await
                .expect("load imported dists row");
        assert!(
            imported_deleted,
            "the source dists copy leaves the artifact list"
        );
        let hosted_deleted: bool =
            sqlx::query_scalar("SELECT is_deleted FROM artifacts WHERE id = $1")
                .bind(hosted_dists)
                .fetch_one(&f.pool)
                .await
                .expect("load hosted dists row");
        assert!(
            !hosted_deleted,
            "a hosted upload under dists is not touched"
        );

        let again = service
            .backfill(&repo, false, 100, None)
            .await
            .expect("second backfill succeeds");
        assert_eq!(again.artifacts_scanned, 0);
        assert_eq!(again.packages_registered, 0);
        assert_eq!(again.dists_removed, 0);

        f.teardown().await;
    }

    /// A dry run must report what would change and write nothing.
    #[tokio::test]
    async fn dry_run_reports_without_writing() {
        let Some(f) = tdh::Fixture::setup("local", "debian").await else {
            return;
        };
        let repo = fixture_repository(&f).await;
        let path = "pool/main/h/hello/hello_2.0_amd64.deb";
        let artifact_id = seed_package(
            &f,
            path,
            "hello",
            "2.0",
            minimal_deb("hello", "2.0", "amd64", "dry run"),
        )
        .await;
        seed_dists_row(
            &f,
            "dists/bookworm/Release",
            ArtifactOrigin::migration(&f.repo_key, None).to_json(),
        )
        .await;

        let service = DebianBackfillService::new(f.pool.clone(), f.state.storage_registry.clone());
        let result = service
            .backfill(&repo, true, 100, None)
            .await
            .expect("dry run succeeds");
        assert!(result.dry_run);
        assert_eq!(result.artifacts_scanned, 1);
        assert_eq!(result.packages_registered, 1);
        assert_eq!(result.dists_removed, 1);
        assert_eq!(metadata_count(&f.pool, artifact_id).await, 0);
        let packages: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM packages WHERE repository_id = $1")
                .bind(f.repo_id)
                .fetch_one(&f.pool)
                .await
                .expect("count packages");
        assert_eq!(packages, 0);
        let dists_live: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM artifacts \
             WHERE repository_id = $1 AND is_deleted = false AND path LIKE 'dists/%'",
        )
        .bind(f.repo_id)
        .fetch_one(&f.pool)
        .await
        .expect("count live dists");
        assert_eq!(dists_live, 1);

        f.teardown().await;
    }

    /// One bad package is reported, and the rest of the repository is still
    /// repaired. A flat `pool/<file>.deb` row is filed under `pool/main/`.
    #[tokio::test]
    async fn failed_package_does_not_abort_the_run() {
        let Some(f) = tdh::Fixture::setup("local", "debian").await else {
            return;
        };
        let repo = fixture_repository(&f).await;
        let good_path = "pool/main/h/hello/hello_3.0_amd64.deb";
        let good_id = seed_package(
            &f,
            good_path,
            "hello",
            "3.0",
            minimal_deb("hello", "3.0", "amd64", "good"),
        )
        .await;
        let bad_path = "pool/main/b/broken/broken_1.0_amd64.deb";
        let bad_id = seed_package(&f, bad_path, "broken", "1.0", b"not a deb".to_vec()).await;
        let flat_path = "pool/flat_1.0_all.deb";
        let flat_id = seed_package(
            &f,
            flat_path,
            "flat",
            "1.0",
            minimal_deb("flat", "1.0", "all", "flat"),
        )
        .await;

        let service = DebianBackfillService::new(f.pool.clone(), f.state.storage_registry.clone());
        let result = service
            .backfill(&repo, false, 100, None)
            .await
            .expect("backfill succeeds");
        assert_eq!(result.artifacts_scanned, 3);
        assert_eq!(result.packages_registered, 2);
        assert_eq!(result.packages_relocated, 1);
        assert_eq!(result.artifacts_skipped, 0);
        assert_eq!(result.artifacts_failed, 1);
        assert_eq!(result.errors.len(), 1);
        assert!(result.errors[0].contains(bad_path), "{:?}", result.errors);
        assert_eq!(metadata_count(&f.pool, good_id).await, 1);
        assert_eq!(metadata_count(&f.pool, bad_id).await, 0);
        assert_eq!(metadata_count(&f.pool, flat_id).await, 1);
        assert_eq!(
            artifact_path(&f.pool, flat_id).await,
            "pool/main/flat_1.0_all.deb"
        );

        f.teardown().await;
    }

    /// `limit` bounds one call and `truncated` says another is needed.
    #[tokio::test]
    async fn limit_stops_and_reports_truncation() {
        let Some(f) = tdh::Fixture::setup("local", "debian").await else {
            return;
        };
        let repo = fixture_repository(&f).await;
        for (package, version) in [("one", "1.0"), ("two", "2.0")] {
            let path = format!(
                "pool/main/{}/{package}/{package}_{version}_amd64.deb",
                &package[..1]
            );
            seed_package(
                &f,
                &path,
                package,
                version,
                minimal_deb(package, version, "amd64", package),
            )
            .await;
        }

        let service = DebianBackfillService::new(f.pool.clone(), f.state.storage_registry.clone());
        let first = service
            .backfill(&repo, false, 1, None)
            .await
            .expect("first backfill succeeds");
        assert_eq!(first.artifacts_scanned, 1);
        assert_eq!(first.packages_registered, 1);
        assert!(first.truncated);

        let second = service
            .backfill(&repo, false, 10, None)
            .await
            .expect("second backfill succeeds");
        assert_eq!(second.artifacts_scanned, 1);
        assert_eq!(second.packages_registered, 1);
        assert!(!second.truncated);

        f.teardown().await;
    }

    /// #4740: a pre-#4657 import of a Nexus apt repository or an Ubuntu pool
    /// mirror kept the `pool/<letter>/<name>/` layout, which has no component
    /// segment. The backfill must file it under `main`, the component the
    /// migration importer now picks without `deb.component`, not under the
    /// letter, or the package stays missing from `dists/<dist>/main/`.
    #[tokio::test]
    async fn letter_layout_package_is_filed_under_main() {
        let Some(f) = tdh::Fixture::setup("local", "debian").await else {
            return;
        };
        let repo = fixture_repository(&f).await;
        let source_path = "pool/h/hello/hello_4.0_amd64.deb";
        let filed_path = "pool/main/h/hello/hello_4.0_amd64.deb";
        let artifact_id = seed_package(
            &f,
            source_path,
            "hello",
            "4.0",
            minimal_deb("hello", "4.0", "amd64", "letter layout"),
        )
        .await;

        let service = DebianBackfillService::new(f.pool.clone(), f.state.storage_registry.clone());
        let dry = service
            .backfill(&repo, true, 100, None)
            .await
            .expect("dry run succeeds");
        assert_eq!(dry.packages_registered, 1);
        assert_eq!(dry.packages_relocated, 1);
        assert_eq!(dry.registered_paths, vec![filed_path.to_string()]);
        assert_eq!(artifact_path(&f.pool, artifact_id).await, source_path);

        let result = service
            .backfill(&repo, false, 100, None)
            .await
            .expect("backfill succeeds");
        assert_eq!(result.packages_registered, 1);
        assert_eq!(result.packages_relocated, 1);
        assert_eq!(result.artifacts_failed, 0, "{:?}", result.errors);
        assert_eq!(result.registered_paths, vec![filed_path.to_string()]);
        assert_eq!(artifact_path(&f.pool, artifact_id).await, filed_path);

        let metadata: serde_json::Value =
            sqlx::query_scalar("SELECT metadata FROM artifact_metadata WHERE artifact_id = $1")
                .bind(artifact_id)
                .fetch_one(&f.pool)
                .await
                .expect("control document");
        assert_eq!(metadata["component"], "main");

        let main = render_packages_index(&f.pool, f.repo_id, "main", "amd64")
            .await
            .expect("render main Packages");
        assert!(main.contains("Package: hello\n"), "{main}");
        assert!(
            main.contains(&format!("Filename: {filed_path}\n")),
            "{main}"
        );
        let letter = render_packages_index(&f.pool, f.repo_id, "h", "amd64")
            .await
            .expect("render h Packages");
        assert!(!letter.contains("Package: hello"), "{letter}");

        f.teardown().await;
    }

    /// A misfiled row whose bytes are already live at the destination is
    /// retired; a different package or a trashed row at the destination is
    /// reported and nothing is moved.
    #[tokio::test]
    async fn relocation_merges_duplicates_and_refuses_conflicts() {
        let Some(f) = tdh::Fixture::setup("local", "debian").await else {
            return;
        };
        let repo = fixture_repository(&f).await;
        let seed = |path: &'static str, name: &'static str, checksum: &'static str| {
            let f = &f;
            async move {
                tdh::seed_artifact_with_checksum(
                    &f.state,
                    &f.pool,
                    &f.repo_info("local", None),
                    &format!("debian-backfill-{}", Uuid::new_v4()),
                    path,
                    name,
                    "1.0",
                    "application/vnd.debian.binary-package",
                    Bytes::from(minimal_deb(name, "1.0", "amd64", name)),
                    f.user_id,
                    checksum,
                )
                .await
            }
        };
        // Same bytes already filed under main: the misfiled copy is retired.
        let kept = seed("pool/main/d/dup/dup_1.0_amd64.deb", "dup", "same").await;
        let dup = seed("pool/d/dup/dup_1.0_amd64.deb", "dup", "same").await;
        // A different package already at the destination.
        seed("pool/main/c/clash/clash_1.0_amd64.deb", "clash", "theirs").await;
        let clash = seed("pool/c/clash/clash_1.0_amd64.deb", "clash", "ours").await;
        // A trashed row at the destination.
        let trashed = seed("pool/main/t/trash/trash_1.0_amd64.deb", "trash", "x").await;
        sqlx::query("UPDATE artifacts SET is_deleted = true WHERE id = $1")
            .bind(trashed)
            .execute(&f.pool)
            .await
            .expect("trash row");
        let behind_trash = seed("pool/t/trash/trash_1.0_amd64.deb", "trash", "x").await;

        // A second misfiled copy aimed at the same free destination as a
        // first one, with different bytes: the first moves, the second is
        // refused (the dry run must judge it against the planned move).
        seed("pool/p/pair/pair_1.0_amd64.deb", "pair", "first").await;
        seed("p/pair/pair_1.0_amd64.deb", "pair", "second").await;
        assert_eq!(
            crate::services::migration_worker::debian_destination_path(
                "pool/p/pair/pair_1.0_amd64.deb",
                None
            ),
            crate::services::migration_worker::debian_destination_path(
                "p/pair/pair_1.0_amd64.deb",
                None
            ),
            "both copies are aimed at one destination"
        );

        let service = DebianBackfillService::new(f.pool.clone(), f.state.storage_registry.clone());
        // The dry run checks each move's destination, so it reports the same
        // counts and refusals as the real run below and writes nothing.
        let dry = service
            .backfill(&repo, true, 100, None)
            .await
            .expect("dry run succeeds");
        let expected_failed = 3;
        assert_eq!(dry.artifacts_failed, expected_failed, "{:?}", dry.errors);
        assert!(
            dry.errors
                .iter()
                .any(|e| e.contains("clash_1.0_amd64.deb") && e.contains("different package")),
            "{:?}",
            dry.errors
        );
        assert!(
            dry.errors
                .iter()
                .any(|e| e.contains("trash_1.0_amd64.deb") && e.contains("deleted row")),
            "{:?}",
            dry.errors
        );
        assert_eq!(
            artifact_path(&f.pool, clash).await,
            "pool/c/clash/clash_1.0_amd64.deb"
        );
        assert!(!is_deleted(&f.pool, dup).await, "a dry run retires nothing");

        let result = service
            .backfill(&repo, false, 100, None)
            .await
            .expect("backfill succeeds");
        assert_eq!(
            result.artifacts_failed, expected_failed,
            "{:?}",
            result.errors
        );
        assert_eq!(dry.packages_registered, result.packages_registered);
        assert_eq!(dry.packages_relocated, result.packages_relocated);
        assert_eq!(dry.errors, result.errors);
        assert!(
            result
                .errors
                .iter()
                .any(|e| e.contains("clash_1.0_amd64.deb") && e.contains("different package")),
            "{:?}",
            result.errors
        );
        assert!(
            result
                .errors
                .iter()
                .any(|e| e.contains("trash_1.0_amd64.deb") && e.contains("deleted row")),
            "{:?}",
            result.errors
        );

        assert!(
            is_deleted(&f.pool, dup).await,
            "the misfiled copy is retired"
        );
        assert!(!is_deleted(&f.pool, kept).await);
        assert_eq!(metadata_count(&f.pool, kept).await, 1);
        assert_eq!(
            artifact_path(&f.pool, clash).await,
            "pool/c/clash/clash_1.0_amd64.deb"
        );
        assert!(!is_deleted(&f.pool, clash).await);
        assert_eq!(metadata_count(&f.pool, clash).await, 0);
        assert_eq!(
            artifact_path(&f.pool, behind_trash).await,
            "pool/t/trash/trash_1.0_amd64.deb"
        );
        assert_eq!(metadata_count(&f.pool, behind_trash).await, 0);

        f.teardown().await;
    }

    /// A package that keeps failing must not hold back the rest: a truncated
    /// call returns `next_after`, and passing it as `after` continues past
    /// whatever the previous call examined, whichever id order the rows got.
    #[tokio::test]
    async fn after_cursor_walks_past_failing_packages() {
        let Some(f) = tdh::Fixture::setup("local", "debian").await else {
            return;
        };
        let repo = fixture_repository(&f).await;
        let good_id = seed_package(
            &f,
            "pool/main/g/good/good_1.0_amd64.deb",
            "good",
            "1.0",
            minimal_deb("good", "1.0", "amd64", "good"),
        )
        .await;
        let bad_id = seed_package(
            &f,
            "pool/main/b/bad/bad_1.0_amd64.deb",
            "bad",
            "1.0",
            b"not a deb".to_vec(),
        )
        .await;

        let service = DebianBackfillService::new(f.pool.clone(), f.state.storage_registry.clone());
        let first = service
            .backfill(&repo, false, 1, None)
            .await
            .expect("first call succeeds");
        assert_eq!(first.artifacts_scanned, 1);
        assert!(first.truncated);
        let after = first.next_after.expect("a truncated call returns a cursor");
        assert_eq!(after, good_id.min(bad_id));

        let second = service
            .backfill(&repo, false, 1, Some(after))
            .await
            .expect("second call succeeds");
        assert_eq!(second.artifacts_scanned, 1);
        assert!(!second.truncated);
        assert_eq!(second.next_after, None);
        assert_eq!(
            first.packages_registered + second.packages_registered,
            1,
            "the good package is registered whichever call reaches it"
        );
        assert_eq!(first.artifacts_failed + second.artifacts_failed, 1);
        assert_eq!(metadata_count(&f.pool, good_id).await, 1);

        f.teardown().await;
    }

    /// Only hosted Debian repositories are migration targets.
    #[tokio::test]
    async fn rejects_other_formats_and_repository_types() {
        let Some(generic) = tdh::Fixture::setup("local", "generic").await else {
            return;
        };
        let repo = fixture_repository(&generic).await;
        let err = DebianBackfillService::new(
            generic.pool.clone(),
            generic.state.storage_registry.clone(),
        )
        .backfill(&repo, true, 10, None)
        .await
        .expect_err("a generic repository is not a Debian migration target");
        assert!(matches!(err, AppError::UnprocessableEntity(_)));
        generic.teardown().await;

        let Some(remote) = tdh::Fixture::setup("remote", "debian").await else {
            return;
        };
        let repo = fixture_repository(&remote).await;
        let err =
            DebianBackfillService::new(remote.pool.clone(), remote.state.storage_registry.clone())
                .backfill(&repo, true, 10, None)
                .await
                .expect_err("a remote repository is not a migration target");
        assert!(matches!(err, AppError::UnprocessableEntity(_)));
        remote.teardown().await;
    }
}
