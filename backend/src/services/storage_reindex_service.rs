//! Reconcile a repository's stored objects with its artifact rows (#1570).
//!
//! "Ghost artifacts" are objects that exist in storage (and may still be
//! reachable through derived reads) but have no `artifacts` row, left behind
//! when a delete or an upload failed between the object write and the DB
//! write. The reindex walks the repository's OWN key namespace, registers a
//! row for every artifact object that has none, and reports rows whose object
//! is gone.
//!
//! Scope and safety:
//! - Only the Maven family (Maven/Gradle) is supported: their object keys are
//!   path-addressed (`maven/{path}` under a filesystem repository root, or
//!   `maven/{repository_id}/{path}` on shared cloud namespaces, #2624), so the
//!   artifact path is recoverable from the key. Legacy flat cloud keys
//!   (`maven/{path}` shared by every repository) cannot be attributed to one
//!   repository and are never scanned.
//! - Row-less objects (checksum sidecars, `maven-metadata.xml`) and paths that
//!   are not Maven coordinates are skipped.
//! - A path with ANY row, live or soft-deleted, is left alone: a soft-deleted
//!   row's object belongs to storage GC and must not be resurrected.
//! - Idempotent: the insert is `ON CONFLICT DO NOTHING`, so a re-run, or a
//!   concurrent upload that registers the same path first, never duplicates
//!   or overwrites a row.
//! - The object is hashed while streaming (one chunk in memory) so the row
//!   records the real SHA-256 and size of the bytes it points at.
//! - In-flight uploads: an object modified less than [`RECENT_OBJECT_GUARD_MINUTES`]
//!   ago may belong to an upload that has written its bytes but not yet its
//!   row, so it is skipped (`skipped_recent`) rather than registered ahead of
//!   the uploader. An object whose listing reports no (parsable) modification
//!   time cannot be proven settled either, so it is skipped too
//!   (`skipped_unknown_age`); the S3 #3593 REST fallback parses
//!   `<LastModified>` so this is the exception, not the OSS norm.
//! - Bounded: at most `limit` objects are registered per call; the result
//!   says when more remain.
//! - One reindex per repository at a time (advisory lock).

use std::collections::HashSet;
use std::sync::Arc;

use chrono::{DateTime, Utc};
use serde::Serialize;
use sqlx::PgPool;
use utoipa::ToSchema;
use uuid::Uuid;

use crate::error::{AppError, Result};
use crate::formats::maven::MavenHandler;
use crate::models::repository::{Repository, RepositoryFormat};
use crate::services::cluster_lock::{lease_object_id, ClusterLock, PgAdvisoryLock};
use crate::storage::{ListedKey, StorageBackend, StorageKeyScheme, StorageRegistry};

/// Advisory-lock class for the per-repository reindex.
pub const STORAGE_REINDEX_LOCK_CLASS: i32 = 0x1570;

const SAMPLE_CAP: usize = 100;

/// Objects modified more recently than this (minutes) are left for their
/// uploader.
pub const RECENT_OBJECT_GUARD_MINUTES: i64 = 5;

/// How old a listed object is, relative to the in-flight-upload guard.
#[derive(Debug, PartialEq, Eq)]
enum ObjectAge {
    /// Older than the guard: a settled ghost candidate.
    Settled,
    /// Modified within the guard: its upload may still be committing.
    Recent,
    /// The listing reported no modification time: cannot be proven settled.
    Unknown,
}

fn object_age(last_modified: Option<DateTime<Utc>>, now: DateTime<Utc>) -> ObjectAge {
    match last_modified {
        None => ObjectAge::Unknown,
        Some(m) if now - m >= chrono::Duration::minutes(RECENT_OBJECT_GUARD_MINUTES) => {
            ObjectAge::Settled
        }
        Some(_) => ObjectAge::Recent,
    }
}

/// Result of one reindex call.
#[derive(Debug, Default, Clone, Serialize, ToSchema)]
pub struct StorageReindexResult {
    pub dry_run: bool,
    /// Objects listed in the repository's key namespace.
    pub scanned: u64,
    /// Rows created (or, on a dry run, that would be created).
    pub registered: u64,
    /// Objects left alone: already registered, row-less sidecar/metadata,
    /// not a Maven coordinate, or owned by a soft-deleted row.
    pub skipped: u64,
    /// Live rows in the scanned namespace whose object is missing.
    pub missing_objects: u64,
    /// Unregistered objects modified within the last 5 minutes, left alone
    /// because their upload may still be committing its row.
    pub skipped_recent: u64,
    /// Unregistered objects whose listing reported no modification time, left
    /// alone because they cannot be proven settled.
    pub skipped_unknown_age: u64,
    /// True when `limit` stopped registration before every ghost was handled.
    pub truncated: bool,
    /// Sample of registered paths.
    pub registered_paths: Vec<String>,
    /// Sample of paths whose row has no object.
    pub missing_object_paths: Vec<String>,
    pub errors: Vec<String>,
}

/// The key prefix a repository's Maven objects live under, and the backend
/// shape that decides it.
pub fn maven_namespace_prefix(
    scheme: StorageKeyScheme,
    storage_backend: &str,
    repo_id: Uuid,
) -> Option<String> {
    // `write_key` of a probe path gives exactly the prefix new writes use.
    let probe = scheme.write_key(storage_backend, "maven", repo_id, "x");
    let prefix = probe.strip_suffix('x')?.to_string();
    // A flat cloud key is shared by every repository: not attributable.
    if prefix == "maven/" && !crate::storage::backend_is_repo_isolated(storage_backend) {
        return None;
    }
    Some(prefix)
}

pub struct StorageReindexService {
    db: PgPool,
    storage_registry: Arc<StorageRegistry>,
}

enum Candidate {
    Register { key: String, path: String },
    Skip,
}

fn classify_key(key: &str, prefix: &str) -> Candidate {
    let Some(path) = key.strip_prefix(prefix) else {
        return Candidate::Skip;
    };
    if path.is_empty()
        || crate::api::handlers::maven::is_rowless_maven_path(path)
        || MavenHandler::parse_coordinates(path).is_err()
    {
        return Candidate::Skip;
    }
    Candidate::Register {
        key: key.to_string(),
        path: path.to_string(),
    }
}

impl StorageReindexService {
    pub fn new(db: PgPool, storage_registry: Arc<StorageRegistry>) -> Self {
        Self {
            db,
            storage_registry,
        }
    }

    pub async fn reindex(
        &self,
        repo: &Repository,
        dry_run: bool,
        limit: u64,
        actor: Option<Uuid>,
    ) -> Result<StorageReindexResult> {
        self.reindex_at(repo, dry_run, limit, actor, Utc::now())
            .await
    }

    /// [`Self::reindex`] with an explicit clock for the recent-object guard.
    pub(crate) async fn reindex_at(
        &self,
        repo: &Repository,
        dry_run: bool,
        limit: u64,
        actor: Option<Uuid>,
        now: DateTime<Utc>,
    ) -> Result<StorageReindexResult> {
        if !matches!(
            repo.format,
            RepositoryFormat::Maven | RepositoryFormat::Gradle
        ) {
            return Err(AppError::UnprocessableEntity(format!(
                "storage reindex supports Maven and Gradle repositories; '{}' is {:?}",
                repo.key, repo.format
            )));
        }
        let prefix =
            maven_namespace_prefix(StorageKeyScheme::from_env(), &repo.storage_backend, repo.id)
                .ok_or_else(|| {
                    AppError::UnprocessableEntity(
                        "this repository writes legacy flat keys shared by every repository \
                     (STORAGE_KEY_SCHEME=flat on a cloud backend); they cannot be attributed \
                     to one repository"
                            .into(),
                    )
                })?;
        let storage = self
            .storage_registry
            .backend_for(&repo.storage_location())?;
        let keys = storage.list_keys(&prefix).await?.ok_or_else(|| {
            AppError::UnprocessableEntity(format!(
                "storage backend '{}' cannot enumerate objects",
                repo.storage_backend
            ))
        })?;

        let lease = PgAdvisoryLock::new(self.db.clone())
            .try_acquire(
                STORAGE_REINDEX_LOCK_CLASS,
                lease_object_id(&repo.id.to_string()),
            )
            .await?
            .ok_or_else(|| {
                AppError::Conflict("A storage reindex of this repository is already running".into())
            })?;
        let result = self
            .reindex_keys(
                repo.id,
                storage.as_ref(),
                &prefix,
                keys,
                dry_run,
                limit,
                actor,
                now,
            )
            .await;
        lease.release().await;
        result
    }

    #[allow(clippy::too_many_arguments)]
    async fn reindex_keys(
        &self,
        repo_id: Uuid,
        storage: &dyn StorageBackend,
        prefix: &str,
        keys: Vec<ListedKey>,
        dry_run: bool,
        limit: u64,
        actor: Option<Uuid>,
        now: DateTime<Utc>,
    ) -> Result<StorageReindexResult> {
        let mut result = StorageReindexResult {
            dry_run,
            ..Default::default()
        };

        // Every path with a row (live or soft-deleted), and the live rows'
        // keys inside this namespace for the missing-object report.
        let rows: Vec<(String, String, bool)> = sqlx::query_as(
            "SELECT path, storage_key, is_deleted FROM artifacts WHERE repository_id = $1",
        )
        .bind(repo_id)
        .fetch_all(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;
        let known_paths: HashSet<&str> = rows.iter().map(|(p, _, _)| p.as_str()).collect();
        let listed: HashSet<&str> = keys.iter().map(|l| l.key.as_str()).collect();
        for (path, key, deleted) in &rows {
            if !deleted && key.starts_with(prefix) && !listed.contains(key.as_str()) {
                result.missing_objects += 1;
                if result.missing_object_paths.len() < SAMPLE_CAP {
                    result.missing_object_paths.push(path.clone());
                }
            }
        }

        for listed_key in &keys {
            result.scanned += 1;
            let (key, path) = match classify_key(&listed_key.key, prefix) {
                Candidate::Register { key, path } if !known_paths.contains(path.as_str()) => {
                    (key, path)
                }
                _ => {
                    result.skipped += 1;
                    continue;
                }
            };
            match object_age(listed_key.last_modified, now) {
                ObjectAge::Settled => {}
                ObjectAge::Recent => {
                    result.skipped_recent += 1;
                    continue;
                }
                ObjectAge::Unknown => {
                    result.skipped_unknown_age += 1;
                    continue;
                }
            }
            if result.registered >= limit {
                result.truncated = true;
                continue;
            }
            if dry_run {
                result.registered += 1;
                push_sample(&mut result.registered_paths, &path);
                continue;
            }
            match self.register(repo_id, storage, &key, &path, actor).await {
                Ok(true) => {
                    result.registered += 1;
                    push_sample(&mut result.registered_paths, &path);
                }
                Ok(false) => result.skipped += 1,
                Err(e) => {
                    if result.errors.len() < SAMPLE_CAP {
                        result.errors.push(format!("{path}: {e}"));
                    }
                }
            }
        }
        Ok(result)
    }

    /// Hash the object and insert its row. `Ok(false)` when a row appeared
    /// meanwhile (concurrent upload won) or the object vanished.
    async fn register(
        &self,
        repo_id: Uuid,
        storage: &dyn StorageBackend,
        key: &str,
        path: &str,
        actor: Option<Uuid>,
    ) -> Result<bool> {
        let coords = MavenHandler::parse_coordinates(path)?;
        let stream = match storage.get_stream(key).await {
            Ok(s) => s,
            Err(AppError::NotFound(_)) => return Ok(false),
            Err(e) => return Err(e),
        };
        // All three digests, as the Maven upload path records them.
        let mut hasher = crate::services::artifact_service::MultiHasher::new();
        let mut size = 0u64;
        let mut stream = stream;
        while let Some(chunk) = futures::StreamExt::next(&mut stream).await {
            let chunk = chunk?;
            size += chunk.len() as u64;
            hasher.update(&chunk);
        }
        let digests = hasher.finalize();

        let mut tx = self
            .db
            .begin()
            .await
            .map_err(|e| AppError::Database(e.to_string()))?;
        let id: Option<Uuid> = sqlx::query_scalar(
            "INSERT INTO artifacts (repository_id, path, name, version, size_bytes, \
                 checksum_sha256, checksum_sha1, checksum_md5, content_type, storage_key, \
                 uploaded_by) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11) \
             ON CONFLICT (repository_id, path) DO NOTHING RETURNING id",
        )
        .bind(repo_id)
        .bind(path)
        .bind(&coords.artifact_id)
        .bind(&coords.version)
        .bind(size as i64)
        .bind(&digests.sha256)
        .bind(&digests.sha1)
        .bind(&digests.md5)
        .bind(crate::api::handlers::maven::content_type_for_path(path))
        .bind(key)
        .bind(actor)
        .fetch_optional(&mut *tx)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;
        let Some(id) = id else {
            return Ok(false);
        };
        let mut metadata = serde_json::json!({
            "groupId": coords.group_id,
            "artifactId": coords.artifact_id,
            "version": coords.version,
            "extension": coords.extension,
            "reindexedFromStorage": true,
        });
        if let Some(classifier) = &coords.classifier {
            metadata["classifier"] = serde_json::Value::String(classifier.clone());
        }
        sqlx::query(
            "INSERT INTO artifact_metadata (artifact_id, format, metadata) VALUES ($1, 'maven', $2) \
             ON CONFLICT (artifact_id) DO NOTHING",
        )
        .bind(id)
        .bind(&metadata)
        .execute(&mut *tx)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;
        tx.commit()
            .await
            .map_err(|e| AppError::Database(e.to_string()))?;

        crate::api::handlers::maven::invalidate_maven_metadata_cache(
            repo_id,
            &coords.group_id,
            &coords.artifact_id,
        )
        .await;
        Ok(true)
    }
}

fn push_sample(v: &mut Vec<String>, path: &str) {
    if v.len() < SAMPLE_CAP {
        v.push(path.to_string());
    }
}

#[cfg(ak_test_shard = "services-2")]
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn namespace_prefix_follows_the_write_scheme() {
        let id = Uuid::nil();
        assert_eq!(
            maven_namespace_prefix(StorageKeyScheme::RepoScoped, "filesystem", id).as_deref(),
            Some("maven/")
        );
        assert_eq!(
            maven_namespace_prefix(StorageKeyScheme::RepoScoped, "s3", id),
            Some(format!("maven/{id}/"))
        );
        assert_eq!(
            maven_namespace_prefix(StorageKeyScheme::Flat, "s3", id),
            None
        );
    }

    #[test]
    fn recent_objects_are_not_settled() {
        let now = Utc::now();
        assert_eq!(
            object_age(Some(now - chrono::Duration::minutes(1)), now),
            ObjectAge::Recent
        );
        assert_eq!(
            object_age(Some(now - chrono::Duration::minutes(6)), now),
            ObjectAge::Settled
        );
        // #1570 review: no mtime is NOT settled (previously registered).
        assert_eq!(object_age(None, now), ObjectAge::Unknown);
    }

    #[test]
    fn classify_skips_rowless_and_non_coordinates() {
        let p = "maven/";
        assert!(matches!(
            classify_key("maven/com/ex/lib/1.0/lib-1.0.jar", p),
            Candidate::Register { ref path, .. } if path == "com/ex/lib/1.0/lib-1.0.jar"
        ));
        assert!(matches!(
            classify_key("maven/com/ex/lib/1.0/lib-1.0.jar.sha1", p),
            Candidate::Skip
        ));
        assert!(matches!(
            classify_key("maven/com/ex/lib/maven-metadata.xml", p),
            Candidate::Skip
        ));
        assert!(matches!(classify_key("maven/junk", p), Candidate::Skip));
        assert!(matches!(
            classify_key("other/com/ex/lib/1.0/lib-1.0.jar", p),
            Candidate::Skip
        ));
    }
}

#[cfg(ak_test_shard = "services-2")]
#[cfg(test)]
mod db_tests {
    use super::*;
    use crate::api::handlers::test_db_helpers as tdh;
    use bytes::Bytes;
    use sha2::Digest;

    /// #1570: an object stored under the repository's namespace with no row
    /// (a ghost) is registered with its real checksum; a dry run registers
    /// nothing; a re-run is a no-op; row-less sidecars are skipped; a live
    /// row whose object is gone is reported.
    #[tokio::test]
    async fn reindex_registers_ghosts_idempotently() {
        let Some(fx) = tdh::Fixture::setup("local", "maven").await else {
            return;
        };
        let storage = fx
            .state
            .storage_for_repo(&crate::storage::StorageLocation {
                backend: "filesystem".into(),
                path: fx.storage_dir.to_string_lossy().into_owned(),
            })
            .expect("storage");
        let ghost_path = "com/example/ghost/1.0/ghost-1.0.jar";
        let body = Bytes::from_static(b"ghost-jar-bytes");
        storage
            .put(&format!("maven/{ghost_path}"), body.clone())
            .await
            .expect("put ghost");
        storage
            .put(
                &format!("maven/{ghost_path}.sha1"),
                Bytes::from_static(b"abc"),
            )
            .await
            .expect("put sidecar");
        // A live row whose object never existed.
        sqlx::query(
            "INSERT INTO artifacts (repository_id, path, name, version, size_bytes, \
             checksum_sha256, content_type, storage_key) \
             VALUES ($1, 'com/example/gone/1.0/gone-1.0.jar', 'gone', '1.0', 1, 'x', \
             'application/java-archive', 'maven/com/example/gone/1.0/gone-1.0.jar')",
        )
        .bind(fx.repo_id)
        .execute(&fx.pool)
        .await
        .expect("seed missing row");

        let repo = crate::services::repository_service::RepositoryService::new(fx.pool.clone())
            .get_by_key(&fx.repo_key)
            .await
            .expect("repo");
        let svc = StorageReindexService::new(fx.pool.clone(), fx.state.storage_registry.clone());

        // Just written: inside the in-flight-upload guard, so left alone.
        let fresh = svc
            .reindex(&repo, false, 100, None)
            .await
            .expect("fresh run");
        let later = Utc::now() + chrono::Duration::minutes(10);
        let dry = svc
            .reindex_at(&repo, true, 100, None, later)
            .await
            .expect("dry run");
        let rows_after_dry: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM artifacts WHERE repository_id = $1 AND path = $2",
        )
        .bind(fx.repo_id)
        .bind(ghost_path)
        .fetch_one(&fx.pool)
        .await
        .unwrap();

        let live = svc
            .reindex_at(&repo, false, 100, Some(fx.user_id), later)
            .await
            .expect("live run");
        let row: (String, i64, String, Option<String>) = sqlx::query_as(
            "SELECT checksum_sha256, size_bytes, storage_key, checksum_sha1 FROM artifacts \
             WHERE repository_id = $1 AND path = $2 AND is_deleted = false",
        )
        .bind(fx.repo_id)
        .bind(ghost_path)
        .fetch_one(&fx.pool)
        .await
        .expect("ghost row registered");
        let again = svc
            .reindex_at(&repo, false, 100, None, later)
            .await
            .expect("re-run");
        fx.teardown().await;

        assert_eq!(fresh.registered, 0, "{fresh:?}");
        assert_eq!(fresh.skipped_recent, 1, "{fresh:?}");
        assert_eq!(dry.registered, 1, "{dry:?}");
        assert_eq!(rows_after_dry, 0, "a dry run must not write");
        assert_eq!(live.scanned, 2, "{live:?}");
        assert_eq!(live.registered, 1, "{live:?}");
        assert_eq!(live.skipped, 1, "the .sha1 sidecar is row-less: {live:?}");
        assert_eq!(live.missing_objects, 1, "{live:?}");
        assert_eq!(row.0.trim(), hex::encode(sha2::Sha256::digest(&body)));
        assert_eq!(row.1, body.len() as i64);
        assert_eq!(row.2, format!("maven/{ghost_path}"));
        assert_eq!(
            row.3.as_deref().map(str::trim),
            Some(hex::encode(sha1::Sha1::digest(&body)).as_str()),
            "sha1 recorded like the Maven upload path"
        );
        assert_eq!(again.registered, 0, "re-run must be a no-op: {again:?}");
    }

    /// #1570 review (S-b): an object whose listing carries no modification
    /// time (e.g. an S3 endpoint that omits `<LastModified>`) cannot be
    /// proven settled and must not be registered.
    #[tokio::test]
    async fn reindex_skips_objects_of_unknown_age() {
        let Some(fx) = tdh::Fixture::setup("local", "maven").await else {
            return;
        };
        let storage = fx
            .state
            .storage_for_repo(&crate::storage::StorageLocation {
                backend: "filesystem".into(),
                path: fx.storage_dir.to_string_lossy().into_owned(),
            })
            .expect("storage");
        let path = "com/example/ageless/1.0/ageless-1.0.jar";
        let key = format!("maven/{path}");
        storage
            .put(&key, Bytes::from_static(b"ageless"))
            .await
            .expect("put");
        let svc = StorageReindexService::new(fx.pool.clone(), fx.state.storage_registry.clone());
        let later = Utc::now() + chrono::Duration::minutes(10);
        let res = svc
            .reindex_keys(
                fx.repo_id,
                storage.as_ref(),
                "maven/",
                vec![ListedKey {
                    key: key.clone(),
                    last_modified: None,
                }],
                false,
                100,
                None,
                later,
            )
            .await
            .expect("reindex");
        let rows: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM artifacts WHERE repository_id = $1 AND path = $2",
        )
        .bind(fx.repo_id)
        .bind(path)
        .fetch_one(&fx.pool)
        .await
        .unwrap();
        fx.teardown().await;

        assert_eq!(res.skipped_unknown_age, 1, "{res:?}");
        assert_eq!(res.registered, 0, "{res:?}");
        assert_eq!(rows, 0);
    }

    #[tokio::test]
    async fn reindex_rejects_non_maven_repositories() {
        let Some(fx) = tdh::Fixture::setup("local", "generic").await else {
            return;
        };
        let repo = crate::services::repository_service::RepositoryService::new(fx.pool.clone())
            .get_by_key(&fx.repo_key)
            .await
            .expect("repo");
        let res = StorageReindexService::new(fx.pool.clone(), fx.state.storage_registry.clone())
            .reindex(&repo, true, 10, None)
            .await;
        fx.teardown().await;
        assert!(
            matches!(res, Err(AppError::UnprocessableEntity(_))),
            "{res:?}"
        );
    }
}
