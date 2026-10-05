//! RPM curated-snapshot version retention (#2359, RPM mirror Phase 4).
//!
//! Every [`create_version`](crate::services::rpm_publish_service::create_version)
//! adds a `repository_versions` row, and every publish stores signed repodata
//! under `curation/{repo}/publications/{N}/`, where the `@N` serve path also
//! caches each verified package it hands out. Nothing ever removed either, so a
//! nightly mirror grew one full snapshot per night forever.
//!
//! With `RPM_VERSION_RETENTION_KEEP=N` set (unset or `0` keeps everything, the
//! default), an hourly scheduler pass keeps, per repository, the `N` newest
//! versions plus the active publication, deletes every older
//! `repository_versions` row (its membership rows cascade) and then deletes the
//! objects under each pruned version's storage prefix.
//!
//! Safety properties:
//! - The active publication (`repositories.active_publication_id`) is never
//!   selected, and the delete re-checks it inside the same transaction that
//!   holds the repository row lock, so a concurrent publish either commits
//!   first (its version is then active and kept) or finds its version gone and
//!   cleans up after itself (see `rpm_publish_service::publish`).
//! - The newest version is always kept (`N >= 1`), so `MAX(version_number)`
//!   never moves backwards and a pruned `@N` number is never reissued.
//! - Rows are deleted before objects. Once the row is gone `@N` is
//!   unresolvable, so deleting its objects cannot break a client mid-download
//!   of anything still advertised.
//! - On backends that can list keys (filesystem, S3, GCS) objects are found by
//!   listing `curation/{repo}/publications/` and deleting every key whose
//!   version number has no row (and is not newer than the newest row). Every
//!   repository with a version row is visited on every pass, so objects a
//!   crash or a racing `@N` cache fill leave behind are collected on the next
//!   pass even when nothing new was pruned. On a backend that cannot list
//!   (Azure), the pruned published versions' known keys (repodata plus one
//!   cached package per member) are deleted instead.
//! - One replica runs a pass at a time (scheduler lease, renewed for the whole
//!   pass); a lost lease stops the pass between repositories.

use std::collections::{BTreeMap, BTreeSet};

use sqlx::PgPool;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

use crate::error::AppError;
use crate::services::rpm_publish_service::{
    create_version_lock_key, publication_prefix, publications_root, PUBLICATION_REPODATA_FILES,
};
use crate::storage::{StorageBackend, StorageLocation, StorageRegistry};

/// How many curated versions to keep per repository (besides the active one).
pub const RPM_VERSION_RETENTION_KEEP_ENV: &str = "RPM_VERSION_RETENTION_KEEP";

/// Scheduler lease name for the retention pass.
pub const RETENTION_LEASE_NAME: &str = "rpm_version_retention";

/// Lease TTL; the pass renews it for as long as it runs.
pub const RETENTION_LEASE_TTL_SECS: f64 = 600.0;

/// How often the pass runs.
pub const RETENTION_INTERVAL_SECS: u64 = 3600;

/// Parse the keep count. Unset, empty, `0` or unparsable disables retention:
/// pruning is destructive, so anything but an explicit positive count keeps
/// every version.
pub fn parse_keep(raw: Option<&str>) -> Option<u32> {
    let raw = raw.map(str::trim).filter(|v| !v.is_empty())?;
    match raw.parse::<u32>() {
        Ok(0) => None,
        Ok(n) => Some(n),
        Err(_) => {
            tracing::warn!(
                "{RPM_VERSION_RETENTION_KEEP_ENV}='{raw}' is not a non-negative integer; \
                 RPM version retention stays disabled"
            );
            None
        }
    }
}

/// [`parse_keep`] over the process environment.
pub fn keep_from_env() -> Option<u32> {
    parse_keep(
        std::env::var(RPM_VERSION_RETENTION_KEEP_ENV)
            .ok()
            .as_deref(),
    )
}

/// The versions of one repository to prune: everything outside the `keep`
/// highest version numbers, except the active publication. `keep == 0` prunes
/// nothing (retention disabled), so the newest version always survives.
pub(crate) fn select_prunable(
    versions: &[(Uuid, i64)],
    active: Option<Uuid>,
    keep: u32,
) -> Vec<Uuid> {
    if keep == 0 {
        return Vec::new();
    }
    let mut newest_first: Vec<&(Uuid, i64)> = versions.iter().collect();
    newest_first.sort_unstable_by_key(|a| std::cmp::Reverse(a.1));
    newest_first
        .into_iter()
        .skip(keep as usize)
        .filter(|(id, _)| Some(*id) != active)
        .map(|(id, _)| *id)
        .collect()
}

/// The keys a pruned version is known to own: its repodata plus one cached
/// package per frozen member. This is the whole prefix on a backend that
/// cannot list keys.
pub(crate) fn known_version_keys(prefix: &str, member_filenames: &[String]) -> Vec<String> {
    PUBLICATION_REPODATA_FILES
        .iter()
        .map(|name| format!("{prefix}/{name}"))
        .chain(
            member_filenames
                .iter()
                .map(|f| format!("{prefix}/packages/{f}")),
        )
        .collect()
}

/// The version number a listed key under [`publications_root`] belongs to, or
/// `None` for a key outside that layout.
pub(crate) fn listed_version_number(root: &str, key: &str) -> Option<i64> {
    let rest = key.strip_prefix(root)?;
    let (number, tail) = rest.split_once('/')?;
    if tail.is_empty() || number.is_empty() || !number.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    number.parse().ok()
}

/// Whether a listed key is a stray: it belongs to a version number with no
/// `repository_versions` row that is not newer than the newest surviving one.
/// A number above the newest is left alone, since a create/publish that
/// started after this pass read the rows may be writing it.
pub(crate) fn is_stray_key(
    root: &str,
    key: &str,
    surviving: &BTreeSet<i64>,
    newest: Option<i64>,
) -> bool {
    match (listed_version_number(root, key), newest) {
        (Some(n), Some(max)) => n <= max && !surviving.contains(&n),
        _ => false,
    }
}

/// The version numbers of `versions` whose ids were not deleted.
pub(crate) fn surviving_numbers(
    versions: &[(Uuid, i64)],
    deleted: impl IntoIterator<Item = Uuid>,
) -> BTreeSet<i64> {
    let deleted: BTreeSet<Uuid> = deleted.into_iter().collect();
    versions
        .iter()
        .filter(|(id, _)| !deleted.contains(id))
        .map(|(_, n)| *n)
        .collect()
}

/// What one pass did.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct RetentionReport {
    pub repositories: u64,
    pub versions_pruned: u64,
    pub objects_deleted: u64,
    pub delete_failures: u64,
}

/// A version removed from the database whose objects may still need deleting
/// on a backend that cannot list. `member_filenames` is empty for a version
/// that was never published: `@N` only caches packages for published versions,
/// so only repodata a crashed publish left behind can exist under its prefix.
#[derive(Debug)]
struct PrunedVersion {
    prefix: String,
    member_filenames: Vec<String>,
}

/// What [`prune_rows`] removed and kept.
#[derive(Debug, Default)]
struct PrunedRows {
    /// Number of `repository_versions` rows deleted.
    deleted: u64,
    /// The deleted versions, for the known-key fallback.
    pruned: Vec<PrunedVersion>,
    /// Version numbers still present after the delete, for the stray sweep.
    surviving: BTreeSet<i64>,
}

/// Delete the prunable rows of one repository and return what their objects
/// are, plus the surviving version numbers for the stray sweep.
async fn prune_rows(db: &PgPool, repo_id: Uuid, keep: u32) -> Result<PrunedRows, AppError> {
    let mut tx = db.begin().await?;
    // Pinned like create_version's transaction: every statement after the
    // lock wait must see versions committed while it waited.
    sqlx::query("SET TRANSACTION ISOLATION LEVEL READ COMMITTED")
        .execute(&mut *tx)
        .await?;
    // Serialize with create_version (same key it locks under, #4307) and with
    // publish, which locks the repository row before marking a version.
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
        .bind(create_version_lock_key(repo_id))
        .execute(&mut *tx)
        .await?;
    let active: Option<Option<Uuid>> = sqlx::query_scalar(
        "SELECT active_publication_id FROM repositories WHERE id = $1 FOR NO KEY UPDATE",
    )
    .bind(repo_id)
    .fetch_optional(&mut *tx)
    .await?;
    let Some(active) = active else {
        return Ok(PrunedRows::default());
    };

    let versions: Vec<(Uuid, i64)> = sqlx::query_as(
        "SELECT id, version_number FROM repository_versions WHERE repository_id = $1",
    )
    .bind(repo_id)
    .fetch_all(&mut *tx)
    .await?;
    let prune = select_prunable(&versions, active, keep);
    if prune.is_empty() {
        tx.commit().await?;
        return Ok(PrunedRows {
            surviving: versions.iter().map(|(_, n)| *n).collect(),
            ..Default::default()
        });
    }

    let members: Vec<(Uuid, String)> = sqlx::query_as(
        "SELECT rvp.version_id, rvp.frozen_filename FROM repository_version_packages rvp \
         JOIN repository_versions rv ON rv.id = rvp.version_id \
         WHERE rvp.version_id = ANY($1) AND rv.published_at IS NOT NULL",
    )
    .bind(&prune)
    .fetch_all(&mut *tx)
    .await?;
    let mut by_version: BTreeMap<Uuid, Vec<String>> = BTreeMap::new();
    for (version_id, filename) in members {
        by_version.entry(version_id).or_default().push(filename);
    }

    // The active-publication guard is repeated in SQL: the delete must never
    // remove the version the no-`@N` routes serve, whatever the selection did.
    let deleted: Vec<(Uuid, i64, Option<String>)> = sqlx::query_as(
        "DELETE FROM repository_versions rv \
         WHERE rv.repository_id = $1 AND rv.id = ANY($2) \
           AND NOT EXISTS (SELECT 1 FROM repositories r WHERE r.active_publication_id = rv.id) \
         RETURNING rv.id, rv.version_number, rv.storage_prefix",
    )
    .bind(repo_id)
    .bind(&prune)
    .fetch_all(&mut *tx)
    .await?;
    tx.commit().await?;

    // `surviving` comes from what was actually deleted, not from the
    // selection: a row the SQL guard spared must never look like a stray.
    let surviving = surviving_numbers(&versions, deleted.iter().map(|(id, _, _)| *id));
    let rows = deleted.len() as u64;
    let pruned = deleted
        .into_iter()
        .map(|(id, number, prefix)| PrunedVersion {
            prefix: prefix.unwrap_or_else(|| publication_prefix(repo_id, number)),
            member_filenames: by_version.remove(&id).unwrap_or_default(),
        })
        .collect();
    Ok(PrunedRows {
        deleted: rows,
        pruned,
        surviving,
    })
}

/// Delete one object, treating "already gone" as success.
async fn delete_object(storage: &dyn StorageBackend, key: &str, report: &mut RetentionReport) {
    match storage.delete(key).await {
        Ok(()) => report.objects_deleted += 1,
        Err(AppError::NotFound(_)) => {}
        Err(e) => {
            report.delete_failures += 1;
            tracing::warn!(key, error = %e, "RPM version retention: object delete failed");
        }
    }
}

/// Prune one repository's versions down to `keep` (plus the active one) and
/// delete the pruned versions' objects, accumulating into `report`.
pub async fn prune_repository(
    db: &PgPool,
    storage: &dyn StorageBackend,
    repo_id: Uuid,
    keep: u32,
    report: &mut RetentionReport,
) -> Result<(), AppError> {
    if keep == 0 {
        return Ok(());
    }
    let rows = prune_rows(db, repo_id, keep).await?;
    report.versions_pruned += rows.deleted;

    // Listing backends: delete every object under a version number with no
    // row. That covers the versions just pruned and anything an earlier
    // crash or a racing `@N` cache fill left behind, and only touches keys
    // that exist.
    let root = publications_root(repo_id);
    let newest = rows.surviving.iter().next_back().copied();
    match storage.list_keys(&root).await {
        Ok(Some(listed)) => {
            for listed in listed {
                if is_stray_key(&root, &listed.key, &rows.surviving, newest) {
                    delete_object(storage, &listed.key, report).await;
                }
            }
        }
        // A backend that cannot list (Azure): delete the known keys of the
        // versions just pruned.
        Ok(None) => {
            for version in &rows.pruned {
                for key in known_version_keys(&version.prefix, &version.member_filenames) {
                    delete_object(storage, &key, report).await;
                }
            }
        }
        Err(e) => {
            tracing::warn!(repo_id = %repo_id, error = %e, "RPM version retention: listing failed")
        }
    }
    Ok(())
}

/// One retention pass over every repository holding curated versions (or
/// only `only_repo`). Repositories already at or below `keep` are visited too,
/// so the stray sweep can collect leftovers there. Stops between repositories once `lost` is
/// cancelled. A failure in one repository is logged and does not stop the
/// others.
pub async fn run_retention_pass(
    db: &PgPool,
    registry: &StorageRegistry,
    keep: u32,
    only_repo: Option<Uuid>,
    lost: Option<&CancellationToken>,
) -> Result<RetentionReport, AppError> {
    let mut report = RetentionReport::default();
    if keep == 0 {
        return Ok(report);
    }
    let repos: Vec<(Uuid, String, String)> = sqlx::query_as(
        "SELECT r.id, r.storage_backend, r.storage_path FROM repositories r \
         WHERE EXISTS (SELECT 1 FROM repository_versions rv WHERE rv.repository_id = r.id) \
           AND ($1::uuid IS NULL OR r.id = $1) \
         ORDER BY r.id",
    )
    .bind(only_repo)
    .fetch_all(db)
    .await?;

    for (repo_id, backend, path) in repos {
        if lost.is_some_and(CancellationToken::is_cancelled) {
            tracing::warn!("RPM version retention: scheduler lease lost; stopping the pass");
            break;
        }
        report.repositories += 1;
        let storage = match registry.backend_for(&StorageLocation { backend, path }) {
            Ok(storage) => storage,
            Err(e) => {
                tracing::warn!(repo_id = %repo_id, error = %e, "RPM version retention: no storage");
                continue;
            }
        };
        if let Err(e) = prune_repository(db, storage.as_ref(), repo_id, keep, &mut report).await {
            tracing::warn!(repo_id = %repo_id, error = %e, "RPM version retention failed");
        }
    }
    Ok(report)
}

#[cfg(ak_test_shard = "services-2")]
#[cfg(test)]
mod tests {
    use super::*;

    fn v(n: i64) -> (Uuid, i64) {
        (Uuid::from_u128(n as u128), n)
    }

    #[test]
    fn test_parse_keep_is_off_unless_positive() {
        assert_eq!(parse_keep(None), None);
        assert_eq!(parse_keep(Some("")), None);
        assert_eq!(parse_keep(Some("  ")), None);
        assert_eq!(parse_keep(Some("0")), None);
        assert_eq!(parse_keep(Some("-3")), None);
        assert_eq!(parse_keep(Some("five")), None);
        assert_eq!(parse_keep(Some("5")), Some(5));
        assert_eq!(parse_keep(Some(" 12 ")), Some(12));
    }

    #[test]
    fn test_select_prunable_keeps_newest_n_and_active() {
        let versions = vec![v(3), v(1), v(5), v(2), v(4)];
        // keep 2 -> 5 and 4 survive; 1 is active and survives too.
        let mut pruned = select_prunable(&versions, Some(v(1).0), 2);
        pruned.sort();
        assert_eq!(pruned, vec![v(2).0, v(3).0]);
        // Active inside the window changes nothing.
        let mut pruned = select_prunable(&versions, Some(v(5).0), 2);
        pruned.sort();
        assert_eq!(pruned, vec![v(1).0, v(2).0, v(3).0]);
        // No active publication.
        assert_eq!(select_prunable(&versions, None, 4), vec![v(1).0]);
        // Fewer versions than the window, and disabled retention.
        assert!(select_prunable(&versions, None, 5).is_empty());
        assert!(select_prunable(&versions, None, 0).is_empty());
        assert!(select_prunable(&[], None, 1).is_empty());
    }

    #[test]
    fn test_known_version_keys_cover_repodata_and_cached_packages() {
        let keys = known_version_keys("curation/r/publications/2", &["a-1-1.x86_64.rpm".into()]);
        assert_eq!(keys.len(), PUBLICATION_REPODATA_FILES.len() + 1);
        assert!(keys.contains(&"curation/r/publications/2/repodata/repomd.xml".to_string()));
        assert!(keys.contains(&"curation/r/publications/2/repodata/repomd.xml.asc".to_string()));
        assert!(keys.contains(&"curation/r/publications/2/packages/a-1-1.x86_64.rpm".to_string()));
    }

    #[test]
    fn test_listed_version_number_parses_only_the_publication_layout() {
        let root = "curation/r/publications/";
        assert_eq!(
            listed_version_number(root, "curation/r/publications/12/repodata/repomd.xml"),
            Some(12)
        );
        assert_eq!(
            listed_version_number(root, "curation/r/publications/3/packages/a.rpm"),
            Some(3)
        );
        for key in [
            "curation/r/publications/12",
            "curation/r/publications/12/",
            "curation/r/publications//x",
            "curation/r/publications/1a/x",
            "curation/r/publications/-1/x",
            "curation/other/publications/1/x",
            "packages/a.rpm",
        ] {
            assert_eq!(listed_version_number(root, key), None, "{key}");
        }
    }

    #[test]
    fn test_is_stray_key_spares_surviving_and_newer_versions() {
        let root = "curation/r/publications/";
        let surviving: BTreeSet<i64> = [4, 5].into_iter().collect();
        let key = |n: i64| format!("{root}{n}/repodata/repomd.xml");
        assert!(is_stray_key(root, &key(1), &surviving, Some(5)));
        assert!(is_stray_key(root, &key(3), &surviving, Some(5)));
        assert!(!is_stray_key(root, &key(4), &surviving, Some(5)));
        assert!(!is_stray_key(root, &key(5), &surviving, Some(5)));
        // A version above the newest row may be mid-create; leave it.
        assert!(!is_stray_key(root, &key(6), &surviving, Some(5)));
        // No surviving rows at all: nothing is provably stray.
        assert!(!is_stray_key(root, &key(1), &BTreeSet::new(), None));
        assert!(!is_stray_key(root, "curation/r/other", &surviving, Some(5)));
    }

    // -- DB-backed: the retention contract end to end --------------------------

    async fn seed_version(
        pool: &PgPool,
        repo: Uuid,
        remote: Uuid,
        storage: &dyn StorageBackend,
        n: i64,
        published: bool,
    ) -> Uuid {
        let prefix = publication_prefix(repo, n);
        let id: Uuid = sqlx::query_scalar(
            "INSERT INTO repository_versions \
             (repository_id, version_number, package_count, published_at, storage_prefix) \
             VALUES ($1, $2, 1, CASE WHEN $3 THEN now() END, CASE WHEN $3 THEN $4 END) \
             RETURNING id",
        )
        .bind(repo)
        .bind(n)
        .bind(published)
        .bind(&prefix)
        .fetch_one(pool)
        .await
        .expect("seed version");
        let package: Uuid = sqlx::query_scalar(
            "INSERT INTO curation_packages \
             (staging_repo_id, remote_repo_id, format, package_name, version, release, \
              architecture, checksum_sha256, upstream_path, status) \
             VALUES ($1, $2, 'rpm', $3, '1.0', '1', 'x86_64', 'abc', 'p.rpm', 'approved') \
             RETURNING id",
        )
        .bind(repo)
        .bind(remote)
        .bind(format!("pkg{n}"))
        .fetch_one(pool)
        .await
        .expect("seed package");
        let filename = format!("pkg{n}-1.0-1.x86_64.rpm");
        sqlx::query(
            "INSERT INTO repository_version_packages \
             (version_id, curation_package_id, frozen_checksum_sha256, frozen_upstream_path, \
              frozen_filename) VALUES ($1, $2, 'abc', 'p.rpm', $3)",
        )
        .bind(id)
        .bind(package)
        .bind(&filename)
        .execute(pool)
        .await
        .expect("seed member");
        if published {
            for key in known_version_keys(&prefix, &[filename]) {
                storage
                    .put(&key, bytes::Bytes::from_static(b"x"))
                    .await
                    .expect("seed object");
            }
        }
        id
    }

    async fn version_numbers(pool: &PgPool, repo: Uuid) -> Vec<i64> {
        sqlx::query_scalar(
            "SELECT version_number FROM repository_versions WHERE repository_id = $1 \
             ORDER BY version_number",
        )
        .bind(repo)
        .fetch_all(pool)
        .await
        .unwrap()
    }

    async fn object_exists(storage: &dyn StorageBackend, repo: Uuid, n: i64) -> bool {
        storage
            .exists(&format!(
                "{}/repodata/repomd.xml",
                publication_prefix(repo, n)
            ))
            .await
            .unwrap()
    }

    // Retention keeps the active publication plus the newest N, deletes every
    // other version row and the objects under its storage prefix, including
    // a stray prefix with no row, and leaves a disabled pass a no-op.
    #[tokio::test]
    async fn test_retention_keeps_active_and_newest_and_deletes_prefixes_db() {
        use crate::api::handlers::test_db_helpers as tdh;
        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let (repo, _k, dir) = tdh::create_repo(&pool, "staging", "rpm").await;
        let (remote, _rk, _rd) = tdh::create_repo(&pool, "remote", "rpm").await;
        let (actor, _n) = tdh::create_user(&pool).await;
        let storage = crate::storage::filesystem::FilesystemStorage::new(dir.to_str().unwrap());

        let mut ids = Vec::new();
        for n in 1..=5 {
            // Version 4 was created but never published.
            ids.push(seed_version(&pool, repo, remote, &storage, n, n != 4).await);
        }
        sqlx::query("UPDATE repositories SET active_publication_id = $2 WHERE id = $1")
            .bind(repo)
            .bind(ids[1])
            .execute(&pool)
            .await
            .unwrap();
        // A leftover prefix whose row is already gone.
        let stray = format!("{}/repodata/repomd.xml", publication_prefix(repo, 0));
        storage
            .put(&stray, bytes::Bytes::from_static(b"x"))
            .await
            .unwrap();

        // Disabled retention touches nothing.
        let mut report = RetentionReport::default();
        prune_repository(&pool, &storage, repo, 0, &mut report)
            .await
            .unwrap();
        assert_eq!(version_numbers(&pool, repo).await, vec![1, 2, 3, 4, 5]);

        let mut report = RetentionReport::default();
        prune_repository(&pool, &storage, repo, 2, &mut report)
            .await
            .unwrap();
        // Active (2) + newest two (4, 5) survive.
        assert_eq!(version_numbers(&pool, repo).await, vec![2, 4, 5]);
        assert_eq!(report.versions_pruned, 2);
        assert_eq!(report.delete_failures, 0);
        // 1 and 3: six repodata blobs + one cached package each, plus the stray.
        assert_eq!(report.objects_deleted, 2 * 7 + 1);
        assert!(!object_exists(&storage, repo, 1).await);
        assert!(!object_exists(&storage, repo, 3).await);
        assert!(!storage.exists(&stray).await.unwrap());
        assert!(object_exists(&storage, repo, 2).await);
        assert!(object_exists(&storage, repo, 5).await);
        let members: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM repository_version_packages WHERE version_id = ANY($1)",
        )
        .bind(vec![ids[0], ids[2]])
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(members, 0, "membership rows cascade with the version");

        // A second pass is idempotent; keep 1 still spares the active version.
        let mut report = RetentionReport::default();
        prune_repository(&pool, &storage, repo, 1, &mut report)
            .await
            .unwrap();
        assert_eq!(version_numbers(&pool, repo).await, vec![2, 5]);
        assert_eq!(report.versions_pruned, 1);

        tdh::cleanup(&pool, repo, actor).await;
        tdh::cleanup(&pool, remote, actor).await;
    }

    // The scheduled pass resolves each repository's storage through the
    // registry and prunes it. A lease already lost before the pass starts
    // means it does no work at all (the token is checked before every
    // repository; this pins the check, not a mid-pass stop).
    #[tokio::test]
    async fn test_retention_pass_uses_registry_and_skips_work_once_lease_lost_db() {
        use crate::api::handlers::test_db_helpers as tdh;
        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let (repo, _k, dir) = tdh::create_repo(&pool, "staging", "rpm").await;
        let (remote, _rk, _rd) = tdh::create_repo(&pool, "remote", "rpm").await;
        let (actor, _n) = tdh::create_user(&pool).await;
        let storage = crate::storage::filesystem::FilesystemStorage::new(dir.to_str().unwrap());
        for n in 1..=3 {
            seed_version(&pool, repo, remote, &storage, n, true).await;
        }
        let registry = StorageRegistry::new(Default::default(), "filesystem".to_string());

        let lost = CancellationToken::new();
        lost.cancel();
        let report = run_retention_pass(&pool, &registry, 1, Some(repo), Some(&lost))
            .await
            .unwrap();
        assert_eq!(report.versions_pruned, 0);
        assert_eq!(version_numbers(&pool, repo).await, vec![1, 2, 3]);

        assert_eq!(
            run_retention_pass(&pool, &registry, 0, Some(repo), None)
                .await
                .unwrap(),
            RetentionReport::default()
        );

        let report = run_retention_pass(&pool, &registry, 1, Some(repo), None)
            .await
            .unwrap();
        assert_eq!(report.versions_pruned, 2, "{report:?}");
        assert_eq!(report.repositories, 1);
        assert_eq!(version_numbers(&pool, repo).await, vec![3]);
        assert!(!object_exists(&storage, repo, 1).await);
        assert!(object_exists(&storage, repo, 3).await);

        tdh::cleanup(&pool, repo, actor).await;
        tdh::cleanup(&pool, remote, actor).await;
    }

    // A repository already at `keep` versions is still visited, so a leftover
    // prefix with no row (a crashed pass or publish) is swept on the next pass
    // even though nothing new is pruned.
    #[tokio::test]
    async fn test_retention_pass_sweeps_leftovers_on_repo_at_keep_db() {
        use crate::api::handlers::test_db_helpers as tdh;
        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let (repo, _k, dir) = tdh::create_repo(&pool, "staging", "rpm").await;
        let (remote, _rk, _rd) = tdh::create_repo(&pool, "remote", "rpm").await;
        let (actor, _n) = tdh::create_user(&pool).await;
        let storage = crate::storage::filesystem::FilesystemStorage::new(dir.to_str().unwrap());
        for n in 2..=3 {
            seed_version(&pool, repo, remote, &storage, n, true).await;
        }
        let stray = format!("{}/packages/old.rpm", publication_prefix(repo, 1));
        storage
            .put(&stray, bytes::Bytes::from_static(b"x"))
            .await
            .unwrap();
        let registry = StorageRegistry::new(Default::default(), "filesystem".to_string());

        let report = run_retention_pass(&pool, &registry, 2, Some(repo), None)
            .await
            .unwrap();
        assert_eq!(report.repositories, 1);
        assert_eq!(report.versions_pruned, 0);
        assert_eq!(report.objects_deleted, 1, "{report:?}");
        assert!(!storage.exists(&stray).await.unwrap());
        assert!(object_exists(&storage, repo, 2).await);
        assert!(object_exists(&storage, repo, 3).await);
        assert_eq!(version_numbers(&pool, repo).await, vec![2, 3]);

        tdh::cleanup(&pool, repo, actor).await;
        tdh::cleanup(&pool, remote, actor).await;
    }

    // On a backend that cannot list (Azure), a pruned published version's
    // repodata and cached packages are deleted by known key, and a pruned
    // unpublished version only has its repodata (left by a crashed publish)
    // deleted, never a per-member package delete.
    #[tokio::test]
    async fn test_retention_known_key_fallback_without_listing_db() {
        use crate::api::handlers::test_db_helpers as tdh;
        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let (repo, _k, _dir) = tdh::create_repo(&pool, "staging", "rpm").await;
        let (remote, _rk, _rd) = tdh::create_repo(&pool, "remote", "rpm").await;
        let (actor, _n) = tdh::create_user(&pool).await;
        let storage = tdh::MemStorage::default();
        assert!(storage.list_keys("x/").await.unwrap().is_none());
        seed_version(&pool, repo, remote, &storage, 1, true).await;
        seed_version(&pool, repo, remote, &storage, 2, false).await;
        seed_version(&pool, repo, remote, &storage, 3, true).await;
        // Repodata a crashed publish of version 2 left behind.
        let leftover = format!("{}/repodata/repomd.xml", publication_prefix(repo, 2));
        storage
            .put(&leftover, bytes::Bytes::from_static(b"x"))
            .await
            .unwrap();

        let mut report = RetentionReport::default();
        prune_repository(&pool, &storage, repo, 1, &mut report)
            .await
            .unwrap();
        assert_eq!(version_numbers(&pool, repo).await, vec![3]);
        assert_eq!(report.versions_pruned, 2);
        // MemStorage counts every delete: 7 for version 1, 6 repodata for 2.
        assert_eq!(report.objects_deleted, 7 + 6, "{report:?}");
        let remaining: Vec<String> = storage.objects.lock().unwrap().keys().cloned().collect();
        let v3 = publication_prefix(repo, 3);
        assert_eq!(remaining.len(), 7, "{remaining:?}");
        assert!(remaining.iter().all(|k| k.starts_with(&format!("{v3}/"))));

        tdh::cleanup(&pool, repo, actor).await;
        tdh::cleanup(&pool, remote, actor).await;
    }

    #[test]
    fn test_surviving_numbers_follow_the_actual_delete() {
        let versions = vec![v(1), v(2), v(3)];
        // A row the SQL guard spared stays in `surviving`.
        let surviving = surviving_numbers(&versions, [v(1).0]);
        assert_eq!(surviving.into_iter().collect::<Vec<_>>(), vec![2, 3]);
        assert_eq!(surviving_numbers(&versions, []).len(), 3);
    }
}
