//! Deduplicated storage accounting service (epic #2056, P1).
//!
//! Computes the true *physical* storage footprint per repository across the
//! three physical sources — `artifacts` (CAS / coordinate / OCI manifests),
//! `oci_blobs` (OCI layers, previously omitted from all accounting), and the
//! `proxy_cache_artifacts` catalog — and materialises the result into
//! `repository_storage_stats` + `instance_storage_stats` so the API can read
//! it in O(1).
//!
//! This is a **parallel, read-only** accounting layer. It does NOT feed quota
//! enforcement: `RepositoryService::check_quota` continues to read the live
//! logical `SUM` (see #2056 §7). Repointing quota at the deduplicated number
//! would loosen effective limits and is a deliberate non-change here.
//!
//! # Dedup model
//!
//! Every physical object is identified by a *dedup key* (its storage
//! key / digest). The three sources are normalised into one
//! `(repository_id, dedup_key, size_bytes)` relation ([`REPO_OBJECT_UNION_SQL`]),
//! then a single aggregate pass yields, per `(repository_id, dedup_key)`, the
//! object size, the in-repo reference count (the logical multiplier), and the
//! global count of distinct repositories referencing the key. The pure
//! [`compute_stats`] function turns those rows into per-repo figures, branching
//! on the backend-aware [`DedupScope`]:
//!
//! * `filesystem` (`DedupScope::PerRepo`): a digest present in two repos is two
//!   physical files, so `shared_bytes` is always 0 and the instance total is
//!   the sum over every `(repo, key)`.
//! * cloud `s3`/`gcs`/`azure` (`DedupScope::Instance`): one physical object
//!   backs a digest across all repos, so a key seen in >1 repo is `shared`, and
//!   the instance total counts each global key once.

use std::collections::{HashMap, HashSet};

use sqlx::{PgPool, Row};
use uuid::Uuid;

use crate::error::{AppError, Result};

/// Prefix that namespaces an OCI layer blob's dedup key so it can never
/// collide with an `artifacts.storage_key` (manifests use `oci-manifests/`).
///
/// Shared source of truth for the `oci_blobs` contribution: both this module's
/// `repo_object` union and the GC footprint report key OCI layers off the
/// digest, so the normalisation lives in one place.
pub const OCI_BLOB_DEDUP_PREFIX: &str = "oci-blobs/";

/// The three-source `repo_object` relation: one row per *reference*, projected
/// to `(repository_id, dedup_key, size_bytes)`.
///
/// Kept as a single shared fragment so the aggregate query has exactly one
/// definition of "what bytes a repository references" (avoids CTE copy-paste
/// and drift with the GC reference model).
///
/// * `artifacts` (live, non-proxy) — `storage_key` is the physical identity
///   (CAS `cas/…`, coordinate formats, `oci-manifests/…`). Proxy-cache leftover
///   rows are excluded to mirror the #2218 / #2531 accounting exclusion.
/// * `oci_blobs` — keyed by `'oci-blobs/' || digest`; `size_bytes` is the true
///   layer size. **This is the OCI accounting gap #2056 closes.**
/// * `proxy_cache_artifacts` — path-keyed per repo, never cross-repo shared and
///   effectively never duplicated (logical == physical == unique).
const REPO_OBJECT_UNION_SQL: &str = r#"
    SELECT repository_id, storage_key AS dedup_key, size_bytes
      FROM artifacts
     WHERE is_deleted = false
       AND storage_key NOT LIKE 'proxy-cache/%'
    UNION ALL
    SELECT repository_id, 'oci-blobs/' || digest AS dedup_key, size_bytes
      FROM oci_blobs
    UNION ALL
    SELECT repository_id, storage_key AS dedup_key, size_bytes
      FROM proxy_cache_artifacts
"#;

/// Backend-aware deduplication scope. `filesystem` shards physical objects
/// per repository; cloud backends share one object instance-wide.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DedupScope {
    /// Filesystem: `(repo_id, dedup_key)` is the physical unit; `shared` = 0.
    PerRepo,
    /// Cloud (s3/gcs/azure): the global `dedup_key` is the physical unit.
    Instance,
}

impl DedupScope {
    /// Map a `config.storage_backend` string to a dedup scope. Anything that is
    /// not a known cloud backend (i.e. `filesystem` or an unknown value) is
    /// treated conservatively as `PerRepo`, which never over-reports sharing.
    pub fn from_backend(backend: &str) -> Self {
        match backend {
            "s3" | "gcs" | "azure" => DedupScope::Instance,
            _ => DedupScope::PerRepo,
        }
    }

    /// The `dedup_scope` label persisted alongside the stats so consumers know
    /// which backend semantics produced the numbers.
    pub fn as_str(self) -> &'static str {
        match self {
            DedupScope::PerRepo => "per_repo",
            DedupScope::Instance => "instance",
        }
    }
}

/// One `(repository_id, dedup_key)` aggregate row produced by the recompute
/// query. `size_bytes` is the object's physical size (MAX over identical-size
/// rows); `ref_count` is the number of references within this repo (the
/// logical multiplier); `repo_count` is the number of distinct repositories
/// referencing this key across the instance.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RepoObjectRow {
    pub repository_id: Uuid,
    pub dedup_key: String,
    pub size_bytes: i64,
    pub ref_count: i64,
    pub repo_count: i64,
}

/// Per-repository deduplicated figures.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct RepoStats {
    /// Sum over every reference (per-row) — the display "logical" total.
    pub logical_bytes: i64,
    /// Deduplicated footprint within the dedup scope.
    pub physical_bytes: i64,
    /// Physical bytes of keys referenced only by this repo.
    pub unique_bytes: i64,
    /// physical_bytes - unique_bytes (0 on filesystem).
    pub shared_bytes: i64,
    /// Distinct dedup keys referenced by this repo.
    pub blob_count: i64,
}

/// The full result of a recompute: per-repo stats keyed by repository id plus
/// the instance-level globally-distinct footprint.
#[derive(Debug, Clone, PartialEq)]
pub struct ComputedStats {
    pub per_repo: HashMap<Uuid, RepoStats>,
    pub instance_unique_bytes: i64,
}

/// `logical / physical`, defined as `1.0` when there is no physical footprint
/// (nothing stored ⇒ no dedup savings). Shared with the API response mapping so
/// the ratio is computed one way only.
pub fn dedup_ratio(logical_bytes: i64, physical_bytes: i64) -> f64 {
    if physical_bytes <= 0 {
        1.0
    } else {
        logical_bytes as f64 / physical_bytes as f64
    }
}

/// Pure aggregation of `(repo, dedup_key)` rows into per-repo + instance
/// figures under a given [`DedupScope`]. No I/O — this is the unit-tested core
/// of the dedup model.
pub fn compute_stats(rows: &[RepoObjectRow], scope: DedupScope) -> ComputedStats {
    let mut per_repo: HashMap<Uuid, RepoStats> = HashMap::new();
    // Instance total: on cloud, count each global dedup key once; on
    // filesystem, every (repo, key) is its own physical file.
    let mut seen_global_keys: HashSet<&str> = HashSet::new();
    let mut instance_unique_bytes: i64 = 0;

    for row in rows {
        let entry = per_repo.entry(row.repository_id).or_default();
        entry.blob_count += 1;
        entry.physical_bytes += row.size_bytes;
        // Every reference contributes size_bytes to logical (content-addressed
        // rows share a size, so size * ref_count == the per-row sum).
        entry.logical_bytes += row.size_bytes * row.ref_count;

        match scope {
            DedupScope::PerRepo => {
                // A key in two repos is two files: nothing is shared, and each
                // (repo, key) is a distinct physical object instance-wide.
                entry.unique_bytes += row.size_bytes;
                instance_unique_bytes += row.size_bytes;
            }
            DedupScope::Instance => {
                if row.repo_count <= 1 {
                    entry.unique_bytes += row.size_bytes;
                }
                if seen_global_keys.insert(row.dedup_key.as_str()) {
                    instance_unique_bytes += row.size_bytes;
                }
            }
        }
    }

    // shared = physical - unique (0 on filesystem by construction).
    for stats in per_repo.values_mut() {
        stats.shared_bytes = stats.physical_bytes - stats.unique_bytes;
    }

    ComputedStats {
        per_repo,
        instance_unique_bytes,
    }
}

/// Deduplicated storage accounting service. Holds only a DB handle and the
/// backend-derived dedup scope; the heavy aggregation runs on the scheduler /
/// post-GC, never on an API read.
pub struct StorageStatsService {
    db: PgPool,
    scope: DedupScope,
}

impl StorageStatsService {
    /// Construct from the live pool and the configured storage backend string
    /// (`config.storage_backend`).
    pub fn new(db: PgPool, storage_backend: &str) -> Self {
        Self {
            db,
            scope: DedupScope::from_backend(storage_backend),
        }
    }

    /// Run the single heavy aggregate: normalise the three sources into
    /// `repo_object`, then per `(repository_id, dedup_key)` compute the object
    /// size, in-repo reference count, and global distinct-repo count.
    async fn load_repo_object_rows(&self) -> Result<Vec<RepoObjectRow>> {
        // `MAX(size_bytes)` per (repo, key) mirrors the proven GC `per_digest`
        // pattern: identical-size content-addressed rows collapse to one
        // physical size. `repo_count` is the global distinct-repo count for the
        // key (the single expensive cross-repo pass, bounded by object count).
        let sql = format!(
            r#"
            WITH repo_object AS ({union}),
            per_repo_key AS (
                SELECT repository_id,
                       dedup_key,
                       MAX(size_bytes) AS size_bytes,
                       COUNT(*)        AS ref_count
                FROM repo_object
                GROUP BY repository_id, dedup_key
            ),
            key_repo_count AS (
                SELECT dedup_key,
                       COUNT(DISTINCT repository_id) AS repo_count
                FROM repo_object
                GROUP BY dedup_key
            )
            SELECT prk.repository_id,
                   prk.dedup_key,
                   prk.size_bytes,
                   prk.ref_count,
                   krc.repo_count
            FROM per_repo_key prk
            JOIN key_repo_count krc ON krc.dedup_key = prk.dedup_key
            "#,
            union = REPO_OBJECT_UNION_SQL,
        );

        let rows = sqlx::query(&sql)
            .fetch_all(&self.db)
            .await
            .map_err(|e| AppError::Database(e.to_string()))?;

        rows.into_iter()
            .map(|row| {
                Ok(RepoObjectRow {
                    repository_id: row
                        .try_get("repository_id")
                        .map_err(|e| AppError::Database(e.to_string()))?,
                    dedup_key: row
                        .try_get("dedup_key")
                        .map_err(|e| AppError::Database(e.to_string()))?,
                    size_bytes: row.try_get("size_bytes").unwrap_or(0),
                    ref_count: row.try_get("ref_count").unwrap_or(0),
                    repo_count: row.try_get("repo_count").unwrap_or(0),
                })
            })
            .collect()
    }

    /// Full refresh: recompute every repository's footprint + the instance
    /// total and upsert them. Run on the scheduler cadence and after GC.
    pub async fn recompute_all(&self) -> Result<()> {
        let rows = self.load_repo_object_rows().await?;
        let computed = compute_stats(&rows, self.scope);
        self.persist(&computed).await
    }

    /// Persist a computed snapshot: upsert every repo row, prune repos that no
    /// longer have any footprint, and refresh the instance singleton.
    async fn persist(&self, computed: &ComputedStats) -> Result<()> {
        let scope = self.scope.as_str();

        for (repo_id, stats) in &computed.per_repo {
            sqlx::query!(
                r#"
                INSERT INTO repository_storage_stats
                    (repository_id, logical_bytes, physical_bytes, unique_bytes,
                     shared_bytes, blob_count, dedup_scope, computed_at)
                VALUES ($1, $2, $3, $4, $5, $6, $7, now())
                ON CONFLICT (repository_id) DO UPDATE SET
                    logical_bytes  = EXCLUDED.logical_bytes,
                    physical_bytes = EXCLUDED.physical_bytes,
                    unique_bytes   = EXCLUDED.unique_bytes,
                    shared_bytes   = EXCLUDED.shared_bytes,
                    blob_count     = EXCLUDED.blob_count,
                    dedup_scope    = EXCLUDED.dedup_scope,
                    computed_at    = now()
                "#,
                repo_id,
                stats.logical_bytes,
                stats.physical_bytes,
                stats.unique_bytes,
                stats.shared_bytes,
                stats.blob_count,
                scope,
            )
            .execute(&self.db)
            .await
            .map_err(|e| AppError::Database(e.to_string()))?;
        }

        // Zero out repositories that no longer reference any object so a stale
        // non-zero footprint is never served after everything is deleted/GC'd.
        let live_ids: Vec<Uuid> = computed.per_repo.keys().copied().collect();
        sqlx::query!(
            r#"
            UPDATE repository_storage_stats
               SET logical_bytes = 0, physical_bytes = 0, unique_bytes = 0,
                   shared_bytes = 0, blob_count = 0, dedup_scope = $2,
                   computed_at = now()
             WHERE repository_id <> ALL($1)
               AND (logical_bytes <> 0 OR physical_bytes <> 0 OR blob_count <> 0)
            "#,
            &live_ids,
            scope,
        )
        .execute(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        sqlx::query!(
            r#"
            INSERT INTO instance_storage_stats (id, unique_bytes, dedup_scope, computed_at)
            VALUES (true, $1, $2, now())
            ON CONFLICT (id) DO UPDATE SET
                unique_bytes = EXCLUDED.unique_bytes,
                dedup_scope  = EXCLUDED.dedup_scope,
                computed_at  = now()
            "#,
            computed.instance_unique_bytes,
            scope,
        )
        .execute(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        Ok(())
    }

    /// The dedup scope this service computes under (test/introspection helper).
    pub fn scope(&self) -> DedupScope {
        self.scope
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(repo: Uuid, key: &str, size: i64, refs: i64, repos: i64) -> RepoObjectRow {
        RepoObjectRow {
            repository_id: repo,
            dedup_key: key.to_string(),
            size_bytes: size,
            ref_count: refs,
            repo_count: repos,
        }
    }

    #[test]
    fn from_backend_maps_cloud_and_filesystem() {
        assert_eq!(DedupScope::from_backend("s3"), DedupScope::Instance);
        assert_eq!(DedupScope::from_backend("gcs"), DedupScope::Instance);
        assert_eq!(DedupScope::from_backend("azure"), DedupScope::Instance);
        assert_eq!(DedupScope::from_backend("filesystem"), DedupScope::PerRepo);
        // Unknown backends are treated conservatively (never over-report share).
        assert_eq!(DedupScope::from_backend("wat"), DedupScope::PerRepo);
    }

    #[test]
    fn dedup_ratio_guards_zero_physical() {
        assert_eq!(dedup_ratio(0, 0), 1.0);
        assert_eq!(dedup_ratio(100, 0), 1.0);
        assert!((dedup_ratio(300, 100) - 3.0).abs() < f64::EPSILON);
    }

    #[test]
    fn single_ref_key_is_all_unique() {
        let r = Uuid::new_v4();
        let rows = vec![row(r, "cas/aa/bb/x", 100, 1, 1)];
        let out = compute_stats(&rows, DedupScope::Instance);
        let s = out.per_repo[&r];
        assert_eq!(s.logical_bytes, 100);
        assert_eq!(s.physical_bytes, 100);
        assert_eq!(s.unique_bytes, 100);
        assert_eq!(s.shared_bytes, 0);
        assert_eq!(s.blob_count, 1);
        assert_eq!(out.instance_unique_bytes, 100);
    }

    #[test]
    fn n_refs_same_key_dedup_within_repo() {
        // A CAS blob referenced by 3 artifact rows in one repo: logical = 3*s,
        // physical = s, unique = s (matches FixSpec §8 integration case).
        let r = Uuid::new_v4();
        let rows = vec![row(r, "cas/aa/bb/x", 50, 3, 1)];
        let out = compute_stats(&rows, DedupScope::PerRepo);
        let s = out.per_repo[&r];
        assert_eq!(s.logical_bytes, 150);
        assert_eq!(s.physical_bytes, 50);
        assert_eq!(s.unique_bytes, 50);
        assert_eq!(s.shared_bytes, 0);
        assert_eq!(s.blob_count, 1);
    }

    #[test]
    fn filesystem_forces_shared_zero_and_double_counts_instance() {
        // Same digest in repo A and B on filesystem: both physical = s,
        // shared = 0, instance_unique = 2*s (two files).
        let a = Uuid::new_v4();
        let b = Uuid::new_v4();
        let rows = vec![
            row(a, "oci-blobs/sha256:deadbeef", 200, 1, 2),
            row(b, "oci-blobs/sha256:deadbeef", 200, 1, 2),
        ];
        let out = compute_stats(&rows, DedupScope::PerRepo);
        assert_eq!(out.per_repo[&a].physical_bytes, 200);
        assert_eq!(out.per_repo[&a].shared_bytes, 0);
        assert_eq!(out.per_repo[&a].unique_bytes, 200);
        assert_eq!(out.per_repo[&b].shared_bytes, 0);
        assert_eq!(out.instance_unique_bytes, 400);
    }

    #[test]
    fn cloud_splits_shared_and_counts_key_once() {
        // Same digest in repo A and B on cloud: physical = s each,
        // shared = s each, instance_unique = s (one object).
        let a = Uuid::new_v4();
        let b = Uuid::new_v4();
        let rows = vec![
            row(a, "oci-blobs/sha256:deadbeef", 200, 1, 2),
            row(b, "oci-blobs/sha256:deadbeef", 200, 1, 2),
        ];
        let out = compute_stats(&rows, DedupScope::Instance);
        assert_eq!(out.per_repo[&a].physical_bytes, 200);
        assert_eq!(out.per_repo[&a].shared_bytes, 200);
        assert_eq!(out.per_repo[&a].unique_bytes, 0);
        assert_eq!(out.per_repo[&b].shared_bytes, 200);
        assert_eq!(out.instance_unique_bytes, 200);
    }

    #[test]
    fn cloud_mixed_unique_and_shared_in_one_repo() {
        let a = Uuid::new_v4();
        let b = Uuid::new_v4();
        let rows = vec![
            // shared layer (in A and B)
            row(a, "oci-blobs/shared", 100, 1, 2),
            row(b, "oci-blobs/shared", 100, 1, 2),
            // A-only unique layer, referenced twice within A
            row(a, "oci-blobs/aonly", 30, 2, 1),
        ];
        let out = compute_stats(&rows, DedupScope::Instance);
        let sa = out.per_repo[&a];
        assert_eq!(sa.logical_bytes, 100 + 60); // shared once + unique twice
        assert_eq!(sa.physical_bytes, 130);
        assert_eq!(sa.unique_bytes, 30);
        assert_eq!(sa.shared_bytes, 100);
        assert_eq!(sa.blob_count, 2);
        // instance: shared(100) counted once + aonly(30) = 130
        assert_eq!(out.instance_unique_bytes, 130);
    }

    #[test]
    fn oci_blob_prefix_never_collides_with_manifests() {
        // OCI layer keys are namespaced away from artifacts.storage_key
        // (`oci-manifests/…`) so the union cannot merge distinct objects.
        assert!(OCI_BLOB_DEDUP_PREFIX.starts_with("oci-blobs/"));
        assert!(!"oci-manifests/abc".starts_with(OCI_BLOB_DEDUP_PREFIX));
    }
}
