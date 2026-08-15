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
/// * `artifacts` (live, non-proxy, non-OCI-manifest) — `storage_key` is the
///   physical identity (CAS `cas/…`, coordinate formats). Proxy-cache leftover
///   rows are excluded to mirror the #2218 / #2531 accounting exclusion.
/// * `oci_blobs` — keyed by `'oci-blobs/' || digest`; `size_bytes` is the true
///   layer size. **This is the OCI accounting gap #2056 closes.**
/// * `proxy_cache_artifacts` — path-keyed per repo, never cross-repo shared and
///   effectively never duplicated (logical == physical == unique).
///
/// # Why `oci-manifests/%` rows are excluded (#3286)
///
/// `artifacts.size_bytes` for an OCI **image manifest** does not hold the size
/// of the stored manifest object: the push path writes
/// `oci_v2::manifest_total_size(body)` — `config.size` plus the sum of
/// `layers[].size`, i.e. the *aggregate image size* — because GC, quota and
/// scanning enumerate `artifacts` and need the image to weigh what it actually
/// occupies. That column is therefore already the layer bytes, and #3134 added
/// `oci_blobs` (the same layer bytes, at their true physical size) as a second
/// source. Unioning both double-counts every OCI layer: a reporter measured
/// 3097 GB of `unique_bytes` against 1.14 TiB of real bucket usage (~2.7x).
///
/// The manifest JSON documents themselves are consequently not counted here.
/// That is a deliberate, bounded undercount: real manifests are a few KB each
/// (56k live manifests ≈ 164 MB on the reporting instance, ~0.01% of the
/// footprint), and there is no column holding their true object size to
/// substitute. Correcting `artifacts.size_bytes` instead was rejected on
/// purpose — it is the column `RepositoryService::check_quota` sums, so
/// rewriting it would silently loosen every OCI repository's quota.
///
/// [`PATH_REF_UNION_SQL`] deliberately keeps its `oci-manifests/%` rows: that
/// relation drives the *logical* per-path tree, where an image node is expected
/// to weigh the image, and layer blobs are excluded from it entirely (they
/// carry no path), so no double count arises there.
const REPO_OBJECT_UNION_SQL: &str = r#"
    SELECT repository_id, storage_key AS dedup_key, size_bytes
      FROM artifacts
     WHERE is_deleted = false
       AND storage_key NOT LIKE 'proxy-cache/%'
       AND storage_key NOT LIKE 'oci-manifests/%'
    UNION ALL
    SELECT repository_id, 'oci-blobs/' || digest AS dedup_key, size_bytes
      FROM oci_blobs
    UNION ALL
    SELECT repository_id, storage_key AS dedup_key, size_bytes
      FROM proxy_cache_artifacts
"#;

/// Whether a `dedup_key` counts toward the *physical* footprint computed from
/// [`REPO_OBJECT_UNION_SQL`].
///
/// Pure mirror of that relation's `artifacts` filter, so the exclusion rule is
/// unit-testable without a database and the SQL literal cannot drift from the
/// documented intent. Keys under
/// [`OCI_MANIFEST_STORAGE_PREFIX`](crate::storage::keys::OCI_MANIFEST_STORAGE_PREFIX)
/// carry the aggregate image size rather than the stored object size and are
/// counted through `oci_blobs` instead (#3286); `proxy-cache/%` leftovers are
/// counted through `proxy_cache_artifacts` (#2218 / #2531).
pub fn artifact_key_counts_toward_physical_footprint(dedup_key: &str) -> bool {
    !dedup_key.starts_with(crate::storage::keys::OCI_MANIFEST_STORAGE_PREFIX)
        && !dedup_key.starts_with(PROXY_CACHE_STORAGE_PREFIX)
}

/// Storage-key prefix of proxy-cached objects, excluded from the `artifacts`
/// arm of the union because those bytes are accounted through
/// `proxy_cache_artifacts` (#2218 / #2531).
const PROXY_CACHE_STORAGE_PREFIX: &str = "proxy-cache/";

// Pin the `oci-manifests/%` literal embedded in REPO_OBJECT_UNION_SQL to the
// Rust constant, the same guard `storage_gc_service` uses: Postgres cannot read
// Rust constants, so changing the prefix must fail the build here rather than
// silently un-fix #3286.
const _: () = assert!(crate::storage::keys::prefix_matches("oci-manifests/"));

/// The *path-bearing* subset of the repo-object union (#2601): one row per
/// reference that has a logical `path`, projected to
/// `(repository_id, path, dedup_key, size_bytes)`.
///
/// `oci_blobs` is deliberately absent: layer blobs carry no logical path (the
/// blob→image-name edge only exists inside manifest content, not the catalog),
/// so their bytes cannot be placed in the tree. They are surfaced separately
/// as the root node's `unattributed_bytes` so `root.logical_bytes +
/// unattributed_bytes` still reconciles with the repo-level logical total.
/// OCI *manifests* do have paths (`v2/<image>/manifests/<ref>` artifact rows),
/// so the tree still groups per image name at `v2/<image>/`.
const PATH_REF_UNION_SQL: &str = r#"
    SELECT repository_id, path, storage_key AS dedup_key, size_bytes
      FROM artifacts
     WHERE is_deleted = false
       AND storage_key NOT LIKE 'proxy-cache/%'
    UNION ALL
    SELECT repository_id, path, storage_key AS dedup_key, size_bytes
      FROM proxy_cache_artifacts
"#;

/// Maximum directory depth materialized into `repository_path_storage_stats`.
///
/// Caps the row-explosion factor of the prefix explode (each reference emits
/// one row per ancestor level): a pathological 1000-segment path contributes
/// to at most this many prefix nodes instead of 1000. Deeper files still
/// roll up into every ancestor at or above this depth; only nodes *below* it
/// are not individually materialized.
pub const MAX_MATERIALIZED_PATH_DEPTH: i32 = 16;

// The cap bounds the explode factor; keep it positive and small relative to
// real repo layouts (deepest common layouts are ~6-8 levels).
const _: () = assert!(MAX_MATERIALIZED_PATH_DEPTH >= 8 && MAX_MATERIALIZED_PATH_DEPTH <= 64);

/// Normalize a caller-supplied tree prefix to the canonical stored form:
/// no leading/trailing `/`, `''` = repository root.
pub fn normalize_prefix(raw: &str) -> String {
    raw.trim().trim_matches('/').to_string()
}

/// Number of path segments in a canonical prefix (`''` = 0, the root).
pub fn prefix_depth(prefix: &str) -> i32 {
    if prefix.is_empty() {
        0
    } else {
        prefix.split('/').count() as i32
    }
}

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
    /// total and upsert them, then refresh the per-path-prefix tree rollup
    /// (#2601). Run on the scheduler cadence and after GC.
    pub async fn recompute_all(&self) -> Result<()> {
        let rows = self.load_repo_object_rows().await?;
        let computed = compute_stats(&rows, self.scope);
        self.persist(&computed).await?;
        self.recompute_path_stats().await
    }

    /// Rebuild `repository_path_storage_stats` (#2601): one row per
    /// (repository, path prefix) with logical/physical/file/blob figures.
    ///
    /// Runs entirely set-based in Postgres — the path-bearing union is
    /// exploded into its ancestor prefixes (capped at
    /// [`MAX_MATERIALIZED_PATH_DEPTH`]) with a `generate_series` lateral,
    /// deduplicated per `(repo, prefix, dedup_key)`, aggregated per node, and
    /// inserted in one statement. Nothing is shipped to the app; API reads are
    /// then index lookups on the materialized rows (#2516 readiness).
    ///
    /// Delete + reinsert inside one transaction: readers never observe a
    /// partially-rebuilt tree, and pruned paths cannot leave stale rows. A
    /// transaction-scoped advisory lock serializes concurrent rebuilds (the
    /// cron tick can overlap a GC-triggered refresh) — the loser simply
    /// rebuilds again, which is idempotent. An incremental (trigger-maintained)
    /// variant is the deferred 1.7.0 perf follow-up alongside the P1 keyset
    /// recompute (#2056).
    pub async fn recompute_path_stats(&self) -> Result<()> {
        let mut tx = self
            .db
            .begin()
            .await
            .map_err(|e| AppError::Database(e.to_string()))?;

        // Serialize whole-table rebuilds: without this, two overlapping
        // refreshers both DELETE against the same snapshot and then collide on
        // the PK during reinsert. Released automatically at commit/rollback.
        sqlx::query(
            "SELECT pg_advisory_xact_lock(hashtext('repository_path_storage_stats_rebuild'))",
        )
        .execute(&mut *tx)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        sqlx::query("DELETE FROM repository_path_storage_stats")
            .execute(&mut *tx)
            .await
            .map_err(|e| AppError::Database(e.to_string()))?;

        // Explode each path-bearing reference into its ancestor prefixes:
        // depth 0 is the root (''), depth g is the first g segments joined by
        // '/'. The file's own full path is never a prefix node (g stops at
        // cardinality - 1), so leaves aggregate into their parent directory.
        let insert_sql = format!(
            r#"
            WITH path_ref AS ({union}),
            exploded AS (
                SELECT pr.repository_id,
                       pr.dedup_key,
                       pr.size_bytes,
                       g.depth,
                       CASE WHEN g.depth = 0 THEN ''
                            ELSE array_to_string((pr.segs)[1:g.depth], '/')
                       END AS prefix
                  FROM (SELECT repository_id, dedup_key, size_bytes,
                               string_to_array(trim(leading '/' from path), '/') AS segs
                          FROM path_ref) pr
                 CROSS JOIN LATERAL generate_series(
                     0, LEAST(cardinality(pr.segs) - 1, {max_depth})
                 ) AS g(depth)
            ),
            per_prefix_key AS (
                SELECT repository_id, prefix, depth, dedup_key,
                       MAX(size_bytes) AS size_bytes,
                       COUNT(*)        AS ref_count,
                       SUM(size_bytes) AS logical_bytes
                  FROM exploded
                 GROUP BY repository_id, prefix, depth, dedup_key
            )
            INSERT INTO repository_path_storage_stats
                (repository_id, prefix, depth, logical_bytes, physical_bytes,
                 file_count, blob_count, unattributed_bytes, computed_at)
            SELECT repository_id, prefix, depth,
                   COALESCE(SUM(logical_bytes), 0)::BIGINT,
                   COALESCE(SUM(size_bytes), 0)::BIGINT,
                   COALESCE(SUM(ref_count), 0)::BIGINT,
                   COUNT(*)::BIGINT,
                   0, now()
              FROM per_prefix_key
             GROUP BY repository_id, prefix, depth
            "#,
            union = PATH_REF_UNION_SQL,
            max_depth = MAX_MATERIALIZED_PATH_DEPTH,
        );
        sqlx::query(&insert_sql)
            .execute(&mut *tx)
            .await
            .map_err(|e| AppError::Database(e.to_string()))?;

        // OCI layer bytes have no logical path; record them on the root row so
        // the tree total still reconciles with the repo-level logical total.
        // The upsert also creates the root row for blob-only repositories.
        sqlx::query(
            r#"
            INSERT INTO repository_path_storage_stats
                (repository_id, prefix, depth, unattributed_bytes, computed_at)
            SELECT repository_id, '', 0, SUM(size_bytes)::BIGINT, now()
              FROM oci_blobs
             GROUP BY repository_id
            ON CONFLICT (repository_id, prefix) DO UPDATE
               SET unattributed_bytes = EXCLUDED.unattributed_bytes,
                   computed_at        = EXCLUDED.computed_at
            "#,
        )
        .execute(&mut *tx)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        tx.commit()
            .await
            .map_err(|e| AppError::Database(e.to_string()))
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

    // --- #3286: OCI manifest rows must not re-count layer bytes -------------

    #[test]
    fn oci_manifest_keys_are_excluded_from_the_physical_footprint() {
        // `artifacts.size_bytes` for an image manifest holds the aggregate
        // image size (config + layers), not the ~3 KB manifest object, so
        // counting it alongside `oci_blobs` double-counts every layer.
        assert!(!artifact_key_counts_toward_physical_footprint(
            "oci-manifests/sha256:deadbeef"
        ));
    }

    #[test]
    fn proxy_cache_keys_are_excluded_from_the_physical_footprint() {
        // Accounted through `proxy_cache_artifacts` instead (#2218 / #2531).
        assert!(!artifact_key_counts_toward_physical_footprint(
            "proxy-cache/repo/path/__content__"
        ));
    }

    #[test]
    fn real_artifact_keys_still_count_toward_the_physical_footprint() {
        for key in [
            "cas/aa/bb/sha256:beef",
            "maven/com/example/app/1.0/app-1.0.jar",
            "oci-blobs/sha256:beef",
            // Near-misses: only the exact prefixes are excluded.
            "oci-manifest/sha256:beef",
            "not-proxy-cache/x",
        ] {
            assert!(
                artifact_key_counts_toward_physical_footprint(key),
                "{key} must still be counted"
            );
        }
    }

    #[test]
    fn repo_object_union_excludes_both_non_physical_artifact_prefixes() {
        // The pure predicate above documents the rule; this pins the SQL that
        // actually implements it, so the two cannot drift (the compile-time
        // `prefix_matches` guard pins the literal to the Rust constant).
        assert!(
            REPO_OBJECT_UNION_SQL.contains("storage_key NOT LIKE 'oci-manifests/%'"),
            "REPO_OBJECT_UNION_SQL must exclude OCI manifest rows (#3286); their \
             size_bytes is the image size, already counted via oci_blobs"
        );
        assert!(
            REPO_OBJECT_UNION_SQL.contains("storage_key NOT LIKE 'proxy-cache/%'"),
            "REPO_OBJECT_UNION_SQL must keep excluding proxy-cache leftovers (#2218)"
        );
        // The path tree is a LOGICAL view and intentionally keeps manifests:
        // layer blobs carry no path, so it has no double count to fix.
        assert!(
            !PATH_REF_UNION_SQL.contains("oci-manifests"),
            "PATH_REF_UNION_SQL must keep OCI manifest rows so the per-image tree \
             node still weighs the image"
        );
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
    fn normalize_prefix_strips_slashes_and_whitespace() {
        assert_eq!(normalize_prefix(""), "");
        assert_eq!(normalize_prefix("/"), "");
        assert_eq!(normalize_prefix("a/b"), "a/b");
        assert_eq!(normalize_prefix("/a/b/"), "a/b");
        assert_eq!(normalize_prefix("  /a/b/  "), "a/b");
        assert_eq!(normalize_prefix("///"), "");
    }

    #[test]
    fn prefix_depth_counts_segments() {
        assert_eq!(prefix_depth(""), 0);
        assert_eq!(prefix_depth("a"), 1);
        assert_eq!(prefix_depth("a/b"), 2);
        assert_eq!(prefix_depth("v2/library/nginx"), 3);
    }

    #[test]
    fn path_union_excludes_pathless_oci_blobs() {
        // The tree union must never include oci_blobs (no logical path): those
        // bytes are surfaced as root `unattributed_bytes` instead. Guard the
        // SQL fragment against a drive-by "add the third source for parity".
        assert!(!PATH_REF_UNION_SQL.contains("oci_blobs"));
        assert!(PATH_REF_UNION_SQL.contains("FROM artifacts"));
        assert!(PATH_REF_UNION_SQL.contains("proxy_cache_artifacts"));
    }

    #[test]
    fn oci_blob_prefix_never_collides_with_manifests() {
        // OCI layer keys are namespaced away from artifacts.storage_key
        // (`oci-manifests/…`) so the union cannot merge distinct objects.
        assert!(OCI_BLOB_DEDUP_PREFIX.starts_with("oci-blobs/"));
        assert!(!"oci-manifests/abc".starts_with(OCI_BLOB_DEDUP_PREFIX));
    }
}

/// DB-backed tests for `recompute_path_stats` / `recompute_all` (#2601):
/// seed the three physical sources against a real Postgres and assert the
/// materialized `repository_path_storage_stats` rows. Each test creates its
/// own uniquely-keyed repository, so the whole-table rebuild (serialized by
/// the advisory lock, reading committed data) converges to the same rows for
/// this repo regardless of concurrently running peers. Skips cleanly when no
/// `DATABASE_URL` is configured; under [`crate::testing::REQUIRE_DB_ENV`]
/// (CI) an unreachable database fails loudly instead (#2924).
#[cfg(test)]
mod db_tests {
    use super::*;
    use crate::api::handlers::test_db_helpers as tdh;
    use sqlx::PgPool;

    async fn try_pool() -> Option<PgPool> {
        crate::testing::try_pool_with(3).await
    }

    fn unique(prefix: &str) -> String {
        format!("{}-{}", prefix, &Uuid::new_v4().to_string()[..8])
    }

    async fn insert_repo(pool: &PgPool, backend: &str) -> Uuid {
        let id = Uuid::new_v4();
        let key = unique("pstats-repo");
        sqlx::query(
            r#"
            INSERT INTO repositories (id, key, name, format, repo_type, storage_backend, storage_path, is_public)
            VALUES ($1, $2, $2, 'generic'::repository_format, 'local'::repository_type, $3, $4, true)
            "#,
        )
        .bind(id)
        .bind(&key)
        .bind(backend)
        .bind(format!("/data/{key}"))
        .execute(pool)
        .await
        .expect("failed to insert repository");
        id
    }

    async fn insert_artifact(pool: &PgPool, repo: Uuid, path: &str, storage_key: &str, size: i64) {
        sqlx::query(
            r#"
            INSERT INTO artifacts
                (id, repository_id, path, name, size_bytes, checksum_sha256,
                 content_type, storage_key, is_deleted)
            VALUES ($1, $2, $3, $3, $4, repeat('a', 64), 'application/octet-stream', $5, false)
            "#,
        )
        .bind(Uuid::new_v4())
        .bind(repo)
        .bind(path)
        .bind(size)
        .bind(storage_key)
        .execute(pool)
        .await
        .expect("failed to insert artifact");
    }

    async fn insert_oci_blob(pool: &PgPool, repo: Uuid, digest: &str, size: i64) {
        sqlx::query(
            r#"
            INSERT INTO oci_blobs (id, repository_id, digest, size_bytes, storage_key)
            VALUES ($1, $2, $3, $4, $5)
            "#,
        )
        .bind(Uuid::new_v4())
        .bind(repo)
        .bind(digest)
        .bind(size)
        .bind(format!("oci-blobs/{digest}"))
        .execute(pool)
        .await
        .expect("failed to insert oci blob");
    }

    async fn insert_proxy_cache(pool: &PgPool, repo: Uuid, path: &str, size: i64) {
        sqlx::query(
            r#"
            INSERT INTO proxy_cache_artifacts
                (id, repository_id, path, storage_key, metadata_key, size_bytes)
            VALUES ($1, $2, $3, $4, $5, $6)
            "#,
        )
        .bind(Uuid::new_v4())
        .bind(repo)
        .bind(path)
        .bind(format!("proxy-cache/{}/{}/__content__", repo, path))
        .bind(format!("proxy-cache/{}/{}/__cache_meta__.json", repo, path))
        .bind(size)
        .execute(pool)
        .await
        .expect("failed to insert proxy cache row");
    }

    #[derive(Debug)]
    struct Node {
        depth: i32,
        logical: i64,
        physical: i64,
        files: i64,
        blobs: i64,
        unattributed: i64,
    }

    async fn read_node(pool: &PgPool, repo: Uuid, prefix: &str) -> Option<Node> {
        sqlx::query_as::<_, (i32, i64, i64, i64, i64, i64)>(
            r#"
            SELECT depth, logical_bytes, physical_bytes, file_count, blob_count,
                   unattributed_bytes
              FROM repository_path_storage_stats
             WHERE repository_id = $1 AND prefix = $2
            "#,
        )
        .bind(repo)
        .bind(prefix)
        .fetch_optional(pool)
        .await
        .expect("query path stats")
        .map(
            |(depth, logical, physical, files, blobs, unattributed)| Node {
                depth,
                logical,
                physical,
                files,
                blobs,
                unattributed,
            },
        )
    }

    /// Rebuild only the per-prefix tree (the function under test here).
    async fn recompute_tree(pool: &PgPool) {
        tdh::recompute_storage_stats_with_retry(pool, false).await;
    }

    async fn cleanup(pool: &PgPool, repo: Uuid) {
        // `repository_path_storage_stats` cascades from `repositories`.
        let _ = sqlx::query("DELETE FROM repositories WHERE id = $1")
            .bind(repo)
            .execute(pool)
            .await;
    }

    #[tokio::test]
    async fn nested_prefixes_roll_up_every_ancestor_level_db() {
        let Some(pool) = try_pool().await else {
            return;
        };
        let _guard = tdh::path_stats_serial_lock().await;
        let repo = insert_repo(&pool, "filesystem").await;
        insert_artifact(&pool, repo, "libs/app/a.jar", &unique("cas/k"), 100).await;
        insert_artifact(&pool, repo, "libs/app/b.jar", &unique("cas/k"), 50).await;
        insert_artifact(&pool, repo, "libs/core/c.jar", &unique("cas/k"), 25).await;
        insert_artifact(&pool, repo, "top.txt", &unique("cas/k"), 10).await;

        // Full pipeline once: `recompute_all` chains the repo-level persist
        // AND the path rollup (#2601's change to it).
        tdh::recompute_storage_stats_with_retry(&pool, true).await;

        let root = read_node(&pool, repo, "").await.expect("root node");
        assert_eq!(root.depth, 0);
        assert_eq!(root.logical, 185, "root sums every reference");
        assert_eq!(root.files, 4);
        assert_eq!(root.blobs, 4);

        let libs = read_node(&pool, repo, "libs").await.expect("libs node");
        assert_eq!(libs.depth, 1);
        assert_eq!(libs.logical, 175);
        assert_eq!(libs.files, 3);

        let app = read_node(&pool, repo, "libs/app").await.expect("app node");
        assert_eq!(app.depth, 2);
        assert_eq!(app.logical, 150);
        assert_eq!(app.files, 2);

        let core = read_node(&pool, repo, "libs/core")
            .await
            .expect("core node");
        assert_eq!(core.logical, 25);
        assert_eq!(core.files, 1);

        // A file's full path is never itself a prefix node.
        assert!(read_node(&pool, repo, "top.txt").await.is_none());
        assert!(read_node(&pool, repo, "libs/app/a.jar").await.is_none());

        cleanup(&pool, repo).await;
    }

    #[tokio::test]
    async fn shared_object_counts_once_at_common_ancestor_db() {
        let Some(pool) = try_pool().await else {
            return;
        };
        let _guard = tdh::path_stats_serial_lock().await;
        let repo = insert_repo(&pool, "filesystem").await;
        // One CAS object referenced from two sibling subtrees (x twice, y once).
        let key = format!("cas/aa/bb/{}", Uuid::new_v4());
        insert_artifact(&pool, repo, "x/one.bin", &key, 1000).await;
        insert_artifact(&pool, repo, "x/two.bin", &key, 1000).await;
        insert_artifact(&pool, repo, "y/three.bin", &key, 1000).await;

        recompute_tree(&pool).await;

        let root = read_node(&pool, repo, "").await.expect("root node");
        assert_eq!(root.logical, 3000, "logical = every reference");
        assert_eq!(root.physical, 1000, "one physical object at the root");
        assert_eq!(root.files, 3);
        assert_eq!(root.blobs, 1);

        let x = read_node(&pool, repo, "x").await.expect("x node");
        assert_eq!(x.logical, 2000);
        assert_eq!(x.physical, 1000, "the object counts once within x");
        assert_eq!(x.blobs, 1);

        let y = read_node(&pool, repo, "y").await.expect("y node");
        assert_eq!(y.logical, 1000);
        assert_eq!(y.physical, 1000);

        // The dedup signal: children's physical sums past the parent's because
        // the shared object appears in both subtrees but once at the ancestor.
        assert!(x.physical + y.physical > root.physical);

        cleanup(&pool, repo).await;
    }

    #[tokio::test]
    async fn oci_layer_bytes_land_in_root_unattributed_db() {
        let Some(pool) = try_pool().await else {
            return;
        };
        let _guard = tdh::path_stats_serial_lock().await;
        let repo = insert_repo(&pool, "filesystem").await;
        // Manifests are path-bearing artifact rows; layers have no logical path.
        insert_artifact(
            &pool,
            repo,
            "v2/library/nginx/manifests/latest",
            &format!("oci-manifests/{}", Uuid::new_v4()),
            512,
        )
        .await;
        let layer = format!("sha256:{}", Uuid::new_v4().simple());
        insert_oci_blob(&pool, repo, &layer, 4096).await;

        recompute_tree(&pool).await;

        let root = read_node(&pool, repo, "").await.expect("root node");
        assert_eq!(root.logical, 512, "tree covers path-bearing rows only");
        assert_eq!(
            root.unattributed, 4096,
            "layer bytes surface as unattributed on the root"
        );
        // logical + unattributed reconciles with the repo-level logical total.
        assert_eq!(root.logical + root.unattributed, 512 + 4096);

        // The image still groups by name through its manifest path.
        let image = read_node(&pool, repo, "v2/library/nginx")
            .await
            .expect("image node");
        assert_eq!(image.logical, 512);
        assert_eq!(image.unattributed, 0, "unattributed is a root-only figure");

        cleanup(&pool, repo).await;
    }

    #[tokio::test]
    async fn blob_only_repo_gets_a_root_row_db() {
        let Some(pool) = try_pool().await else {
            return;
        };
        let _guard = tdh::path_stats_serial_lock().await;
        let repo = insert_repo(&pool, "filesystem").await;
        insert_oci_blob(
            &pool,
            repo,
            &format!("sha256:{}", Uuid::new_v4().simple()),
            2048,
        )
        .await;

        recompute_tree(&pool).await;

        let root = read_node(&pool, repo, "").await.expect("root node");
        assert_eq!(root.logical, 0);
        assert_eq!(root.unattributed, 2048);

        cleanup(&pool, repo).await;
    }

    #[tokio::test]
    async fn proxy_cache_rows_are_path_attributed_db() {
        let Some(pool) = try_pool().await else {
            return;
        };
        let _guard = tdh::path_stats_serial_lock().await;
        let repo = insert_repo(&pool, "filesystem").await;
        insert_proxy_cache(&pool, repo, "simple/click/click-8.0.0.whl", 300).await;

        recompute_tree(&pool).await;

        let root = read_node(&pool, repo, "").await.expect("root node");
        assert_eq!(root.logical, 300);
        let simple = read_node(&pool, repo, "simple").await.expect("simple node");
        assert_eq!(simple.logical, 300);
        let pkg = read_node(&pool, repo, "simple/click")
            .await
            .expect("package node");
        assert_eq!(pkg.logical, 300);
        assert_eq!(pkg.files, 1);

        cleanup(&pool, repo).await;
    }

    #[tokio::test]
    async fn recompute_prunes_stale_prefixes_db() {
        let Some(pool) = try_pool().await else {
            return;
        };
        let _guard = tdh::path_stats_serial_lock().await;
        let repo = insert_repo(&pool, "filesystem").await;
        insert_artifact(&pool, repo, "old/tree/file.bin", &unique("cas/k"), 100).await;

        recompute_tree(&pool).await;
        assert!(read_node(&pool, repo, "old/tree").await.is_some());

        // Soft-delete (the artifact-delete path): the reference must drop out
        // of the tree on the next rebuild, not linger as a stale row.
        sqlx::query("UPDATE artifacts SET is_deleted = true WHERE repository_id = $1")
            .bind(repo)
            .execute(&pool)
            .await
            .expect("soft-delete artifacts");

        recompute_tree(&pool).await;
        assert!(
            read_node(&pool, repo, "old/tree").await.is_none(),
            "stale prefix rows must be pruned by the rebuild"
        );

        cleanup(&pool, repo).await;
    }

    #[tokio::test]
    async fn pathological_deep_paths_are_depth_capped_db() {
        let Some(pool) = try_pool().await else {
            return;
        };
        let _guard = tdh::path_stats_serial_lock().await;
        let repo = insert_repo(&pool, "filesystem").await;
        // 40 segments: d1/d2/.../d40 — well past the materialization cap.
        let deep: Vec<String> = (1..=40).map(|i| format!("d{i}")).collect();
        insert_artifact(&pool, repo, &deep.join("/"), &unique("cas/k"), 100).await;

        recompute_tree(&pool).await;

        // Materialized exactly at the cap...
        let at_cap = deep[..MAX_MATERIALIZED_PATH_DEPTH as usize].join("/");
        let node = read_node(&pool, repo, &at_cap).await.expect("cap node");
        assert_eq!(node.depth, MAX_MATERIALIZED_PATH_DEPTH);
        assert_eq!(node.logical, 100, "deep file rolls up into the cap node");

        // ...but not below it.
        let below_cap = deep[..(MAX_MATERIALIZED_PATH_DEPTH as usize + 1)].join("/");
        assert!(read_node(&pool, repo, &below_cap).await.is_none());

        // Root still accounts for the file once.
        let root = read_node(&pool, repo, "").await.expect("root node");
        assert_eq!(root.logical, 100);
        assert_eq!(root.files, 1);

        cleanup(&pool, repo).await;
    }

    #[tokio::test]
    async fn leading_slash_paths_normalize_into_the_same_tree_db() {
        let Some(pool) = try_pool().await else {
            return;
        };
        let _guard = tdh::path_stats_serial_lock().await;
        let repo = insert_repo(&pool, "filesystem").await;
        insert_artifact(&pool, repo, "/abs/one.bin", &unique("cas/k"), 40).await;
        insert_artifact(&pool, repo, "abs/two.bin", &unique("cas/k"), 60).await;

        recompute_tree(&pool).await;

        let abs = read_node(&pool, repo, "abs").await.expect("abs node");
        assert_eq!(
            abs.logical, 100,
            "leading-slash and bare paths share one node"
        );
        assert_eq!(abs.files, 2);

        cleanup(&pool, repo).await;
    }
}
