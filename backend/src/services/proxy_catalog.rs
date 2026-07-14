//! Persisted proxy-cache catalog CRUD (#2218 accounting, #2270 visibility /
//! download counting).
//!
//! Proxy-cached objects deliberately carry NO `artifacts` row (#1280, which
//! fixed the #1278 doubled-prefix 500 on the filesystem backend). That left the
//! DB blind to proxy-cached bytes, so storage accounting, cache listing, and
//! download counting could not see them. This module owns the SEPARATE
//! `proxy_cache_artifacts` catalog table (migration 159) plus the sibling
//! `proxy_download_statistics` table (migration 160): a queryable index the
//! format-handler serve path never reads, so it cannot re-open #1278.
//!
//! The catalog row is upserted at sidecar-commit time inside
//! [`crate::services::proxy_service::CachePersister`] with the TRUE written
//! byte count + checksum, deleted on cache invalidation, and self-heals for
//! pre-existing objects via a best-effort lazy backfill on cache hit. The SQL
//! lives here (rather than inline in `proxy_service.rs`) so the near-duplicate
//! query bodies stay out of the jscpd Rust-duplication window and the write
//! path stays small.

use sqlx::PgPool;
use uuid::Uuid;

use crate::error::{AppError, Result};

/// One catalog row's browsable fields (visibility seam for #2270 / PF-002).
#[derive(Debug, Clone)]
pub struct ProxyCacheEntry {
    pub id: Uuid,
    pub repository_id: Uuid,
    pub path: String,
    pub storage_key: String,
    pub size_bytes: i64,
    pub checksum_sha256: Option<String>,
    pub content_type: Option<String>,
}

/// Upsert a catalog row at cache-write (sidecar-commit) time.
///
/// Keyed on `(repository_id, path)`: a re-cache of the same logical object
/// (a mutable index refreshed upstream, an overwrite) updates the size,
/// checksum, keys, content-type and upstream URL in place instead of drifting
/// into a duplicate row. `cached_at`/`last_accessed_at` are refreshed so the
/// row reflects the newest write. Best-effort at the call site: a failure here
/// must never fail the client's stream/response.
#[allow(clippy::too_many_arguments)]
pub async fn upsert(
    db: &PgPool,
    repository_id: Uuid,
    path: &str,
    storage_key: &str,
    metadata_key: &str,
    size_bytes: i64,
    checksum_sha256: Option<&str>,
    content_type: Option<&str>,
    upstream_url: Option<&str>,
) -> Result<()> {
    sqlx::query!(
        r#"
        INSERT INTO proxy_cache_artifacts
            (repository_id, path, storage_key, metadata_key, size_bytes,
             checksum_sha256, content_type, upstream_url, cached_at, last_accessed_at)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, now(), now())
        ON CONFLICT (repository_id, path) DO UPDATE SET
            storage_key      = EXCLUDED.storage_key,
            metadata_key     = EXCLUDED.metadata_key,
            size_bytes       = EXCLUDED.size_bytes,
            checksum_sha256  = EXCLUDED.checksum_sha256,
            content_type     = EXCLUDED.content_type,
            upstream_url     = EXCLUDED.upstream_url,
            cached_at        = now(),
            last_accessed_at = now()
        "#,
        repository_id,
        path,
        storage_key,
        metadata_key,
        size_bytes,
        checksum_sha256,
        content_type,
        upstream_url,
    )
    .execute(db)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;
    Ok(())
}

/// Lazy backfill for a pre-existing, un-cataloged cached object discovered on a
/// cache HIT.
///
/// `ON CONFLICT DO NOTHING` on the body fields (so a concurrent authoritative
/// write is never clobbered by a backfill guess) while still bumping
/// `last_accessed_at`, which doubles as the PF-002 lifecycle seam. Fire-and-
/// forget from the serve path — never blocks the response.
#[allow(clippy::too_many_arguments)]
pub async fn backfill_from_sidecar(
    db: &PgPool,
    repository_id: Uuid,
    path: &str,
    storage_key: &str,
    metadata_key: &str,
    size_bytes: i64,
    checksum_sha256: Option<&str>,
    content_type: Option<&str>,
) -> Result<()> {
    sqlx::query!(
        r#"
        INSERT INTO proxy_cache_artifacts
            (repository_id, path, storage_key, metadata_key, size_bytes,
             checksum_sha256, content_type, cached_at, last_accessed_at)
        VALUES ($1, $2, $3, $4, $5, $6, $7, now(), now())
        ON CONFLICT (repository_id, path) DO UPDATE SET
            last_accessed_at = now()
        "#,
        repository_id,
        path,
        storage_key,
        metadata_key,
        size_bytes,
        checksum_sha256,
        content_type,
    )
    .execute(db)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;
    Ok(())
}

/// Delete the catalog row for a purged cache entry, keyed on the physical
/// content storage key (`proxy-cache/<repo>/<path>/__content__`). Wired into
/// the `invalidate_cache*` paths so accounting does not drift when an entry is
/// evicted. Repo deletion is handled by `ON DELETE CASCADE`.
pub async fn delete_by_key(db: &PgPool, storage_key: &str) -> Result<u64> {
    let res = sqlx::query!(
        "DELETE FROM proxy_cache_artifacts WHERE storage_key = $1",
        storage_key
    )
    .execute(db)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;
    Ok(res.rows_affected())
}

/// Sum of cataloged proxy-cache bytes for one repository (#2218). The
/// accounting queries in `repositories.rs` / `repository_service.rs` inline the
/// equivalent UNION so hosted + proxy bytes come back in a single round trip;
/// this stand-alone helper backs the module's unit tests and any single-repo
/// caller that only needs the proxy figure.
pub async fn sum_by_repo(db: &PgPool, repository_id: Uuid) -> Result<i64> {
    let sum = sqlx::query_scalar!(
        r#"
        SELECT COALESCE(SUM(size_bytes), 0)::BIGINT AS "sum!"
        FROM proxy_cache_artifacts
        WHERE repository_id = $1
        "#,
        repository_id
    )
    .fetch_one(db)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;
    Ok(sum)
}

/// Keyset-paged catalog listing for one repository, ordered by `path`
/// (#2270 visibility / PF-002 seam). `after` is the last path from the previous
/// page (exclusive); pass `None` for the first page.
pub async fn list_paged(
    db: &PgPool,
    repository_id: Uuid,
    after: Option<&str>,
    limit: i64,
) -> Result<Vec<ProxyCacheEntry>> {
    let rows = sqlx::query!(
        r#"
        SELECT id, repository_id, path, storage_key, size_bytes,
               checksum_sha256, content_type
        FROM proxy_cache_artifacts
        WHERE repository_id = $1
          AND ($2::TEXT IS NULL OR path > $2)
        ORDER BY path
        LIMIT $3
        "#,
        repository_id,
        after,
        limit,
    )
    .fetch_all(db)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;

    Ok(rows
        .into_iter()
        .map(|r| ProxyCacheEntry {
            id: r.id,
            repository_id: r.repository_id,
            path: r.path,
            storage_key: r.storage_key,
            size_bytes: r.size_bytes,
            checksum_sha256: r.checksum_sha256,
            content_type: r.content_type,
        })
        .collect())
}

/// Record one proxy-served download into the sibling `proxy_download_statistics`
/// table (#2270 / #2260), resolving the catalog id for `(repository_id, path)`
/// inside the INSERT. Records nothing when no catalog row exists for the path
/// (e.g. a serve that never touched the cache). The caller applies the HEAD
/// guard, mirroring `artifact_service::record_download`'s `is_head` short
/// circuit so a metadata probe never inflates the count. Best-effort: a failure
/// is logged by the caller, never surfaced to the client.
pub async fn record_proxy_download(
    db: &PgPool,
    repository_id: Uuid,
    path: &str,
    user_id: Option<Uuid>,
    ip_address: Option<&str>,
    user_agent: Option<&str>,
) -> Result<u64> {
    let res = sqlx::query!(
        r#"
        INSERT INTO proxy_download_statistics
            (proxy_cache_id, user_id, ip_address, user_agent)
        SELECT id, $3, $4, $5
        FROM proxy_cache_artifacts
        WHERE repository_id = $1 AND path = $2
        "#,
        repository_id,
        path,
        user_id,
        ip_address,
        user_agent,
    )
    .execute(db)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;
    Ok(res.rows_affected())
}

/// Count of proxy downloads recorded for one repository's cached objects.
/// Backs analytics that `UNION ALL` the hosted `download_statistics` count with
/// the proxy sibling; exposed here so the union math lives beside the table.
pub async fn download_count_by_repo(db: &PgPool, repository_id: Uuid) -> Result<i64> {
    let count = sqlx::query_scalar!(
        r#"
        SELECT COUNT(*)::BIGINT AS "count!"
        FROM proxy_download_statistics pds
        JOIN proxy_cache_artifacts pca ON pca.id = pds.proxy_cache_id
        WHERE pca.repository_id = $1
        "#,
        repository_id
    )
    .fetch_one(db)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;
    Ok(count)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::handlers::test_db_helpers as tdh;
    use sqlx::PgPool;

    /// Insert a minimal remote `repositories` row so the catalog FK is
    /// satisfied, and return its id. Uses a unique key per call so the shared
    /// CI test database never collides across tests/reruns. Mirrors the
    /// minimal-insert pattern used elsewhere in the handler tests (only the
    /// NOT-NULL-without-default columns are supplied; a remote repo requires
    /// `upstream_url` per the `check_upstream_url` constraint).
    async fn insert_repo(pool: &PgPool) -> Uuid {
        let id = Uuid::new_v4();
        let key = format!("pcc-{}", id.simple());
        sqlx::query(
            "INSERT INTO repositories (id, key, name, storage_path, repo_type, format, upstream_url) \
             VALUES ($1, $2, $2, $3, 'remote'::repository_type, 'pypi'::repository_format, \
                     'https://pypi.org/simple/')",
        )
        .bind(id)
        .bind(&key)
        .bind(format!("/tmp/{key}"))
        .execute(pool)
        .await
        .expect("insert repo");
        id
    }

    /// Remove the repo (and, via `ON DELETE CASCADE`, its catalog +
    /// proxy-download rows) so the shared test DB stays clean.
    async fn cleanup_repo(pool: &PgPool, id: Uuid) {
        let _ = sqlx::query("DELETE FROM repositories WHERE id = $1")
            .bind(id)
            .execute(pool)
            .await;
    }

    #[tokio::test]
    async fn test_upsert_is_idempotent_and_updates_in_place() {
        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let repo = insert_repo(&pool).await;
        let path = "simple/click/click-8.0.0-py3-none-any.whl";
        let key = format!("proxy-cache/upsert/{path}/__content__");
        let meta = format!("proxy-cache/upsert/{path}/__cache_meta__.json");

        upsert(
            &pool,
            repo,
            path,
            &key,
            &meta,
            100,
            Some("aaa"),
            Some("application/octet-stream"),
            None,
        )
        .await
        .expect("first upsert");
        // Re-cache the SAME logical object with a new size/checksum (mutable
        // overwrite): must UPDATE in place, not create a second row.
        upsert(
            &pool,
            repo,
            path,
            &key,
            &meta,
            250,
            Some("bbb"),
            Some("application/octet-stream"),
            None,
        )
        .await
        .expect("second upsert");

        let rows = list_paged(&pool, repo, None, 100).await.unwrap();
        assert_eq!(rows.len(), 1, "dedup on (repo, path): exactly one row");
        assert_eq!(rows[0].size_bytes, 250, "size updated to the latest write");
        assert_eq!(rows[0].checksum_sha256.as_deref(), Some("bbb"));
        assert_eq!(sum_by_repo(&pool, repo).await.unwrap(), 250);
        cleanup_repo(&pool, repo).await;
    }

    #[tokio::test]
    async fn test_delete_by_key_removes_row() {
        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let repo = insert_repo(&pool).await;
        let key = format!("proxy-cache/{}/p/__content__", repo.simple());
        upsert(&pool, repo, "p", &key, "m", 42, Some("c"), None, None)
            .await
            .unwrap();
        assert_eq!(sum_by_repo(&pool, repo).await.unwrap(), 42);

        let deleted = delete_by_key(&pool, &key).await.unwrap();
        assert_eq!(deleted, 1, "one catalog row deleted on invalidate");
        assert_eq!(sum_by_repo(&pool, repo).await.unwrap(), 0);
        cleanup_repo(&pool, repo).await;
    }

    #[tokio::test]
    async fn test_backfill_inserts_then_does_not_clobber() {
        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let repo = insert_repo(&pool).await;
        let path = "simple/x/x-1.0.whl";
        let key = format!("proxy-cache/{}/k/__content__", repo.simple());

        // Absent -> backfill creates the row.
        backfill_from_sidecar(&pool, repo, path, &key, "m", 500, Some("sha"), None)
            .await
            .unwrap();
        let rows = list_paged(&pool, repo, None, 100).await.unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].size_bytes, 500);

        // Present -> a second backfill must NOT clobber the authoritative body
        // (ON CONFLICT DO NOTHING on size/checksum; only last_accessed bumps).
        backfill_from_sidecar(&pool, repo, path, &key, "m", 999, Some("other"), None)
            .await
            .unwrap();
        let rows = list_paged(&pool, repo, None, 100).await.unwrap();
        assert_eq!(rows.len(), 1, "still one row");
        assert_eq!(rows[0].size_bytes, 500, "backfill never overwrites size");
        assert_eq!(rows[0].checksum_sha256.as_deref(), Some("sha"));
        cleanup_repo(&pool, repo).await;
    }

    #[tokio::test]
    async fn test_record_proxy_download_counts_only_when_cataloged() {
        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let repo = insert_repo(&pool).await;
        let path = "simple/pkg/pkg-1.0.whl";
        let key = format!("proxy-cache/{}/k/__content__", repo.simple());

        // No catalog row yet -> nothing recorded.
        let n = record_proxy_download(&pool, repo, path, None, None, None)
            .await
            .unwrap();
        assert_eq!(n, 0, "no catalog row -> no proxy download recorded");
        assert_eq!(download_count_by_repo(&pool, repo).await.unwrap(), 0);

        upsert(&pool, repo, path, &key, "m", 10, Some("c"), None, None)
            .await
            .unwrap();

        let n = record_proxy_download(&pool, repo, path, None, Some("1.2.3.4"), Some("pip/24"))
            .await
            .unwrap();
        assert_eq!(n, 1, "cataloged object -> one proxy download recorded");
        record_proxy_download(&pool, repo, path, None, None, None)
            .await
            .unwrap();
        assert_eq!(download_count_by_repo(&pool, repo).await.unwrap(), 2);
        cleanup_repo(&pool, repo).await;
    }

    #[tokio::test]
    async fn test_list_paged_is_keyset_ordered() {
        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let repo = insert_repo(&pool).await;
        for p in ["a/1", "b/2", "c/3"] {
            upsert(
                &pool,
                repo,
                p,
                &format!("proxy-cache/{}/{p}/__content__", repo.simple()),
                "m",
                1,
                None,
                None,
                None,
            )
            .await
            .unwrap();
        }
        let first = list_paged(&pool, repo, None, 2).await.unwrap();
        assert_eq!(
            first.iter().map(|e| e.path.as_str()).collect::<Vec<_>>(),
            ["a/1", "b/2"]
        );
        let next = list_paged(&pool, repo, Some("b/2"), 2).await.unwrap();
        assert_eq!(
            next.iter().map(|e| e.path.as_str()).collect::<Vec<_>>(),
            ["c/3"]
        );
        cleanup_repo(&pool, repo).await;
    }

    /// Accounting UNION (#2218): a remote repo's `storage_used_bytes` sums the
    /// proxy-cache catalog, excludes legacy `proxy-cache/%` rows still in
    /// `artifacts` (dedup-safe), and includes hosted (non-proxy) artifact rows.
    #[tokio::test]
    async fn test_storage_usage_unions_catalog_and_excludes_legacy_proxy_rows() {
        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let repo = insert_repo(&pool).await;

        // Hosted (non-proxy) artifact row: counted.
        sqlx::query(
            "INSERT INTO artifacts (repository_id, path, name, size_bytes, checksum_sha256, \
             content_type, storage_key) VALUES ($1, 'a/hosted.whl', 'hosted.whl', 100, 'h', \
             'application/octet-stream', $2)",
        )
        .bind(repo)
        .bind(format!("{}/hosted.whl", repo.simple()))
        .execute(&pool)
        .await
        .expect("insert hosted artifact");

        // Legacy pre-#1280 proxy leftover row in `artifacts`: EXCLUDED so it is
        // not double counted against the catalog.
        sqlx::query(
            "INSERT INTO artifacts (repository_id, path, name, size_bytes, checksum_sha256, \
             content_type, storage_key) VALUES ($1, 'legacy', 'legacy', 500, 'l', \
             'application/octet-stream', $2)",
        )
        .bind(repo)
        .bind(format!("proxy-cache/{}/legacy/__content__", repo.simple()))
        .execute(&pool)
        .await
        .expect("insert legacy proxy artifact");

        // Catalog row: counted.
        upsert(
            &pool,
            repo,
            "simple/pkg/pkg.whl",
            &format!("proxy-cache/{}/k/__content__", repo.simple()),
            "m",
            250,
            Some("c"),
            None,
            None,
        )
        .await
        .unwrap();

        let usage = crate::services::repository_service::RepositoryService::new(pool.clone())
            .get_storage_usage(repo)
            .await
            .expect("storage usage");
        assert_eq!(
            usage, 350,
            "hosted(100) + catalog(250); legacy proxy-cache/% artifact(500) excluded"
        );
        cleanup_repo(&pool, repo).await;
    }
}
