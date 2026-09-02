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

/// True when a stored catalog row is the transient placeholder
/// [`record_proxy_download`] inserts on the request path (`size_bytes = 0`,
/// `checksum_sha256 IS NULL`) rather than an authoritative row written by the
/// tee's [`upsert`].
///
/// Pure mirror of the `ON CONFLICT` guard in [`backfill_from_sidecar`], kept in
/// Rust so the placeholder definition has one testable statement and cannot
/// drift from the SQL that applies it.
///
/// Both conditions are required. A genuinely cached zero-byte object still
/// carries its checksum, so it is never mistaken for a placeholder — and even
/// if it were, the sidecar would repair it to the same `size_bytes = 0`.
pub fn is_placeholder_catalog_row(size_bytes: i64, checksum_sha256: Option<&str>) -> bool {
    size_bytes == 0 && checksum_sha256.is_none()
}

/// Lazy backfill for a pre-existing, un-cataloged cached object discovered on a
/// cache HIT.
///
/// Inserts the row when absent. When a row already exists the conflict arm
/// **repairs it if it is still a placeholder** (#3305) and otherwise leaves the
/// authoritative body fields untouched, always bumping `last_accessed_at`
/// (which doubles as the PF-002 lifecycle seam). Fire-and-forget from the serve
/// path — never blocks the response, and safely skippable (the bounded limiter
/// added in #3289 drops these under saturation; the next hit retries).
///
/// # Why the conflict arm has to repair (#3305)
///
/// `record_proxy_download` is awaited *inline on the request* and ensures a
/// catalog row for `(repository_id, path)` so the first serve counts (#2537),
/// inserting a placeholder with `size_bytes = 0` and a NULL checksum. The
/// backfill runs detached and therefore normally *loses* that race. While the
/// conflict arm only touched `last_accessed_at`, the losing backfill returned
/// without ever writing the real size / checksum / content type, and nothing
/// else repaired the row — so the #2218 / #2270 self-healing this function
/// exists for was inert for exactly the pre-catalog entries it targets, and
/// storage accounting read zeros for them.
///
/// Since the placeholder insert is on the request path, the backfill is by
/// definition almost always an UPDATE; the conflict arm is the path that
/// matters. Repair is scoped by [`is_placeholder_catalog_row`] so a genuinely
/// populated row is never overwritten by a stale sidecar guess — the original
/// no-clobber contract still holds for every authoritative row.
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
            storage_key = CASE
                WHEN proxy_cache_artifacts.size_bytes = 0
                 AND proxy_cache_artifacts.checksum_sha256 IS NULL
                THEN EXCLUDED.storage_key ELSE proxy_cache_artifacts.storage_key END,
            metadata_key = CASE
                WHEN proxy_cache_artifacts.size_bytes = 0
                 AND proxy_cache_artifacts.checksum_sha256 IS NULL
                THEN EXCLUDED.metadata_key ELSE proxy_cache_artifacts.metadata_key END,
            size_bytes = CASE
                WHEN proxy_cache_artifacts.size_bytes = 0
                 AND proxy_cache_artifacts.checksum_sha256 IS NULL
                THEN EXCLUDED.size_bytes ELSE proxy_cache_artifacts.size_bytes END,
            content_type = CASE
                WHEN proxy_cache_artifacts.size_bytes = 0
                 AND proxy_cache_artifacts.checksum_sha256 IS NULL
                THEN EXCLUDED.content_type ELSE proxy_cache_artifacts.content_type END,
            -- Assigned LAST: the guard reads the stored checksum, and an
            -- UPDATE SET list evaluates every right-hand side against the OLD
            -- row, so ordering is presentational only. Kept last regardless so
            -- the guard column is visibly the one being replaced.
            checksum_sha256 = CASE
                WHEN proxy_cache_artifacts.size_bytes = 0
                 AND proxy_cache_artifacts.checksum_sha256 IS NULL
                THEN EXCLUDED.checksum_sha256 ELSE proxy_cache_artifacts.checksum_sha256 END,
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

// ---------------------------------------------------------------------------
// Cached INDEX responses vs cached ARTIFACTS
// ---------------------------------------------------------------------------
//
// A pull-through cache stores the upstream INDEX responses next to the package
// files, in the same table and with the same shape:
//
//     simple/idna/                           text/html              26281
//     simple/idna/idna-3.18-py3-none-any.whl binary/octet-stream    65455
//
// The `simple/<pkg>/` row is a cached HTML index page, not an artifact. Left
// unfiltered it renders in the artifact listing with an EMPTY name column, and
// -- worse -- it counts as an unscanned item in the proxy scan summary, where
// it is a permanent false positive: an HTML index has no package inventory, so
// no scan can ever clear it and the operator is shown an "unknown" status with
// no available remedy.
//
// These rows are NOT deleted and caching them is not changed: they are real
// cache entries occupying real bytes, so storage accounting
// ([`sum_by_repo`] and the repository usage rollups) deliberately still counts
// them. Only their PRESENTATION as artifacts and their inclusion in scan counts
// is wrong.
//
// CONSEQUENCE, and it is the correct trade: a repository's storage total no
// longer reconciles with the sum of its listed artifacts' sizes. The listing
// answers "what packages are cached here", storage answers "what bytes are on
// disk", and index responses are bytes that are not packages. Any future
// reconciliation check between the two must account for index rows rather than
// "fixing" this filter.
//
// The definition lives HERE, once, and is consumed by both the artifact listing
// ([`browse_page`] / [`browse_count`]) and every proxy-scan query in
// `api::handlers::security`. Two copies would drift and the two views would
// disagree again, which is the bug this exists to prevent --
// `cached_index_sql_and_rust_agree` pins the SQL and Rust forms to each other.

/// Basename of the PEP 691 JSON index response. Its HTML sibling has no
/// basename of its own -- the upstream URL ends in `/`, so the cached path
/// does too, which is the other half of [`is_cached_index_path`].
pub const CACHED_INDEX_BASENAME: &str = "index.v1+json";

/// True when `path` names a cached upstream index/metadata response rather
/// than a package artifact.
///
/// Deliberately narrow. It matches a trailing `/` and an EXACT basename, never
/// a substring: `simple/index/index-1.0.whl` and `pkg/my-index.v1+json` are
/// real artifacts and must keep listing and scanning normally.
pub fn is_cached_index_path(path: &str) -> bool {
    path.ends_with('/') || path.rsplit('/').next() == Some(CACHED_INDEX_BASENAME)
}

/// The SQL form of [`is_cached_index_path`], for `path_column` (pass a
/// qualified `alias.path` when the query joins). Interpolated rather than
/// bound because it is composed into projections shared across several
/// queries; [`CACHED_INDEX_BASENAME`] is a compile-time constant containing no
/// quote or `LIKE` metacharacter, which `cached_index_basename_is_sql_safe`
/// enforces.
pub fn cached_index_sql(path_column: &str) -> String {
    format!(
        "({c} LIKE '%/' OR {c} = '{b}' OR {c} LIKE '%/{b}')",
        c = path_column,
        b = CACHED_INDEX_BASENAME
    )
}

/// Negation of [`cached_index_sql`], i.e. "this row is a real artifact".
pub fn not_cached_index_sql(path_column: &str) -> String {
    format!("NOT {}", cached_index_sql(path_column))
}

/// One catalog row as surfaced by the remote-repository browse listing
/// (PF-002 / #2519). Unlike [`ProxyCacheEntry`] this carries `cached_at`, so
/// the listing can render the cache timestamp without reading the storage
/// sidecar for each page item.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct ProxyCacheBrowseRow {
    pub path: String,
    pub size_bytes: i64,
    pub checksum_sha256: Option<String>,
    pub content_type: Option<String>,
    pub cached_at: chrono::DateTime<chrono::Utc>,
}

/// Whether ANY catalog row exists for the repository. O(1) via the
/// `(repository_id, path)` unique index. The browse listing uses this to
/// decide between catalog-backed keyset paging (PF-002 / #2519) and the
/// legacy storage-prefix reconstruction for pre-catalog caches that have no
/// rows yet.
pub async fn has_rows(db: &PgPool, repository_id: Uuid) -> Result<bool> {
    let exists = sqlx::query_scalar!(
        r#"
        SELECT EXISTS(
            SELECT 1 FROM proxy_cache_artifacts WHERE repository_id = $1
        ) AS "exists!"
        "#,
        repository_id
    )
    .fetch_one(db)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;
    Ok(exists)
}

/// One keyset page of the remote-repository browse listing (PF-002 / #2519),
/// ordered by `path` and examining O(page) rows via the `(repository_id,
/// path)` unique index — never the whole cached set.
///
/// `prefix_like` / `q_like` are complete, pre-escaped `LIKE` patterns (the
/// caller appends/wraps `%` around `escape_like_literal` output) matched
/// under `ESCAPE '\'`; `q_like` matches case-insensitively (`ILIKE`),
/// mirroring the legacy in-memory substring filter. `after_path` is the last
/// path of the previous page (exclusive keyset bound); `offset` supports the
/// legacy `page=N` addressing when no cursor is supplied (pass 0 with a
/// cursor). The caller passes `limit = per_page + 1` and uses the extra row
/// as the authoritative `has_more` signal (#2520 pattern).
///
/// Cached index responses ([`is_cached_index_path`]) are excluded: they are
/// cache entries, not artifacts, and listing them produced rows with an empty
/// name. They remain in the table and in storage accounting.
pub async fn browse_page(
    db: &PgPool,
    repository_id: Uuid,
    prefix_like: Option<&str>,
    q_like: Option<&str>,
    after_path: Option<&str>,
    offset: i64,
    limit: i64,
) -> Result<Vec<ProxyCacheBrowseRow>> {
    // Composed rather than a `query!` literal so the index-response filter is
    // the SAME expression the scan queries use -- see the module note above.
    let rows = sqlx::query_as::<_, ProxyCacheBrowseRow>(sqlx::AssertSqlSafe(&*format!(
        r#"
        SELECT path, size_bytes, checksum_sha256, content_type, cached_at
        FROM proxy_cache_artifacts
        WHERE repository_id = $1
          AND ($2::TEXT IS NULL OR path LIKE $2 ESCAPE '\')
          AND ($3::TEXT IS NULL OR path ILIKE $3 ESCAPE '\')
          AND ($4::TEXT IS NULL OR path > $4)
          AND {not_index}
        ORDER BY path
        LIMIT $5 OFFSET $6
        "#,
        not_index = not_cached_index_sql("path"),
    )))
    .bind(repository_id)
    .bind(prefix_like)
    .bind(q_like)
    .bind(after_path)
    .bind(limit)
    .bind(offset)
    .fetch_all(db)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;

    Ok(rows)
}

/// Exact match count for [`browse_page`]'s filters, behind the listing's
/// explicit `?count=exact` opt-in (#2520 pattern): the default response
/// reports a cheap lower-bound total plus an authoritative `has_more`.
///
/// Excludes cached index responses on the same terms as [`browse_page`], so
/// the count matches the rows the listing actually returns.
pub async fn browse_count(
    db: &PgPool,
    repository_id: Uuid,
    prefix_like: Option<&str>,
    q_like: Option<&str>,
) -> Result<i64> {
    let count = sqlx::query_scalar::<_, i64>(sqlx::AssertSqlSafe(&*format!(
        r#"
        SELECT COUNT(*)::BIGINT
        FROM proxy_cache_artifacts
        WHERE repository_id = $1
          AND ($2::TEXT IS NULL OR path LIKE $2 ESCAPE '\')
          AND ($3::TEXT IS NULL OR path ILIKE $3 ESCAPE '\')
          AND {not_index}
        "#,
        not_index = not_cached_index_sql("path"),
    )))
    .bind(repository_id)
    .bind(prefix_like)
    .bind(q_like)
    .fetch_one(db)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;
    Ok(count)
}

/// Every cached object path living under any of `path_prefixes`, ordered by
/// `path` and bounded by `limit` (#3270).
///
/// Mirrors the hosted-side `ArtifactService::list_by_path_prefixes` (same
/// `LIKE ANY` shape, same "caller supplies directory prefixes" contract) so
/// the remote Maven grouped listing can fill in each component's file list
/// from the proxy cache catalog the way the hosted one fills it from the
/// `artifacts` table. The caller passes O(page) prefixes and re-checks the
/// prefix in Rust, so an artifactId containing a `LIKE` wildcard (`_` is
/// legal in Maven coordinates) can only over-fetch, never mis-attribute; the
/// patterns are wrapped in [`crate::api::handlers::like_any_overmatch_accepted`]
/// to say so in code (#3557).
pub async fn paths_under_prefixes(
    db: &PgPool,
    repository_id: Uuid,
    path_prefixes: &[String],
    limit: i64,
) -> Result<Vec<String>> {
    if path_prefixes.is_empty() || limit <= 0 {
        return Ok(Vec::new());
    }
    let patterns: Vec<String> = path_prefixes
        .iter()
        .map(|p| crate::api::handlers::like_any_overmatch_accepted(format!("{}%", p)))
        .collect();

    // Runtime-checked (not `query!`): keeps the offline `.sqlx` cache
    // untouched, matching `list_by_path_prefixes`'s untyped `LIKE ANY` query.
    let paths: Vec<String> = sqlx::query_scalar(
        r#"
        SELECT path
        FROM proxy_cache_artifacts
        WHERE repository_id = $1
          AND path LIKE ANY($2)
        ORDER BY path
        LIMIT $3
        "#,
    )
    .bind(repository_id)
    .bind(&patterns[..])
    .bind(limit)
    .fetch_all(db)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;

    Ok(paths)
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

/// One catalog row by `(repository_id, path)` -- the exact uniqueness key --
/// for the on-demand rescan path (#3396).
///
/// Scoped to `repository_id` and returning `None` for both "no such path" and
/// "that path is another repository's", so the caller's 404 is not a
/// cross-tenant existence oracle.
pub async fn find_cached_entry(
    db: &PgPool,
    repository_id: Uuid,
    path: &str,
) -> Result<Option<ProxyCacheEntry>> {
    let row = sqlx::query!(
        r#"
        SELECT id, repository_id, path, storage_key, size_bytes,
               checksum_sha256, content_type
        FROM proxy_cache_artifacts
        WHERE repository_id = $1 AND path = $2
        "#,
        repository_id,
        path,
    )
    .fetch_optional(db)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;

    Ok(row.map(|r| ProxyCacheEntry {
        id: r.id,
        repository_id: r.repository_id,
        path: r.path,
        storage_key: r.storage_key,
        size_bytes: r.size_bytes,
        checksum_sha256: r.checksum_sha256,
        content_type: r.content_type,
    }))
}

/// Record one proxy-served download into the sibling `proxy_download_statistics`
/// table (#2270 / #2260), counted against the `proxy_cache_artifacts` catalog
/// row for `(repository_id, path)`.
///
/// On a cache MISS the authoritative catalog row is written asynchronously by
/// the streaming tee, and only once the client has fully consumed the body
/// (`CachePersister::tee_stream`'s commit arm). It therefore does not yet exist
/// when the serve is recorded, which previously made the FIRST download of each
/// freshly-cached object record +0 while every subsequent hit counted (#2537).
/// To make the first serve count, this ensures a catalog row for
/// `(repository_id, path)` exists — inserting a transient placeholder (`size 0`,
/// `checksum NULL`) the tee later refines IN PLACE with the true size/checksum
/// via its own `ON CONFLICT (repository_id, path) DO UPDATE` upsert — and
/// records the serve against that row's id, in one statement. `storage_key` /
/// `metadata_key` are the derived proxy-cache keys for the placeholder; both are
/// overwritten by the tee's authoritative upsert (and are only used when this
/// call actually inserts the row). A cache HIT (row already present) leaves the
/// authoritative body fields untouched and only bumps `last_accessed_at`, then
/// records — so exactly one `proxy_download_statistics` row is written per
/// serve, with no double count and the proxy sibling kept fully separate from
/// the hot `download_statistics` table.
///
/// The caller applies the HEAD guard, mirroring
/// `artifact_service::record_download`'s `is_head` short circuit so a metadata
/// probe never inflates the count. Best-effort: a failure is logged by the
/// caller, never surfaced to the client.
#[allow(clippy::too_many_arguments)]
pub async fn record_proxy_download(
    db: &PgPool,
    repository_id: Uuid,
    path: &str,
    storage_key: &str,
    metadata_key: &str,
    user_id: Option<Uuid>,
    ip_address: Option<&str>,
    user_agent: Option<&str>,
) -> Result<u64> {
    let res = sqlx::query!(
        r#"
        WITH ensured AS (
            INSERT INTO proxy_cache_artifacts
                (repository_id, path, storage_key, metadata_key, size_bytes,
                 cached_at, last_accessed_at)
            VALUES ($1, $2, $3, $4, 0, now(), now())
            ON CONFLICT (repository_id, path) DO UPDATE SET
                last_accessed_at = now()
            RETURNING id
        )
        INSERT INTO proxy_download_statistics
            (proxy_cache_id, user_id, ip_address, user_agent)
        SELECT id, $5, $6, $7 FROM ensured
        "#,
        repository_id,
        path,
        storage_key,
        metadata_key,
        user_id,
        ip_address,
        user_agent,
    )
    .execute(db)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;
    Ok(res.rows_affected())
}

/// Recorded proxy-download counts for the given cached `paths`, keyed by path
/// (#3265). Paths with no recorded serve are absent from the map; the caller
/// substitutes zero.
///
/// Batched (`= ANY`) so a listing page costs one query rather than one per
/// row, mirroring `ArtifactService::get_download_stats_batch` on the hosted
/// side. Runtime-checked so the offline `.sqlx` cache is untouched.
pub async fn download_counts_by_paths(
    db: &PgPool,
    repository_id: Uuid,
    paths: &[String],
) -> Result<std::collections::HashMap<String, i64>> {
    if paths.is_empty() {
        return Ok(std::collections::HashMap::new());
    }
    let rows: Vec<(String, i64)> = sqlx::query_as(
        r#"
        SELECT a.path, COUNT(d.id)::BIGINT
        FROM proxy_cache_artifacts a
        LEFT JOIN proxy_download_statistics d ON d.proxy_cache_id = a.id
        WHERE a.repository_id = $1
          AND a.path = ANY($2)
        GROUP BY a.path
        "#,
    )
    .bind(repository_id)
    .bind(paths)
    .fetch_all(db)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;

    Ok(rows.into_iter().collect())
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

    /// Sample paths spanning both sides of the index/artifact boundary,
    /// including the near-misses that a substring match would wrongly catch.
    /// Shared by the Rust-side and SQL-side assertions so both are pinned to
    /// exactly the same expectations.
    const INDEX_PATH_SAMPLES: &[(&str, bool)] = &[
        // Cached upstream index responses.
        ("simple/idna/", true),
        ("simple/pyyaml/", true),
        ("simple/", true),
        ("simple/idna/index.v1+json", true),
        ("index.v1+json", true),
        // Real artifacts. None of these may ever be filtered out.
        ("simple/idna/idna-3.18-py3-none-any.whl", false),
        ("simple/pyyaml/PyYAML-5.3.1.tar.gz", false),
        // Near-misses: a package literally named `index`, and a file whose
        // name merely ENDS with the index basename. Substring matching would
        // silently hide both from the listing and from the scan counts.
        ("simple/index/index-1.0.tar.gz", false),
        ("simple/foo/my-index.v1+json", false),
        ("simple/foo/index.v1+json.asc", false),
        ("simple/foo/bar.whl", false),
    ];

    #[test]
    fn is_cached_index_path_matches_indexes_and_spares_artifacts() {
        for (path, expected) in INDEX_PATH_SAMPLES {
            assert_eq!(
                is_cached_index_path(path),
                *expected,
                "is_cached_index_path({:?}) should be {}",
                path,
                expected
            );
        }
    }

    /// [`cached_index_sql`] interpolates [`CACHED_INDEX_BASENAME`] into a SQL
    /// string literal and into `LIKE` patterns. Guard the two assumptions that
    /// makes: no quote (which would break out of the literal) and no `LIKE`
    /// metacharacter (which would silently widen the match).
    #[test]
    fn cached_index_basename_is_sql_safe() {
        for bad in ['\'', '%', '_', '\\'] {
            assert!(
                !CACHED_INDEX_BASENAME.contains(bad),
                "CACHED_INDEX_BASENAME must not contain {:?}; it is interpolated \
                 into a SQL literal and a LIKE pattern",
                bad
            );
        }
        let sql = cached_index_sql("pca.path");
        assert!(sql.contains("pca.path LIKE '%/'"));
        assert!(not_cached_index_sql("path").starts_with("NOT ("));
    }

    /// THE anti-drift test. [`is_cached_index_path`] and [`cached_index_sql`]
    /// are two encodings of one definition -- one used in Rust, one pushed into
    /// Postgres -- and the whole point of this predicate is that the artifact
    /// listing and the proxy-scan counts agree about what an artifact is.
    /// Evaluate the SQL form in the database over every sample and require it
    /// to return exactly what the Rust form returns.
    #[tokio::test]
    async fn cached_index_sql_and_rust_agree() {
        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let paths: Vec<String> = INDEX_PATH_SAMPLES
            .iter()
            .map(|(p, _)| (*p).to_string())
            .collect();
        // Evaluate the predicate in Postgres against the samples as a values
        // list, so no catalog rows (and no repository fixture) are needed.
        let sql = format!(
            "SELECT s.path, {} AS is_index FROM UNNEST($1::TEXT[]) AS s(path) ORDER BY s.path",
            cached_index_sql("s.path")
        );
        let rows: Vec<(String, bool)> = sqlx::query_as(sqlx::AssertSqlSafe(&*sql))
            .bind(&paths)
            .fetch_all(&pool)
            .await
            .expect("evaluate cached_index_sql in postgres");
        assert_eq!(rows.len(), INDEX_PATH_SAMPLES.len());
        for (path, sql_says) in rows {
            assert_eq!(
                sql_says,
                is_cached_index_path(&path),
                "SQL and Rust disagree about {:?}: SQL={}, Rust={}",
                path,
                sql_says,
                is_cached_index_path(&path)
            );
        }
    }

    /// The artifact listing must not surface cached index responses -- they
    /// rendered with an empty Name column -- while storage accounting must
    /// still count their bytes. Both halves in one test so a "fix" that simply
    /// stops caching or deletes the rows fails here.
    #[tokio::test]
    async fn browse_excludes_index_responses_but_storage_still_counts_them() {
        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let repo = insert_repo(&pool).await;
        let seed = |path: &'static str, size: i64| {
            let pool = pool.clone();
            async move {
                upsert(
                    &pool,
                    repo,
                    path,
                    &format!("proxy-cache/idx/{path}/__content__"),
                    &format!("proxy-cache/idx/{path}/__cache_meta__.json"),
                    size,
                    Some("d"),
                    Some("text/html"),
                    None,
                )
                .await
                .expect("seed");
            }
        };
        seed("simple/idna/", 26281).await;
        seed("simple/idna/index.v1+json", 1000).await;
        seed("simple/idna/idna-3.18-py3-none-any.whl", 65455).await;
        // Near-miss artifact: must survive the filter.
        seed("simple/index/index-1.0.tar.gz", 20).await;

        let rows = browse_page(&pool, repo, None, None, None, 0, 50)
            .await
            .expect("browse");
        let listed: Vec<&str> = rows.iter().map(|r| r.path.as_str()).collect();
        assert_eq!(
            listed,
            vec![
                "simple/idna/idna-3.18-py3-none-any.whl",
                "simple/index/index-1.0.tar.gz"
            ],
            "only real artifacts are listed"
        );
        assert!(
            rows.iter().all(|r| !r.path.ends_with('/')),
            "no empty-name rows"
        );
        assert_eq!(
            browse_count(&pool, repo, None, None).await.expect("count"),
            2,
            "the exact count must match the rows the listing returns"
        );

        // Storage accounting is deliberately NOT filtered: the index responses
        // are real cached bytes on disk. This is why a repository's storage
        // total no longer reconciles with the sum of its listed artifacts.
        assert_eq!(
            sum_by_repo(&pool, repo).await.expect("sum"),
            26281 + 1000 + 65455 + 20,
            "storage accounting must still see cached index responses"
        );

        cleanup_repo(&pool, repo).await;
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

    // --- #3305: the backfill must repair the placeholder row it races -------

    #[test]
    fn placeholder_predicate_needs_zero_size_and_null_checksum() {
        assert!(
            is_placeholder_catalog_row(0, None),
            "the row record_proxy_download inserts is the placeholder"
        );
        assert!(
            !is_placeholder_catalog_row(4096, None),
            "a sized row is authoritative even without a checksum"
        );
        assert!(
            !is_placeholder_catalog_row(0, Some("abc")),
            "a genuinely cached zero-byte object carries its checksum"
        );
        assert!(!is_placeholder_catalog_row(4096, Some("abc")));
    }

    /// #3305 regression test. `record_proxy_download` is awaited inline on the
    /// request and inserts a `size_bytes = 0` placeholder; the lazy backfill
    /// runs detached and normally loses that race. Before the fix its conflict
    /// arm only bumped `last_accessed_at`, so the placeholder was permanent and
    /// the #2218/#2270 self-healing was inert.
    ///
    /// The foreground insert is made to win DETERMINISTICALLY here (it is
    /// simply called first), and the assertions are on the REPAIRED VALUES —
    /// asserting a row merely exists, or that the backfill "ran", would pass
    /// with the bug in place.
    #[tokio::test]
    async fn test_backfill_repairs_the_placeholder_row_it_races() {
        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let repo = insert_repo(&pool).await;
        let path = "simple/racy/racy-2.0.whl";
        let key = format!("proxy-cache/{}/{path}/__content__", repo.simple());
        let meta = format!("proxy-cache/{}/{path}/__cache_meta__.json", repo.simple());

        // 1. The request path wins the race and leaves a placeholder.
        record_proxy_download(&pool, repo, path, &key, &meta, None, None, None)
            .await
            .expect("record serve");
        let rows = list_paged(&pool, repo, None, 100).await.unwrap();
        assert_eq!(rows.len(), 1);
        assert!(
            is_placeholder_catalog_row(rows[0].size_bytes, rows[0].checksum_sha256.as_deref()),
            "precondition: the foreground insert left a placeholder"
        );

        // 2. The detached backfill arrives second and must REPAIR it.
        backfill_from_sidecar(
            &pool,
            repo,
            path,
            &key,
            &meta,
            8192,
            Some("realchecksum"),
            Some("application/octet-stream"),
        )
        .await
        .expect("backfill");

        let rows = list_paged(&pool, repo, None, 100).await.unwrap();
        assert_eq!(rows.len(), 1, "still exactly one row");
        assert_eq!(
            rows[0].size_bytes, 8192,
            "the placeholder's size must be repaired from the sidecar (#3305)"
        );
        assert_eq!(
            rows[0].checksum_sha256.as_deref(),
            Some("realchecksum"),
            "the placeholder's checksum must be repaired from the sidecar (#3305)"
        );
        assert_eq!(
            rows[0].content_type.as_deref(),
            Some("application/octet-stream"),
            "the placeholder's content type must be repaired from the sidecar (#3305)"
        );
        assert_eq!(
            sum_by_repo(&pool, repo).await.unwrap(),
            8192,
            "storage accounting must stop reading zeros for repaired entries"
        );
        cleanup_repo(&pool, repo).await;
    }

    /// The repair is scoped to placeholders: a genuinely cached zero-byte
    /// object (size 0 WITH a checksum) is authoritative and a later sidecar
    /// guess must not overwrite it.
    #[tokio::test]
    async fn test_backfill_does_not_repair_an_authoritative_zero_byte_row() {
        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let repo = insert_repo(&pool).await;
        let path = "simple/empty/empty-1.0.whl";
        let key = format!("proxy-cache/{}/{path}/__content__", repo.simple());

        upsert(
            &pool,
            repo,
            path,
            &key,
            "m",
            0,
            Some("e3b0c442"),
            None,
            None,
        )
        .await
        .expect("authoritative zero-byte upsert");

        backfill_from_sidecar(
            &pool,
            repo,
            path,
            "other-key",
            "m2",
            77,
            Some("wrong"),
            None,
        )
        .await
        .expect("backfill");

        let rows = list_paged(&pool, repo, None, 100).await.unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].size_bytes, 0, "authoritative size preserved");
        assert_eq!(rows[0].checksum_sha256.as_deref(), Some("e3b0c442"));
        assert_eq!(
            rows[0].storage_key, key,
            "authoritative storage key preserved"
        );
        cleanup_repo(&pool, repo).await;
    }

    /// #2537: the FIRST serve of a freshly-cached object must count even though
    /// its authoritative catalog row is written asynchronously by the streaming
    /// tee only after the client drains the body. The recorder ensures the row
    /// (transient placeholder) so the first serve records +1, the tee later
    /// refines that same row in place, and subsequent hits keep counting — with
    /// exactly one `proxy_download_statistics` row per serve.
    #[tokio::test]
    async fn test_record_proxy_download_counts_first_serve_before_tee_commit() {
        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let repo = insert_repo(&pool).await;
        let path = "simple/pkg/pkg-1.0.whl";
        let key = format!("proxy-cache/{}/{path}/__content__", repo.simple());
        let meta = format!("proxy-cache/{}/{path}/__cache_meta__.json", repo.simple());

        // FIRST serve on a cache miss: no authoritative catalog row exists yet
        // (the tee has not committed), but the serve must still count.
        let n = record_proxy_download(
            &pool,
            repo,
            path,
            &key,
            &meta,
            None,
            Some("1.2.3.4"),
            Some("pip/24"),
        )
        .await
        .unwrap();
        assert_eq!(
            n, 1,
            "first serve counts even before the tee commits the row"
        );
        assert_eq!(download_count_by_repo(&pool, repo).await.unwrap(), 1);

        // A transient placeholder row now exists (size 0, awaiting refresh).
        let rows = list_paged(&pool, repo, None, 100).await.unwrap();
        assert_eq!(rows.len(), 1, "one catalog row ensured by the first serve");
        assert_eq!(rows[0].size_bytes, 0, "placeholder awaits the tee refresh");

        // The tee commit refines the SAME row in place with the true size /
        // checksum (no duplicate row).
        upsert(&pool, repo, path, &key, &meta, 4096, Some("c"), None, None)
            .await
            .unwrap();
        let rows = list_paged(&pool, repo, None, 100).await.unwrap();
        assert_eq!(
            rows.len(),
            1,
            "tee upsert refines in place, no duplicate row"
        );
        assert_eq!(rows[0].size_bytes, 4096, "tee filled the true size");

        // SECOND serve (a warm cache hit) counts too: exactly one more row.
        let n = record_proxy_download(&pool, repo, path, &key, &meta, None, None, None)
            .await
            .unwrap();
        assert_eq!(n, 1, "warm hit records one more download");
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

    /// PF-002 (#2519): the browse page must return exact contents across a
    /// full keyset walk, with each call bounded by `limit` — it must never
    /// hand the caller the whole cached set at once.
    #[tokio::test]
    async fn test_browse_page_keyset_walk_is_bounded_and_exact() {
        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let repo = insert_repo(&pool).await;
        let total = 25usize;
        let per_page = 10usize;
        for i in 0..total {
            let p = format!("pkg/obj-{i:03}.bin");
            upsert(
                &pool,
                repo,
                &p,
                &format!("proxy-cache/{}/{p}/__content__", repo.simple()),
                "m",
                i as i64,
                Some("c"),
                None,
                None,
            )
            .await
            .unwrap();
        }

        let mut walked: Vec<String> = Vec::new();
        let mut after: Option<String> = None;
        let mut pages = 0;
        loop {
            let rows = browse_page(
                &pool,
                repo,
                None,
                None,
                after.as_deref(),
                0,
                (per_page + 1) as i64,
            )
            .await
            .unwrap();
            // Bounded: never more than per_page + 1 rows per call, even
            // though 25 rows exist.
            assert!(rows.len() <= per_page + 1, "page is bounded by limit");
            let has_more = rows.len() > per_page;
            let page_rows = &rows[..rows.len().min(per_page)];
            walked.extend(page_rows.iter().map(|r| r.path.clone()));
            pages += 1;
            match (has_more, pages) {
                (true, 1 | 2) => {} // first two pages are full with more behind
                (false, 3) => break,
                (hm, n) => panic!("unexpected has_more={hm} on page {n}"),
            }
            after = page_rows.last().map(|r| r.path.clone());
        }

        let expected: Vec<String> = (0..total).map(|i| format!("pkg/obj-{i:03}.bin")).collect();
        assert_eq!(walked, expected, "full walk yields every row exactly once");
        assert_eq!(browse_count(&pool, repo, None, None).await.unwrap(), 25);
        cleanup_repo(&pool, repo).await;
    }

    /// PF-002 (#2519): prefix + substring filters match the legacy in-memory
    /// semantics (prefix = starts_with, `q` = case-insensitive substring) and
    /// LIKE metacharacters in user input match literally.
    #[tokio::test]
    async fn test_browse_page_filters_and_like_escaping() {
        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let repo = insert_repo(&pool).await;
        // Paths are all-lowercase and same-case so the asserted relative
        // order is identical under any database collation (C vs linguistic);
        // case-insensitivity is exercised through the QUERY side below.
        for p in ["a/one.whl", "a/two.whl", "b/100%_done.whl", "b/100xy.whl"] {
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
        let escape = |s: &str| {
            let mut out = String::new();
            for ch in s.chars() {
                if matches!(ch, '\\' | '%' | '_') {
                    out.push('\\');
                }
                out.push(ch);
            }
            out
        };

        // Prefix filter: starts_with semantics.
        let rows = browse_page(&pool, repo, Some("a/%"), None, None, 0, 10)
            .await
            .unwrap();
        assert_eq!(
            rows.iter().map(|r| r.path.as_str()).collect::<Vec<_>>(),
            ["a/one.whl", "a/two.whl"]
        );

        // Substring filter is case-insensitive, like the legacy
        // `to_lowercase().contains()` filter: an upper-cased needle still
        // matches the lower-cased stored path.
        let rows = browse_page(&pool, repo, None, Some("%TWO%"), None, 0, 10)
            .await
            .unwrap();
        assert_eq!(
            rows.iter().map(|r| r.path.as_str()).collect::<Vec<_>>(),
            ["a/two.whl"]
        );

        // `%` / `_` in user input match literally once escaped: `100%_`
        // must match only the literal path, not wildcard onto `100xy`.
        let q = format!("%{}%", escape("100%_"));
        let rows = browse_page(&pool, repo, None, Some(&q), None, 0, 10)
            .await
            .unwrap();
        assert_eq!(
            rows.iter().map(|r| r.path.as_str()).collect::<Vec<_>>(),
            ["b/100%_done.whl"]
        );
        assert_eq!(
            browse_count(&pool, repo, None, Some(&q)).await.unwrap(),
            1,
            "count applies the same escaped filters as the page"
        );
        cleanup_repo(&pool, repo).await;
    }

    /// `has_rows` distinguishes a cataloged repo from a pre-catalog (or empty)
    /// one, which is what gates the legacy storage-listing fallback.
    #[tokio::test]
    async fn test_has_rows_gates_catalog_vs_fallback() {
        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let repo = insert_repo(&pool).await;
        assert!(!has_rows(&pool, repo).await.unwrap(), "empty catalog");
        upsert(&pool, repo, "p", "proxy-k", "m", 1, None, None, None)
            .await
            .unwrap();
        assert!(has_rows(&pool, repo).await.unwrap(), "cataloged repo");
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

    /// Catalog a set of cached object paths for one repository, deriving a
    /// plausible content storage key for each. Shared by the #3270 / #3265
    /// tests below so the fixture setup is written once.
    async fn cache_paths(pool: &PgPool, repo: Uuid, paths: &[&str]) {
        for path in paths {
            upsert(
                pool,
                repo,
                path,
                &format!("proxy-cache/{}/{path}/__content__", repo.simple()),
                "m",
                10,
                Some("c"),
                None,
                None,
            )
            .await
            .expect("catalog cached path");
        }
    }

    /// #3270: the remote Maven grouped listing fills each component's file
    /// list from this query, so it must return every object under the GAV
    /// directory and nothing from a sibling GAV.
    #[tokio::test]
    async fn test_paths_under_prefixes_scopes_to_the_given_directories() {
        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let repo = insert_repo(&pool).await;
        cache_paths(
            &pool,
            repo,
            &[
                "com/google/guava/guava/33.6.0-jre/guava-33.6.0-jre.jar",
                "com/google/guava/guava/33.6.0-jre/guava-33.6.0-jre.pom",
                "com/google/guava/guava/32.0.0-jre/guava-32.0.0-jre.jar",
                "org/other/thing/1.0/thing-1.0.jar",
            ],
        )
        .await;

        let found = paths_under_prefixes(
            &pool,
            repo,
            &["com/google/guava/guava/33.6.0-jre/".to_string()],
            100,
        )
        .await
        .expect("prefix query");
        assert_eq!(
            found,
            vec![
                "com/google/guava/guava/33.6.0-jre/guava-33.6.0-jre.jar".to_string(),
                "com/google/guava/guava/33.6.0-jre/guava-33.6.0-jre.pom".to_string(),
            ],
            "only the requested GAV directory, ordered by path"
        );

        // No prefixes / a non-positive limit short-circuit without a query.
        assert!(paths_under_prefixes(&pool, repo, &[], 100)
            .await
            .unwrap()
            .is_empty());
        assert!(paths_under_prefixes(
            &pool,
            repo,
            &["com/google/guava/guava/33.6.0-jre/".to_string()],
            0
        )
        .await
        .unwrap()
        .is_empty());
        cleanup_repo(&pool, repo).await;
    }

    /// #3265: proxy serves were recorded but never surfaced, so every cached
    /// row in the remote listing reported `download_count: 0`.
    #[tokio::test]
    async fn test_download_counts_by_paths_reports_recorded_serves() {
        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let repo = insert_repo(&pool).await;
        let served = "com/google/guava/guava/33.6.0-jre/guava-33.6.0-jre.jar";
        let untouched = "com/google/guava/guava/33.6.0-jre/guava-33.6.0-jre.pom";
        cache_paths(&pool, repo, &[served, untouched]).await;
        for _ in 0..3 {
            record_proxy_download(&pool, repo, served, "k", "m", None, None, None)
                .await
                .unwrap();
        }

        let counts =
            download_counts_by_paths(&pool, repo, &[served.to_string(), untouched.to_string()])
                .await
                .expect("count query");
        assert_eq!(counts.get(served).copied(), Some(3));
        assert_eq!(
            counts.get(untouched).copied(),
            Some(0),
            "a cached-but-never-served object reports zero, not absent"
        );
        assert!(download_counts_by_paths(&pool, repo, &[])
            .await
            .unwrap()
            .is_empty());
        cleanup_repo(&pool, repo).await;
    }
}
