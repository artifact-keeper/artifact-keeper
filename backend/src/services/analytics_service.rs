//! Storage analytics and reporting service.
//!
//! Provides time-series storage metrics, artifact aging reports,
//! per-repository breakdowns, and scheduled metric snapshots.

use chrono::{DateTime, NaiveDate, Utc};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use utoipa::ToSchema;
use uuid::Uuid;

use crate::error::{AppError, Result};

/// Analytics service for storage and usage reporting.
pub struct AnalyticsService {
    db: PgPool,
}

/// A single day's storage metrics snapshot.
#[derive(Debug, Serialize, Deserialize, sqlx::FromRow, ToSchema)]
pub struct StorageSnapshot {
    pub snapshot_date: NaiveDate,
    pub total_repositories: i64,
    /// Rows in `artifacts` (for OCI repositories that is manifests only —
    /// layer/config blobs are content-addressed objects, not artifacts), the
    /// same deliberate decision as the dashboard's
    /// `SystemStats::total_artifacts` (#3134). Unlike the byte total, this
    /// count still includes legacy backfilled `proxy-cache/%` rows.
    pub total_artifacts: i64,
    /// All stored bytes at snapshot time, summed from
    /// `repository_usage_ledger` (`hosted_bytes + proxy_bytes + oci_bytes`) —
    /// the same source as the dashboard `total_storage_bytes` and quota
    /// admission (#3134/#3249), so the analytics series is consistent with
    /// both by construction. Includes OCI layer/config blob bytes
    /// (`oci_blobs`) and proxy-cached bytes (`proxy_cache_artifacts`);
    /// excludes legacy backfilled `proxy-cache/%` `artifacts` rows (their
    /// bytes are represented by the proxy-cache catalog instead). This is the
    /// LOGICAL figure: a blob cross-repo-mounted into N repositories counts
    /// once per repository, matching the per-repo storage column and quota.
    pub total_storage_bytes: i64,
    pub total_downloads: i64,
    pub total_users: i64,
    /// The proxy-cache half of the three totals above (migration 210).
    /// Proxy-cached objects carry no `artifacts` row (#1280) and their serves
    /// land in `proxy_download_statistics`, so the `total_*` figures stay
    /// hosted-only and these carry the remote side. 0 for snapshots taken
    /// before migration 210 and when deserializing older payloads.
    #[serde(default)]
    pub proxy_artifact_count: i64,
    #[serde(default)]
    pub proxy_storage_bytes: i64,
    #[serde(default)]
    pub proxy_download_count: i64,
}

/// Per-repository metrics snapshot.
#[derive(Debug, Serialize, Deserialize, sqlx::FromRow, ToSchema)]
pub struct RepositorySnapshot {
    pub repository_id: Uuid,
    pub repository_name: Option<String>,
    pub repository_key: Option<String>,
    pub snapshot_date: NaiveDate,
    pub artifact_count: i64,
    pub storage_bytes: i64,
    pub download_count: i64,
}

/// Current per-repository storage breakdown.
#[derive(Debug, Serialize, Deserialize, sqlx::FromRow, ToSchema)]
pub struct RepositoryStorageBreakdown {
    pub repository_id: Uuid,
    pub repository_key: String,
    pub repository_name: String,
    pub format: String,
    pub artifact_count: i64,
    pub storage_bytes: i64,
    pub download_count: i64,
    /// The proxy-cache half of `artifact_count` / `storage_bytes`, read from
    /// `proxy_cache_artifacts` (those rows never appear in `artifacts`, #1280).
    /// Hosted figures above are unchanged; defaults to 0 on older payloads.
    #[serde(default)]
    pub proxy_artifact_count: i64,
    #[serde(default)]
    pub proxy_storage_bytes: i64,
    /// Downloads served by this repository's remote pull-through proxy
    /// (`proxy_download_statistics`, #2537/#2704). Proxy-cached objects carry
    /// no `artifacts` row (#1280), so these serves are counted in a sibling
    /// table and were previously not readable through any API. Kept separate
    /// from `download_count` (hosted serves) so existing consumers are
    /// unaffected; defaults to 0 when deserializing older payloads.
    #[serde(default)]
    pub proxy_download_count: i64,
    pub last_upload_at: Option<DateTime<Utc>>,
}

/// Artifact aging report entry.
#[derive(Debug, Serialize, Deserialize, sqlx::FromRow, ToSchema)]
pub struct StaleArtifact {
    pub artifact_id: Uuid,
    pub repository_key: String,
    pub name: String,
    pub path: String,
    pub size_bytes: i64,
    pub created_at: DateTime<Utc>,
    pub last_downloaded_at: Option<DateTime<Utc>>,
    pub days_since_download: i64,
    pub download_count: i64,
}

/// Growth summary for a time range.
///
/// Computed from `storage_metrics` daily snapshots. **Accounting-basis note
/// (#3249):** snapshots taken before the #3134/#3249 fix summed
/// `artifacts.size_bytes` only, missing OCI layer/config blob bytes
/// (`oci_blobs`) and proxy-cached bytes (`proxy_cache_artifacts`) while
/// counting legacy backfilled `proxy-cache/%` rows. Those historical rows are
/// deliberately left as recorded — the source tables hold no history, so past
/// values cannot be recomputed, only fabricated. A growth series that spans
/// the fix date therefore shows a one-day upward step in
/// `storage_bytes_start/end` / `storage_growth_bytes` /
/// `storage_growth_percent` when the corrected accounting first lands; it is
/// a measurement correction, not real growth.
#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct GrowthSummary {
    pub period_start: NaiveDate,
    pub period_end: NaiveDate,
    pub storage_bytes_start: i64,
    pub storage_bytes_end: i64,
    pub storage_growth_bytes: i64,
    pub storage_growth_percent: f64,
    pub artifacts_start: i64,
    pub artifacts_end: i64,
    pub artifacts_added: i64,
    pub downloads_in_period: i64,
}

/// Download trend data point.
#[derive(Debug, Serialize, Deserialize, sqlx::FromRow, ToSchema)]
pub struct DownloadTrend {
    pub date: NaiveDate,
    pub download_count: i64,
    /// Proxy-served (pull-through) downloads for the day, from the sibling
    /// `proxy_download_statistics` table (#2537/#2704). Additive: hosted
    /// serves stay in `download_count` unchanged; defaults to 0 when
    /// deserializing older payloads.
    #[serde(default)]
    pub proxy_download_count: i64,
}

impl AnalyticsService {
    pub fn new(db: PgPool) -> Self {
        Self { db }
    }

    /// Capture a daily snapshot of system-wide metrics.
    /// Should be called once per day (via scheduled background task).
    pub async fn capture_daily_snapshot(&self) -> Result<StorageSnapshot> {
        let snapshot = sqlx::query_as::<_, StorageSnapshot>(
            r#"
            INSERT INTO storage_metrics (
                snapshot_date, total_repositories, total_artifacts,
                total_storage_bytes, total_downloads, total_users,
                proxy_artifact_count, proxy_storage_bytes, proxy_download_count
            )
            SELECT
                CURRENT_DATE,
                (SELECT COUNT(*) FROM repositories),
                (SELECT COUNT(*) FROM artifacts WHERE is_deleted = false),
                -- #3134/#3249: same source as `GET /api/v1/admin/stats`
                -- (`repository_usage_ledger`, trigger-maintained), so the
                -- snapshot trend does not diverge from the dashboard total
                -- by OCI blob and proxy-cached bytes.
                (SELECT COALESCE(SUM(hosted_bytes + proxy_bytes + oci_bytes), 0)
                 FROM repository_usage_ledger),
                (SELECT COUNT(*) FROM download_statistics),
                (SELECT COUNT(*) FROM users),
                (SELECT COUNT(*) FROM proxy_cache_artifacts),
                (SELECT COALESCE(SUM(size_bytes), 0) FROM proxy_cache_artifacts),
                (SELECT COUNT(*) FROM proxy_download_statistics)
            ON CONFLICT (snapshot_date) DO UPDATE SET
                total_repositories = EXCLUDED.total_repositories,
                total_artifacts = EXCLUDED.total_artifacts,
                total_storage_bytes = EXCLUDED.total_storage_bytes,
                total_downloads = EXCLUDED.total_downloads,
                total_users = EXCLUDED.total_users,
                proxy_artifact_count = EXCLUDED.proxy_artifact_count,
                proxy_storage_bytes = EXCLUDED.proxy_storage_bytes,
                proxy_download_count = EXCLUDED.proxy_download_count
            RETURNING
                snapshot_date,
                total_repositories,
                total_artifacts,
                total_storage_bytes,
                total_downloads,
                total_users,
                proxy_artifact_count,
                proxy_storage_bytes,
                proxy_download_count
            "#,
        )
        .fetch_one(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        Ok(snapshot)
    }

    /// Capture per-repository metrics for today.
    pub async fn capture_repository_snapshots(&self) -> Result<Vec<RepositorySnapshot>> {
        let snapshots = sqlx::query_as::<_, RepositorySnapshot>(
            r#"
            INSERT INTO repository_metrics (repository_id, snapshot_date, artifact_count, storage_bytes, download_count)
            SELECT
                r.id,
                CURRENT_DATE,
                COUNT(a.id),
                COALESCE(SUM(a.size_bytes), 0),
                (SELECT COUNT(*) FROM download_statistics ds
                 JOIN artifacts a2 ON a2.id = ds.artifact_id
                 WHERE a2.repository_id = r.id)
            FROM repositories r
            LEFT JOIN artifacts a ON a.repository_id = r.id AND a.is_deleted = false
            GROUP BY r.id
            ON CONFLICT (repository_id, snapshot_date) DO UPDATE SET
                artifact_count = EXCLUDED.artifact_count,
                storage_bytes = EXCLUDED.storage_bytes,
                download_count = EXCLUDED.download_count
            RETURNING
                repository_id,
                NULL::TEXT as repository_name,
                NULL::TEXT as repository_key,
                snapshot_date,
                artifact_count,
                storage_bytes,
                download_count
            "#,
        )
        .fetch_all(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        Ok(snapshots)
    }

    /// Get storage trend over a date range.
    pub async fn get_storage_trend(
        &self,
        from: NaiveDate,
        to: NaiveDate,
    ) -> Result<Vec<StorageSnapshot>> {
        let snapshots = sqlx::query_as::<_, StorageSnapshot>(
            r#"
            SELECT
                snapshot_date,
                total_repositories,
                total_artifacts,
                total_storage_bytes,
                total_downloads,
                total_users,
                proxy_artifact_count,
                proxy_storage_bytes,
                proxy_download_count
            FROM storage_metrics
            WHERE snapshot_date BETWEEN $1 AND $2
            ORDER BY snapshot_date ASC
            "#,
        )
        .bind(from)
        .bind(to)
        .fetch_all(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        Ok(snapshots)
    }

    /// Get per-repository storage trend.
    pub async fn get_repository_trend(
        &self,
        repository_id: Uuid,
        from: NaiveDate,
        to: NaiveDate,
    ) -> Result<Vec<RepositorySnapshot>> {
        let snapshots = sqlx::query_as::<_, RepositorySnapshot>(
            r#"
            SELECT
                rm.repository_id,
                r.name as repository_name,
                r.key as repository_key,
                rm.snapshot_date,
                rm.artifact_count,
                rm.storage_bytes,
                rm.download_count
            FROM repository_metrics rm
            JOIN repositories r ON r.id = rm.repository_id
            WHERE rm.repository_id = $1
              AND rm.snapshot_date BETWEEN $2 AND $3
            ORDER BY rm.snapshot_date ASC
            "#,
        )
        .bind(repository_id)
        .bind(from)
        .bind(to)
        .fetch_all(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        Ok(snapshots)
    }

    /// Get current per-repository storage breakdown.
    pub async fn get_storage_breakdown(&self) -> Result<Vec<RepositoryStorageBreakdown>> {
        let breakdown = sqlx::query_as::<_, RepositoryStorageBreakdown>(
            r#"
            SELECT
                r.id as repository_id,
                r.key as repository_key,
                r.name as repository_name,
                r.format::TEXT as format,
                COUNT(a.id) as artifact_count,
                COALESCE(SUM(a.size_bytes), 0)::BIGINT as storage_bytes,
                (SELECT COUNT(*) FROM download_statistics ds
                 JOIN artifacts a2 ON a2.id = ds.artifact_id
                 WHERE a2.repository_id = r.id)::BIGINT as download_count,
                pc.artifact_count as proxy_artifact_count,
                pc.storage_bytes as proxy_storage_bytes,
                (SELECT COUNT(*) FROM proxy_download_statistics pds
                 JOIN proxy_cache_artifacts pca ON pca.id = pds.proxy_cache_id
                 WHERE pca.repository_id = r.id)::BIGINT as proxy_download_count,
                MAX(a.created_at) as last_upload_at
            FROM repositories r
            LEFT JOIN artifacts a ON a.repository_id = r.id AND a.is_deleted = false
            -- One indexed pass over the proxy catalog per repository, feeding
            -- both proxy columns and the ordering below.
            LEFT JOIN LATERAL (
                SELECT COUNT(*)::BIGINT as artifact_count,
                       COALESCE(SUM(p.size_bytes), 0)::BIGINT as storage_bytes
                FROM proxy_cache_artifacts p
                WHERE p.repository_id = r.id
            ) pc ON TRUE
            GROUP BY r.id, r.key, r.name, r.format, pc.artifact_count, pc.storage_bytes
            -- Order by the total the UI shows: a remote repository holds all of
            -- its bytes in proxy_cache_artifacts and would otherwise sort last.
            ORDER BY COALESCE(SUM(a.size_bytes), 0) + pc.storage_bytes DESC
            "#,
        )
        .fetch_all(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        Ok(breakdown)
    }

    /// Get stale artifacts that haven't been downloaded in N days.
    pub async fn get_stale_artifacts(
        &self,
        days_threshold: i32,
        limit: i64,
    ) -> Result<Vec<StaleArtifact>> {
        let stale = sqlx::query_as::<_, StaleArtifact>(
            r#"
            SELECT
                a.id as artifact_id,
                r.key as repository_key,
                a.name,
                a.path,
                a.size_bytes,
                a.created_at,
                ds_last.last_download as last_downloaded_at,
                COALESCE(
                    EXTRACT(DAY FROM NOW() - ds_last.last_download)::BIGINT,
                    EXTRACT(DAY FROM NOW() - a.created_at)::BIGINT
                ) as days_since_download,
                COALESCE(ds_count.cnt, 0)::BIGINT as download_count
            FROM artifacts a
            JOIN repositories r ON r.id = a.repository_id
            LEFT JOIN LATERAL (
                SELECT MAX(ds.downloaded_at) as last_download
                FROM download_statistics ds
                WHERE ds.artifact_id = a.id
            ) ds_last ON true
            LEFT JOIN LATERAL (
                SELECT COUNT(*) as cnt
                FROM download_statistics ds
                WHERE ds.artifact_id = a.id
            ) ds_count ON true
            WHERE a.is_deleted = false
              AND (
                  ds_last.last_download IS NULL AND a.created_at < NOW() - make_interval(days => $1)
                  OR ds_last.last_download < NOW() - make_interval(days => $1)
              )
            ORDER BY a.size_bytes DESC
            LIMIT $2
            "#,
        )
        .bind(days_threshold)
        .bind(limit)
        .fetch_all(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        Ok(stale)
    }

    /// Get growth summary for a date range.
    pub async fn get_growth_summary(
        &self,
        from: NaiveDate,
        to: NaiveDate,
    ) -> Result<GrowthSummary> {
        let start = sqlx::query_as::<_, StorageSnapshot>(
            r#"
            SELECT snapshot_date, total_repositories, total_artifacts,
                   total_storage_bytes, total_downloads, total_users,
                   proxy_artifact_count, proxy_storage_bytes, proxy_download_count
            FROM storage_metrics
            WHERE snapshot_date <= $1
            ORDER BY snapshot_date DESC
            LIMIT 1
            "#,
        )
        .bind(from)
        .fetch_optional(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        let end = sqlx::query_as::<_, StorageSnapshot>(
            r#"
            SELECT snapshot_date, total_repositories, total_artifacts,
                   total_storage_bytes, total_downloads, total_users,
                   proxy_artifact_count, proxy_storage_bytes, proxy_download_count
            FROM storage_metrics
            WHERE snapshot_date <= $1
            ORDER BY snapshot_date DESC
            LIMIT 1
            "#,
        )
        .bind(to)
        .fetch_optional(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        let (start_bytes, start_artifacts) = start
            .as_ref()
            .map(|s| (s.total_storage_bytes, s.total_artifacts))
            .unwrap_or((0, 0));
        let (end_bytes, end_artifacts, end_downloads) = end
            .as_ref()
            .map(|s| (s.total_storage_bytes, s.total_artifacts, s.total_downloads))
            .unwrap_or((0, 0, 0));

        let growth_bytes = end_bytes - start_bytes;
        let growth_percent = if start_bytes > 0 {
            (growth_bytes as f64 / start_bytes as f64) * 100.0
        } else if end_bytes > 0 {
            100.0
        } else {
            0.0
        };

        Ok(GrowthSummary {
            period_start: from,
            period_end: to,
            storage_bytes_start: start_bytes,
            storage_bytes_end: end_bytes,
            storage_growth_bytes: growth_bytes,
            storage_growth_percent: growth_percent,
            artifacts_start: start_artifacts,
            artifacts_end: end_artifacts,
            artifacts_added: end_artifacts - start_artifacts,
            downloads_in_period: end_downloads - start.map(|s| s.total_downloads).unwrap_or(0),
        })
    }

    /// Get download trends (daily counts) for a date range.
    ///
    /// Hosted serves (`download_statistics`) and proxy pull-through serves
    /// (`proxy_download_statistics`, #2537/#2704) are UNIONed by day — the
    /// union `proxy_catalog::download_count_by_repo`'s docs anticipated —
    /// and reported as separate fields so existing consumers of
    /// `download_count` see unchanged values.
    pub async fn get_download_trends(
        &self,
        from: NaiveDate,
        to: NaiveDate,
    ) -> Result<Vec<DownloadTrend>> {
        let trends = sqlx::query_as::<_, DownloadTrend>(
            r#"
            SELECT
                u.date as date,
                COALESCE(SUM(u.hosted), 0)::BIGINT as download_count,
                COALESCE(SUM(u.proxied), 0)::BIGINT as proxy_download_count
            FROM (
                SELECT downloaded_at::DATE as date, 1 as hosted, 0 as proxied
                FROM download_statistics
                WHERE downloaded_at::DATE BETWEEN $1 AND $2
                UNION ALL
                SELECT downloaded_at::DATE as date, 0 as hosted, 1 as proxied
                FROM proxy_download_statistics
                WHERE downloaded_at::DATE BETWEEN $1 AND $2
            ) u
            GROUP BY u.date
            ORDER BY u.date ASC
            "#,
        )
        .bind(from)
        .bind(to)
        .fetch_all(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        Ok(trends)
    }

    /// Cleanup old metric snapshots beyond retention period.
    pub async fn cleanup_old_snapshots(&self, keep_days: i32) -> Result<u64> {
        let result = sqlx::query(
            "DELETE FROM storage_metrics WHERE snapshot_date < CURRENT_DATE - make_interval(days => $1)",
        )
        .bind(keep_days)
        .execute(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        let result2 = sqlx::query(
            "DELETE FROM repository_metrics WHERE snapshot_date < CURRENT_DATE - make_interval(days => $1)",
        )
        .bind(keep_days)
        .execute(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        Ok(result.rows_affected() + result2.rows_affected())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::NaiveDate;

    // -----------------------------------------------------------------------
    // StorageSnapshot
    // -----------------------------------------------------------------------

    #[test]
    fn test_storage_snapshot_serialization() {
        let snapshot = StorageSnapshot {
            snapshot_date: NaiveDate::from_ymd_opt(2024, 6, 15).unwrap(),
            total_repositories: 10,
            total_artifacts: 500,
            total_storage_bytes: 1_073_741_824,
            total_downloads: 5000,
            total_users: 25,
            proxy_artifact_count: 40,
            proxy_storage_bytes: 4096,
            proxy_download_count: 9,
        };
        let json = serde_json::to_value(&snapshot).unwrap();
        assert_eq!(json["snapshot_date"], "2024-06-15");
        assert_eq!(json["total_repositories"], 10);
        assert_eq!(json["total_artifacts"], 500);
        assert_eq!(json["total_storage_bytes"], 1_073_741_824);
        assert_eq!(json["total_downloads"], 5000);
        assert_eq!(json["total_users"], 25);
        // Migration 210: the proxy halves are ADDITIVE siblings; the hosted
        // `total_*` figures above are unchanged.
        assert_eq!(json["proxy_artifact_count"], 40);
        assert_eq!(json["proxy_storage_bytes"], 4096);
        assert_eq!(json["proxy_download_count"], 9);
    }

    #[test]
    fn test_storage_snapshot_deserialization() {
        let json = r#"{
            "snapshot_date": "2024-06-15",
            "total_repositories": 10,
            "total_artifacts": 500,
            "total_storage_bytes": 1073741824,
            "total_downloads": 5000,
            "total_users": 25
        }"#;
        let snapshot: StorageSnapshot = serde_json::from_str(json).unwrap();
        assert_eq!(
            snapshot.snapshot_date,
            NaiveDate::from_ymd_opt(2024, 6, 15).unwrap()
        );
        assert_eq!(snapshot.total_repositories, 10);
        // Payload predating migration 210 — proxy halves default to 0.
        assert_eq!(snapshot.proxy_artifact_count, 0);
        assert_eq!(snapshot.proxy_storage_bytes, 0);
        assert_eq!(snapshot.proxy_download_count, 0);
    }

    #[test]
    fn test_storage_snapshot_zero_values() {
        let snapshot = StorageSnapshot {
            snapshot_date: NaiveDate::from_ymd_opt(2024, 1, 1).unwrap(),
            total_repositories: 0,
            total_artifacts: 0,
            total_storage_bytes: 0,
            total_downloads: 0,
            total_users: 0,
            proxy_artifact_count: 0,
            proxy_storage_bytes: 0,
            proxy_download_count: 0,
        };
        let json = serde_json::to_value(&snapshot).unwrap();
        assert_eq!(json["total_storage_bytes"], 0);
    }

    // -----------------------------------------------------------------------
    // RepositorySnapshot
    // -----------------------------------------------------------------------

    #[test]
    fn test_repository_snapshot_serialization() {
        let snapshot = RepositorySnapshot {
            repository_id: Uuid::nil(),
            repository_name: Some("my-repo".to_string()),
            repository_key: Some("my-repo-key".to_string()),
            snapshot_date: NaiveDate::from_ymd_opt(2024, 6, 15).unwrap(),
            artifact_count: 100,
            storage_bytes: 536_870_912,
            download_count: 1000,
        };
        let json = serde_json::to_value(&snapshot).unwrap();
        assert_eq!(json["repository_name"], "my-repo");
        assert_eq!(json["artifact_count"], 100);
    }

    #[test]
    fn test_repository_snapshot_optional_fields_null() {
        let snapshot = RepositorySnapshot {
            repository_id: Uuid::nil(),
            repository_name: None,
            repository_key: None,
            snapshot_date: NaiveDate::from_ymd_opt(2024, 1, 1).unwrap(),
            artifact_count: 0,
            storage_bytes: 0,
            download_count: 0,
        };
        let json = serde_json::to_value(&snapshot).unwrap();
        assert!(json["repository_name"].is_null());
        assert!(json["repository_key"].is_null());
    }

    // -----------------------------------------------------------------------
    // RepositoryStorageBreakdown
    // -----------------------------------------------------------------------

    #[test]
    fn test_repository_storage_breakdown_serialization() {
        let breakdown = RepositoryStorageBreakdown {
            repository_id: Uuid::nil(),
            repository_key: "maven-central".to_string(),
            repository_name: "Maven Central".to_string(),
            format: "maven".to_string(),
            artifact_count: 200,
            storage_bytes: 2_147_483_648,
            download_count: 10000,
            proxy_artifact_count: 30,
            proxy_storage_bytes: 1024,
            proxy_download_count: 7,
            last_upload_at: Some(Utc::now()),
        };
        let json = serde_json::to_value(&breakdown).unwrap();
        assert_eq!(json["repository_key"], "maven-central");
        assert_eq!(json["format"], "maven");
        assert_eq!(json["artifact_count"], 200);
        // #2704: the proxy figures are ADDITIVE sibling fields; the hosted
        // `artifact_count` / `storage_bytes` / `download_count` are unchanged.
        assert_eq!(json["proxy_artifact_count"], 30);
        assert_eq!(json["proxy_storage_bytes"], 1024);
        assert_eq!(json["proxy_download_count"], 7);
        assert_eq!(json["download_count"], 10000);
    }

    #[test]
    fn test_repository_storage_breakdown_no_uploads() {
        let breakdown = RepositoryStorageBreakdown {
            repository_id: Uuid::nil(),
            repository_key: "empty-repo".to_string(),
            repository_name: "Empty Repo".to_string(),
            format: "generic".to_string(),
            artifact_count: 0,
            storage_bytes: 0,
            download_count: 0,
            proxy_artifact_count: 0,
            proxy_storage_bytes: 0,
            proxy_download_count: 0,
            last_upload_at: None,
        };
        let json = serde_json::to_value(&breakdown).unwrap();
        assert!(json["last_upload_at"].is_null());
        assert_eq!(json["artifact_count"], 0);
    }

    // -----------------------------------------------------------------------
    // StaleArtifact
    // -----------------------------------------------------------------------

    #[test]
    fn test_stale_artifact_serialization() {
        let stale = StaleArtifact {
            artifact_id: Uuid::nil(),
            repository_key: "old-repo".to_string(),
            name: "old-lib-1.0.jar".to_string(),
            path: "com/example/old-lib/1.0/old-lib-1.0.jar".to_string(),
            size_bytes: 1_048_576,
            created_at: Utc::now(),
            last_downloaded_at: None,
            days_since_download: 365,
            download_count: 0,
        };
        let json = serde_json::to_value(&stale).unwrap();
        assert_eq!(json["name"], "old-lib-1.0.jar");
        assert_eq!(json["days_since_download"], 365);
        assert_eq!(json["download_count"], 0);
        assert!(json["last_downloaded_at"].is_null());
    }

    #[test]
    fn test_stale_artifact_with_last_download() {
        let stale = StaleArtifact {
            artifact_id: Uuid::nil(),
            repository_key: "repo".to_string(),
            name: "lib.jar".to_string(),
            path: "lib.jar".to_string(),
            size_bytes: 512,
            created_at: Utc::now(),
            last_downloaded_at: Some(Utc::now()),
            days_since_download: 90,
            download_count: 5,
        };
        let json = serde_json::to_value(&stale).unwrap();
        assert!(!json["last_downloaded_at"].is_null());
    }

    // -----------------------------------------------------------------------
    // GrowthSummary
    // -----------------------------------------------------------------------

    #[test]
    fn test_growth_summary_serialization() {
        let summary = GrowthSummary {
            period_start: NaiveDate::from_ymd_opt(2024, 1, 1).unwrap(),
            period_end: NaiveDate::from_ymd_opt(2024, 6, 30).unwrap(),
            storage_bytes_start: 1_000_000_000,
            storage_bytes_end: 2_000_000_000,
            storage_growth_bytes: 1_000_000_000,
            storage_growth_percent: 100.0,
            artifacts_start: 100,
            artifacts_end: 250,
            artifacts_added: 150,
            downloads_in_period: 5000,
        };
        let json = serde_json::to_value(&summary).unwrap();
        assert_eq!(json["storage_growth_percent"], 100.0);
        assert_eq!(json["artifacts_added"], 150);
    }

    #[test]
    fn test_growth_summary_zero_growth() {
        let summary = GrowthSummary {
            period_start: NaiveDate::from_ymd_opt(2024, 1, 1).unwrap(),
            period_end: NaiveDate::from_ymd_opt(2024, 1, 31).unwrap(),
            storage_bytes_start: 1_000_000,
            storage_bytes_end: 1_000_000,
            storage_growth_bytes: 0,
            storage_growth_percent: 0.0,
            artifacts_start: 10,
            artifacts_end: 10,
            artifacts_added: 0,
            downloads_in_period: 50,
        };
        let json = serde_json::to_value(&summary).unwrap();
        assert_eq!(json["storage_growth_bytes"], 0);
        assert_eq!(json["storage_growth_percent"], 0.0);
    }

    // -----------------------------------------------------------------------
    // Growth percent calculation logic (from get_growth_summary)
    // -----------------------------------------------------------------------

    #[test]
    fn test_growth_percent_calculation_normal() {
        let start_bytes: i64 = 1_000_000;
        let end_bytes: i64 = 1_500_000;
        let growth_bytes = end_bytes - start_bytes;
        let growth_percent = if start_bytes > 0 {
            (growth_bytes as f64 / start_bytes as f64) * 100.0
        } else if end_bytes > 0 {
            100.0
        } else {
            0.0
        };
        assert!((growth_percent - 50.0).abs() < 0.001);
    }

    #[test]
    fn test_growth_percent_calculation_from_zero() {
        let start_bytes: i64 = 0;
        let end_bytes: i64 = 1_000_000;
        let growth_bytes = end_bytes - start_bytes;
        let growth_percent = if start_bytes > 0 {
            (growth_bytes as f64 / start_bytes as f64) * 100.0
        } else if end_bytes > 0 {
            100.0
        } else {
            0.0
        };
        assert_eq!(growth_percent, 100.0);
    }

    #[test]
    fn test_growth_percent_calculation_both_zero() {
        let start_bytes: i64 = 0;
        let end_bytes: i64 = 0;
        let _growth_bytes = end_bytes - start_bytes;
        let growth_percent = if start_bytes > 0 {
            (0.0_f64 / start_bytes as f64) * 100.0
        } else if end_bytes > 0 {
            100.0
        } else {
            0.0
        };
        assert_eq!(growth_percent, 0.0);
    }

    #[test]
    fn test_growth_percent_calculation_shrinkage() {
        let start_bytes: i64 = 2_000_000;
        let end_bytes: i64 = 1_000_000;
        let growth_bytes = end_bytes - start_bytes;
        let growth_percent = if start_bytes > 0 {
            (growth_bytes as f64 / start_bytes as f64) * 100.0
        } else if end_bytes > 0 {
            100.0
        } else {
            0.0
        };
        assert!((growth_percent - (-50.0)).abs() < 0.001);
    }

    // -----------------------------------------------------------------------
    // DownloadTrend
    // -----------------------------------------------------------------------

    #[test]
    fn test_download_trend_serialization() {
        let trend = DownloadTrend {
            date: NaiveDate::from_ymd_opt(2024, 6, 15).unwrap(),
            download_count: 42,
            proxy_download_count: 3,
        };
        let json = serde_json::to_value(&trend).unwrap();
        assert_eq!(json["date"], "2024-06-15");
        assert_eq!(json["download_count"], 42);
        // #2704: proxy serves surface as a separate additive field.
        assert_eq!(json["proxy_download_count"], 3);
    }

    #[test]
    fn test_download_trend_deserialization() {
        let json = r#"{"date": "2024-06-15", "download_count": 100}"#;
        let trend: DownloadTrend = serde_json::from_str(json).unwrap();
        assert_eq!(trend.date, NaiveDate::from_ymd_opt(2024, 6, 15).unwrap());
        assert_eq!(trend.download_count, 100);
        // Additive-compat: an older payload without the field defaults to 0.
        assert_eq!(trend.proxy_download_count, 0);
    }

    // -----------------------------------------------------------------------
    // #2704: proxy downloads are readable through the analytics read APIs
    // (DB-backed; skips cleanly when DATABASE_URL is unset)
    // -----------------------------------------------------------------------

    /// A recorded proxy serve must be visible via every analytics read
    /// surface: the per-repo `storage/breakdown` `proxy_download_count`
    /// (exactly 1 for a fresh repo), the `downloads/trend` daily point, and
    /// — with migration 210 — the cached object's count/bytes in both the
    /// breakdown and the daily `storage/trend` snapshot. Pre-#2704 none of
    /// these fields existed; the proxy tables had no HTTP-readable surface.
    #[tokio::test]
    async fn test_analytics_reads_surface_proxy_download_count_db() {
        use crate::api::handlers::test_db_helpers as tdh;
        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let (repo_id, repo_key, _dir) = tdh::create_repo(&pool, "remote", "generic").await;

        // Record one proxy serve through the canonical recorder (the same
        // helper the serve paths call), which also ensures the catalog row.
        crate::services::proxy_catalog::record_proxy_download(
            &pool,
            repo_id,
            "files/obj.bin",
            "proxy-cache/k/files/obj.bin/__content__",
            "proxy-cache/k/files/obj.bin/__meta__",
            None,
            None,
            Some("analytics-test"),
        )
        .await
        .expect("record proxy download");

        // The recorder ensures the catalog row with size 0; give it a size so
        // the byte rollup is distinguishable from the count.
        sqlx::query("UPDATE proxy_cache_artifacts SET size_bytes = 4096 WHERE repository_id = $1")
            .bind(repo_id)
            .execute(&pool)
            .await
            .expect("size the cached object");

        // A hosted repository holding LESS than the cached object above: the
        // breakdown orders by hosted + proxy bytes, so the remote repo (all of
        // whose bytes live in the proxy catalog) must still come first.
        let (hosted_repo_id, _hosted_key, _hosted_dir) =
            tdh::create_repo(&pool, "local", "generic").await;
        sqlx::query(
            "INSERT INTO artifacts \
               (id, repository_id, path, name, size_bytes, checksum_sha256, \
                content_type, storage_key, is_deleted) \
             VALUES ($1, $2, 'small.bin', 'small.bin', 1024, repeat('a', 64), \
                     'application/octet-stream', 'local/small.bin', false)",
        )
        .bind(Uuid::new_v4())
        .bind(hosted_repo_id)
        .execute(&pool)
        .await
        .expect("insert hosted artifact");

        let service = AnalyticsService::new(pool.clone());

        // Per-repo surface: the fresh repo reports exactly the one proxy
        // serve, with zero hosted downloads.
        let breakdown = service
            .get_storage_breakdown()
            .await
            .expect("storage breakdown");
        let row = breakdown
            .iter()
            .find(|b| b.repository_id == repo_id)
            .expect("fresh repo present in breakdown");
        let (proxy_count, hosted_count, row_key) = (
            row.proxy_download_count,
            row.download_count,
            row.repository_key.clone(),
        );
        let (proxy_artifacts, proxy_bytes, hosted_artifacts, hosted_bytes) = (
            row.proxy_artifact_count,
            row.proxy_storage_bytes,
            row.artifact_count,
            row.storage_bytes,
        );

        // Ordering: the proxy-only repo (4096 cached bytes) outranks the hosted
        // repo (1024 bytes). Pre-change the ORDER BY saw only hosted bytes and
        // put the remote repo last.
        let rank = |id: Uuid| breakdown.iter().position(|b| b.repository_id == id);
        let (remote_rank, hosted_rank) = (rank(repo_id), rank(hosted_repo_id));

        let today = chrono::Utc::now().date_naive();

        // Snapshot surface: today's capture carries the proxy halves too, so
        // the storage trend stops under-reporting pull-through caches
        // (migration 210).
        service
            .capture_daily_snapshot()
            .await
            .expect("capture snapshot");
        let snapshot = service
            .get_storage_trend(today, today)
            .await
            .expect("storage trend")
            .pop()
            .expect("today's snapshot");
        let (snap_proxy_artifacts, snap_proxy_bytes, snap_proxy_downloads) = (
            snapshot.proxy_artifact_count,
            snapshot.proxy_storage_bytes,
            snapshot.proxy_download_count,
        );

        // Instance trend surface: today's point includes the proxy serve.
        // (Shared test DB: other tests may add rows concurrently, so assert
        // presence via >= 1, not an exact count.)
        let trends = service
            .get_download_trends(today, today)
            .await
            .expect("download trends");
        let today_proxy = trends
            .iter()
            .find(|t| t.date == today)
            .map(|t| t.proxy_download_count)
            .unwrap_or(0);

        // Cleanup BEFORE asserting so a failure still leaves the DB clean
        // (repo delete cascades the catalog + proxy stat rows).
        let _ = sqlx::query("DELETE FROM repositories WHERE id = ANY($1)")
            .bind(vec![repo_id, hosted_repo_id])
            .execute(&pool)
            .await;

        assert_eq!(row_key, repo_key);
        assert_eq!(
            proxy_count, 1,
            "per-repo breakdown must surface the recorded proxy serve (#2704)"
        );
        assert_eq!(
            hosted_count, 0,
            "hosted download_count must be unchanged by proxy serves"
        );
        assert_eq!(
            (proxy_artifacts, proxy_bytes),
            (1, 4096),
            "per-repo breakdown must surface the cached object's count and bytes"
        );
        assert_eq!(
            (hosted_artifacts, hosted_bytes),
            (0, 0),
            "hosted artifact_count/storage_bytes must be unchanged by proxy caching"
        );
        assert!(
            today_proxy >= 1,
            "downloads/trend must include today's proxy serve in proxy_download_count (#2704), got {today_proxy}"
        );
        assert!(
            remote_rank < hosted_rank,
            "breakdown must order by hosted + proxy bytes: remote repo ranked \
             {remote_rank:?}, smaller hosted repo {hosted_rank:?}"
        );
        assert!(
            snap_proxy_artifacts >= 1 && snap_proxy_bytes >= 4096 && snap_proxy_downloads >= 1,
            "daily snapshot must carry the proxy halves (migration 210), got \
             {snap_proxy_artifacts} objects / {snap_proxy_bytes} bytes / {snap_proxy_downloads} serves"
        );
    }

    /// Migration 212 must fill the proxy halves of a snapshot captured before
    /// 196 landed, reconstructing them from the proxy tables' own timestamps.
    /// Without it the storage trend shows a wall of zeros with only today's
    /// row populated. Exercises the migration's statement scoped to one
    /// historic snapshot date, as `repository_service`'s ledger true-up test
    /// does for migration 183.
    #[tokio::test]
    async fn test_storage_metrics_proxy_backfill_fills_historic_rows_db() {
        use crate::api::handlers::test_db_helpers as tdh;
        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let (repo_id, _key, _dir) = tdh::create_repo(&pool, "remote", "generic").await;

        // A cached object and a serve, both dated well before any snapshot a
        // concurrent test could write, so the cumulative figures are stable.
        let cache_id = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO proxy_cache_artifacts \
               (id, repository_id, path, storage_key, metadata_key, size_bytes, cached_at) \
             VALUES ($1, $2, 'files/old.bin', 'proxy-cache/k/old/__content__', \
                     'proxy-cache/k/old/__meta__', 4096, '1990-06-01T00:00:00Z')",
        )
        .bind(cache_id)
        .bind(repo_id)
        .execute(&pool)
        .await
        .expect("insert historic cache row");
        sqlx::query(
            "INSERT INTO proxy_download_statistics (proxy_cache_id, downloaded_at) \
             VALUES ($1, '1990-06-02T00:00:00Z')",
        )
        .bind(cache_id)
        .execute(&pool)
        .await
        .expect("insert historic proxy serve");

        // A pre-210 snapshot: hosted figures present, proxy halves at 0.
        let day = NaiveDate::from_ymd_opt(1990, 7, 1).unwrap();
        sqlx::query(
            "INSERT INTO storage_metrics \
               (snapshot_date, total_repositories, total_artifacts, total_storage_bytes, \
                total_downloads, total_users) \
             VALUES ($1, 1, 0, 0, 0, 1) \
             ON CONFLICT (snapshot_date) DO UPDATE SET \
                proxy_artifact_count = 0, proxy_storage_bytes = 0, proxy_download_count = 0",
        )
        .bind(day)
        .execute(&pool)
        .await
        .expect("insert historic snapshot");

        // What the proxy tables say as of that date — the figure the migration
        // must land in the row.
        let (want_objects, want_bytes): (i64, i64) = sqlx::query_as(
            "SELECT COUNT(*)::BIGINT, COALESCE(SUM(size_bytes), 0)::BIGINT \
             FROM proxy_cache_artifacts WHERE cached_at::date <= $1",
        )
        .bind(day)
        .fetch_one(&pool)
        .await
        .expect("expected cache totals");
        let want_serves: i64 = sqlx::query_scalar(
            "SELECT COUNT(*)::BIGINT FROM proxy_download_statistics \
             WHERE downloaded_at::date <= $1",
        )
        .bind(day)
        .fetch_one(&pool)
        .await
        .expect("expected serve total");

        // Migration 212's statement, scoped to this snapshot date so
        // concurrently running DB tests are untouched.
        sqlx::query(
            "WITH cache_daily AS ( \
                 SELECT cached_at::date AS day, COUNT(*)::BIGINT AS objects, \
                        COALESCE(SUM(size_bytes), 0)::BIGINT AS bytes \
                 FROM proxy_cache_artifacts GROUP BY 1 \
             ), serve_daily AS ( \
                 SELECT downloaded_at::date AS day, COUNT(*)::BIGINT AS serves \
                 FROM proxy_download_statistics GROUP BY 1 \
             ) \
             UPDATE storage_metrics sm \
             SET proxy_artifact_count = COALESCE( \
                     (SELECT SUM(objects) FROM cache_daily WHERE day <= sm.snapshot_date), 0)::BIGINT, \
                 proxy_storage_bytes = COALESCE( \
                     (SELECT SUM(bytes) FROM cache_daily WHERE day <= sm.snapshot_date), 0)::BIGINT, \
                 proxy_download_count = COALESCE( \
                     (SELECT SUM(serves) FROM serve_daily WHERE day <= sm.snapshot_date), 0)::BIGINT \
             WHERE sm.snapshot_date = $1 \
               AND sm.proxy_artifact_count = 0 \
               AND sm.proxy_storage_bytes = 0 \
               AND sm.proxy_download_count = 0",
        )
        .bind(day)
        .execute(&pool)
        .await
        .expect("run backfill");

        let got: (i64, i64, i64) = sqlx::query_as(
            "SELECT proxy_artifact_count, proxy_storage_bytes, proxy_download_count \
             FROM storage_metrics WHERE snapshot_date = $1",
        )
        .bind(day)
        .fetch_one(&pool)
        .await
        .expect("read back snapshot");

        // Cleanup BEFORE asserting so a failure still leaves the DB clean.
        let _ = sqlx::query("DELETE FROM storage_metrics WHERE snapshot_date = $1")
            .bind(day)
            .execute(&pool)
            .await;
        let _ = sqlx::query("DELETE FROM repositories WHERE id = $1")
            .bind(repo_id)
            .execute(&pool)
            .await;

        assert!(
            got.0 > 0 && got.1 > 0 && got.2 > 0,
            "historic row must stop reporting zero remote usage, got {got:?}"
        );
        assert_eq!(
            got,
            (want_objects, want_bytes, want_serves),
            "backfill must reconstruct the cumulative proxy figures as of the snapshot date"
        );
    }

    /// DB-backed regression for #3249: the daily `storage_metrics` snapshot's
    /// `total_storage_bytes` must include OCI layer/config blob bytes
    /// (`oci_blobs` — only manifests land in `artifacts`) and proxy-cached
    /// bytes (`proxy_cache_artifacts`), and must NOT count legacy backfilled
    /// `proxy-cache/%` `artifacts` rows. Same accounting (and same fixture
    /// semantics) as the #3134 dashboard test
    /// (`admin::tests::test_system_stats_total_storage_includes_oci_blob_bytes`):
    ///  - LOGICAL counting: a blob digest cross-repo-mounted into two
    ///    repositories counts once per repository, and extra
    ///    `manifest_blob_refs` rows for the same blob do NOT multiply it;
    ///  - positive control: a non-OCI repository's hosted bytes are still
    ///    counted unchanged.
    ///
    /// Test-strategy note (why #3249 was scoped out of #3134's PR): the
    /// snapshot upsert is keyed cluster-wide on `CURRENT_DATE`, so the
    /// written row can never be fixture-scoped — any global-value assertion
    /// races every concurrently running test (the #3129 flake class). This
    /// test therefore never asserts the stored row's absolute value. It calls
    /// `capture_daily_snapshot()` itself before and after seeding and asserts
    /// the DELTA between the two RETURNING payloads, with the two defenses
    /// the #3134 test proved out under a full parallel suite run:
    ///  - fixture sizes are TERABYTE-scale integers (no real storage is
    ///    written), so every wrong composition (blob bytes missing, legacy
    ///    row double count, per-reference multiplication, physical-once
    ///    dedup) lands >= 23 TB outside the window while concurrent tests
    ///    move KBs-to-GBs;
    ///  - the check tolerates +/- `SLACK` (10 GB) of unrelated churn inside
    ///    the observation window and retries a few times.
    /// The repeated upserts themselves are safe: each overwrites today's row
    /// with a fresh cluster-wide aggregate, which is exactly what the daily
    /// scheduler does, and no other test asserts `storage_metrics` contents.
    #[tokio::test]
    async fn test_capture_daily_snapshot_includes_oci_blob_and_proxy_cache_bytes() {
        use crate::api::handlers::test_db_helpers as tdh;
        use crate::services::repository_service::RepositoryService;

        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let service = AnalyticsService::new(pool.clone());
        let repo_service = RepositoryService::new(pool.clone());

        // Distinctive prime multiples of 1 TB so the expected delta cannot be
        // assembled by accident from a different combination of components.
        const TB: i64 = 1_000_000_000_000;
        const MANIFEST: i64 = 11 * TB; // artifacts row in the docker repo
        const BLOB_SHARED: i64 = 23 * TB; // digest mounted in BOTH docker repos
        const BLOB_SOLO: i64 = 37 * TB; // blob only in the first docker repo
        const HOSTED_PLAIN: i64 = 41 * TB; // artifacts row in the generic repo (positive control)
        const LEGACY: i64 = 53 * TB; // legacy `proxy-cache/%` artifacts row (must be excluded)
        const CACHED: i64 = 61 * TB; // proxy_cache_artifacts catalog row
        const SLACK: i64 = 10_000_000_000; // unrelated concurrent churn budget

        // Once per repo: BLOB_SHARED twice (two repos), refs don't multiply,
        // legacy row excluded.
        const EXPECTED_TOTAL_DELTA: i64 =
            MANIFEST + 2 * BLOB_SHARED + BLOB_SOLO + HOSTED_PLAIN + CACHED;

        let (oci_a, _, _) = tdh::create_repo(&pool, "local", "docker").await;
        let (oci_b, _, _) = tdh::create_repo(&pool, "local", "docker").await;
        let (plain, _, _) = tdh::create_repo(&pool, "local", "generic").await;
        let (remote, _, _) = tdh::create_repo(&pool, "remote", "pypi").await;
        let repo_ids = [oci_a, oci_b, plain, remote];

        let mut matched = false;
        for _attempt in 0..5 {
            let before = service
                .capture_daily_snapshot()
                .await
                .expect("capture baseline snapshot");

            let digest_shared = format!("sha256:{:0>64}", Uuid::new_v4().simple());
            let digest_solo = format!("sha256:{:0>64}", Uuid::new_v4().simple());

            for (repo, name, size, storage_key) in [
                (
                    oci_a,
                    "manifest",
                    MANIFEST,
                    format!("oci/{oci_a}/manifests/m"),
                ),
                (
                    plain,
                    "plain",
                    HOSTED_PLAIN,
                    format!("generic/{plain}/plain.bin"),
                ),
                (
                    remote,
                    "legacy",
                    LEGACY,
                    format!("proxy-cache/{remote}/legacy.whl"),
                ),
            ] {
                sqlx::query(
                    "INSERT INTO artifacts (repository_id, path, name, version, size_bytes, \
                     checksum_sha256, content_type, storage_key) \
                     VALUES ($1, $2, $3, '1.0.0', $4, $5, 'application/octet-stream', $6)",
                )
                .bind(repo)
                .bind(format!("snapshot-3249/{name}/{}", Uuid::new_v4()))
                .bind(name)
                .bind(size)
                .bind(format!("{:0>64}", "3249"))
                .bind(storage_key)
                .execute(&pool)
                .await
                .expect("seed artifacts row");
            }

            for (repo, digest, size) in [
                (oci_a, &digest_shared, BLOB_SHARED),
                (oci_b, &digest_shared, BLOB_SHARED),
                (oci_a, &digest_solo, BLOB_SOLO),
            ] {
                sqlx::query(
                    "INSERT INTO oci_blobs (repository_id, digest, size_bytes, storage_key) \
                     VALUES ($1, $2, $3, $4)",
                )
                .bind(repo)
                .bind(digest)
                .bind(size)
                .bind(format!("oci-blobs/{digest}"))
                .execute(&pool)
                .await
                .expect("seed oci_blobs row");
            }

            // Two manifests referencing the shared blob in the same repo:
            // per-REFERENCE counting would inflate the figure; per-repo-row
            // counting (the ledger's) must not.
            for i in 0..2 {
                sqlx::query(
                    "INSERT INTO manifest_blob_refs \
                     (manifest_digest, blob_digest, repository_id, kind) \
                     VALUES ($1, $2, $3, 'layer')",
                )
                .bind(format!("sha256:{:0>63}{i}", Uuid::new_v4().simple()))
                .bind(&digest_shared)
                .bind(oci_a)
                .execute(&pool)
                .await
                .expect("seed manifest_blob_refs row");
            }

            sqlx::query(
                "INSERT INTO proxy_cache_artifacts \
                 (repository_id, path, storage_key, metadata_key, size_bytes) \
                 VALUES ($1, $2, $3, $4, $5)",
            )
            .bind(remote)
            .bind("snapshot-3249/legacy.whl")
            .bind(format!(
                "proxy-cache/{remote}/snapshot-3249/legacy.whl/__content__"
            ))
            .bind(format!(
                "proxy-cache/{remote}/snapshot-3249/legacy.whl/__cache_meta__.json"
            ))
            .bind(CACHED)
            .execute(&pool)
            .await
            .expect("seed proxy cache row");

            // The migration-182 triggers charge the ledger inline; reconcile
            // anyway so the assertion binds to the documented authoritative
            // per-repo sums rather than to trigger bookkeeping.
            for repo in repo_ids {
                repo_service
                    .reconcile_usage_ledger(repo)
                    .await
                    .expect("reconcile usage ledger");
            }

            let after = service
                .capture_daily_snapshot()
                .await
                .expect("capture post-seed snapshot");

            // Remove this attempt's rows before deciding, so a retry re-seeds
            // from a clean slate.
            for table in ["manifest_blob_refs", "oci_blobs", "proxy_cache_artifacts"] {
                let sql = format!("DELETE FROM {table} WHERE repository_id = ANY($1)");
                sqlx::query(sqlx::AssertSqlSafe(&*sql))
                    .bind(&repo_ids[..])
                    .execute(&pool)
                    .await
                    .expect("cleanup seeded rows");
            }
            sqlx::query("DELETE FROM artifacts WHERE repository_id = ANY($1)")
                .bind(&repo_ids[..])
                .execute(&pool)
                .await
                .expect("cleanup seeded artifacts");

            let total_delta = after.total_storage_bytes - before.total_storage_bytes;
            if (total_delta - EXPECTED_TOTAL_DELTA).abs() <= SLACK {
                matched = true;
                break;
            }
            eprintln!(
                "attempt saw snapshot total_storage_bytes delta {total_delta} \
                 (expected {EXPECTED_TOTAL_DELTA}); retrying"
            );
        }
        // Clean up the fixture repositories BEFORE asserting, so a failing
        // run does not leak them into the shared test database.
        sqlx::query("DELETE FROM repositories WHERE id = ANY($1)")
            .bind(&repo_ids[..])
            .execute(&pool)
            .await
            .expect("cleanup repos");

        assert!(
            matched,
            "capture_daily_snapshot never reflected the seeded storage: expected \
             total_storage_bytes +{EXPECTED_TOTAL_DELTA} +/- {SLACK} (manifest {MANIFEST} + \
             shared blob {BLOB_SHARED} once per mounted repo + solo blob {BLOB_SOLO} + hosted \
             {HOSTED_PLAIN} + cached {CACHED}, legacy proxy-cache/% row {LEGACY} excluded)"
        );
    }
}
