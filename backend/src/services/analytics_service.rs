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
    pub total_artifacts: i64,
    pub total_storage_bytes: i64,
    pub total_downloads: i64,
    pub total_users: i64,
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
                total_storage_bytes, total_downloads, total_users
            )
            SELECT
                CURRENT_DATE,
                (SELECT COUNT(*) FROM repositories),
                (SELECT COUNT(*) FROM artifacts WHERE is_deleted = false),
                (SELECT COALESCE(SUM(size_bytes), 0) FROM artifacts WHERE is_deleted = false),
                (SELECT COUNT(*) FROM download_statistics),
                (SELECT COUNT(*) FROM users)
            ON CONFLICT (snapshot_date) DO UPDATE SET
                total_repositories = EXCLUDED.total_repositories,
                total_artifacts = EXCLUDED.total_artifacts,
                total_storage_bytes = EXCLUDED.total_storage_bytes,
                total_downloads = EXCLUDED.total_downloads,
                total_users = EXCLUDED.total_users
            RETURNING
                snapshot_date,
                total_repositories,
                total_artifacts,
                total_storage_bytes,
                total_downloads,
                total_users
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
                total_users
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
                MAX(a.created_at) as last_upload_at
            FROM repositories r
            LEFT JOIN artifacts a ON a.repository_id = r.id AND a.is_deleted = false
            GROUP BY r.id, r.key, r.name, r.format
            ORDER BY COALESCE(SUM(a.size_bytes), 0) DESC
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
                   total_storage_bytes, total_downloads, total_users
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
                   total_storage_bytes, total_downloads, total_users
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
    pub async fn get_download_trends(
        &self,
        from: NaiveDate,
        to: NaiveDate,
    ) -> Result<Vec<DownloadTrend>> {
        let trends = sqlx::query_as::<_, DownloadTrend>(
            r#"
            SELECT
                downloaded_at::DATE as date,
                COUNT(*) as download_count
            FROM download_statistics
            WHERE downloaded_at::DATE BETWEEN $1 AND $2
            GROUP BY downloaded_at::DATE
            ORDER BY downloaded_at::DATE ASC
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
        };
        let json = serde_json::to_value(&snapshot).unwrap();
        assert_eq!(json["snapshot_date"], "2024-06-15");
        assert_eq!(json["total_repositories"], 10);
        assert_eq!(json["total_artifacts"], 500);
        assert_eq!(json["total_storage_bytes"], 1_073_741_824);
        assert_eq!(json["total_downloads"], 5000);
        assert_eq!(json["total_users"], 25);
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
            last_upload_at: Some(Utc::now()),
        };
        let json = serde_json::to_value(&breakdown).unwrap();
        assert_eq!(json["repository_key"], "maven-central");
        assert_eq!(json["format"], "maven");
        assert_eq!(json["artifact_count"], 200);
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
        };
        let json = serde_json::to_value(&trend).unwrap();
        assert_eq!(json["date"], "2024-06-15");
        assert_eq!(json["download_count"], 42);
    }

    #[test]
    fn test_download_trend_deserialization() {
        let json = r#"{"date": "2024-06-15", "download_count": 100}"#;
        let trend: DownloadTrend = serde_json::from_str(json).unwrap();
        assert_eq!(trend.date, NaiveDate::from_ymd_opt(2024, 6, 15).unwrap());
        assert_eq!(trend.download_count, 100);
    }
}
