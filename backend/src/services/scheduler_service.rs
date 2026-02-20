//! Background task scheduler.
//!
//! Runs periodic tasks: daily metric snapshots, lifecycle policy execution,
//! health monitoring, backup schedule execution, and metric gauge updates.

use chrono::Utc;
use cron::Schedule;
use sqlx::PgPool;
use std::str::FromStr;
use std::sync::Arc;
use tokio::time::{interval, Duration};

use crate::config::Config;
use crate::services::analytics_service::AnalyticsService;
use crate::services::backup_service::{BackupService, BackupType, CreateBackupRequest};
use crate::services::health_monitor_service::{HealthMonitorService, MonitorConfig};
use crate::services::lifecycle_service::LifecycleService;
use crate::services::metrics_service;
use crate::services::storage_service::StorageService;
use crate::services::sync_policy_service::SyncPolicyService;

/// Database gauge stats for Prometheus metrics.
#[derive(Debug, sqlx::FromRow)]
struct GaugeStats {
    pub repos: i64,
    pub artifacts: i64,
    pub storage: i64,
    pub users: i64,
}

/// Spawn all background scheduler tasks.
/// Returns join handles for graceful shutdown (not currently used, fire-and-forget).
pub fn spawn_all(
    db: PgPool,
    config: Config,
    primary_storage: Arc<dyn crate::storage::StorageBackend>,
) {
    // Daily metrics snapshot (runs every hour, captures once per day via UPSERT)
    {
        let db = db.clone();
        tokio::spawn(async move {
            // Initial delay to let the server start up
            tokio::time::sleep(Duration::from_secs(30)).await;
            let service = AnalyticsService::new(db);
            let mut ticker = interval(Duration::from_secs(3600)); // 1 hour

            loop {
                ticker.tick().await;
                tracing::debug!("Running daily metrics snapshot");

                if let Err(e) = service.capture_daily_snapshot().await {
                    tracing::warn!("Failed to capture daily storage snapshot: {}", e);
                }
                if let Err(e) = service.capture_repository_snapshots().await {
                    tracing::warn!("Failed to capture repository snapshots: {}", e);
                }
            }
        });
    }

    // Gauge metrics updater (every 5 minutes)
    {
        let db = db.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_secs(10)).await;
            let mut ticker = interval(Duration::from_secs(300)); // 5 minutes

            loop {
                ticker.tick().await;
                if let Err(e) = update_gauge_metrics(&db).await {
                    tracing::warn!("Failed to update gauge metrics: {}", e);
                }
            }
        });
    }

    // Health monitoring (every 60 seconds)
    {
        let db = db.clone();
        let config_clone = config.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_secs(15)).await;
            let monitor = HealthMonitorService::new(db, MonitorConfig::default());
            let mut ticker = interval(Duration::from_secs(60));

            loop {
                ticker.tick().await;
                match monitor.check_all_services(&config_clone).await {
                    Ok(results) => {
                        for entry in &results {
                            if entry.status != "healthy" {
                                tracing::warn!(
                                    "Service '{}' is {}: {:?}",
                                    entry.service_name,
                                    entry.status,
                                    entry.message
                                );
                            }
                        }
                    }
                    Err(e) => {
                        tracing::warn!("Health monitoring cycle failed: {}", e);
                    }
                }
            }
        });
    }

    // Lifecycle policy execution (every 6 hours)
    {
        let db = db.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_secs(60)).await;
            let service = LifecycleService::new(db);
            let mut ticker = interval(Duration::from_secs(6 * 3600)); // 6 hours

            loop {
                ticker.tick().await;
                tracing::info!("Running scheduled lifecycle policy execution");

                match service.execute_all_enabled().await {
                    Ok(results) => {
                        let total_removed: i64 = results.iter().map(|r| r.artifacts_removed).sum();
                        let total_freed: i64 = results.iter().map(|r| r.bytes_freed).sum();
                        if total_removed > 0 {
                            tracing::info!(
                                "Lifecycle cleanup: removed {} artifacts, freed {} bytes across {} policies",
                                total_removed,
                                total_freed,
                                results.len()
                            );
                            metrics_service::record_cleanup("lifecycle", total_removed as u64);
                        }
                    }
                    Err(e) => {
                        tracing::warn!("Lifecycle policy execution failed: {}", e);
                    }
                }
            }
        });
    }

    // Storage garbage collection (every hour)
    {
        let db = db.clone();
        let config_clone = config.clone();
        let gc_storage = primary_storage.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_secs(120)).await;
            let service = crate::services::storage_gc_service::StorageGcService::new(
                db,
                gc_storage,
                config_clone.storage_backend.clone(),
            );
            let mut ticker = interval(Duration::from_secs(3600)); // 1 hour

            loop {
                ticker.tick().await;
                tracing::info!("Running scheduled storage garbage collection");

                match service.run_gc(false).await {
                    Ok(result) => {
                        if result.storage_keys_deleted > 0 {
                            tracing::info!(
                                "Storage GC: deleted {} keys, removed {} artifacts, freed {} bytes",
                                result.storage_keys_deleted,
                                result.artifacts_removed,
                                result.bytes_freed
                            );
                            metrics_service::record_cleanup(
                                "storage_gc",
                                result.artifacts_removed as u64,
                            );
                        }
                        if !result.errors.is_empty() {
                            tracing::warn!(
                                "Storage GC completed with {} errors",
                                result.errors.len()
                            );
                        }
                    }
                    Err(e) => {
                        tracing::warn!("Storage garbage collection failed: {}", e);
                    }
                }
            }
        });
    }

    // Backup schedule execution (check every 5 minutes)
    {
        let db = db.clone();
        let config_clone = config.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_secs(45)).await;
            let mut ticker = interval(Duration::from_secs(300)); // 5 minutes

            loop {
                ticker.tick().await;
                if let Err(e) = execute_due_backup_schedules(&db, &config_clone).await {
                    tracing::warn!("Backup schedule check failed: {}", e);
                }
            }
        });
    }

    // Sync policy re-evaluation (every 5 minutes)
    {
        let db = db.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_secs(120)).await;
            let mut ticker = interval(Duration::from_secs(300)); // 5 minutes

            loop {
                ticker.tick().await;
                tracing::debug!("Running periodic sync policy evaluation");

                let svc = SyncPolicyService::new(db.clone());
                if let Err(e) = svc.evaluate_policies().await {
                    tracing::warn!("Periodic sync policy evaluation failed: {}", e);
                }
            }
        });
    }

    tracing::info!(
        "Background schedulers started: metrics, health monitor, lifecycle, backup schedules, sync policies"
    );
}

/// A row from the backup_schedules table.
#[derive(Debug, sqlx::FromRow)]
struct BackupScheduleRow {
    pub id: uuid::Uuid,
    pub name: String,
    pub backup_type: BackupType,
    pub cron_expression: String,
    pub include_repositories: Option<Vec<uuid::Uuid>>,
}

/// Check for due backup schedules and execute them.
async fn execute_due_backup_schedules(db: &PgPool, config: &Config) -> crate::error::Result<()> {
    // Find schedules where next_run_at <= now
    let due_schedules = sqlx::query_as::<_, BackupScheduleRow>(
        r#"
        SELECT id, name, backup_type, cron_expression, include_repositories
        FROM backup_schedules
        WHERE is_enabled = true
          AND (next_run_at IS NULL OR next_run_at <= NOW())
        ORDER BY next_run_at ASC NULLS FIRST
        LIMIT 5
        "#,
    )
    .fetch_all(db)
    .await
    .map_err(|e| crate::error::AppError::Database(e.to_string()))?;

    if due_schedules.is_empty() {
        return Ok(());
    }

    let storage = match StorageService::from_config(config).await {
        Ok(s) => Arc::new(s),
        Err(e) => {
            tracing::error!(
                "Failed to create storage service for scheduled backups: {}",
                e
            );
            return Err(e);
        }
    };

    for schedule_row in &due_schedules {
        tracing::info!(
            "Executing scheduled backup '{}' (type: {:?})",
            schedule_row.name,
            schedule_row.backup_type
        );

        let service = BackupService::new(db.clone(), storage.clone());

        // Create and execute the backup
        let create_result = service
            .create(CreateBackupRequest {
                backup_type: schedule_row.backup_type,
                repository_ids: schedule_row.include_repositories.clone(),
                created_by: None, // system-initiated
            })
            .await;

        let backup_type_str = format!("{:?}", schedule_row.backup_type).to_lowercase();
        let start = std::time::Instant::now();

        match create_result {
            Ok(backup) => match service.execute(backup.id).await {
                Ok(completed) => {
                    let elapsed = start.elapsed().as_secs_f64();
                    tracing::info!(
                        "Scheduled backup '{}' completed: {} bytes, {} artifacts",
                        schedule_row.name,
                        completed.size_bytes.unwrap_or(0),
                        completed.artifact_count.unwrap_or(0)
                    );
                    metrics_service::record_backup(&backup_type_str, true, elapsed);
                }
                Err(e) => {
                    let elapsed = start.elapsed().as_secs_f64();
                    tracing::error!(
                        "Scheduled backup '{}' execution failed: {}",
                        schedule_row.name,
                        e
                    );
                    metrics_service::record_backup(&backup_type_str, false, elapsed);
                }
            },
            Err(e) => {
                let elapsed = start.elapsed().as_secs_f64();
                tracing::error!(
                    "Failed to create scheduled backup '{}': {}",
                    schedule_row.name,
                    e
                );
                metrics_service::record_backup(&backup_type_str, false, elapsed);
            }
        }

        // Compute and update next_run_at from cron expression
        let next_run = compute_next_run(&schedule_row.cron_expression);
        let _ = sqlx::query(
            "UPDATE backup_schedules SET last_run_at = NOW(), next_run_at = $2, updated_at = NOW() WHERE id = $1",
        )
        .bind(schedule_row.id)
        .bind(next_run)
        .execute(db)
        .await;
    }

    Ok(())
}

/// Normalize a cron expression: if 5-field, prepend "0 " for the seconds field.
pub(crate) fn normalize_cron_expression(cron_expr: &str) -> String {
    if cron_expr.split_whitespace().count() == 5 {
        format!("0 {}", cron_expr)
    } else {
        cron_expr.to_string()
    }
}

/// Parse a (possibly already normalized) cron expression into a Schedule.
/// Returns None if the expression is invalid.
pub(crate) fn parse_cron_schedule(normalized: &str) -> Option<Schedule> {
    Schedule::from_str(normalized).ok()
}

/// Parse a cron expression and compute the next run time.
fn compute_next_run(cron_expr: &str) -> Option<chrono::DateTime<Utc>> {
    let normalized = normalize_cron_expression(cron_expr);

    match parse_cron_schedule(&normalized) {
        Some(schedule) => schedule.upcoming(Utc).next(),
        None => {
            tracing::warn!(
                "Invalid cron expression '{}'. Falling back to 24h from now.",
                cron_expr,
            );
            Some(Utc::now() + chrono::Duration::hours(24))
        }
    }
}

/// Update Prometheus gauge metrics from database state.
async fn update_gauge_metrics(db: &PgPool) -> crate::error::Result<()> {
    let stats = sqlx::query_as::<_, GaugeStats>(
        r#"
        SELECT
            (SELECT COUNT(*) FROM repositories) as repos,
            (SELECT COUNT(*) FROM artifacts WHERE is_deleted = false) as artifacts,
            (SELECT COALESCE(SUM(size_bytes), 0)::BIGINT FROM artifacts WHERE is_deleted = false) as storage,
            (SELECT COUNT(*) FROM users) as users
        "#,
    )
    .fetch_one(db)
    .await
    .map_err(|e| crate::error::AppError::Database(e.to_string()))?;

    metrics_service::set_storage_gauge(stats.storage, stats.artifacts, stats.repos);
    metrics_service::set_user_gauge(stats.users);
    metrics_service::set_db_pool_gauges(db);

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // compute_next_run
    // -----------------------------------------------------------------------

    #[test]
    fn test_compute_next_run_valid_5_field_cron() {
        // Every day at midnight: "0 0 * * *"
        let result = compute_next_run("0 0 * * *");
        assert!(
            result.is_some(),
            "Should parse a valid 5-field cron expression"
        );
        let next = result.unwrap();
        assert!(next > Utc::now(), "Next run should be in the future");
    }

    #[test]
    fn test_compute_next_run_valid_6_field_cron() {
        // 6-field with seconds: "0 0 0 * * *"  (every day at midnight)
        let result = compute_next_run("0 0 0 * * *");
        assert!(
            result.is_some(),
            "Should parse a valid 6-field cron expression"
        );
        let next = result.unwrap();
        assert!(next > Utc::now());
    }

    #[test]
    fn test_compute_next_run_valid_7_field_cron() {
        // 7-field with seconds and year: "0 30 9 * * * *"
        let result = compute_next_run("0 30 9 * * * *");
        assert!(
            result.is_some(),
            "Should parse a valid 7-field cron expression"
        );
    }

    #[test]
    fn test_compute_next_run_every_minute() {
        // Every minute: "* * * * *"
        let result = compute_next_run("* * * * *");
        assert!(result.is_some());
        let next = result.unwrap();
        // Should be within 60 seconds from now
        let diff = next - Utc::now();
        assert!(diff.num_seconds() <= 60);
    }

    #[test]
    fn test_compute_next_run_invalid_cron_falls_back_to_24h() {
        let before = Utc::now();
        let result = compute_next_run("this is not valid cron");
        assert!(
            result.is_some(),
            "Invalid cron should fall back to 24h from now"
        );
        let next = result.unwrap();
        // Should be roughly 24 hours from now (allow some tolerance)
        let diff = next - before;
        assert!(
            diff.num_hours() >= 23 && diff.num_hours() <= 25,
            "Fallback should be ~24 hours from now, got {} hours",
            diff.num_hours()
        );
    }

    #[test]
    fn test_compute_next_run_empty_string_falls_back() {
        let result = compute_next_run("");
        assert!(result.is_some(), "Empty string should fall back to 24h");
        let diff = result.unwrap() - Utc::now();
        assert!(diff.num_hours() >= 23);
    }

    #[test]
    fn test_compute_next_run_5_field_prepends_seconds() {
        // The function should prepend "0 " for 5-field expressions
        // "30 2 * * *" -> "0 30 2 * * *" (2:30 AM daily)
        let result = compute_next_run("30 2 * * *");
        assert!(result.is_some());
    }

    #[test]
    fn test_compute_next_run_hourly() {
        // Every hour at minute 0: "0 * * * *"
        let result = compute_next_run("0 * * * *");
        assert!(result.is_some());
        let next = result.unwrap();
        let diff = next - Utc::now();
        assert!(diff.num_minutes() <= 60);
    }

    // -----------------------------------------------------------------------
    // GaugeStats struct
    // -----------------------------------------------------------------------

    #[test]
    fn test_gauge_stats_construction() {
        let stats = GaugeStats {
            repos: 10,
            artifacts: 500,
            storage: 1_073_741_824, // 1 GB
            users: 25,
        };
        assert_eq!(stats.repos, 10);
        assert_eq!(stats.artifacts, 500);
        assert_eq!(stats.storage, 1_073_741_824);
        assert_eq!(stats.users, 25);
    }

    #[test]
    fn test_gauge_stats_debug() {
        let stats = GaugeStats {
            repos: 0,
            artifacts: 0,
            storage: 0,
            users: 0,
        };
        let debug_str = format!("{:?}", stats);
        assert!(debug_str.contains("GaugeStats"));
        assert!(debug_str.contains("repos: 0"));
    }

    // -----------------------------------------------------------------------
    // BackupScheduleRow struct
    // -----------------------------------------------------------------------

    #[test]
    fn test_backup_schedule_row_construction() {
        let row = BackupScheduleRow {
            id: uuid::Uuid::new_v4(),
            name: "nightly-backup".to_string(),
            backup_type: BackupType::Full,
            cron_expression: "0 2 * * *".to_string(),
            include_repositories: None,
        };
        assert_eq!(row.name, "nightly-backup");
        assert_eq!(row.cron_expression, "0 2 * * *");
        assert!(row.include_repositories.is_none());
    }

    #[test]
    fn test_backup_schedule_row_with_repositories() {
        let repo_ids = vec![uuid::Uuid::new_v4(), uuid::Uuid::new_v4()];
        let row = BackupScheduleRow {
            id: uuid::Uuid::new_v4(),
            name: "selective-backup".to_string(),
            backup_type: BackupType::Incremental,
            cron_expression: "0 3 * * 0".to_string(),
            include_repositories: Some(repo_ids.clone()),
        };
        assert_eq!(row.include_repositories.as_ref().unwrap().len(), 2);
    }

    #[test]
    fn test_backup_schedule_row_debug() {
        let row = BackupScheduleRow {
            id: uuid::Uuid::new_v4(),
            name: "test".to_string(),
            backup_type: BackupType::Metadata,
            cron_expression: "0 0 * * *".to_string(),
            include_repositories: None,
        };
        let debug_str = format!("{:?}", row);
        assert!(debug_str.contains("BackupScheduleRow"));
        assert!(debug_str.contains("test"));
    }

    // -----------------------------------------------------------------------
    // normalize_cron_expression (extracted pure function)
    // -----------------------------------------------------------------------

    #[test]
    fn test_normalize_cron_5_field() {
        assert_eq!(normalize_cron_expression("0 0 * * *"), "0 0 0 * * *");
    }

    #[test]
    fn test_normalize_cron_6_field_unchanged() {
        assert_eq!(normalize_cron_expression("0 0 0 * * *"), "0 0 0 * * *");
    }

    #[test]
    fn test_normalize_cron_7_field_unchanged() {
        assert_eq!(
            normalize_cron_expression("0 30 9 * * * *"),
            "0 30 9 * * * *"
        );
    }

    #[test]
    fn test_normalize_cron_1_field_unchanged() {
        // Less than 5 fields, not modified
        assert_eq!(normalize_cron_expression("invalid"), "invalid");
    }

    #[test]
    fn test_cron_5_field_detection() {
        let five = "0 0 * * *";
        assert_eq!(five.split_whitespace().count(), 5);

        let six = "0 0 0 * * *";
        assert_eq!(six.split_whitespace().count(), 6);

        let seven = "0 0 0 * * * *";
        assert_eq!(seven.split_whitespace().count(), 7);
    }

    // -----------------------------------------------------------------------
    // parse_cron_schedule (extracted pure function)
    // -----------------------------------------------------------------------

    #[test]
    fn test_parse_cron_schedule_valid() {
        let schedule = parse_cron_schedule("0 0 0 * * *");
        assert!(schedule.is_some());
    }

    #[test]
    fn test_parse_cron_schedule_invalid() {
        let schedule = parse_cron_schedule("not valid cron");
        assert!(schedule.is_none());
    }

    #[test]
    fn test_parse_cron_schedule_empty() {
        let schedule = parse_cron_schedule("");
        assert!(schedule.is_none());
    }

    #[test]
    fn test_parse_cron_schedule_every_minute() {
        // "0 * * * * *" = every minute (with seconds field)
        let schedule = parse_cron_schedule("0 * * * * *");
        assert!(schedule.is_some());
    }

    #[test]
    fn test_parse_cron_schedule_yields_future_times() {
        let schedule = parse_cron_schedule("0 * * * * *").unwrap();
        let next = schedule.upcoming(Utc).next();
        assert!(next.is_some());
        assert!(next.unwrap() > Utc::now());
    }
}
