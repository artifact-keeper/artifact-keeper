//! Background task scheduler.
//!
//! Runs periodic tasks: daily metric snapshots, lifecycle policy execution,
//! health monitoring, backup schedule execution, and metric gauge updates.

use sqlx::PgPool;
use tokio::time::{interval, Duration};

use crate::config::Config;
use crate::services::analytics_service::AnalyticsService;
use crate::services::health_monitor_service::{HealthMonitorService, MonitorConfig};
use crate::services::lifecycle_service::LifecycleService;
use crate::services::metrics_service;

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
pub fn spawn_all(db: PgPool, config: Config) {
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
                        let total_removed: i64 =
                            results.iter().map(|r| r.artifacts_removed).sum();
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

    tracing::info!("Background schedulers started: metrics, health monitor, lifecycle");
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

    Ok(())
}
