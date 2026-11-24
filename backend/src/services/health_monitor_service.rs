//! Health monitoring and alert pipeline service.
//!
//! Monitors service health, tracks state transitions, fires webhook alerts,
//! and manages alert suppression to prevent spam during extended outages.

use chrono::{DateTime, Utc};
use futures::future::BoxFuture;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use std::sync::Arc;
use std::time::Duration;
use utoipa::ToSchema;

use crate::config::Config;
use crate::error::{AppError, Result};
use crate::storage::StorageBackend;

/// A health check result for a single service.
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow, ToSchema)]
pub struct ServiceHealthEntry {
    pub service_name: String,
    pub status: String,
    pub previous_status: Option<String>,
    pub message: Option<String>,
    pub response_time_ms: Option<i32>,
    pub checked_at: DateTime<Utc>,
}

/// Alert state for a service.
#[derive(Debug, Serialize, Deserialize, sqlx::FromRow, ToSchema)]
pub struct AlertState {
    pub service_name: String,
    pub current_status: String,
    pub consecutive_failures: i32,
    pub last_alert_sent_at: Option<DateTime<Utc>>,
    pub suppressed_until: Option<DateTime<Utc>>,
    pub updated_at: DateTime<Utc>,
}

/// Configuration for health monitoring thresholds.
#[derive(Debug, Clone)]
pub struct MonitorConfig {
    /// Number of consecutive failures before alerting.
    pub alert_threshold: i32,
    /// Cooldown in minutes between repeat alerts for the same service.
    pub alert_cooldown_minutes: i32,
    /// Timeout for health check HTTP requests in seconds.
    pub check_timeout_secs: u64,
}

impl Default for MonitorConfig {
    fn default() -> Self {
        Self {
            alert_threshold: 3,
            alert_cooldown_minutes: 15,
            check_timeout_secs: 5,
        }
    }
}

/// Webhook event types for health monitoring.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "event_type")]
pub enum HealthEvent {
    ServiceDown {
        service_name: String,
        message: String,
        consecutive_failures: i32,
        timestamp: DateTime<Utc>,
    },
    ServiceRecovered {
        service_name: String,
        downtime_started: Option<DateTime<Utc>>,
        timestamp: DateTime<Utc>,
    },
    ServiceDegraded {
        service_name: String,
        response_time_ms: i32,
        threshold_ms: i32,
        timestamp: DateTime<Utc>,
    },
}

pub struct HealthMonitorService {
    db: PgPool,
    config: MonitorConfig,
    http_client: Client,
}

/// Determine whether the periodic health monitor should probe
/// Dependency-Track. Returns the configured URL only when both the
/// integration is explicitly enabled (`DEPENDENCY_TRACK_ENABLED=true`) and
/// a URL is configured. Any other combination returns `None`, meaning the
/// monitor skips DT entirely (no HTTP probe, no log entry, no alert
/// state).
///
/// This is the single point that gates every periodic DT touch from the
/// monitoring pipeline. It exists as a free function so unit tests can
/// pin the "disabled => no probe" invariant without spinning up a
/// database (issues #1395, #1480).
pub(crate) fn dependency_track_probe_url(config: &Config) -> Option<&str> {
    if !config.dependency_track_enabled {
        return None;
    }
    config.dependency_track_url.as_deref()
}

/// Resolve optional HTTP Basic credentials for a probe, matching
/// `OpenSearchService::new`: auth is applied only when **both** username
/// and password are present. A single-sided credential must not partially
/// authenticate (issue #2944).
pub(crate) fn optional_basic_auth<'a>(
    username: Option<&'a str>,
    password: Option<&'a str>,
) -> Option<(&'a str, &'a str)> {
    match (username, password) {
        (Some(u), Some(p)) => Some((u, p)),
        _ => None,
    }
}

/// OpenSearch monitor credentials from app config (same Basic rule as
/// the search client). Free function so unit tests can pin the matrix
/// without a database or live cluster.
pub(crate) fn opensearch_probe_basic_auth(config: &Config) -> Option<(&str, &str)> {
    optional_basic_auth(
        config.opensearch_username.as_deref(),
        config.opensearch_password.as_deref(),
    )
}

/// Issue a GET probe and map the outcome to monitor status strings.
///
/// When `basic` is `Some((user, pass))`, send HTTP Basic auth — required
/// for secured OpenSearch (e.g. AWS managed + FGAC) so monitoring does
/// not false-red with HTTP 401 while search still works (issue #2944).
pub(crate) async fn probe_http_endpoint(
    client: &Client,
    full_url: &str,
    basic: Option<(&str, &str)>,
) -> (String, Option<String>) {
    let mut req = client.get(full_url);
    if let Some((user, pass)) = basic {
        req = req.basic_auth(user, Some(pass));
    }

    match req.send().await {
        Ok(resp) if resp.status().is_success() => ("healthy".to_string(), None),
        Ok(resp) => (
            "unhealthy".to_string(),
            Some(format!("HTTP {}", resp.status())),
        ),
        Err(e) => (
            "unavailable".to_string(),
            Some(format!("Connection failed: {}", e)),
        ),
    }
}

/// One dependency probe's result, before it is recorded.
struct ProbeOutcome {
    status: String,
    message: Option<String>,
    response_time_ms: i32,
}

fn elapsed_ms(start: std::time::Instant) -> i32 {
    i32::try_from(start.elapsed().as_millis()).unwrap_or(i32::MAX)
}

/// Fold a `/health` check status into the health log's vocabulary
/// (`service_health_log.status` allows healthy, unhealthy, unavailable and
/// degraded): the storage check's `unknown` (an unrecognised backend) is
/// `unhealthy`.
fn monitor_status(status: &str) -> String {
    match status {
        "healthy" | "unhealthy" | "unavailable" | "degraded" => status.to_string(),
        _ => "unhealthy".to_string(),
    }
}

/// The scanner-adapter endpoints the monitor probes (#5651): the adapter
/// image and filesystem scans use (`TRIVY_ADAPTER_URL`), and the scan
/// worker's own adapter (`SCAN_WORKER_TRIVY_ADAPTER_URL`) when it is a
/// different one. Each is probed at the adapter's `/probe/healthy`.
pub(crate) fn scanner_adapter_probe_urls(config: &Config) -> Vec<(&'static str, &str)> {
    let mut urls = Vec::new();
    let primary = config.trivy_adapter_url.as_deref();
    if let Some(url) = primary {
        urls.push(("scanner-adapter", url));
    }
    if let Some(url) = config.scan_worker_trivy_adapter_url.as_deref() {
        if Some(url.trim_end_matches('/')) != primary.map(|p| p.trim_end_matches('/')) {
            urls.push(("scanner-adapter-worker", url));
        }
    }
    urls
}

/// `Some((postgres_started_at, last_check))` when Postgres started after the
/// last recorded database check, i.e. it restarted in between (#5651). No
/// previous check (a fresh install) is not a restart.
pub(crate) fn postgres_restart_since(
    started_at: DateTime<Utc>,
    last_check: Option<DateTime<Utc>>,
) -> Option<(DateTime<Utc>, DateTime<Utc>)> {
    let last_check = last_check?;
    (started_at > last_check).then_some((started_at, last_check))
}

fn postgres_restart_message(started_at: DateTime<Utc>, last_check: DateTime<Utc>) -> String {
    format!(
        "Postgres restarted at {}: the database was down or restarting at some point after the check at {}",
        started_at.to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        last_check.to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
    )
}

impl HealthMonitorService {
    pub fn new(db: PgPool, config: MonitorConfig) -> Self {
        let http_client = crate::services::http_client::internal_service_client_builder()
            .timeout(Duration::from_secs(config.check_timeout_secs))
            .build()
            .unwrap_or_default();

        Self {
            db,
            config,
            http_client,
        }
    }

    /// Check a single service's health and record the result.
    ///
    /// `basic_auth` is optional HTTP Basic credentials. OpenSearch probes
    /// pass `OPENSEARCH_USERNAME`/`OPENSEARCH_PASSWORD` when both are set
    /// so secured clusters are not false-red (issue #2944). Other services
    /// pass `None`.
    pub async fn check_service(
        &self,
        service_name: &str,
        url: &str,
        health_path: &str,
        basic_auth: Option<(&str, &str)>,
    ) -> Result<ServiceHealthEntry> {
        let outcome = self.probe_service(url, health_path, basic_auth).await;
        self.record_probe(service_name, outcome).await
    }

    /// Probe an HTTP dependency without touching the database.
    async fn probe_service(
        &self,
        url: &str,
        health_path: &str,
        basic_auth: Option<(&str, &str)>,
    ) -> ProbeOutcome {
        let full_url = format!("{}{}", url.trim_end_matches('/'), health_path);
        let start = std::time::Instant::now();
        let (status, message) = probe_http_endpoint(&self.http_client, &full_url, basic_auth).await;
        ProbeOutcome {
            status,
            message,
            response_time_ms: elapsed_ms(start),
        }
    }

    /// Probe the storage backend through the `/health` storage check (#5651).
    ///
    /// It shares that check's 5 s cache and 2 s deadline, so the monitor adds
    /// no storage traffic while `/health` is being polled, and a hung store
    /// costs the tick at most the deadline.
    async fn probe_storage(
        &self,
        app_config: &Config,
        storage: &Arc<dyn StorageBackend>,
    ) -> ProbeOutcome {
        let start = std::time::Instant::now();
        let check = crate::api::handlers::health::storage_health(app_config, storage).await;
        ProbeOutcome {
            status: monitor_status(&check.status),
            message: check.message,
            response_time_ms: elapsed_ms(start),
        }
    }

    /// Write one probe outcome to the health log and the alert state.
    async fn record_probe(
        &self,
        service_name: &str,
        outcome: ProbeOutcome,
    ) -> Result<ServiceHealthEntry> {
        let previous = sqlx::query_scalar::<_, String>(
            r#"SELECT current_status FROM alert_state WHERE service_name = $1"#,
        )
        .bind(service_name)
        .fetch_optional(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        let entry = ServiceHealthEntry {
            service_name: service_name.to_string(),
            status: outcome.status,
            previous_status: previous,
            message: outcome.message,
            response_time_ms: Some(outcome.response_time_ms),
            checked_at: Utc::now(),
        };
        crate::services::metrics_service::record_health_monitor_status(
            &entry.service_name,
            entry.status == "healthy",
        );
        self.insert_log(&entry, None).await?;
        self.update_alert_state(&entry).await?;
        Ok(entry)
    }

    /// Append `entry` to `service_health_log`. `checked_at` overrides the
    /// row's timestamp (the database clock's `NOW()` otherwise).
    async fn insert_log(
        &self,
        entry: &ServiceHealthEntry,
        checked_at: Option<DateTime<Utc>>,
    ) -> Result<()> {
        sqlx::query(
            r#"
            INSERT INTO service_health_log (service_name, status, previous_status, message, response_time_ms, checked_at)
            VALUES ($1, $2, $3, $4, $5, COALESCE($6, NOW()))
            "#,
        )
        .bind(&entry.service_name)
        .bind(&entry.status)
        .bind(&entry.previous_status)
        .bind(&entry.message)
        .bind(entry.response_time_ms)
        .bind(checked_at)
        .execute(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;
        Ok(())
    }

    /// Check database health directly.
    ///
    /// Returns the current entry, preceded by an `unavailable` entry when
    /// Postgres restarted since the previous database check (#5651). The
    /// monitor runs once a minute and cannot write while the database is
    /// down, so a restart between two checks used to leave only healthy rows
    /// behind. `pg_postmaster_start_time()` later than the last recorded
    /// check is the restart's trace: one extra scalar in the same round trip,
    /// read through `idx_service_health_log_service`.
    pub async fn check_database(&self) -> Result<Vec<ServiceHealthEntry>> {
        let start = std::time::Instant::now();

        let probe = sqlx::query_as::<_, (DateTime<Utc>, Option<DateTime<Utc>>)>(
            "SELECT pg_postmaster_start_time(), \
                    (SELECT max(checked_at) FROM service_health_log \
                     WHERE service_name = 'database')",
        )
        .fetch_one(&self.db)
        .await;
        let response_time_ms = elapsed_ms(start);

        let (status, message, restart) = match probe {
            Ok((started_at, last_check)) => (
                "healthy".to_string(),
                None,
                postgres_restart_since(started_at, last_check),
            ),
            Err(e) => (
                "unavailable".to_string(),
                Some(format!("Database unreachable: {}", e)),
                None,
            ),
        };

        let previous = sqlx::query_scalar::<_, String>(
            r#"SELECT current_status FROM alert_state WHERE service_name = 'database'"#,
        )
        .fetch_optional(&self.db)
        .await
        .ok()
        .flatten();

        // Skip logging if the DB is down, since we can't write. The gauge
        // still says so.
        if status != "healthy" {
            crate::services::metrics_service::record_health_monitor_status("database", false);
            return Ok(vec![ServiceHealthEntry {
                service_name: "database".to_string(),
                status,
                previous_status: previous,
                message,
                response_time_ms: Some(response_time_ms),
                checked_at: Utc::now(),
            }]);
        }

        let mut entries = Vec::with_capacity(2);
        let mut previous = previous;
        if let Some((started_at, last_check)) = restart {
            let restarted = ServiceHealthEntry {
                service_name: "database".to_string(),
                status: "unavailable".to_string(),
                previous_status: previous.clone(),
                message: Some(postgres_restart_message(started_at, last_check)),
                response_time_ms: None,
                checked_at: started_at,
            };
            // The scheduler tick and POST /monitoring/check can see the same
            // restart at once; the advisory lock plus the re-check under it
            // records it once.
            if self.record_restart_once(&restarted, started_at).await? {
                tracing::warn!(
                    postgres_started_at = %started_at,
                    last_check = %last_check,
                    "Health monitor: Postgres restarted since the last database check"
                );
                crate::services::metrics_service::record_health_monitor_postgres_restart();
                // A restart is an outage even when it is over by the next
                // check, so it is alerted at once rather than after
                // `alert_threshold` consecutive failures: the alert state gets
                // `last_alert_sent_at` (the recovery event's downtime start)
                // and `ak_health_monitor_postgres_restarts_total` counts it
                // for a Prometheus alert.
                self.update_alert_state(&restarted).await?;
                self.mark_restart_alert(&restarted).await?;
                previous = Some(restarted.status.clone());
                entries.push(restarted);
            }
        }

        let entry = ServiceHealthEntry {
            service_name: "database".to_string(),
            status,
            previous_status: previous,
            message,
            response_time_ms: Some(response_time_ms),
            checked_at: Utc::now(),
        };
        crate::services::metrics_service::record_health_monitor_status("database", true);
        self.insert_log(&entry, None).await?;
        self.update_alert_state(&entry).await?;
        entries.push(entry);
        Ok(entries)
    }

    /// Run health checks against all configured services.
    ///
    /// `storage` is the primary storage backend; `None` leaves storage
    /// unchecked. The dependency probes run concurrently, so a tick costs
    /// the slowest probe (at most `check_timeout_secs`, 2 s for storage)
    /// rather than the sum of every dead dependency's timeout (#5651).
    pub async fn check_all_services(
        &self,
        app_config: &Config,
        storage: Option<&Arc<dyn StorageBackend>>,
    ) -> Result<Vec<ServiceHealthEntry>> {
        let mut results = self.check_database().await?;

        let mut probes: Vec<BoxFuture<'_, (&'static str, ProbeOutcome)>> = Vec::new();

        // Storage (#5651): an object-store outage (MinIO, S3) or a full or
        // read-only volume.
        if let Some(storage) = storage {
            probes.push(Box::pin(async move {
                ("storage", self.probe_storage(app_config, storage).await)
            }));
        }

        // Scanner adapter (#5651): image and filesystem scans go to it, and
        // it is a separate pod that can be evicted or OOM-killed.
        for (name, url) in scanner_adapter_probe_urls(app_config) {
            probes.push(Box::pin(async move {
                (name, self.probe_service(url, "/probe/healthy", None).await)
            }));
        }

        // Trivy
        if let Some(url) = &app_config.trivy_url {
            probes.push(Box::pin(async move {
                ("trivy", self.probe_service(url, "/healthz", None).await)
            }));
        }

        // OpenSearch — apply Basic when both username and password are set
        // (same rule as OpenSearchService). Without credentials the probe
        // stays anonymous for DISABLE_SECURITY_PLUGIN / local compose.
        if let Some(url) = &app_config.opensearch_url {
            probes.push(Box::pin(async move {
                (
                    "opensearch",
                    self.probe_service(
                        url,
                        "/_cluster/health",
                        opensearch_probe_basic_auth(app_config),
                    )
                    .await,
                )
            }));
        }

        // OpenSCAP
        if let Some(url) = &app_config.openscap_url {
            probes.push(Box::pin(async move {
                ("openscap", self.probe_service(url, "/health", None).await)
            }));
        }

        // Dependency-Track
        //
        // Only probe when the integration is explicitly enabled. Previously
        // this checked `dependency_track_url.is_some()` alone, which meant
        // an operator running with `DEPENDENCY_TRACK_ENABLED=false` (or
        // simply unset, which is now the default) but with a stale
        // `DEPENDENCY_TRACK_URL` would still see periodic green/red status
        // entries in the monitoring dashboard. That created the
        // inconsistency reported in issues #1395 and #1480: monitoring
        // would report DT as reachable while the Security dashboard
        // simultaneously reported it as disabled or unavailable. Gating on
        // the enabled flag ensures that a disabled DT integration produces
        // no probes, no log entries, and no alert-state churn.
        if let Some(url) = dependency_track_probe_url(app_config) {
            probes.push(Box::pin(async move {
                (
                    "dependency-track",
                    self.probe_service(url, "/api/version", None).await,
                )
            }));
        }

        // Record every outcome even when one write fails, so a transient
        // database error leaves no later service's row or gauge stale; the
        // first error is still returned.
        let mut first_err = None;
        for (name, outcome) in futures::future::join_all(probes).await {
            match self.record_probe(name, outcome).await {
                Ok(entry) => results.push(entry),
                Err(e) => {
                    tracing::warn!(service = name, error = %e, "Health monitor: could not record a check");
                    first_err.get_or_insert(e);
                }
            }
        }
        if let Some(e) = first_err {
            return Err(e);
        }

        Ok(results)
    }

    /// Insert the restart row unless another check already did (#5651).
    /// Returns whether this call recorded it.
    async fn record_restart_once(
        &self,
        restarted: &ServiceHealthEntry,
        started_at: DateTime<Utc>,
    ) -> Result<bool> {
        let mut tx = self
            .db
            .begin()
            .await
            .map_err(|e| AppError::Database(e.to_string()))?;
        sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended('ak_health_monitor_database_restart', 0))")
            .execute(&mut *tx)
            .await
            .map_err(|e| AppError::Database(e.to_string()))?;
        let inserted = sqlx::query(
            r#"
            INSERT INTO service_health_log (service_name, status, previous_status, message, response_time_ms, checked_at)
            SELECT $1, $2, $3, $4, $5, $6
            WHERE NOT EXISTS (
                SELECT 1 FROM service_health_log
                WHERE service_name = $1 AND checked_at >= $6
            )
            "#,
        )
        .bind(&restarted.service_name)
        .bind(&restarted.status)
        .bind(&restarted.previous_status)
        .bind(&restarted.message)
        .bind(restarted.response_time_ms)
        .bind(started_at)
        .execute(&mut *tx)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?
        .rows_affected();
        tx.commit()
            .await
            .map_err(|e| AppError::Database(e.to_string()))?;
        Ok(inserted == 1)
    }

    /// Record a restart as alerted: it reaches the alert threshold at once
    /// and stamps `last_alert_sent_at`. The healthy check right after resets
    /// the failure count, as for any recovery; the stamp stays.
    async fn mark_restart_alert(&self, restarted: &ServiceHealthEntry) -> Result<()> {
        sqlx::query(
            "UPDATE alert_state SET consecutive_failures = GREATEST(consecutive_failures, $2), \
             last_alert_sent_at = NOW() WHERE service_name = $1",
        )
        .bind(&restarted.service_name)
        .bind(self.config.alert_threshold)
        .execute(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;
        Ok(())
    }

    /// Update alert state and determine if alerts should fire.
    async fn update_alert_state(&self, entry: &ServiceHealthEntry) -> Result<Option<HealthEvent>> {
        let is_healthy = entry.status == "healthy";

        // Upsert alert state
        let alert_state = sqlx::query_as::<_, AlertState>(
            r#"
            INSERT INTO alert_state (service_name, current_status, consecutive_failures)
            VALUES ($1, $2, $3)
            ON CONFLICT (service_name) DO UPDATE SET
                current_status = $2,
                consecutive_failures = CASE
                    WHEN $2 = 'healthy' THEN 0
                    ELSE alert_state.consecutive_failures + 1
                END,
                updated_at = NOW()
            RETURNING
                service_name,
                current_status,
                consecutive_failures,
                last_alert_sent_at,
                suppressed_until,
                updated_at
            "#,
        )
        .bind(&entry.service_name)
        .bind(&entry.status)
        .bind(if is_healthy { 0i32 } else { 1i32 })
        .fetch_one(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        // Determine if we should fire an event
        let now = Utc::now();

        // Check suppression
        if let Some(suppressed_until) = alert_state.suppressed_until {
            if now < suppressed_until {
                return Ok(None);
            }
        }

        // Service recovered
        if is_healthy && entry.previous_status.as_deref() != Some("healthy") {
            let event = HealthEvent::ServiceRecovered {
                service_name: entry.service_name.clone(),
                downtime_started: alert_state.last_alert_sent_at,
                timestamp: now,
            };
            return Ok(Some(event));
        }

        // Service down - check threshold
        if !is_healthy && alert_state.consecutive_failures >= self.config.alert_threshold {
            // Check cooldown
            if let Some(last_alert) = alert_state.last_alert_sent_at {
                let cooldown = chrono::Duration::minutes(self.config.alert_cooldown_minutes as i64);
                if now - last_alert < cooldown {
                    return Ok(None);
                }
            }

            // Fire alert and update last_alert_sent_at
            sqlx::query(
                "UPDATE alert_state SET last_alert_sent_at = NOW() WHERE service_name = $1",
            )
            .bind(&entry.service_name)
            .execute(&self.db)
            .await
            .map_err(|e| AppError::Database(e.to_string()))?;

            let event = HealthEvent::ServiceDown {
                service_name: entry.service_name.clone(),
                message: entry.message.clone().unwrap_or_default(),
                consecutive_failures: alert_state.consecutive_failures,
                timestamp: now,
            };
            return Ok(Some(event));
        }

        Ok(None)
    }

    /// Get recent health log entries for a service.
    pub async fn get_health_log(
        &self,
        service_name: Option<&str>,
        limit: i64,
    ) -> Result<Vec<ServiceHealthEntry>> {
        let entries = sqlx::query_as::<_, ServiceHealthEntry>(
            r#"
            SELECT
                service_name,
                status,
                previous_status,
                message,
                response_time_ms,
                checked_at
            FROM service_health_log
            WHERE ($1::TEXT IS NULL OR service_name = $1)
            ORDER BY checked_at DESC
            LIMIT $2
            "#,
        )
        .bind(service_name)
        .bind(limit)
        .fetch_all(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        Ok(entries)
    }

    /// Get current alert states for all services.
    pub async fn get_alert_states(&self) -> Result<Vec<AlertState>> {
        let states = sqlx::query_as::<_, AlertState>(
            r#"
            SELECT
                service_name,
                current_status,
                consecutive_failures,
                last_alert_sent_at,
                suppressed_until,
                updated_at
            FROM alert_state
            ORDER BY service_name
            "#,
        )
        .fetch_all(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        Ok(states)
    }

    /// Suppress alerts for a service until a given time.
    pub async fn suppress_alerts(&self, service_name: &str, until: DateTime<Utc>) -> Result<()> {
        sqlx::query("UPDATE alert_state SET suppressed_until = $2 WHERE service_name = $1")
            .bind(service_name)
            .bind(until)
            .execute(&self.db)
            .await
            .map_err(|e| AppError::Database(e.to_string()))?;

        Ok(())
    }

    /// Cleanup old health log entries.
    pub async fn cleanup_health_log(&self, keep_days: i32) -> Result<u64> {
        let result = sqlx::query(
            "DELETE FROM service_health_log WHERE checked_at < NOW() - make_interval(days => $1)",
        )
        .bind(keep_days)
        .execute(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        Ok(result.rows_affected())
    }
}

#[cfg(ak_test_shard = "services-1")]
#[cfg(test)]
mod tests {
    use super::*;
    #[allow(unused_imports)]
    use serde_json::json;

    // -----------------------------------------------------------------------
    // MonitorConfig Default tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_monitor_config_default() {
        let config = MonitorConfig::default();
        assert_eq!(config.alert_threshold, 3);
        assert_eq!(config.alert_cooldown_minutes, 15);
        assert_eq!(config.check_timeout_secs, 5);
    }

    #[test]
    fn test_monitor_config_custom() {
        let config = MonitorConfig {
            alert_threshold: 5,
            alert_cooldown_minutes: 30,
            check_timeout_secs: 10,
        };
        assert_eq!(config.alert_threshold, 5);
        assert_eq!(config.alert_cooldown_minutes, 30);
        assert_eq!(config.check_timeout_secs, 10);
    }

    #[test]
    fn test_monitor_config_clone() {
        let config = MonitorConfig::default();
        let config2 = config.clone();
        assert_eq!(config.alert_threshold, config2.alert_threshold);
        assert_eq!(
            config.alert_cooldown_minutes,
            config2.alert_cooldown_minutes
        );
        assert_eq!(config.check_timeout_secs, config2.check_timeout_secs);
    }

    // -----------------------------------------------------------------------
    // ServiceHealthEntry serialization tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_service_health_entry_serialization() {
        let now = Utc::now();
        let entry = ServiceHealthEntry {
            service_name: "database".to_string(),
            status: "healthy".to_string(),
            previous_status: Some("unhealthy".to_string()),
            message: None,
            response_time_ms: Some(42),
            checked_at: now,
        };

        let json = serde_json::to_string(&entry).unwrap();
        assert!(json.contains("\"service_name\":\"database\""));
        assert!(json.contains("\"status\":\"healthy\""));
        assert!(json.contains("\"previous_status\":\"unhealthy\""));
        assert!(json.contains("\"response_time_ms\":42"));
    }

    #[test]
    fn test_service_health_entry_deserialization() {
        let now = Utc::now();
        let json_val = json!({
            "service_name": "trivy",
            "status": "unavailable",
            "previous_status": null,
            "message": "Connection refused",
            "response_time_ms": null,
            "checked_at": now
        });

        let entry: ServiceHealthEntry = serde_json::from_value(json_val).unwrap();
        assert_eq!(entry.service_name, "trivy");
        assert_eq!(entry.status, "unavailable");
        assert!(entry.previous_status.is_none());
        assert_eq!(entry.message, Some("Connection refused".to_string()));
        assert!(entry.response_time_ms.is_none());
    }

    #[test]
    fn test_service_health_entry_clone() {
        let entry = ServiceHealthEntry {
            service_name: "test".to_string(),
            status: "healthy".to_string(),
            previous_status: None,
            message: None,
            response_time_ms: Some(10),
            checked_at: Utc::now(),
        };
        let cloned = entry.clone();
        assert_eq!(entry.service_name, cloned.service_name);
        assert_eq!(entry.status, cloned.status);
        assert_eq!(entry.response_time_ms, cloned.response_time_ms);
    }

    // -----------------------------------------------------------------------
    // AlertState serialization tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_alert_state_serialization() {
        let now = Utc::now();
        let state = AlertState {
            service_name: "opensearch".to_string(),
            current_status: "unhealthy".to_string(),
            consecutive_failures: 5,
            last_alert_sent_at: Some(now),
            suppressed_until: None,
            updated_at: now,
        };

        let json = serde_json::to_string(&state).unwrap();
        assert!(json.contains("\"service_name\":\"opensearch\""));
        assert!(json.contains("\"consecutive_failures\":5"));
    }

    #[test]
    fn test_alert_state_deserialization() {
        let now = Utc::now();
        let json_val = json!({
            "service_name": "database",
            "current_status": "healthy",
            "consecutive_failures": 0,
            "last_alert_sent_at": null,
            "suppressed_until": null,
            "updated_at": now
        });

        let state: AlertState = serde_json::from_value(json_val).unwrap();
        assert_eq!(state.service_name, "database");
        assert_eq!(state.current_status, "healthy");
        assert_eq!(state.consecutive_failures, 0);
        assert!(state.last_alert_sent_at.is_none());
        assert!(state.suppressed_until.is_none());
    }

    // -----------------------------------------------------------------------
    // HealthEvent serialization tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_health_event_service_down_serialization() {
        let event = HealthEvent::ServiceDown {
            service_name: "database".to_string(),
            message: "Connection refused".to_string(),
            consecutive_failures: 3,
            timestamp: Utc::now(),
        };

        let json = serde_json::to_string(&event).unwrap();
        assert!(json.contains("\"event_type\":\"ServiceDown\""));
        assert!(json.contains("\"service_name\":\"database\""));
        assert!(json.contains("\"consecutive_failures\":3"));
        assert!(json.contains("\"message\":\"Connection refused\""));
    }

    #[test]
    fn test_health_event_service_recovered_serialization() {
        let now = Utc::now();
        let event = HealthEvent::ServiceRecovered {
            service_name: "opensearch".to_string(),
            downtime_started: Some(now),
            timestamp: now,
        };

        let json = serde_json::to_string(&event).unwrap();
        assert!(json.contains("\"event_type\":\"ServiceRecovered\""));
        assert!(json.contains("\"service_name\":\"opensearch\""));
    }

    #[test]
    fn test_health_event_service_recovered_no_downtime_start() {
        let event = HealthEvent::ServiceRecovered {
            service_name: "trivy".to_string(),
            downtime_started: None,
            timestamp: Utc::now(),
        };

        let json = serde_json::to_string(&event).unwrap();
        assert!(json.contains("\"downtime_started\":null"));
    }

    #[test]
    fn test_health_event_service_degraded_serialization() {
        let event = HealthEvent::ServiceDegraded {
            service_name: "openscap".to_string(),
            response_time_ms: 5000,
            threshold_ms: 3000,
            timestamp: Utc::now(),
        };

        let json = serde_json::to_string(&event).unwrap();
        assert!(json.contains("\"event_type\":\"ServiceDegraded\""));
        assert!(json.contains("\"response_time_ms\":5000"));
        assert!(json.contains("\"threshold_ms\":3000"));
    }

    // -----------------------------------------------------------------------
    // HealthEvent Clone tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_health_event_clone() {
        let event = HealthEvent::ServiceDown {
            service_name: "db".to_string(),
            message: "down".to_string(),
            consecutive_failures: 2,
            timestamp: Utc::now(),
        };
        let cloned = event.clone();
        // Both should serialize to the same JSON
        assert_eq!(
            serde_json::to_string(&event).unwrap(),
            serde_json::to_string(&cloned).unwrap()
        );
    }

    // -----------------------------------------------------------------------
    // URL construction logic tests (mirrors check_service)
    // -----------------------------------------------------------------------

    #[test]
    fn test_health_check_url_construction() {
        let url = "http://localhost:7700";
        let health_path = "/health";
        let full_url = format!("{}{}", url.trim_end_matches('/'), health_path);
        assert_eq!(full_url, "http://localhost:7700/health");
    }

    #[test]
    fn test_health_check_url_construction_trailing_slash() {
        let url = "http://localhost:7700/";
        let health_path = "/health";
        let full_url = format!("{}{}", url.trim_end_matches('/'), health_path);
        assert_eq!(full_url, "http://localhost:7700/health");
    }

    #[test]
    fn test_health_check_url_construction_no_trailing_slash() {
        let url = "https://trivy.internal:8090";
        let health_path = "/healthz";
        let full_url = format!("{}{}", url.trim_end_matches('/'), health_path);
        assert_eq!(full_url, "https://trivy.internal:8090/healthz");
    }

    // -----------------------------------------------------------------------
    // is_healthy logic tests (mirrors update_alert_state)
    // -----------------------------------------------------------------------

    #[test]
    fn test_is_healthy_logic() {
        assert!("healthy" == "healthy");
        assert!("unhealthy" != "healthy");
        assert!("unavailable" != "healthy");
    }

    // -----------------------------------------------------------------------
    // Recovery event detection logic
    // -----------------------------------------------------------------------

    #[test]
    fn test_recovery_detection_from_unhealthy() {
        let is_healthy = true;
        let previous_status: Option<&str> = Some("unhealthy");
        let should_fire_recovery = is_healthy && previous_status != Some("healthy");
        assert!(should_fire_recovery);
    }

    #[test]
    fn test_no_recovery_when_already_healthy() {
        let is_healthy = true;
        let previous_status: Option<&str> = Some("healthy");
        let should_fire_recovery = is_healthy && previous_status != Some("healthy");
        assert!(!should_fire_recovery);
    }

    #[test]
    fn test_no_recovery_when_still_down() {
        let is_healthy = false;
        let previous_status: Option<&str> = Some("unhealthy");
        let should_fire_recovery = is_healthy && previous_status != Some("healthy");
        assert!(!should_fire_recovery);
    }

    #[test]
    fn test_recovery_from_none_previous() {
        let is_healthy = true;
        let previous_status: Option<&str> = None;
        let should_fire_recovery = is_healthy && previous_status != Some("healthy");
        assert!(should_fire_recovery);
    }

    // -----------------------------------------------------------------------
    // Alert threshold logic tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_alert_threshold_met() {
        let config = MonitorConfig::default();
        let consecutive_failures = 3;
        assert!(consecutive_failures >= config.alert_threshold);
    }

    #[test]
    fn test_alert_threshold_not_met() {
        let config = MonitorConfig::default();
        let consecutive_failures = 2;
        assert!(consecutive_failures < config.alert_threshold);
    }

    // -----------------------------------------------------------------------
    // Alert cooldown logic
    // -----------------------------------------------------------------------

    #[test]
    fn test_alert_cooldown_logic() {
        let config = MonitorConfig::default();
        let cooldown = chrono::Duration::minutes(config.alert_cooldown_minutes as i64);
        let now = Utc::now();
        let last_alert = now - chrono::Duration::minutes(10);
        // 10 minutes < 15 minutes cooldown, so should NOT re-alert
        assert!(now - last_alert < cooldown);
    }

    #[test]
    fn test_alert_cooldown_expired() {
        let config = MonitorConfig::default();
        let cooldown = chrono::Duration::minutes(config.alert_cooldown_minutes as i64);
        let now = Utc::now();
        let last_alert = now - chrono::Duration::minutes(20);
        // 20 minutes > 15 minutes cooldown, so should re-alert
        assert!(now - last_alert >= cooldown);
    }

    // -----------------------------------------------------------------------
    // dependency_track_probe_url gate (issues #1395, #1480)
    //
    // The periodic health monitor must not contact Dependency-Track when
    // the integration is disabled, even if `DEPENDENCY_TRACK_URL` is still
    // set in the environment. These tests pin that invariant at the
    // single decision point used by `check_all_services`.
    // -----------------------------------------------------------------------

    #[test]
    fn test_dt_probe_url_disabled_without_url_returns_none() {
        let cfg = Config {
            dependency_track_enabled: false,
            dependency_track_url: None,
            ..Config::default()
        };
        assert!(
            dependency_track_probe_url(&cfg).is_none(),
            "DT disabled and no URL: monitor must not probe"
        );
    }

    #[test]
    fn test_dt_probe_url_disabled_with_stale_url_returns_none() {
        // Regression for #1480: an operator unsetting
        // DEPENDENCY_TRACK_ENABLED while leaving DEPENDENCY_TRACK_URL
        // configured used to keep the monitor probing DT, which reported
        // green/red in the dashboard while the rest of the backend
        // claimed DT was disabled. The gate must return None here.
        let cfg = Config {
            dependency_track_enabled: false,
            dependency_track_url: Some("http://dt.example.com:8081".into()),
            ..Config::default()
        };
        assert!(
            dependency_track_probe_url(&cfg).is_none(),
            "DT disabled but URL set: monitor must not probe (issue #1480)"
        );
    }

    #[test]
    fn test_dt_probe_url_enabled_without_url_returns_none() {
        // Defensive: even with the toggle on, an empty URL means no probe.
        let cfg = Config {
            dependency_track_enabled: true,
            dependency_track_url: None,
            ..Config::default()
        };
        assert!(dependency_track_probe_url(&cfg).is_none());
    }

    #[test]
    fn test_dt_probe_url_enabled_with_url_returns_url() {
        let cfg = Config {
            dependency_track_enabled: true,
            dependency_track_url: Some("http://dt.example.com:8081".into()),
            ..Config::default()
        };
        assert_eq!(
            dependency_track_probe_url(&cfg),
            Some("http://dt.example.com:8081")
        );
    }

    #[test]
    fn test_dt_probe_url_default_config_disabled() {
        // The default Config has DT disabled. This pins the policy that
        // operators must explicitly opt in via DEPENDENCY_TRACK_ENABLED.
        let cfg = Config::default();
        assert!(!cfg.dependency_track_enabled);
        assert!(dependency_track_probe_url(&cfg).is_none());
    }

    // -----------------------------------------------------------------------
    // OpenSearch Basic auth for HealthMonitor probes (issue #2944)
    //
    // Must match OpenSearchService::new: Basic only when both username and
    // password are present. Single-sided credentials must not partially
    // authenticate. probe_http_endpoint must attach Authorization when
    // credentials are provided so secured clusters are not false-red.
    // -----------------------------------------------------------------------

    #[test]
    fn test_optional_basic_auth_both_present() {
        assert_eq!(
            optional_basic_auth(Some("admin"), Some("s3cret")),
            Some(("admin", "s3cret"))
        );
    }

    #[test]
    fn test_optional_basic_auth_only_username() {
        assert!(optional_basic_auth(Some("admin"), None).is_none());
    }

    #[test]
    fn test_optional_basic_auth_only_password() {
        assert!(optional_basic_auth(None, Some("s3cret")).is_none());
    }

    #[test]
    fn test_optional_basic_auth_neither() {
        assert!(optional_basic_auth(None, None).is_none());
    }

    #[test]
    fn test_opensearch_probe_basic_auth_from_config() {
        let with_both = Config {
            opensearch_username: Some("os-user".into()),
            opensearch_password: Some("os-pass".into()),
            ..Config::default()
        };
        assert_eq!(
            opensearch_probe_basic_auth(&with_both),
            Some(("os-user", "os-pass"))
        );

        let username_only = Config {
            opensearch_username: Some("os-user".into()),
            opensearch_password: None,
            ..Config::default()
        };
        assert!(opensearch_probe_basic_auth(&username_only).is_none());

        let neither = Config::default();
        assert!(opensearch_probe_basic_auth(&neither).is_none());
    }

    /// Regression for #2944: without Basic, a secured endpoint returns 401
    /// (false unhealthy). With matching Basic, the same endpoint returns 200.
    ///
    /// Uses a plain reqwest client and a loopback TCP listener (not the
    /// SSRF-guarded monitor client) so the test only pins Authorization
    /// header behavior.
    #[tokio::test]
    async fn test_probe_http_endpoint_basic_auth_required() {
        use base64::Engine;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;

        let expected = format!(
            "Basic {}",
            base64::engine::general_purpose::STANDARD.encode("admin:s3cret")
        );

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let expected_header = expected.clone();
        let server = tokio::spawn(async move {
            for _ in 0..2 {
                if let Ok((mut sock, _)) = listener.accept().await {
                    let mut buf = vec![0u8; 4096];
                    let n = sock.read(&mut buf).await.unwrap_or(0);
                    let req = String::from_utf8_lossy(&buf[..n]);
                    let authorized = req.lines().any(|line| {
                        line.eq_ignore_ascii_case(&format!("Authorization: {expected_header}"))
                    });
                    let body = if authorized {
                        b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                            as &[u8]
                    } else {
                        b"HTTP/1.1 401 Unauthorized\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                    };
                    let _ = sock.write_all(body).await;
                }
            }
        });

        // Plain client: no SSRF resolver. Only testing header attachment.
        let client = reqwest::Client::builder()
            .no_proxy()
            .timeout(Duration::from_secs(2))
            .build()
            .unwrap();
        let url = format!("http://127.0.0.1:{port}/_cluster/health");

        let (status_no_auth, msg_no_auth) = probe_http_endpoint(&client, &url, None).await;
        assert_eq!(
            status_no_auth, "unhealthy",
            "anonymous probe against secured endpoint must be unhealthy: {msg_no_auth:?}"
        );
        assert!(
            msg_no_auth.as_deref().is_some_and(|m| m.contains("401")),
            "expected HTTP 401 message, got {msg_no_auth:?}"
        );

        let (status_auth, msg_auth) =
            probe_http_endpoint(&client, &url, Some(("admin", "s3cret"))).await;
        assert_eq!(
            status_auth, "healthy",
            "Basic-authenticated probe must be healthy: {msg_auth:?}"
        );
        assert!(msg_auth.is_none());

        let _ = server.await;
    }

    // -----------------------------------------------------------------------
    // #5651: storage, scanner adapter and Postgres restarts
    // -----------------------------------------------------------------------

    #[test]
    fn adapter_probe_urls_follow_the_adapter_settings_5651() {
        let mut config = Config::default();
        assert!(scanner_adapter_probe_urls(&config).is_empty());

        config.trivy_adapter_url = Some("http://adapter:8090".to_string());
        assert_eq!(
            scanner_adapter_probe_urls(&config),
            vec![("scanner-adapter", "http://adapter:8090")]
        );

        // The worker's adapter is the same one: probed once.
        config.scan_worker_trivy_adapter_url = Some("http://adapter:8090/".to_string());
        assert_eq!(scanner_adapter_probe_urls(&config).len(), 1);

        config.scan_worker_trivy_adapter_url = Some("http://worker-adapter:8090".to_string());
        assert_eq!(
            scanner_adapter_probe_urls(&config),
            vec![
                ("scanner-adapter", "http://adapter:8090"),
                ("scanner-adapter-worker", "http://worker-adapter:8090"),
            ]
        );

        config.trivy_adapter_url = None;
        assert_eq!(
            scanner_adapter_probe_urls(&config),
            vec![("scanner-adapter-worker", "http://worker-adapter:8090")]
        );
    }

    #[test]
    fn postgres_restart_is_a_start_after_the_last_check_5651() {
        let last = Utc::now() - chrono::Duration::minutes(2);
        let restarted = last + chrono::Duration::seconds(70);
        assert_eq!(
            postgres_restart_since(restarted, Some(last)),
            Some((restarted, last))
        );
        // Started before the last check: the same server we already saw.
        assert_eq!(
            postgres_restart_since(last - chrono::Duration::hours(1), Some(last)),
            None
        );
        // No check recorded yet (a fresh install) is not a restart.
        assert_eq!(postgres_restart_since(restarted, None), None);
        let msg = postgres_restart_message(restarted, last);
        assert!(msg.starts_with("Postgres restarted at "), "{msg}");
    }

    #[test]
    fn storage_check_statuses_fit_the_health_log_5651() {
        for ok in ["healthy", "unhealthy", "unavailable", "degraded"] {
            assert_eq!(monitor_status(ok), ok);
        }
        // service_health_log.status has a CHECK constraint; the storage
        // check's "unknown" must not violate it.
        assert_eq!(monitor_status("unknown"), "unhealthy");
    }

    /// A storage backend whose connectivity probe fails, for the monitor.
    struct DownStorage;

    #[async_trait::async_trait]
    impl crate::storage::StorageBackend for DownStorage {
        async fn put(&self, _key: &str, _content: bytes::Bytes) -> crate::error::Result<()> {
            Err(AppError::Storage("down".to_string()))
        }
        async fn get(&self, _key: &str) -> crate::error::Result<bytes::Bytes> {
            Err(AppError::Storage("down".to_string()))
        }
        async fn exists(&self, _key: &str) -> crate::error::Result<bool> {
            Err(AppError::Storage("down".to_string()))
        }
        async fn delete(&self, _key: &str) -> crate::error::Result<()> {
            Err(AppError::Storage("down".to_string()))
        }
        async fn put_stream(
            &self,
            key: &str,
            stream: futures::stream::BoxStream<'static, crate::error::Result<bytes::Bytes>>,
        ) -> crate::error::Result<crate::storage::PutStreamResult> {
            crate::storage::buffered_put_stream_fallback(self, key, stream).await
        }
        async fn health_check(&self) -> crate::error::Result<()> {
            Err(AppError::Storage("connection refused".to_string()))
        }
    }

    /// Against a live database: a database row older than Postgres' start
    /// time is a restart, recorded as an `unavailable` row stamped with the
    /// start time and then the recovery; the next check records no second
    /// restart. A failing storage backend and a dead scanner adapter are
    /// recorded too (#5651).
    #[tokio::test]
    async fn check_all_services_records_restart_storage_and_adapter_5651() {
        let Some(pool) = crate::testing::try_pool_with(3).await else {
            return;
        };
        // The health log is shared state: serialise with any other test
        // that writes it and leave only this test's rows behind on success.
        sqlx::query("DELETE FROM service_health_log WHERE service_name IN ('database', 'storage', 'scanner-adapter')")
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("DELETE FROM alert_state WHERE service_name IN ('database', 'storage', 'scanner-adapter')")
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query(
            "INSERT INTO service_health_log (service_name, status, checked_at) \
             VALUES ('database', 'healthy', pg_postmaster_start_time() - interval '1 minute')",
        )
        .execute(&pool)
        .await
        .unwrap();

        let config = Config {
            storage_backend: "s3".to_string(),
            // Nothing listens on port 9 (discard) on the test host.
            trivy_adapter_url: Some("http://127.0.0.1:9".to_string()),
            ..Config::default()
        };
        let storage: Arc<dyn StorageBackend> = Arc::new(DownStorage);
        let monitor = HealthMonitorService::new(
            pool.clone(),
            MonitorConfig {
                check_timeout_secs: 2,
                ..MonitorConfig::default()
            },
        );

        let results = monitor
            .check_all_services(&config, Some(&storage))
            .await
            .expect("check");
        let by_name = |name: &str| -> Vec<&ServiceHealthEntry> {
            results.iter().filter(|e| e.service_name == name).collect()
        };
        let db = by_name("database");
        assert_eq!(db.len(), 2, "{results:?}");
        assert_eq!(db[0].status, "unavailable");
        assert!(db[0]
            .message
            .as_deref()
            .is_some_and(|m| m.starts_with("Postgres restarted at ")));
        assert_eq!(db[1].status, "healthy");
        assert_eq!(db[1].previous_status.as_deref(), Some("unavailable"));
        assert_eq!(by_name("storage")[0].status, "unhealthy");
        assert_eq!(by_name("scanner-adapter")[0].status, "unavailable");

        let logged: Vec<(String, String)> = sqlx::query_as(
            "SELECT service_name, status FROM service_health_log \
             WHERE service_name IN ('database', 'storage', 'scanner-adapter') \
             ORDER BY checked_at, service_name",
        )
        .fetch_all(&pool)
        .await
        .unwrap();
        assert!(logged.contains(&("database".to_string(), "unavailable".to_string())));
        assert!(logged.contains(&("storage".to_string(), "unhealthy".to_string())));
        assert!(logged.contains(&("scanner-adapter".to_string(), "unavailable".to_string())));

        // Second check: the restart is already recorded.
        let again = monitor.check_database().await.expect("check");
        assert_eq!(again.len(), 1, "{again:?}");
        assert_eq!(again[0].status, "healthy");
    }
}
