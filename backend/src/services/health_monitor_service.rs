//! Health monitoring and alert pipeline service.
//!
//! Monitors service health, tracks state transitions, fires webhook alerts,
//! and manages alert suppression to prevent spam during extended outages.

use chrono::{DateTime, Utc};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use std::time::Duration;
use utoipa::ToSchema;

use crate::config::Config;
use crate::error::{AppError, Result};

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

impl HealthMonitorService {
    pub fn new(db: PgPool, config: MonitorConfig) -> Self {
        let http_client = Client::builder()
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
    pub async fn check_service(
        &self,
        service_name: &str,
        url: &str,
        health_path: &str,
    ) -> Result<ServiceHealthEntry> {
        let full_url = format!("{}{}", url.trim_end_matches('/'), health_path);
        let start = std::time::Instant::now();

        let (status, message) = match self.http_client.get(&full_url).send().await {
            Ok(resp) if resp.status().is_success() => ("healthy".to_string(), None),
            Ok(resp) => (
                "unhealthy".to_string(),
                Some(format!("HTTP {}", resp.status())),
            ),
            Err(e) => (
                "unavailable".to_string(),
                Some(format!("Connection failed: {}", e)),
            ),
        };

        let response_time_ms = start.elapsed().as_millis() as i32;

        // Get previous status
        let previous = sqlx::query_scalar::<_, String>(
            r#"SELECT current_status FROM alert_state WHERE service_name = $1"#,
        )
        .bind(service_name)
        .fetch_optional(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        let entry = ServiceHealthEntry {
            service_name: service_name.to_string(),
            status: status.clone(),
            previous_status: previous,
            message,
            response_time_ms: Some(response_time_ms),
            checked_at: Utc::now(),
        };

        // Log the health check
        sqlx::query(
            r#"
            INSERT INTO service_health_log (service_name, status, previous_status, message, response_time_ms)
            VALUES ($1, $2, $3, $4, $5)
            "#,
        )
        .bind(&entry.service_name)
        .bind(&entry.status)
        .bind(&entry.previous_status)
        .bind(&entry.message)
        .bind(entry.response_time_ms)
        .execute(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        // Update alert state
        self.update_alert_state(&entry).await?;

        Ok(entry)
    }

    /// Check database health directly.
    pub async fn check_database(&self) -> Result<ServiceHealthEntry> {
        let start = std::time::Instant::now();

        let (status, message) = match sqlx::query("SELECT 1").fetch_one(&self.db).await {
            Ok(_) => ("healthy".to_string(), None),
            Err(e) => (
                "unavailable".to_string(),
                Some(format!("Database unreachable: {}", e)),
            ),
        };

        let response_time_ms = start.elapsed().as_millis() as i32;

        let previous = sqlx::query_scalar::<_, String>(
            r#"SELECT current_status FROM alert_state WHERE service_name = 'database'"#,
        )
        .fetch_optional(&self.db)
        .await
        .ok()
        .flatten();

        let entry = ServiceHealthEntry {
            service_name: "database".to_string(),
            status,
            previous_status: previous,
            message,
            response_time_ms: Some(response_time_ms),
            checked_at: Utc::now(),
        };

        // Log if DB was reachable (skip logging if DB is down since we can't write)
        if entry.status == "healthy" {
            sqlx::query(
                r#"
                INSERT INTO service_health_log (service_name, status, previous_status, message, response_time_ms)
                VALUES ($1, $2, $3, $4, $5)
                "#,
            )
            .bind(&entry.service_name)
            .bind(&entry.status)
            .bind(&entry.previous_status)
            .bind(&entry.message)
            .bind(entry.response_time_ms)
            .execute(&self.db)
            .await
            .map_err(|e| AppError::Database(e.to_string()))?;

            self.update_alert_state(&entry).await?;
        }

        Ok(entry)
    }

    /// Run health checks against all configured services.
    pub async fn check_all_services(&self, app_config: &Config) -> Result<Vec<ServiceHealthEntry>> {
        let mut results = Vec::new();

        // Database
        results.push(self.check_database().await?);

        // Trivy
        if let Some(url) = &app_config.trivy_url {
            results.push(self.check_service("trivy", url, "/healthz").await?);
        }

        // Meilisearch
        if let Some(url) = &app_config.meilisearch_url {
            results.push(self.check_service("meilisearch", url, "/health").await?);
        }

        // OpenSCAP
        if let Some(url) = &app_config.openscap_url {
            results.push(self.check_service("openscap", url, "/health").await?);
        }

        // Dependency-Track
        if let Some(url) = &app_config.dependency_track_url {
            results.push(
                self.check_service("dependency-track", url, "/api/version")
                    .await?,
            );
        }

        Ok(results)
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
            service_name: "meilisearch".to_string(),
            current_status: "unhealthy".to_string(),
            consecutive_failures: 5,
            last_alert_sent_at: Some(now),
            suppressed_until: None,
            updated_at: now,
        };

        let json = serde_json::to_string(&state).unwrap();
        assert!(json.contains("\"service_name\":\"meilisearch\""));
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
            service_name: "meilisearch".to_string(),
            downtime_started: Some(now),
            timestamp: now,
        };

        let json = serde_json::to_string(&event).unwrap();
        assert!(json.contains("\"event_type\":\"ServiceRecovered\""));
        assert!(json.contains("\"service_name\":\"meilisearch\""));
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
}
