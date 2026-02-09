//! Opt-in crash reporting and telemetry service.
//!
//! Captures Rust panics, unrecoverable errors, and service failures.
//! All reports are PII-scrubbed before storage or submission.
//! Strictly opt-in: disabled by default, requires explicit admin toggle.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use utoipa::ToSchema;
use uuid::Uuid;

use crate::error::{AppError, Result};

/// A stored crash report.
#[derive(Debug, Serialize, Deserialize, sqlx::FromRow, ToSchema)]
pub struct CrashReport {
    pub id: Uuid,
    pub error_type: String,
    pub error_message: String,
    pub stack_trace: Option<String>,
    pub component: String,
    pub severity: String,
    pub app_version: String,
    pub os_info: Option<String>,
    pub uptime_seconds: Option<i64>,
    #[schema(value_type = Object)]
    pub context: serde_json::Value,
    pub submitted: bool,
    pub submitted_at: Option<DateTime<Utc>>,
    pub submission_error: Option<String>,
    pub error_signature: String,
    pub occurrence_count: i32,
    pub first_seen_at: DateTime<Utc>,
    pub last_seen_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
}

/// Scrub level for PII removal.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ScrubLevel {
    /// Remove only obvious PII (emails, IPs)
    Minimal,
    /// Remove PII + usernames, repo names, artifact names
    Standard,
    /// Remove all potentially identifying information
    Aggressive,
}

impl std::str::FromStr for ScrubLevel {
    type Err = std::convert::Infallible;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        Ok(match s {
            "minimal" => Self::Minimal,
            "aggressive" => Self::Aggressive,
            _ => Self::Standard,
        })
    }
}

/// Row returned from telemetry_settings queries.
#[derive(Debug, sqlx::FromRow)]
struct TelemetrySettingRow {
    pub key: String,
    pub value: serde_json::Value,
}

pub struct CrashReportingService {
    db: PgPool,
}

impl CrashReportingService {
    pub fn new(db: PgPool) -> Self {
        Self { db }
    }

    /// Check if telemetry is enabled.
    pub async fn is_enabled(&self) -> Result<bool> {
        let enabled = sqlx::query_scalar::<_, serde_json::Value>(
            r#"SELECT value FROM telemetry_settings WHERE key = 'telemetry_enabled'"#,
        )
        .fetch_optional(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

        Ok(enabled)
    }

    /// Get the configured scrub level.
    pub async fn get_scrub_level(&self) -> Result<ScrubLevel> {
        let level = sqlx::query_scalar::<_, serde_json::Value>(
            r#"SELECT value FROM telemetry_settings WHERE key = 'telemetry_scrub_level'"#,
        )
        .fetch_optional(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?
        .and_then(|v| v.as_str().map(String::from))
        .unwrap_or_else(|| "standard".to_string());

        Ok(level.parse::<ScrubLevel>().unwrap())
    }

    /// Record a crash/error. Deduplicates by error signature.
    pub async fn record_crash(
        &self,
        error_type: &str,
        error_message: &str,
        stack_trace: Option<&str>,
        component: &str,
        severity: &str,
        context: serde_json::Value,
    ) -> Result<CrashReport> {
        let scrub_level = self.get_scrub_level().await.unwrap_or(ScrubLevel::Standard);

        let scrubbed_message = scrub_pii(error_message, scrub_level);
        let scrubbed_trace = stack_trace.map(|t| scrub_pii(t, scrub_level));
        let scrubbed_context = scrub_json_pii(&context, scrub_level);

        let signature = compute_error_signature(error_type, &scrubbed_message, component);

        let app_version = env!("CARGO_PKG_VERSION").to_string();
        let os_info = format!("{} {}", std::env::consts::OS, std::env::consts::ARCH);

        // Try to increment existing report with same signature
        let existing = sqlx::query_as::<_, CrashReport>(
            r#"
            UPDATE crash_reports
            SET occurrence_count = occurrence_count + 1,
                last_seen_at = NOW(),
                context = $2
            WHERE error_signature = $1
              AND submitted = false
            RETURNING
                id, error_type, error_message, stack_trace, component,
                severity, app_version, os_info, uptime_seconds, context,
                submitted, submitted_at, submission_error,
                error_signature, occurrence_count, first_seen_at,
                last_seen_at, created_at
            "#,
        )
        .bind(&signature)
        .bind(&scrubbed_context)
        .fetch_optional(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        if let Some(report) = existing {
            return Ok(report);
        }

        // Create new crash report
        let report = sqlx::query_as::<_, CrashReport>(
            r#"
            INSERT INTO crash_reports (
                error_type, error_message, stack_trace, component,
                severity, app_version, os_info, context, error_signature
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
            RETURNING
                id, error_type, error_message, stack_trace, component,
                severity, app_version, os_info, uptime_seconds, context,
                submitted, submitted_at, submission_error,
                error_signature, occurrence_count, first_seen_at,
                last_seen_at, created_at
            "#,
        )
        .bind(error_type)
        .bind(&scrubbed_message)
        .bind(&scrubbed_trace)
        .bind(component)
        .bind(severity)
        .bind(&app_version)
        .bind(&os_info)
        .bind(&scrubbed_context)
        .bind(&signature)
        .fetch_one(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        Ok(report)
    }

    /// List pending (unsubmitted) crash reports.
    pub async fn list_pending(&self, limit: i64) -> Result<Vec<CrashReport>> {
        let reports = sqlx::query_as::<_, CrashReport>(
            r#"
            SELECT
                id, error_type, error_message, stack_trace, component,
                severity, app_version, os_info, uptime_seconds, context,
                submitted, submitted_at, submission_error,
                error_signature, occurrence_count, first_seen_at,
                last_seen_at, created_at
            FROM crash_reports
            WHERE submitted = false
            ORDER BY
                CASE severity
                    WHEN 'panic' THEN 0
                    WHEN 'critical' THEN 1
                    WHEN 'error' THEN 2
                    WHEN 'warning' THEN 3
                END,
                occurrence_count DESC
            LIMIT $1
            "#,
        )
        .bind(limit)
        .fetch_all(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        Ok(reports)
    }

    /// List all crash reports with pagination.
    pub async fn list_all(&self, offset: i64, limit: i64) -> Result<(Vec<CrashReport>, i64)> {
        let reports = sqlx::query_as::<_, CrashReport>(
            r#"
            SELECT
                id, error_type, error_message, stack_trace, component,
                severity, app_version, os_info, uptime_seconds, context,
                submitted, submitted_at, submission_error,
                error_signature, occurrence_count, first_seen_at,
                last_seen_at, created_at
            FROM crash_reports
            ORDER BY last_seen_at DESC
            OFFSET $1 LIMIT $2
            "#,
        )
        .bind(offset)
        .bind(limit)
        .fetch_all(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        let total = sqlx::query_scalar::<_, i64>(r#"SELECT COUNT(*) FROM crash_reports"#)
            .fetch_one(&self.db)
            .await
            .map_err(|e| AppError::Database(e.to_string()))?;

        Ok((reports, total))
    }

    /// Get a single crash report.
    pub async fn get_report(&self, id: Uuid) -> Result<CrashReport> {
        sqlx::query_as::<_, CrashReport>(
            r#"
            SELECT
                id, error_type, error_message, stack_trace, component,
                severity, app_version, os_info, uptime_seconds, context,
                submitted, submitted_at, submission_error,
                error_signature, occurrence_count, first_seen_at,
                last_seen_at, created_at
            FROM crash_reports
            WHERE id = $1
            "#,
        )
        .bind(id)
        .fetch_optional(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?
        .ok_or_else(|| AppError::NotFound("Crash report not found".to_string()))
    }

    /// Mark reports as submitted.
    pub async fn mark_submitted(&self, ids: &[Uuid]) -> Result<u64> {
        let result = sqlx::query(
            "UPDATE crash_reports SET submitted = true, submitted_at = NOW() WHERE id = ANY($1)",
        )
        .bind(ids)
        .execute(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        Ok(result.rows_affected())
    }

    /// Delete a crash report.
    pub async fn delete_report(&self, id: Uuid) -> Result<()> {
        sqlx::query("DELETE FROM crash_reports WHERE id = $1")
            .bind(id)
            .execute(&self.db)
            .await
            .map_err(|e| AppError::Database(e.to_string()))?;
        Ok(())
    }

    /// Get telemetry settings.
    pub async fn get_settings(&self) -> Result<TelemetrySettings> {
        let rows = sqlx::query_as::<_, TelemetrySettingRow>(
            r#"SELECT key, value FROM telemetry_settings"#,
        )
        .fetch_all(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        let mut settings = TelemetrySettings::default();
        for row in rows {
            match row.key.as_str() {
                "telemetry_enabled" => {
                    settings.enabled = row.value.as_bool().unwrap_or(false);
                }
                "telemetry_review_before_send" => {
                    settings.review_before_send = row.value.as_bool().unwrap_or(true);
                }
                "telemetry_scrub_level" => {
                    settings.scrub_level = row.value.as_str().unwrap_or("standard").to_string();
                }
                "telemetry_include_logs" => {
                    settings.include_logs = row.value.as_bool().unwrap_or(false);
                }
                _ => {}
            }
        }

        Ok(settings)
    }

    /// Update telemetry settings.
    pub async fn update_settings(&self, settings: &TelemetrySettings) -> Result<()> {
        let updates = vec![
            ("telemetry_enabled", serde_json::json!(settings.enabled)),
            (
                "telemetry_review_before_send",
                serde_json::json!(settings.review_before_send),
            ),
            (
                "telemetry_scrub_level",
                serde_json::json!(settings.scrub_level),
            ),
            (
                "telemetry_include_logs",
                serde_json::json!(settings.include_logs),
            ),
        ];

        for (key, value) in updates {
            sqlx::query(
                "INSERT INTO telemetry_settings (key, value) VALUES ($1, $2)
                 ON CONFLICT (key) DO UPDATE SET value = $2, updated_at = NOW()",
            )
            .bind(key)
            .bind(value)
            .execute(&self.db)
            .await
            .map_err(|e| AppError::Database(e.to_string()))?;
        }

        Ok(())
    }

    /// Cleanup old crash reports beyond retention.
    pub async fn cleanup(&self, keep_days: i32) -> Result<u64> {
        let result = sqlx::query(
            "DELETE FROM crash_reports WHERE submitted = true AND created_at < NOW() - make_interval(days => $1)",
        )
        .bind(keep_days)
        .execute(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        Ok(result.rows_affected())
    }
}

/// Telemetry configuration.
#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct TelemetrySettings {
    pub enabled: bool,
    pub review_before_send: bool,
    pub scrub_level: String,
    pub include_logs: bool,
}

impl Default for TelemetrySettings {
    fn default() -> Self {
        Self {
            enabled: false,
            review_before_send: true,
            scrub_level: "standard".to_string(),
            include_logs: false,
        }
    }
}

/// Compute a stable signature for deduplication.
fn compute_error_signature(error_type: &str, message: &str, component: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(error_type.as_bytes());
    hasher.update(b"|");
    // Use first line of message for signature (rest may vary)
    let first_line = message.lines().next().unwrap_or(message);
    hasher.update(first_line.as_bytes());
    hasher.update(b"|");
    hasher.update(component.as_bytes());
    hex::encode(hasher.finalize())
}

/// Remove PII from a string based on scrub level.
fn scrub_pii(input: &str, level: ScrubLevel) -> String {
    let mut output = input.to_string();

    // All levels: scrub emails
    let email_re = regex::Regex::new(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}").unwrap();
    output = email_re.replace_all(&output, "[EMAIL]").to_string();

    // All levels: scrub IPv4 addresses
    let ipv4_re = regex::Regex::new(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b").unwrap();
    output = ipv4_re.replace_all(&output, "[IP]").to_string();

    if level == ScrubLevel::Minimal {
        return output;
    }

    // Standard+: scrub file paths that look like user directories
    let home_re = regex::Regex::new(r"/(?:home|Users)/[^/\s]+").unwrap();
    output = home_re.replace_all(&output, "/[USER_DIR]").to_string();

    // Standard+: scrub JWT tokens
    let jwt_re =
        regex::Regex::new(r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+").unwrap();
    output = jwt_re.replace_all(&output, "[JWT_TOKEN]").to_string();

    if level == ScrubLevel::Aggressive {
        // Aggressive: scrub anything that looks like a path segment with specific names
        let path_re = regex::Regex::new(r"/[a-zA-Z0-9._-]{3,}/").unwrap();
        output = path_re.replace_all(&output, "/[PATH]/").to_string();
    }

    output
}

/// Scrub PII from JSON values.
fn scrub_json_pii(value: &serde_json::Value, level: ScrubLevel) -> serde_json::Value {
    match value {
        serde_json::Value::String(s) => serde_json::Value::String(scrub_pii(s, level)),
        serde_json::Value::Object(map) => {
            let scrubbed: serde_json::Map<String, serde_json::Value> = map
                .iter()
                .filter(|(key, _)| {
                    // Skip keys that are likely to contain PII
                    let sensitive_keys = [
                        "password",
                        "secret",
                        "token",
                        "api_key",
                        "authorization",
                        "cookie",
                        "session",
                    ];
                    if level != ScrubLevel::Minimal
                        && sensitive_keys
                            .iter()
                            .any(|k| key.to_lowercase().contains(k))
                    {
                        return false;
                    }
                    true
                })
                .map(|(k, v)| (k.clone(), scrub_json_pii(v, level)))
                .collect();
            serde_json::Value::Object(scrubbed)
        }
        serde_json::Value::Array(arr) => {
            serde_json::Value::Array(arr.iter().map(|v| scrub_json_pii(v, level)).collect())
        }
        other => other.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scrub_email() {
        let input = "Error for user john@example.com at 192.168.1.1";
        let result = scrub_pii(input, ScrubLevel::Minimal);
        assert_eq!(result, "Error for user [EMAIL] at [IP]");
    }

    #[test]
    fn test_scrub_standard() {
        let input = "Failed at /home/john/projects/app";
        let result = scrub_pii(input, ScrubLevel::Standard);
        assert!(result.contains("[USER_DIR]"));
        assert!(!result.contains("john"));
    }

    #[test]
    fn test_error_signature_stable() {
        let sig1 = compute_error_signature("panic", "thread panicked", "backend");
        let sig2 = compute_error_signature("panic", "thread panicked", "backend");
        assert_eq!(sig1, sig2);
    }

    #[test]
    fn test_error_signature_differs() {
        let sig1 = compute_error_signature("panic", "error A", "backend");
        let sig2 = compute_error_signature("panic", "error B", "backend");
        assert_ne!(sig1, sig2);
    }
}
