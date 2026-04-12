//! Quarantine period service.
//!
//! Provides pure-function decision logic for artifact quarantine. When enabled
//! (globally or per-repo), newly uploaded artifacts are held in a "quarantined"
//! state for a configurable duration. Downloads are blocked until the artifact
//! is released (scan passed, admin override) or rejected (scan failed, admin).
//!
//! Configuration resolution order:
//! 1. Per-repo keys in `repository_config` (`quarantine_enabled`, `quarantine_duration_minutes`)
//! 2. Global env vars `QUARANTINE_ENABLED` / `QUARANTINE_DURATION_MINUTES`
//! 3. Hardcoded defaults (disabled, 60 minutes)

use chrono::{DateTime, Duration, Utc};
use sqlx::PgPool;
use uuid::Uuid;

use crate::error::{AppError, Result};

/// Default quarantine duration in minutes when not configured.
const DEFAULT_DURATION_MINUTES: i64 = 60;

// ---------------------------------------------------------------------------
// Pure-function decision logic (no I/O, fully testable)
// ---------------------------------------------------------------------------

/// Quarantine status values matching the DB CHECK constraint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QuarantineState {
    Quarantined,
    Released,
    Rejected,
}

impl QuarantineState {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Quarantined => "quarantined",
            Self::Released => "released",
            Self::Rejected => "rejected",
        }
    }
}

/// Resolved quarantine configuration for a single repository.
#[derive(Debug, Clone)]
pub struct QuarantineConfig {
    pub enabled: bool,
    pub duration_minutes: i64,
}

impl Default for QuarantineConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            duration_minutes: DEFAULT_DURATION_MINUTES,
        }
    }
}

/// Determine whether an artifact should be quarantined on upload.
pub fn should_quarantine(config: &QuarantineConfig) -> bool {
    config.enabled
}

/// Calculate the quarantine expiry timestamp from now.
pub fn quarantine_until(config: &QuarantineConfig, now: DateTime<Utc>) -> DateTime<Utc> {
    now + Duration::minutes(config.duration_minutes)
}

/// Decide whether a download should be blocked based on quarantine state.
///
/// Returns `Ok(())` if the download is allowed, or `Err` with a 409 Conflict
/// if the artifact is still quarantined.
pub fn check_download_allowed(
    quarantine_status: Option<&str>,
    quarantine_until_ts: Option<DateTime<Utc>>,
    now: DateTime<Utc>,
) -> Result<()> {
    match quarantine_status {
        Some("quarantined") => {
            // If the quarantine period has expired, allow the download.
            // The background job or next scan will transition the status,
            // but we should not block reads past the hold window.
            if let Some(until) = quarantine_until_ts {
                if now >= until {
                    return Ok(());
                }
            }
            Err(AppError::Conflict(
                "Artifact is quarantined and pending security review".to_string(),
            ))
        }
        Some("rejected") => Err(AppError::Conflict(
            "Artifact was rejected during security review".to_string(),
        )),
        // 'released', 'clean', 'unscanned', 'flagged', or NULL are all downloadable
        _ => Ok(()),
    }
}

/// Determine the new quarantine status after a scan completes.
///
/// `has_findings` indicates whether the scan found any issues (true = findings
/// exist, false = clean scan).
pub fn status_after_scan(has_findings: bool) -> QuarantineState {
    if has_findings {
        QuarantineState::Rejected
    } else {
        QuarantineState::Released
    }
}

// ---------------------------------------------------------------------------
// Database helpers (I/O layer)
// ---------------------------------------------------------------------------

/// Resolve the effective quarantine config for a repository.
///
/// Checks `repository_config` first, then falls back to env vars, then defaults.
pub async fn resolve_config(db: &PgPool, repository_id: Uuid) -> QuarantineConfig {
    let global_enabled = matches!(
        std::env::var("QUARANTINE_ENABLED").as_deref(),
        Ok("true" | "1")
    );
    let global_duration: i64 = std::env::var("QUARANTINE_DURATION_MINUTES")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(DEFAULT_DURATION_MINUTES);

    // Try per-repo overrides from repository_config
    let rows: Vec<(String, Option<String>)> = sqlx::query_as(
        "SELECT key, value FROM repository_config \
         WHERE repository_id = $1 AND key IN ('quarantine_enabled', 'quarantine_duration_minutes')",
    )
    .bind(repository_id)
    .fetch_all(db)
    .await
    .unwrap_or_default();

    let mut enabled = global_enabled;
    let mut duration = global_duration;

    for (key, value) in &rows {
        match key.as_str() {
            "quarantine_enabled" => {
                if let Some(v) = value {
                    enabled = v == "true" || v == "1";
                }
            }
            "quarantine_duration_minutes" => {
                if let Some(v) = value {
                    if let Ok(d) = v.parse::<i64>() {
                        duration = d;
                    }
                }
            }
            _ => {}
        }
    }

    QuarantineConfig {
        enabled,
        duration_minutes: duration,
    }
}

/// Set quarantine status and expiry on an artifact.
pub async fn set_quarantine(
    db: &PgPool,
    artifact_id: Uuid,
    status: &str,
    until: Option<DateTime<Utc>>,
) -> Result<()> {
    sqlx::query("UPDATE artifacts SET quarantine_status = $2, quarantine_until = $3 WHERE id = $1")
        .bind(artifact_id)
        .bind(status)
        .bind(until)
        .execute(db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;
    Ok(())
}

/// Transition a quarantined artifact to released or rejected.
pub async fn transition(db: &PgPool, artifact_id: Uuid, new_status: QuarantineState) -> Result<()> {
    sqlx::query(
        "UPDATE artifacts SET quarantine_status = $2, quarantine_until = NULL WHERE id = $1",
    )
    .bind(artifact_id)
    .bind(new_status.as_str())
    .execute(db)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;
    Ok(())
}

/// Fetch the current quarantine status and expiry for an artifact.
pub async fn get_status(
    db: &PgPool,
    artifact_id: Uuid,
) -> Result<(Option<String>, Option<DateTime<Utc>>)> {
    #[derive(sqlx::FromRow)]
    struct Row {
        quarantine_status: Option<String>,
        quarantine_until: Option<DateTime<Utc>>,
    }

    let row = sqlx::query_as::<_, Row>(
        "SELECT quarantine_status, quarantine_until FROM artifacts WHERE id = $1 AND is_deleted = false",
    )
    .bind(artifact_id)
    .fetch_optional(db)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?
    .ok_or_else(|| AppError::NotFound("Artifact not found".to_string()))?;

    Ok((row.quarantine_status, row.quarantine_until))
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    // -----------------------------------------------------------------------
    // should_quarantine
    // -----------------------------------------------------------------------

    #[test]
    fn test_should_quarantine_enabled() {
        let config = QuarantineConfig {
            enabled: true,
            duration_minutes: 30,
        };
        assert!(should_quarantine(&config));
    }

    #[test]
    fn test_should_quarantine_disabled() {
        let config = QuarantineConfig::default();
        assert!(!should_quarantine(&config));
    }

    // -----------------------------------------------------------------------
    // quarantine_until
    // -----------------------------------------------------------------------

    #[test]
    fn test_quarantine_until_adds_duration() {
        let now = Utc::now();
        let config = QuarantineConfig {
            enabled: true,
            duration_minutes: 120,
        };
        let until = quarantine_until(&config, now);
        let diff = until - now;
        assert_eq!(diff.num_minutes(), 120);
    }

    #[test]
    fn test_quarantine_until_zero_duration() {
        let now = Utc::now();
        let config = QuarantineConfig {
            enabled: true,
            duration_minutes: 0,
        };
        let until = quarantine_until(&config, now);
        assert_eq!(until, now);
    }

    // -----------------------------------------------------------------------
    // check_download_allowed
    // -----------------------------------------------------------------------

    #[test]
    fn test_download_allowed_no_quarantine() {
        let now = Utc::now();
        assert!(check_download_allowed(None, None, now).is_ok());
    }

    #[test]
    fn test_download_allowed_released() {
        let now = Utc::now();
        assert!(check_download_allowed(Some("released"), None, now).is_ok());
    }

    #[test]
    fn test_download_allowed_clean() {
        let now = Utc::now();
        assert!(check_download_allowed(Some("clean"), None, now).is_ok());
    }

    #[test]
    fn test_download_allowed_unscanned() {
        let now = Utc::now();
        assert!(check_download_allowed(Some("unscanned"), None, now).is_ok());
    }

    #[test]
    fn test_download_allowed_flagged() {
        // 'flagged' is from the proxy-scan workflow, not quarantine blocking
        let now = Utc::now();
        assert!(check_download_allowed(Some("flagged"), None, now).is_ok());
    }

    #[test]
    fn test_download_blocked_quarantined_within_window() {
        let now = Utc::now();
        let until = now + Duration::minutes(30);
        let result = check_download_allowed(Some("quarantined"), Some(until), now);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            err.to_string().contains("quarantined"),
            "Error should mention quarantine: {err}"
        );
    }

    #[test]
    fn test_download_allowed_quarantine_expired() {
        let now = Utc::now();
        let until = now - Duration::minutes(5);
        assert!(check_download_allowed(Some("quarantined"), Some(until), now).is_ok());
    }

    #[test]
    fn test_download_blocked_quarantined_no_expiry() {
        // If quarantine_until is NULL but status is 'quarantined', block
        let now = Utc::now();
        let result = check_download_allowed(Some("quarantined"), None, now);
        assert!(result.is_err());
    }

    #[test]
    fn test_download_blocked_rejected() {
        let now = Utc::now();
        let result = check_download_allowed(Some("rejected"), None, now);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            err.to_string().contains("rejected"),
            "Error should mention rejection: {err}"
        );
    }

    // -----------------------------------------------------------------------
    // status_after_scan
    // -----------------------------------------------------------------------

    #[test]
    fn test_status_after_scan_clean() {
        assert_eq!(status_after_scan(false), QuarantineState::Released);
    }

    #[test]
    fn test_status_after_scan_findings() {
        assert_eq!(status_after_scan(true), QuarantineState::Rejected);
    }

    // -----------------------------------------------------------------------
    // QuarantineState::as_str
    // -----------------------------------------------------------------------

    #[test]
    fn test_quarantine_state_strings() {
        assert_eq!(QuarantineState::Quarantined.as_str(), "quarantined");
        assert_eq!(QuarantineState::Released.as_str(), "released");
        assert_eq!(QuarantineState::Rejected.as_str(), "rejected");
    }

    // -----------------------------------------------------------------------
    // QuarantineConfig defaults
    // -----------------------------------------------------------------------

    #[test]
    fn test_quarantine_config_default() {
        let config = QuarantineConfig::default();
        assert!(!config.enabled);
        assert_eq!(config.duration_minutes, 60);
    }
}
