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

/// Calculate the quarantine expiry from the upstream release date.
///
/// The Package Age Policy holds an artifact for `duration_minutes` measured
/// from when it was *released* upstream, not from when this instance first
/// ingested it (#1771). A release date older than the configured window
/// therefore yields an already-elapsed expiry, so an old upstream package is
/// not re-held from its first proxy fetch. Falls back to `now` (matching
/// [`quarantine_until`]) when no release date is known.
pub fn quarantine_until_from_release(
    config: &QuarantineConfig,
    release_date: Option<DateTime<Utc>>,
    now: DateTime<Utc>,
) -> DateTime<Utc> {
    release_date.unwrap_or(now) + Duration::minutes(config.duration_minutes)
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
        Some("rejected") => Err(AppError::Authorization(
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

/// Read the raw per-repository quarantine settings from `repository_config`.
///
/// Unlike [`resolve_config`], this does NOT merge global env defaults: it
/// returns exactly what is stored for the repository (`None` when a key is
/// unset or unparseable) so the repository API can echo the configured policy
/// back to clients (#1770 B).
pub async fn repo_settings(db: &PgPool, repository_id: Uuid) -> (Option<bool>, Option<i64>) {
    let rows: Vec<(String, Option<String>)> = sqlx::query_as(
        "SELECT key, value FROM repository_config \
         WHERE repository_id = $1 AND key IN ('quarantine_enabled', 'quarantine_duration_minutes')",
    )
    .bind(repository_id)
    .fetch_all(db)
    .await
    .unwrap_or_default();

    let mut enabled = None;
    let mut duration = None;

    for (key, value) in &rows {
        match key.as_str() {
            "quarantine_enabled" => {
                if let Some(v) = value {
                    enabled = Some(v == "true" || v == "1");
                }
            }
            "quarantine_duration_minutes" => {
                if let Some(v) = value {
                    if let Ok(d) = v.parse::<i64>() {
                        duration = Some(d);
                    }
                }
            }
            _ => {}
        }
    }

    (enabled, duration)
}

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

    // Per-repo overrides from repository_config take precedence.
    let (enabled, duration) = repo_settings(db, repository_id).await;

    QuarantineConfig {
        enabled: enabled.unwrap_or(global_enabled),
        duration_minutes: validate_duration(duration.unwrap_or(global_duration)),
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
///
/// Only the transition `quarantined -> released` or `quarantined -> rejected`
/// is allowed. Returns 409 Conflict if the artifact is not currently
/// quarantined (e.g. already released or rejected).
pub async fn transition(db: &PgPool, artifact_id: Uuid, new_status: QuarantineState) -> Result<()> {
    // Validate: only quarantined -> released/rejected is allowed
    match new_status {
        QuarantineState::Released | QuarantineState::Rejected => {}
        QuarantineState::Quarantined => {
            return Err(AppError::Conflict(
                "Cannot transition to quarantined state".to_string(),
            ));
        }
    }

    // Use conditional UPDATE to ensure the artifact is currently quarantined.
    // This also prevents race conditions where a scanner tries to overwrite
    // a rejection set by an admin.
    let result = sqlx::query(
        "UPDATE artifacts SET quarantine_status = $2, quarantine_until = NULL \
         WHERE id = $1 AND quarantine_status = 'quarantined'",
    )
    .bind(artifact_id)
    .bind(new_status.as_str())
    .execute(db)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;

    if result.rows_affected() == 0 {
        return Err(AppError::Conflict(
            "Artifact is not in quarantined state; transition not allowed".to_string(),
        ));
    }

    Ok(())
}

/// Fetch the raw `(quarantine_status, quarantine_until)` for a live artifact.
///
/// Returns `Ok(None)` when no matching (non-deleted) row exists. Shared by
/// [`get_status`] and [`check_artifact_download`] so the identical SELECT is
/// expressed once.
async fn fetch_quarantine_fields(
    db: &PgPool,
    artifact_id: Uuid,
) -> Result<Option<(Option<String>, Option<DateTime<Utc>>)>> {
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
    .map_err(|e| AppError::Database(e.to_string()))?;

    Ok(row.map(|r| (r.quarantine_status, r.quarantine_until)))
}

/// Fetch the current quarantine status and expiry for an artifact.
pub async fn get_status(
    db: &PgPool,
    artifact_id: Uuid,
) -> Result<(Option<String>, Option<DateTime<Utc>>)> {
    fetch_quarantine_fields(db, artifact_id)
        .await?
        .ok_or_else(|| AppError::NotFound("Artifact not found".to_string()))
}

/// Fetch quarantine status along with the artifact's repository_id.
///
/// Used by the quarantine status endpoint to enforce repository visibility.
pub async fn get_status_with_repo(
    db: &PgPool,
    artifact_id: Uuid,
) -> Result<(Option<String>, Option<DateTime<Utc>>, Uuid)> {
    #[derive(sqlx::FromRow)]
    struct Row {
        quarantine_status: Option<String>,
        quarantine_until: Option<DateTime<Utc>>,
        repository_id: Uuid,
    }

    let row = sqlx::query_as::<_, Row>(
        "SELECT quarantine_status, quarantine_until, repository_id \
         FROM artifacts WHERE id = $1 AND is_deleted = false",
    )
    .bind(artifact_id)
    .fetch_optional(db)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?
    .ok_or_else(|| AppError::NotFound("Artifact not found".to_string()))?;

    Ok((
        row.quarantine_status,
        row.quarantine_until,
        row.repository_id,
    ))
}

/// Check quarantine status for an artifact before serving it.
///
/// This is the common quarantine gate for all download paths. It queries the
/// artifact's quarantine fields and returns an error if the artifact is
/// quarantined (409 Conflict) or rejected (403 Forbidden).
pub async fn check_artifact_download(db: &PgPool, artifact_id: Uuid) -> Result<()> {
    if let Some((status, until)) = fetch_quarantine_fields(db, artifact_id).await? {
        check_download_allowed(status.as_deref(), until, Utc::now())?;
    }

    Ok(())
}

/// Validate that a quarantine duration is at least 1 minute.
pub fn validate_duration(minutes: i64) -> i64 {
    minutes.max(1)
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
    // quarantine_until_from_release
    // -----------------------------------------------------------------------

    #[test]
    fn test_quarantine_until_from_release_recent_release_in_future() {
        let now = Utc::now();
        let config = QuarantineConfig {
            enabled: true,
            duration_minutes: 120,
        };
        let release = now - Duration::minutes(30);
        let until = quarantine_until_from_release(&config, Some(release), now);
        assert_eq!(until, release + Duration::minutes(120));
        assert!(until > now, "recent release must still be held");
        // The held window composes with check_download_allowed -> blocked.
        assert!(check_download_allowed(Some("quarantined"), Some(until), now).is_err());
    }

    #[test]
    fn test_quarantine_until_from_release_old_release_already_expired() {
        let now = Utc::now();
        let config = QuarantineConfig {
            enabled: true,
            duration_minutes: 60,
        };
        // Released long before the window: the hold has already elapsed.
        let release = now - Duration::days(365);
        let until = quarantine_until_from_release(&config, Some(release), now);
        assert!(until < now, "old release must yield an elapsed window");
        // And composes with check_download_allowed -> downloadable.
        assert!(check_download_allowed(Some("quarantined"), Some(until), now).is_ok());
    }

    #[test]
    fn test_quarantine_until_from_release_falls_back_to_now() {
        let now = Utc::now();
        let config = QuarantineConfig {
            enabled: true,
            duration_minutes: 45,
        };
        let until = quarantine_until_from_release(&config, None, now);
        assert_eq!(until, quarantine_until(&config, now));
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

    // -----------------------------------------------------------------------
    // validate_duration
    // -----------------------------------------------------------------------

    #[test]
    fn test_validate_duration_positive() {
        assert_eq!(validate_duration(30), 30);
        assert_eq!(validate_duration(1), 1);
        assert_eq!(validate_duration(1440), 1440);
    }

    #[test]
    fn test_validate_duration_zero_clamped() {
        assert_eq!(validate_duration(0), 1);
    }

    #[test]
    fn test_validate_duration_negative_clamped() {
        assert_eq!(validate_duration(-10), 1);
        assert_eq!(validate_duration(-1), 1);
    }

    // -----------------------------------------------------------------------
    // rejected returns 403 (Authorization error), not 409 (Conflict)
    // -----------------------------------------------------------------------

    #[test]
    fn test_rejected_returns_forbidden() {
        let now = Utc::now();
        let result = check_download_allowed(Some("rejected"), None, now);
        let err = result.unwrap_err();
        // AppError::Authorization maps to 403 FORBIDDEN
        match err {
            crate::error::AppError::Authorization(_) => {}
            other => panic!("Expected Authorization error, got: {other:?}"),
        }
    }

    #[test]
    fn test_quarantined_returns_conflict() {
        let now = Utc::now();
        let until = now + Duration::minutes(30);
        let result = check_download_allowed(Some("quarantined"), Some(until), now);
        let err = result.unwrap_err();
        // AppError::Conflict maps to 409 CONFLICT
        match err {
            crate::error::AppError::Conflict(_) => {}
            other => panic!("Expected Conflict error, got: {other:?}"),
        }
    }
}
