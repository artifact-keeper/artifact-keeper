//! Quarantine period enforcement for newly published artifacts.
//!
//! When quarantine is enabled, artifacts enter a holding period after upload.
//! During this period they are stored but not available for download. Security
//! scanners run against the artifact, and on completion the quarantine is either
//! released (scans pass) or the artifact is rejected (scans fail). If no scan
//! completes before the quarantine timeout, the artifact is auto-released on
//! the next download attempt.

use chrono::{DateTime, Utc};
use uuid::Uuid;

// ---------------------------------------------------------------------------
// Quarantine status values
// ---------------------------------------------------------------------------

/// Status value for artifacts under active quarantine hold.
pub const STATUS_QUARANTINED: &str = "quarantined";
/// Status value for artifacts released from quarantine (scans passed or admin override).
pub const STATUS_RELEASED: &str = "released";
/// Status value for artifacts rejected by security scans.
pub const STATUS_REJECTED: &str = "rejected";
/// Legacy status: scan completed with no findings.
pub const STATUS_CLEAN: &str = "clean";
/// Legacy status: scan completed with findings.
pub const STATUS_FLAGGED: &str = "flagged";
/// Legacy status: not yet scanned.
pub const STATUS_UNSCANNED: &str = "unscanned";

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/// Quarantine configuration loaded from environment variables.
#[derive(Debug, Clone)]
pub struct QuarantineConfig {
    /// Whether quarantine is enabled globally.
    pub enabled: bool,
    /// Duration of the quarantine hold in minutes.
    pub duration_minutes: u64,
}

impl Default for QuarantineConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            duration_minutes: 60,
        }
    }
}

// ---------------------------------------------------------------------------
// Decision logic (pure functions, easily testable)
// ---------------------------------------------------------------------------

/// Determine whether an artifact is currently blocked by quarantine.
///
/// Returns a `QuarantineDecision` describing whether download should proceed.
/// An artifact is blocked when:
/// - quarantine_status is 'quarantined' AND quarantine_until is in the future
/// - quarantine_status is 'rejected'
///
/// An artifact is NOT blocked when:
/// - quarantine_status is NULL, 'released', 'clean', or 'unscanned'
/// - quarantine_status is 'quarantined' but quarantine_until has passed (auto-release)
/// - quarantine_status is 'flagged' (legacy scan status, not a download block)
pub fn is_quarantine_blocked(
    quarantine_status: Option<&str>,
    quarantine_until: Option<DateTime<Utc>>,
    now: DateTime<Utc>,
) -> QuarantineDecision {
    match quarantine_status {
        Some(STATUS_REJECTED) => QuarantineDecision::Rejected,
        Some(STATUS_QUARANTINED) => {
            if let Some(until) = quarantine_until {
                if now < until {
                    QuarantineDecision::Blocked { expires_at: until }
                } else {
                    // Quarantine period expired, auto-release
                    QuarantineDecision::Expired
                }
            } else {
                // Quarantined without a deadline should not happen, but treat
                // as expired (safe fallback).
                QuarantineDecision::Expired
            }
        }
        // 'released', 'clean', 'unscanned', 'flagged', or NULL: not blocked
        _ => QuarantineDecision::Allowed,
    }
}

/// Result of evaluating quarantine status for an artifact.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QuarantineDecision {
    /// Artifact is available for download.
    Allowed,
    /// Artifact is under active quarantine. Download is blocked until `expires_at`.
    Blocked { expires_at: DateTime<Utc> },
    /// Quarantine period has expired. The artifact should be auto-released.
    Expired,
    /// Artifact was rejected by security scans. Download is permanently blocked
    /// until an administrator manually overrides the status.
    Rejected,
}

/// Compute the quarantine_until timestamp for a new upload.
pub fn compute_quarantine_until(config: &QuarantineConfig, now: DateTime<Utc>) -> DateTime<Utc> {
    now + chrono::Duration::minutes(config.duration_minutes as i64)
}

/// Determine the new quarantine_status after all scans complete.
///
/// If any scan found vulnerabilities (findings_count > 0), the artifact
/// is rejected. Otherwise it is released.
pub fn status_after_scan(findings_count: i32) -> &'static str {
    if findings_count > 0 {
        STATUS_REJECTED
    } else {
        STATUS_RELEASED
    }
}

// ---------------------------------------------------------------------------
// Database helpers
// ---------------------------------------------------------------------------

/// Set quarantine status and deadline on an artifact.
pub async fn set_quarantine(
    db: &sqlx::PgPool,
    artifact_id: Uuid,
    status: &str,
    until: Option<DateTime<Utc>>,
) -> Result<(), sqlx::Error> {
    sqlx::query("UPDATE artifacts SET quarantine_status = $2, quarantine_until = $3 WHERE id = $1")
        .bind(artifact_id)
        .bind(status)
        .bind(until)
        .execute(db)
        .await?;
    Ok(())
}

/// Release an artifact from quarantine (set status to 'released', clear deadline).
pub async fn release_quarantine(db: &sqlx::PgPool, artifact_id: Uuid) -> Result<(), sqlx::Error> {
    sqlx::query(
        "UPDATE artifacts SET quarantine_status = 'released', quarantine_until = NULL WHERE id = $1",
    )
    .bind(artifact_id)
    .execute(db)
    .await?;
    Ok(())
}

/// Reject an artifact (set status to 'rejected', clear deadline).
pub async fn reject_quarantine(db: &sqlx::PgPool, artifact_id: Uuid) -> Result<(), sqlx::Error> {
    sqlx::query(
        "UPDATE artifacts SET quarantine_status = 'rejected', quarantine_until = NULL WHERE id = $1",
    )
    .bind(artifact_id)
    .execute(db)
    .await?;
    Ok(())
}

/// Fetch quarantine fields for an artifact. Returns (quarantine_status, quarantine_until).
pub async fn get_quarantine_info(
    db: &sqlx::PgPool,
    artifact_id: Uuid,
) -> Result<Option<(Option<String>, Option<DateTime<Utc>>)>, sqlx::Error> {
    let row: Option<(Option<String>, Option<DateTime<Utc>>)> = sqlx::query_as(
        "SELECT quarantine_status, quarantine_until FROM artifacts WHERE id = $1 AND is_deleted = false",
    )
    .bind(artifact_id)
    .fetch_optional(db)
    .await?;
    Ok(row)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{Duration, Utc};

    #[test]
    fn test_allowed_when_no_quarantine() {
        let decision = is_quarantine_blocked(None, None, Utc::now());
        assert_eq!(decision, QuarantineDecision::Allowed);
    }

    #[test]
    fn test_allowed_when_released() {
        let decision = is_quarantine_blocked(Some(STATUS_RELEASED), None, Utc::now());
        assert_eq!(decision, QuarantineDecision::Allowed);
    }

    #[test]
    fn test_allowed_when_clean() {
        let decision = is_quarantine_blocked(Some(STATUS_CLEAN), None, Utc::now());
        assert_eq!(decision, QuarantineDecision::Allowed);
    }

    #[test]
    fn test_allowed_when_unscanned() {
        let decision = is_quarantine_blocked(Some(STATUS_UNSCANNED), None, Utc::now());
        assert_eq!(decision, QuarantineDecision::Allowed);
    }

    #[test]
    fn test_allowed_when_flagged_legacy() {
        // 'flagged' is a legacy scan status. It is informational and should
        // not block downloads (the policy engine handles enforcement separately).
        let decision = is_quarantine_blocked(Some(STATUS_FLAGGED), None, Utc::now());
        assert_eq!(decision, QuarantineDecision::Allowed);
    }

    #[test]
    fn test_blocked_during_quarantine() {
        let now = Utc::now();
        let until = now + Duration::hours(1);
        let decision = is_quarantine_blocked(Some(STATUS_QUARANTINED), Some(until), now);
        assert_eq!(decision, QuarantineDecision::Blocked { expires_at: until });
    }

    #[test]
    fn test_expired_quarantine() {
        let now = Utc::now();
        let until = now - Duration::minutes(5);
        let decision = is_quarantine_blocked(Some(STATUS_QUARANTINED), Some(until), now);
        assert_eq!(decision, QuarantineDecision::Expired);
    }

    #[test]
    fn test_expired_quarantine_no_deadline() {
        let now = Utc::now();
        let decision = is_quarantine_blocked(Some(STATUS_QUARANTINED), None, now);
        assert_eq!(decision, QuarantineDecision::Expired);
    }

    #[test]
    fn test_rejected() {
        let now = Utc::now();
        let decision = is_quarantine_blocked(Some(STATUS_REJECTED), None, now);
        assert_eq!(decision, QuarantineDecision::Rejected);
    }

    #[test]
    fn test_rejected_ignores_deadline() {
        let now = Utc::now();
        let until = now + Duration::hours(1);
        let decision = is_quarantine_blocked(Some(STATUS_REJECTED), Some(until), now);
        assert_eq!(decision, QuarantineDecision::Rejected);
    }

    #[test]
    fn test_compute_quarantine_until() {
        let config = QuarantineConfig {
            enabled: true,
            duration_minutes: 120,
        };
        let now = Utc::now();
        let until = compute_quarantine_until(&config, now);
        let diff = until - now;
        assert_eq!(diff.num_minutes(), 120);
    }

    #[test]
    fn test_status_after_scan_clean() {
        assert_eq!(status_after_scan(0), STATUS_RELEASED);
    }

    #[test]
    fn test_status_after_scan_findings() {
        assert_eq!(status_after_scan(1), STATUS_REJECTED);
        assert_eq!(status_after_scan(50), STATUS_REJECTED);
    }

    #[test]
    fn test_status_after_scan_negative_treated_as_clean() {
        // Negative findings count should not happen, but treat it safely.
        assert_eq!(status_after_scan(-1), STATUS_RELEASED);
    }

    #[test]
    fn test_default_config() {
        let config = QuarantineConfig::default();
        assert!(!config.enabled);
        assert_eq!(config.duration_minutes, 60);
    }

    #[test]
    fn test_blocked_at_exact_deadline() {
        // At the exact deadline moment, quarantine should be expired (not blocked).
        // The check is now < until, so at the exact boundary it is NOT less than.
        let now = Utc::now();
        let decision = is_quarantine_blocked(Some(STATUS_QUARANTINED), Some(now), now);
        assert_eq!(decision, QuarantineDecision::Expired);
    }
}
