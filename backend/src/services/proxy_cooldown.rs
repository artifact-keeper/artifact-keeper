//! Remote proxy publish-age cooldown policy (#1558).
//!
//! For pull-through (remote/virtual) repositories this implements a
//! "publish-age cooldown": newly published upstream package versions are
//! withheld from ordinary clients until they are at least N minutes old,
//! measured from the *upstream publish timestamp* (not Artifact Keeper's first
//! ingest time). This blunts fast-burn supply-chain attacks where a malicious
//! version is published with compromised credentials and pulled into CI within
//! hours, before the registry or scanners catch it.
//!
//! Unlike [`crate::services::quarantine_service`] (which holds locally uploaded
//! artifact rows), this policy operates on proxy metadata/age and does not
//! require the proxied artifact to exist in the `artifacts` table — so it works
//! today without depending on the #1278 storage-routing rework.
//!
//! Configuration resolution order:
//! 1. Per-repo keys in `repository_config`
//!    (`remote_publish_age_cooldown_enabled`, `remote_publish_age_cooldown_minutes`)
//! 2. Global env vars
//!    (`REMOTE_PUBLISH_AGE_COOLDOWN_ENABLED`, `REMOTE_PUBLISH_AGE_COOLDOWN_MINUTES`)
//! 3. Hardcoded defaults (disabled, 14 days)

use chrono::{DateTime, Duration, Utc};
use sqlx::PgPool;
use uuid::Uuid;

/// Default cooldown window in minutes when enabled but not otherwise
/// configured: 14 days (14 * 24 * 60).
pub const DEFAULT_COOLDOWN_MINUTES: i64 = 20_160;

// ---------------------------------------------------------------------------
// Pure-function decision logic (no I/O, fully testable)
// ---------------------------------------------------------------------------

/// Resolved publish-age cooldown configuration for a single repository.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CooldownConfig {
    pub enabled: bool,
    pub min_age_minutes: i64,
}

impl Default for CooldownConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            min_age_minutes: DEFAULT_COOLDOWN_MINUTES,
        }
    }
}

/// Clamp a configured cooldown to a non-negative value. A cooldown of `0`
/// disables the hold for that repository (e.g. a trusted upstream that already
/// enforces its own cooldown), which is why this floor is `0` rather than `1`.
pub fn validate_minutes(minutes: i64) -> i64 {
    minutes.max(0)
}

/// Parse an upstream publish timestamp. Accepts RFC 3339 / ISO 8601 (the shape
/// npm packument `time` maps and PyPI `upload-time` use, e.g.
/// `2026-03-24T18:05:11.123Z`).
pub fn parse_publish_time(s: &str) -> Option<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(s)
        .ok()
        .map(|dt| dt.with_timezone(&Utc))
}

/// The instant a version published at `published_at` becomes serveable under a
/// cooldown of `min_age_minutes`.
pub fn available_at(published_at: DateTime<Utc>, min_age_minutes: i64) -> DateTime<Utc> {
    published_at + Duration::minutes(min_age_minutes)
}

/// Whether a version published at `published_at` is still inside its cooldown
/// window at `now`. A disabled config or a non-positive window never blocks.
pub fn is_blocked(cfg: &CooldownConfig, published_at: DateTime<Utc>, now: DateTime<Utc>) -> bool {
    if !cfg.enabled || cfg.min_age_minutes <= 0 {
        return false;
    }
    now < available_at(published_at, cfg.min_age_minutes)
}

// ---------------------------------------------------------------------------
// Configuration resolution (I/O layer)
// ---------------------------------------------------------------------------

/// Read the raw per-repository cooldown settings from `repository_config`.
/// Returns `None` for a key that is unset or unparseable.
pub async fn repo_settings(db: &PgPool, repository_id: Uuid) -> (Option<bool>, Option<i64>) {
    let rows: Vec<(String, Option<String>)> = sqlx::query_as(
        "SELECT key, value FROM repository_config \
         WHERE repository_id = $1 \
           AND key IN ('remote_publish_age_cooldown_enabled', 'remote_publish_age_cooldown_minutes')",
    )
    .bind(repository_id)
    .fetch_all(db)
    .await
    .unwrap_or_default();

    let mut enabled = None;
    let mut minutes = None;

    for (key, value) in &rows {
        match key.as_str() {
            "remote_publish_age_cooldown_enabled" => {
                if let Some(v) = value {
                    enabled = Some(v == "true" || v == "1");
                }
            }
            "remote_publish_age_cooldown_minutes" => {
                if let Some(v) = value {
                    if let Ok(m) = v.parse::<i64>() {
                        minutes = Some(m);
                    }
                }
            }
            _ => {}
        }
    }

    (enabled, minutes)
}

/// Resolve the effective cooldown config for a repository.
///
/// Checks `repository_config` first, then env vars, then defaults.
pub async fn resolve_config(db: &PgPool, repository_id: Uuid) -> CooldownConfig {
    let global_enabled = matches!(
        std::env::var("REMOTE_PUBLISH_AGE_COOLDOWN_ENABLED").as_deref(),
        Ok("true" | "1")
    );
    let global_minutes: i64 = std::env::var("REMOTE_PUBLISH_AGE_COOLDOWN_MINUTES")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(DEFAULT_COOLDOWN_MINUTES);

    let (enabled, minutes) = repo_settings(db, repository_id).await;

    CooldownConfig {
        enabled: enabled.unwrap_or(global_enabled),
        min_age_minutes: validate_minutes(minutes.unwrap_or(global_minutes)),
    }
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(enabled: bool, minutes: i64) -> CooldownConfig {
        CooldownConfig {
            enabled,
            min_age_minutes: minutes,
        }
    }

    #[test]
    fn default_is_disabled_with_14_day_window() {
        let c = CooldownConfig::default();
        assert!(!c.enabled);
        assert_eq!(c.min_age_minutes, 20_160);
    }

    #[test]
    fn validate_minutes_floors_at_zero() {
        assert_eq!(validate_minutes(-5), 0);
        assert_eq!(validate_minutes(0), 0);
        assert_eq!(validate_minutes(100), 100);
    }

    #[test]
    fn parse_publish_time_accepts_iso8601() {
        assert!(parse_publish_time("2026-03-24T18:05:11.123Z").is_some());
        assert!(parse_publish_time("2026-03-24T18:05:11Z").is_some());
        assert!(parse_publish_time("not-a-date").is_none());
        assert!(parse_publish_time("").is_none());
    }

    #[test]
    fn disabled_never_blocks() {
        let now = Utc::now();
        let just_published = now - Duration::minutes(1);
        assert!(!is_blocked(&cfg(false, 20_160), just_published, now));
    }

    #[test]
    fn zero_window_never_blocks() {
        let now = Utc::now();
        let just_published = now - Duration::seconds(1);
        assert!(!is_blocked(&cfg(true, 0), just_published, now));
    }

    #[test]
    fn fresh_version_is_blocked_old_version_is_allowed() {
        let now = Utc::now();
        let c = cfg(true, 20_160); // 14 days

        let three_hours_old = now - Duration::hours(3);
        assert!(is_blocked(&c, three_hours_old, now));

        let fifteen_days_old = now - Duration::days(15);
        assert!(!is_blocked(&c, fifteen_days_old, now));
    }

    #[test]
    fn boundary_exactly_at_window_is_allowed() {
        let now = Utc::now();
        let c = cfg(true, 60);
        let exactly_one_hour = now - Duration::minutes(60);
        // available_at == now, and the gate is `now < available_at`.
        assert!(!is_blocked(&c, exactly_one_hour, now));
    }

    #[test]
    fn available_at_adds_window() {
        let published = parse_publish_time("2026-03-24T00:00:00Z").unwrap();
        let avail = available_at(published, 20_160);
        assert_eq!(avail, published + Duration::days(14));
    }
}
