//! The instance-wide storage quota (`STORAGE_QUOTA_BYTES`).
//!
//! Usage is the sum of `repository_usage_ledger` (`hosted + proxy + oci`
//! bytes), the figure `GET /api/v1/admin/stats` reports as
//! `total_storage_bytes`. The ledger is maintained by triggers in the same
//! transaction as every write and delete, so enforcement is live: a delete
//! frees its bytes for the next upload at once.
//!
//! Two checks enforce it:
//!
//! * [`admit_declared`], before the body is read: a write whose declared
//!   `Content-Length` would take usage over the quota, or any write once
//!   usage is at the quota, is refused (read-only at 100 %).
//! * [`instance_denial`], inside the shared publish admission
//!   ([`crate::services::repository_service::RepositoryService::check_quota_locked`]
//!   and its unlocked preflight), once the size is known: this is the check
//!   that covers a body sent without a length, and it nets out the bytes an
//!   overwrite replaces.
//!
//! The settings are process-wide (installed with the application state), so
//! the service-layer admission paths, which only hold a database pool, can
//! read them.

use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::RwLock;

use serde::Serialize;
use sqlx::PgPool;
use utoipa::ToSchema;

use super::{format_bytes, percent, QuotaRefusal};
use crate::config::QuotaSettings;
use crate::error::Result;
use crate::services::repository_service::{QuotaDenial, QuotaScope};

#[derive(Debug, Clone, Default)]
struct Settings {
    quota_bytes: u64,
    warn_percent: u8,
    help_url: Option<String>,
}

static SETTINGS: RwLock<Option<Settings>> = RwLock::new(None);

/// Last observed state, so a crossing is logged once rather than on every
/// upload: 0 ok, 1 warning, 2 exceeded.
static LAST_STATE: AtomicU8 = AtomicU8::new(0);

/// Install the storage-quota settings for this process.
pub fn install(settings: &QuotaSettings) {
    let next = Settings {
        quota_bytes: settings.storage_quota_bytes,
        warn_percent: settings.storage_warn_percent,
        help_url: settings.help_url.clone(),
    };
    *SETTINGS.write().unwrap_or_else(|p| p.into_inner()) = Some(next);
    metrics::gauge!("ak_storage_quota_bytes").set(settings.storage_quota_bytes as f64);
}

fn settings() -> Settings {
    SETTINGS
        .read()
        .unwrap_or_else(|p| p.into_inner())
        .clone()
        .unwrap_or(Settings {
            warn_percent: 80,
            ..Settings::default()
        })
}

/// Whether an instance storage quota is configured.
pub fn enabled() -> bool {
    settings().quota_bytes > 0
}

/// `QUOTA_HELP_URL`, when configured.
pub fn help_url() -> Option<String> {
    settings().help_url
}

/// Bytes the instance stores: the sum of every repository's usage ledger.
pub async fn instance_used_bytes(db: &PgPool) -> Result<u64> {
    let total: i64 = sqlx::query_scalar(
        "SELECT COALESCE(SUM(hosted_bytes + proxy_bytes + oci_bytes), 0)::BIGINT \
           FROM repository_usage_ledger",
    )
    .fetch_one(db)
    .await?;
    Ok(u64::try_from(total).unwrap_or(0))
}

/// `ok`, `warning` (at or above the warning threshold) or `exceeded` (at or
/// above the quota).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum StorageState {
    Ok,
    Warning,
    Exceeded,
}

/// The state of `used` against `quota` with a warning threshold of
/// `warn_percent`.
pub(crate) fn state_of(quota: u64, used: u64, warn_percent: u8) -> StorageState {
    if quota == 0 {
        StorageState::Ok
    } else if used >= quota {
        StorageState::Exceeded
    } else if u128::from(used) * 100 >= u128::from(quota) * u128::from(warn_percent) {
        StorageState::Warning
    } else {
        StorageState::Ok
    }
}

/// Record a usage reading: the gauges, and one log line per state change.
pub fn observe(used: u64) {
    let s = settings();
    metrics::gauge!("ak_storage_used_bytes").set(used as f64);
    metrics::gauge!("ak_storage_quota_bytes").set(s.quota_bytes as f64);
    let state = state_of(s.quota_bytes, used, s.warn_percent);
    let code = match state {
        StorageState::Ok => 0,
        StorageState::Warning => 1,
        StorageState::Exceeded => 2,
    };
    let previous = LAST_STATE.swap(code, Ordering::Relaxed);
    if previous == code {
        return;
    }
    let (used_h, quota_h) = (format_bytes(used), format_bytes(s.quota_bytes));
    match state {
        StorageState::Exceeded => tracing::warn!(
            used_bytes = used,
            quota_bytes = s.quota_bytes,
            "storage quota reached ({used_h} of {quota_h}): writes that store new bytes \
             are refused until artifacts are deleted or the quota is raised"
        ),
        StorageState::Warning if code > previous => tracing::warn!(
            used_bytes = used,
            quota_bytes = s.quota_bytes,
            warn_percent = s.warn_percent,
            "storage usage crossed the warning threshold ({used_h} of {quota_h})"
        ),
        _ => tracing::info!(
            used_bytes = used,
            quota_bytes = s.quota_bytes,
            "storage usage is back below the {} threshold ({used_h} of {quota_h})",
            if previous == 2 { "quota" } else { "warning" }
        ),
    }
}

/// The instance-quota denial of a write that adds `additional_bytes`, or
/// `None` when it fits (or adds nothing, or no quota is set).
pub async fn instance_denial(db: &PgPool, additional_bytes: i64) -> Result<Option<QuotaDenial>> {
    let quota = settings().quota_bytes;
    if quota == 0 || additional_bytes <= 0 {
        return Ok(None);
    }
    let used = instance_used_bytes(db).await?;
    observe(used);
    let additional = u64::try_from(additional_bytes).unwrap_or(0);
    Ok(
        (used.saturating_add(additional) > quota).then(|| QuotaDenial {
            scope: QuotaScope::Instance,
            limit_bytes: i64::try_from(quota).unwrap_or(i64::MAX),
            used_bytes: i64::try_from(used).unwrap_or(i64::MAX),
            repository: None,
            project: None,
        }),
    )
}

/// Pre-body admission of a write that declares `declared` bytes (`None` for
/// a body without `Content-Length`): refused once usage is at the quota, or
/// when the declared length would take it over.
pub(crate) fn declared_write_refused(quota: u64, used: u64, declared: Option<u64>) -> bool {
    quota > 0 && (used >= quota || declared.is_some_and(|d| used.saturating_add(d) > quota))
}

/// The pre-body admission of [`declared_write_refused`], as the refusal to
/// answer with.
pub async fn admit_declared(db: &PgPool, declared: Option<u64>) -> Result<Option<QuotaRefusal>> {
    let s = settings();
    if s.quota_bytes == 0 {
        return Ok(None);
    }
    let used = instance_used_bytes(db).await?;
    observe(used);
    Ok(declared_write_refused(s.quota_bytes, used, declared)
        .then(|| QuotaRefusal::instance_storage(s.quota_bytes, used, s.help_url.clone())))
}

/// Whether the instance is at its storage quota. A proxy (remote)
/// repository consults it before caching an upstream response: at the quota
/// the response is still served, only not cached. A failed lookup answers
/// `false` (cache as before).
pub async fn at_quota(db: &PgPool) -> bool {
    let quota = settings().quota_bytes;
    if quota == 0 {
        return false;
    }
    match instance_used_bytes(db).await {
        Ok(used) => {
            observe(used);
            used >= quota
        }
        Err(e) => {
            tracing::warn!(error = %e, "storage quota lookup failed; caching as usual");
            false
        }
    }
}

/// The `storage_quota` object of `GET /api/v1/system/quota`.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct StorageQuotaStatus {
    pub enabled: bool,
    pub quota_bytes: Option<u64>,
    pub used_bytes: u64,
    pub percent: Option<f64>,
    pub warn_percent: u8,
    pub state: StorageState,
}

impl StorageQuotaStatus {
    /// No quota configured, with `used` bytes stored.
    pub fn unset(used: i64) -> Self {
        Self {
            enabled: false,
            quota_bytes: None,
            used_bytes: u64::try_from(used).unwrap_or(0),
            percent: None,
            warn_percent: 80,
            state: StorageState::Ok,
        }
    }
}

/// Current storage quota figures.
pub async fn status(db: &PgPool) -> Result<StorageQuotaStatus> {
    let s = settings();
    let used = instance_used_bytes(db).await?;
    if s.quota_bytes > 0 {
        observe(used);
    }
    Ok(StorageQuotaStatus {
        enabled: s.quota_bytes > 0,
        quota_bytes: (s.quota_bytes > 0).then_some(s.quota_bytes),
        used_bytes: used,
        percent: percent(used, s.quota_bytes),
        warn_percent: s.warn_percent,
        state: state_of(s.quota_bytes, used, s.warn_percent),
    })
}

#[cfg(ak_test_shard = "services-1")]
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn state_follows_the_thresholds() {
        assert_eq!(state_of(0, 999, 80), StorageState::Ok);
        assert_eq!(state_of(100, 79, 80), StorageState::Ok);
        assert_eq!(state_of(100, 80, 80), StorageState::Warning);
        assert_eq!(state_of(100, 99, 80), StorageState::Warning);
        assert_eq!(state_of(100, 100, 80), StorageState::Exceeded);
        assert_eq!(state_of(100, 150, 80), StorageState::Exceeded);
        assert_eq!(state_of(u64::MAX, u64::MAX - 1, 99), StorageState::Warning);
    }

    #[test]
    fn declared_writes_are_refused_at_the_quota_or_when_they_would_cross_it() {
        // No quota: never.
        assert!(!declared_write_refused(0, u64::MAX, Some(u64::MAX)));
        // Below the quota: a body that fits, or one without a length, passes.
        assert!(!declared_write_refused(100, 60, Some(40)));
        assert!(!declared_write_refused(100, 60, None));
        assert!(!declared_write_refused(100, 60, Some(0)));
        // A declared body that would cross the quota is refused.
        assert!(declared_write_refused(100, 60, Some(41)));
        assert!(declared_write_refused(100, 1, Some(u64::MAX)));
        // At (or over) the quota every write is refused, even an empty one.
        assert!(declared_write_refused(100, 100, None));
        assert!(declared_write_refused(100, 100, Some(0)));
        assert!(declared_write_refused(100, 150, Some(1)));
    }

    #[test]
    fn install_toggles_enabled_and_help_url() {
        install(&QuotaSettings {
            storage_quota_bytes: 10,
            help_url: Some("https://example.test/q".into()),
            ..QuotaSettings::default()
        });
        assert!(enabled());
        assert_eq!(help_url().as_deref(), Some("https://example.test/q"));
        install(&QuotaSettings::default());
        assert!(!enabled());
        assert_eq!(help_url(), None);
    }
}
