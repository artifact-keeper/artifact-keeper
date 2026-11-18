//! The monthly download transfer quota (`TRANSFER_QUOTA_BYTES`).
//!
//! Each replica counts the bytes it sends on artifact downloads in memory
//! ([`TransferMeter::record`]) and adds them to one row per calendar month
//! (UTC) of `transfer_quota_usage` every few seconds ([`TransferMeter::flush`]).
//! The upsert returns the month's total across every replica, so all
//! replicas and restarts share one counter; between flushes a replica sees
//! the shared total plus its own unflushed bytes. A crash loses at most one
//! flush interval of counting.
//!
//! The quota is soft up to the grace band: downloads keep working until the
//! month's total reaches `quota * (100 + grace) / 100`, after which artifact
//! downloads answer `429 TRANSFER_QUOTA_EXCEEDED` with `Retry-After` set to
//! the seconds until the next month starts. A download that started before
//! the limit was reached is finished, so the total can overshoot the hard
//! limit by what was in flight.

use std::sync::atomic::{AtomicU64, AtomicU8, Ordering};
use std::sync::Arc;
use std::time::Duration;

use chrono::{DateTime, Datelike, NaiveDate, SecondsFormat, TimeZone, Utc};
use serde::Serialize;
use sqlx::PgPool;
use tokio::sync::Mutex;
use utoipa::ToSchema;

use super::{format_bytes, percent, QuotaRefusal};
use crate::config::QuotaSettings;

/// How often each replica adds its counted bytes to the shared counter.
pub const FLUSH_INTERVAL: Duration = Duration::from_secs(10);

/// First day of the month `at` falls in (UTC).
pub(crate) fn period_start(at: DateTime<Utc>) -> NaiveDate {
    NaiveDate::from_ymd_opt(at.year(), at.month(), 1).expect("first of the month")
}

/// 00:00 UTC on the first day of the month after `start`.
pub(crate) fn period_end(start: NaiveDate) -> DateTime<Utc> {
    let (year, month) = if start.month() == 12 {
        (start.year() + 1, 1)
    } else {
        (start.year(), start.month() + 1)
    };
    Utc.with_ymd_and_hms(year, month, 1, 0, 0, 0)
        .single()
        .expect("valid month start")
}

/// Seconds from `now` until the next period starts (at least 1).
pub(crate) fn retry_after_secs(now: DateTime<Utc>) -> u64 {
    let end = period_end(period_start(now));
    u64::try_from((end - now).num_seconds()).unwrap_or(0).max(1)
}

/// `quota * (100 + grace) / 100`, saturating.
pub(crate) fn hard_limit(quota: u64, grace_percent: u32) -> u64 {
    let limit = u128::from(quota) * (100 + u128::from(grace_percent)) / 100;
    u64::try_from(limit).unwrap_or(u64::MAX)
}

/// `ok`, `warning` (at or above the warning threshold), `over` (at or above
/// the quota, inside the grace band, still serving) or `refusing` (at the
/// hard limit).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum TransferState {
    Ok,
    Warning,
    Over,
    Refusing,
}

pub(crate) fn state_of(
    quota: u64,
    used: u64,
    warn_percent: u8,
    grace_percent: u32,
) -> TransferState {
    if quota == 0 {
        TransferState::Ok
    } else if used >= hard_limit(quota, grace_percent) {
        TransferState::Refusing
    } else if used >= quota {
        TransferState::Over
    } else if u128::from(used) * 100 >= u128::from(quota) * u128::from(warn_percent) {
        TransferState::Warning
    } else {
        TransferState::Ok
    }
}

/// The `transfer_quota` object of `GET /api/v1/system/quota`.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct TransferQuotaStatus {
    pub enabled: bool,
    pub quota_bytes: Option<u64>,
    pub used_bytes: u64,
    pub percent: Option<f64>,
    pub warn_percent: u8,
    pub grace_percent: u32,
    pub hard_limit_bytes: Option<u64>,
    pub state: TransferState,
    /// Start of the current period (RFC 3339, UTC).
    pub period_start: String,
    /// End of the current period, the start of the next (RFC 3339, UTC).
    pub period_end: String,
}

impl TransferQuotaStatus {
    /// No quota configured and nothing counted, for the current month.
    pub fn unset() -> Self {
        let start = period_start(Utc::now());
        Self {
            enabled: false,
            quota_bytes: None,
            used_bytes: 0,
            percent: None,
            warn_percent: 80,
            grace_percent: 0,
            hard_limit_bytes: None,
            state: TransferState::Ok,
            period_start: Utc
                .from_utc_datetime(&start.and_hms_opt(0, 0, 0).expect("midnight"))
                .to_rfc3339_opts(SecondsFormat::Secs, true),
            period_end: period_end(start).to_rfc3339_opts(SecondsFormat::Secs, true),
        }
    }
}

/// The month's shared total as last read from the database.
#[derive(Debug)]
struct Flushed {
    period: NaiveDate,
    total: u64,
}

/// One replica's view of the monthly transfer counter.
#[derive(Debug)]
pub struct TransferMeter {
    db: PgPool,
    quota_bytes: u64,
    warn_percent: u8,
    grace_percent: u32,
    help_url: Option<String>,
    /// Bytes counted here and not yet added to the shared counter.
    pending: AtomicU64,
    /// The shared total of the current period, as of the last flush.
    shared_total: AtomicU64,
    flushed: Mutex<Flushed>,
    last_state: AtomicU8,
}

impl TransferMeter {
    pub fn new(db: PgPool, settings: &QuotaSettings) -> Arc<Self> {
        metrics::gauge!("ak_transfer_quota_bytes").set(settings.transfer_quota_bytes as f64);
        Arc::new(Self {
            db,
            quota_bytes: settings.transfer_quota_bytes,
            warn_percent: settings.transfer_warn_percent,
            grace_percent: settings.transfer_grace_percent,
            help_url: settings.help_url.clone(),
            pending: AtomicU64::new(0),
            shared_total: AtomicU64::new(0),
            flushed: Mutex::new(Flushed {
                period: period_start(Utc::now()),
                total: 0,
            }),
            last_state: AtomicU8::new(TransferState::Ok as u8),
        })
    }

    /// Whether a transfer quota is configured.
    pub fn enabled(&self) -> bool {
        self.quota_bytes > 0
    }

    /// Count `bytes` sent to a client.
    pub fn record(&self, bytes: u64) {
        if bytes > 0 {
            self.pending.fetch_add(bytes, Ordering::Relaxed);
        }
    }

    /// This replica's view of the current period's total: the shared total
    /// of the last flush plus what it counted since.
    pub fn used_bytes(&self) -> u64 {
        self.shared_total
            .load(Ordering::Relaxed)
            .saturating_add(self.pending.load(Ordering::Relaxed))
    }

    /// The refusal a download answers with at `now`, or `None` while
    /// downloads are allowed.
    pub fn refusal_at(&self, now: DateTime<Utc>) -> Option<QuotaRefusal> {
        if self.quota_bytes == 0 {
            return None;
        }
        let used = self.used_bytes();
        (used >= hard_limit(self.quota_bytes, self.grace_percent)).then(|| {
            QuotaRefusal::transfer(
                self.quota_bytes,
                used,
                period_end(period_start(now)),
                retry_after_secs(now),
                self.help_url.clone(),
            )
        })
    }

    /// [`Self::refusal_at`] now.
    pub fn refusal(&self) -> Option<QuotaRefusal> {
        self.refusal_at(Utc::now())
    }

    /// Add this replica's counted bytes to the shared counter of the current
    /// period and read the period's total back. On a database error the
    /// bytes stay pending for the next flush.
    pub async fn flush(&self) -> crate::error::Result<u64> {
        self.flush_at(Utc::now()).await
    }

    pub(crate) async fn flush_at(&self, now: DateTime<Utc>) -> crate::error::Result<u64> {
        let mut flushed = self.flushed.lock().await;
        let period = period_start(now);
        let pending = self.pending.swap(0, Ordering::Relaxed);
        if flushed.period != period {
            // The month turned since the last flush: what was counted since
            // then belongs (almost all) to the month that ended.
            if let Err(e) = self.add(flushed.period, pending).await {
                self.pending.fetch_add(pending, Ordering::Relaxed);
                return Err(e);
            }
            flushed.period = period;
            flushed.total = 0;
            self.shared_total.store(0, Ordering::Relaxed);
            return self.add_and_store(&mut flushed, 0).await;
        }
        self.add_and_store(&mut flushed, pending).await
    }

    async fn add_and_store(&self, flushed: &mut Flushed, bytes: u64) -> crate::error::Result<u64> {
        match self.add(flushed.period, bytes).await {
            Ok(total) => {
                flushed.total = total;
                self.shared_total.store(total, Ordering::Relaxed);
                self.observe();
                Ok(total)
            }
            Err(e) => {
                self.pending.fetch_add(bytes, Ordering::Relaxed);
                Err(e)
            }
        }
    }

    /// Add `bytes` to `period`'s row and return its total.
    async fn add(&self, period: NaiveDate, bytes: u64) -> crate::error::Result<u64> {
        let bytes = i64::try_from(bytes).unwrap_or(i64::MAX);
        let total: i64 = if bytes == 0 {
            sqlx::query_scalar("SELECT bytes FROM transfer_quota_usage WHERE period_start = $1")
                .bind(period)
                .fetch_optional(&self.db)
                .await?
                .unwrap_or(0)
        } else {
            sqlx::query_scalar(
                "INSERT INTO transfer_quota_usage (period_start, bytes) VALUES ($1, $2) \
                 ON CONFLICT (period_start) DO UPDATE \
                    SET bytes = transfer_quota_usage.bytes + EXCLUDED.bytes, \
                        updated_at = NOW() \
                 RETURNING bytes",
            )
            .bind(period)
            .bind(bytes)
            .fetch_one(&self.db)
            .await?
        };
        Ok(u64::try_from(total).unwrap_or(0))
    }

    /// Gauges, and one log line per state change.
    fn observe(&self) {
        let used = self.used_bytes();
        metrics::gauge!("ak_transfer_used_bytes").set(used as f64);
        metrics::gauge!("ak_transfer_quota_bytes").set(self.quota_bytes as f64);
        let state = state_of(
            self.quota_bytes,
            used,
            self.warn_percent,
            self.grace_percent,
        );
        let previous = self.last_state.swap(state as u8, Ordering::Relaxed);
        if previous == state as u8 {
            return;
        }
        let (used_h, quota_h) = (format_bytes(used), format_bytes(self.quota_bytes));
        match state {
            TransferState::Refusing => tracing::warn!(
                used_bytes = used,
                quota_bytes = self.quota_bytes,
                "download transfer quota hard limit reached ({used_h} of {quota_h} this \
                 month): artifact downloads are refused until the next month"
            ),
            TransferState::Over if state as u8 > previous => tracing::warn!(
                used_bytes = used,
                quota_bytes = self.quota_bytes,
                grace_percent = self.grace_percent,
                "download transfer quota reached ({used_h} of {quota_h} this month); \
                 downloads continue through the grace band"
            ),
            TransferState::Warning if state as u8 > previous => tracing::warn!(
                used_bytes = used,
                quota_bytes = self.quota_bytes,
                warn_percent = self.warn_percent,
                "download transfer crossed the warning threshold ({used_h} of {quota_h} \
                 this month)"
            ),
            _ => tracing::info!(
                used_bytes = used,
                quota_bytes = self.quota_bytes,
                "download transfer state is now {state:?} ({used_h} of {quota_h})"
            ),
        }
    }

    /// Current figures, after a flush so they include every replica's
    /// flushed bytes.
    pub async fn status(&self) -> TransferQuotaStatus {
        let now = Utc::now();
        if let Err(e) = self.flush_at(now).await {
            tracing::warn!(error = %e, "transfer counter flush failed; reporting the cached total");
        }
        self.status_at(now)
    }

    pub(crate) fn status_at(&self, now: DateTime<Utc>) -> TransferQuotaStatus {
        let used = self.used_bytes();
        let start = period_start(now);
        let enabled = self.quota_bytes > 0;
        TransferQuotaStatus {
            enabled,
            quota_bytes: enabled.then_some(self.quota_bytes),
            used_bytes: used,
            percent: percent(used, self.quota_bytes),
            warn_percent: self.warn_percent,
            grace_percent: self.grace_percent,
            hard_limit_bytes: enabled.then(|| hard_limit(self.quota_bytes, self.grace_percent)),
            state: state_of(
                self.quota_bytes,
                used,
                self.warn_percent,
                self.grace_percent,
            ),
            period_start: Utc
                .from_utc_datetime(&start.and_hms_opt(0, 0, 0).expect("midnight"))
                .to_rfc3339_opts(SecondsFormat::Secs, true),
            period_end: period_end(start).to_rfc3339_opts(SecondsFormat::Secs, true),
        }
    }

    /// Flush every [`FLUSH_INTERVAL`] for the life of the process, and keep
    /// the storage-quota gauges current while there.
    pub fn spawn_flusher(self: &Arc<Self>) -> tokio::task::JoinHandle<()> {
        let meter = Arc::clone(self);
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(FLUSH_INTERVAL);
            tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                tick.tick().await;
                if let Err(e) = meter.flush().await {
                    tracing::warn!(error = %e, "transfer counter flush failed; retrying");
                }
                if super::storage::enabled() {
                    match super::storage::instance_used_bytes(&meter.db).await {
                        Ok(used) => super::storage::observe(used),
                        Err(e) => tracing::debug!(error = %e, "storage usage read failed"),
                    }
                }
            }
        })
    }
}

#[cfg(ak_test_shard = "services-1")]
#[cfg(test)]
mod tests {
    use super::*;

    fn at(y: i32, m: u32, d: u32, h: u32, min: u32, s: u32) -> DateTime<Utc> {
        Utc.with_ymd_and_hms(y, m, d, h, min, s).unwrap()
    }

    #[test]
    fn periods_are_calendar_months_in_utc() {
        assert_eq!(
            period_start(at(2026, 11, 12, 15, 0, 0)),
            NaiveDate::from_ymd_opt(2026, 11, 1).unwrap()
        );
        assert_eq!(
            period_end(NaiveDate::from_ymd_opt(2026, 11, 1).unwrap()),
            at(2026, 12, 1, 0, 0, 0)
        );
        assert_eq!(
            period_end(NaiveDate::from_ymd_opt(2026, 12, 1).unwrap()),
            at(2027, 1, 1, 0, 0, 0)
        );
    }

    #[test]
    fn retry_after_counts_the_seconds_to_the_next_month() {
        assert_eq!(retry_after_secs(at(2026, 11, 30, 23, 59, 0)), 60);
        assert_eq!(retry_after_secs(at(2026, 12, 31, 23, 0, 0)), 3600);
        assert_eq!(retry_after_secs(at(2026, 2, 1, 0, 0, 0)), 28 * 86_400);
    }

    #[test]
    fn hard_limit_and_state_follow_the_grace_band() {
        assert_eq!(hard_limit(100, 0), 100);
        assert_eq!(hard_limit(100, 25), 125);
        assert_eq!(hard_limit(u64::MAX, 25), u64::MAX);
        assert_eq!(state_of(0, 1, 80, 25), TransferState::Ok);
        assert_eq!(state_of(100, 79, 80, 25), TransferState::Ok);
        assert_eq!(state_of(100, 80, 80, 25), TransferState::Warning);
        assert_eq!(state_of(100, 100, 80, 25), TransferState::Over);
        assert_eq!(state_of(100, 124, 80, 25), TransferState::Over);
        assert_eq!(state_of(100, 125, 80, 25), TransferState::Refusing);
        assert_eq!(state_of(100, 100, 80, 0), TransferState::Refusing);
    }

    fn lazy_pool() -> PgPool {
        sqlx::postgres::PgPoolOptions::new()
            .connect_lazy("postgres://localhost/unused")
            .expect("lazy pool")
    }

    #[tokio::test]
    async fn refusal_starts_at_the_hard_limit_with_retry_after() {
        let meter = TransferMeter::new(
            lazy_pool(),
            &QuotaSettings {
                transfer_quota_bytes: 100,
                transfer_grace_percent: 25,
                ..QuotaSettings::default()
            },
        );
        let now = at(2026, 11, 30, 23, 0, 0);
        meter.record(124);
        assert!(meter.refusal_at(now).is_none(), "inside the grace band");
        meter.record(1);
        let refusal = meter.refusal_at(now).expect("at the hard limit");
        assert_eq!(refusal.status(), axum::http::StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(refusal.retry_after_seconds, Some(3600));
        assert_eq!(refusal.period_end, Some(at(2026, 12, 1, 0, 0, 0)));
        assert_eq!(refusal.limit_bytes, 100);
        assert_eq!(refusal.used_bytes, Some(125));
        let status = meter.status_at(now);
        assert_eq!(status.state, TransferState::Refusing);
        assert_eq!(status.hard_limit_bytes, Some(125));
        assert_eq!(status.period_start, "2026-11-01T00:00:00Z");
        assert_eq!(status.period_end, "2026-12-01T00:00:00Z");
        assert_eq!(status.percent, Some(125.0));
    }

    #[tokio::test]
    async fn without_a_quota_nothing_is_refused() {
        let meter = TransferMeter::new(lazy_pool(), &QuotaSettings::default());
        meter.record(u64::MAX / 2);
        assert!(!meter.enabled());
        assert!(meter.refusal().is_none());
        let status = meter.status_at(Utc::now());
        assert!(!status.enabled);
        assert_eq!(status.quota_bytes, None);
        assert_eq!(status.hard_limit_bytes, None);
        assert_eq!(status.state, TransferState::Ok);
    }

    /// Two replicas (two meters over one database) share one counter, a
    /// flush carries bytes into the period they were counted in, and a
    /// failed flush keeps them pending.
    #[tokio::test]
    async fn two_replicas_share_one_monthly_counter() {
        let Some(pool) = crate::api::handlers::test_db_helpers::try_pool().await else {
            return;
        };
        let settings = QuotaSettings {
            transfer_quota_bytes: 1000,
            ..QuotaSettings::default()
        };
        // A period far from any other test's, cleaned before and after.
        let now = at(2091, 3, 15, 12, 0, 0);
        let period = period_start(now);
        let next = at(2091, 4, 1, 0, 0, 5);
        let cleanup = || async {
            sqlx::query("DELETE FROM transfer_quota_usage WHERE period_start >= $1")
                .bind(period)
                .execute(&pool)
                .await
                .unwrap();
        };
        cleanup().await;

        let a = TransferMeter::new(pool.clone(), &settings);
        let b = TransferMeter::new(pool.clone(), &settings);
        *a.flushed.lock().await = Flushed { period, total: 0 };
        *b.flushed.lock().await = Flushed { period, total: 0 };

        a.record(600);
        assert_eq!(a.flush_at(now).await.unwrap(), 600);
        assert_eq!(b.used_bytes(), 0, "b has not read the shared total yet");
        b.record(300);
        assert_eq!(b.flush_at(now).await.unwrap(), 900);
        assert_eq!(
            a.flush_at(now).await.unwrap(),
            900,
            "a refreshes with nothing pending"
        );
        assert!(a.refusal_at(now).is_none());

        b.record(100);
        assert!(
            b.refusal_at(now).is_some(),
            "b counts its own unflushed bytes"
        );
        assert!(a.refusal_at(now).is_none(), "a has not seen them yet");
        b.flush_at(now).await.unwrap();
        a.flush_at(now).await.unwrap();
        assert!(a.refusal_at(now).is_some(), "after a flush both refuse");

        // The month turns: bytes counted before the turn go to the old
        // month, and the new one starts from zero.
        a.record(50);
        assert_eq!(a.flush_at(next).await.unwrap(), 0);
        assert!(a.refusal_at(next).is_none());
        let old: i64 =
            sqlx::query_scalar("SELECT bytes FROM transfer_quota_usage WHERE period_start = $1")
                .bind(period)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(old, 1050);

        cleanup().await;
    }
}
