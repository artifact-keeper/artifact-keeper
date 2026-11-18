//! Per-member circuit breaker for virtual-repository downloads (#5810).
//!
//! A Remote member of a virtual repository that keeps failing (it misses the
//! download deadline, refuses connections or answers `5xx`) costs every
//! download through the virtual one deadline before the next member is
//! served. After [`BREAKER_FAILURES_ENV`] consecutive failures the breaker
//! for that member opens: for [`BREAKER_OPEN_SECS_ENV`] seconds the walk
//! passes over the member without dialling it, as if it were unavailable.
//! Then one request is admitted as a probe (half-open): its success closes
//! the breaker, its failure opens it again for another period.
//!
//! The state is in memory, per member and per replica: each replica learns
//! on its own that a member is down. A permanent answer (`404`, `401`,
//! `403`, ...) is a success here, because the member answered.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Duration;

use tokio::time::Instant;
use uuid::Uuid;

use crate::error::AppError;
use crate::services::proxy_service::{
    classify_member_fetch_failure, upstream_error_status, MemberFetchFailure,
};

/// Consecutive failures that open a member's breaker. Default
/// [`DEFAULT_BREAKER_FAILURES`]; values below 1 are read as 1.
pub const BREAKER_FAILURES_ENV: &str = "AK_VIRTUAL_MEMBER_BREAKER_FAILURES";

/// Seconds an open breaker skips its member before admitting a probe.
/// Default [`DEFAULT_BREAKER_OPEN_SECS`]; `0` disables the breaker.
pub const BREAKER_OPEN_SECS_ENV: &str = "AK_VIRTUAL_MEMBER_BREAKER_OPEN_SECS";

/// Default for [`BREAKER_FAILURES_ENV`].
pub const DEFAULT_BREAKER_FAILURES: u32 = 3;

/// Default for [`BREAKER_OPEN_SECS_ENV`].
pub const DEFAULT_BREAKER_OPEN_SECS: u64 = 30;

/// Gauge set to `1` while a member's breaker is open and `0` once it closes.
pub const BREAKER_OPEN_GAUGE: &str = "ak_virtual_member_breaker_open";

/// Whether a member fetch error counts against the member's breaker: the
/// member could not answer because of its upstream (a `5xx`, a connect or
/// transport failure, a timeout). A permanent answer (`404`, `401`, `403`,
/// `451`, ...) and a request to slow down (`408`, `425`, `429`) do not: the
/// upstream answered. Nor does a fault on this server's side (database).
pub fn fetch_error_trips_breaker(err: &AppError) -> bool {
    if classify_member_fetch_failure(err) != MemberFetchFailure::Unavailable {
        return false;
    }
    if matches!(err, AppError::Database(_) | AppError::Sqlx(_)) {
        return false;
    }
    match upstream_error_status(err) {
        Some(status) => status.is_server_error(),
        None => true,
    }
}

#[derive(Debug, Default)]
struct MemberState {
    consecutive_failures: u32,
    /// Set while the breaker is open (or half-open, once the instant has
    /// passed).
    open_until: Option<Instant>,
    /// A half-open probe is in flight; other requests keep skipping.
    probing: bool,
}

/// Whether the walk may dial a member. Dropping a probe admission that was
/// never resolved (the request was cancelled, or a higher member won) frees
/// the probe slot for the next request.
#[must_use]
pub struct Admission<'a> {
    breaker: &'a MemberBreaker,
    member: Uuid,
    probe: bool,
}

impl Admission<'_> {
    /// Whether this request is the half-open probe.
    pub fn is_probe(&self) -> bool {
        self.probe
    }
}

impl Drop for Admission<'_> {
    fn drop(&mut self) {
        if !self.probe {
            return;
        }
        let mut members = self.breaker.lock();
        if let Some(state) = members.get_mut(&self.member) {
            state.probing = false;
        }
    }
}

/// The per-member breakers of one proxy service.
#[derive(Debug)]
pub struct MemberBreaker {
    failures: u32,
    /// `None`: disabled.
    open_for: Option<Duration>,
    members: Mutex<HashMap<Uuid, MemberState>>,
}

impl Default for MemberBreaker {
    fn default() -> Self {
        Self::new(
            DEFAULT_BREAKER_FAILURES,
            Duration::from_secs(DEFAULT_BREAKER_OPEN_SECS),
        )
    }
}

impl MemberBreaker {
    /// A breaker opening after `failures` consecutive failures for
    /// `open_for` (zero: disabled).
    pub fn new(failures: u32, open_for: Duration) -> Self {
        Self {
            failures: failures.max(1),
            open_for: (!open_for.is_zero()).then_some(open_for),
            members: Mutex::new(HashMap::new()),
        }
    }

    /// From [`BREAKER_FAILURES_ENV`] and [`BREAKER_OPEN_SECS_ENV`].
    pub fn from_env() -> Self {
        Self::from_values(
            std::env::var(BREAKER_FAILURES_ENV).ok().as_deref(),
            std::env::var(BREAKER_OPEN_SECS_ENV).ok().as_deref(),
        )
    }

    fn from_values(failures: Option<&str>, open_secs: Option<&str>) -> Self {
        let failures = failures
            .and_then(|v| v.trim().parse::<u32>().ok())
            .unwrap_or(DEFAULT_BREAKER_FAILURES);
        let open_secs = open_secs
            .and_then(|v| v.trim().parse::<u64>().ok())
            .unwrap_or(DEFAULT_BREAKER_OPEN_SECS);
        Self::new(failures, Duration::from_secs(open_secs))
    }

    /// Whether the breaker is enabled.
    pub fn is_enabled(&self) -> bool {
        self.open_for.is_some()
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<Uuid, MemberState>> {
        // The state is a few counters; a panic while holding the lock leaves
        // nothing worth refusing to read.
        self.members
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Admit a request to `member`, or `None` when its breaker is open (the
    /// walk passes over it without dialling). Once the open period has
    /// passed, exactly one request is admitted as the probe.
    pub fn admit(&self, member: Uuid) -> Option<Admission<'_>> {
        let closed = Admission {
            breaker: self,
            member,
            probe: false,
        };
        if !self.is_enabled() {
            return Some(closed);
        }
        let mut members = self.lock();
        let Some(state) = members.get_mut(&member) else {
            return Some(closed);
        };
        let Some(open_until) = state.open_until else {
            return Some(closed);
        };
        if Instant::now() < open_until || state.probing {
            return None;
        }
        state.probing = true;
        Some(Admission {
            breaker: self,
            member,
            probe: true,
        })
    }

    /// Record how `member` (key `member_key`, for the metric and the log)
    /// answered: `tripped` is a deadline miss, a connect error or a `5xx`;
    /// anything else (including a `404`) is a success and closes the
    /// breaker.
    pub fn record(&self, member: Uuid, member_key: &str, tripped: bool) {
        let Some(open_for) = self.open_for else {
            return;
        };
        let mut members = self.lock();
        if !tripped {
            if let Some(state) = members.remove(&member) {
                if state.open_until.is_some() {
                    metrics::gauge!(BREAKER_OPEN_GAUGE, "member" => member_key.to_string())
                        .set(0.0);
                    tracing::info!(
                        member = %member_key,
                        "virtual member answered again; its download breaker is closed"
                    );
                }
            }
            return;
        }
        let state = members.entry(member).or_default();
        state.consecutive_failures = state.consecutive_failures.saturating_add(1);
        let was_open = state.open_until.is_some();
        if was_open || state.consecutive_failures >= self.failures {
            state.open_until = Some(Instant::now() + open_for);
            state.probing = false;
            if !was_open {
                metrics::gauge!(BREAKER_OPEN_GAUGE, "member" => member_key.to_string()).set(1.0);
            }
            tracing::warn!(
                member = %member_key,
                consecutive_failures = state.consecutive_failures,
                open_secs = open_for.as_secs(),
                "virtual member keeps failing; downloads skip it without dialling until the \
                 breaker admits a probe ({BREAKER_FAILURES_ENV}, {BREAKER_OPEN_SECS_ENV})"
            );
        }
    }
}

#[cfg(ak_test_shard = "services-2")]
#[cfg(test)]
mod tests {
    use super::*;

    const OPEN: Duration = Duration::from_secs(30);

    fn trip(b: &MemberBreaker, id: Uuid, n: u32) {
        for _ in 0..n {
            let admitted = b.admit(id).expect("closed breaker admits");
            drop(admitted);
            b.record(id, "m", true);
        }
    }

    #[tokio::test(start_paused = true)]
    async fn opens_after_consecutive_failures_5810() {
        let b = MemberBreaker::new(3, OPEN);
        let id = Uuid::new_v4();
        trip(&b, id, 2);
        assert!(b.admit(id).is_some(), "still closed after 2 of 3");
        trip(&b, id, 1);
        assert!(b.admit(id).is_none(), "open after 3 consecutive failures");
    }

    #[tokio::test(start_paused = true)]
    async fn a_success_resets_the_count_5810() {
        let b = MemberBreaker::new(3, OPEN);
        let id = Uuid::new_v4();
        trip(&b, id, 2);
        b.record(id, "m", false);
        trip(&b, id, 2);
        assert!(
            b.admit(id).is_some(),
            "the count is of consecutive failures"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn half_open_admits_one_probe_and_recovers_5810() {
        let b = MemberBreaker::new(1, OPEN);
        let id = Uuid::new_v4();
        trip(&b, id, 1);
        assert!(b.admit(id).is_none());
        tokio::time::advance(OPEN).await;
        let probe = b.admit(id).expect("the open period passed: one probe");
        assert!(probe.is_probe());
        assert!(b.admit(id).is_none(), "only one probe at a time");
        b.record(id, "m", false);
        drop(probe);
        let next = b.admit(id).expect("the probe succeeded: closed");
        assert!(!next.is_probe());
    }

    #[tokio::test(start_paused = true)]
    async fn failed_probe_reopens_5810() {
        let b = MemberBreaker::new(3, OPEN);
        let id = Uuid::new_v4();
        trip(&b, id, 3);
        tokio::time::advance(OPEN).await;
        let probe = b.admit(id).expect("probe");
        b.record(id, "m", true);
        drop(probe);
        assert!(b.admit(id).is_none(), "one failed probe reopens it");
        tokio::time::advance(OPEN).await;
        assert!(b.admit(id).is_some_and(|a| a.is_probe()));
    }

    #[tokio::test(start_paused = true)]
    async fn an_abandoned_probe_frees_the_slot_5810() {
        let b = MemberBreaker::new(1, OPEN);
        let id = Uuid::new_v4();
        trip(&b, id, 1);
        tokio::time::advance(OPEN).await;
        drop(b.admit(id).expect("probe"));
        assert!(
            b.admit(id).is_some_and(|a| a.is_probe()),
            "a cancelled probe must not wedge the breaker open"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn zero_open_secs_disables_5810() {
        let b = MemberBreaker::from_values(Some("1"), Some("0"));
        assert!(!b.is_enabled());
        let id = Uuid::new_v4();
        trip(&b, id, 10);
        assert!(b.admit(id).is_some());
    }

    #[test]
    fn settings_5810() {
        let b = MemberBreaker::from_values(None, None);
        assert_eq!(b.failures, DEFAULT_BREAKER_FAILURES);
        assert_eq!(
            b.open_for,
            Some(Duration::from_secs(DEFAULT_BREAKER_OPEN_SECS))
        );
        let b = MemberBreaker::from_values(Some("0"), Some("junk"));
        assert_eq!(b.failures, 1, "a threshold of zero is read as one");
        assert_eq!(
            b.open_for,
            Some(Duration::from_secs(DEFAULT_BREAKER_OPEN_SECS))
        );
    }

    #[test]
    fn only_upstream_failures_trip_5810() {
        // The message shape `upstream_status_message` gives every upstream
        // status error: a 5xx is `ServiceUnavailable`, a 4xx `BadGateway`.
        let status = |code: u16| {
            let status = axum::http::StatusCode::from_u16(code).expect("status");
            let message = format!("Upstream returned error status {status}: http://upstream");
            if status.is_server_error() {
                AppError::ServiceUnavailable(message)
            } else {
                AppError::BadGateway(message)
            }
        };
        assert!(fetch_error_trips_breaker(&status(503)));
        assert!(fetch_error_trips_breaker(&status(500)));
        assert!(fetch_error_trips_breaker(&AppError::BadGateway(
            "connection refused".into()
        )));
        for code in [401u16, 403, 404, 410, 451, 429, 408] {
            assert!(!fetch_error_trips_breaker(&status(code)), "{code}");
        }
        assert!(!fetch_error_trips_breaker(&AppError::NotFound("x".into())));
        assert!(!fetch_error_trips_breaker(&AppError::Authorization(
            "x".into()
        )));
    }
}
