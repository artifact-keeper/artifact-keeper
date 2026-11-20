//! Digest-keyed proxy scan verdict store (#2954).
//!
//! Proxy-cached bytes are deliberately NOT written to `artifacts` (#1278/#1280),
//! so the `artifact_id`-keyed `scan_results` pipeline cannot hold a verdict for
//! a proxied object. This service persists a content-addressed
//! (`checksum_sha256`) verdict in `proxy_scan_results`, independent of
//! `artifacts`, so that:
//!
//!   * a repeat pull of a known-vulnerable digest is blocked WITHOUT re-fetching
//!     upstream or re-scanning (the fast path), and
//!   * a verdict is shared across repos/tenants pulling identical bytes (same
//!     bytes = same CVEs) and survives proxy-cache eviction.
//!
//! The freshness and fail-open/closed decision logic lives in pure functions so
//! it is unit-testable without a database.

use chrono::{DateTime, Duration, Utc};
use sqlx::PgPool;
use uuid::Uuid;

use crate::error::{AppError, Result};
use crate::models::security::Severity;

/// A persisted proxy scan verdict row.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct ProxyScanRow {
    pub checksum_sha256: String,
    pub scan_type: String,
    pub verdict: String,
    pub findings_count: i32,
    pub critical_count: i32,
    pub high_count: i32,
    pub medium_count: i32,
    pub low_count: i32,
    pub max_severity: Option<String>,
    pub scanner_version: Option<String>,
    pub scanned_at: DateTime<Utc>,
}

/// The three terminal verdicts stored in `proxy_scan_results.verdict`.
pub const VERDICT_CLEAN: &str = "clean";
pub const VERDICT_VULNERABLE: &str = "vulnerable";
pub const VERDICT_ERROR: &str = "error";

/// Whether a stored verdict means the artifact must be blocked when the repo's
/// scan policy blocks. Only a `vulnerable` verdict blocks; `clean` serves and
/// `error` is inconclusive (handled by the fail-open/closed decision, not here).
pub fn verdict_blocks(verdict: &str) -> bool {
    verdict == VERDICT_VULNERABLE
}

/// The severity policy a repo applies to a BLOCKING (`vulnerable`) verdict on
/// the inline proxy/OCI scan gate (#3243 stage 3 / #3246).
///
/// `scan_configs.block_on_policy_violation` (DEFAULT `false`, migration 022) is
/// the explicit per-repo opt-in that makes `scan_configs.severity_threshold`
/// enforced: when it is on, a finding at or above the threshold counts as a
/// policy violation and blocks the pull — exactly the behavior both fields have
/// always documented. When it is off (every repo that never touched it), the
/// gate keeps its historical block-on-any-finding posture, so wiring the column
/// changes nothing for a repository on defaults.
///
/// Fail-closed requirements (#3243):
/// * a `vulnerable` verdict whose stored `max_severity` is NULL or unparseable
///   (legacy rows) must still block even when a threshold is configured —
///   serve only when the severity is KNOWN and strictly below the threshold;
/// * an unparseable *configured* threshold falls back to block-on-any rather
///   than guessing a level.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProxySeverityGate {
    /// Historical posture (and the posture of every repo that has not opted
    /// in): ANY finding blocks, severity not consulted.
    BlockOnAny,
    /// Opted-in posture: findings at or above this severity block; a verdict
    /// whose highest severity is known and strictly below it serves.
    Threshold(Severity),
    /// Record-only posture (#3645, `proxy_scan_action = 'record_only'`): the
    /// verdict is scanned and recorded exactly as under enforcement, but no
    /// verdict ever blocks a pull. Only a repository that explicitly selects
    /// the record-only action resolves to this gate; it is the WEAKEST gate,
    /// so any enforcing side of a stricter-of-two combination wins.
    RecordOnly,
}

impl ProxySeverityGate {
    /// Derive the gate from a repo's `scan_configs` row. Absent row, opt-out,
    /// or an unparseable stored threshold all mean [`Self::BlockOnAny`].
    pub fn from_config(block_on_policy_violation: bool, severity_threshold: &str) -> Self {
        if !block_on_policy_violation {
            return Self::BlockOnAny;
        }
        match Severity::from_str_loose(severity_threshold) {
            Some(t) => Self::Threshold(t),
            // A configured-but-unparseable threshold must not weaken the gate.
            None => Self::BlockOnAny,
        }
    }

    /// Does a `vulnerable` verdict with this highest observed severity block?
    ///
    /// `None` (missing / unparseable stored `max_severity`) blocks under every
    /// gate: an ungraded vulnerable verdict is fail-closed, never fail-open.
    pub fn blocks(self, max_severity: Option<Severity>) -> bool {
        match self {
            Self::RecordOnly => false,
            Self::BlockOnAny => true,
            Self::Threshold(t) => match max_severity {
                None => true,
                Some(s) => s.meets_threshold(t),
            },
        }
    }

    /// The stricter of two gates, for Virtual repos (stricter-of-two over the
    /// virtual's own config and the member's, matching `stricter_scan_policy`).
    /// `BlockOnAny` dominates; between two thresholds the one that blocks MORE
    /// severities wins (`Severity` is ordered Critical=0 .. Info=4, and a
    /// threshold blocks everything at-or-above it, so the numerically larger
    /// variant is the stricter gate).
    /// `RecordOnly` is the weakest gate: it yields to anything that enforces.
    pub fn stricter(a: Self, b: Self) -> Self {
        match (a, b) {
            (Self::BlockOnAny, _) | (_, Self::BlockOnAny) => Self::BlockOnAny,
            (Self::RecordOnly, other) | (other, Self::RecordOnly) => other,
            (Self::Threshold(x), Self::Threshold(y)) => Self::Threshold(x.max(y)),
        }
    }

    /// True for the record-only gate (#3645): verdicts are recorded, never
    /// enforced.
    pub fn is_record_only(self) -> bool {
        matches!(self, Self::RecordOnly)
    }
}

/// Whether a cached verdict may be reused for a fresh pull.
///
/// A verdict is reusable while it is within the TTL window AND (when both the
/// stored and the live scanner version strings are known) the scanner version
/// matches. A CVE-DB bump changes the version string, so a `clean` verdict from
/// yesterday's DB is naturally ignored and the bytes are re-scanned against
/// today's CVEs. When either version string is unknown (probe failed / legacy
/// row) we fall back to the TTL alone rather than forcing an unbounded re-scan.
///
/// Verdicts the same scanner binary graded against another DB build are
/// covered only by [`verdict_is_reusable`] (#6300): an OLDER build within the
/// DB-update grace, a NEWER one while the fleet first saw it within the trust
/// window ([`DbUpdateGrace::trusts_newer`]).
pub fn verdict_is_fresh(
    scanned_at: DateTime<Utc>,
    stored_version: Option<&str>,
    current_version: Option<&str>,
    ttl_days: i64,
    now: DateTime<Utc>,
) -> bool {
    let within_ttl = now < scanned_at + Duration::days(ttl_days);
    let version_ok = match (stored_version, current_version) {
        (Some(a), Some(b)) => a == b,
        // Unknown on either side: cannot prove a mismatch, rely on TTL.
        _ => true,
    };
    within_ttl && version_ok
}

// ---------------------------------------------------------------------------
// Vulnerability-DB update grace (#6300)
// ---------------------------------------------------------------------------
//
// The stored provenance carries the DB build (`grype-0.120.1+db-2026-11-10`,
// #3287), so every DB update used to make every stored verdict stale at once:
// the next pull of each cached package re-scanned on the request path
// (fail_closed: the client waited, or got a 423) or queued a scan (fail_open),
// all in the same hour.
//
// Instead, for a bounded window after the fleet first saw a new DB build, a
// verdict the SAME scanner binary graded against the PREVIOUS build keeps
// deciding the pull, and the pull queues a re-grade of the cached bytes in the
// lowest scan band (`PRIORITY_REGRADE`), so the work follows what is pulled,
// runs on spare capacity, and never holds a client. The window depends on the
// repository's scan action: `PROXY_SCAN_DB_GRACE_HOURS` (default 6) for
// `fail_open` and `record_only`, which serve the pull either way, and
// `PROXY_SCAN_DB_GRACE_HOURS_FAIL_CLOSED` (default 0: off) for `fail_closed`,
// where the grace means a pull can be served clean from a verdict made before
// the new DB added an advisory, so the operator has to opt in. What holds:
//
// * a `vulnerable` verdict keeps blocking;
// * nothing unscanned is served, and an unknown version on either side gets
//   no grace (#2976's fail-closed rule is untouched);
// * a scanner binary upgrade, or a verdict older than the newest build this
//   fleet recorded below the live one, is re-scanned exactly as before;
// * the window is anchored on the fleet-wide first sighting
//   (`proxy_scan_db_versions`), so neither a restart nor a new replica
//   reopens it. Past it, a digest whose re-grade is still queued keeps the
//   grace for at most one more window (no cliff of inline re-scans for work
//   already queued); anything else behaves exactly as before.
//
// Process-wide state: the record below, `LAST_GRACE_FAILURE` and the windows
// are statics, read on the hot path without a database query. Tests that set
// them (`set_db_grace_for_test`) rely on nextest running each test in its own
// process (.config/nextest.toml; CLAUDE.md "Use cargo nextest"), and the pure
// `*_under` functions take the grace as an argument for everything else.

/// Env var: hours a verdict graded against the previous vulnerability-DB
/// build keeps deciding pulls on a `fail_open` or `record_only` repository
/// after the fleet first saw a new build (#6300). `0` turns that grace off.
/// Blank or unparsable keeps the default; more than [`MAX_DB_GRACE_HOURS`] is
/// clamped to it, with a warning.
pub const DB_GRACE_ENV: &str = "PROXY_SCAN_DB_GRACE_HOURS";

/// Default for [`DB_GRACE_ENV`].
pub const DEFAULT_DB_GRACE_HOURS: i64 = 6;

/// Ceiling for [`DB_GRACE_ENV`]: three days covers a weekend's DB imports on
/// an air-gapped install without letting a verdict outlive several builds.
pub const MAX_DB_GRACE_HOURS: i64 = 72;

/// Env var: the same grace for a `fail_closed` repository. Off (`0`) unless
/// the operator opts in: within it a pull can be served clean from a verdict
/// made before the new DB added an advisory.
pub const DB_GRACE_FAIL_CLOSED_ENV: &str = "PROXY_SCAN_DB_GRACE_HOURS_FAIL_CLOSED";

/// Default for [`DB_GRACE_FAIL_CLOSED_ENV`]: off.
pub const DEFAULT_DB_GRACE_FAIL_CLOSED_HOURS: i64 = 0;

/// Ceiling for [`DB_GRACE_FAIL_CLOSED_ENV`].
pub const MAX_DB_GRACE_FAIL_CLOSED_HOURS: i64 = 24;

/// Parse one grace setting: whole hours, `0` off, clamped to `max`.
pub fn parse_db_grace_hours(name: &str, raw: Option<&str>, default: i64, max: i64) -> Duration {
    let hours = match raw.map(str::trim).filter(|v| !v.is_empty()) {
        None => default,
        Some(v) => match v.parse::<i64>() {
            Ok(h) if h > max => {
                tracing::warn!(
                    value = %v,
                    "{name} is above its ceiling of {max} hours; using {max}"
                );
                max
            }
            Ok(h) if h >= 0 => h,
            _ => {
                tracing::warn!(
                    value = %v,
                    "{name} is not a whole number of hours; using the default of {default}"
                );
                default
            }
        },
    };
    Duration::hours(hours)
}

/// The two grace windows (#6300).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DbGraceWindows {
    /// `fail_open` and `record_only` ([`DB_GRACE_ENV`]).
    pub serving: Duration,
    /// `fail_closed` ([`DB_GRACE_FAIL_CLOSED_ENV`]).
    pub fail_closed: Duration,
}

impl DbGraceWindows {
    pub fn from_env(get: impl Fn(&str) -> Option<String>) -> Self {
        Self {
            serving: parse_db_grace_hours(
                DB_GRACE_ENV,
                get(DB_GRACE_ENV).as_deref(),
                DEFAULT_DB_GRACE_HOURS,
                MAX_DB_GRACE_HOURS,
            ),
            fail_closed: parse_db_grace_hours(
                DB_GRACE_FAIL_CLOSED_ENV,
                get(DB_GRACE_FAIL_CLOSED_ENV).as_deref(),
                DEFAULT_DB_GRACE_FAIL_CLOSED_HOURS,
                MAX_DB_GRACE_FAIL_CLOSED_HOURS,
            ),
        }
    }

    pub fn for_action(&self, action: ProxyScanAction) -> Duration {
        if action.is_fail_closed() {
            self.fail_closed
        } else {
            self.serving
        }
    }

    /// How far back the newer builds are read at load: the longer of the two
    /// windows. Each pull then bounds the trust by its own action's window
    /// ([`DbUpdateGrace::trusts_newer`]).
    pub fn newer_build_trust(&self) -> Duration {
        self.serving.max(self.fail_closed)
    }

    /// Whether either window is open at all.
    pub fn any(&self) -> bool {
        self.serving > Duration::zero() || self.fail_closed > Duration::zero()
    }
}

/// Publish `ak_proxy_scan_db_grace_window_seconds` (both classes, `0` when
/// off). Called at startup, after the metrics recorder is installed, so the
/// gauges exist whether or not a CVE scanner is configured.
pub fn publish_db_grace_window_gauges() {
    let windows = db_grace_windows();
    crate::services::metrics_service::record_proxy_scan_db_grace_window(
        windows.serving.num_seconds() as f64,
        windows.fail_closed.num_seconds() as f64,
    );
}

/// The windows this process applies, read once.
pub fn db_grace_windows() -> DbGraceWindows {
    static WINDOWS: std::sync::OnceLock<DbGraceWindows> = std::sync::OnceLock::new();
    *WINDOWS.get_or_init(|| DbGraceWindows::from_env(|k| std::env::var(k).ok()))
}

/// A scanner version token split into the scanner binary and its DB build:
/// `grype-0.120.1+db-2026-11-10` is `("grype-0.120.1", Some("2026-11-10"))`.
pub fn split_scanner_version(version: &str) -> (&str, Option<&str>) {
    match version.split_once("+db-") {
        Some((cli, db)) if !cli.is_empty() && !db.is_empty() => (cli, Some(db)),
        _ => (version, None),
    }
}

/// Whether a DB build token is the `YYYY-MM-DD` shape `db_build_date_token`
/// produces, so that two of them order as dates when compared as strings.
fn is_build_date(token: &str) -> bool {
    let b = token.as_bytes();
    b.len() == 10
        && b.iter().enumerate().all(|(i, c)| match i {
            4 | 7 => *c == b'-',
            _ => c.is_ascii_digit(),
        })
}

/// How a stored verdict's provenance relates to another version token.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DbProvenance {
    /// The same token.
    Same,
    /// The same scanner binary, an older DB build.
    OlderDb,
    /// The same scanner binary, a newer DB build.
    NewerDb,
    /// Another binary, a token without a DB build on either side, or a build
    /// that is not a `YYYY-MM-DD` date.
    Different,
}

/// Compare `stored` with `other`. DB builds are `YYYY-MM-DD` tokens
/// (`db_build_date_token`), so they order as strings; any other shape cannot
/// be ordered and is [`DbProvenance::Different`].
pub fn compare_provenance(stored: &str, other: &str) -> DbProvenance {
    if stored == other {
        return DbProvenance::Same;
    }
    match (split_scanner_version(stored), split_scanner_version(other)) {
        ((a, Some(da)), (b, Some(db))) if a == b && is_build_date(da) && is_build_date(db) => {
            match da.cmp(db) {
                std::cmp::Ordering::Less => DbProvenance::OlderDb,
                std::cmp::Ordering::Greater => DbProvenance::NewerDb,
                std::cmp::Ordering::Equal => DbProvenance::Same,
            }
        }
        _ => DbProvenance::Different,
    }
}

/// One action class's window, on this replica's clock.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GraceWindow {
    /// The grace ends here.
    pub until: DateTime<Utc>,
    /// A digest whose re-grade is still queued keeps the grace up to here:
    /// one more window, so the backlog drains without a cliff of inline
    /// re-scans and is still bounded if nothing drains it.
    pub queued_until: DateTime<Utc>,
}

impl GraceWindow {
    /// `age` is how long ago the fleet first saw the build, measured on the
    /// database clock; `now` is this replica's.
    pub fn new(now: DateTime<Utc>, age: Duration, window: Duration) -> Option<Self> {
        if window <= Duration::zero() {
            return None;
        }
        let until = now - age + window;
        Some(Self {
            until,
            queued_until: until + window,
        })
    }
}

/// What the fleet recorded about the live CVE-scanner version's arrival
/// (`proxy_scan_db_versions`): the newest same-binary build recorded below it,
/// and the window per action class.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DbUpdateGrace {
    pub live: String,
    pub previous: Option<String>,
    pub serving: Option<GraceWindow>,
    pub fail_closed: Option<GraceWindow>,
    /// Same-binary builds NEWER than the live one, and when the fleet first
    /// saw each (on this replica's clock). A verdict one of them graded is
    /// reused for a pull for that pull's action window after the sighting
    /// ([`Self::trusts_newer`]), so `fail_closed` at `0` never trusts one,
    /// and a newer build the operator rolled back (it graded something
    /// wrongly) stops being trusted instead of standing for the whole TTL.
    pub newer: Vec<(String, DateTime<Utc>)>,
}

impl DbUpdateGrace {
    fn window(&self, action: ProxyScanAction) -> Option<&GraceWindow> {
        if action.is_fail_closed() {
            self.fail_closed.as_ref()
        } else {
            self.serving.as_ref()
        }
    }

    /// Whether `stored` is the build this grace covers: the same binary as
    /// `live`, older than it, and no older than the newest build recorded
    /// below it. The window is not consulted.
    pub fn covers_build(&self, stored: &str, live: &str) -> bool {
        self.live == live
            && compare_provenance(stored, live) == DbProvenance::OlderDb
            && self.previous.as_deref().is_some_and(|p| {
                matches!(
                    compare_provenance(stored, p),
                    DbProvenance::Same | DbProvenance::NewerDb
                )
            })
    }

    /// Whether a verdict graded at `stored`, a NEWER build than `live`, is
    /// still trusted for a pull under `action` at `now`: first seen within
    /// that action's window (see [`Self::newer`]). No window for the action,
    /// no trust: the pull re-scans exactly as before 1.13.0.
    pub fn trusts_newer(
        &self,
        stored: &str,
        live: &str,
        action: ProxyScanAction,
        now: DateTime<Utc>,
    ) -> bool {
        let Some(w) = self.window(action) else {
            return false;
        };
        let length = w.queued_until - w.until;
        self.live == live
            && compare_provenance(stored, live) == DbProvenance::NewerDb
            && self
                .newer
                .iter()
                .any(|(build, seen)| build == stored && now < *seen + length)
    }

    /// Whether a verdict graded at `stored` may decide a pull under `action`
    /// while `live` is the live version: a trusted newer build
    /// ([`Self::trusts_newer`], within the action's window), or [`Self::covers_build`] within
    /// the action's window, or, with `regrade_queued`, within its extension.
    pub fn vouches_for(
        &self,
        stored: &str,
        live: &str,
        action: ProxyScanAction,
        now: DateTime<Utc>,
        regrade_queued: bool,
    ) -> bool {
        if self.trusts_newer(stored, live, action, now) {
            return true;
        }
        self.covers_build(stored, live)
            && self
                .window(action)
                .is_some_and(|w| now < w.until || (regrade_queued && now < w.queued_until))
    }

    /// Whether only a queued re-grade could still let `stored` decide a pull:
    /// covered build, past the window, inside its extension. The caller then
    /// asks whether a re-grade of the digest is queued.
    pub fn only_a_queued_regrade_vouches(
        &self,
        stored: &str,
        live: &str,
        action: ProxyScanAction,
        now: DateTime<Utc>,
    ) -> bool {
        self.covers_build(stored, live)
            && self
                .window(action)
                .is_some_and(|w| now >= w.until && now < w.queued_until)
    }
}

/// Whether only a queued re-grade could still let a verdict graded at
/// `stored` decide a pull under `action` (#6300): the caller then asks whether
/// one is queued and, if so, decides with
/// [`decide_serve_with_queued_regrade`]. A map read, no query.
pub fn grace_extension_possible(
    stored: Option<&str>,
    live: Option<&str>,
    action: ProxyScanAction,
    now: DateTime<Utc>,
) -> bool {
    let (Some(stored), Some(live)) = (stored, live) else {
        return false;
    };
    with_live_db_grace(Some(live), |grace| {
        grace.is_some_and(|g| g.only_a_queued_regrade_vouches(stored, live, action, now))
    })
}

/// Whether a reused verdict graded at `stored` was reused only under the DB
/// grace, so the pull should queue a re-grade (#6300).
pub fn verdict_needs_regrade(stored: Option<&str>, live: Option<&str>) -> bool {
    matches!(
        (stored, live),
        (Some(s), Some(l)) if compare_provenance(s, l) == DbProvenance::OlderDb
    )
}

type GraceRecord =
    std::sync::RwLock<std::collections::HashMap<String, (DbUpdateGrace, std::time::Instant)>>;

/// This process's grace per live version (see the section comment on
/// process-wide state).
fn grace_record() -> &'static GraceRecord {
    static RECORD: std::sync::OnceLock<GraceRecord> = std::sync::OnceLock::new();
    RECORD.get_or_init(Default::default)
}

/// Run `f` with this process's grace for `live`, `None` when there is none.
pub fn with_live_db_grace<R>(live: Option<&str>, f: impl FnOnce(Option<&DbUpdateGrace>) -> R) -> R {
    let Some(live) = live else { return f(None) };
    match grace_record().read() {
        Ok(record) => f(record.get(live).map(|(g, _)| g)),
        Err(_) => f(None),
    }
}

/// Put `grace` in this process's record, as [`observe_live_scanner_version`]
/// would after reading it from the database. Process-wide: only for tests
/// that run in their own process, as nextest runs every test.
#[cfg(test)]
pub(crate) fn set_db_grace_for_test(grace: DbUpdateGrace) {
    grace_record()
        .write()
        .expect("grace record")
        .insert(grace.live.clone(), (grace, std::time::Instant::now()));
}

/// Last failed attempt to record a live version, so a database outage costs
/// one query a minute rather than one per pull. Process-wide, like the record.
static LAST_GRACE_FAILURE: std::sync::Mutex<Option<std::time::Instant>> =
    std::sync::Mutex::new(None);

const GRACE_RETRY_AFTER: std::time::Duration = std::time::Duration::from_secs(60);

/// How long a loaded grace record is used before it is read again.
const GRACE_RELOAD_AFTER: std::time::Duration = std::time::Duration::from_secs(60);

/// Record that this process sees `live` as the CVE-scanner version, and load
/// its grace (#6300). Once per version per process; every call after that is
/// a map read. Nothing is recorded with both windows off, for a token without
/// a DB build, or when the database cannot be read (then there is no grace,
/// which is the behaviour before it existed).
pub async fn observe_live_scanner_version(db: &PgPool, live: &str) {
    let windows = db_grace_windows();
    if !windows.any() || split_scanner_version(live).1.is_none() {
        return;
    }
    // Reloaded every minute: a newer build another replica records later
    // has to be learned, and one past its trust window dropped.
    if grace_record()
        .read()
        .map(|r| {
            r.get(live)
                .is_some_and(|(_, loaded)| loaded.elapsed() < GRACE_RELOAD_AFTER)
        })
        .unwrap_or(true)
    {
        return;
    }
    if let Ok(last) = LAST_GRACE_FAILURE.lock() {
        if last.is_some_and(|at| at.elapsed() < GRACE_RETRY_AFTER) {
            return;
        }
    }
    // One load at a time per process; a pull meanwhile uses what is there.
    static LOADING: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
    if LOADING.swap(true, std::sync::atomic::Ordering::AcqRel) {
        return;
    }
    struct Loading;
    impl Drop for Loading {
        fn drop(&mut self) {
            LOADING.store(false, std::sync::atomic::Ordering::Release);
        }
    }
    let _loading = Loading;
    match load_db_update_grace(db, live, windows).await {
        Ok(record) => {
            let changed = with_live_db_grace(Some(live), |old| {
                old.is_none_or(|o| {
                    let builds = |g: &DbUpdateGrace| {
                        g.newer
                            .iter()
                            .map(|(b, _)| b.clone())
                            .collect::<std::collections::BTreeSet<_>>()
                    };
                    o.previous != record.previous || builds(o) != builds(&record)
                })
            });
            if changed {
                tracing::info!(
                    live = %record.live, previous = ?record.previous,
                    serving_until = ?record.serving.map(|w| w.until),
                    fail_closed_until = ?record.fail_closed.map(|w| w.until),
                    trusted_newer = ?record.newer,
                    "vulnerability-DB update grace for proxy scan verdicts (#6300)"
                );
            }
            if let Ok(mut map) = grace_record().write() {
                // A handful of versions over a process's life; never let it grow.
                if map.len() >= 16 {
                    map.clear();
                }
                map.insert(live.to_string(), (record, std::time::Instant::now()));
            }
        }
        Err(e) => {
            tracing::warn!(
                live = %live, error = %e,
                "could not record the live CVE-scanner version; no DB-update grace \
                 until it is (verdicts from the previous DB build are re-scanned)"
            );
            if let Ok(mut last) = LAST_GRACE_FAILURE.lock() {
                *last = Some(std::time::Instant::now());
            }
        }
    }
}

/// Insert `live` into `proxy_scan_db_versions` if new, and read back how long
/// ago the fleet first saw it (on the database clock, so replica clock skew
/// does not move the window) and the newest same-binary build below it. The
/// previous build is chosen by build date, not by when it was recorded: a
/// replica with an older DB recorded late (a pinned or rolled-back DB, an
/// air-gapped import, a new pod on an old bundled DB) must not become the
/// previous build and widen the grace to every build up to the live one.
/// Runtime queries (no macro) so this adds no offline sqlx data.
pub async fn load_db_update_grace(
    db: &PgPool,
    live: &str,
    windows: DbGraceWindows,
) -> Result<DbUpdateGrace> {
    let db_err = |e: sqlx::Error| AppError::Database(e.to_string());
    // The no-op update makes RETURNING hand back the existing row's time.
    let age_secs: f64 = sqlx::query_scalar(
        "INSERT INTO proxy_scan_db_versions (scanner_version) VALUES ($1) \
         ON CONFLICT (scanner_version) DO UPDATE SET scanner_version = EXCLUDED.scanner_version \
         RETURNING EXTRACT(EPOCH FROM (now() - first_seen_at))::float8",
    )
    .bind(live)
    .fetch_one(db)
    .await
    .map_err(db_err)?;
    let cli = split_scanner_version(live).0;
    let below: Vec<String> = sqlx::query_scalar(
        "SELECT scanner_version FROM proxy_scan_db_versions \
         WHERE starts_with(scanner_version, $1 || '+db-') AND scanner_version < $2 \
         ORDER BY scanner_version DESC LIMIT 32",
    )
    .bind(cli)
    .bind(live)
    .fetch_all(db)
    .await
    .map_err(db_err)?;
    // String order is date order only for well-formed builds.
    let previous = below
        .into_iter()
        .find(|v| compare_provenance(v, live) == DbProvenance::OlderDb);
    let now = Utc::now();
    let since = |secs: f64| Duration::milliseconds((secs.max(0.0) * 1000.0) as i64);
    let trust = windows.newer_build_trust();
    let above: Vec<(String, f64)> = sqlx::query_as(
        "SELECT scanner_version, EXTRACT(EPOCH FROM (now() - first_seen_at))::float8 \
         FROM proxy_scan_db_versions \
         WHERE starts_with(scanner_version, $1 || '+db-') AND scanner_version > $2 \
           AND first_seen_at > now() - make_interval(secs => $3) \
         ORDER BY scanner_version DESC LIMIT 32",
    )
    .bind(cli)
    .bind(live)
    .bind(trust.num_seconds() as f64)
    .fetch_all(db)
    .await
    .map_err(db_err)?;
    let newer = above
        .into_iter()
        .filter(|(v, _)| compare_provenance(v, live) == DbProvenance::NewerDb)
        .map(|(v, secs)| (v, now - since(secs)))
        .collect();
    let age = since(age_secs);
    Ok(DbUpdateGrace {
        live: live.to_string(),
        previous,
        serving: GraceWindow::new(now, age, windows.serving),
        fail_closed: GraceWindow::new(now, age, windows.fail_closed),
        newer,
    })
}

/// Per-repo action for the inline proxy scan on a first pull of an unknown
/// digest (reuses the `block_unscanned` semantics).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProxyScanAction {
    /// Latency-first (default): serve the first pull immediately and scan
    /// asynchronously; the NEXT pull of that digest is blocked if vulnerable.
    /// Must be loud (warn + audit + `X-AK-Scan: pending`).
    FailOpen,
    /// Never serve unscanned bytes: scan inline before serving; a vulnerable
    /// verdict is a 403, and an over-cap / budget-exceeded / scan-error object
    /// returns 423 rather than a 200 of unscanned bytes.
    FailClosed,
    /// Record-only (#3645): scan and record exactly as fail-open does (serve
    /// the first pull with `X-AK-Scan: pending`, scan asynchronously), but
    /// never withhold a pull: a vulnerable verdict is served with
    /// `X-AK-Scan: recorded`, and an over-cap / inconclusive scan serves
    /// pending. Visibility without enforcement.
    RecordOnly,
}

impl ProxyScanAction {
    /// Map the `scan_configs.proxy_scan_action` column onto the enum. Unknown /
    /// legacy values default to the safe-for-availability fail-open behavior,
    /// matching the column default.
    pub fn from_db(value: &str) -> Self {
        match value {
            "fail_closed" => ProxyScanAction::FailClosed,
            "record_only" => ProxyScanAction::RecordOnly,
            _ => ProxyScanAction::FailOpen,
        }
    }

    /// The `scan_configs.proxy_scan_action` token for this action.
    pub fn as_db_str(self) -> &'static str {
        match self {
            ProxyScanAction::FailOpen => "fail_open",
            ProxyScanAction::FailClosed => "fail_closed",
            ProxyScanAction::RecordOnly => "record_only",
        }
    }

    pub fn is_fail_closed(self) -> bool {
        matches!(self, ProxyScanAction::FailClosed)
    }

    pub fn is_record_only(self) -> bool {
        matches!(self, ProxyScanAction::RecordOnly)
    }
}

/// Whether a cached verdict may SHORT-CIRCUIT the serve path for this repo's
/// scan action — the policy-aware gate the serve path actually asks.
///
/// [`verdict_is_fresh`] answers the narrower, policy-free question "can we
/// prove this verdict is stale?", and deliberately fails OPEN when a version
/// string is unknown on either side (probe failed / legacy row): it cannot
/// prove a mismatch, so it relies on the TTL. That default is right for
/// fail-open, but on a `fail_closed` repo it is a hole: the freshness check
/// runs BEFORE the inline scan, so an unprovable `clean` verdict short-circuits
/// the whole fail-closed gate (including the #2954 "the CVE engine actually
/// ran" condition) and serves cached-clean bytes that nothing on this node can
/// currently vouch for.
///
/// That unknown-version window is common exactly when it matters most: a Grype
/// UPGRADE — the CVE-DB advance #2976 is about — transiently fails
/// `grype --version` (a >=60s [`VERSION_CACHE_MISS_TTL`] window), a missing
/// binary makes it permanent, and a loaded host can push the probe past its
/// 5s timeout. A node that 423s a FRESH pull (provably fail-closed) must not
/// serve a stale `clean` digest through the same policy.
///
/// So under `fail_closed` a CLEAN verdict is reusable only when its provenance
/// is PROVEN current — both version strings known and equal. Otherwise the
/// verdict is treated as stale and the caller falls through to the re-scan
/// branch, whose inconclusive outcome correctly fail-closes (423). This
/// self-heals: the re-scan records the live version, so the next pull of that
/// digest hits the cache normally.
///
/// Everything else is unchanged: `fail_open` keeps the TTL-only fallback (its
/// re-scan branch serves-with-pending anyway, so availability is unaffected),
/// and non-`clean` verdicts keep their existing handling — a cached
/// `vulnerable` verdict still blocks via [`verdict_blocks`].
///
/// [`VERSION_CACHE_MISS_TTL`]: crate::services::scanner_service
pub fn verdict_is_reusable(
    verdict: &str,
    scanned_at: DateTime<Utc>,
    stored_version: Option<&str>,
    current_version: Option<&str>,
    action: ProxyScanAction,
    ttl_days: i64,
    now: DateTime<Utc>,
) -> bool {
    with_live_db_grace(current_version, |grace| {
        verdict_is_reusable_under(
            verdict,
            scanned_at,
            stored_version,
            current_version,
            action,
            ttl_days,
            now,
            grace,
            false,
        )
    })
}

/// [`verdict_is_reusable`] with the live version's DB-update grace passed in,
/// and whether a re-grade of the digest is known to be queued (#6300): a
/// verdict from the build the grace covers is reusable within the action's
/// window, or within its extension while the re-grade is queued.
#[allow(clippy::too_many_arguments)]
pub fn verdict_is_reusable_under(
    verdict: &str,
    scanned_at: DateTime<Utc>,
    stored_version: Option<&str>,
    current_version: Option<&str>,
    action: ProxyScanAction,
    ttl_days: i64,
    now: DateTime<Utc>,
    grace: Option<&DbUpdateGrace>,
    regrade_queued: bool,
) -> bool {
    let fresh = verdict_is_fresh(scanned_at, stored_version, current_version, ttl_days, now)
        || (now < scanned_at + Duration::days(ttl_days)
            && match (stored_version, current_version, grace) {
                (Some(s), Some(l), Some(g)) => g.vouches_for(s, l, action, now, regrade_queued),
                _ => false,
            });
    if !fresh {
        return false;
    }
    if action.is_fail_closed() && verdict == VERDICT_CLEAN {
        // Fail-closed: "not provably stale" is not good enough for a clean
        // verdict; require provably-current provenance.
        return matches!((stored_version, current_version), (Some(_), Some(_)));
    }
    true
}

/// Outcome when the inline scan could NOT produce a conclusive clean/vulnerable
/// verdict before serve time: the object was over the byte cap, the inline scan
/// budget was exceeded, or the scanner errored.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InconclusiveOutcome {
    /// Serve now with `X-AK-Scan: pending` + warn + audit; scan asynchronously.
    ServePending,
    /// 423 Locked, never a 200 of unscanned bytes.
    Locked,
}

/// Pure decision for the inconclusive branch (over-cap / budget / scan error):
/// fail-open serves-with-pending, fail-closed locks. Record-only (#3645)
/// never withholds, so it serves pending like fail-open.
pub fn decide_inconclusive(action: ProxyScanAction) -> InconclusiveOutcome {
    match action {
        ProxyScanAction::FailOpen | ProxyScanAction::RecordOnly => {
            InconclusiveOutcome::ServePending
        }
        ProxyScanAction::FailClosed => InconclusiveOutcome::Locked,
    }
}

/// What the proxy serve path must do for one pull, given the stored verdict
/// row (if any), the LIVE CVE-scanner version, and the repo's scan action.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServeDecision {
    /// Fresh reusable clean verdict: serve the buffered bytes (`X-AK-Scan:
    /// clean`), no re-scan.
    ServeCached,
    /// Fresh reusable vulnerable verdict: block (403) without re-scanning.
    BlockCached,
    /// Fail-closed with no reusable verdict: scan inline before serving a
    /// single byte; the scan outcome then serves / blocks / 423s.
    ScanInline,
    /// Fail-open with no reusable verdict: serve now (`X-AK-Scan: pending`)
    /// and scan asynchronously so the NEXT pull of this digest is gated.
    ServePendingScanAsync,
}

/// The freshness + fail-open/closed serve state machine, single-sourced for
/// every proxy format (PyPI wheels, npm tarballs, OCI manifests). Lifted from
/// the PyPI serve path so per-format handlers cannot re-implement — and
/// silently drift on — the two carried defenses:
///
/// * #2976: an UNKNOWN live CVE-scanner version (`current_version = None`)
///   under `fail_closed` must NOT reuse a cached `clean` verdict — the pull
///   falls through to the re-scan branch ([`verdict_is_reusable`]).
/// * #2954: the re-scan branch under `fail_closed` is [`ServeDecision::
///   ScanInline`], whose inconclusive outcome the caller fail-closes (423)
///   rather than serving unscanned bytes.
///
/// Pure over the row + versions + clock (the one `warn!` is observability,
/// not behavior), so the regression cases are unit-testable without a DB or a
/// live scanner.
pub fn decide_serve(
    row: Option<&ProxyScanRow>,
    current_version: Option<&str>,
    action: ProxyScanAction,
    ttl_days: i64,
    now: DateTime<Utc>,
) -> ServeDecision {
    decide_serve_with_queued_regrade(row, current_version, action, ttl_days, now, false)
}

/// [`decide_serve`] for a digest whose re-grade is known to be queued
/// (`regrade_queued`), which keeps a verdict the DB-update grace covers
/// reusable past the window, up to its extension (#6300).
pub fn decide_serve_with_queued_regrade(
    row: Option<&ProxyScanRow>,
    current_version: Option<&str>,
    action: ProxyScanAction,
    ttl_days: i64,
    now: DateTime<Utc>,
    regrade_queued: bool,
) -> ServeDecision {
    if let Some(row) = row {
        let reusable = with_live_db_grace(current_version, |grace| {
            verdict_is_reusable_under(
                &row.verdict,
                row.scanned_at,
                row.scanner_version.as_deref(),
                current_version,
                action,
                ttl_days,
                now,
                grace,
                regrade_queued,
            )
        });
        if !reusable && current_version.is_none() && action.is_fail_closed() {
            tracing::warn!(
                stored_version = ?row.scanner_version,
                "live CVE-scanner version unknown; not reusing the cached verdict \
                 on a fail-closed repo (re-scanning)"
            );
        }
        if reusable {
            return if verdict_blocks(&row.verdict) {
                ServeDecision::BlockCached
            } else {
                ServeDecision::ServeCached
            };
        }
    }
    if action.is_fail_closed() {
        ServeDecision::ScanInline
    } else {
        ServeDecision::ServePendingScanAsync
    }
}

/// A stored verdict as the proxy-cache fast paths read it (#4514): the row,
/// the coordinate it was graded as (`pin_identity`, #4952) and how many
/// components it was graded on (`components_cataloged`).
#[derive(Debug, Clone)]
pub struct StoredProxyVerdict {
    pub row: ProxyScanRow,
    pub pin_identity: Option<String>,
    pub components_cataloged: Option<i32>,
}

/// Whether a stored verdict graded nothing: `clean` with no findings,
/// recorded with no pin and with no component cataloged. Under `fail_closed`
/// such a verdict is not reused (part of #3396).
pub fn clean_verdict_graded_nothing(
    row: &ProxyScanRow,
    stored_pin: Option<&str>,
    components_cataloged: Option<i32>,
) -> bool {
    row.verdict == VERDICT_CLEAN
        && row.findings_count == 0
        && components_cataloged.unwrap_or(0) <= 0
        && stored_pin.is_none()
}

/// What a presigned redirect to a cached package may do with a cached body of
/// a Remote that scans on proxy (#4514), given the stored verdict for the
/// body's SHA-256.
///
/// A redirect cannot scan: it hands out a cached object without buffering
/// it. So they only consult the stored verdict, by the same rules the
/// buffered gate ([`decide_serve`]) applies before it would scan.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CacheScanGate {
    /// Nothing stored refuses these bytes: serve them.
    Serve,
    /// A reusable `vulnerable` verdict that the repository's severity gate
    /// blocks: refuse with the scan block (`403`).
    Block,
    /// `fail_closed` and no reusable verdict that lets the bytes through: not
    /// for a fast path. The redirect declines, and the request is served by
    /// a path that reads the body itself.
    NotForFastPath,
}

/// The pure decision behind [`CacheScanGate`] (#4514).
///
/// * Record-only never refuses.
/// * A reusable `vulnerable` verdict refuses when the severity gate blocks
///   it, and is served when it is below an opted-in threshold, exactly as in
///   [`decide_serve`]'s `BlockCached` arm.
/// * Under `fail_closed`, only a reusable `clean` verdict that graded
///   something (see [`clean_verdict_graded_nothing`]) AND was graded as a
///   coordinate the bytes carry themselves is good enough. The buffered gate
///   reuses a verdict only when it pertains to the coordinate the request
///   names (#4952); a fast path has no request coordinate, so a verdict
///   graded as a request-pinned coordinate (Go, Composer, Conan, Debian, RPM,
///   Alpine) or graded without a pin is not reused there. Anything else, no
///   verdict included, is [`CacheScanGate::NotForFastPath`].
/// * Under `fail_open`, everything else is served, as the buffered gate
///   serves it `pending`.
///
/// `current_version` is the live CVE-scanner version, `None` when unknown:
/// as in [`verdict_is_reusable`], a clean verdict is then not reusable under
/// `fail_closed`. A clean verdict reusable only under the vulnerability-DB
/// update grace (#6300) is [`CacheScanGate::NotForFastPath`] under
/// `fail_closed`, so the pull reaches the gate that re-grades it.
pub fn decide_cache_scan_gate(
    stored: Option<&StoredProxyVerdict>,
    current_version: Option<&str>,
    action: ProxyScanAction,
    severity_gate: ProxySeverityGate,
    ttl_days: i64,
    now: DateTime<Utc>,
) -> CacheScanGate {
    if action.is_record_only() || severity_gate.is_record_only() {
        return CacheScanGate::Serve;
    }
    let reusable = stored.filter(|s| {
        verdict_is_reusable(
            &s.row.verdict,
            s.row.scanned_at,
            s.row.scanner_version.as_deref(),
            current_version,
            action,
            ttl_days,
            now,
        )
    });
    if let Some(s) = reusable {
        if verdict_blocks(&s.row.verdict) {
            let max_severity = s
                .row
                .max_severity
                .as_deref()
                .and_then(Severity::from_str_loose);
            return if severity_gate.blocks(max_severity) {
                CacheScanGate::Block
            } else {
                CacheScanGate::Serve
            };
        }
    }
    if !action.is_fail_closed() {
        return CacheScanGate::Serve;
    }
    let pinned_by_the_bytes = |pin: Option<&str>| {
        pin.is_some_and(|pin| {
            !crate::services::scanner_service::ExpectedComponent::pin_identity_is_request_pinned(
                pin,
            )
        })
    };
    match reusable {
        // #6300: a verdict reusable only under the DB-update grace goes to
        // the buffered gate, which serves it the same way and also queues its
        // re-grade; a redirect would serve it without, until the grace ends.
        Some(s)
            if s.row.verdict == VERDICT_CLEAN
                && pinned_by_the_bytes(s.pin_identity.as_deref())
                && !verdict_needs_regrade(s.row.scanner_version.as_deref(), current_version)
                && !clean_verdict_graded_nothing(
                    &s.row,
                    s.pin_identity.as_deref(),
                    s.components_cataloged,
                ) =>
        {
            CacheScanGate::Serve
        }
        _ => CacheScanGate::NotForFastPath,
    }
}

/// How long the fast paths reuse a verdict read (#4514). A write on this
/// replica drops the entry, but a read already in flight can store the
/// previous value again, so a new verdict is only guaranteed to be seen,
/// on every replica, within this window.
const VERDICT_MEMO_TTL: std::time::Duration = std::time::Duration::from_secs(30);

/// Entries in the fast-path verdict memo (#4514), keyed by digest and scan
/// type. About 300 B each.
const VERDICT_MEMO_CAPACITY: u64 = 10_000;

type VerdictMemo = moka::future::Cache<(String, String), Option<StoredProxyVerdict>>;

/// The in-process memo of verdict reads for the proxy-cache fast paths
/// (#4514). Only the fast paths read through it; the buffered gate reads the
/// table directly, so the decision that scans always sees the current row.
fn verdict_memo() -> &'static VerdictMemo {
    static MEMO: std::sync::OnceLock<VerdictMemo> = std::sync::OnceLock::new();
    MEMO.get_or_init(|| {
        moka::future::Cache::builder()
            .max_capacity(VERDICT_MEMO_CAPACITY)
            .time_to_live(VERDICT_MEMO_TTL)
            .build()
    })
}

/// Drop the memoised verdict read for `(checksum_sha256, scan_type)` after a
/// write on this replica.
async fn forget_memoised_verdict(checksum_sha256: &str, scan_type: &str) {
    verdict_memo()
        .invalidate(&(checksum_sha256.to_string(), scan_type.to_string()))
        .await;
}

// ---------------------------------------------------------------------------
// Proxy scan visibility (#3348): pure state-mapping + staleness helpers
// ---------------------------------------------------------------------------
//
// GET /api/v1/repositories/:key/security/proxy-scans reads this same table
// but must never invent a state the write path cannot produce. These helpers
// are the single source for that mapping so the handler and its tests share
// one definition instead of re-deriving it inline.

/// The three states the read endpoint may report. `error` is deliberately
/// excluded: `VERDICT_ERROR` has zero production writers (see module docs on
/// [`decide_inconclusive`]), so surfacing it as a fourth state would document
/// dead code as a real UI affordance.
pub const STATE_CLEAN: &str = "clean";
pub const STATE_VULNERABLE: &str = "vulnerable";
pub const STATE_NOT_SCANNED: &str = "not_scanned";

/// `not_scanned` reason: `scan_configs.scan_on_proxy` is `false`, INCLUDING
/// when the row is absent (the default state — see
/// [`ScanConfigService::is_proxy_scan_enabled`](crate::services::scan_config_service::ScanConfigService::is_proxy_scan_enabled)).
pub const NOT_SCANNED_REASON_SCANNING_DISABLED: &str = "scanning_disabled";
/// `not_scanned` reason: everything else — over the size cap, identity
/// unestablished, a failed scan, or (defensively) an unrecognized verdict
/// token. Must never be worded to imply the content is safe.
pub const NOT_SCANNED_REASON_UNKNOWN: &str = "unknown";

/// Derive `(state, reason)` for one proxy-cached digest from its verdict (if
/// any row was found by the `checksum_sha256 + scan_type` join) and whether
/// proxy scanning is enabled for the calling repository.
///
/// `reason` is `Some` iff `state == STATE_NOT_SCANNED`; `None` for `clean` /
/// `vulnerable`. A naive `WHERE scan_on_proxy = false` join on an absent
/// `scan_configs` row would return no rows at all and misfile the repo's
/// default (never-configured) state as `unknown` instead of
/// `scanning_disabled` — callers must resolve `scan_on_proxy` via
/// `is_proxy_scan_enabled`'s `unwrap_or(false)` BEFORE calling this, not via
/// a raw join, so that default is captured correctly.
pub fn derive_proxy_scan_state(
    verdict: Option<&str>,
    scan_on_proxy: bool,
) -> (&'static str, Option<&'static str>) {
    match verdict {
        Some(VERDICT_CLEAN) => (STATE_CLEAN, None),
        Some(VERDICT_VULNERABLE) => (STATE_VULNERABLE, None),
        // VERDICT_ERROR or any other unrecognized token: no writer produces
        // this today, but fold defensively into not_scanned/unknown rather
        // than panicking or fabricating a fourth state.
        Some(_) => (STATE_NOT_SCANNED, Some(NOT_SCANNED_REASON_UNKNOWN)),
        None if !scan_on_proxy => (
            STATE_NOT_SCANNED,
            Some(NOT_SCANNED_REASON_SCANNING_DISABLED),
        ),
        None => (STATE_NOT_SCANNED, Some(NOT_SCANNED_REASON_UNKNOWN)),
    }
}

/// Age-based staleness for the read endpoint: `scanned_at < now - ttl_days`.
///
/// Deliberately NOT [`verdict_is_reusable`]: that function is policy-
/// contaminated (factors in `fail_closed`, so the same row would render stale
/// in one repository and fresh in another) and needs a live scanner-version
/// probe, neither of which a read-only summary aggregate can do.
///
/// Boundary: the serve-path freshness gate ([`verdict_is_fresh`]) tests
/// `now < scanned_at + ttl` (strict). The equivalent strict form of this
/// staleness test is `now > scanned_at + ttl`, so at exact equality
/// (`scanned_at + ttl == now`) a verdict is reported as neither fresh nor
/// stale by either function — consistent, not a gap.
///
/// A digest with no verdict row (`not_scanned`) is never stale: there is
/// nothing to have gone stale. Callers with a nullable `scanned_at` from a
/// `LEFT JOIN` must route it through this function (or an equivalent
/// `COALESCE(..., false)`) rather than a raw SQL comparison — a raw
/// `scanned_at < now() - interval` against a NULL `scanned_at` evaluates to
/// SQL NULL, which — if ever used as a `GROUP BY` key — creates a spurious
/// third group alongside `true`/`false`.
pub fn is_proxy_scan_stale(
    scanned_at: Option<DateTime<Utc>>,
    ttl_days: i64,
    now: DateTime<Utc>,
) -> bool {
    match scanned_at {
        Some(t) => t < now - Duration::days(ttl_days),
        None => false,
    }
}

pub struct ProxyScanService {
    db: PgPool,
}

impl ProxyScanService {
    pub fn new(db: PgPool) -> Self {
        Self { db }
    }

    /// Look up a stored verdict for `(checksum_sha256, scan_type)`.
    pub async fn lookup_verdict(
        &self,
        checksum_sha256: &str,
        scan_type: &str,
    ) -> Result<Option<ProxyScanRow>> {
        let row = sqlx::query_as!(
            ProxyScanRow,
            r#"
            SELECT checksum_sha256, scan_type, verdict,
                   findings_count, critical_count, high_count, medium_count, low_count,
                   max_severity, scanner_version, scanned_at
            FROM proxy_scan_results
            WHERE checksum_sha256 = $1 AND scan_type = $2
            "#,
            checksum_sha256,
            scan_type,
        )
        .fetch_optional(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        Ok(row)
    }

    /// [`lookup_verdict`](Self::lookup_verdict) plus the coordinate the
    /// verdict was graded as (`pin_identity`, #4952) and the number of
    /// components it was graded on (`components_cataloged`, `None` when not
    /// recorded), in one read, for the inline gate's reuse decision (#3396).
    /// Runtime query (no macro) so this adds no offline sqlx data.
    pub async fn lookup_verdict_with_pin(
        &self,
        checksum_sha256: &str,
        scan_type: &str,
    ) -> Result<Option<(ProxyScanRow, Option<String>, Option<i32>)>> {
        #[derive(sqlx::FromRow)]
        struct PinnedRow {
            #[sqlx(flatten)]
            row: ProxyScanRow,
            pin_identity: Option<String>,
            components_cataloged: Option<i32>,
        }
        let row = sqlx::query_as::<_, PinnedRow>(
            r#"
            SELECT checksum_sha256, scan_type, verdict,
                   findings_count, critical_count, high_count, medium_count, low_count,
                   max_severity, scanner_version, scanned_at, pin_identity,
                   components_cataloged
            FROM proxy_scan_results
            WHERE checksum_sha256 = $1 AND scan_type = $2
            "#,
        )
        .bind(checksum_sha256)
        .bind(scan_type)
        .fetch_optional(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;
        Ok(row.map(|r| (r.row, r.pin_identity, r.components_cataloged)))
    }

    /// [`lookup_verdict_with_pin`](Self::lookup_verdict_with_pin) through the
    /// fast-path memo (#4514), for the proxy-cache readers that consult a
    /// stored verdict on every hit. A miss (`None`) is memoised too, so a hot
    /// unscanned object costs no query per hit.
    pub async fn lookup_verdict_memoized(
        &self,
        checksum_sha256: &str,
        scan_type: &str,
    ) -> Result<Option<StoredProxyVerdict>> {
        let key = (checksum_sha256.to_string(), scan_type.to_string());
        verdict_memo()
            .try_get_with(key, async {
                self.lookup_verdict_with_pin(checksum_sha256, scan_type)
                    .await
                    .map(|found| {
                        found.map(
                            |(row, pin_identity, components_cataloged)| StoredProxyVerdict {
                                row,
                                pin_identity,
                                components_cataloged,
                            },
                        )
                    })
            })
            .await
            .map_err(|e| AppError::Database(e.to_string()))
    }

    /// The stored verdict for `(checksum_sha256, scan_type)`, the number of
    /// components it was graded on (`components_cataloged`, `None` when not
    /// recorded), the coordinate it was graded as (`pin_identity`) and its
    /// `max_severity` (#5628), for the rescan's replacement rule (#3396).
    /// Runtime query (no macro) so this adds no offline sqlx data.
    #[allow(clippy::type_complexity)]
    pub async fn lookup_verdict_catalog(
        &self,
        checksum_sha256: &str,
        scan_type: &str,
    ) -> Result<Option<(String, Option<i32>, Option<String>, Option<String>)>> {
        sqlx::query_as::<_, (String, Option<i32>, Option<String>, Option<String>)>(
            "SELECT verdict, components_cataloged, pin_identity, max_severity \
             FROM proxy_scan_results \
             WHERE checksum_sha256 = $1 AND scan_type = $2",
        )
        .bind(checksum_sha256)
        .bind(scan_type)
        .fetch_optional(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))
    }

    /// Upsert a verdict keyed on `(checksum_sha256, scan_type)`. A newer scan of
    /// the same bytes (e.g. against a bumped CVE-DB) replaces the prior row.
    /// Leaves `components_cataloged` as it was; the inline gate records through
    /// [`record_verdict_with_catalog`](Self::record_verdict_with_catalog),
    /// which writes it with the verdict (#4594).
    #[allow(clippy::too_many_arguments)]
    pub async fn record_verdict(
        &self,
        checksum_sha256: &str,
        scan_type: &str,
        verdict: &str,
        findings_count: i32,
        critical_count: i32,
        high_count: i32,
        medium_count: i32,
        low_count: i32,
        max_severity: Option<&str>,
        scanner_version: Option<&str>,
        repository_id: Option<Uuid>,
    ) -> Result<()> {
        sqlx::query!(
            r#"
            INSERT INTO proxy_scan_results (
                checksum_sha256, scan_type, verdict,
                findings_count, critical_count, high_count, medium_count, low_count,
                max_severity, scanner_version, repository_id, scanned_at
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, now())
            ON CONFLICT (checksum_sha256, scan_type) DO UPDATE SET
                verdict = EXCLUDED.verdict,
                findings_count = EXCLUDED.findings_count,
                critical_count = EXCLUDED.critical_count,
                high_count = EXCLUDED.high_count,
                medium_count = EXCLUDED.medium_count,
                low_count = EXCLUDED.low_count,
                max_severity = EXCLUDED.max_severity,
                scanner_version = EXCLUDED.scanner_version,
                repository_id = EXCLUDED.repository_id,
                scanned_at = now()
            "#,
            checksum_sha256,
            scan_type,
            verdict,
            findings_count,
            critical_count,
            high_count,
            medium_count,
            low_count,
            max_severity,
            scanner_version,
            repository_id,
        )
        .execute(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;
        forget_memoised_verdict(checksum_sha256, scan_type).await;

        Ok(())
    }

    /// All stored verdict rows for one content digest, across scan types
    /// (#3244 admin inspect). Runtime query (no macro) so the admin surface
    /// adds no offline sqlx data.
    pub async fn list_verdicts_for_digest(
        &self,
        checksum_sha256: &str,
    ) -> Result<Vec<ProxyScanRow>> {
        sqlx::query_as::<_, ProxyScanRow>(
            r#"
            SELECT checksum_sha256, scan_type, verdict,
                   findings_count, critical_count, high_count, medium_count, low_count,
                   max_severity, scanner_version, scanned_at
            FROM proxy_scan_results
            WHERE checksum_sha256 = $1
            ORDER BY scan_type
            "#,
        )
        .bind(checksum_sha256)
        .fetch_all(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))
    }

    /// Delete every stored verdict row for one content digest, returning the
    /// deleted rows (#3244 admin invalidate).
    ///
    /// Semantics are "force re-assessment on the next pull", NOT a waiver:
    /// the next pull of the digest re-scans (inline under `fail_closed`,
    /// async under `fail_open`) and re-records whatever the engine finds — a
    /// still-flagged image immediately re-records `vulnerable`. Only the
    /// stale/false-positive-since-fixed case is durably resolved by this.
    pub async fn delete_verdicts_for_digest(
        &self,
        checksum_sha256: &str,
    ) -> Result<Vec<ProxyScanRow>> {
        let deleted = sqlx::query_as::<_, ProxyScanRow>(
            r#"
            DELETE FROM proxy_scan_results
            WHERE checksum_sha256 = $1
            RETURNING checksum_sha256, scan_type, verdict,
                      findings_count, critical_count, high_count, medium_count, low_count,
                      max_severity, scanner_version, scanned_at
            "#,
        )
        .bind(checksum_sha256)
        .fetch_all(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;
        for row in &deleted {
            forget_memoised_verdict(checksum_sha256, &row.scan_type).await;
        }
        Ok(deleted)
    }

    /// Persist the package inventory the inline proxy scan cataloged, so an
    /// SBOM can later be generated for this digest without re-fetching or
    /// re-scanning the bytes.
    ///
    /// Digest-keyed and repository-agnostic by design: the inventory is a
    /// property of the content, so byte-identical artifacts cached in many
    /// repositories share one set of rows, and no tenant's cache eviction can
    /// destroy an inventory another tenant is serving.
    ///
    /// An empty inventory is a no-op rather than a delete. A scanner that
    /// reports nothing must not erase a richer inventory recorded earlier for
    /// the same digest — that would silently downgrade an existing SBOM.
    ///
    /// Uses `UNNEST` so the whole inventory is one round trip regardless of
    /// component count, and `ON CONFLICT DO UPDATE` so a re-scan refreshes
    /// metadata rather than accumulating duplicates.
    pub async fn record_packages(
        &self,
        checksum_sha256: &str,
        scan_type: &str,
        packages: &[crate::models::security::RawPackage],
    ) -> Result<()> {
        if packages.is_empty() {
            return Ok(());
        }

        let names: Vec<String> = packages.iter().map(|p| p.name.clone()).collect();
        let versions: Vec<Option<String>> = packages.iter().map(|p| p.version.clone()).collect();
        let purls: Vec<Option<String>> = packages.iter().map(|p| p.purl.clone()).collect();
        let licenses: Vec<Option<String>> = packages.iter().map(|p| p.license.clone()).collect();

        sqlx::query(
            r#"
            INSERT INTO proxy_scan_packages (
                checksum_sha256, scan_type, name, version, purl, license, recorded_at
            )
            SELECT $1, $2, u.name, u.version, u.purl, u.license, now()
            FROM UNNEST($3::text[], $4::text[], $5::text[], $6::text[])
                AS u(name, version, purl, license)
            ON CONFLICT (checksum_sha256, scan_type, name, COALESCE(version, ''))
            DO UPDATE SET
                purl = COALESCE(EXCLUDED.purl, proxy_scan_packages.purl),
                license = COALESCE(EXCLUDED.license, proxy_scan_packages.license),
                recorded_at = now()
            "#,
        )
        .bind(checksum_sha256)
        .bind(scan_type)
        .bind(&names)
        .bind(&versions)
        .bind(&purls)
        .bind(&licenses)
        .execute(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        Ok(())
    }

    /// Record how complete the inventory just written by
    /// [`record_packages`](Self::record_packages) is (#4096), on the verdict row
    /// for `(checksum_sha256, scan_type)`.
    ///
    /// `None` means the CVE-authoritative scanner read every target it found;
    /// `Some("partial")` means it saw at least one it could not parse (#1153).
    /// Written unconditionally (a later complete scan clears an earlier
    /// `partial`), but only by the caller that also wrote the inventory, so the
    /// marker always describes the scan whose packages the SBOM is built from:
    /// a rescan that reports no packages leaves both the inventory and its
    /// completeness alone.
    ///
    /// A no-op when no verdict row exists (its upsert failed); the SBOM then
    /// renders without a marker until the digest is scanned again, exactly as
    /// for a verdict recorded before migration 252. Runtime query (no macro)
    /// so this adds no offline sqlx data.
    pub async fn record_inventory_completeness(
        &self,
        checksum_sha256: &str,
        scan_type: &str,
        scan_completeness: Option<&str>,
    ) -> Result<()> {
        sqlx::query(
            r#"
            UPDATE proxy_scan_results
            SET scan_completeness = $3
            WHERE checksum_sha256 = $1 AND scan_type = $2
            "#,
        )
        .bind(checksum_sha256)
        .bind(scan_type)
        .bind(scan_completeness)
        .execute(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        Ok(())
    }

    /// [`record_verdict`](Self::record_verdict) plus the number of components
    /// the CVE engine cataloged (#4594), in ONE upsert, so a reader never
    /// sees the new verdict with the previous scan's count. `Some(0)` on a
    /// clean verdict means it was graded on file contents only; `None` means
    /// the engine reported no catalog. The inline gate and the rescan
    /// endpoint record through this. Runtime query (no macro) so this adds
    /// no offline sqlx data.
    ///
    /// `pin_identity` is the coordinate the verdict was graded as
    /// ([`ExpectedComponent::pin_identity`](crate::services::scanner_service::ExpectedComponent::pin_identity)),
    /// `None` for a scan without one (#4952); it is replaced with the verdict.
    #[allow(clippy::too_many_arguments)]
    pub async fn record_verdict_with_catalog(
        &self,
        checksum_sha256: &str,
        scan_type: &str,
        verdict: &str,
        findings_count: i32,
        critical_count: i32,
        high_count: i32,
        medium_count: i32,
        low_count: i32,
        max_severity: Option<&str>,
        scanner_version: Option<&str>,
        repository_id: Option<Uuid>,
        components_cataloged: Option<i32>,
        pin_identity: Option<&str>,
    ) -> Result<()> {
        self.upsert_verdict(
            checksum_sha256,
            scan_type,
            verdict,
            findings_count,
            critical_count,
            high_count,
            medium_count,
            low_count,
            max_severity,
            scanner_version,
            repository_id,
            components_cataloged,
            pin_identity,
            None,
        )
        .await
        .map(|_| ())
    }

    /// [`record_verdict_with_catalog`](Self::record_verdict_with_catalog) for a
    /// scan that took a while (#5231): with `observed` set, the row is written only
    /// if its `scanned_at` is still that value (`None` inside: there was no row),
    /// so a verdict recorded since the scan started is not overwritten. Returns
    /// whether the row was written. `observed: None` always writes.
    #[allow(clippy::too_many_arguments)]
    pub async fn record_verdict_if_unchanged(
        &self,
        checksum_sha256: &str,
        scan_type: &str,
        verdict: &str,
        findings_count: i32,
        critical_count: i32,
        high_count: i32,
        medium_count: i32,
        low_count: i32,
        max_severity: Option<&str>,
        scanner_version: Option<&str>,
        repository_id: Option<Uuid>,
        components_cataloged: Option<i32>,
        pin_identity: Option<&str>,
        observed: Option<Option<DateTime<Utc>>>,
    ) -> Result<bool> {
        self.upsert_verdict(
            checksum_sha256,
            scan_type,
            verdict,
            findings_count,
            critical_count,
            high_count,
            medium_count,
            low_count,
            max_severity,
            scanner_version,
            repository_id,
            components_cataloged,
            pin_identity,
            observed,
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    async fn upsert_verdict(
        &self,
        checksum_sha256: &str,
        scan_type: &str,
        verdict: &str,
        findings_count: i32,
        critical_count: i32,
        high_count: i32,
        medium_count: i32,
        low_count: i32,
        max_severity: Option<&str>,
        scanner_version: Option<&str>,
        repository_id: Option<Uuid>,
        components_cataloged: Option<i32>,
        pin_identity: Option<&str>,
        observed: Option<Option<DateTime<Utc>>>,
    ) -> Result<bool> {
        let written = sqlx::query(
            r#"
            INSERT INTO proxy_scan_results (
                checksum_sha256, scan_type, verdict,
                findings_count, critical_count, high_count, medium_count, low_count,
                max_severity, scanner_version, repository_id, components_cataloged,
                pin_identity, scanned_at
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, now())
            ON CONFLICT (checksum_sha256, scan_type) DO UPDATE SET
                verdict = EXCLUDED.verdict,
                findings_count = EXCLUDED.findings_count,
                critical_count = EXCLUDED.critical_count,
                high_count = EXCLUDED.high_count,
                medium_count = EXCLUDED.medium_count,
                low_count = EXCLUDED.low_count,
                max_severity = EXCLUDED.max_severity,
                scanner_version = EXCLUDED.scanner_version,
                repository_id = EXCLUDED.repository_id,
                components_cataloged = EXCLUDED.components_cataloged,
                pin_identity = EXCLUDED.pin_identity,
                scanned_at = now()
            WHERE NOT $14 OR proxy_scan_results.scanned_at IS NOT DISTINCT FROM $15
            "#,
        )
        .bind(checksum_sha256)
        .bind(scan_type)
        .bind(verdict)
        .bind(findings_count)
        .bind(critical_count)
        .bind(high_count)
        .bind(medium_count)
        .bind(low_count)
        .bind(max_severity)
        .bind(scanner_version)
        .bind(repository_id)
        .bind(components_cataloged)
        .bind(pin_identity)
        .bind(observed.is_some())
        .bind(observed.flatten())
        .execute(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?
        .rows_affected()
            > 0;
        forget_memoised_verdict(checksum_sha256, scan_type).await;

        Ok(written)
    }

    /// The completeness recorded by
    /// [`record_inventory_completeness`](Self::record_inventory_completeness)
    /// for a digest's inventory, for the proxy SBOM's completeness marker.
    ///
    /// `None` when complete, when no verdict row exists, and for verdicts
    /// recorded before migration 252. `complete` is also folded to `None` so
    /// a complete inventory renders byte-identically to the hosted path's
    /// complete SBOMs (no marker).
    pub async fn fetch_inventory_completeness(
        &self,
        checksum_sha256: &str,
        scan_type: &str,
    ) -> Result<Option<String>> {
        let value: Option<Option<String>> = sqlx::query_scalar(
            r#"
            SELECT scan_completeness
            FROM proxy_scan_results
            WHERE checksum_sha256 = $1 AND scan_type = $2
            "#,
        )
        .bind(checksum_sha256)
        .bind(scan_type)
        .fetch_optional(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        Ok(value.flatten().filter(|c| c != "complete"))
    }

    /// Read back the inventory for a digest, for SBOM generation.
    ///
    /// Filtered on `scan_type` because the uniqueness key includes it: an
    /// unfiltered read would merge two engines' inventories into one SBOM the
    /// day a second scan type is written.
    ///
    /// An empty result means "no inventory recorded", which callers must
    /// render as unknown — never as an empty and therefore falsely clean SBOM.
    pub async fn fetch_packages(
        &self,
        checksum_sha256: &str,
        scan_type: &str,
    ) -> Result<Vec<crate::models::security::RawPackage>> {
        #[allow(clippy::type_complexity)]
        let rows: Vec<(String, Option<String>, Option<String>, Option<String>)> = sqlx::query_as(
            r#"
            SELECT name, version, purl, license
            FROM proxy_scan_packages
            WHERE checksum_sha256 = $1 AND scan_type = $2
            ORDER BY name, version
            "#,
        )
        .bind(checksum_sha256)
        .bind(scan_type)
        .fetch_all(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        Ok(rows
            .into_iter()
            .map(
                |(name, version, purl, license)| crate::models::security::RawPackage {
                    name,
                    version,
                    purl,
                    license,
                    source_target: None,
                },
            )
            .collect())
    }

    /// Persist the per-CVE detail behind a proxy verdict (#3395).
    ///
    /// `proxy_scan_results` stores counts and a max severity; it cannot answer
    /// "which CVE blocked my build?". These rows can. Same shape and same
    /// reasoning as [`record_packages`](Self::record_packages): digest-keyed
    /// (no `repository_id`, so one copy serves every tenant caching identical
    /// bytes), one `UNNEST` round trip regardless of finding count, and
    /// `ON CONFLICT DO UPDATE` so a rescan refreshes rather than accumulates.
    ///
    /// An empty list is a no-op rather than a delete, for the same reason: a
    /// scanner that reports nothing must not erase detail recorded earlier for
    /// the same digest. The consequence is that a digest whose CVEs were
    /// genuinely all fixed keeps stale rows until it is rescanned with
    /// findings — acceptable, because the VERDICT (which is what gates
    /// distribution) is replaced unconditionally by `record_verdict`, and a
    /// clean verdict suppresses this detail on the read path.
    ///
    /// The caller MUST pass a list already deduplicated on
    /// `(cve_id, package_name, package_version)` — see
    /// [`crate::services::scanner_service::retain_proxy_findings`]. Postgres
    /// rejects an upsert whose own tuple set hits one row twice.
    pub async fn record_findings(
        &self,
        checksum_sha256: &str,
        scan_type: &str,
        findings: &[crate::models::security::ProxyFinding],
    ) -> Result<()> {
        if findings.is_empty() {
            return Ok(());
        }

        let cve_ids: Vec<String> = findings.iter().map(|f| f.cve_id.clone()).collect();
        let severities: Vec<String> = findings.iter().map(|f| f.severity.clone()).collect();
        let names: Vec<Option<String>> = findings.iter().map(|f| f.package_name.clone()).collect();
        let versions: Vec<Option<String>> =
            findings.iter().map(|f| f.package_version.clone()).collect();
        let fixed: Vec<Option<String>> = findings.iter().map(|f| f.fixed_version.clone()).collect();
        let titles: Vec<Option<String>> = findings.iter().map(|f| f.title.clone()).collect();

        sqlx::query(
            r#"
            INSERT INTO proxy_scan_findings (
                checksum_sha256, scan_type, cve_id, severity,
                package_name, package_version, fixed_version, title, recorded_at
            )
            SELECT $1, $2, u.cve_id, u.severity,
                   u.package_name, u.package_version, u.fixed_version, u.title, now()
            FROM UNNEST($3::text[], $4::text[], $5::text[], $6::text[], $7::text[], $8::text[])
                AS u(cve_id, severity, package_name, package_version, fixed_version, title)
            ON CONFLICT (
                checksum_sha256, scan_type, cve_id,
                COALESCE(package_name, ''), COALESCE(package_version, '')
            )
            DO UPDATE SET
                severity = EXCLUDED.severity,
                fixed_version = COALESCE(EXCLUDED.fixed_version, proxy_scan_findings.fixed_version),
                title = COALESCE(EXCLUDED.title, proxy_scan_findings.title),
                recorded_at = now()
            "#,
        )
        .bind(checksum_sha256)
        .bind(scan_type)
        .bind(&cve_ids)
        .bind(&severities)
        .bind(&names)
        .bind(&versions)
        .bind(&fixed)
        .bind(&titles)
        .execute(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        Ok(())
    }

    /// Read back the per-CVE detail for a digest (#3395).
    ///
    /// Ordered most severe first so a truncated UI rendering shows the finding
    /// that matters. `severity` is a token, not an enum, in the database, so
    /// the ordering is an explicit CASE rather than a column sort — an unknown
    /// token sorts last rather than in the middle of the real severities.
    ///
    /// `scan_type`-filtered for the same reason as
    /// [`fetch_packages`](Self::fetch_packages).
    pub async fn fetch_findings(
        &self,
        checksum_sha256: &str,
        scan_type: &str,
        limit: i64,
    ) -> Result<Vec<crate::models::security::ProxyFinding>> {
        #[allow(clippy::type_complexity)]
        let rows: Vec<(
            String,
            String,
            Option<String>,
            Option<String>,
            Option<String>,
            Option<String>,
        )> = sqlx::query_as(
            r#"
            SELECT cve_id, severity, package_name, package_version, fixed_version, title
            FROM proxy_scan_findings
            WHERE checksum_sha256 = $1 AND scan_type = $2
            ORDER BY CASE severity
                         WHEN 'critical' THEN 0
                         WHEN 'high' THEN 1
                         WHEN 'medium' THEN 2
                         WHEN 'low' THEN 3
                         WHEN 'info' THEN 4
                         ELSE 5
                     END,
                     cve_id, package_name
            LIMIT $3
            "#,
        )
        .bind(checksum_sha256)
        .bind(scan_type)
        .bind(limit)
        .fetch_all(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        Ok(rows
            .into_iter()
            .map(
                |(cve_id, severity, package_name, package_version, fixed_version, title)| {
                    crate::models::security::ProxyFinding {
                        cve_id,
                        severity,
                        package_name,
                        package_version,
                        fixed_version,
                        title,
                    }
                },
            )
            .collect())
    }
}

#[cfg(ak_test_shard = "services-1")]
#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // ProxySeverityGate (#3243 stage 3 / #3246)
    // -----------------------------------------------------------------------

    /// The opt-in boolean is load-bearing: with `block_on_policy_violation`
    /// off (the column default), the stored threshold is inert and the gate is
    /// the historical block-on-any — no repository changes behavior on
    /// upgrade without an operator having flipped the toggle.
    #[test]
    fn severity_gate_requires_explicit_opt_in() {
        assert_eq!(
            ProxySeverityGate::from_config(false, "high"),
            ProxySeverityGate::BlockOnAny,
            "the default 'high' threshold must NOT weaken the gate while the \
             opt-in is off"
        );
        assert_eq!(
            ProxySeverityGate::from_config(true, "high"),
            ProxySeverityGate::Threshold(Severity::High)
        );
        // Normalized vocabulary parses; junk fails closed to block-on-any.
        assert_eq!(
            ProxySeverityGate::from_config(true, "CRITICAL"),
            ProxySeverityGate::Threshold(Severity::Critical)
        );
        assert_eq!(
            ProxySeverityGate::from_config(true, "garbage"),
            ProxySeverityGate::BlockOnAny,
            "an unparseable configured threshold must fail closed"
        );
    }

    /// #3645: the record-only gate never blocks -- not even an ungraded
    /// verdict -- and is the weakest gate in a stricter-of-two combination.
    #[test]
    fn record_only_gate_never_blocks_and_yields_to_any_enforcing_gate() {
        let ro = ProxySeverityGate::RecordOnly;
        for sev in [
            Some(Severity::Critical),
            Some(Severity::High),
            Some(Severity::Info),
            None,
        ] {
            assert!(!ro.blocks(sev), "record-only must not block {sev:?}");
        }
        let high = ProxySeverityGate::Threshold(Severity::High);
        assert_eq!(ProxySeverityGate::stricter(ro, high), high);
        assert_eq!(ProxySeverityGate::stricter(high, ro), high);
        assert_eq!(
            ProxySeverityGate::stricter(ro, ProxySeverityGate::BlockOnAny),
            ProxySeverityGate::BlockOnAny
        );
        assert_eq!(ProxySeverityGate::stricter(ro, ro), ro);
        assert!(ro.is_record_only());
        assert!(!high.is_record_only());
    }

    /// #3645: the record-only action round-trips through the column, never
    /// scans inline (so it can never 423 on a first pull), and serves an
    /// inconclusive / over-cap outcome pending rather than locking.
    #[test]
    fn record_only_action_scans_async_and_never_locks() {
        for a in [
            ProxyScanAction::FailOpen,
            ProxyScanAction::FailClosed,
            ProxyScanAction::RecordOnly,
        ] {
            assert_eq!(ProxyScanAction::from_db(a.as_db_str()), a);
        }
        let ro = ProxyScanAction::RecordOnly;
        assert!(ro.is_record_only() && !ro.is_fail_closed());
        assert_eq!(decide_inconclusive(ro), InconclusiveOutcome::ServePending);
        assert_eq!(
            decide_serve(None, Some("grype-1"), ro, 30, Utc::now()),
            ServeDecision::ServePendingScanAsync
        );
    }

    /// The blocking decision itself: serve ONLY when the verdict's highest
    /// severity is known and strictly below the threshold; everything else —
    /// at/above threshold, unknown severity, no opt-in — blocks.
    #[test]
    fn severity_gate_blocks_fail_closed() {
        let high = ProxySeverityGate::Threshold(Severity::High);
        // At or above the threshold blocks.
        assert!(high.blocks(Some(Severity::Critical)));
        assert!(high.blocks(Some(Severity::High)));
        // Strictly below serves.
        assert!(!high.blocks(Some(Severity::Medium)));
        assert!(!high.blocks(Some(Severity::Low)));
        assert!(!high.blocks(Some(Severity::Info)));
        // Fail closed: a legacy row with no stored max_severity blocks even
        // with a threshold configured (#3243's hard requirement).
        assert!(high.blocks(None));
        // Block-on-any ignores severity entirely, including unknown.
        assert!(ProxySeverityGate::BlockOnAny.blocks(Some(Severity::Info)));
        assert!(ProxySeverityGate::BlockOnAny.blocks(None));
        // Threshold(Info) blocks every KNOWN severity — "block on anything"
        // stays expressible after opting in.
        let info = ProxySeverityGate::Threshold(Severity::Info);
        assert!(info.blocks(Some(Severity::Info)));
        assert!(info.blocks(Some(Severity::Critical)));
    }

    /// Stricter-of-two for Virtual repos: `BlockOnAny` dominates, and between
    /// two thresholds the one that blocks MORE severities wins — a virtual
    /// repo can never become the lax route around a member's posture (#3025
    /// direction).
    #[test]
    fn severity_gate_stricter_of_two() {
        use ProxySeverityGate::*;
        assert_eq!(
            ProxySeverityGate::stricter(BlockOnAny, Threshold(Severity::Critical)),
            BlockOnAny
        );
        assert_eq!(
            ProxySeverityGate::stricter(Threshold(Severity::Critical), BlockOnAny),
            BlockOnAny
        );
        // Threshold(Low) blocks {critical,high,medium,low}; Threshold(Critical)
        // blocks only {critical} — Low is the stricter of the pair.
        assert_eq!(
            ProxySeverityGate::stricter(Threshold(Severity::Critical), Threshold(Severity::Low)),
            Threshold(Severity::Low)
        );
        assert_eq!(
            ProxySeverityGate::stricter(BlockOnAny, BlockOnAny),
            BlockOnAny
        );
    }

    #[test]
    fn verdict_blocks_only_vulnerable() {
        assert!(verdict_blocks(VERDICT_VULNERABLE));
        assert!(!verdict_blocks(VERDICT_CLEAN));
        assert!(!verdict_blocks(VERDICT_ERROR));
        assert!(!verdict_blocks("something-else"));
    }

    #[test]
    fn fresh_within_ttl_same_version() {
        let now = Utc::now();
        let scanned = now - Duration::days(1);
        assert!(verdict_is_fresh(
            scanned,
            Some("grype-0.83.0"),
            Some("grype-0.83.0"),
            30,
            now
        ));
    }

    #[test]
    fn stale_past_ttl() {
        let now = Utc::now();
        let scanned = now - Duration::days(31);
        assert!(!verdict_is_fresh(
            scanned,
            Some("grype-0.83.0"),
            Some("grype-0.83.0"),
            30,
            now
        ));
    }

    #[test]
    fn stale_on_version_mismatch_even_within_ttl() {
        // A CVE-DB bump changes the version string: a yesterday-clean verdict
        // must be re-evaluated against today's CVEs.
        let now = Utc::now();
        let scanned = now - Duration::days(1);
        assert!(!verdict_is_fresh(
            scanned,
            Some("grype-0.83.0"),
            Some("grype-0.84.0"),
            30,
            now
        ));
    }

    #[test]
    fn unknown_version_falls_back_to_ttl() {
        let now = Utc::now();
        let scanned = now - Duration::days(1);
        // Either side unknown => cannot prove a mismatch, rely on TTL.
        assert!(verdict_is_fresh(
            scanned,
            None,
            Some("grype-0.84.0"),
            30,
            now
        ));
        assert!(verdict_is_fresh(
            scanned,
            Some("grype-0.83.0"),
            None,
            30,
            now
        ));
        assert!(!verdict_is_fresh(
            now - Duration::days(31),
            None,
            None,
            30,
            now
        ));
    }

    /// #2976 follow-up: `verdict_is_fresh` fails OPEN on an unknown version
    /// (it cannot prove a mismatch). `verdict_is_reusable` must NOT let that
    /// default short-circuit a fail-closed repo for a CLEAN verdict — the
    /// freshness check runs before the inline scan, so an unprovable clean
    /// verdict would otherwise serve bytes nothing on this node can vouch for.
    #[test]
    fn unknown_version_is_not_reusable_for_clean_under_fail_closed() {
        let now = Utc::now();
        let scanned = now - Duration::days(1); // well within TTL
        let cases = [
            (None, Some("grype-0.84.0")), // live probe known, legacy row
            (Some("grype-0.84.0"), None), // stored known, probe failed
            (None, None),                 // neither known
        ];
        for (stored, current) in cases {
            assert!(
                verdict_is_fresh(scanned, stored, current, 30, now),
                "precondition: the policy-free check still fails open"
            );
            assert!(
                !verdict_is_reusable(
                    VERDICT_CLEAN,
                    scanned,
                    stored,
                    current,
                    ProxyScanAction::FailClosed,
                    30,
                    now
                ),
                "fail-closed + clean + unprovable provenance ({stored:?}/{current:?}) \
                 must re-scan, never serve from cache"
            );
            // Fail-open is unchanged: its re-scan branch serves-with-pending
            // anyway, so the TTL-only fallback costs no availability.
            assert!(verdict_is_reusable(
                VERDICT_CLEAN,
                scanned,
                stored,
                current,
                ProxyScanAction::FailOpen,
                30,
                now
            ));
            // Non-clean verdicts keep their existing handling under both
            // actions: a cached `vulnerable` row must still short-circuit to
            // the block path rather than being re-fetched/re-scanned.
            assert!(verdict_is_reusable(
                VERDICT_VULNERABLE,
                scanned,
                stored,
                current,
                ProxyScanAction::FailClosed,
                30,
                now
            ));
        }
    }

    /// The working paths are untouched: a PROVEN version match is reusable
    /// under both actions, a proven mismatch is not, and an expired TTL is
    /// never reusable regardless of provenance.
    #[test]
    fn reusable_matches_fresh_when_both_versions_known() {
        let now = Utc::now();
        let scanned = now - Duration::days(1);
        for action in [ProxyScanAction::FailClosed, ProxyScanAction::FailOpen] {
            assert!(verdict_is_reusable(
                VERDICT_CLEAN,
                scanned,
                Some("grype-0.83.0"),
                Some("grype-0.83.0"),
                action,
                30,
                now
            ));
            assert!(!verdict_is_reusable(
                VERDICT_CLEAN,
                scanned,
                Some("grype-0.83.0"),
                Some("grype-0.84.0"),
                action,
                30,
                now
            ));
            assert!(!verdict_is_reusable(
                VERDICT_CLEAN,
                now - Duration::days(31),
                Some("grype-0.83.0"),
                Some("grype-0.83.0"),
                action,
                30,
                now
            ));
        }
    }

    #[test]
    fn action_from_db_defaults_fail_open() {
        assert_eq!(
            ProxyScanAction::from_db("fail_closed"),
            ProxyScanAction::FailClosed
        );
        assert_eq!(
            ProxyScanAction::from_db("fail_open"),
            ProxyScanAction::FailOpen
        );
        // Unknown / legacy => fail-open (matches the column default).
        assert_eq!(
            ProxyScanAction::from_db("garbage"),
            ProxyScanAction::FailOpen
        );
        assert!(ProxyScanAction::FailClosed.is_fail_closed());
        assert!(!ProxyScanAction::FailOpen.is_fail_closed());
    }

    /// DB-backed round trip: record → lookup → upsert-on-conflict → lookup.
    /// Covers the two sqlx paths (`record_verdict`, `lookup_verdict`) against
    /// the real `proxy_scan_results` schema (unique key + CHECK vocabulary).
    /// Skips cleanly when DATABASE_URL is unset.
    #[tokio::test]
    async fn record_and_lookup_verdict_roundtrip_and_upsert() {
        use crate::api::handlers::test_db_helpers as tdh;
        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let svc = ProxyScanService::new(pool.clone());
        // Unique digest per run so parallel/repeat runs never collide.
        let digest = format!("{:0>64}", uuid::Uuid::new_v4().simple());

        // Missing digest: no row.
        let missing = svc.lookup_verdict(&digest, "grype").await.expect("lookup");
        assert!(missing.is_none(), "unknown digest must have no verdict");

        // First record: clean.
        svc.record_verdict(
            &digest,
            "grype",
            VERDICT_CLEAN,
            0,
            0,
            0,
            0,
            0,
            None,
            Some("grype-0.99.0-test"),
            None,
        )
        .await
        .expect("record clean");
        let row = svc
            .lookup_verdict(&digest, "grype")
            .await
            .expect("lookup")
            .expect("row after record");
        assert_eq!(row.verdict, VERDICT_CLEAN);
        assert_eq!(row.findings_count, 0);
        assert_eq!(row.max_severity, None);
        assert_eq!(row.scanner_version.as_deref(), Some("grype-0.99.0-test"));

        // Re-record the SAME digest (e.g. re-scan against a bumped CVE-DB
        // that now flags it): the upsert must replace, not duplicate/err.
        svc.record_verdict(
            &digest,
            "grype",
            VERDICT_VULNERABLE,
            2,
            1,
            1,
            0,
            0,
            Some("critical"),
            Some("grype-1.0.0-test"),
            None,
        )
        .await
        .expect("upsert vulnerable");
        let row = svc
            .lookup_verdict(&digest, "grype")
            .await
            .expect("lookup")
            .expect("row after upsert");
        assert_eq!(row.verdict, VERDICT_VULNERABLE);
        assert_eq!(row.findings_count, 2);
        assert_eq!(row.critical_count, 1);
        assert_eq!(row.high_count, 1);
        assert_eq!(row.max_severity.as_deref(), Some("critical"));
        assert_eq!(row.scanner_version.as_deref(), Some("grype-1.0.0-test"));
        // A different scan_type is a distinct verdict slot.
        assert!(svc
            .lookup_verdict(&digest, "trivy")
            .await
            .expect("lookup other type")
            .is_none());

        sqlx::query("DELETE FROM proxy_scan_results WHERE checksum_sha256 = $1")
            .bind(&digest)
            .execute(&pool)
            .await
            .expect("cleanup");
    }

    /// #4096: the inventory completeness round-trips through the verdict row,
    /// a later complete scan clears an earlier `partial`, `complete` reads back
    /// as `None` (no marker), and a digest with no verdict row reads `None`
    /// instead of erroring.
    #[tokio::test]
    async fn inventory_completeness_roundtrip_and_clear() {
        use crate::api::handlers::test_db_helpers as tdh;
        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let svc = ProxyScanService::new(pool.clone());
        let digest = format!("{:0>64}", uuid::Uuid::new_v4().simple());

        // No verdict row: the write is a no-op and the read is None.
        svc.record_inventory_completeness(&digest, "grype", Some("partial"))
            .await
            .expect("no-op write");
        assert_eq!(
            svc.fetch_inventory_completeness(&digest, "grype")
                .await
                .expect("fetch missing"),
            None
        );

        svc.record_verdict(
            &digest,
            "grype",
            VERDICT_CLEAN,
            0,
            0,
            0,
            0,
            0,
            None,
            Some("grype-0.99.0-test"),
            None,
        )
        .await
        .expect("record verdict");
        // A verdict recorded without a completeness (pre-252 shape) is None.
        assert_eq!(
            svc.fetch_inventory_completeness(&digest, "grype")
                .await
                .expect("fetch unset"),
            None
        );

        svc.record_inventory_completeness(&digest, "grype", Some("partial"))
            .await
            .expect("record partial");
        assert_eq!(
            svc.fetch_inventory_completeness(&digest, "grype")
                .await
                .expect("fetch partial")
                .as_deref(),
            Some("partial")
        );
        // Scoped by scan type like the inventory itself.
        assert_eq!(
            svc.fetch_inventory_completeness(&digest, "trivy")
                .await
                .expect("fetch other type"),
            None
        );

        // A re-upserted verdict does not erase it: only the inventory writer
        // owns this column.
        svc.record_verdict(
            &digest,
            "grype",
            VERDICT_CLEAN,
            0,
            0,
            0,
            0,
            0,
            None,
            Some("grype-0.99.1-test"),
            None,
        )
        .await
        .expect("re-record verdict");
        assert_eq!(
            svc.fetch_inventory_completeness(&digest, "grype")
                .await
                .expect("fetch after upsert")
                .as_deref(),
            Some("partial")
        );

        // A later complete inventory clears it; an explicit "complete" also
        // reads back as None so the SBOM carries no marker.
        svc.record_inventory_completeness(&digest, "grype", None)
            .await
            .expect("record complete");
        assert_eq!(
            svc.fetch_inventory_completeness(&digest, "grype")
                .await
                .expect("fetch cleared"),
            None
        );
        svc.record_inventory_completeness(&digest, "grype", Some("complete"))
            .await
            .expect("record explicit complete");
        assert_eq!(
            svc.fetch_inventory_completeness(&digest, "grype")
                .await
                .expect("fetch explicit complete"),
            None
        );

        sqlx::query("DELETE FROM proxy_scan_results WHERE checksum_sha256 = $1")
            .bind(&digest)
            .execute(&pool)
            .await
            .expect("cleanup");
    }

    fn row(
        verdict: &str,
        scanned_at: DateTime<Utc>,
        scanner_version: Option<&str>,
    ) -> ProxyScanRow {
        ProxyScanRow {
            checksum_sha256: "0".repeat(64),
            scan_type: "grype".to_string(),
            verdict: verdict.to_string(),
            findings_count: i32::from(verdict == VERDICT_VULNERABLE),
            critical_count: 0,
            high_count: 0,
            medium_count: 0,
            low_count: 0,
            max_severity: None,
            scanner_version: scanner_version.map(str::to_string),
            scanned_at,
        }
    }

    /// The serve state machine truth table, single-sourced for every proxy
    /// format: fresh-clean serves, fresh-vulnerable blocks, and every
    /// no-reusable-verdict case forks on the action (fail-closed scans
    /// inline, fail-open serves pending + async scan).
    #[test]
    fn decide_serve_truth_table() {
        let now = Utc::now();
        let fresh = now - Duration::days(1);
        let live = Some("grype-0.84.0");

        // Fresh reusable clean -> serve from cache (both actions).
        for action in [ProxyScanAction::FailClosed, ProxyScanAction::FailOpen] {
            assert_eq!(
                decide_serve(
                    Some(&row(VERDICT_CLEAN, fresh, live)),
                    live,
                    action,
                    30,
                    now
                ),
                ServeDecision::ServeCached
            );
            // Fresh reusable vulnerable -> block from cache, no re-scan.
            assert_eq!(
                decide_serve(
                    Some(&row(VERDICT_VULNERABLE, fresh, live)),
                    live,
                    action,
                    30,
                    now
                ),
                ServeDecision::BlockCached
            );
        }

        // No row at all: first pull of this digest.
        assert_eq!(
            decide_serve(None, live, ProxyScanAction::FailClosed, 30, now),
            ServeDecision::ScanInline
        );
        assert_eq!(
            decide_serve(None, live, ProxyScanAction::FailOpen, 30, now),
            ServeDecision::ServePendingScanAsync
        );

        // Stale rows fall through to the same first-pull fork: past-TTL...
        let expired = now - Duration::days(31);
        assert_eq!(
            decide_serve(
                Some(&row(VERDICT_CLEAN, expired, live)),
                live,
                ProxyScanAction::FailClosed,
                30,
                now
            ),
            ServeDecision::ScanInline
        );
        // ...and a scanner/CVE-DB version bump within the TTL (#2976).
        assert_eq!(
            decide_serve(
                Some(&row(VERDICT_CLEAN, fresh, Some("grype-0.83.0"))),
                live,
                ProxyScanAction::FailClosed,
                30,
                now
            ),
            ServeDecision::ScanInline
        );
        assert_eq!(
            decide_serve(
                Some(&row(VERDICT_CLEAN, fresh, Some("grype-0.83.0"))),
                live,
                ProxyScanAction::FailOpen,
                30,
                now
            ),
            ServeDecision::ServePendingScanAsync
        );
    }

    /// THE #2976 case, pinned at the decision seam every format now shares:
    /// a cached `clean` verdict whose provenance cannot be proven current
    /// (live version probe returned `None`) must NOT short-circuit a
    /// fail-closed repo — the pull re-scans inline. Fail-open keeps the
    /// TTL-only fallback (its re-scan branch serves-with-pending anyway).
    #[test]
    fn decide_serve_probe_none_fail_closed_rescans_clean() {
        let now = Utc::now();
        let fresh = now - Duration::days(1);
        let clean = row(VERDICT_CLEAN, fresh, Some("grype-0.83.0"));

        assert_eq!(
            decide_serve(Some(&clean), None, ProxyScanAction::FailClosed, 30, now),
            ServeDecision::ScanInline,
            "probe-None + fail_closed must re-scan, never serve stale-clean"
        );
        assert_eq!(
            decide_serve(Some(&clean), None, ProxyScanAction::FailOpen, 30, now),
            ServeDecision::ServeCached,
            "fail-open keeps the TTL-only fallback on an unknown live version"
        );
        // A cached vulnerable verdict still blocks even with no live version:
        // never re-fetch/re-scan bytes already known bad.
        let vuln = row(VERDICT_VULNERABLE, fresh, Some("grype-0.83.0"));
        assert_eq!(
            decide_serve(Some(&vuln), None, ProxyScanAction::FailClosed, 30, now),
            ServeDecision::BlockCached
        );
    }

    // -----------------------------------------------------------------
    // Proxy scan visibility (#3348): state mapping + staleness
    // -----------------------------------------------------------------

    #[test]
    fn derive_state_clean_and_vulnerable_have_no_reason() {
        assert_eq!(
            derive_proxy_scan_state(Some(VERDICT_CLEAN), true),
            (STATE_CLEAN, None)
        );
        assert_eq!(
            derive_proxy_scan_state(Some(VERDICT_CLEAN), false),
            (STATE_CLEAN, None),
            "a stored clean verdict is reported as clean regardless of the \
             calling repo's current scan_on_proxy setting (verdicts are global)"
        );
        assert_eq!(
            derive_proxy_scan_state(Some(VERDICT_VULNERABLE), true),
            (STATE_VULNERABLE, None)
        );
        assert_eq!(
            derive_proxy_scan_state(Some(VERDICT_VULNERABLE), false),
            (STATE_VULNERABLE, None)
        );
    }

    #[test]
    fn derive_state_no_row_scanning_disabled() {
        assert_eq!(
            derive_proxy_scan_state(None, false),
            (
                STATE_NOT_SCANNED,
                Some(NOT_SCANNED_REASON_SCANNING_DISABLED)
            )
        );
    }

    /// The absent-`scan_configs` row case: the caller resolves
    /// `scan_on_proxy` via `is_proxy_scan_enabled`'s `unwrap_or(false)`
    /// BEFORE calling this function, so "no config row ever saved" arrives
    /// here as `scan_on_proxy = false` — identical to an explicit disable —
    /// and must resolve to `scanning_disabled`, matching what the proxy gate
    /// actually does for that repository.
    #[test]
    fn derive_state_absent_config_row_resolves_scanning_disabled() {
        let never_configured_default = false; // is_proxy_scan_enabled().unwrap_or(false)
        assert_eq!(
            derive_proxy_scan_state(None, never_configured_default),
            (
                STATE_NOT_SCANNED,
                Some(NOT_SCANNED_REASON_SCANNING_DISABLED)
            )
        );
    }

    #[test]
    fn derive_state_no_row_scanning_enabled_is_unknown() {
        assert_eq!(
            derive_proxy_scan_state(None, true),
            (STATE_NOT_SCANNED, Some(NOT_SCANNED_REASON_UNKNOWN))
        );
    }

    #[test]
    fn derive_state_unrecognized_verdict_token_folds_to_unknown() {
        // Defensive: VERDICT_ERROR (and anything else unrecognized) has zero
        // production writers but must not panic or invent a fourth state.
        assert_eq!(
            derive_proxy_scan_state(Some(VERDICT_ERROR), true),
            (STATE_NOT_SCANNED, Some(NOT_SCANNED_REASON_UNKNOWN))
        );
        assert_eq!(
            derive_proxy_scan_state(Some("garbage"), false),
            (STATE_NOT_SCANNED, Some(NOT_SCANNED_REASON_UNKNOWN))
        );
    }

    #[test]
    fn stale_not_scanned_row_is_never_stale() {
        assert!(!is_proxy_scan_stale(None, 30, Utc::now()));
    }

    #[test]
    fn stale_age_based_boundary() {
        let now = Utc::now();
        // Well within the TTL: fresh.
        assert!(!is_proxy_scan_stale(Some(now - Duration::days(1)), 30, now));
        // Well past the TTL: stale.
        assert!(is_proxy_scan_stale(Some(now - Duration::days(31)), 30, now));
        // Exact boundary (`scanned_at == now - ttl_days`): the formula is a
        // strict `<`, so equality is NOT stale. Pick a side, per the design
        // doc, matching the serve-path gate's strict `now < scanned_at + ttl`.
        assert!(!is_proxy_scan_stale(
            Some(now - Duration::days(30)),
            30,
            now
        ));
        // One nanosecond past the boundary: stale.
        assert!(is_proxy_scan_stale(
            Some(now - Duration::days(30) - Duration::nanoseconds(1)),
            30,
            now
        ));
    }

    // -----------------------------------------------------------------------
    // Per-CVE detail (#3395)
    // -----------------------------------------------------------------------

    /// DB-backed round trip against the real `proxy_scan_findings` schema:
    /// write → read back in severity order → rewrite (the rescan case) → read.
    ///
    /// Four contracts, each of which broke a real read path when absent:
    ///   * severity ordering is by MEANING, not alphabetical — `critical`
    ///     sorts before `high` before `low`, and an unrecognized token sorts
    ///     LAST rather than into the middle of the real severities;
    ///   * `scan_type` scopes the read, so a second engine's rows never merge
    ///     into the first's list;
    ///   * a re-record upserts in place rather than accumulating duplicates;
    ///   * an EMPTY list is a no-op, not a delete — a scanner that reports
    ///     nothing must not erase detail recorded earlier for the same digest.
    #[tokio::test]
    async fn record_and_fetch_findings_roundtrip_orders_scopes_and_upserts() {
        use crate::api::handlers::test_db_helpers as tdh;
        use crate::models::security::ProxyFinding;
        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let svc = ProxyScanService::new(pool.clone());
        let digest = format!("{:0>64}", uuid::Uuid::new_v4().simple());

        let mk = |cve: &str, sev: &str, pkg: &str| ProxyFinding {
            cve_id: cve.to_string(),
            severity: sev.to_string(),
            package_name: Some(pkg.to_string()),
            package_version: Some("0.15.0".to_string()),
            fixed_version: Some("0.15.3".to_string()),
            title: Some(format!("{cve} in {pkg}")),
        };

        assert!(
            svc.fetch_findings(&digest, "grype", 50)
                .await
                .expect("fetch empty")
                .is_empty(),
            "unknown digest has no detail"
        );

        // Inserted in a deliberately unhelpful order, including a token the
        // CASE does not know.
        svc.record_findings(
            &digest,
            "grype",
            &[
                mk("CVE-2021-30", "low", "werkzeug"),
                mk("CVE-2021-10", "critical", "werkzeug"),
                mk("CVE-2021-40", "banana", "werkzeug"),
                mk("CVE-2021-20", "high", "werkzeug"),
            ],
        )
        .await
        .expect("record findings");

        let rows = svc
            .fetch_findings(&digest, "grype", 50)
            .await
            .expect("fetch");
        assert_eq!(
            rows.iter().map(|r| r.severity.as_str()).collect::<Vec<_>>(),
            vec!["critical", "high", "low", "banana"],
            "most severe first; an unknown token sorts LAST, never in the middle"
        );
        assert_eq!(rows[0].cve_id, "CVE-2021-10");
        assert_eq!(rows[0].fixed_version.as_deref(), Some("0.15.3"));

        // A different scan type is a different inventory.
        svc.record_findings(&digest, "trivy", &[mk("CVE-9999-1", "critical", "other")])
            .await
            .expect("record other scan type");
        let grype = svc
            .fetch_findings(&digest, "grype", 50)
            .await
            .expect("fetch");
        assert_eq!(grype.len(), 4, "the trivy row must not join this list");

        // Rescan: same keys, refreshed severity — upsert, not accumulate.
        svc.record_findings(&digest, "grype", &[mk("CVE-2021-30", "medium", "werkzeug")])
            .await
            .expect("re-record");
        let rows = svc
            .fetch_findings(&digest, "grype", 50)
            .await
            .expect("fetch");
        assert_eq!(rows.len(), 4, "upsert in place");
        let updated = rows
            .iter()
            .find(|r| r.cve_id == "CVE-2021-30")
            .expect("row still present");
        assert_eq!(updated.severity, "medium");

        // Empty is a no-op, never a delete.
        svc.record_findings(&digest, "grype", &[])
            .await
            .expect("empty record");
        assert_eq!(
            svc.fetch_findings(&digest, "grype", 50)
                .await
                .expect("fetch")
                .len(),
            4,
            "an empty report must not erase detail recorded earlier"
        );

        // The limit is applied, and applied AFTER the ordering, so a truncated
        // list keeps the most severe findings rather than an arbitrary slice.
        let capped = svc
            .fetch_findings(&digest, "grype", 2)
            .await
            .expect("fetch");
        assert_eq!(capped.len(), 2);
        assert_eq!(capped[0].severity, "critical");

        let _ = sqlx::query("DELETE FROM proxy_scan_findings WHERE checksum_sha256 = $1")
            .bind(&digest)
            .execute(&pool)
            .await;
    }

    #[test]
    fn inconclusive_is_pending_open_locked_closed() {
        // Over-cap / budget / scan-error: fail-open serves-with-pending,
        // fail-closed never serves unscanned bytes.
        assert_eq!(
            decide_inconclusive(ProxyScanAction::FailOpen),
            InconclusiveOutcome::ServePending
        );
        assert_eq!(
            decide_inconclusive(ProxyScanAction::FailClosed),
            InconclusiveOutcome::Locked
        );
    }

    fn stored(
        verdict: &str,
        scanned_at: DateTime<Utc>,
        scanner_version: Option<&str>,
        pin_identity: Option<&str>,
        components_cataloged: Option<i32>,
    ) -> StoredProxyVerdict {
        StoredProxyVerdict {
            row: row(verdict, scanned_at, scanner_version),
            pin_identity: pin_identity.map(str::to_string),
            components_cataloged,
        }
    }

    /// #4514: what a proxy-cache fast path may do with a scanning Remote's
    /// cached body, from the verdict stored for its digest.
    #[test]
    fn cache_scan_gate_truth_table_4514() {
        use CacheScanGate::*;
        let now = Utc::now();
        let fresh = now - Duration::days(1);
        let expired = now - Duration::days(31);
        let live = Some("grype-0.84.0");
        let gate = |s: Option<&StoredProxyVerdict>, v, action, sg| {
            decide_cache_scan_gate(s, v, action, sg, 30, now)
        };
        let closed = ProxyScanAction::FailClosed;
        let open = ProxyScanAction::FailOpen;
        let any = ProxySeverityGate::BlockOnAny;

        let clean = stored(VERDICT_CLEAN, fresh, live, Some("python|foo|1.0"), Some(3));
        let vulnerable = stored(
            VERDICT_VULNERABLE,
            fresh,
            live,
            Some("python|foo|1.0"),
            Some(3),
        );

        // A fresh vulnerable verdict blocks under both enforcing actions.
        assert_eq!(gate(Some(&vulnerable), live, closed, any), Block);
        assert_eq!(gate(Some(&vulnerable), live, open, any), Block);
        // ... with the live version unknown too: it only gates `clean` reuse.
        assert_eq!(gate(Some(&vulnerable), None, closed, any), Block);

        // A fresh clean verdict serves under both actions.
        assert_eq!(gate(Some(&clean), live, closed, any), Serve);
        assert_eq!(gate(Some(&clean), live, open, any), Serve);

        // Fail-closed: no verdict, a stale one, an unprovable clean one
        // (#2976) or a clean one that graded nothing (#3396) is not for a
        // fast path.
        assert_eq!(gate(None, live, closed, any), NotForFastPath);
        let stale_clean = stored(VERDICT_CLEAN, expired, live, None, Some(3));
        assert_eq!(gate(Some(&stale_clean), live, closed, any), NotForFastPath);
        assert_eq!(gate(Some(&clean), None, closed, any), NotForFastPath);
        let graded_nothing = stored(VERDICT_CLEAN, fresh, live, None, Some(0));
        assert_eq!(
            gate(Some(&graded_nothing), live, closed, any),
            NotForFastPath
        );
        // #4952: a clean verdict graded as a coordinate the request names
        // (here a Go module) or graded with no pin at all (an on-demand
        // rescan) pertains to one request only; a fast path has none.
        let go_pin = Some("go|example.com/m|v1.0.0");
        let request_pinned = stored(VERDICT_CLEAN, fresh, live, go_pin, Some(3));
        assert_eq!(
            gate(Some(&request_pinned), live, closed, any),
            NotForFastPath
        );
        let unpinned = stored(VERDICT_CLEAN, fresh, live, None, Some(3));
        assert_eq!(gate(Some(&unpinned), live, closed, any), NotForFastPath);
        assert_eq!(gate(Some(&request_pinned), live, open, any), Serve);
        // A blocking verdict refuses whatever coordinate it was graded as.
        let vulnerable_go = stored(VERDICT_VULNERABLE, fresh, live, go_pin, Some(3));
        assert_eq!(gate(Some(&vulnerable_go), live, closed, any), Block);
        let errored = stored(VERDICT_ERROR, fresh, live, None, None);
        assert_eq!(gate(Some(&errored), live, closed, any), NotForFastPath);
        let stale_vulnerable = stored(VERDICT_VULNERABLE, expired, live, None, Some(3));
        assert_eq!(
            gate(Some(&stale_vulnerable), live, closed, any),
            NotForFastPath
        );

        // Fail-open: the buffered gate would serve all of those `pending`.
        assert_eq!(gate(None, live, open, any), Serve);
        assert_eq!(gate(Some(&stale_vulnerable), live, open, any), Serve);
        assert_eq!(gate(Some(&graded_nothing), live, open, any), Serve);

        // A vulnerable verdict below an opted-in threshold serves (#3243);
        // an ungraded one (no max_severity) blocks under every gate.
        let mut low = vulnerable.clone();
        low.row.max_severity = Some("low".to_string());
        let high_threshold = ProxySeverityGate::Threshold(Severity::High);
        assert_eq!(gate(Some(&low), live, closed, high_threshold), Serve);
        assert_eq!(gate(Some(&vulnerable), live, closed, high_threshold), Block);

        // Record-only never refuses, whatever is stored.
        for record_only in [
            (ProxyScanAction::RecordOnly, ProxySeverityGate::RecordOnly),
            (closed, ProxySeverityGate::RecordOnly),
        ] {
            assert_eq!(
                gate(Some(&vulnerable), live, record_only.0, record_only.1),
                Serve
            );
            assert_eq!(gate(None, live, record_only.0, record_only.1), Serve);
        }
    }

    // -----------------------------------------------------------------------
    // Vulnerability-DB update grace (#6300)
    // -----------------------------------------------------------------------

    const LIVE: &str = "grype-0.120.1+db-2026-11-19";
    const PREVIOUS: &str = "grype-0.120.1+db-2026-11-18";
    const TWO_BEHIND: &str = "grype-0.120.1+db-2026-11-17";
    const OPEN: ProxyScanAction = ProxyScanAction::FailOpen;
    const CLOSED: ProxyScanAction = ProxyScanAction::FailClosed;

    /// A grace for `LIVE` whose windows (both of `window`) began `age` ago.
    fn grace_aged(now: DateTime<Utc>, age: Duration, window: Duration) -> DbUpdateGrace {
        DbUpdateGrace {
            live: LIVE.to_string(),
            previous: Some(PREVIOUS.to_string()),
            serving: GraceWindow::new(now, age, window),
            fail_closed: GraceWindow::new(now, age, window),
            newer: Vec::new(),
        }
    }

    fn windows(pairs: &[(&str, &str)]) -> DbGraceWindows {
        let map: std::collections::HashMap<String, String> = pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        DbGraceWindows::from_env(|k| map.get(k).cloned())
    }

    /// The default depends on the action: 6 h for fail_open / record_only,
    /// off for fail_closed unless the operator opts in, each with its own
    /// ceiling. Bad values keep the default (cases from #6307, credit
    /// nicola-preda: `-3`, `1.5`, an overflowing number).
    #[test]
    fn db_grace_windows_default_per_action_and_parse_whole_hours() {
        let unset = windows(&[]);
        assert_eq!(unset.serving, Duration::hours(6));
        assert_eq!(unset.fail_closed, Duration::zero(), "fail_closed is opt-in");
        assert_eq!(unset.for_action(OPEN), Duration::hours(6));
        assert_eq!(
            unset.for_action(ProxyScanAction::RecordOnly),
            Duration::hours(6)
        );
        assert_eq!(unset.for_action(CLOSED), Duration::zero());
        assert!(unset.any());
        assert!(!windows(&[(DB_GRACE_ENV, "0")]).any());

        let set = windows(&[(DB_GRACE_ENV, "12"), (DB_GRACE_FAIL_CLOSED_ENV, "4")]);
        assert_eq!(
            (set.serving, set.fail_closed),
            (Duration::hours(12), Duration::hours(4))
        );
        let clamped = windows(&[(DB_GRACE_ENV, "1000"), (DB_GRACE_FAIL_CLOSED_ENV, "1000")]);
        assert_eq!(
            (clamped.serving, clamped.fail_closed),
            (Duration::hours(72), Duration::hours(24))
        );
        for junk in ["-3", "1.5", "6h", "a day", "9223372036854775807999", "  "] {
            let w = windows(&[(DB_GRACE_ENV, junk), (DB_GRACE_FAIL_CLOSED_ENV, junk)]);
            assert_eq!(
                (w.serving, w.fail_closed),
                (Duration::hours(6), Duration::zero()),
                "{junk:?}"
            );
        }
    }

    #[test]
    fn provenance_compares_the_db_build_only_for_the_same_binary() {
        assert_eq!(
            split_scanner_version(LIVE),
            ("grype-0.120.1", Some("2026-11-19"))
        );
        assert_eq!(
            split_scanner_version("grype-0.120.1"),
            ("grype-0.120.1", None)
        );
        assert_eq!(split_scanner_version("grype+db-"), ("grype+db-", None));
        assert_eq!(compare_provenance(LIVE, LIVE), DbProvenance::Same);
        assert_eq!(compare_provenance(PREVIOUS, LIVE), DbProvenance::OlderDb);
        assert_eq!(compare_provenance(LIVE, PREVIOUS), DbProvenance::NewerDb);
        // A binary upgrade is never a DB update, whatever the dates say.
        assert_eq!(
            compare_provenance("grype-0.119.0+db-2026-11-18", LIVE),
            DbProvenance::Different
        );
        // No DB build on either side: nothing to compare.
        assert_eq!(
            compare_provenance("grype-0.120.1", LIVE),
            DbProvenance::Different
        );
        // A build that is not a YYYY-MM-DD date cannot be ordered.
        for odd in [
            "2026-11-1",
            "20261118",
            "2026-11-18T00",
            "abcd-ef-gh",
            "9999",
        ] {
            assert_eq!(
                compare_provenance(&format!("grype-0.120.1+db-{odd}"), LIVE),
                DbProvenance::Different,
                "{odd}"
            );
        }
    }

    /// The grace covers only the newest build below the live one, only within
    /// the action's window, or within its extension while a re-grade is
    /// queued, and only for the version it was recorded for.
    #[test]
    fn db_grace_vouches_only_for_the_previous_build_while_open() {
        let now = Utc::now();
        let six = Duration::hours(6);
        let open = grace_aged(now, Duration::hours(1), six);
        let past = grace_aged(now, Duration::hours(7), six);
        let beyond = grace_aged(now, Duration::hours(13), six);

        assert!(open.vouches_for(PREVIOUS, LIVE, OPEN, now, false));
        assert!(
            !past.vouches_for(PREVIOUS, LIVE, OPEN, now, false),
            "past the window"
        );
        assert!(
            past.vouches_for(PREVIOUS, LIVE, OPEN, now, true),
            "a queued re-grade keeps it, for one more window"
        );
        assert!(past.only_a_queued_regrade_vouches(PREVIOUS, LIVE, OPEN, now));
        assert!(!open.only_a_queued_regrade_vouches(PREVIOUS, LIVE, OPEN, now));
        assert!(
            !beyond.vouches_for(PREVIOUS, LIVE, OPEN, now, true),
            "bounded"
        );
        assert!(!beyond.only_a_queued_regrade_vouches(PREVIOUS, LIVE, OPEN, now));
        assert!(
            !open.vouches_for(TWO_BEHIND, LIVE, OPEN, now, true),
            "two builds behind is re-scanned"
        );
        assert!(
            !open.vouches_for("grype-0.119.0+db-2026-11-18", LIVE, OPEN, now, false),
            "a binary upgrade is re-scanned"
        );
        assert!(!open.vouches_for("grype-0.120.1", LIVE, OPEN, now, false));
        assert!(
            !open.vouches_for(PREVIOUS, "grype-0.120.1+db-2026-11-20", OPEN, now, false),
            "a grace recorded for another live version says nothing"
        );
        // Between the previous build and the live one (a build this fleet
        // never recorded) is at least as current as the previous one.
        let skipped = DbUpdateGrace {
            previous: Some("grype-0.120.1+db-2026-11-16".to_string()),
            ..open.clone()
        };
        assert!(skipped.vouches_for(TWO_BEHIND, LIVE, OPEN, now, false));
        // Nothing recorded below the live version: no grace at all.
        let first = DbUpdateGrace {
            previous: None,
            ..open.clone()
        };
        assert!(!first.vouches_for(PREVIOUS, LIVE, OPEN, now, false));
        // A window of 0 for the action is no grace for it.
        let fail_closed_off = DbUpdateGrace {
            fail_closed: GraceWindow::new(now, Duration::hours(1), Duration::zero()),
            ..open.clone()
        };
        assert!(fail_closed_off.vouches_for(PREVIOUS, LIVE, OPEN, now, false));
        assert!(!fail_closed_off.vouches_for(PREVIOUS, LIVE, CLOSED, now, true));
    }

    /// Only the exact build is fresh on its own; an OLDER build is reusable
    /// only through the grace, per action, within the TTL.
    #[test]
    fn freshness_is_the_exact_build_and_reuse_follows_the_grace() {
        let now = Utc::now();
        let scanned = now - Duration::days(1);
        let newer = "grype-0.120.1+db-2026-11-20";
        assert!(verdict_is_fresh(scanned, Some(LIVE), Some(LIVE), 30, now));
        assert!(!verdict_is_fresh(scanned, Some(newer), Some(LIVE), 30, now));
        assert!(!verdict_is_fresh(
            scanned,
            Some(PREVIOUS),
            Some(LIVE),
            30,
            now
        ));
        assert!(
            !verdict_is_reusable(
                VERDICT_CLEAN,
                scanned,
                Some(newer),
                Some(LIVE),
                CLOSED,
                30,
                now
            ),
            "no grace recorded: a newer build is not trusted"
        );

        let open = grace_aged(now, Duration::hours(1), Duration::hours(6));
        let reuse = |action, scanned_at, grace: Option<&DbUpdateGrace>, queued| {
            verdict_is_reusable_under(
                VERDICT_CLEAN,
                scanned_at,
                Some(PREVIOUS),
                Some(LIVE),
                action,
                30,
                now,
                grace,
                queued,
            )
        };
        assert!(!reuse(OPEN, scanned, None, false), "no grace recorded");
        assert!(reuse(OPEN, scanned, Some(&open), false));
        assert!(reuse(CLOSED, scanned, Some(&open), false), "opted in");
        assert!(
            !reuse(OPEN, now - Duration::days(31), Some(&open), true),
            "the TTL still applies"
        );
        // Unknown live version: no grace, so fail_closed does not reuse it.
        assert!(!verdict_is_reusable_under(
            VERDICT_CLEAN,
            scanned,
            Some(PREVIOUS),
            None,
            CLOSED,
            30,
            now,
            Some(&open),
            true
        ));
    }

    /// Through the process record, as the serve paths see it.
    #[test]
    fn serve_decisions_follow_the_recorded_grace() {
        let now = Utc::now();
        let scanned = now - Duration::days(1);
        let row = |verdict: &str, version: &str| ProxyScanRow {
            checksum_sha256: "d".repeat(64),
            scan_type: "grype".to_string(),
            verdict: verdict.to_string(),
            findings_count: 0,
            critical_count: 0,
            high_count: 0,
            medium_count: 0,
            low_count: 0,
            max_severity: None,
            scanner_version: Some(version.to_string()),
            scanned_at: scanned,
        };
        let clean = row(VERDICT_CLEAN, PREVIOUS);
        assert_eq!(
            decide_serve(Some(&clean), Some(LIVE), OPEN, 30, now),
            ServeDecision::ServePendingScanAsync,
            "no grace recorded in this process"
        );

        // fail_open has a window, fail_closed none (the default).
        set_db_grace_for_test(DbUpdateGrace {
            fail_closed: None,
            ..grace_aged(now, Duration::hours(1), Duration::hours(6))
        });
        assert_eq!(
            decide_serve(Some(&clean), Some(LIVE), OPEN, 30, now),
            ServeDecision::ServeCached
        );
        assert_eq!(
            decide_serve(Some(&clean), Some(LIVE), CLOSED, 30, now),
            ServeDecision::ScanInline,
            "fail_closed re-scans unless the operator opted in"
        );
        assert_eq!(
            decide_serve(
                Some(&row(VERDICT_VULNERABLE, PREVIOUS)),
                Some(LIVE),
                OPEN,
                30,
                now
            ),
            ServeDecision::BlockCached,
            "a vulnerable verdict keeps blocking through the grace"
        );
        assert_eq!(
            decide_serve(
                Some(&row(VERDICT_CLEAN, TWO_BEHIND)),
                Some(LIVE),
                OPEN,
                30,
                now
            ),
            ServeDecision::ServePendingScanAsync
        );

        // fail_closed opted in, past the window: only a queued re-grade
        // keeps it, and only for one more window.
        set_db_grace_for_test(grace_aged(now, Duration::hours(7), Duration::hours(6)));
        assert!(grace_extension_possible(
            Some(PREVIOUS),
            Some(LIVE),
            CLOSED,
            now
        ));
        assert_eq!(
            decide_serve(Some(&clean), Some(LIVE), CLOSED, 30, now),
            ServeDecision::ScanInline
        );
        assert_eq!(
            decide_serve_with_queued_regrade(Some(&clean), Some(LIVE), CLOSED, 30, now, true),
            ServeDecision::ServeCached
        );
        assert!(!grace_extension_possible(
            Some(TWO_BEHIND),
            Some(LIVE),
            CLOSED,
            now
        ));

        // Opted in and open: the fast paths leave a grace-only clean verdict
        // to the buffered gate, which queues its re-grade; a vulnerable one
        // still blocks there.
        set_db_grace_for_test(grace_aged(now, Duration::hours(1), Duration::hours(6)));
        let pinned = |verdict: &str| StoredProxyVerdict {
            row: row(verdict, PREVIOUS),
            pin_identity: Some("python|foo|1.0".to_string()),
            components_cataloged: Some(1),
        };
        assert_eq!(
            decide_serve(Some(&clean), Some(LIVE), CLOSED, 30, now),
            ServeDecision::ServeCached
        );
        assert_eq!(
            decide_cache_scan_gate(
                Some(&pinned(VERDICT_CLEAN)),
                Some(LIVE),
                CLOSED,
                ProxySeverityGate::BlockOnAny,
                30,
                now
            ),
            CacheScanGate::NotForFastPath
        );
        assert_eq!(
            decide_cache_scan_gate(
                Some(&pinned(VERDICT_VULNERABLE)),
                Some(LIVE),
                CLOSED,
                ProxySeverityGate::BlockOnAny,
                30,
                now
            ),
            CacheScanGate::Block
        );
    }

    /// A NEWER build's verdict is reused (the rolling-upgrade ping-pong) only
    /// while the fleet first saw that build within the trust window. A build
    /// rolled back because it graded something wrongly therefore stops being
    /// trusted at the end of that window, instead of standing for the whole
    /// TTL; a newer build this replica never loaded is not trusted at all.
    #[test]
    fn a_rolled_back_newer_build_is_trusted_only_within_its_window() {
        let now = Utc::now();
        let scanned = now - Duration::hours(2);
        let rolled_back = "grype-0.120.1+db-2026-11-20";
        let reuse = |grace: &DbUpdateGrace, action| {
            verdict_is_reusable_under(
                VERDICT_CLEAN,
                scanned,
                Some(rolled_back),
                Some(LIVE),
                action,
                30,
                now,
                Some(grace),
                false,
            )
        };
        // Both windows 6 h (fail_closed opted in); the newer build was first
        // seen an hour ago.
        let base = grace_aged(now, Duration::days(3), Duration::hours(6));
        let recent = DbUpdateGrace {
            newer: vec![(rolled_back.to_string(), now - Duration::hours(1))],
            ..base.clone()
        };
        assert!(reuse(&recent, OPEN));
        assert!(
            reuse(&recent, CLOSED),
            "opted in: graded with more advisories"
        );
        // The defaults: fail_closed has no window, so it re-scans exactly as
        // before 1.13.0 even for a recent newer build; fail_open trusts it.
        let defaults = DbUpdateGrace {
            fail_closed: None,
            ..recent.clone()
        };
        assert!(reuse(&defaults, OPEN));
        assert!(
            !reuse(&defaults, CLOSED),
            "fail_closed at 0 must re-scan a newer build's verdict"
        );
        // Each action's own window bounds it: a 1 h fail_closed window has
        // lapsed for a build seen 2 h ago while the 6 h one has not.
        let short_closed = DbUpdateGrace {
            newer: vec![(rolled_back.to_string(), now - Duration::hours(2))],
            fail_closed: GraceWindow::new(now, Duration::days(3), Duration::hours(1)),
            ..base.clone()
        };
        assert!(reuse(&short_closed, OPEN));
        assert!(!reuse(&short_closed, CLOSED));
        let lapsed = DbUpdateGrace {
            newer: vec![(rolled_back.to_string(), now - Duration::hours(7))],
            ..base.clone()
        };
        assert!(
            !reuse(&lapsed, OPEN),
            "rolled back: re-scanned after the window"
        );
        assert!(!reuse(&lapsed, CLOSED));
        assert!(!reuse(&base, OPEN), "never loaded: not trusted");
        // Another binary's newer build is never trusted.
        let other = DbUpdateGrace {
            newer: vec![(
                "grype-0.121.0+db-2026-11-20".to_string(),
                now - Duration::hours(1),
            )],
            ..base.clone()
        };
        assert!(!other.trusts_newer("grype-0.121.0+db-2026-11-20", LIVE, OPEN, now));
        // Both windows 0: no trust at all, the behaviour before 1.13.0.
        assert_eq!(
            DbGraceWindows {
                serving: Duration::zero(),
                fail_closed: Duration::zero()
            }
            .newer_build_trust(),
            Duration::zero()
        );
    }

    #[test]
    fn only_a_verdict_from_an_older_db_build_needs_a_regrade() {
        assert!(verdict_needs_regrade(Some(PREVIOUS), Some(LIVE)));
        assert!(!verdict_needs_regrade(Some(LIVE), Some(LIVE)));
        assert!(!verdict_needs_regrade(Some(LIVE), Some(PREVIOUS)));
        assert!(!verdict_needs_regrade(None, Some(LIVE)));
        assert!(!verdict_needs_regrade(Some(PREVIOUS), None));
        assert!(!verdict_needs_regrade(
            Some("grype-0.119.0+db-2026-11-18"),
            Some(LIVE)
        ));
    }

    /// The window is anchored on the fleet-wide first sighting (a reload, as
    /// on a restart or another replica, does not reopen it), and the previous
    /// build is the newest same-binary BUILD below the live one, whenever it
    /// was recorded: a stale build recorded late (a pinned DB, a rollback, a
    /// new pod on an old bundled DB) does not become the previous build.
    #[tokio::test]
    async fn db_grace_is_anchored_on_the_first_sighting_and_the_newest_lower_build() {
        use crate::api::handlers::test_db_helpers as tdh;
        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        // A binary no other test uses, so its rows are this test's.
        let cli = format!("grype-6300.{}", uuid::Uuid::new_v4().simple());
        let token = |db: &str| format!("{cli}+db-{db}");
        sqlx::query(
            "INSERT INTO proxy_scan_db_versions (scanner_version, first_seen_at) VALUES \
             ($1, now() - interval '3 days'), ($2, now() - interval '2 days'), \
             ($3, now() - interval '1 day'), ($4, now() - interval '1 hour'), \
             ($5, now() - interval '1 hour'), ($6, now() - interval '3 days')",
        )
        .bind(token("2026-11-17"))
        .bind(token("2026-11-18"))
        // Another binary's newer build is not this one's previous version.
        .bind(format!("{cli}-other+db-2026-11-18"))
        // A stale build recorded LAST.
        .bind(token("2026-11-10"))
        // Newer than the live build: one seen within the trust window, one
        // seen long ago (a build since rolled back).
        .bind(token("2026-11-20"))
        .bind(token("2026-11-21"))
        .execute(&pool)
        .await
        .expect("seed earlier versions");

        let live = token("2026-11-19");
        let six = DbGraceWindows {
            serving: Duration::hours(6),
            fail_closed: Duration::hours(2),
        };
        let first = load_db_update_grace(&pool, &live, six)
            .await
            .expect("first load");
        assert_eq!(
            first.previous.as_deref(),
            Some(token("2026-11-18").as_str()),
            "the newest build below the live one, not the last one recorded"
        );
        assert!(!first.covers_build(&token("2026-11-10"), &live));
        assert_eq!(
            first
                .newer
                .iter()
                .map(|(b, _)| b.clone())
                .collect::<Vec<_>>(),
            vec![token("2026-11-20")],
            "only a newer build first seen within the trust window"
        );
        let now = Utc::now();
        // Seen an hour ago: 5 h left of the 6 h serving window, 1 h of the
        // 2 h fail_closed one.
        let o = ProxyScanAction::FailOpen;
        let c = ProxyScanAction::FailClosed;
        assert!(first.trusts_newer(&token("2026-11-20"), &live, o, now));
        assert!(first.trusts_newer(&token("2026-11-20"), &live, c, now));
        assert!(!first.trusts_newer(&token("2026-11-21"), &live, o, now));
        let later = now + Duration::minutes(90);
        assert!(first.trusts_newer(&token("2026-11-20"), &live, o, later));
        assert!(!first.trusts_newer(&token("2026-11-20"), &live, c, later));
        assert!(!first.trusts_newer(&token("2026-11-20"), &live, o, now + Duration::hours(6)));
        assert!(!first.covers_build(&token("2026-11-17"), &live));
        let serving = first.serving.expect("serving window");
        let fail_closed = first.fail_closed.expect("fail_closed window");
        assert!(serving.until > Utc::now() + Duration::hours(5));
        assert!(fail_closed.until < Utc::now() + Duration::hours(2));
        assert_eq!(serving.queued_until - serving.until, Duration::hours(6));

        // Reloaded an hour "later" (the row aged): the same end, give or take
        // the time between the two loads.
        sqlx::query(
            "UPDATE proxy_scan_db_versions SET first_seen_at = first_seen_at - interval '1 hour' \
             WHERE scanner_version = $1",
        )
        .bind(&live)
        .execute(&pool)
        .await
        .expect("age");
        let again = load_db_update_grace(&pool, &live, six)
            .await
            .expect("second load");
        let moved = (serving.until - again.serving.expect("window").until).num_seconds();
        assert!(
            (3590..=3610).contains(&moved),
            "a reload must not reopen the window ({moved}s)"
        );

        sqlx::query("DELETE FROM proxy_scan_db_versions WHERE starts_with(scanner_version, $1)")
            .bind(&cli)
            .execute(&pool)
            .await
            .expect("cleanup");
    }
}
