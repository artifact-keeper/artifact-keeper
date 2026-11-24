//! Disk usage thresholds on the storage volume (#5191).
//!
//! The storage quotas count what the instance stores; they do not see the
//! volume it stores it on. Per-repository quotas can add up to more than the
//! disk, proxy caches grow on their own, and deleted artifacts wait in the
//! trash, so with the filesystem backend the first sign of a full disk used to
//! be a failed write once it was already full. Two thresholds, read from the
//! filesystem itself, stop that before it happens:
//!
//! * **Warn** (`STORAGE_DISK_WARN_PERCENT`, default 95): a `warn` log line
//!   when usage crosses it, repeated at most every [`REPEAT_LOG_EVERY`] while
//!   it stays there, and `ak_storage_disk_state` = 1.
//! * **Block** (`STORAGE_DISK_BLOCK_PERCENT`, default off): writes that store
//!   new bytes are refused with `403 DISK_THRESHOLD_EXCEEDED`
//!   ([`QuotaRefusal::disk_threshold`]): before the body is read on the
//!   upload routes ([`super::http::upload_admission`]), once the size is known
//!   in the shared publish admission ([`super::storage::instance_denial`],
//!   which every caller reaches, trusted replication included), and in the
//!   migration importer (which pauses the job) and filesystem backups.
//!   Restores and OCI blob mounts are exempt. A write whose declared
//!   `Content-Length` would take the volume over the threshold is refused
//!   too. Reads, deletes, lifecycle and garbage collection keep
//!   working, so an operator can free space without a restart. A remote
//!   (proxy) repository keeps serving what it fetches upstream, streamed, but
//!   does not cache it. Writes resume once usage is
//!   [`UNBLOCK_HYSTERESIS_PERCENT`] point below the threshold, so a volume
//!   hovering at the threshold does not flap.
//!
//! Usage is `df`'s figure: bytes in use over bytes in use plus bytes
//! available to an unprivileged writer (`statvfs`), so space reserved for
//! root counts as full. The volumes measured are `STORAGE_PATH` when the
//! storage backend is `filesystem`, and `AK_UPLOAD_STAGING_DIR` when it is
//! set; the fullest one decides. With an object-store backend (S3, Azure,
//! GCS) there is no volume to measure and only the staging directory, if set,
//! is watched. A repository with its own filesystem storage location on
//! another volume is not measured.
//!
//! A background task ([`spawn_monitor`]) takes the reading every
//! `STORAGE_DISK_CHECK_INTERVAL_SECS` (default 5), every second once the
//! volume is at a threshold ([`next_wait`]), on a blocking thread; the
//! request path only reads the cached result, so no request ever waits on
//! `statvfs` (which can stall on a network filesystem). Until the first
//! reading, and when both thresholds are off, nothing is refused. A failed
//! reading keeps the last state.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, RwLock};
use std::time::{Duration, Instant};

use serde::Serialize;
use utoipa::ToSchema;

use super::QuotaRefusal;
use crate::config::{Config, QuotaSettings};
use crate::services::repository_service::{QuotaDenial, QuotaScope};

/// How far (in percentage points) usage must fall below the block threshold
/// before writes resume.
pub const UNBLOCK_HYSTERESIS_PERCENT: f64 = 1.0;

/// While the volume stays above a threshold the warning is repeated at most
/// this often.
pub const REPEAT_LOG_EVERY: Duration = Duration::from_secs(600);

/// One volume's `statvfs` figures, in bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, ToSchema)]
pub struct DiskReading {
    /// The filesystem's size (`f_blocks`).
    pub total_bytes: u64,
    /// Bytes in use (`f_blocks - f_bfree`).
    pub used_bytes: u64,
    /// Bytes an unprivileged writer can still use (`f_bavail`).
    pub free_bytes: u64,
}

impl DiskReading {
    /// What usage is measured against: used plus available, as `df` does.
    pub fn capacity_bytes(&self) -> u64 {
        self.used_bytes.saturating_add(self.free_bytes)
    }

    /// Usage in percent of [`Self::capacity_bytes`]; `0` for an empty
    /// filesystem.
    pub fn used_percent(&self) -> f64 {
        percent_of(self.used_bytes, self.capacity_bytes())
    }
}

fn percent_of(part: u64, whole: u64) -> f64 {
    if whole == 0 {
        0.0
    } else {
        part as f64 * 100.0 / whole as f64
    }
}

/// `ok`, `warning` (at or above the warning threshold) or `blocked` (writes
/// refused).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum DiskState {
    Ok,
    Warning,
    Blocked,
}

impl DiskState {
    /// The `ak_storage_disk_state` value.
    fn gauge(self) -> f64 {
        match self {
            Self::Ok => 0.0,
            Self::Warning => 1.0,
            Self::Blocked => 2.0,
        }
    }
}

/// The state after a reading of `used_percent`, coming from `previous`.
/// A threshold of `0` is off.
pub(crate) fn next_state(previous: DiskState, used_percent: f64, warn: u8, block: u8) -> DiskState {
    if block > 0 {
        let block = f64::from(block);
        if used_percent >= block
            || (previous == DiskState::Blocked && used_percent > block - UNBLOCK_HYSTERESIS_PERCENT)
        {
            return DiskState::Blocked;
        }
    }
    if warn > 0 && used_percent >= f64::from(warn) {
        DiskState::Warning
    } else {
        DiskState::Ok
    }
}

/// The last reading of the fullest volume, and the state it put the
/// instance in.
#[derive(Debug, Clone, PartialEq)]
struct Snapshot {
    volume: &'static str,
    reading: DiskReading,
    state: DiskState,
    block_percent: u8,
}

static SNAPSHOT: RwLock<Option<Snapshot>> = RwLock::new(None);
/// `SNAPSHOT.state == Blocked`, for the proxy cache-fill check.
static BLOCKED: AtomicBool = AtomicBool::new(false);

fn snapshot() -> Option<Snapshot> {
    SNAPSHOT.read().unwrap_or_else(|p| p.into_inner()).clone()
}

/// Whether `declared` more bytes would take the volume to the block
/// threshold.
fn would_cross(reading: &DiskReading, block_percent: u8, declared: u64) -> bool {
    declared > 0
        && u128::from(reading.used_bytes.saturating_add(declared)) * 100
            >= u128::from(reading.capacity_bytes()) * u128::from(block_percent)
}

/// The refusal of a write that declares `declared` bytes under `snap`.
fn refusal_under(snap: &Snapshot, declared: Option<u64>) -> Option<QuotaRefusal> {
    if snap.block_percent == 0 {
        return None;
    }
    let refused = snap.state == DiskState::Blocked
        || declared.is_some_and(|d| would_cross(&snap.reading, snap.block_percent, d));
    refused.then(|| {
        QuotaRefusal::disk_threshold(
            snap.reading.capacity_bytes(),
            snap.reading.used_bytes,
            snap.block_percent,
            declared,
        )
    })
}

/// Pre-body admission: the refusal of a write that declares `declared`
/// bytes (`None` without a `Content-Length`), or `None` to admit it. Every
/// write is refused while the volume is blocked; below it, one whose declared
/// length would take the volume to the threshold. Reads the cached reading
/// only.
pub fn refusal(declared: Option<u64>) -> Option<QuotaRefusal> {
    refusal_under(&snapshot()?, declared)
}

/// The service-layer form of [`refusal`] for a write of `additional_bytes`
/// whose size is known: `None` for a write that adds nothing.
pub fn denial(additional_bytes: i64) -> Option<QuotaDenial> {
    let additional = u64::try_from(additional_bytes).ok().filter(|n| *n > 0)?;
    let snap = snapshot()?;
    refusal_under(&snap, Some(additional))?;
    let mut denial = QuotaDenial::new(
        QuotaScope::Disk,
        i64::try_from(snap.reading.capacity_bytes()).unwrap_or(i64::MAX),
        i64::try_from(snap.reading.used_bytes).unwrap_or(i64::MAX),
    )
    .with_additional(additional_bytes);
    denial.threshold_percent = Some(snap.block_percent);
    Some(denial)
}

/// Whether the volume is blocked. A remote (proxy) repository asks before it
/// caches an upstream response: while blocked it serves the response without
/// writing it to storage.
pub fn cache_fills_blocked() -> bool {
    BLOCKED.load(Ordering::Relaxed)
}

/// The `disk` object of `GET /api/v1/system/quota`.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct DiskStatus {
    /// Whether any threshold is on and a volume is measured.
    pub enabled: bool,
    /// `STORAGE_DISK_WARN_PERCENT`; `0` is off.
    pub warn_percent: u8,
    /// `STORAGE_DISK_BLOCK_PERCENT`; `0` is off.
    pub block_percent: u8,
    /// `storage` or `staging`: the fullest volume measured.
    pub volume: Option<String>,
    /// That volume's last reading; `None` before the first one.
    pub reading: Option<DiskReading>,
    /// Its usage in percent, two decimals.
    pub used_percent: Option<f64>,
    pub state: DiskState,
}

/// The current thresholds and last reading.
pub fn status(settings: &QuotaSettings) -> DiskStatus {
    let snap = snapshot();
    DiskStatus {
        enabled: snap.is_some(),
        warn_percent: settings.disk_warn_percent,
        block_percent: settings.disk_block_percent,
        volume: snap.as_ref().map(|s| s.volume.to_string()),
        reading: snap.as_ref().map(|s| s.reading),
        used_percent: snap
            .as_ref()
            .map(|s| (s.reading.used_percent() * 100.0).round() / 100.0),
        state: snap.map(|s| s.state).unwrap_or(DiskState::Ok),
    }
}

/// A volume the monitor measures.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Volume {
    /// The `volume` label of the gauges.
    pub label: &'static str,
    pub path: PathBuf,
}

/// The volumes to measure: `STORAGE_PATH` for the filesystem backend, and
/// `staging_dir` (`AK_UPLOAD_STAGING_DIR`) when set.
pub fn volumes(
    storage_backend: &str,
    storage_path: &str,
    staging_dir: Option<&str>,
) -> Vec<Volume> {
    let mut out = Vec::new();
    if storage_backend == "filesystem" && !storage_path.trim().is_empty() {
        out.push(Volume {
            label: "storage",
            path: PathBuf::from(storage_path),
        });
    }
    if let Some(dir) = staging_dir.map(str::trim).filter(|d| !d.is_empty()) {
        out.push(Volume {
            label: "staging",
            path: PathBuf::from(dir),
        });
    }
    out
}

/// `statvfs` of the filesystem holding `path`.
#[cfg(target_os = "linux")]
#[allow(clippy::unnecessary_cast)] // the field types differ between targets
pub fn measure(path: &Path) -> std::io::Result<DiskReading> {
    use std::os::unix::ffi::OsStrExt;
    let c_path = std::ffi::CString::new(path.as_os_str().as_bytes())?;
    // SAFETY: `statvfs` writes only into the struct it is handed, which is
    // plain data and valid when zeroed; `c_path` is NUL-terminated and
    // outlives the call.
    let mut st: libc::statvfs = unsafe { std::mem::zeroed() };
    if unsafe { libc::statvfs(c_path.as_ptr(), &mut st) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    let block = if st.f_frsize > 0 {
        st.f_frsize as u64
    } else {
        st.f_bsize as u64
    };
    let total = (st.f_blocks as u64).saturating_mul(block);
    let free_all = (st.f_bfree as u64).saturating_mul(block);
    Ok(DiskReading {
        total_bytes: total,
        used_bytes: total.saturating_sub(free_all),
        free_bytes: (st.f_bavail as u64).saturating_mul(block),
    })
}

/// No `statvfs` here: the thresholds are not enforced on this platform.
#[cfg(not(target_os = "linux"))]
pub fn measure(_path: &Path) -> std::io::Result<DiskReading> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "disk usage thresholds are only measured on Linux",
    ))
}

/// What the monitor remembers between readings for its log lines.
struct LogState {
    state: DiskState,
    last_logged: Option<Instant>,
    last_error: Option<Instant>,
}

static LOG: Mutex<LogState> = Mutex::new(LogState {
    state: DiskState::Ok,
    last_logged: None,
    last_error: None,
});

/// Whether a line about `state` is due: on a change, or every
/// [`REPEAT_LOG_EVERY`] while it is not `ok`.
fn log_due(previous: DiskState, state: DiskState, last: Option<Instant>, now: Instant) -> bool {
    previous != state
        || (state != DiskState::Ok
            && last.is_none_or(|at| now.duration_since(at) >= REPEAT_LOG_EVERY))
}

/// Apply one round of readings: the gauges, the state, its log line.
/// Volumes whose reading failed are `Err`; with no reading at all the last
/// state stays.
pub(crate) fn apply(
    settings: &QuotaSettings,
    readings: &[(&'static str, std::io::Result<DiskReading>)],
) {
    let mut fullest: Option<(&'static str, DiskReading)> = None;
    for (label, reading) in readings {
        match reading {
            Ok(r) => {
                metrics::gauge!("ak_storage_disk_total_bytes", "volume" => *label)
                    .set(r.total_bytes as f64);
                metrics::gauge!("ak_storage_disk_free_bytes", "volume" => *label)
                    .set(r.free_bytes as f64);
                metrics::gauge!("ak_storage_disk_used_percent", "volume" => *label)
                    .set(r.used_percent());
                if fullest.is_none_or(|(_, f)| r.used_percent() > f.used_percent()) {
                    fullest = Some((*label, *r));
                }
            }
            Err(e) => {
                let mut log = LOG.lock().unwrap_or_else(|p| p.into_inner());
                let now = Instant::now();
                if log
                    .last_error
                    .is_none_or(|at| now.duration_since(at) >= REPEAT_LOG_EVERY)
                {
                    log.last_error = Some(now);
                    tracing::warn!(volume = *label, error = %e, "disk usage reading failed; keeping the last state");
                }
            }
        }
    }
    let Some((volume, reading)) = fullest else {
        return;
    };
    let mut log = LOG.lock().unwrap_or_else(|p| p.into_inner());
    let previous = log.state;
    let state = next_state(
        previous,
        reading.used_percent(),
        settings.disk_warn_percent,
        settings.disk_block_percent,
    );
    *SNAPSHOT.write().unwrap_or_else(|p| p.into_inner()) = Some(Snapshot {
        volume,
        reading,
        state,
        block_percent: settings.disk_block_percent,
    });
    BLOCKED.store(state == DiskState::Blocked, Ordering::Relaxed);
    metrics::gauge!("ak_storage_disk_state").set(state.gauge());

    let now = Instant::now();
    if !log_due(previous, state, log.last_logged, now) {
        log.state = state;
        return;
    }
    log.state = state;
    log.last_logged = Some(now);
    let used_percent = (reading.used_percent() * 10.0).round() / 10.0;
    let (used, capacity) = (
        super::format_bytes(reading.used_bytes),
        super::format_bytes(reading.capacity_bytes()),
    );
    match state {
        DiskState::Blocked => tracing::warn!(
            volume,
            used_percent,
            free_bytes = reading.free_bytes,
            block_percent = settings.disk_block_percent,
            "storage volume is {used_percent}% full ({used} of {capacity}): writes are refused \
             with 403 DISK_THRESHOLD_EXCEEDED until disk is freed or storage is added; \
             downloads keep working"
        ),
        DiskState::Warning => tracing::warn!(
            volume,
            used_percent,
            free_bytes = reading.free_bytes,
            warn_percent = settings.disk_warn_percent,
            "storage volume is {used_percent}% full ({used} of {capacity}): free disk or add \
             storage"
        ),
        DiskState::Ok => tracing::info!(
            volume,
            used_percent,
            "storage volume is back below its disk thresholds ({used} of {capacity})"
        ),
    }
}

/// How long until the next reading: the configured interval while the
/// volume is below every threshold, at most [`PRESSURE_INTERVAL`] once it is
/// at the warn threshold or blocked, so a long upload session is checked
/// against a reading at most that old.
pub(crate) fn next_wait(interval: Duration, state: Option<DiskState>) -> Duration {
    match state {
        Some(DiskState::Warning | DiskState::Blocked) => interval.min(PRESSURE_INTERVAL),
        _ => interval,
    }
}

/// The reading interval under disk pressure.
pub const PRESSURE_INTERVAL: Duration = Duration::from_secs(1);

/// Start the background reading of the storage volumes, or `None` when both
/// thresholds are off or there is no volume to measure (an object-store
/// backend without `AK_UPLOAD_STAGING_DIR`).
pub fn spawn_monitor(
    config: &Config,
    shutdown: tokio_util::sync::CancellationToken,
) -> Option<tokio::task::JoinHandle<()>> {
    let settings = config.quotas.clone();
    metrics::gauge!("ak_storage_disk_threshold_percent", "level" => "warn")
        .set(f64::from(settings.disk_warn_percent));
    metrics::gauge!("ak_storage_disk_threshold_percent", "level" => "block")
        .set(f64::from(settings.disk_block_percent));
    if settings.disk_warn_percent == 0 && settings.disk_block_percent == 0 {
        return None;
    }
    let staging = std::env::var("AK_UPLOAD_STAGING_DIR").ok();
    let volumes = volumes(
        &config.storage_backend,
        &config.storage_path,
        staging.as_deref(),
    );
    if volumes.is_empty() {
        tracing::info!(
            storage_backend = %config.storage_backend,
            "disk usage thresholds do not apply to an object-store backend; not measured"
        );
        return None;
    }
    if cfg!(not(target_os = "linux")) {
        tracing::warn!("disk usage thresholds are only measured on Linux; not enforced");
        return None;
    }
    tracing::info!(
        warn_percent = settings.disk_warn_percent,
        block_percent = settings.disk_block_percent,
        interval_secs = settings.disk_check_interval_secs,
        volumes = ?volumes.iter().map(|v| v.path.display().to_string()).collect::<Vec<_>>(),
        "disk usage thresholds enabled"
    );
    let interval = Duration::from_secs(settings.disk_check_interval_secs.max(1));
    Some(tokio::spawn(async move {
        let mut wait = Duration::ZERO;
        loop {
            tokio::select! {
                _ = shutdown.cancelled() => return,
                _ = tokio::time::sleep(wait) => {}
            }
            let vols = volumes.clone();
            let readings = tokio::task::spawn_blocking(move || {
                vols.iter()
                    .map(|v| (v.label, measure(&v.path)))
                    .collect::<Vec<_>>()
            })
            .await;
            match readings {
                Ok(readings) => apply(&settings, &readings),
                Err(e) => tracing::warn!(error = %e, "disk usage reading task failed"),
            }
            wait = next_wait(interval, snapshot().map(|s| s.state));
        }
    }))
}

/// Put the volume in (or take it out of) the blocked state for a test in
/// another module: 99 % of 100 bytes used, blocked at 95 %.
#[cfg(test)]
#[allow(dead_code)]
pub(crate) fn block_for_tests(blocked: bool) {
    let snap = blocked.then_some(Snapshot {
        volume: "storage",
        reading: DiskReading {
            total_bytes: 100,
            used_bytes: 99,
            free_bytes: 1,
        },
        state: DiskState::Blocked,
        block_percent: 95,
    });
    *SNAPSHOT.write().unwrap_or_else(|p| p.into_inner()) = snap;
    BLOCKED.store(blocked, Ordering::Relaxed);
}

#[cfg(ak_test_shard = "services-1")]
#[cfg(test)]
mod tests {
    use super::*;

    const GIB: u64 = 1 << 30;

    fn reset_for_tests() {
        *SNAPSHOT.write().unwrap_or_else(|p| p.into_inner()) = None;
        BLOCKED.store(false, Ordering::Relaxed);
        let mut log = LOG.lock().unwrap_or_else(|p| p.into_inner());
        log.state = DiskState::Ok;
        log.last_logged = None;
        log.last_error = None;
    }

    async fn json_of(
        response: axum::response::Response,
    ) -> (axum::http::StatusCode, serde_json::Value) {
        use http_body_util::BodyExt;
        let status = response.status();
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        (status, serde_json::from_slice(&bytes).expect("json body"))
    }

    fn reading(used: u64, free: u64) -> DiskReading {
        DiskReading {
            total_bytes: used + free,
            used_bytes: used,
            free_bytes: free,
        }
    }

    fn settings(warn: u8, block: u8) -> QuotaSettings {
        QuotaSettings {
            disk_warn_percent: warn,
            disk_block_percent: block,
            ..QuotaSettings::default()
        }
    }

    #[test]
    fn usage_is_measured_against_used_plus_available_like_df() {
        // 10 GiB filesystem, 1 GiB reserved for root: 8 used, 1 available.
        let r = DiskReading {
            total_bytes: 10 * GIB,
            used_bytes: 8 * GIB,
            free_bytes: GIB,
        };
        assert_eq!(r.capacity_bytes(), 9 * GIB);
        assert!((r.used_percent() - 88.888).abs() < 0.01);
        assert_eq!(reading(0, 0).used_percent(), 0.0);
    }

    #[test]
    fn state_follows_the_thresholds_with_hysteresis_on_the_block() {
        use DiskState::*;
        assert_eq!(next_state(Ok, 99.9, 0, 0), Ok);
        assert_eq!(next_state(Ok, 94.9, 95, 98), Ok);
        assert_eq!(next_state(Ok, 95.0, 95, 98), Warning);
        assert_eq!(next_state(Warning, 98.0, 95, 98), Blocked);
        // Blocked stays blocked until a full point below the threshold.
        assert_eq!(next_state(Blocked, 97.5, 95, 98), Blocked);
        assert_eq!(next_state(Blocked, 97.0, 95, 98), Warning);
        assert_eq!(next_state(Blocked, 50.0, 95, 98), Ok);
        // Coming from below, 97.5 does not block.
        assert_eq!(next_state(Warning, 97.5, 95, 98), Warning);
        // Block only, no warning threshold.
        assert_eq!(next_state(Ok, 97.0, 0, 98), Ok);
        assert_eq!(next_state(Ok, 99.0, 0, 98), Blocked);
        // Warn only never blocks.
        assert_eq!(next_state(Ok, 100.0, 95, 0), Warning);
    }

    #[test]
    fn blocked_refuses_every_write_and_below_only_one_that_would_cross() {
        let blocked = Snapshot {
            volume: "storage",
            reading: reading(99, 1),
            state: DiskState::Blocked,
            block_percent: 98,
        };
        for declared in [None, Some(0), Some(1), Some(GIB)] {
            let r = refusal_under(&blocked, declared).expect("blocked");
            assert_eq!(r.code(), "DISK_THRESHOLD_EXCEEDED");
            assert_eq!(r.content_length, declared);
        }
        let below = Snapshot {
            state: DiskState::Warning,
            reading: reading(96, 4),
            ..blocked.clone()
        };
        assert!(refusal_under(&below, None).is_none());
        assert!(refusal_under(&below, Some(0)).is_none());
        assert!(refusal_under(&below, Some(1)).is_none());
        // 96 + 2 = 98 of 100: reaches the threshold.
        assert!(refusal_under(&below, Some(2)).is_some());
        // Off: never, whatever the state says.
        let off = Snapshot {
            block_percent: 0,
            ..blocked
        };
        assert!(refusal_under(&off, Some(u64::MAX)).is_none());
    }

    #[tokio::test]
    async fn instance_denial_carries_the_disk_block_to_every_caller() {
        // Trusted peer replication only asks `instance_denial`; with no
        // instance quota that needs no query (the pool is never connected).
        let pool = sqlx::PgPool::connect_lazy("postgres://nobody@127.0.0.1:1/none").unwrap();
        block_for_tests(true);
        let d = super::super::storage::instance_denial(&pool, 10)
            .await
            .unwrap()
            .expect("blocked");
        assert_eq!(d.scope, QuotaScope::Disk);
        assert_eq!(d.refusal().code(), "DISK_THRESHOLD_EXCEEDED");
        assert!(super::super::storage::instance_denial(&pool, 0)
            .await
            .unwrap()
            .is_none());
        block_for_tests(false);
        assert!(super::super::storage::instance_denial(&pool, 10)
            .await
            .unwrap()
            .is_none());
    }

    #[test]
    fn readings_come_every_second_under_pressure() {
        let five = Duration::from_secs(5);
        assert_eq!(next_wait(five, None), five);
        assert_eq!(next_wait(five, Some(DiskState::Ok)), five);
        assert_eq!(next_wait(five, Some(DiskState::Warning)), PRESSURE_INTERVAL);
        assert_eq!(next_wait(five, Some(DiskState::Blocked)), PRESSURE_INTERVAL);
        let half = Duration::from_millis(500);
        assert_eq!(next_wait(half, Some(DiskState::Blocked)), half);
    }

    #[test]
    fn log_lines_are_rate_limited_while_above_a_threshold() {
        use DiskState::*;
        let now = Instant::now();
        let recent = Some(now);
        assert!(log_due(Ok, Warning, recent, now));
        assert!(log_due(Warning, Ok, recent, now));
        assert!(!log_due(Warning, Warning, recent, now));
        assert!(!log_due(Ok, Ok, None, now));
        assert!(log_due(Blocked, Blocked, None, now));
        let later = now + REPEAT_LOG_EVERY;
        assert!(log_due(Blocked, Blocked, recent, later));
    }

    #[test]
    fn volumes_cover_the_filesystem_backend_and_the_staging_dir() {
        assert_eq!(
            volumes("filesystem", "/data", None),
            vec![Volume {
                label: "storage",
                path: "/data".into()
            }]
        );
        assert!(volumes("s3", "prefix", None).is_empty());
        assert!(volumes("s3", "prefix", Some("  ")).is_empty());
        assert_eq!(
            volumes("azure", "", Some("/scratch")),
            vec![Volume {
                label: "staging",
                path: "/scratch".into()
            }]
        );
        assert_eq!(volumes("filesystem", "/data", Some("/scratch")).len(), 2);
    }

    #[tokio::test]
    async fn applied_readings_drive_admission_metrics_and_recovery() {
        use metrics_util::debugging::{DebugValue, DebuggingRecorder};
        let recorder = DebuggingRecorder::new();
        let snapshotter = recorder.snapshotter();
        let _guard = metrics::set_default_local_recorder(&recorder);
        reset_for_tests();
        let s = settings(90, 95);
        // Nothing measured yet: nothing refused.
        assert!(refusal(Some(GIB)).is_none());
        assert!(denial(1).is_none());

        apply(&s, &[("storage", Ok(reading(96, 4)))]);
        assert!(cache_fills_blocked());
        let refused = refusal(None).expect("blocked");
        let (code, body) = json_of(axum::response::IntoResponse::into_response(refused)).await;
        assert_eq!(code, axum::http::StatusCode::FORBIDDEN);
        assert_eq!(body["code"], "DISK_THRESHOLD_EXCEEDED");
        assert!(body["message"]
            .as_str()
            .unwrap()
            .starts_with("server storage nearly full: free disk or add storage"));
        assert_eq!(body["threshold_percent"], 95);
        let d = denial(10).expect("service-layer denial");
        assert_eq!(d.scope, QuotaScope::Disk);
        let r = d.refusal();
        assert_eq!(r.code(), "DISK_THRESHOLD_EXCEEDED");
        assert_eq!(r.kind.label(), "disk");
        assert!(matches!(
            d.into_error(),
            crate::error::AppError::QuotaRefused(_)
        ));
        // A delete or same-size rewrite adds nothing and is never refused.
        assert!(denial(0).is_none());
        assert!(denial(-5).is_none());

        // A failed reading keeps the state.
        apply(
            &s,
            &[("storage", Err(std::io::Error::other("stale handle")))],
        );
        assert!(cache_fills_blocked());
        // Inside the hysteresis band: still blocked.
        apply(&s, &[("storage", Ok(reading(945, 55)))]);
        assert!(refusal(None).is_some());
        // Freed: writes resume, the warning stays.
        apply(&s, &[("storage", Ok(reading(92, 8)))]);
        assert!(!cache_fills_blocked());
        assert!(refusal(Some(1)).is_none());
        assert_eq!(status(&s).state, DiskState::Warning);
        // The fullest volume decides.
        apply(
            &s,
            &[
                ("storage", Ok(reading(10, 90))),
                ("staging", Ok(reading(99, 1))),
            ],
        );
        let st = status(&s);
        assert_eq!(st.state, DiskState::Blocked);
        assert_eq!(st.volume.as_deref(), Some("staging"));

        let state_gauge = snapshotter
            .snapshot()
            .into_vec()
            .into_iter()
            .find(|(key, ..)| key.key().name() == "ak_storage_disk_state")
            .map(|(_, _, _, value)| value);
        assert_eq!(state_gauge, Some(DebugValue::Gauge(2.0.into())));
        reset_for_tests();
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn measure_reads_a_real_filesystem() {
        let r = measure(&std::env::temp_dir()).expect("statvfs of the temp dir");
        assert!(r.total_bytes > 0);
        assert!(r.used_bytes <= r.total_bytes);
        assert!(r.free_bytes <= r.total_bytes);
        assert!(measure(Path::new("/definitely/not/here/5191")).is_err());
    }
}
