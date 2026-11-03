//! Proxy scans that outlive the request that started them (#5231).
//!
//! A first install fetches many never-seen files at once, and each needs a
//! scan. Scans run a few at a time, so most of them queue. The scan itself now
//! runs in its own task, tracked here by what it is scanning, and a request
//! only waits for it. A request that stops waiting leaves the scan running, so
//! the verdict is there for the next pull, and that next pull joins a scan
//! still in flight instead of starting a second one.
//!
//! The table is what keeps this bounded, because a scan with no request behind
//! it costs nothing a client can see:
//!
//! - An entry holds the file's bytes until its verdict is recorded, so entries
//!   and bytes are capped, overall and per repository. A repository that fills
//!   its share refuses only its own files.
//! - A request waiting on a scan holds a router slot and, if it joined, a buffer
//!   of its own. Those are capped per scan and per repository, and the buffer
//!   counts against the byte caps.
//! - A queued scan that only a waiting request wanted leaves the queue
//!   [`ABANDON_GRACE`] after the last such request has gone. A scan from a
//!   `record_only` or `fail_open` pull has no request to wait for and stays.
//!
//! What runs at once is still decided only by the scan extraction permits. The
//! table is per process: another replica knows nothing of it, and a restart
//! loses what is queued, for the next pull to start again.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::sync::watch;
use tokio::time::Instant;
use uuid::Uuid;

use super::proxy_helpers::ProxyScanInconclusive;
use crate::services::scanner_service::ProxyScanVerdict;

tokio::task_local! {
    /// When the request being served must have its answer, on a route under the
    /// router's request timeout. That clock started when the request arrived, so
    /// anything already spent on it (the upstream fetch) has to come out of a wait.
    pub(crate) static REQUEST_ANSWER_BY: Instant;
}

/// How long after arriving a request under `timeout_secs` must have its answer:
/// three quarters of the timeout, the headroom that
/// [`proxy_rescan_budget`](crate::services::scanner_service::proxy_rescan_budget)
/// leaves too. `None` when the timeout is disabled.
pub(crate) fn answer_within(timeout_secs: u64) -> Option<Duration> {
    if timeout_secs == 0 {
        return None;
    }
    let outer = Duration::from_secs(timeout_secs);
    Some(outer.saturating_sub((outer / 4).max(Duration::from_secs(1))))
}

/// How long a queued scan stays after the last request waiting on it has gone,
/// whether it was refused or hung up. A retry inside this keeps the scan's place.
pub(crate) const ABANDON_GRACE: Duration = Duration::from_secs(30);

/// Default for the most file bytes the table holds at once.
const DEFAULT_MAX_IN_FLIGHT_BYTES: usize = 1024 * 1024 * 1024;

/// Env var overriding [`DEFAULT_MAX_IN_FLIGHT_BYTES`]. A blank, non-numeric or
/// zero value falls back to the default. A value too small for two files at the
/// byte cap is raised to that, so that a repository's half of it can always hold
/// a file the gate accepts.
const MAX_IN_FLIGHT_BYTES_ENV: &str = "AK_PROXY_SCAN_QUEUE_BUDGET_BYTES";

fn max_in_flight_bytes() -> usize {
    std::env::var(MAX_IN_FLIGHT_BYTES_ENV)
        .ok()
        .and_then(|v| v.trim().parse::<usize>().ok())
        .filter(|v| *v > 0)
        .unwrap_or(DEFAULT_MAX_IN_FLIGHT_BYTES)
        .max(2 * crate::services::scanner_service::PROXY_SCAN_MAX_BYTES)
}

/// What the table will hold.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Limits {
    pub scans: usize,
    pub bytes: usize,
    pub repo_scans: usize,
    pub repo_bytes: usize,
    pub scan_waiters: usize,
    pub repo_waiters: usize,
}

impl Limits {
    /// A repository gets a quarter of the scans, which still queues a 1,024-file
    /// install, and half of the bytes, which holds two files at the byte cap. A
    /// request costs a router slot, so one repository's waiters stay within half
    /// of the default `GLOBAL_MAX_CONCURRENCY`.
    fn with_bytes(bytes: usize) -> Self {
        Self {
            scans: 4096,
            bytes,
            repo_scans: 1024,
            repo_bytes: bytes / 2,
            scan_waiters: 16,
            repo_waiters: 256,
        }
    }
}

/// What was out of room, for the `ak_proxy_scan_queue_refused_total` label.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TableFull {
    Scans,
    Bytes,
    RepoScans,
    RepoBytes,
    ScanWaiters,
    RepoWaiters,
}

impl TableFull {
    pub(crate) fn label(self) -> &'static str {
        match self {
            Self::Scans => "scans",
            Self::Bytes => "bytes",
            Self::RepoScans => "repository_scans",
            Self::RepoBytes => "repository_bytes",
            Self::ScanWaiters => "scan_waiters",
            Self::RepoWaiters => "repository_waiters",
        }
    }
}

/// What one scan is grading. The digest alone is not enough: a verdict graded
/// as another coordinate does not answer this request (#4952), and the file name
/// decides how the bytes are staged, so they may not join a scan that reads them
/// as something else (#3396). The repository is part of it because the verdict
/// row and the fair-share permit name it.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) struct ScanKey {
    pub repo_id: Uuid,
    pub digest: String,
    pub file: String,
    pub pin: Option<String>,
}

/// How far a scan has got. Requests read this from a [`ScanWaiter`].
#[derive(Debug, Clone)]
pub(crate) enum ScanProgress {
    /// Waiting for a scan permit.
    Queued,
    /// Holding a permit since this instant.
    Running(Instant),
    /// Finished, and its verdict row is written. The verdict carries no package
    /// inventory or findings: those are written after this.
    Done(Result<ProxyScanVerdict, ProxyScanInconclusive>),
}

/// Whether the caller waits for the scan, or only wants it done.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ScanIntent {
    Wait,
    Background,
}

/// The running side of a scan in the table. Dropping it frees the scan's place,
/// so a scan that panics cannot hold bytes or block a later scan of the file.
pub(crate) struct ScanTicket {
    table: Arc<InFlightScans>,
    key: ScanKey,
    id: u64,
    size: usize,
    progress: watch::Sender<ScanProgress>,
    idle: watch::Receiver<Option<Instant>>,
}

impl ScanTicket {
    pub(crate) fn report(&self, progress: ScanProgress) {
        self.progress.send_replace(progress);
    }

    /// Resolves when nobody has wanted this scan for [`ABANDON_GRACE`].
    pub(crate) async fn abandoned(&self) {
        let mut idle = self.idle.clone();
        loop {
            let since = *idle.borrow_and_update();
            tokio::select! {
                changed = idle.changed() => {
                    if changed.is_err() {
                        std::future::pending::<()>().await;
                    }
                }
                () = async {
                    match since {
                        Some(since) => tokio::time::sleep_until(since + ABANDON_GRACE).await,
                        None => std::future::pending().await,
                    }
                } => return,
            }
        }
    }
}

impl Drop for ScanTicket {
    fn drop(&mut self) {
        let mut inner = self.table.lock();
        if inner.scans.get(&self.key).is_some_and(|e| e.id == self.id) {
            inner.scans.remove(&self.key);
        }
        inner.bytes = inner.bytes.saturating_sub(self.size);
        inner.release_repo(self.key.repo_id, 1, self.size, 0);
    }
}

/// A request's place behind a scan. Dropping it, which is also what a client
/// hanging up does, gives back what the request was counted for.
pub(crate) struct ScanWaiter {
    table: Arc<InFlightScans>,
    key: ScanKey,
    id: u64,
    charged: usize,
    watch: watch::Receiver<ScanProgress>,
}

impl Drop for ScanWaiter {
    fn drop(&mut self) {
        let mut inner = self.table.lock();
        inner.bytes = inner.bytes.saturating_sub(self.charged);
        inner.release_repo(self.key.repo_id, 0, self.charged, 1);
        if let Some(entry) = inner.scans.get_mut(&self.key) {
            if entry.id == self.id {
                entry.waiters = entry.waiters.saturating_sub(1);
                if entry.waiters == 0 && !entry.background {
                    entry.idle.send_replace(Some(Instant::now()));
                }
            }
        }
    }
}

/// The answer to asking for a scan of a file. The waiter is there when the
/// caller said it would wait.
pub(crate) enum ScanEntry {
    /// The file is already being scanned.
    Joined(Option<ScanWaiter>),
    /// This caller must run the scan, and report through the ticket.
    Started(Option<ScanWaiter>, ScanTicket),
    /// No room.
    Full(TableFull),
}

struct Entry {
    id: u64,
    idle: watch::Sender<Option<Instant>>,
    progress: watch::Receiver<ScanProgress>,
    waiters: usize,
    background: bool,
}

#[derive(Default)]
struct RepoUse {
    scans: usize,
    bytes: usize,
    waiters: usize,
}

#[derive(Default)]
struct Inner {
    next_id: u64,
    scans: HashMap<ScanKey, Entry>,
    bytes: usize,
    repos: HashMap<Uuid, RepoUse>,
}

impl Inner {
    fn release_repo(&mut self, repo: Uuid, scans: usize, bytes: usize, waiters: usize) {
        if let Some(usage) = self.repos.get_mut(&repo) {
            usage.scans = usage.scans.saturating_sub(scans);
            usage.bytes = usage.bytes.saturating_sub(bytes);
            usage.waiters = usage.waiters.saturating_sub(waiters);
            if usage.scans == 0 && usage.waiters == 0 {
                self.repos.remove(&repo);
            }
        }
    }
}

pub(crate) struct InFlightScans {
    inner: Mutex<Inner>,
    limits: Limits,
}

impl InFlightScans {
    pub(crate) fn new(limits: Limits) -> Arc<Self> {
        Arc::new(Self {
            inner: Mutex::new(Inner::default()),
            limits,
        })
    }

    /// The process-wide table.
    pub(crate) fn global() -> Arc<Self> {
        static TABLE: std::sync::OnceLock<Arc<InFlightScans>> = std::sync::OnceLock::new();
        TABLE
            .get_or_init(|| Self::new(Limits::with_bytes(max_in_flight_bytes())))
            .clone()
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        // Every critical section is a few map operations that leave the table
        // consistent, so a poisoned lock is still safe to use.
        self.inner.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// Whether `bytes` more fit, overall and for a repository already using
    /// `repo_bytes`.
    fn bytes_fit(&self, inner: &Inner, repo_bytes: usize, bytes: usize) -> Result<(), TableFull> {
        if repo_bytes.saturating_add(bytes) > self.limits.repo_bytes {
            return Err(TableFull::RepoBytes);
        }
        if inner.bytes.saturating_add(bytes) > self.limits.bytes {
            return Err(TableFull::Bytes);
        }
        Ok(())
    }

    /// Join the scan of `key`, or claim room for a new one of `size` bytes.
    pub(crate) fn enter(
        self: &Arc<Self>,
        key: ScanKey,
        size: usize,
        intent: ScanIntent,
    ) -> ScanEntry {
        let wait = intent == ScanIntent::Wait;
        let mut guard = self.lock();
        let inner = &mut *guard;
        let usage = inner.repos.get(&key.repo_id);
        let (repo_scans, repo_bytes, repo_waiters) =
            usage.map_or((0, 0, 0), |u| (u.scans, u.bytes, u.waiters));
        if wait && repo_waiters >= self.limits.repo_waiters {
            return ScanEntry::Full(TableFull::RepoWaiters);
        }

        if let Some(entry) = inner.scans.get(&key) {
            let (id, progress, waiters) = (entry.id, entry.progress.clone(), entry.waiters);
            if !wait {
                let entry = inner.scans.get_mut(&key).expect("just read");
                entry.background = true;
                entry.idle.send_replace(None);
                return ScanEntry::Joined(None);
            }
            if waiters >= self.limits.scan_waiters {
                return ScanEntry::Full(TableFull::ScanWaiters);
            }
            // A joining request holds a buffer of its own while it waits.
            if let Err(full) = self.bytes_fit(inner, repo_bytes, size) {
                return ScanEntry::Full(full);
            }
            let entry = inner.scans.get_mut(&key).expect("just read");
            entry.waiters += 1;
            entry.idle.send_replace(None);
            inner.bytes += size;
            let usage = inner.repos.entry(key.repo_id).or_default();
            usage.bytes += size;
            usage.waiters += 1;
            return ScanEntry::Joined(Some(ScanWaiter {
                table: self.clone(),
                key,
                id,
                charged: size,
                watch: progress,
            }));
        }

        if repo_scans >= self.limits.repo_scans {
            return ScanEntry::Full(TableFull::RepoScans);
        }
        if inner.scans.len() >= self.limits.scans {
            return ScanEntry::Full(TableFull::Scans);
        }
        if let Err(full) = self.bytes_fit(inner, repo_bytes, size) {
            return ScanEntry::Full(full);
        }
        inner.next_id += 1;
        let id = inner.next_id;
        let (progress, watch) = watch::channel(ScanProgress::Queued);
        let (idle, idle_rx) = watch::channel(None);
        inner.scans.insert(
            key.clone(),
            Entry {
                id,
                idle,
                progress: watch.clone(),
                waiters: usize::from(wait),
                background: !wait,
            },
        );
        inner.bytes += size;
        let usage = inner.repos.entry(key.repo_id).or_default();
        usage.scans += 1;
        usage.bytes += size;
        usage.waiters += usize::from(wait);
        let waiter = wait.then(|| ScanWaiter {
            table: self.clone(),
            key: key.clone(),
            id,
            charged: 0,
            watch,
        });
        ScanEntry::Started(
            waiter,
            ScanTicket {
                table: self.clone(),
                key,
                id,
                size,
                progress,
                idle: idle_rx,
            },
        )
    }

    #[cfg(test)]
    fn usage(&self) -> (usize, usize) {
        let inner = self.lock();
        (inner.scans.len(), inner.bytes)
    }
}

/// Wait for a scan's verdict, for as long as one request is prepared to.
///
/// `queue_wait` bounds the time spent waiting for a scan to get a permit.
/// `budget` bounds the time spent waiting for a running scan, and starts when
/// the scan starts, or when this request arrived if that is later. `answer_by`
/// is when the request must have its answer whatever those two say. A scan that
/// misses any of them is inconclusive for this request, and a retry finds out
/// about it from the verdict row. Giving up here does not stop a running scan.
pub(crate) async fn wait_for_verdict(
    mut waiter: ScanWaiter,
    budget: Duration,
    queue_wait: Duration,
    answer_by: Option<Instant>,
) -> Result<ProxyScanVerdict, ProxyScanInconclusive> {
    let arrived = Instant::now();
    loop {
        let deadline = match &*waiter.watch.borrow_and_update() {
            ScanProgress::Done(result) => return result.clone(),
            ScanProgress::Queued => arrived + queue_wait,
            ScanProgress::Running(started) => (*started).max(arrived) + budget,
        };
        let deadline = answer_by.map_or(deadline, |by| deadline.min(by));
        tokio::select! {
            changed = waiter.watch.changed() => {
                // The scan's task ended without an outcome: it panicked.
                if changed.is_err() {
                    return match &*waiter.watch.borrow() {
                        ScanProgress::Done(result) => result.clone(),
                        _ => Err(ProxyScanInconclusive::ScanFailed),
                    };
                }
            }
            () = tokio::time::sleep_until(deadline) => {
                return Err(ProxyScanInconclusive::BudgetExceeded);
            }
        }
    }
}

#[cfg(ak_test_shard = "handlers-2")]
#[cfg(test)]
mod tests {
    use super::*;

    const SECOND: Duration = Duration::from_secs(1);
    const LIMITS: Limits = Limits {
        scans: 8,
        bytes: 100,
        repo_scans: 4,
        repo_bytes: 60,
        scan_waiters: 3,
        repo_waiters: 6,
    };

    fn key_in(repo: u128, n: u8) -> ScanKey {
        ScanKey {
            repo_id: Uuid::from_u128(repo),
            digest: format!("{n:064x}"),
            file: "pkg-1.0.0.tgz".to_string(),
            pin: None,
        }
    }

    fn key(n: u8) -> ScanKey {
        key_in(1, n)
    }

    fn started(entry: ScanEntry) -> (Option<ScanWaiter>, ScanTicket) {
        match entry {
            ScanEntry::Started(waiter, ticket) => (waiter, ticket),
            _ => panic!("expected a new scan"),
        }
    }

    fn full(entry: ScanEntry) -> TableFull {
        match entry {
            ScanEntry::Full(reason) => reason,
            _ => panic!("expected a refusal"),
        }
    }

    fn waiting(table: &Arc<InFlightScans>, key: ScanKey, size: usize) -> (ScanWaiter, ScanTicket) {
        let (waiter, ticket) = started(table.enter(key, size, ScanIntent::Wait));
        (waiter.expect("the caller waits"), ticket)
    }

    fn clean() -> ProxyScanVerdict {
        ProxyScanVerdict {
            findings_count: 0,
            critical_count: 0,
            high_count: 0,
            medium_count: 0,
            low_count: 0,
            max_severity: None,
            scanner_version: None,
            packages: Vec::new(),
            scan_completeness: None,
            findings: Vec::new(),
            components_cataloged: None,
        }
    }

    #[test]
    fn a_request_is_answered_inside_every_request_timeout() {
        assert_eq!(answer_within(0), None, "layer disabled");
        assert_eq!(answer_within(120), Some(90 * SECOND));
        for timeout in 1..=3600_u64 {
            let within = answer_within(timeout).expect("a timeout is set");
            assert!(within < Duration::from_secs(timeout), "{timeout}");
            assert!(
                within <= Duration::from_secs(timeout) * 3 / 4,
                "three quarters at {timeout}"
            );
        }
    }

    #[test]
    fn a_second_request_for_a_file_joins_its_scan() {
        let table = InFlightScans::new(LIMITS);
        let _first = waiting(&table, key(1), 10);
        let joined = table.enter(key(1), 10, ScanIntent::Wait);
        assert!(matches!(joined, ScanEntry::Joined(Some(_))));
        assert_eq!(table.usage(), (1, 20), "its buffer counts");
        drop(joined);
        assert_eq!(table.usage(), (1, 10), "and is given back");
    }

    #[test]
    fn the_same_digest_as_another_coordinate_or_file_is_another_scan() {
        let table = InFlightScans::new(LIMITS);
        let _first = waiting(&table, key(1), 1);
        let other_pin = ScanKey {
            pin: Some("npm:other@1.0.0".to_string()),
            ..key(1)
        };
        let other_file = ScanKey {
            file: "pkg-1.0.0.whl".to_string(),
            ..key(1)
        };
        for other in [other_pin, other_file] {
            assert!(matches!(
                table.enter(other, 1, ScanIntent::Wait),
                ScanEntry::Started(..)
            ));
        }
    }

    #[test]
    fn a_repository_fills_only_its_share_of_the_table() {
        let table = InFlightScans::new(LIMITS);
        let scans: Vec<_> = (0..4)
            .map(|n| started(table.enter(key(n), 1, ScanIntent::Background)))
            .collect();
        assert_eq!(
            full(table.enter(key(9), 1, ScanIntent::Background)),
            TableFull::RepoScans
        );
        assert!(matches!(
            table.enter(key_in(2, 9), 1, ScanIntent::Background),
            ScanEntry::Started(..)
        ));
        drop(scans);
        assert_eq!(table.usage(), (0, 0));

        let big = started(table.enter(key(1), 55, ScanIntent::Background));
        assert_eq!(
            full(table.enter(key(2), 6, ScanIntent::Background)),
            TableFull::RepoBytes
        );
        let other = started(table.enter(key_in(2, 1), 40, ScanIntent::Background));
        assert_eq!(
            full(table.enter(key_in(3, 1), 6, ScanIntent::Background)),
            TableFull::Bytes
        );
        drop((big, other));
        assert_eq!(table.usage(), (0, 0));
    }

    #[test]
    fn the_table_is_capped_overall() {
        let table = InFlightScans::new(LIMITS);
        let scans: Vec<_> = (0..8)
            .map(|n| started(table.enter(key_in(u128::from(n / 4), n), 0, ScanIntent::Background)))
            .collect();
        assert_eq!(
            full(table.enter(key_in(9, 1), 0, ScanIntent::Background)),
            TableFull::Scans
        );
        drop(scans);
        assert_eq!(table.usage(), (0, 0));
        assert!(table.lock().repos.is_empty(), "no repository left behind");
    }

    #[test]
    fn joining_requests_are_capped_per_scan_and_per_repository() {
        let table = InFlightScans::new(LIMITS);
        let first = waiting(&table, key(1), 0);
        let joiners: Vec<_> = (0..2)
            .map(|_| table.enter(key(1), 0, ScanIntent::Wait))
            .collect();
        assert_eq!(
            full(table.enter(key(1), 0, ScanIntent::Wait)),
            TableFull::ScanWaiters
        );
        let more = waiting(&table, key(2), 0);
        let second: Vec<_> = (0..2)
            .map(|_| table.enter(key(2), 0, ScanIntent::Wait))
            .collect();
        assert_eq!(
            full(table.enter(key(3), 0, ScanIntent::Wait)),
            TableFull::RepoWaiters
        );
        assert!(
            matches!(
                table.enter(key(3), 0, ScanIntent::Background),
                ScanEntry::Started(None, _)
            ),
            "a pull that does not wait holds no slot"
        );
        drop((first, joiners, more, second));
    }

    #[test]
    fn a_joining_requests_buffer_counts_against_the_byte_caps() {
        let table = InFlightScans::new(LIMITS);
        let _first = waiting(&table, key(1), 30);
        let _second = table.enter(key(1), 30, ScanIntent::Wait);
        assert_eq!(
            full(table.enter(key(1), 30, ScanIntent::Wait)),
            TableFull::RepoBytes
        );
    }

    #[test]
    fn the_byte_cap_holds_two_files_at_the_byte_cap() {
        std::env::set_var(MAX_IN_FLIGHT_BYTES_ENV, "1");
        let raised = max_in_flight_bytes();
        std::env::set_var(MAX_IN_FLIGHT_BYTES_ENV, "not a number");
        let fallback = max_in_flight_bytes();
        std::env::remove_var(MAX_IN_FLIGHT_BYTES_ENV);
        assert_eq!(
            Limits::with_bytes(raised).repo_bytes,
            crate::services::scanner_service::PROXY_SCAN_MAX_BYTES
        );
        assert_eq!(fallback, DEFAULT_MAX_IN_FLIGHT_BYTES);
    }

    #[tokio::test(start_paused = true)]
    async fn time_in_the_queue_does_not_spend_the_budget() {
        let table = InFlightScans::new(LIMITS);
        let (watch, ticket) = waiting(&table, key(1), 1);
        let waiter = tokio::spawn(wait_for_verdict(watch, 30 * SECOND, 60 * SECOND, None));

        // Queued for longer than the budget, then runs well within it.
        tokio::time::sleep(45 * SECOND).await;
        ticket.report(ScanProgress::Running(Instant::now()));
        tokio::time::sleep(5 * SECOND).await;
        assert!(!waiter.is_finished());
        ticket.report(ScanProgress::Done(Ok(clean())));

        assert!(waiter.await.unwrap().is_ok());
    }

    #[tokio::test(start_paused = true)]
    async fn the_queue_wait_is_bounded_on_its_own() {
        let table = InFlightScans::new(LIMITS);
        let (watch, _ticket) = waiting(&table, key(1), 1);
        let begun = Instant::now();
        let result = wait_for_verdict(watch, 30 * SECOND, 60 * SECOND, None).await;
        assert!(matches!(result, Err(ProxyScanInconclusive::BudgetExceeded)));
        assert_eq!(begun.elapsed(), 60 * SECOND);
    }

    #[tokio::test(start_paused = true)]
    async fn a_scan_over_the_budget_is_inconclusive_for_the_request() {
        let table = InFlightScans::new(LIMITS);
        let (watch, ticket) = waiting(&table, key(1), 1);
        ticket.report(ScanProgress::Running(Instant::now()));
        let begun = Instant::now();
        let result = wait_for_verdict(watch, 30 * SECOND, 60 * SECOND, None).await;
        assert!(matches!(result, Err(ProxyScanInconclusive::BudgetExceeded)));
        assert_eq!(begun.elapsed(), 30 * SECOND);
    }

    #[tokio::test(start_paused = true)]
    async fn the_answer_by_time_beats_both_waits() {
        let table = InFlightScans::new(LIMITS);
        let (watch, ticket) = waiting(&table, key(1), 1);
        let begun = Instant::now();
        let by = begun + 7 * SECOND;
        let queued = wait_for_verdict(watch, 30 * SECOND, 60 * SECOND, Some(by)).await;
        assert!(matches!(queued, Err(ProxyScanInconclusive::BudgetExceeded)));
        assert_eq!(begun.elapsed(), 7 * SECOND);

        ticket.report(ScanProgress::Running(Instant::now()));
        let ScanEntry::Joined(Some(joined)) = table.enter(key(1), 1, ScanIntent::Wait) else {
            panic!("the scan is still in flight");
        };
        let by = Instant::now() + 2 * SECOND;
        let running = wait_for_verdict(joined, 30 * SECOND, 60 * SECOND, Some(by)).await;
        assert!(matches!(
            running,
            Err(ProxyScanInconclusive::BudgetExceeded)
        ));
        assert_eq!(begun.elapsed(), 9 * SECOND);
    }

    #[tokio::test(start_paused = true)]
    async fn a_retry_joining_a_running_scan_gets_a_budget_of_its_own() {
        let table = InFlightScans::new(LIMITS);
        let (_watch, ticket) = waiting(&table, key(1), 1);
        ticket.report(ScanProgress::Running(Instant::now()));
        tokio::time::sleep(31 * SECOND).await;

        let ScanEntry::Joined(Some(joined)) = table.enter(key(1), 1, ScanIntent::Wait) else {
            panic!("the scan is still in flight");
        };
        let waiter = tokio::spawn(wait_for_verdict(joined, 30 * SECOND, 60 * SECOND, None));
        tokio::time::sleep(5 * SECOND).await;
        ticket.report(ScanProgress::Done(Ok(clean())));
        assert!(waiter.await.unwrap().is_ok());
    }

    #[tokio::test(start_paused = true)]
    async fn a_scan_that_dies_without_an_outcome_is_inconclusive_and_frees_its_place() {
        let table = InFlightScans::new(LIMITS);
        let (watch, ticket) = waiting(&table, key(1), 1);
        let waiter = tokio::spawn(wait_for_verdict(watch, 30 * SECOND, 60 * SECOND, None));
        tokio::task::yield_now().await;
        drop(ticket);
        assert!(matches!(
            waiter.await.unwrap(),
            Err(ProxyScanInconclusive::ScanFailed)
        ));
        assert_eq!(table.usage(), (0, 0));
    }

    /// Whether `ticket` reports abandoned within `within` of now.
    async fn abandoned_within(ticket: &ScanTicket, within: Duration) -> bool {
        tokio::time::timeout(within, ticket.abandoned())
            .await
            .is_ok()
    }

    #[tokio::test(start_paused = true)]
    async fn a_scan_is_abandoned_only_after_the_grace_with_nobody_waiting() {
        let table = InFlightScans::new(LIMITS);
        let (watch, ticket) = waiting(&table, key(1), 1);
        assert!(
            !abandoned_within(&ticket, 300 * SECOND).await,
            "a request is waiting"
        );

        drop(watch);
        assert!(!abandoned_within(&ticket, ABANDON_GRACE - SECOND).await);

        // A retry inside the grace keeps its place, and starts the grace again
        // when it goes.
        let joined = table.enter(key(1), 1, ScanIntent::Wait);
        assert!(!abandoned_within(&ticket, 300 * SECOND).await);
        drop(joined);
        assert!(!abandoned_within(&ticket, ABANDON_GRACE - SECOND).await);
        assert!(abandoned_within(&ticket, 2 * SECOND).await);
    }

    #[tokio::test(start_paused = true)]
    async fn a_background_scan_is_never_abandoned() {
        let table = InFlightScans::new(LIMITS);
        let (_none, ticket) = started(table.enter(key(1), 1, ScanIntent::Background));
        assert!(!abandoned_within(&ticket, 3600 * SECOND).await);

        // Nor is one a record_only pull joined after a request left.
        let (watch, ticket) = waiting(&table, key(2), 1);
        drop(watch);
        assert!(matches!(
            table.enter(key(2), 1, ScanIntent::Background),
            ScanEntry::Joined(None)
        ));
        assert!(!abandoned_within(&ticket, 3600 * SECOND).await);
    }
}
