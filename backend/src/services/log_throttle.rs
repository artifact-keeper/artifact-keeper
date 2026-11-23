//! Rate limits for log lines that can repeat on every request (#5617, #5840).
//!
//! Two shapes:
//!
//! * [`LogEvery`]: one call site, at most one line per interval. The line
//!   that is let through reports how many were held back since the last one,
//!   so the volume is still visible. The matching counter metric carries the
//!   exact count.
//! * [`FirstSighting`]: a keyed variant. It answers `true` the first time a
//!   key is seen within a window, so the caller logs the first sighting
//!   loudly and the repeats quietly.
//!
//! Both are in-process. A fleet of replicas logs once per replica.

use std::collections::HashMap;
use std::hash::Hash;
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

/// At most one log line per `interval` for one call site.
///
/// Declare it as a `static` next to the log line:
///
/// ```ignore
/// static LOG: LogEvery = LogEvery::new(Duration::from_secs(60));
/// if let Some(held_back) = LOG.check() {
///     tracing::warn!(held_back, "...");
/// }
/// ```
pub struct LogEvery {
    interval: Duration,
    /// Milliseconds since [`epoch`] of the last line let through, or
    /// `i64::MIN` for none yet.
    last_ms: AtomicI64,
    /// Lines held back since the last one let through.
    held_back: AtomicU64,
}

/// The process-wide reference instant the timestamps above count from.
fn epoch() -> Instant {
    static EPOCH: OnceLock<Instant> = OnceLock::new();
    *EPOCH.get_or_init(Instant::now)
}

impl LogEvery {
    pub const fn new(interval: Duration) -> Self {
        Self {
            interval,
            last_ms: AtomicI64::new(i64::MIN),
            held_back: AtomicU64::new(0),
        }
    }

    /// `Some(n)` when the caller should log now, where `n` is how many lines
    /// were held back since the previous one; `None` to stay quiet.
    pub fn check(&self) -> Option<u64> {
        self.check_at(epoch().elapsed())
    }

    fn check_at(&self, now: Duration) -> Option<u64> {
        let now_ms = i64::try_from(now.as_millis()).unwrap_or(i64::MAX);
        let interval_ms = i64::try_from(self.interval.as_millis()).unwrap_or(i64::MAX);
        let last = self.last_ms.load(Ordering::Relaxed);
        let due = last == i64::MIN || now_ms.saturating_sub(last) >= interval_ms;
        // One caller wins the slot; the others count as held back.
        if due
            && self
                .last_ms
                .compare_exchange(last, now_ms, Ordering::Relaxed, Ordering::Relaxed)
                .is_ok()
        {
            return Some(self.held_back.swap(0, Ordering::Relaxed));
        }
        self.held_back.fetch_add(1, Ordering::Relaxed);
        None
    }
}

/// Whether a key is seen for the first time within a window.
///
/// Bounded: at `max_keys` it first drops the keys whose window has passed,
/// and if that frees nothing it forgets every key. Forgetting errs towards
/// logging again, never towards hiding a first sighting.
pub struct FirstSighting<K> {
    window: Duration,
    max_keys: usize,
    seen: Mutex<HashMap<K, Instant>>,
}

impl<K: Eq + Hash> FirstSighting<K> {
    pub fn new(window: Duration, max_keys: usize) -> Self {
        Self {
            window,
            max_keys: max_keys.max(1),
            seen: Mutex::new(HashMap::new()),
        }
    }

    /// `true` when `key` was not seen within the window (and records it now).
    pub fn first(&self, key: K) -> bool {
        self.first_at(key, Instant::now())
    }

    fn first_at(&self, key: K, now: Instant) -> bool {
        let mut seen = self.seen.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(at) = seen.get(&key) {
            if now.saturating_duration_since(*at) < self.window {
                return false;
            }
        }
        if seen.len() >= self.max_keys && !seen.contains_key(&key) {
            let window = self.window;
            seen.retain(|_, at| now.saturating_duration_since(*at) < window);
            if seen.len() >= self.max_keys {
                seen.clear();
            }
        }
        seen.insert(key, now);
        true
    }
}

#[cfg(ak_test_shard = "services-2")]
#[cfg(test)]
mod tests {
    use super::*;

    const SEC: Duration = Duration::from_secs(1);

    #[test]
    fn log_every_lets_one_line_through_per_interval_and_counts_the_rest() {
        let log = LogEvery::new(60 * SEC);
        assert_eq!(log.check_at(100 * SEC), Some(0), "the first line is logged");
        for t in 101..160 {
            assert_eq!(log.check_at(t * SEC), None, "held back at {t}");
        }
        assert_eq!(
            log.check_at(160 * SEC),
            Some(59),
            "reports what it held back"
        );
        assert_eq!(log.check_at(161 * SEC), None);
        assert_eq!(log.check_at(220 * SEC), Some(1));
    }

    #[test]
    fn first_sighting_is_per_key_and_per_window() {
        let seen = FirstSighting::new(3600 * SEC, 16);
        let t0 = Instant::now();
        assert!(seen.first_at(("repo", "pkg"), t0));
        assert!(!seen.first_at(("repo", "pkg"), t0 + 10 * SEC));
        assert!(
            seen.first_at(("repo", "other"), t0 + 10 * SEC),
            "another key"
        );
        assert!(
            seen.first_at(("repo2", "pkg"), t0 + 10 * SEC),
            "another repo"
        );
        assert!(
            seen.first_at(("repo", "pkg"), t0 + 3601 * SEC),
            "the window passed"
        );
    }

    #[test]
    fn first_sighting_stays_bounded_and_forgets_rather_than_hides() {
        let seen = FirstSighting::new(3600 * SEC, 4);
        let t0 = Instant::now();
        for k in 0..4 {
            assert!(seen.first_at(k, t0));
        }
        // Full of live keys: a new key is still a first sighting.
        assert!(seen.first_at(99, t0 + SEC));
        assert!(seen.seen.lock().unwrap().len() <= 4);
        // After the window the key is new again, and then seen.
        assert!(seen.first_at(100, t0 + 4000 * SEC));
        assert!(!seen.first_at(100, t0 + 4001 * SEC));
    }
}
