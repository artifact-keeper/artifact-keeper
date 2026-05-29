use std::collections::HashMap;
use std::future::Future;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use tokio::sync::Notify;

pub const DEFAULT_PROXY_HYDRATION_WAIT_TIMEOUT: Duration = Duration::from_secs(65);

const FOLLOWER_WAIT_SLICE: Duration = Duration::from_millis(250);

type LocalHydrationMap = Arc<Mutex<HashMap<String, Arc<Notify>>>>;

enum LocalHydrationRole {
    /// The caller won the election and must produce the value. The
    /// [`LeaderLease`] guard releases the slot (and notifies followers) on
    /// drop, so the slot is freed even if the leader future is cancelled
    /// mid-fetch.
    Leader(LeaderLease),
    Follower(Arc<Notify>),
}

/// RAII guard held by the hydration leader. On drop it removes the leader's
/// slot from the shared map (if it still owns it) and wakes any followers so
/// they re-check the cache and, if the slot is now free, elect a new leader.
///
/// Using a guard rather than an explicit release call is what makes the
/// coordinator cancellation-safe: if the surrounding request future is dropped
/// (e.g. the HTTP client disconnects) while the leader is awaiting the upstream
/// fetch, the slot must not leak. A leaked slot would otherwise poison the key
/// for the whole `DEFAULT_PROXY_HYDRATION_WAIT_TIMEOUT` window, because every
/// subsequent caller would join as a follower and never elect a replacement
/// leader. `Drop` runs on cancellation, so the slot is always reclaimed.
struct LeaderLease {
    key: String,
    notify: Arc<Notify>,
}

impl Drop for LeaderLease {
    fn drop(&mut self) {
        let map = local_hydration_map();
        // The map mutex is only ever held for synchronous map operations
        // (never across an await), so a std Mutex is safe and lets us release
        // from a synchronous Drop. `lock()` only fails on poisoning, which we
        // recover from since the contained map is still structurally valid.
        let mut guard = map.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let owns_slot = guard
            .get(&self.key)
            .map(|current| Arc::ptr_eq(current, &self.notify))
            .unwrap_or(false);
        if owns_slot {
            guard.remove(&self.key);
        }
        drop(guard);
        // Wake followers regardless: they re-check the cache and re-run the
        // election. If the leader succeeded the value is now cached; if it was
        // cancelled the slot is free for a follower to become the new leader.
        self.notify.notify_waiters();
    }
}

fn local_hydration_map() -> &'static LocalHydrationMap {
    static LOCAL_HYDRATIONS: OnceLock<LocalHydrationMap> = OnceLock::new();
    LOCAL_HYDRATIONS.get_or_init(|| Arc::new(Mutex::new(HashMap::new())))
}

fn acquire_local_hydration(key: &str) -> LocalHydrationRole {
    let map = local_hydration_map();
    let mut guard = map.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    if let Some(existing) = guard.get(key) {
        return LocalHydrationRole::Follower(existing.clone());
    }

    let notify = Arc::new(Notify::new());
    guard.insert(key.to_string(), notify.clone());
    LocalHydrationRole::Leader(LeaderLease {
        key: key.to_string(),
        notify,
    })
}

pub async fn coordinate_proxy_hydration<T, E, Check, CheckFut, Produce, ProduceFut, TimeoutErr>(
    lease_key: &str,
    check: Check,
    produce: Produce,
    timeout_error: TimeoutErr,
) -> std::result::Result<T, E>
where
    Check: Fn() -> CheckFut,
    CheckFut: Future<Output = std::result::Result<Option<T>, E>>,
    Produce: FnOnce() -> ProduceFut,
    ProduceFut: Future<Output = std::result::Result<T, E>>,
    TimeoutErr: Fn() -> E,
{
    let deadline = Instant::now() + DEFAULT_PROXY_HYDRATION_WAIT_TIMEOUT;
    let mut produce = Some(produce);

    loop {
        if let Some(value) = check().await? {
            return Ok(value);
        }

        if Instant::now() >= deadline {
            return Err(timeout_error());
        }

        match acquire_local_hydration(lease_key) {
            LocalHydrationRole::Follower(notify) => {
                let remaining = deadline.saturating_duration_since(Instant::now());
                if remaining.is_zero() {
                    return Err(timeout_error());
                }

                let _ = tokio::time::timeout(remaining.min(FOLLOWER_WAIT_SLICE), notify.notified())
                    .await;
            }
            LocalHydrationRole::Leader(lease) => {
                // `lease` lives until this arm returns, including when the
                // future is dropped mid-`produce` (cancellation): Drop frees
                // the slot and notifies followers in both cases.
                if let Some(value) = check().await? {
                    return Ok(value);
                }

                if Instant::now() >= deadline {
                    return Err(timeout_error());
                }

                let outcome = produce
                    .take()
                    .expect("proxy hydration producer should only run once")(
                )
                .await;
                drop(lease);
                return outcome;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn map_len() -> usize {
        local_hydration_map()
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .len()
    }

    fn map_contains(key: &str) -> bool {
        local_hydration_map()
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .contains_key(key)
    }

    #[tokio::test]
    async fn leader_runs_producer_when_cache_empty() {
        let key = format!("test-leader-{}", uuid::Uuid::new_v4());
        let produced = AtomicUsize::new(0);
        let result: Result<u32, ()> = coordinate_proxy_hydration(
            &key,
            || async { Ok(None) },
            || async {
                produced.fetch_add(1, Ordering::SeqCst);
                Ok(7)
            },
            || (),
        )
        .await;
        assert_eq!(result, Ok(7));
        assert_eq!(produced.load(Ordering::SeqCst), 1);
        // Slot is released after success.
        assert!(!map_contains(&key));
    }

    #[tokio::test]
    async fn check_hit_skips_producer() {
        let key = format!("test-hit-{}", uuid::Uuid::new_v4());
        let result: Result<u32, ()> = coordinate_proxy_hydration(
            &key,
            || async { Ok(Some(42)) },
            || async { panic!("producer must not run on cache hit") },
            || (),
        )
        .await;
        assert_eq!(result, Ok(42));
        assert!(!map_contains(&key));
    }

    #[tokio::test]
    async fn slot_released_after_producer_error() {
        let key = format!("test-err-{}", uuid::Uuid::new_v4());
        let result: Result<u32, &'static str> = coordinate_proxy_hydration(
            &key,
            || async { Ok(None) },
            || async { Err("boom") },
            || "timeout",
        )
        .await;
        assert_eq!(result, Err("boom"));
        // Slot must be freed on the error path so the key is not poisoned.
        assert!(!map_contains(&key));
    }

    #[tokio::test]
    async fn cancelled_leader_does_not_poison_key() {
        let key = format!("test-cancel-{}", uuid::Uuid::new_v4());
        let before = map_len();

        // Leader future parks forever inside the producer; we cancel it by
        // dropping the timeout-wrapped future. The Drop guard must reclaim the
        // slot so a subsequent caller can become leader.
        {
            let fut = coordinate_proxy_hydration(
                &key,
                || async { Ok::<Option<u32>, ()>(None) },
                || async {
                    futures::future::pending::<()>().await;
                    unreachable!()
                },
                || (),
            );
            let _ = tokio::time::timeout(Duration::from_millis(50), fut).await;
        }
        // After the cancelled leader is dropped, the slot must be gone.
        assert!(!map_contains(&key));
        assert_eq!(map_len(), before);

        // A fresh caller must be able to win the election and produce.
        let result: Result<u32, ()> =
            coordinate_proxy_hydration(&key, || async { Ok(None) }, || async { Ok(99) }, || ())
                .await;
        assert_eq!(result, Ok(99));
        assert!(!map_contains(&key));
    }
}
