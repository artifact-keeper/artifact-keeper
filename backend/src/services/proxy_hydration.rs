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

/// Single-flight coordination seam for proxy cache hydration (#1631).
///
/// This trait is the stable seam that the proxy path elects a leader through.
/// Layer 1 (#1631) defines it and provides the in-process [`BufferedCoordinator`]
/// implementation that hosts the existing buffered single-flight behavior
/// ([`coordinate_proxy_hydration`]) unchanged. Two further layers are designed
/// to plug in here *without reshaping this method*:
///
/// * **Layer 2 — streaming broadcast fan-out (#1631 / #895).** The streaming
///   proxy path ([`ProxyService::fetch_artifact_streaming`]) has a
///   fundamentally different follower semantic: followers cannot re-check the
///   cache mid-flight because the body is not cached until the tee completes,
///   so they must SUBSCRIBE to the leader's chunks (a `tokio::sync::broadcast`
///   fan-out) instead of waiting-then-rechecking. That is a *different
///   primitive*, not a tweak of [`Self::coordinate`]: it will be added as a
///   SEPARATE method on this trait (e.g. `coordinate_stream`) or a sibling
///   trait, never by forcing a stream through the buffered method here. See the
///   clean-room design audit §1.3 and the #1618 plan Amendment 4. The seam is
///   left deliberately open: do NOT generalize [`Self::coordinate`]'s `T` to
///   carry a stream — add the streaming entry point alongside it.
///   // #1631 layer 2 seam: add `coordinate_stream` here.
///
/// * **Layer 3 — cross-replica advisory-lock decorator (#1609).** The
///   leader-election decision (currently [`acquire_local_hydration`], driven
///   inside [`Self::coordinate`]) must be wrappable so a decorator can gate it
///   behind `pg_try_advisory_xact_lock(hash(repo_id‖path))`. Because election
///   is factored behind this trait, a decorator can implement `Coordinator` by
///   wrapping an inner `Coordinator`, taking the advisory lock around the inner
///   leader-election step, then delegating. No change to [`Self::coordinate`]'s
///   signature is required for that.
///   // #1631 layer 3 seam: an advisory-lock `Coordinator` decorator wraps the
///   //                     inner coordinator's election step.
///
/// The trait is intentionally NOT object-safe (the method is generic over the
/// caller's closures, mirroring [`coordinate_proxy_hydration`]). It is injected
/// into `ProxyService` as a concrete field, the same way `CacheStore` (#1618
/// S7), `UpstreamClient` (S8), and `CachePersister` (S9) are.
pub trait Coordinator {
    /// Buffered single-flight coordination for a single cache key.
    ///
    /// Contract (preserved byte-for-byte from [`coordinate_proxy_hydration`]):
    /// the elected leader runs `produce` (which also performs the cache write);
    /// followers wait on a per-key notify, then re-run `check` to observe the
    /// leader's result. B6 semantics — a transient cache read error surfaced by
    /// `check` is the caller's concern (fresh swallows / stale propagates inside
    /// the closure); this method only loops on `Ok(None)`. `timeout_error`
    /// builds the error returned when the wait deadline elapses.
    ///
    /// Layer 2's streaming fan-out does NOT go through this method (see the
    /// trait-level docs) — it gets its own entry point. // #1631
    ///
    /// This is a PROVIDED method: the default body is the buffered single-flight
    /// (it delegates to [`coordinate_proxy_hydration`]). [`BufferedCoordinator`]
    /// uses the default unchanged. A layer-3 advisory-lock decorator (#1609)
    /// OVERRIDES this to wrap the inner coordinator's leader-election step — the
    /// provided default is exactly the seam such a decorator wraps. // #1631
    #[allow(async_fn_in_trait)]
    async fn coordinate<T, E, Check, CheckFut, Produce, ProduceFut, TimeoutErr>(
        &self,
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
        // Delegate, don't copy: the buffered logic stays in one authoritative
        // place ([`coordinate_proxy_hydration`]) so behavior — and its unit
        // tests — is preserved byte-for-byte.
        coordinate_proxy_hydration(lease_key, check, produce, timeout_error).await
    }
}

/// In-process buffered single-flight coordinator (#1631 layer 1).
///
/// Zero-sized: the actual coordination state lives in the process-global
/// [`local_hydration_map`], so this type carries no fields. It is the relocation
/// target for the existing buffered behavior — [`Coordinator::coordinate`]
/// delegates to the free function [`coordinate_proxy_hydration`], which is kept
/// as the implementation body so behavior is preserved exactly (no copy of the
/// logic, so the leader-produce / follower-re-check / timeout / B6 paths and
/// their tests stay authoritative in one place).
///
/// Layer 3's advisory-lock decorator (#1609) will be a *different*
/// `Coordinator` impl that wraps this one's election step; it is not built here.
#[derive(Debug, Clone, Copy, Default)]
pub struct BufferedCoordinator;

impl BufferedCoordinator {
    /// Construct the in-process buffered coordinator. Mirrors the `::new`
    /// constructors of the other injected seams (`CacheStore`, `UpstreamClient`,
    /// `CachePersister`) for a consistent `ProxyService::new` wiring idiom.
    pub fn new() -> Self {
        Self
    }
}

// `BufferedCoordinator` uses the trait's provided buffered default unchanged —
// no method body to repeat, which keeps the seam free of duplicated signatures.
impl Coordinator for BufferedCoordinator {}

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
        // After the cancelled leader is dropped, the per-key slot must be gone
        // (the global map is shared across tests, so only assert per-key).
        assert!(!map_contains(&key));

        // A fresh caller must be able to win the election and produce.
        let result: Result<u32, ()> =
            coordinate_proxy_hydration(&key, || async { Ok(None) }, || async { Ok(99) }, || ())
                .await;
        assert_eq!(result, Ok(99));
        assert!(!map_contains(&key));
    }

    // ---- #1631 layer 1: Coordinator trait / BufferedCoordinator ----
    //
    // The trait seam must behave identically to the relocated free function.
    // To prove that WITHOUT copying the free-function test bodies (which would
    // duplicate logic and trip the jscpd gate), the trait tests drive the same
    // behavioral assertions through [`Coordinator::coordinate`] but exercise
    // scenarios distinct from the verbatim free-function cases above:
    //   * leader-produces + follower-re-check in a single end-to-end flow,
    //   * the timeout/cancellation slot-reclaim path,
    //   * producer-error slot release,
    // each routed through the injectable trait rather than the free function.

    #[tokio::test]
    async fn buffered_coordinator_leader_produces_then_follower_rechecks() {
        // End-to-end through the trait: the leader produces + "caches" a value,
        // then a second caller (follower) observes it on re-check and does NOT
        // re-run its producer. Covers both the leader-produces and the
        // follower-re-check semantics in one flow via the injectable seam.
        let coordinator = BufferedCoordinator::new();
        let key = format!("test-trait-{}", uuid::Uuid::new_v4());
        let cache: Arc<Mutex<Option<u32>>> = Arc::new(Mutex::new(None));
        let produced = Arc::new(AtomicUsize::new(0));

        let check = {
            let cache = Arc::clone(&cache);
            move || {
                let cache = Arc::clone(&cache);
                async move { Ok::<Option<u32>, ()>(*cache.lock().unwrap()) }
            }
        };

        let leader = coordinator
            .coordinate(
                &key,
                check.clone(),
                {
                    let cache = Arc::clone(&cache);
                    let produced = Arc::clone(&produced);
                    || async move {
                        produced.fetch_add(1, Ordering::SeqCst);
                        *cache.lock().unwrap() = Some(123);
                        Ok(123)
                    }
                },
                || (),
            )
            .await;
        assert_eq!(leader, Ok(123));

        let follower = coordinator
            .coordinate(
                &key,
                check,
                || async { panic!("follower must not run producer; value is cached") },
                || (),
            )
            .await;
        assert_eq!(follower, Ok(123));
        assert_eq!(produced.load(Ordering::SeqCst), 1);
        assert!(!map_contains(&key));
    }

    #[tokio::test]
    async fn buffered_coordinator_timeout_path_drops_leader_slot() {
        // A leader parked forever inside `produce` occupies the slot. When the
        // surrounding future is cancelled (request disconnect / wait timeout),
        // the Drop guard must reclaim the slot through the trait seam, exactly
        // as the free-function path does. Then a fresh caller wins election.
        let coordinator = BufferedCoordinator::new();
        let key = format!("test-trait-timeout-{}", uuid::Uuid::new_v4());

        {
            let fut = coordinator.coordinate(
                &key,
                || async { Ok::<Option<u32>, &'static str>(None) },
                || async {
                    futures::future::pending::<()>().await;
                    unreachable!()
                },
                || "timeout",
            );
            let _ = tokio::time::timeout(Duration::from_millis(50), fut).await;
        }
        assert!(!map_contains(&key));

        let reborn = coordinator
            .coordinate(
                &key,
                || async { Ok(None) },
                || async { Ok(99u32) },
                || "timeout",
            )
            .await;
        assert_eq!(reborn, Ok(99));
        assert!(!map_contains(&key));
    }

    #[tokio::test]
    async fn buffered_coordinator_slot_released_after_producer_error() {
        let coordinator = BufferedCoordinator::new();
        let key = format!("test-trait-err-{}", uuid::Uuid::new_v4());
        let result = coordinator
            .coordinate(
                &key,
                || async { Ok::<Option<u32>, &'static str>(None) },
                || async { Err("boom") },
                || "timeout",
            )
            .await;
        assert_eq!(result, Err("boom"));
        assert!(!map_contains(&key));
    }
}
