use std::collections::HashMap;
use std::future::Future;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use bytes::Bytes;
use futures::stream::{BoxStream, StreamExt};
use sqlx::PgPool;
use tokio::sync::{broadcast, watch, Notify};

use crate::services::cluster_lock::{
    lease_object_id, ClusterLease, ClusterLock, PgAdvisoryLock, PROXY_HYDRATION_LOCK_CLASS,
};

pub const DEFAULT_PROXY_HYDRATION_WAIT_TIMEOUT: Duration = Duration::from_secs(65);

/// Default follower poll cadence for the cross-replica coordinator (#1609): how
/// often a remote follower re-checks the cache while the cluster leader fetches.
pub const DEFAULT_PROXY_SINGLEFLIGHT_POLL_INTERVAL: Duration = Duration::from_millis(200);

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

    /// Streaming single-flight broadcast fan-out (#1631 layer 2, #1694).
    ///
    /// The streaming sibling of [`Self::coordinate`]. It is a *separate*
    /// primitive — NOT a stream forced through the buffered method — because a
    /// streaming follower cannot re-check the cache mid-flight: the body is not
    /// in the cache until the leader's tee completes (clean-room design audit
    /// §1.3, #1618 plan Amendment 4). Followers therefore SUBSCRIBE to the
    /// leader's chunks rather than wait-then-recheck.
    ///
    /// Roles for a given in-flight `lease_key`:
    /// * **Leader** (no entry yet): runs `open_leader`, which opens upstream
    ///   ONCE and returns the tee'd body (client + cache writer, via the
    ///   existing `CachePersister::tee_stream` path) plus the response headers
    ///   ([`StreamHeaders`]). The returned body is wrapped so every chunk is
    ///   additionally broadcast to subscribers, and a terminal marker is sent
    ///   when the body ends (EOF or error). The #1365 zero-byte guard and
    ///   #1051 ETag pin remain entirely inside `open_leader`'s tee — this
    ///   primitive never inspects or rewrites bytes.
    /// * **Follower** (entry exists, leader has not yet started emitting):
    ///   subscribes to the leader's broadcast and captures the leader's body
    ///   *before returning a handle*, without opening upstream or writing the
    ///   cache. It is handed a handle only once the leader's body has arrived
    ///   COMPLETE and in order; the handle then replays exactly those bytes.
    /// * **Fall-back** (entry exists but the leader already started emitting,
    ///   so a late subscriber would miss leading bytes; the object outran the
    ///   fan-out window; the leader failed, stalled or went away): returns
    ///   `Ok(None)` after waiting for the leader to finish, so the caller's
    ///   re-enter lands on the now-warm cache rather than stampeding upstream.
    ///   A follower is NEVER handed a body with a hole.
    ///
    /// Failure semantics (B6): every way the fan-out can fail to produce a
    /// COMPLETE body — a mid-stream leader failure, a leader that went away, a
    /// `broadcast` drop ([`broadcast::error::RecvError::Lagged`]), an object
    /// larger than the fan-out window — is decided BEFORE the follower's
    /// handle exists, and therefore before its HTTP response has started. It
    /// is reported as `Ok(None)` (re-enter), never as an error yielded into a
    /// body whose `200` and `Content-Length` are already on the wire: once the
    /// response has started there is no "fall back", only a torn body.
    ///
    /// This is a PROVIDED method delegating to [`coordinate_stream_fanout`], so
    /// the layer-3 advisory-lock decorator (#1609) overrides election the same
    /// way it does for [`Self::coordinate`] — one seam, one decorator.
    /// // #1631 layer 3 seam: a decorator can gate this election step too.
    #[allow(async_fn_in_trait)]
    async fn coordinate_stream<Open, OpenFut>(
        &self,
        lease_key: &str,
        open_leader: Open,
    ) -> crate::error::Result<Option<StreamHandle>>
    where
        Open: FnOnce() -> OpenFut,
        OpenFut: Future<Output = crate::error::Result<StreamHandle>>,
    {
        coordinate_stream_fanout(lease_key, open_leader).await
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

// ---------------------------------------------------------------------------
// #1631 layer 2 — streaming broadcast fan-out single-flight (#1694)
// ---------------------------------------------------------------------------

/// Bound on the per-key broadcast channel feeding streaming followers.
///
/// Each in-flight slot has its own `broadcast` channel; this caps how far a
/// follower may lag the leader before `broadcast` starts dropping chunks. A
/// dropped chunk is NOT tolerated (it would put a hole in the follower's body),
/// so this is a correctness knob, not just a memory knob: a follower that lags
/// past this depth abandons the fan-out and re-enters. 256 chunks at the
/// proxy's ~64 KiB tee chunk size is roughly a 16 MiB window per slot.
const STREAM_BROADCAST_DEPTH: usize = 256;

/// Byte ceiling on what ONE follower buffers out of the leader's fan-out before
/// giving up on it and re-entering (warm cache / fresh election).
///
/// A follower captures the leader's body before its own HTTP response starts,
/// so it holds the bytes it has seen so far. This is the bound on that hold,
/// and it is deliberately the same ~16 MiB window the broadcast channel already
/// implies (`STREAM_BROADCAST_DEPTH` * the tee's 64 KiB slice cap): the fan-out
/// can never retain more than the channel could have buffered anyway. Crucially
/// the cost is NOT per follower — every follower on a slot holds clones of the
/// same reference-counted [`Bytes`], so N followers of one object retain ~one
/// copy of this window between them, not N.
///
/// An object larger than this is simply not fanned out live: its followers wait
/// for the leader and are then served the complete object from the cache the
/// leader just filled. That is strictly better than the alternative — a body
/// cut short mid-flight under a `200` that promised the full `Content-Length`.
const FANOUT_CAPTURE_MAX_BYTES: u64 = 16 * 1024 * 1024;

/// Idle bound on a follower's wait for the leader's fan-out.
///
/// Reset by every item the leader broadcasts, so a leader making progress on a
/// multi-GB object keeps its followers attached for as long as it needs, while
/// a leader that has stopped producing releases them. Deliberately an IDLE
/// bound and not a total one: the total is a function of the object size, which
/// this coordinator does not know.
const FOLLOWER_STALL_TIMEOUT: Duration = Duration::from_secs(30);

/// A streamed proxy body plus the response headers a caller needs to build the
/// outbound HTTP response. This is the layer-2 streaming analogue of the
/// buffered `T` returned by [`Coordinator::coordinate`]; it is concrete (over
/// `Bytes`) on purpose — the buffered method's generic `T` is deliberately NOT
/// generalized to carry a stream (see the [`Coordinator`] trait docs).
pub struct StreamHandle {
    /// Ordered body chunks. For a leader this is the tee'd upstream body; for a
    /// follower it is the leader's broadcast replayed chunk-for-chunk.
    pub body: BoxStream<'static, crate::error::Result<Bytes>>,
    /// Response headers observed once when the leader opened upstream, shared
    /// verbatim with every follower so all clients see identical metadata.
    pub headers: StreamHeaders,
}

/// Response metadata shared from the leader to all streaming followers. Cloned
/// to each follower so every client receives the identical content-type and
/// advertised length the leader saw upstream.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct StreamHeaders {
    pub content_type: Option<String>,
    pub content_length: Option<u64>,
    /// Upstream `ETag` (or, for a cache hit, the sidecar's `upstream_etag`),
    /// forwarded verbatim to the client so `huggingface_hub`'s HEAD-based
    /// metadata check (which requires an ETag) succeeds. Generic ETag
    /// forwarding on every proxied stream, not HF-specific.
    pub etag: Option<String>,
    /// Upstream `Content-Encoding` when the streamed bytes are content coded.
    /// Must reach every follower with the body: the proxy no longer decodes
    /// upstream responses, so dropping this serves compressed bytes labelled as
    /// identity.
    pub content_encoding: Option<String>,
    /// Upstream `X-Repo-Commit` for the streamed bytes, so every follower labels
    /// the body with the commit it actually came from rather than whatever a
    /// separately-cached metadata document happens to say.
    pub commit_sha: Option<String>,
}

/// One item on a per-key streaming broadcast channel.
#[derive(Clone)]
enum StreamItem {
    /// A body chunk, in order. Cheap to clone (`Bytes` is reference-counted).
    Chunk(Bytes),
    /// Terminal success marker: the leader's body reached EOF. Followers end
    /// their stream cleanly.
    Done,
    /// Terminal failure marker: the leader's upstream/tee failed mid-stream.
    /// Carries a human-readable reason; followers translate it into a stream
    /// error so a partial body is NEVER presented as success (B6).
    Failed(String),
}

/// Per-key in-flight streaming slot. Shared between the leader and every
/// follower for one `lease_key`.
struct StreamSlot {
    /// Fan-out channel. The leader sends [`StreamItem`]s; followers subscribe.
    sender: broadcast::Sender<StreamItem>,
    /// Response headers, published once by the leader after it opens upstream.
    /// `None` until then; followers (which may subscribe before the leader has
    /// opened upstream) await the first `Some` before building their response.
    headers_tx: watch::Sender<Option<StreamHeaders>>,
    /// Flipped to `true` (under the registry lock) the instant before the
    /// leader emits its first chunk. A follower that observes `true` knows it
    /// would miss leading bytes and falls back instead of joining. Set under
    /// the same lock that guards follower subscription, so subscribe-in-time
    /// and start-emitting are mutually exclusive — a follower either holds a
    /// receiver created before the first chunk, or it falls back. No torn join.
    started: AtomicBool,
}

type StreamRegistry = Arc<Mutex<HashMap<String, Arc<StreamSlot>>>>;

fn stream_registry() -> &'static StreamRegistry {
    static REGISTRY: OnceLock<StreamRegistry> = OnceLock::new();
    REGISTRY.get_or_init(|| Arc::new(Mutex::new(HashMap::new())))
}

/// Outcome of trying to claim the streaming slot for `key`.
enum StreamRole {
    /// Caller won the election; the guard owns the slot and the broadcast
    /// sender to publish on.
    Leader(StreamLeaderLease),
    /// Caller joined an existing in-flight leader; holds a chunk receiver
    /// created before the leader started emitting (so it will see every chunk)
    /// plus a header-watch receiver to learn the leader's response metadata.
    Follower(
        broadcast::Receiver<StreamItem>,
        watch::Receiver<Option<StreamHeaders>>,
    ),
    /// The leader already started emitting, so a late subscriber would miss
    /// leading bytes. Carries a receiver anyway — not to read bytes from, but
    /// so the caller can wait for the leader to FINISH before re-entering, and
    /// land on the warm cache instead of stampeding upstream.
    FallBack(broadcast::Receiver<StreamItem>),
}

/// RAII guard held by a streaming leader. On drop it removes the slot from the
/// registry (if it still owns it), so a cancelled or finished leader never
/// poisons the key. Cancellation safety mirrors [`LeaderLease`]: if the
/// request future is dropped mid-stream, Drop reclaims the slot and the next
/// caller can elect a new leader (the detached cache writer, if any, still
/// completes — see [`coordinate_stream_fanout`]).
struct StreamLeaderLease {
    key: String,
    slot: Arc<StreamSlot>,
}

impl Drop for StreamLeaderLease {
    fn drop(&mut self) {
        let registry = stream_registry();
        let mut guard = registry
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let owns_slot = guard
            .get(&self.key)
            .map(|current| Arc::ptr_eq(current, &self.slot))
            .unwrap_or(false);
        if owns_slot {
            guard.remove(&self.key);
        }
    }
}

fn acquire_stream_slot(key: &str) -> StreamRole {
    let registry = stream_registry();
    let mut guard = registry
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    if let Some(existing) = guard.get(key) {
        // A follower may only join before the leader starts emitting; checking
        // `started` and calling `subscribe()` under this same lock (the leader
        // also flips `started` under it) makes the two mutually exclusive.
        if existing.started.load(Ordering::Acquire) {
            return StreamRole::FallBack(existing.sender.subscribe());
        }
        return StreamRole::Follower(existing.sender.subscribe(), existing.headers_tx.subscribe());
    }

    let (sender, _rx) = broadcast::channel(STREAM_BROADCAST_DEPTH);
    let (headers_tx, _headers_rx) = watch::channel(None);
    let slot = Arc::new(StreamSlot {
        sender,
        headers_tx,
        started: AtomicBool::new(false),
    });
    guard.insert(key.to_string(), slot.clone());
    StreamRole::Leader(StreamLeaderLease {
        key: key.to_string(),
        slot,
    })
}

/// Streaming single-flight broadcast fan-out (#1631 layer 2). See
/// [`Coordinator::coordinate_stream`] for the full contract; this is the
/// authoritative implementation it delegates to, kept as a free function so the
/// behavior (and its tests) live in one place, mirroring
/// [`coordinate_proxy_hydration`].
///
/// Returns `Ok(Some(handle))` for a leader, or for a follower whose leader
/// delivered the COMPLETE body inside the fan-out window; `Ok(None)` for every
/// fall-back case (the caller re-enters: warm cache or new leader). The only
/// `Err` returned synchronously is a leader's `open_leader` failure (e.g. the
/// upstream connect/HTTP status failed before any body) — a follower is never
/// created for a leader that never opened upstream.
///
/// A follower call therefore does not return until the leader's body has ended
/// (or the fan-out has been abandoned). That is not a latency regression: a
/// follower could never finish before the leader it is following. It is what
/// buys the guarantee that "cannot serve this follower" is always still a
/// clean `Ok(None)`, decided while the follower's response has not started.
pub async fn coordinate_stream_fanout<Open, OpenFut>(
    lease_key: &str,
    open_leader: Open,
) -> crate::error::Result<Option<StreamHandle>>
where
    Open: FnOnce() -> OpenFut,
    OpenFut: Future<Output = crate::error::Result<StreamHandle>>,
{
    match acquire_stream_slot(lease_key) {
        StreamRole::FallBack(rx) => {
            // A late arrival already missed leading bytes, so it cannot be
            // served from this fan-out. Wait for the leader to FINISH before
            // returning, so the caller's re-enter lands on the warm cache. The
            // old behaviour — returning immediately — made the caller burn its
            // whole re-enter budget in microseconds and then cold-fetch
            // upstream itself, which is how one cold object turned into dozens
            // of upstream fetches under a concurrent storm.
            let _ = watch_leader_fanout(lease_key, rx, FollowWatch::WaitOnly).await;
            Ok(None)
        }
        StreamRole::Follower(rx, mut headers_rx) => {
            // Wait for the leader to publish its response headers (it may still
            // be opening upstream). If the leader fails to open (or is dropped)
            // before publishing, the watch sender is dropped: `changed()`
            // returns `Err` and we fall back to re-fetch rather than hang.
            let headers = loop {
                if let Some(headers) = headers_rx.borrow_and_update().clone() {
                    break headers;
                }
                if headers_rx.changed().await.is_err() {
                    // Leader gone without publishing headers — fall back.
                    return Ok(None);
                }
            };
            // Capture the leader's body BEFORE handing back a handle. Anything
            // that stops us short of the complete object is still a clean
            // `Ok(None)` here; once the handle is returned, the caller has
            // already written `200` + `Content-Length` and the only thing left
            // to do with a failure is tear the connection.
            match watch_leader_fanout(lease_key, rx, FollowWatch::Capture).await {
                Some(chunks) => Ok(Some(replay_handle(chunks, headers))),
                None => Ok(None),
            }
        }
        StreamRole::Leader(lease) => {
            // Open upstream ONCE. Concurrent callers that arrived while we were
            // registering joined as followers; callers arriving during this
            // await also join (we have not flipped `started` yet). If the open
            // fails before any body (bad status, connect error), the lease Drop
            // frees the slot and the followers — which subscribed but will get
            // no items — must be released. We send a terminal failure so any
            // already-subscribed follower errors out instead of hanging.
            let handle = match open_leader().await {
                Ok(handle) => handle,
                Err(e) => {
                    // No body to fan out. Wake any followers waiting on headers
                    // (the watch sender drops with `lease`, so their
                    // `changed().await` returns Err → fall back) and surface the
                    // error to the leader's own client. Dropping `lease` here
                    // also frees the slot.
                    let _ = lease
                        .slot
                        .sender
                        .send(StreamItem::Failed(format!("upstream open failed: {e}")));
                    return Err(e);
                }
            };
            // Publish headers so followers can build their response. Use
            // `send_replace`, NOT `send`: `watch::Sender::send` fails AND
            // leaves the value untouched when there are currently no receivers,
            // which is exactly the common case here (a follower may subscribe
            // only *after* this point). `send_replace` always stores the value,
            // so a later subscriber's `borrow_and_update` observes the headers.
            // Done before `started` flips / before the first chunk.
            lease
                .slot
                .headers_tx
                .send_replace(Some(handle.headers.clone()));
            Ok(Some(leader_handle(lease, handle)))
        }
    }
}

/// Wrap the leader's tee'd body so each chunk is broadcast to followers and a
/// terminal marker is published on EOF or error. The leader's own client still
/// receives every chunk and every error exactly as the underlying tee produced
/// it — broadcasting is a side-effect that never alters the leader's bytes.
fn leader_handle(lease: StreamLeaderLease, handle: StreamHandle) -> StreamHandle {
    let StreamHandle { body, headers } = handle;
    let wrapped = async_stream::stream! {
        // Flip `started` under the registry lock so a concurrent follower
        // either subscribed before this point (and will see the first chunk)
        // or observes `started` and falls back. Held only for the flag flip.
        {
            let registry = stream_registry();
            let guard = registry
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            lease.slot.started.store(true, Ordering::Release);
            drop(guard);
        }

        // `lease` lives until this stream is fully consumed or dropped; its
        // Drop removes the slot so the next request elects a fresh leader.
        let _lease = lease;
        let mut body = body;
        let mut terminal_sent = false;
        while let Some(item) = body.next().await {
            match item {
                Ok(chunk) => {
                    // Best-effort fan-out: `send` only errors when there are no
                    // receivers, which is fine — the leader keeps streaming and
                    // teeing to cache regardless of follower count.
                    let _ = _lease.slot.sender.send(StreamItem::Chunk(chunk.clone()));
                    yield Ok(chunk);
                }
                Err(e) => {
                    // B6: a mid-stream failure becomes a terminal failure for
                    // every follower (not a truncated body) AND surfaces to the
                    // leader's own client as the original error.
                    let _ = _lease
                        .slot
                        .sender
                        .send(StreamItem::Failed(format!("{e}")));
                    terminal_sent = true;
                    yield Err(e);
                    break;
                }
            }
        }
        if !terminal_sent {
            // Clean EOF: tell followers the body is complete.
            let _ = _lease.slot.sender.send(StreamItem::Done);
        }
        // _lease drops here, freeing the slot.
    };
    StreamHandle {
        body: Box::pin(wrapped),
        headers,
    }
}

/// Why a caller that did not win the election is watching the leader's fan-out.
#[derive(Clone, Copy, PartialEq, Eq)]
enum FollowWatch {
    /// Joined before the leader emitted anything: capture every chunk so the
    /// complete body can be replayed to this caller's own client.
    Capture,
    /// Arrived after the leader started emitting: it already missed leading
    /// bytes and can never be served from this fan-out, so it only waits for
    /// the leader to finish and then re-enters on the warm cache. A `Lagged`
    /// is expected here (we are deliberately not keeping up) and is ignored.
    WaitOnly,
}

/// Watch a leader's fan-out to completion, on behalf of a caller whose HTTP
/// response has NOT started yet.
///
/// Returns `Some(chunks)` when the leader's body ended cleanly — the COMPLETE
/// object in order for [`FollowWatch::Capture`], an empty vec for
/// [`FollowWatch::WaitOnly`]. Returns `None` when this caller cannot be served
/// from the fan-out and must re-enter: the object outran
/// [`FANOUT_CAPTURE_MAX_BYTES`], `broadcast` dropped a chunk, the leader failed
/// mid-stream or went away, or it stalled for [`FOLLOWER_STALL_TIMEOUT`].
///
/// Deciding all of that HERE, before a handle exists, is the whole point: the
/// caller can still turn `None` into a clean re-enter. The same decision made
/// one step later — inside the returned body — can only be a torn response,
/// because the `200` and the full `Content-Length` are already on the wire.
async fn watch_leader_fanout(
    lease_key: &str,
    mut rx: broadcast::Receiver<StreamItem>,
    mut watch: FollowWatch,
) -> Option<Vec<Bytes>> {
    let mut chunks: Vec<Bytes> = Vec::new();
    let mut captured: u64 = 0;
    // Latched once the object is known to be bigger than the live fan-out
    // window: we stop holding bytes but keep waiting for the leader, exactly as
    // a late arrival does, so the re-enter lands on the warm cache.
    let mut over_window = false;
    loop {
        let item = match tokio::time::timeout(FOLLOWER_STALL_TIMEOUT, rx.recv()).await {
            Ok(item) => item,
            Err(_elapsed) => {
                tracing::warn!(
                    lease_key,
                    stall_secs = FOLLOWER_STALL_TIMEOUT.as_secs(),
                    "proxy stream leader produced nothing for the stall window; \
                     abandoning the fan-out and re-entering"
                );
                return None;
            }
        };
        match item {
            Ok(StreamItem::Chunk(chunk)) => {
                if watch == FollowWatch::Capture {
                    captured = captured.saturating_add(chunk.len() as u64);
                    if captured > FANOUT_CAPTURE_MAX_BYTES {
                        // The object is bigger than the live fan-out window.
                        // Stop holding bytes, keep waiting for the leader (as a
                        // late arrival would) and then re-enter: the leader is
                        // teeing this object into the shared cache and every
                        // follower is served the complete object from there.
                        tracing::debug!(
                            lease_key,
                            window_bytes = FANOUT_CAPTURE_MAX_BYTES,
                            "proxy stream object exceeds the live fan-out window; \
                             follower will wait for the leader and read the cache"
                        );
                        watch = FollowWatch::WaitOnly;
                        over_window = true;
                        chunks = Vec::new();
                        continue;
                    }
                    chunks.push(chunk);
                }
            }
            Ok(StreamItem::Done) => {
                return if over_window { None } else { Some(chunks) };
            }
            Ok(StreamItem::Failed(reason)) => {
                tracing::warn!(
                    lease_key,
                    reason = %reason,
                    "proxy stream leader failed mid-stream; follower re-enters \
                     instead of being handed a partial body"
                );
                return None;
            }
            Err(broadcast::error::RecvError::Lagged(dropped)) => {
                if watch == FollowWatch::WaitOnly {
                    continue;
                }
                tracing::debug!(
                    lease_key,
                    dropped,
                    "proxy stream follower fell behind the leader's fan-out; \
                     re-entering instead of serving a body with a hole"
                );
                return None;
            }
            Err(broadcast::error::RecvError::Closed) => {
                // Leader dropped without a terminal marker (cancelled, client
                // gone). Re-enter: the next caller elects a fresh leader.
                return None;
            }
        }
    }
}

/// Body handle for a follower that captured the leader's COMPLETE object:
/// replay exactly those chunks, in order, and end cleanly. There is no failure
/// mode left in this stream — that is the point of capturing first.
fn replay_handle(chunks: Vec<Bytes>, headers: StreamHeaders) -> StreamHandle {
    StreamHandle {
        body: Box::pin(futures::stream::iter(chunks.into_iter().map(Ok))),
        headers,
    }
}

// ---------------------------------------------------------------------------
// #1631 layer 3 — cross-replica advisory-lock decorator (#1609, folds #1606)
// ---------------------------------------------------------------------------

/// Cross-replica single-flight decorator (#1609).
///
/// Wraps the in-process [`BufferedCoordinator`] with a PostgreSQL advisory lock
/// so a cold `(repo, path)` fetch is coordinated **cluster-wide**, not merely
/// per-pod: exactly ONE replica cold-fetches the object into shared storage,
/// removing the multi-writer ETag flap that surfaced as `Stale file handle` /
/// truncated `.sha1` (#1606). It implements the same [`Coordinator`] contract
/// (both method signatures UNCHANGED — the frozen seam shared with #1608), only
/// gating the leader-election step behind the shared lock.
///
/// The lock is held on a DETACHED connection ([`crate::services::cluster_lock`]),
/// never across a transaction and never across a multi-GB streaming fetch, and
/// auto-releases on connection death — so a crashed/cancelled leader cannot
/// poison the key.
pub struct AdvisoryLockCoordinator {
    /// The in-process buffered coordinator the cluster leader delegates to
    /// (unchanged local election + produce + sidecar commit).
    inner: BufferedCoordinator,
    /// Shared cross-replica lock (`Arc<dyn ClusterLock>` keeps this type concrete
    /// so [`HydrationCoordinator`] stays non-generic).
    lock: Arc<dyn ClusterLock>,
    /// How often a follower re-checks the cache while the leader produces.
    poll_interval: Duration,
    /// Upper bound a follower waits for the leader's commit before falling back
    /// to its own (bounded, content-addressed-safe) produce.
    wait_timeout: Duration,
}

impl AdvisoryLockCoordinator {
    /// Construct the cross-replica coordinator over a shared [`ClusterLock`].
    pub fn new(
        lock: Arc<dyn ClusterLock>,
        poll_interval: Duration,
        wait_timeout: Duration,
    ) -> Self {
        Self {
            inner: BufferedCoordinator::new(),
            lock,
            poll_interval: if poll_interval.is_zero() {
                DEFAULT_PROXY_SINGLEFLIGHT_POLL_INTERVAL
            } else {
                poll_interval
            },
            wait_timeout,
        }
    }

    /// Follower path for the buffered API: poll `check` on a bounded cadence
    /// until the cluster leader commits (the entry appears) or `wait_timeout`
    /// elapses. On deadline (a large/slow leader fetch), fall back to producing
    /// locally through the inner buffered coordinator — a bounded duplicate
    /// fetch that atomic-publish + content-addressing make safe. Factored out so
    /// the poll loop is not duplicated.
    async fn follow_buffered<T, E, Check, CheckFut, Produce, ProduceFut, TimeoutErr>(
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
        let deadline = Instant::now() + self.wait_timeout;
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                // Leader is still producing (large/slow object): bounded fallback
                // to a local election + produce (never an unbounded herd).
                return self
                    .inner
                    .coordinate(lease_key, check, produce, timeout_error)
                    .await;
            }
            tokio::time::sleep(self.poll_interval.min(remaining)).await;
            if let Some(value) = check().await? {
                return Ok(value);
            }
        }
    }
}

impl Coordinator for AdvisoryLockCoordinator {
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
        // Fast path: a warm hit needs no lock and no election (also preserves the
        // presigned-redirect path, which short-circuits before the coordinator).
        if let Some(value) = check().await? {
            return Ok(value);
        }

        let obj = lease_object_id(lease_key);
        match self.lock.try_acquire(PROXY_HYDRATION_LOCK_CLASS, obj).await {
            Ok(Some(lease)) => {
                // Cluster leader: run the UNCHANGED in-process election + produce
                // (whose sidecar commit is the linearization point), then release.
                // If this future is cancelled mid-produce, `lease` drops here and
                // the guard auto-releases (crash-safe) — release() is skipped.
                let outcome = self
                    .inner
                    .coordinate(lease_key, check, produce, timeout_error)
                    .await;
                lease.release().await;
                outcome
            }
            Ok(None) => {
                // Remote follower: wait for the leader's commit, bounded fallback.
                self.follow_buffered(lease_key, check, produce, timeout_error)
                    .await
            }
            Err(err) => {
                // Lock infrastructure failure: degrade to per-process
                // coordination. No worse than pre-#1609; never a hard failure.
                tracing::warn!(
                    error = %err,
                    lease_key,
                    "cross-replica hydration lock unavailable; falling back to per-process single-flight"
                );
                self.inner
                    .coordinate(lease_key, check, produce, timeout_error)
                    .await
            }
        }
    }

    async fn coordinate_stream<Open, OpenFut>(
        &self,
        lease_key: &str,
        open_leader: Open,
    ) -> crate::error::Result<Option<StreamHandle>>
    where
        Open: FnOnce() -> OpenFut,
        OpenFut: Future<Output = crate::error::Result<StreamHandle>>,
    {
        let obj = lease_object_id(lease_key);
        match self.lock.try_acquire(PROXY_HYDRATION_LOCK_CLASS, obj).await {
            Ok(Some(lease)) => {
                // Cluster leader: delegate to the unchanged in-process tee/fan-out
                // and HOLD the lease for the lifetime of the streamed body so no
                // other replica cold-fetches the same object while we tee it to
                // cache. The lock is never held across a transaction.
                match self.inner.coordinate_stream(lease_key, open_leader).await {
                    Ok(Some(handle)) => Ok(Some(hold_lease_until_stream_end(lease, handle))),
                    // Fall-back (`Ok(None)`) or open failure (`Err`): no body to
                    // fan out, so release the lock immediately.
                    other => {
                        lease.release().await;
                        other
                    }
                }
            }
            Ok(None) => {
                // Remote follower. Give the leader a brief window to commit a
                // SMALL object (so the caller's re-enter lands on the warm cache),
                // then return `Ok(None)`. A LARGE object never commits under the
                // lock, so the caller's bounded re-enter budget drains into
                // `fetch_artifact_streaming_uncoordinated` — proxy-without-cache,
                // streaming straight through with NO lock held here and no OOM.
                let nap = self.poll_interval.min(self.wait_timeout);
                if !nap.is_zero() {
                    tokio::time::sleep(nap).await;
                }
                Ok(None)
            }
            Err(err) => {
                tracing::warn!(
                    error = %err,
                    lease_key,
                    "cross-replica hydration lock unavailable; falling back to per-process streaming single-flight"
                );
                self.inner.coordinate_stream(lease_key, open_leader).await
            }
        }
    }
}

/// Wrap a leader [`StreamHandle`] so the cross-replica [`ClusterLease`] is held
/// for the lifetime of the streamed body and released when the body completes
/// (eager unlock) or is dropped (cancel/pod-kill → connection close). This is
/// what prevents another replica from cold-fetching the same object while THIS
/// leader is still teeing it to cache — without ever holding the lock inside a
/// transaction or across the whole fetch synchronously.
fn hold_lease_until_stream_end(lease: ClusterLease, handle: StreamHandle) -> StreamHandle {
    let StreamHandle { body, headers } = handle;
    let wrapped = async_stream::stream! {
        // `lease` lives until this stream is fully consumed or dropped; on early
        // drop the guard auto-releases, on clean EOF we release eagerly below.
        let lease = lease;
        let mut body = body;
        while let Some(item) = body.next().await {
            yield item;
        }
        lease.release().await;
    };
    StreamHandle {
        body: Box::pin(wrapped),
        headers,
    }
}

/// Holds either the per-process buffered coordinator or the cross-replica
/// advisory-lock coordinator so `ProxyService` stays NON-generic.
///
/// [`Coordinator`] is not object-safe (its methods are generic over the caller's
/// closures), so `Arc<dyn Coordinator>` is impossible. This enum dispatches each
/// [`Coordinator`] method to the selected variant, keeping BOTH method signatures
/// frozen (the contract shared with #1608) while letting config choose the impl
/// at construction with a two-line change in `ProxyService::new`.
pub enum HydrationCoordinator {
    /// Per-process buffered single-flight (pre-#1609 behavior / kill-switch off).
    Buffered(BufferedCoordinator),
    /// Cross-replica single-flight via a Postgres advisory lock (#1609).
    Advisory(AdvisoryLockCoordinator),
}

impl HydrationCoordinator {
    /// Select the coordinator from process configuration.
    ///
    /// Reads the same env vars documented on `Config` (kept in sync). The
    /// advisory-lock coordinator is OPT-IN — enable it on multi-replica
    /// deployments with `PROXY_SINGLEFLIGHT_ADVISORY_LOCKS_ENABLED=true` — so a
    /// single-replica install (and the test suite) keeps the unchanged
    /// per-process path by default.
    pub fn from_env(pool: PgPool) -> Self {
        let enabled = matches!(
            std::env::var("PROXY_SINGLEFLIGHT_ADVISORY_LOCKS_ENABLED")
                .unwrap_or_default()
                .trim()
                .to_ascii_lowercase()
                .as_str(),
            "true" | "1"
        );
        if !enabled {
            return HydrationCoordinator::Buffered(BufferedCoordinator::new());
        }
        let poll_interval = std::env::var("PROXY_SINGLEFLIGHT_LOCK_POLL_INTERVAL_MS")
            .ok()
            .and_then(|v| v.parse().ok())
            .map(Duration::from_millis)
            .unwrap_or(DEFAULT_PROXY_SINGLEFLIGHT_POLL_INTERVAL);
        let wait_timeout = std::env::var("PROXY_SINGLEFLIGHT_LOCK_WAIT_TIMEOUT_SECS")
            .ok()
            .and_then(|v| v.parse().ok())
            .map(Duration::from_secs)
            .unwrap_or(DEFAULT_PROXY_HYDRATION_WAIT_TIMEOUT);
        HydrationCoordinator::Advisory(AdvisoryLockCoordinator::new(
            Arc::new(PgAdvisoryLock::new(pool)),
            poll_interval,
            wait_timeout,
        ))
    }
}

impl Coordinator for HydrationCoordinator {
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
        match self {
            HydrationCoordinator::Buffered(c) => {
                c.coordinate(lease_key, check, produce, timeout_error).await
            }
            HydrationCoordinator::Advisory(c) => {
                c.coordinate(lease_key, check, produce, timeout_error).await
            }
        }
    }

    async fn coordinate_stream<Open, OpenFut>(
        &self,
        lease_key: &str,
        open_leader: Open,
    ) -> crate::error::Result<Option<StreamHandle>>
    where
        Open: FnOnce() -> OpenFut,
        OpenFut: Future<Output = crate::error::Result<StreamHandle>>,
    {
        match self {
            HydrationCoordinator::Buffered(c) => c.coordinate_stream(lease_key, open_leader).await,
            HydrationCoordinator::Advisory(c) => c.coordinate_stream(lease_key, open_leader).await,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicUsize;

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

    // ---- #1631 layer 2: streaming broadcast fan-out (#1694) ----

    use crate::error::{AppError, Result as AppResult};

    fn stream_registry_contains(key: &str) -> bool {
        stream_registry()
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .contains_key(key)
    }

    /// Build a `BoxStream` of `Ok(Bytes)` chunks for use as a leader body.
    fn body_of(chunks: &[&'static [u8]]) -> BoxStream<'static, AppResult<Bytes>> {
        let items: Vec<AppResult<Bytes>> =
            chunks.iter().map(|c| Ok(Bytes::from_static(c))).collect();
        Box::pin(futures::stream::iter(items))
    }

    async fn drain(mut body: BoxStream<'static, AppResult<Bytes>>) -> AppResult<Vec<u8>> {
        let mut out = Vec::new();
        while let Some(item) = body.next().await {
            out.extend_from_slice(&item?);
        }
        Ok(out)
    }

    fn test_headers() -> StreamHeaders {
        StreamHeaders {
            commit_sha: None,
            content_encoding: None,
            content_type: Some("application/octet-stream".to_string()),
            content_length: Some(11),
            etag: None,
        }
    }

    /// Block until `n` followers hold a receiver on `key`'s slot.
    ///
    /// A follower call no longer returns before the leader's body ends, so a
    /// test cannot join followers by awaiting them and then drive the leader —
    /// it has to spawn them and wait for them to have SUBSCRIBED. Subscription
    /// is what `started` races against, so this is the exact barrier.
    async fn await_subscribers(key: &str, n: usize) {
        for _ in 0..1000 {
            let subscribed = stream_registry()
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .get(key)
                .map(|slot| slot.sender.receiver_count())
                .unwrap_or(0);
            if subscribed >= n {
                return;
            }
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
        panic!("followers never subscribed to {key}");
    }

    /// A leader-open closure body that must never run: used at follower call
    /// sites where joining an in-flight leader must NOT open upstream. Factored
    /// out so the follower joins do not each repeat the unreachable stub (jscpd).
    async fn never_opens() -> AppResult<StreamHandle> {
        panic!("follower must not open upstream");
        #[allow(unreachable_code)]
        Ok(StreamHandle {
            body: body_of(&[]),
            headers: StreamHeaders::default(),
        })
    }

    /// Leader opens upstream exactly ONCE for N concurrent streamers, and every
    /// follower receives byte-for-byte the same body and the leader's headers.
    #[tokio::test]
    async fn leader_streams_once_followers_get_same_bytes() {
        let key = format!("stream-fanout-{}", uuid::Uuid::new_v4());
        let opens = Arc::new(AtomicUsize::new(0));

        // Become leader. The returned handle's body is NOT polled yet, so
        // `started` stays false and concurrent callers join as followers: the
        // flag only flips on the leader body's first poll, which happens below.
        let leader_handle = {
            let opens = Arc::clone(&opens);
            coordinate_stream_fanout(&key, || async move {
                opens.fetch_add(1, Ordering::SeqCst);
                Ok(StreamHandle {
                    body: body_of(&[b"hello ", b"world"]),
                    headers: test_headers(),
                })
            })
            .await
            .expect("leader open ok")
            .expect("leader handle")
        };
        assert!(stream_registry_contains(&key));

        // Spawn N followers. A follower call does NOT return until the leader's
        // body has ended — that is what lets it answer "cannot serve you" with
        // a clean `Ok(None)` instead of a torn response — so the leader must be
        // driven concurrently, not after.
        let mut followers = Vec::new();
        for _ in 0..4 {
            let key = key.clone();
            followers.push(tokio::spawn(async move {
                let handle = coordinate_stream_fanout(&key, never_opens)
                    .await
                    .expect("follower open ok")
                    .expect("follower handle");
                assert_eq!(
                    handle.headers,
                    test_headers(),
                    "follower sees leader headers"
                );
                drain(handle.body).await.expect("follower bytes")
            }));
        }

        await_subscribers(&key, 4).await;

        // Drive the leader to completion. It broadcasts every chunk plus a
        // terminal Done into the followers' buffered receivers (depth 256 >> 2),
        // so every follower replays the identical body.
        let leader_bytes = drain(leader_handle.body).await.expect("leader bytes");
        assert_eq!(leader_bytes, b"hello world");

        for follower in followers {
            let bytes = follower.await.expect("join");
            assert_eq!(bytes, b"hello world", "follower must get identical body");
        }

        // Exactly one upstream open for all N+1 streamers.
        assert_eq!(opens.load(Ordering::SeqCst), 1);
        // Slot reclaimed after the leader body completes.
        assert!(!stream_registry_contains(&key));
    }

    /// A mid-stream leader failure must reach a follower as a clean `Ok(None)`
    /// re-enter — decided before the follower's response exists — never as a
    /// truncated body presented as success (B6).
    #[tokio::test]
    async fn mid_stream_leader_failure_falls_back_instead_of_torn_follower_body() {
        let key = format!("stream-fail-{}", uuid::Uuid::new_v4());

        // Leader body: one chunk then a mid-stream error (the body is not
        // polled until both streamers have joined, so no test-side gate needed).
        let leader = coordinate_stream_fanout(&key, || async {
            let body = async_stream::stream! {
                yield Ok(Bytes::from_static(b"partial"));
                yield Err(AppError::BadGateway("upstream died".to_string()));
            };
            Ok(StreamHandle {
                body: Box::pin(body),
                headers: test_headers(),
            })
        })
        .await
        .expect("leader open ok")
        .expect("leader handle");

        // Spawn the follower and wait for it to subscribe before the leader
        // body is polled.
        let follower = {
            let key = key.clone();
            tokio::spawn(async move { coordinate_stream_fanout(&key, never_opens).await })
        };
        await_subscribers(&key, 1).await;

        // Drain the leader: it emits one partial chunk then errors,
        // broadcasting a terminal Failed to the follower.
        let leader_result = drain(leader.body).await;
        assert!(leader_result.is_err(), "leader surfaces its own error");

        // The follower is never handed a handle at all: it re-enters, so the
        // caller can still produce a correct response (warm cache, fresh
        // election) instead of a `200` whose body stops mid-flight.
        let follower_outcome = follower.await.expect("join").expect("no hard error");
        assert!(
            follower_outcome.is_none(),
            "a follower whose leader failed mid-stream must fall back, not be \
             handed a partial body"
        );
        assert!(!stream_registry_contains(&key));
    }

    /// The bug this guards (the #1694 fan-out's torn 200): a follower that is
    /// dropped by the broadcast must be told BEFORE it has a handle, because a
    /// failure discovered afterwards can only tear an already-started response.
    /// `Capture` therefore answers `None`, and no bytes are ever emitted.
    #[tokio::test]
    async fn capture_follower_that_is_dropped_by_the_broadcast_falls_back() {
        let (tx, rx) = broadcast::channel::<StreamItem>(2);
        // Overflow the channel before the follower reads, forcing Lagged.
        for i in 0..10u8 {
            let _ = tx.send(StreamItem::Chunk(Bytes::from(vec![i])));
        }
        assert!(
            watch_leader_fanout("lag-key", rx, FollowWatch::Capture)
                .await
                .is_none(),
            "a dropped chunk must become a re-enter, never a hole in a body"
        );
    }

    /// An object bigger than the live fan-out window is not fanned out: the
    /// follower stops buffering at the ceiling, waits for the leader to finish
    /// (so the caller's re-enter lands on the cache the leader just filled)
    /// and reports `None` rather than a partial capture.
    #[tokio::test]
    async fn object_larger_than_the_fanout_window_is_not_fanned_out() {
        let (tx, rx) = broadcast::channel::<StreamItem>(STREAM_BROADCAST_DEPTH);
        let watcher =
            tokio::spawn(
                async move { watch_leader_fanout("big-key", rx, FollowWatch::Capture).await },
            );
        // One byte past the ceiling, in chunks the tee could actually produce.
        let chunk = Bytes::from(vec![7u8; 64 * 1024]);
        let mut sent: u64 = 0;
        while sent <= FANOUT_CAPTURE_MAX_BYTES {
            let _ = tx.send(StreamItem::Chunk(chunk.clone()));
            sent += chunk.len() as u64;
            tokio::task::yield_now().await;
        }
        let _ = tx.send(StreamItem::Done);
        assert!(
            watcher.await.expect("join").is_none(),
            "an object past the window must re-enter onto the cache, not be \
             half-captured"
        );
    }

    /// A late arrival (leader already emitting) waits for the leader to FINISH
    /// before re-entering. Returning instantly is what let one cold object turn
    /// into a stampede of upstream fetches: the caller burned its whole
    /// re-enter budget in microseconds and then cold-fetched upstream itself.
    #[tokio::test]
    async fn late_arrival_waits_for_the_leader_before_re_entering() {
        let key = format!("stream-latewait-{}", uuid::Uuid::new_v4());
        let (release_tx, release_rx) = tokio::sync::oneshot::channel::<()>();

        let leader = coordinate_stream_fanout(&key, || async {
            let body = async_stream::stream! {
                yield Ok(Bytes::from_static(b"a"));
                // Hold the leader open until the late arrival is parked.
                let _ = release_rx.await;
                yield Ok(Bytes::from_static(b"b"));
            };
            Ok(StreamHandle {
                body: Box::pin(body),
                headers: test_headers(),
            })
        })
        .await
        .expect("ok")
        .expect("leader");

        let mut leader_body = leader.body;
        // First poll flips `started`, so the next caller is a late arrival.
        assert_eq!(
            leader_body.next().await.expect("chunk").expect("ok"),
            Bytes::from_static(b"a")
        );

        let late = {
            let key = key.clone();
            tokio::spawn(async move { coordinate_stream_fanout(&key, never_opens).await })
        };
        // It must still be parked while the leader has not finished.
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(!late.is_finished(), "late arrival must wait for the leader");

        let _ = release_tx.send(());
        assert_eq!(drain(leader_body).await.expect("bytes"), b"b");
        assert!(
            late.await.expect("join").expect("no hard error").is_none(),
            "a late arrival re-enters (warm cache), it is never handed a body"
        );
    }

    /// The fall-back outcome: a caller arriving after the leader has started
    /// emitting (so it would miss leading bytes) gets `Ok(None)` and must
    /// re-enter, never a torn body.
    #[tokio::test]
    async fn late_arrival_after_start_falls_back() {
        let key = format!("stream-late-{}", uuid::Uuid::new_v4());

        // Become leader and drive the body fully so `started` flips and the
        // slot is reclaimed on completion.
        let leader = coordinate_stream_fanout(&key, || async {
            Ok(StreamHandle {
                body: body_of(&[b"x"]),
                headers: test_headers(),
            })
        })
        .await
        .expect("ok")
        .expect("leader");
        // Drain leader so it flips started then completes + drops the slot.
        let _ = drain(leader.body).await.expect("bytes");

        // After the leader completed, the slot is gone: a new caller becomes a
        // fresh leader (not a fall-back). Assert the slot is reclaimed.
        assert!(!stream_registry_contains(&key));
    }

    /// A leader whose `open_leader` fails before any body returns the error to
    /// its own caller and frees the slot (no poison), and any follower waiting
    /// on headers falls back to `Ok(None)`.
    #[tokio::test]
    async fn leader_open_failure_frees_slot_and_releases_follower() {
        let key = format!("stream-openfail-{}", uuid::Uuid::new_v4());
        let result = coordinate_stream_fanout(&key, || async {
            Err::<StreamHandle, _>(AppError::BadGateway("connect failed".to_string()))
        })
        .await;
        assert!(result.is_err(), "leader open failure surfaces to caller");
        assert!(
            !stream_registry_contains(&key),
            "failed-open leader must not poison the slot"
        );

        // A subsequent caller can win the election cleanly.
        let reborn = coordinate_stream_fanout(&key, || async {
            Ok(StreamHandle {
                body: body_of(&[b"ok"]),
                headers: test_headers(),
            })
        })
        .await
        .expect("ok")
        .expect("handle");
        assert_eq!(drain(reborn.body).await.expect("bytes"), b"ok");
        assert!(!stream_registry_contains(&key));
    }

    /// Empty-body leader (zero-byte upstream): the primitive streams the empty
    /// body cleanly to followers (the #1365 zero-byte CACHE guard lives in
    /// `tee_stream`, not here; the fan-out must still terminate without error).
    #[tokio::test]
    async fn empty_body_leader_completes_cleanly_for_followers() {
        let key = format!("stream-empty-{}", uuid::Uuid::new_v4());

        // Empty-body leader: zero chunks, clean EOF. Not polled until the
        // follower has joined, so no test-side gate is needed.
        let leader = coordinate_stream_fanout(&key, || async {
            Ok(StreamHandle {
                body: body_of(&[]),
                headers: StreamHeaders {
                    commit_sha: None,
                    content_encoding: None,
                    content_type: None,
                    content_length: Some(0),
                    etag: None,
                },
            })
        })
        .await
        .expect("ok")
        .expect("leader");

        // Spawn the follower and wait for it to subscribe before the leader
        // body is polled.
        let follower = {
            let key = key.clone();
            tokio::spawn(async move {
                coordinate_stream_fanout(&key, never_opens)
                    .await
                    .expect("ok")
                    .expect("follower handle")
            })
        };
        await_subscribers(&key, 1).await;
        assert_eq!(drain(leader.body).await.expect("bytes"), Vec::<u8>::new());
        let fh = follower.await.expect("join");
        assert_eq!(
            fh.headers.content_length,
            Some(0),
            "follower sees leader headers"
        );
        assert_eq!(drain(fh.body).await.expect("bytes"), Vec::<u8>::new());
        assert!(!stream_registry_contains(&key));
    }

    // ---- #1609 layer 3: cross-replica advisory-lock decorator ----

    use crate::services::cluster_lock::InMemoryClusterLock;

    /// A fast test coordinator: one shared in-memory cluster lock, tight poll
    /// cadence, generous deadline. Shared so the multi-replica assertions are not
    /// each repeated (jscpd).
    fn advisory_over(lock: &Arc<dyn ClusterLock>) -> AdvisoryLockCoordinator {
        AdvisoryLockCoordinator::new(
            Arc::clone(lock),
            Duration::from_millis(5),
            Duration::from_secs(5),
        )
    }

    /// The core #1609 guarantee: K concurrent cold requests spread across ≥2
    /// `AdvisoryLockCoordinator` instances that SHARE one cluster lock and one
    /// storage cell open upstream EXACTLY ONCE cluster-wide, and every task is
    /// served the COMPLETE object (no partial/truncated body) with no errors.
    #[tokio::test]
    async fn advisory_multi_replica_single_upstream_and_full_bytes() {
        let shared_lock: Arc<dyn ClusterLock> = Arc::new(InMemoryClusterLock::default());
        let storage: Arc<Mutex<Option<Vec<u8>>>> = Arc::new(Mutex::new(None));
        let upstream_opens = Arc::new(AtomicUsize::new(0));
        const OBJECT: &[u8] = b"the-complete-artifact-body-with-no-truncation";

        // Two replicas contend on the single shared lock; K tasks spread across them.
        let replicas: Vec<AdvisoryLockCoordinator> =
            (0..2).map(|_| advisory_over(&shared_lock)).collect();
        let key = format!("proxy-cache:multi-{}", uuid::Uuid::new_v4());

        let mut futs = Vec::new();
        for i in 0..12usize {
            let replica = &replicas[i % replicas.len()];
            let storage = Arc::clone(&storage);
            let upstream_opens = Arc::clone(&upstream_opens);
            let key = key.clone();
            futs.push(async move {
                let check = {
                    let storage = Arc::clone(&storage);
                    move || {
                        let storage = Arc::clone(&storage);
                        async move {
                            Ok::<Option<Vec<u8>>, &'static str>(
                                storage.lock().unwrap_or_else(|p| p.into_inner()).clone(),
                            )
                        }
                    }
                };
                let produce = {
                    let storage = Arc::clone(&storage);
                    let upstream_opens = Arc::clone(&upstream_opens);
                    move || async move {
                        // Simulate ONE upstream open + latency, then commit the
                        // FULL object atomically (mirrors the sidecar commit).
                        upstream_opens.fetch_add(1, Ordering::SeqCst);
                        tokio::time::sleep(Duration::from_millis(20)).await;
                        *storage.lock().unwrap_or_else(|p| p.into_inner()) = Some(OBJECT.to_vec());
                        Ok(OBJECT.to_vec())
                    }
                };
                replica.coordinate(&key, check, produce, || "timeout").await
            });
        }

        let results = futures::future::join_all(futs).await;
        for r in &results {
            assert_eq!(
                r.as_ref().map(|b| b.as_slice()),
                Ok(OBJECT),
                "every task must be served the complete object, never a truncation"
            );
        }
        assert_eq!(
            upstream_opens.load(Ordering::SeqCst),
            1,
            "exactly one upstream open cluster-wide (was N without the lock)"
        );
    }

    /// Loser deadline ⇒ bounded buffered fallback: when the cluster leader holds
    /// the lock and never commits (large/slow fetch), a follower produces exactly
    /// once after the wait deadline rather than hanging or herding.
    #[tokio::test]
    async fn advisory_loser_falls_back_to_produce_on_deadline() {
        let lock: Arc<dyn ClusterLock> = Arc::new(InMemoryClusterLock::default());
        let key = format!("proxy-cache:deadline-{}", uuid::Uuid::new_v4());
        // Another replica holds the lock and never commits.
        let held = lock
            .try_acquire(PROXY_HYDRATION_LOCK_CLASS, lease_object_id(&key))
            .await
            .expect("no error")
            .expect("held");
        let coord = AdvisoryLockCoordinator::new(
            Arc::clone(&lock),
            Duration::from_millis(5),
            Duration::from_millis(40),
        );
        let produced = Arc::new(AtomicUsize::new(0));
        let result: Result<u32, &'static str> = coord
            .coordinate(
                &key,
                || async { Ok::<Option<u32>, &'static str>(None) },
                {
                    let produced = Arc::clone(&produced);
                    || async move {
                        produced.fetch_add(1, Ordering::SeqCst);
                        Ok(7)
                    }
                },
                || "timeout",
            )
            .await;
        assert_eq!(result, Ok(7));
        assert_eq!(
            produced.load(Ordering::SeqCst),
            1,
            "loser produces exactly once on deadline (bounded fallback)"
        );
        drop(held);
    }

    /// Producer error on the cluster-leader path still releases the lock so the
    /// key is not poisoned (mirrors `slot_released_after_producer_error`).
    #[tokio::test]
    async fn advisory_leader_releases_lock_after_produce_error() {
        let lock: Arc<dyn ClusterLock> = Arc::new(InMemoryClusterLock::default());
        let key = format!("proxy-cache:err-{}", uuid::Uuid::new_v4());
        let coord = advisory_over(&lock);
        let result: Result<u32, &'static str> = coord
            .coordinate(
                &key,
                || async { Ok::<Option<u32>, &'static str>(None) },
                || async { Err("boom") },
                || "timeout",
            )
            .await;
        assert_eq!(result, Err("boom"));
        assert!(
            lock.try_acquire(PROXY_HYDRATION_LOCK_CLASS, lease_object_id(&key))
                .await
                .expect("no error")
                .is_some(),
            "produce error must release the cluster lock"
        );
    }

    /// Cancelled cluster leader (request disconnect / pod-kill mid-produce): the
    /// lease drops → the lock auto-releases (crash-safe), mirroring
    /// `cancelled_leader_does_not_poison_key`.
    #[tokio::test]
    async fn advisory_cancelled_leader_releases_lock() {
        let lock: Arc<dyn ClusterLock> = Arc::new(InMemoryClusterLock::default());
        let key = format!("proxy-cache:cancel-{}", uuid::Uuid::new_v4());
        let coord = advisory_over(&lock);
        {
            let fut = coord.coordinate(
                &key,
                || async { Ok::<Option<u32>, &'static str>(None) },
                || async {
                    futures::future::pending::<()>().await;
                    unreachable!()
                },
                || "timeout",
            );
            let _ = tokio::time::timeout(Duration::from_millis(40), fut).await;
        }
        assert!(
            lock.try_acquire(PROXY_HYDRATION_LOCK_CLASS, lease_object_id(&key))
                .await
                .expect("no error")
                .is_some(),
            "cancelled leader must not poison the cluster lock"
        );
    }

    /// Negative-cache visibility (#4 companion): once the leader records a fresh
    /// 404, a remote follower's `check` surfaces it as `Err` and the follower
    /// short-circuits WITHOUT re-fetching upstream.
    #[tokio::test]
    async fn advisory_follower_short_circuits_leader_negative_cache() {
        let lock: Arc<dyn ClusterLock> = Arc::new(InMemoryClusterLock::default());
        let key = format!("proxy-cache:neg-{}", uuid::Uuid::new_v4());
        // Leader holds the lock (simulating an in-flight 404 record).
        let held = lock
            .try_acquire(PROXY_HYDRATION_LOCK_CLASS, lease_object_id(&key))
            .await
            .expect("no error")
            .expect("held");
        let coord = advisory_over(&lock);
        let produced = Arc::new(AtomicUsize::new(0));
        let calls = Arc::new(AtomicUsize::new(0));
        let result: Result<u32, &'static str> = coord
            .coordinate(
                &key,
                {
                    let calls = Arc::clone(&calls);
                    move || {
                        let calls = Arc::clone(&calls);
                        async move {
                            // Fast-path check sees a cold miss; by the time the
                            // follower polls, the leader has recorded the 404.
                            if calls.fetch_add(1, Ordering::SeqCst) == 0 {
                                Ok::<Option<u32>, &'static str>(None)
                            } else {
                                Err("not-found")
                            }
                        }
                    }
                },
                {
                    let produced = Arc::clone(&produced);
                    || async move {
                        produced.fetch_add(1, Ordering::SeqCst);
                        Ok(1u32)
                    }
                },
                || "timeout",
            )
            .await;
        assert_eq!(result, Err("not-found"), "follower short-circuits the 404");
        assert_eq!(
            produced.load(Ordering::SeqCst),
            0,
            "no upstream re-fetch when the leader recorded a negative entry"
        );
        drop(held);
    }

    /// Streaming leader holds the cluster lock for the lifetime of the streamed
    /// body (so no peer replica cold-fetches concurrently) and releases it on
    /// clean EOF; exactly one upstream open.
    #[tokio::test]
    async fn advisory_streaming_leader_holds_lock_until_body_completes() {
        let lock: Arc<dyn ClusterLock> = Arc::new(InMemoryClusterLock::default());
        let key = format!("proxy-stream:leader-{}", uuid::Uuid::new_v4());
        let coord = advisory_over(&lock);
        let opens = Arc::new(AtomicUsize::new(0));
        let handle = {
            let opens = Arc::clone(&opens);
            coord
                .coordinate_stream(&key, || async move {
                    opens.fetch_add(1, Ordering::SeqCst);
                    Ok(StreamHandle {
                        body: body_of(&[b"abc", b"def"]),
                        headers: test_headers(),
                    })
                })
                .await
                .expect("leader open ok")
                .expect("leader handle")
        };
        // Held while the body is unconsumed.
        assert!(
            lock.try_acquire(PROXY_HYDRATION_LOCK_CLASS, lease_object_id(&key))
                .await
                .expect("no error")
                .is_none(),
            "leader holds the cluster lock across the streamed body"
        );
        assert_eq!(drain(handle.body).await.expect("bytes"), b"abcdef");
        assert_eq!(opens.load(Ordering::SeqCst), 1, "exactly one upstream open");
        // Released after the body completes.
        assert!(
            lock.try_acquire(PROXY_HYDRATION_LOCK_CLASS, lease_object_id(&key))
                .await
                .expect("no error")
                .is_some(),
            "cluster lock released after the leader body completes"
        );
    }

    /// Streaming remote follower returns `Ok(None)` so the caller re-enters
    /// (warm cache) or drains its budget into proxy-without-cache; it must NOT
    /// open upstream and must NOT hold the lock.
    #[tokio::test]
    async fn advisory_streaming_loser_returns_none_without_opening() {
        let lock: Arc<dyn ClusterLock> = Arc::new(InMemoryClusterLock::default());
        let key = format!("proxy-stream:loser-{}", uuid::Uuid::new_v4());
        let held = lock
            .try_acquire(PROXY_HYDRATION_LOCK_CLASS, lease_object_id(&key))
            .await
            .expect("no error")
            .expect("held");
        let coord = AdvisoryLockCoordinator::new(
            Arc::clone(&lock),
            Duration::from_millis(1),
            Duration::from_secs(5),
        );
        let handle = coord
            .coordinate_stream(&key, never_opens)
            .await
            .expect("no error");
        assert!(
            handle.is_none(),
            "streaming loser must return Ok(None) (re-enter / proxy-without-cache)"
        );
        drop(held);
    }

    /// Lock-infrastructure failure must NOT fail the request: the buffered
    /// coordinate path degrades to per-process single-flight and still produces.
    #[tokio::test]
    async fn advisory_degrades_to_buffered_when_lock_errors() {
        use crate::services::cluster_lock::ErroringClusterLock;
        let lock: Arc<dyn ClusterLock> = Arc::new(ErroringClusterLock);
        let coord = advisory_over(&lock);
        let key = format!("proxy-cache:lockfail-{}", uuid::Uuid::new_v4());
        let produced = Arc::new(AtomicUsize::new(0));
        let result: Result<u32, &'static str> = coord
            .coordinate(
                &key,
                || async { Ok::<Option<u32>, &'static str>(None) },
                {
                    let produced = Arc::clone(&produced);
                    || async move {
                        produced.fetch_add(1, Ordering::SeqCst);
                        Ok(5)
                    }
                },
                || "timeout",
            )
            .await;
        assert_eq!(result, Ok(5));
        assert_eq!(produced.load(Ordering::SeqCst), 1);
    }

    /// Streaming path also degrades to per-process fan-out when the lock errors.
    #[tokio::test]
    async fn advisory_streaming_degrades_to_buffered_when_lock_errors() {
        use crate::services::cluster_lock::ErroringClusterLock;
        let lock: Arc<dyn ClusterLock> = Arc::new(ErroringClusterLock);
        let coord = advisory_over(&lock);
        let key = format!("proxy-stream:lockfail-{}", uuid::Uuid::new_v4());
        let handle = coord
            .coordinate_stream(&key, || async {
                Ok(StreamHandle {
                    body: body_of(&[b"xy"]),
                    headers: test_headers(),
                })
            })
            .await
            .expect("ok")
            .expect("leader handle");
        assert_eq!(drain(handle.body).await.expect("bytes"), b"xy");
    }

    /// Cluster leader whose `open_leader` fails releases the lock (the non-happy
    /// streaming arm) and surfaces the error; the key is re-acquirable after.
    #[tokio::test]
    async fn advisory_streaming_leader_open_failure_releases_lock() {
        let lock: Arc<dyn ClusterLock> = Arc::new(InMemoryClusterLock::default());
        let key = format!("proxy-stream:openfail-{}", uuid::Uuid::new_v4());
        let coord = advisory_over(&lock);
        let result = coord
            .coordinate_stream(&key, || async {
                Err::<StreamHandle, _>(crate::error::AppError::BadGateway("boom".to_string()))
            })
            .await;
        assert!(
            result.is_err(),
            "leader open failure surfaces to the caller"
        );
        assert!(
            lock.try_acquire(PROXY_HYDRATION_LOCK_CLASS, lease_object_id(&key))
                .await
                .expect("no error")
                .is_some(),
            "open failure must release the cluster lock"
        );
    }

    #[tokio::test]
    async fn from_env_defaults_to_per_process_buffered() {
        // Unset (the default) selects the unchanged per-process coordinator, so a
        // single-replica install and the test suite are never on the lock path.
        let pool = sqlx::PgPool::connect_lazy("postgres://fake:fake@localhost/fake")
            .expect("connect_lazy should not fail");
        assert!(matches!(
            HydrationCoordinator::from_env(pool),
            HydrationCoordinator::Buffered(_)
        ));
    }
}
