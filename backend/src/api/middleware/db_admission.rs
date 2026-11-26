//! Router-wide database admission gate (#4182).
//!
//! Under a burst (a fleet of package installers, each fetching dozens of
//! files at once) every request needs pooled database connections for its
//! credential check, repository and artifact lookups, and the pool has
//! `DATABASE_MAX_CONNECTIONS` of them. Each query is a separate acquire, and
//! the pool's queue is FIFO, so with far more requests in flight than
//! connections every acquire of every request waits behind the whole crowd:
//! a request's latency becomes the queue wait times its query count, the
//! same for every request, and the whole burst slows down together until
//! clients time out or an acquire reaches `DATABASE_ACQUIRE_TIMEOUT_SECS`
//! (5 s) and is answered `503` only then.
//!
//! The gate runs before any authentication, database or storage work and
//! bounds how many requests compete for the pool at once: up to
//! `DATABASE_REQUEST_CONCURRENCY` requests (default four per pool connection)
//! hold an admission permit for their handler phase, from the gate until the
//! response head is ready (a download's body streams after that, without a
//! permit). When every slot is held and the pool is busy, a request may
//! queue for one for up to `DATABASE_REQUEST_ACQUIRE_WAIT_MS` (default: the
//! pool's own acquire timeout, so it only sheds what would have waited that
//! long on the pool anyway; a database that is down still fails at the
//! acquire timeout as before). Before queueing, the gate predicts
//! the wait from what it measures (requests queued ahead x the moving
//! average of how long a slot is held / slots): a backlog predicted to
//! outlast the budget is answered at once with the same `503 POOL_EXHAUSTED`
//! body the pool timeout produces and a `Retry-After` (1 to 30 s) predicted
//! from the queue plus every client already told to come back, so clients
//! return spread out over the backlog instead of colliding again. A request that
//! queues and still gets no slot in time is answered the same way. Sheds are
//! counted in `ak_db_requests_shed_total`. An admitted request queues behind
//! at most the other slot holders, so it finishes in a bounded time instead
//! of slowing down with the whole burst.
//!
//! The permits only shed while the pool is busy: when every permit is held
//! but the pool has room (connections it has not opened yet, or a quarter of
//! them idle), a request runs without one, so slow uploads or upstream
//! fetches holding permits never shed anything on their own.
//!
//! # Fairness between clients (#6344)
//!
//! Whoever arrives first would otherwise get every slot, so one anonymous
//! flood (a single IP, or a misbehaving CI job) could hold them all and get
//! everyone else shed. Two rules apply, both only while the pool is busy:
//!
//! * **A reserved share for credentialed requests.**
//!   `DATABASE_REQUEST_CREDENTIALED_RESERVE_PERCENT` (default 25) of the
//!   slots can only be taken by a request that presents a credential (an
//!   `Authorization` header, `X-API-Key`, `X-NuGet-ApiKey`, the session
//!   cookie, or a `/t/<token>/` path). Anonymous requests share the rest. The
//!   gate cannot verify a credential without a database round trip, so this
//!   is only a hint: a request with a forged header takes a reserved slot
//!   and is answered 401 by authentication. While other clients wait, one
//!   address can hold at most its per-client share of the slots that way; a
//!   flood of forged headers from many addresses can still fill the reserve,
//!   and then credentialed clients compete with it first come, first served,
//!   as everyone did without the reserve.
//! * **A per-client share under contention.** Requests are keyed by the
//!   best-effort client IP (the rate limiter's key, honouring
//!   `RATE_LIMIT_TRUSTED_PROXY_CIDRS`; an IPv6 client by its /64) into a
//!   fixed table of counters, so
//!   memory stays bounded however many addresses a flood uses. A client that
//!   already holds or waits for `DATABASE_REQUEST_CLIENT_SHARE_PERCENT`
//!   (default 25, one slot per pool connection with the default slots) of
//!   the slots is not queued while another client is waiting: it is shed at
//!   once, so the slots it releases go to the others. A client alone on a
//!   busy pool is never limited by its share, so the gate stays
//!   work-conserving.
//!
//! `0` turns either rule off; with both off the gate hands out slots first come, first served.
//! Fairness sheds are also counted in `ak_db_admission_sheds_total` by
//! `class` (`anonymous` / `credentialed`) and `reason` (`backlog` /
//! `client_share`).
//!
//! A shed request has done no work at all; in particular it has not
//! authenticated, so a shed can never let a request through (it is a `503`,
//! never a `2xx`), and an admitted request goes through every check exactly
//! as before. Health and readiness probes and the main-port metrics scrape
//! are never gated, and the probes read the database through their own small
//! pool ([`crate::db::create_probe_pool`]), so a saturated request pool
//! neither makes a busy replica look dead nor blinds monitoring.
//!
//! `DATABASE_REQUEST_ACQUIRE_WAIT_MS=0` or `DATABASE_REQUEST_CONCURRENCY=0`
//! turns the gate off.

use std::hash::BuildHasher;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU32, AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::{
    extract::{ConnectInfo, Request, State},
    http::{header, HeaderMap, HeaderValue, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
    Json,
};
use sqlx::PgPool;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

use super::rate_limit::CidrRange;

/// Counter of requests the gate answered `503` without running them.
pub const SHED_METRIC: &str = "ak_db_requests_shed_total";

/// The same sheds by `class` and `reason` (#6344).
pub const SHED_BY_CLASS_METRIC: &str = "ak_db_admission_sheds_total";

/// Paths the gate never sheds besides the probes: the main-port Prometheus
/// scrape, so monitoring is not blinded during the very incident it should
/// show. (The separate `METRICS_PORT` listener has no gate at all.)
const EXEMPT_PATHS: &[&str] = &["/api/v1/admin/metrics"];

/// At most one shed WARN per this many seconds.
const SHED_WARN_INTERVAL_SECS: u64 = 300;

/// Longest `Retry-After` the gate sends, in seconds.
const MAX_RETRY_AFTER_SECS: u64 = 30;

/// Weight of the newest sample in the moving average of slot hold times
/// (1/16: smooth over a few dozen requests, follow a shift within ~50).
const HOLD_EWMA_SHIFT: u32 = 4;

/// Counters in the per-client table. Clients that hash to the same counter
/// share one share, which only ever makes the gate stricter with them, and
/// only under contention.
const CLIENT_BUCKETS: usize = 4096;

/// The fairness rules (#6344), as percentages of the slots. `0` turns a rule
/// off.
#[derive(Debug, Clone, Default)]
pub struct Fairness {
    /// Share of the slots only credentialed requests may take.
    pub credentialed_reserve_percent: u8,
    /// Share of the slots one client may hold or wait for while another
    /// client is waiting.
    pub client_share_percent: u8,
    /// Proxies whose `X-Forwarded-For` names the client
    /// (`RATE_LIMIT_TRUSTED_PROXY_CIDRS`).
    pub trusted_proxies: Vec<CidrRange>,
}

impl Fairness {
    /// No fairness: the gate as it was before #6344.
    pub const OFF: Self = Self {
        credentialed_reserve_percent: 0,
        client_share_percent: 0,
        trusted_proxies: Vec::new(),
    };
}

/// Slots reserved for credentialed requests out of `capacity`: the
/// percentage rounded down, always leaving anonymous requests at least one.
/// Pure.
pub(crate) fn reserved_slots(capacity: usize, percent: u8) -> usize {
    (capacity.saturating_mul(usize::from(percent.min(100))) / 100).min(capacity.saturating_sub(1))
}

/// Slots one client may hold or wait for under contention: the percentage of
/// `capacity`, at least one; `0` when the rule is off. Pure.
pub(crate) fn client_share_slots(capacity: usize, percent: u8) -> usize {
    if percent == 0 || percent >= 100 {
        return 0;
    }
    (capacity.saturating_mul(usize::from(percent)) / 100).max(1)
}

/// What the gate knows about a request before running it: whether it
/// presents a credential, and which client counter it belongs to.
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct Caller {
    pub credentialed: bool,
    pub bucket: Option<usize>,
}

/// The gate's state: the request pool, the handler-phase slots, the longest
/// predicted wait a request is allowed to queue for, and what it measures to
/// predict that wait.
pub struct DbAdmission {
    pool: PgPool,
    /// Slots any request may take.
    permits: Arc<Semaphore>,
    /// Slots only credentialed requests may take (#6344); `None` when the
    /// reserve is off.
    reserved_permits: Option<Arc<Semaphore>>,
    capacity: usize,
    /// Size of `permits` (`capacity` less the reserve).
    general: usize,
    /// Size of `reserved_permits`.
    reserved: usize,
    wait: Duration,
    /// Requests queued for a slot right now.
    waiters: AtomicUsize,
    /// The credentialed ones among them.
    credentialed_waiters: AtomicUsize,
    /// Requests shed with a `Retry-After` that has not run out yet: clients
    /// that will be back, and that a newcomer's prediction has to count, or
    /// the gate tells everyone to return at the same short interval and they
    /// collide again.
    deferred: DeferredRing,
    /// [`now_secs`] of the last shed WARN (`u64::MAX`: none yet).
    last_warn: AtomicU64,
    /// Moving average of how long a request holds its slot, in microseconds
    /// (0 until the first slot is returned).
    avg_hold_us: AtomicU64,
    /// Per-client share (#6344): slots one client may hold or wait for while
    /// another is waiting; `0` when off.
    client_share: usize,
    /// Requests per client counter that are in the gate, waiting for a slot
    /// or holding one.
    clients: Box<[AtomicU32]>,
    /// Keys the client counters; random per process, so a client cannot
    /// choose to land on another's counter.
    client_hasher: std::collections::hash_map::RandomState,
    /// [`now_millis`] until which clients are contending: an under-share
    /// client found every slot held. While it lasts, a client at its share is
    /// shed instead of queued.
    contended_until_ms: AtomicU64,
    trusted_proxies: Vec<CidrRange>,
}

/// One request counted against its client while it is in the gate or holds
/// a slot.
pub(crate) struct ClientEntry {
    gate: Arc<DbAdmission>,
    bucket: usize,
}

impl Drop for ClientEntry {
    fn drop(&mut self) {
        self.gate.clients[self.bucket].fetch_sub(1, Ordering::Relaxed);
    }
}

/// A held slot. Returning it feeds the hold-time average the wait
/// prediction uses.
pub(crate) struct Slot {
    _permit: OwnedSemaphorePermit,
    _client: Option<ClientEntry>,
    since: Instant,
    gate: Arc<DbAdmission>,
}

impl Drop for Slot {
    fn drop(&mut self) {
        self.gate.record_hold(self.since.elapsed());
    }
}

/// Why a request was shed (the `reason` label).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ShedReason {
    /// The backlog is predicted to outlast the wait, or the wait ran out.
    Backlog,
    /// The client already holds its share while others wait (#6344).
    ClientShare,
}

/// What [`DbAdmission::admit`] decided.
pub(crate) enum Admission {
    /// Run, holding the slot (if any) until the response head is ready.
    Run(Option<Slot>),
    /// Shed, telling the client to come back after this many seconds.
    Shed {
        retry_after_secs: u64,
        reason: ShedReason,
    },
}

impl DbAdmission {
    /// The gate for `pool`, or `None` when `wait_ms` or `concurrency` is `0`
    /// (gate off).
    pub fn new(
        pool: PgPool,
        wait_ms: u64,
        concurrency: usize,
        fairness: Fairness,
    ) -> Option<Arc<Self>> {
        (wait_ms > 0 && concurrency > 0).then(|| {
            let reserved = reserved_slots(concurrency, fairness.credentialed_reserve_percent);
            let general = concurrency - reserved;
            let client_share = client_share_slots(concurrency, fairness.client_share_percent);
            Arc::new(Self {
                pool,
                permits: Arc::new(Semaphore::new(general)),
                reserved_permits: (reserved > 0).then(|| Arc::new(Semaphore::new(reserved))),
                capacity: concurrency,
                general,
                reserved,
                wait: Duration::from_millis(wait_ms),
                waiters: AtomicUsize::new(0),
                credentialed_waiters: AtomicUsize::new(0),
                deferred: DeferredRing::default(),
                last_warn: AtomicU64::new(u64::MAX),
                avg_hold_us: AtomicU64::new(0),
                client_share,
                clients: if client_share > 0 {
                    (0..CLIENT_BUCKETS).map(|_| AtomicU32::new(0)).collect()
                } else {
                    Box::new([])
                },
                client_hasher: Default::default(),
                contended_until_ms: AtomicU64::new(0),
                trusted_proxies: fairness.trusted_proxies,
            })
        })
    }

    /// What the gate needs to know about `req`. No database work: header
    /// and peer-address inspection only.
    pub(crate) fn caller_of(&self, req: &Request) -> Caller {
        let credentialed = presents_credential(req.headers(), req.uri().path());
        let bucket = (self.client_share > 0).then(|| {
            let peer = req
                .extensions()
                .get::<ConnectInfo<SocketAddr>>()
                .map(|ci| ci.0.ip());
            let ip = super::rate_limit::resolve_client_ip_addr(
                req.headers(),
                peer,
                &self.trusted_proxies,
            );
            self.bucket_of(ip)
        });
        Caller {
            credentialed,
            bucket,
        }
    }

    fn bucket_of(&self, ip: Option<IpAddr>) -> usize {
        (self.client_hasher.hash_one(ip.map(client_key)) % CLIENT_BUCKETS as u64) as usize
    }

    fn record_hold(&self, held: Duration) {
        // A slot held for longer than the wait budget (a request stuck on a
        // lock, a slow upload) counts as the budget: one outlier must not
        // make the gate predict long waits for the fast requests after it.
        let sample = held.min(self.wait).as_micros().min(u64::MAX as u128) as u64;
        // A lost update under contention only skips one sample.
        let old = self.avg_hold_us.load(Ordering::Relaxed);
        let new = if old == 0 {
            sample.max(1)
        } else {
            (old - (old >> HOLD_EWMA_SHIFT) + (sample >> HOLD_EWMA_SHIFT)).max(1)
        };
        self.avg_hold_us.store(new, Ordering::Relaxed);
    }

    fn slot(self: &Arc<Self>, permit: OwnedSemaphorePermit, client: Option<ClientEntry>) -> Slot {
        Slot {
            _permit: permit,
            _client: client,
            since: Instant::now(),
            gate: self.clone(),
        }
    }

    /// A free slot for `credentialed` without waiting: a general one, else
    /// (credentialed only) a reserved one.
    fn try_permit(&self, credentialed: bool) -> Option<OwnedSemaphorePermit> {
        if let Ok(permit) = self.permits.clone().try_acquire_owned() {
            return Some(permit);
        }
        match (&self.reserved_permits, credentialed) {
            (Some(reserved), true) => reserved.clone().try_acquire_owned().ok(),
            _ => None,
        }
    }

    /// Wait for a slot: a general one, or (credentialed only) whichever of a
    /// general or a reserved one comes first.
    async fn acquire_permit(&self, credentialed: bool) -> Option<OwnedSemaphorePermit> {
        match (&self.reserved_permits, credentialed) {
            (Some(reserved), true) => {
                tokio::select! {
                    p = self.permits.clone().acquire_owned() => p.ok(),
                    p = reserved.clone().acquire_owned() => p.ok(),
                }
            }
            _ => self.permits.clone().acquire_owned().await.ok(),
        }
    }

    /// Count the request against its client while it is in the gate; the
    /// count without it is what the client already holds or waits for.
    fn enter_client(self: &Arc<Self>, bucket: Option<usize>) -> (Option<ClientEntry>, usize) {
        match bucket {
            Some(bucket) if self.client_share > 0 => {
                let before = self.clients[bucket].fetch_add(1, Ordering::Relaxed) as usize;
                (
                    Some(ClientEntry {
                        gate: self.clone(),
                        bucket,
                    }),
                    before,
                )
            }
            _ => (None, 0),
        }
    }

    /// Admit or shed one request.
    pub(crate) async fn admit(self: &Arc<Self>, caller: Caller) -> Admission {
        // Counted before the slot is taken, so a client alone on the gate
        // always sees its own slot holders and never mistakes itself for
        // contention.
        let (client, ahead_of_self) = self.enter_client(caller.bucket);
        if let Some(permit) = self.try_permit(caller.credentialed) {
            return Admission::Run(Some(self.slot(permit, client)));
        }
        // Every slot is held. That only means the pool is the bottleneck
        // when the pool is busy too; slots held by slow uploads or upstream
        // fetches next to an idle pool must not shed anything.
        if pool_has_room(&self.pool) {
            return Admission::Run(None);
        }
        if client.is_some() {
            let now_ms = now_millis();
            if ahead_of_self < self.client_share {
                // An under-share client finds every slot held: the others
                // hold them, so clients are contending.
                self.contended_until_ms
                    .fetch_max(now_ms + self.contention_window_ms(), Ordering::Relaxed);
            } else if self.contended_until_ms.load(Ordering::Relaxed) > now_ms {
                // At its share while another client waits: shed at once, so
                // the slots this client releases go to the others.
                return self.shed(ShedReason::ClientShare);
            }
        }
        // Queue only when the queue ahead is predicted to clear within the
        // wait; otherwise say at once how long the backlog is.
        // With nobody queued yet the request always gets to wait: a
        // prediction needs a queue to be about.
        let queued = self.waiters.load(Ordering::Relaxed);
        if queued > 0 && self.predicted_wait_for(caller.credentialed, queued) > self.wait {
            return self.shed(ShedReason::Backlog);
        }
        // Counted while queued, by a guard: this future is dropped mid-wait
        // whenever the request goes away (a reset stream or connection, the
        // request timeout, the upload progress deadline), and a hand-written
        // decrement after the `.await` would then never run.
        let acquired = {
            let _queued = WaiterGuard::enter(&self.waiters);
            let _credentialed = caller
                .credentialed
                .then(|| WaiterGuard::enter(&self.credentialed_waiters));
            tokio::time::timeout(self.wait, self.acquire_permit(caller.credentialed)).await
        };
        match acquired {
            Ok(Some(permit)) => Admission::Run(Some(self.slot(permit, client))),
            // Out of time: run it anyway if the pool has room by now.
            _ if pool_has_room(&self.pool) => Admission::Run(None),
            _ => self.shed(ShedReason::Backlog),
        }
    }

    /// How long contention lasts after an under-share client found every
    /// slot held: the wait budget, at least a second, long enough for the
    /// slots held by the clients at their share to turn over.
    fn contention_window_ms(&self) -> u64 {
        (self.wait.as_millis() as u64).max(1000)
    }

    /// The predicted wait of a newcomer with `queued` requests ahead. An
    /// anonymous request is served by the general slots only; a credentialed
    /// one by the reserved slots too, behind the credentialed queue there or
    /// the whole queue across every slot, whichever is shorter.
    fn predicted_wait_for(&self, credentialed: bool, queued: usize) -> Duration {
        let avg = self.avg_hold();
        if self.reserved == 0 {
            return predicted_wait(queued + 1, avg, self.capacity);
        }
        if credentialed {
            let ahead = self.credentialed_waiters.load(Ordering::Relaxed);
            predicted_wait(ahead + 1, avg, self.reserved).min(predicted_wait(
                queued + 1,
                avg,
                self.capacity,
            ))
        } else {
            predicted_wait(queued + 1, avg, self.general)
        }
    }

    fn avg_hold(&self) -> Duration {
        Duration::from_micros(self.avg_hold_us.load(Ordering::Relaxed))
    }

    /// Shed, with a `Retry-After` for when the queue ahead plus everyone
    /// already told to come back should have been served (at least the wait
    /// budget), counting the client as deferred until that runs out.
    fn shed(&self, reason: ShedReason) -> Admission {
        let now = now_secs();
        let backlog = self.waiters.load(Ordering::Relaxed) + self.deferred.live(now) + 1;
        let predicted = predicted_wait(backlog, self.avg_hold(), self.capacity).max(self.wait);
        let retry_after_secs = retry_after_secs(predicted);
        // A client that ignores `Retry-After` and comes straight back is
        // counted again on each shed. That inflates the prediction for
        // everyone (towards the 30 s cap) only while such a client keeps
        // hammering, and each count expires with its own Retry-After; the
        // per-client share (#6344) keeps such a client from also holding
        // the slots the others need.
        self.deferred.add(now + retry_after_secs);
        self.warn_shedding(now, retry_after_secs);
        Admission::Shed {
            retry_after_secs,
            reason,
        }
    }

    /// One WARN when shedding starts, then at most one per
    /// [`SHED_WARN_INTERVAL_SECS`]; the per-request count is the metric.
    fn warn_shedding(&self, now: u64, retry_after_secs: u64) {
        let last = self.last_warn.load(Ordering::Relaxed);
        let due = last == u64::MAX || now.saturating_sub(last) >= SHED_WARN_INTERVAL_SECS;
        if due
            && self
                .last_warn
                .compare_exchange(last, now, Ordering::Relaxed, Ordering::Relaxed)
                .is_ok()
        {
            tracing::warn!(
                wait_ms = self.wait.as_millis() as u64,
                slots = self.capacity,
                reserved_slots = self.reserved,
                client_share = self.client_share,
                retry_after_secs,
                "database admission gate is shedding requests with 503 POOL_EXHAUSTED: the \
                 request pool is saturated (budget DATABASE_REQUEST_ACQUIRE_WAIT_MS, slots \
                 DATABASE_REQUEST_CONCURRENCY, pool DATABASE_MAX_CONNECTIONS; see \
                 ak_db_requests_shed_total). Logged at most every {SHED_WARN_INTERVAL_SECS} s."
            );
        }
    }
}

/// The address a client is counted under: an IPv4 address (an IPv4-mapped
/// IPv6 one included) as itself, an IPv6 address by its /64, which one host
/// or one customer site gets, so rotating through a /64 is still one client.
/// Pure.
pub(crate) fn client_key(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V4(v4) => IpAddr::V4(v4),
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None => {
                let s = v6.segments();
                IpAddr::V6(std::net::Ipv6Addr::new(s[0], s[1], s[2], s[3], 0, 0, 0, 0))
            }
        },
    }
}

/// Whether a request presents a credential the gate can see without a
/// database round trip: what [`crate::api::middleware::auth::extract_token`]
/// reads (`Authorization`, `X-API-Key`, the session cookie), NuGet's push
/// key header, or a conda-style `/t/<token>/` path. A hint, not a check.
pub(crate) fn presents_credential(headers: &HeaderMap, path: &str) -> bool {
    crate::api::middleware::auth::request_carries_credentials(headers)
        || headers.contains_key("x-nuget-apikey")
        || path
            .strip_prefix("/t/")
            .is_some_and(|rest| rest.split_once('/').is_some_and(|(t, _)| !t.is_empty()))
}

/// Seconds on a monotonic clock that starts with the process.
pub(crate) fn now_secs() -> u64 {
    process_clock().elapsed().as_secs()
}

/// Milliseconds on the same clock.
fn now_millis() -> u64 {
    process_clock().elapsed().as_millis() as u64
}

fn process_clock() -> &'static Instant {
    static START: std::sync::OnceLock<Instant> = std::sync::OnceLock::new();
    START.get_or_init(Instant::now)
}

/// Ring size for [`DeferredRing`]: longer than the longest Retry-After, so
/// two live expiry seconds never share a bucket.
const DEFERRED_BUCKETS: usize = MAX_RETRY_AFTER_SECS as usize + 2;

/// Clients shed with a Retry-After that has not run out, as counts per
/// expiry second in a ring (no timer task per shed).
#[derive(Default)]
pub(crate) struct DeferredRing {
    /// `(expiry second, count)` per bucket, indexed by expiry % len.
    buckets: std::sync::Mutex<[(u64, usize); DEFERRED_BUCKETS]>,
}

impl DeferredRing {
    /// Count one client deferred until `expires` (in [`now_secs`] seconds).
    pub(crate) fn add(&self, expires: u64) {
        let mut buckets = self.buckets.lock().unwrap_or_else(|e| e.into_inner());
        let bucket = &mut buckets[(expires % DEFERRED_BUCKETS as u64) as usize];
        if bucket.0 == expires {
            bucket.1 += 1;
        } else {
            // A stale bucket from an earlier lap of the ring: reuse it.
            *bucket = (expires, 1);
        }
    }

    /// Clients whose Retry-After has not run out at `now`.
    pub(crate) fn live(&self, now: u64) -> usize {
        let buckets = self.buckets.lock().unwrap_or_else(|e| e.into_inner());
        buckets
            .iter()
            .filter(|(expires, _)| *expires > now)
            .map(|(_, count)| count)
            .sum()
    }
}

/// Counts one request as queued for a slot for as long as it lives.
struct WaiterGuard<'a>(&'a AtomicUsize);

impl<'a> WaiterGuard<'a> {
    fn enter(waiters: &'a AtomicUsize) -> Self {
        waiters.fetch_add(1, Ordering::Relaxed);
        Self(waiters)
    }
}

impl Drop for WaiterGuard<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::Relaxed);
    }
}

/// How long the `position`-th request in the slot queue should wait: the
/// requests ahead of it, each holding a slot for `avg_hold` on average,
/// served `capacity` at a time. Zero before any hold time is known (the gate
/// then just waits, bounded by its budget). Pure.
pub(crate) fn predicted_wait(position: usize, avg_hold: Duration, capacity: usize) -> Duration {
    let position = position.min(u32::MAX as usize) as u32;
    let capacity = capacity.clamp(1, u32::MAX as usize) as u32;
    avg_hold.saturating_mul(position) / capacity
}

/// `Retry-After` for a predicted wait: whole seconds, rounded up, at least
/// 1 and at most [`MAX_RETRY_AFTER_SECS`]. Clients that honour it come back
/// about when the backlog ahead of them has cleared instead of competing
/// with it every second. Pure.
pub(crate) fn retry_after_secs(predicted: Duration) -> u64 {
    predicted
        .as_millis()
        .div_ceil(1000)
        .clamp(1, MAX_RETRY_AFTER_SECS as u128) as u64
}

/// Whether a pool with `size` open connections, `idle` of them idle, and a
/// ceiling of `max` clearly has capacity to spare: room to open another
/// connection, or at least a quarter of its connections idle. A single idle
/// connection does not count: under load one is idle for an instant every
/// time a query returns its connection, before the next waiter takes it.
/// Pure, so the decision is pinned without a database.
pub(crate) fn pool_room(size: u32, idle: usize, max: u32) -> bool {
    size < max || idle >= (max as usize / 4).max(2)
}

/// [`pool_room`] for a live pool.
fn pool_has_room(pool: &PgPool) -> bool {
    pool_room(
        pool.size(),
        pool.num_idle(),
        pool.options().get_max_connections(),
    )
}

/// The shed answer: byte-for-byte the body a pool acquire timeout produces
/// (`AppError::Sqlx(PoolTimedOut)`), so clients and dashboards that key off
/// `POOL_EXHAUSTED` see the same thing, only sooner, with `Retry-After` set
/// to the predicted backlog ([`retry_after_secs`]).
///
/// Built here rather than through `AppError` so a burst of sheds costs a
/// counter increment each, not a `warn` log line each; the response carries
/// [`crate::error::ExpectedOutcome`] so the trace layer does not log it as a
/// server fault either.
pub(crate) fn shed_response(retry_after_secs: u64) -> Response {
    let body = Json(serde_json::json!({
        "code": "POOL_EXHAUSTED",
        "message": "Database connection pool is saturated, retry shortly",
    }));
    let mut response = (StatusCode::SERVICE_UNAVAILABLE, body).into_response();
    response
        .headers_mut()
        .insert(header::RETRY_AFTER, HeaderValue::from(retry_after_secs));
    response
        .extensions_mut()
        .insert(crate::error::ExpectedOutcome);
    response
}

/// Whether the gate leaves `path` alone: probes
/// ([`crate::api::routes::is_probe_path`], `/livez` included) and
/// [`EXEMPT_PATHS`].
pub(crate) fn is_exempt(path: &str) -> bool {
    crate::api::routes::is_probe_path(path) || EXEMPT_PATHS.contains(&path)
}

/// The gate.
pub async fn db_admission_gate(
    State(gate): State<Arc<DbAdmission>>,
    req: Request,
    next: Next,
) -> Response {
    if is_exempt(req.uri().path()) {
        return next.run(req).await;
    }
    let caller = gate.caller_of(&req);
    match gate.admit(caller).await {
        Admission::Run(_slot) => next.run(req).await,
        Admission::Shed {
            retry_after_secs,
            reason,
        } => {
            metrics::counter!(SHED_METRIC).increment(1);
            metrics::counter!(
                SHED_BY_CLASS_METRIC,
                "class" => if caller.credentialed { "credentialed" } else { "anonymous" },
                "reason" => match reason {
                    ShedReason::Backlog => "backlog",
                    ShedReason::ClientShare => "client_share",
                },
            )
            .increment(1);
            tracing::debug!(
                retry_after_secs,
                ?reason,
                credentialed = caller.credentialed,
                pool_size = gate.pool.size(),
                path = %req.uri().path(),
                "request shed: database admission backlog over the wait budget"
            );
            shed_response(retry_after_secs)
        }
    }
}

#[cfg(ak_test_shard = "services-2")]
#[cfg(test)]
#[allow(clippy::disallowed_methods)] // streaming-invariant: test-only reads of a tiny JSON error body
mod tests {
    use super::*;
    use axum::{body::Body, routing::get, Router};
    use tower::ServiceExt;

    #[test]
    fn room_means_unopened_connections_or_a_quarter_idle() {
        assert!(pool_room(3, 0, 4), "room to open a connection");
        assert!(pool_room(0, 0, 4), "a cold pool");
        assert!(!pool_room(4, 0, 4), "all open, none idle");
        assert!(
            !pool_room(4, 1, 4),
            "one idle connection is churn, not room"
        );
        assert!(pool_room(4, 2, 4));
        assert!(!pool_room(50, 11, 50));
        assert!(pool_room(50, 12, 50), "a quarter of 50 idle");
    }

    #[tokio::test]
    async fn zero_wait_or_zero_concurrency_turns_the_gate_off() {
        let pool = PgPool::connect_lazy("postgres://u:p@127.0.0.1:1/db").unwrap();
        assert!(DbAdmission::new(pool.clone(), 0, 8, Fairness::OFF).is_none());
        assert!(DbAdmission::new(pool.clone(), 250, 0, Fairness::OFF).is_none());
        let gate =
            DbAdmission::new(pool, 250, 8, Fairness::OFF).expect("both non-zero build the gate");
        assert_eq!(gate.wait, Duration::from_millis(250));
        assert_eq!(gate.permits.available_permits(), 8);
    }

    #[tokio::test]
    async fn shed_response_is_the_pool_exhausted_503_with_retry_after() {
        let response = shed_response(7);
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(response.headers()[header::RETRY_AFTER], "7");
        assert!(response
            .extensions()
            .get::<crate::error::ExpectedOutcome>()
            .is_some());
        let bytes = axum::body::to_bytes(response.into_body(), 4096)
            .await
            .unwrap();
        let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        // The same body `AppError::Sqlx(PoolTimedOut)` renders, so clients
        // keyed off the code see no difference except the latency.
        let reference = crate::error::AppError::Sqlx(sqlx::Error::PoolTimedOut).into_response();
        let ref_bytes = axum::body::to_bytes(reference.into_body(), 4096)
            .await
            .unwrap();
        let ref_body: serde_json::Value = serde_json::from_slice(&ref_bytes).unwrap();
        assert_eq!(body, ref_body);
    }

    #[tokio::test]
    async fn permits_held_next_to_a_pool_with_room_shed_nothing() {
        // A lazy pool has no connections and room for one: with the only
        // permit held, a request still runs at once (without a permit), and
        // the gate never touches the (unreachable) database.
        let pool = PgPool::connect_lazy("postgres://u:p@127.0.0.1:1/db").unwrap();
        let gate = DbAdmission::new(pool, 30_000, 1, Fairness::OFF).unwrap();
        let started = std::time::Instant::now();
        let first = gate.admit(Caller::default()).await;
        assert!(
            matches!(first, Admission::Run(Some(_))),
            "took the only slot"
        );
        assert!(matches!(
            gate.admit(Caller::default()).await,
            Admission::Run(None)
        ));
        // Waiting would take the 30 s budget.
        assert!(started.elapsed() < Duration::from_secs(10));
    }

    #[test]
    fn predicted_wait_is_the_queue_ahead_over_the_slots() {
        let hold = Duration::from_millis(250);
        // 1,168 queued behind 32 slots held 250 ms each: about 9 s.
        assert_eq!(predicted_wait(1168, hold, 32), Duration::from_millis(9125));
        assert_eq!(
            predicted_wait(8, hold, 32),
            Duration::from_millis(62) + Duration::from_micros(500)
        );
        assert_eq!(
            predicted_wait(5, Duration::ZERO, 32),
            Duration::ZERO,
            "no data yet"
        );
        assert_eq!(
            predicted_wait(5, hold, 0),
            hold * 5,
            "capacity 0 cannot divide by zero"
        );
    }

    #[test]
    fn retry_after_rounds_up_and_is_bounded() {
        assert_eq!(retry_after_secs(Duration::ZERO), 1);
        assert_eq!(retry_after_secs(Duration::from_millis(2001)), 3);
        assert_eq!(retry_after_secs(Duration::from_millis(9125)), 10);
        assert_eq!(
            retry_after_secs(Duration::from_secs(600)),
            MAX_RETRY_AFTER_SECS
        );
    }

    #[test]
    fn probes_and_the_metrics_scrape_are_exempt() {
        for path in [
            "/health",
            "/healthz",
            "/ready",
            "/readyz",
            "/livez",
            "/api/v1/admin/metrics",
        ] {
            assert!(is_exempt(path), "{path}");
        }
        for path in [
            "/api/v1/repositories",
            "/api/v1/admin/metrics/x",
            "/metrics2",
        ] {
            assert!(!is_exempt(path), "{path}");
        }
    }

    #[test]
    fn hold_average_follows_the_samples() {
        let pool_url = "postgres://u:p@127.0.0.1:1/db";
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let gate = DbAdmission::new(
                PgPool::connect_lazy(pool_url).unwrap(),
                2000,
                4,
                Fairness::OFF,
            )
            .unwrap();
            gate.record_hold(Duration::from_millis(160));
            assert_eq!(
                gate.avg_hold_us.load(Ordering::Relaxed),
                160_000,
                "first sample"
            );
            for _ in 0..200 {
                gate.record_hold(Duration::from_millis(16));
            }
            let avg = gate.avg_hold_us.load(Ordering::Relaxed);
            assert!(
                (15_000..=17_000).contains(&avg),
                "converged to 16 ms: {avg}"
            );
            let clamp = DbAdmission::new(
                PgPool::connect_lazy(pool_url).unwrap(),
                2000,
                4,
                Fairness::OFF,
            )
            .unwrap();
            clamp.record_hold(Duration::from_secs(60));
            assert_eq!(
                clamp.avg_hold_us.load(Ordering::Relaxed),
                2_000_000,
                "a hold longer than the wait counts as the wait"
            );
        });
    }

    /// A backlog predicted to outlast the wait is shed at once, with the
    /// predicted backlog (the queue ahead plus the clients already deferred)
    /// as `Retry-After`, instead of queueing to be shed at the end of the
    /// wait.
    #[tokio::test]
    async fn a_backlog_longer_than_the_wait_sheds_at_once_with_its_length() {
        let Some(pool) = db_or_skip(module_path!()).await else {
            return;
        };
        let gate = DbAdmission::new(pool.clone(), 2_000, 1, Fairness::OFF).unwrap();
        let Admission::Run(Some(_held_slot)) = gate.admit(Caller::default()).await else {
            panic!("an idle gate hands out its slot");
        };
        let _held_conn = pool.acquire().await.expect("hold the only connection");
        // Slots have been held 5 s on average; one request is already queued.
        gate.avg_hold_us.store(5_000_000, Ordering::Relaxed);
        gate.waiters.store(1, Ordering::Relaxed);
        let started = std::time::Instant::now();
        let decision = gate.admit(Caller::default()).await;
        // Queueing would take the whole 2 s wait; a shed at once does not.
        assert!(started.elapsed() < gate.wait, "no queueing");
        match decision {
            Admission::Shed {
                retry_after_secs, ..
            } => assert_eq!(retry_after_secs, 10),
            Admission::Run(_) => panic!("a 10 s backlog over a 2 s wait must shed"),
        }
        // The client just told to come back counts toward the next one's
        // Retry-After, so returning clients are spread out, not bunched.
        assert_eq!(gate.deferred.live(now_secs()), 1);
        match gate.admit(Caller::default()).await {
            Admission::Shed {
                retry_after_secs, ..
            } => assert_eq!(retry_after_secs, 15),
            Admission::Run(_) => panic!("still over the wait"),
        }
    }

    /// A one-connection pool for the DB-backed tests. CI sets
    /// `AK_TESTS_REQUIRE_DB=1`, under which an unreachable database panics
    /// inside `try_pool_with`; without it the test says loudly that it did
    /// not run instead of passing silently.
    async fn db_or_skip(test: &str) -> Option<PgPool> {
        let pool = crate::testing::try_pool_with(1).await;
        if pool.is_none() {
            eprintln!(
                "SKIPPED {test}: no DATABASE_URL (set AK_TESTS_REQUIRE_DB=1 to fail instead)"
            );
        }
        pool
    }

    #[tokio::test]
    async fn the_shed_warning_is_rate_limited() {
        let pool = PgPool::connect_lazy("postgres://u:p@127.0.0.1:1/db").unwrap();
        let gate = DbAdmission::new(pool, 2000, 4, Fairness::OFF).unwrap();
        gate.warn_shedding(100, 3);
        assert_eq!(
            gate.last_warn.load(Ordering::Relaxed),
            100,
            "first shed warns"
        );
        gate.warn_shedding(100 + SHED_WARN_INTERVAL_SECS - 1, 3);
        assert_eq!(
            gate.last_warn.load(Ordering::Relaxed),
            100,
            "not again so soon"
        );
        gate.warn_shedding(100 + SHED_WARN_INTERVAL_SECS, 3);
        assert_eq!(
            gate.last_warn.load(Ordering::Relaxed),
            100 + SHED_WARN_INTERVAL_SECS
        );
    }

    #[test]
    fn deferred_ring_counts_until_each_expiry_and_reuses_old_buckets() {
        let ring = DeferredRing::default();
        ring.add(10);
        ring.add(10);
        ring.add(12);
        assert_eq!(ring.live(9), 3);
        assert_eq!(ring.live(10), 1, "the two expiring at 10 are gone at 10");
        assert_eq!(ring.live(12), 0);
        // A lap later the bucket for 10 is reused, not added to.
        ring.add(10 + DEFERRED_BUCKETS as u64);
        assert_eq!(ring.live(20), 1);
    }

    #[test]
    fn predicted_wait_survives_extreme_inputs() {
        // Capacity past u32::MAX must not truncate to 0 and divide by zero.
        let huge = usize::MAX;
        assert_eq!(
            predicted_wait(1, Duration::from_secs(1), huge),
            Duration::ZERO
        );
        assert!(predicted_wait(huge, Duration::from_secs(1), 1) > Duration::from_secs(1 << 31));
    }

    /// The request goes away (reset stream, request timeout) while it is
    /// queued for a slot: the admit future is dropped mid-wait, and the
    /// queued count must still come back down, or the first-waiter rule,
    /// the predicted wait and Retry-After stay inflated until restart.
    #[tokio::test]
    async fn a_request_dropped_while_queued_leaves_the_queue_count_at_zero() {
        let Some(pool) = db_or_skip(module_path!()).await else {
            return;
        };
        let gate = DbAdmission::new(pool.clone(), 30_000, 1, Fairness::OFF).unwrap();
        let Admission::Run(Some(_held_slot)) = gate.admit(Caller::default()).await else {
            panic!("an idle gate hands out its slot");
        };
        let _held_conn = pool.acquire().await.expect("hold the only connection");

        let queued = {
            let gate = gate.clone();
            tokio::spawn(async move { gate.admit(Caller::default()).await })
        };
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        while gate.waiters.load(Ordering::Relaxed) == 0 {
            assert!(std::time::Instant::now() < deadline, "never queued");
            tokio::task::yield_now().await;
        }
        queued.abort();
        let _ = queued.await;
        assert_eq!(gate.waiters.load(Ordering::Relaxed), 0);

        // And via a timeout wrapper, the shape the request timeout has.
        let _ =
            tokio::time::timeout(Duration::from_millis(50), gate.admit(Caller::default())).await;
        assert_eq!(gate.waiters.load(Ordering::Relaxed), 0);
    }

    fn gated_router(gate: Arc<DbAdmission>) -> Router {
        Router::new()
            .route("/work", get(|| async { "ok" }))
            .route("/readyz", get(|| async { "ready" }))
            .route("/api/v1/admin/metrics", get(|| async { "metrics" }))
            .layer(axum::middleware::from_fn_with_state(
                gate,
                db_admission_gate,
            ))
    }

    async fn status_of(router: &Router, path: &str) -> (StatusCode, Duration) {
        let started = std::time::Instant::now();
        let response = router
            .clone()
            .oneshot(Request::builder().uri(path).body(Body::empty()).unwrap())
            .await
            .unwrap();
        (response.status(), started.elapsed())
    }

    /// The deterministic shape of #4182: a one-connection pool whose only
    /// connection, and the gate's only permit, are held by a slow request.
    /// The next request is answered 503 within the admission wait instead of
    /// queueing to the pool's acquire timeout (30 s here); a probe still
    /// passes; a permit released within the wait admits the request; and
    /// once both are released, requests are admitted again. Timings are
    /// asserted against the 30 s alternative, with room for a loaded runner.
    #[tokio::test]
    async fn saturated_pool_sheds_fast_and_recovers() {
        let Some(pool) = db_or_skip(module_path!()).await else {
            return;
        };
        let gate = DbAdmission::new(pool.clone(), 1_000, 1, Fairness::OFF).unwrap();
        let router = gated_router(gate.clone());

        let (status, _) = status_of(&router, "/work").await;
        assert_eq!(status, StatusCode::OK, "control: an idle gate admits");

        let Admission::Run(Some(held_permit)) = gate.admit(Caller::default()).await else {
            panic!("an idle gate hands out its slot");
        };
        let held_conn = pool.acquire().await.expect("hold the only connection");
        let (status, elapsed) = status_of(&router, "/work").await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert!(
            elapsed < Duration::from_secs(10),
            "shed after the 1 s wait, not the pool's 30 s acquire timeout: {elapsed:?}"
        );
        let (status, _) = status_of(&router, "/readyz").await;
        assert_eq!(status, StatusCode::OK, "probes are never gated");
        let (status, _) = status_of(&router, "/api/v1/admin/metrics").await;
        assert_eq!(status, StatusCode::OK, "the metrics scrape is never gated");

        let release = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(50)).await;
            drop(held_permit);
        });
        let (status, _) = status_of(&router, "/work").await;
        assert_eq!(status, StatusCode::OK, "permit released within the wait");
        release.await.unwrap();

        drop(held_conn);
        let (status, _) = status_of(&router, "/work").await;
        assert_eq!(status, StatusCode::OK, "control: admitted after release");
    }

    // ---- #6344: fairness between clients ----------------------------------

    fn anonymous(bucket: usize) -> Caller {
        Caller {
            credentialed: false,
            bucket: Some(bucket),
        }
    }

    fn credentialed(bucket: usize) -> Caller {
        Caller {
            credentialed: true,
            bucket: Some(bucket),
        }
    }

    fn fair(reserve: u8, share: u8) -> Fairness {
        Fairness {
            credentialed_reserve_percent: reserve,
            client_share_percent: share,
            trusted_proxies: Vec::new(),
        }
    }

    #[test]
    fn reserve_and_share_are_percentages_of_the_slots_6344() {
        assert_eq!(reserved_slots(200, 25), 50);
        assert_eq!(reserved_slots(4, 25), 1);
        assert_eq!(reserved_slots(3, 25), 0, "rounded down");
        assert_eq!(reserved_slots(4, 100), 3, "anonymous keeps one slot");
        assert_eq!(reserved_slots(1, 50), 0);
        assert_eq!(reserved_slots(8, 0), 0);
        assert_eq!(client_share_slots(200, 25), 50);
        assert_eq!(client_share_slots(4, 25), 1);
        assert_eq!(client_share_slots(2, 25), 1, "at least one slot");
        assert_eq!(client_share_slots(8, 0), 0, "off");
        assert_eq!(client_share_slots(8, 100), 0, "a 100 % share is no limit");
    }

    #[test]
    fn credential_hints_are_the_carriers_auth_reads_6344() {
        let with = |name: &str, value: &str| {
            let mut h = HeaderMap::new();
            h.insert(
                axum::http::HeaderName::from_bytes(name.as_bytes()).unwrap(),
                HeaderValue::from_str(value).unwrap(),
            );
            h
        };
        let none = HeaderMap::new();
        assert!(!presents_credential(&none, "/api/v1/repositories"));
        assert!(presents_credential(
            &with("authorization", "Bearer x"),
            "/pypi/r/simple/"
        ));
        assert!(presents_credential(
            &with("authorization", "Basic dTpw"),
            "/"
        ));
        assert!(presents_credential(&with("x-api-key", "k"), "/"));
        assert!(presents_credential(&with("x-nuget-apikey", "k"), "/"));
        assert!(presents_credential(
            &with("cookie", "a=b; ak_access_token=t"),
            "/"
        ));
        assert!(!presents_credential(&with("cookie", "a=b"), "/"));
        assert!(presents_credential(
            &none,
            "/t/tok/conda/r/noarch/repodata.json"
        ));
        assert!(!presents_credential(&none, "/t//conda/r"));
        assert!(!presents_credential(&none, "/t/"));
        assert!(!presents_credential(&none, "/tools/x"));
    }

    #[tokio::test]
    async fn caller_of_keys_by_client_ip_and_reads_the_hint_6344() {
        let pool = PgPool::connect_lazy("postgres://u:p@127.0.0.1:1/db").unwrap();
        let gate = DbAdmission::new(pool, 2000, 8, fair(25, 25)).unwrap();
        let req = |peer: &str, auth: Option<&str>| {
            let mut b = Request::builder().uri("/api/v1/repositories");
            if let Some(a) = auth {
                b = b.header(header::AUTHORIZATION, a);
            }
            let mut r = b.body(Body::empty()).unwrap();
            r.extensions_mut()
                .insert(ConnectInfo(peer.parse::<SocketAddr>().unwrap()));
            r
        };
        let a1 = gate.caller_of(&req("10.0.0.1:1000", None));
        let a2 = gate.caller_of(&req("10.0.0.1:2000", Some("Bearer t")));
        let b = gate.caller_of(&req("10.0.0.2:1000", None));
        assert!(!a1.credentialed && a2.credentialed && !b.credentialed);
        assert_eq!(a1.bucket, a2.bucket, "one client per IP, any port");
        assert!(a1.bucket.is_some() && b.bucket.is_some());
        // Off: no counter at all.
        let off = DbAdmission::new(
            PgPool::connect_lazy("postgres://u:p@127.0.0.1:1/db").unwrap(),
            2000,
            8,
            fair(25, 0),
        )
        .unwrap();
        assert_eq!(off.caller_of(&req("10.0.0.1:1", None)).bucket, None);
    }

    /// The deterministic shape of #6344: a busy pool, and an anonymous flood
    /// holding every slot it may take. Before the reserve the next request,
    /// whoever sent it, waited out the budget and was shed; now a request
    /// presenting a credential takes a reserved slot at once, while the
    /// flood's next request is the one shed.
    #[tokio::test]
    async fn an_anonymous_flood_cannot_take_the_credentialed_reserve_6344() {
        let Some(pool) = db_or_skip(module_path!()).await else {
            return;
        };
        // 4 slots, 1 reserved; the per-client share off to isolate the rule.
        let gate = DbAdmission::new(pool.clone(), 300, 4, fair(25, 0)).unwrap();
        assert_eq!((gate.general, gate.reserved), (3, 1));
        let _held_conn = pool.acquire().await.expect("hold the only connection");
        let mut flood = Vec::new();
        for _ in 0..3 {
            match gate.admit(anonymous(1)).await {
                Admission::Run(Some(slot)) => flood.push(slot),
                _ => panic!("the general slots are free"),
            }
        }
        match gate.admit(anonymous(2)).await {
            Admission::Shed { reason, .. } => assert_eq!(reason, ShedReason::Backlog),
            Admission::Run(_) => panic!("anonymous requests may not take the reserve"),
        }
        let started = std::time::Instant::now();
        let Admission::Run(Some(_reserved)) = gate.admit(credentialed(3)).await else {
            panic!("a credentialed request takes the reserved slot");
        };
        assert!(started.elapsed() < gate.wait, "at once, without queueing");

        // With the reserve off the same credentialed request is shed like
        // everyone else's (the gate as #4182 shipped it).
        let legacy = DbAdmission::new(pool.clone(), 300, 4, Fairness::OFF).unwrap();
        let mut legacy_flood = Vec::new();
        for _ in 0..4 {
            if let Admission::Run(Some(slot)) = legacy.admit(anonymous(1)).await {
                legacy_flood.push(slot);
            }
        }
        assert!(matches!(
            legacy.admit(credentialed(3)).await,
            Admission::Shed { .. }
        ));
    }

    /// A client alone on a busy pool keeps queueing past its share (the gate
    /// stays work-conserving); once another client has to wait, the client
    /// at its share is shed at once and the next free slot goes to the other.
    #[tokio::test]
    async fn a_client_at_its_share_yields_to_a_waiting_client_6344() {
        let Some(pool) = db_or_skip(module_path!()).await else {
            return;
        };
        // 4 slots, a share of 1, no reserve.
        let gate = DbAdmission::new(pool.clone(), 5_000, 4, fair(0, 25)).unwrap();
        assert_eq!(gate.client_share, 1);
        let _held_conn = pool.acquire().await.expect("hold the only connection");
        let mut held = Vec::new();
        for _ in 0..4 {
            match gate.admit(anonymous(7)).await {
                Admission::Run(Some(slot)) => held.push(slot),
                _ => panic!("free slots"),
            }
        }
        // Alone: client 7 queues for a fifth slot instead of being shed.
        let alone =
            tokio::time::timeout(Duration::from_millis(100), gate.admit(anonymous(7))).await;
        assert!(alone.is_err(), "queued (timed out waiting), not shed");

        // Client 8 has to wait: contention.
        let waiting = {
            let gate = gate.clone();
            tokio::spawn(async move { gate.admit(anonymous(8)).await })
        };
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        while gate.waiters.load(Ordering::Relaxed) == 0 {
            assert!(
                std::time::Instant::now() < deadline,
                "client 8 never queued"
            );
            tokio::task::yield_now().await;
        }
        let started = std::time::Instant::now();
        match gate.admit(anonymous(7)).await {
            Admission::Shed { reason, .. } => assert_eq!(reason, ShedReason::ClientShare),
            Admission::Run(_) => panic!("client 7 is at its share while 8 waits"),
        }
        assert!(started.elapsed() < Duration::from_secs(1), "shed at once");
        // Client 7 releases a slot: it goes to client 8.
        drop(held.pop());
        let Admission::Run(Some(_slot)) = waiting.await.unwrap() else {
            panic!("client 8 gets the released slot");
        };
        assert_eq!(gate.clients[7].load(Ordering::Relaxed), 3);
        drop(held);
        assert_eq!(gate.clients[7].load(Ordering::Relaxed), 0, "counts return");
    }

    #[test]
    fn ipv6_clients_are_counted_by_their_64_6344() {
        let k = |s: &str| client_key(s.parse().unwrap());
        assert_eq!(
            k("2001:db8:1:2:aaaa::1"),
            k("2001:db8:1:2:ffff:1:2:3"),
            "same /64"
        );
        assert_ne!(k("2001:db8:1:2::1"), k("2001:db8:1:3::1"), "next /64");
        assert_eq!(
            k("::ffff:10.0.0.7"),
            k("10.0.0.7"),
            "IPv4-mapped is the IPv4 client"
        );
        assert_ne!(k("10.0.0.7"), k("10.0.0.8"));
    }

    /// Contention lasts its window only: once it has run out, a client at
    /// its share queues again instead of being shed.
    #[tokio::test]
    async fn contention_expires_after_its_window_6344() {
        let Some(pool) = db_or_skip(module_path!()).await else {
            return;
        };
        let gate = DbAdmission::new(pool.clone(), 5_000, 2, fair(0, 50)).unwrap();
        let _held_conn = pool.acquire().await.expect("hold the only connection");
        let mut held = Vec::new();
        for _ in 0..2 {
            let Admission::Run(Some(slot)) = gate.admit(anonymous(3)).await else {
                panic!("free slots");
            };
            held.push(slot);
        }
        gate.contended_until_ms
            .store(now_millis() + 50, Ordering::Relaxed);
        assert!(
            matches!(
                gate.admit(anonymous(3)).await,
                Admission::Shed {
                    reason: ShedReason::ClientShare,
                    ..
                }
            ),
            "inside the window: shed"
        );
        tokio::time::sleep(Duration::from_millis(80)).await;
        let queued =
            tokio::time::timeout(Duration::from_millis(100), gate.admit(anonymous(3))).await;
        assert!(queued.is_err(), "after the window: queued, not shed");
    }

    /// A credentialed request that has to wait takes whichever slot frees
    /// first, a reserved one included; an anonymous waiter never takes it.
    #[tokio::test]
    async fn a_credentialed_waiter_gets_a_reserved_slot_6344() {
        let Some(pool) = db_or_skip(module_path!()).await else {
            return;
        };
        let gate = DbAdmission::new(pool.clone(), 5_000, 4, fair(25, 0)).unwrap();
        let _held_conn = pool.acquire().await.expect("hold the only connection");
        let mut general = Vec::new();
        for _ in 0..3 {
            let Admission::Run(Some(slot)) = gate.admit(anonymous(1)).await else {
                panic!("general slots free");
            };
            general.push(slot);
        }
        let Admission::Run(Some(reserved)) = gate.admit(credentialed(2)).await else {
            panic!("the reserved slot is free");
        };
        let anon = {
            let gate = gate.clone();
            tokio::spawn(async move { gate.admit(anonymous(4)).await })
        };
        let cred = {
            let gate = gate.clone();
            tokio::spawn(async move { gate.admit(credentialed(5)).await })
        };
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        while gate.waiters.load(Ordering::Relaxed) < 2 {
            assert!(std::time::Instant::now() < deadline, "both never queued");
            tokio::task::yield_now().await;
        }
        drop(reserved);
        let Admission::Run(Some(_slot)) = cred.await.unwrap() else {
            panic!("the credentialed waiter gets the released reserved slot");
        };
        assert!(
            !anon.is_finished(),
            "the anonymous waiter is still waiting for a general slot"
        );
        drop(general.pop());
        let Admission::Run(Some(_slot)) = anon.await.unwrap() else {
            panic!("the anonymous waiter gets the released general slot");
        };
    }
}
