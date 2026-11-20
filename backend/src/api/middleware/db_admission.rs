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
//! queue for one for up to `DATABASE_REQUEST_ACQUIRE_WAIT_MS` (default 2 s,
//! below the pool's 5 s acquire timeout). Before queueing, the gate predicts
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

use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::{
    extract::{Request, State},
    http::{header, HeaderValue, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
    Json,
};
use sqlx::PgPool;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

/// Counter of requests the gate answered `503` without running them.
pub const SHED_METRIC: &str = "ak_db_requests_shed_total";

/// Paths the gate never sheds besides the probes: the main-port Prometheus
/// scrape, so monitoring is not blinded during the very incident it should
/// show. (The separate `METRICS_PORT` listener has no gate at all.)
const EXEMPT_PATHS: &[&str] = &["/api/v1/admin/metrics"];

/// Longest `Retry-After` the gate sends, in seconds.
const MAX_RETRY_AFTER_SECS: u64 = 30;

/// Weight of the newest sample in the moving average of slot hold times
/// (1/16: smooth over a few dozen requests, follow a shift within ~50).
const HOLD_EWMA_SHIFT: u32 = 4;

/// The gate's state: the request pool, the handler-phase slots, the longest
/// predicted wait a request is allowed to queue for, and what it measures to
/// predict that wait.
pub struct DbAdmission {
    pool: PgPool,
    permits: Arc<Semaphore>,
    capacity: usize,
    wait: Duration,
    /// Requests queued for a slot right now.
    waiters: AtomicUsize,
    /// Requests shed with a `Retry-After` that has not run out yet: clients
    /// that will be back, and that a newcomer's prediction has to count, or
    /// the gate tells everyone to return at the same short interval and they
    /// collide again.
    deferred: Arc<AtomicUsize>,
    /// Moving average of how long a request holds its slot, in microseconds
    /// (0 until the first slot is returned).
    avg_hold_us: AtomicU64,
}

/// A held slot. Returning it feeds the hold-time average the wait
/// prediction uses.
pub(crate) struct Slot {
    _permit: OwnedSemaphorePermit,
    since: Instant,
    gate: Arc<DbAdmission>,
}

impl Drop for Slot {
    fn drop(&mut self) {
        self.gate.record_hold(self.since.elapsed());
    }
}

/// What [`DbAdmission::admit`] decided.
pub(crate) enum Admission {
    /// Run, holding the slot (if any) until the response head is ready.
    Run(Option<Slot>),
    /// Shed, telling the client to come back after this many seconds.
    Shed { retry_after_secs: u64 },
}

impl DbAdmission {
    /// The gate for `pool`, or `None` when `wait_ms` or `concurrency` is `0`
    /// (gate off).
    pub fn new(pool: PgPool, wait_ms: u64, concurrency: usize) -> Option<Arc<Self>> {
        (wait_ms > 0 && concurrency > 0).then(|| {
            Arc::new(Self {
                pool,
                permits: Arc::new(Semaphore::new(concurrency)),
                capacity: concurrency,
                wait: Duration::from_millis(wait_ms),
                waiters: AtomicUsize::new(0),
                deferred: Arc::new(AtomicUsize::new(0)),
                avg_hold_us: AtomicU64::new(0),
            })
        })
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

    fn slot(self: &Arc<Self>, permit: OwnedSemaphorePermit) -> Slot {
        Slot {
            _permit: permit,
            since: Instant::now(),
            gate: self.clone(),
        }
    }

    /// Admit or shed one request.
    pub(crate) async fn admit(self: &Arc<Self>) -> Admission {
        if let Ok(permit) = self.permits.clone().try_acquire_owned() {
            return Admission::Run(Some(self.slot(permit)));
        }
        // Every slot is held. That only means the pool is the bottleneck
        // when the pool is busy too; slots held by slow uploads or upstream
        // fetches next to an idle pool must not shed anything.
        if pool_has_room(&self.pool) {
            return Admission::Run(None);
        }
        // Queue only when the queue ahead is predicted to clear within the
        // wait; otherwise say at once how long the backlog is.
        // With nobody queued yet the request always gets to wait: a
        // prediction needs a queue to be about.
        let queued = self.waiters.load(Ordering::Relaxed);
        if queued > 0 && predicted_wait(queued + 1, self.avg_hold(), self.capacity) > self.wait {
            return self.shed();
        }
        self.waiters.fetch_add(1, Ordering::Relaxed);
        let acquired = tokio::time::timeout(self.wait, self.permits.clone().acquire_owned()).await;
        self.waiters.fetch_sub(1, Ordering::Relaxed);
        match acquired {
            Ok(Ok(permit)) => Admission::Run(Some(self.slot(permit))),
            // Out of time: run it anyway if the pool has room by now.
            _ if pool_has_room(&self.pool) => Admission::Run(None),
            _ => self.shed(),
        }
    }

    fn avg_hold(&self) -> Duration {
        Duration::from_micros(self.avg_hold_us.load(Ordering::Relaxed))
    }

    /// Shed, with a `Retry-After` for when the queue ahead plus everyone
    /// already told to come back should have been served (at least the wait
    /// budget), counting the client as deferred until that runs out.
    fn shed(&self) -> Admission {
        let backlog =
            self.waiters.load(Ordering::Relaxed) + self.deferred.load(Ordering::Relaxed) + 1;
        let predicted = predicted_wait(backlog, self.avg_hold(), self.capacity).max(self.wait);
        let retry_after_secs = retry_after_secs(predicted);
        self.deferred.fetch_add(1, Ordering::Relaxed);
        let deferred = self.deferred.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_secs(retry_after_secs)).await;
            deferred.fetch_sub(1, Ordering::Relaxed);
        });
        Admission::Shed { retry_after_secs }
    }
}

/// How long the `position`-th request in the slot queue should wait: the
/// requests ahead of it, each holding a slot for `avg_hold` on average,
/// served `capacity` at a time. Zero before any hold time is known (the gate
/// then just waits, bounded by its budget). Pure.
pub(crate) fn predicted_wait(position: usize, avg_hold: Duration, capacity: usize) -> Duration {
    avg_hold.saturating_mul(position.min(u32::MAX as usize) as u32) / capacity.max(1) as u32
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
    match gate.admit().await {
        Admission::Run(_slot) => next.run(req).await,
        Admission::Shed { retry_after_secs } => {
            metrics::counter!(SHED_METRIC).increment(1);
            tracing::debug!(
                retry_after_secs,
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
        assert!(DbAdmission::new(pool.clone(), 0, 8).is_none());
        assert!(DbAdmission::new(pool.clone(), 250, 0).is_none());
        let gate = DbAdmission::new(pool, 250, 8).expect("both non-zero build the gate");
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
        let gate = DbAdmission::new(pool, 5_000, 1).unwrap();
        let started = std::time::Instant::now();
        let first = gate.admit().await;
        assert!(
            matches!(first, Admission::Run(Some(_))),
            "took the only slot"
        );
        assert!(matches!(gate.admit().await, Admission::Run(None)));
        assert!(started.elapsed() < Duration::from_secs(1));
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
            let gate = DbAdmission::new(PgPool::connect_lazy(pool_url).unwrap(), 2000, 4).unwrap();
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
            let clamp = DbAdmission::new(PgPool::connect_lazy(pool_url).unwrap(), 2000, 4).unwrap();
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
        let Some(pool) = crate::testing::try_pool_with(1).await else {
            return;
        };
        let gate = DbAdmission::new(pool.clone(), 2_000, 1).unwrap();
        let Admission::Run(Some(_held_slot)) = gate.admit().await else {
            panic!("an idle gate hands out its slot");
        };
        let _held_conn = pool.acquire().await.expect("hold the only connection");
        // Slots have been held 5 s on average; one request is already queued.
        gate.avg_hold_us.store(5_000_000, Ordering::Relaxed);
        gate.waiters.store(1, Ordering::Relaxed);
        let started = std::time::Instant::now();
        let decision = gate.admit().await;
        assert!(
            started.elapsed() < Duration::from_millis(500),
            "no queueing"
        );
        match decision {
            Admission::Shed { retry_after_secs } => assert_eq!(retry_after_secs, 10),
            Admission::Run(_) => panic!("a 10 s backlog over a 2 s wait must shed"),
        }
        // The client just told to come back counts toward the next one's
        // Retry-After, so returning clients are spread out, not bunched.
        assert_eq!(gate.deferred.load(Ordering::Relaxed), 1);
        match gate.admit().await {
            Admission::Shed { retry_after_secs } => assert_eq!(retry_after_secs, 15),
            Admission::Run(_) => panic!("still over the wait"),
        }
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
    /// once both are released, requests are admitted again.
    #[tokio::test]
    async fn saturated_pool_sheds_fast_and_recovers() {
        let Some(pool) = crate::testing::try_pool_with(1).await else {
            return;
        };
        let gate = DbAdmission::new(pool.clone(), 200, 1).unwrap();
        let router = gated_router(gate.clone());

        let (status, _) = status_of(&router, "/work").await;
        assert_eq!(status, StatusCode::OK, "control: an idle gate admits");

        let Admission::Run(Some(held_permit)) = gate.admit().await else {
            panic!("an idle gate hands out its slot");
        };
        let held_conn = pool.acquire().await.expect("hold the only connection");
        let (status, elapsed) = status_of(&router, "/work").await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert!(
            elapsed < Duration::from_secs(2),
            "shed after the 200 ms wait, not the pool's acquire timeout: {elapsed:?}"
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
}
