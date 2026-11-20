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
//! permit). When every permit is held and the pool is busy, a request waits
//! up to `DATABASE_REQUEST_ACQUIRE_WAIT_MS` (default 500 ms) for a permit and
//! is otherwise answered at once with the same `503 POOL_EXHAUSTED` +
//! `Retry-After: 1` body the pool timeout produces, counted in
//! `ak_db_requests_shed_total`. An admitted request queues behind at most the
//! other permit holders, so it finishes in a bounded time instead of slowing
//! down with the whole burst.
//!
//! The permits only shed while the pool is busy: when every permit is held
//! but the pool has room (connections it has not opened yet, or a quarter of
//! them idle), a request runs without one, so slow uploads or upstream
//! fetches holding permits never shed anything on their own.
//!
//! A shed request has done no work at all; in particular it has not
//! authenticated, so a shed can never let a request through (it is a `503`,
//! never a `2xx`), and an admitted request goes through every check exactly
//! as before. Health and readiness probes are never gated, and read the
//! database through their own small pool ([`crate::db::create_probe_pool`]),
//! so a saturated request pool does not make a busy replica look dead.
//!
//! `DATABASE_REQUEST_ACQUIRE_WAIT_MS=0` or `DATABASE_REQUEST_CONCURRENCY=0`
//! turns the gate off.

use std::sync::Arc;
use std::time::Duration;

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

/// The gate's state: the request pool, the handler-phase permits, and how
/// long a request may wait for a permit while the pool is busy.
#[derive(Clone)]
pub struct DbAdmission {
    pool: PgPool,
    permits: Arc<Semaphore>,
    wait: Duration,
}

impl DbAdmission {
    /// The gate for `pool`, or `None` when `wait_ms` or `concurrency` is `0`
    /// (gate off).
    pub fn new(pool: PgPool, wait_ms: u64, concurrency: usize) -> Option<Arc<Self>> {
        (wait_ms > 0 && concurrency > 0).then(|| {
            Arc::new(Self {
                pool,
                permits: Arc::new(Semaphore::new(concurrency)),
                wait: Duration::from_millis(wait_ms),
            })
        })
    }

    /// Admit or shed one request. `Some(permit)` runs it, holding the
    /// permit (if any) until its response head is ready; `None` sheds it.
    pub(crate) async fn admit(&self) -> Option<Option<OwnedSemaphorePermit>> {
        let permits = &self.permits;
        if let Ok(permit) = permits.clone().try_acquire_owned() {
            return Some(Some(permit));
        }
        // Every permit is held. That only means the pool is the bottleneck
        // when the pool is busy too; permits held by slow uploads or upstream
        // fetches next to an idle pool must not shed anything.
        if pool_has_room(&self.pool) {
            return Some(None);
        }
        match tokio::time::timeout(self.wait, permits.clone().acquire_owned()).await {
            Ok(Ok(permit)) => Some(Some(permit)),
            // Out of time: run it anyway if the pool has room by now.
            _ => pool_has_room(&self.pool).then_some(None),
        }
    }
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
/// (`AppError::Sqlx(PoolTimedOut)`), with `Retry-After: 1`, so clients and
/// dashboards that key off `POOL_EXHAUSTED` see the same thing, only sooner.
///
/// Built here rather than through `AppError` so a burst of sheds costs a
/// counter increment each, not a `warn` log line each; the response carries
/// [`crate::error::ExpectedOutcome`] so the trace layer does not log it as a
/// server fault either.
pub(crate) fn shed_response() -> Response {
    let body = Json(serde_json::json!({
        "code": "POOL_EXHAUSTED",
        "message": "Database connection pool is saturated, retry shortly",
    }));
    let mut response = (StatusCode::SERVICE_UNAVAILABLE, body).into_response();
    response.headers_mut().insert(
        header::RETRY_AFTER,
        HeaderValue::from_static(crate::error::RETRY_AFTER_SECS_ON_503),
    );
    response
        .extensions_mut()
        .insert(crate::error::ExpectedOutcome);
    response
}

/// The gate. Probes ([`crate::api::routes::is_probe_path`]) always pass.
pub async fn db_admission_gate(
    State(gate): State<Arc<DbAdmission>>,
    req: Request,
    next: Next,
) -> Response {
    if crate::api::routes::is_probe_path(req.uri().path()) {
        return next.run(req).await;
    }
    if let Some(_permit) = gate.admit().await {
        return next.run(req).await;
    }
    metrics::counter!(SHED_METRIC).increment(1);
    tracing::debug!(
        wait_ms = gate.wait.as_millis() as u64,
        pool_size = gate.pool.size(),
        path = %req.uri().path(),
        "request shed: no database connection within the admission wait"
    );
    shed_response()
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
        let response = shed_response();
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(response.headers()[header::RETRY_AFTER], "1");
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
        let first = gate.admit().await.expect("admitted");
        assert!(first.is_some(), "took the only permit");
        assert!(matches!(gate.admit().await, Some(None)));
        assert!(started.elapsed() < Duration::from_secs(1));
    }

    fn gated_router(gate: Arc<DbAdmission>) -> Router {
        Router::new()
            .route("/work", get(|| async { "ok" }))
            .route("/readyz", get(|| async { "ready" }))
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

        let held_permit = gate.admit().await.expect("idle gate").expect("permit");
        let held_conn = pool.acquire().await.expect("hold the only connection");
        let (status, elapsed) = status_of(&router, "/work").await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert!(
            elapsed < Duration::from_secs(2),
            "shed after the 200 ms wait, not the pool's acquire timeout: {elapsed:?}"
        );
        let (status, _) = status_of(&router, "/readyz").await;
        assert_eq!(status, StatusCode::OK, "probes are never gated");

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
