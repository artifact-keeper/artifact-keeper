//! Database connection pool setup and shared transaction retry helpers.

use crate::config::Config;
use crate::error::{DeadlockError, Result};
use rand::RngExt;
use sqlx::postgres::{PgConnectOptions, PgPool, PgPoolOptions};
use std::str::FromStr;
use std::time::Duration;

/// Connections idle longer than this run a full `SELECT 1` probe before being
/// returned by the pool. Short-idle acquires skip the probe to keep the hot
/// path free of an extra round trip.
const IDLE_LIVENESS_THRESHOLD: Duration = Duration::from_secs(30);

/// Server-side TCP keepalive triple — `(idle seconds, probe interval seconds,
/// probe count)` — armed on every connection the pool opens (#4549). Dedicated
/// advisory-lock sessions re-arm the same values after `detach` (#4013).
///
/// A pod that disappears without closing its sockets (force-deleted pod, lost
/// node) sends no FIN or RST, so Postgres keeps its sessions — and whatever
/// those sessions hold — until the kernel's default keepalive gives up: about
/// two hours on Linux. On a 3-replica deployment that is
/// `DATABASE_MAX_CONNECTIONS` ghost sessions per replica, enough to fill
/// `max_connections` and crash-loop the replacement pod on
/// `Sqlx(PoolTimedOut)` long before the ghosts expire (#4549). With these
/// values the server declares the peer dead after
/// `idle + interval * count` = 30 s and ends the session.
///
/// `tcp_keepalives_*` configure the SERVER's end of each connection, so the
/// connecting client sets them per session: the pool's `after_connect` hook
/// ([`arm_tcp_keepalives`]) sets them on every connection it opens, unless
/// `DATABASE_TCP_KEEPALIVES=false`. They are deliberately NOT sent as
/// startup `options`: PgBouncer refuses unknown startup parameters by
/// default, so that would break installs behind it. Detached connections are
/// pooled connections taken out of circulation (`PoolConnection::detach`),
/// so they inherit the same session settings — "pool and detached" in
/// #4549's words. Postgres accepts and ignores these settings on a
/// Unix-domain socket (the GUC reads back as `0`), which is harmless: a local
/// socket closes with its process anyway, so it cannot leave ghosts behind.
pub const TCP_KEEPALIVES: (&str, &str, &str) = ("15", "5", "3");

/// Set [`TCP_KEEPALIVES`] on one session (#4549, #4013). Shared by the pool's
/// `after_connect` hook and the dedicated advisory-lock sessions in
/// `cluster_lock`, so the two can never disagree.
pub(crate) async fn arm_tcp_keepalives(
    conn: &mut sqlx::PgConnection,
) -> std::result::Result<(), sqlx::Error> {
    let (idle, interval, count) = TCP_KEEPALIVES;
    sqlx::query(
        "SELECT set_config('tcp_keepalives_idle', $1, false), \
                set_config('tcp_keepalives_interval', $2, false), \
                set_config('tcp_keepalives_count', $3, false)",
    )
    .bind(idle)
    .bind(interval)
    .bind(count)
    .execute(conn)
    .await
    .map(|_| ())
}

/// Set once the pool's keepalive hook has logged a failure, so a pooler that
/// refuses the settings on every connection logs one warning, not one per
/// connection.
static KEEPALIVE_ARM_WARNED: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

/// The pool's `after_connect` body: arm the keepalives, and on failure warn
/// once and keep the connection. A pooler in transaction mode (PgBouncer,
/// RDS Proxy) may refuse or not carry session settings; the connection is
/// still perfectly usable, it just keeps the server's keepalive defaults.
async fn arm_pool_connection_keepalives(conn: &mut sqlx::PgConnection) {
    if let Err(e) = arm_tcp_keepalives(conn).await {
        if !KEEPALIVE_ARM_WARNED.swap(true, std::sync::atomic::Ordering::Relaxed) {
            tracing::warn!(
                error = %e,
                "database pool: could not set server-side TCP keepalives on a new \
                 connection; continuing with the server's defaults (a connection \
                 pooler may not honour session settings; set \
                 DATABASE_TCP_KEEPALIVES=false to stop trying). Logged once."
            );
        }
    }
}

/// Wall-clock cap on the whole startup connect window (#4549): no further
/// attempt starts once the next backoff would end past this, so a database
/// that stays down fails the process within about a minute even when
/// `DATABASE_ACQUIRE_TIMEOUT_SECS` is raised (an attempt already running
/// still finishes its own acquire timeout). With the defaults (5 attempts,
/// 5 s acquire timeout) the attempt count ends startup first, after about
/// 40 s.
const STARTUP_CONNECT_DEADLINE: Duration = Duration::from_secs(60);

/// How many times [`create_pool`] attempts the initial connect before startup
/// gives up (#4549).
///
/// Five, not "until it succeeds" and not one: a replacement pod used to exit
/// on the first `Sqlx(PoolTimedOut)` and enter CrashLoopBackOff, while the
/// condition that refused it — Postgres finishing a restart, a
/// rolling-update surge pod draining, a burst of `too many clients` refusals —
/// cleared within seconds. Five jittered attempts ride out that transient,
/// and a database that is genuinely broken still ends startup after a bounded,
/// logged window instead of hanging the deployment. Each attempt is one sqlx
/// connect, itself bounded by `DATABASE_ACQUIRE_TIMEOUT_SECS`.
const STARTUP_CONNECT_ATTEMPTS: u32 = 5;

/// Backoff before the connect attempt following `failed` failed attempts
/// (`failed` is 1-based): 1 s, 2 s, 4 s, then capped at 8 s, each jittered
/// ±50%.
///
/// Doubling so a Postgres already refusing connections is not probed on a
/// fixed cadence; capped so the whole startup window stays near a minute;
/// jittered so replicas restarting together — exactly when the connection
/// budget is tight — do not retry in lockstep and collide again.
fn startup_connect_backoff(failed: u32) -> Duration {
    let base_ms = 1_000_u64 << failed.saturating_sub(1).min(3);
    let ms = rand::rng().random_range(base_ms / 2..=base_ms + base_ms / 2);
    Duration::from_millis(ms)
}

/// The connection-budget sentence attached to the final startup connect
/// failure (#4549): what this replica opens, and the arithmetic that has to
/// fit under the server's `max_connections`.
fn connection_budget(config: &Config) -> String {
    format!(
        "connection budget: DATABASE_MAX_CONNECTIONS={} pool connections per replica \
         (DATABASE_ACQUIRE_TIMEOUT_SECS={}), plus single-flight lock/wait connections \
         held outside the pool (capped per replica by PROXY_SINGLEFLIGHT_MAX_LOCK_WAITERS), \
         plus one rolling-update surge replica, must stay below Postgres max_connections \
         (see the Database section of .env.example)",
        config.database_max_connections, config.database_acquire_timeout_secs
    )
}

/// One startup connect attempt: build the pool and establish its first
/// connection(s). Kept separate from [`create_pool`] so the retry loop can be
/// exercised without a live database.
async fn build_pool(
    config: &Config,
    options: &PgConnectOptions,
) -> std::result::Result<PgPool, sqlx::Error> {
    let mut pool_options = PgPoolOptions::new()
        .max_connections(config.database_max_connections)
        .min_connections(config.database_min_connections)
        .acquire_timeout(Duration::from_secs(config.database_acquire_timeout_secs))
        .idle_timeout(Duration::from_secs(config.database_idle_timeout_secs))
        .max_lifetime(Duration::from_secs(config.database_max_lifetime_secs))
        .before_acquire(|conn, meta| {
            Box::pin(async move {
                // sqlx's default `test_before_acquire` only sends a protocol
                // PING, which can succeed on a TCP socket that has been
                // silently broken by an upstream event (CNI flow reflow,
                // NAT rotation, brief Postgres unavailability). When that
                // happens, the next real query fails with an IO error and
                // the pool keeps handing back the same dead connection,
                // turning a transient glitch into a permanent outage that
                // only a pod restart fixes. Issue #1877.
                //
                // For connections that have actually been idle, run a real
                // query so a stale socket is detected here and the
                // connection is evicted by sqlx before any caller sees it.
                if meta.idle_for >= IDLE_LIVENESS_THRESHOLD {
                    sqlx::query("SELECT 1").execute(&mut *conn).await?;
                }
                Ok(true)
            })
        });
    if config.database_tcp_keepalives {
        // #4549: arm the server-side keepalives on every new connection with
        // a plain query rather than startup `options`, which PgBouncer
        // refuses by default. Never fails the connection.
        pool_options = pool_options.after_connect(|conn, _meta| {
            Box::pin(async move {
                arm_pool_connection_keepalives(conn).await;
                Ok(())
            })
        });
    }
    pool_options.connect_with(options.clone()).await
}

/// Run `connect` up to `attempts` times with the jittered doubling backoff of
/// [`startup_connect_backoff`] (#4549), counting every failure in
/// `ak_db_pool_connection_failures_total{stage="startup"}` and naming
/// `budget` — the sentence from [`connection_budget`] — in the final error's
/// log line.
///
/// Bounded, in the same spirit as [`retry_on_deadlock`]: whichever attempt
/// decides the outcome is the answer, so a database that stays down ends
/// startup with the underlying error after a window long enough to outlast
/// the transient that used to put the replacement pod into CrashLoopBackOff.
async fn retry_initial_connect<T, E, F, Fut>(
    budget: &str,
    attempts: u32,
    deadline: Duration,
    mut connect: F,
) -> std::result::Result<T, E>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = std::result::Result<T, E>>,
    E: std::fmt::Display,
{
    let started = tokio::time::Instant::now();
    let mut attempt = 1;
    loop {
        match connect().await {
            Ok(value) => return Ok(value),
            Err(err) => {
                // Connection refusals and pool acquire timeouts at startup
                // were invisible outside the logs (#4549); count them.
                crate::services::metrics_service::record_db_pool_connection_failure("startup");
                let backoff = startup_connect_backoff(attempt);
                if attempt >= attempts || started.elapsed() + backoff >= deadline {
                    tracing::error!(
                        "database pool: giving up on the initial connect after \
                         {attempt} attempts in {}s: {err} ({budget})",
                        started.elapsed().as_secs()
                    );
                    return Err(err);
                }
                tracing::warn!(
                    "database pool: initial connect attempt {attempt}/{attempts} failed: \
                     {err}; retrying in {}ms",
                    backoff.as_millis()
                );
                tokio::time::sleep(backoff).await;
                attempt += 1;
            }
        }
    }
}

/// Create a new database connection pool using the connection pool settings
/// from [`Config`]. Pool sizing and timeouts are configurable via the
/// `DATABASE_MAX_CONNECTIONS`, `DATABASE_MIN_CONNECTIONS`,
/// `DATABASE_ACQUIRE_TIMEOUT_SECS`, `DATABASE_IDLE_TIMEOUT_SECS`, and
/// `DATABASE_MAX_LIFETIME_SECS` environment variables. See `.env.example`
/// for the default values and for sizing the fleet against the server's
/// `max_connections` (#4549).
///
/// Two #4549 behaviours wrap the plain pool build: every connection arms
/// [`TCP_KEEPALIVES`] in an `after_connect` hook (unless
/// `DATABASE_TCP_KEEPALIVES=false`), and the first connect is retried up to
/// [`STARTUP_CONNECT_ATTEMPTS`] times, within [`STARTUP_CONNECT_DEADLINE`],
/// instead of giving up on the first `PoolTimedOut`.
pub async fn create_pool(config: &Config) -> Result<PgPool> {
    let options = PgConnectOptions::from_str(&config.database_url)?;
    let budget = connection_budget(config);
    let pool = retry_initial_connect(
        &budget,
        STARTUP_CONNECT_ATTEMPTS,
        STARTUP_CONNECT_DEADLINE,
        || async { build_pool(config, &options).await },
    )
    .await?;
    Ok(pool)
}

/// How many times a transaction that can lose a lock-order race is attempted
/// before its `40P01` is surfaced (#4004).
///
/// Three, not "until it succeeds": a deadlock means some *other* transaction
/// won and is about to commit, so the next attempt normally finds the
/// contended rows free. A cycle that survives three attempts is a lock-order
/// defect, and burying it behind an unbounded retry loop would hide it.
const DEADLOCK_RETRY_ATTEMPTS: u32 = 3;

/// Backoff bounds between deadlock retries. Jittered so two replicas (or two
/// test processes) that deadlocked against each other do not re-collide in
/// lockstep on the retry.
const DEADLOCK_RETRY_BACKOFF_MS: std::ops::RangeInclusive<u64> = 50..=200;

/// Run `op`, retrying it on Postgres' `40P01 deadlock detected` up to
/// [`DEADLOCK_RETRY_ATTEMPTS`] times with a jittered backoff (#4004).
///
/// Postgres resolves a lock cycle by aborting one participant, so the loser
/// gets a plain error for work that is perfectly valid — a repository delete
/// racing the storage-stats rebuild returned a 500, and the same race failed
/// CI. Consistent lock ordering is the real fix and is applied at both sites;
/// this is the backstop for any cycle that ordering does not cover, including
/// the ones introduced by future callers.
///
/// `op` MUST be a whole transaction, not a fragment of one: a deadlocked
/// transaction is already rolled back by the server, so retrying anything less
/// than the entire unit would run against an aborted transaction. Every
/// current caller passes an idempotent unit (a single `DELETE`, a full
/// materialized-view rebuild), which is what makes re-running it safe.
pub(crate) async fn retry_on_deadlock<T, E, F, Fut>(
    what: &str,
    mut op: F,
) -> std::result::Result<T, E>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = std::result::Result<T, E>>,
    E: DeadlockError + std::fmt::Display,
{
    for attempt in 1..DEADLOCK_RETRY_ATTEMPTS {
        match op().await {
            Ok(value) => return Ok(value),
            Err(e) if e.is_deadlock() => {
                let backoff =
                    Duration::from_millis(rand::rng().random_range(DEADLOCK_RETRY_BACKOFF_MS));
                tracing::warn!(
                    "{}: deadlock detected (40P01) on attempt {}/{}, retrying in {}ms: {}",
                    what,
                    attempt,
                    DEADLOCK_RETRY_ATTEMPTS,
                    backoff.as_millis(),
                    e
                );
                tokio::time::sleep(backoff).await;
            }
            Err(e) => return Err(e),
        }
    }
    // Last attempt: whatever it returns is the answer, deadlock or not.
    op().await
}

#[cfg(ak_test_shard = "services-2")]
#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::{is_deadlock, AppError};
    use std::sync::atomic::{AtomicU32, Ordering};
    use uuid::Uuid;

    /// Provoke a real `40P01` and hand back the `sqlx::Error` Postgres raised.
    ///
    /// Two transactions, two rows, opposite order — the minimal shape of the
    /// cycle #4004 hit in the wild. Both rows are this test's own fixture
    /// repositories, so nothing else in the shared database is touched.
    async fn provoke_deadlock(pool: &PgPool) -> sqlx::Error {
        async fn seed(pool: &PgPool) -> Uuid {
            let id = Uuid::new_v4();
            let key = format!("deadlock-4004-{}", &id.to_string()[..8]);
            sqlx::query(
                "INSERT INTO repositories (id, key, name, format, repo_type, storage_path) \
                 VALUES ($1, $2, $2, 'generic'::repository_format, \
                         'local'::repository_type, $3)",
            )
            .bind(id)
            .bind(&key)
            .bind(format!("/data/{key}"))
            .execute(pool)
            .await
            .expect("seed fixture repository");
            id
        }
        let (left, right) = (seed(pool).await, seed(pool).await);

        async fn touch(
            tx: &mut sqlx::PgConnection,
            id: Uuid,
        ) -> std::result::Result<(), sqlx::Error> {
            sqlx::query("UPDATE repositories SET description = 'x' WHERE id = $1")
                .bind(id)
                .execute(tx)
                .await
                .map(|_| ())
        }

        let mut a = pool.begin().await.expect("begin a");
        let mut b = pool.begin().await.expect("begin b");
        touch(&mut a, left).await.expect("a takes left");
        touch(&mut b, right).await.expect("b takes right");

        // Each now reaches for the row the other holds. Exactly one is chosen
        // as the deadlock victim; whichever it is, its error is what we want.
        let (ra, rb) = tokio::join!(touch(&mut a, right), touch(&mut b, left));
        let _ = a.rollback().await;
        let _ = b.rollback().await;
        for id in [left, right] {
            let _ = sqlx::query("DELETE FROM repositories WHERE id = $1")
                .bind(id)
                .execute(pool)
                .await;
        }
        match (ra, rb) {
            (Err(e), _) | (_, Err(e)) => e,
            (Ok(()), Ok(())) => panic!("the two transactions did not deadlock"),
        }
    }

    /// #5168: a real `40P01` that reaches a client, past any retry, answers a
    /// retryable 503 with Retry-After in both the typed and stringified forms.
    #[tokio::test]
    async fn real_deadlock_answers_503_with_retry_after_5168() {
        use axum::http::{header, StatusCode};
        use axum::response::IntoResponse;
        let Some(pool) = crate::testing::try_pool_with(4).await else {
            return;
        };
        let err = provoke_deadlock(&pool).await;
        let flattened = AppError::Database(err.to_string());
        for response in [
            AppError::Sqlx(err).into_response(),
            flattened.into_response(),
        ] {
            assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
            assert!(response.headers().contains_key(header::RETRY_AFTER));
        }
    }

    /// #4004: a real `40P01` is classified as retryable in both the typed and
    /// the already-stringified form, and [`retry_on_deadlock`] re-runs the
    /// loser a bounded number of times.
    #[tokio::test]
    async fn deadlocks_are_classified_and_retried_a_bounded_number_of_times_4004() {
        let Some(pool) = crate::testing::try_pool_with(4).await else {
            return;
        };
        let err = provoke_deadlock(&pool).await;
        assert!(
            is_deadlock(&err),
            "a real 40P01 must be recognised, got: {err:?}"
        );
        let message = err.to_string();
        assert!(
            AppError::Sqlx(err).is_deadlock(),
            "the typed AppError arm must recognise it"
        );
        assert!(
            AppError::Database(message.clone()).is_deadlock(),
            "the stringified arm must recognise it too, since most call sites \
             flatten DB errors to Database(e.to_string()): {message}"
        );

        // A loser that succeeds on its second run is retried, not surfaced.
        let attempts = AtomicU32::new(0);
        let outcome: std::result::Result<u32, AppError> = retry_on_deadlock("test", || async {
            let n = attempts.fetch_add(1, Ordering::SeqCst) + 1;
            if n == 1 {
                Err(AppError::Database(message.clone()))
            } else {
                Ok(n)
            }
        })
        .await;
        assert_eq!(outcome.expect("second attempt succeeds"), 2);
        assert_eq!(attempts.load(Ordering::SeqCst), 2);

        // A cycle that never clears is surfaced after a bounded number of
        // attempts rather than retried forever.
        let attempts = AtomicU32::new(0);
        let outcome: std::result::Result<(), AppError> = retry_on_deadlock("test", || async {
            attempts.fetch_add(1, Ordering::SeqCst);
            Err(AppError::Database(message.clone()))
        })
        .await;
        assert!(outcome.is_err(), "a persistent deadlock must surface");
        assert_eq!(
            attempts.load(Ordering::SeqCst),
            DEADLOCK_RETRY_ATTEMPTS,
            "exactly {DEADLOCK_RETRY_ATTEMPTS} attempts, no more"
        );

        // Anything that is not a deadlock is returned on the first attempt.
        let attempts = AtomicU32::new(0);
        let outcome: std::result::Result<(), AppError> = retry_on_deadlock("test", || async {
            attempts.fetch_add(1, Ordering::SeqCst);
            Err(AppError::NotFound("nope".into()))
        })
        .await;
        assert!(outcome.is_err());
        assert_eq!(attempts.load(Ordering::SeqCst), 1);
    }

    /// #4549: the startup backoff doubles from 1 s to an 8 s cap and jitters
    /// inside ±50%, so replicas that restart together do not retry in
    /// lockstep and the retry window stays bounded.
    #[test]
    fn startup_connect_backoff_doubles_caps_and_jitters_4549() {
        let mut saw_spread = false;
        for failed in 1..=6_u32 {
            let base_ms = 1_000_u64 << failed.saturating_sub(1).min(3);
            let mut first = None;
            for _ in 0..32 {
                let ms = startup_connect_backoff(failed).as_millis() as u64;
                assert!(
                    (base_ms / 2..=base_ms + base_ms / 2).contains(&ms),
                    "{failed} failed attempts: {ms}ms outside [{}, {}]",
                    base_ms / 2,
                    base_ms + base_ms / 2
                );
                match first {
                    None => first = Some(ms),
                    Some(seen) => saw_spread |= seen != ms,
                }
            }
        }
        // Jitter is load-bearing (lockstep retries), not decoration.
        assert!(saw_spread, "32 samples per delay must not all be identical");
        // Past the fourth failure the cap holds: attempts 4..=6 use the same
        // 8 s ceiling rather than growing without bound.
        for failed in [4_u32, 5, 6, 50] {
            let ms = startup_connect_backoff(failed).as_millis() as u64;
            assert!(
                (4_000..=12_000).contains(&ms),
                "{failed} failed attempts must cap at 8s +/-50%, got {ms}ms"
            );
        }
    }

    /// #4549: the sentence attached to a startup connect failure names what
    /// this replica opens and the arithmetic that must fit under the server's
    /// `max_connections`, so the log line alone is enough to size the fleet.
    #[test]
    fn connection_budget_names_the_pool_and_the_formula_4549() {
        let config = Config {
            database_max_connections: 20,
            database_acquire_timeout_secs: 7,
            ..Config::default()
        };
        let budget = connection_budget(&config);
        for needle in [
            "DATABASE_MAX_CONNECTIONS=20",
            "DATABASE_ACQUIRE_TIMEOUT_SECS=7",
            "PROXY_SINGLEFLIGHT_MAX_LOCK_WAITERS",
            "max_connections",
            "surge",
            ".env.example",
        ] {
            assert!(
                budget.contains(needle),
                "the budget must name {needle:?}: {budget}"
            );
        }
    }

    /// #4549: the initial connect is retried a bounded number of times, every
    /// failure counts toward the startup-stage metric, and a database that
    /// never answers surfaces the last error instead of hanging — the shape
    /// that used to put a replacement pod into CrashLoopBackOff on the first
    /// `PoolTimedOut`.
    #[tokio::test(start_paused = true)]
    async fn startup_connect_retries_a_bounded_number_of_times_4549() {
        use metrics_util::debugging::{DebugValue, DebuggingRecorder, Snapshotter};

        let recorder = DebuggingRecorder::new();
        let snapshotter = recorder.snapshotter();
        let _guard = metrics::set_default_local_recorder(&recorder);

        // Read the counter once at the end: a `DebuggingRecorder` snapshot
        // *resets* counters on read (`swap(0)`), so a mid-test read would
        // return only the increment since the previous read.
        fn startup_failures(snapshotter: &Snapshotter) -> u64 {
            snapshotter
                .snapshot()
                .into_vec()
                .into_iter()
                .find(|(key, ..)| key.key().name() == "ak_db_pool_connection_failures_total")
                .map(|(.., value)| match value {
                    DebugValue::Counter(n) => n,
                    other => panic!("expected a counter, got {other:?}"),
                })
                .unwrap_or(0)
        }

        // Two transient refusals, then success: retried, each failure counted
        // exactly once, and the value handed back untouched.
        let mut calls = 0_u32;
        let outcome: std::result::Result<u32, sqlx::Error> = retry_initial_connect(
            "budget",
            STARTUP_CONNECT_ATTEMPTS,
            STARTUP_CONNECT_DEADLINE,
            || {
                calls += 1;
                let n = calls;
                async move {
                    if n <= 2 {
                        Err(sqlx::Error::PoolTimedOut)
                    } else {
                        Ok(n)
                    }
                }
            },
        )
        .await;
        assert_eq!(outcome.expect("the third attempt succeeds"), 3);
        assert_eq!(calls, 3);

        // A database that never comes up: exactly STARTUP_CONNECT_ATTEMPTS
        // attempts, then the underlying error — no unbounded hang, no
        // swallowed failure — and the give-up attempt counted too.
        let mut calls = 0_u32;
        let outcome: std::result::Result<u32, sqlx::Error> = retry_initial_connect(
            "budget",
            STARTUP_CONNECT_ATTEMPTS,
            STARTUP_CONNECT_DEADLINE,
            || {
                calls += 1;
                async { Err(sqlx::Error::PoolTimedOut) }
            },
        )
        .await;
        assert!(
            matches!(outcome, Err(sqlx::Error::PoolTimedOut)),
            "the last attempt's error is what surfaces"
        );
        assert_eq!(calls, STARTUP_CONNECT_ATTEMPTS);

        // Every failed attempt — the two interim ones and all five give-ups —
        // is counted in ak_db_pool_connection_failures_total{stage="startup"}.
        assert_eq!(
            startup_failures(&snapshotter),
            2 + u64::from(STARTUP_CONNECT_ATTEMPTS),
            "each failed attempt increments ak_db_pool_connection_failures_total"
        );
    }

    /// #4828: the test above records through a local recorder, so it cannot
    /// see that in the binary the startup failures were counted before the
    /// Prometheus recorder existed and went to the no-op default. Pin the
    /// order in `main`: the recorder is installed before the pool is built.
    #[test]
    fn metrics_recorder_is_installed_before_the_startup_pool_connect_4828() {
        let main_rs = include_str!("main.rs");
        let recorder = main_rs
            .find("metrics_service::init_metrics()")
            .expect("main installs the Prometheus recorder");
        let pool = main_rs
            .find("db::create_pool(")
            .expect("main builds the database pool");
        assert!(
            recorder < pool,
            "metrics_service::init_metrics() must run before db::create_pool(), \
             or ak_db_pool_connection_failures_total{{stage=\"startup\"}} is lost"
        );
        assert_eq!(
            main_rs.matches("db::create_pool(").count(),
            1,
            "a second pool build in main must be checked against the recorder too"
        );
    }

    /// #4549: a raised `DATABASE_ACQUIRE_TIMEOUT_SECS` cannot stretch startup
    /// to minutes: no new attempt starts once the next backoff would end past
    /// [`STARTUP_CONNECT_DEADLINE`], so the process fails within about a
    /// minute plus at most one running attempt.
    #[tokio::test(start_paused = true)]
    async fn startup_connect_stops_at_the_deadline_4549() {
        let started = tokio::time::Instant::now();
        let mut calls = 0_u32;
        let outcome: std::result::Result<u32, sqlx::Error> = retry_initial_connect(
            "budget",
            STARTUP_CONNECT_ATTEMPTS,
            STARTUP_CONNECT_DEADLINE,
            || {
                calls += 1;
                async {
                    // An attempt bounded by a 30 s acquire timeout.
                    tokio::time::sleep(Duration::from_secs(30)).await;
                    Err(sqlx::Error::PoolTimedOut)
                }
            },
        )
        .await;
        assert!(matches!(outcome, Err(sqlx::Error::PoolTimedOut)));
        assert_eq!(calls, 2, "30 s attempts: the third would start past 60 s");
        assert!(
            started.elapsed() < STARTUP_CONNECT_DEADLINE + Duration::from_secs(5),
            "gave up after {:?}",
            started.elapsed()
        );
    }

    /// #4549 (hardware-shaped): every connection the pool opens — a pooled one
    /// and the detached shape a single-flight lock session takes after
    /// `PoolConnection::detach` — carries the server-side TCP keepalive GUCs,
    /// so Postgres ends a force-killed pod's ghost sessions in ~30 s instead
    /// of after the OS default (~2 h). Skips on a Unix-socket test database,
    /// where Postgres ignores these settings (they read back as `0`).
    #[tokio::test]
    async fn pool_connections_arm_server_side_keepalives_4549() {
        use sqlx::Connection;

        let Some(url) = crate::testing::require_db_url() else {
            return;
        };
        // Fail-fast reachability probe (#2986): without AK_TESTS_REQUIRE_DB an
        // unreachable database skips instead of burning the startup retry
        // window; with it, this panics carrying the connect error.
        let probe = crate::testing::bounded_connect(&url).await;
        let Some(conn) = crate::testing::on_connect_result(probe) else {
            return;
        };
        conn.close().await.expect("close the probe connection");

        let config = Config {
            database_url: url,
            database_max_connections: 2,
            database_min_connections: 0,
            database_acquire_timeout_secs: 10,
            ..Config::default()
        };
        let pool = create_pool(&config)
            .await
            .expect("the probe connected, so create_pool must too");

        async fn keepalives(conn: &mut sqlx::PgConnection) -> (String, String, String) {
            sqlx::query_as(
                "SELECT current_setting('tcp_keepalives_idle'), \
                        current_setting('tcp_keepalives_interval'), \
                        current_setting('tcp_keepalives_count')",
            )
            .fetch_one(conn)
            .await
            .expect("read the session keepalive settings")
        }

        let expected = (
            TCP_KEEPALIVES.0.to_string(),
            TCP_KEEPALIVES.1.to_string(),
            TCP_KEEPALIVES.2.to_string(),
        );
        let mut pooled = pool.acquire().await.expect("acquire a pooled connection");
        let tcp: bool = sqlx::query_scalar("SELECT inet_client_addr() IS NOT NULL")
            .fetch_one(&mut *pooled)
            .await
            .expect("transport");
        if !tcp {
            pool.close().await;
            return; // keepalives do not apply to a Unix socket
        }
        assert_eq!(
            keepalives(&mut pooled).await,
            expected,
            "a pooled connection must carry the keepalives armed by after_connect"
        );
        let mut detached = pooled.detach();
        assert_eq!(
            keepalives(&mut detached).await,
            expected,
            "a detached connection is the same session and keeps them"
        );
        drop(detached);
        pool.close().await;
    }

    /// #4549: `DATABASE_TCP_KEEPALIVES=false` skips the `after_connect` hook,
    /// so a deployment behind a pooler that mishandles session settings can
    /// turn it off. Skips on a Unix socket, like the test above.
    #[tokio::test]
    async fn pool_keepalive_hook_is_skipped_when_disabled_4549() {
        let Some(url) = crate::testing::require_db_url() else {
            return;
        };
        let probe = crate::testing::bounded_connect(&url).await;
        let Some(conn) = crate::testing::on_connect_result(probe) else {
            return;
        };
        sqlx::Connection::close(conn)
            .await
            .expect("close the probe connection");

        let config = Config {
            database_url: url,
            database_max_connections: 1,
            database_min_connections: 0,
            database_acquire_timeout_secs: 10,
            database_tcp_keepalives: false,
            ..Config::default()
        };
        let pool = create_pool(&config)
            .await
            .expect("the probe connected, so create_pool must too");
        let mut conn = pool.acquire().await.expect("acquire a pooled connection");
        let (tcp, idle, source): (bool, String, String) = sqlx::query_as(
            "SELECT inet_client_addr() IS NOT NULL, current_setting('tcp_keepalives_idle'), \
                    (SELECT source FROM pg_settings WHERE name = 'tcp_keepalives_idle')",
        )
        .fetch_one(&mut *conn)
        .await
        .expect("read the session keepalive setting");
        drop(conn);
        pool.close().await;
        if !tcp {
            return;
        }
        assert_ne!(
            source, "session",
            "with the hook disabled nothing sets tcp_keepalives_idle (now {idle})"
        );
    }
}
