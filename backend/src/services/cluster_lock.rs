//! Cross-replica single-flight lock for pull-through cache hydration (#1609).
//!
//! The per-process single-flight coordinator ([`crate::services::proxy_hydration`])
//! elects one leader *inside a single pod*. Across N replicas up to N leaders can
//! still cold-fetch the same `(repo, path)` into the shared storage backend at
//! once, flapping the object's ETag under readers (`Stale file handle`) and
//! re-writing the `.sha1` sidecar mid-read (`ChecksumFormatError`) — see #1606.
//!
//! This module adds a tiny lock seam so the hydration coordinator can collapse
//! the herd *cluster-wide* to exactly one writer per cold key. The real
//! implementation is a PostgreSQL session advisory lock held on a **detached**
//! connection so it auto-releases on connection death (crash/cancel/pod-kill)
//! without leaking a lock back into the pool. An in-memory implementation backs
//! the unit tests so the coordinator is exercisable without a live database.

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use sqlx::PgPool;

use crate::error::Result;

/// Dedicated advisory-lock namespace (`classid`) for proxy cache hydration.
///
/// PostgreSQL's two-argument advisory locks `(classid int4, objid int4)` occupy
/// a key space **separate** from the single-argument `bigint` form used elsewhere
/// in the codebase (`main.rs` `hashtext('admin_password_init')`,
/// `scheduler_service.rs` `STUCK_SCAN_LOCK_ID`), so a lock in this class can never
/// collide with those. `objid` is a deterministic hash of the lease key
/// ([`lease_object_id`]).
pub const PROXY_HYDRATION_LOCK_CLASS: i32 = 0x1609;

/// Derive the advisory-lock `objid` for a hydration lease key.
///
/// Uses FNV-1a (32-bit) so the mapping is byte-stable and identical on every
/// replica running the same binary — the property that makes the lock serialize a
/// single `(repo, path)` cold fetch cluster-wide. It deliberately does NOT depend
/// on Postgres `hashtext`, avoiding a DB round-trip and any server-version
/// coupling; Postgres treats the two `int4`s purely as an opaque lock identity.
pub fn lease_object_id(lease_key: &str) -> i32 {
    let mut hash: u32 = 0x811c_9dc5;
    for byte in lease_key.as_bytes() {
        hash ^= u32::from(*byte);
        hash = hash.wrapping_mul(0x0100_0193);
    }
    hash as i32
}

/// A held cross-replica lock.
///
/// Dropping the guard releases the lock (crash-safe path); [`ClusterLease::release`]
/// releases it eagerly on the happy path.
pub enum ClusterLease {
    /// A real PostgreSQL session advisory lock held on a DETACHED connection.
    Postgres(PgAdvisoryLease),
    /// An in-memory lock used by unit tests (no database).
    #[cfg(test)]
    InMemory(InMemoryLease),
}

impl ClusterLease {
    /// Eagerly release the lock on the happy path. For the Postgres lease this
    /// issues `pg_advisory_unlock` and then closes the detached connection; for
    /// the in-memory lease it drops the guard (which frees the key). If this is
    /// never called (panic / cancel / pod-kill), `Drop` still releases the lock.
    pub async fn release(self) {
        match self {
            ClusterLease::Postgres(lease) => lease.release().await,
            #[cfg(test)]
            ClusterLease::InMemory(lease) => drop(lease),
        }
    }
}

/// Cross-replica advisory-lock seam.
///
/// Behind a trait so the hydration decorator is unit-testable with an in-memory
/// lock (no live Postgres, matching the Tier-1 `--lib` CI profile). The real
/// implementation is [`PgAdvisoryLock`].
#[async_trait]
pub trait ClusterLock: Send + Sync {
    /// Try to acquire `(class, obj)` WITHOUT blocking.
    ///
    /// * `Ok(Some(_))` — acquired; the caller is the cluster leader.
    /// * `Ok(None)` — already held by another replica; the caller is a follower.
    /// * `Err(_)` — lock infrastructure failure; the caller degrades to
    ///   per-process coordination (no worse than the pre-#1609 behavior).
    async fn try_acquire(&self, class: i32, obj: i32) -> Result<Option<ClusterLease>>;

    /// Acquire `(class, obj)`, BLOCKING for at most `timeout` while another
    /// replica holds it (#4013).
    ///
    /// * `Ok(Some(_))` — acquired. For a waiter this is the wake-up signal: the
    ///   previous holder released, which the streaming leader does only after
    ///   its cache publish, so the object is now readable from the cache.
    /// * `Ok(None)` — `timeout` elapsed with the lock still held elsewhere.
    /// * `Err(_)` — lock infrastructure failure.
    ///
    /// The provided body polls [`Self::try_acquire`] every
    /// [`BLOCKING_ACQUIRE_POLL`]; it backs the in-memory test locks. The
    /// Postgres implementation overrides it with a server-side wait that wakes
    /// at the holder's release.
    async fn acquire_blocking(
        &self,
        class: i32,
        obj: i32,
        timeout: Duration,
    ) -> Result<Option<ClusterLease>> {
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            if let Some(lease) = self.try_acquire(class, obj).await? {
                return Ok(Some(lease));
            }
            let now = tokio::time::Instant::now();
            if now >= deadline {
                return Ok(None);
            }
            tokio::time::sleep(BLOCKING_ACQUIRE_POLL.min(deadline - now)).await;
        }
    }
}

/// Poll cadence of the provided [`ClusterLock::acquire_blocking`] body.
pub const BLOCKING_ACQUIRE_POLL: Duration = Duration::from_millis(5);

/// Arm [`crate::db::TCP_KEEPALIVES`] on a dedicated lock session.
///
/// The values are shared with the pool (#4549), one source of truth for the
/// ~30 s dead-peer reclaim, so a lock session can never diverge from the
/// connections around it. When a replica's node disappears (force-deleted
/// pod, node loss) its sockets close silently — no FIN, no RST — and
/// Postgres keeps the dead session, and the advisory lock it holds, until the
/// kernel's default keepalive gives up (about two hours on Linux). With
/// these the server declares the peer dead after about
/// `idle + interval * count` = 30 s and ends the session, which releases the
/// lock and wakes the waiters on the other replicas. Since #4549 the pool
/// arms them at connect time too; the explicit re-arm here keeps #4013's
/// guarantee independent of how the session was obtained (tests build pools
/// without the pool's connect options), so a stale lock can never outlive a
/// stale connection.
///
/// Best-effort: a Unix-socket session ignores them and a failure only keeps
/// the server's defaults, so errors are not surfaced.
async fn arm_dead_peer_keepalives(conn: &mut sqlx::PgConnection) {
    let _ = crate::db::arm_tcp_keepalives(conn).await;
}

/// How often the server checks that a blocked waiter's client is still
/// connected (`client_connection_check_interval`, PG 14+), so a cancelled wait
/// frees its backend within about this long instead of after `lock_timeout`.
const CLIENT_CONNECTION_CHECK_INTERVAL: &str = "1s";

/// Postgres `lock_timeout` value for a blocking advisory wait of `timeout`.
///
/// `lock_timeout = 0` means "wait forever" in Postgres, so a zero (or sub-ms)
/// timeout is rounded UP to 1 ms rather than silently becoming unbounded.
fn lock_timeout_setting(timeout: Duration) -> String {
    let ms = timeout.as_millis().clamp(1, i32::MAX as u128);
    format!("{ms}ms")
}

/// `true` when `err` ended a lock wait because time ran out: `lock_timeout`
/// (SQLSTATE 55P03 `lock_not_available`), or a role/database
/// `statement_timeout` shorter than it (57014 `query_canceled`). Either way the
/// holder is still working and the waiter should fetch on its own; neither is
/// a lock-infrastructure failure.
fn is_wait_expired(err: &sqlx::Error) -> bool {
    err.as_database_error()
        .and_then(|db| db.code())
        .is_some_and(|code| is_wait_expiry_code(&code))
}

fn is_wait_expiry_code(code: &str) -> bool {
    matches!(code, "55P03" | "57014")
}

/// Real PostgreSQL advisory-lock implementation (#1609).
#[derive(Clone)]
pub struct PgAdvisoryLock {
    pool: PgPool,
    /// Bounds how many lock connections exist outside `pool` at once: the
    /// detached leader connection and the dedicated wait session (#4552).
    /// Neither counts against `pool`, which keeps opening its own, so without
    /// this one lock per in-flight hydration can open an unbounded number of
    /// server connections.
    detached: Arc<tokio::sync::Semaphore>,
}

/// Default cap on detached lock connections per [`PgAdvisoryLock`], for the
/// background-job call sites that build one per operation. The proxy hydration
/// coordinator keeps a long-lived shared lock instead and derives its own cap
/// from `PROXY_SINGLEFLIGHT_MAX_LOCK_WAITERS`, which is the only path where a
/// request storm can produce many concurrent leases.
pub const DEFAULT_LOCK_MAX_CONNECTIONS: usize = 16;

impl PgAdvisoryLock {
    pub fn new(pool: PgPool) -> Self {
        Self::with_max_connections(pool, DEFAULT_LOCK_MAX_CONNECTIONS)
    }

    pub fn with_max_connections(pool: PgPool, max: usize) -> Self {
        Self {
            pool,
            detached: Arc::new(tokio::sync::Semaphore::new(max.max(1))),
        }
    }

    /// A full cap is an error, which every caller degrades to per-process
    /// single-flight rather than opening another connection.
    fn detach_permit(&self) -> Result<tokio::sync::OwnedSemaphorePermit> {
        self.detached.clone().try_acquire_owned().map_err(|_| {
            crate::error::AppError::ServiceUnavailable(
                "advisory lock connection cap reached".to_string(),
            )
        })
    }

    /// Open the dedicated session a blocking wait runs on (#4552): the pool's
    /// connect options with sqlx's slow-statement logging turned off, bounded
    /// by the pool's acquire timeout. It never belongs to the pool, so it
    /// closes on drop exactly like the detached connection it replaces.
    async fn connect_wait_session(&self) -> Result<sqlx::PgConnection> {
        use sqlx::Connection;
        let options = wait_session_options(&self.pool.connect_options());
        match tokio::time::timeout(
            self.pool.options().get_acquire_timeout(),
            sqlx::PgConnection::connect_with(&options),
        )
        .await
        {
            Ok(conn) => Ok(conn?),
            Err(_) => Err(sqlx::Error::PoolTimedOut.into()),
        }
    }
}

/// Connect options for a blocking advisory-lock wait session (#4552): the
/// pool's options with slow-statement logging off, since the lock statement is
/// expected to block for as long as the leader's fill takes.
fn wait_session_options(
    pool_options: &sqlx::postgres::PgConnectOptions,
) -> sqlx::postgres::PgConnectOptions {
    use sqlx::ConnectOptions;
    pool_options
        .clone()
        .log_slow_statements(tracing::log::LevelFilter::Off, Duration::MAX)
}

#[async_trait]
impl ClusterLock for PgAdvisoryLock {
    async fn try_acquire(&self, class: i32, obj: i32) -> Result<Option<ClusterLease>> {
        // Acquire a pooled connection just long enough to attempt the lock. Use
        // a RUNTIME query (not the `query!` macro) so no `cargo sqlx prepare`
        // offline metadata is required (avoids the known Check-Rust CI gap).
        let mut conn = self.pool.acquire().await?;
        let acquired: bool = sqlx::query_scalar("SELECT pg_try_advisory_lock($1, $2)")
            .bind(class)
            .bind(obj)
            .fetch_one(&mut *conn)
            .await?;
        if !acquired {
            // Loser: no lock is held, so returning this connection to the pool
            // is safe. (A *pooled* session lock would survive return-to-pool and
            // poison the key — which is exactly why the winner detaches below.)
            return Ok(None);
        }
        // Winner: DETACH the connection so the SESSION lock is tied to a
        // connection we own outright. On the happy path `release` unlocks and
        // drops it; on panic/cancel/pod-kill the guard drops, the detached
        // connection CLOSES, and Postgres releases the session lock (crash-safe).
        let permit = match self.detach_permit() {
            Ok(p) => p,
            Err(e) => {
                let _ = sqlx::query("SELECT pg_advisory_unlock($1, $2)")
                    .bind(class)
                    .bind(obj)
                    .execute(&mut *conn)
                    .await;
                return Err(e);
            }
        };
        let mut detached = conn.detach();
        arm_dead_peer_keepalives(&mut detached).await;
        Ok(Some(ClusterLease::Postgres(PgAdvisoryLease {
            conn: Some(detached),
            class,
            obj,
            _permit: permit,
        })))
    }

    async fn acquire_blocking(
        &self,
        class: i32,
        obj: i32,
        timeout: Duration,
    ) -> Result<Option<ClusterLease>> {
        // DETACH before the blocking statement, not after it: if this future
        // is cancelled mid-wait (client gone) a pooled connection would go back
        // to the pool while Postgres may still grant it the session lock, which
        // would then poison the key for every replica. A detached connection
        // simply closes on drop, and the server drops the wait (or the lock)
        // with it. It also means the session-level `lock_timeout` below never
        // leaks into a pooled connection.
        //
        // #4552: the session is opened from the pool's own connect options
        // (same server, credentials, TLS and startup options) rather than
        // acquired and detached, because sqlx fixes a connection's
        // slow-statement logging at connect time. The wait below is SUPPOSED
        // to take as long as the leader's fill; at sqlx's default 1 s
        // threshold every follower logged a "slow statement" WARN per cold
        // object. The outcome is logged once at DEBUG instead.
        let permit = self.detach_permit()?;
        let mut conn = self.connect_wait_session().await?;
        sqlx::query("SELECT set_config('lock_timeout', $1, false)")
            .bind(lock_timeout_setting(timeout))
            .execute(&mut conn)
            .await?;
        // A backend asleep in a lock wait does not notice that its client went
        // away: without this a cancelled wait (client gone, ingress timeout)
        // keeps a server connection and its place in the lock queue until the
        // lock is granted or `lock_timeout` fires. PG 14+ polls the socket at
        // this interval and ends the wait. Best-effort: older servers reject
        // the setting and simply keep the pre-14 behaviour.
        let _ = sqlx::query("SELECT set_config('client_connection_check_interval', $1, false)")
            .bind(CLIENT_CONNECTION_CHECK_INTERVAL)
            .execute(&mut conn)
            .await;
        // A waiter that is granted the lock holds it until it releases; if its
        // node died meanwhile, only keepalives free it.
        arm_dead_peer_keepalives(&mut conn).await;
        let started = std::time::Instant::now();
        let outcome = sqlx::query("SELECT pg_advisory_lock($1, $2)")
            .bind(class)
            .bind(obj)
            .execute(&mut conn)
            .await;
        let waited_secs = started.elapsed().as_secs_f64();
        match outcome {
            Ok(_) => {
                tracing::debug!(
                    class,
                    obj,
                    waited_secs,
                    "cluster lock: advisory-lock wait ended, lock acquired"
                );
                Ok(Some(ClusterLease::Postgres(PgAdvisoryLease {
                    conn: Some(conn),
                    class,
                    obj,
                    _permit: permit,
                })))
            }
            // The holder is still working after `timeout`: not an error, the
            // caller falls back to fetching on its own. `conn` closes here.
            Err(e) if is_wait_expired(&e) => {
                tracing::debug!(
                    class,
                    obj,
                    waited_secs,
                    "cluster lock: advisory-lock wait expired while still held"
                );
                Ok(None)
            }
            Err(e) => Err(e.into()),
        }
    }
}

/// RAII guard for a held Postgres session advisory lock (#1609).
///
/// Owns the detached connection acquired by [`PgAdvisoryLock::try_acquire`]. No
/// explicit `Drop` impl is needed for the crash path: dropping the guard drops
/// the owned [`sqlx::PgConnection`], which closes it, and Postgres releases every
/// session lock held by that backend on disconnect.
pub struct PgAdvisoryLease {
    conn: Option<sqlx::PgConnection>,
    class: i32,
    obj: i32,
    _permit: tokio::sync::OwnedSemaphorePermit,
}

impl PgAdvisoryLease {
    async fn release(mut self) {
        if let Some(mut conn) = self.conn.take() {
            // Best-effort explicit unlock; if it fails, dropping the detached
            // connection below still releases the session lock on close.
            let _ = sqlx::query("SELECT pg_advisory_unlock($1, $2)")
                .bind(self.class)
                .bind(self.obj)
                .execute(&mut conn)
                .await;
            // `conn` drops here (detached => closed, never returned to the pool).
        }
    }
}

/// In-memory [`ClusterLock`] for unit tests: a shared set of held `(class, obj)`
/// keys so several simulated "replicas" (each wrapping this one lock) can contend
/// on ONE lock with no database.
#[cfg(test)]
#[derive(Clone, Default)]
pub struct InMemoryClusterLock {
    held: std::sync::Arc<std::sync::Mutex<std::collections::HashSet<(i32, i32)>>>,
}

#[cfg(test)]
#[async_trait]
impl ClusterLock for InMemoryClusterLock {
    async fn try_acquire(&self, class: i32, obj: i32) -> Result<Option<ClusterLease>> {
        let mut held = self.held.lock().unwrap_or_else(|p| p.into_inner());
        if held.contains(&(class, obj)) {
            return Ok(None);
        }
        held.insert((class, obj));
        Ok(Some(ClusterLease::InMemory(InMemoryLease {
            held: std::sync::Arc::clone(&self.held),
            key: (class, obj),
        })))
    }
}

/// A [`ClusterLock`] that always fails to acquire, for exercising the
/// coordinator's "lock infrastructure unavailable → degrade to per-process
/// single-flight" path in unit tests.
#[cfg(test)]
#[derive(Clone, Default)]
pub struct ErroringClusterLock;

#[cfg(test)]
#[async_trait]
impl ClusterLock for ErroringClusterLock {
    async fn try_acquire(&self, _class: i32, _obj: i32) -> Result<Option<ClusterLease>> {
        Err(simulated_lock_failure())
    }
}

#[cfg(test)]
fn simulated_lock_failure() -> crate::error::AppError {
    crate::error::AppError::Database("simulated cluster-lock backend failure".to_string())
}

/// A [`ClusterLock`] whose `try_acquire` always LOSES (another replica holds the
/// key) but whose blocking wait fails, for exercising the coordinator's
/// "lock lost, then the wait itself errors" path in unit tests.
#[cfg(test)]
#[derive(Clone, Default)]
pub struct LosingThenErroringClusterLock;

#[cfg(test)]
#[async_trait]
impl ClusterLock for LosingThenErroringClusterLock {
    async fn try_acquire(&self, _class: i32, _obj: i32) -> Result<Option<ClusterLease>> {
        Ok(None)
    }

    async fn acquire_blocking(
        &self,
        _class: i32,
        _obj: i32,
        _timeout: Duration,
    ) -> Result<Option<ClusterLease>> {
        Err(simulated_lock_failure())
    }
}

/// Guard for [`InMemoryClusterLock`]; frees its key on drop (release OR cancel),
/// mirroring the Postgres lease's crash-safe auto-release.
#[cfg(test)]
pub struct InMemoryLease {
    held: std::sync::Arc<std::sync::Mutex<std::collections::HashSet<(i32, i32)>>>,
    key: (i32, i32),
}

#[cfg(test)]
impl Drop for InMemoryLease {
    fn drop(&mut self) {
        self.held
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .remove(&self.key);
    }
}

#[cfg(ak_test_shard = "services-1")]
#[cfg(test)]
mod tests {
    use super::*;

    /// The connection cap itself, without a database: a detached connection no
    /// longer counts against the pool, so if this were unbounded every
    /// in-flight lock would open one more server connection. At the cap the
    /// lock must refuse (degrading the caller to per-process single-flight)
    /// rather than queue or detach another, and permits must return on drop.
    #[tokio::test]
    async fn detached_lock_connections_are_capped_and_return_on_drop() {
        let pool = sqlx::postgres::PgPoolOptions::new()
            .connect_lazy("postgres://unused@127.0.0.1:1/unused")
            .expect("lazy pool");
        let lock = PgAdvisoryLock::with_max_connections(pool, 2);
        let held: Vec<_> = (0..2)
            .map(|i| {
                lock.detach_permit()
                    .unwrap_or_else(|e| panic!("permit {i}: {e}"))
            })
            .collect();
        assert!(
            matches!(
                lock.detach_permit(),
                Err(crate::error::AppError::ServiceUnavailable(_))
            ),
            "at the cap the lock must refuse, not detach another connection"
        );
        drop(held);
        assert!(
            lock.detach_permit().is_ok(),
            "permits return when a lease drops"
        );
    }

    /// A cap of zero would make the lock permanently unusable, so it floors at
    /// one: a misconfigured env var degrades to serial locking, never to a
    /// coordinator that can never acquire.
    #[tokio::test]
    async fn a_zero_cap_floors_at_one_connection() {
        let pool = sqlx::postgres::PgPoolOptions::new()
            .connect_lazy("postgres://unused@127.0.0.1:1/unused")
            .expect("lazy pool");
        let lock = PgAdvisoryLock::with_max_connections(pool, 0);
        let held = lock
            .detach_permit()
            .expect("one permit is always available");
        assert!(lock.detach_permit().is_err());
        drop(held);
    }

    #[test]
    fn lease_object_id_is_deterministic_and_key_sensitive() {
        // Same key -> same objid on every replica (the cross-replica invariant).
        assert_eq!(
            lease_object_id("proxy-cache:repo/a/b.jar"),
            lease_object_id("proxy-cache:repo/a/b.jar")
        );
        // Distinct keys almost never collide.
        assert_ne!(
            lease_object_id("proxy-cache:repo/a/b.jar"),
            lease_object_id("proxy-cache:repo/a/c.jar")
        );
    }

    #[tokio::test]
    async fn in_memory_lock_serializes_and_releases() {
        let lock = InMemoryClusterLock::default();
        let obj = lease_object_id("k");

        // First acquire wins.
        let lease = lock
            .try_acquire(PROXY_HYDRATION_LOCK_CLASS, obj)
            .await
            .expect("no error")
            .expect("acquired");
        // A second contender for the same key loses while the lease is held.
        assert!(lock
            .try_acquire(PROXY_HYDRATION_LOCK_CLASS, obj)
            .await
            .expect("no error")
            .is_none());

        // Releasing frees the key so a later contender can win.
        lease.release().await;
        let reborn = lock
            .try_acquire(PROXY_HYDRATION_LOCK_CLASS, obj)
            .await
            .expect("no error");
        assert!(reborn.is_some(), "key must be re-acquirable after release");
    }

    #[tokio::test]
    async fn in_memory_lock_releases_on_guard_drop() {
        let lock = InMemoryClusterLock::default();
        let obj = lease_object_id("drop-key");
        {
            let _lease = lock
                .try_acquire(PROXY_HYDRATION_LOCK_CLASS, obj)
                .await
                .expect("no error")
                .expect("acquired");
            // guard dropped at end of scope WITHOUT calling release()
        }
        assert!(
            lock.try_acquire(PROXY_HYDRATION_LOCK_CLASS, obj)
                .await
                .expect("no error")
                .is_some(),
            "dropping the guard must auto-release the lock"
        );
    }

    #[tokio::test]
    async fn in_memory_lock_independent_keys_do_not_contend() {
        let lock = InMemoryClusterLock::default();
        let a = lock
            .try_acquire(PROXY_HYDRATION_LOCK_CLASS, lease_object_id("a"))
            .await
            .expect("no error");
        let b = lock
            .try_acquire(PROXY_HYDRATION_LOCK_CLASS, lease_object_id("b"))
            .await
            .expect("no error");
        assert!(a.is_some() && b.is_some(), "distinct keys never contend");
    }

    /// Tier-2: the REAL Postgres advisory lock serializes two contenders on one
    /// key, releases eagerly via `release`, and — the crash-safety guarantee —
    /// releases when the detached-connection guard is simply dropped. No-ops when
    /// `DATABASE_URL` is unset (matches the rest of the DB-backed suite).
    #[tokio::test]
    async fn pg_advisory_lock_serializes_and_releases_on_drop() {
        use crate::api::handlers::test_db_helpers as tdh;
        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let lock = PgAdvisoryLock::new(pool);
        let key = format!("proxy-cache:pgtest-{}", uuid::Uuid::new_v4());
        let obj = lease_object_id(&key);

        // Leader acquires; a concurrent contender for the same key loses.
        let lease = lock
            .try_acquire(PROXY_HYDRATION_LOCK_CLASS, obj)
            .await
            .expect("query ok")
            .expect("acquired");
        assert!(
            lock.try_acquire(PROXY_HYDRATION_LOCK_CLASS, obj)
                .await
                .expect("query ok")
                .is_none(),
            "a peer must not acquire the same key while it is held"
        );

        // Explicit release frees it for the next winner.
        lease.release().await;
        let reborn = lock
            .try_acquire(PROXY_HYDRATION_LOCK_CLASS, obj)
            .await
            .expect("query ok")
            .expect("re-acquired after release");

        // Crash path: drop the guard WITHOUT release; the detached connection
        // closes and Postgres releases the session lock. Poll for re-acquire.
        drop(reborn);
        let mut freed = false;
        for _ in 0..40 {
            if let Some(guard) = lock
                .try_acquire(PROXY_HYDRATION_LOCK_CLASS, obj)
                .await
                .expect("query ok")
            {
                guard.release().await;
                freed = true;
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
        assert!(
            freed,
            "dropping the guard must release the advisory lock (connection close)"
        );
    }

    #[test]
    fn lock_timeout_setting_never_becomes_unbounded() {
        // `lock_timeout = 0` is "wait forever" in Postgres: a zero timeout
        // must round UP, never down.
        assert_eq!(lock_timeout_setting(Duration::ZERO), "1ms");
        assert_eq!(lock_timeout_setting(Duration::from_micros(300)), "1ms");
        assert_eq!(lock_timeout_setting(Duration::from_secs(65)), "65000ms");
        assert_eq!(
            lock_timeout_setting(Duration::from_secs(u64::MAX / 4)),
            format!("{}ms", i32::MAX)
        );
    }

    #[test]
    fn non_database_errors_are_not_lock_timeouts() {
        assert!(!is_wait_expired(&sqlx::Error::RowNotFound));
        assert!(!is_wait_expired(&sqlx::Error::PoolTimedOut));
    }

    #[test]
    fn statement_timeout_counts_as_an_expired_wait() {
        assert!(is_wait_expiry_code("55P03"), "lock_timeout");
        assert!(is_wait_expiry_code("57014"), "statement_timeout");
        assert!(!is_wait_expiry_code("40P01"), "deadlock is a real error");
        assert!(
            !is_wait_expiry_code("08006"),
            "connection failure is a real error"
        );
    }

    #[tokio::test]
    async fn provided_blocking_acquire_waits_for_release_then_wins() {
        let lock = InMemoryClusterLock::default();
        let obj = lease_object_id("blocking");
        let held = lock
            .try_acquire(PROXY_HYDRATION_LOCK_CLASS, obj)
            .await
            .expect("no error")
            .expect("acquired");
        let waiter = {
            let lock = lock.clone();
            tokio::spawn(async move {
                lock.acquire_blocking(PROXY_HYDRATION_LOCK_CLASS, obj, Duration::from_secs(5))
                    .await
            })
        };
        tokio::time::sleep(Duration::from_millis(30)).await;
        assert!(!waiter.is_finished(), "waiter blocks while the key is held");
        held.release().await;
        let won = waiter.await.expect("join").expect("no error");
        assert!(won.is_some(), "waiter acquires once the holder releases");
    }

    #[tokio::test]
    async fn provided_blocking_acquire_times_out_while_held() {
        let lock = InMemoryClusterLock::default();
        let obj = lease_object_id("blocking-timeout");
        let _held = lock
            .try_acquire(PROXY_HYDRATION_LOCK_CLASS, obj)
            .await
            .expect("no error")
            .expect("acquired");
        let got = lock
            .acquire_blocking(PROXY_HYDRATION_LOCK_CLASS, obj, Duration::from_millis(20))
            .await
            .expect("no error");
        assert!(
            got.is_none(),
            "timeout while held is Ok(None), not an error"
        );
    }

    #[tokio::test]
    async fn blocking_acquire_surfaces_backend_errors() {
        let err = ErroringClusterLock
            .acquire_blocking(PROXY_HYDRATION_LOCK_CLASS, 1, Duration::from_millis(5))
            .await;
        assert!(err.is_err());
        let err = LosingThenErroringClusterLock
            .acquire_blocking(PROXY_HYDRATION_LOCK_CLASS, 1, Duration::from_millis(5))
            .await;
        assert!(err.is_err());
    }

    /// Tier-2 (#4013): the REAL blocking advisory wait wakes when the holder
    /// releases, times out with `Ok(None)` (SQLSTATE 55P03 under
    /// `lock_timeout`) while it is held, and a cancelled wait never leaves a
    /// lock behind. Two separate pools stand in for two replicas.
    #[tokio::test]
    async fn pg_blocking_acquire_wakes_on_release_and_times_out() {
        use crate::api::handlers::test_db_helpers as tdh;
        let Some(pool_a) = tdh::try_pool().await else {
            return;
        };
        let Some(pool_b) = tdh::try_pool().await else {
            return;
        };
        let replica_a = PgAdvisoryLock::new(pool_a);
        let replica_b = PgAdvisoryLock::new(pool_b);
        let key = format!("proxy-cache:pgblock-{}", uuid::Uuid::new_v4());
        let obj = lease_object_id(&key);

        let held = replica_a
            .try_acquire(PROXY_HYDRATION_LOCK_CLASS, obj)
            .await
            .expect("query ok")
            .expect("acquired");

        // Timeout while held: Ok(None), not an error.
        let started = std::time::Instant::now();
        let timed_out = replica_b
            .acquire_blocking(PROXY_HYDRATION_LOCK_CLASS, obj, Duration::from_millis(150))
            .await
            .expect("lock_timeout maps to Ok(None)");
        assert!(timed_out.is_none());
        assert!(started.elapsed() >= Duration::from_millis(140));

        // A cancelled wait must not leave a lock behind once the holder goes.
        let cancelled = tokio::time::timeout(
            Duration::from_millis(50),
            replica_b.acquire_blocking(PROXY_HYDRATION_LOCK_CLASS, obj, Duration::from_secs(30)),
        )
        .await;
        assert!(cancelled.is_err(), "wait was still blocked when cancelled");

        // Wake on release.
        let waiter = tokio::spawn(async move {
            replica_b
                .acquire_blocking(PROXY_HYDRATION_LOCK_CLASS, obj, Duration::from_secs(30))
                .await
        });
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(!waiter.is_finished(), "waiter blocks while held");
        held.release().await;
        let woke = tokio::time::timeout(Duration::from_secs(5), waiter)
            .await
            .expect("waiter woke promptly after release")
            .expect("join")
            .expect("query ok")
            .expect("acquired after release");
        woke.release().await;

        // Nothing leaked: the key is free again.
        let free = replica_a
            .try_acquire(PROXY_HYDRATION_LOCK_CLASS, obj)
            .await
            .expect("query ok")
            .expect("free after the waiter released");
        free.release().await;
    }
    /// #4552: a follower's expected advisory-lock wait must not be reported
    /// as a sqlx "slow statement" WARN, however long the leader's fill takes;
    /// the outcome is logged once at DEBUG with the wait time instead.
    #[tokio::test]
    async fn pg_blocking_wait_is_not_logged_as_a_slow_statement() {
        use crate::api::handlers::test_db_helpers as tdh;
        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let lock = PgAdvisoryLock::new(pool);
        let key = format!("proxy-cache:pgslowlog-{}", uuid::Uuid::new_v4());
        let obj = lease_object_id(&key);
        let held = lock
            .try_acquire(PROXY_HYDRATION_LOCK_CLASS, obj)
            .await
            .expect("query ok")
            .expect("acquired");

        let capture = tdh::LogCapture::default();
        let _guard = capture.install(tracing::Level::TRACE);
        // Past sqlx's default 1 s slow-statement threshold, once while the
        // wait expires and once while it is granted on release.
        let expired = lock
            .acquire_blocking(
                PROXY_HYDRATION_LOCK_CLASS,
                obj,
                Duration::from_millis(1_200),
            )
            .await
            .expect("lock_timeout maps to Ok(None)");
        assert!(expired.is_none());
        let releaser = async {
            tokio::time::sleep(Duration::from_millis(1_200)).await;
            held.release().await;
        };
        let (granted, ()) = tokio::join!(
            lock.acquire_blocking(PROXY_HYDRATION_LOCK_CLASS, obj, Duration::from_secs(30)),
            releaser
        );
        granted
            .expect("query ok")
            .expect("acquired after release")
            .release()
            .await;

        let logs = capture.text();
        assert!(
            !logs.contains("slow statement"),
            "an expected advisory-lock wait must not log a slow statement:\n{logs}"
        );
        assert!(
            logs.contains("advisory-lock wait expired while still held"),
            "the expired wait is logged once at DEBUG:\n{logs}"
        );
        assert!(
            logs.contains("advisory-lock wait ended, lock acquired")
                && logs.contains("waited_secs"),
            "the granted wait is logged once at DEBUG with its duration:\n{logs}"
        );
    }

    /// #4013 review: a cancelled blocking wait must not leave a server backend
    /// queued on the lock until `lock_timeout`. With
    /// `client_connection_check_interval` the server notices the closed
    /// client and drops the waiter within about a second. PG 14+ only.
    #[tokio::test]
    async fn pg_cancelled_blocking_wait_frees_its_backend() {
        use crate::api::handlers::test_db_helpers as tdh;
        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let version: i32 = sqlx::query_scalar("SELECT current_setting('server_version_num')::int")
            .fetch_one(&pool)
            .await
            .expect("version");
        if version < 140_000 {
            return;
        }
        let lock = PgAdvisoryLock::new(pool.clone());
        let key = format!("proxy-cache:pgcancel-{}", uuid::Uuid::new_v4());
        let obj = lease_object_id(&key);
        let held = lock
            .try_acquire(PROXY_HYDRATION_LOCK_CLASS, obj)
            .await
            .expect("query ok")
            .expect("acquired");
        let waiting = || async {
            sqlx::query_scalar::<_, i64>(
                "SELECT count(*) FROM pg_locks WHERE locktype = 'advisory' \
                 AND classid::bigint = $1 AND objid::bigint = $2 AND NOT granted",
            )
            .bind(i64::from(PROXY_HYDRATION_LOCK_CLASS))
            .bind(i64::from(obj as u32))
            .fetch_one(&pool)
            .await
            .expect("pg_locks")
        };
        let cancelled = tokio::time::timeout(
            Duration::from_millis(300),
            lock.acquire_blocking(PROXY_HYDRATION_LOCK_CLASS, obj, Duration::from_secs(60)),
        )
        .await;
        assert!(
            cancelled.is_err(),
            "the wait was still blocked when cancelled"
        );
        let mut freed = false;
        for _ in 0..50 {
            if waiting().await == 0 {
                freed = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        assert!(
            freed,
            "the server must drop a cancelled waiter well before lock_timeout (60 s)"
        );
        held.release().await;
    }
    /// #4013 review: a session `statement_timeout` shorter than the wait
    /// cancels `pg_advisory_lock` with 57014. That is an expired wait
    /// (`Ok(None)`, fetch on our own), not a lock-infrastructure error.
    #[tokio::test]
    async fn pg_statement_timeout_ends_the_wait_like_lock_timeout() {
        use crate::api::handlers::test_db_helpers as tdh;
        use std::str::FromStr;
        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let url = std::env::var("DATABASE_URL").expect("try_pool implies DATABASE_URL");
        let options = sqlx::postgres::PgConnectOptions::from_str(&url)
            .expect("url")
            .options([("statement_timeout", "150")]);
        let short = sqlx::postgres::PgPoolOptions::new()
            .max_connections(2)
            .connect_with(options)
            .await
            .expect("pool with a short statement_timeout");
        let holder = PgAdvisoryLock::new(pool);
        let waiter = PgAdvisoryLock::new(short);
        let key = format!("proxy-cache:pgstmt-{}", uuid::Uuid::new_v4());
        let obj = lease_object_id(&key);
        let held = holder
            .try_acquire(PROXY_HYDRATION_LOCK_CLASS, obj)
            .await
            .expect("query ok")
            .expect("acquired");
        let started = std::time::Instant::now();
        let got = waiter
            .acquire_blocking(PROXY_HYDRATION_LOCK_CLASS, obj, Duration::from_secs(30))
            .await
            .expect("57014 maps to Ok(None), not Err");
        assert!(got.is_none());
        assert!(
            started.elapsed() < Duration::from_secs(10),
            "ended by statement_timeout, not lock_timeout"
        );
        held.release().await;
    }
    /// #4013 (hardware verification): the leader's lock-holding session and a
    /// waiter's session both carry server-side keepalives, so a replica whose
    /// node vanished is reaped in about 30 s instead of the kernel default.
    #[tokio::test]
    async fn pg_lock_sessions_carry_dead_peer_keepalives() {
        use crate::api::handlers::test_db_helpers as tdh;
        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let lock = PgAdvisoryLock::new(pool);
        let key = format!("proxy-cache:pgkeepalive-{}", uuid::Uuid::new_v4());
        let obj = lease_object_id(&key);
        let mut leases = vec![lock
            .try_acquire(PROXY_HYDRATION_LOCK_CLASS, obj)
            .await
            .expect("query ok")
            .expect("leader")];
        let other = lease_object_id(&format!("{key}-waiter"));
        leases.push(
            lock.acquire_blocking(PROXY_HYDRATION_LOCK_CLASS, other, Duration::from_secs(5))
                .await
                .expect("query ok")
                .expect("free key is granted at once"),
        );
        for lease in &mut leases {
            let ClusterLease::Postgres(lease) = lease else {
                panic!("postgres lease");
            };
            let conn = lease.conn.as_mut().expect("held connection");
            let tcp: bool = sqlx::query_scalar("SELECT inet_client_addr() IS NOT NULL")
                .fetch_one(&mut *conn)
                .await
                .expect("transport");
            if !tcp {
                continue; // keepalives do not apply to a Unix socket
            }
            let settings: (String, String, String) = sqlx::query_as(
                "SELECT current_setting('tcp_keepalives_idle'), \
                        current_setting('tcp_keepalives_interval'), \
                        current_setting('tcp_keepalives_count')",
            )
            .fetch_one(&mut *conn)
            .await
            .expect("settings");
            let (idle, interval, count) = crate::db::TCP_KEEPALIVES;
            assert_eq!(
                settings,
                (idle.to_string(), interval.to_string(), count.to_string())
            );
        }
        for lease in leases {
            lease.release().await;
        }
    }

    /// #4013 (hardware verification): when the leader's session dies (here
    /// `pg_terminate_backend`, what the keepalive reaper does to a vanished
    /// node), its lock is released and a waiter on another replica wakes at
    /// once, then wins the re-election, well inside 2 s.
    #[tokio::test]
    async fn pg_waiter_reelects_promptly_when_the_leader_session_dies() {
        use crate::api::handlers::test_db_helpers as tdh;
        let Some(pool_a) = tdh::try_pool().await else {
            return;
        };
        let Some(pool_b) = tdh::try_pool().await else {
            return;
        };
        let admin = pool_a.clone();
        let replica_a = PgAdvisoryLock::new(pool_a);
        let replica_b = PgAdvisoryLock::new(pool_b);
        let key = format!("proxy-cache:pgdeadleader-{}", uuid::Uuid::new_v4());
        let obj = lease_object_id(&key);
        let leader = replica_a
            .try_acquire(PROXY_HYDRATION_LOCK_CLASS, obj)
            .await
            .expect("query ok")
            .expect("leader");
        let waiter = tokio::spawn(async move {
            let woke = replica_b
                .acquire_blocking(PROXY_HYDRATION_LOCK_CLASS, obj, Duration::from_secs(60))
                .await;
            (replica_b, woke)
        });
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert!(
            !waiter.is_finished(),
            "waiter blocks behind the live leader"
        );

        let started = std::time::Instant::now();
        let terminated: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM (SELECT pg_terminate_backend(pid) FROM pg_locks \
             WHERE locktype = 'advisory' AND classid::bigint = $1 \
               AND objid::bigint = $2 AND granted) t",
        )
        .bind(i64::from(PROXY_HYDRATION_LOCK_CLASS))
        .bind(i64::from(obj as u32))
        .fetch_one(&admin)
        .await
        .expect("terminate the leader session");
        assert_eq!(terminated, 1, "exactly the leader's session held the lock");

        let (replica_b, woke) = tokio::time::timeout(Duration::from_secs(2), waiter)
            .await
            .expect("the waiter wakes as soon as the leader session is gone")
            .expect("join");
        let woke = woke.expect("query ok").expect("granted, not timed out");
        // The woken waiter releases and re-elects (ReElect -> re-enter); the
        // re-election finds the lock free and wins it.
        woke.release().await;
        let reelected = replica_b
            .try_acquire(PROXY_HYDRATION_LOCK_CLASS, obj)
            .await
            .expect("query ok")
            .expect("re-elected leader");
        assert!(
            started.elapsed() < Duration::from_secs(2),
            "re-election within 2 s of the leader's death, not the 60 s wait"
        );
        reelected.release().await;
        drop(leader); // its connection is already dead
    }

    /// At the cap, the lock must refuse rather than detach another connection,
    /// and the refused key must not be left locked on the server.
    #[tokio::test]
    async fn pg_advisory_lock_detached_connections_are_capped() {
        use crate::api::handlers::test_db_helpers as tdh;
        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let lock = PgAdvisoryLock::with_max_connections(pool, 1);
        let key = |k: &str| lease_object_id(&format!("cap-{k}-{}", uuid::Uuid::new_v4()));
        let held = lock
            .try_acquire(PROXY_HYDRATION_LOCK_CLASS, key("a"))
            .await
            .expect("query ok")
            .expect("acquired");
        let b = key("b");
        assert!(
            lock.try_acquire(PROXY_HYDRATION_LOCK_CLASS, b)
                .await
                .is_err(),
            "a full cap must error, not detach another connection"
        );
        assert!(lock
            .acquire_blocking(
                PROXY_HYDRATION_LOCK_CLASS,
                key("c"),
                Duration::from_millis(50)
            )
            .await
            .is_err());
        held.release().await;
        let again = lock
            .try_acquire(PROXY_HYDRATION_LOCK_CLASS, b)
            .await
            .expect("query ok")
            .expect("the refused key was not left locked");
        again.release().await;
    }
}
