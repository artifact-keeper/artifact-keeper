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

/// Server-side TCP keepalives for a session that holds or waits on an advisory
/// lock (#4013): idle seconds, probe interval seconds, probe count.
///
/// When a replica's node disappears (force-deleted pod, node loss) its
/// sockets close silently: no FIN, no RST. Postgres then keeps the dead
/// session, and the advisory lock it holds, until the kernel's default
/// keepalive gives up (about two hours on Linux). With these the server
/// declares the peer dead after about `idle + interval * count` = 30 s and
/// ends the session, which releases the lock and wakes the waiters on the
/// other replicas. Only the dedicated lock sessions get them, never the pool.
const LOCK_SESSION_KEEPALIVES: (&str, &str, &str) = ("15", "5", "3");

/// Arm [`LOCK_SESSION_KEEPALIVES`] on a dedicated lock session. Best-effort:
/// a Unix-socket session ignores them and a failure only keeps the server's
/// defaults, so errors are not surfaced.
async fn arm_dead_peer_keepalives(conn: &mut sqlx::PgConnection) {
    let (idle, interval, count) = LOCK_SESSION_KEEPALIVES;
    let _ = sqlx::query(
        "SELECT set_config('tcp_keepalives_idle', $1, false), \
                set_config('tcp_keepalives_interval', $2, false), \
                set_config('tcp_keepalives_count', $3, false)",
    )
    .bind(idle)
    .bind(interval)
    .bind(count)
    .execute(conn)
    .await;
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
}

impl PgAdvisoryLock {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
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
        let mut detached = conn.detach();
        arm_dead_peer_keepalives(&mut detached).await;
        Ok(Some(ClusterLease::Postgres(PgAdvisoryLease {
            conn: Some(detached),
            class,
            obj,
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
        let mut conn = self.pool.acquire().await?.detach();
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
        match sqlx::query("SELECT pg_advisory_lock($1, $2)")
            .bind(class)
            .bind(obj)
            .execute(&mut conn)
            .await
        {
            Ok(_) => Ok(Some(ClusterLease::Postgres(PgAdvisoryLease {
                conn: Some(conn),
                class,
                obj,
            }))),
            // The holder is still working after `timeout`: not an error, the
            // caller falls back to fetching on its own. `conn` closes here.
            Err(e) if is_wait_expired(&e) => Ok(None),
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
            let (idle, interval, count) = LOCK_SESSION_KEEPALIVES;
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
}
