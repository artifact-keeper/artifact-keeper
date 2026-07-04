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
        let detached = conn.detach();
        Ok(Some(ClusterLease::Postgres(PgAdvisoryLease {
            conn: Some(detached),
            class,
            obj,
        })))
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
        Err(crate::error::AppError::Database(
            "simulated cluster-lock backend failure".to_string(),
        ))
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
}
