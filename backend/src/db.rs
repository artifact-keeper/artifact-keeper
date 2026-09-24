//! Database connection pool setup and shared transaction retry helpers.

use crate::config::Config;
use crate::error::{DeadlockError, Result};
use rand::RngExt;
use sqlx::postgres::{PgPool, PgPoolOptions};
use std::time::Duration;

/// Connections idle longer than this run a full `SELECT 1` probe before being
/// returned by the pool. Short-idle acquires skip the probe to keep the hot
/// path free of an extra round trip.
const IDLE_LIVENESS_THRESHOLD: Duration = Duration::from_secs(30);

/// Create a new database connection pool using the connection pool settings
/// from [`Config`]. Pool sizing and timeouts are configurable via the
/// `DATABASE_MAX_CONNECTIONS`, `DATABASE_MIN_CONNECTIONS`,
/// `DATABASE_ACQUIRE_TIMEOUT_SECS`, `DATABASE_IDLE_TIMEOUT_SECS`, and
/// `DATABASE_MAX_LIFETIME_SECS` environment variables. See `.env.example`
/// for the default values.
pub async fn create_pool(config: &Config) -> Result<PgPool> {
    let pool = PgPoolOptions::new()
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
        })
        .connect(&config.database_url)
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
}
