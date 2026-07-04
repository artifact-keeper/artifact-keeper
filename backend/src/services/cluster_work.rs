//! Cluster-wide background-work claim primitives.
//!
//! Multiple backend replicas share one Postgres database. Any background job
//! that (a) selects work because it is due/pending/stale and (b) performs a
//! non-idempotent side effect (peer HTTP, SMTP, storage delete, archive write)
//! must claim that work durably in Postgres *before* the side effect, or every
//! replica performs it once per tick.
//!
//! This module holds the shared vocabulary for those claims:
//!
//! * [`WorkerIdentity`] — stable per-process owner id, for diagnostics.
//! * [`Claimed<T>`] — a row payload plus proof of ownership (`claim_token`).
//!   Side-effecting workers should accept `Claimed<Row>`, not a bare id, so
//!   an unclaimed call site does not typecheck.
//! * [`SchedulerLease`] / [`try_acquire_scheduler_lease`] — a durable lease
//!   for singleton periodic jobs, backed by the `scheduler_leases` table
//!   (migration 143).
//!
//! Coordination patterns (declare one when adding recurring work):
//!
//! | Pattern            | Use for                                            |
//! |--------------------|----------------------------------------------------|
//! | `RowClaimedQueue`  | Independent rows drained concurrently across replicas (claim CTE with `FOR UPDATE SKIP LOCKED`). |
//! | `SingletonLease`   | Exactly one replica runs a coarse periodic job ([`try_acquire_scheduler_lease`]). |
//! | `DueRun`           | A schedule produces one durable run per due time (unique `(schedule_id, scheduled_for)` row). |
//! | `StateMachineLease`| A request/finalizer owns a row through states (`state` + `state_token`, like OCI upload completion). |
//! | `IdempotentDbOnly` | Duplicate execution is acceptable; side effects are DB-only/idempotent. |
//!
//! Row-level claim SQL stays per-table (typed, reviewable) rather than
//! string-built here; see `sync_worker::claim_pending_sync_tasks` for the
//! reference `RowClaimedQueue` implementation. The random `claim_token` is
//! the correctness guard everywhere; `owner_id`/`claimed_by` is diagnostic.
//!
//! The cross-replica *advisory lock* seam (in-flight, auto-released on
//! connection death, no durable state) lives in
//! [`crate::services::cluster_lock`]; leases here are durable and survive the
//! claiming process, which is what queue-like retryable work needs.

use chrono::{DateTime, Utc};
use sqlx::PgPool;
use std::ops::Deref;
use std::sync::OnceLock;
use uuid::Uuid;

use crate::error::{AppError, Result};

// ---------------------------------------------------------------------------
// WorkerIdentity
// ---------------------------------------------------------------------------

/// Stable identity for this backend process, recorded as `claimed_by` /
/// `owner_id` on claims.
///
/// The identity is diagnostic ("which pod grabbed this row?") and enables
/// cheap lease self-renewal; it is deliberately NOT the correctness guard.
/// Two processes can never share an identity because it includes a random
/// per-boot uuid, but even a spoofed identity cannot steal work: finalize /
/// release paths match on the random `claim_token`.
pub struct WorkerIdentity {
    id: String,
}

impl WorkerIdentity {
    /// The process-wide identity: `<host>:<pid>:<boot-uuid>`.
    ///
    /// `<host>` prefers `POD_NAME` (set by the Helm chart's downward API),
    /// then `HOSTNAME`, then a literal fallback.
    pub fn for_process() -> &'static WorkerIdentity {
        static IDENTITY: OnceLock<WorkerIdentity> = OnceLock::new();
        IDENTITY.get_or_init(|| WorkerIdentity {
            id: Self::compose(
                std::env::var("POD_NAME")
                    .or_else(|_| std::env::var("HOSTNAME"))
                    .ok()
                    .as_deref(),
                std::process::id(),
                Uuid::new_v4(),
            ),
        })
    }

    /// Pure composition helper, split out so unit tests can pin the format
    /// without touching process globals.
    fn compose(host: Option<&str>, pid: u32, boot: Uuid) -> String {
        let host = match host {
            Some(h) if !h.is_empty() => h,
            _ => "unknown-host",
        };
        format!("{host}:{pid}:{boot}")
    }

    pub fn as_str(&self) -> &str {
        &self.id
    }
}

// ---------------------------------------------------------------------------
// Claimed<T>
// ---------------------------------------------------------------------------

/// A work row this process owns, carrying the proof of ownership.
///
/// Constructed only by table-specific claim statements (`UPDATE ... RETURNING`
/// over `FOR UPDATE SKIP LOCKED` candidates, or `INSERT ... ON CONFLICT ...
/// RETURNING`). Workers that perform external side effects should take
/// `Claimed<Row>` instead of a row/id so unclaimed call sites fail to compile.
///
/// Every success/failure finalizer for a claimed row must predicate on the
/// token (`... AND claim_token = $n AND status = 'in_progress'`) so a worker
/// whose claim expired and was re-claimed elsewhere cannot clobber the new
/// owner's state.
#[derive(Debug)]
pub struct Claimed<T> {
    row: T,
    claim_token: Uuid,
    claimed_by: String,
    claim_expires_at: DateTime<Utc>,
}

impl<T> Claimed<T> {
    /// Wrap a row returned by a claim statement. Callers must pass the token
    /// RETURNED by that statement, never a token they minted separately.
    pub fn from_claim_row(
        row: T,
        claim_token: Uuid,
        claimed_by: String,
        claim_expires_at: DateTime<Utc>,
    ) -> Self {
        Self {
            row,
            claim_token,
            claimed_by,
            claim_expires_at,
        }
    }

    /// The random per-claim token; bind this in every finalizer predicate.
    pub fn claim_token(&self) -> Uuid {
        self.claim_token
    }

    /// Diagnostic owner identity recorded on the claim.
    pub fn claimed_by(&self) -> &str {
        &self.claimed_by
    }

    /// When the claim lapses and the row becomes reclaimable by other
    /// replicas. Long-running workers should extend this before it passes.
    pub fn claim_expires_at(&self) -> DateTime<Utc> {
        self.claim_expires_at
    }

    pub fn into_row(self) -> T {
        self.row
    }
}

impl<T> Deref for Claimed<T> {
    type Target = T;

    fn deref(&self) -> &T {
        &self.row
    }
}

// ---------------------------------------------------------------------------
// Singleton scheduler leases
// ---------------------------------------------------------------------------

/// A held (or renewed) singleton job lease from `scheduler_leases`.
///
/// Unlike [`crate::services::cluster_lock::ClusterLease`] this is durable
/// state: it survives the claiming process and expires by wall clock, so a
/// crashed holder blocks the job for at most `ttl_secs`. Dropping the struct
/// releases nothing — call [`release`](Self::release) on the happy path or
/// let the TTL lapse.
#[derive(Debug)]
pub struct SchedulerLease {
    job_name: String,
    claim_token: Uuid,
    lease_expires_at: DateTime<Utc>,
}

impl SchedulerLease {
    pub fn lease_expires_at(&self) -> DateTime<Utc> {
        self.lease_expires_at
    }

    /// Extend the lease by `ttl_secs` from now. Returns `false` (and stops
    /// being the holder) if the lease was lost — expired and re-claimed by
    /// another replica — in which case the caller should stop side effects.
    pub async fn renew(&mut self, db: &PgPool, ttl_secs: f64) -> Result<bool> {
        let renewed: Option<DateTime<Utc>> = sqlx::query_scalar(
            r#"
            UPDATE scheduler_leases
            SET lease_expires_at = NOW() + make_interval(secs => $3),
                updated_at = NOW()
            WHERE job_name = $1
              AND claim_token = $2
            RETURNING lease_expires_at
            "#,
        )
        .bind(&self.job_name)
        .bind(self.claim_token)
        .bind(ttl_secs)
        .fetch_optional(db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        match renewed {
            Some(expires) => {
                self.lease_expires_at = expires;
                Ok(true)
            }
            None => Ok(false),
        }
    }

    /// Release the lease early so another replica can claim the job without
    /// waiting out the TTL. Token-guarded: releasing a lease that was already
    /// lost is a no-op.
    pub async fn release(self, db: &PgPool) {
        let result = sqlx::query(
            r#"
            UPDATE scheduler_leases
            SET lease_expires_at = NOW(), updated_at = NOW()
            WHERE job_name = $1
              AND claim_token = $2
            "#,
        )
        .bind(&self.job_name)
        .bind(self.claim_token)
        .execute(db)
        .await;
        if let Err(e) = result {
            // Harmless: the lease still lapses at its TTL.
            tracing::debug!(job = %self.job_name, error = %e, "scheduler lease release failed");
        }
    }
}

/// Try to claim the named singleton job lease for `ttl_secs`.
///
/// Returns `Ok(Some(lease))` when this process is the holder — either the
/// lease was absent/expired, or this same `owner_id` already held it (renewal,
/// which keeps a periodic job pinned to its current healthy holder). Returns
/// `Ok(None)` when another live owner holds it; the caller should skip the
/// tick, not error.
pub async fn try_acquire_scheduler_lease(
    db: &PgPool,
    job_name: &str,
    owner_id: &str,
    ttl_secs: f64,
) -> Result<Option<SchedulerLease>> {
    let row: Option<(Uuid, DateTime<Utc>)> = sqlx::query_as(
        r#"
        INSERT INTO scheduler_leases (job_name, owner_id, claim_token, lease_expires_at)
        VALUES ($1, $2, gen_random_uuid(), NOW() + make_interval(secs => $3))
        ON CONFLICT (job_name) DO UPDATE
        SET owner_id = EXCLUDED.owner_id,
            claim_token = EXCLUDED.claim_token,
            lease_expires_at = EXCLUDED.lease_expires_at,
            updated_at = NOW()
        WHERE scheduler_leases.lease_expires_at <= NOW()
           OR scheduler_leases.owner_id = EXCLUDED.owner_id
        RETURNING claim_token, lease_expires_at
        "#,
    )
    .bind(job_name)
    .bind(owner_id)
    .bind(ttl_secs)
    .fetch_optional(db)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;

    Ok(row.map(|(claim_token, lease_expires_at)| SchedulerLease {
        job_name: job_name.to_string(),
        claim_token,
        lease_expires_at,
    }))
}

/// Convenience wrapper: claim with the process identity, mapping infra errors
/// to "not the holder" with a warning. Periodic jobs should degrade to
/// skipping a tick when the lease table is unreachable, not crash the loop.
pub async fn try_acquire_scheduler_lease_quiet(
    db: &PgPool,
    job_name: &str,
    ttl_secs: f64,
) -> Option<SchedulerLease> {
    match try_acquire_scheduler_lease(
        db,
        job_name,
        WorkerIdentity::for_process().as_str(),
        ttl_secs,
    )
    .await
    {
        Ok(lease) => lease,
        Err(e) => {
            tracing::warn!(job = %job_name, error = %e, "scheduler lease acquire failed; skipping tick");
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn worker_identity_compose_includes_host_pid_and_boot() {
        let boot = Uuid::new_v4();
        let id = WorkerIdentity::compose(Some("pod-a"), 42, boot);
        assert_eq!(id, format!("pod-a:42:{boot}"));
    }

    #[test]
    fn worker_identity_compose_falls_back_without_host() {
        let boot = Uuid::new_v4();
        assert!(WorkerIdentity::compose(None, 1, boot).starts_with("unknown-host:1:"));
        assert!(WorkerIdentity::compose(Some(""), 1, boot).starts_with("unknown-host:1:"));
    }

    #[test]
    fn worker_identity_for_process_is_stable() {
        let a = WorkerIdentity::for_process().as_str().to_string();
        let b = WorkerIdentity::for_process().as_str().to_string();
        assert_eq!(a, b, "identity must be stable for the process lifetime");
    }

    #[test]
    fn claimed_exposes_row_and_proof() {
        let expires = Utc::now() + chrono::Duration::seconds(60);
        let token = Uuid::new_v4();
        let claimed = Claimed::from_claim_row(7_i64, token, "w1".to_string(), expires);
        assert_eq!(*claimed, 7);
        assert_eq!(claimed.claim_token(), token);
        assert_eq!(claimed.claimed_by(), "w1");
        assert_eq!(claimed.claim_expires_at(), expires);
        assert_eq!(claimed.into_row(), 7);
    }

    /// Tier-2 (needs DATABASE_URL): full lease lifecycle — claim, contend,
    /// self-renew, token-guarded renew-after-loss, release, reclaim.
    #[tokio::test]
    async fn scheduler_lease_lifecycle() {
        use crate::api::handlers::test_db_helpers as tdh;
        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let job = format!("test-lease-{}", Uuid::new_v4());

        // First claimant wins.
        let lease = try_acquire_scheduler_lease(&pool, &job, "owner-a", 60.0)
            .await
            .expect("query ok")
            .expect("first claim wins");

        // A different owner is refused while the lease is live.
        assert!(
            try_acquire_scheduler_lease(&pool, &job, "owner-b", 60.0)
                .await
                .expect("query ok")
                .is_none(),
            "live lease must not be claimable by another owner"
        );

        // The same owner re-claims (renewal path for periodic ticks).
        let renewed = try_acquire_scheduler_lease(&pool, &job, "owner-a", 60.0)
            .await
            .expect("query ok")
            .expect("same owner must be able to renew");

        // The original lease object lost its token to the renewal above:
        // token-guarded renew must now report the loss.
        let mut stale = lease;
        assert!(
            !stale.renew(&pool, 60.0).await.expect("query ok"),
            "renew with a superseded token must fail"
        );

        // Release frees the job for a different owner immediately.
        renewed.release(&pool).await;
        let taken_over = try_acquire_scheduler_lease(&pool, &job, "owner-b", 60.0)
            .await
            .expect("query ok");
        assert!(
            taken_over.is_some(),
            "released lease must be claimable by another owner"
        );

        // Cleanup.
        let _ = sqlx::query("DELETE FROM scheduler_leases WHERE job_name = $1")
            .bind(&job)
            .execute(&pool)
            .await;
    }

    /// Tier-2: an expired lease is reclaimed in place by a new owner.
    #[tokio::test]
    async fn scheduler_lease_expired_is_reclaimable() {
        use crate::api::handlers::test_db_helpers as tdh;
        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let job = format!("test-lease-{}", Uuid::new_v4());

        // Claim with a TTL that is already in the past.
        let _expired = try_acquire_scheduler_lease(&pool, &job, "owner-a", -1.0)
            .await
            .expect("query ok")
            .expect("claim");

        let reclaimed = try_acquire_scheduler_lease(&pool, &job, "owner-b", 60.0)
            .await
            .expect("query ok");
        assert!(
            reclaimed.is_some(),
            "expired lease must be reclaimable by a new owner"
        );

        let _ = sqlx::query("DELETE FROM scheduler_leases WHERE job_name = $1")
            .bind(&job)
            .execute(&pool)
            .await;
    }
}
