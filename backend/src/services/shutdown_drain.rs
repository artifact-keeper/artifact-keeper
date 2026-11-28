//! The shutdown drain (#5921): fail readiness first, keep serving, then
//! close the listeners.
//!
//! On SIGTERM the server used to cancel its shutdown token and stop
//! accepting connections at once. A load balancer or ingress learns that an
//! endpoint is gone asynchronously (Kubernetes EndpointSlices reach
//! ingress-nginx in about 1-2 s), so it kept sending requests to the
//! terminating replica in that window and they failed with `connection
//! refused`, which the proxy answered as 502. With a single ready replica
//! (one-replica deployments, a rollout narrowed to one pod) its retries had
//! no other peer to go to.
//!
//! Shutdown now runs in phases:
//!
//! 1. **Stop requested** (SIGTERM, Ctrl+C, or the Windows service stop): the
//!    process is marked draining. `/readyz` and `/ready` answer `503` with
//!    `shutting_down` in `failing`, so health-checking load balancers and the
//!    kubelet take the replica out of rotation; `/livez` and `/health` keep
//!    their usual answers, so nothing restarts the process meanwhile.
//!    Background workers stop claiming new work: scheduler leases are not
//!    acquired, the webhook delivery, sync and scheduled-backup workers claim
//!    nothing new, and the workers that watch the stop token (scan queue,
//!    resumers, resolvers, backfills) wind down. A job running under a
//!    scheduler lease is told to stop through its lease-loss token and keeps
//!    its lease while it winds down. Migrations keep running
//!    until the listeners close and are paused then (#6253).
//! 2. **Drain**: the listeners stay open and requests, new and in flight,
//!    are served normally for `SHUTDOWN_DRAIN_SECS`. The default is
//!    [`DEFAULT_DRAIN_SECS`] (0: close at once, the behaviour before 1.13.0);
//!    5-10 s is the recommended value behind a Kubernetes Service or
//!    ingress. A second signal at any point forces an immediate exit.
//! 3. **Close**: the HTTP, gRPC and metrics listeners stop accepting and the
//!    in-flight requests finish, as before. Shutdown then waits for the
//!    scheduler jobs still running here, until [`SCHEDULER_JOB_WAIT_GRACE`]
//!    after the end of the drain, and releases the leases this process holds
//!    so another replica picks those jobs up without waiting out their TTL.
//!    The lease of a job still running at that point is not released: it
//!    lapses at its TTL, so no other replica starts the job while this one may
//!    still be doing it.
//!
//! The drain must fit inside the platform's stop budget together with the
//! longest request: Kubernetes' `terminationGracePeriodSeconds` (default 30)
//! counts from the moment the preStop hook starts, and `docker stop` sends
//! SIGKILL 10 s after SIGTERM by default. See
//! `docs/operations/graceful-shutdown.md`.

use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;
use tokio_util::sync::CancellationToken;

/// Environment variable holding the drain length in seconds.
pub const ENV_VAR: &str = "SHUTDOWN_DRAIN_SECS";

/// The spelling the issue proposed, accepted as an alias.
pub const ENV_VAR_ALIAS: &str = "SHUTDOWN_DRAIN_SECONDS";

/// Default drain: none, so a stop closes the listeners at once as before
/// 1.13.0 (readiness still fails and background claims still stop first).
/// Deployments behind a load balancer set 5-10 s; see
/// `docs/operations/graceful-shutdown.md` for how that fits the platform's
/// stop budget.
pub const DEFAULT_DRAIN_SECS: u64 = 0;

/// Upper bound, so a typo cannot hold a stopping process for hours.
pub const MAX_DRAIN_SECS: u64 = 300;

/// Extra time, from the stop signal, for scheduler jobs to stop after the
/// listeners close (#6487). The drain deadline alone had already passed when
/// the job wait started, so a running job kept its lease until the TTL.
pub const SCHEDULER_JOB_WAIT_GRACE: Duration = Duration::from_secs(5);

/// Gauge: 1 while this process is draining.
pub const DRAINING_METRIC: &str = "ak_shutdown_draining";

static DRAINING: AtomicBool = AtomicBool::new(false);

/// When the drain ends: the stop request plus `SHUTDOWN_DRAIN_SECS`.
static DRAIN_DEADLINE: std::sync::OnceLock<tokio::time::Instant> = std::sync::OnceLock::new();

/// When scheduler jobs must have stopped: the drain deadline plus
/// [`SCHEDULER_JOB_WAIT_GRACE`] (#6487).
static SCHEDULER_JOB_WAIT_DEADLINE: std::sync::OnceLock<tokio::time::Instant> =
    std::sync::OnceLock::new();

/// When the drain ends (the stop request plus the drain), once a stop was
/// requested.
pub fn drain_deadline() -> Option<tokio::time::Instant> {
    DRAIN_DEADLINE.get().copied()
}

/// The deadline for waiting on scheduler jobs during shutdown (#6487). It is
/// set when the stop is requested, so the wait still has time left after the
/// listeners have closed.
pub fn scheduler_job_wait_deadline() -> Option<tokio::time::Instant> {
    SCHEDULER_JOB_WAIT_DEADLINE.get().copied()
}

/// Whether a stop was requested and this process is draining or closing.
/// Readiness answers 503 and background workers claim no new work.
pub fn is_draining() -> bool {
    DRAINING.load(Ordering::Acquire)
}

/// Mark the process draining. Idempotent.
pub fn begin() {
    if !DRAINING.swap(true, Ordering::AcqRel) {
        metrics::gauge!(DRAINING_METRIC).set(1.0);
    }
}

#[cfg(test)]
pub(crate) fn reset_for_test() {
    DRAINING.store(false, Ordering::Release);
}

/// The configured drain length: `SHUTDOWN_DRAIN_SECS`, else
/// `SHUTDOWN_DRAIN_SECONDS`, else [`DEFAULT_DRAIN_SECS`]; capped at
/// [`MAX_DRAIN_SECS`]. `0` keeps the old behaviour (close at once).
pub fn drain_from_env() -> Duration {
    let primary = std::env::var(ENV_VAR).ok();
    let alias = std::env::var(ENV_VAR_ALIAS).ok();
    parse_drain(primary.as_deref().or(alias.as_deref()))
}

fn parse_drain(value: Option<&str>) -> Duration {
    let secs = match value.map(str::trim) {
        None | Some("") => DEFAULT_DRAIN_SECS,
        Some(v) => match v.parse::<u64>() {
            Ok(secs) => secs,
            Err(_) => {
                tracing::warn!(
                    value = v,
                    "{ENV_VAR} is not a whole number of seconds; using the default \
                     {DEFAULT_DRAIN_SECS}"
                );
                DEFAULT_DRAIN_SECS
            }
        },
    };
    if secs > MAX_DRAIN_SECS {
        tracing::warn!("{ENV_VAR}={secs} is above the {MAX_DRAIN_SECS} s cap; using the cap");
    }
    Duration::from_secs(secs.min(MAX_DRAIN_SECS))
}

/// Run the drain: wait for `stop`, mark the process draining, keep serving
/// for `drain`, then cancel `serve`, which closes the listeners. (A second
/// signal is handled by the caller: it exits the process at once.)
pub async fn drain_then_close(stop: CancellationToken, serve: CancellationToken, drain: Duration) {
    stop.cancelled().await;
    let stopped_at = tokio::time::Instant::now();
    let _ = DRAIN_DEADLINE.set(stopped_at + drain);
    let _ = SCHEDULER_JOB_WAIT_DEADLINE.set(stopped_at + drain + SCHEDULER_JOB_WAIT_GRACE);
    begin();
    crate::services::cluster_work::stop_scheduler_jobs();
    if drain.is_zero() {
        tracing::info!("shutdown: {ENV_VAR}=0, closing the listeners now");
    } else {
        tracing::info!(
            drain_secs = drain.as_secs(),
            "shutdown: draining for {}s; /readyz answers 503, requests are still served, \
             background workers claim no new work (signal again to exit at once)",
            drain.as_secs()
        );
        tokio::time::sleep(drain).await;
    }
    tracing::info!("shutdown: drain over, closing the listeners");
    serve.cancel();
}

#[cfg(ak_test_shard = "services-2")]
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn drain_defaults_parses_and_caps() {
        assert_eq!(
            parse_drain(None),
            Duration::ZERO,
            "the default keeps the old behaviour"
        );
        assert_eq!(parse_drain(None), Duration::from_secs(DEFAULT_DRAIN_SECS));
        assert_eq!(
            parse_drain(Some("")),
            Duration::from_secs(DEFAULT_DRAIN_SECS)
        );
        assert_eq!(parse_drain(Some("0")), Duration::ZERO);
        assert_eq!(parse_drain(Some(" 15 ")), Duration::from_secs(15));
        assert_eq!(
            parse_drain(Some("ten")),
            Duration::from_secs(DEFAULT_DRAIN_SECS)
        );
        assert_eq!(
            parse_drain(Some("-1")),
            Duration::from_secs(DEFAULT_DRAIN_SECS)
        );
        assert_eq!(
            parse_drain(Some("86400")),
            Duration::from_secs(MAX_DRAIN_SECS)
        );
    }

    #[tokio::test(start_paused = true)]
    async fn readiness_flips_at_once_and_the_listeners_close_after_the_drain() {
        reset_for_test();
        let stop = CancellationToken::new();
        let serve = CancellationToken::new();
        let task = tokio::spawn(drain_then_close(
            stop.clone(),
            serve.clone(),
            Duration::from_secs(10),
        ));
        tokio::task::yield_now().await;
        assert!(!is_draining(), "nothing drains before a stop is requested");

        stop.cancel();
        tokio::time::sleep(Duration::from_millis(1)).await;
        assert!(is_draining(), "a stop marks the process draining at once");
        assert!(
            !serve.is_cancelled(),
            "the listeners stay open while draining"
        );

        tokio::time::sleep(Duration::from_secs(9)).await;
        assert!(!serve.is_cancelled(), "still serving 9 s into a 10 s drain");

        tokio::time::sleep(Duration::from_secs(2)).await;
        assert!(
            serve.is_cancelled(),
            "the listeners close once the drain is over"
        );
        task.await.unwrap();
        reset_for_test();
    }

    #[tokio::test(start_paused = true)]
    async fn a_zero_drain_closes_at_once() {
        reset_for_test();
        let stop = CancellationToken::new();
        let serve = CancellationToken::new();
        stop.cancel();
        drain_then_close(stop, serve.clone(), Duration::ZERO).await;
        assert!(serve.is_cancelled());
        assert!(is_draining());
        reset_for_test();
    }

    /// #6487: the job wait must not inherit the drain deadline, which has
    /// already passed by the time the listeners close.
    #[tokio::test(start_paused = true)]
    async fn scheduler_jobs_get_a_bounded_wait_after_the_listeners_close() {
        reset_for_test();
        let stop = CancellationToken::new();
        let serve = CancellationToken::new();
        let drain = Duration::from_secs(10);
        let task = tokio::spawn(drain_then_close(stop.clone(), serve.clone(), drain));
        stop.cancel();
        tokio::time::sleep(Duration::from_millis(1)).await;

        let drain_deadline = drain_deadline().expect("a stop sets the drain deadline");
        let job_deadline = scheduler_job_wait_deadline().expect("a stop sets the job deadline");
        assert_eq!(job_deadline - drain_deadline, SCHEDULER_JOB_WAIT_GRACE);

        tokio::time::sleep(drain + Duration::from_millis(1)).await;
        assert!(
            serve.is_cancelled(),
            "the listeners close at the drain deadline"
        );
        task.await.unwrap();
        assert!(
            scheduler_job_wait_deadline().expect("job deadline is still set")
                > tokio::time::Instant::now(),
            "the job wait has time left after the listeners close"
        );
        reset_for_test();
    }
}
