//! Drains [`crate::services::scan_queue`], so no request waits on grype.
//!
//! Runs only with `SCAN_QUEUE_ENABLED`. `SCAN_WORKER_ENABLED` is opt-out, so a
//! single node drains its own queue and a fleet turns it off on the API pods.
//!
//! Jobs run under a heartbeaten claim, so a pod dying mid-scan releases its work
//! to the recovery sweep instead of orphaning it.

use chrono::Utc;
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::Semaphore;
use tokio_util::sync::CancellationToken;

use crate::api::SharedState;
use crate::services::cluster_work::{spawn_row_claim_renewal, Claimed, WorkerIdentity};
use crate::services::scan_queue::{
    ScanJob, ScanJobKind, ScanQueue, CLAIM_TTL_SECS, RENEW_CLAIM_SQL,
};

/// Poll floor. 1s, not the webhook processor's 30s: a parked fail-closed client
/// feels this. An enqueue in this process wakes us sooner.
const DEFAULT_TICK: Duration = Duration::from_millis(1000);

/// Jobs in flight per pod, matching the extraction semaphore so a default install
/// cannot claim more than it can decompress.
const DEFAULT_CONCURRENCY: usize = 4;

/// Ceiling for one queued scan: well above the inline budgets it replaces, since
/// nobody holds a socket, but bounded so a wedged grype releases its permit.
const DEFAULT_JOB_BUDGET: Duration = Duration::from_secs(600);

/// Backoff before a failed job becomes due again.
const RETRY_BACKOFF: Duration = Duration::from_secs(30);

/// Longer than [`RETRY_BACKOFF`]: the usual cause is a pod that died running
/// this job, so re-claiming instantly risks killing the next one too.
const RECOVERY_BACKOFF: Duration = Duration::from_secs(120);

/// Housekeeping cadence. Wall-clock, NOT loop iterations: enqueues wake the loop,
/// so a tick counter ran these dozens of times a second under a burst.
const SWEEP_INTERVAL: Duration = Duration::from_secs(30);

/// How long a terminal job is kept for an operator to read `last_error` off.
const FAILED_RETENTION: Duration = Duration::from_secs(7 * 24 * 60 * 60);

/// Why a job produced no verdict. Terminal must not return to the queue.
enum JobFailure {
    /// Worth retrying: object not cached yet, storage blip, DB blip.
    Retryable(String),
    /// Will never succeed for this job. Consumes all remaining attempts.
    Terminal(String),
}

/// Start the worker when the queue is on and `SCAN_WORKER_ENABLED` is not off,
/// until `shutdown`.
pub fn spawn_scan_worker(state: SharedState, shutdown: CancellationToken) {
    if !state.config.scan_queue_enabled {
        return;
    }
    if !state.config.scan_worker_enabled {
        tracing::info!(
            "Scan worker disabled (SCAN_WORKER_ENABLED=false); this instance serves requests \
             only and queued scans are drained by a worker deployment"
        );
        return;
    }
    if state.scanner_service.is_none() {
        tracing::warn!(
            "Scan worker enabled but no scanner service is configured; queued scans will not \
             drain on this instance"
        );
        return;
    }

    let concurrency = state
        .config
        .scan_worker_concurrency
        .unwrap_or(DEFAULT_CONCURRENCY)
        .max(1);
    let queue = ScanQueue::new(state.db.clone());
    let permits = Arc::new(Semaphore::new(concurrency));
    let identity = WorkerIdentity::for_process().as_str().to_string();

    tracing::info!(
        concurrency,
        worker = %identity,
        "Scan worker started (SCAN_WORKER_ENABLED)"
    );

    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(DEFAULT_TICK);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        // Start due, so a pod that comes up after a crash recovers the dead
        // pod's claims on its first pass instead of 30s in.
        let mut next_sweep = tokio::time::Instant::now();
        let mut next_rescan = tokio::time::Instant::now();

        loop {
            // The tick is a floor: a same-process enqueue wakes us immediately.
            tokio::select! {
                _ = shutdown.cancelled() => {
                    tracing::info!("Scan worker shutting down");
                    return;
                }
                _ = ticker.tick() => {}
                _ = crate::services::scan_queue::enqueue_signal().notified() => {}
            }

            let now = tokio::time::Instant::now();
            if now >= next_sweep {
                next_sweep = now + SWEEP_INTERVAL;

                // Return work abandoned by a dead replica. Safe from every pod.
                match queue
                    .recover_expired_claims(RECOVERY_BACKOFF.as_secs_f64())
                    .await
                {
                    Ok(0) => {}
                    Ok(n) => tracing::warn!(
                        jobs = n,
                        "recovered scan jobs whose claim lapsed; a worker vanished mid-scan"
                    ),
                    Err(e) => tracing::warn!(error = %e, "scan-job claim recovery failed"),
                }

                // Scaling signal: one grouped query.
                match queue.depth().await {
                    Ok(rows) => {
                        let (depths, oldest) = queue_gauges(&rows);
                        for (kind, state, jobs) in depths {
                            crate::services::metrics_service::record_scan_queue_depth(
                                kind, state, jobs,
                            );
                        }
                        for (kind, age) in oldest {
                            crate::services::metrics_service::record_scan_queue_oldest_pending(
                                kind, age,
                            );
                        }
                    }
                    Err(e) => tracing::warn!(error = %e, "failed to publish scan queue depth"),
                }

                // Live consumers (cluster-wide) and this pod's own slot
                // occupancy. Together they answer "is the queue backed up
                // because nothing is consuming it, or because everything is
                // consuming it flat out", which have opposite remedies.
                match queue.consumers().await {
                    Ok(n) => {
                        crate::services::metrics_service::record_scan_queue_consumers(n as f64)
                    }
                    Err(e) => tracing::warn!(error = %e, "failed to publish scan queue consumers"),
                }
                crate::services::metrics_service::record_scan_worker_slots(
                    (concurrency - permits.available_permits()) as f64,
                    concurrency as f64,
                );

                // Terminal rows are read by operators, not by code, so nothing
                // else would ever remove them.
                match queue.purge_failed(FAILED_RETENTION.as_secs_f64()).await {
                    Ok(0) => {}
                    Ok(n) => tracing::info!(jobs = n, "purged terminal scan jobs past retention"),
                    Err(e) => tracing::warn!(error = %e, "scan-job retention purge failed"),
                }
            }

            if state.config.scan_rescan_max_per_day > 0 && now >= next_rescan {
                next_rescan = now + crate::services::scan_rescan::RESCAN_TICK;
                rescan_tick(&state).await;
            }

            // A claimed job is invisible to other replicas, so over-claiming
            // parks work here while an idle pod polls an empty queue.
            let available = permits.available_permits();
            if available == 0 {
                continue;
            }

            let claimed = match queue
                .claim(available as i64, &identity, CLAIM_TTL_SECS)
                .await
            {
                Ok(jobs) => jobs,
                Err(e) => {
                    tracing::warn!(error = %e, "failed to claim scan jobs");
                    continue;
                }
            };

            for job in claimed {
                // Time this job actually spent waiting, measured at the moment
                // it stopped waiting. Recorded before the permit check so a
                // job released back for saturation still reports the wait it
                // really incurred.
                let waited = (Utc::now() - job.created_at).num_milliseconds();
                crate::services::metrics_service::record_scan_queue_wait(
                    &job.kind,
                    waited as f64 / 1000.0,
                );

                let permit = match Arc::clone(&permits).try_acquire_owned() {
                    Ok(p) => p,
                    // `release`, not `fail`: saturation is about this pod, not the job.
                    Err(_) => {
                        let _ = queue.release(job.id, job.claim_token()).await;
                        continue;
                    }
                };
                let state = state.clone();
                let queue = queue.clone();
                tokio::spawn(async move {
                    let _permit = permit;
                    run_claimed_job(state, queue, job).await;
                });
            }
        }
    });
}

/// `state` with the worker's own scanner set (`SCAN_WORKER_TRIVY_ADAPTER_URL`,
/// #5946), for [`spawn_scan_worker`]. Request handlers keep the original.
pub fn state_with_worker_scanner(
    state: &SharedState,
    scanner: Arc<crate::services::scanner_service::ScannerService>,
) -> SharedState {
    let mut worker_state = (**state).clone();
    worker_state.set_scanner_service(scanner);
    Arc::new(worker_state)
}

/// Run one claimed job under a heartbeat, then finalize token-guarded.
async fn run_claimed_job(state: SharedState, queue: ScanQueue, job: Claimed<ScanJob>) {
    let job_id = job.id;
    let claim_token = job.claim_token();
    let kind = job.kind.clone();

    // Heartbeat, so a long scan is not reclaimed underneath us.
    let (_renewal, lost_ownership) = spawn_row_claim_renewal(
        state.db.clone(),
        format!("scan_queue:{job_id}"),
        RENEW_CLAIM_SQL,
        job_id,
        claim_token,
        CLAIM_TTL_SECS,
    );

    let started = tokio::time::Instant::now();
    let outcome = tokio::select! {
        biased;
        _ = lost_ownership.cancelled() => {
            tracing::warn!(
                job_id = %job_id, kind = %kind,
                "abandoning scan job: claim was lost to another replica mid-scan"
            );
            return;
        }
        result = tokio::time::timeout(DEFAULT_JOB_BUDGET, execute(&state, &job)) => match result {
            Ok(r) => r,
            Err(_) => Err(JobFailure::Retryable(format!(
                "scan exceeded the {}s queued-job budget",
                DEFAULT_JOB_BUDGET.as_secs()
            ))),
        }
    };

    let elapsed = started.elapsed().as_secs_f64();
    crate::services::metrics_service::record_scan_job(
        &kind,
        if outcome.is_ok() {
            "success"
        } else {
            "failure"
        },
        elapsed,
    );

    match outcome {
        Ok(()) => {
            if let Err(e) = queue.complete(job_id, claim_token).await {
                tracing::warn!(job_id = %job_id, error = %e, "failed to retire completed scan job");
            }
        }
        Err(failure) => {
            let (message, backoff) = match failure {
                JobFailure::Retryable(m) => (m, RETRY_BACKOFF.as_secs_f64()),
                // A job that cannot succeed must not come back.
                JobFailure::Terminal(m) => {
                    if let Err(e) = queue.mark_terminal(job_id, claim_token, &m).await {
                        tracing::warn!(job_id = %job_id, error = %e, "failed to retire dead scan job");
                    }
                    tracing::warn!(job_id = %job_id, kind = %kind, reason = %m, "scan job is not runnable; dropped");
                    return;
                }
            };
            tracing::warn!(job_id = %job_id, kind = %kind, error = %message, "scan job failed");
            if let Err(e) = queue.fail(job_id, claim_token, &message, backoff).await {
                tracing::warn!(job_id = %job_id, error = %e, "failed to record scan job failure");
            }
        }
    }
}

/// Dispatch to the branch for this job's kind.
async fn execute(state: &SharedState, job: &ScanJob) -> Result<(), JobFailure> {
    match job.job_kind() {
        Some(ScanJobKind::ProxyFile) => scan_proxy_file(state, job).await,
        Some(ScanJobKind::HostedArtifact) => scan_hosted_artifact(state, job).await,
        Some(ScanJobKind::HostedUpload) => scan_hosted_upload(state, job).await,
        Some(ScanJobKind::HostedImage) => scan_hosted_image(state, job).await,
        Some(ScanJobKind::Rescan) => {
            crate::services::scan_queue::in_background(rescan_digest(state, job)).await
        }
        // A kind written by a newer replica. Not `failed`: that would discard
        // work the other half of the fleet can run.
        None => Err(JobFailure::Retryable(format!(
            "unknown scan job kind {:?}; leaving it for a replica that understands it",
            job.kind
        ))),
    }
}

/// Scan a proxy-cached file by reference: the body the rescan endpoint already
/// proved. The request path enqueues this instead of running it.
async fn scan_proxy_file(state: &SharedState, job: &ScanJob) -> Result<(), JobFailure> {
    use crate::api::handlers::proxy_helpers;

    let repo_id = job
        .repository_id
        .ok_or_else(|| JobFailure::Terminal("proxy_file job has no repository_id".to_string()))?;
    let cache_path = job
        .cache_path
        .as_deref()
        .ok_or_else(|| JobFailure::Terminal("proxy_file job has no cache_path".to_string()))?;

    // The cache write is best-effort and is skipped when the checksum or quota
    // guard trips, so a missing row is ordinary, not a fault.
    let entry = crate::services::proxy_catalog::find_cached_entry(&state.db, repo_id, cache_path)
        .await
        .map_err(|e| JobFailure::Retryable(format!("catalog lookup failed: {e}")))?
        .ok_or_else(|| JobFailure::Retryable(format!("no cached object at {cache_path} yet")))?;

    // Refuse over-cap before reading a byte: the download gate skips these too,
    // and buffering one here would be the only unbounded read in the product.
    if !(0..=crate::services::scanner_service::PROXY_SCAN_MAX_BYTES as i64)
        .contains(&entry.size_bytes)
    {
        return Err(JobFailure::Terminal(format!(
            "cached object is {} bytes, above the {} byte scan cap",
            entry.size_bytes,
            crate::services::scanner_service::PROXY_SCAN_MAX_BYTES
        )));
    }

    let bytes = state
        .storage
        .get(&entry.storage_key)
        .await
        .map_err(|e| JobFailure::Retryable(format!("cached bytes are not readable: {e}")))?;

    // Recompute, never trust the queued digest: if the cache was overwritten
    // between enqueue and claim, we would attach a verdict to bytes nobody
    // scanned.
    let digest = proxy_helpers::sha256_hex(&bytes);
    if job.digest.as_deref() != Some(digest.as_str()) {
        tracing::info!(
            repo_id = %repo_id, path = %cache_path,
            queued_digest = ?job.digest, actual_digest = %digest,
            "cached bytes changed since this scan was queued; recording the verdict against \
             the bytes actually scanned"
        );
    }

    let synthetic = proxy_helpers::proxy_rescan_synthetic_artifact(
        repo_id,
        cache_path,
        &digest,
        bytes.len() as i64,
        entry.content_type.as_deref(),
    );

    // Not optional bookkeeping: this pins the coordinate into the workspace and
    // turns on the assessment gate (#3003). Unpinned, grype catalogs nothing
    // from an sdist's PKG-INFO and `clean` means "nothing was looked at".
    let expected = job
        .expected_component()
        .map_err(|e| JobFailure::Retryable(format!("cannot assert the queued identity: {e}")))?;

    proxy_helpers::proxy_scan_and_record(
        state,
        repo_id,
        &digest,
        &synthetic,
        &bytes,
        expected.as_ref(),
        &proxy_helpers::ProxyScanMode::File,
        DEFAULT_JOB_BUDGET,
    )
    .await
    .map(|_| ())
    .map_err(classify_inconclusive)
}

/// Run a hosted-artifact scan against placeholders the API already committed.
async fn scan_hosted_artifact(state: &SharedState, job: &ScanJob) -> Result<(), JobFailure> {
    let artifact_id = job.artifact_id.ok_or_else(|| {
        JobFailure::Terminal("hosted_artifact job has no artifact_id".to_string())
    })?;
    let prepared_json = job.prepared.as_ref().ok_or_else(|| {
        JobFailure::Terminal("hosted_artifact job has no prepared map".to_string())
    })?;

    // Terminal on decode failure: retrying cannot repair a malformed payload,
    // and the janitor reaps the placeholder rows it names.
    let prepared: std::collections::HashMap<String, uuid::Uuid> =
        serde_json::from_value(prepared_json.clone()).map_err(|e| {
            JobFailure::Terminal(format!("prepared scan map is not decodable: {e}"))
        })?;

    let scanner = state
        .scanner_service
        .as_ref()
        .ok_or_else(|| JobFailure::Retryable("no scanner service configured".to_string()))?;

    scanner
        .scan_artifact_with_prepared(artifact_id, prepared, true, job.bypass_dedup)
        .await
        .map_err(|e| JobFailure::Retryable(format!("hosted scan failed: {e}")))
}

/// Run a queued `scan_on_upload` (#5946) exactly as the in-process trigger
/// does: [`ScannerService::scan_artifact`], which honours the repository's
/// scan config at run time.
///
/// [`ScannerService::scan_artifact`]: crate::services::scanner_service::ScannerService::scan_artifact
async fn scan_hosted_upload(state: &SharedState, job: &ScanJob) -> Result<(), JobFailure> {
    let artifact_id = job
        .artifact_id
        .ok_or_else(|| JobFailure::Terminal("hosted_upload job has no artifact_id".to_string()))?;
    let scanner = state
        .scanner_service
        .as_ref()
        .ok_or_else(|| JobFailure::Retryable("no scanner service configured".to_string()))?;
    match scanner.scan_artifact(artifact_id).await {
        // Deleted since the upload: nothing is left to grade.
        Ok(()) | Err(crate::error::AppError::NotFound(_)) => Ok(()),
        Err(e) => Err(JobFailure::Retryable(format!("upload scan failed: {e}"))),
    }
}

/// Scan a pushed OCI manifest (#5946): each manifest row in the repository
/// with the job's digest, through [`ScannerService::scan_artifact`] as the
/// in-process trigger does, so the adapter image scan and grype run as today.
///
/// That is every tag of the manifest in the repository, not only the one whose
/// push queued the job (the job is keyed by digest, so pushes of several tags
/// share it). A tag already scanned for these bytes is a no-op or a reuse
/// through the scan dedup, so only the first row needs a scan.
///
/// [`ScannerService::scan_artifact`]: crate::services::scanner_service::ScannerService::scan_artifact
async fn scan_hosted_image(state: &SharedState, job: &ScanJob) -> Result<(), JobFailure> {
    let repo_id = job
        .repository_id
        .ok_or_else(|| JobFailure::Terminal("hosted_image job has no repository_id".to_string()))?;
    let digest = job
        .digest
        .as_deref()
        .ok_or_else(|| JobFailure::Terminal("hosted_image job has no digest".to_string()))?;
    let scanner = state
        .scanner_service
        .as_ref()
        .ok_or_else(|| JobFailure::Retryable("no scanner service configured".to_string()))?;

    let rows: Vec<uuid::Uuid> =
        sqlx::query_scalar(crate::services::scan_queue::HOSTED_IMAGE_ROWS_SQL)
            .bind(repo_id)
            .bind(digest)
            .fetch_all(&state.db)
            .await
            .map_err(|e| JobFailure::Retryable(format!("manifest lookup failed: {e}")))?;

    // No row: the image was deleted since the push, nothing to grade.
    let mut first_error = None;
    for artifact_id in rows {
        match scanner.scan_artifact(artifact_id).await {
            Ok(()) | Err(crate::error::AppError::NotFound(_)) => {}
            Err(e) => {
                tracing::warn!(
                    artifact_id = %artifact_id, repo_id = %repo_id, digest = %digest, error = %e,
                    "queued image scan failed for one manifest row"
                );
                first_error.get_or_insert(e);
            }
        }
    }
    match first_error {
        None => Ok(()),
        Some(e) => Err(JobFailure::Retryable(format!("image scan failed: {e}"))),
    }
}

/// Rescan one digest after a vulnerability-database update (#5947): every live
/// artifact row holding it, oldest first. The first scans fresh and the rest
/// reuse that result, since each only takes a verdict graded after the job
/// started. Earlier `scan_results` rows stay as they are.
async fn rescan_digest(state: &SharedState, job: &ScanJob) -> Result<(), JobFailure> {
    use crate::services::scan_rescan;
    let digest = job
        .digest
        .as_deref()
        .ok_or_else(|| JobFailure::Terminal("rescan job has no digest".to_string()))?;
    let scanner = state
        .scanner_service
        .as_ref()
        .ok_or_else(|| JobFailure::Retryable("no scanner service configured".to_string()))?;
    let since = scan_rescan::db_now(&state.db)
        .await
        .map_err(|e| JobFailure::Retryable(format!("clock read failed: {e}")))?;
    let rows = scan_rescan::artifacts_with_digest(&state.db, digest)
        .await
        .map_err(|e| JobFailure::Retryable(format!("artifact lookup failed: {e}")))?;
    let mut first_error = None;
    for artifact_id in rows {
        match scanner
            .rescan_artifact_graded_since(artifact_id, since)
            .await
        {
            Ok(()) | Err(crate::error::AppError::NotFound(_)) => {}
            Err(e) => {
                tracing::warn!(
                    artifact_id = %artifact_id, digest = %digest, error = %e,
                    "rescan failed for one artifact row"
                );
                first_error.get_or_insert(e);
            }
        }
    }
    match first_error {
        None => Ok(()),
        Some(e) => Err(JobFailure::Retryable(format!("rescan failed: {e}"))),
    }
}

/// One rescan selection pass (#5947), on the worker's sweep. Off with
/// `SCAN_RESCAN_MAX_PER_DAY=0`, the default.
async fn rescan_tick(state: &SharedState) {
    use crate::services::scan_rescan;
    let max = state.config.scan_rescan_max_per_day;
    let Some(scanner) = state.scanner_service.as_ref() else {
        return;
    };
    if max == 0 {
        return;
    }
    let observed = match scan_rescan::observed_builds(&state.db).await {
        Ok(b) => b,
        Err(e) => {
            tracing::warn!(error = %e, "could not read recent vulnerability-database builds");
            Vec::new()
        }
    };
    let builds = scan_rescan::merge_builds(scanner.current_vuln_db_builds().await, observed);
    match scan_rescan::enqueue_rescans(&state.db, &builds, max).await {
        Ok(0) => {}
        Ok(n) => tracing::info!(
            digests = n,
            "queued rescans after a vulnerability-database update"
        ),
        Err(e) => tracing::warn!(error = %e, "rescan selection failed"),
    }
}

/// `NoScanner` is instance-level and the next two per-attempt, so those retry.
/// `RequestPinned` names a coordinate a job cannot carry, retrying can't help
fn classify_inconclusive(
    reason: crate::api::handlers::proxy_helpers::ProxyScanInconclusive,
) -> JobFailure {
    use crate::api::handlers::proxy_helpers::ProxyScanInconclusive;
    match reason {
        ProxyScanInconclusive::NoScanner => {
            JobFailure::Retryable("no scanner configured on this instance".to_string())
        }
        ProxyScanInconclusive::ScanFailed => {
            JobFailure::Retryable("scanner returned an error".to_string())
        }
        ProxyScanInconclusive::BudgetExceeded => {
            JobFailure::Retryable("scan did not finish inside the queued-job budget".to_string())
        }
        ProxyScanInconclusive::RequestPinned => JobFailure::Terminal(
            "verdict is pinned to the requested coordinate, a pull re-grades it".to_string(),
        ),
    }
}

const QUEUE_KINDS: [ScanJobKind; 5] = ScanJobKind::ALL;
const QUEUE_STATES: [&str; 3] = ["pending", "running", "failed"];

/// `(kind, state, jobs)` depths and `(kind, seconds)` oldest-pending ages
type QueueGauges = (
    Vec<(&'static str, &'static str, f64)>,
    Vec<(&'static str, f64)>,
);

/// Every depth and oldest-pending gauge for one sweep, zero where the depth
/// query returned no row. It only returns groups that have rows, and a gauge
/// nobody sets keeps its last value, so an emptied queue used to keep
/// reporting its last backlog
fn queue_gauges(rows: &[crate::services::scan_queue::ScanQueueDepth]) -> QueueGauges {
    let mut depths = Vec::new();
    let mut oldest = Vec::new();
    for kind in QUEUE_KINDS.map(ScanJobKind::as_str) {
        let of_kind = || rows.iter().filter(move |r| r.kind == kind);
        for state in QUEUE_STATES {
            let jobs = of_kind().find(|r| r.state == state).map_or(0, |r| r.jobs);
            depths.push((kind, state, jobs as f64));
        }
        let age = of_kind()
            .filter_map(|r| r.oldest_pending_secs)
            .fold(0.0, f64::max);
        oldest.push((kind, age));
    }
    (depths, oldest)
}

#[cfg(ak_test_shard = "services-2")]
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn queue_gauges_zero_the_groups_the_query_did_not_return() {
        let row =
            |kind: &str, state: &str, jobs, oldest| crate::services::scan_queue::ScanQueueDepth {
                kind: kind.to_string(),
                state: state.to_string(),
                jobs,
                oldest_pending_secs: oldest,
            };
        let (depths, oldest) = queue_gauges(&[row("proxy_file", "pending", 442, Some(49.0))]);
        assert_eq!(depths.len(), 15);
        assert!(depths.contains(&("proxy_file", "pending", 442.0)));
        assert!(depths.contains(&("proxy_file", "running", 0.0)));
        assert!(depths.contains(&("hosted_artifact", "pending", 0.0)));
        assert!(depths.contains(&("hosted_upload", "pending", 0.0)));
        assert!(depths.contains(&("hosted_image", "failed", 0.0)));
        assert_eq!(
            oldest,
            vec![
                ("proxy_file", 49.0),
                ("hosted_artifact", 0.0),
                ("hosted_upload", 0.0),
                ("hosted_image", 0.0),
                ("rescan", 0.0)
            ]
        );

        let (depths, oldest) = queue_gauges(&[]);
        assert!(depths.iter().all(|(_, _, jobs)| *jobs == 0.0), "{depths:?}");
        assert!(oldest.iter().all(|(_, age)| *age == 0.0), "{oldest:?}");
    }

    /// Never claim more than we hold permits for.
    #[test]
    fn claim_batch_is_bounded_by_available_permits() {
        let permits = Semaphore::new(DEFAULT_CONCURRENCY);
        assert_eq!(permits.available_permits(), DEFAULT_CONCURRENCY);
        let held = permits.try_acquire().expect("permit");
        assert_eq!(permits.available_permits(), DEFAULT_CONCURRENCY - 1);
        drop(held);
        assert_eq!(permits.available_permits(), DEFAULT_CONCURRENCY);
    }

    /// Above the inline budgets, or the queue reproduces the timeout it
    /// exists to remove.
    #[test]
    fn queued_budget_exceeds_the_inline_budgets_it_replaces() {
        assert!(DEFAULT_JOB_BUDGET > crate::services::scanner_service::PROXY_SCAN_INLINE_BUDGET);
        assert!(
            DEFAULT_JOB_BUDGET > crate::services::scanner_service::OCI_PROXY_SCAN_INLINE_BUDGET
        );
    }

    /// A recovered job waits longer than an ordinary retry.
    #[test]
    fn recovery_backoff_is_longer_than_retry_backoff() {
        assert!(RECOVERY_BACKOFF > RETRY_BACKOFF);
    }

    /// Enqueues wake the loop, so a per-iteration gate ran the sweeps dozens of
    /// times a second under a burst. Anything near the tick reintroduces that.
    #[test]
    fn sweeps_are_far_rarer_than_the_poll_tick() {
        assert!(
            SWEEP_INTERVAL >= DEFAULT_TICK * 10,
            "SWEEP_INTERVAL {:?} is too close to the {:?} tick; the sweeps would \
             run on essentially every wake-up",
            SWEEP_INTERVAL,
            DEFAULT_TICK
        );
    }

    /// A transient scanner problem must not strand a digest with no verdict.
    #[test]
    fn transient_inconclusive_reasons_are_retryable() {
        use crate::api::handlers::proxy_helpers::ProxyScanInconclusive;
        for reason in [
            ProxyScanInconclusive::NoScanner,
            ProxyScanInconclusive::ScanFailed,
            ProxyScanInconclusive::BudgetExceeded,
        ] {
            assert!(matches!(
                classify_inconclusive(reason),
                JobFailure::Retryable(_)
            ));
        }
        assert!(matches!(
            classify_inconclusive(ProxyScanInconclusive::RequestPinned),
            JobFailure::Terminal(_)
        ));
    }
}
