//! Background task scheduler.
//!
//! Runs periodic tasks: daily metric snapshots, lifecycle policy execution,
//! health monitoring, backup schedule execution, and metric gauge updates.

use chrono::Utc;
use cron::Schedule;
use sqlx::PgPool;
use std::str::FromStr;
use std::sync::Arc;
use tokio::time::{interval, Duration, MissedTickBehavior};

use crate::config::Config;
use crate::services::age_gate_service::AgeGateService;
use crate::services::analytics_service::AnalyticsService;
use crate::services::backup_service::{BackupService, BackupType, CreateBackupRequest};
use crate::services::event_bus::EventBus;
use crate::services::health_monitor_service::{HealthMonitorService, MonitorConfig};
use crate::services::lifecycle_service::LifecycleService;
use crate::services::metrics_service;
use crate::services::scan_result_service::ScanResultService;
use crate::services::smtp_service::SmtpService;
use crate::services::storage_service::StorageService;
use crate::services::sync_policy_service::SyncPolicyService;

/// TTL for the lifecycle-cycle singleton lease. Bounds a crashed holder; a
/// live holder heartbeats it for as long as the cycle runs.
const LIFECYCLE_LEASE_TTL_SECS: f64 = 3600.0;
/// TTL for the curation-sync singleton lease (#2357 S11), kept slightly above
/// the 300s tick so the job stays pinned to its current holder between ticks.
const CURATION_SYNC_LEASE_TTL_SECS: f64 = 360.0;

/// Database gauge stats for Prometheus metrics.
#[derive(Debug, sqlx::FromRow)]
struct GaugeStats {
    pub repos: i64,
    pub artifacts: i64,
    pub storage: i64,
    pub users: i64,
}

/// Per-replica startup-delay jitter (PR #1212 audit, M2).
///
/// Returns a `Duration` equal to `base_secs + uniform(0, 30)` seconds.
/// Multiple replicas spawned by the same Helm release start within a
/// few milliseconds of each other and would otherwise fire their first
/// tick at the same instant; the jitter spreads them across a 30 s
/// window so audit-log writes and metric upticks de-synchronize, even
/// in the legitimate case where the advisory lock briefly contends.
fn jittered_startup_delay(base_secs: u64) -> Duration {
    let jitter = rand::random::<u64>() % 30;
    Duration::from_secs(base_secs.saturating_add(jitter))
}

/// Spawn all background scheduler tasks.
/// Returns join handles for graceful shutdown (not currently used, fire-and-forget).
pub fn spawn_all(
    db: PgPool,
    config: Config,
    _primary_storage: Arc<dyn crate::storage::StorageBackend>,
    storage_registry: Arc<crate::storage::StorageRegistry>,
    smtp_service: Option<Arc<SmtpService>>,
    event_bus: Arc<EventBus>,
) {
    // Daily metrics snapshot (runs every hour, captures once per day via UPSERT)
    {
        let db = db.clone();
        tokio::spawn(async move {
            // Initial delay to let the server start up
            tokio::time::sleep(Duration::from_secs(30)).await;
            let service = AnalyticsService::new(db);
            let mut ticker = interval(Duration::from_secs(3600)); // 1 hour

            loop {
                ticker.tick().await;
                tracing::debug!("Running daily metrics snapshot");

                if let Err(e) = service.capture_daily_snapshot().await {
                    tracing::warn!("Failed to capture daily storage snapshot: {}", e);
                }
                if let Err(e) = service.capture_repository_snapshots().await {
                    tracing::warn!("Failed to capture repository snapshots: {}", e);
                }
            }
        });
    }

    // Gauge metrics updater (every 5 minutes)
    {
        let db = db.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_secs(10)).await;
            let mut ticker = interval(Duration::from_secs(300)); // 5 minutes

            loop {
                ticker.tick().await;
                if let Err(e) = update_gauge_metrics(&db).await {
                    tracing::warn!("Failed to update gauge metrics: {}", e);
                }
            }
        });
    }

    // API-token cache invalidation map prune (every hour).
    //
    // The invalidation map records when each user's API-token cache entries
    // were marked stale. Entries older than 2 * API_TOKEN_CACHE_TTL_SECS
    // (10 min) are no longer needed because any cache entry they would
    // reject has itself expired. Pruning during invalidate_user_token_cache_entries
    // covers the high-churn case; this periodic task keeps memory bounded
    // when deactivations are infrequent. Issue #931.
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_secs(60)).await;
        let mut ticker = interval(Duration::from_secs(3600)); // 1 hour

        loop {
            ticker.tick().await;
            let dropped = crate::services::auth_service::prune_stale_user_token_invalidations();
            if dropped > 0 {
                tracing::debug!(
                    "Pruned {} stale API-token cache invalidation entries",
                    dropped
                );
            }
        }
    });

    // Refresh-token jti table cleanup (every hour). Drops rows whose
    // underlying refresh JWT expired more than the grace window ago. The
    // grace allows admins / forensics to inspect recently-replayed tokens
    // (their `revoked_at` row would otherwise vanish the moment the JWT
    // expired). Issue #1174.
    {
        let db = db.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_secs(90)).await;
            let mut ticker = interval(Duration::from_secs(3600)); // 1 hour
            let grace = chrono::Duration::hours(24);

            loop {
                ticker.tick().await;
                match crate::services::auth_service::AuthService::cleanup_expired_refresh_token_jti(
                    &db, grace,
                )
                .await
                {
                    Ok(0) => {}
                    Ok(n) => {
                        tracing::debug!("Pruned {} expired refresh_token_jti rows", n);
                    }
                    Err(e) => {
                        tracing::warn!("refresh_token_jti cleanup failed: {}", e);
                    }
                }
                match crate::services::auth_service::AuthService::cleanup_expired_totp_pending_jti(
                    &db, grace,
                )
                .await
                {
                    Ok(0) => {}
                    Ok(n) => {
                        tracing::debug!("Pruned {} expired totp_pending_jti rows", n);
                    }
                    Err(e) => {
                        tracing::warn!("totp_pending_jti cleanup failed: {}", e);
                    }
                }
            }
        });
    }

    // Health monitoring (every 60 seconds)
    //
    // Singleton lease (cluster_work): without it every replica writes a
    // health-log row per interval and the alert_state upsert advances
    // consecutive_failures by replica count. Holding (not releasing) the
    // lease pins the job to one healthy replica — the same owner renews on
    // each 60s tick — while the 90s TTL hands the job over within ~30s of
    // that replica dying.
    {
        let db = db.clone();
        let config_clone = config.clone();
        tokio::spawn(async move {
            tokio::time::sleep(jittered_startup_delay(15)).await;
            let monitor = HealthMonitorService::new(db.clone(), MonitorConfig::default());
            let mut ticker = interval(Duration::from_secs(60));

            loop {
                ticker.tick().await;
                let Some(_lease) =
                    crate::services::cluster_work::try_acquire_scheduler_lease_quiet(
                        &db,
                        "health_monitor",
                        90.0,
                    )
                    .await
                else {
                    tracing::debug!("Another replica owns the health monitor lease; skipping");
                    continue;
                };
                match monitor.check_all_services(&config_clone).await {
                    Ok(results) => {
                        for entry in &results {
                            if entry.status != "healthy" {
                                tracing::warn!(
                                    "Service '{}' is {}: {:?}",
                                    entry.service_name,
                                    entry.status,
                                    entry.message
                                );
                            }
                        }
                    }
                    Err(e) => {
                        tracing::warn!("Health monitoring cycle failed: {}", e);
                    }
                }
            }
        });
    }

    // Lifecycle policy execution (configurable check interval)
    //
    // Singleton lease (cluster_work): every replica evaluates the same due
    // policies from last_run_at, so without coordination each due policy
    // executes once per replica (duplicate soft-delete scans, metrics, and
    // last_run bookkeeping). The lease is released after the tick — the
    // fresh last_run_at then gates the next replica's is_policy_due check —
    // and the 1h TTL bounds a crashed mid-execution holder.
    {
        let db = db.clone();
        let check_secs = config.lifecycle_check_interval_secs;
        tokio::spawn(async move {
            tokio::time::sleep(jittered_startup_delay(60)).await;
            let service = LifecycleService::new(db.clone());
            let mut ticker = interval(Duration::from_secs(check_secs));

            loop {
                ticker.tick().await;
                tracing::debug!("Checking for due lifecycle policies");

                let Some(lease) = crate::services::cluster_work::try_acquire_scheduler_lease_quiet(
                    &db,
                    "lifecycle_policy_execution",
                    LIFECYCLE_LEASE_TTL_SECS,
                )
                .await
                else {
                    tracing::debug!("Another replica owns the lifecycle lease; skipping tick");
                    continue;
                };
                // A cycle over many policies can outlive the fixed TTL, which
                // would let a second replica start a duplicate cycle. Keep the
                // lease alive for as long as this one runs.
                let lease_renewal = lease.spawn_renewal(db.clone(), LIFECYCLE_LEASE_TTL_SECS);

                match service.execute_due_policies().await {
                    Ok(results) => {
                        let total_removed: i64 = results.iter().map(|r| r.artifacts_removed).sum();
                        let total_freed: i64 = results.iter().map(|r| r.bytes_freed).sum();
                        if total_removed > 0 {
                            tracing::info!(
                                "Lifecycle cleanup: removed {} artifacts, freed {} bytes across {} policies",
                                total_removed,
                                total_freed,
                                results.len()
                            );
                            metrics_service::record_cleanup("lifecycle", total_removed as u64);
                        }
                    }
                    Err(e) => {
                        tracing::warn!("Lifecycle policy execution failed: {}", e);
                    }
                }

                drop(lease_renewal);
                lease.release(&db).await;
            }
        });
    }

    // Stuck-scan janitor (every `stuck_scan_check_interval_secs`, default 10 min).
    //
    // Pre-allocated `scan_results` rows can be left wedged in `status='running'`
    // when the scan worker crashes mid-flight (OOM, pod evicted, panic, deploy
    // mid-scan). Without this sweep they accumulate forever, polluting
    // dashboards and the dedup path. Reaps rows whose `started_at` predates
    // `stuck_scan_threshold_secs` (issue #1015).
    //
    // Multi-replica safety (PR #1212 audit, H3): `cleanup_stuck_scans_with_limit`
    // takes `pg_try_advisory_xact_lock(STUCK_SCAN_LOCK_ID)` inside the
    // reap transaction so only one replica writes audit rows per tick. The
    // startup delay is jittered (M2) so replicas do not contend on the
    // very first tick. `MissedTickBehavior::Delay` keeps the cadence
    // honest when a tick takes longer than the interval (large backlog).
    {
        let db = db.clone();
        let threshold_secs = config.stuck_scan_threshold_secs;
        let check_secs = config.stuck_scan_check_interval_secs;
        let reap_limit = config.stuck_scan_reap_limit;
        tokio::spawn(async move {
            tokio::time::sleep(jittered_startup_delay(90)).await;
            let service = ScanResultService::new(db);
            let mut ticker = interval(Duration::from_secs(check_secs));
            ticker.set_missed_tick_behavior(MissedTickBehavior::Delay);

            loop {
                ticker.tick().await;
                tracing::debug!("Sweeping for stuck 'running' scan_results rows");

                match service
                    .cleanup_stuck_scans_with_limit(Duration::from_secs(threshold_secs), reap_limit)
                    .await
                {
                    Ok(reaped) if reaped > 0 => {
                        tracing::info!(
                            "Stuck-scan janitor: reaped {} orphaned scan_results rows (threshold: {}s)",
                            reaped,
                            threshold_secs,
                        );
                        metrics_service::record_cleanup("stuck_scans", reaped);
                    }
                    Ok(_) => {}
                    Err(e) => {
                        tracing::warn!("Stuck-scan janitor sweep failed: {}", e);
                    }
                }
            }
        });
    }

    // Storage garbage collection (cron-based, default: hourly)
    {
        let db = db.clone();
        let config_clone = config.clone();
        let gc_registry = storage_registry.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_secs(120)).await;
            // Kept for the blob-GC readiness gate below; the pool itself is
            // moved into the GC service on the next line.
            let gate_db = db.clone();
            // Post-GC storage-stats refresher (#2056): recompute the
            // deduplicated `repository_storage_stats` right after each GC pass
            // so the materialized numbers settle once reclaim has run. This is
            // read-only accounting and never touches the quota path.
            let stats_service = crate::services::storage_stats_service::StorageStatsService::new(
                db.clone(),
                &config_clone.storage_backend,
            );
            // Blob deletion is opt-in (#1408). When BLOB_GC_ENABLED is unset
            // the scheduled pass runs DRY-RUN: it logs what it would reclaim
            // but deletes nothing. Bias to leaking storage over losing data.
            let blob_gc_dry_run = !config_clone.blob_gc_enabled;
            let service =
                crate::services::storage_gc_service::StorageGcService::new(db, gc_registry);

            let normalized = normalize_cron_expression(&config_clone.gc_schedule);
            let gc_schedule = match parse_cron_schedule(&normalized) {
                Some(s) => s,
                None => {
                    tracing::warn!(
                        "Invalid GC_SCHEDULE '{}', falling back to hourly",
                        config_clone.gc_schedule,
                    );
                    Schedule::from_str("0 0 * * * *").expect("default hourly cron is valid")
                }
            };

            loop {
                let next = gc_schedule
                    .upcoming(Utc)
                    .next()
                    .expect("cron schedule should always have a next occurrence");
                let delay = (next - Utc::now())
                    .to_std()
                    .unwrap_or(std::time::Duration::from_secs(3600));
                tokio::time::sleep(delay).await;

                tracing::info!("Running scheduled storage garbage collection");

                match service.run_gc(false).await {
                    Ok(result) => {
                        if result.storage_keys_deleted > 0 {
                            tracing::info!(
                                "Storage GC: deleted {} keys, removed {} artifacts, freed {} bytes",
                                result.storage_keys_deleted,
                                result.artifacts_removed,
                                result.bytes_freed
                            );
                            metrics_service::record_cleanup(
                                "storage_gc",
                                result.artifacts_removed as u64,
                            );
                        }
                        if !result.errors.is_empty() {
                            tracing::warn!(
                                "Storage GC completed with {} errors",
                                result.errors.len()
                            );
                            // Surface the actual messages, not just the count,
                            // so the orchestration-layer log is actionable.
                            for err in &result.errors {
                                tracing::warn!(gc_error = %err, "Storage GC error");
                            }
                        }
                    }
                    Err(e) => {
                        tracing::warn!("Storage garbage collection failed: {}", e);
                    }
                }

                // Blob layer GC runs in the same tick: the manifest GC pass
                // above frees `oci-manifests/...` storage keys, this pass
                // frees `oci-blobs/...` ones that no live manifest references
                // (via `manifest_blob_refs`). Both passes are independent —
                // blob GC reads its own snapshot from `oci_blobs` and does
                // not depend on the artifact-level GC having run first.
                //
                // SAFETY (#1408): blob deletion is irreversible, so two
                // safeguards gate the destructive path here, in addition to
                // the grace window and locked per-row re-check inside
                // `run_blob_gc`:
                //
                //  1. Readiness gate (design from #1409 review, finding 3):
                //     blob GC trusts `manifest_blob_refs` as the live blob
                //     set, so it must not delete until a successful backfill
                //     has populated refs for every live image manifest.
                //     Otherwise a partial or failed startup backfill (e.g.
                //     object storage briefly unreachable when bodies were
                //     read) would make live layers look orphaned and GC would
                //     delete them. We skip the *live* pass while refs are
                //     incomplete or the readiness query itself fails; the
                //     next tick re-checks and resumes once refs are complete.
                //
                //  2. Dry-run default: unless BLOB_GC_ENABLED is set, the
                //     pass runs in dry-run mode and never deletes. A dry-run
                //     pass is always safe to run, even when the readiness
                //     gate is not yet satisfied, so we only enforce the gate
                //     when about to delete for real.
                let mut blob_gc_dry_run_this_tick = blob_gc_dry_run;
                if !blob_gc_dry_run_this_tick {
                    match crate::services::manifest_blob_refs_backfill::any_live_manifest_missing_refs(
                        &gate_db,
                    )
                    .await
                    {
                        Ok(true) => {
                            // #3285: name the offending digests. Without this,
                            // diagnosing a stuck gate meant reconstructing the
                            // gate query by hand against the database.
                            let blockers =
                                crate::services::manifest_blob_refs_backfill::list_live_manifests_missing_refs(
                                    &gate_db,
                                    crate::services::manifest_blob_refs_backfill::GATE_BLOCKER_SAMPLE_LIMIT,
                                )
                                .await
                                .unwrap_or_default();
                            tracing::warn!(
                                blocking_manifests = %crate::services::manifest_blob_refs_backfill::describe_gate_blockers(&blockers),
                                "Blob GC: manifest_blob_refs is incomplete for one or more live \
                                 image manifests (startup backfill unfinished or partially \
                                 failed); forcing dry-run this tick and retrying next tick"
                            );
                            blob_gc_dry_run_this_tick = true;
                        }
                        Err(e) => {
                            tracing::warn!(
                                "Blob GC: could not verify manifest_blob_refs readiness ({}); \
                                 forcing dry-run this tick",
                                e
                            );
                            blob_gc_dry_run_this_tick = true;
                        }
                        Ok(false) => {}
                    }
                }

                // Two-phase mark-and-sweep (#1660). Phase A marks aged orphan
                // candidates (`pending_delete_at`, a pure row update with no
                // storage I/O) every tick; Phase B sweeps blobs marked at
                // least `blob_gc_sweep_grace_secs` ago that are still orphan,
                // deleting storage then row under the same push-path row lock.
                // Splitting the phases keeps storage deletion out of the
                // commit-then-delete TOCTOU: a re-push in the mark->sweep
                // window resurrects the blob (clears the marker under the lock)
                // so the sweep skips it. Both phases honour the dry-run /
                // readiness gate above — in dry-run neither writes nor clears a
                // marker and nothing is deleted.
                match service.run_blob_gc_mark(blob_gc_dry_run_this_tick).await {
                    Ok(result) => {
                        if result.dry_run && result.storage_keys_deleted > 0 {
                            tracing::info!(
                                "Blob GC (dry-run): would mark {} orphan blobs pending deletion \
                                 (set BLOB_GC_ENABLED=true to enable mark-and-sweep)",
                                result.storage_keys_deleted,
                            );
                        } else if !result.dry_run && result.storage_keys_deleted > 0 {
                            tracing::info!(
                                "Blob GC: marked {} orphan blobs pending deletion",
                                result.storage_keys_deleted,
                            );
                        }
                        if !result.errors.is_empty() {
                            tracing::warn!(
                                "Blob GC mark completed with {} errors",
                                result.errors.len()
                            );
                            for err in &result.errors {
                                tracing::warn!(gc_error = %err, "Blob GC mark error");
                            }
                        }
                    }
                    Err(e) => {
                        tracing::warn!("Blob GC mark pass failed: {}", e);
                    }
                }

                match service
                    .run_blob_gc_sweep(
                        blob_gc_dry_run_this_tick,
                        config_clone.blob_gc_sweep_grace_secs as i64,
                    )
                    .await
                {
                    Ok(result) => {
                        if result.dry_run && result.storage_keys_deleted > 0 {
                            tracing::info!(
                                "Blob GC (dry-run): would sweep {} marked blob objects, {} bytes \
                                 (set BLOB_GC_ENABLED=true to delete)",
                                result.storage_keys_deleted,
                                result.bytes_freed
                            );
                        } else if !result.dry_run && result.storage_keys_deleted > 0 {
                            tracing::info!(
                                "Blob GC: swept {} blob objects, freed {} bytes",
                                result.storage_keys_deleted,
                                result.bytes_freed
                            );
                            metrics_service::record_cleanup(
                                "blob_gc",
                                result.storage_keys_deleted as u64,
                            );
                        }
                        if !result.errors.is_empty() {
                            tracing::warn!(
                                "Blob GC sweep completed with {} errors",
                                result.errors.len()
                            );
                            for err in &result.errors {
                                tracing::warn!(gc_error = %err, "Blob GC sweep error");
                            }
                        }
                    }
                    Err(e) => {
                        tracing::warn!("Blob GC sweep pass failed: {}", e);
                    }
                }

                // Post-GC refresh (#2056): recompute deduplicated storage stats
                // now that this tick's reclaim has settled so the materialized
                // table reflects the post-GC footprint. Reporting-only.
                if let Err(e) = stats_service.recompute_all().await {
                    tracing::warn!("Post-GC storage-stats refresh failed: {}", e);
                }
            }
        });
    }

    // Deduplicated storage-stats refresher (cron-based, default: every 4h).
    // Materializes `repository_storage_stats` / `instance_storage_stats` so the
    // storage API reads are O(1). Independent of GC so stats stay fresh even
    // when nothing is reclaimed (#2056). Read-only: never affects quota.
    {
        let db = db.clone();
        let config_clone = config.clone();
        tokio::spawn(async move {
            tokio::time::sleep(jittered_startup_delay(150)).await;
            let stats_service = crate::services::storage_stats_service::StorageStatsService::new(
                db,
                &config_clone.storage_backend,
            );

            let normalized = normalize_cron_expression(&config_clone.storage_stats_schedule);
            let schedule = match parse_cron_schedule(&normalized) {
                Some(s) => s,
                None => {
                    tracing::warn!(
                        "Invalid STORAGE_STATS_SCHEDULE '{}', falling back to every 4h",
                        config_clone.storage_stats_schedule,
                    );
                    Schedule::from_str("0 0 */4 * * *").expect("default 4-hourly cron is valid")
                }
            };

            loop {
                let next = schedule
                    .upcoming(Utc)
                    .next()
                    .expect("cron schedule should always have a next occurrence");
                let delay = (next - Utc::now())
                    .to_std()
                    .unwrap_or(std::time::Duration::from_secs(4 * 3600));
                tokio::time::sleep(delay).await;

                tracing::debug!("Running scheduled deduplicated storage-stats refresh");
                if let Err(e) = stats_service.recompute_all().await {
                    tracing::warn!("Scheduled storage-stats refresh failed: {}", e);
                }
            }
        });
    }

    // Usage-ledger reconciler (PF-007 #2523, every 30 min).
    // Trues up `repository_usage_ledger` against the authoritative live sums
    // so drift from any write path that did not maintain the ledger self-heals.
    // Cheap index-ranged aggregates off the request path; the mandatory safety
    // net behind the ledger-serialized quota admission.
    {
        let db = db.clone();
        tokio::spawn(async move {
            tokio::time::sleep(jittered_startup_delay(200)).await;
            let repo_service = crate::services::repository_service::RepositoryService::new(db);
            let mut ticker = interval(Duration::from_secs(1800));
            ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);
            loop {
                ticker.tick().await;
                match repo_service.reconcile_all_usage_ledgers().await {
                    Ok(report) if report.repositories_repaired > 0 => {
                        tracing::warn!(
                            repositories_checked = report.repositories_checked,
                            repositories_repaired = report.repositories_repaired,
                            drift_bytes = report.total_drift_bytes,
                            "Repaired repository_usage_ledger drift"
                        );
                    }
                    Ok(_) => {}
                    Err(e) => {
                        tracing::warn!("Usage-ledger reconciliation failed: {}", e);
                    }
                }
            }
        });
    }

    // Backup schedule execution (check every 5 minutes)
    {
        let db = db.clone();
        let config_clone = config.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_secs(45)).await;
            let mut ticker = interval(Duration::from_secs(300)); // 5 minutes

            loop {
                ticker.tick().await;
                if let Err(e) = execute_due_backup_schedules(&db, &config_clone).await {
                    tracing::warn!("Backup schedule check failed: {}", e);
                }
            }
        });
    }

    // Sync policy re-evaluation (every 5 minutes)
    {
        let db = db.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_secs(120)).await;
            let mut ticker = interval(Duration::from_secs(300)); // 5 minutes

            loop {
                ticker.tick().await;
                tracing::debug!("Running periodic sync policy evaluation");

                let svc = SyncPolicyService::new(db.clone());
                if let Err(e) = svc.evaluate_policies().await {
                    tracing::warn!("Periodic sync policy evaluation failed: {}", e);
                }
            }
        });
    }

    // Webhook delivery retry processor (every 30 seconds)
    {
        let db = db.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_secs(15)).await;
            let mut ticker = interval(Duration::from_secs(30));
            loop {
                ticker.tick().await;
                if let Err(e) = crate::api::handlers::webhooks::process_webhook_retries(&db).await {
                    tracing::warn!("Webhook retry processing failed: {}", e);
                }
            }
        });
    }

    // Webhook previous-secret cleanup (every 10 minutes). Clears the
    // overlap-window ciphertext once the rotation grace period expires.
    {
        let db = db.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_secs(60)).await;
            let mut ticker = interval(Duration::from_secs(600));
            loop {
                ticker.tick().await;
                match crate::api::handlers::webhooks::cleanup_expired_previous_secrets(&db).await {
                    Ok(0) => {}
                    Ok(n) => {
                        tracing::info!("Cleared {} expired webhook previous-secret entries", n)
                    }
                    Err(e) => tracing::warn!("Webhook previous-secret cleanup failed: {}", e),
                }
            }
        });
    }

    // Curation upstream metadata sync (checks every 5 minutes for repos due for sync)
    {
        let db = db.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_secs(45)).await;
            let mut ticker = interval(Duration::from_secs(300));

            loop {
                ticker.tick().await;
                tracing::debug!("Checking for curation repos due for upstream sync");

                // Cluster-lease the sweep (#2357 S11): only one replica runs the
                // scheduled curation sync per tick. Without this every replica
                // fans out N concurrent upstream syncs. A TTL slightly above the
                // 300s tick keeps the job pinned to its current holder; if the
                // lease table is unreachable the replica skips the tick rather
                // than crashing the loop.
                let lease = crate::services::cluster_work::try_acquire_scheduler_lease_quiet(
                    &db,
                    "curation_sync",
                    CURATION_SYNC_LEASE_TTL_SECS,
                )
                .await;
                if lease.is_none() {
                    tracing::debug!(
                        "Curation sync: another replica holds the lease; skipping tick"
                    );
                    continue;
                }

                // A sweep over many staging repos can outlive the TTL (each
                // repo is an upstream fetch + evaluate), which would let a
                // second replica start a duplicate cycle while this one is
                // still running. Heartbeat the lease for the whole cycle.
                let renewal = lease
                    .as_ref()
                    .map(|l| l.spawn_renewal(db.clone(), CURATION_SYNC_LEASE_TTL_SECS));

                if let Err(e) = run_curation_sync_cycle(&db, None).await {
                    tracing::warn!("Curation sync cycle failed: {}", e);
                }

                drop(renewal);
                if let Some(lease) = lease {
                    lease.release(&db).await;
                }
            }
        });
    }

    // Chunked upload session cleanup + orphaned incus staging sweep (every hour)
    {
        let db = db.clone();
        // #1654: the DB-tracked session reaper below only covers uploads that
        // inserted a session row. A monolithic incus upload — or a chunked one
        // killed before its INSERT — stages bytes to a file with no DB row, so
        // a receive cut short by OOM / eviction / restart leaves an orphan that
        // nothing reaps. `sweep_orphan_staging_files` exists but was only wired
        // to the manual admin /cleanup endpoint (gap in merged #1622). Run it on
        // the same hourly cadence and 24h threshold as the session reaper.
        let storage_path = config.storage_path.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_secs(120)).await;
            let mut ticker = interval(Duration::from_secs(3600)); // 1 hour

            loop {
                ticker.tick().await;
                tracing::debug!("Cleaning up expired upload sessions");

                match crate::services::upload_service::UploadService::cleanup_expired(&db).await {
                    Ok(count) if count > 0 => {
                        tracing::info!("Cleaned up {} expired upload sessions", count);
                    }
                    Err(e) => {
                        tracing::warn!("Upload session cleanup failed: {}", e);
                    }
                    _ => {}
                }

                let swept =
                    crate::api::handlers::incus::sweep_orphan_staging_files(&storage_path, 24)
                        .await;
                if swept > 0 {
                    tracing::info!("Swept {} orphaned incus staging file(s)", swept);
                }
            }
        });
    }

    // Password expiry notifications (configurable interval, default: hourly)
    if config.password_expiry_days > 0 {
        if let Some(smtp) = smtp_service {
            let db = db.clone();
            let expiry_days = config.password_expiry_days;
            let warning_tiers = config.password_expiry_warning_days.clone();
            let check_secs = config.password_expiry_check_interval_secs;
            tokio::spawn(async move {
                tokio::time::sleep(Duration::from_secs(60)).await;
                let mut ticker = interval(Duration::from_secs(check_secs));

                loop {
                    ticker.tick().await;
                    tracing::debug!("Checking for password expiry notifications");

                    match crate::services::password_expiry_service::send_expiry_notifications(
                        &db,
                        &smtp,
                        expiry_days,
                        &warning_tiers,
                    )
                    .await
                    {
                        Ok(count) if count > 0 => {
                            tracing::info!("Sent {} password expiry notification(s)", count,);
                        }
                        Err(e) => {
                            tracing::warn!("Password expiry notification check failed: {}", e);
                        }
                        _ => {}
                    }
                }
            });
            tracing::info!(
                "Background schedulers started: metrics, health monitor, lifecycle, stuck-scan janitor, backup schedules, sync policies, webhook retries, curation sync, upload cleanup, password expiry notifications"
            );
        } else {
            tracing::info!(
                "Background schedulers started: metrics, health monitor, lifecycle, stuck-scan janitor, backup schedules, sync policies, webhook retries, curation sync, upload cleanup (password expiry notifications skipped: SMTP not configured)"
            );
        }
    } else {
        tracing::info!(
            "Background schedulers started: metrics, health monitor, lifecycle, stuck-scan janitor, backup schedules, sync policies, webhook retries, curation sync, upload cleanup"
        );
    }
    // Download-ticket cleanup (every 10 minutes).
    //
    // Tickets self-expire on use via `expires_at > NOW()` in
    // `validate_download_ticket`, so this is hygiene rather than correctness.
    // 30-second TTL plus high churn means rows accumulate quickly under load
    // even though each row is small. A 10-minute cadence keeps the table from
    // unbounded growth without spamming the database.
    {
        let db = db.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_secs(60)).await;
            let mut ticker = interval(Duration::from_secs(600)); // 10 minutes

            loop {
                ticker.tick().await;
                tracing::debug!("Cleaning up expired download tickets");

                match crate::services::auth_config_service::AuthConfigService::cleanup_expired_download_tickets(&db).await {
                    Ok(count) if count > 0 => {
                        tracing::debug!("Cleaned up {} expired download tickets", count);
                    }
                    Err(e) => {
                        tracing::warn!("Download ticket cleanup failed: {}", e);
                    }
                    _ => {}
                }
            }
        });
    }

    // Age-gate auto-approval sweep (every 5 minutes).
    //
    // The npm packument / PyPI simple-index filters intentionally do NOT flip a
    // pending review to `approved` when its version crosses the age threshold —
    // that would be a write on a cacheable metadata GET. Instead this sweep does
    // the bookkeeping off the request path: one UPDATE per tick approves every
    // pending review whose version has aged past its repo's threshold. Serving is
    // unaffected in the interim (the filters decide directly from the publish
    // timestamp), so this only keeps the review queue's persisted status accurate.
    // The UPDATE is idempotent and row-locked, so running it on multiple replicas
    // is safe; startup jitter de-synchronizes replicas' first tick.
    {
        let db = db.clone();
        let event_bus = event_bus.clone();
        tokio::spawn(async move {
            tokio::time::sleep(jittered_startup_delay(75)).await;
            let service = AgeGateService::new(db, event_bus);
            let mut ticker = interval(Duration::from_secs(300)); // 5 minutes
            ticker.set_missed_tick_behavior(MissedTickBehavior::Delay);

            loop {
                ticker.tick().await;
                match service.auto_approve_aged_reviews().await {
                    Ok(n) if n > 0 => {
                        tracing::info!("Age-gate sweep: auto-approved {} aged review(s)", n);
                    }
                    Ok(_) => {}
                    Err(e) => {
                        tracing::warn!("Age-gate auto-approval sweep failed: {}", e);
                    }
                }
            }
        });
    }

    tracing::info!(
        "Background schedulers started: metrics, health monitor, lifecycle, stuck-scan janitor, backup schedules, sync policies, webhook retries, curation sync, upload cleanup, download ticket cleanup, age-gate auto-approval"
    );
}

/// A due occurrence discovered by the scheduler's bounded candidate query.
#[derive(Debug, sqlx::FromRow)]
struct DueBackupSchedule {
    pub id: uuid::Uuid,
    pub due_at: chrono::DateTime<Utc>,
}

/// The current backup schedule payload returned by the claim statement.
#[derive(Debug, sqlx::FromRow)]
struct BackupScheduleRow {
    pub id: uuid::Uuid,
    pub name: String,
    pub backup_type: BackupType,
    pub include_repositories: Option<Vec<uuid::Uuid>>,
}

/// Raw row decoded from the atomic schedule claim statement.
#[derive(Debug, sqlx::FromRow)]
struct ClaimedBackupScheduleRow {
    pub run_id: uuid::Uuid,
    pub claim_token: uuid::Uuid,
    pub name: String,
    pub backup_type: BackupType,
    pub include_repositories: Option<Vec<uuid::Uuid>>,
    pub scheduled_for: chrono::DateTime<Utc>,
}

/// A short failover boundary kept alive by a token-guarded heartbeat while
/// archive creation/execution is active.
const BACKUP_RUN_CLAIM_TTL_SECS: f64 = 15.0 * 60.0;

/// Proof that this worker owns one durable backup occurrence.
#[derive(Clone, Copy)]
struct BackupRunClaim {
    run_id: uuid::Uuid,
    claim_token: uuid::Uuid,
    scheduled_for: chrono::DateTime<Utc>,
}

/// A due schedule payload and the proof that this worker claimed it from the
/// same database snapshot.
struct ClaimedBackupSchedule {
    schedule: BackupScheduleRow,
    claim: BackupRunClaim,
}

/// Claim `(schedule_id, scheduled_for)` before any backup side effect.
///
/// The candidate query is only a bounded discovery pass. This statement locks
/// and rechecks the schedule before inserting the run, so a schedule disabled
/// or rescheduled after discovery cannot launch a stale backup. The execution
/// payload also comes from this claim-time snapshot rather than the candidate
/// row.
async fn claim_backup_schedule_run(
    db: &PgPool,
    schedule_id: uuid::Uuid,
    scheduled_for: chrono::DateTime<Utc>,
    claimed_by: &str,
    claim_ttl_secs: f64,
) -> crate::error::Result<Option<ClaimedBackupSchedule>> {
    let row = sqlx::query_as::<_, ClaimedBackupScheduleRow>(
        r#"
        WITH eligible AS MATERIALIZED (
            SELECT id, name, backup_type, include_repositories,
                   COALESCE(next_run_at, 'epoch'::timestamptz) AS due_at
            FROM backup_schedules
            WHERE id = $1
              AND is_enabled = true
              AND (next_run_at IS NULL OR next_run_at <= NOW())
              AND COALESCE(next_run_at, 'epoch'::timestamptz) = $2
            FOR UPDATE
        ), claimed AS (
            INSERT INTO backup_schedule_runs
                (schedule_id, scheduled_for, claimed_by, claim_token, claim_expires_at)
            SELECT id, due_at, $3, gen_random_uuid(),
                   NOW() + make_interval(secs => $4)
            FROM eligible
            -- Disambiguate INSERT ... SELECT from the ON CONFLICT clause.
            WHERE true
            ON CONFLICT (schedule_id, scheduled_for) DO UPDATE
            SET claimed_by = EXCLUDED.claimed_by,
                claim_token = EXCLUDED.claim_token,
                claim_expires_at = EXCLUDED.claim_expires_at,
                status = 'running',
                backup_id = NULL,
                error_message = NULL,
                started_at = NOW(),
                completed_at = NULL
            WHERE backup_schedule_runs.status = 'running'
              AND backup_schedule_runs.claim_expires_at <= NOW()
            RETURNING id AS run_id, claim_token, schedule_id, scheduled_for
        )
        SELECT c.run_id, c.claim_token, e.name, e.backup_type,
               e.include_repositories, c.scheduled_for
        FROM claimed c
        JOIN eligible e
          ON e.id = c.schedule_id
         AND e.due_at = c.scheduled_for
        "#,
    )
    .bind(schedule_id)
    .bind(scheduled_for)
    .bind(claimed_by)
    .bind(claim_ttl_secs)
    .fetch_optional(db)
    .await
    .map_err(|e| crate::error::AppError::Database(e.to_string()))?;

    Ok(row.map(|row| ClaimedBackupSchedule {
        schedule: BackupScheduleRow {
            id: schedule_id,
            name: row.name,
            backup_type: row.backup_type,
            include_repositories: row.include_repositories,
        },
        claim: BackupRunClaim {
            run_id: row.run_id,
            claim_token: row.claim_token,
            scheduled_for: row.scheduled_for,
        },
    }))
}

async fn renew_backup_schedule_run_claim(
    db: &PgPool,
    claim: &BackupRunClaim,
    claim_ttl_secs: f64,
) -> crate::error::Result<bool> {
    let result = sqlx::query(
        r#"
        UPDATE backup_schedule_runs
        SET claim_expires_at = NOW() + make_interval(secs => $3)
        WHERE id = $1
          AND claim_token = $2
          AND status = 'running'
        "#,
    )
    .bind(claim.run_id)
    .bind(claim.claim_token)
    .bind(claim_ttl_secs)
    .execute(db)
    .await
    .map_err(|e| crate::error::AppError::Database(e.to_string()))?;

    Ok(result.rows_affected() == 1)
}

fn spawn_backup_run_renewal(
    db: PgPool,
    claim: BackupRunClaim,
    claim_ttl_secs: f64,
) -> crate::services::cluster_work::RenewalGuard {
    crate::services::cluster_work::spawn_renewal_loop(
        format!("backup schedule run {}", claim.run_id),
        claim_ttl_secs,
        move || {
            let db = db.clone();
            async move {
                renew_backup_schedule_run_claim(&db, &claim, claim_ttl_secs)
                    .await
                    .map_err(|e| e.to_string())
            }
        },
    )
}

/// Token-fence the run outcome and advance the schedule in one transaction.
///
/// Locking and reading the schedule at finalize time means a long-running
/// backup uses the administrator's current cron expression. The schedule is
/// advanced only if it still points at the occurrence this claim satisfied;
/// an explicit reschedule wins and is not overwritten.
async fn finalize_backup_schedule_run(
    db: &PgPool,
    schedule_id: uuid::Uuid,
    claim: &BackupRunClaim,
    succeeded: bool,
    backup_id: Option<uuid::Uuid>,
    error_message: Option<&str>,
) -> crate::error::Result<bool> {
    let mut tx = db
        .begin()
        .await
        .map_err(|e| crate::error::AppError::Database(e.to_string()))?;

    let schedule: Option<(String, chrono::DateTime<Utc>)> = sqlx::query_as(
        r#"
        SELECT cron_expression, COALESCE(next_run_at, 'epoch'::timestamptz)
        FROM backup_schedules
        WHERE id = $1
        FOR UPDATE
        "#,
    )
    .bind(schedule_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(|e| crate::error::AppError::Database(e.to_string()))?;

    let Some((current_cron, current_due_at)) = schedule else {
        tx.rollback()
            .await
            .map_err(|e| crate::error::AppError::Database(e.to_string()))?;
        return Ok(false);
    };

    let run_update = sqlx::query(
        r#"
        UPDATE backup_schedule_runs
        SET status = $3,
            backup_id = $4,
            error_message = $5,
            completed_at = NOW()
        WHERE id = $1
          AND claim_token = $2
          AND status = 'running'
        "#,
    )
    .bind(claim.run_id)
    .bind(claim.claim_token)
    .bind(if succeeded { "completed" } else { "failed" })
    .bind(backup_id)
    .bind(error_message)
    .execute(&mut *tx)
    .await
    .map_err(|e| crate::error::AppError::Database(e.to_string()))?;

    if run_update.rows_affected() != 1 {
        tx.rollback()
            .await
            .map_err(|e| crate::error::AppError::Database(e.to_string()))?;
        return Ok(false);
    }

    if current_due_at == claim.scheduled_for {
        let next_run = compute_next_run(&current_cron);
        if next_run.is_none() {
            tracing::warn!(
                schedule_id = %schedule_id,
                cron_expression = %current_cron,
                "Backup schedule has no further occurrence; disabling it"
            );
        }
        // A valid cron with no future occurrence (a year-qualified expression
        // whose window has passed) yields NULL here. Leaving such a schedule
        // enabled makes it permanently due at the 'epoch' sentinel, and once
        // its terminal `(schedule_id, 'epoch')` run row exists no claim can
        // ever succeed again — while it still occupies one of the five
        // candidate slots. Disabling it drops it out of the candidate query
        // instead of silently starving live schedules. `is_enabled` is
        // otherwise left untouched so an administrator who disabled the
        // schedule mid-run is not overridden.
        let schedule_update = sqlx::query(
            r#"
            UPDATE backup_schedules
            SET last_run_at = NOW(),
                next_run_at = $2,
                is_enabled = CASE WHEN $2::timestamptz IS NULL THEN false ELSE is_enabled END,
                updated_at = NOW()
            WHERE id = $1
              AND COALESCE(next_run_at, 'epoch'::timestamptz) = $3
            "#,
        )
        .bind(schedule_id)
        .bind(next_run)
        .bind(claim.scheduled_for)
        .execute(&mut *tx)
        .await
        .map_err(|e| crate::error::AppError::Database(e.to_string()))?;

        if schedule_update.rows_affected() != 1 {
            return Err(crate::error::AppError::Database(
                "backup schedule changed despite its finalize lock".to_string(),
            ));
        }
    } else {
        tracing::info!(
            schedule_id = %schedule_id,
            claimed_due_at = %claim.scheduled_for,
            current_due_at = %current_due_at,
            "Backup run finalized without overwriting a rescheduled occurrence"
        );
    }

    tx.commit()
        .await
        .map_err(|e| crate::error::AppError::Database(e.to_string()))?;
    Ok(true)
}

/// Check for due backup schedules and execute them.
async fn execute_due_backup_schedules(db: &PgPool, config: &Config) -> crate::error::Result<()> {
    // Find schedules where next_run_at <= now
    let due_schedules = sqlx::query_as::<_, DueBackupSchedule>(
        r#"
        SELECT id, COALESCE(next_run_at, 'epoch'::timestamptz) AS due_at
        FROM backup_schedules
        WHERE is_enabled = true
          AND (next_run_at IS NULL OR next_run_at <= NOW())
        ORDER BY next_run_at ASC NULLS FIRST
        LIMIT 5
        "#,
    )
    .fetch_all(db)
    .await
    .map_err(|e| crate::error::AppError::Database(e.to_string()))?;

    if due_schedules.is_empty() {
        return Ok(());
    }

    // Handle that reads ARTIFACT BYTES: must carry the configured `S3_PREFIX`
    // so it resolves the keys primary storage wrote artifacts under (#3171).
    let storage = match StorageService::artifact_source_from_config(config).await {
        Ok(s) => Arc::new(s),
        Err(e) => {
            tracing::error!(
                "Failed to create storage service for scheduled backups: {}",
                e
            );
            return Err(e);
        }
    };

    // Handle that backup ARCHIVES live on. Kept prefix-less (the historical
    // layout) so archives written before #3171 stay reachable.
    let archive_root = match StorageService::from_config(config).await {
        Ok(s) => Arc::new(s),
        Err(e) => {
            tracing::error!(
                "Failed to create archive storage service for scheduled backups: {}",
                e
            );
            return Err(e);
        }
    };

    // Route backup archives to a dedicated bucket when BACKUP_S3_BUCKET is set
    // (#2507); otherwise this is a clone of the prefix-less archive handle.
    let archive_storage =
        match StorageService::backup_archive_from_config(config, &archive_root).await {
            Ok(s) => s,
            Err(e) => {
                tracing::error!(
                    "Failed to create backup archive storage for scheduled backups: {}",
                    e
                );
                return Err(e);
            }
        };

    for due_schedule in &due_schedules {
        let claimed = match claim_backup_schedule_run(
            db,
            due_schedule.id,
            due_schedule.due_at,
            crate::services::cluster_work::WorkerIdentity::for_process().as_str(),
            BACKUP_RUN_CLAIM_TTL_SECS,
        )
        .await
        {
            Ok(Some(claim)) => claim,
            Ok(None) => {
                tracing::debug!(
                    schedule_id = %due_schedule.id,
                    due_at = %due_schedule.due_at,
                    "Backup occurrence changed, disabled, already claimed, or completed"
                );
                continue;
            }
            Err(e) => {
                tracing::warn!(
                    schedule_id = %due_schedule.id,
                    due_at = %due_schedule.due_at,
                    error = %e,
                    "Failed to claim due backup occurrence"
                );
                continue;
            }
        };
        let ClaimedBackupSchedule {
            schedule: schedule_row,
            claim,
        } = claimed;

        tracing::info!(
            "Executing scheduled backup '{}' (type: {:?})",
            schedule_row.name,
            schedule_row.backup_type
        );

        let service = BackupService::with_archive_storage(
            db.clone(),
            storage.clone(),
            archive_storage.clone(),
        );
        let run_renewal = spawn_backup_run_renewal(db.clone(), claim, BACKUP_RUN_CLAIM_TTL_SECS);

        // Create and execute the backup
        let create_result = service
            .create(CreateBackupRequest {
                backup_type: schedule_row.backup_type,
                repository_ids: schedule_row.include_repositories.clone(),
                exclude_repository_ids: None, // schedules use include-lists today
                since: None,                  // schedules back up every artifact (#2789)
                created_by: None,             // system-initiated
                name: None,                   // scheduled backups keep the default {uuid} name
            })
            .await;

        let backup_type_str = format!("{:?}", schedule_row.backup_type).to_lowercase();
        let start = std::time::Instant::now();

        let (succeeded, backup_id, error_message) = match create_result {
            Ok(backup) => match service.execute(backup.id).await {
                Ok(completed) => {
                    let elapsed = start.elapsed().as_secs_f64();
                    tracing::info!(
                        "Scheduled backup '{}' completed: {} bytes, {} artifacts",
                        schedule_row.name,
                        completed.size_bytes.unwrap_or(0),
                        completed.artifact_count.unwrap_or(0)
                    );
                    metrics_service::record_backup(&backup_type_str, true, elapsed);
                    (true, Some(backup.id), None)
                }
                Err(e) => {
                    let elapsed = start.elapsed().as_secs_f64();
                    tracing::error!(
                        "Scheduled backup '{}' execution failed: {}",
                        schedule_row.name,
                        e
                    );
                    metrics_service::record_backup(&backup_type_str, false, elapsed);
                    (false, Some(backup.id), Some(e.to_string()))
                }
            },
            Err(e) => {
                let elapsed = start.elapsed().as_secs_f64();
                tracing::error!(
                    "Failed to create scheduled backup '{}': {}",
                    schedule_row.name,
                    e
                );
                metrics_service::record_backup(&backup_type_str, false, elapsed);
                (false, None, Some(e.to_string()))
            }
        };

        let finalized = finalize_backup_schedule_run(
            db,
            schedule_row.id,
            &claim,
            succeeded,
            backup_id,
            error_message.as_deref(),
        )
        .await;
        drop(run_renewal);

        match finalized {
            Ok(true) => {}
            Ok(false) => tracing::warn!(
                run_id = %claim.run_id,
                "Backup completed after its run claim was lost; schedule was not advanced"
            ),
            Err(e) => tracing::warn!(
                run_id = %claim.run_id,
                error = %e,
                "Failed to atomically finalize backup run and schedule"
            ),
        }
    }

    Ok(())
}

/// Normalize a cron expression: if 5-field, prepend "0 " for the seconds field.
pub(crate) fn normalize_cron_expression(cron_expr: &str) -> String {
    if cron_expr.split_whitespace().count() == 5 {
        format!("0 {}", cron_expr)
    } else {
        cron_expr.to_string()
    }
}

/// Parse a (possibly already normalized) cron expression into a Schedule.
/// Returns None if the expression is invalid.
pub(crate) fn parse_cron_schedule(normalized: &str) -> Option<Schedule> {
    Schedule::from_str(normalized).ok()
}

/// Parse a cron expression and compute the next run time.
///
/// An *invalid* expression falls back to 24h from now, so a typo does not
/// silently stop a schedule. `None` means something different and narrower:
/// the expression parsed but has no future occurrence at all (the `cron`
/// crate accepts 7-field year-qualified expressions such as
/// `0 0 3 * * * 2020`). Callers must not treat that as "run again soon" —
/// see [`finalize_backup_schedule_run`], which disables the schedule.
fn compute_next_run(cron_expr: &str) -> Option<chrono::DateTime<Utc>> {
    let normalized = normalize_cron_expression(cron_expr);

    match parse_cron_schedule(&normalized) {
        Some(schedule) => schedule.upcoming(Utc).next(),
        None => {
            tracing::warn!(
                "Invalid cron expression '{}'. Falling back to 24h from now.",
                cron_expr,
            );
            Some(Utc::now() + chrono::Duration::hours(24))
        }
    }
}

/// Update Prometheus gauge metrics from database state.
async fn update_gauge_metrics(db: &PgPool) -> crate::error::Result<()> {
    let stats = sqlx::query_as::<_, GaugeStats>(
        r#"
        SELECT
            (SELECT COUNT(*) FROM repositories) as repos,
            (SELECT COUNT(*) FROM artifacts WHERE is_deleted = false) as artifacts,
            (SELECT COALESCE(SUM(size_bytes), 0)::BIGINT FROM artifacts WHERE is_deleted = false) as storage,
            (SELECT COUNT(*) FROM users) as users
        "#,
    )
    .fetch_one(db)
    .await
    .map_err(|e| crate::error::AppError::Database(e.to_string()))?;

    metrics_service::set_storage_gauge(stats.storage, stats.artifacts, stats.repos);
    metrics_service::set_user_gauge(stats.users);
    metrics_service::set_db_pool_gauges(db);

    Ok(())
}

/// One row of the curation-sync work query: `(staging_id, format,
/// remote_id, upstream_url, default_action, sync_interval_secs,
/// trusted_gpg_key, allow_unverified)`. Named to keep the `query_as` type off
/// clippy's `type_complexity` radar (#2357 added the trusted-key column; #2569
/// added the fail-closed opt-out flag).
type CurationSyncRow = (
    uuid::Uuid,
    String,
    uuid::Uuid,
    String,
    String,
    i32,
    Option<String>,
    bool,
);

/// Outcome of the keyless RPM curation-sync gate (#2569). When no trusted GPG
/// key is configured, the sync no longer defaults open: it is fail-closed and
/// ingests nothing unless the repo has explicitly opted into unverified
/// upstream ingest.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum KeylessSync {
    /// The repo opted into unverified upstream (`curation_allow_unverified =
    /// true`): proceed, but treat the batch as UNVERIFIED (no checksum-chain
    /// enforcement — the legacy pre-#2357 behavior, preserved for existing
    /// keyless repos that opt in).
    ProceedUnverified,
    /// No trusted key and no opt-in: refuse (fail-closed default). Skip this
    /// repo — zero packages ingested — rather than trusting unauthenticated
    /// upstream metadata.
    Refuse,
}

/// Decide the keyless-upstream outcome (#2569). Pure so the fail-closed default
/// is unit-testable without any DB or network I/O: `false` (no opt-in) must be
/// `Refuse`; only an explicit `curation_allow_unverified = true` opts back into
/// the legacy unverified-ingest behavior.
fn keyless_sync_decision(allow_unverified: bool) -> KeylessSync {
    if allow_unverified {
        KeylessSync::ProceedUnverified
    } else {
        KeylessSync::Refuse
    }
}

/// Find all staging repos with curation enabled, fetch upstream metadata, and evaluate new packages.
///
/// When `only_repo` is `Some(id)` the cycle is restricted to that single staging
/// repository — the code path the manual `POST /curation/repos/{key}/sync`
/// trigger (#2357) uses; when `None` it sweeps every due repo (the scheduled
/// path). The scheduled invocation is cluster-leased by its caller so only one
/// replica sweeps per tick.
pub(crate) async fn run_curation_sync_cycle(
    db: &PgPool,
    only_repo: Option<uuid::Uuid>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    use crate::services::curation_service::CurationService;
    use crate::services::curation_sync;

    // Find repos due for sync. `trusted_gpg_key` (#2357) is read from the remote
    // so the RPM path can authenticate repomd.xml before ingest. The optional
    // `only_repo` filter scopes the sweep to one repo for the manual trigger.
    //
    // `curation_sync_interval_secs` is now honored via
    // `curation_last_synced_at`: the interval was previously read into the
    // row and never used, so every enabled staging repo re-fetched upstream
    // metadata on every 5-minute tick regardless of its configuration. The
    // 60s floor keeps a misconfigured interval from turning the tick into a
    // hot loop against the upstream. The manual single-repo trigger bypasses
    // the interval — an operator asking for a sync gets one.
    let repos: Vec<CurationSyncRow> = sqlx::query_as(
        r#"SELECT r.id, r.format::text, r.curation_source_repo_id, remote.upstream_url,
                      r.curation_default_action, r.curation_sync_interval_secs,
                      remote.trusted_gpg_key, r.curation_allow_unverified
               FROM repositories r
               JOIN repositories remote ON remote.id = r.curation_source_repo_id
               WHERE r.curation_enabled = true
                 AND r.curation_source_repo_id IS NOT NULL
                 AND r.repo_type = 'staging'
                 AND remote.upstream_url IS NOT NULL
                 AND ($1::uuid IS NULL OR r.id = $1)
                 AND (
                    $1::uuid IS NOT NULL
                    OR r.curation_last_synced_at IS NULL
                    OR r.curation_last_synced_at
                       + make_interval(secs => GREATEST(r.curation_sync_interval_secs, 60)::double precision)
                       <= NOW()
                 )"#,
    )
    .bind(only_repo)
    .fetch_all(db)
    .await?;

    if repos.is_empty() {
        return Ok(());
    }

    let curation = CurationService::new(db.clone());
    // One TTL-cached download-count source for the whole sweep, so `popularity`
    // rules (#2949) evaluated across many packages / staging repos share
    // lookups instead of hammering the public stats APIs.
    let popularity_source =
        crate::services::curation::popularity_source::HttpPopularitySource::new().cached();
    let client = crate::services::http_client::base_client_builder()
        .timeout(std::time::Duration::from_secs(60))
        .build()?;

    for (
        staging_id,
        format,
        remote_id,
        upstream_url,
        default_action,
        _interval,
        trusted_gpg_key,
        allow_unverified,
    ) in &repos
    {
        let upstream_auth = crate::services::upstream_auth::load_upstream_auth(db, *remote_id)
            .await
            .unwrap_or(None);

        // pypi/npm have no enumerable global upstream index — they are ingested
        // ON DEMAND by the proxy seam (#2955 Stage 2). There is nothing to walk
        // here; instead evaluate the pending rows the proxy enqueued, exactly as
        // rpm/debian rows are evaluated after upsert, running attestation
        // verification off this tick first (never on the hot download path).
        if matches!(format.as_str(), "pypi" | "npm") {
            evaluate_ondemand_curation(
                &curation,
                *staging_id,
                default_action,
                format,
                upstream_url,
                &popularity_source,
                &client,
                &upstream_auth,
            )
            .await;
            let _ = sqlx::query(
                "UPDATE repositories SET curation_last_synced_at = NOW() WHERE id = $1",
            )
            .bind(staging_id)
            .execute(db)
            .await;
            continue;
        }

        let entries = match format.as_str() {
            "rpm" => {
                let base = upstream_url.trim_end_matches('/');
                let repomd_url = format!("{}/repodata/repomd.xml", base);
                let mut repomd_req = client.get(&repomd_url);
                if let Some(ref auth) = upstream_auth {
                    repomd_req =
                        crate::services::upstream_auth::apply_upstream_auth(repomd_req, auth);
                }
                // Fetch repomd.xml as raw bytes so a detached signature can be
                // verified over the exact content before its checksums are trusted.
                let repomd_bytes = match repomd_req.send().await {
                    Ok(resp) if resp.status().is_success() => {
                        #[allow(clippy::disallowed_methods)]
                        // STREAMING-EXEMPT: capped-metadata (upstream repomd.xml) buffered for signature verify + href parse; not an artifact blob (#1608)
                        match resp.bytes().await {
                            Ok(b) => b,
                            Err(e) => {
                                tracing::warn!("RPM repomd.xml read error: {}", e);
                                continue;
                            }
                        }
                    }
                    Ok(resp) => {
                        tracing::warn!("RPM repomd.xml fetch failed: {}", resp.status());
                        continue;
                    }
                    Err(e) => {
                        tracing::warn!("RPM repomd.xml fetch error: {}", e);
                        continue;
                    }
                };

                // GPG-verify-before-ingest (#2357 S4): when a trusted key is
                // configured on the remote, fetch repomd.xml.asc and verify the
                // detached signature over repomd.xml. Fail-closed — any fetch,
                // parse, or verification failure skips this repo (zero packages
                // ingested) rather than trusting unauthenticated metadata. With
                // no trusted key the sync is now ALSO fail-closed by default
                // (#2569): it refuses to ingest unverified upstream metadata
                // unless the repo has explicitly opted in via
                // `curation_allow_unverified`, in which case the batch proceeds
                // as "unverified upstream" (the legacy behavior).
                // `verified` gates the primary.xml checksum-chain enforcement
                // below: a signature over repomd alone does NOT authenticate a
                // tampered primary — repomd's <checksum> must pin it.
                let verified = match trusted_gpg_key.as_deref().filter(|k| !k.trim().is_empty()) {
                    Some(trusted_key) => {
                        let asc_url = format!("{}/repodata/repomd.xml.asc", base);
                        let mut asc_req = client.get(&asc_url);
                        if let Some(ref auth) = upstream_auth {
                            asc_req =
                                crate::services::upstream_auth::apply_upstream_auth(asc_req, auth);
                        }
                        let asc = match asc_req.send().await {
                            Ok(resp) if resp.status().is_success() => {
                                resp.text().await.unwrap_or_default()
                            }
                            _ => {
                                tracing::warn!(
                                    "RPM curation sync: trusted GPG key set but repomd.xml.asc unavailable for staging repo {}; refusing unverified upstream",
                                    staging_id
                                );
                                continue;
                            }
                        };
                        match crate::services::signing_service::verify_detached(
                            trusted_key,
                            &repomd_bytes,
                            &asc,
                        ) {
                            Ok(()) => {
                                tracing::debug!(
                                    "RPM curation sync: verified repomd.xml signature for staging repo {}",
                                    staging_id
                                );
                                true
                            }
                            Err(e) => {
                                tracing::warn!(
                                    "RPM curation sync: repomd.xml signature verification FAILED for staging repo {}: {}; refusing upstream (0 packages ingested)",
                                    staging_id,
                                    e
                                );
                                continue;
                            }
                        }
                    }
                    None => match keyless_sync_decision(*allow_unverified) {
                        // Fail-closed default (#2569): no trusted key and no
                        // explicit opt-in — refuse the upstream, ingest nothing.
                        KeylessSync::Refuse => {
                            tracing::warn!(
                                "RPM curation sync: no trusted GPG key configured for staging repo {} and curation_allow_unverified is not set; refusing UNVERIFIED upstream (0 packages ingested). Set trusted_gpg_key to authenticate the upstream, or curation_allow_unverified=true to opt into unverified ingest.",
                                staging_id
                            );
                            continue;
                        }
                        // Explicit opt-in: proceed as "unverified upstream"
                        // (legacy behavior; no checksum-chain enforcement).
                        KeylessSync::ProceedUnverified => {
                            tracing::warn!(
                                "RPM curation sync: no trusted GPG key configured for staging repo {}; curation_allow_unverified is set, ingesting UNVERIFIED upstream metadata (set trusted_gpg_key to enforce upstream signatures)",
                                staging_id
                            );
                            false
                        }
                    },
                };

                // Parse the primary reference (href + repomd-pinned checksums)
                // from repomd. When `verified`, this comes from the signed
                // repomd, so its <checksum> can be trusted to pin primary.xml.
                let repomd_str = String::from_utf8_lossy(&repomd_bytes);
                let primary_ref = crate::services::curation_sync::extract_primary_data(&repomd_str);
                let primary_path = primary_ref
                    .as_ref()
                    .map(|d| d.href.clone())
                    .unwrap_or_else(|| "repodata/primary.xml.gz".to_string());
                let primary_url = format!("{}/{}", base, primary_path);
                let mut primary_req = client.get(&primary_url);
                if let Some(ref auth) = upstream_auth {
                    primary_req =
                        crate::services::upstream_auth::apply_upstream_auth(primary_req, auth);
                }
                match primary_req.send().await {
                    Ok(resp) if resp.status().is_success() => {
                        #[allow(clippy::disallowed_methods)]
                        // STREAMING-EXEMPT: capped-metadata (upstream repo index) buffered for gz-decode; not an artifact blob (#1608)
                        let bytes = resp.bytes().await?;

                        // Chain-of-trust (#2357 HIGH): when the repo is
                        // signature-verified, the FETCHED primary.xml.gz must
                        // match the <checksum> pinned in the signed repomd.xml
                        // BEFORE it is parsed/ingested. Fail-closed on a
                        // missing / unsupported / mismatching checksum — this is
                        // what binds primary.xml to the signed repomd, defeating
                        // a tampered/replayed primary served at the signed href.
                        // (No enforcement on the unverified path: backward-compat
                        // for existing no-key RPM curation repos.)
                        if verified
                            && !crate::services::curation_sync::primary_gz_pinned_by_repomd(
                                primary_ref.as_ref(),
                                &bytes,
                            )
                        {
                            tracing::warn!(
                                "RPM curation sync: primary.xml.gz does NOT match the checksum pinned in the signed repomd.xml for staging repo {}; refusing upstream (0 packages ingested)",
                                staging_id
                            );
                            continue;
                        }

                        let xml = if primary_path.ends_with(".gz") {
                            // Bound the upstream-index decompression (#2556): a
                            // malicious/compromised upstream mirror cannot inflate
                            // primary.xml.gz unbounded during sync. #2561: the
                            // permit-scoped decode also caps CONCURRENT decodes.
                            crate::util::bounded_archive::with_ingest_extraction(|| {
                                decompress_upstream_index_gz(&bytes)
                            })??
                        } else {
                            String::from_utf8_lossy(&bytes).to_string()
                        };

                        // Defense-in-depth: when the signed repomd also declares
                        // an <open-checksum> over the decompressed primary.xml,
                        // enforce it too (only when present — the compressed
                        // <checksum> above already binds the exact bytes).
                        if verified {
                            if let Some(d) = primary_ref.as_ref() {
                                if let (Some(ot), Some(ov)) =
                                    (d.open_checksum_type.as_deref(), d.open_checksum.as_deref())
                                {
                                    if !crate::services::curation_sync::repodata_checksum_matches(
                                        ot,
                                        ov,
                                        xml.as_bytes(),
                                    ) {
                                        tracing::warn!(
                                            "RPM curation sync: decompressed primary.xml open-checksum mismatch vs signed repomd for staging repo {}; refusing upstream",
                                            staging_id
                                        );
                                        continue;
                                    }
                                }
                            }
                        }

                        curation_sync::parse_rpm_primary_xml(&xml)
                    }
                    Ok(resp) => {
                        tracing::warn!("RPM primary.xml fetch failed: {}", resp.status());
                        continue;
                    }
                    Err(e) => {
                        tracing::warn!("RPM primary.xml fetch error: {}", e);
                        continue;
                    }
                }
            }
            "debian" => {
                let packages_url = format!("{}/Packages.gz", upstream_url.trim_end_matches('/'));
                let mut packages_req = client.get(&packages_url);
                if let Some(ref auth) = upstream_auth {
                    packages_req =
                        crate::services::upstream_auth::apply_upstream_auth(packages_req, auth);
                }
                match packages_req.send().await {
                    Ok(resp) if resp.status().is_success() => {
                        #[allow(clippy::disallowed_methods)]
                        // STREAMING-EXEMPT: capped-metadata (upstream repo index) buffered for gz-decode; not an artifact blob (#1608)
                        let bytes = resp.bytes().await?;
                        // Bound the upstream-index decompression (#2556): a
                        // malicious/compromised upstream mirror cannot inflate
                        // Packages.gz unbounded during sync. #2561: the
                        // permit-scoped decode also caps CONCURRENT decodes.
                        let content =
                            crate::util::bounded_archive::with_ingest_extraction(|| {
                                decompress_upstream_index_gz(&bytes)
                            })??;
                        curation_sync::parse_deb_packages_index(&content, "main")
                    }
                    _ => {
                        // Fall back to uncompressed
                        let plain_url = format!("{}/Packages", upstream_url.trim_end_matches('/'));
                        let mut plain_req = client.get(&plain_url);
                        if let Some(ref auth) = upstream_auth {
                            plain_req = crate::services::upstream_auth::apply_upstream_auth(
                                plain_req, auth,
                            );
                        }
                        match plain_req.send().await {
                            Ok(resp) if resp.status().is_success() => {
                                let content = resp.text().await?;
                                curation_sync::parse_deb_packages_index(&content, "main")
                            }
                            _ => {
                                tracing::warn!("DEB Packages fetch failed for {}", upstream_url);
                                continue;
                            }
                        }
                    }
                }
            }
            _ => {
                tracing::debug!("Curation sync not yet implemented for format: {}", format);
                continue;
            }
        };

        tracing::info!(
            "Curation sync: {} entries parsed for staging repo {}",
            entries.len(),
            staging_id
        );

        for entry in &entries {
            match curation
                .upsert_package(
                    *staging_id,
                    *remote_id,
                    &entry.format,
                    &entry.package_name,
                    &entry.version,
                    entry.release.as_deref(),
                    entry.architecture.as_deref(),
                    entry.checksum_sha256.as_deref(),
                    &entry.upstream_path,
                    &entry.metadata,
                    entry.primary_metadata.as_ref(),
                )
                .await
            {
                Ok(pkg) if pkg.status == "pending" => {
                    // Typed dispatch (#2947): pattern + publisher_trust +
                    // popularity rules all apply, with the upstream metadata
                    // blob as the evaluation context.
                    let eval = curation
                        .evaluate_package_typed(
                            *staging_id,
                            default_action,
                            &entry.format,
                            &entry.package_name,
                            &entry.version,
                            entry.architecture.as_deref(),
                            &entry.metadata,
                            &popularity_source,
                        )
                        .await;

                    if let Ok((decision, rule_id)) = eval {
                        let (status, reason) =
                            CurationService::decision_to_status_reason(&decision, rule_id);
                        let _ = curation
                            .set_package_status(pkg.id, status, &reason, None, rule_id)
                            .await;
                    }
                }
                Ok(_) => {} // Already processed
                Err(e) => {
                    tracing::warn!(
                        "Failed to upsert curation package {}: {}",
                        entry.package_name,
                        e
                    );
                }
            }
        }

        // Successful fetch+evaluate: stamp the bookkeeping so this repo is
        // not due again until its configured interval elapses. Failed
        // fetches `continue` above without stamping and retry next tick.
        let _ =
            sqlx::query("UPDATE repositories SET curation_last_synced_at = NOW() WHERE id = $1")
                .bind(staging_id)
                .execute(db)
                .await;
    }

    Ok(())
}

/// Max distribution-file size the off-hot-path verifier will fetch to bind an
/// attestation subject (#2955). A wheel/sdist beyond this is treated as
/// unverifiable (fail-safe: the row stays unverified and Flags), never OOM.
const MAX_VERIFY_DIST_BYTES: usize = 128 * 1024 * 1024;

/// Evaluate the pending on-demand-ingested pypi/npm curation rows for one
/// staging repo (#2955 Stage 2/3). For each pending row: run attestation
/// verification off the hot path (pypi only; npm records the unsupported
/// reason), persist the result, inject a verified marker into the evaluation
/// context on success, then run the typed rule dispatch exactly as rpm/debian.
///
/// Every step is fail-SAFE: any error yields at most today's behavior (the row
/// stays unverified and the publisher-trust evaluator Flags it), never a false
/// `verified=true` and never a dead sync loop.
#[allow(clippy::too_many_arguments)]
async fn evaluate_ondemand_curation(
    curation: &crate::services::curation_service::CurationService,
    staging_id: uuid::Uuid,
    default_action: &str,
    format: &str,
    upstream_url: &str,
    popularity_source: &dyn crate::services::curation::popularity_source::PopularitySource,
    client: &reqwest::Client,
    upstream_auth: &Option<crate::services::upstream_auth::UpstreamAuthType>,
) {
    use crate::services::curation::{attestation_verify, publisher_source};
    use crate::services::curation_service::CurationService;

    const MAX_PENDING_PER_TICK: i64 = 500;
    let pending = match curation
        .list_pending_packages_by_format(staging_id, format, MAX_PENDING_PER_TICK)
        .await
    {
        Ok(p) => p,
        Err(e) => {
            tracing::warn!(
                staging_repo_id = %staging_id,
                format = %format,
                error = %e,
                "on-demand curation: failed to load pending packages"
            );
            return;
        }
    };
    if pending.is_empty() {
        return;
    }

    // Fail-safe trust root: if the vendored root is somehow unusable, we simply
    // never verify (rows stay unverified → Flag), never an outage.
    let trust = attestation_verify::TrustRoot::vendored().ok();
    let allowlist: Vec<String> = attestation_verify::DEFAULT_ISSUER_ALLOWLIST
        .iter()
        .map(|s| s.to_string())
        .collect();

    for pkg in pending {
        let mut eval_metadata = pkg.metadata.clone();
        // The marker below is a trusted server-side assertion: `extract_publisher`
        // short-circuits on it and returns `verified = true`. Clear whatever the
        // stored row carried BEFORE deciding whether to inject one, so the only
        // way to reach the verified arm is this tick's own `AttestationVerdict`.
        // Without this the loop inserts on success but never removes, so on the
        // failure and npm paths a stale or planted marker survives into the
        // evaluation untouched.
        if publisher_source::strip_verification_marker(&mut eval_metadata) {
            tracing::warn!(
                package = %pkg.package_name,
                version = %pkg.version,
                "curation eval: dropped a pre-existing attestation-verification marker from stored metadata"
            );
        }

        match format {
            "pypi" => {
                // #3230: the persisted record is the source of truth when it is
                // still usable. Re-verifying means re-downloading the whole
                // distribution from the upstream, and a verification is a
                // statement about an immutable digest — so a fresh record short-
                // circuits the network work AND, more importantly, survives the
                // tick that computed it. `reusable_verdict` fails safe: any
                // doubt returns None and we verify again.
                let cached = attestation_verify::reusable_verdict(
                    &attestation_verify::AttestationRecord::of(&pkg),
                    &allowlist,
                    chrono::Utc::now(),
                );
                let verdict = match cached {
                    Some(v) => v,
                    None => {
                        let verdict = match &trust {
                            Some(t) => {
                                verify_pypi_curation_row(
                                    client,
                                    upstream_auth,
                                    upstream_url,
                                    &pkg,
                                    &allowlist,
                                    t,
                                )
                                .await
                            }
                            None => attestation_verify::AttestationVerdict::unverified(),
                        };
                        let _ = curation
                            .record_attestation(
                                pkg.id,
                                verdict.state.as_str(),
                                verdict.identity.as_deref(),
                                verdict.issuer.as_deref(),
                                verdict.owner.as_deref(),
                                verdict.error.as_deref(),
                            )
                            .await;
                        verdict
                    }
                };
                attestation_verify::apply_verified_marker(&mut eval_metadata, Some(&verdict));
            }
            "npm" => {
                // npm is ingested but unsupported (sha512-only subject binding);
                // it never verifies and stays on the fail-safe Flag.
                let verdict = attestation_verify::verify_npm_unsupported();
                let _ = curation
                    .record_attestation(
                        pkg.id,
                        verdict.state.as_str(),
                        None,
                        None,
                        None,
                        verdict.error.as_deref(),
                    )
                    .await;
            }
            _ => {}
        }

        if let Ok((decision, rule_id)) = curation
            .evaluate_package_typed(
                staging_id,
                default_action,
                format,
                &pkg.package_name,
                &pkg.version,
                pkg.architecture.as_deref(),
                &eval_metadata,
                popularity_source,
            )
            .await
        {
            let (status, reason) = CurationService::decision_to_status_reason(&decision, rule_id);
            let _ = curation
                .set_package_status(pkg.id, status, &reason, None, rule_id)
                .await;
        }
    }
}

/// Verify one pending pypi curation row's attestation, off the hot path.
///
/// The on-demand proxy seam enqueues pypi rows with only name+version+filename
/// (it serves the simple index, not the JSON API), so this step best-effort
/// ENRICHES the row from the upstream — fetching `{base}/pypi/{n}/{v}/json` for
/// the distribution URL and the PEP 740 `{base}/integrity/.../provenance` — then
/// downloads the exact distribution bytes and verifies. Every miss (no upstream
/// JSON, no provenance, fetch/parse error, non-PyPI-shaped mirror) yields
/// `unverified`/`failed` (fail-safe), never a false `verified`.
async fn verify_pypi_curation_row(
    client: &reqwest::Client,
    upstream_auth: &Option<crate::services::upstream_auth::UpstreamAuthType>,
    upstream_url: &str,
    pkg: &crate::models::curation::CurationPackage,
    allowlist: &[String],
    trust: &crate::services::curation::attestation_verify::TrustRoot,
) -> crate::services::curation::attestation_verify::AttestationVerdict {
    use crate::services::curation::attestation_verify::{
        verify_pypi_provenance, AttestationVerdict,
    };
    use crate::services::curation_sync::build_pypi_curation_entry;

    // Resolve the distribution filename we are gating.
    let filename = pkg
        .metadata
        .get("_ak_dist")
        .and_then(|d| d.get("filename"))
        .and_then(|v| v.as_str())
        .map(str::to_string)
        .unwrap_or_else(|| pkg.upstream_path.clone());
    if filename.is_empty() {
        return AttestationVerdict::unverified();
    }

    // The package name, version and filename on this row are parsed straight out
    // of a proxy request path (`normalize_pep503` / `version_from_pypi_filename`)
    // and are interpolated below into URLs fetched WITH the repository's upstream
    // credentials. `version_from_pypi_filename` returns whatever sits between the
    // dashes, so without this gate a distribution named `foo-1.0?x-py3-none-any.whl`
    // injects a query string and `foo-..-py3-none-any.whl` traverses a path
    // segment (`Url::parse` normalises `..` away), turning the enrichment fetch
    // into a credentialed request-forgery primitive against arbitrary paths on an
    // internal mirror. Reject rather than encode: every value that can legitimately
    // appear here is already within these character sets (PEP 503 §"Normalized
    // Names" for the name, PEP 440 §"Appendix: Parsing version strings" for the
    // version, PEP 427/625 for the distribution filename), so a value outside them
    // is not a package we can verify anyway.
    if !is_safe_upstream_path_segment(&pkg.package_name)
        || !is_safe_upstream_path_segment(&pkg.version)
        || !is_safe_upstream_path_segment(&filename)
    {
        return AttestationVerdict::failure(
            "attestation lookup skipped: package name, version or filename contains characters that are not valid in a PyPI path segment".to_string(),
        );
    }

    // The PyPI base (strip a trailing `/simple[/]` from a simple-index upstream).
    let base = pypi_base_url(upstream_url);

    // Enrich: fetch the PEP 740 provenance first — it is absent for the
    // overwhelming majority of distributions, and returning early on that miss
    // saves the JSON round-trip entirely.
    let prov_url = format!(
        "{base}/integrity/{}/{}/{}/provenance",
        pkg.package_name, pkg.version, filename
    );
    let provenance = bounded_get_json(client, upstream_auth, &prov_url).await;
    let Some(provenance) = provenance else {
        // No provenance published upstream: exactly today's behavior.
        return AttestationVerdict::unverified();
    };

    let json_url = format!("{base}/pypi/{}/{}/json", pkg.package_name, pkg.version);
    let pypi_json = bounded_get_json(client, upstream_auth, &json_url).await;

    // Build a full entry (dist URL + merged provenance) from whatever we fetched.
    let entry = pypi_json.as_ref().and_then(|j| {
        build_pypi_curation_entry(&pkg.package_name, &pkg.version, j, Some(&provenance))
    });
    let dist_url = entry
        .as_ref()
        .and_then(|e| e.metadata.get("_ak_dist"))
        .and_then(|d| d.get("url"))
        .and_then(|v| v.as_str())
        .map(str::to_string);
    let Some(dist_url) = dist_url else {
        return AttestationVerdict::failure(
            "could not resolve the distribution download URL for attestation verification"
                .to_string(),
        );
    };

    // `dist_url` is copied verbatim out of the upstream's own JSON document
    // (`urls[].url`), so a hostile or compromised mirror chooses it. Send the
    // repository's configured upstream credentials ONLY when it stays on the
    // configured upstream's origin — same rule as the NuGet remote-search fix
    // (#3130/#2925). Network-level SSRF is already refused at connect time by the
    // shared DNS guard; this is specifically about not handing an operator's
    // Basic/token header to whatever public host the mirror names.
    let dist_auth = if same_upstream_origin(upstream_url, &dist_url) {
        upstream_auth.clone()
    } else {
        None
    };
    let Some(bytes) = bounded_download(client, &dist_auth, &dist_url).await else {
        return AttestationVerdict::failure(format!(
            "could not fetch distribution `{filename}` for attestation verification"
        ));
    };

    verify_pypi_provenance(&provenance, &bytes, &filename, allowlist, trust).await
}

/// Characters permitted in a PyPI path segment we build a credentialed upstream
/// URL from. Covers PEP 503 normalized names (`[a-z0-9-]`), PEP 440 versions
/// (which add `.`, `_`, `+`, `!`) and PEP 427/625 distribution filenames (which
/// add nothing else). Everything that could change the shape of the request —
/// `/`, `?`, `#`, `%`, `:`, `@`, whitespace, control characters — is refused.
fn is_safe_upstream_path_segment(s: &str) -> bool {
    !s.is_empty()
        && s != "."
        && s != ".."
        && s.len() <= 512
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '.' | '_' | '+' | '!'))
}

/// True when `resource_url` is on the same host and port as `upstream_url`.
/// Anything unparseable is treated as a different origin (fail closed).
fn same_upstream_origin(upstream_url: &str, resource_url: &str) -> bool {
    match (
        reqwest::Url::parse(upstream_url),
        reqwest::Url::parse(resource_url),
    ) {
        (Ok(up), Ok(res)) => {
            up.host_str().map(str::to_ascii_lowercase)
                == res.host_str().map(str::to_ascii_lowercase)
                && up.port_or_known_default() == res.port_or_known_default()
        }
        _ => false,
    }
}

/// Normalize a pypi remote's upstream URL to the API base by trimming a trailing
/// `/simple` (PEP 503 index) and slashes: `https://pypi.org/simple/` →
/// `https://pypi.org`.
fn pypi_base_url(upstream_url: &str) -> String {
    let trimmed = upstream_url.trim_end_matches('/');
    trimmed
        .strip_suffix("/simple")
        .unwrap_or(trimmed)
        .trim_end_matches('/')
        .to_string()
}

/// Bounded GET of a small JSON body (metadata / provenance). Returns `None` on
/// any transport error, non-2xx, oversize body, or parse failure (fail-safe).
async fn bounded_get_json(
    client: &reqwest::Client,
    upstream_auth: &Option<crate::services::upstream_auth::UpstreamAuthType>,
    url: &str,
) -> Option<serde_json::Value> {
    const MAX_JSON_BYTES: usize = 8 * 1024 * 1024;
    let mut req = client.get(url);
    if let Some(auth) = upstream_auth {
        req = crate::services::upstream_auth::apply_upstream_auth(req, auth);
    }
    let resp = req.send().await.ok()?;
    if !resp.status().is_success() {
        return None;
    }
    use futures::StreamExt;
    let mut stream = resp.bytes_stream();
    let mut buf: Vec<u8> = Vec::new();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.ok()?;
        if buf.len().saturating_add(chunk.len()) > MAX_JSON_BYTES {
            return None;
        }
        buf.extend_from_slice(&chunk);
    }
    serde_json::from_slice(&buf).ok()
}

/// Bounded, streaming download of a distribution file for attestation
/// verification. Returns `None` on any transport error, non-2xx status, or if
/// the body exceeds [`MAX_VERIFY_DIST_BYTES`] (so a hostile/huge artifact cannot
/// OOM the sync tick).
async fn bounded_download(
    client: &reqwest::Client,
    upstream_auth: &Option<crate::services::upstream_auth::UpstreamAuthType>,
    url: &str,
) -> Option<Vec<u8>> {
    use futures::StreamExt;

    let mut req = client.get(url);
    if let Some(auth) = upstream_auth {
        req = crate::services::upstream_auth::apply_upstream_auth(req, auth);
    }
    let resp = req.send().await.ok()?;
    if !resp.status().is_success() {
        return None;
    }
    let mut stream = resp.bytes_stream();
    let mut buf: Vec<u8> = Vec::new();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.ok()?;
        if buf.len().saturating_add(chunk.len()) > MAX_VERIFY_DIST_BYTES {
            return None;
        }
        buf.extend_from_slice(&chunk);
    }
    Some(buf)
}

/// Decompress a gzip-compressed upstream repo index (RPM `primary.xml.gz`,
/// Debian `Packages.gz`) during proxy-sync, bounded by the shared total-byte
/// budget (#2556) so a malicious/compromised upstream mirror cannot inflate the
/// index unbounded. This is the egress analogue of the rubygems
/// `parse_upstream_specs` upload-side hardening. A budget breach surfaces as an
/// `io::Error`, which propagates up the sync path (the sync fails, bounded).
fn decompress_upstream_index_gz(bytes: &[u8]) -> std::io::Result<String> {
    decompress_upstream_index_gz_limited(
        bytes,
        crate::util::bounded_archive::max_ingest_decompressed_bytes(),
    )
}

/// `_limited` seam for [`decompress_upstream_index_gz`] — lets tests drive a
/// tiny budget against a tiny gzip-bomb fixture.
fn decompress_upstream_index_gz_limited(bytes: &[u8], budget: u64) -> std::io::Result<String> {
    use std::io::Read;
    let mut decoder =
        crate::util::bounded_archive::budgeted_to(flate2::read::GzDecoder::new(bytes), budget);
    let mut s = String::new();
    decoder.read_to_string(&mut s)?;
    Ok(s)
}

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // #2955 — guards on the credentialed attestation-enrichment fetches
    // -----------------------------------------------------------------------

    #[test]
    fn safe_path_segment_admits_real_pypi_identifiers() {
        // Real PEP 503 names, PEP 440 versions and PEP 427/625 filenames must
        // pass, or the guard silently switches attestation verification off for
        // legitimate packages — a false negative is as bad as a false positive
        // here, it just fails quietly instead of loudly.
        for ok in [
            "sigstore",
            "zope-interface",
            "ruamel-yaml-clib",
            "4.5.0",
            "1.0.0rc1",
            "2!1.0.dev4",
            "1.0.0+local.1",
            "0.1.0.post1",
            "sigstore-4.5.0-py3-none-any.whl",
            "sigstore-4.5.0.tar.gz",
            "ruamel.yaml.clib-0.2.8-cp312-cp312-manylinux_2_17_x86_64.whl",
        ] {
            assert!(is_safe_upstream_path_segment(ok), "must admit {ok:?}");
        }
    }

    #[test]
    fn safe_path_segment_refuses_anything_that_reshapes_the_request() {
        // These are reachable: `version_from_pypi_filename` returns whatever sits
        // between the dashes of a request-path filename, with no charset check,
        // and the result is interpolated into a URL fetched with the repository's
        // upstream credentials.
        for bad in [
            "",                    // empty segment collapses the path
            ".",                   // no-op segment
            "..",                  // `Url::parse` normalises this away — traversal
            "1.0?x=y",             // query injection
            "1.0#frag",            // fragment truncation
            "1.0%2f..%2fadmin",    // encoded traversal
            "a/b",                 // literal path separator
            "user:pass@evil.test", // userinfo
            "1.0 0",               // whitespace
            "1.0\n",               // control character
            "1.0\u{0}",            // NUL
            "café",                // non-ASCII (IDNA/percent-encoding ambiguity)
        ] {
            assert!(!is_safe_upstream_path_segment(bad), "must refuse {bad:?}");
        }
        // Length bound.
        assert!(!is_safe_upstream_path_segment(&"a".repeat(513)));
        assert!(is_safe_upstream_path_segment(&"a".repeat(512)));
    }

    #[test]
    fn same_upstream_origin_gates_credentials_to_the_configured_host() {
        // On-origin: credentials travel (the common case — pypi.org serves its
        // distributions from files.pythonhosted.org, which is NOT the same origin,
        // so public PyPI simply gets an unauthenticated download; that is correct).
        assert!(same_upstream_origin(
            "https://mirror.internal/simple/",
            "https://mirror.internal/packages/sigstore-4.5.0-py3-none-any.whl"
        ));
        // Scheme-default ports count as equal.
        assert!(same_upstream_origin(
            "https://mirror.internal:443/simple/",
            "https://mirror.internal/x.whl"
        ));
        // Host case is not significant.
        assert!(same_upstream_origin(
            "https://Mirror.Internal/simple/",
            "https://mirror.internal/x.whl"
        ));

        // Off-origin: a hostile mirror naming any other host must not receive the
        // operator's configured upstream credentials.
        assert!(!same_upstream_origin(
            "https://mirror.internal/simple/",
            "https://attacker.example/x.whl"
        ));
        assert!(!same_upstream_origin(
            "https://mirror.internal/simple/",
            "https://mirror.internal.attacker.example/x.whl"
        ));
        assert!(!same_upstream_origin(
            "https://mirror.internal/simple/",
            "https://mirror.internal:8443/x.whl"
        ));
        assert!(!same_upstream_origin(
            "https://pypi.org/simple/",
            "https://files.pythonhosted.org/packages/x.whl"
        ));
        // Unparseable on either side fails closed.
        assert!(!same_upstream_origin(
            "not a url",
            "https://mirror.internal/x"
        ));
        assert!(!same_upstream_origin(
            "https://mirror.internal/",
            "not a url"
        ));
    }

    // -----------------------------------------------------------------------
    // #2556 — bounded upstream-index decompression
    // -----------------------------------------------------------------------

    fn gzip(data: &[u8]) -> Vec<u8> {
        use std::io::Write;
        let mut enc = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::best());
        enc.write_all(data).unwrap();
        enc.finish().unwrap()
    }

    #[test]
    fn test_upstream_index_gz_normal_decompresses() {
        let index = b"Package: nginx\nVersion: 1.24.0-1\n\nPackage: curl\nVersion: 8.0\n";
        let gz = gzip(index);
        let out = decompress_upstream_index_gz(&gz).expect("legit index decompresses");
        assert_eq!(out.as_bytes(), index);
    }

    #[test]
    fn test_upstream_index_gz_bomb_is_bounded() {
        // A tiny gzip that inflates past a small budget → aborts mid-inflate
        // with an io error rather than ballooning (a compromised upstream
        // mirror serving primary.xml.gz / Packages.gz cannot exhaust memory).
        let bomb = gzip(&vec![0u8; 4 * 1024 * 1024]);
        assert!(bomb.len() < 64 * 1024, "gzip of zeros compresses tiny");
        assert!(
            decompress_upstream_index_gz_limited(&bomb, 4096).is_err(),
            "upstream index bomb past budget must be bounded/rejected"
        );
    }

    // #2357 regression fence: the RPM GPG-verify/lease changes edit the SHARED
    // `run_curation_sync_cycle`, so the Debian curation path is in blast radius.
    // Assert the Debian branch's decompress -> parse still works end to end:
    // a gzip-encoded `Packages` index round-trips through the (now shared,
    // bounded) `decompress_upstream_index_gz` and yields the expected packages.
    #[test]
    fn test_debian_packages_index_still_decompresses_and_parses() {
        use crate::services::curation_sync;
        let packages = "Package: nginx\nVersion: 1.24.0-1\nArchitecture: amd64\nFilename: pool/main/n/nginx/nginx_1.24.0-1_amd64.deb\nSHA256: abc123\n\nPackage: curl\nVersion: 8.5.0-1\nArchitecture: amd64\nFilename: pool/main/c/curl/curl_8.5.0-1_amd64.deb\nSHA256: def456\n";
        let gz = gzip(packages.as_bytes());
        let content =
            decompress_upstream_index_gz(&gz).expect("debian Packages.gz must still decompress");
        let entries = curation_sync::parse_deb_packages_index(&content, "main");
        assert_eq!(entries.len(), 2, "both debian packages must parse");
        assert!(
            entries.iter().any(|e| e.package_name == "nginx"),
            "nginx must be present after debian decompress+parse"
        );
        assert!(entries.iter().all(|e| e.format == "debian"));
    }

    // -----------------------------------------------------------------------
    // #2569 — RPM curation keyless-sync fail-closed default
    // -----------------------------------------------------------------------

    /// The security-relevant guard: with NO trusted GPG key configured, a
    /// curation sync must be fail-closed by DEFAULT — it refuses to ingest
    /// unverified upstream metadata. Only an explicit opt-in
    /// (`curation_allow_unverified = true`) reverts to the legacy
    /// unverified-ingest behavior. Before #2569 the keyless path always
    /// ingested unverified (equivalent to `ProceedUnverified` for both inputs);
    /// this pins the flipped default.
    #[test]
    fn test_keyless_sync_defaults_fail_closed() {
        // Default (no opt-in) -> refuse (0 packages ingested).
        assert_eq!(
            keyless_sync_decision(false),
            KeylessSync::Refuse,
            "keyless sync with no opt-in must be fail-closed (refuse), not ingest unverified"
        );
        // Explicit opt-in -> proceed as unverified (legacy escape hatch).
        assert_eq!(
            keyless_sync_decision(true),
            KeylessSync::ProceedUnverified,
            "curation_allow_unverified=true must opt back into unverified ingest"
        );
    }

    // -----------------------------------------------------------------------
    // compute_next_run
    // -----------------------------------------------------------------------

    #[test]
    fn test_compute_next_run_valid_5_field_cron() {
        // Every day at midnight: "0 0 * * *"
        let result = compute_next_run("0 0 * * *");
        assert!(
            result.is_some(),
            "Should parse a valid 5-field cron expression"
        );
        let next = result.unwrap();
        assert!(next > Utc::now(), "Next run should be in the future");
    }

    #[test]
    fn test_compute_next_run_valid_6_field_cron() {
        // 6-field with seconds: "0 0 0 * * *"  (every day at midnight)
        let result = compute_next_run("0 0 0 * * *");
        assert!(
            result.is_some(),
            "Should parse a valid 6-field cron expression"
        );
        let next = result.unwrap();
        assert!(next > Utc::now());
    }

    #[test]
    fn test_compute_next_run_valid_7_field_cron() {
        // 7-field with seconds and year: "0 30 9 * * * *"
        let result = compute_next_run("0 30 9 * * * *");
        assert!(
            result.is_some(),
            "Should parse a valid 7-field cron expression"
        );
    }

    #[test]
    fn test_compute_next_run_every_minute() {
        // Every minute: "* * * * *"
        let result = compute_next_run("* * * * *");
        assert!(result.is_some());
        let next = result.unwrap();
        // Should be within 60 seconds from now
        let diff = next - Utc::now();
        assert!(diff.num_seconds() <= 60);
    }

    #[test]
    fn test_compute_next_run_invalid_cron_falls_back_to_24h() {
        let before = Utc::now();
        let result = compute_next_run("this is not valid cron");
        assert!(
            result.is_some(),
            "Invalid cron should fall back to 24h from now"
        );
        let next = result.unwrap();
        // Should be roughly 24 hours from now (allow some tolerance)
        let diff = next - before;
        assert!(
            diff.num_hours() >= 23 && diff.num_hours() <= 25,
            "Fallback should be ~24 hours from now, got {} hours",
            diff.num_hours()
        );
    }

    #[test]
    fn test_compute_next_run_empty_string_falls_back() {
        let result = compute_next_run("");
        assert!(result.is_some(), "Empty string should fall back to 24h");
        let diff = result.unwrap() - Utc::now();
        assert!(diff.num_hours() >= 23);
    }

    #[test]
    fn test_compute_next_run_5_field_prepends_seconds() {
        // The function should prepend "0 " for 5-field expressions
        // "30 2 * * *" -> "0 30 2 * * *" (2:30 AM daily)
        let result = compute_next_run("30 2 * * *");
        assert!(result.is_some());
    }

    #[test]
    fn test_compute_next_run_hourly() {
        // Every hour at minute 0: "0 * * * *"
        let result = compute_next_run("0 * * * *");
        assert!(result.is_some());
        let next = result.unwrap();
        let diff = next - Utc::now();
        assert!(diff.num_minutes() <= 60);
    }

    // -----------------------------------------------------------------------
    // GaugeStats struct
    // -----------------------------------------------------------------------

    #[test]
    fn test_gauge_stats_construction() {
        let stats = GaugeStats {
            repos: 10,
            artifacts: 500,
            storage: 1_073_741_824, // 1 GB
            users: 25,
        };
        assert_eq!(stats.repos, 10);
        assert_eq!(stats.artifacts, 500);
        assert_eq!(stats.storage, 1_073_741_824);
        assert_eq!(stats.users, 25);
    }

    #[test]
    fn test_gauge_stats_debug() {
        let stats = GaugeStats {
            repos: 0,
            artifacts: 0,
            storage: 0,
            users: 0,
        };
        let debug_str = format!("{:?}", stats);
        assert!(debug_str.contains("GaugeStats"));
        assert!(debug_str.contains("repos: 0"));
    }

    // -----------------------------------------------------------------------
    // BackupScheduleRow struct
    // -----------------------------------------------------------------------

    #[test]
    fn test_backup_schedule_row_construction() {
        let row = BackupScheduleRow {
            id: uuid::Uuid::new_v4(),
            name: "nightly-backup".to_string(),
            backup_type: BackupType::Full,
            include_repositories: None,
        };
        assert_eq!(row.name, "nightly-backup");
        assert!(row.include_repositories.is_none());
    }

    #[test]
    fn test_backup_schedule_row_with_repositories() {
        let repo_ids = vec![uuid::Uuid::new_v4(), uuid::Uuid::new_v4()];
        let row = BackupScheduleRow {
            id: uuid::Uuid::new_v4(),
            name: "selective-backup".to_string(),
            backup_type: BackupType::Incremental,
            include_repositories: Some(repo_ids.clone()),
        };
        assert_eq!(row.include_repositories.as_ref().unwrap().len(), 2);
    }

    #[test]
    fn test_backup_schedule_row_debug() {
        let row = BackupScheduleRow {
            id: uuid::Uuid::new_v4(),
            name: "test".to_string(),
            backup_type: BackupType::Metadata,
            include_repositories: None,
        };
        let debug_str = format!("{:?}", row);
        assert!(debug_str.contains("BackupScheduleRow"));
        assert!(debug_str.contains("test"));
    }

    // -----------------------------------------------------------------------
    // normalize_cron_expression (extracted pure function)
    // -----------------------------------------------------------------------

    #[test]
    fn test_normalize_cron_5_field() {
        assert_eq!(normalize_cron_expression("0 0 * * *"), "0 0 0 * * *");
    }

    #[test]
    fn test_normalize_cron_6_field_unchanged() {
        assert_eq!(normalize_cron_expression("0 0 0 * * *"), "0 0 0 * * *");
    }

    #[test]
    fn test_normalize_cron_7_field_unchanged() {
        assert_eq!(
            normalize_cron_expression("0 30 9 * * * *"),
            "0 30 9 * * * *"
        );
    }

    #[test]
    fn test_normalize_cron_1_field_unchanged() {
        // Less than 5 fields, not modified
        assert_eq!(normalize_cron_expression("invalid"), "invalid");
    }

    #[test]
    fn test_cron_5_field_detection() {
        let five = "0 0 * * *";
        assert_eq!(five.split_whitespace().count(), 5);

        let six = "0 0 0 * * *";
        assert_eq!(six.split_whitespace().count(), 6);

        let seven = "0 0 0 * * * *";
        assert_eq!(seven.split_whitespace().count(), 7);
    }

    // -----------------------------------------------------------------------
    // parse_cron_schedule (extracted pure function)
    // -----------------------------------------------------------------------

    #[test]
    fn test_parse_cron_schedule_valid() {
        let schedule = parse_cron_schedule("0 0 0 * * *");
        assert!(schedule.is_some());
    }

    #[test]
    fn test_parse_cron_schedule_invalid() {
        let schedule = parse_cron_schedule("not valid cron");
        assert!(schedule.is_none());
    }

    #[test]
    fn test_parse_cron_schedule_empty() {
        let schedule = parse_cron_schedule("");
        assert!(schedule.is_none());
    }

    #[test]
    fn test_parse_cron_schedule_every_minute() {
        // "0 * * * * *" = every minute (with seconds field)
        let schedule = parse_cron_schedule("0 * * * * *");
        assert!(schedule.is_some());
    }

    /// A year-qualified 7-field expression whose window has passed is VALID
    /// cron but has no future occurrence. `compute_next_run` must report that
    /// as `None` rather than reusing the invalid-expression 24h fallback,
    /// which would silently keep running an exhausted schedule forever.
    #[test]
    fn test_compute_next_run_is_none_for_exhausted_year_cron() {
        let exhausted = "0 0 3 * * * 2020";
        assert!(
            parse_cron_schedule(exhausted).is_some(),
            "the expression must parse; this is not the invalid-cron case"
        );
        assert!(
            compute_next_run(exhausted).is_none(),
            "a cron with no future occurrence must not fall back to 24h"
        );
    }

    #[test]
    fn test_parse_cron_schedule_yields_future_times() {
        let schedule = parse_cron_schedule("0 * * * * *").unwrap();
        let next = schedule.upcoming(Utc).next();
        assert!(next.is_some());
        assert!(next.unwrap() > Utc::now());
    }

    // -----------------------------------------------------------------------
    // Backup schedule run claims (Tier-2: no-op without DATABASE_URL)
    // -----------------------------------------------------------------------

    async fn insert_test_backup_schedule_with_cron(
        pool: &sqlx::PgPool,
        cron_expression: &str,
    ) -> (uuid::Uuid, chrono::DateTime<Utc>) {
        let id = uuid::Uuid::new_v4();
        let due_at: chrono::DateTime<Utc> = sqlx::query_scalar(
            "INSERT INTO backup_schedules \
                 (id, name, backup_type, cron_expression, storage_destination, \
                  is_enabled, next_run_at) \
             VALUES ($1, $2, 'full', $3, '/tmp/backup-claim-test', \
                     true, NOW() - INTERVAL '1 minute') \
             RETURNING next_run_at",
        )
        .bind(id)
        .bind(format!("claim-test-{}", &id.to_string()[..8]))
        .bind(cron_expression)
        .fetch_one(pool)
        .await
        .expect("insert backup schedule");
        (id, due_at)
    }

    async fn insert_test_backup_schedule(
        pool: &sqlx::PgPool,
    ) -> (uuid::Uuid, chrono::DateTime<Utc>) {
        insert_test_backup_schedule_with_cron(pool, "0 2 * * *").await
    }

    async fn cleanup_test_backup_schedule(pool: &sqlx::PgPool, schedule_id: uuid::Uuid) {
        let _ = sqlx::query("DELETE FROM backup_schedules WHERE id = $1")
            .bind(schedule_id)
            .execute(pool)
            .await;
    }

    async fn insert_test_backup(pool: &sqlx::PgPool) -> uuid::Uuid {
        sqlx::query_scalar(
            "INSERT INTO backups (backup_type, storage_path) \
             VALUES ('full', $1) RETURNING id",
        )
        .bind(format!("backups/test/{}.tar.gz", uuid::Uuid::new_v4()))
        .fetch_one(pool)
        .await
        .expect("insert backup")
    }

    async fn cleanup_test_backup(pool: &sqlx::PgPool, backup_id: uuid::Uuid) {
        let _ = sqlx::query("DELETE FROM backups WHERE id = $1")
            .bind(backup_id)
            .execute(pool)
            .await;
    }

    #[tokio::test]
    async fn backup_run_claim_is_exactly_once_and_advances_atomically() {
        use crate::api::handlers::test_db_helpers as tdh;
        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let (schedule_id, due_at) = insert_test_backup_schedule(&pool).await;

        let winner = claim_backup_schedule_run(&pool, schedule_id, due_at, "replica-a", 3600.0)
            .await
            .expect("claim query ok")
            .expect("first claim wins");
        let backup_id = insert_test_backup(&pool).await;

        assert!(
            claim_backup_schedule_run(&pool, schedule_id, due_at, "replica-b", 3600.0)
                .await
                .expect("claim query ok")
                .is_none(),
            "a live run claim must block another replica"
        );

        assert!(
            finalize_backup_schedule_run(
                &pool,
                schedule_id,
                &winner.claim,
                true,
                Some(backup_id),
                None,
            )
            .await
            .expect("finalize transaction"),
            "the owner must finalize"
        );

        let (status, next_run_at, recorded_backup_id): (
            String,
            Option<chrono::DateTime<Utc>>,
            Option<uuid::Uuid>,
        ) = sqlx::query_as(
            "SELECT r.status, s.next_run_at, r.backup_id \
             FROM backup_schedule_runs r \
             JOIN backup_schedules s ON s.id = r.schedule_id \
             WHERE r.id = $1",
        )
        .bind(winner.claim.run_id)
        .fetch_one(&pool)
        .await
        .expect("fetch finalized run and schedule");
        assert_eq!(status, "completed");
        assert!(next_run_at.is_some_and(|next| next > due_at));
        assert_eq!(recorded_backup_id, Some(backup_id));

        assert!(
            claim_backup_schedule_run(&pool, schedule_id, due_at, "replica-b", 3600.0)
                .await
                .expect("claim query ok")
                .is_none(),
            "a completed occurrence must never be reclaimed"
        );

        cleanup_test_backup_schedule(&pool, schedule_id).await;
        cleanup_test_backup(&pool, backup_id).await;
    }

    #[tokio::test]
    async fn backup_run_reclaim_renews_and_fences_stale_owner() {
        use crate::api::handlers::test_db_helpers as tdh;
        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let (schedule_id, due_at) = insert_test_backup_schedule(&pool).await;

        let stale = claim_backup_schedule_run(&pool, schedule_id, due_at, "dead", -1.0)
            .await
            .expect("claim query ok")
            .expect("claim");
        let fresh = claim_backup_schedule_run(&pool, schedule_id, due_at, "live", 3600.0)
            .await
            .expect("claim query ok")
            .expect("expired run must be reclaimed");
        assert_eq!(stale.claim.run_id, fresh.claim.run_id);

        assert!(
            !renew_backup_schedule_run_claim(&pool, &stale.claim, 3600.0)
                .await
                .expect("renew query"),
            "a stale token must not renew"
        );
        assert!(
            renew_backup_schedule_run_claim(&pool, &fresh.claim, 3600.0)
                .await
                .expect("renew query"),
            "the live owner must renew"
        );
        assert!(
            !finalize_backup_schedule_run(&pool, schedule_id, &stale.claim, true, None, None)
                .await
                .expect("stale finalize query"),
            "a stale token must not finalize"
        );
        assert!(finalize_backup_schedule_run(
            &pool,
            schedule_id,
            &fresh.claim,
            false,
            None,
            Some("boom"),
        )
        .await
        .expect("fresh finalize query"));

        cleanup_test_backup_schedule(&pool, schedule_id).await;
    }

    #[tokio::test]
    async fn backup_claim_revalidates_candidate_and_refreshes_payload() {
        use crate::api::handlers::test_db_helpers as tdh;
        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let (schedule_id, due_at) = insert_test_backup_schedule(&pool).await;

        sqlx::query("UPDATE backup_schedules SET is_enabled = false WHERE id = $1")
            .bind(schedule_id)
            .execute(&pool)
            .await
            .expect("disable schedule");
        assert!(
            claim_backup_schedule_run(&pool, schedule_id, due_at, "replica-a", 3600.0)
                .await
                .expect("claim query")
                .is_none(),
            "a schedule disabled after discovery must not be claimed"
        );

        sqlx::query(
            "UPDATE backup_schedules \
             SET is_enabled = true, next_run_at = NOW() + INTERVAL '2 days' \
             WHERE id = $1",
        )
        .bind(schedule_id)
        .execute(&pool)
        .await
        .expect("reschedule occurrence");
        assert!(
            claim_backup_schedule_run(&pool, schedule_id, due_at, "replica-a", 3600.0)
                .await
                .expect("claim query")
                .is_none(),
            "a changed due occurrence must not be claimed from a stale candidate"
        );

        let repository_id = uuid::Uuid::new_v4();
        let current_name = format!("updated-claim-test-{}", &schedule_id.to_string()[..8]);
        sqlx::query(
            "UPDATE backup_schedules \
             SET name = $2, backup_type = 'incremental', \
                 include_repositories = ARRAY[$3], next_run_at = $4 \
             WHERE id = $1",
        )
        .bind(schedule_id)
        .bind(&current_name)
        .bind(repository_id)
        .bind(due_at)
        .execute(&pool)
        .await
        .expect("refresh due schedule payload");

        let claimed = claim_backup_schedule_run(&pool, schedule_id, due_at, "replica-a", 3600.0)
            .await
            .expect("claim query")
            .expect("current occurrence is claimable");
        assert_eq!(claimed.schedule.name, current_name);
        assert_eq!(claimed.schedule.backup_type, BackupType::Incremental);
        assert_eq!(
            claimed.schedule.include_repositories,
            Some(vec![repository_id])
        );
        assert_eq!(claimed.claim.scheduled_for, due_at);

        cleanup_test_backup_schedule(&pool, schedule_id).await;
    }

    /// A schedule whose cron has no further occurrence must be disabled at
    /// finalize instead of being left with `next_run_at = NULL`. A NULL
    /// next run is permanently due at the `'epoch'` sentinel, and once this
    /// run's terminal `(schedule_id, 'epoch')` ledger row exists no claim can
    /// ever succeed again — while the schedule still occupies one of the five
    /// candidate slots the discovery query hands out.
    #[tokio::test]
    async fn exhausted_cron_disables_the_schedule_instead_of_wedging_it() {
        use crate::api::handlers::test_db_helpers as tdh;
        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let (schedule_id, due_at) =
            insert_test_backup_schedule_with_cron(&pool, "0 0 3 * * * 2020").await;

        let claimed = claim_backup_schedule_run(&pool, schedule_id, due_at, "replica-a", 3600.0)
            .await
            .expect("claim query ok")
            .expect("a due schedule is claimable");
        assert!(
            finalize_backup_schedule_run(&pool, schedule_id, &claimed.claim, true, None, None)
                .await
                .expect("finalize transaction")
        );

        let (is_enabled, next_run_at): (bool, Option<chrono::DateTime<Utc>>) =
            sqlx::query_as("SELECT is_enabled, next_run_at FROM backup_schedules WHERE id = $1")
                .bind(schedule_id)
                .fetch_one(&pool)
                .await
                .expect("fetch schedule");
        assert!(
            next_run_at.is_none(),
            "an exhausted cron has no next occurrence to record"
        );
        assert!(
            !is_enabled,
            "an exhausted schedule must be disabled, not left permanently due"
        );

        // The candidate query must no longer offer it, so it cannot occupy a
        // due-schedule slot forever.
        let candidates = sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM backup_schedules \
             WHERE id = $1 AND is_enabled = true \
               AND (next_run_at IS NULL OR next_run_at <= NOW())",
        )
        .bind(schedule_id)
        .fetch_one(&pool)
        .await
        .expect("count candidates");
        assert_eq!(candidates, 0, "a disabled schedule must not be discovered");

        cleanup_test_backup_schedule(&pool, schedule_id).await;
    }

    /// The disable is scoped to the exhausted-cron case: a schedule an
    /// administrator disabled while the run was in flight must stay disabled,
    /// and a normal schedule keeps whatever `is_enabled` it has.
    #[tokio::test]
    async fn finalize_does_not_re_enable_a_schedule_disabled_mid_run() {
        use crate::api::handlers::test_db_helpers as tdh;
        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let (schedule_id, due_at) = insert_test_backup_schedule(&pool).await;

        let claimed = claim_backup_schedule_run(&pool, schedule_id, due_at, "replica-a", 3600.0)
            .await
            .expect("claim query ok")
            .expect("a due schedule is claimable");
        sqlx::query("UPDATE backup_schedules SET is_enabled = false WHERE id = $1")
            .bind(schedule_id)
            .execute(&pool)
            .await
            .expect("administrator disables the schedule mid-run");

        assert!(
            finalize_backup_schedule_run(&pool, schedule_id, &claimed.claim, true, None, None)
                .await
                .expect("finalize transaction")
        );

        let (is_enabled, next_run_at): (bool, Option<chrono::DateTime<Utc>>) =
            sqlx::query_as("SELECT is_enabled, next_run_at FROM backup_schedules WHERE id = $1")
                .bind(schedule_id)
                .fetch_one(&pool)
                .await
                .expect("fetch schedule");
        assert!(
            !is_enabled,
            "finalize must not re-enable a schedule the administrator disabled"
        );
        assert!(
            next_run_at.is_some_and(|next| next > due_at),
            "a live cron still advances its occurrence"
        );

        cleanup_test_backup_schedule(&pool, schedule_id).await;
    }

    #[tokio::test]
    async fn backup_finalize_does_not_overwrite_a_rescheduled_occurrence() {
        use crate::api::handlers::test_db_helpers as tdh;
        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let (schedule_id, due_at) = insert_test_backup_schedule(&pool).await;
        let claimed = claim_backup_schedule_run(&pool, schedule_id, due_at, "replica-a", 3600.0)
            .await
            .expect("claim query ok")
            .expect("claim");

        let rescheduled_for: chrono::DateTime<Utc> = sqlx::query_scalar(
            "UPDATE backup_schedules \
             SET cron_expression = '0 4 * * *', next_run_at = NOW() + INTERVAL '2 days' \
             WHERE id = $1 RETURNING next_run_at",
        )
        .bind(schedule_id)
        .fetch_one(&pool)
        .await
        .expect("reschedule");

        assert!(
            finalize_backup_schedule_run(&pool, schedule_id, &claimed.claim, true, None, None)
                .await
                .expect("finalize transaction")
        );
        let after: chrono::DateTime<Utc> =
            sqlx::query_scalar("SELECT next_run_at FROM backup_schedules WHERE id = $1")
                .bind(schedule_id)
                .fetch_one(&pool)
                .await
                .expect("fetch schedule");
        assert_eq!(after, rescheduled_for, "the administrator's schedule wins");

        cleanup_test_backup_schedule(&pool, schedule_id).await;
    }
}
