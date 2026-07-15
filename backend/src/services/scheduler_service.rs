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
    {
        let db = db.clone();
        let config_clone = config.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_secs(15)).await;
            let monitor = HealthMonitorService::new(db, MonitorConfig::default());
            let mut ticker = interval(Duration::from_secs(60));

            loop {
                ticker.tick().await;
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
    {
        let db = db.clone();
        let check_secs = config.lifecycle_check_interval_secs;
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_secs(60)).await;
            let service = LifecycleService::new(db);
            let mut ticker = interval(Duration::from_secs(check_secs));

            loop {
                ticker.tick().await;
                tracing::debug!("Checking for due lifecycle policies");

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
                            tracing::warn!(
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
                    360.0,
                )
                .await;
                if lease.is_none() {
                    tracing::debug!(
                        "Curation sync: another replica holds the lease; skipping tick"
                    );
                    continue;
                }

                if let Err(e) = run_curation_sync_cycle(&db, None).await {
                    tracing::warn!("Curation sync cycle failed: {}", e);
                }

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

/// A row from the backup_schedules table.
#[derive(Debug, sqlx::FromRow)]
struct BackupScheduleRow {
    pub id: uuid::Uuid,
    pub name: String,
    pub backup_type: BackupType,
    pub cron_expression: String,
    pub include_repositories: Option<Vec<uuid::Uuid>>,
}

/// Check for due backup schedules and execute them.
async fn execute_due_backup_schedules(db: &PgPool, config: &Config) -> crate::error::Result<()> {
    // Find schedules where next_run_at <= now
    let due_schedules = sqlx::query_as::<_, BackupScheduleRow>(
        r#"
        SELECT id, name, backup_type, cron_expression, include_repositories
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

    let storage = match StorageService::from_config(config).await {
        Ok(s) => Arc::new(s),
        Err(e) => {
            tracing::error!(
                "Failed to create storage service for scheduled backups: {}",
                e
            );
            return Err(e);
        }
    };

    for schedule_row in &due_schedules {
        tracing::info!(
            "Executing scheduled backup '{}' (type: {:?})",
            schedule_row.name,
            schedule_row.backup_type
        );

        let service = BackupService::new(db.clone(), storage.clone());

        // Create and execute the backup
        let create_result = service
            .create(CreateBackupRequest {
                backup_type: schedule_row.backup_type,
                repository_ids: schedule_row.include_repositories.clone(),
                created_by: None, // system-initiated
            })
            .await;

        let backup_type_str = format!("{:?}", schedule_row.backup_type).to_lowercase();
        let start = std::time::Instant::now();

        match create_result {
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
                }
                Err(e) => {
                    let elapsed = start.elapsed().as_secs_f64();
                    tracing::error!(
                        "Scheduled backup '{}' execution failed: {}",
                        schedule_row.name,
                        e
                    );
                    metrics_service::record_backup(&backup_type_str, false, elapsed);
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
            }
        }

        // Compute and update next_run_at from cron expression
        let next_run = compute_next_run(&schedule_row.cron_expression);
        let _ = sqlx::query(
            "UPDATE backup_schedules SET last_run_at = NOW(), next_run_at = $2, updated_at = NOW() WHERE id = $1",
        )
        .bind(schedule_row.id)
        .bind(next_run)
        .execute(db)
        .await;
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
/// trusted_gpg_key)`. Named to keep the `query_as` type off clippy's
/// `type_complexity` radar (#2357 added the trusted-key column).
type CurationSyncRow = (
    uuid::Uuid,
    String,
    uuid::Uuid,
    String,
    String,
    i32,
    Option<String>,
);

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
    let repos: Vec<CurationSyncRow> = sqlx::query_as(
        r#"SELECT r.id, r.format::text, r.curation_source_repo_id, remote.upstream_url,
                      r.curation_default_action, r.curation_sync_interval_secs,
                      remote.trusted_gpg_key
               FROM repositories r
               JOIN repositories remote ON remote.id = r.curation_source_repo_id
               WHERE r.curation_enabled = true
                 AND r.curation_source_repo_id IS NOT NULL
                 AND r.repo_type = 'staging'
                 AND remote.upstream_url IS NOT NULL
                 AND ($1::uuid IS NULL OR r.id = $1)"#,
    )
    .bind(only_repo)
    .fetch_all(db)
    .await?;

    if repos.is_empty() {
        return Ok(());
    }

    let curation = CurationService::new(db.clone());
    let client = crate::services::http_client::base_client_builder()
        .timeout(std::time::Duration::from_secs(60))
        .build()?;

    for (staging_id, format, remote_id, upstream_url, default_action, _interval, trusted_gpg_key) in
        &repos
    {
        let upstream_auth = crate::services::upstream_auth::load_upstream_auth(db, *remote_id)
            .await
            .unwrap_or(None);

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
                // no trusted key the batch proceeds as "unverified upstream".
                match trusted_gpg_key
                    .as_deref()
                    .filter(|k| !k.trim().is_empty())
                {
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
                            Ok(()) => tracing::debug!(
                                "RPM curation sync: verified repomd.xml signature for staging repo {}",
                                staging_id
                            ),
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
                    None => tracing::info!(
                        "RPM curation sync: no trusted GPG key configured for staging repo {}; ingesting unverified upstream metadata",
                        staging_id
                    ),
                }

                // Find primary.xml location from repomd.xml, fall back to default path.
                let repomd_str = String::from_utf8_lossy(&repomd_bytes);
                let primary_path =
                    crate::services::curation_sync::extract_primary_href(&repomd_str)
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
                        let xml = if primary_path.ends_with(".gz") {
                            // Bound the upstream-index decompression (#2556): a
                            // malicious/compromised upstream mirror cannot inflate
                            // primary.xml.gz unbounded during sync.
                            decompress_upstream_index_gz(&bytes)?
                        } else {
                            String::from_utf8_lossy(&bytes).to_string()
                        };
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
                        // Packages.gz unbounded during sync.
                        let content = decompress_upstream_index_gz(&bytes)?;
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
                )
                .await
            {
                Ok(pkg) if pkg.status == "pending" => {
                    let eval = curation
                        .evaluate_package(
                            *staging_id,
                            default_action,
                            &entry.package_name,
                            &entry.version,
                            entry.architecture.as_deref(),
                        )
                        .await;

                    if let Ok(eval) = eval {
                        let status = match eval.action.as_str() {
                            "allow" => "approved",
                            "block" => "blocked",
                            _ => "review",
                        };
                        let _ = curation
                            .set_package_status(pkg.id, status, &eval.reason, None, eval.rule_id)
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
    }

    Ok(())
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
            cron_expression: "0 2 * * *".to_string(),
            include_repositories: None,
        };
        assert_eq!(row.name, "nightly-backup");
        assert_eq!(row.cron_expression, "0 2 * * *");
        assert!(row.include_repositories.is_none());
    }

    #[test]
    fn test_backup_schedule_row_with_repositories() {
        let repo_ids = vec![uuid::Uuid::new_v4(), uuid::Uuid::new_v4()];
        let row = BackupScheduleRow {
            id: uuid::Uuid::new_v4(),
            name: "selective-backup".to_string(),
            backup_type: BackupType::Incremental,
            cron_expression: "0 3 * * 0".to_string(),
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
            cron_expression: "0 0 * * *".to_string(),
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

    #[test]
    fn test_parse_cron_schedule_yields_future_times() {
        let schedule = parse_cron_schedule("0 * * * * *").unwrap();
        let next = schedule.upcoming(Utc).next();
        assert!(next.is_some());
        assert!(next.unwrap() > Utc::now());
    }
}
