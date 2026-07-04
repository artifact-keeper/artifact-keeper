//! Background sync worker.
//!
//! Processes the `sync_tasks` queue by transferring artifacts to remote peer
//! instances.  Runs on a 10-second tick, respects per-peer concurrency limits,
//! sync windows, and configurable backoff on failures.
//!
//! For artifacts larger than `SYNC_CHUNKED_THRESHOLD_BYTES`, the worker creates
//! a resumable upload session on the remote peer instead of sending the full
//! file in a single HTTP request. This prevents timeouts and memory exhaustion
//! when syncing large Docker images, ML models, etc.

use crate::services::cluster_work::{Claimed, WorkerIdentity};
use crate::storage::{StorageLocation, StorageRegistry};
use chrono::{NaiveTime, Timelike, Utc};
use sqlx::PgPool;
use std::sync::Arc;
use tokio::time::{interval, Duration};
use uuid::Uuid;

/// Default stale peer threshold in minutes (peers with no heartbeat for this
/// long are marked offline).  Matches the admin settings default.
///
/// Override with `PEER_STALE_THRESHOLD_MINUTES` (positive integer).  In e2e
/// mesh tests this is typically lowered to 1 minute so failover fits within
/// a 90s test budget; production should keep the conservative default to
/// avoid flapping under transient heartbeat loss.
const STALE_PEER_THRESHOLD_MINUTES: i32 = 5;

/// Default interval between active peer liveness probes.
const PEER_HEARTBEAT_INTERVAL_SECS: u64 = 60;

/// Default timeout for one peer liveness probe request.
const PEER_HEARTBEAT_TIMEOUT_SECS: u64 = 10;

/// How many ticks (10s each) between stale peer detection runs.
/// 6 ticks = 60 seconds.
///
/// Override with `PEER_STALE_CHECK_INTERVAL_TICKS` (positive integer).  Each
/// tick is `TICK_INTERVAL_SECS` (10s); the failover detection latency is
/// `(stale_check_interval_ticks * 10s) + (stale_threshold_minutes * 60s)`.
const STALE_CHECK_INTERVAL_TICKS: u64 = 6;

/// Read the configured stale-peer threshold (minutes) from
/// `PEER_STALE_THRESHOLD_MINUTES`, falling back to
/// `STALE_PEER_THRESHOLD_MINUTES`.  Non-positive values are rejected so we
/// never disable detection by accident.
pub(crate) fn stale_peer_threshold_minutes() -> i32 {
    std::env::var("PEER_STALE_THRESHOLD_MINUTES")
        .ok()
        .and_then(|v| v.parse::<i32>().ok())
        .filter(|&n| n > 0)
        .unwrap_or(STALE_PEER_THRESHOLD_MINUTES)
}

/// Read the configured stale-check tick interval from
/// `PEER_STALE_CHECK_INTERVAL_TICKS`, falling back to
/// `STALE_CHECK_INTERVAL_TICKS`.  Non-positive values are rejected.
pub(crate) fn stale_check_interval_ticks() -> u64 {
    std::env::var("PEER_STALE_CHECK_INTERVAL_TICKS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .filter(|&n| n > 0)
        .unwrap_or(STALE_CHECK_INTERVAL_TICKS)
}

/// Compute the worst-case failover-detection deadline (in seconds) for a
/// given configuration. The deadline is the sum of the polling cadence and
/// the heartbeat threshold: that is the latest point at which a healthy
/// peer can be expected to discover an offline originating peer.
pub(crate) fn failover_detection_deadline_secs(
    stale_check_interval_ticks: u64,
    stale_threshold_minutes: i32,
    tick_interval_secs: u64,
) -> u64 {
    let poll_secs = stale_check_interval_ticks.saturating_mul(tick_interval_secs);
    let threshold_secs = (stale_threshold_minutes.max(0) as u64).saturating_mul(60);
    poll_secs.saturating_add(threshold_secs)
}

/// Duration of each worker tick in seconds.
const TICK_INTERVAL_SECS: u64 = 10;

/// Default per-peer TCP connect timeout (seconds) for sync transfers.
///
/// Bounds how long a single transfer waits to establish a connection to a
/// peer. Without this, a peer whose endpoint black-holes connections (firewall
/// DROP, dead host) would hold a transfer slot for the full request timeout
/// (300s). In a fan-out to multiple peers, that unreachable peer would then
/// occupy one of its own concurrency slots for minutes. Capping the connect
/// phase lets the worker fail the broken leg quickly and retry under backoff,
/// while healthy peers (separate tasks) are unaffected.
///
/// Override with `SYNC_PEER_CONNECT_TIMEOUT_SECS` (positive integer).
const DEFAULT_PEER_CONNECT_TIMEOUT_SECS: u64 = 10;

/// Read the configured per-peer connect timeout from
/// `SYNC_PEER_CONNECT_TIMEOUT_SECS`, falling back to
/// `DEFAULT_PEER_CONNECT_TIMEOUT_SECS`. Non-positive values are rejected.
pub(crate) fn peer_connect_timeout_secs() -> u64 {
    std::env::var("SYNC_PEER_CONNECT_TIMEOUT_SECS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .filter(|&n| n > 0)
        .unwrap_or(DEFAULT_PEER_CONNECT_TIMEOUT_SECS)
}

/// Default threshold (in bytes) above which chunked transfer is used instead
/// of a single-request upload.  100 MB.
/// Override with the `SYNC_CHUNKED_THRESHOLD_BYTES` env var.
const DEFAULT_CHUNKED_THRESHOLD_BYTES: i64 = 100 * 1024 * 1024;

/// Default chunk size (in bytes) for chunked transfers.  50 MB.
/// Override with the `SYNC_CHUNK_SIZE_BYTES` env var.
const DEFAULT_SYNC_CHUNK_SIZE_BYTES: i32 = 50 * 1024 * 1024;

const REPLICATION_REQUEST_HEADER: &str = "X-Artifact-Keeper-Replication";
const REPLICATION_REQUEST_VALUE: &str = "true";
const CHECKSUM_SHA256_HEADER: &str = "x-checksum-sha256";

/// Default retry backoff cap for sync tasks.
///
/// The default base backoff is the same value, so retries happen every five
/// minutes unless operators explicitly opt back into exponential backoff.
pub(crate) const DEFAULT_SYNC_TASK_RETRY_BACKOFF_MAX_SECS: u64 = 300;

/// Default maximum retries for sync tasks (matches migration default).
#[allow(dead_code)]
pub(crate) const DEFAULT_MAX_RETRIES: i32 = 3;

/// Second key (lock *class*) for the per-peer claim advisory lock, keeping it in
/// a distinct namespace from other two-key `pg_advisory_xact_lock` users such as
/// the scan-result preparer (`scan_result_service`). The first key is the peer
/// id folded to an `i32` (`fold_uuid_to_lock_key`), so the lock is granular
/// per peer: different peers' claim ticks never serialize against each other.
const SYNC_TASK_CLAIM_LOCK_CLASS: i32 = 0x5317;

/// Default TTL for a sync-task claim (`sync_tasks.claim_expires_at`).
///
/// A claim proves one replica owns a task's side effects. If the owner dies
/// mid-transfer, the task stays invisible to other replicas until the claim
/// expires, so the TTL bounds crash-recovery latency. Chunked transfers
/// extend the claim after every uploaded chunk, so the TTL only has to cover
/// the longest single chunk (50 MB default) plus the request timeout, not the
/// whole artifact.
///
/// Override with `SYNC_TASK_CLAIM_TTL_SECS` (positive integer).
const DEFAULT_SYNC_TASK_CLAIM_TTL_SECS: u64 = 1800;

/// Read the configured sync-task claim TTL from `SYNC_TASK_CLAIM_TTL_SECS`,
/// falling back to [`DEFAULT_SYNC_TASK_CLAIM_TTL_SECS`]. Non-positive values
/// are rejected so claims can never be born expired.
pub(crate) fn sync_task_claim_ttl_secs() -> u64 {
    std::env::var("SYNC_TASK_CLAIM_TTL_SECS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .filter(|&n| n > 0)
        .unwrap_or(DEFAULT_SYNC_TASK_CLAIM_TTL_SECS)
}

/// Check whether the current tick should trigger a stale peer detection run.
///
/// Returns `true` every `interval_ticks` ticks (e.g. every 6th tick = 60s
/// when each tick is 10s).
pub(crate) fn should_run_stale_check(tick_count: u64, interval_ticks: u64) -> bool {
    interval_ticks > 0 && tick_count % interval_ticks == 0
}

/// Check whether the current tick should trigger an active peer heartbeat probe.
pub(crate) fn should_run_peer_heartbeat_probe(tick_count: u64, interval_ticks: u64) -> bool {
    tick_count > 0 && interval_ticks > 0 && (tick_count == 1 || tick_count % interval_ticks == 0)
}

/// Compute the effective stale check period in seconds.
///
/// Useful for operators to understand the actual detection delay.
#[allow(dead_code)]
pub(crate) fn stale_check_period_secs() -> u64 {
    TICK_INTERVAL_SECS * STALE_CHECK_INTERVAL_TICKS
}

/// Build a log message for a stale peer detection result.
///
/// Returns `Some(message)` when peers were marked offline, `None` when
/// no peers were stale.
pub(crate) fn format_stale_detection_log(
    marked_count: u64,
    threshold_minutes: i32,
) -> Option<String> {
    if marked_count > 0 {
        Some(format!(
            "Marked {} stale peer(s) as offline (no heartbeat for {}+ minutes)",
            marked_count, threshold_minutes
        ))
    } else {
        None
    }
}

/// Spawn the background sync worker.
///
/// The worker runs in an infinite loop on a 10-second interval, picking up
/// pending sync tasks and dispatching transfers to remote peers.  Every 60
/// seconds it also checks for stale peers and marks them offline.
pub async fn spawn_sync_worker(db: PgPool, storage_registry: Arc<StorageRegistry>) {
    tokio::spawn(async move {
        // Small startup delay so the server can finish initializing.
        tokio::time::sleep(Duration::from_secs(5)).await;
        let mut tick = interval(Duration::from_secs(TICK_INTERVAL_SECS));
        let connect_timeout = peer_connect_timeout_secs();
        let client = crate::services::http_client::base_client_builder()
            .timeout(Duration::from_secs(300))
            // Bound the connect phase so an unreachable peer in a fan-out
            // fails fast instead of holding a transfer slot for the full
            // request timeout.
            .connect_timeout(Duration::from_secs(connect_timeout))
            .build()
            .expect("Failed to build HTTP client for sync worker");

        let mut tick_count: u64 = 0;
        let stale_interval_ticks = stale_check_interval_ticks();
        let stale_threshold_min = stale_peer_threshold_minutes();
        let peer_heartbeat_enabled = env_bool("PEER_HEARTBEAT_ENABLED", true);
        let peer_heartbeat_interval_secs = env_u64_min(
            "PEER_HEARTBEAT_INTERVAL_SECS",
            PEER_HEARTBEAT_INTERVAL_SECS,
            TICK_INTERVAL_SECS,
        );
        let peer_heartbeat_interval_ticks =
            interval_ticks_for_secs(peer_heartbeat_interval_secs, TICK_INTERVAL_SECS);
        let peer_heartbeat_timeout_secs = env_u64_min(
            "PEER_HEARTBEAT_TIMEOUT_SECS",
            PEER_HEARTBEAT_TIMEOUT_SECS,
            1,
        );
        let retry_policy = SyncRetryPolicy::from_env();
        tracing::info!(
            "Sync worker started: stale-check every {}s, threshold {}m, failover deadline ~{}s",
            stale_interval_ticks * TICK_INTERVAL_SECS,
            stale_threshold_min,
            failover_detection_deadline_secs(
                stale_interval_ticks,
                stale_threshold_min,
                TICK_INTERVAL_SECS,
            )
        );
        tracing::info!(
            "Peer heartbeat probes are {} (interval={}s, timeout={}s)",
            if peer_heartbeat_enabled {
                "enabled"
            } else {
                "disabled"
            },
            peer_heartbeat_interval_secs,
            peer_heartbeat_timeout_secs,
        );
        tracing::info!(
            "Sync task retry policy: max_retries={}, backoff_base={}s, backoff_max={}s",
            retry_policy.max_retries,
            retry_policy.backoff_base_secs,
            retry_policy.backoff_max_secs,
        );

        loop {
            tick.tick().await;
            tick_count += 1;

            if peer_heartbeat_enabled
                && should_run_peer_heartbeat_probe(tick_count, peer_heartbeat_interval_ticks)
            {
                run_peer_heartbeat_probes(
                    &db,
                    &client,
                    Duration::from_secs(peer_heartbeat_timeout_secs),
                )
                .await;
            }

            // Periodically check for stale peers and mark them offline.
            if should_run_stale_check(tick_count, stale_interval_ticks) {
                run_stale_peer_detection(&db, stale_threshold_min).await;
            }

            if let Err(e) =
                process_pending_tasks(&db, &client, storage_registry.clone(), retry_policy).await
            {
                tracing::error!("Sync worker error: {e}");
            }
        }
    });
}

/// Detect peers that have not sent a heartbeat within the threshold and
/// mark them offline.
async fn run_stale_peer_detection(db: &PgPool, threshold_minutes: i32) {
    let peer_service = crate::services::peer_instance_service::PeerInstanceService::new(db.clone());
    match peer_service.mark_stale_offline(threshold_minutes).await {
        Ok(count) => {
            if let Some(msg) = format_stale_detection_log(count, threshold_minutes) {
                tracing::info!("{}", msg);
            }
        }
        Err(e) => {
            tracing::error!("Failed to run stale peer detection: {e}");
        }
    }
}

async fn run_peer_heartbeat_probes(
    db: &PgPool,
    client: &reqwest::Client,
    request_timeout: Duration,
) {
    let peers: Vec<PeerHeartbeatRow> = match sqlx::query_as(
        r#"
        SELECT id, name, endpoint_url, api_key
        FROM peer_instances
        WHERE is_local = false
        "#,
    )
    .fetch_all(db)
    .await
    {
        Ok(peers) => peers,
        Err(e) => {
            tracing::warn!("Failed to load peers for heartbeat probe: {e}");
            return;
        }
    };

    for peer in peers {
        match probe_peer(client, &peer, request_timeout).await {
            Ok(()) => {
                if let Err(e) = mark_peer_online(db, peer.id).await {
                    tracing::warn!(
                        "Peer heartbeat probe succeeded for '{}', but status update failed: {e}",
                        peer.name
                    );
                }
            }
            Err(e) => {
                tracing::warn!("Peer heartbeat probe failed for '{}': {e}", peer.name);
                if let Err(update_err) = mark_peer_probe_failed(db, peer.id).await {
                    tracing::warn!(
                        "Failed to record heartbeat probe failure for '{}': {update_err}",
                        peer.name
                    );
                }
            }
        }
    }
}

async fn probe_peer(
    client: &reqwest::Client,
    peer: &PeerHeartbeatRow,
    request_timeout: Duration,
) -> Result<(), String> {
    let url = format!("{}/api/v1/peers", peer.endpoint_url.trim_end_matches('/'));
    let response = client
        .get(&url)
        .header("Authorization", format!("Bearer {}", peer.api_key))
        .timeout(request_timeout)
        .send()
        .await
        .map_err(|e| format!("request to {url} failed: {e}"))?;

    if response.status().is_success() {
        Ok(())
    } else {
        Err(format!(
            "request to {url} returned HTTP {}",
            response.status()
        ))
    }
}

async fn mark_peer_online(db: &PgPool, peer_id: Uuid) -> Result<(), sqlx::Error> {
    sqlx::query(
        r#"
        UPDATE peer_instances
        SET status = 'online',
            last_heartbeat_at = NOW(),
            consecutive_failures = 0,
            updated_at = NOW()
        WHERE id = $1
        "#,
    )
    .bind(peer_id)
    .execute(db)
    .await?;

    Ok(())
}

async fn mark_peer_probe_failed(db: &PgPool, peer_id: Uuid) -> Result<(), sqlx::Error> {
    sqlx::query(
        r#"
        UPDATE peer_instances
        SET consecutive_failures = CASE
                WHEN consecutive_failures < 2147483647 THEN consecutive_failures + 1
                ELSE consecutive_failures
            END,
            updated_at = NOW()
        WHERE id = $1
        "#,
    )
    .bind(peer_id)
    .execute(db)
    .await?;

    Ok(())
}

fn env_bool(key: &str, default: bool) -> bool {
    match std::env::var(key) {
        Ok(value) => match value.to_ascii_lowercase().as_str() {
            "1" | "true" | "yes" | "on" => true,
            "0" | "false" | "no" | "off" => false,
            _ => default,
        },
        Err(_) => default,
    }
}

fn env_u64_min(key: &str, default: u64, min: u64) -> u64 {
    std::env::var(key)
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(default)
        .max(min)
}

fn env_i32_min(key: &str, default: i32, min: i32) -> i32 {
    std::env::var(key)
        .ok()
        .and_then(|value| value.parse::<i32>().ok())
        .unwrap_or(default)
        .max(min)
}

#[derive(Debug, Clone, Copy)]
struct SyncRetryPolicy {
    max_retries: i32,
    backoff_base_secs: u64,
    backoff_max_secs: u64,
}

impl SyncRetryPolicy {
    fn from_env() -> Self {
        let backoff_max_secs = env_u64_min(
            "SYNC_TASK_RETRY_BACKOFF_MAX_SECS",
            DEFAULT_SYNC_TASK_RETRY_BACKOFF_MAX_SECS,
            1,
        );
        let backoff_base_secs =
            env_u64_min("SYNC_TASK_RETRY_BACKOFF_BASE_SECS", backoff_max_secs, 1);
        let max_retries = env_i32_min("SYNC_TASK_MAX_RETRIES", DEFAULT_MAX_RETRIES, 1);

        Self {
            max_retries,
            backoff_base_secs,
            backoff_max_secs,
        }
    }

    fn calculate_backoff(self, consecutive_failures: i32) -> Duration {
        calculate_configured_backoff(
            consecutive_failures,
            self.backoff_base_secs,
            self.backoff_max_secs,
        )
    }
}

fn interval_ticks_for_secs(interval_secs: u64, tick_secs: u64) -> u64 {
    interval_secs.div_ceil(tick_secs).max(1)
}

// ── Internal row types ──────────────────────────────────────────────────────

/// Lightweight projection of `peer_instances` used by the worker.
#[derive(Debug, sqlx::FromRow)]
struct PeerRow {
    id: Uuid,
    name: String,
    endpoint_url: String,
    api_key: String,
    sync_window_start: Option<NaiveTime>,
    sync_window_end: Option<NaiveTime>,
    sync_window_timezone: Option<String>,
    concurrent_transfers_limit: Option<i32>,
    active_transfers: i32,
}

/// Lightweight projection used by active peer heartbeat probes.
#[derive(Debug, sqlx::FromRow)]
struct PeerHeartbeatRow {
    id: Uuid,
    name: String,
    endpoint_url: String,
    api_key: String,
}

/// Lightweight projection of a pending sync task joined with the artifact.
#[derive(Debug, sqlx::FromRow)]
#[allow(dead_code)]
struct TaskRow {
    id: Uuid,
    peer_instance_id: Uuid,
    artifact_id: Uuid,
    priority: i32,
    storage_key: String,
    artifact_size: i64,
    artifact_name: String,
    artifact_version: Option<String>,
    artifact_path: String,
    artifact_metadata_format: Option<String>,
    artifact_metadata: Option<serde_json::Value>,
    artifact_metadata_properties: Option<serde_json::Value>,
    package_description: Option<String>,
    package_metadata: Option<serde_json::Value>,
    repository_key: String,
    repository_id: Uuid,
    repository_storage_backend: String,
    repository_storage_path: String,
    content_type: String,
    checksum_sha256: String,
    task_type: String,
    replication_filter: Option<serde_json::Value>,
    retry_count: i32,
    max_retries: i32,
}

// ── Scored peer selection ────────────────────────────────────────────────────

/// Resolve the best peer endpoint for a sync task using scored peer selection.
///
/// If the local peer instance is known and scored peers are available for the
/// artifact, returns the highest-scoring peer's endpoint URL and API key.
/// Otherwise returns `None`, signalling the caller to use the task's default peer.
/// Pick the best peer from a list of scored peers.
///
/// Returns the peer with the highest score, or `None` if the list is empty.
fn pick_best_peer(
    scored: &[crate::services::peer_service::ScoredPeer],
) -> Option<&crate::services::peer_service::ScoredPeer> {
    scored.iter().max_by(|a, b| {
        a.score
            .partial_cmp(&b.score)
            .unwrap_or(std::cmp::Ordering::Equal)
    })
}

async fn resolve_scored_peer(
    db: &PgPool,
    local_peer_id: Option<Uuid>,
    artifact_id: Uuid,
    default_peer_name: &str,
) -> Option<(String, String)> {
    let local_id = local_peer_id?;

    let peer_service = crate::services::peer_service::PeerService::new(db.clone());
    let scored = match peer_service
        .get_scored_peers_for_artifact(local_id, artifact_id)
        .await
    {
        Ok(peers) => peers,
        Err(e) => {
            tracing::warn!(
                "Scored peer lookup failed for artifact {}, falling back to default peer '{}': {e}",
                artifact_id,
                default_peer_name,
            );
            return None;
        }
    };

    // Pick the peer with the highest score.
    let best = pick_best_peer(&scored)?;

    // Look up the API key for the scored peer.
    let api_key: Option<String> =
        sqlx::query_scalar("SELECT api_key FROM peer_instances WHERE id = $1")
            .bind(best.node_id)
            .fetch_optional(db)
            .await
            .ok()
            .flatten();

    let api_key = api_key?;

    tracing::debug!(
        "Scored peer selection for artifact {}: chose peer {} (score={:.2}, latency={:?}ms, chunks={}) over default peer '{}'",
        artifact_id,
        best.node_id,
        best.score,
        best.latency_ms,
        best.available_chunks,
        default_peer_name,
    );

    Some((best.endpoint_url.clone(), api_key))
}

/// Look up the local peer instance ID.
///
/// Returns `None` if no local instance is configured (single-node deployments).
/// The result is cached for the lifetime of a single `process_pending_tasks` tick.
async fn get_local_peer_id(db: &PgPool) -> Option<Uuid> {
    sqlx::query_scalar("SELECT id FROM peer_instances WHERE is_local = true LIMIT 1")
        .fetch_optional(db)
        .await
        .ok()
        .flatten()
}

// ── Cluster-wide task claims (RowClaimedQueue) ──────────────────────────────

/// Atomically claim up to `available_slots` due pending tasks for one peer.
///
/// This is the reference `RowClaimedQueue` implementation described in
/// [`crate::services::cluster_work`]: candidates are selected with
/// `FOR UPDATE SKIP LOCKED` and flipped `pending -> in_progress` with a fresh
/// `claim_token` in the same statement, so two replicas ticking concurrently
/// drain disjoint rows instead of double-executing the same peer push/delete.
///
/// The effective batch size is additionally capped, inside the statement, by
/// `concurrent_limit` minus the number of live (unexpired) `in_progress`
/// claims for the peer. That derives per-peer concurrency from claimed rows
/// rather than trusting the racy `peer_instances.active_transfers` counter
/// alone, which each replica reads before the others increment it. To make that
/// cap hold even when two replicas' claim statements overlap exactly (where the
/// in-statement count alone is racy under READ COMMITTED), the whole claim runs
/// under a per-peer transaction-scoped advisory lock (see the body).
async fn claim_pending_sync_tasks(
    db: &PgPool,
    peer_id: Uuid,
    available_slots: i64,
    concurrent_limit: i64,
    max_retries: i32,
    claimed_by: &str,
    claim_ttl_secs: f64,
) -> Result<Vec<Claimed<TaskRow>>, String> {
    use crate::services::scan_result_service::fold_uuid_to_lock_key;
    use sqlx::{FromRow, Row};

    // Serialize the *claim step* per peer with a transaction-scoped advisory
    // lock. The in-statement live-claim count below caps a single claimer, but
    // under READ COMMITTED it is racy across replicas: two claim statements that
    // truly overlap each read a live count that excludes the other's not-yet-
    // committed claim, so each grabs up to `concurrent_limit` rows on disjoint
    // (SKIP LOCKED) candidates — collectively oversubscribing the peer by
    // replica count. Holding a per-peer lock across the claim forces the second
    // claimer to observe the first's committed claims before counting, making
    // the cap hard. The lock is released on commit/rollback; different peers use
    // different keys and never block one another.
    let mut tx = db
        .begin()
        .await
        .map_err(|e| format!("Failed to open claim transaction for peer {peer_id}: {e}"))?;
    sqlx::query("SELECT pg_advisory_xact_lock($1, $2)")
        .bind(fold_uuid_to_lock_key(peer_id))
        .bind(SYNC_TASK_CLAIM_LOCK_CLASS)
        .execute(&mut *tx)
        .await
        .map_err(|e| format!("Failed to take claim lock for peer {peer_id}: {e}"))?;

    let rows = sqlx::query(
        r#"
        WITH candidate AS (
            SELECT st.id
            FROM sync_tasks st
            JOIN artifacts a ON a.id = st.artifact_id
            WHERE st.peer_instance_id = $1
              AND st.status = 'pending'
              AND (st.claim_expires_at IS NULL OR st.claim_expires_at <= NOW())
              AND (st.task_type = 'delete' OR a.is_deleted = false)
            ORDER BY st.priority DESC, st.created_at ASC
            LIMIT LEAST(
                $2,
                GREATEST(
                    $3 - (
                        SELECT COUNT(*)
                        FROM sync_tasks
                        WHERE peer_instance_id = $1
                          AND status = 'in_progress'
                          AND claim_token IS NOT NULL
                          AND claim_expires_at > NOW()
                    ),
                    0
                )
            )
            FOR UPDATE OF st SKIP LOCKED
        ),
        claimed AS (
            UPDATE sync_tasks st
            SET status = 'in_progress',
                started_at = NOW(),
                claimed_by = $5,
                claim_token = gen_random_uuid(),
                claim_expires_at = NOW() + make_interval(secs => $6)
            FROM candidate
            WHERE st.id = candidate.id
            RETURNING st.*
        )
        SELECT
            c.id,
            c.peer_instance_id,
            c.artifact_id,
            c.priority,
            a.storage_key,
            a.size_bytes AS artifact_size,
            a.name AS artifact_name,
            a.version AS artifact_version,
            a.path AS artifact_path,
            am.format AS artifact_metadata_format,
            am.metadata AS artifact_metadata,
            am.properties AS artifact_metadata_properties,
            CASE
                WHEN p.version = a.version THEN p.description
                ELSE NULL
            END AS package_description,
            CASE
                WHEN p.version = a.version THEN p.metadata
                ELSE NULL
            END AS package_metadata,
            r.key AS repository_key,
            r.id AS repository_id,
            r.storage_backend AS repository_storage_backend,
            r.storage_path AS repository_storage_path,
            a.content_type,
            a.checksum_sha256,
            c.task_type,
            prs.replication_filter,
            c.retry_count,
            GREATEST(c.max_retries, $4)::INT AS max_retries,
            c.claim_token,
            c.claimed_by,
            c.claim_expires_at
        FROM claimed c
        JOIN artifacts a ON a.id = c.artifact_id
        JOIN repositories r ON r.id = a.repository_id
        LEFT JOIN artifact_metadata am ON am.artifact_id = a.id
        LEFT JOIN packages p
            ON p.repository_id = r.id
           AND p.name = a.name
        LEFT JOIN peer_repo_subscriptions prs
            ON prs.peer_instance_id = c.peer_instance_id
           AND prs.repository_id = r.id
        ORDER BY c.priority DESC, c.created_at ASC
        "#,
    )
    .bind(peer_id)
    .bind(available_slots)
    .bind(concurrent_limit)
    .bind(max_retries)
    .bind(claimed_by)
    .bind(claim_ttl_secs)
    .fetch_all(&mut *tx)
    .await
    .map_err(|e| format!("Failed to claim tasks for peer {peer_id}: {e}"))?;

    tx.commit()
        .await
        .map_err(|e| format!("Failed to commit claim for peer {peer_id}: {e}"))?;

    rows.into_iter()
        .map(|row| {
            let task =
                TaskRow::from_row(&row).map_err(|e| format!("Failed to decode task row: {e}"))?;
            let claim_token: Uuid = row
                .try_get("claim_token")
                .map_err(|e| format!("Failed to decode claim_token: {e}"))?;
            let claimed_by: String = row
                .try_get("claimed_by")
                .map_err(|e| format!("Failed to decode claimed_by: {e}"))?;
            let claim_expires_at: chrono::DateTime<Utc> = row
                .try_get("claim_expires_at")
                .map_err(|e| format!("Failed to decode claim_expires_at: {e}"))?;
            Ok(Claimed::from_claim_row(
                task,
                claim_token,
                claimed_by,
                claim_expires_at,
            ))
        })
        .collect()
}

/// Reset expired `in_progress` claims to `pending` so tasks abandoned by a
/// crashed replica become retryable, and walk back the per-peer
/// `active_transfers` counter the dead owner never decremented.
///
/// The counter compensation is best-effort bookkeeping (an owner that died
/// between claiming and incrementing walks the counter toward zero, which the
/// `GREATEST(..., 0)` clamp absorbs); correctness against double execution
/// rests on the claim token, not the counter.
async fn recover_expired_sync_task_claims(db: &PgPool) -> Result<u64, String> {
    let result = sqlx::query(
        r#"
        WITH recovered AS (
            UPDATE sync_tasks
            SET status = 'pending',
                started_at = NULL,
                claimed_by = NULL,
                claim_token = NULL,
                claim_expires_at = NULL
            WHERE status = 'in_progress'
              AND (
                  claim_token IS NULL
                  OR claimed_by IS NULL
                  OR claim_expires_at IS NULL
                  OR claim_expires_at <= NOW()
              )
            RETURNING peer_instance_id
        ),
        counts AS (
            SELECT peer_instance_id, COUNT(*)::INT AS n
            FROM recovered
            GROUP BY peer_instance_id
        )
        UPDATE peer_instances p
        SET active_transfers = GREATEST(p.active_transfers - counts.n, 0),
            updated_at = NOW()
        FROM counts
        WHERE p.id = counts.peer_instance_id
        RETURNING counts.n
        "#,
    )
    .fetch_all(db)
    .await
    .map_err(|e| format!("Failed to recover expired sync task claims: {e}"))?;

    use sqlx::Row;
    let recovered: i64 = result
        .iter()
        .map(|row| row.try_get::<i32, _>("n").unwrap_or(0) as i64)
        .sum();
    Ok(recovered.max(0) as u64)
}

/// Extend the caller's claim on a task. Chunked transfers call this after
/// every uploaded chunk so a healthy long transfer keeps its lease while a
/// crashed one lapses within one TTL. Best-effort: a lost claim surfaces at
/// the token-guarded finalize, not here.
async fn extend_sync_task_claim(db: &PgPool, task: &Claimed<TaskRow>, claim_ttl_secs: f64) {
    let _ = sqlx::query(
        r#"
        UPDATE sync_tasks
        SET claim_expires_at = NOW() + make_interval(secs => $2)
        WHERE id = $1
          AND status = 'in_progress'
          AND claim_token = $3
        "#,
    )
    .bind(task.id)
    .bind(claim_ttl_secs)
    .bind(task.claim_token())
    .execute(db)
    .await;
}

// ── Core logic ──────────────────────────────────────────────────────────────

/// Process all eligible peers and their pending sync tasks.
async fn process_pending_tasks(
    db: &PgPool,
    client: &reqwest::Client,
    storage_registry: Arc<StorageRegistry>,
    retry_policy: SyncRetryPolicy,
) -> Result<(), String> {
    // Reset in_progress tasks whose claim lapsed (owner crashed or lost its
    // DB connection mid-transfer) so they become claimable again.
    match recover_expired_sync_task_claims(db).await {
        Ok(0) => {}
        Ok(n) => tracing::info!("Recovered {} sync task(s) with expired claims", n),
        Err(e) => tracing::warn!("{e}"),
    }

    // Fetch non-local peers that are online or syncing and not in backoff.
    let peers: Vec<PeerRow> = sqlx::query_as(
        r#"
        SELECT
            id, name, endpoint_url, api_key,
            sync_window_start, sync_window_end, sync_window_timezone,
            concurrent_transfers_limit, active_transfers
        FROM peer_instances
        WHERE is_local = false
          AND status IN ('online', 'syncing')
          AND (backoff_until IS NULL OR backoff_until <= NOW())
        "#,
    )
    .fetch_all(db)
    .await
    .map_err(|e| format!("Failed to fetch peers: {e}"))?;

    if peers.is_empty() {
        return Ok(());
    }

    // Resolve the local peer instance ID once per tick. This is used for scored
    // peer selection and is None on single-node deployments.
    let local_peer_id = get_local_peer_id(db).await;

    // Reset retriable failed tasks for peers that have recovered (backoff expired).
    // This runs once per tick for all recovered peers in a single query.
    let retried = sqlx::query(
        r#"
        UPDATE sync_tasks
        SET status = 'pending', error_message = NULL, started_at = NULL, completed_at = NULL,
            claimed_by = NULL, claim_token = NULL, claim_expires_at = NULL
        WHERE status = 'failed'
          AND retry_count < GREATEST(max_retries, $1)
          AND EXISTS (
              SELECT 1
              FROM artifacts a
              WHERE a.id = sync_tasks.artifact_id
                AND (sync_tasks.task_type = 'delete' OR a.is_deleted = false)
          )
          AND peer_instance_id = ANY(
              SELECT id FROM peer_instances
              WHERE is_local = false
                AND status IN ('online', 'syncing')
                AND (backoff_until IS NULL OR backoff_until <= NOW())
          )
        "#,
    )
    .bind(retry_policy.max_retries)
    .execute(db)
    .await
    .map_err(|e| format!("Failed to reset retriable tasks: {e}"))?;

    if retried.rows_affected() > 0 {
        tracing::info!(
            "Reset {} failed sync task(s) for retry after peer recovery",
            retried.rows_affected()
        );
    }

    let now = Utc::now();

    for peer in &peers {
        // ── Sync window check ───────────────────────────────────────────
        if let (Some(start), Some(end)) = (peer.sync_window_start, peer.sync_window_end) {
            let tz_name = peer.sync_window_timezone.as_deref().unwrap_or("UTC");
            let utc_offset_secs = parse_utc_offset_secs(tz_name);
            let peer_now_secs =
                (now.num_seconds_from_midnight() as i64 + utc_offset_secs).rem_euclid(86400);
            let peer_time = NaiveTime::from_num_seconds_from_midnight_opt(peer_now_secs as u32, 0)
                .unwrap_or(NaiveTime::from_hms_opt(0, 0, 0).unwrap());

            if !is_within_sync_window(start, end, peer_time) {
                tracing::debug!(
                    "Peer '{}' outside sync window ({} - {}), skipping",
                    peer.name,
                    start,
                    end
                );
                continue;
            }
        }

        // ── Concurrency check ───────────────────────────────────────────
        let available_slots =
            compute_available_slots(peer.concurrent_transfers_limit, peer.active_transfers);
        if available_slots <= 0 {
            tracing::debug!(
                "Peer '{}' at concurrency limit ({}/{}), skipping",
                peer.name,
                peer.active_transfers,
                peer.concurrent_transfers_limit.unwrap_or(5)
            );
            continue;
        }

        // ── Claim pending tasks (RowClaimedQueue) ───────────────────────
        // Claiming (not just selecting) is what stops a second replica from
        // executing the same task in this window; the in-statement live-claim
        // count additionally stops N replicas from collectively oversubscribing
        // the peer through the stale `active_transfers` snapshot above.
        let tasks = claim_pending_sync_tasks(
            db,
            peer.id,
            available_slots as i64,
            peer.concurrent_transfers_limit.unwrap_or(5) as i64,
            retry_policy.max_retries,
            WorkerIdentity::for_process().as_str(),
            sync_task_claim_ttl_secs() as f64,
        )
        .await
        .map_err(|e| format!("Failed to claim tasks for peer '{}': {e}", peer.name))?;

        if tasks.is_empty() {
            continue;
        }

        tracing::info!(
            "Dispatching {} sync task(s) to peer '{}'",
            tasks.len(),
            peer.name
        );

        // Spawn each transfer concurrently, skipping filtered artifacts.
        for task in tasks {
            // Build an identifier combining name + version for filter matching.
            let identifier = match &task.artifact_version {
                Some(v) if !v.is_empty() => format!("{}:{}", task.artifact_name, v),
                _ => task.artifact_name.clone(),
            };
            if !matches_replication_filter(&identifier, task.replication_filter.as_ref()) {
                tracing::debug!(
                    "Artifact '{}' filtered out by replication filter for peer '{}', marking completed",
                    identifier,
                    peer.name
                );
                let _ = sqlx::query(
                    "UPDATE sync_tasks \
                     SET status = 'completed', completed_at = NOW(), \
                         claimed_by = NULL, claim_token = NULL, claim_expires_at = NULL \
                     WHERE id = $1 AND status = 'in_progress' AND claim_token = $2",
                )
                .bind(task.id)
                .bind(task.claim_token())
                .execute(db)
                .await;
                continue;
            }

            // Attempt scored peer selection: if a better-scoring peer is available
            // for this artifact, use its endpoint instead of the task's default.
            let (peer_endpoint, peer_api_key) =
                resolve_scored_peer(db, local_peer_id, task.artifact_id, &peer.name)
                    .await
                    .unwrap_or_else(|| (peer.endpoint_url.clone(), peer.api_key.clone()));

            let db = db.clone();
            let client = client.clone();
            let peer_name = peer.name.clone();
            let storage_registry = storage_registry.clone();

            tokio::spawn(async move {
                if let Err(e) = execute_transfer(
                    &db,
                    &client,
                    storage_registry,
                    &task,
                    &peer_endpoint,
                    &peer_api_key,
                    retry_policy,
                )
                .await
                {
                    tracing::error!(
                        "Transfer failed for task {} to peer '{}': {e}",
                        task.id,
                        peer_name
                    );
                }
            });
        }
    }

    Ok(())
}

/// Execute a single claimed sync task (push or delete) to a remote peer.
///
/// Takes [`Claimed<TaskRow>`], not a bare row: the caller must have won the
/// atomic claim (which already flipped the task `in_progress`), and every
/// finalizer below re-asserts the claim token before writing.
async fn execute_transfer(
    db: &PgPool,
    client: &reqwest::Client,
    storage_registry: Arc<StorageRegistry>,
    task: &Claimed<TaskRow>,
    peer_endpoint: &str,
    peer_api_key: &str,
    retry_policy: SyncRetryPolicy,
) -> Result<(), String> {
    // 1. Increment active_transfers (the claim already marked the task
    //    in_progress and stamped the claim columns).
    sqlx::query(
        r#"
        UPDATE peer_instances
        SET active_transfers = active_transfers + 1, updated_at = NOW()
        WHERE id = $1
        "#,
    )
    .bind(task.peer_instance_id)
    .execute(db)
    .await
    .map_err(|e| format!("Failed to increment active_transfers: {e}"))?;

    if task.task_type == "delete" {
        return execute_delete(db, client, task, peer_endpoint, peer_api_key, retry_policy).await;
    }

    // Push flow: decide between single-request upload and chunked transfer
    // based on the artifact size or the need to preserve metadata.
    let threshold = chunked_threshold_bytes();
    if should_use_chunked_transfer_for_task(task, threshold) {
        return execute_chunked_transfer(
            db,
            client,
            &storage_registry,
            task,
            peer_endpoint,
            peer_api_key,
            retry_policy,
        )
        .await;
    }

    // Fast path for small artifacts: read entire file and PUT it to the same
    // artifact path on the remote peer. POST /artifacts is the multipart upload
    // endpoint.

    // 2. Read the artifact bytes from local storage.
    let file_bytes = match read_artifact_from_storage(&storage_registry, task).await {
        Ok(bytes) => bytes,
        Err(e) => {
            handle_transfer_failure(db, task, &format!("Storage read error: {e}"), retry_policy)
                .await;
            return Err(format!("Storage read error: {e}"));
        }
    };

    let bytes_len = file_bytes.len() as i64;

    // 3. PUT the artifact to the remote peer.
    let url = build_transfer_url(peer_endpoint, &task.repository_key, &task.artifact_path);

    let request = replication_put_headers(task, peer_api_key)
        .into_iter()
        .fold(client.put(&url), |req, (name, value)| {
            req.header(name, value)
        });
    let result = request.body(file_bytes).send().await;

    match result {
        Ok(response) if response.status().is_success() => {
            // 4a. Success path.
            handle_transfer_success(db, task, bytes_len).await;
            tracing::info!(
                "Synced artifact '{}' ({} bytes) to peer (task {})",
                task.artifact_name,
                bytes_len,
                task.id
            );
            Ok(())
        }
        Ok(response) => {
            let status = response.status();
            let body = response
                .text()
                .await
                .unwrap_or_else(|_| unreadable_response_body());
            let msg = format_peer_response_failure("Remote peer returned", status.as_u16(), &body);
            handle_transfer_failure(db, task, &msg, retry_policy).await;
            Err(msg)
        }
        Err(e) => {
            let msg = format!("HTTP request failed: {e}");
            handle_transfer_failure(db, task, &msg, retry_policy).await;
            Err(msg)
        }
    }
}

/// Execute a chunked upload for a large replicated artifact.
///
/// Instead of reading the entire artifact into memory and sending it in one
/// request, this creates a regular upload session on the remote peer, sends
/// each byte range as one PATCH request, then asks the peer to finalize the
/// upload into its repository storage. This is intentionally the same API used
/// by direct large uploads: it works when the target peer has never seen the
/// artifact before, verifies the final checksum, and materializes the target
/// artifact row + storage object on completion.
async fn execute_chunked_transfer(
    db: &PgPool,
    client: &reqwest::Client,
    storage_registry: &StorageRegistry,
    task: &Claimed<TaskRow>,
    peer_endpoint: &str,
    peer_api_key: &str,
    retry_policy: SyncRetryPolicy,
) -> Result<(), String> {
    let chunk_size = sync_chunk_size_bytes();

    tracing::info!(
        "Using chunked transfer for artifact '{}' ({} bytes, chunk_size={}) to peer (task {})",
        task.artifact_name,
        task.artifact_size,
        chunk_size,
        task.id
    );

    // 1. Initialize a resumable upload session on the remote peer.
    let init_url = build_chunked_upload_session_url(peer_endpoint);
    let init_body = build_chunked_upload_session_body(task, chunk_size);

    let init_response = client
        .post(&init_url)
        .header("Authorization", format!("Bearer {}", peer_api_key))
        .header(REPLICATION_REQUEST_HEADER, REPLICATION_REQUEST_VALUE)
        .header("Content-Type", "application/json")
        .json(&init_body)
        .send()
        .await
        .map_err(|e| format!("Failed to init chunked upload: {e}"))?;

    if !init_response.status().is_success() {
        let status = init_response.status();
        let body = init_response
            .text()
            .await
            .unwrap_or_else(|_| unreadable_response_body());
        let msg =
            format_peer_response_failure("Chunked upload init returned", status.as_u16(), &body);
        handle_transfer_failure(db, task, &msg, retry_policy).await;
        return Err(msg);
    }

    let session: serde_json::Value = match init_response.json().await {
        Ok(session) => session,
        Err(e) => {
            let msg = format!("Failed to parse upload session response: {e}");
            handle_transfer_failure(db, task, &msg, retry_policy).await;
            return Err(msg);
        }
    };

    let session_id = match parse_chunked_session_id(&session) {
        Some(session_id) => session_id,
        None => {
            let msg = "Missing session_id in chunked upload init response".to_string();
            handle_transfer_failure(db, task, &msg, retry_policy).await;
            return Err(msg);
        }
    };

    // 2. Upload chunks one at a time. Each chunk is read through the
    // repository's storage backend using `get_range`; for S3 this is a
    // true HTTP Range GET rather than a full-object re-download.
    let chunk_ranges = compute_chunk_ranges(task.artifact_size, chunk_size);
    let mut bytes_transferred: i64 = 0;

    for (chunk_index, byte_offset, byte_length) in &chunk_ranges {
        // Read just this chunk from storage.
        let chunk_data = match read_artifact_chunk_from_storage(
            storage_registry,
            task,
            *byte_offset as u64,
            *byte_length as usize,
        )
        .await
        {
            Ok(data) => data,
            Err(e) => {
                let msg = format!(
                    "Failed to read chunk {} (offset={}, len={}): {e}",
                    chunk_index, byte_offset, byte_length
                );
                cancel_chunked_upload_session(client, peer_endpoint, peer_api_key, &session_id)
                    .await;
                handle_transfer_failure(db, task, &msg, retry_policy).await;
                return Err(msg);
            }
        };

        // Upload the chunk to the peer's resumable upload session. The
        // Content-Range header lets the receiver write it at the correct
        // offset in its temp file before final checksum verification.
        let chunk_upload_url = build_chunked_upload_chunk_url(peer_endpoint, &session_id);
        let content_range = build_content_range(*byte_offset, *byte_length, task.artifact_size);

        let upload_result = client
            .patch(&chunk_upload_url)
            .header("Authorization", format!("Bearer {}", peer_api_key))
            .header(REPLICATION_REQUEST_HEADER, REPLICATION_REQUEST_VALUE)
            .header("Content-Type", "application/octet-stream")
            .header("Content-Range", content_range)
            .body(chunk_data)
            .send()
            .await;

        match upload_result {
            Ok(resp) if resp.status().is_success() => {
                bytes_transferred += *byte_length as i64;
                // Keep the claim alive: a healthy multi-chunk transfer must
                // not lapse mid-flight, while a crashed one expires within
                // one TTL of its last completed chunk.
                extend_sync_task_claim(db, task, sync_task_claim_ttl_secs() as f64).await;
                tracing::debug!(
                    "Chunk {}/{} uploaded for task {} ({} bytes)",
                    chunk_index + 1,
                    chunk_ranges.len(),
                    task.id,
                    byte_length
                );
            }
            Ok(resp) => {
                let status = resp.status();
                let body = resp
                    .text()
                    .await
                    .unwrap_or_else(|_| unreadable_response_body());
                let msg = format!("Chunk {} upload returned {status}: {body}", chunk_index);
                cancel_chunked_upload_session(client, peer_endpoint, peer_api_key, &session_id)
                    .await;
                handle_transfer_failure(db, task, &msg, retry_policy).await;
                return Err(msg);
            }
            Err(e) => {
                let msg = format!("Chunk {} upload failed: {e}", chunk_index);
                cancel_chunked_upload_session(client, peer_endpoint, peer_api_key, &session_id)
                    .await;
                handle_transfer_failure(db, task, &msg, retry_policy).await;
                return Err(msg);
            }
        }
    }

    // 3. Finalize the upload session. The remote peer verifies the complete
    // file SHA-256, writes to the repository's configured storage backend, and
    // creates/updates the target artifact row.
    let session_complete_url = build_chunked_upload_complete_url(peer_endpoint, &session_id);

    let complete_result = client
        .put(&session_complete_url)
        .header("Authorization", format!("Bearer {}", peer_api_key))
        .header(REPLICATION_REQUEST_HEADER, REPLICATION_REQUEST_VALUE)
        .send()
        .await;

    match complete_result {
        Ok(resp) if resp.status().is_success() => {
            handle_transfer_success(db, task, bytes_transferred).await;
            tracing::info!(
                "Chunked transfer complete for artifact '{}' ({} bytes in {} chunks) to peer (task {})",
                task.artifact_name,
                bytes_transferred,
                chunk_ranges.len(),
                task.id
            );
            Ok(())
        }
        Ok(resp) => {
            let status = resp.status();
            let body = resp
                .text()
                .await
                .unwrap_or_else(|_| unreadable_response_body());
            let msg = format!("Chunked upload session complete returned {status}: {body}");
            cancel_chunked_upload_session(client, peer_endpoint, peer_api_key, &session_id).await;
            handle_transfer_failure(db, task, &msg, retry_policy).await;
            Err(msg)
        }
        Err(e) => {
            let msg = format!("Chunked upload session complete failed: {e}");
            cancel_chunked_upload_session(client, peer_endpoint, peer_api_key, &session_id).await;
            handle_transfer_failure(db, task, &msg, retry_policy).await;
            Err(msg)
        }
    }
}

/// Execute a delete task: tell the remote peer to remove an artifact.
async fn execute_delete(
    db: &PgPool,
    client: &reqwest::Client,
    task: &Claimed<TaskRow>,
    peer_endpoint: &str,
    peer_api_key: &str,
    retry_policy: SyncRetryPolicy,
) -> Result<(), String> {
    let url = build_delete_url(peer_endpoint, &task.repository_key, &task.artifact_path);

    let result = client
        .delete(&url)
        .header("Authorization", format!("Bearer {}", peer_api_key))
        .header(REPLICATION_REQUEST_HEADER, REPLICATION_REQUEST_VALUE)
        .send()
        .await;

    match result {
        Ok(response) if delete_response_is_success(response.status().as_u16()) => {
            // 404 is acceptable: the artifact may already be gone.
            handle_transfer_success(db, task, 0).await;
            tracing::info!(
                "Deleted artifact '{}' from peer (task {})",
                task.artifact_path,
                task.id
            );
            Ok(())
        }
        Ok(response) => {
            let status = response.status();
            let body = response
                .text()
                .await
                .unwrap_or_else(|_| unreadable_response_body());
            let msg = format!("Remote peer returned {status} for delete: {body}");
            handle_transfer_failure(db, task, &msg, retry_policy).await;
            Err(msg)
        }
        Err(e) => {
            let msg = format!("HTTP delete request failed: {e}");
            handle_transfer_failure(db, task, &msg, retry_policy).await;
            Err(msg)
        }
    }
}

fn storage_location_for_task(task: &TaskRow) -> StorageLocation {
    StorageLocation {
        backend: task.repository_storage_backend.clone(),
        path: task.repository_storage_path.clone(),
    }
}

fn storage_for_task(
    storage_registry: &StorageRegistry,
    task: &TaskRow,
) -> Result<Arc<dyn crate::storage::StorageBackend>, String> {
    let location = storage_location_for_task(task);
    storage_registry.backend_for(&location).map_err(|e| {
        format!(
            "Failed to resolve storage backend '{}': {e}",
            location.backend
        )
    })
}

/// Read artifact bytes through the repository's configured storage backend.
async fn read_artifact_from_storage(
    storage_registry: &StorageRegistry,
    task: &TaskRow,
) -> Result<Vec<u8>, String> {
    let storage = storage_for_task(storage_registry, task)?;

    storage
        .get(&task.storage_key)
        .await
        .map(|bytes| bytes.to_vec())
        .map_err(|e| {
            let location = storage_location_for_task(task);
            format!(
                "Failed to read '{}' from storage backend '{}': {e}",
                task.storage_key, location.backend
            )
        })
}

/// Read a specific byte range through the repository's configured storage backend.
async fn read_artifact_chunk_from_storage(
    storage_registry: &StorageRegistry,
    task: &TaskRow,
    offset: u64,
    length: usize,
) -> Result<Vec<u8>, String> {
    if length == 0 {
        return Ok(Vec::new());
    }

    let storage = storage_for_task(storage_registry, task)?;
    let bytes = storage
        .get_range(&task.storage_key, offset, length)
        .await
        .map_err(|e| {
            let location = storage_location_for_task(task);
            format!(
                "Failed to read range for '{}' from storage backend '{}' (offset={}, length={}): {e}",
                task.storage_key, location.backend, offset, length
            )
        })?;

    if bytes.len() == length {
        Ok(bytes.to_vec())
    } else {
        let location = storage_location_for_task(task);
        Err(format!(
            "Failed to read complete chunk for '{}' from storage backend '{}' (offset={}, length={}, got={})",
            task.storage_key,
            location.backend,
            offset,
            length,
            bytes.len()
        ))
    }
}

/// Handle a successful transfer: mark task completed, update peer counters.
///
/// The completion is token-guarded: if this worker's claim expired and the
/// task was recovered (and possibly re-claimed) elsewhere, the UPDATE matches
/// zero rows and the peer counters are left for the current owner to settle.
async fn handle_transfer_success(db: &PgPool, task: &Claimed<TaskRow>, bytes_transferred: i64) {
    // Mark task completed (owner only).
    let finalized = sqlx::query(
        r#"
        UPDATE sync_tasks
        SET status = 'completed', completed_at = NOW(), bytes_transferred = $2,
            claimed_by = NULL, claim_token = NULL, claim_expires_at = NULL
        WHERE id = $1
          AND status = 'in_progress'
          AND claim_token = $3
        "#,
    )
    .bind(task.id)
    .bind(bytes_transferred)
    .bind(task.claim_token())
    .execute(db)
    .await;

    match finalized {
        Ok(result) if result.rows_affected() == 1 => {}
        Ok(_) => {
            tracing::warn!(
                "Sync task {} finished but its claim was lost (expired and recovered); \
                 leaving task/peer state to the current owner",
                task.id
            );
            return;
        }
        Err(e) => {
            tracing::warn!("Failed to mark sync task {} completed: {e}", task.id);
            return;
        }
    }

    // Update peer instance counters.
    let _ = sqlx::query(
        r#"
        UPDATE peer_instances
        SET
            active_transfers = GREATEST(active_transfers - 1, 0),
            consecutive_failures = 0,
            bytes_transferred_total = bytes_transferred_total + $2,
            last_sync_at = NOW(),
            updated_at = NOW()
        WHERE id = $1
        "#,
    )
    .bind(task.peer_instance_id)
    .bind(bytes_transferred)
    .execute(db)
    .await;

    // Update the subscription's last_replicated_at.
    let _ = sqlx::query(
        r#"
        UPDATE peer_repo_subscriptions
        SET last_replicated_at = NOW()
        WHERE peer_instance_id = $1 AND repository_id = $2
        "#,
    )
    .bind(task.peer_instance_id)
    .bind(task.repository_id)
    .execute(db)
    .await;
}

/// Outcome of evaluating a sync task failure.
#[derive(Debug, Clone, PartialEq)]
pub(crate) enum RetryDecision {
    /// Task will be retried once the peer recovers.
    WillRetry { attempt: i32, max_retries: i32 },
    /// Task has exhausted all retry attempts and is permanently failed.
    PermanentlyFailed { total_attempts: i32 },
}

impl RetryDecision {
    /// The updated retry count to persist after this failure.
    pub(crate) fn new_retry_count(&self) -> i32 {
        match self {
            RetryDecision::WillRetry { attempt, .. } => *attempt,
            RetryDecision::PermanentlyFailed { total_attempts } => *total_attempts,
        }
    }

    /// Whether the task can still be retried.
    pub(crate) fn is_retriable(&self) -> bool {
        matches!(self, RetryDecision::WillRetry { .. })
    }
}

/// Evaluate the outcome of a sync task failure.
///
/// Increments the retry counter and decides whether the task should be
/// retried or permanently marked as failed.
pub(crate) fn evaluate_task_failure(retry_count: i32, max_retries: i32) -> RetryDecision {
    let new_count = retry_count + 1;
    if new_count < max_retries {
        RetryDecision::WillRetry {
            attempt: new_count,
            max_retries,
        }
    } else {
        RetryDecision::PermanentlyFailed {
            total_attempts: new_count,
        }
    }
}

/// Build a human-readable log message describing the retry outcome.
pub(crate) fn format_retry_log(
    task_id: Uuid,
    decision: &RetryDecision,
    error_message: &str,
) -> String {
    match decision {
        RetryDecision::WillRetry {
            attempt,
            max_retries,
        } => {
            format!(
                "Sync task {} failed (attempt {}/{}), will retry after peer recovery",
                task_id, attempt, max_retries
            )
        }
        RetryDecision::PermanentlyFailed { total_attempts } => {
            format!(
                "Sync task {} permanently failed after {} attempts: {}",
                task_id, total_attempts, error_message
            )
        }
    }
}

/// Handle a failed transfer: mark task, apply backoff, update peer counters.
///
/// If the task has remaining retries (`retry_count < max_retries`), it is
/// marked `failed` with an incremented `retry_count`. The peer-recovery
/// reset at the top of `process_pending_tasks` will flip it back to
/// `pending` once the peer's backoff expires.
async fn handle_transfer_failure(
    db: &PgPool,
    task: &Claimed<TaskRow>,
    error_message: &str,
    retry_policy: SyncRetryPolicy,
) {
    let decision = evaluate_task_failure(task.retry_count, task.max_retries);

    // Mark task as failed with updated retry count (owner only). If the claim
    // was lost, the current owner drives the task's fate; skip the peer
    // backoff/counter updates too so this stale worker cannot double-penalize
    // the peer for one logical attempt.
    let failed = sqlx::query(
        r#"
        UPDATE sync_tasks
        SET status = 'failed',
            completed_at = NOW(),
            error_message = $2,
            retry_count = $3,
            claimed_by = NULL,
            claim_token = NULL,
            claim_expires_at = NULL
        WHERE id = $1
          AND status = 'in_progress'
          AND claim_token = $4
        "#,
    )
    .bind(task.id)
    .bind(error_message)
    .bind(decision.new_retry_count())
    .bind(task.claim_token())
    .execute(db)
    .await;

    match failed {
        Ok(result) if result.rows_affected() == 1 => {}
        Ok(_) => {
            tracing::warn!(
                "Sync task {} failed here but its claim was lost (expired and recovered); \
                 skipping task/peer failure bookkeeping",
                task.id
            );
            return;
        }
        Err(e) => {
            tracing::warn!("Failed to mark sync task {} failed: {e}", task.id);
            return;
        }
    }

    let log_msg = format_retry_log(task.id, &decision, error_message);
    if decision.is_retriable() {
        tracing::info!("{}", log_msg);
    } else {
        tracing::warn!("{}", log_msg);
    }

    // Fetch current consecutive_failures to compute backoff.
    let consecutive: i32 =
        sqlx::query_scalar("SELECT consecutive_failures FROM peer_instances WHERE id = $1")
            .bind(task.peer_instance_id)
            .fetch_one(db)
            .await
            .unwrap_or(0);

    let backoff = retry_policy.calculate_backoff(consecutive);

    // Update peer instance: decrement active_transfers, bump failure counters, set backoff.
    let _ = sqlx::query(
        r#"
        UPDATE peer_instances
        SET
            active_transfers = GREATEST(active_transfers - 1, 0),
            consecutive_failures = consecutive_failures + 1,
            transfer_failures_total = transfer_failures_total + 1,
            backoff_until = NOW() + $2::INTERVAL,
            updated_at = NOW()
        WHERE id = $1
        "#,
    )
    .bind(task.peer_instance_id)
    .bind(format!("{} seconds", backoff.as_secs()))
    .execute(db)
    .await;
}

/// Build the full URL for uploading an artifact to a remote peer.
pub(crate) fn build_transfer_url(
    peer_endpoint: &str,
    repository_key: &str,
    artifact_path: &str,
) -> String {
    format!(
        "{}/api/v1/repositories/{}/artifacts/{}",
        peer_endpoint.trim_end_matches('/'),
        repository_key,
        encode_artifact_path(artifact_path)
    )
}

/// Build the full URL for deleting an artifact from a remote peer.
pub(crate) fn build_delete_url(
    peer_endpoint: &str,
    repository_key: &str,
    artifact_path: &str,
) -> String {
    format!(
        "{}/api/v1/repositories/{}/artifacts/{}",
        peer_endpoint.trim_end_matches('/'),
        repository_key,
        encode_artifact_path(artifact_path)
    )
}

fn encode_artifact_path(path: &str) -> String {
    path.split('/')
        .map(percent_encode_path_segment)
        .collect::<Vec<_>>()
        .join("/")
}

fn percent_encode_path_segment(segment: &str) -> String {
    let mut encoded = String::with_capacity(segment.len());

    for byte in segment.as_bytes() {
        match *byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                encoded.push(*byte as char)
            }
            other => encoded.push_str(&format!("%{other:02X}")),
        }
    }

    encoded
}

/// Build the URL to initialize a resumable upload session on a peer.
pub(crate) fn build_chunked_upload_session_url(peer_endpoint: &str) -> String {
    format!("{}/api/v1/uploads", peer_endpoint.trim_end_matches('/'))
}

fn build_chunked_upload_session_body(task: &TaskRow, chunk_size: i32) -> serde_json::Value {
    serde_json::json!({
        "repository_key": task.repository_key,
        "artifact_path": task.artifact_path,
        "artifact_name": task.artifact_name,
        "artifact_version": task.artifact_version,
        "artifact_metadata_format": task.artifact_metadata_format,
        "artifact_metadata": task.artifact_metadata,
        "artifact_metadata_properties": task.artifact_metadata_properties,
        "package_description": task.package_description,
        "package_metadata": task.package_metadata,
        "total_size": task.artifact_size,
        "checksum_sha256": task.checksum_sha256,
        "chunk_size": chunk_size,
        "content_type": task.content_type,
    })
}

/// Build the ordered header set for a single-request replication PUT.
///
/// Returns `(name, value)` pairs in the exact order the receiving peer's upload
/// handler expects: bearer auth, the replication marker, content type, the
/// artifact name/version/path metadata, and finally the source SHA-256 the peer
/// re-verifies against the streamed bytes. A missing artifact version is sent as
/// an empty string, matching the direct-upload contract.
fn replication_put_headers(task: &TaskRow, peer_api_key: &str) -> Vec<(&'static str, String)> {
    vec![
        ("Authorization", format!("Bearer {}", peer_api_key)),
        (
            REPLICATION_REQUEST_HEADER,
            REPLICATION_REQUEST_VALUE.to_string(),
        ),
        ("Content-Type", task.content_type.clone()),
        ("X-Artifact-Name", task.artifact_name.clone()),
        (
            "X-Artifact-Version",
            task.artifact_version.clone().unwrap_or_default(),
        ),
        ("X-Artifact-Path", task.artifact_path.clone()),
        (CHECKSUM_SHA256_HEADER, task.checksum_sha256.clone()),
    ]
}

/// Extract the resumable upload session id from a peer's init response body.
///
/// The peer returns a JSON object containing a `session_id` string field. This
/// returns `None` when the field is absent, not a string, or not a valid UUID —
/// in every one of those cases the caller treats the init as failed.
pub(crate) fn parse_chunked_session_id(session: &serde_json::Value) -> Option<Uuid> {
    session["session_id"]
        .as_str()
        .and_then(|s| Uuid::parse_str(s).ok())
}

/// Decide whether a peer's response to a replicated delete counts as success.
///
/// Any 2xx status is success. `404 Not Found` is also treated as success because
/// the artifact may already be absent on the peer (idempotent delete); retrying
/// would never make it "more deleted".
pub(crate) fn delete_response_is_success(status: u16) -> bool {
    (200..300).contains(&status) || status == 404
}

/// Placeholder used when a peer's HTTP error response body cannot be read.
///
/// Shared by every transfer path so a network error while reading the body of
/// an already-failed response never masks the original status code.
pub(crate) fn unreadable_response_body() -> String {
    "<unreadable>".to_string()
}

/// Build the error message for a peer that returned a non-success status during
/// replication, in the form `"<action> <status>: <body>"`.
///
/// `action` describes the replication step that failed (e.g.
/// `"Remote peer returned"` or `"Chunked upload init returned"`).
pub(crate) fn format_peer_response_failure(action: &str, status: u16, body: &str) -> String {
    format!("{action} {status}: {body}")
}

/// Build the URL to upload one chunk to a resumable upload session.
pub(crate) fn build_chunked_upload_chunk_url(peer_endpoint: &str, session_id: &Uuid) -> String {
    format!(
        "{}/api/v1/uploads/{}",
        peer_endpoint.trim_end_matches('/'),
        session_id
    )
}

/// Build the URL to finalize a resumable upload session.
pub(crate) fn build_chunked_upload_complete_url(peer_endpoint: &str, session_id: &Uuid) -> String {
    format!(
        "{}/api/v1/uploads/{}/complete",
        peer_endpoint.trim_end_matches('/'),
        session_id
    )
}

/// Build the RFC 9110 byte range header for one chunk.
pub(crate) fn build_content_range(byte_offset: i64, byte_length: i32, total_size: i64) -> String {
    let end = byte_offset + byte_length as i64 - 1;
    format!("bytes {}-{}/{}", byte_offset, end, total_size)
}

async fn cancel_chunked_upload_session(
    client: &reqwest::Client,
    peer_endpoint: &str,
    peer_api_key: &str,
    session_id: &Uuid,
) {
    let url = build_chunked_upload_chunk_url(peer_endpoint, session_id);
    if let Err(e) = client
        .delete(&url)
        .header("Authorization", format!("Bearer {}", peer_api_key))
        .header(REPLICATION_REQUEST_HEADER, REPLICATION_REQUEST_VALUE)
        .send()
        .await
    {
        tracing::warn!(
            session_id = %session_id,
            error = %e,
            "Failed to cancel remote chunked upload session after transfer error"
        );
    }
}

/// Read the configured chunked transfer threshold from `SYNC_CHUNKED_THRESHOLD_BYTES`,
/// falling back to `DEFAULT_CHUNKED_THRESHOLD_BYTES` (100 MB).
pub(crate) fn chunked_threshold_bytes() -> i64 {
    std::env::var("SYNC_CHUNKED_THRESHOLD_BYTES")
        .ok()
        .and_then(|v| v.parse::<i64>().ok())
        .unwrap_or(DEFAULT_CHUNKED_THRESHOLD_BYTES)
}

/// Read the configured chunk size from `SYNC_CHUNK_SIZE_BYTES`,
/// falling back to `DEFAULT_SYNC_CHUNK_SIZE_BYTES` (50 MB).
pub(crate) fn sync_chunk_size_bytes() -> i32 {
    std::env::var("SYNC_CHUNK_SIZE_BYTES")
        .ok()
        .and_then(|v| v.parse::<i32>().ok())
        .unwrap_or(DEFAULT_SYNC_CHUNK_SIZE_BYTES)
}

/// Decide whether a given artifact size should use chunked transfer.
pub(crate) fn should_use_chunked_transfer(artifact_size: i64, threshold: i64) -> bool {
    artifact_size >= threshold
}

fn task_has_replication_metadata(task: &TaskRow) -> bool {
    (task.artifact_metadata_format.is_some() && task.artifact_metadata.is_some())
        || task.package_description.is_some()
        || task.package_metadata.is_some()
}

fn should_use_chunked_transfer_for_task(task: &TaskRow, threshold: i64) -> bool {
    should_use_chunked_transfer(task.artifact_size, threshold)
        || task_has_replication_metadata(task)
}

/// Compute the list of (chunk_index, byte_offset, byte_length) for a given
/// total size and chunk size.
pub(crate) fn compute_chunk_ranges(total_size: i64, chunk_size: i32) -> Vec<(i32, i64, i32)> {
    if total_size <= 0 || chunk_size <= 0 {
        return vec![];
    }
    let total_chunks = ((total_size as f64) / (chunk_size as f64)).ceil() as i32;
    (0..total_chunks)
        .map(|i| {
            let byte_offset = (i as i64) * (chunk_size as i64);
            let byte_length = if i == total_chunks - 1 {
                (total_size - byte_offset) as i32
            } else {
                chunk_size
            };
            (i, byte_offset, byte_length)
        })
        .collect()
}

/// Compute the number of available transfer slots for a peer.
/// Returns 0 or negative if the peer is at or over capacity.
pub(crate) fn compute_available_slots(
    concurrent_transfers_limit: Option<i32>,
    active_transfers: i32,
) -> i32 {
    let max_concurrent = concurrent_transfers_limit.unwrap_or(5);
    max_concurrent - active_transfers
}

// ── Pure helper functions ───────────────────────────────────────────────────

/// Check if an artifact name/version matches the replication filter.
/// Returns true if the artifact should be replicated.
///
/// The filter is a JSON object with optional `include_patterns` and
/// `exclude_patterns` arrays.  When `include_patterns` is non-empty, at least
/// one pattern must match.  Any matching `exclude_patterns` entry rejects the
/// artifact.  A `None` filter (or null JSON) means replicate everything.
fn matches_replication_filter(
    artifact_identifier: &str,
    filter: Option<&serde_json::Value>,
) -> bool {
    let filter = match filter {
        Some(f) => f,
        None => return true, // No filter = replicate everything
    };

    // Check include patterns (if specified, at least one must match).
    if let Some(includes) = filter.get("include_patterns").and_then(|v| v.as_array()) {
        if !includes.is_empty() {
            let mut any_match = false;
            for pattern in includes {
                if let Some(pat_str) = pattern.as_str() {
                    match regex::Regex::new(pat_str) {
                        Ok(re) => {
                            if re.is_match(artifact_identifier) {
                                any_match = true;
                                break;
                            }
                        }
                        Err(e) => {
                            tracing::warn!("Invalid replication filter regex '{}': {}", pat_str, e);
                            return false;
                        }
                    }
                }
            }
            if !any_match {
                return false;
            }
        }
    }

    // Check exclude patterns (if any match, exclude).
    if let Some(excludes) = filter.get("exclude_patterns").and_then(|v| v.as_array()) {
        for pattern in excludes {
            if let Some(pat_str) = pattern.as_str() {
                match regex::Regex::new(pat_str) {
                    Ok(re) => {
                        if re.is_match(artifact_identifier) {
                            return false;
                        }
                    }
                    Err(e) => {
                        tracing::warn!("Invalid replication filter regex '{}': {}", pat_str, e);
                    }
                }
            }
        }
    }

    true
}

/// Calculate backoff duration from consecutive failure count using the default
/// retry policy.
pub fn calculate_backoff(consecutive_failures: i32) -> Duration {
    SyncRetryPolicy::from_env().calculate_backoff(consecutive_failures)
}

pub(crate) fn calculate_configured_backoff(
    consecutive_failures: i32,
    base_secs: u64,
    max_secs: u64,
) -> Duration {
    let failures = consecutive_failures.max(0) as u32;
    let capped_base = base_secs.max(1);
    let capped_max = max_secs.max(1);
    let secs = std::cmp::min(
        capped_max,
        capped_base.saturating_mul(2u64.saturating_pow(failures)),
    );
    Duration::from_secs(secs)
}

/// Check whether a given time falls within a sync window.
///
/// Handles windows that wrap past midnight (e.g. 22:00 - 06:00).
pub fn is_within_sync_window(start: NaiveTime, end: NaiveTime, now: NaiveTime) -> bool {
    if start <= end {
        // Same-day window: e.g. 02:00 - 06:00
        now >= start && now < end
    } else {
        // Overnight window: e.g. 22:00 - 06:00
        now >= start || now < end
    }
}

/// Parse a timezone string into a UTC offset in seconds.
///
/// Supports:
///   - `"UTC"` → 0
///   - Fixed offsets: `"+05:30"`, `"-08:00"`, `"+0530"`, `"-0800"`
///   - IANA-style common abbreviations as best-effort:
///     `"EST"` → -5h, `"PST"` → -8h, `"CET"` → +1h, etc.
///
/// Falls back to 0 (UTC) for unrecognized values.
fn parse_utc_offset_secs(tz: &str) -> i64 {
    let tz = tz.trim();

    if tz.eq_ignore_ascii_case("UTC") || tz.eq_ignore_ascii_case("GMT") {
        return 0;
    }

    // Try parsing fixed offset like "+05:30", "-08:00", "+0530", "-0800"
    if tz.starts_with('+') || tz.starts_with('-') {
        let sign: i64 = if tz.starts_with('-') { -1 } else { 1 };
        let digits = &tz[1..];
        let (hours, minutes) = if digits.contains(':') {
            let parts: Vec<&str> = digits.split(':').collect();
            if parts.len() == 2 {
                (
                    parts[0].parse::<i64>().unwrap_or(0),
                    parts[1].parse::<i64>().unwrap_or(0),
                )
            } else {
                return 0;
            }
        } else if digits.len() == 4 {
            (
                digits[..2].parse::<i64>().unwrap_or(0),
                digits[2..].parse::<i64>().unwrap_or(0),
            )
        } else {
            return 0;
        };
        return sign * (hours * 3600 + minutes * 60);
    }

    // Common abbreviations (best-effort).
    match tz.to_uppercase().as_str() {
        "EST" => -5 * 3600,
        "EDT" => -4 * 3600,
        "CST" => -6 * 3600,
        "CDT" => -5 * 3600,
        "MST" => -7 * 3600,
        "MDT" => -6 * 3600,
        "PST" => -8 * 3600,
        "PDT" => -7 * 3600,
        "CET" => 3600,
        "CEST" => 2 * 3600,
        "EET" => 2 * 3600,
        "EEST" => 3 * 3600,
        "IST" => 5 * 3600 + 1800,
        "JST" => 9 * 3600,
        "AEST" => 10 * 3600,
        "AEDT" => 11 * 3600,
        "NZST" => 12 * 3600,
        "NZDT" => 13 * 3600,
        _ => {
            tracing::warn!(
                "Unrecognized timezone '{}', defaulting to UTC for sync window",
                tz
            );
            0
        }
    }
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::services::repo_selector_service::RepoSelector;
    use crate::services::sync_policy_service::{
        ArtifactFilter, CreateSyncPolicyRequest, PeerSelector, SyncPolicyService,
    };
    use bytes::Bytes;
    use chrono::NaiveTime;
    use futures::stream::BoxStream;
    use std::collections::HashMap;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};
    use tokio::time::Duration;

    struct RangeRecordingBackend {
        data: Bytes,
        range_calls: Mutex<Vec<(String, u64, usize)>>,
        stream_calls: AtomicUsize,
    }

    impl RangeRecordingBackend {
        fn new(data: &'static [u8]) -> Self {
            Self {
                data: Bytes::from_static(data),
                range_calls: Mutex::new(Vec::new()),
                stream_calls: AtomicUsize::new(0),
            }
        }
    }

    #[async_trait::async_trait]
    impl crate::storage::StorageBackend for RangeRecordingBackend {
        async fn put(&self, _key: &str, _content: Bytes) -> crate::error::Result<()> {
            Ok(())
        }

        async fn get(&self, _key: &str) -> crate::error::Result<Bytes> {
            Ok(self.data.clone())
        }

        async fn exists(&self, _key: &str) -> crate::error::Result<bool> {
            Ok(true)
        }

        async fn delete(&self, _key: &str) -> crate::error::Result<()> {
            Ok(())
        }

        async fn get_stream(
            &self,
            _key: &str,
        ) -> crate::error::Result<BoxStream<'static, crate::error::Result<Bytes>>> {
            self.stream_calls.fetch_add(1, Ordering::SeqCst);
            Err(crate::error::AppError::Storage(
                "get_stream should not be used for chunk reads".to_string(),
            ))
        }

        async fn get_range(
            &self,
            key: &str,
            offset: u64,
            length: usize,
        ) -> crate::error::Result<Bytes> {
            self.range_calls
                .lock()
                .unwrap()
                .push((key.to_string(), offset, length));

            let start = offset as usize;
            if start >= self.data.len() {
                return Ok(Bytes::new());
            }

            let end = start.saturating_add(length).min(self.data.len());
            Ok(self.data.slice(start..end))
        }
        async fn put_stream(
            &self,
            key: &str,
            stream: futures::stream::BoxStream<'static, crate::error::Result<bytes::Bytes>>,
        ) -> crate::error::Result<crate::storage::PutStreamResult> {
            crate::storage::buffered_put_stream_fallback(self, key, stream).await
        }
    }

    fn test_task(storage_backend: &str) -> TaskRow {
        TaskRow {
            id: Uuid::new_v4(),
            peer_instance_id: Uuid::new_v4(),
            artifact_id: Uuid::new_v4(),
            priority: 0,
            storage_key: "object-key".to_string(),
            artifact_size: 26,
            artifact_name: "artifact.bin".to_string(),
            artifact_version: None,
            artifact_path: "path/artifact.bin".to_string(),
            artifact_metadata_format: None,
            artifact_metadata: None,
            artifact_metadata_properties: None,
            package_description: None,
            package_metadata: None,
            repository_key: "repo".to_string(),
            repository_id: Uuid::new_v4(),
            repository_storage_backend: storage_backend.to_string(),
            repository_storage_path: String::new(),
            content_type: "application/octet-stream".to_string(),
            checksum_sha256: "source-sha256".to_string(),
            task_type: "push".to_string(),
            replication_filter: None,
            retry_count: 0,
            max_retries: DEFAULT_MAX_RETRIES,
        }
    }

    #[tokio::test]
    async fn test_read_artifact_chunk_uses_storage_range_read() {
        let backend = Arc::new(RangeRecordingBackend::new(b"abcdefghijklmnopqrstuvwxyz"));
        let mut backends: HashMap<String, Arc<dyn crate::storage::StorageBackend>> = HashMap::new();
        backends.insert("s3-peer".to_string(), backend.clone());
        let registry = StorageRegistry::new(backends, "s3-peer".to_string());
        let task = test_task("s3-peer");

        let chunk = read_artifact_chunk_from_storage(&registry, &task, 5, 8)
            .await
            .unwrap();

        assert_eq!(chunk, b"fghijklm");
        assert_eq!(
            *backend.range_calls.lock().unwrap(),
            vec![("object-key".to_string(), 5, 8)]
        );
        assert_eq!(backend.stream_calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn test_read_artifact_chunk_rejects_short_range_read() {
        let backend = Arc::new(RangeRecordingBackend::new(b"abcdefghijklmnopqrstuvwxyz"));
        let mut backends: HashMap<String, Arc<dyn crate::storage::StorageBackend>> = HashMap::new();
        backends.insert("s3-peer".to_string(), backend);
        let registry = StorageRegistry::new(backends, "s3-peer".to_string());
        let task = test_task("s3-peer");

        let err = read_artifact_chunk_from_storage(&registry, &task, 24, 4)
            .await
            .unwrap_err();

        assert!(err.contains("Failed to read complete chunk"));
        assert!(err.contains("got=2"));
    }

    #[test]
    fn test_replication_upload_checksum_header_matches_put_handler() {
        assert_eq!(CHECKSUM_SHA256_HEADER, "x-checksum-sha256");
    }

    /// Storage backend whose reads always fail, used to exercise the storage
    /// error-handling branches in the transfer path without a real backend.
    struct FailingReadBackend;

    #[async_trait::async_trait]
    impl crate::storage::StorageBackend for FailingReadBackend {
        async fn put(&self, _key: &str, _content: Bytes) -> crate::error::Result<()> {
            Ok(())
        }

        async fn get(&self, _key: &str) -> crate::error::Result<Bytes> {
            Err(crate::error::AppError::Storage("boom-get".to_string()))
        }

        async fn exists(&self, _key: &str) -> crate::error::Result<bool> {
            Ok(true)
        }

        async fn delete(&self, _key: &str) -> crate::error::Result<()> {
            Ok(())
        }

        async fn get_stream(
            &self,
            _key: &str,
        ) -> crate::error::Result<BoxStream<'static, crate::error::Result<Bytes>>> {
            Err(crate::error::AppError::Storage("boom-stream".to_string()))
        }

        async fn get_range(
            &self,
            _key: &str,
            _offset: u64,
            _length: usize,
        ) -> crate::error::Result<Bytes> {
            Err(crate::error::AppError::Storage("boom-range".to_string()))
        }
        async fn put_stream(
            &self,
            key: &str,
            stream: futures::stream::BoxStream<'static, crate::error::Result<bytes::Bytes>>,
        ) -> crate::error::Result<crate::storage::PutStreamResult> {
            crate::storage::buffered_put_stream_fallback(self, key, stream).await
        }
    }

    fn registry_with(
        name: &str,
        backend: Arc<dyn crate::storage::StorageBackend>,
    ) -> StorageRegistry {
        let mut backends: HashMap<String, Arc<dyn crate::storage::StorageBackend>> = HashMap::new();
        backends.insert(name.to_string(), backend);
        StorageRegistry::new(backends, name.to_string())
    }

    #[test]
    fn test_storage_for_task_resolves_registered_backend() {
        let registry = registry_with("s3-peer", Arc::new(FailingReadBackend));
        let task = test_task("s3-peer");
        assert!(storage_for_task(&registry, &task).is_ok());
    }

    #[test]
    fn test_storage_for_task_reports_unresolvable_backend() {
        let registry = registry_with("s3-peer", Arc::new(FailingReadBackend));
        let task = test_task("does-not-exist");
        let err = match storage_for_task(&registry, &task) {
            Ok(_) => panic!("expected unresolvable backend to error"),
            Err(e) => e,
        };
        assert!(err.contains("Failed to resolve storage backend"));
        assert!(err.contains("does-not-exist"));
    }

    #[tokio::test]
    async fn test_read_artifact_from_storage_success() {
        let backend = Arc::new(RangeRecordingBackend::new(b"hello-world"));
        let registry = registry_with("s3-peer", backend);
        let task = test_task("s3-peer");

        let bytes = read_artifact_from_storage(&registry, &task).await.unwrap();
        assert_eq!(bytes, b"hello-world");
    }

    #[tokio::test]
    async fn test_read_artifact_from_storage_reports_backend_error() {
        let registry = registry_with("s3-peer", Arc::new(FailingReadBackend));
        let task = test_task("s3-peer");

        let err = read_artifact_from_storage(&registry, &task)
            .await
            .unwrap_err();
        assert!(err.contains("Failed to read"));
        assert!(err.contains("boom-get"));
    }

    #[tokio::test]
    async fn test_read_artifact_chunk_zero_length_short_circuits_without_backend_call() {
        let registry = registry_with("s3-peer", Arc::new(FailingReadBackend));
        let task = test_task("s3-peer");

        // A zero-length chunk must return empty bytes without ever touching the
        // backend (which would otherwise error).
        let chunk = read_artifact_chunk_from_storage(&registry, &task, 0, 0)
            .await
            .unwrap();
        assert!(chunk.is_empty());
    }

    #[tokio::test]
    async fn test_read_artifact_chunk_reports_backend_range_error() {
        let registry = registry_with("s3-peer", Arc::new(FailingReadBackend));
        let task = test_task("s3-peer");

        let err = read_artifact_chunk_from_storage(&registry, &task, 5, 8)
            .await
            .unwrap_err();
        assert!(err.contains("Failed to read range"));
        assert!(err.contains("boom-range"));
    }

    #[test]
    fn test_delete_response_is_success_status_boundaries() {
        // 199 is below the 2xx range; 300 is above it; both must be failures.
        assert!(!delete_response_is_success(199));
        assert!(!delete_response_is_success(300));
        // 299 is the inclusive top of the 2xx range.
        assert!(delete_response_is_success(299));
        // 403/410 are ordinary failures even though they are "not present"-ish.
        assert!(!delete_response_is_success(410));
    }

    #[test]
    fn test_format_peer_response_failure_preserves_multiline_body() {
        let body = "line1\nline2";
        let msg = format_peer_response_failure("Remote peer returned", 422, body);
        assert!(msg.starts_with("Remote peer returned 422: "));
        assert!(msg.ends_with("line1\nline2"));
    }

    // ── replication_put_headers ──────────────────────────────────────────

    #[test]
    fn test_replication_put_headers_order_and_values() {
        let mut task = test_task("s3-peer");
        task.content_type = "application/zip".to_string();
        task.artifact_name = "pkg.bin".to_string();
        task.artifact_version = Some("1.2.3".to_string());
        task.artifact_path = "a/b/pkg.bin".to_string();
        task.checksum_sha256 = "deadbeef".to_string();

        let headers = replication_put_headers(&task, "secret-key");

        assert_eq!(
            headers,
            vec![
                ("Authorization", "Bearer secret-key".to_string()),
                (REPLICATION_REQUEST_HEADER, "true".to_string()),
                ("Content-Type", "application/zip".to_string()),
                ("X-Artifact-Name", "pkg.bin".to_string()),
                ("X-Artifact-Version", "1.2.3".to_string()),
                ("X-Artifact-Path", "a/b/pkg.bin".to_string()),
                (CHECKSUM_SHA256_HEADER, "deadbeef".to_string()),
            ]
        );
    }

    #[test]
    fn test_replication_put_headers_missing_version_sends_empty_string() {
        let mut task = test_task("s3-peer");
        task.artifact_version = None;

        let headers = replication_put_headers(&task, "k");
        let version = headers
            .iter()
            .find(|(name, _)| *name == "X-Artifact-Version")
            .map(|(_, value)| value.clone());
        assert_eq!(version, Some(String::new()));
    }

    // ── parse_chunked_session_id ─────────────────────────────────────────

    #[test]
    fn test_parse_chunked_session_id_accepts_valid_uuid() {
        let id = Uuid::new_v4();
        let body = serde_json::json!({ "session_id": id.to_string() });
        assert_eq!(parse_chunked_session_id(&body), Some(id));
    }

    #[test]
    fn test_parse_chunked_session_id_rejects_missing_field() {
        let body = serde_json::json!({ "other": "value" });
        assert_eq!(parse_chunked_session_id(&body), None);
    }

    #[test]
    fn test_parse_chunked_session_id_rejects_non_string_field() {
        let body = serde_json::json!({ "session_id": 1234 });
        assert_eq!(parse_chunked_session_id(&body), None);
    }

    #[test]
    fn test_parse_chunked_session_id_rejects_malformed_uuid() {
        let body = serde_json::json!({ "session_id": "not-a-uuid" });
        assert_eq!(parse_chunked_session_id(&body), None);
    }

    #[test]
    fn test_parse_chunked_session_id_rejects_null_and_non_object() {
        let null_field = serde_json::json!({ "session_id": serde_json::Value::Null });
        assert_eq!(parse_chunked_session_id(&null_field), None);

        let array_body = serde_json::json!(["session_id"]);
        assert_eq!(parse_chunked_session_id(&array_body), None);
    }

    #[test]
    fn test_parse_chunked_session_id_accepts_hyphenated_uuid_roundtrip() {
        let id = Uuid::parse_str("123e4567-e89b-12d3-a456-426614174000").unwrap();
        let body = serde_json::json!({ "session_id": "123e4567-e89b-12d3-a456-426614174000" });
        assert_eq!(parse_chunked_session_id(&body), Some(id));
    }

    // ── chunk reads at multiple offsets ──────────────────────────────────

    #[tokio::test]
    async fn test_read_artifact_chunk_reads_distinct_offsets() {
        let backend = Arc::new(RangeRecordingBackend::new(b"0123456789"));
        let registry = registry_with("s3-peer", backend.clone());
        let task = test_task("s3-peer");

        let head = read_artifact_chunk_from_storage(&registry, &task, 0, 4)
            .await
            .unwrap();
        assert_eq!(head, b"0123");

        let tail = read_artifact_chunk_from_storage(&registry, &task, 6, 4)
            .await
            .unwrap();
        assert_eq!(tail, b"6789");

        let calls = backend.range_calls.lock().unwrap().clone();
        assert_eq!(
            calls,
            vec![
                ("object-key".to_string(), 0, 4),
                ("object-key".to_string(), 6, 4),
            ]
        );
    }

    #[test]
    fn test_build_chunked_upload_session_body_serializes_absent_version_as_null() {
        let mut task = test_task("filesystem");
        task.artifact_version = None;

        let body = build_chunked_upload_session_body(&task, 1_024);
        assert!(body["artifact_version"].is_null());
        assert_eq!(body["chunk_size"], 1_024);
        assert_eq!(body["total_size"], task.artifact_size);
        assert_eq!(body["checksum_sha256"], task.checksum_sha256);
    }

    // ── delete_response_is_success ───────────────────────────────────────

    #[test]
    fn test_delete_response_is_success_for_2xx() {
        assert!(delete_response_is_success(200));
        assert!(delete_response_is_success(202));
        assert!(delete_response_is_success(299));
    }

    #[test]
    fn test_delete_response_is_success_treats_404_as_idempotent() {
        assert!(delete_response_is_success(404));
    }

    #[test]
    fn test_delete_response_is_success_rejects_other_errors() {
        assert!(!delete_response_is_success(400));
        assert!(!delete_response_is_success(403));
        assert!(!delete_response_is_success(409));
        assert!(!delete_response_is_success(500));
        assert!(!delete_response_is_success(503));
    }

    // ── peer failure message helpers ─────────────────────────────────────

    #[test]
    fn test_unreadable_response_body_placeholder() {
        assert_eq!(unreadable_response_body(), "<unreadable>");
    }

    #[test]
    fn test_format_peer_response_failure_includes_status_and_body() {
        assert_eq!(
            format_peer_response_failure("Remote peer returned", 500, "boom"),
            "Remote peer returned 500: boom"
        );
    }

    #[test]
    fn test_format_peer_response_failure_supports_dynamic_action() {
        assert_eq!(
            format_peer_response_failure("Chunk 3 upload returned", 409, "conflict"),
            "Chunk 3 upload returned 409: conflict"
        );
    }

    #[test]
    fn test_format_peer_response_failure_with_empty_body() {
        assert_eq!(
            format_peer_response_failure("Chunked upload init returned", 502, ""),
            "Chunked upload init returned 502: "
        );
    }

    // ── calculate_backoff ───────────────────────────────────────────────

    #[test]
    fn test_backoff_zero_failures() {
        // Default policy retries every five minutes.
        let d = calculate_backoff(0);
        assert_eq!(d, Duration::from_secs(300));
    }

    #[test]
    fn test_backoff_one_failure() {
        // Default base and max are both 300s, so there is no ramp-up.
        let d = calculate_backoff(1);
        assert_eq!(d, Duration::from_secs(300));
    }

    #[test]
    fn test_backoff_two_failures() {
        let d = calculate_backoff(2);
        assert_eq!(d, Duration::from_secs(300));
    }

    #[test]
    fn test_backoff_three_failures() {
        let d = calculate_backoff(3);
        assert_eq!(d, Duration::from_secs(300));
    }

    #[test]
    fn test_backoff_four_failures() {
        let d = calculate_backoff(4);
        assert_eq!(d, Duration::from_secs(300));
    }

    #[test]
    fn test_backoff_five_failures_capped() {
        let d = calculate_backoff(5);
        assert_eq!(d, Duration::from_secs(300));
    }

    #[test]
    fn test_backoff_large_failures_capped() {
        // Should never exceed 300s regardless of failure count.
        let d = calculate_backoff(100);
        assert_eq!(d, Duration::from_secs(300));
    }

    #[test]
    fn test_backoff_negative_failures_treated_as_zero() {
        // Negative shouldn't happen but handle gracefully.
        let d = calculate_backoff(-1);
        assert_eq!(d, Duration::from_secs(300));
    }

    #[test]
    fn test_configured_backoff_can_use_old_exponential_shape() {
        assert_eq!(
            calculate_configured_backoff(0, 10, 300),
            Duration::from_secs(10)
        );
        assert_eq!(
            calculate_configured_backoff(1, 10, 300),
            Duration::from_secs(20)
        );
        assert_eq!(
            calculate_configured_backoff(4, 10, 300),
            Duration::from_secs(160)
        );
        assert_eq!(
            calculate_configured_backoff(5, 10, 300),
            Duration::from_secs(300)
        );
    }

    // ── env parsing helpers ─────────────────────────────────────────────

    #[test]
    fn test_env_bool_parses_truthy_and_falsey() {
        let key = "SYNC_TEST_ENV_BOOL_TRUTHY";
        for v in ["1", "true", "TRUE", "yes", "on"] {
            std::env::set_var(key, v);
            assert!(env_bool(key, false), "{v} should be true");
        }
        for v in ["0", "false", "no", "off"] {
            std::env::set_var(key, v);
            assert!(!env_bool(key, true), "{v} should be false");
        }
        std::env::remove_var(key);
    }

    #[test]
    fn test_env_bool_falls_back_on_unset_and_garbage() {
        let key = "SYNC_TEST_ENV_BOOL_FALLBACK";
        std::env::remove_var(key);
        assert!(env_bool(key, true));
        assert!(!env_bool(key, false));
        std::env::set_var(key, "maybe");
        assert!(env_bool(key, true));
        std::env::remove_var(key);
    }

    #[test]
    fn test_env_u64_min_clamps_and_defaults() {
        let key = "SYNC_TEST_ENV_U64";
        std::env::remove_var(key);
        // Unset -> default, but never below min.
        assert_eq!(env_u64_min(key, 5, 10), 10);
        assert_eq!(env_u64_min(key, 50, 10), 50);
        std::env::set_var(key, "3");
        assert_eq!(env_u64_min(key, 50, 10), 10); // parsed value clamped up to min
        std::env::set_var(key, "100");
        assert_eq!(env_u64_min(key, 50, 10), 100);
        std::env::set_var(key, "notanumber");
        assert_eq!(env_u64_min(key, 50, 10), 50); // garbage -> default
        std::env::remove_var(key);
    }

    #[test]
    fn test_env_i32_min_clamps_and_defaults() {
        let key = "SYNC_TEST_ENV_I32";
        std::env::remove_var(key);
        assert_eq!(env_i32_min(key, 3, 1), 3);
        std::env::set_var(key, "0");
        assert_eq!(env_i32_min(key, 3, 1), 1); // clamped up to min
        std::env::set_var(key, "9");
        assert_eq!(env_i32_min(key, 3, 1), 9);
        std::env::set_var(key, "nope");
        assert_eq!(env_i32_min(key, 3, 1), 3);
        std::env::remove_var(key);
    }

    // ── SyncRetryPolicy ─────────────────────────────────────────────────

    #[test]
    fn test_sync_retry_policy_default_is_flat_300s() {
        // The default backoff is flat 300s: base == max == 300, so every
        // attempt waits the full window (the changelog-flagged behavior
        // change from exponential to flat).
        for var in [
            "SYNC_TASK_RETRY_BACKOFF_MAX_SECS",
            "SYNC_TASK_RETRY_BACKOFF_BASE_SECS",
            "SYNC_TASK_MAX_RETRIES",
        ] {
            std::env::remove_var(var);
        }
        let policy = SyncRetryPolicy::from_env();
        assert_eq!(policy.max_retries, DEFAULT_MAX_RETRIES);
        assert_eq!(
            policy.backoff_max_secs,
            DEFAULT_SYNC_TASK_RETRY_BACKOFF_MAX_SECS
        );
        // base defaults to max, so backoff is flat at the max for every attempt.
        assert_eq!(policy.backoff_base_secs, policy.backoff_max_secs);
        assert_eq!(policy.calculate_backoff(0), Duration::from_secs(300));
        assert_eq!(policy.calculate_backoff(5), Duration::from_secs(300));
    }

    // ── interval_ticks_for_secs ─────────────────────────────────────────

    #[test]
    fn test_interval_ticks_for_secs_rounds_up_and_floors_at_one() {
        assert_eq!(interval_ticks_for_secs(60, 10), 6);
        assert_eq!(interval_ticks_for_secs(61, 10), 7); // rounds up
        assert_eq!(interval_ticks_for_secs(5, 10), 1); // never below 1 tick
        assert_eq!(interval_ticks_for_secs(0, 10), 1);
    }

    // ── storage_location_for_task ───────────────────────────────────────

    #[test]
    fn test_storage_location_for_task_uses_repository_columns() {
        let mut task = test_task("s3-peer");
        task.repository_storage_backend = "gcs-east".to_string();
        task.repository_storage_path = "repos/generic".to_string();
        let location = storage_location_for_task(&task);
        assert_eq!(location.backend, "gcs-east");
        assert_eq!(location.path, "repos/generic");
    }

    // ── build_transfer_url / path encoding ──────────────────────────────

    #[test]
    fn test_build_transfer_url_encodes_path_and_trims_slash() {
        let url = build_transfer_url("https://peer.example/", "my-repo", "a b/c+d/e.bin");
        assert_eq!(
            url,
            "https://peer.example/api/v1/repositories/my-repo/artifacts/a%20b/c%2Bd/e.bin"
        );
    }

    #[test]
    fn test_encode_artifact_path_preserves_separators_and_unreserved() {
        assert_eq!(
            encode_artifact_path("foo/bar.baz_1-2~3"),
            "foo/bar.baz_1-2~3"
        );
        assert_eq!(encode_artifact_path("a/b c"), "a/b%20c");
    }

    #[test]
    fn test_percent_encode_path_segment_escapes_reserved_bytes() {
        assert_eq!(percent_encode_path_segment("a b"), "a%20b");
        assert_eq!(percent_encode_path_segment("100%"), "100%25");
        assert_eq!(percent_encode_path_segment("ok-._~"), "ok-._~");
    }

    // ── is_within_sync_window ───────────────────────────────────────────

    #[test]
    fn test_sync_window_same_day_inside() {
        let start = NaiveTime::from_hms_opt(2, 0, 0).unwrap();
        let end = NaiveTime::from_hms_opt(6, 0, 0).unwrap();
        let now = NaiveTime::from_hms_opt(3, 30, 0).unwrap();
        assert!(is_within_sync_window(start, end, now));
    }

    #[test]
    fn test_sync_window_same_day_outside_before() {
        let start = NaiveTime::from_hms_opt(2, 0, 0).unwrap();
        let end = NaiveTime::from_hms_opt(6, 0, 0).unwrap();
        let now = NaiveTime::from_hms_opt(1, 0, 0).unwrap();
        assert!(!is_within_sync_window(start, end, now));
    }

    #[test]
    fn test_sync_window_same_day_outside_after() {
        let start = NaiveTime::from_hms_opt(2, 0, 0).unwrap();
        let end = NaiveTime::from_hms_opt(6, 0, 0).unwrap();
        let now = NaiveTime::from_hms_opt(6, 0, 0).unwrap();
        // end is exclusive
        assert!(!is_within_sync_window(start, end, now));
    }

    #[test]
    fn test_sync_window_same_day_at_start() {
        let start = NaiveTime::from_hms_opt(2, 0, 0).unwrap();
        let end = NaiveTime::from_hms_opt(6, 0, 0).unwrap();
        let now = NaiveTime::from_hms_opt(2, 0, 0).unwrap();
        // start is inclusive
        assert!(is_within_sync_window(start, end, now));
    }

    #[test]
    fn test_sync_window_overnight_inside_after_start() {
        let start = NaiveTime::from_hms_opt(22, 0, 0).unwrap();
        let end = NaiveTime::from_hms_opt(6, 0, 0).unwrap();
        let now = NaiveTime::from_hms_opt(23, 0, 0).unwrap();
        assert!(is_within_sync_window(start, end, now));
    }

    #[test]
    fn test_sync_window_overnight_inside_before_end() {
        let start = NaiveTime::from_hms_opt(22, 0, 0).unwrap();
        let end = NaiveTime::from_hms_opt(6, 0, 0).unwrap();
        let now = NaiveTime::from_hms_opt(3, 0, 0).unwrap();
        assert!(is_within_sync_window(start, end, now));
    }

    #[test]
    fn test_sync_window_overnight_outside() {
        let start = NaiveTime::from_hms_opt(22, 0, 0).unwrap();
        let end = NaiveTime::from_hms_opt(6, 0, 0).unwrap();
        let now = NaiveTime::from_hms_opt(12, 0, 0).unwrap();
        assert!(!is_within_sync_window(start, end, now));
    }

    #[test]
    fn test_sync_window_full_day() {
        // start == end means empty window (never true).
        let start = NaiveTime::from_hms_opt(0, 0, 0).unwrap();
        let end = NaiveTime::from_hms_opt(0, 0, 0).unwrap();
        let now = NaiveTime::from_hms_opt(12, 0, 0).unwrap();
        // start <= end, now >= start but now >= end → false
        assert!(!is_within_sync_window(start, end, now));
    }

    // ── parse_utc_offset_secs ───────────────────────────────────────────

    #[test]
    fn test_parse_utc() {
        assert_eq!(parse_utc_offset_secs("UTC"), 0);
        assert_eq!(parse_utc_offset_secs("utc"), 0);
        assert_eq!(parse_utc_offset_secs("GMT"), 0);
    }

    #[test]
    fn test_parse_fixed_offset_colon() {
        assert_eq!(parse_utc_offset_secs("+05:30"), 5 * 3600 + 30 * 60);
        assert_eq!(parse_utc_offset_secs("-08:00"), -8 * 3600);
        assert_eq!(parse_utc_offset_secs("+00:00"), 0);
    }

    #[test]
    fn test_parse_fixed_offset_no_colon() {
        assert_eq!(parse_utc_offset_secs("+0530"), 5 * 3600 + 30 * 60);
        assert_eq!(parse_utc_offset_secs("-0800"), -8 * 3600);
    }

    #[test]
    fn test_parse_common_abbreviations() {
        assert_eq!(parse_utc_offset_secs("EST"), -5 * 3600);
        assert_eq!(parse_utc_offset_secs("PST"), -8 * 3600);
        assert_eq!(parse_utc_offset_secs("CET"), 3600);
        assert_eq!(parse_utc_offset_secs("JST"), 9 * 3600);
        assert_eq!(parse_utc_offset_secs("IST"), 5 * 3600 + 1800);
    }

    #[test]
    fn test_parse_unknown_timezone_defaults_to_utc() {
        assert_eq!(parse_utc_offset_secs("Mars/Olympus"), 0);
        assert_eq!(parse_utc_offset_secs("INVALID"), 0);
    }

    // ── build_transfer_url (extracted pure function) ─────────────────────

    #[test]
    fn test_build_transfer_url_basic() {
        assert_eq!(
            build_transfer_url("https://peer.example.com", "maven-releases", "org/acme/app.jar"),
            "https://peer.example.com/api/v1/repositories/maven-releases/artifacts/org/acme/app.jar"
        );
    }

    #[test]
    fn test_build_transfer_url_trailing_slash() {
        assert_eq!(
            build_transfer_url("https://peer.example.com/", "npm-proxy", "@scope/pkg.tgz"),
            "https://peer.example.com/api/v1/repositories/npm-proxy/artifacts/%40scope/pkg.tgz"
        );
    }

    #[test]
    fn test_build_transfer_url_multiple_trailing_slashes() {
        assert_eq!(
            build_transfer_url(
                "https://peer.example.com///",
                "cargo-local",
                "crates/foo crate"
            ),
            "https://peer.example.com/api/v1/repositories/cargo-local/artifacts/crates/foo%20crate"
        );
    }

    #[test]
    fn test_build_transfer_url_with_port() {
        assert_eq!(
            build_transfer_url("http://localhost:8080", "docker-hub", "v2/name/manifests/latest"),
            "http://localhost:8080/api/v1/repositories/docker-hub/artifacts/v2/name/manifests/latest"
        );
    }

    #[test]
    fn test_build_transfer_url_with_path_prefix() {
        assert_eq!(
            build_transfer_url("https://peer.example.com/v2", "pypi-local", "pkg/file?x=1"),
            "https://peer.example.com/v2/api/v1/repositories/pypi-local/artifacts/pkg/file%3Fx%3D1"
        );
    }

    #[test]
    fn test_build_delete_url_encodes_artifact_path() {
        assert_eq!(
            build_delete_url("https://peer.example.com", "raw", "dir/file name.txt"),
            "https://peer.example.com/api/v1/repositories/raw/artifacts/dir/file%20name.txt"
        );
    }

    // ── compute_available_slots (extracted pure function) ─────────────────

    #[test]
    fn test_compute_available_slots_basic() {
        assert_eq!(compute_available_slots(Some(3), 2), 1);
    }

    #[test]
    fn test_compute_available_slots_at_limit() {
        assert_eq!(compute_available_slots(Some(3), 3), 0);
    }

    #[test]
    fn test_compute_available_slots_over_limit() {
        assert_eq!(compute_available_slots(Some(3), 5), -2);
    }

    #[test]
    fn test_compute_available_slots_default_limit() {
        // None defaults to 5
        assert_eq!(compute_available_slots(None, 2), 3);
    }

    #[test]
    fn test_compute_available_slots_default_limit_at_capacity() {
        assert_eq!(compute_available_slots(None, 5), 0);
    }

    #[test]
    fn test_compute_available_slots_zero_active() {
        assert_eq!(compute_available_slots(Some(10), 0), 10);
    }

    // ── Edge cases: no peers, no tasks ──────────────────────────────────

    #[test]
    fn test_empty_peers_no_panic() {
        let peers: Vec<PeerRow> = vec![];
        assert!(peers.is_empty());
    }

    #[test]
    fn test_empty_tasks_no_dispatch() {
        let tasks: Vec<TaskRow> = vec![];
        assert!(tasks.is_empty());
    }

    // ── Sync window with timezone offset ────────────────────────────────

    #[test]
    fn test_sync_window_with_positive_offset() {
        // Peer timezone is +05:30 (IST).
        // sync_window: 02:00 - 06:00 IST
        // UTC time: 00:00 → IST time: 05:30 → inside window
        let start = NaiveTime::from_hms_opt(2, 0, 0).unwrap();
        let end = NaiveTime::from_hms_opt(6, 0, 0).unwrap();

        let offset_secs = parse_utc_offset_secs("+05:30");
        // Simulate UTC 00:00
        let utc_secs: i64 = 0;
        let local_secs = (utc_secs + offset_secs).rem_euclid(86400);
        let local_time =
            NaiveTime::from_num_seconds_from_midnight_opt(local_secs as u32, 0).unwrap();

        assert_eq!(local_time, NaiveTime::from_hms_opt(5, 30, 0).unwrap());
        assert!(is_within_sync_window(start, end, local_time));
    }

    #[test]
    fn test_sync_window_with_negative_offset() {
        // Peer timezone is -08:00 (PST).
        // sync_window: 22:00 - 06:00 PST (overnight)
        // UTC time: 07:00 → PST time: 23:00 → inside window
        let start = NaiveTime::from_hms_opt(22, 0, 0).unwrap();
        let end = NaiveTime::from_hms_opt(6, 0, 0).unwrap();

        let offset_secs = parse_utc_offset_secs("-08:00");
        // Simulate UTC 07:00
        let utc_secs: i64 = 7 * 3600;
        let local_secs = (utc_secs + offset_secs).rem_euclid(86400);
        let local_time =
            NaiveTime::from_num_seconds_from_midnight_opt(local_secs as u32, 0).unwrap();

        assert_eq!(local_time, NaiveTime::from_hms_opt(23, 0, 0).unwrap());
        assert!(is_within_sync_window(start, end, local_time));
    }

    // ── matches_replication_filter ─────────────────────────────────────

    #[test]
    fn test_matches_replication_filter_no_filter() {
        assert!(matches_replication_filter("anything", None));
    }

    #[test]
    fn test_matches_replication_filter_include_match() {
        let filter = serde_json::json!({
            "include_patterns": ["^v\\d+\\."]
        });
        assert!(matches_replication_filter("v1.2.3", Some(&filter)));
        assert!(!matches_replication_filter("snapshot-1.0", Some(&filter)));
    }

    #[test]
    fn test_matches_replication_filter_exclude_match() {
        let filter = serde_json::json!({
            "exclude_patterns": [".*-SNAPSHOT$"]
        });
        assert!(matches_replication_filter("v1.0.0", Some(&filter)));
        assert!(!matches_replication_filter(
            "v1.0.0-SNAPSHOT",
            Some(&filter)
        ));
    }

    #[test]
    fn test_matches_replication_filter_include_and_exclude() {
        let filter = serde_json::json!({
            "include_patterns": ["^v\\d+\\."],
            "exclude_patterns": [".*-SNAPSHOT$"]
        });
        assert!(matches_replication_filter("v1.0.0", Some(&filter)));
        assert!(!matches_replication_filter(
            "v1.0.0-SNAPSHOT",
            Some(&filter)
        ));
        assert!(!matches_replication_filter("snapshot-1.0", Some(&filter)));
    }

    #[test]
    fn test_matches_replication_filter_invalid_regex() {
        let filter = serde_json::json!({
            "include_patterns": ["[invalid"]
        });
        assert!(!matches_replication_filter("anything", Some(&filter)));
    }

    #[test]
    fn test_matches_replication_filter_empty_patterns() {
        let filter = serde_json::json!({
            "include_patterns": [],
            "exclude_patterns": []
        });
        assert!(matches_replication_filter("anything", Some(&filter)));
    }

    // ── evaluate_task_failure / RetryDecision ───────────────────────────

    #[test]
    fn test_evaluate_first_failure_will_retry() {
        let decision = evaluate_task_failure(0, 3);
        assert_eq!(
            decision,
            RetryDecision::WillRetry {
                attempt: 1,
                max_retries: 3
            }
        );
    }

    #[test]
    fn test_evaluate_second_failure_will_retry() {
        let decision = evaluate_task_failure(1, 3);
        assert_eq!(
            decision,
            RetryDecision::WillRetry {
                attempt: 2,
                max_retries: 3
            }
        );
    }

    #[test]
    fn test_evaluate_at_max_permanently_failed() {
        let decision = evaluate_task_failure(2, 3);
        // retry_count=2, after increment=3, matches max_retries=3 → permanently failed
        assert_eq!(
            decision,
            RetryDecision::PermanentlyFailed { total_attempts: 3 }
        );
    }

    #[test]
    fn test_evaluate_over_max_permanently_failed() {
        let decision = evaluate_task_failure(5, 3);
        assert_eq!(
            decision,
            RetryDecision::PermanentlyFailed { total_attempts: 6 }
        );
    }

    #[test]
    fn test_evaluate_zero_max_retries() {
        // No retries allowed at all.
        let decision = evaluate_task_failure(0, 0);
        assert_eq!(
            decision,
            RetryDecision::PermanentlyFailed { total_attempts: 1 }
        );
    }

    #[test]
    fn test_evaluate_single_retry_allowed() {
        // max_retries=1: first failure (0→1) already exhausts the single retry
        assert_eq!(
            evaluate_task_failure(0, 1),
            RetryDecision::PermanentlyFailed { total_attempts: 1 }
        );
    }

    #[test]
    fn test_evaluate_two_retries_allowed() {
        // max_retries=2: first failure (0→1) is retriable
        assert_eq!(
            evaluate_task_failure(0, 2),
            RetryDecision::WillRetry {
                attempt: 1,
                max_retries: 2
            }
        );
        // second failure (1→2) exhausts retries
        assert_eq!(
            evaluate_task_failure(1, 2),
            RetryDecision::PermanentlyFailed { total_attempts: 2 }
        );
    }

    #[test]
    fn test_evaluate_high_max_retries() {
        assert_eq!(
            evaluate_task_failure(0, 100),
            RetryDecision::WillRetry {
                attempt: 1,
                max_retries: 100
            }
        );
        assert_eq!(
            evaluate_task_failure(98, 100),
            RetryDecision::WillRetry {
                attempt: 99,
                max_retries: 100
            }
        );
        assert_eq!(
            evaluate_task_failure(99, 100),
            RetryDecision::PermanentlyFailed {
                total_attempts: 100
            }
        );
    }

    #[test]
    fn test_evaluate_extracts_correct_attempt_number() {
        // Verify the attempt number is always retry_count + 1
        for i in 0..5 {
            let decision = evaluate_task_failure(i, 10);
            match decision {
                RetryDecision::WillRetry { attempt, .. } => assert_eq!(attempt, i + 1),
                RetryDecision::PermanentlyFailed { total_attempts } => {
                    assert_eq!(total_attempts, i + 1)
                }
            }
        }
    }

    // ── RetryDecision methods ──────────────────────────────────────────────

    #[test]
    fn test_retry_decision_new_retry_count_will_retry() {
        let d = evaluate_task_failure(0, 3);
        assert_eq!(d.new_retry_count(), 1);
    }

    #[test]
    fn test_retry_decision_new_retry_count_permanently_failed() {
        let d = evaluate_task_failure(2, 3);
        assert_eq!(d.new_retry_count(), 3);
    }

    #[test]
    fn test_retry_decision_is_retriable_true() {
        let d = evaluate_task_failure(0, 3);
        assert!(d.is_retriable());
    }

    #[test]
    fn test_retry_decision_is_retriable_false() {
        let d = evaluate_task_failure(2, 3);
        assert!(!d.is_retriable());
    }

    #[test]
    fn test_retry_decision_is_retriable_zero_max() {
        let d = evaluate_task_failure(0, 0);
        assert!(!d.is_retriable());
    }

    #[test]
    fn test_retry_decision_clone_eq() {
        let d1 = evaluate_task_failure(0, 3);
        let d2 = d1.clone();
        assert_eq!(d1, d2);
    }

    // ── format_retry_log ────────────────────────────────────────────────

    #[test]
    fn test_format_retry_log_will_retry() {
        let task_id = Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap();
        let decision = RetryDecision::WillRetry {
            attempt: 1,
            max_retries: 3,
        };
        let msg = format_retry_log(task_id, &decision, "connection refused");
        assert!(msg.contains("attempt 1/3"));
        assert!(msg.contains("will retry"));
        assert!(msg.contains(&task_id.to_string()));
    }

    #[test]
    fn test_format_retry_log_permanently_failed() {
        let task_id = Uuid::parse_str("00000000-0000-0000-0000-000000000002").unwrap();
        let decision = RetryDecision::PermanentlyFailed { total_attempts: 3 };
        let msg = format_retry_log(task_id, &decision, "timeout");
        assert!(msg.contains("permanently failed"));
        assert!(msg.contains("3 attempts"));
        assert!(msg.contains("timeout"));
        assert!(msg.contains(&task_id.to_string()));
    }

    #[test]
    fn test_format_retry_log_includes_error_for_permanent() {
        let task_id = Uuid::parse_str("00000000-0000-0000-0000-000000000003").unwrap();
        let decision = RetryDecision::PermanentlyFailed { total_attempts: 5 };
        let msg = format_retry_log(task_id, &decision, "remote returned 503");
        assert!(msg.contains("remote returned 503"));
    }

    #[test]
    fn test_format_retry_log_will_retry_no_error_in_message() {
        let task_id = Uuid::parse_str("00000000-0000-0000-0000-000000000004").unwrap();
        let decision = RetryDecision::WillRetry {
            attempt: 2,
            max_retries: 5,
        };
        let msg = format_retry_log(task_id, &decision, "some error");
        // Will retry messages don't include the error text
        assert!(!msg.contains("some error"));
        assert!(msg.contains("attempt 2/5"));
    }

    // ── DEFAULT_MAX_RETRIES ───────────────────────────────────────────────

    #[test]
    fn test_default_max_retries() {
        assert_eq!(DEFAULT_MAX_RETRIES, 3);
        // First two failures are retriable with default max.
        assert!(evaluate_task_failure(0, DEFAULT_MAX_RETRIES).is_retriable());
        assert!(evaluate_task_failure(1, DEFAULT_MAX_RETRIES).is_retriable());
        // Third failure exhausts retries.
        assert!(!evaluate_task_failure(2, DEFAULT_MAX_RETRIES).is_retriable());
    }

    // ── should_run_stale_check ────────────────────────────────────────────

    #[test]
    fn test_stale_check_fires_on_interval() {
        // With interval=6, ticks 6, 12, 18 should trigger.
        assert!(should_run_stale_check(6, 6));
        assert!(should_run_stale_check(12, 6));
        assert!(should_run_stale_check(18, 6));
    }

    #[test]
    fn test_stale_check_skips_between_intervals() {
        // Ticks 1-5, 7-11 should not trigger.
        for tick in 1..6 {
            assert!(!should_run_stale_check(tick, 6));
        }
        for tick in 7..12 {
            assert!(!should_run_stale_check(tick, 6));
        }
    }

    #[test]
    fn test_stale_check_tick_zero_fires() {
        // Tick 0 is divisible by any interval, so it triggers.
        assert!(should_run_stale_check(0, 6));
    }

    #[test]
    fn test_stale_check_interval_one_always_fires() {
        // With interval=1, every tick triggers.
        assert!(should_run_stale_check(1, 1));
        assert!(should_run_stale_check(2, 1));
        assert!(should_run_stale_check(100, 1));
    }

    #[test]
    fn test_stale_check_interval_zero_never_fires() {
        // Interval of 0 should never trigger (division by zero guard).
        assert!(!should_run_stale_check(0, 0));
        assert!(!should_run_stale_check(6, 0));
    }

    #[test]
    fn test_stale_check_large_tick() {
        // Large tick counts still work correctly.
        assert!(should_run_stale_check(600, 6));
        assert!(!should_run_stale_check(601, 6));
    }

    #[test]
    fn test_stale_check_default_interval() {
        // Verify the actual constant value works as expected.
        assert_eq!(STALE_CHECK_INTERVAL_TICKS, 6);
        assert!(should_run_stale_check(6, STALE_CHECK_INTERVAL_TICKS));
        assert!(!should_run_stale_check(5, STALE_CHECK_INTERVAL_TICKS));
    }

    #[test]
    fn test_peer_heartbeat_probe_fires_on_first_tick_and_interval() {
        assert!(should_run_peer_heartbeat_probe(1, 6));
        assert!(should_run_peer_heartbeat_probe(6, 6));
        assert!(should_run_peer_heartbeat_probe(12, 6));
        assert!(!should_run_peer_heartbeat_probe(2, 6));
        assert!(!should_run_peer_heartbeat_probe(0, 6));
    }

    #[test]
    fn test_peer_heartbeat_probe_interval_zero_never_fires() {
        assert!(!should_run_peer_heartbeat_probe(1, 0));
        assert!(!should_run_peer_heartbeat_probe(6, 0));
    }

    #[test]
    fn test_stale_threshold_default() {
        // Verify the threshold matches the admin default of 5 minutes.
        assert_eq!(STALE_PEER_THRESHOLD_MINUTES, 5);
    }

    #[test]
    fn test_stale_check_period_secs() {
        // 10s tick * 6 ticks = 60s check period.
        assert_eq!(stale_check_period_secs(), 60);
    }

    #[test]
    fn test_tick_interval_constant() {
        assert_eq!(TICK_INTERVAL_SECS, 10);
    }

    // ── format_stale_detection_log ──────────────────────────────────────

    #[test]
    fn test_format_stale_log_some_peers() {
        let msg = format_stale_detection_log(3, 5);
        assert!(msg.is_some());
        let text = msg.unwrap();
        assert!(text.contains("3 stale peer(s)"));
        assert!(text.contains("5+ minutes"));
    }

    #[test]
    fn test_format_stale_log_one_peer() {
        let msg = format_stale_detection_log(1, 5);
        assert!(msg.is_some());
        assert!(msg.unwrap().contains("1 stale peer(s)"));
    }

    #[test]
    fn test_format_stale_log_zero_peers() {
        let msg = format_stale_detection_log(0, 5);
        assert!(msg.is_none());
    }

    #[test]
    fn test_format_stale_log_custom_threshold() {
        let msg = format_stale_detection_log(2, 10);
        assert!(msg.is_some());
        assert!(msg.unwrap().contains("10+ minutes"));
    }

    #[test]
    fn test_format_stale_log_large_count() {
        let msg = format_stale_detection_log(100, 5);
        assert!(msg.is_some());
        assert!(msg.unwrap().contains("100 stale peer(s)"));
    }

    // ── failover deadline / env override (Bug #1440 A) ────────────────────

    #[test]
    fn test_failover_deadline_production_defaults() {
        // 6 ticks * 10s + 5min * 60s = 60 + 300 = 360s.
        // This is the absolute floor for failover detection with stock config,
        // which is why a 90s mesh-test budget cannot pass without overrides.
        let d = failover_detection_deadline_secs(6, 5, 10);
        assert_eq!(d, 360);
    }

    #[test]
    fn test_failover_deadline_e2e_overrides_fit_90s_budget() {
        // With PEER_STALE_CHECK_INTERVAL_TICKS=2 and
        // PEER_STALE_THRESHOLD_MINUTES=1, the deadline is
        // (2*10) + (1*60) = 80s, which fits the 90s test budget.
        let d = failover_detection_deadline_secs(2, 1, 10);
        assert_eq!(d, 80);
        assert!(d < 90, "e2e override must leave room before 90s budget");
    }

    #[test]
    fn test_failover_deadline_zero_threshold() {
        // Threshold of 0 means "detect immediately after the next poll".
        // We never enable this in code (the parser filters out 0), but the
        // deadline math must not panic.
        assert_eq!(failover_detection_deadline_secs(6, 0, 10), 60);
        assert_eq!(failover_detection_deadline_secs(0, 0, 10), 0);
    }

    #[test]
    fn test_failover_deadline_saturating_overflow() {
        // u64 saturating math must not panic on absurd inputs.
        let d = failover_detection_deadline_secs(u64::MAX, i32::MAX, u64::MAX);
        assert_eq!(d, u64::MAX);
    }

    // Env-var tests share process state with the rest of the test binary;
    // serialise them with a local mutex so parallel test runs don't race.
    static ENV_GUARD: std::sync::Mutex<()> = std::sync::Mutex::new(());

    #[test]
    fn test_stale_peer_threshold_env_override() {
        let _g = ENV_GUARD.lock().unwrap();
        std::env::set_var("PEER_STALE_THRESHOLD_MINUTES", "1");
        let observed = stale_peer_threshold_minutes();
        std::env::remove_var("PEER_STALE_THRESHOLD_MINUTES");
        assert_eq!(observed, 1);
        assert_eq!(stale_peer_threshold_minutes(), STALE_PEER_THRESHOLD_MINUTES);
    }

    #[test]
    fn test_stale_peer_threshold_rejects_non_positive() {
        let _g = ENV_GUARD.lock().unwrap();
        for bad in ["0", "-1", "garbage"] {
            std::env::set_var("PEER_STALE_THRESHOLD_MINUTES", bad);
            let observed = stale_peer_threshold_minutes();
            std::env::remove_var("PEER_STALE_THRESHOLD_MINUTES");
            assert_eq!(
                observed, STALE_PEER_THRESHOLD_MINUTES,
                "rejected value {bad:?} should fall back to default"
            );
        }
    }

    #[test]
    fn test_stale_check_interval_ticks_env_override() {
        let _g = ENV_GUARD.lock().unwrap();
        std::env::set_var("PEER_STALE_CHECK_INTERVAL_TICKS", "2");
        let observed = stale_check_interval_ticks();
        std::env::remove_var("PEER_STALE_CHECK_INTERVAL_TICKS");
        assert_eq!(observed, 2);

        std::env::set_var("PEER_STALE_CHECK_INTERVAL_TICKS", "0");
        let observed_zero = stale_check_interval_ticks();
        std::env::remove_var("PEER_STALE_CHECK_INTERVAL_TICKS");
        assert_eq!(observed_zero, STALE_CHECK_INTERVAL_TICKS);
    }

    // ── pick_best_peer ────────────────────────────────────────────────────

    #[test]
    fn test_pick_best_peer_returns_highest_score() {
        use crate::services::peer_service::ScoredPeer;

        let peers = vec![
            ScoredPeer {
                node_id: Uuid::new_v4(),
                endpoint_url: "http://peer1".to_string(),
                latency_ms: Some(100),
                bandwidth_estimate_bps: Some(1_000_000),
                available_chunks: 5,
                score: 50.0,
            },
            ScoredPeer {
                node_id: Uuid::new_v4(),
                endpoint_url: "http://peer2".to_string(),
                latency_ms: Some(50),
                bandwidth_estimate_bps: Some(2_000_000),
                available_chunks: 10,
                score: 200.0,
            },
            ScoredPeer {
                node_id: Uuid::new_v4(),
                endpoint_url: "http://peer3".to_string(),
                latency_ms: Some(200),
                bandwidth_estimate_bps: Some(500_000),
                available_chunks: 3,
                score: 7.5,
            },
        ];

        let best = pick_best_peer(&peers).unwrap();
        assert_eq!(best.endpoint_url, "http://peer2");
        assert!((best.score - 200.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_pick_best_peer_empty_returns_none() {
        let peers: Vec<crate::services::peer_service::ScoredPeer> = vec![];
        assert!(pick_best_peer(&peers).is_none());
    }

    #[test]
    fn test_pick_best_peer_single_peer() {
        use crate::services::peer_service::ScoredPeer;

        let peers = vec![ScoredPeer {
            node_id: Uuid::new_v4(),
            endpoint_url: "http://only-peer".to_string(),
            latency_ms: Some(100),
            bandwidth_estimate_bps: Some(1_000_000),
            available_chunks: 1,
            score: 10.0,
        }];

        let best = pick_best_peer(&peers).unwrap();
        assert_eq!(best.endpoint_url, "http://only-peer");
    }

    #[test]
    fn test_pick_best_peer_equal_scores() {
        use crate::services::peer_service::ScoredPeer;

        let peers = vec![
            ScoredPeer {
                node_id: Uuid::new_v4(),
                endpoint_url: "http://peer-a".to_string(),
                latency_ms: Some(100),
                bandwidth_estimate_bps: Some(1_000_000),
                available_chunks: 5,
                score: 42.0,
            },
            ScoredPeer {
                node_id: Uuid::new_v4(),
                endpoint_url: "http://peer-b".to_string(),
                latency_ms: Some(80),
                bandwidth_estimate_bps: Some(2_000_000),
                available_chunks: 3,
                score: 42.0,
            },
        ];

        let best = pick_best_peer(&peers);
        assert!(
            best.is_some(),
            "must return a peer when both have equal scores"
        );
        assert!((best.unwrap().score - 42.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_pick_best_peer_nan_score() {
        use crate::services::peer_service::ScoredPeer;

        // A peer with a valid score should be preferred over one with NaN.
        // Because partial_cmp returns None for NaN comparisons and the
        // implementation falls back to Ordering::Equal, we place the valid
        // peer first so that NaN does not shadow it via the tie-breaking
        // behaviour of max_by (which returns the later element on Equal).
        let peers = vec![
            ScoredPeer {
                node_id: Uuid::new_v4(),
                endpoint_url: "http://valid".to_string(),
                latency_ms: Some(50),
                bandwidth_estimate_bps: Some(1_000_000),
                available_chunks: 5,
                score: 100.0,
            },
            ScoredPeer {
                node_id: Uuid::new_v4(),
                endpoint_url: "http://nan-peer".to_string(),
                latency_ms: Some(200),
                bandwidth_estimate_bps: Some(500_000),
                available_chunks: 1,
                score: f64::NAN,
            },
        ];

        // When NaN is last and compared with Equal fallback, max_by picks the
        // later element. Verify we get *some* result regardless.
        let best = pick_best_peer(&peers);
        assert!(
            best.is_some(),
            "must return a peer even when NaN is present"
        );

        // With NaN first and valid second, the valid peer should win since
        // NaN vs valid yields Equal and max_by keeps the later (valid) one.
        let peers_reversed = vec![
            ScoredPeer {
                node_id: Uuid::new_v4(),
                endpoint_url: "http://nan-peer".to_string(),
                latency_ms: Some(200),
                bandwidth_estimate_bps: Some(500_000),
                available_chunks: 1,
                score: f64::NAN,
            },
            ScoredPeer {
                node_id: Uuid::new_v4(),
                endpoint_url: "http://valid".to_string(),
                latency_ms: Some(50),
                bandwidth_estimate_bps: Some(1_000_000),
                available_chunks: 5,
                score: 100.0,
            },
        ];

        let best2 = pick_best_peer(&peers_reversed).unwrap();
        assert_eq!(
            best2.endpoint_url, "http://valid",
            "valid peer should win when NaN peer precedes it"
        );
    }

    #[test]
    fn test_pick_best_peer_zero_score() {
        use crate::services::peer_service::ScoredPeer;

        let peers = vec![ScoredPeer {
            node_id: Uuid::new_v4(),
            endpoint_url: "http://zero-score".to_string(),
            latency_ms: Some(300),
            bandwidth_estimate_bps: Some(100_000),
            available_chunks: 0,
            score: 0.0,
        }];

        let best = pick_best_peer(&peers).unwrap();
        assert_eq!(best.endpoint_url, "http://zero-score");
        assert!((best.score - 0.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_pick_best_peer_negative_score() {
        use crate::services::peer_service::ScoredPeer;

        let peers = vec![
            ScoredPeer {
                node_id: Uuid::new_v4(),
                endpoint_url: "http://negative".to_string(),
                latency_ms: Some(500),
                bandwidth_estimate_bps: Some(100_000),
                available_chunks: 1,
                score: -10.0,
            },
            ScoredPeer {
                node_id: Uuid::new_v4(),
                endpoint_url: "http://positive".to_string(),
                latency_ms: Some(50),
                bandwidth_estimate_bps: Some(5_000_000),
                available_chunks: 8,
                score: 25.0,
            },
        ];

        let best = pick_best_peer(&peers).unwrap();
        assert_eq!(best.endpoint_url, "http://positive");
        assert!((best.score - 25.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_pick_best_peer_large_list() {
        use crate::services::peer_service::ScoredPeer;

        let scores = [1.0, 99.5, 33.0, 78.2, 12.0, 55.5, 200.0, 44.4, 88.8, 5.0];
        let peers: Vec<ScoredPeer> = scores
            .iter()
            .enumerate()
            .map(|(i, &s)| ScoredPeer {
                node_id: Uuid::new_v4(),
                endpoint_url: format!("http://peer-{i}"),
                latency_ms: Some((i as i32 + 1) * 10),
                bandwidth_estimate_bps: Some(1_000_000),
                available_chunks: i as i32,
                score: s,
            })
            .collect();

        assert_eq!(peers.len(), 10);

        let best = pick_best_peer(&peers).unwrap();
        assert_eq!(best.endpoint_url, "http://peer-6");
        assert!((best.score - 200.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_pick_best_peer_preserves_all_fields() {
        use crate::services::peer_service::ScoredPeer;

        let node_id = Uuid::new_v4();
        let peers = vec![ScoredPeer {
            node_id,
            endpoint_url: "http://full-check".to_string(),
            latency_ms: Some(77),
            bandwidth_estimate_bps: Some(3_500_000),
            available_chunks: 42,
            score: 99.9,
        }];

        let best = pick_best_peer(&peers).unwrap();
        assert_eq!(best.node_id, node_id);
        assert_eq!(best.endpoint_url, "http://full-check");
        assert_eq!(best.latency_ms, Some(77));
        assert_eq!(best.bandwidth_estimate_bps, Some(3_500_000));
        assert_eq!(best.available_chunks, 42);
        assert!((best.score - 99.9).abs() < f64::EPSILON);
    }

    // ── constants ────────────────────────────────────────────────────────

    #[test]
    fn test_default_max_retries_constant() {
        assert_eq!(DEFAULT_MAX_RETRIES, 3);
    }

    // ── Chunked transfer threshold ─────────────────────────────────────

    #[test]
    fn test_default_chunked_threshold() {
        // 100 MB
        assert_eq!(DEFAULT_CHUNKED_THRESHOLD_BYTES, 100 * 1024 * 1024);
    }

    #[test]
    fn test_default_sync_chunk_size() {
        // 50 MB
        assert_eq!(DEFAULT_SYNC_CHUNK_SIZE_BYTES, 50 * 1024 * 1024);
    }

    #[test]
    fn test_should_use_chunked_transfer_above_threshold() {
        let threshold: i64 = 100 * 1024 * 1024;
        assert!(should_use_chunked_transfer(threshold, threshold));
        assert!(should_use_chunked_transfer(threshold + 1, threshold));
        assert!(should_use_chunked_transfer(500 * 1024 * 1024, threshold));
    }

    #[test]
    fn test_should_use_chunked_transfer_below_threshold() {
        let threshold: i64 = 100 * 1024 * 1024;
        assert!(!should_use_chunked_transfer(threshold - 1, threshold));
        assert!(!should_use_chunked_transfer(0, threshold));
        assert!(!should_use_chunked_transfer(1024, threshold));
    }

    #[test]
    fn test_should_use_chunked_transfer_zero_threshold() {
        // A threshold of 0 means all artifacts use chunked transfer.
        assert!(should_use_chunked_transfer(0, 0));
        assert!(should_use_chunked_transfer(1, 0));
    }

    #[test]
    fn test_should_use_chunked_transfer_for_task_uses_size_threshold() {
        let mut task = test_task("filesystem");
        task.artifact_size = 100 * 1024 * 1024;

        assert!(should_use_chunked_transfer_for_task(
            &task,
            100 * 1024 * 1024
        ));
    }

    #[test]
    fn test_should_use_chunked_transfer_for_task_forces_metadata_tasks() {
        let mut task = test_task("filesystem");
        task.artifact_size = 1024;
        task.artifact_metadata_format = Some("debian".to_string());
        task.artifact_metadata = Some(serde_json::json!({"format": "debian"}));

        assert!(should_use_chunked_transfer_for_task(
            &task,
            100 * 1024 * 1024
        ));
    }

    #[test]
    fn test_should_use_chunked_transfer_for_task_keeps_plain_small_fast_path() {
        let mut task = test_task("filesystem");
        task.artifact_size = 1024;

        assert!(!should_use_chunked_transfer_for_task(
            &task,
            100 * 1024 * 1024
        ));
    }

    // ── compute_chunk_ranges ───────────────────────────────────────────

    #[test]
    fn test_compute_chunk_ranges_exact_division() {
        let ranges = compute_chunk_ranges(4 * 1024 * 1024, 1024 * 1024);
        assert_eq!(ranges.len(), 4);
        for (i, (idx, offset, length)) in ranges.iter().enumerate() {
            assert_eq!(*idx, i as i32);
            assert_eq!(*offset, (i as i64) * 1024 * 1024);
            assert_eq!(*length, 1024 * 1024);
        }
    }

    #[test]
    fn test_compute_chunk_ranges_non_exact_division() {
        // 2.5 MB split into 1 MB chunks: [1MB, 1MB, 0.5MB]
        let total_size: i64 = 2_500_000;
        let chunk_size: i32 = 1_000_000;
        let ranges = compute_chunk_ranges(total_size, chunk_size);
        assert_eq!(ranges.len(), 3);

        assert_eq!(ranges[0], (0, 0, 1_000_000));
        assert_eq!(ranges[1], (1, 1_000_000, 1_000_000));
        assert_eq!(ranges[2], (2, 2_000_000, 500_000));
    }

    #[test]
    fn test_compute_chunk_ranges_single_chunk() {
        let ranges = compute_chunk_ranges(500, 1024 * 1024);
        assert_eq!(ranges.len(), 1);
        assert_eq!(ranges[0], (0, 0, 500));
    }

    #[test]
    fn test_compute_chunk_ranges_empty_file() {
        let ranges = compute_chunk_ranges(0, 1024 * 1024);
        assert!(ranges.is_empty());
    }

    #[test]
    fn test_compute_chunk_ranges_zero_chunk_size() {
        let ranges = compute_chunk_ranges(1000, 0);
        assert!(ranges.is_empty());
    }

    #[test]
    fn test_compute_chunk_ranges_negative_inputs() {
        assert!(compute_chunk_ranges(-1, 1024).is_empty());
        assert!(compute_chunk_ranges(1024, -1).is_empty());
    }

    #[test]
    fn test_compute_chunk_ranges_one_byte_file() {
        let ranges = compute_chunk_ranges(1, 1024 * 1024);
        assert_eq!(ranges.len(), 1);
        assert_eq!(ranges[0], (0, 0, 1));
    }

    #[test]
    fn test_compute_chunk_ranges_sum_equals_total() {
        let total_size: i64 = 123_456_789;
        let chunk_size: i32 = 10_000_000;
        let ranges = compute_chunk_ranges(total_size, chunk_size);

        let sum: i64 = ranges.iter().map(|(_, _, len)| *len as i64).sum();
        assert_eq!(sum, total_size);
    }

    #[test]
    fn test_compute_chunk_ranges_contiguous() {
        let total_size: i64 = 77_777_777;
        let chunk_size: i32 = 25_000_000;
        let ranges = compute_chunk_ranges(total_size, chunk_size);

        // Each chunk starts where the previous one ended.
        for i in 1..ranges.len() {
            let prev_end = ranges[i - 1].1 + ranges[i - 1].2 as i64;
            assert_eq!(ranges[i].1, prev_end);
        }
    }

    // ── chunked upload URL helpers ─────────────────────────────────────

    #[test]
    fn test_build_chunked_upload_session_url() {
        assert_eq!(
            build_chunked_upload_session_url("https://peer.example.com"),
            "https://peer.example.com/api/v1/uploads"
        );
    }

    #[test]
    fn test_build_chunked_upload_session_url_trailing_slash() {
        assert_eq!(
            build_chunked_upload_session_url("https://peer.example.com/"),
            "https://peer.example.com/api/v1/uploads"
        );
    }

    #[test]
    fn test_build_chunked_upload_session_body_preserves_artifact_metadata() {
        let mut task = test_task("filesystem");
        task.artifact_name = "name-check".to_string();
        task.artifact_version = Some("20260603T072902Z".to_string());
        task.artifact_path = "name-check/20260603T072902Z/large-160m.bin".to_string();

        let body = build_chunked_upload_session_body(&task, 52_428_800);

        assert_eq!(body["repository_key"], "repo");
        assert_eq!(
            body["artifact_path"],
            "name-check/20260603T072902Z/large-160m.bin"
        );
        assert_eq!(body["artifact_name"], "name-check");
        assert_eq!(body["artifact_version"], "20260603T072902Z");
        assert_eq!(body["chunk_size"], 52_428_800);
    }

    #[test]
    fn test_build_chunked_upload_session_body_preserves_replication_metadata() {
        let mut task = test_task("filesystem");
        task.artifact_metadata_format = Some("debian".to_string());
        task.artifact_metadata = Some(serde_json::json!({
            "format": "debian",
            "architecture": "amd64",
            "component": "main"
        }));
        task.artifact_metadata_properties = Some(serde_json::json!({"source": "lux"}));
        task.package_description = Some("replicated Debian package".to_string());
        task.package_metadata = Some(serde_json::json!({
            "format": "debian",
            "component": "main"
        }));

        let body = build_chunked_upload_session_body(&task, 52_428_800);

        assert_eq!(body["artifact_metadata_format"], "debian");
        assert_eq!(body["artifact_metadata"]["architecture"], "amd64");
        assert_eq!(body["artifact_metadata_properties"]["source"], "lux");
        assert_eq!(body["package_description"], "replicated Debian package");
        assert_eq!(body["package_metadata"]["component"], "main");
    }

    #[test]
    fn test_build_chunked_upload_chunk_url() {
        let session_id = Uuid::parse_str("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa").unwrap();
        assert_eq!(
            build_chunked_upload_chunk_url("https://peer.example.com", &session_id),
            "https://peer.example.com/api/v1/uploads/aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
        );
    }

    #[test]
    fn test_build_chunked_upload_chunk_url_trailing_slash() {
        let session_id = Uuid::parse_str("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb").unwrap();
        assert_eq!(
            build_chunked_upload_chunk_url("https://peer.example.com/", &session_id),
            "https://peer.example.com/api/v1/uploads/bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"
        );
    }

    #[test]
    fn test_build_chunked_upload_complete_url() {
        let session_id = Uuid::parse_str("cccccccc-cccc-cccc-cccc-cccccccccccc").unwrap();
        assert_eq!(
            build_chunked_upload_complete_url("https://peer.example.com", &session_id),
            "https://peer.example.com/api/v1/uploads/cccccccc-cccc-cccc-cccc-cccccccccccc/complete"
        );
    }

    #[test]
    fn test_build_chunked_upload_complete_url_trailing_slash() {
        let session_id = Uuid::parse_str("dddddddd-dddd-dddd-dddd-dddddddddddd").unwrap();
        assert_eq!(
            build_chunked_upload_complete_url("https://peer.example.com/", &session_id),
            "https://peer.example.com/api/v1/uploads/dddddddd-dddd-dddd-dddd-dddddddddddd/complete"
        );
    }

    #[test]
    fn test_build_content_range_first_chunk() {
        assert_eq!(build_content_range(0, 1024, 4096), "bytes 0-1023/4096");
    }

    #[test]
    fn test_build_content_range_middle_chunk() {
        assert_eq!(
            build_content_range(1_048_576, 1_048_576, 3_145_728),
            "bytes 1048576-2097151/3145728"
        );
    }

    #[test]
    fn test_build_content_range_last_short_chunk() {
        assert_eq!(
            build_content_range(104_857_600, 10, 104_857_610),
            "bytes 104857600-104857609/104857610"
        );
    }

    // ── chunked_threshold_bytes / sync_chunk_size_bytes ─────────────────

    #[test]
    fn test_chunked_threshold_bytes_default() {
        // Clear env var to test default. This test may be affected by env
        // state but the default should be 100MB when the var is unset.
        let val = DEFAULT_CHUNKED_THRESHOLD_BYTES;
        assert_eq!(val, 104_857_600);
    }

    #[test]
    fn test_sync_chunk_size_bytes_default() {
        let val = DEFAULT_SYNC_CHUNK_SIZE_BYTES;
        assert_eq!(val, 52_428_800);
    }

    // ── peer_connect_timeout_secs ───────────────────────────────────────

    #[test]
    fn test_peer_connect_timeout_default_is_bounded() {
        // The default must be small relative to the 300s request timeout so a
        // black-holed peer in a fan-out cannot hold a transfer slot for long.
        // Pins the exact default; 10 is well under the 300s request timeout.
        assert_eq!(DEFAULT_PEER_CONNECT_TIMEOUT_SECS, 10);
    }

    #[test]
    fn test_peer_connect_timeout_env_override() {
        // Guarded against parallel env mutation by using a unique read path:
        // set, read, clear. Other tests don't touch this var.
        std::env::set_var("SYNC_PEER_CONNECT_TIMEOUT_SECS", "3");
        assert_eq!(peer_connect_timeout_secs(), 3);
        std::env::set_var("SYNC_PEER_CONNECT_TIMEOUT_SECS", "0");
        // Non-positive is rejected, falls back to default.
        assert_eq!(
            peer_connect_timeout_secs(),
            DEFAULT_PEER_CONNECT_TIMEOUT_SECS
        );
        std::env::set_var("SYNC_PEER_CONNECT_TIMEOUT_SECS", "notanumber");
        assert_eq!(
            peer_connect_timeout_secs(),
            DEFAULT_PEER_CONNECT_TIMEOUT_SECS
        );
        std::env::remove_var("SYNC_PEER_CONNECT_TIMEOUT_SECS");
    }

    // -----------------------------------------------------------------------
    // Cluster-wide task claims (Tier-2: no-op without DATABASE_URL)
    // -----------------------------------------------------------------------

    /// Peer + repo + N artifacts + N pending sync tasks, torn down by
    /// [`teardown_claim_fixture`].
    struct ClaimFixture {
        pool: sqlx::PgPool,
        peer_id: Uuid,
        repo_id: Uuid,
        user_id: Uuid,
        task_ids: Vec<Uuid>,
    }

    async fn setup_claim_fixture(tasks: usize) -> Option<ClaimFixture> {
        use crate::api::handlers::test_db_helpers as tdh;
        let pool = tdh::try_pool().await?;
        let (user_id, _username) = tdh::create_user(&pool).await;
        let (repo_id, _repo_key, _path) = tdh::create_repo(&pool, "local", "generic").await;
        let peer_id = tdh::register_test_peer(&pool, "sync-claim", "t").await;

        let mut task_ids = Vec::with_capacity(tasks);
        for i in 0..tasks {
            let tag = Uuid::new_v4();
            let Ok(artifact_id) = crate::api::handlers::proxy_helpers::insert_artifact(
                &pool,
                crate::api::handlers::proxy_helpers::NewArtifact {
                    repository_id: repo_id,
                    path: &format!("claim-test/{tag}/{i}.bin"),
                    name: &format!("claim-test-{tag}-{i}"),
                    version: "1.0.0",
                    size_bytes: 3,
                    checksum_sha256: "claim-test",
                    content_type: "application/octet-stream",
                    storage_key: &format!("claim-test/{tag}/{i}"),
                    uploaded_by: user_id,
                },
            )
            .await
            else {
                panic!("insert artifact");
            };

            let task_id: Uuid = sqlx::query_scalar(
                "INSERT INTO sync_tasks (peer_instance_id, artifact_id, status, priority) \
                 VALUES ($1, $2, 'pending', 0) RETURNING id",
            )
            .bind(peer_id)
            .bind(artifact_id)
            .fetch_one(&pool)
            .await
            .expect("insert sync task");
            task_ids.push(task_id);
        }

        Some(ClaimFixture {
            pool,
            peer_id,
            repo_id,
            user_id,
            task_ids,
        })
    }

    async fn teardown_claim_fixture(f: &ClaimFixture) {
        use crate::api::handlers::test_db_helpers as tdh;
        let _ = sqlx::query("DELETE FROM sync_tasks WHERE peer_instance_id = $1")
            .bind(f.peer_id)
            .execute(&f.pool)
            .await;
        let _ = sqlx::query("DELETE FROM peer_instances WHERE id = $1")
            .bind(f.peer_id)
            .execute(&f.pool)
            .await;
        tdh::cleanup(&f.pool, f.repo_id, f.user_id).await;
    }

    async fn claim_all(
        f: &ClaimFixture,
        slots: i64,
        limit: i64,
        worker: &str,
        ttl: f64,
    ) -> Vec<Claimed<TaskRow>> {
        claim_pending_sync_tasks(&f.pool, f.peer_id, slots, limit, 3, worker, ttl)
            .await
            .expect("claim query ok")
    }

    /// Two claimers drain disjoint rows; a claimed row is never handed out
    /// twice while its claim is live — the exactly-once core of the fix.
    #[tokio::test]
    async fn claim_pending_sync_tasks_is_exactly_once() {
        let Some(f) = setup_claim_fixture(1).await else {
            return;
        };

        let first = claim_all(&f, 5, 5, "worker-a", 60.0).await;
        assert_eq!(first.len(), 1, "single pending task must be claimable");
        assert_eq!(first[0].id, f.task_ids[0]);
        assert_eq!(first[0].claimed_by(), "worker-a");

        // Second claimer sees nothing: the row is in_progress with a live claim.
        let second = claim_all(&f, 5, 5, "worker-b", 60.0).await;
        assert!(
            second.is_empty(),
            "a claimed task must not be claimable again while the claim is live"
        );

        // Owner completes; the terminal state is visible and claim columns clear.
        handle_transfer_success(&f.pool, &first[0], 3).await;
        let (status, token): (String, Option<Uuid>) =
            sqlx::query_as("SELECT status::TEXT, claim_token FROM sync_tasks WHERE id = $1")
                .bind(f.task_ids[0])
                .fetch_one(&f.pool)
                .await
                .expect("fetch task");
        assert_eq!(status, "completed");
        assert!(token.is_none(), "completion must clear the claim");

        teardown_claim_fixture(&f).await;
    }

    /// The in-statement live-claim count caps the batch at the peer's
    /// concurrency limit even when the stale active_transfers snapshot
    /// suggests more slots are free.
    #[tokio::test]
    async fn claim_pending_sync_tasks_caps_at_live_concurrency() {
        let Some(f) = setup_claim_fixture(3).await else {
            return;
        };

        // available_slots (from the stale counter) says 5, but the true peer
        // limit is 2: the claim must hand out at most 2.
        let batch = claim_all(&f, 5, 2, "worker-a", 60.0).await;
        assert_eq!(batch.len(), 2, "claim must honor the concurrency limit");

        // With 2 live claims outstanding the peer is saturated.
        let extra = claim_all(&f, 5, 2, "worker-b", 60.0).await;
        assert!(extra.is_empty(), "saturated peer must yield no more claims");

        // Completing one frees a slot for the remaining task.
        handle_transfer_success(&f.pool, &batch[0], 3).await;
        let refill = claim_all(&f, 5, 2, "worker-b", 60.0).await;
        assert_eq!(refill.len(), 1, "finished claim must free one slot");

        teardown_claim_fixture(&f).await;
    }

    /// Expired claims are recovered to pending (crash recovery), and a stale
    /// owner's token can no longer finalize the row afterwards.
    #[tokio::test]
    async fn expired_sync_task_claims_recover_and_fence_stale_owner() {
        let Some(f) = setup_claim_fixture(1).await else {
            return;
        };

        // Claim with an already-expired TTL to simulate a dead owner.
        let stale = claim_all(&f, 5, 5, "worker-dead", -1.0).await;
        assert_eq!(stale.len(), 1);

        let recovered = recover_expired_sync_task_claims(&f.pool)
            .await
            .expect("recovery query ok");
        assert_eq!(recovered, 1, "expired claim must be recovered");

        let (status, token): (String, Option<Uuid>) =
            sqlx::query_as("SELECT status::TEXT, claim_token FROM sync_tasks WHERE id = $1")
                .bind(f.task_ids[0])
                .fetch_one(&f.pool)
                .await
                .expect("fetch task");
        assert_eq!(status, "pending", "recovered task must be pending again");
        assert!(token.is_none(), "recovery must clear the claim");

        // A new owner claims the recovered task...
        let fresh = claim_all(&f, 5, 5, "worker-new", 60.0).await;
        assert_eq!(fresh.len(), 1);

        // ...and the dead owner's finalizers are fenced by the token check.
        handle_transfer_success(&f.pool, &stale[0], 999).await;
        let (status, bytes): (String, i64) =
            sqlx::query_as("SELECT status::TEXT, bytes_transferred FROM sync_tasks WHERE id = $1")
                .bind(f.task_ids[0])
                .fetch_one(&f.pool)
                .await
                .expect("fetch task");
        assert_eq!(
            status, "in_progress",
            "stale owner must not complete a re-claimed task"
        );
        assert_eq!(bytes, 0, "stale owner must not write bytes_transferred");

        teardown_claim_fixture(&f).await;
    }

    /// Rows left `in_progress` by pre-claim code have no claim token or expiry.
    /// They must not occupy peer capacity forever after the claim columns land.
    #[tokio::test]
    async fn legacy_in_progress_sync_task_without_claim_metadata_recovers() {
        let Some(f) = setup_claim_fixture(1).await else {
            return;
        };

        sqlx::query(
            r#"
            UPDATE sync_tasks
            SET status = 'in_progress',
                started_at = NOW(),
                claimed_by = NULL,
                claim_token = NULL,
                claim_expires_at = NULL
            WHERE id = $1
            "#,
        )
        .bind(f.task_ids[0])
        .execute(&f.pool)
        .await
        .expect("seed legacy in_progress task");
        sqlx::query("UPDATE peer_instances SET active_transfers = 1 WHERE id = $1")
            .bind(f.peer_id)
            .execute(&f.pool)
            .await
            .expect("seed active transfer counter");

        let recovered = recover_expired_sync_task_claims(&f.pool)
            .await
            .expect("recovery query ok");
        assert_eq!(recovered, 1, "legacy in_progress task must recover");

        let (status, token, claim_expires_at, active_transfers): (
            String,
            Option<Uuid>,
            Option<chrono::DateTime<Utc>>,
            i32,
        ) = sqlx::query_as(
            r#"
            SELECT st.status::TEXT, st.claim_token, st.claim_expires_at, p.active_transfers
            FROM sync_tasks st
            JOIN peer_instances p ON p.id = st.peer_instance_id
            WHERE st.id = $1
            "#,
        )
        .bind(f.task_ids[0])
        .fetch_one(&f.pool)
        .await
        .expect("fetch recovered task");

        assert_eq!(status, "pending");
        assert!(token.is_none(), "recovery must clear claim_token");
        assert!(
            claim_expires_at.is_none(),
            "recovery must clear claim_expires_at"
        );
        assert_eq!(
            active_transfers, 0,
            "recovery must compensate the peer transfer counter"
        );

        teardown_claim_fixture(&f).await;
    }

    /// Policy re-evaluation must not reset a live claimed row back to
    /// `pending`; otherwise the owner later loses its token-fenced finalizer
    /// and leaks the peer's active transfer counter.
    #[tokio::test]
    async fn sync_policy_reevaluation_preserves_live_claim_and_finalizes() {
        let Some(f) = setup_claim_fixture(1).await else {
            return;
        };

        let svc = SyncPolicyService::new(f.pool.clone());
        let policy = svc
            .create_policy(CreateSyncPolicyRequest {
                name: format!("sync-claim-policy-{}", Uuid::new_v4()),
                description: "preserve live sync task claims".to_string(),
                enabled: true,
                repo_selector: RepoSelector {
                    match_repos: vec![f.repo_id],
                    ..Default::default()
                },
                peer_selector: PeerSelector {
                    match_peers: vec![f.peer_id],
                    ..Default::default()
                },
                replication_mode: "push".to_string(),
                priority: 0,
                artifact_filter: ArtifactFilter::default(),
                precedence: 100,
            })
            .await
            .expect("create sync policy");

        let claimed = claim_all(&f, 5, 5, "worker-a", 60.0).await;
        assert_eq!(claimed.len(), 1, "task must be claimable");
        let task = &claimed[0];
        let claim_token = task.claim_token();

        sqlx::query("UPDATE peer_instances SET active_transfers = 1 WHERE id = $1")
            .bind(f.peer_id)
            .execute(&f.pool)
            .await
            .expect("seed active transfer counter");

        svc.evaluate_for_artifact(task.artifact_id)
            .await
            .expect("re-evaluate artifact policy");

        let (status, token, claimed_by): (String, Option<Uuid>, Option<String>) = sqlx::query_as(
            "SELECT status::TEXT, claim_token, claimed_by FROM sync_tasks WHERE id = $1",
        )
        .bind(task.id)
        .fetch_one(&f.pool)
        .await
        .expect("fetch task after policy re-evaluation");
        assert_eq!(status, "in_progress");
        assert_eq!(token, Some(claim_token), "policy must preserve claim token");
        assert_eq!(
            claimed_by.as_deref(),
            Some("worker-a"),
            "policy must preserve claimed_by"
        );

        handle_transfer_success(&f.pool, task, 3).await;

        let (status, token, active_transfers, bytes_transferred): (String, Option<Uuid>, i32, i64) =
            sqlx::query_as(
                r#"
            SELECT st.status::TEXT, st.claim_token, p.active_transfers, st.bytes_transferred
            FROM sync_tasks st
            JOIN peer_instances p ON p.id = st.peer_instance_id
            WHERE st.id = $1
            "#,
            )
            .bind(task.id)
            .fetch_one(&f.pool)
            .await
            .expect("fetch finalized task");
        assert_eq!(status, "completed");
        assert!(
            token.is_none(),
            "successful finalize must clear claim token"
        );
        assert_eq!(
            active_transfers, 0,
            "successful finalize must decrement active_transfers"
        );
        assert_eq!(bytes_transferred, 3);

        let _ = sqlx::query("DELETE FROM sync_policies WHERE id = $1")
            .bind(policy.id)
            .execute(&f.pool)
            .await;
        teardown_claim_fixture(&f).await;
    }

    /// Fire `workers` claimers at one peer as concurrently as the runtime
    /// allows — a [`tokio::sync::Barrier`] releases them together — and return
    /// how many tasks each one claimed. Every claimer uses `available_slots`
    /// and `concurrent_limit`, mirroring N replicas ticking at the same instant
    /// off the same stale `active_transfers` snapshot.
    async fn claim_counts_concurrently(
        f: &ClaimFixture,
        workers: usize,
        slots: i64,
        limit: i64,
        ttl: f64,
    ) -> Vec<usize> {
        let barrier = Arc::new(tokio::sync::Barrier::new(workers));
        let mut handles = Vec::with_capacity(workers);
        for i in 0..workers {
            let pool = f.pool.clone();
            let peer_id = f.peer_id;
            let barrier = barrier.clone();
            let worker = format!("worker-{i}");
            handles.push(tokio::spawn(async move {
                barrier.wait().await;
                claim_pending_sync_tasks(&pool, peer_id, slots, limit, 3, &worker, ttl)
                    .await
                    .expect("claim query ok")
                    .len()
            }));
        }
        let mut counts = Vec::with_capacity(workers);
        for h in handles {
            counts.push(h.await.expect("claim task join"));
        }
        counts
    }

    /// Two replicas racing for the same single pending task: exactly one wins
    /// it, never both. The sequential `claim_pending_sync_tasks_is_exactly_once`
    /// cannot exercise this — there the first claim commits (flipping the row
    /// `in_progress`) before the second even selects candidates, so the race
    /// window never opens.
    #[tokio::test]
    async fn claim_pending_sync_tasks_exactly_once_under_concurrency() {
        let Some(f) = setup_claim_fixture(1).await else {
            return;
        };

        let counts = claim_counts_concurrently(&f, 2, 5, 5, 60.0).await;
        let total: usize = counts.iter().sum();
        assert_eq!(
            total, 1,
            "one pending task must be claimed by exactly one of two concurrent \
             replicas, never both (per-worker claims: {counts:?})"
        );

        teardown_claim_fixture(&f).await;
    }

    /// Two replicas ticking together, each believing from the stale
    /// `active_transfers` snapshot that all 5 slots are free, must not
    /// collectively exceed the peer's true concurrency limit of 2. The per-peer
    /// claim advisory lock makes the live-claim cap hold even when the two claim
    /// statements overlap exactly (where the in-statement `COUNT(*)` alone is
    /// racy under READ COMMITTED and would let each grab 2 on disjoint rows).
    #[tokio::test]
    async fn claim_pending_sync_tasks_caps_peer_under_concurrency() {
        let Some(f) = setup_claim_fixture(4).await else {
            return;
        };

        // available_slots = 5 (stale/over-optimistic), true peer limit = 2.
        let counts = claim_counts_concurrently(&f, 2, 5, 2, 60.0).await;
        let total: usize = counts.iter().sum();
        assert_eq!(
            total, 2,
            "two concurrent replicas must claim exactly the 2 available slots \
             and never oversubscribe the peer (per-worker claims: {counts:?})"
        );

        teardown_claim_fixture(&f).await;
    }
}
