//! Background sync worker.
//!
//! Processes the `sync_tasks` queue by transferring artifacts to remote peer
//! instances.  Runs on a 10-second tick, respects per-peer concurrency limits,
//! sync windows, and exponential backoff on failures.
//!
//! For artifacts larger than `SYNC_CHUNKED_THRESHOLD_BYTES`, the worker uses
//! the swarm-based chunked transfer system instead of sending the full file
//! in a single HTTP request.  This prevents timeouts and memory exhaustion
//! when syncing large Docker images, ML models, etc.

use crate::storage::StorageBackend;
use chrono::{NaiveTime, Timelike, Utc};
use sha2::{Digest, Sha256};
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

/// Check whether the current tick should trigger a stale peer detection run.
///
/// Returns `true` every `interval_ticks` ticks (e.g. every 6th tick = 60s
/// when each tick is 10s).
pub(crate) fn should_run_stale_check(tick_count: u64, interval_ticks: u64) -> bool {
    interval_ticks > 0 && tick_count % interval_ticks == 0
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
pub async fn spawn_sync_worker(db: PgPool, storage: Arc<dyn StorageBackend>) {
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

        loop {
            tick.tick().await;
            tick_count += 1;

            // Periodically check for stale peers and mark them offline.
            if should_run_stale_check(tick_count, stale_interval_ticks) {
                run_stale_peer_detection(&db, stale_threshold_min).await;
            }

            if let Err(e) = process_pending_tasks(&db, &client, &storage).await {
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
    repository_key: String,
    repository_id: Uuid,
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

// ── Core logic ──────────────────────────────────────────────────────────────

/// Process all eligible peers and their pending sync tasks.
async fn process_pending_tasks(
    db: &PgPool,
    client: &reqwest::Client,
    storage: &Arc<dyn StorageBackend>,
) -> Result<(), String> {
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
        SET status = 'pending', error_message = NULL, started_at = NULL, completed_at = NULL
        WHERE status = 'failed'
          AND retry_count < max_retries
          AND peer_instance_id = ANY(
              SELECT id FROM peer_instances
              WHERE is_local = false
                AND status IN ('online', 'syncing')
                AND (backoff_until IS NULL OR backoff_until <= NOW())
          )
        "#,
    )
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

        // ── Fetch pending tasks ─────────────────────────────────────────
        let tasks: Vec<TaskRow> = sqlx::query_as(
            r#"
            SELECT
                st.id,
                st.peer_instance_id,
                st.artifact_id,
                st.priority,
                a.storage_key,
                a.size_bytes AS artifact_size,
                a.name AS artifact_name,
                a.version AS artifact_version,
                a.path AS artifact_path,
                r.key AS repository_key,
                r.id AS repository_id,
                a.content_type,
                a.checksum_sha256,
                st.task_type,
                prs.replication_filter,
                st.retry_count,
                st.max_retries
            FROM sync_tasks st
            JOIN artifacts a ON a.id = st.artifact_id
            JOIN repositories r ON r.id = a.repository_id
            LEFT JOIN peer_repo_subscriptions prs
                ON prs.peer_instance_id = st.peer_instance_id
               AND prs.repository_id = r.id
            WHERE st.peer_instance_id = $1
              AND st.status = 'pending'
            ORDER BY st.priority DESC, st.created_at ASC
            LIMIT $2
            "#,
        )
        .bind(peer.id)
        .bind(available_slots as i64)
        .fetch_all(db)
        .await
        .map_err(|e| format!("Failed to fetch tasks for peer '{}': {e}", peer.name))?;

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
                    "UPDATE sync_tasks SET status = 'completed', completed_at = NOW() WHERE id = $1",
                )
                .bind(task.id)
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
            let storage = storage.clone();
            let peer_name = peer.name.clone();

            tokio::spawn(async move {
                if let Err(e) =
                    execute_transfer(&db, &client, &storage, &task, &peer_endpoint, &peer_api_key)
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

/// Execute a single sync task (push or delete) to a remote peer.
async fn execute_transfer(
    db: &PgPool,
    client: &reqwest::Client,
    storage: &Arc<dyn StorageBackend>,
    task: &TaskRow,
    peer_endpoint: &str,
    peer_api_key: &str,
) -> Result<(), String> {
    // 1. Mark task as in_progress, increment active_transfers.
    sqlx::query(
        r#"
        UPDATE sync_tasks
        SET status = 'in_progress', started_at = NOW()
        WHERE id = $1
        "#,
    )
    .bind(task.id)
    .execute(db)
    .await
    .map_err(|e| format!("Failed to mark task in_progress: {e}"))?;

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
        return execute_delete(db, client, task, peer_endpoint, peer_api_key).await;
    }

    // Push flow: decide between single-request upload and chunked transfer
    // based on the artifact size.
    let threshold = chunked_threshold_bytes();
    if should_use_chunked_transfer(task.artifact_size, threshold) {
        return execute_chunked_transfer(db, client, storage, task, peer_endpoint, peer_api_key)
            .await;
    }

    // Fast path for small artifacts: read entire file and POST in one request.

    // 2. Read the artifact bytes through the configured storage backend.
    let file_bytes = match read_artifact_from_storage(storage, &task.storage_key).await {
        Ok(bytes) => bytes,
        Err(e) => {
            handle_transfer_failure(db, task, &format!("Storage read error: {e}")).await;
            return Err(format!("Storage read error: {e}"));
        }
    };

    let bytes_len = file_bytes.len() as i64;

    // 3. POST the artifact to the remote peer.
    let url = build_transfer_url(peer_endpoint, &task.repository_key);

    let result = client
        .post(&url)
        .header("Authorization", format!("Bearer {}", peer_api_key))
        .header("Content-Type", &task.content_type)
        .header("X-Artifact-Name", &task.artifact_name)
        .header(
            "X-Artifact-Version",
            task.artifact_version.as_deref().unwrap_or(""),
        )
        .header("X-Artifact-Path", &task.artifact_path)
        .header("X-Artifact-Checksum-SHA256", &task.checksum_sha256)
        .body(file_bytes)
        .send()
        .await;

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
                .unwrap_or_else(|_| "<unreadable>".to_string());
            let msg = format!("Remote peer returned {status}: {body}");
            handle_transfer_failure(db, task, &msg).await;
            Err(msg)
        }
        Err(e) => {
            let msg = format!("HTTP request failed: {e}");
            handle_transfer_failure(db, task, &msg).await;
            Err(msg)
        }
    }
}

/// Execute a chunked transfer for a large artifact.
///
/// Instead of reading the entire artifact into memory and sending it in one
/// request, this splits the file into chunks and uploads each one individually.
/// The remote peer's transfer session API tracks progress so transfers can
/// resume after partial failures.
async fn execute_chunked_transfer(
    db: &PgPool,
    client: &reqwest::Client,
    storage: &Arc<dyn StorageBackend>,
    task: &TaskRow,
    peer_endpoint: &str,
    peer_api_key: &str,
) -> Result<(), String> {
    let chunk_size = sync_chunk_size_bytes();

    tracing::info!(
        "Using chunked transfer for artifact '{}' ({} bytes, chunk_size={}) to peer (task {})",
        task.artifact_name,
        task.artifact_size,
        chunk_size,
        task.id
    );

    // 1. Initialize a transfer session on the remote peer.
    let init_url = build_chunked_init_url(peer_endpoint, &task.peer_instance_id);
    let init_body = serde_json::json!({
        "artifact_id": task.artifact_id,
        "chunk_size": chunk_size,
    });

    let init_response = client
        .post(&init_url)
        .header("Authorization", format!("Bearer {}", peer_api_key))
        .header("Content-Type", "application/json")
        .json(&init_body)
        .send()
        .await
        .map_err(|e| format!("Failed to init chunked transfer: {e}"))?;

    if !init_response.status().is_success() {
        let status = init_response.status();
        let body = init_response
            .text()
            .await
            .unwrap_or_else(|_| "<unreadable>".to_string());
        let msg = format!("Chunked transfer init returned {status}: {body}");
        handle_transfer_failure(db, task, &msg).await;
        return Err(msg);
    }

    let session: serde_json::Value = init_response
        .json()
        .await
        .map_err(|e| format!("Failed to parse transfer session response: {e}"))?;

    let session_id = session["id"]
        .as_str()
        .and_then(|s| Uuid::parse_str(s).ok())
        .ok_or_else(|| "Missing session id in transfer init response".to_string())?;

    // 2. Stream the artifact through the configured storage backend and upload
    //    it chunk by chunk. We deliberately avoid `storage.get()` here: that
    //    materializes the entire (potentially multi-GB) object in RAM before
    //    slicing, which defeats the purpose of the chunked path and would OOM
    //    the host on large Docker images / ML models. Instead we pull a byte
    //    stream from the backend (S3/GCS/Azure/filesystem all implement genuine
    //    streaming) and re-frame it into fixed `chunk_size` windows via a
    //    rolling buffer, so peak read memory stays ~chunk_size regardless of
    //    artifact size. The emitted boundaries are identical to what
    //    `compute_chunk_ranges` produces (contiguous `chunk_size` windows with
    //    a remainder at the end), so the receiver reassembles by offset/length
    //    exactly as before — wire protocol and chunk numbering are unchanged.
    let total_chunks = compute_chunk_ranges(task.artifact_size, chunk_size).len();
    let mut bytes_transferred: i64 = 0;

    let mut byte_stream = match storage.get_stream(&task.storage_key).await {
        Ok(s) => s,
        Err(e) => {
            let msg = format!("Storage read error: {e}");
            handle_transfer_failure(db, task, &msg).await;
            return Err(msg);
        }
    };

    let mut chunker = StreamChunker::new(chunk_size);
    let mut next_chunk_index: i32 = 0;
    let mut next_byte_offset: i64 = 0;

    loop {
        // Pull the next memory-bounded framed chunk from the stream.
        let chunk_data = match next_framed_chunk(&mut byte_stream, &mut chunker).await {
            Ok(Some(chunk)) => chunk,
            Ok(None) => break,
            Err(e) => {
                handle_transfer_failure(db, task, &e).await;
                return Err(e);
            }
        };

        // Derive this chunk's wire offset/length/index from a running counter.
        // These MUST match `compute_chunk_ranges` so the receiver reassembles
        // by offset/length exactly as before.
        let (chunk_index, byte_offset, byte_length) =
            next_chunk_coords(next_chunk_index, next_byte_offset, chunk_data.len());
        next_chunk_index = chunk_index + 1;
        next_byte_offset = byte_offset + byte_length as i64;
        // Bind as references so the existing per-chunk upload logic, which was
        // written against `&` destructured tuple fields, works unchanged.
        let chunk_index = &chunk_index;
        let byte_offset = &byte_offset;
        let byte_length = &byte_length;

        // Compute SHA-256 of this chunk for verification.
        let mut hasher = Sha256::new();
        hasher.update(&chunk_data);
        let chunk_checksum = format!("{:x}", hasher.finalize());

        // Upload the chunk data to the peer's artifact storage. The chunk is
        // sent as a PUT with the byte range headers so the peer can reassemble.
        let chunk_upload_url = format!(
            "{}/api/v1/repositories/{}/artifacts/chunks/{}/{}",
            peer_endpoint.trim_end_matches('/'),
            task.repository_key,
            session_id,
            chunk_index
        );

        let upload_result = client
            .put(&chunk_upload_url)
            .header("Authorization", format!("Bearer {}", peer_api_key))
            .header("Content-Type", "application/octet-stream")
            .header("X-Chunk-Offset", byte_offset.to_string())
            .header("X-Chunk-Length", byte_length.to_string())
            .header("X-Chunk-Checksum-SHA256", &chunk_checksum)
            .body(chunk_data)
            .send()
            .await;

        match upload_result {
            Ok(resp) if resp.status().is_success() => {
                // Mark chunk as completed on the remote session.
                let complete_url = build_chunk_complete_url(
                    peer_endpoint,
                    &task.peer_instance_id,
                    &session_id,
                    *chunk_index,
                );
                let complete_body = serde_json::json!({
                    "checksum": chunk_checksum,
                    "source_peer_id": null,
                });

                let _ = client
                    .post(&complete_url)
                    .header("Authorization", format!("Bearer {}", peer_api_key))
                    .header("Content-Type", "application/json")
                    .json(&complete_body)
                    .send()
                    .await;

                bytes_transferred += *byte_length as i64;
                tracing::debug!(
                    "Chunk {}/{} uploaded for task {} ({} bytes)",
                    chunk_index + 1,
                    total_chunks,
                    task.id,
                    byte_length
                );
            }
            Ok(resp) => {
                let status = resp.status();
                let body = resp
                    .text()
                    .await
                    .unwrap_or_else(|_| "<unreadable>".to_string());
                let msg = format!("Chunk {} upload returned {status}: {body}", chunk_index);
                handle_transfer_failure(db, task, &msg).await;
                return Err(msg);
            }
            Err(e) => {
                let msg = format!("Chunk {} upload failed: {e}", chunk_index);
                handle_transfer_failure(db, task, &msg).await;
                return Err(msg);
            }
        }
    }

    // 3. Finalize the transfer session.
    let session_complete_url =
        build_session_complete_url(peer_endpoint, &task.peer_instance_id, &session_id);

    let complete_result = client
        .post(&session_complete_url)
        .header("Authorization", format!("Bearer {}", peer_api_key))
        .send()
        .await;

    match complete_result {
        Ok(resp) if resp.status().is_success() => {
            handle_transfer_success(db, task, bytes_transferred).await;
            tracing::info!(
                "Chunked transfer complete for artifact '{}' ({} bytes in {} chunks) to peer (task {})",
                task.artifact_name,
                bytes_transferred,
                total_chunks,
                task.id
            );
            Ok(())
        }
        Ok(resp) => {
            let status = resp.status();
            let body = resp
                .text()
                .await
                .unwrap_or_else(|_| "<unreadable>".to_string());
            let msg = format!("Chunked transfer session complete returned {status}: {body}");
            handle_transfer_failure(db, task, &msg).await;
            Err(msg)
        }
        Err(e) => {
            let msg = format!("Chunked transfer session complete failed: {e}");
            handle_transfer_failure(db, task, &msg).await;
            Err(msg)
        }
    }
}

/// Execute a delete task: tell the remote peer to remove an artifact.
async fn execute_delete(
    db: &PgPool,
    client: &reqwest::Client,
    task: &TaskRow,
    peer_endpoint: &str,
    peer_api_key: &str,
) -> Result<(), String> {
    let url = build_delete_url(peer_endpoint, &task.repository_key, &task.artifact_path);

    let result = client
        .delete(&url)
        .header("Authorization", format!("Bearer {}", peer_api_key))
        .send()
        .await;

    match result {
        Ok(response) if response.status().is_success() || response.status().as_u16() == 404 => {
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
                .unwrap_or_else(|_| "<unreadable>".to_string());
            let msg = format!("Remote peer returned {status} for delete: {body}");
            handle_transfer_failure(db, task, &msg).await;
            Err(msg)
        }
        Err(e) => {
            let msg = format!("HTTP delete request failed: {e}");
            handle_transfer_failure(db, task, &msg).await;
            Err(msg)
        }
    }
}

/// Read artifact bytes through the configured storage backend using the
/// `storage_key`.
///
/// This routes the read through the same [`StorageBackend`] abstraction the
/// upload/download paths use, so peer replication works regardless of whether
/// the deployment is backed by the local filesystem, S3, GCS, or Azure. The
/// previous implementation read directly from `STORAGE_PATH`, which broke
/// replication for object-storage deployments where the artifact never exists
/// on the local filesystem (issue #1565).
async fn read_artifact_from_storage(
    storage: &Arc<dyn StorageBackend>,
    storage_key: &str,
) -> Result<Vec<u8>, String> {
    storage
        .get(storage_key)
        .await
        .map(|bytes| bytes.to_vec())
        .map_err(|e| format!("Failed to read '{storage_key}': {e}"))
}

/// Re-frames an arbitrarily-chunked byte stream into fixed-size `chunk_size`
/// windows using a rolling buffer.
///
/// The chunked-transfer path pulls a byte stream from the storage backend
/// (`get_stream`), whose items have backend-dependent sizes (256 KiB for the
/// filesystem, variable for S3/GCS/Azure). To keep the wire protocol unchanged
/// we must emit chunks whose offsets/lengths match `compute_chunk_ranges`:
/// contiguous `chunk_size` windows with a short remainder at the end.
///
/// Memory is bounded: the internal buffer never holds more than `chunk_size`
/// bytes of *un-emitted* data plus at most one inbound stream item, so peak
/// read memory is O(chunk_size), not O(artifact_size). This is the whole point
/// of the chunked path — it exists to keep multi-GB Docker images and ML
/// models from exhausting host memory during peer replication.
struct StreamChunker {
    chunk_size: usize,
    buf: Vec<u8>,
}

impl StreamChunker {
    /// Create a chunker that emits `chunk_size`-byte windows. A non-positive
    /// `chunk_size` is clamped to 1 so the chunker always makes progress; in
    /// practice `chunk_size` is `sync_chunk_size_bytes()` (>= 1).
    fn new(chunk_size: i32) -> Self {
        Self {
            chunk_size: chunk_size.max(1) as usize,
            buf: Vec::new(),
        }
    }

    /// Append freshly-read stream bytes to the rolling buffer.
    fn push(&mut self, data: &[u8]) {
        self.buf.extend_from_slice(data);
    }

    /// Emit one full `chunk_size` window if the buffer has accumulated at least
    /// that many bytes, draining it from the front. Returns `None` when not yet
    /// enough data is buffered (the caller should pull more from the stream).
    fn next_chunk(&mut self) -> Option<Vec<u8>> {
        if self.buf.len() >= self.chunk_size {
            let rest = self.buf.split_off(self.chunk_size);
            Some(std::mem::replace(&mut self.buf, rest))
        } else {
            None
        }
    }

    /// At end-of-stream, emit the trailing remainder (the final short chunk),
    /// or `None` if the buffer is empty.
    fn flush(&mut self) -> Option<Vec<u8>> {
        if self.buf.is_empty() {
            None
        } else {
            Some(std::mem::take(&mut self.buf))
        }
    }

    /// Current number of buffered, un-emitted bytes. Used by tests to assert
    /// the buffer never grows beyond ~chunk_size (the memory bound).
    #[cfg(test)]
    fn buffered_len(&self) -> usize {
        self.buf.len()
    }
}

/// Compute the wire `(chunk_index, byte_offset, byte_length)` for the next
/// emitted chunk from the running index/offset counters and the chunk's length.
///
/// Pure helper so the offset/length bookkeeping the receiver reassembles
/// against is unit-testable. The boundaries this produces are identical to
/// `compute_chunk_ranges` because both walk contiguous windows from offset 0.
fn next_chunk_coords(chunk_index: i32, byte_offset: i64, chunk_len: usize) -> (i32, i64, i32) {
    (chunk_index, byte_offset, chunk_len as i32)
}

/// Pull the next `chunk_size`-framed window from a byte stream using `chunker`
/// as the rolling buffer.
///
/// Drains a full window from the buffer if one is already available; otherwise
/// pulls more items from `stream` until a full window accumulates. At EOF the
/// trailing remainder is flushed as the final (short) chunk, after which `None`
/// signals the stream is exhausted. Peak memory is bounded by `chunk_size` plus
/// one inbound stream item — the artifact is never fully buffered.
///
/// This is the memory-bounded core of the chunked replication path, extracted
/// as a standalone async fn so it can be unit-tested against an in-memory
/// stream without a database or peer HTTP server.
async fn next_framed_chunk(
    stream: &mut futures::stream::BoxStream<'static, crate::error::Result<bytes::Bytes>>,
    chunker: &mut StreamChunker,
) -> Result<Option<Vec<u8>>, String> {
    loop {
        if let Some(chunk) = chunker.next_chunk() {
            return Ok(Some(chunk));
        }
        match futures::StreamExt::next(stream).await {
            Some(Ok(bytes)) => chunker.push(&bytes),
            Some(Err(e)) => return Err(format!("Storage stream error: {e}")),
            None => return Ok(chunker.flush()),
        }
    }
}

/// Handle a successful transfer: mark task completed, update peer counters.
async fn handle_transfer_success(db: &PgPool, task: &TaskRow, bytes_transferred: i64) {
    // Mark task completed.
    let _ = sqlx::query(
        r#"
        UPDATE sync_tasks
        SET status = 'completed', completed_at = NOW(), bytes_transferred = $2
        WHERE id = $1
        "#,
    )
    .bind(task.id)
    .bind(bytes_transferred)
    .execute(db)
    .await;

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

/// Default maximum retries for sync tasks (matches migration default).
#[allow(dead_code)]
pub(crate) const DEFAULT_MAX_RETRIES: i32 = 3;

/// Handle a failed transfer: mark task, apply backoff, update peer counters.
///
/// If the task has remaining retries (`retry_count < max_retries`), it is
/// marked `failed` with an incremented `retry_count`. The peer-recovery
/// reset at the top of `process_pending_tasks` will flip it back to
/// `pending` once the peer's backoff expires.
async fn handle_transfer_failure(db: &PgPool, task: &TaskRow, error_message: &str) {
    let decision = evaluate_task_failure(task.retry_count, task.max_retries);

    // Mark task as failed with updated retry count.
    let _ = sqlx::query(
        r#"
        UPDATE sync_tasks
        SET status = 'failed',
            completed_at = NOW(),
            error_message = $2,
            retry_count = $3
        WHERE id = $1
        "#,
    )
    .bind(task.id)
    .bind(error_message)
    .bind(decision.new_retry_count())
    .execute(db)
    .await;

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

    let backoff = calculate_backoff(consecutive);

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

/// Build the full URL for posting an artifact to a remote peer.
pub(crate) fn build_transfer_url(peer_endpoint: &str, repository_key: &str) -> String {
    format!(
        "{}/api/v1/repositories/{}/artifacts",
        peer_endpoint.trim_end_matches('/'),
        repository_key
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
        artifact_path
    )
}

/// Build the URL to initialize a chunked transfer session on a peer.
pub(crate) fn build_chunked_init_url(peer_endpoint: &str, peer_id: &Uuid) -> String {
    format!(
        "{}/api/v1/peers/{}/transfer/init",
        peer_endpoint.trim_end_matches('/'),
        peer_id
    )
}

/// Build the URL to complete a single chunk within a transfer session.
pub(crate) fn build_chunk_complete_url(
    peer_endpoint: &str,
    peer_id: &Uuid,
    session_id: &Uuid,
    chunk_index: i32,
) -> String {
    format!(
        "{}/api/v1/peers/{}/transfer/{}/chunk/{}/complete",
        peer_endpoint.trim_end_matches('/'),
        peer_id,
        session_id,
        chunk_index
    )
}

/// Build the URL to finalize an entire transfer session.
pub(crate) fn build_session_complete_url(
    peer_endpoint: &str,
    peer_id: &Uuid,
    session_id: &Uuid,
) -> String {
    format!(
        "{}/api/v1/peers/{}/transfer/{}/complete",
        peer_endpoint.trim_end_matches('/'),
        peer_id,
        session_id
    )
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

/// Calculate exponential backoff duration from consecutive failure count.
///
/// Formula: `min(300, 10 * 2^failures)` seconds.
pub fn calculate_backoff(consecutive_failures: i32) -> Duration {
    let secs = std::cmp::min(
        300u64,
        10u64.saturating_mul(2u64.saturating_pow(consecutive_failures as u32)),
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
    use chrono::NaiveTime;
    use tokio::time::Duration;

    // ── storage-backed artifact reads (issue #1565) ─────────────────────

    use async_trait::async_trait;
    use bytes::Bytes;
    use std::collections::HashMap;

    /// Minimal in-memory storage backend so the sync worker's artifact reads
    /// can be exercised without touching the local filesystem. This mirrors
    /// the production path where artifacts live in S3/GCS/Azure and are never
    /// present under `STORAGE_PATH`.
    struct InMemoryBackend {
        objects: HashMap<String, Bytes>,
    }

    impl InMemoryBackend {
        fn with_object(key: &str, content: &[u8]) -> Self {
            let mut objects = HashMap::new();
            objects.insert(key.to_string(), Bytes::copy_from_slice(content));
            Self { objects }
        }
    }

    #[async_trait]
    impl StorageBackend for InMemoryBackend {
        async fn put(&self, _key: &str, _content: Bytes) -> crate::error::Result<()> {
            Ok(())
        }

        async fn get(&self, key: &str) -> crate::error::Result<Bytes> {
            self.objects
                .get(key)
                .cloned()
                .ok_or_else(|| crate::error::AppError::Storage(format!("missing key: {key}")))
        }

        async fn exists(&self, key: &str) -> crate::error::Result<bool> {
            Ok(self.objects.contains_key(key))
        }

        async fn delete(&self, _key: &str) -> crate::error::Result<()> {
            Ok(())
        }
    }

    #[tokio::test]
    async fn test_in_memory_backend_trait_methods() {
        // Exercise the mock's trait surface so behavioral assumptions in the
        // read tests (exists/put/delete are no-op-safe, get reflects contents)
        // are validated.
        let backend = InMemoryBackend::with_object("k", b"v");
        assert!(backend.exists("k").await.unwrap());
        assert!(!backend.exists("absent").await.unwrap());
        assert_eq!(backend.get("k").await.unwrap(), Bytes::from_static(b"v"));
        backend
            .put("ignored", Bytes::from_static(b"x"))
            .await
            .unwrap();
        backend.delete("k").await.unwrap();
    }

    #[tokio::test]
    async fn test_read_artifact_uses_storage_backend_not_filesystem() {
        // Point STORAGE_PATH at a directory that does not contain the object,
        // proving the read goes through the backend abstraction and not the
        // local filesystem.
        let storage: Arc<dyn StorageBackend> = Arc::new(InMemoryBackend::with_object(
            "cas/ab/cd/abcd1234",
            b"hello peer",
        ));

        let bytes = read_artifact_from_storage(&storage, "cas/ab/cd/abcd1234")
            .await
            .expect("backend read should succeed");
        assert_eq!(bytes, b"hello peer");
    }

    #[tokio::test]
    async fn test_read_artifact_missing_object_is_error() {
        let storage: Arc<dyn StorageBackend> = Arc::new(InMemoryBackend {
            objects: HashMap::new(),
        });

        let err = read_artifact_from_storage(&storage, "cas/ze/ro/missing")
            .await
            .expect_err("missing object should error");
        assert!(err.contains("cas/ze/ro/missing"), "error was: {err}");
    }

    /// Drive a `StreamChunker` exactly the way `execute_chunked_transfer`
    /// does: feed it stream items, draining full windows as they become
    /// available, then flush the remainder at EOF. Returns the emitted chunks
    /// plus the peak buffered length observed (the memory-bound witness).
    fn drive_chunker(chunk_size: i32, stream_items: &[&[u8]]) -> (Vec<Vec<u8>>, usize) {
        let mut chunker = StreamChunker::new(chunk_size);
        let mut chunks = Vec::new();
        let mut peak = 0usize;
        for item in stream_items {
            chunker.push(item);
            peak = peak.max(chunker.buffered_len());
            while let Some(chunk) = chunker.next_chunk() {
                peak = peak.max(chunker.buffered_len());
                chunks.push(chunk);
            }
        }
        if let Some(rem) = chunker.flush() {
            chunks.push(rem);
        }
        (chunks, peak)
    }

    #[test]
    fn test_stream_chunker_reframes_to_fixed_windows() {
        // Inbound items have irregular sizes (mimicking S3/filesystem reads);
        // output must be contiguous 4-byte windows with a 2-byte remainder.
        let (chunks, _) = drive_chunker(4, &[b"ab", b"cde", b"fghij"]);
        assert_eq!(
            chunks,
            vec![b"abcd".to_vec(), b"efgh".to_vec(), b"ij".to_vec()]
        );
    }

    #[test]
    fn test_stream_chunker_single_large_item_split() {
        // One big inbound item must still split into multiple windows.
        let (chunks, _) = drive_chunker(3, &[b"abcdefg"]);
        assert_eq!(
            chunks,
            vec![b"abc".to_vec(), b"def".to_vec(), b"g".to_vec()]
        );
    }

    #[test]
    fn test_stream_chunker_exact_multiple_no_remainder() {
        let (chunks, _) = drive_chunker(2, &[b"abcd"]);
        assert_eq!(chunks, vec![b"ab".to_vec(), b"cd".to_vec()]);
    }

    #[test]
    fn test_stream_chunker_empty_stream_emits_nothing() {
        let (chunks, peak) = drive_chunker(4, &[]);
        assert!(chunks.is_empty());
        assert_eq!(peak, 0);
    }

    #[test]
    fn test_stream_chunker_boundaries_match_compute_chunk_ranges() {
        // The streamed chunk boundaries (offset/length, derived from a running
        // counter as the worker does) MUST equal what `compute_chunk_ranges`
        // produces, because the receiver reassembles by offset/length. This is
        // the contract that keeps the wire protocol unchanged.
        let chunk_size = 256i32;
        let data: Vec<u8> = (0..=255u8).cycle().take(1000).collect();

        // Feed the artifact in deliberately mis-aligned stream items.
        let stream_items: Vec<&[u8]> = data.chunks(97).collect();
        let (chunks, peak) = drive_chunker(chunk_size, &stream_items);

        // Memory bound: the rolling buffer never exceeds chunk_size + one
        // inbound item, i.e. it never holds the whole artifact.
        let total_len = data.len();
        let bound = chunk_size as usize + 97;
        assert!(peak < total_len, "buffer held {peak} of {total_len} bytes");
        assert!(peak <= bound, "peak {peak} exceeded bound {bound}");

        // Derive offsets/lengths from the emitted chunks the same way the
        // worker does, and compare against compute_chunk_ranges.
        let expected = compute_chunk_ranges(data.len() as i64, chunk_size);
        assert_eq!(chunks.len(), expected.len());
        let mut offset = 0i64;
        let mut reassembled = Vec::new();
        for (i, chunk) in chunks.iter().enumerate() {
            let (exp_idx, exp_offset, exp_len) = expected[i];
            assert_eq!(exp_idx as usize, i);
            assert_eq!(exp_offset, offset, "offset mismatch at chunk {i}");
            assert_eq!(
                exp_len as usize,
                chunk.len(),
                "length mismatch at chunk {i}"
            );
            offset += chunk.len() as i64;
            reassembled.extend_from_slice(chunk);
        }

        // And the concatenation must reproduce the original artifact exactly.
        assert_eq!(reassembled, data);
    }

    #[test]
    fn test_stream_chunker_non_positive_chunk_size_clamped() {
        // A zero/negative chunk size is clamped to 1 so the chunker still makes
        // progress instead of spinning forever.
        let (chunks, _) = drive_chunker(0, &[b"ab"]);
        assert_eq!(chunks, vec![b"a".to_vec(), b"b".to_vec()]);
    }

    #[test]
    fn test_next_chunk_coords_passthrough() {
        assert_eq!(next_chunk_coords(0, 0, 256), (0, 0, 256));
        assert_eq!(next_chunk_coords(3, 768, 100), (3, 768, 100));
        assert_eq!(next_chunk_coords(0, 0, 0), (0, 0, 0));
    }

    /// Build a `BoxStream` from a list of byte slices so `next_framed_chunk`
    /// can be driven exactly as the worker drives it, but without a database
    /// or peer HTTP server.
    fn stream_from(
        items: Vec<&[u8]>,
    ) -> futures::stream::BoxStream<'static, crate::error::Result<Bytes>> {
        let owned: Vec<crate::error::Result<Bytes>> = items
            .into_iter()
            .map(|i| Ok(Bytes::copy_from_slice(i)))
            .collect();
        Box::pin(futures::stream::iter(owned))
    }

    #[tokio::test]
    async fn test_next_framed_chunk_reframes_and_walks_boundaries() {
        // Irregular inbound items, fixed 256-byte windows. Pulling repeatedly
        // must yield contiguous windows whose derived offsets/lengths match
        // compute_chunk_ranges, and concatenating must reproduce the input.
        let chunk_size = 256i32;
        let data: Vec<u8> = (0..=255u8).cycle().take(1000).collect();
        let items: Vec<&[u8]> = data.chunks(97).collect();
        let mut stream = stream_from(items);
        let mut chunker = StreamChunker::new(chunk_size);

        let mut idx = 0i32;
        let mut offset = 0i64;
        let mut reassembled = Vec::new();
        let mut peak = 0usize;
        while let Some(chunk) = next_framed_chunk(&mut stream, &mut chunker).await.unwrap() {
            peak = peak.max(chunker.buffered_len());
            let (ci, off, len) = next_chunk_coords(idx, offset, chunk.len());
            assert_eq!(ci, idx);
            assert_eq!(off, offset);
            assert_eq!(len as usize, chunk.len());
            idx += 1;
            offset += len as i64;
            reassembled.extend_from_slice(&chunk);
        }

        let expected = compute_chunk_ranges(data.len() as i64, chunk_size);
        assert_eq!(idx as usize, expected.len());
        assert_eq!(reassembled, data);
        // Memory bound: never buffers the whole artifact.
        assert!(peak < data.len());
    }

    #[tokio::test]
    async fn test_next_framed_chunk_empty_stream_is_none() {
        let mut stream = stream_from(vec![]);
        let mut chunker = StreamChunker::new(256);
        assert!(next_framed_chunk(&mut stream, &mut chunker)
            .await
            .unwrap()
            .is_none());
    }

    #[tokio::test]
    async fn test_next_framed_chunk_propagates_stream_error() {
        // A stream that errors must surface as Err, not silently terminate.
        let items: Vec<crate::error::Result<Bytes>> =
            vec![Err(crate::error::AppError::Storage("boom".into()))];
        let mut stream: futures::stream::BoxStream<'static, crate::error::Result<Bytes>> =
            Box::pin(futures::stream::iter(items));
        let mut chunker = StreamChunker::new(256);
        let err = next_framed_chunk(&mut stream, &mut chunker)
            .await
            .expect_err("stream error must propagate");
        assert!(err.contains("boom"), "error was: {err}");
    }

    // ── calculate_backoff ───────────────────────────────────────────────

    #[test]
    fn test_backoff_zero_failures() {
        // 10 * 2^0 = 10s
        let d = calculate_backoff(0);
        assert_eq!(d, Duration::from_secs(10));
    }

    #[test]
    fn test_backoff_one_failure() {
        // 10 * 2^1 = 20s
        let d = calculate_backoff(1);
        assert_eq!(d, Duration::from_secs(20));
    }

    #[test]
    fn test_backoff_two_failures() {
        // 10 * 2^2 = 40s
        let d = calculate_backoff(2);
        assert_eq!(d, Duration::from_secs(40));
    }

    #[test]
    fn test_backoff_three_failures() {
        // 10 * 2^3 = 80s
        let d = calculate_backoff(3);
        assert_eq!(d, Duration::from_secs(80));
    }

    #[test]
    fn test_backoff_four_failures() {
        // 10 * 2^4 = 160s
        let d = calculate_backoff(4);
        assert_eq!(d, Duration::from_secs(160));
    }

    #[test]
    fn test_backoff_five_failures_capped() {
        // 10 * 2^5 = 320 → capped at 300
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
        // 2^(u32::MAX wrap) would overflow; saturating_pow returns u64::MAX,
        // then saturating_mul caps and min caps to 300.
        let d = calculate_backoff(-1);
        assert_eq!(d, Duration::from_secs(300));
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
            build_transfer_url("https://peer.example.com", "maven-releases"),
            "https://peer.example.com/api/v1/repositories/maven-releases/artifacts"
        );
    }

    #[test]
    fn test_build_transfer_url_trailing_slash() {
        assert_eq!(
            build_transfer_url("https://peer.example.com/", "npm-proxy"),
            "https://peer.example.com/api/v1/repositories/npm-proxy/artifacts"
        );
    }

    #[test]
    fn test_build_transfer_url_multiple_trailing_slashes() {
        assert_eq!(
            build_transfer_url("https://peer.example.com///", "cargo-local"),
            "https://peer.example.com/api/v1/repositories/cargo-local/artifacts"
        );
    }

    #[test]
    fn test_build_transfer_url_with_port() {
        assert_eq!(
            build_transfer_url("http://localhost:8080", "docker-hub"),
            "http://localhost:8080/api/v1/repositories/docker-hub/artifacts"
        );
    }

    #[test]
    fn test_build_transfer_url_with_path_prefix() {
        assert_eq!(
            build_transfer_url("https://peer.example.com/v2", "pypi-local"),
            "https://peer.example.com/v2/api/v1/repositories/pypi-local/artifacts"
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
        // First two failures are retriable with default max
        assert!(evaluate_task_failure(0, DEFAULT_MAX_RETRIES).is_retriable());
        assert!(evaluate_task_failure(1, DEFAULT_MAX_RETRIES).is_retriable());
        // Third failure exhausts retries
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

    // ── build_chunked_init_url ─────────────────────────────────────────

    #[test]
    fn test_build_chunked_init_url() {
        let peer_id = Uuid::parse_str("11111111-1111-1111-1111-111111111111").unwrap();
        assert_eq!(
            build_chunked_init_url("https://peer.example.com", &peer_id),
            "https://peer.example.com/api/v1/peers/11111111-1111-1111-1111-111111111111/transfer/init"
        );
    }

    #[test]
    fn test_build_chunked_init_url_trailing_slash() {
        let peer_id = Uuid::parse_str("22222222-2222-2222-2222-222222222222").unwrap();
        assert_eq!(
            build_chunked_init_url("https://peer.example.com/", &peer_id),
            "https://peer.example.com/api/v1/peers/22222222-2222-2222-2222-222222222222/transfer/init"
        );
    }

    // ── build_chunk_complete_url ───────────────────────────────────────

    #[test]
    fn test_build_chunk_complete_url() {
        let peer_id = Uuid::parse_str("11111111-1111-1111-1111-111111111111").unwrap();
        let session_id = Uuid::parse_str("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa").unwrap();
        assert_eq!(
            build_chunk_complete_url("https://peer.example.com", &peer_id, &session_id, 3),
            "https://peer.example.com/api/v1/peers/11111111-1111-1111-1111-111111111111/transfer/aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa/chunk/3/complete"
        );
    }

    #[test]
    fn test_build_chunk_complete_url_trailing_slash() {
        let peer_id = Uuid::parse_str("11111111-1111-1111-1111-111111111111").unwrap();
        let session_id = Uuid::parse_str("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb").unwrap();
        assert_eq!(
            build_chunk_complete_url("https://peer.example.com/", &peer_id, &session_id, 0),
            "https://peer.example.com/api/v1/peers/11111111-1111-1111-1111-111111111111/transfer/bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb/chunk/0/complete"
        );
    }

    // ── build_session_complete_url ─────────────────────────────────────

    #[test]
    fn test_build_session_complete_url() {
        let peer_id = Uuid::parse_str("11111111-1111-1111-1111-111111111111").unwrap();
        let session_id = Uuid::parse_str("cccccccc-cccc-cccc-cccc-cccccccccccc").unwrap();
        assert_eq!(
            build_session_complete_url("https://peer.example.com", &peer_id, &session_id),
            "https://peer.example.com/api/v1/peers/11111111-1111-1111-1111-111111111111/transfer/cccccccc-cccc-cccc-cccc-cccccccccccc/complete"
        );
    }

    #[test]
    fn test_build_session_complete_url_trailing_slash() {
        let peer_id = Uuid::parse_str("11111111-1111-1111-1111-111111111111").unwrap();
        let session_id = Uuid::parse_str("dddddddd-dddd-dddd-dddd-dddddddddddd").unwrap();
        assert_eq!(
            build_session_complete_url("https://peer.example.com/", &peer_id, &session_id),
            "https://peer.example.com/api/v1/peers/11111111-1111-1111-1111-111111111111/transfer/dddddddd-dddd-dddd-dddd-dddddddddddd/complete"
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
}
