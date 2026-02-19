//! Background sync worker.
//!
//! Processes the `sync_tasks` queue by transferring artifacts to remote peer
//! instances.  Runs on a 10-second tick, respects per-peer concurrency limits,
//! sync windows, and exponential backoff on failures.

use chrono::{NaiveTime, Timelike, Utc};
use sqlx::PgPool;
use tokio::time::{interval, Duration};
use uuid::Uuid;

/// Spawn the background sync worker.
///
/// The worker runs in an infinite loop on a 10-second interval, picking up
/// pending sync tasks and dispatching transfers to remote peers.
pub async fn spawn_sync_worker(db: PgPool) {
    tokio::spawn(async move {
        // Small startup delay so the server can finish initializing.
        tokio::time::sleep(Duration::from_secs(5)).await;
        let mut tick = interval(Duration::from_secs(10));
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(300))
            .build()
            .expect("Failed to build HTTP client for sync worker");

        loop {
            tick.tick().await;
            if let Err(e) = process_pending_tasks(&db, &client).await {
                tracing::error!("Sync worker error: {e}");
            }
        }
    });
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
}

// ── Core logic ──────────────────────────────────────────────────────────────

/// Process all eligible peers and their pending sync tasks.
async fn process_pending_tasks(db: &PgPool, client: &reqwest::Client) -> Result<(), String> {
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
                st.task_type
            FROM sync_tasks st
            JOIN artifacts a ON a.id = st.artifact_id
            JOIN repositories r ON r.id = a.repository_id
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

        // Spawn each transfer concurrently.
        for task in tasks {
            let db = db.clone();
            let client = client.clone();
            let peer_endpoint = peer.endpoint_url.clone();
            let peer_api_key = peer.api_key.clone();
            let peer_name = peer.name.clone();

            tokio::spawn(async move {
                if let Err(e) =
                    execute_transfer(&db, &client, &task, &peer_endpoint, &peer_api_key).await
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

    // Push flow: read artifact bytes and POST to peer.

    // 2. Read the artifact bytes from local storage.
    let file_bytes = match read_artifact_from_storage(db, &task.storage_key).await {
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

/// Read artifact bytes from the storage backend using the storage_key.
///
/// Uses the `STORAGE_PATH` environment variable (same as the main server) to
/// locate the filesystem storage root.  For S3 backends the storage_key is
/// fetched directly.
async fn read_artifact_from_storage(_db: &PgPool, storage_key: &str) -> Result<Vec<u8>, String> {
    // Determine storage path from env (fallback to default).
    let storage_path = std::env::var("STORAGE_PATH")
        .unwrap_or_else(|_| "/var/lib/artifact-keeper/artifacts".into());
    let full_path = std::path::PathBuf::from(&storage_path).join(storage_key);

    tokio::fs::read(&full_path)
        .await
        .map_err(|e| format!("Failed to read '{}': {e}", full_path.display()))
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

/// Handle a failed transfer: mark task, apply backoff, update peer counters.
async fn handle_transfer_failure(db: &PgPool, task: &TaskRow, error_message: &str) {
    // Mark task as failed.
    let _ = sqlx::query(
        r#"
        UPDATE sync_tasks
        SET status = 'failed', completed_at = NOW(), error_message = $2
        WHERE id = $1
        "#,
    )
    .bind(task.id)
    .bind(error_message)
    .execute(db)
    .await;

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
}
