//! Network-aware sync scheduler with bandwidth control.
//!
//! Fetches pending sync tasks from the primary registry and downloads
//! artifacts respecting priority, sync windows, concurrency limits,
//! and bandwidth constraints via a token bucket rate limiter.

use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

use chrono::NaiveTime;
use uuid::Uuid;

use crate::EdgeState;

/// Maximum concurrent sync downloads.
const MAX_SYNC_CONCURRENCY: i32 = 4;

/// Base interval between scheduler ticks.
const SCHEDULER_INTERVAL_SECS: u64 = 15;

/// Maximum backoff duration on consecutive failures.
const MAX_BACKOFF_SECS: u64 = 3600;

/// Priority threshold: P0 tasks (priority 0) bypass sync window restrictions.
const P0_PRIORITY: i32 = 0;

/// A pending sync task from the primary.
#[derive(Debug, Clone, serde::Deserialize)]
pub struct SyncTask {
    pub id: Uuid,
    pub artifact_id: Uuid,
    pub storage_key: String,
    pub artifact_size: i64,
    pub priority: i32,
}

/// Token bucket rate limiter for bandwidth control.
///
/// Replenishes tokens at `max_bps` bytes per second. Each download
/// must acquire tokens before transferring data.
pub struct TokenBucket {
    max_bps: i64,
    available: tokio::sync::Mutex<f64>,
    last_refill: tokio::sync::Mutex<std::time::Instant>,
}

impl TokenBucket {
    /// Create a new token bucket with the given maximum bytes per second.
    ///
    /// If `max_bps` is zero or negative, the bucket is effectively unlimited.
    pub fn new(max_bps: i64) -> Self {
        Self {
            max_bps,
            available: tokio::sync::Mutex::new(max_bps as f64),
            last_refill: tokio::sync::Mutex::new(std::time::Instant::now()),
        }
    }

    /// Refill tokens based on elapsed time since last refill.
    async fn refill(&self) {
        let mut last = self.last_refill.lock().await;
        let mut available = self.available.lock().await;

        let now = std::time::Instant::now();
        let elapsed = now.duration_since(*last).as_secs_f64();
        *last = now;

        let added = elapsed * self.max_bps as f64;
        *available = (*available + added).min(self.max_bps as f64);
    }

    /// Try to consume `bytes` tokens without blocking.
    ///
    /// Returns `true` if enough tokens were available.
    pub async fn try_consume(&self, bytes: usize) -> bool {
        if self.max_bps <= 0 {
            return true;
        }

        self.refill().await;

        let mut available = self.available.lock().await;
        let needed = bytes as f64;

        if *available >= needed {
            *available -= needed;
            true
        } else {
            false
        }
    }

    /// Wait until enough tokens are available, then consume them.
    pub async fn wait_for(&self, bytes: usize) {
        if self.max_bps <= 0 {
            return;
        }

        loop {
            if self.try_consume(bytes).await {
                return;
            }

            // Estimate how long to wait for the required tokens
            let available = *self.available.lock().await;
            let deficit = bytes as f64 - available;
            let wait_secs = (deficit / self.max_bps as f64).max(0.01);

            tokio::time::sleep(Duration::from_secs_f64(wait_secs)).await;
        }
    }
}

/// Check whether the current local time falls within the configured sync window.
///
/// If either bound is `None`, the window is considered open (no restriction).
/// When `start` is after `end`, the window wraps across midnight
/// (e.g. 22:00 - 06:00).
pub fn is_within_sync_window(start: Option<NaiveTime>, end: Option<NaiveTime>) -> bool {
    let (start, end) = match (start, end) {
        (Some(s), Some(e)) => (s, e),
        _ => return true,
    };

    let now = chrono::Local::now().time();

    if start <= end {
        // Same-day window, e.g. 02:00 - 06:00
        now >= start && now <= end
    } else {
        // Overnight window, e.g. 22:00 - 06:00
        now >= start || now <= end
    }
}

/// Fetch pending sync tasks from the primary registry.
pub async fn fetch_sync_tasks(
    client: &reqwest::Client,
    state: &EdgeState,
) -> anyhow::Result<Vec<SyncTask>> {
    let node_id = state.node_id();
    let url = format!(
        "{}/api/v1/edge-nodes/{}/sync/tasks",
        state.primary_url, node_id
    );

    let response = client
        .get(&url)
        .header("Authorization", format!("Bearer {}", state.api_key))
        .send()
        .await?
        .error_for_status()?;

    Ok(response.json().await?)
}

/// Report a sync task as completed to the primary registry.
async fn report_task_complete(
    client: &reqwest::Client,
    state: &EdgeState,
    task_id: Uuid,
) -> anyhow::Result<()> {
    let node_id = state.node_id();
    let url = format!(
        "{}/api/v1/edge-nodes/{}/sync/tasks/{}/complete",
        state.primary_url, node_id, task_id
    );

    client
        .post(&url)
        .header("Authorization", format!("Bearer {}", state.api_key))
        .json(&serde_json::json!({}))
        .send()
        .await?
        .error_for_status()?;

    Ok(())
}

/// Execute a single sync task: download the artifact and cache it.
async fn execute_sync_task(
    client: &reqwest::Client,
    state: &Arc<EdgeState>,
    task: &SyncTask,
    rate_limiter: &TokenBucket,
) -> anyhow::Result<()> {
    tracing::info!(
        task_id = %task.id,
        artifact_id = %task.artifact_id,
        storage_key = %task.storage_key,
        size = task.artifact_size,
        priority = task.priority,
        "Starting sync task"
    );

    // Rate limit based on artifact size
    rate_limiter.wait_for(task.artifact_size as usize).await;

    state.active_transfers.fetch_add(1, Ordering::Relaxed);
    let result =
        crate::sync::fetch_artifact_by_id(client, state, task.artifact_id, task.artifact_size)
            .await;
    state.active_transfers.fetch_sub(1, Ordering::Relaxed);

    let artifact_bytes = result?;

    state
        .bytes_transferred
        .fetch_add(artifact_bytes.len() as i64, Ordering::Relaxed);

    // Cache the artifact using the storage key
    state.cache.put(task.storage_key.clone(), artifact_bytes);

    // Report completion to primary
    if let Err(e) = report_task_complete(client, state, task.id).await {
        tracing::warn!(task_id = %task.id, error = %e, "Failed to report task completion");
    }

    tracing::info!(
        task_id = %task.id,
        artifact_id = %task.artifact_id,
        "Sync task completed"
    );

    Ok(())
}

/// Main background loop that polls for sync tasks and executes them.
///
/// Behavior:
/// - Ticks every 15 seconds
/// - Skips when offline or before node registration
/// - P0 tasks bypass the sync window; other priorities respect it
/// - Respects `MAX_SYNC_CONCURRENCY` concurrent downloads
/// - Uses a token bucket rate limiter for bandwidth control
/// - Applies exponential backoff on consecutive failures (max 3600s)
pub async fn sync_scheduler_loop(state: Arc<EdgeState>) {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(60))
        .build()
        .unwrap();

    // Read bandwidth limit from environment (bytes/sec, 0 = unlimited)
    let max_bps: i64 = std::env::var("SYNC_BANDWIDTH_LIMIT_BPS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);

    let rate_limiter = Arc::new(TokenBucket::new(max_bps));

    // Read optional sync window from environment (HH:MM format)
    let sync_window_start: Option<NaiveTime> = std::env::var("SYNC_WINDOW_START")
        .ok()
        .and_then(|v| NaiveTime::parse_from_str(&v, "%H:%M").ok());

    let sync_window_end: Option<NaiveTime> = std::env::var("SYNC_WINDOW_END")
        .ok()
        .and_then(|v| NaiveTime::parse_from_str(&v, "%H:%M").ok());

    if max_bps > 0 {
        tracing::info!(max_bps, "Sync scheduler bandwidth limit configured");
    }
    if sync_window_start.is_some() || sync_window_end.is_some() {
        tracing::info!(
            start = ?sync_window_start,
            end = ?sync_window_end,
            "Sync window configured"
        );
    }

    // Initial delay to let heartbeat establish connection first
    tokio::time::sleep(Duration::from_secs(5)).await;

    let mut backoff_secs: u64 = 0;

    loop {
        // Apply backoff if there have been consecutive failures
        let sleep_duration = if backoff_secs > 0 {
            Duration::from_secs(backoff_secs)
        } else {
            Duration::from_secs(SCHEDULER_INTERVAL_SECS)
        };
        tokio::time::sleep(sleep_duration).await;

        // Skip when offline
        if state.is_offline.load(Ordering::SeqCst) {
            continue;
        }

        // Skip if we don't have a node ID yet
        let node_id = state.node_id();
        if node_id.is_nil() {
            continue;
        }

        // Fetch pending tasks
        let tasks = match fetch_sync_tasks(&client, &state).await {
            Ok(tasks) => {
                // Reset backoff on successful fetch
                if backoff_secs > 0 {
                    tracing::info!("Sync scheduler recovered, resetting backoff");
                    backoff_secs = 0;
                }
                state.consecutive_failures.store(0, Ordering::Relaxed);
                tasks
            }
            Err(e) => {
                let failures = state.consecutive_failures.fetch_add(1, Ordering::Relaxed) + 1;
                backoff_secs = compute_backoff(failures);
                tracing::warn!(
                    error = %e,
                    failures,
                    backoff_secs,
                    "Failed to fetch sync tasks"
                );
                continue;
            }
        };

        if tasks.is_empty() {
            continue;
        }

        let in_window = is_within_sync_window(sync_window_start, sync_window_end);

        // Separate P0 tasks (always run) from lower priority tasks (respect window)
        let (p0_tasks, scheduled_tasks): (Vec<_>, Vec<_>) =
            tasks.into_iter().partition(|t| t.priority == P0_PRIORITY);

        let mut tasks_to_run = p0_tasks;
        if in_window {
            tasks_to_run.extend(scheduled_tasks);
        } else if !tasks_to_run.is_empty() {
            tracing::debug!(
                scheduled_count = scheduled_tasks.len(),
                "Outside sync window, running only P0 tasks"
            );
        } else {
            tracing::debug!("Outside sync window, no P0 tasks to run");
            continue;
        }

        // Sort by priority (lower number = higher priority)
        tasks_to_run.sort_by_key(|t| t.priority);

        // Respect concurrency limit
        let current_active = state.active_transfers.load(Ordering::Relaxed);
        let available_slots = (MAX_SYNC_CONCURRENCY - current_active).max(0) as usize;

        if available_slots == 0 {
            tracing::debug!("No available transfer slots, deferring sync tasks");
            continue;
        }

        let batch: Vec<_> = tasks_to_run.into_iter().take(available_slots).collect();

        tracing::info!(count = batch.len(), "Executing sync task batch");

        // Execute tasks concurrently
        let mut handles = Vec::new();
        for task in batch {
            let client = client.clone();
            let state = state.clone();
            let limiter = rate_limiter.clone();

            let handle = tokio::spawn(async move {
                if let Err(e) = execute_sync_task(&client, &state, &task, &limiter).await {
                    tracing::warn!(
                        task_id = %task.id,
                        artifact_id = %task.artifact_id,
                        error = %e,
                        "Sync task failed"
                    );
                }
            });
            handles.push(handle);
        }

        // Wait for all tasks in the batch to complete
        for handle in handles {
            let _ = handle.await;
        }
    }
}

/// Compute exponential backoff duration from failure count, capped at MAX_BACKOFF_SECS.
fn compute_backoff(failures: u32) -> u64 {
    let base: u64 = SCHEDULER_INTERVAL_SECS * 2u64.pow(failures.min(10));
    base.min(MAX_BACKOFF_SECS)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sync_window_no_bounds() {
        assert!(is_within_sync_window(None, None));
        assert!(is_within_sync_window(
            Some(NaiveTime::from_hms_opt(2, 0, 0).unwrap()),
            None
        ));
        assert!(is_within_sync_window(
            None,
            Some(NaiveTime::from_hms_opt(6, 0, 0).unwrap())
        ));
    }

    #[test]
    fn test_compute_backoff_capped() {
        assert!(compute_backoff(0) <= MAX_BACKOFF_SECS);
        assert_eq!(compute_backoff(20), MAX_BACKOFF_SECS);
    }

    #[tokio::test]
    async fn test_token_bucket_unlimited() {
        let bucket = TokenBucket::new(0);
        assert!(bucket.try_consume(1_000_000).await);
    }

    #[tokio::test]
    async fn test_token_bucket_consume() {
        let bucket = TokenBucket::new(1000);
        // Should be able to consume up to max_bps initially
        assert!(bucket.try_consume(500).await);
        assert!(bucket.try_consume(500).await);
        // Should fail when exhausted
        assert!(!bucket.try_consume(500).await);
    }
}
