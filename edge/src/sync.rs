//! Sync and heartbeat logic with chunked transfer support.

use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

use uuid::Uuid;

use crate::EdgeState;

/// Send heartbeat to primary registry.
///
/// This loop sends periodic heartbeats to the primary server, reporting
/// cache status and connectivity. Heartbeat failures are used to detect
/// offline mode transitions.
pub async fn heartbeat_loop(state: Arc<EdgeState>) {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .unwrap();

    let interval = Duration::from_secs(30);

    loop {
        match send_heartbeat(&client, &state).await {
            Ok(heartbeat_response) => {
                tracing::debug!("Heartbeat sent successfully");
                // Successful heartbeat means we're online
                if state.is_offline.load(Ordering::SeqCst) {
                    state.is_offline.store(false, Ordering::SeqCst);
                    tracing::info!("Heartbeat successful - transitioning to online mode");
                }
                // Update last contact time
                let mut last_contact = state.last_primary_contact.write().await;
                *last_contact = Some(std::time::Instant::now());

                // If the heartbeat response includes our node ID, store it
                if let Some(id) = heartbeat_response {
                    let mut node_id = state.edge_node_id.write().await;
                    if node_id.is_none() {
                        *node_id = Some(id);
                        tracing::info!(node_id = %id, "Edge node ID registered");
                    }
                }
            }
            Err(e) => {
                tracing::warn!("Heartbeat failed: {}", e);
                if is_heartbeat_connectivity_error(&e) && !state.is_offline.load(Ordering::SeqCst) {
                    state.is_offline.store(true, Ordering::SeqCst);
                    tracing::warn!(
                        "Heartbeat connectivity failure - transitioning to offline mode"
                    );
                }
            }
        }

        tokio::time::sleep(interval).await;
    }
}

/// Check if a heartbeat error indicates a connectivity problem.
fn is_heartbeat_connectivity_error(err: &anyhow::Error) -> bool {
    if let Some(reqwest_err) = err.downcast_ref::<reqwest::Error>() {
        return reqwest_err.is_connect() || reqwest_err.is_timeout() || reqwest_err.is_request();
    }
    let msg = err.to_string().to_lowercase();
    msg.contains("connection refused")
        || msg.contains("network unreachable")
        || msg.contains("host unreachable")
        || msg.contains("timed out")
        || msg.contains("dns")
}

/// Heartbeat response that may include the edge node's registered ID.
#[derive(Debug, serde::Deserialize)]
struct HeartbeatResponse {
    #[serde(default)]
    node_id: Option<Uuid>,
}

async fn send_heartbeat(
    client: &reqwest::Client,
    state: &EdgeState,
) -> anyhow::Result<Option<Uuid>> {
    let url = format!("{}/api/v1/edge-nodes/heartbeat", state.primary_url);

    let is_offline = state.is_offline.load(Ordering::SeqCst);

    let payload = serde_json::json!({
        "cache_size_bytes": state.cache.size(),
        "cache_entries": state.cache.len(),
        "is_offline": is_offline,
    });

    let response = client
        .post(&url)
        .header("Authorization", format!("Bearer {}", state.api_key))
        .json(&payload)
        .send()
        .await?
        .error_for_status()?;

    // Try to parse a node_id from the response body
    let node_id = response
        .json::<HeartbeatResponse>()
        .await
        .ok()
        .and_then(|r| r.node_id);

    Ok(node_id)
}

/// Fetch artifact from primary.
///
/// For small artifacts (< CHUNKED_TRANSFER_THRESHOLD), fetches the whole file.
/// For large artifacts when chunked transfer is enabled, uses the swarm-based
/// chunked transfer protocol with multi-peer support and resume capability.
pub async fn fetch_from_primary(
    client: &reqwest::Client,
    state: &EdgeState,
    repo_key: &str,
    artifact_path: &str,
) -> anyhow::Result<bytes::Bytes> {
    // Simple whole-file fetch (used for all artifacts currently;
    // chunked_fetch is available for artifact-ID-based transfers
    // triggered by the sync loop)
    let url = format!(
        "{}/api/v1/repositories/{}/artifacts/{}/download",
        state.primary_url, repo_key, artifact_path
    );

    let response = client
        .get(&url)
        .header("Authorization", format!("Bearer {}", state.api_key))
        .send()
        .await?
        .error_for_status()?;

    Ok(response.bytes().await?)
}

/// Fetch an artifact by ID using chunked transfer when appropriate.
///
/// This is used by the background sync loop for scheduled replication.
/// It decides between simple fetch and chunked transfer based on size.
pub async fn fetch_artifact_by_id(
    client: &reqwest::Client,
    state: &Arc<EdgeState>,
    artifact_id: Uuid,
    artifact_size: i64,
) -> anyhow::Result<bytes::Bytes> {
    let use_chunked = state.chunked_transfer_enabled
        && artifact_size as u64 >= crate::CHUNKED_TRANSFER_THRESHOLD
        && state.edge_node_id.read().await.is_some();

    if use_chunked {
        tracing::info!(
            artifact_id = %artifact_id,
            size = artifact_size,
            "Using chunked transfer"
        );
        crate::transfer::chunked_fetch(client, state, artifact_id).await
    } else {
        tracing::debug!(
            artifact_id = %artifact_id,
            size = artifact_size,
            "Using simple fetch"
        );
        // Fall back to direct download from primary
        let url = format!(
            "{}/api/v1/artifacts/{}/download",
            state.primary_url, artifact_id
        );

        let response = client
            .get(&url)
            .header("Authorization", format!("Bearer {}", state.api_key))
            .send()
            .await?
            .error_for_status()?;

        Ok(response.bytes().await?)
    }
}
