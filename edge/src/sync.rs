//! Sync and heartbeat logic.

use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

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
            Ok(_) => {
                tracing::debug!("Heartbeat sent successfully");
                // Successful heartbeat means we're online
                if state.is_offline.load(Ordering::SeqCst) {
                    state.is_offline.store(false, Ordering::SeqCst);
                    tracing::info!("Heartbeat successful - transitioning to online mode");
                }
                // Update last contact time
                let mut last_contact = state.last_primary_contact.write().await;
                *last_contact = Some(std::time::Instant::now());
            }
            Err(e) => {
                tracing::warn!("Heartbeat failed: {}", e);
                // Check if this is a connectivity error
                if is_heartbeat_connectivity_error(&e)
                    && !state.is_offline.load(Ordering::SeqCst)
                {
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

async fn send_heartbeat(client: &reqwest::Client, state: &EdgeState) -> anyhow::Result<()> {
    let url = format!("{}/api/v1/edge-nodes/heartbeat", state.primary_url);

    let is_offline = state.is_offline.load(Ordering::SeqCst);

    let payload = serde_json::json!({
        "cache_size_bytes": state.cache.size(),
        "cache_entries": state.cache.len(),
        "is_offline": is_offline,
    });

    client
        .post(&url)
        .header("Authorization", format!("Bearer {}", state.api_key))
        .json(&payload)
        .send()
        .await?
        .error_for_status()?;

    Ok(())
}

/// Fetch artifact from primary
pub async fn fetch_from_primary(
    client: &reqwest::Client,
    state: &EdgeState,
    repo_key: &str,
    artifact_path: &str,
) -> anyhow::Result<bytes::Bytes> {
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
